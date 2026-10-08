import { createReadStream, createWriteStream } from 'node:fs';
import { readFile, rm, stat } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import type { DrmEndpoint, DrmSystem, EncryptionScheme, MediaKind, ScreenVeilManifest } from '../shared/manifest.ts';
import { guessKind, type TranscodeOptions } from './ffmpeg.ts';
import { type KeySource, type KeyStore, assertSafeId, fileKeyStore, randomKeys } from './keys.ts';
import { LicenseError, type LicenseProvider } from './license.ts';
import { newContentId, protectFile } from './packager.ts';
import { type LicenseTokenClaims, issueLicenseToken, verifyLicenseToken } from './tokens.ts';

export interface ScreenVeilApiOptions {
  /** Assets go to `<dataDir>/assets/<id>/`, keys to `<dataDir>/keys/` (unless keyStore is given). */
  dataDir: string;
  /** URL prefix of every route. Default "/api". */
  basePath?: string;
  /** License providers, one per DRM system you want to support. */
  licenses: LicenseProvider[];
  keySource?: KeySource;
  keyStore?: KeyStore;
  scheme?: EncryptionScheme;
  /**
   * Secret for license tokens. When set, license requests must carry
   * `Authorization: Bearer <token>` issued by {@link issueLicenseToken} for that asset.
   */
  tokenSecret?: string;
  /** Extra check run on every license request (after token verification). */
  authorizeLicense?: (ctx: { id: string; system: DrmSystem; req: IncomingMessage; claims?: LicenseTokenClaims }) => boolean | Promise<boolean>;
  /** Who may upload. Uploads are disabled unless this is provided. */
  authorizeUpload?: (req: IncomingMessage) => boolean | Promise<boolean>;
  /**
   * Who may obtain a license token from `POST {basePath}/assets/:id/token`. Return a subject
   * string (user id) to allow, or false to deny. Disabled unless provided; in production your
   * own backend usually calls issueLicenseToken() directly instead.
   */
  issueToken?: (req: IncomingMessage, id: string) => string | false | Promise<string | false>;
  tokenTtlSeconds?: number;
  maxUploadBytes?: number;
  /** Value for Access-Control-Allow-Origin. Omit to disable CORS headers. */
  corsOrigin?: string;
  transcode?: TranscodeOptions;
  /** Called with errors that become HTTP 500s. Default: console.error. */
  onError?: (err: unknown) => void;
}

type Next = (err?: unknown) => void;
export type ScreenVeilHandler = (req: IncomingMessage, res: ServerResponse, next?: Next) => void;

const SYSTEMS: DrmSystem[] = ['widevine', 'playready', 'fairplay', 'clearkey'];

/**
 * The ScreenVeil Web API as a plain Node request handler. Works with `http.createServer`,
 * Express (`app.use(handler)`), Connect, Fastify's middie, etc.
 *
 * Routes (prefix = basePath):
 *   POST /assets?filename=photo.jpg[&kind=image|video]   upload raw bytes, returns the manifest
 *   GET  /assets/:id/manifest.json
 *   GET  /assets/:id/media.mp4                            supports Range requests
 *   POST /assets/:id/token                                issue a license token (if enabled)
 *   POST /license/:system/:id                             CDM challenge -> license
 *   GET  /license/fairplay/:id/certificate
 */
export function createScreenVeilApi(options: ScreenVeilApiOptions): ScreenVeilHandler {
  const base = (options.basePath ?? '/api').replace(/\/$/, '');
  const assetsDir = join(options.dataDir, 'assets');
  const keyStore = options.keyStore ?? fileKeyStore(join(options.dataDir, 'keys'));
  const keySource = options.keySource ?? randomKeys();
  const providers = new Map(options.licenses.map((p) => [p.system, p]));
  const maxUpload = options.maxUploadBytes ?? 500 * 1024 * 1024;
  const onError = options.onError ?? ((e: unknown) => console.error('[screenveil]', e));

  const drmEndpoints = (): Partial<Record<DrmSystem, DrmEndpoint>> => {
    const out: Partial<Record<DrmSystem, DrmEndpoint>> = {};
    for (const s of SYSTEMS) {
      if (!providers.has(s)) continue;
      out[s] = {
        licenseUrl: `${base}/license/${s}/{id}`,
        ...(s === 'fairplay' ? { certificateUrl: `${base}/license/fairplay/{id}/certificate` } : {}),
      };
    }
    return out;
  };

  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(body));
  };

  const readBody = async (req: IncomingMessage, limit: number): Promise<Buffer> => {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > limit) throw new LicenseError('Request body too large', 413);
      chunks.push(c as Buffer);
    }
    return Buffer.concat(chunks);
  };

  const loadManifest = async (id: string): Promise<ScreenVeilManifest | undefined> => {
    try {
      return JSON.parse(await readFile(join(assetsDir, id, 'manifest.json'), 'utf8'));
    } catch {
      return undefined;
    }
  };

  async function handleUpload(req: IncomingMessage, res: ServerResponse, url: URL) {
    if (!options.authorizeUpload || !(await options.authorizeUpload(req))) return json(res, 403, { error: 'Uploads are not allowed' });
    const declared = Number(req.headers['content-length'] ?? 0);
    if (declared > maxUpload) return json(res, 413, { error: 'File too large' });
    const filename = url.searchParams.get('filename') ?? 'upload';
    const kindParam = url.searchParams.get('kind');
    const kind: MediaKind =
      kindParam === 'image' || kindParam === 'video' ? kindParam : guessKind(filename, req.headers['content-type']);
    const ext = (filename.match(/\.[A-Za-z0-9]{1,5}$/)?.[0] ?? '').toLowerCase();
    const tmp = join(tmpdir(), `screenveil-up-${randomBytes(8).toString('hex')}${ext}`);
    try {
      let size = 0;
      const limiter = new Transform({
        transform(chunk: Buffer, _enc, cb) {
          size += chunk.length;
          cb(size > maxUpload ? new LicenseError('File too large', 413) : null, chunk);
        },
      });
      await pipeline(req, limiter, createWriteStream(tmp));
      if (size === 0) return json(res, 400, { error: 'Empty upload' });
      const id = newContentId();
      let manifest: ScreenVeilManifest;
      try {
        ({ manifest } = await protectFile(tmp, join(assetsDir, id), {
          id,
          kind,
          scheme: options.scheme,
          keySource,
          keyStore,
          drm: drmEndpoints(),
          transcode: options.transcode,
        }));
      } catch (e) {
        if (e instanceof Error && e.message.startsWith('ffmpeg exited')) {
          return json(res, 422, { error: 'Could not decode the uploaded file as an image or video' });
        }
        throw e;
      }
      json(res, 201, { id, manifestUrl: `${base}/assets/${id}/manifest.json`, manifest });
    } finally {
      await rm(tmp, { force: true });
    }
  }

  async function serveMedia(req: IncomingMessage, res: ServerResponse, id: string) {
    const file = join(assetsDir, id, 'media.mp4');
    let size: number;
    try {
      size = (await stat(file)).size;
    } catch {
      return json(res, 404, { error: 'Not found' });
    }
    const headers: Record<string, string | number> = {
      'Content-Type': 'video/mp4',
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'public, max-age=3600',
    };
    const range = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range ?? ''));
    if (range && (range[1] || range[2])) {
      let start = range[1] ? Number(range[1]) : size - Number(range[2]);
      let end = range[1] && range[2] ? Number(range[2]) : size - 1;
      start = Math.max(0, start);
      end = Math.min(end, size - 1);
      if (start > end) {
        res.writeHead(416, { 'Content-Range': `bytes */${size}` });
        return res.end();
      }
      res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${size}`, 'Content-Length': end - start + 1 });
      if (req.method === 'HEAD') return res.end();
      return pipeline(createReadStream(file, { start, end }), res);
    }
    res.writeHead(200, { ...headers, 'Content-Length': size });
    if (req.method === 'HEAD') return res.end();
    return pipeline(createReadStream(file), res);
  }

  async function handleLicense(req: IncomingMessage, res: ServerResponse, system: DrmSystem, id: string, certificate: boolean) {
    const provider = providers.get(system);
    if (!provider) return json(res, 404, { error: `DRM system ${system} is not enabled` });
    let claims: LicenseTokenClaims | undefined;
    if (options.tokenSecret) {
      const auth = String(req.headers.authorization ?? '');
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      claims = verifyLicenseToken(options.tokenSecret, token, id) ?? undefined;
      if (!claims) return json(res, 401, { error: 'Missing or invalid license token' });
    }
    if (options.authorizeLicense && !(await options.authorizeLicense({ id, system, req, claims }))) {
      return json(res, 403, { error: 'Not allowed' });
    }
    if (certificate) {
      if (!provider.certificate) return json(res, 404, { error: 'No certificate for this system' });
      const out = await provider.certificate({ id, headers: req.headers, claims });
      res.writeHead(200, { 'Content-Type': out.contentType ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
      return res.end(out.body);
    }
    const key = await keyStore.get(id);
    const manifest = await loadManifest(id);
    if (!key || !manifest) return json(res, 404, { error: 'Unknown asset' });
    const challenge = await readBody(req, 1024 * 1024);
    const out = await provider.acquire(challenge, { id, key, scheme: manifest.scheme, headers: req.headers, claims });
    res.writeHead(200, { 'Content-Type': out.contentType ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(out.body);
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (!url.pathname.startsWith(`${base}/`)) return false;
    const parts = url.pathname.slice(base.length + 1).split('/');
    const method = req.method ?? 'GET';

    if (options.corsOrigin) {
      res.setHeader('Access-Control-Allow-Origin', options.corsOrigin);
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Range');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Content-Length');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
      if (method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return true;
      }
    }

    if (parts[0] === 'assets' && parts.length === 1 && method === 'POST') {
      await handleUpload(req, res, url);
      return true;
    }
    if (parts[0] === 'assets' && parts.length === 3) {
      const id = parts[1];
      try {
        assertSafeId(id);
      } catch {
        json(res, 400, { error: 'Invalid id' });
        return true;
      }
      if (parts[2] === 'manifest.json' && (method === 'GET' || method === 'HEAD')) {
        const m = await loadManifest(id);
        if (!m) json(res, 404, { error: 'Not found' });
        else json(res, 200, m);
        return true;
      }
      if (parts[2] === 'media.mp4' && (method === 'GET' || method === 'HEAD')) {
        await serveMedia(req, res, id);
        return true;
      }
      if (parts[2] === 'token' && method === 'POST') {
        if (!options.issueToken || !options.tokenSecret) {
          json(res, 404, { error: 'Token endpoint disabled' });
          return true;
        }
        if (!(await loadManifest(id))) {
          json(res, 404, { error: 'Unknown asset' });
          return true;
        }
        const subject = await options.issueToken(req, id);
        if (subject === false) {
          json(res, 403, { error: 'Not allowed' });
          return true;
        }
        const token = issueLicenseToken(options.tokenSecret, { contentId: id, subject, ttlSeconds: options.tokenTtlSeconds });
        json(res, 200, { token });
        return true;
      }
    }
    if (parts[0] === 'license' && (parts.length === 3 || parts.length === 4)) {
      const system = parts[1] as DrmSystem;
      const id = parts[2];
      const isCert = parts.length === 4 && parts[3] === 'certificate';
      if (!SYSTEMS.includes(system) || (parts.length === 4 && !isCert)) return false;
      try {
        assertSafeId(id);
      } catch {
        json(res, 400, { error: 'Invalid id' });
        return true;
      }
      if (!isCert && method !== 'POST') {
        json(res, 405, { error: 'Use POST' });
        return true;
      }
      await handleLicense(req, res, system, id, isCert);
      return true;
    }
    return false;
  }

  return (req, res, next) => {
    route(req, res)
      .then((handled) => {
        if (handled) return;
        if (next) next();
        else json(res, 404, { error: 'Not found' });
      })
      .catch((err: unknown) => {
        if (err instanceof LicenseError) {
          if (!res.headersSent) json(res, err.status, { error: err.message });
          return;
        }
        onError(err);
        if (!res.headersSent) json(res, 500, { error: 'Internal error' });
        else res.destroy();
      });
  };
}
