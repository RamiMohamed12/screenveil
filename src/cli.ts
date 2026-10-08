#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { createReadStream, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import type { DrmEndpoint, DrmSystem, EncryptionScheme, MediaKind } from './shared/manifest.ts';
import { createScreenVeilApi, type ScreenVeilApiOptions } from './server/api.ts';
import { fileKeyStore, randomKeys, widevineTestKeys } from './server/keys.ts';
import { clearKeyLicense, playReadyTestLicense, widevineTestLicense } from './server/license.ts';
import { protectFile } from './server/packager.ts';

const HELP = `screenveil - DRM-protected images and videos that show up black in screenshots

Usage:
  screenveil serve [--dev] [--config file.mjs] [--port 8080] [--host localhost] [--data ./screenveil-data]
  screenveil protect <file> [--dev] [--data ./screenveil-data] [--out dir] [--id name]
                            [--kind image|video] [--scheme cenc|cbcs] [--systems widevine,playready]
                            [--license-base /api]

serve     Runs the Web API (upload, manifests, media, license proxy) and a demo page.
          --dev     uses Google's and Microsoft's public DRM test servers. No setup needed,
                    but NOT for production: test servers hand out keys to anyone.
          --config  a module whose default export is ScreenVeilApiOptions (or a function returning them).
protect   Encrypts one file into <data>/assets/<id>/ and stores its key in <data>/keys/.
`;

function fail(msg: string): never {
  console.error(`error: ${msg}\n`);
  console.error(HELP);
  process.exit(1);
}

async function serve(argv: string[]) {
  const { values } = parseArgs({
    args: argv,
    options: {
      dev: { type: 'boolean', default: false },
      config: { type: 'string' },
      port: { type: 'string', default: process.env.PORT ?? '8080' },
      host: { type: 'string', default: 'localhost' },
      data: { type: 'string', default: './screenveil-data' },
      secret: { type: 'string', default: process.env.SCREENVEIL_TOKEN_SECRET },
      'allow-clearkey': { type: 'boolean', default: false },
      scheme: { type: 'string', default: 'cenc' },
    },
  });
  const dataDir = resolve(values.data as string);
  let options: ScreenVeilApiOptions;
  if (values.config) {
    const mod = (await import(pathToFileURL(resolve(values.config)).href)) as { default: unknown };
    const exported = typeof mod.default === 'function' ? await (mod.default as () => unknown)() : mod.default;
    options = { dataDir, ...(exported as Partial<ScreenVeilApiOptions>) } as ScreenVeilApiOptions;
    if (!options.licenses?.length) fail('config must define at least one license provider in `licenses`');
  } else if (values.dev) {
    const secret = values.secret ?? randomBytes(24).toString('base64url');
    options = {
      dataDir,
      scheme: values.scheme as EncryptionScheme,
      keySource: widevineTestKeys(),
      licenses: [
        widevineTestLicense(),
        playReadyTestLicense({ securityLevel: 3000 }),
        ...(values['allow-clearkey'] ? [clearKeyLicense()] : []),
      ],
      tokenSecret: secret,
      authorizeUpload: () => true,
      issueToken: () => 'demo-user',
    };
    console.warn(
      '\n  DEV MODE: keys come from the public Widevine UAT key server and licenses from public\n' +
        '  Widevine/PlayReady test servers. Anyone can obtain these keys. Do not use for real content.\n',
    );
  } else {
    fail('serve needs --dev (public test DRM servers) or --config <file> (your DRM provider)');
  }

  const api = createScreenVeilApi(options);
  const demo = new URL('../examples/demo/index.html', import.meta.url);
  const bundle = new URL('./screenveil.global.js', import.meta.url);
  const server = createServer((req, res) => {
    api(req, res, () => {
      const path = new URL(req.url ?? '/', 'http://x').pathname;
      const file = path === '/' ? demo : path === '/screenveil.js' ? bundle : null;
      if (!file || !existsSync(file)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      res.writeHead(200, {
        'Content-Type': path === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8',
        'Cache-Control': 'no-cache',
      });
      createReadStream(file).pipe(res);
    });
  });
  const port = Number(values.port);
  server.listen(port, values.host, () => {
    console.log(`  screenveil listening on http://${values.host}:${port}  (data: ${dataDir})`);
    if (existsSync(demo)) console.log(`  demo page:  http://${values.host}:${port}/`);
  });
}

async function protect(argv: string[]) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      dev: { type: 'boolean', default: false },
      data: { type: 'string', default: './screenveil-data' },
      out: { type: 'string' },
      id: { type: 'string' },
      kind: { type: 'string' },
      scheme: { type: 'string', default: 'cenc' },
      systems: { type: 'string', default: 'widevine,playready' },
      'license-base': { type: 'string', default: '/api' },
    },
  });
  const input = positionals[0];
  if (!input) fail('protect needs an input file');
  if (!existsSync(input)) fail(`no such file: ${input}`);
  const scheme = values.scheme as EncryptionScheme;
  if (scheme !== 'cenc' && scheme !== 'cbcs') fail('--scheme must be cenc or cbcs');
  const kind = values.kind as MediaKind | undefined;
  if (kind && kind !== 'image' && kind !== 'video') fail('--kind must be image or video');
  const dataDir = resolve(values.data as string);
  const base = (values['license-base'] as string).replace(/\/$/, '');
  const drm: Partial<Record<DrmSystem, DrmEndpoint>> = {};
  for (const s of (values.systems as string).split(',').map((x) => x.trim()) as DrmSystem[]) {
    if (!['widevine', 'playready', 'fairplay', 'clearkey'].includes(s)) fail(`unknown DRM system ${s}`);
    drm[s] = {
      licenseUrl: `${base}/license/${s}/{id}`,
      ...(s === 'fairplay' ? { certificateUrl: `${base}/license/fairplay/{id}/certificate` } : {}),
    };
  }
  const id = values.id ?? randomBytes(12).toString('base64url');
  const out = values.out ? resolve(values.out) : join(dataDir, 'assets', id);
  const result = await protectFile(input, out, {
    id,
    kind,
    scheme,
    keySource: values.dev ? widevineTestKeys() : randomKeys(),
    keyStore: fileKeyStore(join(dataDir, 'keys')),
    drm,
  });
  const m = result.manifest;
  console.log(`protected ${input}`);
  console.log(`  id        ${m.id} (${m.kind}, ${m.width}x${m.height}, ${m.duration.toFixed(1)}s, ${m.scheme})`);
  console.log(`  manifest  ${result.manifestPath}`);
  console.log(`  media     ${result.mediaPath}`);
  console.log(`  key       ${join(dataDir, 'keys', `${m.id}.json`)}  (keep private)`);
}

const [cmd, ...rest] = process.argv.slice(2);
const run = cmd === 'serve' ? serve : cmd === 'protect' ? protect : null;
if (!run) {
  console.log(HELP);
  process.exit(cmd && cmd !== 'help' && cmd !== '--help' && cmd !== '-h' ? 1 : 0);
} else {
  run(rest).catch((e: unknown) => {
    console.error(`error: ${(e as Error)?.message ?? e}`);
    process.exit(1);
  });
}
