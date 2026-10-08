import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { createScreenVeilApi } from '../src/server/api.ts';
import { clearKeyLicense } from '../src/server/license.ts';
import { issueLicenseToken } from '../src/server/tokens.ts';
import type { ScreenVeilManifest } from '../src/shared/manifest.ts';
import { ffmpeg, hasFfmpeg, tmp } from './helpers.ts';

const SECRET = 'api-test-secret-0123456789';
let server: Server;
let base = '';
let dataDir = '';
let photo = '';

before(() => {
  dataDir = tmp();
  if (hasFfmpeg) {
    photo = join(dataDir, 'photo.png');
    ffmpeg(['-f', 'lavfi', '-i', 'mandelbrot=size=640x360', '-frames:v', '1', photo]);
  }
  const api = createScreenVeilApi({
    dataDir,
    licenses: [clearKeyLicense()],
    tokenSecret: SECRET,
    authorizeUpload: (req) => req.headers['x-upload-key'] === 'let-me-in',
    onError: () => undefined,
  });
  server = createServer((req, res) => api(req, res));
  return new Promise<void>((r) =>
    server.listen(0, '127.0.0.1', () => {
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
      r();
    }),
  );
});

after(() => {
  server.closeAllConnections();
  return new Promise<void>((r) => server.close(() => r()));
});

const upload = (body: Uint8Array, filename: string, headers: Record<string, string> = { 'x-upload-key': 'let-me-in' }) =>
  fetch(`${base}/assets?filename=${filename}`, { method: 'POST', body: body as BodyInit, headers });

test('uploads require authorization', async () => {
  const res = await upload(Buffer.from('x'), 'a.png', {});
  assert.equal(res.status, 403);
});

test('rejects files ffmpeg cannot decode', { skip: !hasFfmpeg && 'ffmpeg not installed' }, async () => {
  const res = await upload(Buffer.from('definitely not an image'), 'bad.png');
  assert.equal(res.status, 422);
});

test('image upload -> manifest -> media -> license', { skip: !hasFfmpeg && 'ffmpeg not installed' }, async () => {
  const res = await upload(readFileSync(photo), 'photo.png');
  assert.equal(res.status, 201);
  const { id, manifestUrl } = (await res.json()) as { id: string; manifestUrl: string };
  assert.equal(manifestUrl, `/api/assets/${id}/manifest.json`);

  const m = (await (await fetch(`${base}/assets/${id}/manifest.json`)).json()) as ScreenVeilManifest;
  assert.equal(m.kind, 'image');
  assert.equal(m.width, 640);
  assert.equal(m.height, 360);
  assert.equal(m.drm.clearkey?.licenseUrl, `/api/license/clearkey/${id}`);
  assert.ok(!JSON.stringify(m).includes(readFileSync(join(dataDir, 'keys', `${id}.json`), 'utf8').slice(30, 50)));

  // Range requests return exactly the requested bytes.
  const seg = m.segments[0];
  const part = await fetch(`${base}/assets/${id}/media.mp4`, { headers: { Range: `bytes=${seg.start}-${seg.end - 1}` } });
  assert.equal(part.status, 206);
  const bytes = Buffer.from(await part.arrayBuffer());
  assert.equal(bytes.length, seg.end - seg.start);
  assert.equal(bytes.toString('latin1', 4, 8), 'moof');

  // License needs a token for this asset.
  const kid = Buffer.from(m.kid, 'hex').toString('base64url');
  const challenge = JSON.stringify({ kids: [kid], type: 'temporary' });
  const lic = (token?: string) =>
    fetch(`${base}/license/clearkey/${id}`, {
      method: 'POST',
      body: challenge,
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  assert.equal((await lic()).status, 401);
  assert.equal((await lic(issueLicenseToken(SECRET, { contentId: 'other' }))).status, 401);
  const ok = await lic(issueLicenseToken(SECRET, { contentId: id }));
  assert.equal(ok.status, 200);
  const body = (await ok.json()) as { keys: Array<{ kid: string; k: string }> };
  const stored = JSON.parse(readFileSync(join(dataDir, 'keys', `${id}.json`), 'utf8'));
  assert.equal(body.keys[0].kid, kid);
  assert.equal(Buffer.from(body.keys[0].k, 'base64url').toString('hex'), stored.key);
});

test('never serves key files or path traversal', async () => {
  for (const p of ['/assets/..%2Fkeys/manifest.json', '/assets/../keys/x.json', '/license/clearkey/..%2F..']) {
    const res = await fetch(base + p, { method: p.startsWith('/license') ? 'POST' : 'GET' });
    assert.ok([400, 404].includes(res.status), `${p} -> ${res.status}`);
  }
});

test('unknown DRM system and disabled token endpoint', async () => {
  assert.equal((await fetch(`${base}/license/widevine/abc`, { method: 'POST' })).status, 404);
  assert.equal((await fetch(`${base}/assets/abc/token`, { method: 'POST' })).status, 404);
});
