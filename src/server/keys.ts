import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface ContentKey {
  /** 16-byte key ID, hex. */
  kid: string;
  /** 16-byte AES key, hex. Secret. */
  key: string;
  /** Encryption scheme the key was used with (stored by the packager). */
  scheme?: 'cenc' | 'cbcs';
  /** Extra pssh boxes the key source wants embedded (e.g. Widevine content-id pssh), base64. */
  pssh?: string[];
}

/** Where content keys come from. */
export interface KeySource {
  readonly name: string;
  createKey(contentId: string): Promise<ContentKey>;
}

/** Persists keys so license servers can find them later. */
export interface KeyStore {
  get(contentId: string): Promise<ContentKey | undefined>;
  put(contentId: string, key: ContentKey): Promise<void>;
}

/** Random keys generated locally. Use this in production with your own license service. */
export function randomKeys(): KeySource {
  return {
    name: 'random',
    async createKey() {
      return { kid: randomBytes(16).toString('hex'), key: randomBytes(16).toString('hex') };
    },
  };
}

// Public signing credentials of Google's "widevine_test" provider, published in the
// Shaka Packager documentation. They only work against Widevine's UAT (test) servers.
const WIDEVINE_TEST_SIGNING_KEY = '1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9';
const WIDEVINE_TEST_SIGNING_IV = 'd58ce954203b7c9a9a9d467f59839249';
export const WIDEVINE_UAT_KEY_SERVER = 'https://license.uat.widevine.com/cenc/getcontentkey/widevine_test';
export const WIDEVINE_UAT_LICENSE_PROXY = 'https://proxy.uat.widevine.com/proxy?provider=widevine_test';

/**
 * Keys issued by Google's public Widevine UAT key server for the `widevine_test` provider.
 * DEVELOPMENT ONLY: anyone can request the same keys for the same content id.
 * Content packaged this way plays in Chrome via the public UAT license proxy and in
 * Edge via the PlayReady test server, which makes it ideal for demos.
 */
export function widevineTestKeys(opts: { keyServer?: string; fetchImpl?: typeof fetch } = {}): KeySource {
  const server = opts.keyServer ?? WIDEVINE_UAT_KEY_SERVER;
  const doFetch = opts.fetchImpl ?? fetch;
  return {
    name: 'widevine-test',
    async createKey(contentId: string) {
      const request = JSON.stringify({
        content_id: Buffer.from(contentId, 'utf8').toString('base64'),
        tracks: [{ type: 'HD' }],
        drm_types: ['WIDEVINE'],
        policy: '',
      });
      const hash = createHash('sha1').update(request).digest();
      const c = createCipheriv('aes-256-cbc', Buffer.from(WIDEVINE_TEST_SIGNING_KEY, 'hex'), Buffer.from(WIDEVINE_TEST_SIGNING_IV, 'hex'));
      const signature = Buffer.concat([c.update(hash), c.final()]).toString('base64');
      const res = await doFetch(server, {
        method: 'POST',
        body: JSON.stringify({ request: Buffer.from(request).toString('base64'), signature, signer: 'widevine_test' }),
      });
      if (!res.ok) throw new Error(`Widevine UAT key server returned HTTP ${res.status}`);
      const outer = (await res.json()) as { response: string };
      const inner = JSON.parse(Buffer.from(outer.response, 'base64').toString('utf8')) as {
        status: string;
        tracks: Array<{ type: string; key_id: string; key: string; pssh: Array<{ drm_type: string; boxes: string }> }>;
      };
      if (inner.status !== 'OK') throw new Error(`Widevine UAT key server status: ${inner.status}`);
      const t = inner.tracks.find((x) => x.type === 'HD') ?? inner.tracks[0];
      return {
        kid: Buffer.from(t.key_id, 'base64').toString('hex'),
        key: Buffer.from(t.key, 'base64').toString('hex'),
        pssh: t.pssh.filter((p) => p.drm_type === 'WIDEVINE').map((p) => p.boxes),
      };
    },
  };
}

export function memoryKeyStore(): KeyStore {
  const m = new Map<string, ContentKey>();
  return {
    async get(id) {
      return m.get(id);
    },
    async put(id, key) {
      m.set(id, key);
    },
  };
}

const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

export function assertSafeId(id: string): void {
  if (!SAFE_ID.test(id)) throw new Error(`Invalid content id "${id}"`);
}

/** One JSON file per key in a directory. Keep this directory private. */
export function fileKeyStore(dir: string): KeyStore {
  return {
    async get(id) {
      assertSafeId(id);
      try {
        return JSON.parse(await readFile(join(dir, `${id}.json`), 'utf8')) as ContentKey;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
        throw e;
      }
    },
    async put(id, key) {
      assertSafeId(id);
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, `${id}.json`), JSON.stringify(key), { mode: 0o600 });
    },
  };
}
