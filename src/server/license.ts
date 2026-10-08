import type { IncomingHttpHeaders } from 'node:http';
import type { DrmSystem, EncryptionScheme } from '../shared/manifest.ts';
import { type ContentKey, WIDEVINE_UAT_LICENSE_PROXY } from './keys.ts';

export interface LicenseContext {
  /** Content id. */
  id: string;
  key: ContentKey;
  scheme: EncryptionScheme;
  /** Headers of the incoming browser request. */
  headers: IncomingHttpHeaders;
  /** Claims from a verified license token, if tokens are enabled. */
  claims?: Record<string, unknown>;
}

export interface LicenseResponse {
  body: Uint8Array;
  contentType?: string;
}

/** Turns a CDM license challenge into a license for one DRM system. */
export interface LicenseProvider {
  readonly system: DrmSystem;
  /** True for providers that must never be used in production (test servers, Clear Key). */
  readonly insecure?: boolean;
  acquire(challenge: Buffer, ctx: LicenseContext): Promise<LicenseResponse>;
  /** FairPlay only: the application certificate. */
  certificate?(ctx: Omit<LicenseContext, 'key' | 'scheme'>): Promise<LicenseResponse>;
}

export class LicenseError extends Error {
  readonly status: number;
  constructor(message: string, status = 403) {
    super(message);
    this.status = status;
  }
}

/**
 * W3C Clear Key. The browser decrypts in software and the OS does NOT protect the
 * output, so screenshots are NOT blocked. Useful for local development only.
 */
export function clearKeyLicense(): LicenseProvider {
  return {
    system: 'clearkey',
    insecure: true,
    async acquire(challenge, ctx) {
      let req: { kids?: string[]; type?: string };
      try {
        req = JSON.parse(challenge.toString('utf8'));
      } catch {
        throw new LicenseError('Malformed Clear Key request', 400);
      }
      const kid = Buffer.from(ctx.key.kid, 'hex').toString('base64url');
      if (!req.kids?.includes(kid)) throw new LicenseError('Requested key id does not belong to this asset');
      const body = JSON.stringify({
        keys: [{ kty: 'oct', kid, k: Buffer.from(ctx.key.key, 'hex').toString('base64url') }],
        type: req.type ?? 'temporary',
      });
      return { body: Buffer.from(body), contentType: 'application/json' };
    },
  };
}

async function post(url: string, body: Uint8Array, headers: Record<string, string>): Promise<LicenseResponse> {
  const res = await fetch(url, { method: 'POST', body: body as BodyInit, headers });
  const out = Buffer.from(await res.arrayBuffer());
  if (!res.ok) throw new LicenseError(`Upstream license server returned HTTP ${res.status}: ${out.toString('utf8', 0, 300)}`, 502);
  return { body: out, contentType: res.headers.get('content-type') ?? 'application/octet-stream' };
}

export const PLAYREADY_TEST_SERVER = 'https://test.playready.microsoft.com/service/rightsmanager.asmx';

/**
 * Microsoft's public PlayReady test server. It issues licenses for any key you send it,
 * so your content key travels to Microsoft over HTTPS. DEVELOPMENT ONLY.
 * securityLevel 3000 = hardware DRM: video is black in screenshots and recordings on Windows.
 */
export function playReadyTestLicense(opts: { securityLevel?: 150 | 2000 | 3000; url?: string } = {}): LicenseProvider {
  const sl = opts.securityLevel ?? 3000;
  return {
    system: 'playready',
    insecure: true,
    async acquire(challenge, ctx) {
      const ck = Buffer.from(ctx.key.key, 'hex').toString('base64');
      const ckt = ctx.scheme === 'cbcs' ? 'aes128bitcbc' : 'aes128bitctr';
      const url = `${opts.url ?? PLAYREADY_TEST_SERVER}?cfg=(kid:header,sl:${sl},ckt:${ckt},contentkey:${ck})`;
      return post(url, challenge, {
        'Content-Type': 'text/xml; charset=utf-8',
        SOAPAction: '"http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"',
      });
    },
  };
}

/**
 * Google's public Widevine UAT license proxy for the `widevine_test` provider. Only works
 * for content packaged with `widevineTestKeys()`. DEVELOPMENT ONLY.
 */
export function widevineTestLicense(opts: { url?: string } = {}): LicenseProvider {
  return {
    system: 'widevine',
    insecure: true,
    acquire(challenge) {
      return post(opts.url ?? WIDEVINE_UAT_LICENSE_PROXY, challenge, { 'Content-Type': 'application/octet-stream' });
    },
  };
}

export interface ProxyOptions {
  system: DrmSystem;
  /** Upstream license URL, e.g. your EZDRM / Axinom / DRMtoday / PallyCon endpoint. */
  url: string | ((ctx: LicenseContext) => string | Promise<string>);
  /**
   * Extra headers for the upstream request. This is where you put the provider's
   * entitlement token (many accept "bring your own key" tokens that embed ctx.key).
   */
  headers?: (ctx: LicenseContext) => Record<string, string> | Promise<Record<string, string>>;
  /** FairPlay application certificate URL. */
  certificateUrl?: string;
}

/** Forward challenges to a commercial DRM license service. Use this in production. */
export function licenseProxy(opts: ProxyOptions): LicenseProvider {
  const defaultType = opts.system === 'playready' ? 'text/xml; charset=utf-8' : 'application/octet-stream';
  return {
    system: opts.system,
    async acquire(challenge, ctx) {
      const url = typeof opts.url === 'function' ? await opts.url(ctx) : opts.url;
      const extra = opts.headers ? await opts.headers(ctx) : {};
      const headers: Record<string, string> = { 'Content-Type': defaultType, ...extra };
      if (opts.system === 'playready' && !Object.keys(headers).some((h) => h.toLowerCase() === 'soapaction')) {
        headers.SOAPAction = '"http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"';
      }
      return post(url, challenge, headers);
    },
    ...(opts.certificateUrl
      ? {
          async certificate() {
            const res = await fetch(opts.certificateUrl as string);
            if (!res.ok) throw new LicenseError(`Certificate fetch failed: HTTP ${res.status}`, 502);
            return { body: Buffer.from(await res.arrayBuffer()), contentType: 'application/octet-stream' };
          },
        }
      : {}),
  };
}
