import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Short-lived, HMAC-signed license tokens. Your backend issues one after it has decided
 * that the current user may view an asset; the license endpoint only answers requests
 * that carry a valid token for that asset.
 */
export interface LicenseTokenClaims {
  /** Content id the token unlocks. */
  cid: string;
  /** Your user id (optional, shows up in license callbacks and logs). */
  sub?: string;
  /** Expiry, seconds since epoch. */
  exp: number;
  [extra: string]: unknown;
}

export function issueLicenseToken(
  secret: string,
  opts: { contentId: string; subject?: string; ttlSeconds?: number; extra?: Record<string, unknown> },
): string {
  if (!secret || secret.length < 16) throw new Error('Token secret must be at least 16 characters');
  const claims: LicenseTokenClaims = {
    ...opts.extra,
    cid: opts.contentId,
    ...(opts.subject ? { sub: opts.subject } : {}),
    exp: Math.floor(Date.now() / 1000) + (opts.ttlSeconds ?? 300),
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${payload}.${sign(secret, payload)}`;
}

/** Returns the claims if the token is authentic, unexpired and (optionally) for `contentId`. */
export function verifyLicenseToken(secret: string, token: string, contentId?: string): LicenseTokenClaims | null {
  const [payload, sig, ...rest] = token.split('.');
  if (!payload || !sig || rest.length) return null;
  const expected = Buffer.from(sign(secret, payload));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  let claims: LicenseTokenClaims;
  try {
    claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (typeof claims.exp !== 'number' || claims.exp < Date.now() / 1000) return null;
  if (contentId !== undefined && claims.cid !== contentId) return null;
  return claims;
}

function sign(secret: string, payload: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}
