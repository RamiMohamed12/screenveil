import { test } from 'node:test';
import assert from 'node:assert/strict';
import { issueLicenseToken, verifyLicenseToken } from '../src/server/tokens.ts';

const SECRET = 'a-test-secret-that-is-long-enough';

test('valid token verifies for its content id only', () => {
  const t = issueLicenseToken(SECRET, { contentId: 'cat', subject: 'u1' });
  assert.equal(verifyLicenseToken(SECRET, t, 'cat')?.sub, 'u1');
  assert.equal(verifyLicenseToken(SECRET, t, 'dog'), null);
});

test('tampered, foreign and expired tokens are rejected', () => {
  const t = issueLicenseToken(SECRET, { contentId: 'cat' });
  const [p, s] = t.split('.');
  const forged = Buffer.from(JSON.stringify({ cid: 'dog', exp: 9e9 })).toString('base64url');
  assert.equal(verifyLicenseToken(SECRET, `${forged}.${s}`), null);
  assert.equal(verifyLicenseToken('another-secret-that-is-long-enough', t), null);
  assert.equal(verifyLicenseToken(SECRET, `${p}.${s}x`), null);
  assert.equal(verifyLicenseToken(SECRET, 'garbage'), null);
  const expired = issueLicenseToken(SECRET, { contentId: 'cat', ttlSeconds: -1 });
  assert.equal(verifyLicenseToken(SECRET, expired), null);
});

test('short secrets are refused', () => {
  assert.throws(() => issueLicenseToken('short', { contentId: 'x' }));
});
