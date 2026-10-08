import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clearKeyPssh, playReadyKid, playReadyObject, playReadyPssh, SYSTEM_IDS, widevinePssh } from '../src/server/pssh.ts';

const KID = '0123456789abcdef0123456789abcdef';

test('PlayReady KIDs use little-endian GUID byte order', () => {
  assert.equal(playReadyKid(KID).toString('hex'), '67452301ab89efcd0123456789abcdef');
});

test('Clear Key pssh is version 1 with the KID list', () => {
  const b = clearKeyPssh([KID]);
  assert.equal(b.toString('latin1', 4, 8), 'pssh');
  assert.equal(b[8], 1);
  assert.equal(b.subarray(12, 28).toString('hex'), SYSTEM_IDS.common);
  assert.equal(b.readUInt32BE(28), 1);
  assert.equal(b.subarray(32, 48).toString('hex'), KID);
  assert.equal(b.readUInt32BE(48), 0);
  assert.equal(b.readUInt32BE(0), b.length);
});

test('Widevine pssh carries key id and protection scheme', () => {
  const b = widevinePssh([KID], { contentId: 'abc', scheme: 'cbcs' });
  assert.equal(b.subarray(12, 28).toString('hex'), SYSTEM_IDS.widevine);
  const data = b.subarray(32);
  assert.equal(b.readUInt32BE(28), data.length);
  assert.equal(data[0], 0x12); // field 2, bytes
  assert.equal(data[1], 16);
  assert.equal(data.subarray(2, 18).toString('hex'), KID);
  assert.ok(data.includes(Buffer.from('abc')));
});

test('PlayReady object has a valid length prefix and WRMHEADER', () => {
  const pro = playReadyObject([KID], { licenseUrl: 'https://x/?a=1&b=2' });
  assert.equal(pro.readUInt32LE(0), pro.length);
  assert.equal(pro.readUInt16LE(4), 1);
  const xml = pro.subarray(10).toString('utf16le');
  assert.match(xml, /^<WRMHEADER /);
  assert.match(xml, /ALGID="AESCTR"/);
  assert.match(xml, new RegExp(playReadyKid(KID).toString('base64').replace(/[+/]/g, '\$&')));
  assert.match(xml, /a=1&amp;b=2/);
  assert.match(playReadyObject([KID], { scheme: 'cbcs' }).subarray(10).toString('utf16le'), /version="4\.3\.0\.0".*AESCBC/);
  assert.equal(playReadyPssh([KID]).subarray(12, 28).toString('hex'), SYSTEM_IDS.playready);
});
