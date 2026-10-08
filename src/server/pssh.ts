import { fullBox, u32 } from './mp4/boxes.ts';

/** DRM system IDs as registered with DASH-IF. */
export const SYSTEM_IDS = {
  /** W3C "common" system, used by Clear Key. */
  common: '1077efecc0b24d02ace33c1e52e2fb4b',
  widevine: 'edef8ba979d64acea3c827dcd51d21ed',
  playready: '9a04f07998404286ab92e65be0885f95',
} as const;

export type Scheme = 'cenc' | 'cbcs';

function hex(h: string): Buffer {
  const clean = h.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(clean)) throw new Error(`Expected a 16-byte hex id, got "${h}"`);
  return Buffer.from(clean, 'hex');
}

/** pssh version 1 (key IDs in the box) with optional system-specific data. */
export function psshBox(systemId: string, kids: string[], data: Uint8Array = new Uint8Array(0), version: 0 | 1 = 1): Buffer {
  const parts: Uint8Array[] = [hex(systemId)];
  if (version === 1) {
    parts.push(u32(kids.length), ...kids.map(hex));
  }
  parts.push(u32(data.length), data);
  return fullBox('pssh', version, 0, ...parts);
}

export function clearKeyPssh(kids: string[]): Buffer {
  return psshBox(SYSTEM_IDS.common, kids);
}

function varint(n: number): Buffer {
  const out: number[] = [];
  while (n > 0x7f) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return Buffer.from(out);
}

function pbBytes(field: number, value: Uint8Array): Buffer {
  return Buffer.concat([varint((field << 3) | 2), varint(value.length), value]);
}

function pbVarint(field: number, value: number): Buffer {
  return Buffer.concat([varint(field << 3), varint(value)]);
}

/** Widevine PSSH data (WidevinePsshData protobuf). */
export function widevinePsshData(kids: string[], opts: { contentId?: string; provider?: string; scheme?: Scheme } = {}): Buffer {
  const parts: Buffer[] = kids.map((k) => pbBytes(2, hex(k)));
  if (opts.provider) parts.push(pbBytes(3, Buffer.from(opts.provider, 'utf8')));
  if (opts.contentId) parts.push(pbBytes(4, Buffer.from(opts.contentId, 'utf8')));
  const scheme = opts.scheme ?? 'cenc';
  parts.push(pbVarint(9, Buffer.from(scheme, 'latin1').readUInt32BE(0)));
  return Buffer.concat(parts);
}

export function widevinePssh(kids: string[], opts: { contentId?: string; provider?: string; scheme?: Scheme } = {}): Buffer {
  return psshBox(SYSTEM_IDS.widevine, kids, widevinePsshData(kids, opts), 0);
}

/** PlayReady stores KIDs as little-endian GUIDs. */
export function playReadyKid(kidHex: string): Buffer {
  const b = hex(kidHex);
  return Buffer.concat([
    Buffer.from(b.subarray(0, 4)).reverse(),
    Buffer.from(b.subarray(4, 6)).reverse(),
    Buffer.from(b.subarray(6, 8)).reverse(),
    b.subarray(8),
  ]);
}

/** PlayReady Header Object (PRO) carrying a WRMHEADER. */
export function playReadyObject(kids: string[], opts: { licenseUrl?: string; scheme?: Scheme } = {}): Buffer {
  const scheme = opts.scheme ?? 'cenc';
  const alg = scheme === 'cbcs' ? 'AESCBC' : 'AESCTR';
  const kidXml = kids
    .map((k) => `<KID ALGID="${alg}" VALUE="${playReadyKid(k).toString('base64')}"></KID>`)
    .join('');
  const la = opts.licenseUrl ? `<LA_URL>${escapeXml(opts.licenseUrl)}</LA_URL>` : '';
  const version = scheme === 'cbcs' ? '4.3.0.0' : '4.2.0.0';
  const xml =
    `<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="${version}">` +
    `<DATA><PROTECTINFO><KIDS>${kidXml}</KIDS></PROTECTINFO>${la}</DATA></WRMHEADER>`;
  const record = Buffer.from(xml, 'utf16le');
  const pro = Buffer.alloc(10 + record.length);
  pro.writeUInt32LE(pro.length, 0);
  pro.writeUInt16LE(1, 4); // record count
  pro.writeUInt16LE(1, 6); // type 1 = Rights Management Header
  pro.writeUInt16LE(record.length, 8);
  record.copy(pro, 10);
  return pro;
}

export function playReadyPssh(kids: string[], opts: { licenseUrl?: string; scheme?: Scheme } = {}): Buffer {
  return psshBox(SYSTEM_IDS.playready, kids, playReadyObject(kids, opts), 1);
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
