/**
 * Minimal ISO-BMFF (MP4) box reader/writer. Only what the CENC packager needs.
 */

export interface Box {
  type: string;
  /** Offset of the box header inside the buffer it was parsed from. */
  start: number;
  /** Total size including header. */
  size: number;
  /** Header size (8, or 16 for 64-bit sizes). */
  headerSize: number;
  /** Full box bytes, header included (a view, not a copy). */
  data: Buffer;
}

/** Boxes whose payload is only child boxes. */
export const CONTAINER_BOXES = new Set([
  'moov', 'trak', 'mdia', 'minf', 'stbl', 'mvex', 'moof', 'traf', 'edts', 'dinf', 'sinf', 'schi', 'udta',
]);

export function readBoxes(buf: Buffer, start = 0, end = buf.length): Box[] {
  const boxes: Box[] = [];
  let off = start;
  while (off + 8 <= end) {
    let size = buf.readUInt32BE(off);
    const type = buf.toString('latin1', off + 4, off + 8);
    let headerSize = 8;
    if (size === 1) {
      const big = buf.readBigUInt64BE(off + 8);
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`Box ${type} too large`);
      size = Number(big);
      headerSize = 16;
    } else if (size === 0) {
      size = end - off;
    }
    if (size < headerSize || off + size > end) {
      throw new Error(`Malformed MP4: box "${type}" at ${off} has invalid size ${size}`);
    }
    boxes.push({ type, start: off, size, headerSize, data: buf.subarray(off, off + size) });
    off += size;
  }
  return boxes;
}

export function children(box: Box, payloadOffset = box.headerSize): Box[] {
  return readBoxes(box.data, payloadOffset, box.size);
}

export function findChild(box: Box, type: string, payloadOffset?: number): Box | undefined {
  return children(box, payloadOffset).find((b) => b.type === type);
}

/** Walk a path of container boxes, e.g. ['trak', 'mdia', 'minf']. */
export function findPath(box: Box, path: string[]): Box | undefined {
  let cur: Box | undefined = box;
  for (const t of path) {
    if (!cur) return undefined;
    cur = findChild(cur, t);
  }
  return cur;
}

export function box(type: string, ...payload: Uint8Array[]): Buffer {
  const body = Buffer.concat(payload);
  const header = Buffer.alloc(8);
  header.writeUInt32BE(8 + body.length, 0);
  header.write(type, 4, 'latin1');
  return Buffer.concat([header, body]);
}

export function fullBox(type: string, version: number, flags: number, ...payload: Uint8Array[]): Buffer {
  const vf = Buffer.alloc(4);
  vf.writeUInt32BE(((version & 0xff) << 24) | (flags & 0xffffff), 0);
  return box(type, vf, ...payload);
}

/** Rebuild a container box from a header-less list of child buffers, keeping any non-box prefix. */
export function rebuild(type: string, prefix: Uint8Array, kids: Uint8Array[]): Buffer {
  return box(type, prefix, ...kids);
}

export function u8(n: number): Buffer {
  return Buffer.from([n & 0xff]);
}
export function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}
export function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

export function fullBoxHeader(b: Box): { version: number; flags: number } {
  const v = b.data.readUInt32BE(b.headerSize);
  return { version: v >>> 24, flags: v & 0xffffff };
}
