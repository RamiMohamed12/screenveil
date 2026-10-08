/**
 * Common Encryption (ISO/IEC 23001-7) for fragmented MP4 with H.264 video.
 *
 * Supports the two schemes browsers care about:
 *  - 'cenc': AES-128-CTR, 8-byte per-sample IVs (Chrome, Edge, Firefox, Android)
 *  - 'cbcs': AES-128-CBC, 1:9 pattern, constant IV (Safari/FairPlay, plus all of the above on recent versions)
 *
 * Only video tracks are encrypted; audio passes through in the clear.
 */
import { createCipheriv, randomBytes } from 'node:crypto';
import { type Box, box, children, findChild, fullBox, fullBoxHeader, readBoxes, u16, u32, u8 } from './boxes.ts';
import { AvcParamSets, parseAvcC, sliceHeaderSize } from './avc.ts';
import type { Scheme } from '../pssh.ts';

export interface EncryptOptions {
  /** 16-byte key id, hex. */
  kid: string;
  /** 16-byte content key, hex. */
  key: string;
  scheme?: Scheme;
  /** Complete pssh boxes to embed in the init segment. */
  pssh?: Uint8Array[];
  /** cbcs constant IV (16 bytes hex) or cenc IV seed (8 bytes hex). Random if omitted. */
  iv?: string;
}

export interface Fragment {
  /** Byte offset of the moof box in the output. */
  offset: number;
  /** Size of moof + mdat (and anything up to the next moof). */
  size: number;
  /** Presentation start time in seconds (from the first track's tfdt). */
  time: number;
  /** Duration in seconds. */
  duration: number;
}

export interface EncryptResult {
  data: Buffer;
  /** Size of the init segment (ftyp + moov) at the start of data. */
  initSize: number;
  fragments: Fragment[];
  /** Total duration in seconds. */
  duration: number;
  /** RFC 6381 codec strings of the tracks, e.g. ["avc1.640028", "mp4a.40.2"]. */
  codecs: string[];
  encryptedTracks: number[];
  width: number;
  height: number;
  samplesEncrypted: number;
  /** Slices whose header could not be parsed (encrypted with a conservative clear prefix instead). */
  sliceHeaderFallbacks: number;
}

interface TrackState {
  id: number;
  encrypt: boolean;
  lengthSize: number;
  params: AvcParamSets;
  defaultSampleSize: number;
  defaultSampleDuration: number;
  timescale: number;
  /** cenc: next per-sample IV (8 bytes). */
  ivCounter: bigint;
}

interface Subsample {
  clear: number;
  protected: number;
}

const CBCS_CRYPT = 1;
const CBCS_SKIP = 9;

function hexBytes(h: string, len: number, name: string): Buffer {
  const clean = h.replace(/-/g, '');
  if (!new RegExp(`^[0-9a-fA-F]{${len * 2}}$`).test(clean)) throw new Error(`${name} must be ${len} bytes of hex`);
  return Buffer.from(clean, 'hex');
}

function handlerType(trak: Box): string {
  const mdia = findChild(trak, 'mdia');
  const hdlr = mdia && findChild(mdia, 'hdlr');
  return hdlr ? hdlr.data.toString('latin1', hdlr.headerSize + 8, hdlr.headerSize + 12) : '';
}

function trackId(trak: Box): number {
  const tkhd = findChild(trak, 'tkhd');
  if (!tkhd) throw new Error('trak without tkhd');
  const { version } = fullBoxHeader(tkhd);
  return tkhd.data.readUInt32BE(tkhd.headerSize + 4 + (version === 1 ? 16 : 8));
}

function mediaTimescale(trak: Box): number {
  const mdia = findChild(trak, 'mdia');
  const mdhd = mdia && findChild(mdia, 'mdhd');
  if (!mdhd) throw new Error('trak without mdhd');
  const { version } = fullBoxHeader(mdhd);
  return mdhd.data.readUInt32BE(mdhd.headerSize + 4 + (version === 1 ? 16 : 8));
}

/** Visual sample entries: 8-byte header + 78 bytes of fields, then child boxes. */
const VISUAL_ENTRY_FIELDS = 78;
/** Audio sample entries: 8-byte header + 28 bytes of fields (v0). */
const AUDIO_ENTRY_FIELDS = 28;

function codecString(entry: Box, fields: number): string {
  const fourcc = entry.type;
  const kids = readBoxes(entry.data, entry.headerSize + fields, entry.size);
  if (fourcc === 'avc1' || fourcc === 'avc3') {
    const avcC = kids.find((b) => b.type === 'avcC');
    if (!avcC) return fourcc;
    const p = avcC.data.subarray(avcC.headerSize);
    return `${fourcc}.${[p[1], p[2], p[3]].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
  }
  if (fourcc === 'mp4a') return 'mp4a.40.2';
  return fourcc;
}

/** Rebuild a container box, transforming its direct children. */
function mapContainer(b: Box, fn: (child: Box) => Uint8Array | Uint8Array[] | null, prefixLen = 0): Buffer {
  const prefix = b.data.subarray(b.headerSize, b.headerSize + prefixLen);
  const out: Uint8Array[] = [];
  for (const c of children(b, b.headerSize + prefixLen)) {
    const r = fn(c);
    if (r === null) continue;
    if (Array.isArray(r)) out.push(...r);
    else out.push(r);
  }
  return box(b.type, prefix, ...out);
}

function makeSinf(originalFormat: string, scheme: Scheme, kid: Buffer, constantIv: Buffer | null): Buffer {
  const frma = box('frma', Buffer.from(originalFormat, 'latin1'));
  const schm = fullBox('schm', 0, 0, Buffer.from(scheme, 'latin1'), u32(0x00010000));
  const tenc =
    scheme === 'cbcs'
      ? fullBox('tenc', 1, 0, u8(0), u8((CBCS_CRYPT << 4) | CBCS_SKIP), u8(1), u8(0), kid, u8(16), constantIv as Buffer)
      : fullBox('tenc', 0, 0, u8(0), u8(0), u8(1), u8(8), kid);
  return box('sinf', frma, schm, box('schi', tenc));
}

/** Encrypt one H.264 sample in place and return its subsample map. */
function encryptVideoSample(
  sample: Buffer,
  track: TrackState,
  scheme: Scheme,
  key: Buffer,
  iv: Buffer,
  stats: { fallbacks: number },
): Subsample[] {
  const ls = track.lengthSize;
  const subs: Subsample[] = [];
  let pendingClear = 0;
  const ranges: Array<[number, number]> = []; // protected [start, end) inside sample

  const pushEntry = (clear: number, prot: number) => {
    while (clear > 0xffff) {
      subs.push({ clear: 0xffff, protected: 0 });
      clear -= 0xffff;
    }
    subs.push({ clear, protected: prot });
  };

  let off = 0;
  while (off + ls <= sample.length) {
    let naluSize = 0;
    for (let i = 0; i < ls; i++) naluSize = naluSize * 256 + sample[off + i];
    const nalStart = off + ls;
    const nalEnd = nalStart + naluSize;
    if (naluSize === 0 || nalEnd > sample.length) throw new Error('Corrupt H.264 sample: NAL length out of range');
    const nal = sample.subarray(nalStart, nalEnd);
    const type = nal[0] & 0x1f;
    if (type === 7 || type === 8) track.params.add(nal);

    let headerBytes = naluSize; // default: whole NAL clear
    if (type >= 1 && type <= 5) {
      try {
        headerBytes = sliceHeaderSize(nal, track.params);
      } catch {
        stats.fallbacks++;
        headerBytes = Math.min(naluSize, 32);
      }
    }
    let clear = ls + headerBytes;
    let prot = naluSize - headerBytes;
    if (scheme === 'cenc') {
      const extra = prot % 16;
      clear += extra;
      prot -= extra;
    } else if (prot < 16) {
      clear += prot;
      prot = 0;
    }
    if (prot > 0) {
      pushEntry(pendingClear + clear, prot);
      ranges.push([off + clear, nalEnd]);
      pendingClear = 0;
    } else {
      pendingClear += clear;
    }
    off = nalEnd;
  }
  if (off !== sample.length) throw new Error('Corrupt H.264 sample: trailing bytes');
  if (pendingClear > 0 || subs.length === 0) pushEntry(pendingClear, 0);

  if (scheme === 'cenc') {
    const ctr = createCipheriv('aes-128-ctr', key, Buffer.concat([iv, Buffer.alloc(8)]));
    for (const [s, e] of ranges) {
      const enc = ctr.update(sample.subarray(s, e));
      enc.copy(sample, s);
    }
  } else {
    for (const [s, e] of ranges) {
      // cbcs: IV resets per subsample, 1 encrypted block then 9 clear blocks.
      const cbc = createCipheriv('aes-128-cbc', key, iv).setAutoPadding(false);
      for (let p = s; p + 16 <= e; p += 16 * (CBCS_CRYPT + CBCS_SKIP)) {
        const enc = cbc.update(sample.subarray(p, p + 16));
        enc.copy(sample, p);
      }
    }
  }
  return subs;
}

interface TrunInfo {
  box: Box;
  version: number;
  flags: number;
  sampleCount: number;
  dataOffset: number;
  sizes: number[];
  durations: number[];
}

function parseTrun(b: Box, defaultSize: number, defaultDuration: number): TrunInfo {
  const { version, flags } = fullBoxHeader(b);
  const d = b.data;
  let p = b.headerSize + 4;
  const sampleCount = d.readUInt32BE(p);
  p += 4;
  if (!(flags & 0x1)) throw new Error('trun without data_offset is not supported');
  const dataOffset = d.readInt32BE(p);
  p += 4;
  if (flags & 0x4) p += 4;
  const sizes: number[] = [];
  const durations: number[] = [];
  for (let i = 0; i < sampleCount; i++) {
    if (flags & 0x100) {
      durations.push(d.readUInt32BE(p));
      p += 4;
    } else {
      durations.push(defaultDuration);
    }
    if (flags & 0x200) {
      sizes.push(d.readUInt32BE(p));
      p += 4;
    } else {
      sizes.push(defaultSize);
    }
    if (flags & 0x400) p += 4;
    if (flags & 0x800) p += 4;
  }
  return { box: b, version, flags, sampleCount, dataOffset, sizes, durations };
}

function patchTrunOffset(t: TrunInfo, delta: number): Buffer {
  const copy = Buffer.from(t.box.data);
  copy.writeInt32BE(t.dataOffset + delta, t.box.headerSize + 8);
  return copy;
}

/**
 * Encrypt a complete fragmented MP4 (init segment followed by moof/mdat pairs).
 */
export function encryptFragmentedMp4(input: Uint8Array, opts: EncryptOptions): EncryptResult {
  const scheme: Scheme = opts.scheme ?? 'cenc';
  if (scheme !== 'cenc' && scheme !== 'cbcs') throw new Error(`Unsupported scheme ${scheme}`);
  const kid = hexBytes(opts.kid, 16, 'kid');
  const key = hexBytes(opts.key, 16, 'key');
  const constantIv = scheme === 'cbcs' ? (opts.iv ? hexBytes(opts.iv, 16, 'iv') : randomBytes(16)) : null;
  const ivSeed = scheme === 'cenc' ? (opts.iv ? hexBytes(opts.iv, 8, 'iv') : randomBytes(8)) : null;

  // Work on a private copy so the caller's buffer is untouched; mdat payloads are encrypted in place.
  const buf = Buffer.from(input);
  const top = readBoxes(buf);
  const moov = top.find((b) => b.type === 'moov');
  if (!moov) throw new Error('No moov box: input is not an MP4 init segment');
  if (!top.some((b) => b.type === 'moof')) {
    throw new Error('Input is not fragmented. Re-mux with: -movflags frag_keyframe+empty_moov+default_base_moof');
  }

  const tracks = new Map<number, TrackState>();
  let width = 0;
  let height = 0;
  const codecs: string[] = [];

  // trex defaults
  const mvex = findChild(moov, 'mvex');
  const trexDefaults = new Map<number, { duration: number; size: number }>();
  if (mvex) {
    for (const t of children(mvex)) {
      if (t.type !== 'trex') continue;
      const o = t.headerSize;
      trexDefaults.set(t.data.readUInt32BE(o + 4), { duration: t.data.readUInt32BE(o + 12), size: t.data.readUInt32BE(o + 16) });
    }
  }

  const newMoov = mapContainer(moov, (c) => {
    if (c.type === 'pssh') return null; // replaced below
    if (c.type !== 'trak') return c.data;
    const id = trackId(c);
    const isVideo = handlerType(c) === 'vide';
    if (isVideo && width === 0) {
      const tkhd = findChild(c, 'tkhd') as Box;
      width = tkhd.data.readUInt32BE(tkhd.size - 8) >>> 16;
      height = tkhd.data.readUInt32BE(tkhd.size - 4) >>> 16;
    }
    const state: TrackState = {
      id,
      encrypt: isVideo,
      lengthSize: 4,
      params: new AvcParamSets(),
      defaultSampleSize: trexDefaults.get(id)?.size ?? 0,
      defaultSampleDuration: trexDefaults.get(id)?.duration ?? 0,
      timescale: mediaTimescale(c),
      ivCounter: ivSeed ? ivSeed.readBigUInt64BE(0) : 0n,
    };
    tracks.set(id, state);

    const rewriteStsd = (stsd: Box): Buffer => {
      const prefix = stsd.data.subarray(stsd.headerSize, stsd.headerSize + 8);
      const entries = readBoxes(stsd.data, stsd.headerSize + 8, stsd.size);
      const out = entries.map((entry) => {
        if (!isVideo) {
          codecs.push(codecString(entry, AUDIO_ENTRY_FIELDS));
          return entry.data;
        }
        if (entry.type !== 'avc1' && entry.type !== 'avc3') {
          throw new Error(`Video codec "${entry.type}" is not supported; transcode to H.264 (avc1)`);
        }
        codecs.push(codecString(entry, VISUAL_ENTRY_FIELDS));
        const fieldsEnd = entry.headerSize + VISUAL_ENTRY_FIELDS;
        const entryKids = readBoxes(entry.data, fieldsEnd, entry.size);
        const avcC = entryKids.find((b) => b.type === 'avcC');
        if (!avcC) throw new Error('avc1 sample entry without avcC');
        const cfg = parseAvcC(avcC.data.subarray(avcC.headerSize));
        state.lengthSize = cfg.lengthSize;
        for (const n of [...cfg.sps, ...cfg.pps]) state.params.add(n);
        return box(
          'encv',
          entry.data.subarray(entry.headerSize, fieldsEnd),
          ...entryKids.map((k) => k.data),
          makeSinf(entry.type, scheme, kid, constantIv),
        );
      });
      return box('stsd', prefix, ...out);
    };

    const walk = (b: Box): Buffer => {
      if (b.type === 'stsd') return rewriteStsd(b);
      if (['mdia', 'minf', 'stbl'].includes(b.type)) return mapContainer(b, walk);
      return b.data;
    };
    return mapContainer(c, walk);
  });
  const moovWithPssh = Buffer.concat([newMoov, ...(opts.pssh ?? []).map((p) => Buffer.from(p))]);
  const finalMoov = box('moov', moovWithPssh.subarray(8));

  let samplesEncrypted = 0;
  const stats = { fallbacks: 0 };
  const out: Uint8Array[] = [];
  const fragments: Fragment[] = [];
  let lastTiming = { time: 0, duration: 0 };
  let written = 0;
  let initSize = 0;

  for (const b of top) {
    let chunk: Uint8Array;
    if (b.type === 'moov') {
      chunk = finalMoov;
    } else if (b.type === 'moof') {
      chunk = encryptFragment(b);
      fragments.push({ offset: written, size: 0, ...lastTiming });
    } else if (b.type === 'sidx' || b.type === 'mfra') {
      // Byte offsets in these would be stale after moof grows; players do not need them for MSE.
      continue;
    } else {
      chunk = b.data;
    }
    out.push(chunk);
    written += chunk.length;
    if (fragments.length === 0) initSize = written;
    else fragments[fragments.length - 1].size = written - fragments[fragments.length - 1].offset;
  }

  function encryptFragment(moof: Box): Buffer {
    const moofStart = moof.start;
    const trafs = children(moof).filter((c) => c.type === 'traf');
    interface TrafPlan {
      traf: Box;
      truns: TrunInfo[];
      extra: Buffer[]; // saiz + saio (patched later) + senc
      sencPayloadOffsetInExtra: number;
      track?: TrackState;
    }
    const plans: TrafPlan[] = [];
    let timing: { time: number; duration: number } | null = null;

    for (const traf of trafs) {
      const tfhd = findChild(traf, 'tfhd');
      if (!tfhd) throw new Error('traf without tfhd');
      const { flags } = fullBoxHeader(tfhd);
      if (flags & 0x1) throw new Error('tfhd base_data_offset is not supported; use -movflags default_base_moof');
      if (!(flags & 0x20000) && trafs.length > 1) throw new Error('Multi-track fragments need default-base-is-moof');
      const id = tfhd.data.readUInt32BE(tfhd.headerSize + 4);
      const track = tracks.get(id);
      let p = tfhd.headerSize + 8;
      if (flags & 0x2) p += 4;
      if (flags & 0x8) p += 4;
      const defaultDuration = flags & 0x8 ? tfhd.data.readUInt32BE(p - 4) : (track?.defaultSampleDuration ?? 0);
      const defaultSize = flags & 0x10 ? tfhd.data.readUInt32BE(p) : (track?.defaultSampleSize ?? 0);
      const truns = children(traf)
        .filter((c) => c.type === 'trun')
        .map((t) => parseTrun(t, defaultSize, defaultDuration));
      if (track && (timing === null || track.encrypt)) {
        const tfdt = findChild(traf, 'tfdt');
        let base = 0;
        if (tfdt) {
          const v = fullBoxHeader(tfdt).version;
          base = v === 1 ? Number(tfdt.data.readBigUInt64BE(tfdt.headerSize + 4)) : tfdt.data.readUInt32BE(tfdt.headerSize + 4);
        }
        const dur = truns.reduce((a, t) => a + t.durations.reduce((x, y) => x + y, 0), 0);
        timing = { time: base / track.timescale, duration: dur / track.timescale };
      }
      const plan: TrafPlan = { traf, truns, extra: [], sencPayloadOffsetInExtra: 0, track };
      plans.push(plan);
      if (!track?.encrypt) continue;

      const ivs: Buffer[] = [];
      const subsampleMaps: Subsample[][] = [];
      for (const t of truns) {
        let pos = moofStart + t.dataOffset;
        for (const size of t.sizes) {
          const sample = buf.subarray(pos, pos + size);
          if (pos + size > buf.length) throw new Error('Sample data out of range');
          let iv: Buffer;
          if (scheme === 'cenc') {
            iv = Buffer.alloc(8);
            iv.writeBigUInt64BE(track.ivCounter, 0);
            track.ivCounter = (track.ivCounter + 1n) & 0xffffffffffffffffn;
          } else {
            iv = constantIv as Buffer;
          }
          subsampleMaps.push(encryptVideoSample(sample, track, scheme, key, iv, stats));
          if (scheme === 'cenc') ivs.push(iv);
          samplesEncrypted++;
          pos += size;
        }
      }
      const n = subsampleMaps.length;
      const perSample = subsampleMaps.map((subs, i) => {
        const parts: Buffer[] = [];
        if (scheme === 'cenc') parts.push(ivs[i]);
        parts.push(u16(subs.length));
        for (const s of subs) parts.push(u16(s.clear), u32(s.protected));
        return Buffer.concat(parts);
      });
      const sizes = perSample.map((x) => x.length);
      const uniform = sizes.every((s) => s === sizes[0]);
      const saiz = fullBox('saiz', 0, 0, u8(uniform ? sizes[0] : 0), u32(n), ...(uniform ? [] : [Buffer.from(sizes)]));
      if (!uniform && sizes.some((s) => s > 255)) throw new Error('Too many subsamples in one sample');
      const saio = fullBox('saio', 0, 0, u32(1), u32(0)); // offset patched once layout is known
      const senc = fullBox('senc', 0, 0x2, u32(n), ...perSample);
      plan.extra = [saiz, saio, senc];
      plan.sencPayloadOffsetInExtra = saiz.length + saio.length + 16;
    }

    lastTiming = timing ?? { time: 0, duration: 0 };
    const extraTotal = plans.reduce((acc, p) => acc + p.extra.reduce((a, e) => a + e.length, 0), 0);
    if (extraTotal === 0) return moof.data;
    const newMoofSize = moof.size + extraTotal + (moof.headerSize === 16 ? -8 : 0);
    const delta = newMoofSize - moof.size;

    // Assemble moof: keep box order, append saiz/saio/senc to each encrypted traf.
    const parts: Buffer[] = [];
    let cursor = 8; // relative to new moof start
    for (const c of children(moof)) {
      if (c.type !== 'traf') {
        parts.push(c.data);
        cursor += c.size;
        continue;
      }
      const plan = plans.find((p) => p.traf.start === c.start) as TrafPlan;
      const trafKids: Buffer[] = [];
      for (const k of children(c)) {
        if (k.type === 'trun') {
          const t = plan.truns.find((x) => x.box.start === k.start) as TrunInfo;
          trafKids.push(patchTrunOffset(t, delta));
        } else if (k.type === 'tfhd') {
          const copy = Buffer.from(k.data);
          copy.writeUInt32BE(copy.readUInt32BE(k.headerSize) | 0x20000, k.headerSize);
          trafKids.push(copy);
        } else if (k.type === 'saiz' || k.type === 'saio' || k.type === 'senc') {
          throw new Error('Input already contains encryption boxes');
        } else {
          trafKids.push(k.data);
        }
      }
      const kidsLen = trafKids.reduce((a, k) => a + k.length, 0);
      if (plan.extra.length) {
        const saio = plan.extra[1];
        const sencPayload = cursor + 8 + kidsLen + plan.sencPayloadOffsetInExtra;
        saio.writeUInt32BE(sencPayload, saio.length - 4);
      }
      const traf = box('traf', ...trafKids, ...plan.extra);
      parts.push(traf);
      cursor += traf.length;
    }
    const result = box('moof', ...parts);
    if (result.length !== newMoofSize) throw new Error('Internal error: moof size mismatch');
    return result;
  }

  const lastFrag = fragments[fragments.length - 1];
  return {
    data: Buffer.concat(out),
    initSize,
    fragments,
    duration: lastFrag ? lastFrag.time + lastFrag.duration : 0,
    codecs,
    encryptedTracks: [...tracks.values()].filter((t) => t.encrypt).map((t) => t.id),
    width,
    height,
    samplesEncrypted,
    sliceHeaderFallbacks: stats.fallbacks,
  };
}
