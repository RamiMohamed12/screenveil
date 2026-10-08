/**
 * Just enough H.264 parsing to find where each slice header ends, so that
 * subsample encryption leaves NAL + slice headers in the clear. Hardware
 * decoders (PlayReady SL3000, Widevine L1) parse slice headers outside the
 * secure path, so this is required for the screen-capture-blocking path.
 */

export interface Sps {
  id: number;
  chromaArrayType: number;
  separateColourPlane: boolean;
  log2MaxFrameNum: number;
  pocType: number;
  log2MaxPocLsb: number;
  deltaPicOrderAlwaysZero: boolean;
  frameMbsOnly: boolean;
}

export interface Pps {
  id: number;
  spsId: number;
  cabac: boolean;
  bottomFieldPicOrderPresent: boolean;
  numRefIdxL0Default: number;
  numRefIdxL1Default: number;
  weightedPred: boolean;
  weightedBipredIdc: number;
  deblockingFilterControlPresent: boolean;
  redundantPicCntPresent: boolean;
}

export interface AvcConfig {
  lengthSize: number;
  sps: Uint8Array[];
  pps: Uint8Array[];
}

export function parseAvcC(payload: Uint8Array): AvcConfig {
  const p = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  const lengthSize = (p[4] & 0x3) + 1;
  let off = 5;
  const numSps = p[off++] & 0x1f;
  const sps: Uint8Array[] = [];
  for (let i = 0; i < numSps; i++) {
    const len = p.readUInt16BE(off);
    sps.push(p.subarray(off + 2, off + 2 + len));
    off += 2 + len;
  }
  const numPps = p[off++];
  const pps: Uint8Array[] = [];
  for (let i = 0; i < numPps; i++) {
    const len = p.readUInt16BE(off);
    pps.push(p.subarray(off + 2, off + 2 + len));
    off += 2 + len;
  }
  return { lengthSize, sps, pps };
}

/** RBSP view of a NAL unit with a map back to raw byte offsets. */
function unescape(nal: Uint8Array, limit = nal.length): { rbsp: Uint8Array; rawIndex: number[] } {
  const end = Math.min(nal.length, limit);
  const out: number[] = [];
  const rawIndex: number[] = [];
  let zeros = 0;
  for (let i = 0; i < end; i++) {
    const b = nal[i];
    if (zeros >= 2 && b === 3) {
      zeros = 0;
      continue;
    }
    zeros = b === 0 ? zeros + 1 : 0;
    out.push(b);
    rawIndex.push(i);
  }
  return { rbsp: Uint8Array.from(out), rawIndex };
}

class BitReader {
  pos = 0;
  private readonly d: Uint8Array;
  constructor(d: Uint8Array) {
    this.d = d;
  }
  bit(): number {
    const byte = this.pos >> 3;
    if (byte >= this.d.length) throw new RangeError('BitReader overrun');
    const v = (this.d[byte] >> (7 - (this.pos & 7))) & 1;
    this.pos++;
    return v;
  }
  bits(n: number): number {
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 2 + this.bit();
    return v;
  }
  ue(): number {
    let zeros = 0;
    while (this.bit() === 0) {
      if (++zeros > 31) throw new RangeError('Invalid exp-Golomb code');
    }
    return zeros === 0 ? 0 : 2 ** zeros - 1 + this.bits(zeros);
  }
  se(): number {
    const k = this.ue();
    return k & 1 ? (k + 1) / 2 : -(k / 2);
  }
  skip(n: number): void {
    this.pos += n;
  }
}

const HIGH_PROFILES = new Set([100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135]);

function skipScalingList(r: BitReader, size: number): void {
  let last = 8;
  let next = 8;
  for (let j = 0; j < size; j++) {
    if (next !== 0) next = (last + r.se() + 256) % 256;
    last = next === 0 ? last : next;
  }
}

export function parseSps(nal: Uint8Array): Sps {
  const r = new BitReader(unescape(nal).rbsp);
  r.skip(8); // NAL header
  const profile = r.bits(8);
  r.skip(16); // constraint flags + level
  const id = r.ue();
  let chromaFormatIdc = 1;
  let separateColourPlane = false;
  if (HIGH_PROFILES.has(profile)) {
    chromaFormatIdc = r.ue();
    if (chromaFormatIdc === 3) separateColourPlane = r.bit() === 1;
    r.ue(); // bit_depth_luma_minus8
    r.ue(); // bit_depth_chroma_minus8
    r.skip(1); // qpprime_y_zero_transform_bypass_flag
    if (r.bit()) {
      const n = chromaFormatIdc === 3 ? 12 : 8;
      for (let i = 0; i < n; i++) if (r.bit()) skipScalingList(r, i < 6 ? 16 : 64);
    }
  }
  const log2MaxFrameNum = r.ue() + 4;
  const pocType = r.ue();
  let log2MaxPocLsb = 0;
  let deltaPicOrderAlwaysZero = false;
  if (pocType === 0) {
    log2MaxPocLsb = r.ue() + 4;
  } else if (pocType === 1) {
    deltaPicOrderAlwaysZero = r.bit() === 1;
    r.se();
    r.se();
    const n = r.ue();
    for (let i = 0; i < n; i++) r.se();
  }
  r.ue(); // max_num_ref_frames
  r.skip(1); // gaps_in_frame_num_value_allowed_flag
  r.ue(); // pic_width_in_mbs_minus1
  r.ue(); // pic_height_in_map_units_minus1
  const frameMbsOnly = r.bit() === 1;
  return {
    id,
    chromaArrayType: separateColourPlane ? 0 : chromaFormatIdc,
    separateColourPlane,
    log2MaxFrameNum,
    pocType,
    log2MaxPocLsb,
    deltaPicOrderAlwaysZero,
    frameMbsOnly,
  };
}

export function parsePps(nal: Uint8Array): Pps {
  const r = new BitReader(unescape(nal).rbsp);
  r.skip(8);
  const id = r.ue();
  const spsId = r.ue();
  const cabac = r.bit() === 1;
  const bottomFieldPicOrderPresent = r.bit() === 1;
  const numSliceGroups = r.ue() + 1;
  if (numSliceGroups > 1) throw new Error('H.264 slice groups (FMO) are not supported');
  const numRefIdxL0Default = r.ue() + 1;
  const numRefIdxL1Default = r.ue() + 1;
  const weightedPred = r.bit() === 1;
  const weightedBipredIdc = r.bits(2);
  r.se(); // pic_init_qp_minus26
  r.se(); // pic_init_qs_minus26
  r.se(); // chroma_qp_index_offset
  const deblockingFilterControlPresent = r.bit() === 1;
  r.skip(1); // constrained_intra_pred_flag
  const redundantPicCntPresent = r.bit() === 1;
  return {
    id,
    spsId,
    cabac,
    bottomFieldPicOrderPresent,
    numRefIdxL0Default,
    numRefIdxL1Default,
    weightedPred,
    weightedBipredIdc,
    deblockingFilterControlPresent,
    redundantPicCntPresent,
  };
}

export class AvcParamSets {
  readonly sps = new Map<number, Sps>();
  readonly pps = new Map<number, Pps>();

  add(nal: Uint8Array): void {
    const type = nal[0] & 0x1f;
    if (type === 7) {
      const s = parseSps(nal);
      this.sps.set(s.id, s);
    } else if (type === 8) {
      const p = parsePps(nal);
      this.pps.set(p.id, p);
    }
  }
}

function skipRefPicListModification(r: BitReader): void {
  if (!r.bit()) return;
  for (;;) {
    const idc = r.ue();
    if (idc === 3) return;
    if (idc > 5) throw new Error('Invalid modification_of_pic_nums_idc');
    r.ue();
  }
}

function skipPredWeightTable(r: BitReader, sps: Sps, l0: number, l1: number, isB: boolean): void {
  r.ue(); // luma_log2_weight_denom
  if (sps.chromaArrayType !== 0) r.ue();
  const lists = isB ? [l0, l1] : [l0];
  for (const n of lists) {
    for (let i = 0; i < n; i++) {
      if (r.bit()) {
        r.se();
        r.se();
      }
      if (sps.chromaArrayType !== 0 && r.bit()) {
        for (let j = 0; j < 4; j++) r.se();
      }
    }
  }
}

/**
 * Size in bytes of NAL header + slice header for a VCL NAL unit (types 1-5),
 * measured in raw (escaped) bytes from the start of the NAL unit.
 */
export function sliceHeaderSize(nal: Uint8Array, ps: AvcParamSets): number {
  const { rbsp, rawIndex } = unescape(nal, 2048);
  const r = new BitReader(rbsp);
  r.skip(1);
  const refIdc = r.bits(2);
  const nalType = r.bits(5);
  const idr = nalType === 5;
  r.ue(); // first_mb_in_slice
  const sliceType = r.ue() % 5; // 0 P, 1 B, 2 I, 3 SP, 4 SI
  const pps = ps.pps.get(r.ue());
  if (!pps) throw new Error('Slice references unknown PPS');
  const sps = ps.sps.get(pps.spsId);
  if (!sps) throw new Error('PPS references unknown SPS');
  if (sps.separateColourPlane) r.skip(2);
  r.skip(sps.log2MaxFrameNum);
  let fieldPic = false;
  if (!sps.frameMbsOnly) {
    fieldPic = r.bit() === 1;
    if (fieldPic) r.skip(1);
  }
  if (idr) r.ue();
  if (sps.pocType === 0) {
    r.skip(sps.log2MaxPocLsb);
    if (pps.bottomFieldPicOrderPresent && !fieldPic) r.se();
  } else if (sps.pocType === 1 && !sps.deltaPicOrderAlwaysZero) {
    r.se();
    if (pps.bottomFieldPicOrderPresent && !fieldPic) r.se();
  }
  if (pps.redundantPicCntPresent) r.ue();
  const isB = sliceType === 1;
  const isP = sliceType === 0 || sliceType === 3;
  if (isB) r.skip(1); // direct_spatial_mv_pred_flag
  let l0 = pps.numRefIdxL0Default;
  let l1 = pps.numRefIdxL1Default;
  if (isP || isB) {
    if (r.bit()) {
      l0 = r.ue() + 1;
      if (isB) l1 = r.ue() + 1;
    }
  }
  if (sliceType !== 2 && sliceType !== 4) {
    skipRefPicListModification(r);
    if (isB) skipRefPicListModification(r);
  }
  if ((pps.weightedPred && isP) || (pps.weightedBipredIdc === 1 && isB)) {
    skipPredWeightTable(r, sps, l0, l1, isB);
  }
  if (refIdc !== 0) {
    if (idr) {
      r.skip(2);
    } else if (r.bit()) {
      for (;;) {
        const op = r.ue();
        if (op === 0) break;
        if (op === 1 || op === 3) r.ue();
        if (op === 2) r.ue();
        if (op === 3 || op === 6) r.ue();
        if (op === 4) r.ue();
        if (op > 6) throw new Error('Invalid memory_management_control_operation');
      }
    }
  }
  if (pps.cabac && sliceType !== 2 && sliceType !== 4) r.ue();
  r.se(); // slice_qp_delta
  if (sliceType === 3 || sliceType === 4) {
    if (sliceType === 3) r.skip(1);
    r.se();
  }
  if (pps.deblockingFilterControlPresent) {
    if (r.ue() !== 1) {
      r.se();
      r.se();
    }
  }
  const rbspBytes = Math.ceil(r.pos / 8);
  if (rbspBytes >= rawIndex.length) return nal.length;
  return rawIndex[rbspBytes];
}
