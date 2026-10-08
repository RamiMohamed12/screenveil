import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import type { DrmEndpoint, DrmSystem, EncryptionScheme, MediaKind, ScreenVeilManifest } from '../shared/manifest.ts';
import { ffmpegArgs, ffmpegProbeArgs, guessKind, runFfmpeg, type TranscodeOptions } from './ffmpeg.ts';
import { type ContentKey, type KeySource, type KeyStore, assertSafeId, randomKeys } from './keys.ts';
import { encryptFragmentedMp4 } from './mp4/encrypt.ts';
import { clearKeyPssh, playReadyPssh, widevinePssh } from './pssh.ts';

export interface ProtectOptions {
  /** Content id (letters, digits, - and _). Random if omitted. */
  id?: string;
  /** Detected from the file extension if omitted. */
  kind?: MediaKind;
  /**
   * 'cenc' (default) plays in Chrome, Edge, Firefox and Android.
   * 'cbcs' is required for Safari/FairPlay and also plays in current Chrome and Edge.
   */
  scheme?: EncryptionScheme;
  /** Where keys come from. Default: random local keys. */
  keySource?: KeySource;
  /** If given, the content key is saved here under the content id. */
  keyStore?: KeyStore;
  /**
   * License endpoints written into the manifest. `{id}` is replaced with the content id.
   * Relative URLs are resolved by the player against the manifest URL.
   */
  drm?: Partial<Record<DrmSystem, DrmEndpoint>>;
  /** Name of the media file written next to manifest.json. */
  mediaFileName?: string;
  transcode?: TranscodeOptions;
}

export interface ProtectResult {
  manifest: ScreenVeilManifest;
  /** The content key. Store it server-side only; never send it to browsers. */
  key: ContentKey;
  manifestPath: string;
  mediaPath: string;
}

export function newContentId(): string {
  return randomBytes(12).toString('base64url');
}

/**
 * Encrypt an already-fragmented H.264 MP4 and build its manifest. Use this if you run
 * your own transcoding pipeline; otherwise use {@link protectFile}.
 */
export async function protectFragmentedMp4(
  clearMp4: Uint8Array,
  opts: ProtectOptions & { id: string; kind: MediaKind },
): Promise<{ manifest: ScreenVeilManifest; media: Buffer; key: ContentKey }> {
  assertSafeId(opts.id);
  const scheme = opts.scheme ?? 'cenc';
  const key = await (opts.keySource ?? randomKeys()).createKey(opts.id);
  const pssh = [
    clearKeyPssh([key.kid]),
    ...(key.pssh?.length ? key.pssh.map((b) => Buffer.from(b, 'base64')) : [widevinePssh([key.kid], { contentId: opts.id, scheme })]),
    playReadyPssh([key.kid], { scheme }),
  ];
  const enc = encryptFragmentedMp4(clearMp4, { kid: key.kid, key: key.key, scheme, pssh });
  if (enc.encryptedTracks.length === 0) throw new Error('No video track found to protect');

  const videoCodec = enc.codecs.find((c) => c.startsWith('avc')) as string;
  const audioCodec = enc.codecs.find((c) => c.startsWith('mp4a'));
  const drm: Partial<Record<DrmSystem, DrmEndpoint>> = {};
  for (const [system, ep] of Object.entries(opts.drm ?? {}) as Array<[DrmSystem, DrmEndpoint]>) {
    drm[system] = {
      licenseUrl: ep.licenseUrl.replaceAll('{id}', opts.id),
      ...(ep.certificateUrl ? { certificateUrl: ep.certificateUrl.replaceAll('{id}', opts.id) } : {}),
    };
  }
  const manifest: ScreenVeilManifest = {
    version: 1,
    id: opts.id,
    kind: opts.kind,
    url: opts.mediaFileName ?? 'media.mp4',
    mimeType: `video/mp4; codecs="${[videoCodec, audioCodec].filter(Boolean).join(', ')}"`,
    videoCodec,
    ...(audioCodec ? { audioCodec } : {}),
    width: enc.width,
    height: enc.height,
    duration: enc.duration,
    scheme,
    kid: key.kid,
    init: { start: 0, end: enc.initSize },
    segments: enc.fragments.map((f) => ({
      start: f.offset,
      end: f.offset + f.size,
      time: round(f.time),
      duration: round(f.duration),
    })),
    drm,
  };
  if (opts.keyStore) await opts.keyStore.put(opts.id, { ...key, scheme });
  return { manifest, media: enc.data, key };
}

/**
 * Transcode an image or video with ffmpeg, encrypt it, and write `media.mp4` and
 * `manifest.json` into `outDir`.
 */
export async function protectFile(inputPath: string, outDir: string, opts: ProtectOptions = {}): Promise<ProtectResult> {
  const id = opts.id ?? newContentId();
  assertSafeId(id);
  const kind = opts.kind ?? guessKind(basename(inputPath));
  const tmp = join(tmpdir(), `screenveil-${id}-${randomBytes(4).toString('hex')}.mp4`);
  try {
    await runFfmpeg(ffmpegProbeArgs(inputPath), { ...opts.transcode, timeoutMs: 60_000 });
    await runFfmpeg(ffmpegArgs(inputPath, tmp, kind, opts.transcode), opts.transcode);
    const clear = await readFile(tmp);
    const { manifest, media, key } = await protectFragmentedMp4(clear, { ...opts, id, kind });
    await mkdir(outDir, { recursive: true });
    const mediaPath = join(outDir, manifest.url);
    const manifestPath = join(outDir, 'manifest.json');
    await writeFile(mediaPath, media);
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    return { manifest, key, manifestPath, mediaPath };
  } finally {
    await rm(tmp, { force: true });
  }
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}
