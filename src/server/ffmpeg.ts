import { spawn } from 'node:child_process';
import type { MediaKind } from '../shared/manifest.ts';

export interface TranscodeOptions {
  /** Path to the ffmpeg binary. Defaults to $SCREENVEIL_FFMPEG or "ffmpeg" on PATH. */
  ffmpegPath?: string;
  /** Longest edge in pixels. Defaults: 3840 for images, 1920 for video. */
  maxDimension?: number;
  /** x264 CRF (lower = better). Defaults: 14 for images, 20 for video. */
  crf?: number;
  /**
   * How long the still-image video runs before looping, in seconds. Frames after the
   * first are near-empty P-frames, so a long loop costs almost nothing.
   */
  imageLoopSeconds?: number;
  /** Kill ffmpeg after this many milliseconds. Default 15 minutes. */
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT = 15 * 60 * 1000;

/**
 * Fails fast if the input cannot be decoded. Needed before looping an image: with
 * `-loop 1`, ffmpeg retries an undecodable input forever instead of exiting.
 */
export function ffmpegProbeArgs(input: string): string[] {
  return ['-hide_banner', '-loglevel', 'error', '-xerror', '-i', input, '-map', '0:v:0', '-frames:v', '1', '-f', 'null', '-'];
}

export function ffmpegBinary(opts: { ffmpegPath?: string } = {}): string {
  return opts.ffmpegPath ?? process.env.SCREENVEIL_FFMPEG ?? 'ffmpeg';
}

const IMAGE_EXT = /\.(jpe?g|png|webp|gif|bmp|tiff?|avif|heic)$/i;

export function guessKind(filename: string, mime?: string): MediaKind {
  if (mime?.startsWith('image/')) return 'image';
  if (mime?.startsWith('video/')) return 'video';
  return IMAGE_EXT.test(filename) ? 'image' : 'video';
}

/** Arguments that turn any input into a clear, fragmented, H.264 MP4 the encryptor accepts. */
export function ffmpegArgs(input: string, output: string, kind: MediaKind, opts: TranscodeOptions = {}): string[] {
  const fragFlags = ['-movflags', 'frag_keyframe+empty_moov+default_base_moof'];
  if (kind === 'image') {
    const max = opts.maxDimension ?? 3840;
    const seconds = opts.imageLoopSeconds ?? 30;
    return [
      '-hide_banner', '-loglevel', 'error', '-y',
      '-loop', '1', '-framerate', '1', '-i', input,
      '-t', String(seconds),
      '-vf', `scale=w='min(${max},iw)':h='min(${max},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p`,
      '-c:v', 'libx264', '-preset', 'slow', '-tune', 'stillimage', '-crf', String(opts.crf ?? 14),
      '-profile:v', 'high', '-g', String(seconds), '-r', '1',
      '-an', ...fragFlags, '-f', 'mp4', output,
    ];
  }
  const max = opts.maxDimension ?? 1920;
  return [
    '-hide_banner', '-loglevel', 'error', '-y',
    '-i', input,
    '-map', '0:v:0', '-map', '0:a:0?',
    '-vf', `scale=w='min(${max},iw)':h='min(${max},ih)':force_original_aspect_ratio=decrease,scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p`,
    '-c:v', 'libx264', '-preset', 'medium', '-crf', String(opts.crf ?? 20), '-profile:v', 'high',
    // ~2 second fragments so the player can seek and stream with range requests
    '-force_key_frames', 'expr:gte(t,n_forced*2)', '-sc_threshold', '0',
    '-c:a', 'aac', '-b:a', '128k', '-ac', '2',
    ...fragFlags, '-f', 'mp4', output,
  ];
}

export function runFfmpeg(args: string[], opts: { ffmpegPath?: string; timeoutMs?: number } = {}): Promise<void> {
  const bin = ffmpegBinary(opts);
  return new Promise((resolve, reject) => {
    const p = spawn(bin, args, { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
    const timer = setTimeout(() => {
      p.kill('SIGKILL');
      reject(new Error(`ffmpeg exited with code null: timed out after ${opts.timeoutMs ?? DEFAULT_TIMEOUT}ms`));
    }, opts.timeoutMs ?? DEFAULT_TIMEOUT);
    let err = '';
    p.stderr.on('data', (d: Buffer) => {
      err = (err + d.toString()).slice(-4000);
    });
    p.on('error', (e) => {
      clearTimeout(timer);
      reject(
        (e as NodeJS.ErrnoException).code === 'ENOENT'
          ? new Error(`ffmpeg not found ("${bin}"). Install ffmpeg or set SCREENVEIL_FFMPEG / ffmpegPath.`)
          : e,
      );
    });
    p.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`ffmpeg exited with code ${code}: ${err.trim()}`));
    });
  });
}
