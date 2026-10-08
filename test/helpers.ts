import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const hasFfmpeg = spawnSync(process.env.SCREENVEIL_FFMPEG ?? 'ffmpeg', ['-version']).status === 0;

export function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'screenveil-test-'));
}

export function ffmpeg(args: string[]): string {
  const r = spawnSync(process.env.SCREENVEIL_FFMPEG ?? 'ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`ffmpeg failed: ${r.stderr}`);
  return r.stdout;
}

/** Per-frame MD5s of the first video stream, optionally decrypting with a key. */
export function frameHashes(file: string, key?: string): string[] {
  const out = ffmpeg([...(key ? ['-decryption_key', key] : []), '-i', file, '-map', '0:v:0', '-f', 'framemd5', '-']);
  return out
    .split('\n')
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => l.split(',').pop()!.trim());
}
