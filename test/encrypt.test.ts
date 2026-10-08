import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { encryptFragmentedMp4 } from '../src/server/mp4/encrypt.ts';
import { readBoxes, findPath } from '../src/server/mp4/boxes.ts';
import { clearKeyPssh } from '../src/server/pssh.ts';
import { ffmpeg, frameHashes, hasFfmpeg, tmp } from './helpers.ts';

const KID = '00112233445566778899aabbccddeeff';
const KEY = '0f1e2d3c4b5a69788796a5b4c3d2e1f0';
const FRAG = ['-movflags', 'frag_keyframe+empty_moov+default_base_moof'];

// Encoder settings chosen to exercise different slice-header paths.
const PROFILES: Record<string, string[]> = {
  'high (CABAC, B-frames, weighted prediction)': ['-profile:v', 'high', '-x264-params', 'weightp=2:bframes=3:b-pyramid=normal'],
  'baseline (CAVLC, no B-frames)': ['-profile:v', 'baseline'],
  'main, multiple slices per frame': ['-profile:v', 'main', '-x264-params', 'slices=4'],
};

for (const [name, args] of Object.entries(PROFILES)) {
  for (const scheme of ['cenc', 'cbcs'] as const) {
    test(`${scheme}: ${name} decrypts bit-exactly with ffmpeg`, { skip: !hasFfmpeg && 'ffmpeg not installed' }, () => {
      const dir = tmp();
      const clear = join(dir, 'clear.mp4');
      ffmpeg([
        '-f', 'lavfi', '-i', 'testsrc2=size=320x240:rate=25', '-f', 'lavfi', '-i', 'sine=frequency=330',
        '-t', '3', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-g', '25', ...args, '-c:a', 'aac', ...FRAG, clear,
      ]);
      const input = readFileSync(clear);
      const r = encryptFragmentedMp4(input, { kid: KID, key: KEY, scheme, pssh: [clearKeyPssh([KID])] });
      assert.equal(r.sliceHeaderFallbacks, 0, 'every slice header should parse');
      assert.equal(r.samplesEncrypted, 75);
      assert.deepEqual(r.encryptedTracks, [1]);
      assert.equal(r.width, 320);
      assert.equal(r.height, 240);
      assert.ok(Math.abs(r.duration - 3) < 0.1, `duration ${r.duration}`);
      assert.match(r.codecs[0], /^avc1\./);
      assert.equal(r.codecs[1], 'mp4a.40.2');

      // Fragment index points at moof boxes and covers the whole file.
      assert.equal(r.data.toString('latin1', r.initSize + 4, r.initSize + 8), 'moof');
      for (const f of r.fragments) assert.equal(r.data.toString('latin1', f.offset + 4, f.offset + 8), 'moof');
      const last = r.fragments[r.fragments.length - 1];
      assert.equal(last.offset + last.size, r.data.length);

      // Init segment advertises protection.
      const moov = readBoxes(r.data).find((b) => b.type === 'moov')!;
      assert.ok(r.data.subarray(moov.start, moov.start + moov.size).includes(Buffer.from('encv')));
      assert.ok(r.data.subarray(moov.start, moov.start + moov.size).includes(Buffer.from(scheme)));
      assert.ok(findPath(moov, ['pssh']));
      // The input buffer is not modified.
      assert.ok(input.equals(readFileSync(clear)));

      const out = join(dir, 'enc.mp4');
      writeFileSync(out, r.data);
      const expected = frameHashes(clear);
      assert.deepEqual(frameHashes(out, KEY), expected);
      // Without the key the picture must differ (it is actually encrypted).
      let undecrypted: string[] = [];
      try {
        undecrypted = frameHashes(out);
      } catch {
        undecrypted = [];
      }
      assert.notDeepEqual(undecrypted, expected);
    });
  }
}

test('rejects non-fragmented input with a helpful message', { skip: !hasFfmpeg && 'ffmpeg not installed' }, () => {
  const dir = tmp();
  const file = join(dir, 'flat.mp4');
  ffmpeg(['-f', 'lavfi', '-i', 'testsrc2=size=160x120:rate=10', '-t', '1', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', file]);
  assert.throws(() => encryptFragmentedMp4(readFileSync(file), { kid: KID, key: KEY }), /not fragmented/);
});

test('validates key material', () => {
  assert.throws(() => encryptFragmentedMp4(Buffer.alloc(0), { kid: 'xyz', key: KEY }), /kid must be 16 bytes/);
});
