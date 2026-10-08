// Builds the single-file browser bundle (window.ScreenVeil + <screenveil-media>) for <script> tags and CDNs.
import { build } from 'esbuild';
import { chmodSync, readFileSync } from 'node:fs';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
await build({
  entryPoints: ['src/client/global.ts'],
  bundle: true,
  minify: true,
  format: 'iife',
  target: ['chrome100', 'edge100', 'firefox100', 'safari15'],
  outfile: 'dist/screenveil.global.js',
  banner: { js: `/*! screenveil v${version} | MIT | https://github.com/RamiMohamed12/screenveil */` },
  sourcemap: true,
});
try {
  chmodSync('dist/cli.js', 0o755);
} catch {
  // not built yet / Windows
}
