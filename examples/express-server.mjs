// Minimal Express integration. Run: npm i express && node examples/express-server.mjs
// Uses the public test DRM servers so it works without a vendor account. Swap the providers
// for licenseProxy(...) before protecting real content (see examples/screenveil.config.mjs).
import { fileURLToPath } from 'node:url';
import express from 'express';
import {
  createScreenVeilApi,
  issueLicenseToken,
  playReadyTestLicense,
  widevineTestKeys,
  widevineTestLicense,
} from 'screenveil/server';

const TOKEN_SECRET = process.env.SCREENVEIL_TOKEN_SECRET ?? 'change-me-to-a-long-random-string';
const app = express();

app.use(
  createScreenVeilApi({
    dataDir: './screenveil-data',
    keySource: widevineTestKeys(),
    licenses: [widevineTestLicense(), playReadyTestLicense({ securityLevel: 3000 })],
    tokenSecret: TOKEN_SECRET,
    authorizeUpload: () => true, // lock this down in a real app
  }),
);

// Your app decides who can watch. Here everyone can; normally check the session first.
app.get('/token/:id', (req, res) => {
  res.json({ token: issueLicenseToken(TOKEN_SECRET, { contentId: req.params.id, ttlSeconds: 300 }) });
});

app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html>
<input type="file" id="f" accept="image/*,video/*"><div id="out" style="width:640px"></div>
<script src="/screenveil.global.js"></script>
<script>
  f.onchange = async () => {
    const file = f.files[0];
    const up = await (await fetch('/api/assets?filename=' + encodeURIComponent(file.name), { method: 'POST', body: file })).json();
    const { token } = await (await fetch('/token/' + up.id)).json();
    await ScreenVeil.protect(out, { manifest: up.manifestUrl, token });
  };
</script>`);
});

// The single-file browser bundle (window.ScreenVeil). With a bundler, `import { protect } from 'screenveil'` instead.
app.get('/screenveil.global.js', (_req, res) => res.sendFile(fileURLToPath(import.meta.resolve('screenveil/global')), { dotfiles: 'allow' }));

app.listen(3000, () => console.log('http://localhost:3000'));
