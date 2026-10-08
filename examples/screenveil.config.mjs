// Production config for `screenveil serve --config examples/screenveil.config.mjs`.
// Fill in your DRM vendor's license URLs and authentication. The browser never sees these.
import { licenseProxy, randomKeys } from 'screenveil/server';

export default {
  dataDir: process.env.SCREENVEIL_DATA ?? './screenveil-data',
  keySource: randomKeys(),
  tokenSecret: process.env.SCREENVEIL_TOKEN_SECRET,
  // Only your admin tooling may upload.
  authorizeUpload: (req) => req.headers['x-admin-key'] === process.env.SCREENVEIL_ADMIN_KEY,
  licenses: [
    licenseProxy({
      system: 'widevine',
      url: process.env.WIDEVINE_LICENSE_URL,
      // Many vendors accept a signed "bring your own key" token. ctx.key holds { kid, key } (hex).
      headers: async (ctx) => ({ 'x-vendor-token': await makeVendorToken(ctx) }),
    }),
    licenseProxy({
      system: 'playready',
      url: process.env.PLAYREADY_LICENSE_URL,
      headers: async (ctx) => ({ 'x-vendor-token': await makeVendorToken(ctx) }),
    }),
  ],
};

async function makeVendorToken(ctx) {
  // Replace with your vendor's token format (usually a JWT signed with a secret they give you).
  throw new Error(`Implement makeVendorToken for asset ${ctx.id}`);
}
