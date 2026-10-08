# Security

## Reporting a vulnerability

Please open a [private security advisory](https://github.com/RamiMohamed12/screenveil/security/advisories/new)
instead of a public issue. Include steps to reproduce and the browser/OS involved.

## Threat model in one paragraph

screenveil keeps content keys on your server and only releases licenses to browsers that present a valid,
short-lived token, through a DRM module the browser vendor trusts. On platforms with protected video output,
the decrypted picture never reaches screenshots or screen recordings. It does not stop cameras, and it is only
as strong as the DRM path the browser picks: hardware DRM (PlayReady SL3000, Widevine L1, FairPlay) is much
harder to break than software DRM (Widevine L3). Clear Key provides no protection against capture and is refused
by default. Dev mode (`serve --dev`) uses public test key and license servers: anyone can obtain those keys.

## Operational checklist

- Never serve the `keys/` directory. Keep it outside any static root.
- Use a token secret of 32+ random characters and keep token TTLs short.
- Use a commercial DRM license service in production, not the public test servers.
- Set `minProtection: 'hardware'` for the most sensitive content.
