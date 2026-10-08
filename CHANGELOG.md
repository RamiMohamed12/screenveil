# Changelog

## 0.1.0 (2026-10-08)

First release.

- Browser player: key-system probing (PlayReady, Widevine, FairPlay, Clear Key) ordered by protection level,
  MSE playback with range requests, PlayReady challenge unwrapping, `<screenveil-media>` element,
  capture-safety style checks, watermark and context-menu deterrence.
- Node packager: ffmpeg transcoding for images and videos, CENC and CBCS encryption of fragmented H.264 MP4
  with slice-header-aware subsample encryption, Widevine/PlayReady/Clear Key PSSH boxes, manifest with segment index.
- License providers: Clear Key, PlayReady test server, Widevine UAT, and a generic proxy for commercial DRM services.
- Web API handler for Node/Express, HMAC license tokens, file key store, CLI (`protect`, `serve`) and demo page.
