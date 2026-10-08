/** The JSON document that describes one protected asset. Produced by the packager, consumed by the player. */

export type MediaKind = 'image' | 'video';
export type DrmSystem = 'widevine' | 'playready' | 'fairplay' | 'clearkey';
export type EncryptionScheme = 'cenc' | 'cbcs';

export interface DrmEndpoint {
  /** License URL. Relative URLs resolve against the manifest URL. */
  licenseUrl: string;
  /** FairPlay only: URL of the application certificate. */
  certificateUrl?: string;
}

export interface ManifestSegment {
  /** Byte range [start, end) inside the media file. */
  start: number;
  end: number;
  /** Presentation time in seconds. */
  time: number;
  duration: number;
}

export interface ScreenVeilManifest {
  version: 1;
  id: string;
  kind: MediaKind;
  /** Media file URL. Relative URLs resolve against the manifest URL. */
  url: string;
  /** Full MIME type for MediaSource, e.g. `video/mp4; codecs="avc1.640028"`. */
  mimeType: string;
  videoCodec: string;
  audioCodec?: string;
  width: number;
  height: number;
  duration: number;
  scheme: EncryptionScheme;
  /** Key ID (hex). Never the key itself. */
  kid: string;
  init: { start: number; end: number };
  segments: ManifestSegment[];
  drm: Partial<Record<DrmSystem, DrmEndpoint>>;
}
