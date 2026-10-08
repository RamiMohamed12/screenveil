import type { DrmSystem, EncryptionScheme } from '../shared/manifest.ts';

/**
 * How strongly the chosen DRM path protects the picture.
 *  - 'hardware': decrypt + decode in a secure hardware path (PlayReady SL3000, Widevine L1, FairPlay).
 *  - 'software': CDM in software (Widevine L3, PlayReady SL2000). On Windows Chrome/Edge the
 *    compositor still keeps the video out of screenshots and recordings.
 *  - 'none': Clear Key. The browser treats the video like any other; captures show it.
 */
export type Protection = 'hardware' | 'software' | 'none';

export interface KeySystemCandidate {
  system: DrmSystem;
  keySystem: string;
  robustness: string;
  protection: Protection;
}

export const CANDIDATES: KeySystemCandidate[] = [
  { system: 'playready', keySystem: 'com.microsoft.playready.recommendation', robustness: '3000', protection: 'hardware' },
  { system: 'widevine', keySystem: 'com.widevine.alpha', robustness: 'HW_SECURE_ALL', protection: 'hardware' },
  { system: 'widevine', keySystem: 'com.widevine.alpha', robustness: 'HW_SECURE_DECODE', protection: 'hardware' },
  { system: 'fairplay', keySystem: 'com.apple.fps', robustness: '', protection: 'hardware' },
  { system: 'widevine', keySystem: 'com.widevine.alpha', robustness: 'SW_SECURE_DECODE', protection: 'software' },
  { system: 'widevine', keySystem: 'com.widevine.alpha', robustness: 'SW_SECURE_CRYPTO', protection: 'software' },
  { system: 'widevine', keySystem: 'com.widevine.alpha', robustness: '', protection: 'software' },
  { system: 'playready', keySystem: 'com.microsoft.playready.recommendation', robustness: '2000', protection: 'software' },
  { system: 'clearkey', keySystem: 'org.w3.clearkey', robustness: '', protection: 'none' },
];

const RANK: Record<Protection, number> = { none: 0, software: 1, hardware: 2 };

export function meetsProtection(p: Protection, min: Protection): boolean {
  return RANK[p] >= RANK[min];
}

export interface ProbeOptions {
  /** Which DRM systems you have license endpoints for. */
  systems: DrmSystem[];
  videoCodec: string;
  scheme: EncryptionScheme;
  minProtection: Protection;
  /** Optional ordering override, e.g. ['widevine', 'playready']. Protection level still wins. */
  preferred?: DrmSystem[];
}

export interface ProbeResult {
  candidate: KeySystemCandidate;
  access: MediaKeySystemAccess;
}

function config(c: KeySystemCandidate, o: ProbeOptions): MediaKeySystemConfiguration[] {
  const video: MediaKeySystemMediaCapability & { encryptionScheme?: string } = {
    contentType: `video/mp4; codecs="${o.videoCodec}"`,
    robustness: c.robustness,
    encryptionScheme: o.scheme,
  };
  const cfg: MediaKeySystemConfiguration = {
    initDataTypes: c.system === 'fairplay' ? ['sinf', 'cenc'] : ['cenc'],
    videoCapabilities: [video],
    distinctiveIdentifier: 'optional',
    persistentState: 'optional',
    sessionTypes: ['temporary'],
  };
  // Audio is never encrypted by the packager, so no audio capability is requested. Declaring
  // one would also make some CDMs (e.g. PlayReady in Chrome) reject hardware configurations.
  return [cfg];
}

/** Find the strongest key system this browser supports for the given content. */
export async function probeKeySystems(o: ProbeOptions): Promise<ProbeResult | null> {
  if (typeof navigator === 'undefined' || !navigator.requestMediaKeySystemAccess) return null;
  const order = o.preferred ?? [];
  const candidates = CANDIDATES.filter((c) => o.systems.includes(c.system) && meetsProtection(c.protection, o.minProtection))
    .map((c, i) => ({ c, i }))
    .sort((a, b) => {
      const byLevel = RANK[b.c.protection] - RANK[a.c.protection];
      if (byLevel) return byLevel;
      const pa = order.indexOf(a.c.system);
      const pb = order.indexOf(b.c.system);
      if (pa !== pb) return (pa === -1 ? 99 : pa) - (pb === -1 ? 99 : pb);
      return a.i - b.i;
    })
    .map((x) => x.c);
  for (const c of candidates) {
    try {
      const access = await navigator.requestMediaKeySystemAccess(c.keySystem, config(c, o));
      return { candidate: c, access };
    } catch {
      // not supported; try the next one
    }
  }
  return null;
}

/**
 * What would protect content in this browser, without loading any. Handy for showing
 * "use Chrome, Edge or Safari" hints before the user clicks anything.
 */
export async function detectProtection(
  opts: { systems?: DrmSystem[]; scheme?: EncryptionScheme } = {},
): Promise<{ system: DrmSystem; keySystem: string; protection: Protection } | null> {
  const r = await probeKeySystems({
    systems: opts.systems ?? ['playready', 'widevine', 'fairplay'],
    videoCodec: 'avc1.640028',
    scheme: opts.scheme ?? 'cenc',
    minProtection: 'software',
  });
  return r ? { system: r.candidate.system, keySystem: r.candidate.keySystem, protection: r.candidate.protection } : null;
}
