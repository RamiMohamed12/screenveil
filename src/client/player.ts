import type { DrmEndpoint, DrmSystem, ScreenVeilManifest } from '../shared/manifest.ts';
import { applyDeterrence, type DeterrenceOptions } from './deterrence.ts';
import { type KeySystemCandidate, type Protection, probeKeySystems } from './keysystems.ts';

type MaybeAsync<T> = T | Promise<T>;

export interface DrmOverride extends Partial<DrmEndpoint> {
  /** Extra headers sent with every license request for this system. */
  headers?: Record<string, string>;
}

export interface ScreenVeilOptions {
  /** Manifest URL, or a manifest object (then set `baseUrl` for relative URLs). */
  manifest: string | ScreenVeilManifest;
  baseUrl?: string;
  /** License token from your backend, sent as `Authorization: Bearer <token>`. */
  token?: string | (() => MaybeAsync<string>);
  /** Override or add license endpoints per DRM system (e.g. point straight at a DRM vendor). */
  drm?: Partial<Record<DrmSystem, DrmOverride>>;
  /**
   * Weakest protection you accept. Default 'software', which excludes Clear Key because
   * Clear Key video is NOT hidden from screenshots. Use 'hardware' for maximum strictness.
   */
  minProtection?: Protection;
  /** Preferred DRM systems when several are available at the same protection level. */
  preferredSystems?: DrmSystem[];
  /** How the media fits its box. Default 'contain'. */
  fit?: 'contain' | 'cover' | 'fill';
  /** Video only. Defaults: controls on, autoplay off, sound on, no loop. */
  controls?: boolean;
  autoplay?: boolean;
  muted?: boolean;
  loop?: boolean;
  /** Seconds to buffer ahead / keep behind the playhead. Defaults 30 / 30. */
  bufferAhead?: number;
  bufferBehind?: number;
  /** Extra deterrence (context menu block, watermark…). Pass false to disable. */
  deterrence?: DeterrenceOptions | false;
  /** Text shown when this browser cannot play the content with the required protection. */
  unsupportedMessage?: string;
  /** Custom fetch, e.g. to add cookies or credentials to media/manifest requests. */
  fetch?: typeof fetch;
}

export interface ScreenVeilErrorDetail {
  code: 'unsupported' | 'manifest' | 'license' | 'media' | 'output-restricted';
  message: string;
  cause?: unknown;
}

export class ScreenVeilError extends Error {
  readonly code: ScreenVeilErrorDetail['code'];
  constructor(code: ScreenVeilErrorDetail['code'], message: string, cause?: unknown) {
    super(message, { cause });
    this.code = code;
    this.name = 'ScreenVeilError';
  }
}

const STYLE_ID = 'screenveil-style';
const CSS = `
.screenveil{position:relative;display:inline-block;overflow:hidden;background:#000;line-height:0;max-width:100%}
.screenveil>video{width:100%;height:100%;display:block}
.screenveil,.screenveil>video{border-radius:0!important;opacity:1!important;transform:none!important;filter:none!important;
  clip-path:none!important;mask:none!important;mix-blend-mode:normal!important}
.screenveil.screenveil-hidden>video{visibility:hidden}
.screenveil-message{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;padding:1em;
  color:#ddd;font:14px/1.4 system-ui,sans-serif;text-align:center;background:#111}
`;

function injectStyle() {
  if (typeof document === 'undefined' || document.getElementById(STYLE_ID)) return;
  const s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = CSS;
  document.head.appendChild(s);
}

function toBytes(b: ArrayBuffer | ArrayBufferView): Uint8Array {
  return b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}

/**
 * Edge/Chromium wrap PlayReady challenges in a UTF-16 XML envelope that also lists the
 * HTTP headers to send. License servers want only the inner SOAP challenge.
 */
export function unwrapPlayReadyMessage(message: ArrayBuffer): { body: Uint8Array; headers: Record<string, string> } {
  const bytes = new Uint8Array(message);
  const xml = new TextDecoder('utf-16le').decode(bytes);
  if (!xml.includes('<PlayReadyKeyMessage')) return { body: bytes, headers: { 'Content-Type': 'text/xml; charset=utf-8' } };
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const challenge = doc.getElementsByTagName('Challenge')[0]?.textContent ?? '';
  const body = Uint8Array.from(atob(challenge.trim()), (c) => c.charCodeAt(0));
  const headers: Record<string, string> = {};
  const list = doc.getElementsByTagName('HttpHeader');
  for (let i = 0; i < list.length; i++) {
    const name = list[i].getElementsByTagName('name')[0]?.textContent;
    const value = list[i].getElementsByTagName('value')[0]?.textContent;
    if (name && value) headers[name] = value;
  }
  return { body, headers };
}

export interface CaptureSafetyIssue {
  element: Element;
  property: string;
  value: string;
}

/**
 * With software DRM (e.g. Widevine L3 in Chrome on Windows), the browser keeps the video out
 * of screenshots only while it can hand the video to the OS as its own protected overlay
 * plane. Effects that force the browser to blend the video into the page instead make it
 * capturable again: opacity < 1, transforms, filters, masks, blend modes and rounded-corner
 * clipping on the video or any ancestor. Hardware DRM paths stay black regardless.
 */
export function findCaptureSafetyIssues(el: Element): CaptureSafetyIssue[] {
  const issues: CaptureSafetyIssue[] = [];
  for (let cur: Element | null = el; cur && cur !== document.documentElement; cur = cur.parentElement) {
    const s = getComputedStyle(cur);
    const add = (property: string, value: string) => issues.push({ element: cur as Element, property, value });
    if (parseFloat(s.opacity) < 1) add('opacity', s.opacity);
    if (s.transform && s.transform !== 'none') add('transform', s.transform);
    if (s.filter && s.filter !== 'none') add('filter', s.filter);
    if (s.clipPath && s.clipPath !== 'none') add('clip-path', s.clipPath);
    const mask = s.maskImage || s.getPropertyValue('-webkit-mask-image');
    if (mask && mask !== 'none') add('mask-image', mask);
    if (s.mixBlendMode && s.mixBlendMode !== 'normal') add('mix-blend-mode', s.mixBlendMode);
    const rounded = ['borderTopLeftRadius', 'borderTopRightRadius', 'borderBottomLeftRadius', 'borderBottomRightRadius'].some(
      (k) => parseFloat(s[k as 'borderTopLeftRadius']) > 0,
    );
    if (rounded && (s.overflow !== 'visible' || cur === el)) add('border-radius', s.borderRadius);
  }
  return issues;
}

/**
 * Plays one protected asset inside a container element. The picture is decrypted and
 * decoded by the browser's DRM module (CDM), so on platforms with protected output the
 * operating system shows black instead of the media in screenshots and recordings.
 */
export class ScreenVeilPlayer extends EventTarget {
  readonly element: HTMLElement;
  readonly video: HTMLVideoElement;
  manifest!: ScreenVeilManifest;
  /** The DRM path in use, once loaded. */
  keySystem?: KeySystemCandidate;

  private readonly opts: ScreenVeilOptions;
  private readonly doFetch: typeof fetch;
  private mediaUrl = '';
  private baseUrl = '';
  private mediaKeys?: MediaKeys;
  private session?: MediaKeySession;
  private mediaSource?: MediaSource;
  private sourceBuffer?: SourceBuffer;
  private appended = new Set<number>();
  private wholeFile?: Uint8Array;
  private destroyed = false;
  private wake?: () => void;
  private cleanups: Array<() => void> = [];
  private fetchAbort = new AbortController();

  constructor(container: HTMLElement, opts: ScreenVeilOptions) {
    super();
    injectStyle();
    this.opts = opts;
    this.doFetch = opts.fetch ?? fetch.bind(globalThis);
    this.element = container;
    container.classList.add('screenveil');
    const v = document.createElement('video');
    v.playsInline = true;
    v.disablePictureInPicture = true;
    v.setAttribute('disableRemotePlayback', '');
    v.setAttribute('controlsList', 'nodownload noplaybackrate noremoteplayback');
    v.style.objectFit = opts.fit ?? 'contain';
    this.video = v;
    container.appendChild(v);
    if (opts.deterrence !== false) this.cleanups.push(applyDeterrence(container, opts.deterrence ?? {}));
  }

  /** Protection level of the active DRM path. */
  get protection(): Protection | undefined {
    return this.keySystem?.protection;
  }

  async load(): Promise<void> {
    try {
      await this.loadManifest();
      const m = this.manifest;
      const isImage = m.kind === 'image';
      const v = this.video;
      v.muted = isImage || !!this.opts.muted;
      v.loop = isImage || !!this.opts.loop;
      v.autoplay = isImage || !!this.opts.autoplay;
      v.controls = !isImage && this.opts.controls !== false;
      if (!this.element.style.aspectRatio && m.width && m.height) this.element.style.aspectRatio = `${m.width} / ${m.height}`;
      if (isImage) v.setAttribute('aria-label', this.element.getAttribute('aria-label') ?? 'Protected image');

      await this.setupDrm();
      await this.setupMediaSource();
      void this.pump();
      if (v.autoplay) {
        v.play().catch(() => {
          /* autoplay may be blocked for unmuted video; the user can press play */
        });
      }
      this.checkCaptureSafety();
      this.dispatchEvent(new CustomEvent('ready', { detail: { keySystem: this.keySystem } }));
    } catch (e) {
      const err = e instanceof ScreenVeilError ? e : new ScreenVeilError('media', String((e as Error)?.message ?? e), e);
      this.fail(err);
      throw err;
    }
  }

  /**
   * Looks for page styles that would let screenshots capture the video on software DRM.
   * Dispatches a `warning` event (detail = issues) and logs once. Returns the issues.
   */
  checkCaptureSafety(): CaptureSafetyIssue[] {
    if (this.keySystem?.protection !== 'software') return [];
    const issues = findCaptureSafetyIssues(this.video);
    if (issues.length) {
      console.warn(
        '[screenveil] These styles let screenshots capture the protected video with software DRM. ' +
          'Remove them from the player and its ancestors:',
        issues.map((i) => `${i.property}: ${i.value}`),
        issues.map((i) => i.element),
      );
      this.dispatchEvent(new CustomEvent('warning', { detail: { code: 'capture-unsafe-styles', issues } }));
    }
    return issues;
  }

  private fail(err: ScreenVeilError) {
    if (this.destroyed) return;
    const msg = document.createElement('div');
    msg.className = 'screenveil-message';
    msg.textContent =
      err.code === 'unsupported'
        ? (this.opts.unsupportedMessage ??
          'This content is protected and needs a browser with DRM support, such as Chrome, Edge, Safari or Firefox.')
        : err.code === 'output-restricted'
          ? 'This content cannot be shown on the current display.'
          : 'This content could not be loaded.';
    this.element.appendChild(msg);
    this.video.removeAttribute('src');
    this.dispatchEvent(new CustomEvent<ScreenVeilErrorDetail>('error', { detail: { code: err.code, message: err.message, cause: err } }));
  }

  private resolve(url: string): string {
    return new URL(url, this.baseUrl).toString();
  }

  private async loadManifest() {
    const src = this.opts.manifest;
    if (typeof src === 'string') {
      this.baseUrl = new URL(src, location.href).toString();
      const res = await this.doFetch(this.baseUrl, { signal: this.fetchAbort.signal }).catch((e) => {
        throw new ScreenVeilError('manifest', `Could not fetch manifest: ${e}`, e);
      });
      if (!res.ok) throw new ScreenVeilError('manifest', `Manifest request failed with HTTP ${res.status}`);
      this.manifest = (await res.json()) as ScreenVeilManifest;
    } else {
      this.baseUrl = new URL(this.opts.baseUrl ?? location.href, location.href).toString();
      this.manifest = src;
    }
    if (this.manifest?.version !== 1) throw new ScreenVeilError('manifest', 'Unsupported manifest version');
    this.mediaUrl = this.resolve(this.manifest.url);
  }

  private endpoints(): Partial<Record<DrmSystem, DrmOverride>> {
    const out: Partial<Record<DrmSystem, DrmOverride>> = {};
    for (const [s, ep] of Object.entries(this.manifest.drm ?? {}) as Array<[DrmSystem, DrmEndpoint]>) out[s] = { ...ep };
    for (const [s, ep] of Object.entries(this.opts.drm ?? {}) as Array<[DrmSystem, DrmOverride]>) out[s] = { ...out[s], ...ep };
    return out;
  }

  private async setupDrm() {
    const eps = this.endpoints();
    const systems = (Object.keys(eps) as DrmSystem[]).filter((s) => eps[s]?.licenseUrl);
    const probe = await probeKeySystems({
      systems,
      videoCodec: this.manifest.videoCodec,
      scheme: this.manifest.scheme,
      minProtection: this.opts.minProtection ?? 'software',
      preferred: this.opts.preferredSystems,
    });
    if (!probe) {
      throw new ScreenVeilError('unsupported', `No supported DRM system among [${systems.join(', ')}] at the required protection level`);
    }
    this.keySystem = probe.candidate;
    const ep = eps[probe.candidate.system] as DrmOverride;
    const mk = await probe.access.createMediaKeys();
    if (probe.candidate.system === 'fairplay') {
      if (!ep.certificateUrl) throw new ScreenVeilError('license', 'FairPlay needs a certificateUrl');
      const res = await this.doFetch(this.resolve(ep.certificateUrl), { headers: await this.authHeaders(ep) });
      if (!res.ok) throw new ScreenVeilError('license', `FairPlay certificate request failed with HTTP ${res.status}`);
      await mk.setServerCertificate(await res.arrayBuffer());
    }
    await this.video.setMediaKeys(mk);
    this.mediaKeys = mk;

    const onEncrypted = (e: MediaEncryptedEvent) => {
      if (this.session || !e.initData) return;
      this.startSession(e.initDataType, e.initData, ep).catch((err) =>
        this.fail(err instanceof ScreenVeilError ? err : new ScreenVeilError('license', String(err), err)),
      );
    };
    this.video.addEventListener('encrypted', onEncrypted);
    this.cleanups.push(() => this.video.removeEventListener('encrypted', onEncrypted));
  }

  private async authHeaders(ep: DrmOverride): Promise<Record<string, string>> {
    const headers: Record<string, string> = { ...ep.headers };
    const t = this.opts.token;
    const token = typeof t === 'function' ? await t() : t;
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }

  private async startSession(initDataType: string, initData: ArrayBuffer, ep: DrmOverride) {
    const mk = this.mediaKeys as MediaKeys;
    const session = mk.createSession('temporary');
    this.session = session;
    const system = this.keySystem?.system;
    const licenseUrl = this.resolve(ep.licenseUrl as string);

    session.addEventListener('message', (ev) => {
      const e = ev as MediaKeyMessageEvent;
      void (async () => {
        try {
          let body: Uint8Array = toBytes(e.message);
          let headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' };
          if (system === 'playready') ({ body, headers } = unwrapPlayReadyMessage(e.message));
          else if (system === 'clearkey') headers = { 'Content-Type': 'application/json' };
          const res = await this.doFetch(licenseUrl, {
            method: 'POST',
            body: body as BodyInit,
            headers: { ...headers, ...(await this.authHeaders(ep)) },
          });
          if (!res.ok) throw new ScreenVeilError('license', `License request failed with HTTP ${res.status}`);
          await session.update(await res.arrayBuffer());
        } catch (err) {
          this.fail(err instanceof ScreenVeilError ? err : new ScreenVeilError('license', String(err), err));
        }
      })();
    });
    session.addEventListener('keystatuseschange', () => {
      session.keyStatuses.forEach((status) => {
        if (status === 'output-restricted' || status === 'output-downscaled') {
          this.fail(new ScreenVeilError('output-restricted', `Key status: ${status}`));
        } else if (status === 'internal-error' || status === 'expired') {
          this.fail(new ScreenVeilError('license', `Key status: ${status}`));
        }
      });
    });
    await session.generateRequest(initDataType, initData);
  }

  private async setupMediaSource() {
    const MS: typeof MediaSource | undefined =
      (globalThis as { ManagedMediaSource?: typeof MediaSource }).ManagedMediaSource ?? globalThis.MediaSource;
    if (!MS || !MS.isTypeSupported(this.manifest.mimeType)) {
      throw new ScreenVeilError('unsupported', `MediaSource does not support ${this.manifest.mimeType}`);
    }
    const ms = new MS();
    this.mediaSource = ms;
    const url = URL.createObjectURL(ms);
    this.video.disableRemotePlayback = true;
    this.video.src = url;
    this.cleanups.push(() => URL.revokeObjectURL(url));
    await new Promise<void>((resolve) => ms.addEventListener('sourceopen', () => resolve(), { once: true }));
    const sb = ms.addSourceBuffer(this.manifest.mimeType);
    this.sourceBuffer = sb;
    await this.append(await this.fetchRange(this.manifest.init.start, this.manifest.init.end));
    if (this.manifest.duration > 0) ms.duration = this.manifest.duration;

    const wake = () => this.wake?.();
    for (const ev of ['timeupdate', 'seeking', 'play', 'waiting']) {
      this.video.addEventListener(ev, wake);
      this.cleanups.push(() => this.video.removeEventListener(ev, wake));
    }
  }

  private async fetchRange(start: number, end: number): Promise<Uint8Array> {
    if (this.wholeFile) return this.wholeFile.subarray(start, end);
    const res = await this.doFetch(this.mediaUrl, {
      headers: { Range: `bytes=${start}-${end - 1}` },
      signal: this.fetchAbort.signal,
    });
    if (res.status === 206) return new Uint8Array(await res.arrayBuffer());
    if (res.ok) {
      // Server ignored the Range header; keep the whole file and slice locally.
      this.wholeFile = new Uint8Array(await res.arrayBuffer());
      return this.wholeFile.subarray(start, end);
    }
    throw new ScreenVeilError('media', `Media request failed with HTTP ${res.status}`);
  }

  private append(data: Uint8Array): Promise<void> {
    const sb = this.sourceBuffer as SourceBuffer;
    return new Promise((resolve, reject) => {
      const done = () => {
        sb.removeEventListener('updateend', done);
        sb.removeEventListener('error', fail);
        resolve();
      };
      const fail = () => {
        sb.removeEventListener('updateend', done);
        sb.removeEventListener('error', fail);
        reject(new ScreenVeilError('media', 'SourceBuffer append failed'));
      };
      sb.addEventListener('updateend', done);
      sb.addEventListener('error', fail);
      sb.appendBuffer(data as BufferSource);
    });
  }

  private remove(start: number, end: number): Promise<void> {
    const sb = this.sourceBuffer as SourceBuffer;
    return new Promise((resolve) => {
      sb.addEventListener('updateend', () => resolve(), { once: true });
      sb.remove(start, end);
    });
  }

  /** Streams segments around the playhead, evicting old ones. */
  private async pump() {
    const segs = this.manifest.segments;
    const ahead = this.opts.bufferAhead ?? 30;
    const behind = this.opts.bufferBehind ?? 30;
    while (!this.destroyed) {
      const t = this.video.currentTime;
      const next = segs.findIndex(
        (s, i) => !this.appended.has(i) && s.time + s.duration > t - 0.1 && s.time < t + ahead,
      );
      if (next !== -1) {
        try {
          const s = segs[next];
          const data = await this.fetchRange(s.start, s.end);
          if (this.destroyed) return;
          if (this.mediaSource?.readyState === 'ended' && this.mediaSource.duration < this.manifest.duration) {
            this.mediaSource.duration = this.manifest.duration;
          }
          await this.appendWithEviction(data, t, behind);
          this.appended.add(next);
        } catch (e) {
          if (this.destroyed) return;
          this.fail(e instanceof ScreenVeilError ? e : new ScreenVeilError('media', String(e), e));
          return;
        }
        continue;
      }
      if (this.appended.size === segs.length && this.mediaSource?.readyState === 'open') {
        try {
          this.mediaSource.endOfStream();
        } catch {
          /* already ended */
        }
      }
      await new Promise<void>((r) => {
        this.wake = r;
        setTimeout(r, 1000);
      });
    }
  }

  private async appendWithEviction(data: Uint8Array, t: number, behind: number) {
    try {
      await this.append(data);
    } catch (e) {
      // QuotaExceeded or similar: drop old data behind the playhead and retry once.
      const cut = Math.max(0, t - 2);
      if (cut <= 0) throw e;
      await this.remove(0, cut);
      this.forgetBefore(cut);
      await this.append(data);
      return;
    }
    if (t - behind > 0) {
      const sb = this.sourceBuffer as SourceBuffer;
      if (sb.buffered.length && sb.buffered.start(0) < t - behind) {
        await this.remove(0, t - behind);
        this.forgetBefore(t - behind);
      }
    }
  }

  private forgetBefore(cut: number) {
    this.manifest.segments.forEach((s, i) => {
      if (s.time + s.duration <= cut) this.appended.delete(i);
    });
  }

  /** Stop playback, release DRM sessions and remove the video element. */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.fetchAbort.abort();
    this.wake?.();
    this.cleanups.forEach((c) => c());
    this.session?.close().catch(() => undefined);
    this.video.pause();
    this.video.removeAttribute('src');
    this.video.load();
    this.video.remove();
    this.element.querySelectorAll('.screenveil-message').forEach((n) => n.remove());
    this.element.classList.remove('screenveil');
  }
}

/**
 * Protect an image or video. `target` is a container element (or selector). If it is an
 * <img> or <video>, it is replaced by a container with the same classes and size.
 *
 * ```js
 * const player = await protect('#photo', { manifest: '/api/assets/abc/manifest.json', token });
 * ```
 */
export async function protect(target: HTMLElement | string, options: ScreenVeilOptions): Promise<ScreenVeilPlayer> {
  let el = typeof target === 'string' ? document.querySelector<HTMLElement>(target) : target;
  if (!el) throw new ScreenVeilError('media', `protect(): no element matches ${String(target)}`);
  if (el instanceof HTMLImageElement || el instanceof HTMLVideoElement) {
    const box = document.createElement('div');
    box.className = el.className;
    box.style.cssText = el.style.cssText;
    const w = el.getAttribute('width');
    const h = el.getAttribute('height');
    if (w) box.style.width = /^\d+$/.test(w) ? `${w}px` : w;
    if (h) box.style.height = /^\d+$/.test(h) ? `${h}px` : h;
    if (el instanceof HTMLImageElement) {
      box.setAttribute('role', 'img');
      box.setAttribute('aria-label', el.getAttribute('alt') ?? 'Protected image');
    }
    el.replaceWith(box);
    el = box;
  }
  const player = new ScreenVeilPlayer(el, options);
  await player.load();
  return player;
}
