import type { Protection } from './keysystems.ts';
import { ScreenVeilPlayer } from './player.ts';

/**
 * `<screenveil-media manifest="/api/assets/abc/manifest.json" token="…"></screenveil-media>`
 *
 * Attributes: manifest (required), token, min-protection, fit, controls, autoplay, muted,
 * loop, watermark. Events: `ready`, `error` (detail = { code, message }).
 */
// Importing this module during server-side rendering must not throw.
const Base = (typeof HTMLElement === 'undefined' ? class {} : HTMLElement) as typeof HTMLElement;

export class ScreenVeilMediaElement extends Base {
  static observedAttributes = ['manifest', 'token'];
  player?: ScreenVeilPlayer;
  private connected = false;

  connectedCallback() {
    this.connected = true;
    if (!this.style.display) this.style.display = 'inline-block';
    this.start();
  }

  disconnectedCallback() {
    this.connected = false;
    this.player?.destroy();
    this.player = undefined;
  }

  attributeChangedCallback(_name: string, oldValue: string | null, newValue: string | null) {
    if (this.connected && oldValue !== newValue) this.start();
  }

  private flag(name: string): boolean | undefined {
    if (!this.hasAttribute(name)) return undefined;
    return this.getAttribute(name) !== 'false';
  }

  private start() {
    const manifest = this.getAttribute('manifest');
    this.player?.destroy();
    this.player = undefined;
    if (!manifest) return;
    const watermark = this.getAttribute('watermark') ?? undefined;
    const player = new ScreenVeilPlayer(this, {
      manifest,
      token: this.getAttribute('token') ?? undefined,
      minProtection: (this.getAttribute('min-protection') as Protection | null) ?? undefined,
      fit: (this.getAttribute('fit') as 'contain' | 'cover' | 'fill' | null) ?? undefined,
      controls: this.flag('controls'),
      autoplay: this.flag('autoplay'),
      muted: this.flag('muted'),
      loop: this.flag('loop'),
      deterrence: { watermark },
    });
    this.player = player;
    player.addEventListener('ready', (e) => this.dispatchEvent(new CustomEvent('ready', { detail: (e as CustomEvent).detail })));
    player.addEventListener('error', (e) => this.dispatchEvent(new CustomEvent('error', { detail: (e as CustomEvent).detail })));
    player.load().catch(() => {
      /* surfaced through the error event */
    });
  }
}

/** Register `<screenveil-media>` (safe to call more than once). */
export function defineElement(tag = 'screenveil-media'): void {
  if (typeof customElements !== 'undefined' && !customElements.get(tag)) {
    customElements.define(tag, class extends ScreenVeilMediaElement {});
  }
}
