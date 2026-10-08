/**
 * Optional extras that make casual copying harder. None of these are DRM: the screenshot
 * blocking comes from the DRM-protected video surface. These cover the gaps around it
 * (right-click "save as", dragging, camera photos of the screen via a visible watermark).
 *
 * Note: never use CSS filters or blend modes over the protected video. The browser cannot
 * read protected pixels, so effects that need them can make the video itself go black.
 */
export interface DeterrenceOptions {
  /** Block the context menu and dragging on the media. Default true. */
  blockContextMenu?: boolean;
  /** Text tiled over the media, e.g. the viewer's e-mail, to trace leaks from phone photos. */
  watermark?: string;
  /** Hide the media while the page is hidden or the window loses focus. Default false. */
  hideOnBlur?: boolean;
}

export function applyDeterrence(wrapper: HTMLElement, opts: DeterrenceOptions): () => void {
  const cleanups: Array<() => void> = [];
  const on = <K extends keyof HTMLElementEventMap>(el: HTMLElement | Window | Document, type: K | string, fn: EventListener) => {
    el.addEventListener(type, fn);
    cleanups.push(() => el.removeEventListener(type, fn));
  };

  wrapper.style.userSelect = 'none';
  wrapper.style.setProperty('-webkit-user-select', 'none');
  wrapper.style.setProperty('-webkit-touch-callout', 'none');

  if (opts.blockContextMenu !== false) {
    const stop: EventListener = (e) => e.preventDefault();
    on(wrapper, 'contextmenu', stop);
    on(wrapper, 'dragstart', stop);
  }

  if (opts.watermark) {
    const mark = document.createElement('div');
    mark.setAttribute('aria-hidden', 'true');
    mark.className = 'screenveil-watermark';
    const text = opts.watermark.replace(/[<>&]/g, '');
    const svg =
      `<svg xmlns="http://www.w3.org/2000/svg" width="260" height="140">` +
      `<text x="0" y="90" transform="rotate(-24 130 70)" fill="white" fill-opacity="0.28" stroke="black" stroke-opacity="0.25" stroke-width="0.6" ` +
      `font-family="sans-serif" font-size="16">${text}</text></svg>`;
    Object.assign(mark.style, {
      position: 'absolute',
      inset: '0',
      pointerEvents: 'none',
      backgroundImage: `url("data:image/svg+xml;utf8,${encodeURIComponent(svg)}")`,
      zIndex: '2',
    });
    wrapper.appendChild(mark);
    cleanups.push(() => mark.remove());
  }

  if (opts.hideOnBlur) {
    const set = (hidden: boolean) => wrapper.classList.toggle('screenveil-hidden', hidden);
    on(window, 'blur', () => set(true));
    on(window, 'focus', () => set(false));
    on(document, 'visibilitychange', () => set(document.visibilityState === 'hidden'));
  }

  return () => cleanups.forEach((c) => c());
}
