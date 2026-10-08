// Entry for the <script> tag build: exposes window.ScreenVeil and registers <screenveil-media>.
import * as ScreenVeil from './index.ts';

ScreenVeil.defineElement();
(globalThis as unknown as { ScreenVeil: typeof ScreenVeil }).ScreenVeil = ScreenVeil;
