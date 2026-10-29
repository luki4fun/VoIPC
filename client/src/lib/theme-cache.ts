// The last palette a window painted, kept so the next start paints it at once.
//
// The real palette arrives with `load_config`, a round trip after the page has
// already drawn itself in app.css's defaults (VoIPC night): somebody on Navy or
// a light palette saw a charcoal page first, every start. This is a cache and
// nothing more — never a preference: the stored one replaces it moments later,
// and a missing or damaged entry only means the defaults show, as before.

import { TOKENS } from "./theme-tokens.ts";

const KEY = "voipc.theme-cache";
/** Only these are painted: a remembered `--hit` or `--z-modal` would outlive
 *  the real palette, which rewrites only these, for the whole session. */
const PALETTE: ReadonlySet<string> = new Set(TOKENS);

interface Cached {
  tokens: Record<string, string>;
  dark: boolean;
}

/** Remember what applyTheme just painted. */
export function rememberTheme(tokens: Record<string, string>, dark: boolean): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ tokens, dark } satisfies Cached));
  } catch {
    // Storage off or full: the next start shows the defaults first, as before
  }
}

/** Paint the remembered palette before anything else has loaded. */
export function paintRememberedTheme(): void {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return;
    const cached = JSON.parse(raw) as Partial<Cached>;
    if (!cached || typeof cached.tokens !== "object" || cached.tokens === null) return;
    const root = document.documentElement;
    for (const [name, value] of Object.entries(cached.tokens)) {
      // Palette token names and plain colour values only: this came off disk
      if (PALETTE.has(name) && typeof value === "string" && /^[#(),.%\w\s-]+$/.test(value)) {
        root.style.setProperty(name, value);
      }
    }
    root.dataset.theme = cached.dark === false ? "light" : "dark";
  } catch {
    // Unreadable: the defaults paint, as before
  }
}
