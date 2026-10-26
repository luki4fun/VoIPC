// Colour palettes, and the one place that writes them to the document.
//
// Everything visual in the app is already drawn from CSS custom properties
// declared in app.css `:root`. A palette is therefore nothing more than a new
// set of values for those properties, and switching one is a loop over
// `setProperty`. app.css keeps the dark values as its defaults, so the app
// renders correctly before this module has run and if it never runs at all.
//
// Pure module on purpose — no stores, no invoke, no Svelte. It is imported by
// theme.test.ts under Node's own test runner, which has neither.

/** A custom property this module owns. Sizing tokens are not palette. */
import { rememberTheme } from "./theme-cache.ts";

export type TokenName =
  | "--bg-primary"
  | "--bg-secondary"
  | "--bg-tertiary"
  | "--bg-hover"
  | "--text-primary"
  | "--text-secondary"
  | "--accent"
  | "--accent-hover"
  | "--success"
  | "--danger"
  | "--warning"
  | "--border"
  | "--speaking"
  | "--well"
  | "--scrollbar"
  | "--shadow-menu"
  | "--shadow-dialog"
  | "--on-accent"
  | "--on-danger"
  | "--on-success"
  | "--on-warning"
  | "--text-muted"
  | "--scrim"
  | "--focus-ring";

/** Every token a palette must define. A palette missing one is a type error. */
export const TOKENS: readonly TokenName[] = [
  "--bg-primary",
  "--bg-secondary",
  "--bg-tertiary",
  "--bg-hover",
  "--text-primary",
  "--text-secondary",
  "--accent",
  "--accent-hover",
  "--success",
  "--danger",
  "--warning",
  "--border",
  "--speaking",
  "--well",
  "--scrollbar",
  "--shadow-menu",
  "--shadow-dialog",
  "--on-accent",
  "--on-danger",
  "--on-success",
  "--on-warning",
  "--text-muted",
  "--scrim",
  "--focus-ring",
];

export interface Palette {
  id: string;
  label: string;
  /** Drives the `data-theme` attribute, for the few rules a token cannot express. */
  dark: boolean;
  tokens: Record<TokenName, string>;
}

/**
 * The palettes this build ships.
 *
 * `voipc-night` and `voipc-day` are VoIPC's own (2026-10-26), taken from the
 * logo: a mint shield on charcoal. Mint means *live* — the speaking ring, the
 * talk button, a live share, the connected state and the primary action — so
 * a selected row is a raised neutral, never the accent, and a selected row
 * never competes with a face that is talking. Flat mint: no glow, no neon edge.
 *
 * `voipc-dark` ("Navy") is the app as it looked before palettes existed; app.css
 * carries `voipc-night`'s values as its fallbacks now. The Slate pair is the
 * neutral-grey arrangement 0.8.0 made the default; installs that already have
 * one of these stored keep it (the 1.x rule: a choice is never overwritten).
 */
export const PALETTES: readonly Palette[] = [
  {
    id: "voipc-night",
    label: "VoIPC night",
    dark: true,
    tokens: {
      // Charcoal with a little blue in it, the logo's ground. The chat is the
      // lighter surface and the sidebars sit behind it.
      "--bg-primary": "#1c1f24",
      "--bg-secondary": "#16181d",
      "--bg-tertiary": "#0f1114",
      "--bg-hover": "#262a31",
      "--text-primary": "#e3e6ea",
      "--text-secondary": "#a3aab4",
      "--accent": "#3ddbb0",
      "--accent-hover": "#5fe6c2",
      // Success is live too: connected, an active toggle, a share going out
      "--success": "#3ddbb0",
      "--danger": "#f2555a",
      "--warning": "#f2b84b",
      "--border": "#2a2e36",
      "--speaking": "#3ddbb0",
      "--well": "rgba(0, 0, 0, 0.2)",
      "--scrollbar": "#2f343c",
      "--shadow-menu": "0 8px 24px rgba(0, 0, 0, 0.45)",
      "--shadow-dialog": "0 12px 40px rgba(0, 0, 0, 0.55)",
      // Mint is light, so what sits on it is a deep green-black, not white
      "--on-accent": "#06231b",
      "--on-danger": "#0b0d12",
      "--on-success": "#06231b",
      "--on-warning": "#0b0d12",
      "--text-muted": "#8b939e",
      "--scrim": "rgba(0, 0, 0, 0.55)",
      "--focus-ring": "#3ddbb0",
    },
  },
  {
    id: "voipc-day",
    label: "VoIPC day",
    dark: false,
    tokens: {
      "--bg-primary": "#ffffff",
      "--bg-secondary": "#f3f5f6",
      "--bg-tertiary": "#e6eaec",
      "--bg-hover": "#e9edef",
      "--text-primary": "#0e1114",
      "--text-secondary": "#4b5560",
      // The logo's mint does not read on white (1.6:1); this is the same hue
      // taken down until white text sits on it and it reads as text itself.
      "--accent": "#0b7a5f",
      "--accent-hover": "#096a52",
      "--success": "#0b7a5f",
      "--danger": "#c8323a",
      "--warning": "#9a6200",
      "--border": "#d9dee2",
      "--speaking": "#0b7a5f",
      "--well": "rgba(0, 0, 0, 0.05)",
      "--scrollbar": "#c3cad0",
      "--shadow-menu": "0 8px 16px rgba(0, 0, 0, 0.12)",
      "--shadow-dialog": "0 12px 32px rgba(0, 0, 0, 0.18)",
      "--on-accent": "#ffffff",
      "--on-danger": "#ffffff",
      "--on-success": "#ffffff",
      "--on-warning": "#ffffff",
      "--text-muted": "#5f6873",
      "--scrim": "rgba(15, 20, 25, 0.4)",
      "--focus-ring": "#0b7a5f",
    },
  },
  {
    id: "voipc-dark",
    label: "Navy",
    dark: true,
    tokens: {
      "--bg-primary": "#1a1a2e",
      "--bg-secondary": "#16213e",
      "--bg-tertiary": "#0f3460",
      "--bg-hover": "#1a3a6e",
      "--text-primary": "#e0e0e0",
      "--text-secondary": "#a0a0a0",
      "--accent": "#4a9eff",
      "--accent-hover": "#3a8eef",
      "--success": "#4caf50",
      "--danger": "#e74c3c",
      "--warning": "#f39c12",
      "--border": "#2a2a4a",
      "--speaking": "#4caf50",
      "--well": "rgba(0, 0, 0, 0.15)",
      "--scrollbar": "#2a2a4a",
      "--shadow-menu": "0 8px 24px rgba(0, 0, 0, 0.4)",
      "--shadow-dialog": "0 8px 32px rgba(0, 0, 0, 0.5)",
      // What sits on a filled control. White where it clears 4.5:1 on the fill,
      // a near-black ink where it does not (theme.test.ts checks each pair).
      "--on-accent": "#0b0d12",
      "--on-danger": "#0b0d12",
      "--on-success": "#0b0d12",
      "--on-warning": "#0b0d12",
      "--text-muted": "#8a8a96",
      "--scrim": "rgba(0, 0, 0, 0.5)",
      "--focus-ring": "#4a9eff",
    },
  },
  {
    id: "slate-dark",
    label: "Slate dark",
    dark: true,
    tokens: {
      // Greys in the arrangement the chat apps most people come from use: the
      // chat area is the lighter surface and the sidebars sit behind it, which
      // is the other way round from the VoIPC palette and the whole reason this
      // one feels different.
      "--bg-primary": "#313338",
      "--bg-secondary": "#2b2d31",
      "--bg-tertiary": "#1e1f22",
      "--bg-hover": "#404249",
      "--text-primary": "#dbdee1",
      // Discord's "interactive normal", not its muted grey. The muted one is
      // 4.5:1 on the chat background to two decimal places, and this token
      // carries real reading text here — channel descriptions, the status bar.
      "--text-secondary": "#b5bac1",
      // Not #5865f2. Discord's blurple is a *fill* colour — it is what a button
      // is, with white on top — and as text on these greys it measures 2.99:1,
      // which is why Discord's own links in dark mode are blue rather than
      // blurple. This app has one accent token for both jobs, so it takes the
      // lighter blurple: still unmistakably the brand, and readable.
      "--accent": "#7983f5",
      "--accent-hover": "#949cf7",
      "--success": "#23a559",
      "--danger": "#da373c",
      "--warning": "#f0b232",
      "--border": "#3f4147",
      "--speaking": "#23a559",
      "--well": "rgba(0, 0, 0, 0.2)",
      "--scrollbar": "#1a1b1e",
      "--shadow-menu": "0 8px 16px rgba(0, 0, 0, 0.24)",
      "--shadow-dialog": "0 8px 32px rgba(0, 0, 0, 0.32)",
      "--on-accent": "#0b0d12",
      "--on-danger": "#ffffff",
      "--on-success": "#0b0d12",
      "--on-warning": "#0b0d12",
      "--text-muted": "#9ba1aa",
      "--scrim": "rgba(0, 0, 0, 0.5)",
      "--focus-ring": "#7983f5",
    },
  },
  {
    id: "slate-light",
    label: "Slate light",
    dark: false,
    tokens: {
      "--bg-primary": "#ffffff",
      "--bg-secondary": "#f2f3f5",
      "--bg-tertiary": "#e3e5e8",
      "--bg-hover": "#ebedef",
      "--text-primary": "#060607",
      "--text-secondary": "#4e5058",
      "--accent": "#5865f2",
      "--accent-hover": "#4752c4",
      // Darker than the dark theme's: the same green and amber on white are
      // under 3:1, and these are status colours people read.
      "--success": "#248046",
      "--danger": "#d83c3e",
      "--warning": "#b26d0a",
      "--border": "#dcdee1",
      "--speaking": "#248046",
      "--well": "rgba(0, 0, 0, 0.06)",
      "--scrollbar": "#c4c9ce",
      "--shadow-menu": "0 8px 16px rgba(0, 0, 0, 0.1)",
      "--shadow-dialog": "0 8px 32px rgba(0, 0, 0, 0.16)",
      "--on-accent": "#ffffff",
      "--on-danger": "#ffffff",
      "--on-success": "#ffffff",
      "--on-warning": "#0b0d12",
      "--text-muted": "#686a72",
      "--scrim": "rgba(0, 0, 0, 0.32)",
      "--focus-ring": "#5865f2",
    },
  },
  {
    id: "amoled",
    label: "AMOLED black",
    dark: true,
    tokens: {
      // True black, which on an OLED phone is a pixel that is off. The point is
      // battery and glare, so the surfaces stay nearly black rather than
      // stepping up into grey the way an ordinary dark theme does.
      "--bg-primary": "#000000",
      "--bg-secondary": "#0a0a0a",
      "--bg-tertiary": "#141414",
      "--bg-hover": "#1f1f1f",
      "--text-primary": "#e6e6e6",
      "--text-secondary": "#9a9a9a",
      "--accent": "#5865f2",
      "--accent-hover": "#4752c4",
      "--success": "#23a559",
      "--danger": "#da373c",
      "--warning": "#f0b232",
      "--border": "#262626",
      "--speaking": "#23a559",
      "--well": "rgba(255, 255, 255, 0.05)",
      "--scrollbar": "#2e2e2e",
      "--shadow-menu": "0 8px 16px rgba(0, 0, 0, 0.7)",
      "--shadow-dialog": "0 8px 32px rgba(0, 0, 0, 0.8)",
      "--on-accent": "#ffffff",
      "--on-danger": "#ffffff",
      "--on-success": "#0b0d12",
      "--on-warning": "#0b0d12",
      "--text-muted": "#7c7c7c",
      "--scrim": "rgba(0, 0, 0, 0.6)",
      "--focus-ring": "#5865f2",
    },
  },
];

/**
 * The palette a client uses when nobody has chosen one.
 *
 * Dark, because that is what the app is for most of the day and what every
 * screenshot shows. `systemDefaultPaletteId()` picks the light twin when the
 * machine says it prefers light; this is the answer where there is no machine
 * to ask, which includes the Node test runner.
 */
export const DEFAULT_PALETTE_ID = "voipc-night";

/** The light palette that pairs with the default. */
export const DEFAULT_LIGHT_PALETTE_ID = "voipc-day";

/**
 * The palette to start in on this machine, before anybody has chosen.
 *
 * Follows the operating system's own light/dark setting, which is what a
 * browser reports through `prefers-color-scheme` and what Android and Windows
 * pass through to a WebView. Only consulted when nothing is stored: a palette
 * somebody picked is theirs, and the OS does not get to change it afterwards.
 */
export function systemDefaultPaletteId(): string {
  if (typeof globalThis.matchMedia !== "function") return DEFAULT_PALETTE_ID;
  try {
    return globalThis.matchMedia("(prefers-color-scheme: light)").matches
      ? DEFAULT_LIGHT_PALETTE_ID
      : DEFAULT_PALETTE_ID;
  } catch {
    return DEFAULT_PALETTE_ID;
  }
}

/**
 * Palettes that have been renamed, old id to new.
 *
 * A palette id is stored, and `paletteById` falls back to the default for one
 * it does not know — so without this a rename would silently repaint the app of
 * everybody who had chosen that palette.
 */
const RENAMED_PALETTES: Record<string, string> = {
  __proto__: null,
  "discord-dark": "slate-dark",
  "discord-light": "slate-light",
} as unknown as Record<string, string>;

/**
 * A stored palette id under the name this build knows it by.
 *
 * Null-prototype, because the id comes off disk — in the browser, out of
 * localStorage, which the file above notes anyone with devtools is a writer of.
 * A plain object literal would answer `migratePaletteId("toString")` with a
 * function, and that would be written back as somebody's palette.
 */
export function migratePaletteId(id: string): string {
  const renamed = RENAMED_PALETTES[id];
  return typeof renamed === "string" ? renamed : id;
}

/** The palette with that id, or the default. An id from a newer build lands here. */
export function paletteById(id: string): Palette {
  return (
    PALETTES.find((p) => p.id === id) ??
    PALETTES.find((p) => p.id === DEFAULT_PALETTE_ID)!
  );
}

/**
 * A palette's values with the user's own colours laid over them.
 *
 * Overrides naming a token this build does not have are dropped rather than
 * passed through: they would be written to the document as-is, and a typo in a
 * hand-edited settings.json should not end up as a live custom property.
 */
export function resolveTokens(
  paletteId: string,
  overrides: Partial<Record<TokenName, string>> = {},
): Record<TokenName, string> {
  const base = { ...paletteById(paletteId).tokens };
  for (const token of TOKENS) {
    const value = overrides[token];
    if (typeof value === "string" && value.trim() !== "") base[token] = value;
  }
  return base;
}

/**
 * The only thing in the app that writes palette values to the DOM.
 *
 * On `documentElement`, not on the app's own root element: `body` and `#app`
 * read `--bg-primary` (app.css) and both sit outside App.svelte's markup, so a
 * class further down could not reach them.
 *
 * `data-theme` exists for the handful of rules that cannot be expressed as a
 * token swap — the `select` chevron, which is an inlined SVG data URL and so
 * cannot read a variable. Keep that list short and keep it in app.css.
 */
export function applyTheme(tokens: Record<TokenName, string>, dark: boolean): void {
  if (typeof document === "undefined") return; // Node test runner, no DOM
  const root = document.documentElement;
  for (const token of TOKENS) root.style.setProperty(token, tokens[token]);
  root.dataset.theme = dark ? "dark" : "light";
  rememberTheme(tokens, dark);

  // What colours the Android status bar and the browser's own chrome. Harmless
  // where there is no such chrome.
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", tokens["--bg-primary"]);

  // On Android the window is edge to edge and this page paints its own
  // background into the status- and navigation-bar strips, so the icons in
  // them are the only part the system still draws. Dark icons for a light
  // palette, or they are invisible. The bridge exists only in the Android
  // app; everywhere else this is a no-op.
  const bridge = (globalThis as { __VoIPC?: { setSystemBarsLight?: (light: boolean) => void } }).__VoIPC;
  try {
    bridge?.setSystemBarsLight?.(!dark);
  } catch {
    // An older app shell without this method must not cost the palette change
  }
}

// ── Contrast ───────────────────────────────────────────────────────────────
//
// A palette that ships unreadable is a bug nobody files, they just stop using
// the app. theme.test.ts holds every shipped palette to WCAG AA on the pairs
// below, so an unreadable one cannot be merged.

/** `#rgb`, `#rrggbb` or `rgb()/rgba()` to 0-255 channels. null if unparseable. */
export function parseColor(value: string): [number, number, number] | null {
  const hex = value.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hex) {
    const h = hex[1];
    const full =
      h.length === 3 ? h.split("").map((c) => c + c).join("") : h;
    return [
      parseInt(full.slice(0, 2), 16),
      parseInt(full.slice(2, 4), 16),
      parseInt(full.slice(4, 6), 16),
    ];
  }
  const rgb = value.trim().match(/^rgba?\(([^)]+)\)$/i);
  if (rgb) {
    const parts = rgb[1].split(/[,\s/]+/).filter(Boolean).slice(0, 3).map(Number);
    if (parts.length === 3 && parts.every((n) => Number.isFinite(n))) {
      return [parts[0], parts[1], parts[2]];
    }
  }
  return null;
}

/** WCAG relative luminance. */
function luminance([r, g, b]: [number, number, number]): number {
  const lin = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** WCAG contrast ratio, 1 (identical) to 21 (black on white). 0 if unparseable. */
export function contrastRatio(a: string, b: string): number {
  const ca = parseColor(a);
  const cb = parseColor(b);
  if (!ca || !cb) return 0;
  const la = luminance(ca);
  const lb = luminance(cb);
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

/**
 * Foreground/background pairs that actually occur in the UI, with the minimum
 * ratio each has to clear. Secondary text is body text at 11-13px, so it is
 * held to 4.5 like everything else rather than the 3.0 that large text gets.
 */
export const CONTRAST_PAIRS: readonly {
  fg: TokenName;
  bg: TokenName;
  min: number;
  where: string;
}[] = [
  { fg: "--text-primary", bg: "--bg-primary", min: 4.5, where: "titlebar, body" },
  { fg: "--text-primary", bg: "--bg-secondary", min: 4.5, where: "sidebars, panels" },
  { fg: "--text-primary", bg: "--bg-tertiary", min: 4.5, where: "inputs, icon buttons" },
  { fg: "--text-primary", bg: "--bg-hover", min: 4.5, where: "a hovered row" },
  { fg: "--text-secondary", bg: "--bg-primary", min: 4.5, where: "status bar" },
  { fg: "--text-secondary", bg: "--bg-secondary", min: 4.5, where: "channel descriptions" },
  { fg: "--accent", bg: "--bg-secondary", min: 3.0, where: "links, active channel" },
  // Status words in colour: "Live", "Sharing", a reconnecting badge (H5-05)
  { fg: "--success", bg: "--bg-secondary", min: 3.0, where: "a live or sharing status" },
  { fg: "--warning", bg: "--bg-secondary", min: 3.0, where: "a warning status" },
  // Text on a filled control: a primary button, a danger button, a badge, the
  // talk button while it is held. Body-size text, so 4.5 — white on most of
  // these fills does not make it, which is why the ink is a token at all.
  { fg: "--on-accent", bg: "--accent", min: 4.5, where: "primary buttons" },
  { fg: "--on-danger", bg: "--danger", min: 4.5, where: "danger buttons, unread badges" },
  { fg: "--on-success", bg: "--success", min: 4.5, where: "an active toggle" },
  { fg: "--on-success", bg: "--speaking", min: 4.5, where: "the talk button while held" },
  { fg: "--on-warning", bg: "--warning", min: 4.5, where: "a warning badge" },
  // The dimmed text that used to be secondary text at 45-70% opacity: a left
  // channel, an out-of-earshot member. Dimmer, but still readable.
  { fg: "--text-muted", bg: "--bg-primary", min: 4.5, where: "dimmed text in the chat" },
  { fg: "--text-muted", bg: "--bg-secondary", min: 4.5, where: "dimmed rows in the sidebars" },
  // A focus ring is a non-text indicator: 3:1 against what it sits on (WCAG 1.4.11)
  { fg: "--focus-ring", bg: "--bg-primary", min: 3.0, where: "keyboard focus in the chat" },
  { fg: "--focus-ring", bg: "--bg-secondary", min: 3.0, where: "keyboard focus in the sidebars" },
  // Not a WCAG figure: a divider is not text. 1.1 is simply "visible at all",
  // and it is the floor today's dark palette sits just above (#2a2a4a on
  // #16213e is 1.15). It exists so a palette cannot ship with borders that
  // have vanished into their panel.
  { fg: "--border", bg: "--bg-secondary", min: 1.1, where: "panel dividers" },
];
