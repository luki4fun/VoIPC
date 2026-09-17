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
  | "--shadow-dialog";

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
 * `voipc-dark` is the app as it has always looked: these are the exact values
 * from app.css, and the first release to carry this module ships only this one,
 * so nothing anybody sees changes.
 */
export const PALETTES: readonly Palette[] = [
  {
    id: "voipc-dark",
    label: "VoIPC dark",
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
    },
  },
  {
    id: "discord-dark",
    label: "Discord dark",
    dark: true,
    tokens: {
      // Discord's own greys, in this app's roles: the chat area is the lighter
      // surface and the sidebars sit behind it, which is the other way round
      // from the VoIPC palette and the main reason this reads as Discord.
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
    },
  },
  {
    id: "discord-light",
    label: "Discord light",
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
    },
  },
];

export const DEFAULT_PALETTE_ID = "voipc-dark";

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

  // What colours the Android status bar and the browser's own chrome. Harmless
  // where there is no such chrome.
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", tokens["--bg-primary"]);
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
  // Not a WCAG figure: a divider is not text. 1.1 is simply "visible at all",
  // and it is the floor today's dark palette sits just above (#2a2a4a on
  // #16213e is 1.15). It exists so a palette cannot ship with borders that
  // have vanished into their panel.
  { fg: "--border", bg: "--bg-secondary", min: 1.1, where: "panel dividers" },
];
