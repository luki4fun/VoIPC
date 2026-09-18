// The live appearance preferences, and the only writer of `set_ui_prefs`.
//
// The validation, the defaults and the shape live in lib/ui-prefs.ts, which is
// pure so it can be tested; this file is the store around them plus the save.

import { derived, get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import {
  applyTheme,
  paletteById,
  resolveTokens,
  systemDefaultPaletteId,
} from "../theme.js";
import {
  defaultUiPrefs,
  sanitizeUiPrefs,
  type PanelPrefs,
  type UiPrefs,
} from "../ui-prefs.js";

export const uiPrefs = writable<UiPrefs>(defaultUiPrefs());

// Only the two the shells branch on get their own store; everything else is
// read off `uiPrefs` where it is used, and the document gets it as a custom
// property rather than through Svelte at all.
export const uiLayout = derived(uiPrefs, (p) => p.layout);
export const layoutAskedVersion = derived(uiPrefs, (p) => p.layout_asked_version);

/** The panel sizes belonging to the layout that is on screen. */
export const activePanels = derived(uiPrefs, (p): PanelPrefs => p.panels[p.layout]);

/**
 * Keys `sanitizeUiPrefs` did not recognise, kept aside and written back
 * untouched.
 *
 * A user who runs a newer build on one machine and an older one on another
 * would otherwise lose whatever the newer build remembers, every time the older
 * one saves. Nothing reads these; they are ballast we are careful with.
 */
let unknownKeys: Record<string, unknown> = {};

/**
 * What is already on disk, as it would be written.
 *
 * Subscribing to a Svelte store calls you once with the value it already has,
 * and hydration is itself a change — so without this every start would write
 * settings.json straight back with exactly the same bytes, and on Android that
 * is a flash write per launch for nothing. It doubles as the check that a
 * colour dragged back to where it started costs no write either.
 */
let lastSaved: string | null = null;

/**
 * Whether what is in the store came from disk yet.
 *
 * Nothing may be written before it has. `startTheming()` runs as soon as the
 * window opens, but hydration waits on `load_config` — so without this the
 * debounce could fire first and write the *defaults* over a real settings.json,
 * losing the layout somebody chose. The window between the two is normally a
 * few milliseconds and the timer is 400, which is exactly the kind of margin
 * that holds until the day a disk is busy.
 */
let hydrated = false;

/**
 * Whether a layout may be painted yet.
 *
 * Deliberately not the same flag as `hydrated` above, which guards *writing*: a
 * config that failed to load must still render — with the defaults — but must
 * never be written back over the file it failed to read. Without this the first
 * painted frame is the default layout, which for anybody who chose the other
 * one is the wrong shell for as long as the config round trip takes.
 */
export const uiPrefsReady = writable(false);

/**
 * Adopt the `ui_prefs` blob from `load_config`. Called once, from App.svelte's
 * config hydration, before anything renders a layout.
 */
export function hydrateUiPrefs(raw: unknown): void {
  const clean = sanitizeUiPrefs(raw);
  // Nobody has chosen a palette on this install, so the machine's own
  // light/dark setting decides which of the two default palettes to open in.
  // Once somebody picks one it is stored, and this never runs again — the OS
  // switching to light at sunset must not repaint an app somebody set to dark.
  const chosen = raw && typeof raw === "object" && !Array.isArray(raw)
    ? (raw as Record<string, unknown>).palette
    : undefined;
  if (typeof chosen !== "string" || chosen === "") {
    clean.palette = systemDefaultPaletteId();
  }
  unknownKeys = {};
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      if (!(key in clean)) unknownKeys[key] = value;
    }
  }
  uiPrefs.set(clean);
  lastSaved = serialize(clean);
  hydrated = true;
  uiPrefsReady.set(true);
}

/** The exact object `set_ui_prefs` would be handed, as a comparable string. */
function serialize(prefs: UiPrefs): string {
  return JSON.stringify({ ...unknownKeys, ...prefs });
}

/** Change one or more preferences. The save is debounced; this is not. */
export function updateUiPrefs(change: (p: UiPrefs) => void): void {
  uiPrefs.update((p) => {
    const next = structuredClone(p);
    change(next);
    return next;
  });
}

/** Change the panel sizes of the layout currently on screen. */
export function updateActivePanels(change: (panels: PanelPrefs) => void): void {
  updateUiPrefs((p) => change(p.panels[p.layout]));
}

// ── Saving ─────────────────────────────────────────────────────────────────
//
// Debounced, because a colour picker fires on every pixel of its gradient and a
// resize drag would otherwise write settings.json sixty times a second. The
// flushes matter more than the delay: 400 ms is a long time if the window is
// closing.

const SAVE_DELAY_MS = 400;
let saveTimer: ReturnType<typeof setTimeout> | null = null;

function writeNow(): void {
  if (saveTimer !== null) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  if (!hydrated) return;
  const current = get(uiPrefs);
  const text = serialize(current);
  if (text === lastSaved) return;
  lastSaved = text;
  invoke("set_ui_prefs", { prefs: { ...unknownKeys, ...current } }).catch((e: unknown) => {
    // Let the next change try again rather than believing a failed write.
    lastSaved = null;
    console.warn("Could not save appearance settings:", e);
  });
}

function scheduleSave(): void {
  if (saveTimer !== null) clearTimeout(saveTimer);
  saveTimer = setTimeout(writeNow, SAVE_DELAY_MS);
}

/**
 * Start applying preferences to the document and saving changes to them.
 *
 * Called from main.ts for every window that renders UI — the app itself and the
 * screen-share pop-out, which is a separate webview and would otherwise be the
 * one window still painted in the old palette. Not called for `?selftest`,
 * which renders no components at all.
 */
export function startTheming(): void {
  uiPrefs.subscribe((p) => {
    const palette = paletteById(p.palette);
    applyTheme(resolveTokens(p.palette, p.palette_overrides), palette.dark);

    if (typeof document !== "undefined") {
      const root = document.documentElement;
      // `zoom` rather than a transform: a transform would take the fixed-position
      // overlays out of the viewport and move every hit-test with them.
      root.style.setProperty("zoom", p.zoom === 1 ? "" : String(p.zoom));
      root.style.setProperty("--chat-font-size", `${p.chat_font_size}px`);
      root.dataset.density = p.density;
    }

    scheduleSave();
  });

  if (typeof window !== "undefined") {
    // A pending save must not die with the window. `visibilitychange` is the
    // one that actually fires on Android and on a mobile browser being
    // backgrounded; `beforeunload` covers a desktop close.
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden" && saveTimer !== null) writeNow();
    });
    window.addEventListener("beforeunload", () => {
      if (saveTimer !== null) writeNow();
    });
  }
}
