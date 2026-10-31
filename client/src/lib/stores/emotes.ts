// Each server's emotes and stickers (protocol v14), and the PNG each one's file
// was made into on this device (client/src-tauri/src/emotes.rs; in the
// browser web/backend/emotes.ts), as object URLs. Every emote of a server is
// loaded when its list comes, whatever is used: what is fetched then says
// nothing about who uses which.

import { invoke } from "@tauri-apps/api/core";
import { get, writable } from "svelte/store";
import { scoped } from "./scoped";
import { cleanList, countKinds, type Emote } from "../emote-rules";
import { pictureUrl } from "../media";
import { confirmChoice } from "./confirm";
import { uiPrefs, updateUiPrefs } from "./ui-prefs";
import { formatSize } from "../file-rules";
import { savedServers } from "./settings";
import { serverName } from "./servers";

export interface EmoteSet {
  /** Members may send stickers here (the admins' switch). */
  stickers: boolean;
  emotes: Emote[];
}

export const emoteSets = scoped<EmoteSet>(() => ({ stickers: false, emotes: [] }));

/** What an admin may add here; null where the server has no emotes. */
export interface EmoteLimits {
  max_emote_bytes: number;
  max_sticker_bytes: number;
  /** All of them together, and how many there may be. */
  max_total_bytes: number;
  max_items: number;
}
export const emoteLimits = scoped<EmoteLimits | null>(() => null);

/** Per server and `urlKey`: the picture's object URL, its first frame's where
 *  that was asked for (a moving one, for "animate on hover"), or why this
 *  device could not make it. */
export interface EmoteUrls {
  url?: string;
  still?: string;
  error?: string;
}
export const emoteUrls = scoped<Map<string, EmoteUrls>>(() => new Map());

/** One file is made into an emote (128 px) and a sticker (320 px) apart. */
export function urlKey(hash: string, sticker: boolean): string {
  return `${hash}|${sticker ? "s" : "e"}`;
}

/** Pictures being made at once, over every server. */
const AT_ONCE = 3;
let running = 0;
const queue: (() => Promise<void>)[] = [];
/** `first`: something on screen waits for it, ahead of a server's prefetch. */
function later(job: () => Promise<void>, first: boolean) {
  if (first) queue.unshift(job);
  else queue.push(job);
  pump();
}
function pump() {
  while (running < AT_ONCE && queue.length) {
    const job = queue.shift()!;
    running++;
    void job().finally(() => {
      running--;
      pump();
    });
  }
}

/** What is made only into this device's cache ("fetch": every emote of a
 *  server, at once), or into an object URL to show. */
type Want = "fetch" | "url" | "still";
const asked = new Set<string>();
const failed = new Set<string>();
const listed = (server: string, e: Emote) => get(emoteSets.peek(server)).emotes.some((x) => x.hash === e.hash && x.sticker === e.sticker);

function ask(server: string, e: Emote, want: Want, retried = false) {
  const key = `${server}|${urlKey(e.hash, e.sticker)}|${want}`;
  if (asked.has(key) && !retried) return;
  // Waiting for Wi-Fi: what is on this device shows, nothing is fetched
  const wait = get(emoteWait).get(server);
  if (wait && (!wait.missing || wait.missing.has(urlKey(e.hash, e.sticker)))) return;
  asked.add(key);
  later(async () => {
    if (!listed(server, e)) return;
    try {
      const png = new Uint8Array(
        await invoke<ArrayBuffer>("emote_image", {
          server,
          hash: e.hash,
          sticker: e.sticker,
          still: want === "still",
          fetchOnly: want === "fetch",
          len: e.len,
        }),
      );
      // The server's list may have moved on meanwhile: kept only if still listed
      if (want === "fetch" || !listed(server, e)) return;
      const url = pictureUrl(png);
      emoteUrls.of(server).update((m) => {
        const next = new Map(m);
        const had = next.get(urlKey(e.hash, e.sticker));
        const old = had?.[want];
        if (old) URL.revokeObjectURL(old);
        next.set(urlKey(e.hash, e.sticker), { ...had, [want]: url, error: undefined });
        return next;
      });
    } catch (err) {
      // Once more a moment later: a list can come before its connection is
      // ready for the fetch. Then it shows why, until the next list
      if (!retried) return void setTimeout(() => ask(server, e, want, true), 3000);
      failed.add(key);
      console.debug(`emote ${e.name} not shown:`, err);
      emoteUrls.of(server).update((m) =>
        new Map(m).set(urlKey(e.hash, e.sticker), { ...m.get(urlKey(e.hash, e.sticker)), error: String(err).replace(/^Error: /, "") }),
      );
    }
  }, want !== "fetch");
}

/** `emote-list`: the server's new list, as this app takes it (`cleanList`);
 *  what it no longer lists lets go. Every emote is made into this device's
 *  cache now; an object URL only once one is on screen. */
export function setEmotes(server: string, set: EmoteSet): void {
  const emotes = cleanList(set.emotes);
  emoteSets.of(server).set({ stickers: set.stickers, emotes });
  const keep = new Set(emotes.map((e) => urlKey(e.hash, e.sticker)));
  emoteUrls.of(server).update((m) => {
    const next = new Map<string, EmoteUrls>();
    for (const [k, u] of m) {
      if (keep.has(k) && !u.error) next.set(k, u);
      else for (const url of [u.url, u.still]) if (url) URL.revokeObjectURL(url);
    }
    return next;
  });
  // Asked again: what failed, which the new list may have mended
  for (const k of [...asked]) {
    if (!k.startsWith(`${server}|`)) continue;
    const [, hash, kind] = k.split("|");
    if (!keep.has(`${hash}|${kind}`) || failed.has(k)) {
      asked.delete(k);
      failed.delete(k);
    }
  }
  if (metered() && !onMobileData.has(server)) void askMobileData(server, emotes);
  for (const e of emotes) ask(server, e, "fetch");
  // What this device made for emotes no open server lists goes, in time
  const all = [...get(emoteSets.all()).values()].flatMap((s) => s.emotes.map((e) => e.hash));
  invoke("emote_cache_retain", { keep: [...new Set(all)] }).catch(() => {});
}

/** A connection's end (connect.ts `resetServer`, before `dropServer`): its
 *  pictures let go, and the next connection's list asks for them again. */
export function dropEmotes(server: string): void {
  emoteWait.update((m) => {
    const next = new Map(m);
    next.delete(server);
    return next;
  });
  for (const u of get(emoteUrls.peek(server)).values()) for (const url of [u.url, u.still]) if (url) URL.revokeObjectURL(url);
  for (const k of [...asked]) {
    if (k.startsWith(`${server}|`)) {
      asked.delete(k);
      failed.delete(k);
    }
  }
}

// ── On mobile data ───────────────────────────────────────────────────────
//
// A phone on mobile data is asked first, with the size, before a server's
// emotes and stickers are downloaded: all of them or none, so that what is
// fetched still says nothing about which are used. Meanwhile they show as
// their names; on Wi-Fi they come.

/** Servers whose emotes wait for Wi-Fi: what a download would take, and which
 *  (`urlKey`s; null while that is being worked out: all wait). */
export const emoteWait = writable<Map<string, { bytes: number; missing: Set<string> | null }>>(new Map());
/** Servers whose emotes may come over mobile data, this session; and those
 *  asked already, which wait on without asking again at each new list. */
const onMobileData = new Set<string>();
const askedMobile = new Set<string>();

/** Mobile data, as the browser or the Android WebView tells it. shortcut:
 *  where `navigator.connection` is missing (desktop WebViews, Firefox,
 *  Safari) every network counts as unmetered. */
function metered(): boolean {
  const c = (globalThis.navigator as { connection?: { type?: string; saveData?: boolean } } | undefined)?.connection;
  return c?.type === "cellular" || c?.saveData === true;
}

function hold(server: string, wait: { bytes: number; missing: Set<string> | null } | null) {
  emoteWait.update((m) => {
    const next = new Map(m);
    if (wait) next.set(server, wait);
    else next.delete(server);
    return next;
  });
}

/** `server`'s emotes now, over whatever network: what waited is fetched,
 *  and what is on screen asks again (Emote.svelte reads `emoteWait`). */
export function downloadEmotes(server: string): void {
  onMobileData.add(server);
  hold(server, null);
  for (const e of get(emoteSets.peek(server)).emotes) ask(server, e, "fetch");
}

/** Once the first-run questions (microphone, layout) are answered: a question
 *  about emotes stacked on "Let VoIPC hear you" was answered by a stray click.
 *  shortcut: those dialogs keep no store of their own, so their boxes are
 *  looked for; at most ten minutes, then it asks anyway. */
async function afterFirstRun(): Promise<void> {
  const open = () => typeof document !== "undefined" && !!document.querySelector(".audio-setup, .layout-setup");
  // The setup comes up as the connection does, a moment after the list may
  await new Promise((r) => setTimeout(r, 1500));
  for (let i = 0; open() && i < 1200; i++) await new Promise((r) => setTimeout(r, 500));
}

async function askMobileData(server: string, emotes: Emote[]) {
  // "Always on this server", said before: no question, as on Wi-Fi
  if (get(uiPrefs).emotes_mobile_ok.includes(server)) return downloadEmotes(server);
  hold(server, { bytes: 0, missing: null });
  const missing = new Set(
    await invoke<string[]>("emote_missing", { items: emotes.map((e) => ({ hash: e.hash, sticker: e.sticker })) }).catch(() => []),
  );
  const bytes = emotes.filter((e) => missing.has(urlKey(e.hash, e.sticker))).reduce((n, e) => n + e.len, 0);
  if (!bytes) return downloadEmotes(server);
  hold(server, { bytes, missing });
  if (askedMobile.has(server)) return;
  askedMobile.add(server);
  await afterFirstRun();
  // Downloaded meanwhile (back on Wi-Fi, or "Download now" in the picker)
  if (!get(emoteWait).has(server)) return;
  const want = emotes.filter((e) => missing.has(urlKey(e.hash, e.sticker)));
  const stickers = want.filter((e) => e.sticker).length;
  const { ok, option } = await confirmChoice({
    title: "Download emotes on mobile data?",
    body:
      `${serverName(server, get(savedServers))} has ${countKinds(want.length - stickers, stickers)} this device does not have yet: ` +
      `${formatSize(bytes)}. Until they are downloaded they show as their names; on Wi-Fi they come by themselves.`,
    confirm: `Download ${formatSize(bytes)}`,
    cancel: "Wait for Wi-Fi",
    // Kept only with Download: "always wait" is what not ticking it already is
    option: "Always download them on this server, without asking",
  });
  if (ok && option) mobileOk(server, true);
  if (ok) downloadEmotes(server);
}

/** `server` in or out of "Always on this server" (Settings → Files undoes it). */
export function mobileOk(server: string, on: boolean): void {
  updateUiPrefs((p) => {
    const rest = p.emotes_mobile_ok.filter((s) => s !== server);
    p.emotes_mobile_ok = on ? [...rest, server] : rest;
  });
}

const connection = (globalThis.navigator as { connection?: EventTarget } | undefined)?.connection;
connection?.addEventListener?.("change", () => {
  if (!metered()) for (const server of get(emoteWait).keys()) downloadEmotes(server);
});

/** `e` is on screen: its picture, or its first frame (for a reader who
 *  animates only on hover, or never). */
export function wantPicture(server: string, e: Emote, still: boolean): void {
  ask(server, e, still ? "still" : "url");
}

/** A picture an admin asked to make an emote or sticker of (a chat
 *  picture's menu): the Emotes tab opens and takes it into its importer. */
export const pendingImport = writable<{ server: string; name: string; bytes: Uint8Array } | null>(null);

/** The emotes used last, per server, newest first: what the picker and the
 *  `:` completion offer first. Kept on this device only; the server learns
 *  nothing of it. */
const RECENT_KEY = "voipc.emotes.recent";
const RECENT_MAX = 16;

/** Names kept per server under `key`, as this device last wrote them. */
function loadNames(key: string, max: number): Record<string, string[]> {
  if (typeof localStorage === "undefined") return {};
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(key) ?? "{}");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
    return Object.fromEntries(
      Object.entries(raw).map(([server, names]) => [
        server,
        Array.isArray(names) ? names.filter((n): n is string => typeof n === "string").slice(0, max) : [],
      ]),
    );
  } catch {
    return {};
  }
}

export const recentEmotes = writable<Record<string, string[]>>(loadNames(RECENT_KEY, RECENT_MAX));

function save(key: string, all: Record<string, string[]>) {
  try {
    localStorage.setItem(key, JSON.stringify(all));
  } catch {
    // Full, or none here: it is only an order
  }
}

/** `names` were just used on `server`. */
export function noteEmotes(server: string, names: string[]): void {
  if (names.length === 0) return;
  recentEmotes.update((all) => {
    const next = { ...all, [server]: [...new Set([...names, ...(all[server] ?? [])])].slice(0, RECENT_MAX) };
    save(RECENT_KEY, next);
    return next;
  });
}

/** A server taken off this device's list: what was kept here of how its
 *  emotes are used goes too, as the rest of it does. */
export function forgetEmotes(server: string): void {
  if (get(uiPrefs).emotes_mobile_ok.includes(server)) mobileOk(server, false);
  for (const [store, key] of [
    [recentEmotes, RECENT_KEY],
    [favEmotes, FAV_KEY],
  ] as const) {
    store.update((all) => {
      if (!(server in all)) return all;
      const { [server]: _gone, ...rest } = all;
      save(key, rest);
      return rest;
    });
  }
}

/** The emotes and stickers marked favourite, per server: first in the
 *  picker and the `:` completion. On this device only, like the recent. */
const FAV_KEY = "voipc.emotes.fav";
const FAV_MAX = 100;
export const favEmotes = writable<Record<string, string[]>>(loadNames(FAV_KEY, FAV_MAX));

/** `name` a favourite on `server`, or no longer. */
export function toggleFav(server: string, name: string): void {
  favEmotes.update((all) => {
    const had = all[server] ?? [];
    const next = { ...all, [server]: had.includes(name) ? had.filter((n) => n !== name) : [name, ...had].slice(0, FAV_MAX) };
    save(FAV_KEY, next);
    return next;
  });
}

/** Whether the person's system asks for reduced motion (then nothing moves). */
export const reducedMotion = writable(
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches,
);
if (typeof matchMedia === "function") {
  matchMedia("(prefers-reduced-motion: reduce)").addEventListener?.("change", (e) => reducedMotion.set(e.matches));
}
