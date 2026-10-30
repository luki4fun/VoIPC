// Each server's emotes and stickers (protocol v14), and the PNG each one's file
// was made into on this device (client/src-tauri/src/emotes.rs; in the
// browser web/backend/emotes.ts), as object URLs. Every emote of a server is
// loaded when its list comes, whatever is used: what is fetched then says
// nothing about who uses which.

import { invoke } from "@tauri-apps/api/core";
import { get, writable } from "svelte/store";
import { scoped } from "./scoped";
import type { Emote } from "../emote-rules";
import { pictureUrl } from "../media";

export interface EmoteSet {
  /** Members may send stickers here (the admins' switch). */
  stickers: boolean;
  emotes: Emote[];
}

export const emoteSets = scoped<EmoteSet>(() => ({ stickers: false, emotes: [] }));

/** What an admin may add here; null where the server has no emotes. */
export const emoteLimits = scoped<{ max_emote_bytes: number; max_sticker_bytes: number } | null>(() => null);

/** Per server and hash: the picture's object URL, and its first frame's
 *  where that was asked for (a moving one, for "animate on hover"). */
export interface EmoteUrls {
  url?: string;
  still?: string;
}
export const emoteUrls = scoped<Map<string, EmoteUrls>>(() => new Map());

/** Pictures being made at once, over every server. */
const AT_ONCE = 3;
let running = 0;
const queue: (() => Promise<void>)[] = [];
function later(job: () => Promise<void>) {
  queue.push(job);
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

const asked = new Set<string>();

/** Make `e`'s picture (or its still) on `server`, once. */
function ask(server: string, e: Emote, still: boolean) {
  const key = `${server}|${e.hash}|${e.sticker}|${still}`;
  if (asked.has(key)) return;
  asked.add(key);
  later(async () => {
    try {
      const png = new Uint8Array(await invoke<ArrayBuffer>("emote_image", { server, hash: e.hash, sticker: e.sticker, still }));
      // The server's list may have moved on meanwhile: kept only if still listed
      if (!get(emoteSets.peek(server)).emotes.some((x) => x.hash === e.hash)) return;
      const url = pictureUrl(png);
      emoteUrls.of(server).update((m) => {
        const next = new Map(m);
        const had = next.get(e.hash);
        // Two jobs for one picture (a sticker and an emote of one file): one URL
        const old = had?.[still ? "still" : "url"];
        if (old) URL.revokeObjectURL(old);
        next.set(e.hash, { ...had, [still ? "still" : "url"]: url });
        return next;
      });
    } catch (err) {
      asked.delete(key);
      console.debug(`emote ${e.name} not shown:`, err);
    }
  });
}

/** `emote-list`: the server's new list; what it no longer lists lets go. */
export function setEmotes(server: string, set: EmoteSet): void {
  emoteSets.of(server).set(set);
  const keep = new Set(set.emotes.map((e) => e.hash));
  emoteUrls.of(server).update((m) => {
    const next = new Map<string, EmoteUrls>();
    for (const [hash, u] of m) {
      if (keep.has(hash)) next.set(hash, u);
      else for (const url of [u.url, u.still]) if (url) URL.revokeObjectURL(url);
    }
    return next;
  });
  for (const k of [...asked]) if (k.startsWith(`${server}|`) && !keep.has(k.split("|")[1])) asked.delete(k);
  for (const e of set.emotes) ask(server, e, false);
  // What this device made for emotes no open server lists any more goes
  const all = [...get(emoteSets.all()).values()].flatMap((s) => s.emotes.map((e) => e.hash));
  invoke("emote_cache_retain", { keep: [...new Set(all)] }).catch(() => {});
}

/** A connection's end (connect.ts `resetServer`, before `dropServer`): its
 *  pictures let go, and the next connection's list asks for them again. */
export function dropEmotes(server: string): void {
  for (const u of get(emoteUrls.peek(server)).values()) for (const url of [u.url, u.still]) if (url) URL.revokeObjectURL(url);
  for (const k of [...asked]) if (k.startsWith(`${server}|`)) asked.delete(k);
}

/** The first frame of `e`, for a reader who animates only on hover. */
export function wantStill(server: string, e: Emote): void {
  ask(server, e, true);
}

/** Whether the person's system asks for reduced motion (then nothing moves). */
export const reducedMotion = writable(
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches,
);
if (typeof matchMedia === "function") {
  matchMedia("(prefers-reduced-motion: reduce)").addEventListener?.("change", (e) => reducedMotion.set(e.matches));
}
