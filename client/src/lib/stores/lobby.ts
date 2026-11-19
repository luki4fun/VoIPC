// The lobby on a big relay (protocol 25): never sent whole. Its people come a page at a time,
// sections first and then A-Z, into the lobby's roster (`channelRosters`, channel 0), which is
// also who `onlineById` knows of; how many stand there comes from `channel-counts`; while its
// list is on screen and it is small, its joins and leaves come by name.

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { scoped } from "./scoped.js";
import { addToRoster, forgetUser, lazyHere, onlineById } from "./rosters.js";
import type { LobbyCursor, UserInfo } from "../types.js";

export interface LobbyPages {
  /** Where to ask on from; null at the start or the end (`done`). */
  next: LobbyCursor | null;
  /** How many the relay lists, those matching `prefix` with one. */
  total: number;
  /** Each section's rank and count, of the whole lobby; 65535 is nobody's section. */
  sections: [number, number][];
  /** A page is on its way. */
  asked: boolean;
  /** No page after the last one. */
  done: boolean;
  /** Names starting with this, when not empty. */
  prefix: string;
}

const fresh = (prefix = ""): LobbyPages => ({ next: null, total: 0, sections: [], asked: false, done: false, prefix });

export const lobby = scoped<LobbyPages>(() => fresh());

/** The rank `sections` gives those under no sectioned group. */
export const REST_SECTION = 65535;

/** How long a page the backend refused (the link is down, mid-reconnect) stays "on its way".
 *  Not at once: the member list asks again whenever nothing is, and a refusal comes back as a
 *  microtask, so the two would pass control back and forth and never let the page run. */
export const LOBBY_RETRY_MS = 2_000;
/** Each server's latest ask: a refusal frees only its own, not one asked after a reset. */
const lastAsk = new Map<string, number>();

/** The next page, unless one is on its way or there is none. */
export function moreLobby(server: string): void {
  const now = get(lobby.peek(server));
  if (!lazyHere(server) || now.asked || now.done) return;
  const ask = (lastAsk.get(server) ?? 0) + 1;
  lastAsk.set(server, ask);
  lobby.of(server).update((l) => ({ ...l, asked: true }));
  invoke("request_lobby_page", { server, after: now.next, prefix: now.prefix }).catch(() =>
    setTimeout(() => {
      if (lastAsk.get(server) === ask) lobby.of(server).update((l) => ({ ...l, asked: false }));
    }, LOBBY_RETRY_MS),
  );
}

/** From the start: everyone, or the names that begin with `prefix`. */
export function searchLobby(server: string, prefix: string): void {
  const sections = get(lobby.peek(server)).sections;
  lobby.of(server).set({ ...fresh(prefix.trim()), sections });
  moreLobby(server);
}

/** The lobby's rows went (a `user-list` for it says only our own since 25): start again. That
 *  list is a new session's first word, so a lobby list on screen is watched again from it: the
 *  relay forgot the old session's watch, and a page that loads signed in asked before it had one.
 *  A turn later: the list comes in the same read as `Authenticated`, before the backend lists the
 *  session that read it. */
export function resetLobby(server: string): void {
  lobby.of(server).set(fresh());
  if (!watched.get(server)) return;
  clearTimeout(watchAgain.get(server));
  watchAgain.set(
    server,
    setTimeout(() => {
      watchAgain.delete(server);
      if (watched.get(server)) askWatch(server, true);
    }, 0),
  );
}

/** What `lobby-page` brought. A page for a prefix asked before another came is let in: its
 *  rows are lobby rows all the same. */
export function lobbyPage(
  server: string,
  page: { rows: UserInfo[]; next: LobbyCursor | null; total: number; sections: [number, number][]; prefix?: string },
): void {
  addToRoster(server, 0, page.rows);
  // A search for a name being typed: its rows, and the list's place stays where it was
  if (page.prefix !== undefined && page.prefix !== get(lobby.peek(server)).prefix) return;
  lobby.of(server).update((l) => ({
    ...l,
    next: page.next,
    total: page.total,
    sections: page.sections,
    asked: false,
    done: page.next === null,
  }));
}

/** What waits for a lookup's answer, per server: the ids and what to do then. */
const waiting = new Map<string, { ids: number[]; then: () => void; timer: ReturnType<typeof setTimeout> }[]>();

/** What `users` brought: the lobby's people into its roster, and whoever is gone off every list.
 *  Then whatever waited on them goes on. */
export function lookedUp(server: string, rows: UserInfo[], gone: number[]): void {
  addToRoster(
    server,
    0,
    rows.filter((r) => r.channel_id === 0),
  );
  for (const id of gone) forgetUser(server, id);
  const answered = new Set([...rows.map((r) => r.user_id), ...gone]);
  const all = waiting.get(server) ?? [];
  const due = all.filter((w) => w.ids.every((id) => answered.has(id)));
  waiting.set(
    server,
    all.filter((w) => !due.includes(w)),
  );
  for (const w of due) {
    clearTimeout(w.timer);
    w.then();
  }
}

/**
 * `then`, once everyone in `ids` is known here or the relay said they are gone: at once on a
 * relay that sends the lobby whole, or when all are known already; else after a lookup, or
 * after three seconds without its answer. A decision that needs to know who someone is (a
 * history ask from someone standing in the lobby) waits for this instead of refusing them.
 */
export function afterLookup(server: string, ids: number[], then: () => void): void {
  const known = onlineById(server);
  const missing = ids.filter((id) => !known.has(id));
  if (!lazyHere(server) || missing.length === 0) {
    then();
    return;
  }
  const entry = {
    ids: missing,
    then,
    timer: setTimeout(() => {
      waiting.set(
        server,
        (waiting.get(server) ?? []).filter((w) => w !== entry),
      );
      then();
    }, 3000),
  };
  waiting.set(server, [...(waiting.get(server) ?? []), entry]);
  lookUp(server, { ids: missing });
}

/** When each prefix was last searched for a mention, per server. */
const askedPrefixes = new Map<string, Map<string, number>>();

/** Who in the lobby goes by a name starting with `prefix`, for an `@` being typed: their rows
 *  join the lobby's, where the mention list finds them. Each prefix once in half a minute. */
export function searchNames(server: string, prefix: string): void {
  const p = prefix.trim();
  if (!lazyHere(server) || !p) return;
  const asked = askedPrefixes.get(server) ?? new Map<string, number>();
  askedPrefixes.set(server, asked);
  const now = Date.now();
  if (now - (asked.get(p) ?? 0) < 30_000) return;
  asked.set(p, now);
  invoke("request_lobby_page", { server, after: null, prefix: p }).catch(() => {});
}

/** When each name was last looked up, per server. */
const askedNames = new Map<string, Map<string, number>>();

/** Look these names up unless known here or asked in the last minute: who a direct-message
 *  list shows as there, when they stand in the lobby (protocol 25). */
export function lookUpNames(server: string, names: string[]): void {
  if (!lazyHere(server)) return;
  const known = new Set([...onlineById(server).values()].map((u) => u.username));
  const asked = askedNames.get(server) ?? new Map<string, number>();
  askedNames.set(server, asked);
  const now = Date.now();
  const due = [...new Set(names)].filter((n) => n && !known.has(n) && now - (asked.get(n) ?? 0) > 60_000);
  for (let i = 0; i < due.length; i += 64) {
    const chunk = due.slice(i, i + 64);
    for (const n of chunk) asked.set(n, now);
    lookUp(server, { names: chunk });
  }
}

/** Whether each server's lobby list is on screen, for the next session to be told (`resetLobby`). */
const watched = new Map<string, boolean>();
/** A refused watch's next ask, per server. */
const watchAgain = new Map<string, ReturnType<typeof setTimeout>>();

/** Tell the relay. A watch refused (no session yet: a page that loads signed in shows its list
 *  first; or the link is down) is asked again after `LOBBY_RETRY_MS` while the list is on
 *  screen. Without it the relay names no join or leave there, and the list keeps whoever left. */
function askWatch(server: string, on: boolean): void {
  if (!lazyHere(server)) return;
  invoke("watch_lobby", { server, on }).catch(() => {
    if (!on || watchAgain.has(server)) return;
    watchAgain.set(
      server,
      setTimeout(() => {
        watchAgain.delete(server);
        if (watched.get(server)) askWatch(server, true);
      }, LOBBY_RETRY_MS),
    );
  });
}

/** The lobby's list is on screen, or not. */
export function watchLobby(server: string, on: boolean): void {
  watched.set(server, on);
  askWatch(server, on);
}

/** Who these are, if online: one ask, at most 64 in all. A relay before 25 holds the lobby whole. */
export function lookUp(
  server: string,
  ask: { ids?: number[]; names?: string[]; accounts?: number[][] },
): void {
  if (!lazyHere(server)) return;
  const ids = [...new Set(ask.ids ?? [])].slice(0, 64);
  const names = [...new Set(ask.names ?? [])].slice(0, 64 - ids.length);
  const accounts = (ask.accounts ?? []).slice(0, 64 - ids.length - names.length);
  if (ids.length + names.length + accounts.length === 0) return;
  invoke("lookup_users", { server, ids, names, accounts }).catch(() => {});
}
