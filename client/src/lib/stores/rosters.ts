// Who is in every channel, not just the one you are standing in.
//
// The Discord sidebar nests members under each channel, which needs a roster
// per channel. The client is only ever *pushed* its own channel's roster: a
// `UserJoined` broadcast reaches every session, because it doubles as the
// user-count update, but it carries an empty username for anyone outside the
// channel it names. That blanking is deliberate — see `broadcast_user_joined`
// in crates/voipc-server/src/tcp.rs — so the names have to be *asked* for.
//
// `RequestChannelUsers` is that question, and it is the one the server already
// answers carefully: `is_channel_public_or_member` refuses a channel that hides
// its members or has a password to anyone not in it, and `users_in_channel_for`
// substitutes the channel's pseudonyms when it is anonymous and the asker is
// not an admin. Every rule about who may see whom therefore stays on the
// server, where it was. This file only decides *when* to ask.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { channels, currentChannelId } from "./channels.js";
import { isAdmin } from "./connection.js";
import { users } from "./users.js";
import { rosterOf, worthAsking } from "../roster-rules.js";
import type { UserInfo } from "../types.js";

/** channel_id → who is in it, as far as this client is allowed to know. */
export const channelRosters = writable<Map<number, UserInfo[]>>(new Map());

/**
 * Asking is a round trip, and a busy server moves people constantly — one
 * request per join would put a burst on the wire every time a channel fills.
 * Ids collect here and go out together.
 */
const pending = new Set<number>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;
const FLUSH_MS = 250;

function flush(): void {
  flushTimer = null;
  const ids = [...pending];
  pending.clear();
  for (const channelId of ids) {
    invoke("request_channel_users", { channelId }).catch(() => {
      // A channel that vanished between the ask and the answer is not an error
    });
  }
}

/** Ask for one channel's roster, soon. */
export function requestRoster(channelId: number): void {
  const list = get(channels).find((c) => c.channel_id === channelId);
  if (!list || !worthAsking(list, get(currentChannelId), get(isAdmin))) return;
  pending.add(channelId);
  if (flushTimer === null) flushTimer = setTimeout(flush, FLUSH_MS);
}

/** Ask for every channel we are allowed to see into. */
export function requestAllRosters(): void {
  const currentId = get(currentChannelId);
  const admin = get(isAdmin);
  for (const channel of get(channels)) {
    if (worthAsking(channel, currentId, admin)) pending.add(channel.channel_id);
  }
  if (pending.size > 0 && flushTimer === null) flushTimer = setTimeout(flush, FLUSH_MS);
}

/** A `channel-users` reply arrived. */
export function setRoster(channelId: number, list: UserInfo[]): void {
  channelRosters.update((m) => new Map(m).set(channelId, list));
}

/**
 * Our own channel, which is pushed rather than asked for.
 *
 * Kept in the same map so the sidebar has one source for every row, and so the
 * row for the channel we are in is never a stale copy of a roster we asked for
 * before we joined it.
 */
export function setOwnRoster(channelId: number, list: UserInfo[]): void {
  setRoster(channelId, list);
}

/**
 * Patch one person wherever they are.
 *
 * Mute, deafen and screen-share events are broadcast to every session and carry
 * no channel, so rather than re-asking for a roster because somebody muted, the
 * flag is applied to whichever roster holds them.
 */
export function patchRosters(userId: number, patch: Partial<UserInfo>): void {
  channelRosters.update((m) => {
    let changed = false;
    const next = new Map(m);
    for (const [channelId, list] of next) {
      if (!list.some((u) => u.user_id === userId)) continue;
      next.set(
        channelId,
        list.map((u) => (u.user_id === userId ? { ...u, ...patch } : u)),
      );
      changed = true;
    }
    return changed ? next : m;
  });
}

/** A connection's rosters die with it. */
export function clearRosters(): void {
  pending.clear();
  if (flushTimer !== null) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  channelRosters.set(new Map());
}

export { rosterOf };

/** Convenience for components that just want the current values. */
export function currentRosterOf(channelId: number): UserInfo[] {
  return rosterOf(channelId, get(channelRosters), get(currentChannelId), get(users));
}
