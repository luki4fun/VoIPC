// Who is in every channel, not just the one you are standing in.
//
// The modern sidebar nests members under each channel, which needs a roster
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
import { joinedTextChannelIds } from "./chat.js";
import { isAdmin } from "./connection.js";
import { users } from "./users.js";
import { rosterOf, trustRosterCount, worthAsking } from "../roster-rules.js";
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
  if (!list || !worthAsking(list, get(currentChannelId), get(isAdmin), get(joinedTextChannelIds)))
    return;
  pending.add(channelId);
  if (flushTimer === null) flushTimer = setTimeout(flush, FLUSH_MS);
}

/** Ask for every channel we are allowed to see into. */
export function requestAllRosters(): void {
  const currentId = get(currentChannelId);
  const admin = get(isAdmin);
  const joinedText = get(joinedTextChannelIds);
  for (const channel of get(channels)) {
    if (worthAsking(channel, currentId, admin, joinedText)) pending.add(channel.channel_id);
  }
  if (pending.size > 0 && flushTimer === null) flushTimer = setTimeout(flush, FLUSH_MS);
}

/**
 * A roster arrived: a `channel-users` reply, or the `user-list` push for the
 * channel we stand in. The same map for both, so the sidebar has one source per
 * row and our own row is never a stale copy of a roster we asked for before we
 * joined it — those differ, because an anonymous channel answers an outsider
 * with pseudonyms and a member with names.
 *
 * It also settles the row's member count. That count is otherwise arithmetic —
 * the channel list is sent once, at login, and every join and leave after it is
 * a broadcast we add or subtract — so one broadcast that never lands is wrong
 * until the next reconnect. A roster is a fresh count of the same thing, and
 * the client already asks for one on every join and leave, so this is where the
 * two are reconciled. `trustRosterCount` is what keeps a refused answer (also
 * an empty list) from zeroing a channel we are simply not allowed to see into.
 */
export function setRoster(channelId: number, list: UserInfo[]): void {
  channelRosters.update((m) => new Map(m).set(channelId, list));
  const channel = get(channels).find((c) => c.channel_id === channelId);
  if (
    !channel ||
    !trustRosterCount(list, channel, get(currentChannelId), get(isAdmin), get(joinedTextChannelIds))
  ) {
    return;
  }
  // bernd: a channel we may not ask about (a password or hidden members,
  // and not ours) still rides on the arithmetic alone. Put `user_count` in the
  // ChannelUsers reply if that one drifts too.
  if (channel.user_count === list.length) return;
  channels.update((chs) =>
    chs.map((c) => (c.channel_id === channelId ? { ...c, user_count: list.length } : c)),
  );
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
