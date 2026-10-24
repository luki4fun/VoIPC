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

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { channels, currentChannelId } from "./channels.js";
import { joinedTextChannelIds } from "./chat.js";
import { isAdmin } from "./connection.js";
import { scoped } from "./scoped.js";
import { users } from "./users.js";
import { rosterOf, trustRosterCount, worthAsking } from "../roster-rules.js";
import type { UserInfo } from "../types.js";

/** channel_id → who is in it, as far as this client is allowed to know; per server. */
export const channelRosters = scoped<Map<number, UserInfo[]>>(() => new Map());

/**
 * Asking is a round trip, and a busy server moves people constantly — one
 * request per join would put a burst on the wire every time a channel fills.
 * Ids collect here and go out together, per server: the ids are that server's.
 */
const pending = new Map<string, { ids: Set<number>; timer: ReturnType<typeof setTimeout> | null }>();
const FLUSH_MS = 250;

function pendingFor(server: string) {
  let entry = pending.get(server);
  if (!entry) {
    entry = { ids: new Set(), timer: null };
    pending.set(server, entry);
  }
  return entry;
}

function flush(server: string): void {
  const entry = pending.get(server);
  if (!entry) return;
  pending.delete(server);
  for (const channelId of entry.ids) {
    invoke("request_channel_users", { server, channelId }).catch(() => {
      // A channel that vanished between the ask and the answer is not an error
    });
  }
}

function schedule(server: string): void {
  const entry = pendingFor(server);
  if (entry.ids.size > 0 && entry.timer === null) {
    entry.timer = setTimeout(() => flush(server), FLUSH_MS);
  }
}

/** Ask for one channel's roster on a server, soon. */
export function requestRoster(server: string, channelId: number): void {
  const list = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (
    !list ||
    !worthAsking(
      list,
      get(currentChannelId.peek(server)),
      get(isAdmin.peek(server)),
      get(joinedTextChannelIds.peek(server)),
    )
  )
    return;
  pendingFor(server).ids.add(channelId);
  schedule(server);
}

/** Ask for every channel on a server we are allowed to see into. */
export function requestAllRosters(server: string): void {
  const currentId = get(currentChannelId.peek(server));
  const admin = get(isAdmin.peek(server));
  const joinedText = get(joinedTextChannelIds.peek(server));
  const ids = pendingFor(server).ids;
  for (const channel of get(channels.peek(server))) {
    if (worthAsking(channel, currentId, admin, joinedText)) ids.add(channel.channel_id);
  }
  schedule(server);
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
export function setRoster(server: string, channelId: number, list: UserInfo[]): void {
  channelRosters.of(server).update((m) => new Map(m).set(channelId, list));
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (
    !channel ||
    !trustRosterCount(
      list,
      channel,
      get(currentChannelId.peek(server)),
      get(isAdmin.peek(server)),
      get(joinedTextChannelIds.peek(server)),
    )
  ) {
    return;
  }
  // bernd: a channel we may not ask about (a password or hidden members,
  // and not ours) still rides on the arithmetic alone. Put `user_count` in the
  // ChannelUsers reply if that one drifts too.
  if (channel.user_count === list.length) return;
  channels.of(server).update((chs) =>
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
export function patchRosters(server: string, userId: number, patch: Partial<UserInfo>): void {
  channelRosters.of(server).update((m) => {
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

/** A connection's questions die with it; its rosters go with `dropServer`. */
export function clearRosters(server: string): void {
  const entry = pending.get(server);
  if (entry?.timer != null) clearTimeout(entry.timer);
  pending.delete(server);
}

export { rosterOf };

/** Convenience for code that just wants the current values. */
export function currentRosterOf(server: string, channelId: number): UserInfo[] {
  return rosterOf(
    channelId,
    get(channelRosters.peek(server)),
    get(currentChannelId.peek(server)),
    get(users.peek(server)),
  );
}
