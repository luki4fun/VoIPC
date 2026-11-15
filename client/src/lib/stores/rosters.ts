// Who is in every channel, not just the one you are standing in.
//
// The modern sidebar nests members under each channel, which needs a roster
// per channel. The client is only ever *pushed* its own channel's roster: a
// `UserJoined` broadcast reaches every session, because it doubles as the
// user-count update, but it carries an empty username for anyone outside the
// channel it names. That blanking is deliberate — see `broadcast_user_joined`
// in crates/voipc-server/src/session.rs — so the names have to be *asked* for.
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
import { isAdmin, serverAddress } from "./connection.js";
import { scoped } from "./scoped.js";
import { users } from "./users.js";
import { applyRosterChanges, onlineIn, rosterOf, trustRosterCount, worthAsking, type RosterChange } from "../roster-rules.js";
import { livePath } from "../relay-rules.js";
import { olderRelay } from "./relay.js";
import type { UserInfo } from "../types.js";

/** channel_id → who is in it, as far as this client is allowed to know; per server. */
export const channelRosters = scoped<Map<number, UserInfo[]>>(() => new Map());

/** A text channel this connection follows on the live path (`TextJoined`). */
export interface TextSeat {
  /** A gate keeps people out: who is there goes by a list, and a guest gets nothing. */
  gated: boolean;
  /** When the relay last saw a post there, by its clock; 0 for none since it started. */
  lastPost: number;
}

export const textSeats = scoped<ReadonlyMap<number, TextSeat>>(() => new Map());

/** Who `MemberGone` said left a gated or hand-joined channel since the last list of it: a
 *  hand-off asks the device to answer them, and their name may still be on that list. */
export const goneFrom = scoped<ReadonlyMap<number, ReadonlySet<number>>>(() => new Map());

/**
 * Asking is a round trip, and a busy server moves people constantly — one
 * request per join would put a burst on the wire every time a channel fills.
 * Ids collect here and go out together, per server: the ids are that server's.
 */
const pending = new Map<string, { ids: Set<number>; changes: RosterChange[]; timer: ReturnType<typeof setTimeout> | null }>();
const FLUSH_MS = 250;

function pendingFor(server: string) {
  let entry = pending.get(server);
  if (!entry) {
    entry = { ids: new Set(), changes: [], timer: null };
    pending.set(server, entry);
  }
  return entry;
}

function flush(server: string): void {
  const entry = pending.get(server);
  if (!entry) return;
  pending.delete(server);
  if (entry.changes.length > 0) {
    const { rosters, moved } = applyRosterChanges(get(channelRosters.peek(server)), entry.changes);
    channelRosters.of(server).set(rosters);
    channels.of(server).update((chs) =>
      chs.map((c) => (moved.get(c.channel_id) ? { ...c, user_count: Math.max(0, c.user_count + moved.get(c.channel_id)!) } : c)),
    );
  }
  for (const channelId of entry.ids) {
    invoke("request_channel_users", { server, channelId }).catch(() => {
      // A channel that vanished between the ask and the answer is not an error
    });
  }
}

function schedule(server: string): void {
  const entry = pendingFor(server);
  if ((entry.ids.size > 0 || entry.changes.length > 0) && entry.timer === null) {
    entry.timer = setTimeout(() => flush(server), FLUSH_MS);
  }
}

const liveHere = (server: string) => livePath(get(olderRelay.peek(server))?.protocol ?? null);

/** When each room's list was last asked for only to bring its flags up to date. */
const healed = new Map<string, Map<number, number>>();

/**
 * A room's mute and live flags reach only the room, and a join or a leave with a name needs
 * no ask any more, which was what brought them here. So a change there asks now and then:
 * only for the server on screen, and less often the more people are online.
 */
function healFlags(server: string, channelId: number): void {
  if (server !== get(serverAddress) || channelId === 0) return;
  const here = healed.get(server) ?? new Map<number, number>();
  healed.set(server, here);
  const now = Date.now();
  if (now - (here.get(channelId) ?? 0) < Math.max(5000, onlineById(server).size * 5)) return;
  here.set(channelId, now);
  requestRoster(server, channelId);
}

/** A join's broadcast, with the next ones. With a name, the list needs no ask. */
export function noteJoin(server: string, u: UserInfo): void {
  pendingFor(server).changes.push({ join: u });
  schedule(server);
  if (!liveHere(server) || !u.username) requestRoster(server, u.channel_id);
  else healFlags(server, u.channel_id);
}

/** A leave's broadcast, with the next ones. An id of 0 is someone a list here hides. */
export function noteLeft(server: string, channelId: number, id: number): void {
  pendingFor(server).changes.push({ left: id, channel: channelId });
  schedule(server);
  if (!liveHere(server) || !id) requestRoster(server, channelId);
  else healFlags(server, channelId);
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
      liveHere(server),
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
  const live = liveHere(server);
  for (const channel of get(channels.peek(server))) {
    if (worthAsking(channel, currentId, admin, joinedText, live)) ids.add(channel.channel_id);
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
/**
 * The relay says nobody has `id` any more: off the lists now, not when a
 * departure or the next roster gets here, which for a channel we cannot ask
 * about is never. They say where writing to somebody goes (`liveIdOf`).
 */
export function forgetUser(server: string, id: number): void {
  channelRosters.of(server).update((m) => {
    const next = new Map<number, UserInfo[]>();
    for (const [channelId, list] of m) next.set(channelId, list.filter((u) => u.user_id !== id));
    return next;
  });
  users.of(server).update((list) => list.filter((u) => u.user_id !== id));
}

/** Rows of a roster too long for one frame (`channel-page`): they add to it. */
export function addToRoster(server: string, channelId: number, rows: UserInfo[]): void {
  if (!rows.length) return;
  channelRosters.of(server).update((m) => {
    const fresh = new Set(rows.map((u) => u.user_id));
    const kept = (m.get(channelId) ?? []).filter((u) => !fresh.has(u.user_id));
    return new Map(m).set(channelId, [...kept, ...rows]);
  });
  if (channelId === get(currentChannelId.peek(server))) {
    users.of(server).update((list) => {
      const fresh = new Set(rows.map((u) => u.user_id));
      return [...list.filter((u) => !fresh.has(u.user_id)), ...rows];
    });
  }
}

/** This app exchanged a key with them here, so a list of this channel shows them from now on,
 *  unless `MemberGone` said they left it. They may be on a public list with more to say. */
export function exchangedKey(server: string, channelId: number, row: UserInfo): void {
  if (!row.username || get(goneFrom.peek(server)).get(channelId)?.has(row.user_id)) return;
  if (get(channelRosters.peek(server)).get(channelId)?.some((u) => u.user_id === row.user_id)) return;
  addToRoster(server, channelId, [onlineById(server).get(row.user_id) ?? row]);
}

/** Everyone a list of General or of a room names, by id: who is online, as far as anyone
 *  may know. In an open text channel that is who may be reading. */
export function onlineById(server: string): Map<number, UserInfo> {
  return onlineIn(get(channelRosters.peek(server)), get(channels.peek(server)), get(users.peek(server)));
}

/** `id`'s account, on the roster of any channel. */
export function rosterAccount(server: string, id: number): UserInfo["account"] {
  for (const list of get(channelRosters.peek(server)).values()) {
    const u = list.find((x) => x.user_id === id);
    if (u?.account) return u.account;
  }
  return undefined;
}

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
 * flag is applied to whichever roster holds them. `where` says which channels' rows take it.
 */
export function patchRosters(
  server: string,
  userId: number,
  patch: Partial<UserInfo>,
  where: (channelId: number) => boolean = () => true,
): void {
  // A join still in the batch carries their row as it was: what came since goes on it too,
  // or the flush puts the old flag back (a sharer shown as not sharing, with no Resync)
  for (const change of pending.get(server)?.changes ?? []) {
    if ("join" in change && change.join.user_id === userId && where(change.join.channel_id)) {
      change.join = { ...change.join, ...patch };
    }
  }
  channelRosters.of(server).update((m) => {
    let changed = false;
    const next = new Map(m);
    for (const [channelId, list] of next) {
      if (!where(channelId) || !list.some((u) => u.user_id === userId)) continue;
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
  healed.delete(server);
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
