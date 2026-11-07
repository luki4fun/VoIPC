// Two rules about other channels' rosters: which ones are worth asking about,
// and where a row's members come from once they arrive.
//
// Pure, so roster-rules.test.ts can load them under Node's own test runner —
// stores/rosters.ts, which does the asking, reaches the backend and cannot.
//
// The server is the authority on both questions; this mirrors its gate so the
// client does not spend a round trip on an answer it already knows is "no".

import { moderation } from "./relay-rules.ts";
import type { ChannelInfo, UserInfo } from "./types.ts";

/**
 * Would the server answer us about this channel?
 *
 * Mirrors `is_channel_public_or_member` in crates/voipc-server/src/state.rs: a
 * channel that hides its members, or has a password, tells nobody outside it
 * who is in there — and an admin is answered regardless. Our own channel is
 * excluded because it is pushed to us as a `UserList`, which is authoritative
 * and always fresher than anything we asked for.
 *
 * Being wrong here costs an empty reply, never a name we should not have had:
 * the server checks again, and it is the one that decides.
 */
export function worthAsking(
  channel: ChannelInfo,
  currentChannelId: number,
  admin: boolean,
  joinedTextChannelIds: ReadonlySet<number> = new Set(),
  live = false,
): boolean {
  if (channel.channel_id === currentChannelId) return false;
  // On the live path nothing asks about a text channel by itself: an ask says which one a
  // person looks at. An open one's list is who is online, and the sweep keeps the others.
  if (live && channel.text) return false;
  if (admin) return true;
  // A text channel we joined answers us as a member: the server asks whether
  // we are *in* the channel, not which one we stand in. Without this a text
  // channel with a password or hidden members would be asked about once, at
  // the join, and then never again — its roster would freeze while people
  // came and went, in exactly the channels where that matters most.
  if (joinedTextChannelIds.has(channel.channel_id)) return true;
  if (channel.hide_members) return false;
  if (channel.has_password) return false;
  return true;
}

/**
 * Whether a roster that just arrived may correct the channel's member count.
 *
 * The count on a row is arithmetic: the server sends the channel list once, at
 * login, and every join and leave after that is a broadcast the client adds or
 * subtracts. A broadcast that never arrives — the send queue was full, the
 * channel was not in our list yet — is a permanent error, and the number stays
 * wrong until the next reconnect. A roster we asked for is a fresh count, so
 * it heals that.
 *
 * Except when the answer is empty, which the server also sends when it refuses
 * the question (`RequestChannelUsers` for a locked channel we are not in
 * answers `users: []`). "Nobody is in there" and "you may not know" are the
 * same reply, so an empty one only counts where the server would have answered
 * us honestly.
 */
export function trustRosterCount(
  list: UserInfo[],
  channel: ChannelInfo,
  currentChannelId: number,
  admin: boolean,
  joinedTextChannelIds: ReadonlySet<number> = new Set(),
): boolean {
  if (list.length > 0) return true;
  return (
    channel.channel_id === currentChannelId ||
    worthAsking(channel, currentChannelId, admin, joinedTextChannelIds)
  );
}

/** Someone came to a channel or left one, as the broadcast said it. */
export type RosterChange = { join: UserInfo } | { left: number; channel: number };

/**
 * A batch of comings and goings, in the order they came, over the rosters: what each
 * changes, and by how much each channel's count moves. Someone already on the list is
 * replaced and not counted twice, as a list and a broadcast are built separately. A join
 * with no name or no id says only that the count moved: it is all this client may know.
 */
export function applyRosterChanges(
  rosters: ReadonlyMap<number, UserInfo[]>,
  changes: readonly RosterChange[],
): { rosters: Map<number, UserInfo[]>; moved: Map<number, number> } {
  const next = new Map(rosters);
  const moved = new Map<number, number>();
  const count = (channel: number, by: number) => moved.set(channel, (moved.get(channel) ?? 0) + by);
  for (const change of changes) {
    if ("join" in change) {
      const u = change.join;
      const list = next.get(u.channel_id);
      if (!u.username || !u.user_id) {
        count(u.channel_id, 1);
      } else if (list?.some((x) => x.user_id === u.user_id)) {
        next.set(u.channel_id, list.map((x) => (x.user_id === u.user_id ? u : x)));
      } else {
        next.set(u.channel_id, [...(list ?? []), u]);
        count(u.channel_id, 1);
      }
    } else {
      const list = next.get(change.channel);
      if (list) next.set(change.channel, list.filter((x) => x.user_id !== change.left));
      count(change.channel, -1);
    }
  }
  return { rosters: next, moved };
}

/**
 * Who is online in `rosters`, by id: General and the rooms, whose lists anyone may ask for.
 * On the live path that is who may be reading an open text channel.
 */
export function onlineIn(
  rosters: ReadonlyMap<number, UserInfo[]>,
  channels: readonly Pick<ChannelInfo, "channel_id" | "text">[],
  ownUsers: readonly UserInfo[],
): Map<number, UserInfo> {
  const text = new Set(channels.filter((c) => c.text).map((c) => c.channel_id));
  const online = new Map<number, UserInfo>();
  for (const [channelId, list] of rosters) {
    if (text.has(channelId)) continue;
    for (const u of list) online.set(u.user_id, u);
  }
  for (const u of ownUsers) online.set(u.user_id, u);
  return online;
}

/** Who a channel's pane lists: on the live path everyone online for an open text channel,
 *  where anyone may read, and otherwise that channel's own list. */
export function listedHere(
  channelId: number,
  rosters: ReadonlyMap<number, UserInfo[]>,
  currentChannelId: number,
  ownUsers: UserInfo[],
  channels: readonly Pick<ChannelInfo, "channel_id" | "text">[],
  openText: boolean,
): UserInfo[] {
  return openText ? [...onlineIn(rosters, channels, ownUsers).values()] : rosterOf(channelId, rosters as Map<number, UserInfo[]>, currentChannelId, ownUsers);
}

/**
 * The people to draw under a channel row.
 *
 * A roster we fetched before joining a channel must not shadow the push we get
 * once we are in it — those differ, because an anonymous channel answers an
 * outsider with pseudonyms and a member with names.
 */
export function rosterOf(
  channelId: number,
  rosters: Map<number, UserInfo[]>,
  currentChannelId: number,
  ownUsers: UserInfo[],
): UserInfo[] {
  return channelId === currentChannelId ? ownUsers : (rosters.get(channelId) ?? []);
}

/**
 * The people to draw under one row, with *that row's* hide-members rule.
 *
 * `hide_members` belongs to the channel it is set on. A sidebar that draws
 * members under every row has to ask the question once per row: reading it off
 * whichever channel the member list happens to be showing — which follows the
 * text channel the user opened — blanks the row of the voice room they are
 * standing in, whose members they could see a moment ago and can hear right now.
 *
 * Only our own row needs the rule applied here at all. Every other roster was
 * answered by the server, which applies it there and refuses rather than
 * blanking; ours is pushed to us in full, because we are in it.
 */
export function rosterForRow(
  channel: ChannelInfo,
  rosters: Map<number, UserInfo[]>,
  currentChannelId: number,
  ownUsers: UserInfo[],
  admin: boolean,
): UserInfo[] {
  if (channel.channel_id === currentChannelId && channel.hide_members && !admin) return [];
  return rosterOf(channel.channel_id, rosters, currentChannelId, ownUsers);
}

/**
 * Whether to offer an invite to `room`, the one we stand in, on the strength of
 * `voipc:channels` rather than of having made it.
 *
 * Mirrors `check_invite` in crates/voipc-server/src/state.rs, which decides: the
 * lobby takes no invites, and an anonymous room is the one place we go by a
 * pseudonym, from behind which the relay lets nobody summon.
 */
export function summonOffered(room: ChannelInfo | undefined, holds: boolean, protocol: number | null): boolean {
  return holds && moderation(protocol) && !!room && room.channel_id !== 0 && !room.anonymous;
}
