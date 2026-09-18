// Two rules about other channels' rosters: which ones are worth asking about,
// and where a row's members come from once they arrive.
//
// Pure, so roster-rules.test.ts can load them under Node's own test runner —
// stores/rosters.ts, which does the asking, reaches the backend and cannot.
//
// The server is the authority on both questions; this mirrors its gate so the
// client does not spend a round trip on an answer it already knows is "no".

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
): boolean {
  if (channel.channel_id === currentChannelId) return false;
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
