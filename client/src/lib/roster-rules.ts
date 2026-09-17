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
): boolean {
  if (channel.channel_id === currentChannelId) return false;
  if (admin) return true;
  if (channel.hide_members) return false;
  if (channel.has_password) return false;
  return true;
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
