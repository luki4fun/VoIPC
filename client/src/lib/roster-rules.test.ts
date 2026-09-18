// What the sidebar may draw under a channel, and what it must not even ask for.
//
// The server is the authority on both — `is_channel_public_or_member` and
// `users_in_channel_for` in crates/voipc-server/src/state.rs. These pin the
// client's half: that it mirrors the same gate rather than inventing a laxer
// one, and that a roster fetched before joining never shadows the authoritative
// push for the channel we are actually in.

import { test } from "node:test";
import assert from "node:assert/strict";
import { rosterForRow, rosterOf, trustRosterCount, worthAsking } from "./roster-rules.ts";
import type { ChannelInfo, UserInfo } from "./types.ts";

function channel(over: Partial<ChannelInfo> = {}): ChannelInfo {
  return {
    channel_id: 1,
    name: "general",
    description: "",
    max_users: 0,
    user_count: 0,
    has_password: false,
    created_by: null,
    proximity: "off",
    hidden: false,
    anonymous: false,
    screen_share: true,
    hide_members: false,
    routed: false,
    text: false,
    auto_join: false,
    ...over,
  };
}

function user(id: number, name: string): UserInfo {
  return {
    user_id: id,
    username: name,
    channel_id: 1,
    is_muted: false,
    is_deafened: false,
    is_screen_sharing: false,
    is_admin: false,
    shares_history: false,
  };
}

test("an ordinary channel is worth asking about", () => {
  assert.equal(worthAsking(channel(), 0, false), true);
});

test("our own channel is never asked for", () => {
  // It is pushed to us as a UserList, which is both authoritative and fresher.
  assert.equal(worthAsking(channel({ channel_id: 7 }), 7, false), false);
});

test("the client does not ask what the server would refuse", () => {
  // Mirrors is_channel_public_or_member: a channel that hides its members, or
  // carries a password, tells nobody outside it who is in there.
  assert.equal(worthAsking(channel({ hide_members: true }), 0, false), false);
  assert.equal(worthAsking(channel({ has_password: true }), 0, false), false);
});

test("an admin is answered where everyone else is refused", () => {
  assert.equal(worthAsking(channel({ hide_members: true }), 0, true), true);
  assert.equal(worthAsking(channel({ has_password: true }), 0, true), true);
  // Still not our own channel, admin or not.
  assert.equal(worthAsking(channel({ channel_id: 7 }), 7, true), false);
});

test("a text channel we joined is asked about even when it would refuse an outsider", () => {
  // The server answers a member (is_channel_public_or_member), and a text
  // channel is not the channel we stand in, so its roster only ever changes by
  // broadcast. Never asking again would freeze it at the join snapshot.
  const joined = new Set([5]);
  const locked = channel({ channel_id: 5, has_password: true, text: true });
  assert.equal(worthAsking(locked, 0, false), false, "not joined: still refused");
  assert.equal(worthAsking(locked, 0, false, joined), true);
  assert.equal(
    worthAsking(channel({ channel_id: 5, hide_members: true, text: true }), 0, false, joined),
    true,
  );
  // Somebody else's locked channel stays out of reach
  assert.equal(worthAsking(channel({ channel_id: 6, has_password: true }), 0, false, joined), false);
});

test("an anonymous channel is asked about like any other", () => {
  // The pseudonyms are the server's job — it substitutes them in the answer.
  // Refusing to ask would hide a roster the server is willing to give.
  assert.equal(worthAsking(channel({ anonymous: true }), 0, false), true);
});

test("our own channel is drawn from the push, not from a stale answer", () => {
  const asked = new Map([[7, [user(1, "stale")]]]);
  const pushed = [user(1, "fresh"), user(2, "bob")];
  assert.deepEqual(rosterOf(7, asked, 7, pushed), pushed);
});

test("another channel is drawn from what we asked for", () => {
  const asked = new Map([[3, [user(9, "carol")]]]);
  assert.deepEqual(rosterOf(3, asked, 7, []), [user(9, "carol")]);
});

test("a roster corrects the member count, unless the empty one means 'refused'", () => {
  const locked = channel({ channel_id: 5, has_password: true });
  // A name in the answer is a real member, whatever channel it came from
  assert.equal(trustRosterCount([user(1, "a")], locked, 0, false), true);
  // Empty from a channel that would have answered us: really empty
  assert.equal(trustRosterCount([], channel({ channel_id: 5 }), 0, false), true);
  // Empty from one that refuses outsiders: says nothing about how many are in it
  assert.equal(trustRosterCount([], locked, 0, false), false);
  assert.equal(trustRosterCount([], locked, 0, true), true, "an admin is answered");
  assert.equal(trustRosterCount([], locked, 5, false), true, "our own channel is pushed");
  assert.equal(
    trustRosterCount([], channel({ channel_id: 5, has_password: true, text: true }), 0, false, new Set([5])),
    true,
    "a text channel we are in answers us as a member",
  );
});

test("a hidden-member text channel does not blank the room you stand in", () => {
  // Standing in voice channel 7, reading a text channel that hides its members.
  // The rule is the text channel's; the room's roster is not its to hide.
  const room = channel({ channel_id: 7 });
  const secretive = channel({ channel_id: 9, text: true, hide_members: true });
  const here = [user(1, "me"), user(2, "bob")];
  const rosters = new Map([[9, [user(3, "carol")]]]);

  assert.deepEqual(rosterForRow(room, rosters, 7, here, false), here);
  assert.deepEqual(rosterForRow(secretive, rosters, 7, here, false), [user(3, "carol")]);

  // And where it does apply — the channel we are in, whose roster is pushed to
  // us in full rather than filtered by the server — it still applies.
  const hiddenRoom = channel({ channel_id: 7, hide_members: true });
  assert.deepEqual(rosterForRow(hiddenRoom, rosters, 7, here, false), []);
  assert.deepEqual(rosterForRow(hiddenRoom, rosters, 7, here, true), here, "admins always see it");
});

test("a channel we know nothing about draws nobody", () => {
  // Not an error and not a guess: a refused roster and an empty one look the
  // same here on purpose, because the difference is not ours to display.
  assert.deepEqual(rosterOf(42, new Map(), 7, [user(1, "me")]), []);
});
