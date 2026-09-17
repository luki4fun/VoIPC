// What the sidebar may draw under a channel, and what it must not even ask for.
//
// The server is the authority on both — `is_channel_public_or_member` and
// `users_in_channel_for` in crates/voipc-server/src/state.rs. These pin the
// client's half: that it mirrors the same gate rather than inventing a laxer
// one, and that a roster fetched before joining never shadows the authoritative
// push for the channel we are actually in.

import { test } from "node:test";
import assert from "node:assert/strict";
import { rosterOf, worthAsking } from "./roster-rules.ts";
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

test("a channel we know nothing about draws nobody", () => {
  // Not an error and not a guess: a refused roster and an empty one look the
  // same here on purpose, because the difference is not ours to display.
  assert.deepEqual(rosterOf(42, new Map(), 7, [user(1, "me")]), []);
});
