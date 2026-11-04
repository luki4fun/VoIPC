// The composer's side of announcement channels, slow mode and 18+ channels.
// The server enforces the first two; these decide what the composer offers,
// so a post it would refuse is never shown as sent.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canManage,
  canManageAs,
  hideRight,
  needsNsfwConsent,
  postBlock,
  slowModeLabel,
  SLOW_MODE_CHOICES,
} from "./channel-post-rules.ts";

const member = { userId: 7, isAdmin: false, isModerator: false };

test("a channel's managers are its creator, admins and moderators — never in the lobby", () => {
  const ch = { channel_id: 3, created_by: 7 };
  assert.equal(canManage(ch, member), true, "the creator");
  assert.equal(canManage({ channel_id: 3, created_by: null }, member), false, "a member");
  assert.equal(canManage({ channel_id: 3, created_by: null }, { ...member, isAdmin: true }), true);
  assert.equal(canManage({ channel_id: 3, created_by: null }, { ...member, isModerator: true }), true);
  assert.equal(canManage({ channel_id: 0, created_by: null }, { ...member, isAdmin: true }), false);
  // Not connected yet: nobody's creator
  assert.equal(canManage({ channel_id: 3, created_by: null }, { ...member, userId: null }), false);
});

test("someone else manages a channel by their roles in the roster, as the user would", () => {
  const ch = { channel_id: 3, created_by: 9 };
  const ben = { user_id: 7, is_admin: false, is_moderator: false };
  assert.equal(canManageAs(ch, ben), false, "a member pins nothing");
  assert.equal(canManageAs(ch, { ...ben, is_admin: true }), true);
  assert.equal(canManageAs(ch, { ...ben, is_moderator: true }), true);
  assert.equal(canManageAs(ch, { ...ben, user_id: 9 }), true, "the creator");
  assert.equal(canManageAs(ch, { user_id: 7, is_admin: false }), false, "no moderator flag on a server without accounts");
  assert.equal(canManageAs(ch, null), false, "not in the roster: offline, or never here");
  assert.equal(canManageAs({ channel_id: 0, created_by: null }, { ...ben, is_admin: true }), false, "not in the lobby");
});

test("an announcement channel blocks members and lets managers post", () => {
  const ch = { text: true, announce: true, slow_mode_secs: 0 };
  assert.deepEqual(postBlock(ch, false, undefined, 0), { kind: "announce" });
  assert.equal(postBlock(ch, true, undefined, 0), null);
  // The flag means nothing on a voice room (the server refuses to set it there)
  assert.equal(postBlock({ ...ch, text: false }, false, undefined, 0), null);
});

test("slow mode counts down from this client's last post and exempts managers", () => {
  const ch = { text: true, announce: false, slow_mode_secs: 30 };
  assert.equal(postBlock(ch, false, undefined, 1_000), null, "a first post is free");
  assert.deepEqual(postBlock(ch, false, 0, 1_000), { kind: "slow", remainingSecs: 29 });
  assert.deepEqual(postBlock(ch, false, 0, 29_001), { kind: "slow", remainingSecs: 1 });
  assert.equal(postBlock(ch, false, 0, 30_000), null);
  assert.equal(postBlock(ch, true, 0, 1_000), null, "managers are not held back");
  // A channel from an older server has no such field at all
  assert.equal(postBlock({ text: true }, false, 0, 1), null);
});

test("18+ asks only for a marked channel, only until the user says yes", () => {
  assert.equal(needsNsfwConsent({ nsfw: true }, false), true);
  assert.equal(needsNsfwConsent({ nsfw: true }, true), false);
  assert.equal(needsNsfwConsent({ nsfw: false }, false), false);
  assert.equal(needsNsfwConsent({}, false), false);
  assert.equal(needsNsfwConsent(undefined, false), false);
});

test("slow-mode labels read like people talk", () => {
  assert.deepEqual(
    SLOW_MODE_CHOICES.map(slowModeLabel),
    ["Off", "5 s", "10 s", "30 s", "1 min", "5 min", "15 min", "1 h", "6 h"],
  );
  assert.equal(slowModeLabel(90), "90 s");
  // The server's cap: the dialog must not offer more than it accepts
  assert.equal(Math.max(...SLOW_MODE_CHOICES), 6 * 60 * 60);
});

test("whoever may hide: a holder, on anyone but another holder, and nobody in an anonymous channel", () => {
  const open = { anonymous: false };
  const holder = { hide: true, admin: false };
  const admin = { hide: true, admin: true };
  const nobody = { hide: false, admin: false };
  assert.equal(hideRight(open, nobody, false), false, "a plain member");
  assert.equal(hideRight(open, holder, false), true);
  assert.equal(hideRight({ anonymous: true }, holder, false), false, "it would unmask them as staff");
  assert.equal(hideRight({ anonymous: true }, admin, false), false, "an admin neither");
  assert.equal(hideRight(open, holder, true), false, "a listed writer is spared");
  assert.equal(hideRight(open, admin, true), true, "but for an admin, as with a kick");
  assert.equal(hideRight(open, { hide: false, admin: true }, true), true, "an admin holds it whatever the list says");
  // Not a privilege of its own, and no holder of another one hides by it
  assert.equal(hideRight(open, nobody, true), false);
});

test("a hide's holder is not hurried by slow mode, and stays out of an announcement channel", () => {
  const slow = { text: true, announce: false, slow_mode_secs: 60 };
  assert.deepEqual(postBlock(slow, false, 1000, 1000), { kind: "slow", remainingSecs: 60 }, "the control");
  assert.equal(postBlock(slow, false, 1000, 1000, true), null);
  assert.deepEqual(postBlock({ ...slow, announce: true }, false, 1000, 1000, true), { kind: "announce" });
});
