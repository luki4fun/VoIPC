// The member list's pure helpers.

import { test } from "node:test";
import assert from "node:assert/strict";
import type { UserInfo } from "../types.ts";
import { patchUser, visibleMembers } from "./users.ts";

const user = (user_id: number, username: string): UserInfo => ({
  user_id,
  username,
  is_muted: false,
  is_deafened: false,
  is_screen_sharing: false,
  channel_id: 1,
});

const roster = [user(1, "alice"), user(2, "bob"), user(3, "carol")];

test("patchUser replaces one entry and leaves the rest identical", () => {
  const after = patchUser(roster, 2, { is_muted: true });

  assert.equal(after.length, 3);
  assert.equal(after[1].is_muted, true);
  assert.equal(after[1].username, "bob", "the patch must not drop the other fields");
  // Same objects, so a keyed {#each} does not tear down rows that did not change
  assert.equal(after[0], roster[0]);
  assert.equal(after[2], roster[2]);
  assert.notEqual(after[1], roster[1], "the patched row has to be a new object to be reactive");
  assert.equal(roster[1].is_muted, false, "the input list must not be mutated");
});

test("patchUser on an id nobody has is a no-op", () => {
  // Happens between disconnect and the next UserList: our own id is still set,
  // the roster is already empty.
  assert.deepEqual(patchUser(roster, 99, { is_muted: true }), roster);
  assert.deepEqual(patchUser([], 1, { is_muted: true }), []);
});

test("hidden members: yourself and whoever spoke recently", () => {
  const speakers = new Set([3]);
  assert.equal(visibleMembers(roster, 1, speakers, false).length, 3, "off means everyone");

  const shown = visibleMembers(roster, 1, speakers, true).map((u) => u.username);
  assert.deepEqual(shown, ["alice", "carol"]);
});
