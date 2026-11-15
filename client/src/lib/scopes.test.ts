import { test } from "node:test";
import assert from "node:assert/strict";

import { allowed, canWith, grants, noPowerOverAnyone, noTabLine, PRIVILEGES, privilegesOn, SHARE_HISTORY, toggledScope } from "./scopes.ts";

test("a grant covers what l4f says it covers, and nothing more", () => {
  assert.equal(grants("*", "voipc:kick"), true);
  assert.equal(grants("voipc:*", "voipc:kick"), true);
  assert.equal(grants("voipc:*", "voipcx:kick"), false, "a wildcard ends on a segment");
  assert.equal(grants("voipc:kick", "voipc:kickx"), false);
  assert.equal(grants("voipc*", "voipcx"), false, "a malformed grant grants nothing");
  assert.equal(grants("voipc:kick", "voipc:*"), false, "a wildcard is no requirement");
  assert.equal(grants("Voipc:kick", "voipc:kick"), false, "lowercase only");
});

test("can: an admin may do everything, an account what its scopes say", () => {
  assert.equal(allowed(["users:read", "voipc:ban"], "voipc:ban"), true);
  assert.equal(allowed([], "voipc:ban"), false);
  assert.equal(canWith([], true)("roles:admin"), true);
  assert.equal(canWith(["voipc:emotes"], false)("voipc:emotes"), true);
  assert.equal(canWith(["voipc:emotes"], false)("voipc:kick"), false);
});

test("a moderator on a relay before 1.7 still kicks, bans and changes channels", () => {
  for (const s of ["voipc:kick", "voipc:ban", "voipc:channels"]) assert.equal(allowed(["voipc:moderate"], s), true, s);
  assert.equal(allowed(["voipc:moderate"], "voipc:bans"), false, "the ban list stayed an admin's");
  assert.equal(allowed(["voipc:moderate"], "voipc:emotes"), false);
});

test("a relay is offered only the privileges it has heard of", () => {
  const offered = (p: number | null) => privilegesOn(p).map((x) => x.scope);
  const newest = ["voipc:restrict", "voipc:hide", "voipc:reports", "voipc:modlog"];
  const community = ["voipc:profiles", "voipc:mention_all"];
  assert.deepEqual(offered(null), PRIVILEGES.map((x) => x.scope), "our own protocol has them all");
  assert.deepEqual(offered(21), offered(null));
  assert.equal(offered(20).includes(SHARE_HISTORY), false, "a relay at 20 would refuse the whole group");
  assert.deepEqual(offered(19), offered(20));
  for (const s of newest) {
    assert.equal(offered(18).includes(s), false, `${s} at 18`);
    assert.equal(offered(19).includes(s), true, `${s} at 19`);
  }
  for (const s of community) {
    assert.equal(offered(17).includes(s), false, `${s} at 17`);
    assert.equal(offered(18).includes(s), true, `${s} at 18`);
  }
  // Every relay with a group editor keeps what it has always had
  const always = PRIVILEGES.filter((x) => !x.since).map((x) => x.scope);
  assert.deepEqual(offered(16), always);
  for (const s of ["*", "voipc:kick", "voipc:ban", "voipc:channels", "roles:admin"]) assert.equal(always.includes(s), true, s);
});

test("the privileges have one row each, so the group editor's keyed list holds", () => {
  const scopes = PRIVILEGES.map((x) => x.scope);
  assert.equal(new Set(scopes).size, scopes.length);
});

test("a group holding nothing, or only Share history, has no power over anyone", () => {
  assert.equal(noPowerOverAnyone([]), true);
  assert.equal(noPowerOverAnyone([SHARE_HISTORY]), true);
  assert.equal(noPowerOverAnyone([SHARE_HISTORY, "voipc:kick"]), false);
  assert.equal(noPowerOverAnyone(["voipc:mention_all"]), false, "what spares nobody can still be power to hand out");
  assert.equal(noPowerOverAnyone(["voipc:*"]), false);
  assert.equal(noPowerOverAnyone(["*"]), false);
});

// W3-25: Manage accounts alone opened the panel on the Bans form, with no way to the account list
test("managing accounts comes with seeing them, either way round", () => {
  assert.deepEqual(toggledScope(["voipc:ban"], "users:admin", true), ["users:admin", "users:read", "voipc:ban"]);
  assert.deepEqual(toggledScope(["users:admin", "users:read"], "users:read", false), []);
  assert.deepEqual(toggledScope(["users:admin", "users:read"], "users:admin", false), ["users:read"], "seeing alone is fine");
  assert.deepEqual(toggledScope([], "voipc:ban", true), ["voipc:ban"], "the control: others go alone");
  assert.match(noTabLine((s) => s === "users:admin"), /See accounts/);
  assert.doesNotMatch(noTabLine(() => false), /See accounts/);
});
