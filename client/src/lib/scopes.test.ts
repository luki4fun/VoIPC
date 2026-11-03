import { test } from "node:test";
import assert from "node:assert/strict";

import { allowed, canWith, grants } from "./scopes.ts";

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
