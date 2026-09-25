// Name tags. Pure functions only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomTag, shortName, splitName, withTag } from "./username.ts";

test("the tag is the last # and exactly four digits", () => {
  assert.deepEqual(splitName("luki#0420"), { name: "luki", tag: "0420" });
  assert.deepEqual(splitName("a#b#0001"), { name: "a#b", tag: "0001" });
  // Not a tag: all of it is the name
  assert.deepEqual(splitName("luki#12345"), { name: "luki#12345", tag: "" });
  assert.deepEqual(splitName("luki#12"), { name: "luki#12", tag: "" });
  assert.deepEqual(splitName("Guest-1234"), { name: "Guest-1234", tag: "" });
  assert.deepEqual(splitName(""), { name: "", tag: "" });
  assert.equal(shortName("bob#0001"), "bob");
});

test("a missing or malformed tag becomes a random one", () => {
  assert.equal(withTag(" luki ", "0420"), "luki#0420");
  for (const tag of ["", "42", "abcd", "12345"]) {
    const full = withTag("luki", tag);
    assert.match(full, /^luki#\d{4}$/, tag);
  }
  for (let i = 0; i < 1000; i++) assert.match(randomTag(), /^\d{4}$/);
});
