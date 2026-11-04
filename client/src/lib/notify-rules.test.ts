import { test } from "node:test";
import assert from "node:assert/strict";
import { QUIET_ABOVE_MEMBERS, arrival, levelOf, nextLevel } from "./notify-rules.ts";

const other = { mine: false, onScreen: false, forMe: false };
const forMe = { ...other, forMe: true };

test("a choice wins over the channel's size", () => {
  assert.equal(levelOf("nothing", 2), "nothing");
  assert.equal(levelOf("all", 5000), "all");
});

test("with no choice, only a big channel keeps quiet", () => {
  assert.equal(levelOf(undefined, QUIET_ABOVE_MEMBERS), "all");
  assert.equal(levelOf(undefined, QUIET_ABOVE_MEMBERS + 1), "mentions");
});

test("the levels go round", () => {
  assert.deepEqual(["all", "mentions", "nothing"].map((l) => nextLevel(l as "all")), ["mentions", "nothing", "all"]);
});

test("every message counts and sounds on all", () => {
  assert.deepEqual(arrival("all", other), { count: true, sound: true, os: false });
  assert.deepEqual(arrival("all", forMe), { count: true, sound: true, os: true });
});

test("only what is for me does anything on mentions, and it is not silent", () => {
  assert.deepEqual(arrival("mentions", other), { count: false, sound: false, os: false });
  assert.deepEqual(arrival("mentions", forMe), { count: true, sound: true, os: true });
});

test("nothing is nothing, whatever the message", () => {
  assert.deepEqual(arrival("nothing", forMe), { count: false, sound: false, os: false });
});

test("what I am looking at neither counts nor sounds, and may still notify a window out of focus", () => {
  assert.deepEqual(arrival("all", { ...forMe, onScreen: true }), { count: false, sound: false, os: true });
});

test("my own message makes no sound, and tells me nothing", () => {
  assert.deepEqual(arrival("all", { mine: true, onScreen: false, forMe: false }), { count: true, sound: false, os: false });
});
