import { test } from "node:test";
import assert from "node:assert/strict";
import { QUIET_ABOVE_MEMBERS, arrival, holdsToast, levelOf, nextLevel, pageInView } from "./notify-rules.ts";

test("a channel the server asks everyone to follow asks only for what is for you, whatever its size", () => {
  assert.equal(levelOf(undefined, 3, true), "mentions");
  assert.equal(levelOf(undefined, 3, false), "all", "the control: one joined by hand");
  assert.equal(levelOf("all", 3, true), "all", "their own choice stands");
});

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
  // W3-26: one forwarded into another channel counted as unread there
  assert.deepEqual(arrival("all", { mine: true, onScreen: false, forMe: false }), { count: false, sound: false, os: false });
  assert.deepEqual(arrival("all", { mine: false, onScreen: false, forMe: false }), { count: true, sound: true, os: false }, "the control");
});

test("the page counts as in view only if it is both shown and focused", () => {
  const page = (hidden: boolean, focused: boolean) => ({ hidden, hasFocus: () => focused });
  assert.equal(pageInView(page(false, true)), true);
  assert.equal(pageInView(page(true, true)), false, "a WebView behind HOME says it has focus");
  assert.equal(pageInView(page(false, false)), false, "another window has it");
  assert.equal(pageInView(page(true, false)), false);
});

test("only a mouse holds a toast's clock", () => {
  assert.equal(holdsToast("mouse"), true);
  assert.equal(holdsToast("touch"), false, "a tap gives no leave");
  assert.equal(holdsToast("pen"), false);
});
