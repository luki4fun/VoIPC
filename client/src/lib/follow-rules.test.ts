import { test } from "node:test";
import assert from "node:assert/strict";
import { goesByList, marksChannel, quietOn, quietSet, readersLine, stableName, toFollow, type FollowState } from "./follow-rules.ts";
import type { ChannelInfo } from "./types.ts";

const ch = (id: number, over: Partial<ChannelInfo> = {}): ChannelInfo =>
  ({ channel_id: id, name: `c${id}`, text: true, auto_join: true, has_password: false, nsfw: false, ...over }) as ChannelInfo;
const state = (over: Partial<FollowState> = {}): FollowState => ({ sent: new Set(), left: () => false, consented: false, ...over });

test("three hundred channels are one list, sorted, and only what is new", () => {
  const list = Array.from({ length: 300 }, (_, i) => ch(300 - i));
  const all = toFollow(list, state());
  assert.equal(all.length, 300);
  assert.deepEqual(all.slice(0, 3), [1, 2, 3]);
  assert.deepEqual(toFollow(list, state({ sent: new Set(all.slice(1)) })), [1]);
});

test("not a voice room, nor one the server does not ask to be followed", () => {
  assert.deepEqual(toFollow([ch(1, { text: false }), ch(2, { auto_join: false }), ch(3)], state()), [3]);
});

test("a password has nobody to ask, and a channel left stays left", () => {
  assert.deepEqual(toFollow([ch(1, { has_password: true }), ch(2), ch(3)], state({ left: (c) => c.channel_id === 2 })), [3]);
});

test("18+ waits for the person's yes, and comes once they said it", () => {
  const list = [ch(1, { nsfw: true }), ch(2)];
  assert.deepEqual(toFollow(list, state()), [2]);
  assert.deepEqual(toFollow(list, state({ consented: true })), [1, 2]);
});

test("a list decides where there is a gate, or a hand joined it", () => {
  assert.equal(goesByList(ch(1), false), false, "open and followed by itself");
  assert.equal(goesByList(ch(1), true), true, "gated");
  assert.equal(goesByList(ch(1, { auto_join: false }), false), true, "by hand");
  assert.equal(goesByList(ch(1, { has_password: true }), false), true, "behind a password");
  assert.equal(goesByList(ch(1), undefined), true, "not told yet: the careful answer");
  assert.equal(goesByList(undefined, false), true);
});

test("a mark holds across a rename by the channel's log, and by name where there is none", () => {
  const moved = { log: "c:dc-1", name: "new-name" };
  assert.equal(stableName(moved), "c:dc-1");
  assert.equal(marksChannel(["c:dc-1"], moved), true);
  assert.equal(marksChannel(new Set(["old-name"]), moved), false);
  assert.equal(marksChannel(["new-name"], moved), true);
  assert.equal(stableName({ log: "", name: "plain" }), "plain");
  assert.equal(marksChannel(["plain"], { log: "", name: "plain" }), true);
});

test("new readers are named, and past five the rest are a click away, never only a number", () => {
  assert.deepEqual(readersLine(["bob"]), { line: "bob can now read what you write here", all: [] });
  assert.equal(readersLine(["bob", "carol"]).line, "bob and carol can now read what you write here");
  assert.equal(readersLine(["a", "b", "c"]).line, "a, b and c can now read what you write here");
  const seven = ["a", "b", "c", "d", "e", "f", "g"];
  assert.deepEqual(readersLine(seven), { line: "a, b, c, d, e and 2 others can now read what you write here", all: seven });
  assert.equal(readersLine(seven.slice(0, 6)).line, "a, b, c, d, e and 1 other can now read what you write here");
});

test("quiet holds always, or by the network this device is on, and off changes nothing", () => {
  assert.equal(quietOn("off", true), false);
  assert.equal(quietOn("always", false), true);
  assert.equal(quietOn("mobile", false), false);
  assert.equal(quietOn("mobile", true), true);
});

test("everything followed goes quiet but what was picked, by log or by name", () => {
  const list = [ch(1, { log: "c:one" }), ch(2), ch(3)];
  assert.deepEqual([...quietSet(list, ["c:one", "c3"], true)], [2]);
  assert.deepEqual([...quietSet(list, [], false)], [], "when quiet does not hold, nothing");
});
