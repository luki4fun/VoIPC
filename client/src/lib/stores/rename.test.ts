// What this device keeps by a channel's name follows the channel when it is renamed: live
// (`channel-updated`), and while the device was away, by the channel's stored log.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

await import("./node-stores.mjs");
const { channelLogNames, channelMessages, chatKey, clearedBefore, renameChannelChat } = await import("./chat.ts");
const { channelsListed } = await import("./channel-ui.ts");

const S = "h.example:9987";
type Row = { user_id: number; username: string; content: string; timestamp: number; id: string; account: string };
const msg = (content: string, timestamp: number): Row => ({
  user_id: 5,
  username: "bobby",
  content,
  timestamp,
  id: `m-${content}`,
  account: "b0".repeat(16),
});
const texts = (name: string) => (get(channelMessages).get(chatKey(S, name)) ?? []).map((m: Row) => m.content);
// Only the name and the log count here
const ch = (name: string, log: string) => ({ name, log }) as unknown as Parameters<typeof channelsListed>[1][number];

function fresh(chats: Record<string, Row[]>, marks: Record<string, number> = {}) {
  channelMessages.set(new Map(Object.entries(chats).map(([name, rows]) => [chatKey(S, name), rows])));
  clearedBefore.set(new Map(Object.entries(marks).map(([name, at]) => [chatKey(S, name), at])));
}

// W2-12: `#general` deleted, its chat kept here on purpose, then `#chat` renamed onto its name
test("a rename onto a name this device still holds a chat for keeps both, and the later mark", () => {
  fresh({ general: [msg("old1", 10), msg("old2", 30)], chat: [msg("new1", 20), msg("old1", 10)] }, { general: 15, chat: 5 });
  renameChannelChat(S, "chat", "general");
  assert.deepEqual(texts("general"), ["old1", "new1", "old2"], "by time, each once");
  assert.equal(get(clearedBefore).get(chatKey(S, "general")), 15, "what was deleted stays deleted");
  assert.equal(get(channelMessages).has(chatKey(S, "chat")), false);
});

// W3-18
test("a channel renamed while this device was away takes its chat along, by its log", () => {
  fresh({ news: [msg("n", 1)] });
  channelsListed(S, [ch("news", "c:1"), ch("lobby", "")]);
  assert.equal(channelLogNames(S).get("c:1"), "news");
  assert.equal(channelLogNames(S).size, 1, "a channel with no log is not kept");
  channelsListed(S, [ch("updates", "c:1"), ch("lobby", "")]);
  assert.deepEqual(texts("updates"), ["n"]);
  assert.deepEqual(texts("news"), []);
  assert.equal(channelLogNames(S).get("c:1"), "updates");
  // The control: the same list again moves nothing
  channelsListed(S, [ch("updates", "c:1")]);
  assert.deepEqual(texts("updates"), ["n"]);
});

test("names passed along a chain or around a ring each keep their own chat", () => {
  fresh({ a: [msg("A", 1)], b: [msg("B", 2)], x: [msg("X", 3)], y: [msg("Y", 4)] });
  channelsListed(S, [ch("a", "c:a"), ch("b", "c:b"), ch("x", "c:x"), ch("y", "c:y")]);
  // a -> b while b -> c; x and y swap
  channelsListed(S, [ch("b", "c:a"), ch("c", "c:b"), ch("y", "c:x"), ch("x", "c:y")]);
  assert.deepEqual(texts("b"), ["A"]);
  assert.deepEqual(texts("c"), ["B"]);
  assert.deepEqual(texts("y"), ["X"]);
  assert.deepEqual(texts("x"), ["Y"]);
  assert.deepEqual(texts("a"), []);
  assert.equal([...get(channelMessages).keys()].filter((k) => k.includes("\u0000")).length, 0, "nothing left aside");
});
