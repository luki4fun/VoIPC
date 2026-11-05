// A block is a view: what somebody blocked sends is filed like anything else, and
// only stops counting and being listed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

await import("./node-stores.mjs");
const {
  addChannelMessage,
  addDmMessage,
  applyChannelEvent,
  applyDmEvent,
  applyStoredDmEvent,
  channelMessages,
  chatKey,
  clearServerUnread,
  dmConversations,
  dmKey,
  dmList,
  dmMessages,
  ensureAwayDm,
  fileStoredChannelMessage,
  fileStoredDm,
  mergeChannelHistory,
  populateFromArchive,
  quietBlockedDms,
  renameChannelChat,
} = await import("./chat.ts");
const { blocked } = await import("./blocks.ts");
const { serverAddress, userId } = await import("./connection.ts");

const S = "h.example:9987";
const ME = 1;
const BOB = "b0".repeat(16);
const list = new Map([[`a:${BOB}`, "bobby"]]);
const message = (content: string, timestamp: number) => ({ user_id: 5, username: "bobby", content, timestamp, id: `m${timestamp}`, account: BOB });
const stored = (content: string, timestamp: number) => ({
  peer_name: "bobby",
  peer_account: BOB,
  from_me: false,
  message_id: `s${timestamp}`,
  content,
  timestamp,
});
const own = { name: "me", account: "aa".repeat(16) };

function reset(block: boolean) {
  serverAddress.set(S);
  userId.of(S).set(ME);
  dmConversations.of(S).set([]);
  dmMessages.set(new Map());
  blocked.of(S).set(block ? new Map(list) : new Map());
}

const texts = () => (get(dmMessages).get(dmKey(S, "bobby")) ?? []).map((m: { content: string }) => m.content);
const row = () => get(dmConversations.peek(S)).find((c: { username: string }) => c.username === "bobby");
const listed = () => get(dmList).map((r: { convo: { username: string } }) => r.convo.username);

test("the control: a direct message from anybody else counts and is listed", () => {
  reset(false);
  addDmMessage(S, ME, 5, "bobby", ME, message("hello", 10));
  assert.equal(row()?.unread, 1);
  assert.deepEqual(listed(), ["bobby"]);
});

test("a blocked direct message is filed with no unread and no listed row, and unblocking lists it again", () => {
  reset(true);
  addDmMessage(S, ME, 5, "bobby", ME, message("hello", 10));
  assert.deepEqual(texts(), ["hello"], "kept");
  assert.equal(row()?.unread, 0);
  assert.deepEqual(listed(), []);
  blocked.of(S).set(new Map());
  assert.deepEqual(listed(), ["bobby"]);
  assert.equal(row()?.unread, 0, "nothing of it counts afterwards");
});

test("by the name, when the live message's account is unknown", () => {
  reset(true);
  addDmMessage(S, ME, 5, "bobby", ME, { ...message("hello", 10), account: undefined });
  assert.equal(row()?.unread, 0);
  assert.deepEqual(listed(), []);
});

test("the stored path too", () => {
  reset(false);
  fileStoredDm(S, stored("kept for me", 10), own, undefined, undefined);
  assert.equal(row()?.unread, 1, "the control");
  assert.deepEqual(listed(), ["bobby"]);

  reset(true);
  fileStoredDm(S, stored("kept for me", 10), own, undefined, undefined);
  assert.deepEqual(texts(), ["kept for me"], "kept");
  assert.equal(row()?.unread, 0);
  assert.deepEqual(listed(), []);
  blocked.of(S).set(new Map());
  assert.deepEqual(listed(), ["bobby"]);
});

test("what someone newly blocked had waiting stops counting", () => {
  reset(false);
  addDmMessage(S, ME, 5, "bobby", ME, message("hello", 10));
  addDmMessage(S, ME, 6, "carol", ME, { ...message("hi", 11), username: "carol", account: "cc".repeat(16) });
  quietBlockedDms(S);
  assert.equal(row()?.unread, 1, "nobody is blocked yet");
  blocked.of(S).set(new Map(list));
  quietBlockedDms(S);
  assert.equal(row()?.unread, 0);
  assert.equal(get(dmConversations.peek(S)).find((c: { username: string }) => c.username === "carol")?.unread, 1, "and only theirs");
});

// ── A hide in the stored log can come before what it hides ─────────────────────

const ROOM = "lobby";
const HIDER = { user_id: 3, username: "kim", account: "aa".repeat(16) };
const hide = (target: string, at = Date.now(), on = true) => ({ event: { kind: "hide", target, on }, by: HIDER, at, content: "" });
const anyone = () => true;
const spam = (id: string, over: object = {}) => ({ user_id: 9, username: "dan", content: "spam", timestamp: Date.now() - 1000, id, account: "dd".repeat(16), ...over });
const roomRows = () => get(channelMessages).get(chatKey(S, ROOM)) ?? [];

function freshRoom() {
  clearServerUnread(S);
  channelMessages.set(new Map());
  dmMessages.set(new Map());
}

test("a hide before its target takes it when it arrives live, and it is no news", () => {
  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  assert.equal(addChannelMessage(S, ROOM, spam("a")), false, "no count, no sound, no notification with its text");
  assert.equal(roomRows()[0].hide?.on, true);
  assert.equal(roomRows()[0].content, "spam", "kept");
});

test("from the stored log too", () => {
  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  assert.equal(fileStoredChannelMessage(S, ROOM, spam("a")), false);
  assert.equal(roomRows()[0].hide?.on, true);
});

test("and a member's hand-off", () => {
  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  mergeChannelHistory(S, ROOM, [spam("a")], "ann");
  const row = roomRows().find((m: { id?: string }) => m.id === "a");
  assert.equal(row?.hide?.on, true);
});

test("the control: a hide by someone who may not does nothing, then or later", () => {
  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, undefined);
  assert.equal(addChannelMessage(S, ROOM, spam("a")), true, "news like any other");
  assert.equal(roomRows()[0].hide, undefined);
});

test("what it is asked about each copy, it is asked about a later one", () => {
  freshRoom();
  const moderatorsAreSpared = (m: { account?: string }) => m.account !== "ee".repeat(16);
  applyChannelEvent(S, ROOM, hide("a"), false, moderatorsAreSpared);
  assert.equal(addChannelMessage(S, ROOM, spam("a", { account: "ee".repeat(16), username: "kim2" })), true);
  assert.equal(roomRows()[0].hide, undefined);
});

test("a repeated id arriving first does not use the hide up", () => {
  freshRoom();
  addChannelMessage(S, ROOM, spam("a", { account: "ee".repeat(16), username: "evil", content: "decoy" }));
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  assert.equal(roomRows()[0].hide?.on, true);
  fileStoredChannelMessage(S, ROOM, spam("a"));
  assert.deepEqual(roomRows().map((m: { hide?: { on: boolean } }) => m.hide?.on), [true, true]);
});

test("a restore read after it wins whichever arrives first", () => {
  freshRoom();
  const at = Date.now();
  applyChannelEvent(S, ROOM, hide("a", at + 10, false), false, anyone);
  applyChannelEvent(S, ROOM, hide("a", at, true), false, anyone);
  assert.equal(addChannelMessage(S, ROOM, spam("a")), true);
  assert.equal(roomRows()[0].hide?.on, false);
});

test("the archive opening after a hide was read takes it too", () => {
  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  populateFromArchive({ channels: { [chatKey(S, ROOM)]: [spam("a")] }, dms: {} });
  assert.equal(roomRows()[0].hide?.on, true);
});

test("a channel's new name keeps what it remembered, and a new connection does not", () => {
  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  renameChannelChat(S, ROOM, "foyer");
  addChannelMessage(S, "foyer", spam("a"));
  assert.equal(get(channelMessages).get(chatKey(S, "foyer"))?.[0].hide?.on, true);

  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  clearServerUnread(S);
  addChannelMessage(S, ROOM, spam("a"));
  assert.equal(roomRows()[0].hide, undefined);
});

test("it remembers a bounded number per conversation", () => {
  freshRoom();
  for (let i = 0; i < 300; i++) applyChannelEvent(S, ROOM, hide(`old${i}`), false, anyone);
  addChannelMessage(S, ROOM, spam("old0"));
  addChannelMessage(S, ROOM, spam("old299"));
  assert.deepEqual(roomRows().map((m: { hide?: object }) => !!m.hide), [false, true], "the oldest went");
});

test("what a plain member floods it with pushes nobody's hide out", () => {
  freshRoom();
  applyChannelEvent(S, ROOM, hide("a"), false, anyone);
  for (let i = 0; i < 300; i++) applyChannelEvent(S, ROOM, hide(`m${i}`), false, undefined);
  addChannelMessage(S, ROOM, spam("a"));
  assert.equal(roomRows()[0].hide?.on, true);
});

test("a hide in a direct conversation changes nothing, live or stored", () => {
  freshRoom();
  reset(false);
  addDmMessage(S, ME, 5, "bobby", ME, message("hello", 10));
  const before = get(dmMessages).get(dmKey(S, "bobby"));
  const target = before[0].id;
  applyDmEvent(S, ME, 5, "bobby", ME, hide(target));
  applyStoredDmEvent(S, "bobby", hide(target));
  assert.equal(get(dmMessages).get(dmKey(S, "bobby")), before);
  assert.equal(before[0].hide, undefined);
});

test("a report to someone away is filed under their row, not the open conversation or Unknown", () => {
  const server = "report.test:9987";
  const own = { user_id: 1, username: "carla", content: "look", timestamp: 1 };
  // The control: what writing to a made-up id with no row does
  addDmMessage(server, 1, 1, "carla", -12345, { ...own, id: "before" });
  assert.ok(get(dmMessages).get(dmKey(server, "Unknown"))?.some((m) => m.id === "before"), "it had no name");

  const bob = "b0".repeat(16);
  const id = ensureAwayDm(server, "bobby", bob);
  assert.ok(id < 0, "a made-up id");
  addDmMessage(server, 1, 1, "carla", id, { ...own, id: "r1" });
  assert.ok(get(dmMessages).get(dmKey(server, "bobby"))?.some((m) => m.id === "r1"));
  const row = get(dmConversations.peek(server)).find((c) => c.username === "bobby");
  assert.equal(row?.user_id, id);
  assert.equal(row?.account, bob, "where writing to them goes");
  assert.equal(row?.unread, 0, "our own copy counts for nothing");

  // A second one goes in the same row, and one that stands there already stays
  assert.equal(ensureAwayDm(server, "bobby", bob), id);
  assert.equal(get(dmConversations.peek(server)).filter((c) => c.username === "bobby").length, 1);
  addDmMessage(server, 1, 5, "erin", 1, { ...own, user_id: 5, username: "erin", id: "e1" });
  assert.equal(ensureAwayDm(server, "erin", "ee".repeat(16)), 5);
  assert.equal(get(dmConversations.peek(server)).find((c) => c.username === "erin")?.account, "ee".repeat(16));
});
