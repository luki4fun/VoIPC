// What the server says a ban removed: the copies here are hidden, never deleted, in
// channels only, on every way a copy can arrive.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const {
  addChannelMessage,
  applyChannelEvent,
  channelMessages,
  chatKey,
  clearedBefore,
  clearServerUnread,
  dmKey,
  dmMessages,
  fileStoredChannelMessage,
  mergeChannelHistory,
  onPostsHidden,
  populateFromArchive,
  purgeWritten,
} = await import("./chat.ts");
const { rowKey } = await import("../chat-rules.ts");
const { adminAction, adminBanAccount, adminRemovePosts, confirmAdminAction, openAdminAction } = await import("./user-menu.ts");
const { serverAddress } = await import("./connection.ts");

const S = "h.example:9987";
const OTHER = "o.example:9987";
const ROOM = "room";
const DAN_BYTES = new Array(16).fill(0xd0);
const DAN = "d0".repeat(16);
const NOW = Date.now();
const says = (id: string, over: object = {}) => ({ user_id: 5, username: "dan", content: `says ${id}`, timestamp: NOW - 1000, id, account: DAN, ...over });
const mark = (over: object = {}) => ({ account: DAN_BYTES, name: "dan", since_ms: NOW - 3_600_000, before_ms: NOW, by: "bobby", ...over });
const rows = (server = S) => get(channelMessages).get(chatKey(server, ROOM)) ?? [];

function fresh() {
  clearServerUnread(S);
  clearServerUnread(OTHER);
  channelMessages.set(new Map());
  dmMessages.set(new Map());
  clearedBefore.set(new Map());
}

test("a mark hides and never deletes", () => {
  fresh();
  addChannelMessage(S, ROOM, says("a"));
  addChannelMessage(S, ROOM, says("b", { account: "c0".repeat(16), username: "cat" }));
  const key = rowKey(rows()[0]);
  onPostsHidden(S, [mark()]);
  assert.equal(rows().length, 2, "all still here");
  assert.deepEqual(rows()[0].hide, { on: true, at: NOW, by: "bobby", ban: true });
  assert.equal(rows()[0].content, "says a");
  assert.equal(rowKey(rows()[0]), key, "its row stays");
  assert.equal(rows()[1].hide, undefined, "another writer's stays");
  assert.deepEqual([...get(clearedBefore)], [], "nothing is remembered as erased");
});

test("the control: a writer's own purge does remove, with a mark that stays", () => {
  fresh();
  addChannelMessage(S, ROOM, says("a"));
  purgeWritten(S, "channel", ROOM, DAN, NOW);
  assert.equal(rows().length, 0);
  assert.equal(get(clearedBefore).size, 1);
});

test("a direct conversation is the other party's too", () => {
  fresh();
  const key = dmKey(S, "dan");
  dmMessages.set(new Map([[key, [says("a")]]]));
  onPostsHidden(S, [mark()]);
  assert.equal(get(dmMessages).get(key)?.[0].hide, undefined);
});

test("another server's channel of the same name is another room", () => {
  fresh();
  addChannelMessage(OTHER, ROOM, says("a"));
  onPostsHidden(S, [mark()]);
  assert.equal(rows(OTHER)[0].hide, undefined);
});

test("what arrives live after it is hidden, and is no news", () => {
  fresh();
  onPostsHidden(S, [mark()]);
  assert.equal(addChannelMessage(S, ROOM, says("a")), false, "no count, no sound, no notification");
  assert.equal(rows()[0].hide?.ban, true);
  assert.equal(addChannelMessage(S, ROOM, says("later", { timestamp: NOW + 1 })), true, "the control: after the window");
  assert.equal(rows()[1].hide, undefined);
});

test("what the stored log brings too", () => {
  fresh();
  onPostsHidden(S, [mark()]);
  assert.equal(fileStoredChannelMessage(S, ROOM, says("a")), false, "it adds no unread");
  assert.equal(rows()[0].hide?.ban, true);
  assert.equal(fileStoredChannelMessage(S, ROOM, says("b", { account: "c0".repeat(16), username: "cat" })), true, "the control");
});

test("and what a member hands over, by the name it gives", () => {
  fresh();
  onPostsHidden(S, [mark()]);
  mergeChannelHistory(S, ROOM, [says("a", { account: undefined }), says("b", { username: "cat", account: undefined })], "fay");
  const held = rows().filter((m) => m.kind === "shared");
  assert.equal(held.find((m) => m.id === "a")?.hide?.ban, true);
  assert.equal(held.find((m) => m.id === "b")?.hide, undefined);
});

test("a stored copy replacing a live one stays hidden", () => {
  fresh();
  addChannelMessage(S, ROOM, says("a", { account: undefined }));
  onPostsHidden(S, [mark()]);
  fileStoredChannelMessage(S, ROOM, says("a"));
  assert.equal(rows().length, 1);
  assert.equal(rows()[0].account, DAN);
  assert.equal(rows()[0].hide?.ban, true);
});

test("a mark applies to what the archive brings later", () => {
  fresh();
  onPostsHidden(S, [mark()]);
  const stored = { ...says("a"), expires_at: undefined };
  populateFromArchive({ channels: { [chatKey(S, ROOM)]: [stored] }, dms: { [dmKey(S, "dan")]: [stored] }, cleared: {} });
  assert.equal(rows()[0].hide?.ban, true, "it replaces the store, and would have brought it all back");
  assert.equal(get(dmMessages).get(dmKey(S, "dan"))?.[0].hide, undefined);
});

test("a restore does not lift it, even one remembered from before", () => {
  fresh();
  const by = { user_id: 3, username: "mona", account: "aa".repeat(16) };
  const anyone = () => true;
  addChannelMessage(S, ROOM, says("a"));
  onPostsHidden(S, [mark()]);
  applyChannelEvent(S, ROOM, { event: { kind: "hide", target: "a", on: false }, by, at: NOW + 5000, content: "" }, false, anyone);
  assert.equal(rows()[0].hide?.ban, true);
  addChannelMessage(S, ROOM, says("b"));
  assert.equal(rows()[1].hide?.ban, true);
});

test("it is told again at each connect, so a new one starts with nothing", () => {
  fresh();
  onPostsHidden(S, [mark()]);
  clearServerUnread(S);
  assert.equal(addChannelMessage(S, ROOM, says("a")), true);
  assert.equal(rows()[0].hide, undefined);
  onPostsHidden(S, [mark()]);
  assert.equal(rows()[0].hide?.ban, true);
});

test("it holds to the frames and the number of them it is told", () => {
  fresh();
  addChannelMessage(S, ROOM, says("a"));
  addChannelMessage(S, ROOM, says("b", { account: undefined, username: "gus#0001" }));
  onPostsHidden(S, [mark({ account: "e0", name: "eve" })].slice(1));
  assert.equal(rows()[0].hide, undefined, "an empty frame");
  onPostsHidden(S, [mark()]);
  onPostsHidden(S, [mark({ account: null, name: "gus#0001", by: "mona" })]);
  assert.equal(rows()[0].hide?.by, "bobby");
  assert.equal(rows()[1].hide?.by, "mona");
  // Past what any relay honestly says, what it says still takes effect here
  for (let i = 0; i < 50; i++) {
    onPostsHidden(S, Array.from({ length: 100 }, (_, n) => mark({ account: null, name: `n${i}-${n}#0001` })));
  }
  addChannelMessage(S, ROOM, says("c", { account: undefined, username: "named#0001" }));
  onPostsHidden(S, [mark({ account: null, name: "named#0001" })]);
  assert.equal(rows()[2].hide?.ban, true);
});

// ── The ban dialog's two steps ──

const who = { user_id: 9, username: "dan", account: DAN_BYTES };
const lastInvokes = (since: number) => invoked().slice(since).map(([c, a]: [string, any]) => [c, a]);

test("removing with a ban: the ban first, of the account too, then the removal by name", async () => {
  serverAddress.set(S);
  const from = invoked().length;
  openAdminAction(who as never, "ban", 3600, "Ban for 1 hour");
  adminBanAccount.set(false);
  adminRemovePosts.set(86_400);
  await confirmAdminAction();
  const [ban, removal, ...rest] = lastInvokes(from);
  assert.equal(ban[0], "admin_ban");
  assert.equal(ban[1].account, true, "nothing kept goes without the account's ban");
  assert.equal(removal[0], "account_request");
  const { ask, ...sentStep } = (removal[1].request as { AdminAsk: { ask: number } }).AdminAsk;
  assert.equal(typeof ask, "number", "numbered");
  assert.deepEqual(sentStep, { op: { RemovePosts: { name: "dan", window_secs: 86_400 } }, code: null });
  assert.equal(removal[1].server, S);
  assert.deepEqual(rest, []);
});

test("all that is kept is the window 0, which is no 'no'", async () => {
  const from = invoked().length;
  openAdminAction(who as never, "ban", 3600, "Ban for 1 hour");
  adminRemovePosts.set(0);
  await confirmAdminAction();
  assert.deepEqual(lastInvokes(from)[1][1].request.AdminAsk.op, { RemovePosts: { name: "dan", window_secs: 0 } });
});

test("the control: a ban alone removes nothing, and asks only what it asked", async () => {
  const from = invoked().length;
  openAdminAction(who as never, "ban", 3600, "Ban for 1 hour");
  adminBanAccount.set(false);
  await confirmAdminAction();
  const asked = lastInvokes(from);
  assert.equal(asked.length, 1);
  assert.equal(asked[0][1].account, false);
});

test("a kick has no removal, whatever was chosen before", async () => {
  const from = invoked().length;
  openAdminAction(who as never, "ban", 3600, "Ban for 1 hour");
  adminRemovePosts.set(3600);
  openAdminAction(who as never, "kick", 0, "Kick from server");
  assert.equal(get(adminRemovePosts), null, "a new dialog starts at No");
  adminRemovePosts.set(3600);
  await confirmAdminAction();
  assert.deepEqual(lastInvokes(from).map(([c]: [string]) => c), ["admin_kick"]);
  assert.equal(get(adminAction), null);
});
