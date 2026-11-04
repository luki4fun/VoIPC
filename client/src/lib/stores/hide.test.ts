// Who a hide counts from, by what the relay and the roster say: `hideCheck`. The
// rule itself is channel-post-rules.ts `hideRight`, here what feeds it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

await import("./node-stores.mjs");
const { channels } = await import("./channels.ts");
const { hideCheck, unhurriedOn } = await import("./channel-ui.ts");
const { addChannelMessage, applyChannelEvent, channelMessages, chatKey, clearServerUnread } = await import("./chat.ts");
const { foldedLine } = await import("../block-rules.ts");
const { rowKey } = await import("../chat-rules.ts");
const { account } = await import("./account.ts");
const { isAdmin, serverAddress, userId } = await import("./connection.ts");
const { chatMods, onChatMods } = await import("./powers.ts");
const { olderRelay } = await import("./relay.ts");
const { channelRosters } = await import("./rosters.ts");
const { users } = await import("./users.ts");

const S = "h.example:9987";
const ROOM = 4;
const SECRET = 5;
const hex = (b: number) => b.toString(16).padStart(2, "0").repeat(16);
const bytes = (b: number) => new Array(16).fill(b);
const MOD = hex(0xb0);
const ADMIN = hex(0xa0);
const HELPER = hex(0xc0);
const MEMBER = hex(0xd0);
const message = (over: object = {}) => ({ user_id: 9, username: "dan", content: "x", timestamp: 1, id: "m1", account: MEMBER, ...over });

function reset() {
  serverAddress.set(S);
  userId.of(S).set(1);
  isAdmin.of(S).set(false);
  account.of(S).set(null);
  olderRelay.of(S).set(null);
  users.of(S).set([]);
  channelRosters.of(S).set(new Map());
  channels.of(S).set([
    { channel_id: ROOM, name: "room", anonymous: false },
    { channel_id: SECRET, name: "secret", anonymous: true },
  ]);
  onChatMods(S, [
    { account: bytes(0xb0), hide: true, admin: false },
    { account: bytes(0xa0), hide: true, admin: true },
    { account: bytes(0xc0), hide: false, admin: false },
  ]);
}

const offline = (account?: string) => ({ user_id: 0, username: "someone", account });

test("someone listed counts while away: the whole point of the list", () => {
  reset();
  const may = hideCheck(S, ROOM, offline(MOD));
  assert.ok(may, "by account, with no connection of theirs");
  assert.equal(may(message()), true);
});

test("the control: a plain member, a guest, and a holder of something else", () => {
  reset();
  assert.equal(hideCheck(S, ROOM, offline(MEMBER)), undefined);
  assert.equal(hideCheck(S, ROOM, offline(undefined)), undefined);
  assert.equal(hideCheck(S, ROOM, offline(HELPER)), undefined, "listed, without the hide");
});

test("the list is what the relay said last, whole", () => {
  reset();
  onChatMods(S, []);
  assert.equal(hideCheck(S, ROOM, offline(MOD)), undefined);
  assert.equal(get(chatMods.of(S)).size, 0);
  // A repeat from a relay collapses
  onChatMods(S, [{ account: bytes(1), hide: true, admin: false }, { account: bytes(1), hide: false, admin: false }]);
  assert.equal(get(chatMods.of(S)).size, 1);
});

test("nothing counts in an anonymous channel, an admin's neither", () => {
  reset();
  assert.equal(hideCheck(S, SECRET, offline(MOD)), undefined);
  assert.equal(hideCheck(S, SECRET, offline(ADMIN)), undefined);
  assert.equal(hideCheck(S, ROOM + 100, offline(MOD)), undefined, "a channel not listed either");
});

test("nothing counts on a relay that cannot have said so", () => {
  reset();
  olderRelay.of(S).set({ protocol: 18, version: "1.9.0" });
  assert.equal(hideCheck(S, ROOM, offline(ADMIN)), undefined);
  assert.equal(unhurriedOn(S), false);
});

test("a listed writer is spared from a moderator, not an admin; a member's copy names nobody", () => {
  reset();
  const fromMod = hideCheck(S, ROOM, offline(MOD));
  const fromAdmin = hideCheck(S, ROOM, offline(ADMIN));
  const held = message({ account: HELPER });
  assert.equal(fromMod(held), false);
  assert.equal(fromAdmin(held), true);
  assert.equal(fromMod(message({ account: ADMIN })), false, "nor an admin, by a moderator");
  assert.equal(fromMod({ ...held, kind: "shared" }), true, "hearsay");
  assert.equal(fromMod(message({ account: undefined })), true, "no account known: nobody spared");
});

test("a token admin counts through the roster, while they are in it", () => {
  reset();
  const token = { user_id: 7, username: "root" };
  assert.equal(hideCheck(S, ROOM, token), undefined);
  users.of(S).set([{ user_id: 7, username: "root", is_admin: true }]);
  const may = hideCheck(S, ROOM, token);
  assert.ok(may);
  assert.equal(may(message({ account: MOD })), true, "an admin acts on other holders");
  users.of(S).set([]);
  channelRosters.of(S).set(new Map([[ROOM, [{ user_id: 7, username: "root", is_admin: true }]]]));
  assert.ok(hideCheck(S, ROOM, token), "or in the channel's own roster");
});

test("we count by our own scopes, as far as we know them", () => {
  reset();
  const me = { user_id: 1, username: "me", account: MEMBER };
  assert.equal(hideCheck(S, ROOM, me), undefined, "the control");
  assert.equal(unhurriedOn(S), false);
  account.of(S).set({ name: "me", relayId: "", cloud: true, info: { id: bytes(0xd0), scopes: ["voipc:hide"] } });
  assert.equal(unhurriedOn(S), true);
  const may = hideCheck(S, ROOM, me);
  assert.ok(may);
  assert.equal(may(message({ account: MOD })), false, "a moderator still spares another");
  isAdmin.of(S).set(true);
  assert.equal(hideCheck(S, ROOM, me)!(message({ account: MOD })), true);
});

test("someone away is not us, whatever our own id says before it is set", () => {
  reset();
  account.of(S).set({ name: "me", relayId: "", cloud: true, info: { id: bytes(0xd0), scopes: ["voipc:hide"] } });
  // A stored event's sender who is not online has id 0, and so have we until `connect` answers
  userId.of(S).set(0);
  assert.equal(hideCheck(S, ROOM, offline(hex(0xe0))), undefined);
  userId.of(S).set(1);
  assert.equal(hideCheck(S, ROOM, offline(hex(0xe0))), undefined, "nor afterwards");
});

test("a relay asserting a false holder gets a named fake moderator and one click, and destroys nothing", () => {
  reset();
  channelMessages.set(new Map());
  // Listed by nobody's say but the relay's, and signing as an account it made up
  const FAKE = hex(0x66);
  onChatMods(S, [{ account: bytes(0x66), hide: true, admin: true }]);
  const by = { user_id: 0, username: "Head Admin#0001", account: FAKE };
  addChannelMessage(S, "room", message({ content: "the words", account: MEMBER }));
  applyChannelEvent(S, "room", { event: { kind: "hide", target: "m1", on: true }, by, at: 5, content: "" }, false, hideCheck(S, ROOM, by));
  const row = get(channelMessages).get(chatKey(S, "room"))![0];
  const none = new Map<string, string>();
  assert.equal(foldedLine(none, row, false, new Set()), "Removed by Head Admin", "what it can do: say a name");
  assert.equal(row.content, "the words", "and what it cannot: the text is all there");
  assert.equal(foldedLine(none, row, false, new Set([rowKey(row)])), null, "one click from showing");
  // The control: unlisted, the very same event does nothing
  clearServerUnread(S);
  channelMessages.set(new Map());
  onChatMods(S, []);
  addChannelMessage(S, "room", message({ content: "the words", account: MEMBER }));
  applyChannelEvent(S, "room", { event: { kind: "hide", target: "m1", on: true }, by, at: 5, content: "" }, false, hideCheck(S, ROOM, by));
  assert.equal(get(channelMessages).get(chatKey(S, "room"))![0].hide, undefined);
});
