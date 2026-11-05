// What changing a blocked list sends, and what a folded message still shows in.
// A guest's list goes nowhere, and an account's only to its backend as one sealed
// vault write (sync.rs tests what that write holds).

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const { blocked, blockedMember, foldedAt, loadGuestBlocks, onAccountBlocks, revealRow, revealedRows, toggleBlock, unblock } = await import("./blocks.ts");
const { account } = await import("./account.ts");
const { channels } = await import("./channels.ts");
const { notifications } = await import("./notifications.ts");
const { serverKey } = await import("./servers.ts");
const { uiPrefs, updateUiPrefs } = await import("./ui-prefs.ts");
const { dropServer, serverAddress } = await import("./scoped.ts");
const { BLOCKS_MAX } = await import("../block-rules.ts");

const S = "h.example:9987";
const KEY = serverKey(S);
const BOB = [...new Array(16).keys()].map((i) => i + 0xb0);
const BOB_KEY = `a:${BOB.map((x) => x.toString(16)).join("")}`;
const list = () => [...get(blocked.peek(S))];
const stored = () => get(uiPrefs).blocked[KEY];

function reset() {
  dropServer(S);
  updateUiPrefs((p) => {
    p.blocked = {};
  });
  revealedRows.set(new Set());
  notifications.set([]);
  invoked().length = 0;
}

const SIGNED_IN = { name: "me", relayId: "r", info: { id: [1], name: "me", scopes: [], needs_2fa: false, totp_enabled: false }, cloud: false };

test("a guest's block goes nowhere but this device, and a new connection reads it", async () => {
  reset();
  await toggleBlock(S, { username: "Eve#0001" });
  await toggleBlock(S, { account: BOB, username: "bobby" });
  assert.deepEqual(list(), [["g:eve#0001", "Eve#0001"], [BOB_KEY, "bobby"]]);
  assert.deepEqual(stored(), { "g:eve#0001": "Eve#0001", [BOB_KEY]: "bobby" });
  assert.deepEqual(invoked(), [], "no backend was asked for anything");
  // A connection lost forgets the store, and the next one starts from the prefs
  dropServer(S);
  assert.deepEqual(list(), []);
  loadGuestBlocks(S);
  assert.deepEqual(list().length, 2);
  await toggleBlock(S, { username: "eve#0001" });
  assert.deepEqual(list(), [[BOB_KEY, "bobby"]], "taken back, whichever way the name is written");
  await unblock(S, BOB_KEY, "bobby");
  assert.equal(stored(), undefined, "an empty list leaves nothing behind");
  assert.deepEqual(invoked(), []);
});

test("an account's block is one backend command, which answers with the list", async () => {
  reset();
  account.of(S).set(SIGNED_IN);
  await toggleBlock(S, { account: BOB, username: "bobby" });
  assert.deepEqual(invoked(), [["account_block", { server: S, key: BOB_KEY, label: "bobby", on: true }]]);
  assert.equal(stored(), undefined, "never in this device's settings");
  assert.deepEqual(list(), [], "the list is what the backend says");
  onAccountBlocks(S, [[BOB_KEY, "bobby"]]);
  assert.deepEqual(list(), [[BOB_KEY, "bobby"]]);
  invoked().length = 0;
  await toggleBlock(S, { username: "bobby" });
  assert.deepEqual(invoked(), [["account_block", { server: S, key: BOB_KEY, label: "bobby", on: false }]], "by the entry that matched");
  // Browser wasm gives undefined for nothing, the desktop null
  onAccountBlocks(S, undefined);
  assert.deepEqual(list(), []);
  onAccountBlocks(S, null);
  assert.deepEqual(list(), []);
});

test("a guest's list stops at the cap, and says so", async () => {
  reset();
  updateUiPrefs((p) => {
    p.blocked[KEY] = Object.fromEntries([...new Array(BLOCKS_MAX).keys()].map((i) => [`g:${i}`, `${i}`]));
  });
  loadGuestBlocks(S);
  await toggleBlock(S, { username: "one-more" });
  assert.equal(list().length, BLOCKS_MAX);
  assert.ok(get(notifications).some((n: { message: string }) => n.message.includes("at most")));
});

test("a member's mark follows the channel they are listed under", () => {
  reset();
  serverAddress.set(S);
  channels.of(S).set([{ channel_id: 7, name: "masks", anonymous: true }, { channel_id: 8, name: "open", anonymous: false }] as never);
  onAccountBlocks(S, [[BOB_KEY, "bobby"]]);
  const row = { account: BOB, username: "bobby" };
  assert.ok(get(blockedMember)({ ...row, channel_id: 8 }));
  assert.ok(!get(blockedMember)({ ...row, channel_id: 7 }), "nothing behind a pseudonym");
  assert.ok(get(blockedMember)({ ...row, channel_id: 0 }), "the lobby is no channel to hide in");
});

test("search and Files leave out what is folded, until it is shown", () => {
  reset();
  channels.of(S).set([{ channel_id: 7, name: "masks", anonymous: true }, { channel_id: 8, name: "open", anonymous: false }] as never);
  const m = { user_id: 5, username: "bobby", content: "hi", timestamp: 1, id: "m1", account: BOB_KEY.slice(2) };
  const open = { kind: "channel", server: KEY, name: "open" } as const;
  const dm = { kind: "dm", server: KEY, name: "bobby" } as const;
  assert.ok(!get(foldedAt)(open, m), "nobody blocked yet");
  onAccountBlocks(S, [[BOB_KEY, "bobby"]]);
  assert.ok(get(foldedAt)(open, m));
  assert.ok(get(foldedAt)(dm, m));
  assert.ok(!get(foldedAt)({ ...open, name: "masks" }, m), "not behind a pseudonym");
  assert.ok(!get(foldedAt)({ ...open, server: "other.example:1" }, m), "another server's list says nothing here");
  revealRow(m);
  assert.ok(!get(foldedAt)(open, m), "shown, it is found");
});
