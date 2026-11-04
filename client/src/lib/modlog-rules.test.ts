import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeModRows, modAction, modPlace, removalDone, removalHint, removalReachesAccount, removalWindows } from "./modlog-rules.ts";
import type { ModRow } from "./types.ts";

const row = (id: number, reason = ""): ModRow => ({
  id,
  at: 1_800_000_000 + id,
  action: "kick",
  actor: "bobby",
  target: "dan",
  channel: null,
  reason,
  detail: "",
  advisory: false,
});

test("a repeated page leaves each row once, so a keyed each cannot throw", () => {
  const page = [row(5), row(4), row(3)];
  assert.deepEqual(mergeModRows(page, page).map((r) => r.id), [5, 4, 3]);
});

test("an older page goes under, overlapping or not, newest first", () => {
  assert.deepEqual(mergeModRows([row(5), row(4)], [row(4), row(3), row(2)]).map((r) => r.id), [5, 4, 3, 2]);
  // Out of order, as answers can cross when the tab is opened again
  assert.deepEqual(mergeModRows([row(2)], [row(9), row(1)]).map((r) => r.id), [9, 2, 1]);
  assert.deepEqual(mergeModRows([], []), []);
});

test("the row that came last is the one kept", () => {
  assert.equal(mergeModRows([row(5, "old")], [row(5, "new")])[0].reason, "new");
});

test("an action this app does not know shows as the relay names it", () => {
  assert.deepEqual(modAction("kick"), ["kicked", "from the server"]);
  assert.deepEqual(modAction("restrict"), ["restricted", ""]);
  assert.deepEqual(modAction("unrestrict"), ["lifted the restriction on", ""]);
  assert.deepEqual(modAction("summon"), ["invited", "to a channel"]);
  assert.deepEqual(modAction("remove_all_hats"), ["remove_all_hats", ""]);
  // Not a property lookup: the relay's word must not find the object's own
  assert.deepEqual(modAction("constructor"), ["constructor", ""]);
  assert.deepEqual(modAction("__proto__"), ["__proto__", ""]);
});

test("no channel is either server-wide or one this reader cannot see", () => {
  assert.equal(modPlace({ action: "channel_kick", channel: "lobby" }), "#lobby");
  assert.equal(modPlace({ action: "channel_kick", channel: null }), "a channel you cannot see");
  assert.equal(modPlace({ action: "summon", channel: "vault" }), "#vault");
  assert.equal(modPlace({ action: "summon", channel: null }), "a channel you cannot see");
  assert.equal(modPlace({ action: "hide", channel: null }), "a channel you cannot see");
  assert.equal(modPlace({ action: "kick", channel: null }), null);
  assert.equal(modPlace({ action: "ban", channel: null }), null);
  assert.equal(modPlace({ action: "restrict", channel: null }), null);
  // The browser's decoder gives undefined for None
  assert.equal(modPlace({ action: "kick", channel: undefined as unknown as null }), null);
  assert.equal(
    modPlace({ action: "channel_delete", channel: undefined as unknown as null }),
    "a channel you cannot see",
  );
});

test("a removal reads as what it is, and is server-wide", () => {
  assert.deepEqual(modAction("remove_posts"), ["removed the posts of", ""]);
  assert.equal(modPlace({ action: "remove_posts", channel: null }), null, "not a channel kept from the reader");
});

test("only an admin is offered all that is kept, which is the window 0", () => {
  assert.deepEqual(removalWindows(false).map(([s]) => s), [3600, 86_400, 604_800]);
  assert.deepEqual(removalWindows(true).map(([s]) => s), [3600, 86_400, 604_800, 0]);
});

test("a ban's address row says what the removal does to the account of that name", () => {
  const address = { account: false, label: "dan" };
  const accountRow = { account: true, label: "dan" };
  assert.equal(removalReachesAccount(accountRow, [accountRow, address]), true);
  assert.equal(removalReachesAccount(address, [accountRow, address]), true, "the same name, from its address row");
  // The controls: a guest's row, beside someone else's account and another guest's address
  const guest = { account: false, label: "gus#1234" };
  assert.equal(removalReachesAccount(guest, [accountRow, address, guest]), false);
  assert.equal(removalReachesAccount(address, [address, { account: false, label: "dan" }]), false, "no account row");
});

test("what it does, said before and after", () => {
  assert.match(removalHint(true), /not direct messages/);
  assert.match(removalHint(true), /does not undo/);
  assert.match(removalHint(true), /bring back an older message they deleted or edited/);
  assert.match(removalHint(false), /A guest has nothing kept/);
  assert.doesNotMatch(removalHint(false), /older message/, "nothing kept, nothing comes back");
  assert.equal(removalDone(31), "31 kept messages deleted; copies on devices are hidden, not erased");
  assert.equal(removalDone(1), "1 kept message deleted; copies on devices are hidden, not erased");
  assert.equal(removalDone(0), "Nothing kept to delete; copies on devices are hidden, not erased");
});
