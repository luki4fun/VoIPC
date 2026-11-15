import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
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

test("the move's rows read as words", () => {
  assert.deepEqual(modAction("import"), ["began a move from Discord", ""]);
  assert.deepEqual(modAction("import_done"), ["finished a move from Discord", ""]);
  assert.deepEqual(modAction("import_undo"), ["undid a move from Discord", ""]);
  assert.deepEqual(modAction("import_exclude"), ["left someone out of the move from Discord", ""]);
  assert.deepEqual(modAction("import_include"), ["let someone back into the move from Discord", ""]);
  assert.deepEqual(modAction("power_grant"), ["gave", "what they could do on Discord"]);
  assert.deepEqual(modAction("power_drop"), ["said no to", "keeping what they could do on Discord"]);
  assert.deepEqual(modAction("unclaimed_expired"), ["removed accounts nobody signed in to", ""]);
  assert.deepEqual(modAction("archive_delete"), ["deleted posts imported from Discord", ""]);
});

test("every row the relay writes has its words here", () => {
  // Beside the code that writes them, wherever that is: a new action with no line shows raw
  const dir = join(import.meta.dirname, "../../../crates/voipc-server/src");
  const files = readdirSync(dir, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".rs") && !f.includes("tests"));
  const written = new Set<string>();
  for (const f of files) {
    const text = readFileSync(join(dir, f), "utf8");
    for (const m of text.matchAll(/\baction: "(\w+)"/g)) written.add(m[1]);
    for (const m of text.matchAll(/\baction: if \w+ \{\s*"(\w+)"\s*\} else \{\s*"(\w+)"\s*\}/g)) {
      written.add(m[1]);
      written.add(m[2]);
    }
  }
  assert.ok(written.has("import_exclude") && written.has("power_drop") && written.has("kick"), "the source was read at all");
  const raw = [...written].filter((a) => modAction(a)[0] === a);
  assert.deepEqual(raw, []);
});

test("no channel is either server-wide or one this reader cannot see", () => {
  assert.equal(modPlace({ action: "channel_kick", channel: "lobby" }), "#lobby");
  assert.equal(modPlace({ action: "channel_kick", channel: null }), "a channel you cannot see now");
  assert.equal(modPlace({ action: "summon", channel: "vault" }), "#vault");
  assert.equal(modPlace({ action: "summon", channel: null }), "a channel you cannot see now");
  assert.equal(modPlace({ action: "hide", channel: null }), "a channel you cannot see now");
  assert.equal(modPlace({ action: "kick", channel: null }), null);
  assert.equal(modPlace({ action: "ban", channel: null }), null);
  assert.equal(modPlace({ action: "restrict", channel: null }), null);
  // The browser's decoder gives undefined for None
  assert.equal(modPlace({ action: "kick", channel: undefined as unknown as null }), null);
  // W3-30: a deleted channel is one nobody sees now, and its row says it was deleted
  assert.equal(modPlace({ action: "channel_delete", channel: undefined as unknown as null }), null);
  assert.equal(modPlace({ action: "channel_delete", channel: "news" }), "#news", "the control: `*` reads its name");
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
  assert.match(removalHint(true, true), /also takes their posts imported from Discord in that time span, counted by when they were written/);
  assert.doesNotMatch(removalHint(true), /imported/, "an older relay holds none");
  assert.doesNotMatch(removalHint(false, true), /imported/, "a guest has none");
  assert.equal(removalDone(31), "31 kept messages deleted; copies on devices are hidden, not erased");
  assert.equal(removalDone(1), "1 kept message deleted; copies on devices are hidden, not erased");
  assert.equal(removalDone(0), "Nothing kept to delete; copies on devices are hidden, not erased");
});
