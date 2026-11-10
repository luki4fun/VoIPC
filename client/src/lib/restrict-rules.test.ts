import { test } from "node:test";
import assert from "node:assert/strict";
import { heldLine, heldNotice, markTitle, withRows, type Held, type RestrictionRow } from "./restrict-rules.ts";

const NOW = new Date(2026, 10, 4, 14, 0, 0).getTime();
const row = (over: Partial<RestrictionRow>): RestrictionRow => ({
  user_id: 7,
  voice: true,
  text: true,
  direct: false,
  by: "bobby",
  reason: "",
  ...over,
});
const held = (over: Partial<Held>): Held => ({ voice: true, text: true, direct: false, until: NOW + 3_600_000, by: "bobby", reason: "", ...over });

test("no end reads the same from either backend", () => {
  // wasm: undefined, the desktop: null
  for (const r of [row({}), row({ expires_in_secs: null }), row({ expires_in_secs: undefined })]) {
    assert.equal(withRows(new Map(), [r], NOW).get(7)?.until, null);
  }
  assert.equal(withRows(new Map(), [row({ expires_in_secs: 60 })], NOW).get(7)?.until, NOW + 60_000);
  assert.equal(withRows(new Map(), [row({ expires_in_secs: 0 })], NOW).get(7)?.until, NOW, "0 is an end, not none");
});

test("a row with nothing held lifts", () => {
  const had = withRows(new Map(), [row({}), row({ user_id: 8 })], NOW);
  const after = withRows(had, [row({ voice: false, text: false, direct: false, by: "", user_id: 7 })], NOW);
  assert.deepEqual([...after.keys()], [8]);
  assert.equal(had.size, 2, "what it was given is not changed");
});

test("the wait alone holds someone too: direct is enough for a row", () => {
  const after = withRows(new Map(), [row({ voice: false, text: false, direct: true, by: "" })], NOW);
  assert.equal(after.get(7)?.direct, true);
});

test("a repeated id leaves one entry, the last", () => {
  const after = withRows(new Map(), [row({ reason: "first" }), row({ reason: "second" })], NOW);
  assert.equal(after.size, 1);
  assert.equal(after.get(7)?.reason, "second");
});

test("the person is told by whom, until when and why", () => {
  const line = heldLine(held({ reason: "too loud" }), "text", NOW, "en-GB");
  assert.equal(line, "Timed out by @bobby until 15:00: too loud");
  assert.equal(heldLine(held({ text: false }), "voice", NOW, "en-GB"), "Muted by @bobby until 15:00");
  assert.equal(heldLine(held({}), "voice", NOW, "en-GB"), "Timed out by @bobby until 15:00");
  assert.equal(heldLine(held({ until: null }), "text", NOW), "Timed out by @bobby until someone lifts it");
  assert.equal(heldLine(held({ by: "admin token" }), "text", NOW, "en-GB"), "Timed out by an admin until 15:00");
});

test("another day says which", () => {
  const line = heldLine(held({ until: NOW + 2 * 86_400_000 }), "text", NOW, "en-GB");
  assert.match(line, /until 6 Nov 14:00$/);
});

test("the wait says when writing starts", () => {
  const wait = held({ by: "", direct: true });
  assert.equal(heldLine(wait, "text", NOW, "en-GB"), "New here: you can write from 15:00");
  assert.equal(heldLine(wait, "voice", NOW, "en-GB"), "New here: you can speak from 15:00");
  assert.equal(heldLine(wait, "direct", NOW, "en-GB"), "New here: you can write from 15:00");
  // With a moderator's row on top only the wait explains direct messages
  assert.equal(heldLine(held({ direct: true }), "direct", NOW, "en-GB"), "New here: you can write direct messages from 15:00");
});

test("a mark's title says what the row says, and a reason only where it was told", () => {
  assert.equal(markTitle(held({}), NOW, "en-GB"), "Timed out by @bobby until 15:00");
  assert.equal(markTitle(held({ text: false }), NOW, "en-GB"), "Muted by @bobby until 15:00");
  assert.equal(markTitle(held({ voice: false }), NOW, "en-GB"), "Cannot post by @bobby until 15:00");
  assert.equal(markTitle(held({ reason: "too loud" }), NOW, "en-GB"), "Timed out by @bobby until 15:00: too loud");
  assert.equal(markTitle(held({ by: "", direct: true }), NOW, "en-GB"), "New here: cannot speak or write until 15:00");
});

test("the person hears of a change once", () => {
  assert.equal(heldNotice(null, null, NOW), null);
  assert.match(heldNotice(null, held({ text: false }), NOW) ?? "", /^Muted/);
  assert.match(heldNotice(null, held({}), NOW) ?? "", /^Timed out/);
  assert.match(heldNotice(held({}), null, NOW) ?? "", /again/);
  // The snapshot and the broadcast of the same row, a moment apart
  assert.equal(heldNotice(held({}), held({ until: NOW + 3_601_000 }), NOW), null);
  // A later end, or another moderator, is news
  assert.match(heldNotice(held({}), held({ until: NOW + 7_200_000 }), NOW) ?? "", /Timed out/);
  assert.match(heldNotice(held({}), held({ by: "cleo" }), NOW) ?? "", /@cleo/);
  assert.match(heldNotice(held({ until: null }), held({}), NOW) ?? "", /Timed out/);
  assert.equal(heldNotice(held({ until: null }), held({ until: null }), NOW), null);
});
