import { test } from "node:test";
import assert from "node:assert/strict";
import {
  dismissed,
  emptyGk,
  gkLines,
  holdersLine,
  listNames,
  WAITING,
  withAnew,
  withDropped,
  withHolders,
  withReaders,
  withState,
  withWarning,
  unlistedLine,
  type GkChannel,
  type GkState,
} from "./gk-rules.ts";
import { TOO_LARGE_REASON } from "./chat-rules.ts";

const state = (s: GkState["state"], why = "", name?: string): GkState => ({ channel_id: 7, state: s, why, name });
const lines = (ch: GkChannel) => gkLines("#general", ch).map((l) => l.line);

test("all well says nothing", () => {
  assert.deepEqual(gkLines("#general", emptyGk()), []);
  assert.deepEqual(lines(withState(withState(emptyGk(), state("late")), state("ok"))), []);
});

test("late keys say whether a post of ours waits on them", () => {
  assert.deepEqual(lines(withState(emptyGk(), state("late"))), ["#general's keys are late."]);
  const waiting = gkLines("#general", withState(emptyGk(), state("late", WAITING)));
  assert.deepEqual(waiting, [{ key: "state", line: "#general's keys are late. Your message is waiting.", wait: true }]);
});

test("a dropped post says why it was not sent", () => {
  const late = withDropped(withState(emptyGk(), state("late")), { channel_id: 7, why: "late" });
  assert.deepEqual(lines(late), ["#general's keys were late. Your message was not sent."]);
  const nobody = withDropped(withState(emptyGk(), state("no_keyholder")), { channel_id: 7, why: "no_keyholder" });
  assert.deepEqual(lines(nobody), ["Nobody who holds #general's keys is online. Your message was not sent."]);
  const unchecked = withDropped(emptyGk(), { channel_id: 7, why: "unchecked" });
  assert.deepEqual(lines(unchecked), ["Your message to #general could not be checked against its readers and was not sent."]);
});

test("a drop stays told until the keys are well or another post waits", () => {
  const dropped = withDropped(withState(emptyGk(), state("late", WAITING)), { channel_id: 7, why: "late" });
  assert.equal(withState(dropped, state("late")).dropped, "late", "the state after the drop keeps it");
  assert.equal(withState(dropped, state("ok")).dropped, null);
  assert.equal(withState(dropped, state("late", WAITING)).dropped, null);
  assert.equal(withState(dropped, state("held", "guest")).dropped, null);
  assert.equal(dismissed(dropped, "dropped").dropped, null);
});

test("a refusal is told with the server's reason, over any drop it caused", () => {
  const refused = withDropped(withState(emptyGk(), state("refused", "pin.")), { channel_id: 7, why: "refused" });
  assert.deepEqual(gkLines("#general", refused), [{ key: "state", line: "The server refused #general's keys: pin.", wait: false }]);
  // A post past 16 KiB is the post's refusal, not the keys' (owner, 2026-11-19)
  const tooLarge = withDropped(withState(emptyGk(), state("refused", TOO_LARGE_REASON)), { channel_id: 7, why: "refused" });
  assert.deepEqual(gkLines("#general", tooLarge), [
    { key: "state", line: "Your message to #general was not sent: one message holds at most 16 KiB.", wait: false },
  ]);
  // Only that one: other words are the relay's own
  const other = withDropped(withState(emptyGk(), state("refused", "message too large")), { channel_id: 7, why: "refused" });
  assert.deepEqual(gkLines("#general", other), [{ key: "state", line: "The server refused #general's keys: message too large.", wait: false }]);
});

test("a held post says which reader stopped it", () => {
  assert.deepEqual(lines(withState(emptyGk(), state("held", "guest"))), [
    "Your message to #general is waiting: a guest was listed as a reader.",
  ]);
  assert.deepEqual(lines(withState(emptyGk(), state("held", "pin"))), [
    "Your message to #general is waiting: someone's key does not match the one you know.",
  ]);
  assert.deepEqual(lines(withState(emptyGk(), state("held", "old_counter", "ana#1234"))), [
    "Your message to #general is waiting: an old key of ana#1234 was listed.",
  ]);
});

test("names list as a sentence, past three as a count", () => {
  assert.equal(listNames([]), null);
  assert.equal(listNames([], 4), null, "a count alone names nobody");
  assert.equal(listNames(["a"]), "a");
  assert.equal(listNames(["a", "b"]), "a and b");
  assert.equal(listNames(["a", "b", "c"]), "a, b and c");
  assert.equal(listNames(["a", "b", "c", "d"]), "a, b and 2 more");
  assert.equal(listNames(["a"], 3), "a and 3 more");
});

test("new readers gather over folds until waved off", () => {
  let ch = withReaders(emptyGk(), { channel_id: 7, names: ["ana"], unchecked: 0, older_unnamed: false });
  ch = withReaders(ch, { channel_id: 7, names: ["ana", "bo"], unchecked: 1, older_unnamed: true });
  assert.deepEqual(lines(ch), [
    "New readers in #general: ana, bo and 1 more.",
    "People joined #general more than 90 days ago whose names you were not shown.",
  ]);
  assert.deepEqual(lines(dismissed(ch, "readers")), [
    "People joined #general more than 90 days ago whose names you were not shown.",
  ]);
  assert.deepEqual(lines(dismissed(ch, "older")), ["New readers in #general: ana, bo and 1 more."]);
});

test("a room that names no reader shows no reader line", () => {
  const ch = withReaders(emptyGk(), { channel_id: 7, names: [], unchecked: 3, older_unnamed: false });
  assert.deepEqual(lines(ch), []);
});

test("keys made anew name who, where the room shows it", () => {
  assert.deepEqual(lines(withAnew(emptyGk(), { channel_id: 7, by: "ana" })), ["Keys for #general were made anew by ana."]);
  assert.deepEqual(lines(withAnew(emptyGk(), { channel_id: 7, by: "" })), ["Keys for #general were made anew."]);
  assert.deepEqual(lines(dismissed(withAnew(emptyGk(), { channel_id: 7, by: "ana" }), "anew")), []);
});

test("each warning kind has its line, and a kind this build does not know says nothing", () => {
  const warned = (kind: string, n = 0) => gkLines("#general", withWarning(emptyGk(), { channel_id: 7, kind, n }));
  assert.equal(warned("unnamed_seats", 3)[0].line, "This device gave #general's keys to 3 people the server then did not list.");
  assert.equal(warned("unnamed_seats", 1)[0].line, "This device gave #general's keys to 1 person the server then did not list.");
  assert.equal(warned("old_seat_key")[0].line, "An old key of your account was listed in #general.");
  assert.equal(warned("floor_ahead")[0].line, "The server's keys for #general are older than what this device saw.");
  assert.equal(warned("entry_swapped")[0].line, "Your key-holding entry in #general was replaced by a device that is not this one.");
  assert.equal(warned("leaver_may_hear")[0].line, "Someone who left may still hear this room.");
  assert.equal(warned("gated_opened")[0].line, "#general was closed to listed readers and is now open.");
  assert.deepEqual(warned("from_a_later_build"), []);
});

test("a warning for a channel no longer listed is said on its own, without the channel's name", () => {
  // RV q4-q5:1782: a channel left, removed or delisted shows its lines in no chat
  assert.equal(
    unlistedLine({ channel_id: 7, kind: "unnamed_seats", n: 2 }),
    "This device gave the keys of a channel you no longer have to 2 people the server then did not list.",
  );
  assert.equal(
    unlistedLine({ channel_id: 7, kind: "unnamed_seats", n: 1 }),
    "This device gave the keys of a channel you no longer have to 1 person the server then did not list.",
  );
  assert.equal(unlistedLine({ channel_id: 7, kind: "old_seat_key", n: 0 }), "An old key of your account was listed in a channel you no longer have.");
  assert.equal(unlistedLine({ channel_id: 7, kind: "from_a_later_build", n: 0 }), null);
});

test("a warning of a kind already shown replaces it, and goes when waved off", () => {
  let ch = withWarning(emptyGk(), { channel_id: 7, kind: "unnamed_seats", n: 1 });
  ch = withWarning(ch, { channel_id: 7, kind: "unnamed_seats", n: 4 });
  assert.equal(ch.warnings.length, 1);
  assert.equal(ch.warnings[0].n, 4);
  assert.deepEqual(dismissed(ch, "warning:unnamed_seats").warnings, []);
});

test("what becomes of a post comes first, the rest after", () => {
  let ch = withWarning(emptyGk(), { channel_id: 7, kind: "floor_ahead", n: 0 });
  ch = withState(ch, state("late", WAITING));
  assert.deepEqual(
    gkLines("#general", ch).map((l) => l.key),
    ["state", "warning:floor_ahead"],
  );
});

test("keyholders list those online first, and an unnamed one only as a count", () => {
  const ch = withHolders(emptyGk(), {
    channel_id: 7,
    holders: [
      { name: "cy", online: false, kind: "desktop" },
      { name: "ana", online: true, kind: "desktop" },
      { name: "", online: true, kind: "guest" },
    ],
  });
  assert.equal(holdersLine(ch.holders), "Keys held by ana, cy and 1 more");
  assert.equal(holdersLine([]), null);
  assert.equal(holdersLine([{ name: "", online: true, kind: "guest" }]), null, "an anonymous room names none");
});
