import { test } from "node:test";
import assert from "node:assert/strict";
import {
  cleanTakers,
  MAX_REPORT_WHY,
  passedOn,
  REPORT_CHECK,
  reportCheck,
  reportLine,
  reportMark,
  reportPlace,
  takersFor,
} from "./report-rules.ts";
import { forwarded, messageRefs, notificationBody, sanitizeHistory } from "./chat-rules.ts";
import type { ChatMessage, FileRef, Forwarded } from "./types.ts";

const BOB = new Array(16).fill(0xb0);
const BOB_HEX = "b0".repeat(16);
const DAN = new Array(16).fill(0xd0);
const DAN_HEX = "d0".repeat(16);
const ME = { user_id: 1, account: "aa".repeat(16), name: "carla" };

test("cleanTakers keeps each once by name, since a keyed list stops the page at a repeat", () => {
  const list = cleanTakers(
    [
      { user_id: 5, account: BOB, name: "bobby" },
      { user_id: 6, account: DAN, name: "bobby" },
      { user_id: 7, account: null, name: "root" },
    ],
    ME,
  );
  assert.deepEqual(list.map((t) => t.name), ["bobby", "root"]);
  assert.equal(list[0].account, BOB_HEX, "the first of them, its bytes as hex");
});

test("cleanTakers turns the browser's undefined and the desktop's null into null", () => {
  assert.deepEqual(cleanTakers([{ account: BOB, name: "bobby" }], ME), [{ user_id: null, account: BOB_HEX, name: "bobby" }]);
  assert.deepEqual(cleanTakers([{ user_id: null, account: BOB, name: "bobby" }], ME), [{ user_id: null, account: BOB_HEX, name: "bobby" }]);
  assert.deepEqual(cleanTakers([{ user_id: 7, name: "root" }], ME), [{ user_id: 7, account: null, name: "root" }]);
  assert.deepEqual(cleanTakers([{ user_id: 7, account: undefined, name: "root" }], ME), [{ user_id: 7, account: null, name: "root" }]);
  assert.deepEqual(cleanTakers([{ user_id: 7, account: Uint8Array.from(BOB), name: "root" }], ME), [{ user_id: 7, account: BOB_HEX, name: "root" }]);
});

test("cleanTakers leaves out us, whoever has nowhere to send to, and more than the relay may name", () => {
  const someone = { user_id: 5, account: BOB, name: "bobby" };
  assert.deepEqual(cleanTakers([{ ...someone, name: "carla" }], ME), [], "by name");
  assert.deepEqual(cleanTakers([{ ...someone, user_id: 1 }], ME), [], "by id");
  assert.deepEqual(cleanTakers([{ ...someone, account: new Array(16).fill(0xaa) }], ME), [], "by account");
  assert.equal(cleanTakers([someone], ME).length, 1, "the control");
  assert.deepEqual(cleanTakers([{ name: "nowhere" }], ME), []);
  assert.deepEqual(cleanTakers([{ user_id: -1, account: [1, 2], name: "nowhere" }], ME), []);
  assert.deepEqual(cleanTakers([{ user_id: 5, name: "" }], ME), []);
  assert.deepEqual(cleanTakers(undefined, ME), []);
  const many = [1, 2, 3, 4, 5, 6, 7].map((n) => ({ user_id: n + 10, name: `m${n}` }));
  assert.equal(cleanTakers(many, ME).length, 5);
});

test("the writer is never told of a report about them", () => {
  const list = cleanTakers(
    [
      { user_id: 5, account: BOB, name: "bobby" },
      { user_id: 6, account: DAN, name: "dan" },
    ],
    ME,
  );
  assert.deepEqual(takersFor(list, { name: "dan" }).map((t) => t.name), ["bobby"], "by name");
  assert.deepEqual(takersFor(list, { name: "x", account: DAN_HEX }).map((t) => t.name), ["bobby"], "by account");
  assert.deepEqual(takersFor(list, { name: "x", user_id: 6 }).map((t) => t.name), ["bobby"], "by id");
  assert.equal(takersFor(list, { name: "erin", user_id: 9, account: "ee".repeat(16) }).length, 2, "the control");
  // A guest's message has no account and an old one no id: nothing matches nothing
  const noAccount = cleanTakers([{ user_id: 7, name: "root" }], ME);
  assert.equal(takersFor(noAccount, { name: "erin" }).length, 1);
});

test("a mark says what the reporter sees, its reason on one line and bounded", () => {
  const m = { username: "dan", timestamp: 7, id: "m1" };
  assert.deepEqual(reportMark(m, "lobby-chat", "  spam\n\nagain "), {
    name: "dan",
    at: 7,
    report: { channel: "lobby-chat", id: "m1", why: "spam again" },
  });
  assert.equal(Array.from(reportMark(m, "", "w".repeat(400)).report!.why).length, MAX_REPORT_WHY);
  assert.equal(reportMark(m, "", "").report!.channel, "", "a direct message");
  assert.equal("id" in reportMark({ username: "dan", timestamp: 7 }, "", "").report!, false);
  // What is made here survives what a reader does to it
  assert.deepEqual(forwarded(JSON.parse(JSON.stringify(reportMark(m, "lobby-chat", "why")))), reportMark(m, "lobby-chat", "why"));
});

test("passing a report on names who it came from, once", () => {
  const fwd = reportMark({ username: "dan", timestamp: 7, id: "m1" }, "lobby-chat", "");
  const once = passedOn(fwd, "carla");
  assert.equal(once.report!.by, "carla");
  assert.equal(once.report!.id, "m1", "and it stays a report");
  assert.equal(passedOn(once, "bobby").report!.by, "carla", "the first word stands");
  const plain: Forwarded = { name: "dan", at: 7 };
  assert.deepEqual(passedOn(plain, "carla"), plain, "the control: a plain forward has no mark to fill");
});

test("the label says whose word it is, and goes by who actually sent it", () => {
  const fwd = reportMark({ username: "dan#0042", timestamp: 7, id: "m1" }, "lobby-chat", "");
  assert.equal(reportPlace("lobby-chat", false), "in #lobby-chat");
  assert.equal(reportPlace("Voice", true), "in Voice");
  assert.equal(reportPlace("", false), "in a direct message");
  const place = reportPlace("lobby-chat", false);
  assert.equal(reportLine(fwd, "carla#0001", false, place, "T"), "Report from carla. They say dan wrote this in #lobby-chat at T");
  assert.equal(reportLine(fwd, "carla", true, place, "T"), "You reported this. You say dan wrote this in #lobby-chat at T");
  // A mark that names somebody else as the reporter changes who it says it is from: not at all
  const claimed = { ...fwd, report: { ...fwd.report!, by: "annika" } };
  const said = reportLine(claimed, "mallory", false, place, "T");
  assert.ok(said.startsWith("Report passed on by mallory, who says it came from annika."), said);
  assert.ok(!said.includes("Report from annika"), said);
  assert.ok(reportLine(claimed, "bobby", true, place, "T").startsWith("You passed on a report from annika."));
});

const file: FileRef = { hash: "ab".repeat(32), key: "cd".repeat(32), name: "cat.png", size: 10 };
const copy = (more: Partial<ChatMessage> = {}): ChatMessage => ({
  user_id: 5,
  username: "dan",
  content: "buy pills",
  timestamp: 1,
  id: "m1",
  ...more,
});
const report = (content = "buy pills", name = "dan", more: Partial<ChatMessage> = {}) => ({
  content,
  fwd: { name, at: 1, report: { channel: "lobby-chat", id: "m1", why: "" } },
  ...more,
});

test("the check holds a report against the reader's own copy", () => {
  assert.equal(reportCheck(report(), [copy()]), "same");
  assert.equal(reportCheck(report("something else"), [copy()]), "differs");
  assert.equal(reportCheck(report("something else"), [copy({ edited_at: 9 })]), "edited");
  assert.equal(reportCheck(report(), [copy({ edited_at: 9 })]), "same", "edited, but to what they say");
  assert.equal(reportCheck(report(), []), "none");
  assert.equal(reportCheck(report(), [copy({ id: "other" })]), "none");
  assert.equal(REPORT_CHECK.same, "matches your copy");
  assert.equal(REPORT_CHECK.differs, "your copy says otherwise");
  assert.equal(REPORT_CHECK.none, "you have no copy, nothing proves it");
});

test("a copy that proves nothing counts as none", () => {
  assert.equal(reportCheck(report(), [copy({ kind: "shared" })]), "none", "a member's word");
  assert.equal(reportCheck(report(), [copy({ kind: "undecryptable" })]), "none");
  assert.equal(reportCheck(report(), [copy({ kind: "deleted", content: "" })]), "none", "taken back");
  assert.equal(reportCheck(report(), [copy({ kind: "shared" }), copy()]), "same", "the control: beside one of our own");
  const noId = { content: "buy pills", fwd: { name: "dan", at: 1, report: { channel: "lobby-chat", why: "" } } };
  assert.equal(reportCheck(noId, [copy()]), "none");
  const direct = { content: "buy pills", fwd: { name: "dan", at: 1, report: { channel: "", id: "m1", why: "" } } };
  assert.equal(reportCheck(direct, [copy()]), "none", "a direct message has no copy of ours");
  assert.equal(reportCheck({ content: "buy pills" }, [copy()]), "none", "no report at all");
});

test("a report in a member's hand-off is a plain forward, whoever they say sent it", () => {
  const fwd = { name: "dan", at: 1, report: { channel: "lobby-chat", id: "m1", why: "spam" } };
  const forged = { user_id: 1, username: "annika", id: "x1", content: "buy pills", timestamp: Date.now(), fwd };
  const [handed] = sanitizeHistory([forged]);
  assert.equal(handed.kind, "shared");
  assert.deepEqual(handed.fwd, { name: "dan", at: 1 }, "the label stays, the mark does not");
  assert.equal(reportCheck(handed, [copy()]), "none", "so nothing says it matches");
  // The control: the same row as it arrives live, from whoever really sent it
  const live = { ...forged, ...messageRefs(forged) };
  assert.deepEqual(live.fwd, fwd);
  assert.equal(reportCheck(live, [copy()]), "same");
});

test("an id is its writer's to choose, so the name has to fit too", () => {
  assert.equal(reportCheck(report("buy pills", "erin"), [copy()]), "differs");
  assert.equal(reportCheck(report(), [copy({ username: "erin" }), copy()]), "same");
  assert.equal(reportCheck(report("buy pills", "alias-1"), [copy()], true), "same", "names in an anonymous room differ by reader");
  assert.equal(reportCheck(report("other", "alias-1"), [copy()], true), "differs");
});

test("the check reads a file by its hash and an emote by its name", () => {
  assert.equal(reportCheck(report("", "dan", { file }), [copy({ content: "", file })]), "same");
  assert.equal(reportCheck(report("", "dan", { file: { ...file, hash: "ee".repeat(32) } }), [copy({ content: "", file })]), "differs");
  assert.equal(reportCheck(report("", "dan", { file }), [copy({ content: "" })]), "differs");
  // A file that could not go along leaves the words, which still match
  assert.equal(reportCheck(report(), [copy({ file })]), "same");
  const token = `<:wave:${"ab".repeat(16)}>`;
  assert.equal(reportCheck(report(":wave:"), [copy({ content: token })]), "same");
});

test("a report's text stays out of the notification", () => {
  const fwd = reportMark({ username: "dan", timestamp: 7, id: "m1" }, "lobby-chat", "spam");
  assert.equal(notificationBody({ content: "buy pills", fwd }), "Reported a message");
  assert.equal(notificationBody({ content: "", file, fwd }), "Reported a message");
  assert.equal(notificationBody({ content: "buy pills", fwd, expires_at: 5 }), "Reported a message");
  assert.equal(notificationBody({ ...messageRefs({ fwd }), content: "buy pills" }), "Reported a message", "as a listener reads it");
  assert.equal(notificationBody({ content: "buy pills", fwd: { name: "dan", at: 7 } }), "buy pills", "the control: a plain forward says it");
});
