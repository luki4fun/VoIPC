import { test } from "node:test";
import assert from "node:assert/strict";
import { ago, archivedPeers, closeMarkKey, lastSaid, listRows, liveIdOf, reach } from "./dm-rules.ts";
import type { ChatMessage, UserInfo } from "./types.ts";

const S = "h.example:9987";
const msg = (username: string, timestamp: number, more: Partial<ChatMessage> = {}): ChatMessage => ({
  user_id: 1,
  username,
  content: "hi",
  timestamp,
  ...more,
});
const user = (user_id: number, username: string): UserInfo =>
  ({ user_id, username, channel_id: 1, is_muted: false, is_deafened: false, is_screen_sharing: false, is_admin: false }) as UserInfo;

test("the archive's conversations on one server come back, with the peer's account", () => {
  const dms = new Map<string, ChatMessage[]>([
    [`${S}/bob#0001`, [msg("bob#0001", 1, { account: "aa" }), msg("me", 2, { account: "me" }), msg("bob#0001", 3, { account: "bb" })]],
    [`${S}/eve#0002`, [msg("me", 5)]],
    [`other:1/bob#0001`, [msg("bob#0001", 1)]],
  ]);
  assert.deepEqual(archivedPeers(dms, S), [{ name: "bob#0001", account: "bb" }, { name: "eve#0002" }]);
});

test("notices, tombstones and Unknown are not a conversation to list", () => {
  const dms = new Map<string, ChatMessage[]>([
    [`${S}/gone#1`, [msg("", 1, { kind: "notice" }), msg("gone#1", 2, { kind: "deleted" })]],
    [`${S}/Unknown`, [msg("me", 1)]],
    [`${S}/kept#2`, [msg("", 1, { kind: "notice" }), msg("kept#2", 2)]],
  ]);
  assert.deepEqual(archivedPeers(dms, S).map((p) => p.name), ["kept#2"]);
  assert.deepEqual(archivedPeers(dms, ""), []);
});

test("lastSaid skips our own notices", () => {
  const last = lastSaid([msg("a", 1), msg("", 9, { kind: "notice" }), msg("b", 5)]);
  assert.equal(last?.username, "b");
  assert.equal(lastSaid([msg("", 1, { kind: "notice" })]), undefined);
});

test("liveIdOf finds an exact name in our room or any roster", () => {
  const rosters = new Map([[7, [user(42, "bob#0001")]]]);
  assert.equal(liveIdOf("bob#0001", [user(3, "eve")], rosters), 42);
  assert.equal(liveIdOf("eve", [user(3, "eve")], rosters), 3);
  assert.equal(liveIdOf("bob", [], rosters), undefined);
  assert.equal(liveIdOf("", [user(3, "")], rosters), undefined);
});

test("reach: here is live, an away account is kept only with cloud on, a guest is read-only", () => {
  assert.equal(reach(5, undefined, undefined, false), "live");
  assert.equal(reach(-9, 12, undefined, false), "live");
  assert.equal(reach(-9, undefined, "aa", true), "kept");
  assert.equal(reach(-9, undefined, "aa", false), "readonly");
  assert.equal(reach(-9, undefined, undefined, true), "readonly");
});

test("rows go newest first, and a closed one stays out until something newer comes", () => {
  const dms = new Map<string, ChatMessage[]>([
    [`${S}/a`, [msg("a", 10)]],
    [`${S}/b`, [msg("b", 30)]],
    [`${S}/c`, [msg("c", 20)]],
  ]);
  const rows = [{ username: "a", unread: 0 }, { username: "b", unread: 0 }, { username: "c", unread: 0 }];
  const names = (marks: Map<string, number>, active: string | null = null) =>
    listRows(rows, dms, S, marks, active).map((r) => r.convo.username);

  assert.deepEqual(names(new Map()), ["b", "c", "a"]);
  const closedB = new Map([[closeMarkKey(`${S}/b`), 30]]);
  assert.deepEqual(names(closedB), ["c", "a"]);
  // The open one shows whatever its mark says
  assert.deepEqual(names(closedB, "b"), ["b", "c", "a"]);
  // Written to after it was closed: back
  dms.set(`${S}/b`, [msg("b", 30), msg("b", 31)]);
  assert.deepEqual(names(closedB), ["b", "c", "a"]);
});

test("a closed row with unread messages still shows", () => {
  const dms = new Map([[`${S}/a`, [msg("a", 10)]]]);
  const marks = new Map([[closeMarkKey(`${S}/a`), 99]]);
  assert.equal(listRows([{ username: "a", unread: 1 }], dms, S, marks, null).length, 1);
  assert.equal(listRows([{ username: "a", unread: 0 }], dms, S, marks, null).length, 0);
});

test("two rows under one name list once", () => {
  const rows = [{ username: "a", unread: 0 }, { username: "a", unread: 2 }];
  assert.equal(listRows(rows, new Map(), S, new Map(), null).length, 1);
});

test("ago is short at every boundary", () => {
  const now = 1_000_000_000_000;
  assert.equal(ago(now - 59_000, now), "now");
  assert.equal(ago(now - 60_000, now), "1m");
  assert.equal(ago(now - 3_599_000, now), "59m");
  assert.equal(ago(now - 3_600_000, now), "1h");
  assert.equal(ago(now - 86_400_000, now), "1d");
  assert.equal(ago(now - 7 * 86_400_000, now), "1w");
  assert.equal(ago(now - 365 * 86_400_000, now), "1y");
  // A clock behind the message's own is "now", not a negative time
  assert.equal(ago(now + 5_000, now), "now");
});
