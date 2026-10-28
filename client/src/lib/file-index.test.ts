import { test } from "node:test";
import assert from "node:assert/strict";
import { arrangeFiles, fileKind, fileRows, type FileRow } from "./file-index.ts";
import type { ChatMessage, FileRef } from "./types.ts";

const T = 1_700_000_000_000;
function file(hash: string, over: Partial<FileRef> = {}): FileRef {
  return { hash: hash.repeat(64), key: "c".repeat(64), size: 10, z: false, name: "f.bin", ...over };
}
function m(over: Partial<ChatMessage> = {}): ChatMessage {
  return { user_id: 1, username: "Zoë#1234", content: "", timestamp: T, ...over };
}

test("every live message with a file is a row, beside what this device keeps of it", () => {
  const channels = new Map([
    ["a.example:9987/general", [m({ content: "no file" }), m({ file: file("a", { mime: "image/webp" }) })]],
    ["a.example:9987/team/ops", [m({ file: file("b"), expires_at: T })]],
    ["legacy", [m({ file: file("d") })]],
  ]);
  const dms = new Map([["b.example:9987/Bob#0001", [m({ file: file("a", { mime: "video/mp4" }), timestamp: T + 1 })]]]);
  const rows = fileRows(channels, dms, [{ hash: "a".repeat(64), bytes: 42, last_used: T }], T);
  assert.equal(rows.length, 2, "no text-only message, nothing expired, nothing without a server");
  assert.deepEqual(rows[0].place, { kind: "channel", key: "a.example:9987/general", server: "a.example:9987", name: "general" });
  assert.equal(rows[0].kind, "image");
  assert.equal(rows[0].local, 42);
  assert.deepEqual(rows[1].place, { kind: "dm", key: "b.example:9987/Bob#0001", server: "b.example:9987", name: "Bob#0001" });
  assert.equal(rows[1].local, 42, "one blob, kept once, for both of its messages");
  assert.equal(fileRows(channels, new Map(), [], T)[0].local, null);
  assert.deepEqual(
    ["audio/ogg", "text/plain", undefined].map((mime) => fileKind(file("e", { mime }))),
    ["audio", "other", "other"],
  );
});

function row(name: string, over: { size?: number; at?: number; who?: string; server?: string; kind?: "channel" | "dm"; mime?: string; local?: number } = {}): FileRow {
  const server = over.server ?? "a:1";
  const f = file("a", { name, size: over.size ?? 1, mime: over.mime });
  return {
    file: f,
    msg: m({ file: f, timestamp: over.at ?? T, username: over.who ?? "Zoë#1234" }),
    place: { kind: over.kind ?? "channel", key: `${server}/x`, server, name: "x" },
    kind: fileKind(f),
    local: over.local ?? null,
  };
}
const names = (rows: FileRow[]) => rows.map((r) => r.file.name);

test("files are sorted by date, size, name or sender, newest first on a tie", () => {
  const rows = [
    row("b10", { size: 5, at: T + 2, who: "carl" }),
    row("b9", { size: 50, at: T + 1, who: "Anna" }),
    row("a", { size: 5, at: T + 3, who: "bea" }),
  ];
  const by = (sort: "date" | "size" | "name" | "sender") => names(arrangeFiles(rows, { filter: "all", sort, group: "none" })[0].rows);
  assert.deepEqual(by("date"), ["a", "b10", "b9"]);
  assert.deepEqual(by("size"), ["b9", "a", "b10"], "a tie goes to the newer");
  assert.deepEqual(by("name"), ["a", "b9", "b10"], "numbers in names count as numbers");
  assert.deepEqual(by("sender"), ["b9", "a", "b10"], "case aside");
  assert.deepEqual(names(rows), ["b10", "b9", "a"], "the rows given are left as they were");
});

test("files are filtered by kind, or by what this device keeps", () => {
  const rows = [row("p", { mime: "image/png", local: 3 }), row("v", { mime: "video/webm" }), row("t", { mime: "text/plain" })];
  const only = (filter: Parameters<typeof arrangeFiles>[1]["filter"]) =>
    arrangeFiles(rows, { filter, sort: "name", group: "none" }).flatMap((s) => names(s.rows));
  assert.deepEqual(only("image"), ["p"]);
  assert.deepEqual(only("other"), ["t"]);
  assert.deepEqual(only("local"), ["p"]);
  assert.deepEqual(only("audio"), []);
  assert.deepEqual(arrangeFiles(rows, { filter: "audio", sort: "name", group: "none" }), [], "no empty heading");
});

test("headings follow the sort; kinds keep their own order", () => {
  const rows = [
    row("old", { server: "a:1", at: T, mime: "text/plain" }),
    row("new", { server: "b:1", at: T + 5, mime: "image/png" }),
    row("mid", { server: "a:1", at: T + 3, mime: "audio/ogg" }),
    row("dm", { server: "a:1", at: T + 1, kind: "dm" }),
  ];
  const sections = (group: "server" | "conversation" | "kind") =>
    arrangeFiles(rows, { filter: "all", sort: "date", group }).map((s) => [s.id, names(s.rows)]);
  assert.deepEqual(sections("server"), [["b:1", ["new"]], ["a:1", ["mid", "dm", "old"]]]);
  assert.deepEqual(
    sections("conversation"),
    [["channel b:1/x", ["new"]], ["channel a:1/x", ["mid", "old"]], ["dm a:1/x", ["dm"]]],
    "a channel and a person of one name are two conversations",
  );
  assert.deepEqual(sections("kind"), [["image", ["new"]], ["audio", ["mid"]], ["other", ["dm", "old"]]]);
});
