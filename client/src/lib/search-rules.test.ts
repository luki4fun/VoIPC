import { test } from "node:test";
import assert from "node:assert/strict";
import { excerpt, searchMessages, terms } from "./search-rules.ts";
import type { ChatMessage } from "./types.ts";

const T = 1_700_000_000_000;
function m(content: string, at: number, over: Partial<ChatMessage> = {}): ChatMessage {
  return { user_id: 1, username: "Zoë#1234", content, timestamp: T + at, ...over };
}

test("every word must be there, in any case and with or without accents", () => {
  const a = m("Meet at the CAFÉ at noon", 1);
  const b = m("cafe closed today", 2);
  const c = m("noon is fine", 3);
  const hits = searchMessages([{ conv: "general", messages: [a, b, c] }], "cafe");
  assert.deepEqual(hits.map((h) => h.msg), [b, a], "newest first");
  assert.deepEqual(searchMessages([{ conv: "x", messages: [a, b, c] }], "Café NOON").map((h) => h.msg), [a]);
  assert.deepEqual(searchMessages([{ conv: "x", messages: [a] }], "   "), [], "nothing typed finds nothing");
});

test("the writer's name is searched, but not their tag or the markup", () => {
  const a = m("**bold** words", 1);
  assert.equal(searchMessages([{ conv: 1, messages: [a] }], "zoe").length, 1);
  assert.equal(searchMessages([{ conv: 1, messages: [a] }], "1234").length, 0);
  assert.equal(searchMessages([{ conv: 1, messages: [a] }], "**").length, 0);
  assert.equal(searchMessages([{ conv: 1, messages: [a] }], "bold words").length, 1);
});

test("our own lines and placeholders are not results", () => {
  const list = [
    m("Not delivered — cafe", 1, { kind: "notice" }),
    m("cafe", 2, { kind: "history-marker" }),
    m("[encrypted message — decryption failed] cafe", 3, { kind: "undecryptable" }),
  ];
  assert.equal(searchMessages([{ conv: 1, messages: list }], "cafe").length, 0);
});

test("results come from every conversation, capped", () => {
  const many = Array.from({ length: 30 }, (_, i) => m(`hello ${i}`, i));
  const hits = searchMessages([{ conv: "a", messages: many.slice(0, 15) }, { conv: "b", messages: many.slice(15) }], "hello", 10);
  assert.equal(hits.length, 10);
  assert.equal(hits[0].conv, "b");
});

test("an excerpt shows the text as written, with the matches marked", () => {
  const pieces = excerpt("We met at the Café yesterday", terms("cafe"));
  assert.deepEqual(pieces, [
    { v: "We met at the ", hit: false },
    { v: "Café", hit: true },
    { v: " yesterday", hit: false },
  ]);
  const long = `${"x".repeat(200)} needle ${"y".repeat(200)}`;
  const cut = excerpt(long, terms("needle"), 60);
  assert.equal(cut[0].v, "…");
  assert.ok(cut.some((p) => p.hit && p.v === "needle"));
  assert.equal(cut.at(-1)?.v, "…");
});
