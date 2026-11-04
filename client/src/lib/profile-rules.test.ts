import assert from "node:assert/strict";
import { test } from "node:test";

import { readFileSync } from "node:fs";

import { centerSquare, cleanDisplayName, cleanServerName } from "./profile-rules.ts";

test("a display name a relay should have refused is not shown", () => {
  for (const bad of [
    "@bob",
    "bob#1234",
    "bob\uff031234",
    "Support @alice",
    "\uff20alice",
    "\ufe6balice",
    "\u2800",
    "\u034f",
    "Admin‮evil",
    "a​b",
    "a⁦b",
    "a\nb",
    "x".repeat(33),
    "   ",
    "",
    null,
    undefined,
    42,
    { name: "x" },
  ]) {
    assert.equal(cleanDisplayName(bad), null, String(bad));
  }
});

test("an ordinary name is kept, trimmed", () => {
  assert.equal(cleanDisplayName("  Ann Example "), "Ann Example");
  assert.equal(cleanDisplayName("日本語の名前"), "日本語の名前");
  assert.equal(cleanDisplayName("Jürgen #1"), "Jürgen #1");
  assert.equal(cleanDisplayName("\u2764\ufe0f Ann"), "\u2764\ufe0f Ann", "an emoji needs its selector");
  assert.equal(cleanDisplayName("🙂".repeat(32)), "🙂".repeat(32), "characters, not code units");
});

test("the middle square of a picture", () => {
  assert.deepEqual(centerSquare(200, 100), { x: 50, y: 0, side: 100 });
  assert.deepEqual(centerSquare(100, 200), { x: 0, y: 50, side: 100 });
  assert.deepEqual(centerSquare(64, 64), { x: 0, y: 0, side: 64 });
});

test("a server's name is ignored where it would pass for an address or another server", () => {
  const others = ["Home", "ivy.l4f.cc"];
  assert.equal(cleanServerName("Night Owls", others), "Night Owls");
  assert.equal(cleanServerName("  v1.2 Night Owls ", others), "v1.2 Night Owls", "words, not an address");
  assert.equal(cleanServerName("St. Pauli", others), "St. Pauli");
  for (const bad of ["ivy.l4f.cc", "10.0.0.1:9987", "other.example", "chat.example.org (official)", "voipc.example.com :443", "[::1]:9987", "HOME", "evil‮", "x".repeat(33), "", null]) {
    assert.equal(cleanServerName(bad, others), null, String(bad));
  }
});

test("a server's name reads as an address by the list the relay is tested on too", () => {
  const shapes = JSON.parse(readFileSync(new URL("./address-shapes.json", import.meta.url), "utf8"));
  for (const name of shapes.fine) assert.equal(cleanServerName(name, []), name, name);
  for (const name of shapes.address) assert.equal(cleanServerName(name, []), null, name);
});

test("a display name is read without what draws nothing, and may keep what an emoji needs", () => {
  assert.equal(cleanDisplayName("bobby#1234 \u2800"), null, "a tag behind a blank");
  assert.equal(cleanDisplayName("bobby\u{e0061}"), "bobby\u{e0061}", "the relay refused this by name; here only its shape counts");
  const emoji = "\u{1f469}\u200d\u{1f4bb} Ann";
  assert.equal(cleanDisplayName(emoji), emoji);
  const persian = "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645";
  assert.equal(cleanDisplayName(persian), persian);
  assert.equal(cleanDisplayName("a\u200bb"), null, "a zero-width space joins nothing");
});
