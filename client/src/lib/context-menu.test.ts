import { test } from "node:test";
import assert from "node:assert/strict";
import { nativeMenuWanted } from "./context-menu.ts";

test("over selected text the native menu stays, so Copy is there", () => {
  assert.equal(nativeMenuWanted(null, "some words"), true);
});

test("in app chrome with nothing selected it does not", () => {
  assert.equal(nativeMenuWanted(null, ""), false);
  assert.equal(nativeMenuWanted(null, "   "), false);
});

test("in a text field it stays, for Paste and spelling", () => {
  const field = { closest: (sel: string) => (sel.includes("input") ? {} : null) };
  assert.equal(nativeMenuWanted(field as unknown as EventTarget, ""), true);
});
