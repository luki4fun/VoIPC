import { test } from "node:test";
import assert from "node:assert/strict";
import { highlight, type CodeSeg } from "./highlight.ts";

function flat(segs: CodeSeg[]): string {
  return segs.map((s) => ("v" in s ? s.v : flat(s.c))).join("");
}

test("highlighted code is the code, every character of it", () => {
  const code = 'fn main() { let x = 1; // <b>hi</b>\n    println!("{x}"); }';
  const segs = highlight("rust", code);
  assert.ok(segs);
  assert.equal(flat(segs), code);
  const kinds = new Set(segs.flatMap((s) => ("k" in s ? [s.k] : [])));
  for (const k of ["keyword", "comment", "number", "fn"]) assert.ok(kinds.has(k as never), k);
});

test("a language without a grammar is plain text", () => {
  assert.equal(highlight("", "x"), null);
  assert.equal(highlight("klingon", "x"), null);
  assert.equal(highlight("__proto__", "x"), null);
  assert.ok(highlight("ts", "const a: number = 1;"), "aliases count");
});
