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

test("long code, or a long line, stays plain, and costs nothing", () => {
  for (const [lang, code] of [
    ["ini", "a".repeat(60000)],
    ["c", "a ".repeat(30000)],
    ["cpp", "a ".repeat(30000)],
    ["typescript", "a ".repeat(30000)],
  ]) {
    const start = performance.now();
    assert.equal(highlight(lang, code), null, lang);
    const ms = performance.now() - start;
    assert.ok(ms < 100, `${lang}: ${ms.toFixed(0)} ms`);
  }
  const line = "x".repeat(1000);
  assert.ok(highlight("ini", `a = 1\n${line}`), "a line of 1000 is coloured");
  assert.equal(highlight("ini", `a = 1\n${line}x\nb = 2`), null, "a line of 1001 is not");
  const lines = "let a = 1;\n".repeat(400).slice(0, 4000);
  assert.ok(highlight("js", lines), "4000 characters are coloured");
  assert.equal(highlight("js", lines + "\n"), null, "4001 are not");
});
