// The three lists of backend commands agree: what the front end invokes, what
// the native app registers (lib.rs `generate_handler!`) and what the browser
// backend answers (web/backend/commands.ts `handlers`). A name in only one of
// them is a call that fails at runtime on one platform and nowhere else.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const src = join(import.meta.dirname, "..");
const read = (...p: string[]) => readFileSync(join(src, ...p), "utf8");

const native = new Set(
  [...read("..", "src-tauri", "src", "lib.rs").matchAll(/^\s+\w+::(\w+),$/gm)].map((m) => m[1]),
);
const table = read("web", "backend", "commands.ts");
const body = table.slice(table.indexOf("const handlers: Record<string, Handler> = {"));
const web = new Set([...body.slice(0, body.indexOf("\n};")).matchAll(/^ {2}(\w+):/gm)].map((m) => m[1]));

const files = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(join(dir, e.name))
    : /\.(ts|svelte)$/.test(e.name) && !e.name.endsWith(".test.ts") ? [join(dir, e.name)] : []);
const invoked = new Set(
  files(src).flatMap((f) => [...readFileSync(f, "utf8").matchAll(/\binvoke\b[^(\n]*\(\s*"(\w+)"/g)].map((m) => m[1])),
);

/** The browser's own: questions only it has to ask. */
const WEB_ONLY = new Set(["can_pick_output", "get_voice_decoder"]);

test("every invoked command exists in a backend", () => {
  assert.deepEqual([...invoked].filter((c) => !native.has(c) && !web.has(c)), []);
});

test("the browser backend answers nothing the native app lacks", () => {
  assert.deepEqual([...web].filter((c) => !native.has(c) && !WEB_ONLY.has(c)), []);
});

test("the lists were read at all", () => {
  assert.ok(native.size > 100 && web.size > 100 && invoked.size > 100, `${native.size} ${web.size} ${invoked.size}`);
});
