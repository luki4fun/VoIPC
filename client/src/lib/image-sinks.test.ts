// A picture somebody else made reaches the page only as the PNG the sanitizer
// wrote for it (media.ts). This keeps the ways a file's bytes could become
// something the browser decodes to the few that are allowed: media.ts makes
// the object URLs for pictures, videos and sounds; files.ts makes one for a
// download (application/octet-stream); image-prep.ts reads the person's own
// photo before it is sent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const ALLOWED = new Set(["lib/media.ts", "lib/files.ts", "lib/image-prep.ts"]);

function* sources(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name !== "wasm" && name !== "__fixtures__") yield* sources(path);
    } else if (/\.(ts|svelte)$/.test(name) && !name.endsWith(".test.ts")) {
      yield path;
    }
  }
}

test("only media.ts, a download and one's own photo make object URLs", () => {
  const found: string[] = [];
  for (const path of sources(ROOT)) {
    if (readFileSync(path, "utf8").includes("createObjectURL(")) found.push(relative(ROOT, path));
  }
  assert.ok(found.length > 0, "the scan finds the files it guards");
  assert.deepEqual(found.filter((f) => !ALLOWED.has(f)), []);
  assert.match(readFileSync(join(ROOT, "lib/files.ts"), "utf8"), /createObjectURL\(new Blob\(\[bytes[^\]]*\], \{ type: "application\/octet-stream" \}\)\)/);
});

test("no other way to have the browser decode a picture: only one's own photo is read", () => {
  const found: string[] = [];
  for (const path of sources(ROOT)) {
    if (/createImageBitmap\(|readAsDataURL\(|new ImageDecoder\(|["'`]data:image\//.test(readFileSync(path, "utf8"))) found.push(relative(ROOT, path));
  }
  assert.deepEqual(found, ["lib/image-prep.ts"]);
});
