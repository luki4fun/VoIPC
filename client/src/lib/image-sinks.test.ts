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

// W3-9: the scans above miss a picture that goes in another way: bytes no sanitizer wrote,
// handed to `pictureUrl`, or an <img> pointed at something else. A new one fails here until
// someone has looked at where it comes from.
const occurrences = (pattern: RegExp, only: (path: string) => boolean): string[] => {
  const found: string[] = [];
  for (const path of sources(ROOT)) {
    if (!only(path)) continue;
    for (const m of readFileSync(path, "utf8").matchAll(pattern)) found.push(`${relative(ROOT, path)}: ${m[1]}`);
  }
  return found.sort();
};

test("pictureUrl gets only what a sanitizer wrote", () => {
  const calls = occurrences(/(?<!function )pictureUrl\(([^)]*)\)/g, () => true);
  assert.deepEqual(calls, [
    // prepareEmote's preview of what was picked
    "lib/components/EmoteManager.svelte: p.preview",
    // fileImage: the sanitizer's PNG of a file's picture
    "lib/components/chat/FileCard.svelte: pic.png",
    "lib/components/chat/FileCard.svelte: pic.png",
    "lib/components/chat/FileCard.svelte: pic.png",
    // emote_image: the backend's own PNG of the relay's picture
    "lib/stores/emotes.ts: png",
    // prepareEmote's still or preview of a profile picture
    "lib/stores/profiles.ts: png",
  ]);
});

test("an <img> draws only a URL made here", () => {
  const srcs = occurrences(/<img\b[^>]*\bsrc=\{([^}]*)\}/g, (p) => p.endsWith(".svelte"));
  assert.deepEqual(srcs, [
    "lib/components/AdminServer.svelte: iconUrl",
    "lib/components/AvatarPicture.svelte: url",
    "lib/components/EmoteManager.svelte: r.url",
    // A frame the app's own video decoder drew, not a picture file
    "lib/components/ScreenSharePopout.svelte: displayFrame",
    "lib/components/ScreenShareViewer.svelte: displayFrame",
    "lib/components/SharePreview.svelte: $previewFrame",
    "lib/components/chat/FileCard.svelte: url",
    "lib/components/chat/Lightbox.svelte: url",
    "lib/components/modern/ServerRail.svelte: iconOf(entry)",
  ]);
  // None with a src in plain text, which no scan above could follow
  const plain = occurrences(/<img\b[^>]*\bsrc="([^"]*)"/g, (p) => p.endsWith(".svelte"));
  assert.deepEqual(plain, []);
});
