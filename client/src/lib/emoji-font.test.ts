import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { EMOJI_CATEGORIES, EMOJI_NAMES, QUICK_REACTIONS } from "./emoji.ts";

// app.css's "VoIPC Emoji" draws the app's emoji where the system cannot
// (Windows 10). Its unicode-range is the font's cmap: an emoji added to
// emoji.ts without making the font again would be a box there.
const css = readFileSync(new URL("../app.css", import.meta.url), "utf8");
const face = /@font-face\s*{[^}]*"VoIPC Emoji"[^}]*unicode-range:([^;]+);/.exec(css);

function ranges(text: string): [number, number][] {
  return text
    .split(",")
    .map((r) => r.trim().replace(/^U\+/i, ""))
    .filter(Boolean)
    .map((r) => {
      const [a, b = a] = r.split("-");
      return [parseInt(a, 16), parseInt(b, 16)] as [number, number];
    });
}

test("the emoji font's range covers every emoji the app offers", () => {
  assert.ok(face, "app.css has the VoIPC Emoji face with a unicode-range");
  const covered = ranges(face![1]);
  const all = new Set<string>([...EMOJI_CATEGORIES.flatMap((c) => c.emojis), ...Object.values(EMOJI_NAMES), ...QUICK_REACTIONS]);
  const missing: string[] = [];
  for (const emoji of all) {
    for (const ch of emoji) {
      const cp = ch.codePointAt(0)!;
      // Variation selector 16 only asks for the colour form; no glyph of its own
      if (cp === 0xfe0f) continue;
      if (!covered.some(([a, b]) => cp >= a && cp <= b)) missing.push(`${emoji} U+${cp.toString(16).toUpperCase()}`);
    }
  }
  assert.deepEqual(missing, [], "make the font again (app.css says how)");
});
