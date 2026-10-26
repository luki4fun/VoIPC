import { test } from "node:test";
import assert from "node:assert/strict";
import { avatarColor, avatarInk } from "./avatar.ts";
import { contrastRatio } from "./theme.ts";

test("initials read on every avatar colour", () => {
  // Enough names to land on every colour of the set
  const seen = new Set<string>();
  for (let i = 0; i < 400; i++) seen.add(avatarColor(`user-${i}`));
  assert.ok(seen.size >= 8, `only ${seen.size} colours reached`);
  for (const bg of seen) {
    const ratio = contrastRatio(avatarInk(bg), bg);
    assert.ok(ratio >= 4.5, `${bg}: initials at ${ratio.toFixed(2)}:1`);
  }
});

test("the same name always gets the same colour", () => {
  assert.equal(avatarColor("Mira"), avatarColor("Mira"));
});
