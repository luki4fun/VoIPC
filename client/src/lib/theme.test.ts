// The palettes, and the rule that keeps a new one from shipping unreadable.
//
// The contrast pass is the point of this file. Every other check here is cheap
// bookkeeping; that one is a reviewer who actually looks at the colours, and it
// runs before anybody has to.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CONTRAST_PAIRS,
  DEFAULT_PALETTE_ID,
  PALETTES,
  TOKENS,
  contrastRatio,
  paletteById,
  parseColor,
  resolveTokens,
} from "./theme.ts";

test("every palette defines every token", () => {
  for (const palette of PALETTES) {
    for (const token of TOKENS) {
      assert.ok(
        typeof palette.tokens[token] === "string" && palette.tokens[token] !== "",
        `${palette.id} is missing ${token}`,
      );
    }
  }
});

test("every palette is readable", () => {
  for (const palette of PALETTES) {
    for (const pair of CONTRAST_PAIRS) {
      const ratio = contrastRatio(palette.tokens[pair.fg], palette.tokens[pair.bg]);
      assert.ok(
        ratio >= pair.min,
        `${palette.id}: ${pair.fg} on ${pair.bg} (${pair.where}) is ${ratio.toFixed(2)}:1, ` +
          `below the ${pair.min}:1 this pair has to clear`,
      );
    }
  }
});

test("an unknown palette id falls back rather than throwing", () => {
  // A downgrade meets a palette a newer build chose. The app must still start.
  assert.equal(paletteById("no-such-palette").id, DEFAULT_PALETTE_ID);
  assert.equal(paletteById("").id, DEFAULT_PALETTE_ID);
});

test("overrides win over the palette, and only for tokens we know", () => {
  const tokens = resolveTokens(DEFAULT_PALETTE_ID, {
    "--accent": "#ff0000",
    // A token this build does not have. Would be written to the document as a
    // live custom property if it slipped through.
    ["--not-a-token" as never]: "#00ff00",
  });
  assert.equal(tokens["--accent"], "#ff0000");
  assert.equal(tokens["--bg-primary"], paletteById(DEFAULT_PALETTE_ID).tokens["--bg-primary"]);
  assert.ok(!("--not-a-token" in tokens));
});

test("an empty override is not an override", () => {
  // A colour input cleared to "" must leave the palette's own value alone
  // rather than blanking the property.
  const base = paletteById(DEFAULT_PALETTE_ID).tokens["--accent"];
  assert.equal(resolveTokens(DEFAULT_PALETTE_ID, { "--accent": "  " })["--accent"], base);
});

test("colours parse the way CSS writes them", () => {
  assert.deepEqual(parseColor("#fff"), [255, 255, 255]);
  assert.deepEqual(parseColor("#1a1a2e"), [26, 26, 46]);
  assert.deepEqual(parseColor("rgb(74, 158, 255)"), [74, 158, 255]);
  assert.deepEqual(parseColor("rgba(0, 0, 0, 0.15)"), [0, 0, 0]);
  assert.equal(parseColor("papayawhip"), null);
});

test("contrast is the WCAG ratio, and unparseable colours score zero", () => {
  assert.equal(Math.round(contrastRatio("#000000", "#ffffff")), 21);
  assert.equal(Math.round(contrastRatio("#4a9eff", "#4a9eff")), 1);
  // Zero rather than a throw: a shadow token handed to this by mistake should
  // fail the assertion that uses it, not take the suite down.
  assert.equal(contrastRatio("0 8px 24px rgba(0,0,0,.4)", "#ffffff"), 0);
});
