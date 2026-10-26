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
  DEFAULT_LIGHT_PALETTE_ID,
  migratePaletteId,
  paletteById,
  systemDefaultPaletteId,
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

test("both default palettes exist, and one is light", () => {
  // The pair the app opens in before anybody chooses: the dark one where there
  // is no machine to ask, the light one where the machine says it prefers light.
  assert.equal(paletteById(DEFAULT_PALETTE_ID).id, DEFAULT_PALETTE_ID);
  assert.equal(paletteById(DEFAULT_LIGHT_PALETTE_ID).id, DEFAULT_LIGHT_PALETTE_ID);
  assert.equal(paletteById(DEFAULT_PALETTE_ID).dark, true);
  assert.equal(paletteById(DEFAULT_LIGHT_PALETTE_ID).dark, false);
});

test("with no window to ask, the default palette is the dark one", () => {
  // Node has no matchMedia; the app must still start, in the documented palette.
  assert.equal(systemDefaultPaletteId(), DEFAULT_PALETTE_ID);
});

test("a renamed palette still names a palette that exists", () => {
  // The migration is only worth having if it points somewhere: a target that
  // has itself been renamed or dropped falls back to the default, which is the
  // exact silent repaint the migration exists to prevent.
  for (const old of ["discord-dark", "discord-light"]) {
    const migrated = migratePaletteId(old);
    assert.notEqual(migrated, old, `${old} should migrate`);
    assert.equal(paletteById(migrated).id, migrated, `${migrated} is not a palette`);
  }
  // An id nothing renamed comes back untouched
  assert.equal(migratePaletteId("voipc-dark"), "voipc-dark");
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

// MainActivity.kt opens the window in the stored palette's background, before
// the page exists to say what that is, from its own copy of the table. A new
// palette, or a changed background, has to reach that copy too.
test("Android's launch colours match every palette's background", async () => {
  const { readFileSync } = await import("node:fs");
  const kt = readFileSync(
    new URL("../../src-tauri/gen/android/app/src/main/java/com/voipc/app/MainActivity.kt", import.meta.url),
    "utf8",
  );
  const table = new Map(
    [...kt.matchAll(/"([a-z-]+)" to \("(#[0-9a-f]{6})" to (true|false)\)/g)].map((m) => [
      m[1],
      { bg: m[2], light: m[3] === "true" },
    ]),
  );
  for (const p of PALETTES) {
    const row = table.get(p.id);
    assert.ok(row, `MainActivity.kt PALETTE_BACKGROUNDS has no ${p.id}`);
    assert.equal(row.bg, p.tokens["--bg-primary"].toLowerCase(), `${p.id}: background`);
    assert.equal(row.light, !p.dark, `${p.id}: light`);
  }
  for (const [id, row] of table) {
    const p = paletteById(migratePaletteId(id));
    assert.equal(p.id, migratePaletteId(id), `${id} is neither a palette nor a rename of one`);
    assert.equal(row.bg, p.tokens["--bg-primary"].toLowerCase(), `${id}: background`);
  }
});

// The splash of the next start (themes.xml Launch.*, picked by MainActivity):
// one colour per palette in res/values/colors.xml, the palette's background.
test("Android's splash colours match every palette's background", async () => {
  const { readFileSync } = await import("node:fs");
  const res = "../../src-tauri/gen/android/app/src/main/";
  const colors = readFileSync(new URL(res + "res/values/colors.xml", import.meta.url), "utf8");
  const themes = readFileSync(new URL(res + "res/values/themes.xml", import.meta.url), "utf8");
  const kt = readFileSync(new URL(res + "java/com/voipc/app/MainActivity.kt", import.meta.url), "utf8");
  for (const p of PALETTES) {
    const name = p.id.replace(/-/g, "_");
    const m = colors.match(new RegExp(`name="launch_${name}">#FF([0-9A-Fa-f]{6})<`));
    assert.ok(m, `colors.xml has no launch_${name}`);
    assert.equal(`#${m[1].toLowerCase()}`, p.tokens["--bg-primary"].toLowerCase(), `${p.id}: splash colour`);
    assert.ok(themes.includes(`name="Theme.voipc_client.Launch.${name}"`), `themes.xml has no Launch.${name}`);
    assert.ok(kt.includes(`"${p.id}" to R.style.Theme_voipc_client_Launch_${name}`), `MainActivity maps no ${p.id}`);
  }
});

// XML forbids two hyphens in a row inside a comment, and Gradle's resource
// merger stops the whole Android build on one: a comment naming a token such
// as --bg-primary did exactly that (2026-10-26).
test("the Android resource files' comments are valid XML", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const dir = new URL("../../src-tauri/gen/android/app/src/main/res/", import.meta.url);
  for (const sub of readdirSync(dir).filter((d) => d.startsWith("values"))) {
    for (const file of readdirSync(new URL(`${sub}/`, dir)).filter((f) => f.endsWith(".xml"))) {
      const text = readFileSync(new URL(`${sub}/${file}`, dir), "utf8");
      for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) {
        assert.ok(!m[1].includes("--"), `${sub}/${file}: "--" inside a comment`);
      }
    }
  }
});
