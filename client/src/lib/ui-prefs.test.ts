// What happens when the appearance blob on disk is not what this build expects.
//
// It is the one setting stored as an opaque object, which means it is also the
// one nothing on the Rust side validates. In the browser it lives in
// localStorage, where anyone with devtools open is a writer. So the rule under
// test is narrow and absolute: a bad value costs that one preference and
// nothing else ever throws.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SIDEBAR_MAX,
  SIDEBAR_MIN,
  ZOOM_MAX,
  defaultPanels,
  defaultUiPrefs,
  sanitizeUiPrefs,
} from "./ui-prefs.ts";

test("nothing saved yet means the modern layout, never asked", () => {
  for (const nothing of [undefined, null, "", 0, [], "not json"]) {
    const p = sanitizeUiPrefs(nothing);
    assert.equal(p.layout, "modern");
    assert.equal(p.layout_asked_version, 0);
  }
});

test("a full round trip keeps what was chosen", () => {
  const saved = defaultUiPrefs();
  saved.layout = "classic";
  saved.layout_asked_version = 1;
  saved.density = "compact";
  saved.panels.modern.members = 300;
  saved.panels.modern.members_open = false;
  assert.deepEqual(sanitizeUiPrefs(structuredClone(saved)), saved);
});

test("panel widths are clamped to something you can drag back", () => {
  const p = sanitizeUiPrefs({ panels: { classic: { sidebar: 5000, members: -20 } } });
  assert.equal(p.panels.classic.sidebar, SIDEBAR_MAX);
  // Not 0: a member list dragged to nothing is one you cannot get hold of again
  assert.ok(p.panels.classic.members >= 140);
});

test("a width that is not a number falls back instead of becoming NaN", () => {
  // NaN reaches CSS as `width: NaNpx`, which is ignored — so the panel silently
  // takes its content width and the drag handle ends up somewhere unrelated.
  const p = sanitizeUiPrefs({ panels: { classic: { sidebar: "wide" } } });
  assert.equal(p.panels.classic.sidebar, defaultPanels("classic").sidebar);
  assert.ok(Number.isFinite(p.panels.classic.sidebar));
});

test("zoom is clamped, because there is no UI left to undo it with", () => {
  assert.equal(sanitizeUiPrefs({ zoom: 40 }).zoom, ZOOM_MAX);
  assert.equal(sanitizeUiPrefs({ zoom: 0 }).zoom, 0.8);
  assert.equal(sanitizeUiPrefs({ zoom: "big" }).zoom, 1);
});

test("unknown override tokens are dropped, known ones kept", () => {
  const p = sanitizeUiPrefs({
    palette_overrides: { "--accent": "#ff0000", "--made-up": "#00ff00", "--danger": 42 },
  });
  assert.deepEqual(p.palette_overrides, { "--accent": "#ff0000" });
});

test("an unknown layout is not a third layout", () => {
  assert.equal(sanitizeUiPrefs({ layout: "teamspeak" }).layout, "modern");
  assert.equal(sanitizeUiPrefs({ layout: 7 }).layout, "modern");
});

test("a layout chosen under an old name is still that layout", () => {
  // The modern one was `discord` before 0.9.0, and the classic one was briefly
  // `legacy` while this release was being written. Reading both is the whole of
  // the migration: nobody who chose one loses it, and the name this build uses
  // is what gets written back.
  assert.equal(sanitizeUiPrefs({ layout: "discord" }).layout, "modern");
  assert.equal(sanitizeUiPrefs({ layout: "legacy" }).layout, "classic");
  assert.equal(sanitizeUiPrefs({ layout: "classic" }).layout, "classic");
});

test("panel widths dragged under an old name carry over", () => {
  const p = sanitizeUiPrefs({
    panels: { legacy: { sidebar: 300 }, discord: { members: 400 } },
  });
  assert.equal(p.panels.classic.sidebar, 300);
  assert.equal(p.panels.modern.members, 400);
});

test("a palette that was renamed keeps the colours it was chosen for", () => {
  // paletteById falls back to the default for an id it does not know, so a
  // rename without this repaints the app of everyone who picked that palette.
  assert.equal(sanitizeUiPrefs({ palette: "discord-dark" }).palette, "slate-dark");
  assert.equal(sanitizeUiPrefs({ palette: "discord-light" }).palette, "slate-light");
});

test("an unknown palette id is kept, not rewritten", () => {
  // It resolves to the default at render time. Keeping the id means running an
  // older build once does not permanently forget the palette somebody chose.
  assert.equal(sanitizeUiPrefs({ palette: "from-a-newer-build" }).palette, "from-a-newer-build");
});

test("the two layouts start at different widths", () => {
  // The modern rows carry nested members and avatars; 220px is too narrow for
  // them and 240px is wasteful for the classic list.
  assert.notEqual(defaultPanels("classic").sidebar, defaultPanels("modern").sidebar);
  assert.ok(defaultPanels("classic").sidebar >= SIDEBAR_MIN);
  assert.ok(defaultPanels("modern").sidebar <= SIDEBAR_MAX);
});

test("the left-text-channel list survives a round trip, per server", () => {
  const p = sanitizeUiPrefs({
    left_text_channels: { "a.example:9987": ["general", "offtopic"], "b.example:9987": ["general"] },
  });
  assert.deepEqual(p.left_text_channels["a.example:9987"], ["general", "offtopic"]);
  assert.deepEqual(p.left_text_channels["b.example:9987"], ["general"]);
});

test("a malformed left-text-channel list costs that entry, not the app", () => {
  // Hand-edited or written by a newer build: a bad value must never be the
  // reason a channel silently re-joins or the client fails to start.
  const p = sanitizeUiPrefs({
    left_text_channels: {
      "a.example:9987": "general",
      "b.example:9987": ["ok", 42, "", "ok"],
      "c.example:9987": [],
    },
  });
  assert.equal(p.left_text_channels["a.example:9987"], undefined);
  assert.deepEqual(p.left_text_channels["b.example:9987"], ["ok"]);
  assert.equal(p.left_text_channels["c.example:9987"], undefined);
  assert.deepEqual(sanitizeUiPrefs({ left_text_channels: ["nope"] }).left_text_channels, {});
});
