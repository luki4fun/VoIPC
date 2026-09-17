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

test("nothing saved yet means the classic layout, never asked", () => {
  for (const nothing of [undefined, null, "", 0, [], "not json"]) {
    const p = sanitizeUiPrefs(nothing);
    assert.equal(p.layout, "classic");
    assert.equal(p.layout_asked_version, 0);
  }
});

test("a full round trip keeps what was chosen", () => {
  const saved = defaultUiPrefs();
  saved.layout = "discord";
  saved.layout_asked_version = 1;
  saved.density = "compact";
  saved.panels.discord.members = 300;
  saved.panels.discord.members_open = false;
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
  assert.equal(sanitizeUiPrefs({ layout: "teamspeak" }).layout, "classic");
  assert.equal(sanitizeUiPrefs({ layout: 7 }).layout, "classic");
});

test("an unknown palette id is kept, not rewritten", () => {
  // It resolves to the default at render time. Keeping the id means running an
  // older build once does not permanently forget the palette somebody chose.
  assert.equal(sanitizeUiPrefs({ palette: "from-a-newer-build" }).palette, "from-a-newer-build");
});

test("the two layouts start at different widths", () => {
  // Discord's rows carry nested members and avatars; 220px is too narrow for
  // them and 240px is wasteful for the classic list.
  assert.notEqual(defaultPanels("classic").sidebar, defaultPanels("discord").sidebar);
  assert.ok(defaultPanels("classic").sidebar >= SIDEBAR_MIN);
  assert.ok(defaultPanels("discord").sidebar <= SIDEBAR_MAX);
});
