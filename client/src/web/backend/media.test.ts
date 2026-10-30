// A relay's moving-picture numbers as the browser keeps them: held to
// voipc-protocol's ranges, as the desktop app holds them (FileLimits::animation).

import { test } from "node:test";
import assert from "node:assert/strict";
import { motionOf } from "./media.ts";

test("a relay's moving-picture numbers are held to their ranges", () => {
  assert.deepEqual(motionOf({ animation_side: 1024, animation_mb: 128 }), { side: 1024, keepMb: 128 });
  assert.deepEqual(motionOf({ animation_side: 1e9, animation_mb: 0 }), { side: 2560, keepMb: 16 });
  assert.deepEqual(motionOf({}), { side: 1024, keepMb: 128 }, "a relay that says nothing gets the defaults");
});
