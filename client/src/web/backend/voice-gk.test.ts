// A voice room's keys under the group key (types.ts `gkVoiceRoom`, plan part 5): which rooms
// skip the old key paths. The packets themselves open by their sender's key inside wasm
// (voipc-web media.rs, its own tests).

import { test } from "node:test";
import assert from "node:assert/strict";
import { entryAsksHistory, gkVoiceRoom, historyAskSealed, roomAsksBundles } from "./types.ts";
import { gkPosts, type GkPath } from "./live.ts";

test("only a voice room on a relay whose group key is on skips the old key paths", () => {
  const paths: GkPath[] = ["none", "wait", "legacy", "off", "on"];
  assert.deepEqual(
    paths.map((p) => [p, gkVoiceRoom(gkPosts(p), false), gkVoiceRoom(gkPosts(p), true)]),
    [
      ["none", false, false],
      ["wait", false, false],
      ["legacy", false, false],
      ["off", false, false],
      ["on", true, false],
    ],
    "no GroupKeys, or the switch off, keeps every old path; a text channel keeps its own",
  );
});

test("a voice room under the group key asks nobody for a bundle at the join", () => {
  assert.deepEqual(
    [roomAsksBundles(true, false), roomAsksBundles(true, true), roomAsksBundles(false, false), roomAsksBundles(false, true)],
    [true, false, false, false],
    "the old path keeps its key dance; under the group key no key goes over a session",
  );
});

test("a voice room under the group key asks for history sealed, as a text channel does", () => {
  // [text, gkRoom, directHeld] -> sealed
  const rows: [boolean, boolean, boolean, boolean][] = [
    [true, false, false, true],
    [false, true, false, true],
    [false, false, false, false],
    [true, false, true, false],
    [false, true, true, false],
  ];
  assert.deepEqual(
    rows.map(([text, gk, held]) => historyAskSealed(text, gk, held)),
    rows.map((r) => r[3]),
    "no sender key arrives under the group key, so the ask cannot wait for one; the new-member wait refuses a direct message",
  );
});

test("entering a voice room under the group key asks its sharers at once, the lobby never", () => {
  assert.deepEqual(
    [entryAsksHistory(true, 7), entryAsksHistory(true, 0), entryAsksHistory(false, 7), entryAsksHistory(false, 0)],
    [true, false, false, false],
  );
});
