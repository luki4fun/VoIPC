import { test } from "node:test";
import assert from "node:assert/strict";
import { chatEvents, emoteTokenHex, missing, packMoves, newRecoveryKey, relayBanner } from "./relay-rules.ts";

test("a relay of our own protocol holds nothing back", () => {
  assert.equal(chatEvents(null), true);
  assert.equal(emoteTokenHex(null), 32);
  assert.equal(packMoves(null), true);
  assert.equal(newRecoveryKey(null), true);
  assert.deepEqual(missing(null), []);
  assert.equal(relayBanner(null), null);
});

test("each older protocol holds back what its apps cannot read", () => {
  assert.deepEqual(
    [12, 13, 14].map((p) => [chatEvents(p), emoteTokenHex(p), packMoves(p), newRecoveryKey(p)]),
    [
      [false, 20, false, false],
      [true, 20, false, true],
      [true, 20, false, true],
    ],
  );
  assert.deepEqual(missing(13), ["emotes"]);
  assert.deepEqual(missing(14), ["moving emotes between packs"]);
});

test("the banner names the version and what is off", () => {
  assert.deepEqual(relayBanner({ protocol: 13, version: "1.3.1" }), {
    head: "This server runs VoIPC 1.3.1",
    off: "Off until it updates: emotes.",
  });
  assert.deepEqual(relayBanner({ protocol: 12, version: "1.0.0" }), {
    head: "This server runs VoIPC 1.0.0",
    off: "Off until it updates: files; emotes; edits, reactions, pins, forwards; a new recovery key.",
  });
});
