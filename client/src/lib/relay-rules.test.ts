import { test } from "node:test";
import assert from "node:assert/strict";
import { adminOps, chatEvents, emoteTokenHex, missing, packMoves, newRecoveryKey, relayBanner } from "./relay-rules.ts";

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
  assert.deepEqual(missing(13), ["emotes", "users, groups and channel gates", "sign-in with a provider", "channels made in the app, display names and pictures, invite links, @everyone"]);
  assert.deepEqual(missing(14), ["moving emotes between packs", "users, groups and channel gates", "sign-in with a provider", "channels made in the app, display names and pictures, invite links, @everyone"]);
  assert.deepEqual(missing(16), ["sign-in with a provider", "channels made in the app, display names and pictures, invite links, @everyone"]);
});

test("the admin panel works on every relay that has it, not only on our own", () => {
  assert.deepEqual([null, 17, 16, 15, 12].map(adminOps), [true, true, true, false, false]);
});

test("the banner names the version and what is off", () => {
  assert.deepEqual(relayBanner({ protocol: 13, version: "1.3.1" }), {
    head: "This server runs VoIPC 1.3.1",
    off: "Off until it updates: emotes; users, groups and channel gates; sign-in with a provider; channels made in the app, display names and pictures, invite links, @everyone.",
  });
  assert.deepEqual(relayBanner({ protocol: 12, version: "1.0.0" }), {
    head: "This server runs VoIPC 1.0.0",
    off: "Off until it updates: files; emotes; edits, reactions, pins, forwards; a new recovery key; users, groups and channel gates; sign-in with a provider; channels made in the app, display names and pictures, invite links, @everyone.",
  });
});
