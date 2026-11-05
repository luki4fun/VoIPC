import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PROVE_FIRST, adminOps, chatEvents, emoteTokenHex, missing, moderation, moves, packMoves, newRecoveryKey, relayBanner } from "./relay-rules.ts";

test("the words that bring up a setup's proof are the ones the relay says", () => {
  const relay = readFileSync(join(import.meta.dirname, "../../../crates/voipc-server/src/accounts.rs"), "utf8");
  const enable = relay.slice(relay.indexOf("AccountRequest::TotpEnable {"));
  assert.ok(enable.includes(`"${PROVE_FIRST}"`), "or the prompt offers no way on");
});

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
  assert.deepEqual(missing(13), ["emotes", "users, groups and channel gates", "sign-in with a provider", "channels made in the app, display names and pictures, invite links, @everyone", "mute and timeouts, hiding messages, summons, the moderation log, reports", "the move from Discord and its archive"]);
  assert.deepEqual(missing(14), ["moving emotes between packs", "users, groups and channel gates", "sign-in with a provider", "channels made in the app, display names and pictures, invite links, @everyone", "mute and timeouts, hiding messages, summons, the moderation log, reports", "the move from Discord and its archive"]);
  assert.deepEqual(missing(16), ["sign-in with a provider", "channels made in the app, display names and pictures, invite links, @everyone", "mute and timeouts, hiding messages, summons, the moderation log, reports", "the move from Discord and its archive"]);
  assert.deepEqual(missing(18), ["mute and timeouts, hiding messages, summons, the moderation log, reports", "the move from Discord and its archive"]);
  assert.deepEqual(missing(19), ["the move from Discord and its archive"]);
  assert.deepEqual(missing(20), []);
});

test("the admin panel works on every relay that has it, not only on our own", () => {
  assert.deepEqual([null, 17, 16, 15, 12].map(adminOps), [true, true, true, false, false]);
});

test("moderation is on from protocol 19, and on a relay of our own", () => {
  assert.deepEqual([null, 20, 19, 18, 12].map(moderation), [true, true, true, false, false]);
});

test("the move is on from protocol 20, and on a relay of our own", () => {
  assert.deepEqual([null, 21, 20, 19, 12].map(moves), [true, true, true, false, false]);
});

test("the banner names the version and what is off", () => {
  assert.deepEqual(relayBanner({ protocol: 13, version: "1.3.1" }), {
    head: "This server runs VoIPC 1.3.1",
    off: "Off until it updates: emotes; users, groups and channel gates; sign-in with a provider; channels made in the app, display names and pictures, invite links, @everyone; mute and timeouts, hiding messages, summons, the moderation log, reports; the move from Discord and its archive.",
  });
  assert.deepEqual(relayBanner({ protocol: 12, version: "1.0.0" }), {
    head: "This server runs VoIPC 1.0.0",
    off: "Off until it updates: files; emotes; edits, reactions, pins, forwards; a new recovery key; users, groups and channel gates; sign-in with a provider; channels made in the app, display names and pictures, invite links, @everyone; mute and timeouts, hiding messages, summons, the moderation log, reports; the move from Discord and its archive.",
  });
});
