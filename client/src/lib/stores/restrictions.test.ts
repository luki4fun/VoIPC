// A restriction keeps the microphone shut, on the server carrying the call and no
// other, without touching the mute that goes across every server.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const { myRestriction, onRestrictions, restrictions, voiceRestriction } = await import("./restrictions.ts");
const { startTransmit, stopTransmit } = await import("./voice.ts");
const { voice } = await import("./channels.ts");
const { isMuted, isTransmitting, userId } = await import("./connection.ts");
const { dropServer, serverAddress } = await import("./scoped.ts");

const S = "voice.example:9987";
const OTHER = "other.example:9987";
const row = (user_id: number, voice = true) => ({ user_id, voice, text: false, direct: false, by: "bobby", reason: "" });
const lifted = (user_id: number) => ({ user_id, voice: false, text: false, direct: false, by: "", reason: "" });
const transmits = () => invoked().filter(([c]) => c === "start_transmit").length;

async function setup() {
  dropServer(S);
  dropServer(OTHER);
  voice.set({ server: S, channelId: 3 });
  userId.of(S).set(7);
  userId.of(OTHER).set(7);
  serverAddress.set(S);
  isMuted.set(false);
  await stopTransmit();
  isTransmitting.set(false);
  invoked().length = 0;
}

test("no microphone opens while our voice is held on the call's server, and a lift lets it", async () => {
  await setup();
  onRestrictions(S, [row(7)]);
  assert.equal(get(voiceRestriction)?.voice, true);
  await startTransmit();
  assert.equal(transmits(), 0, "the microphone opened");
  assert.equal(get(isMuted), false, "a restriction is no mute: that one goes across servers");
  onRestrictions(S, [lifted(7)]);
  assert.equal(get(voiceRestriction), null);
  await startTransmit();
  assert.equal(transmits(), 1);
  await stopTransmit();
});

test("another's row, or a row on another server, holds nothing back", async () => {
  await setup();
  onRestrictions(S, [row(8)]);
  onRestrictions(OTHER, [row(7)]);
  assert.equal(get(voiceRestriction), null);
  await startTransmit();
  assert.equal(transmits(), 1);
  await stopTransmit();
});

test("a text-only row leaves the microphone", async () => {
  await setup();
  onRestrictions(S, [{ ...row(7, false), text: true }]);
  assert.equal(get(voiceRestriction)?.text, true);
  await startTransmit();
  assert.equal(transmits(), 1);
  await stopTransmit();
});

test("the server on screen and the one carrying the call are told apart", async () => {
  await setup();
  onRestrictions(OTHER, [row(7)]);
  serverAddress.set(OTHER);
  await new Promise((r) => setTimeout(r));
  assert.equal(get(myRestriction)?.voice, true, "on screen");
  assert.equal(get(voiceRestriction), null, "in the call");
  serverAddress.set(S);
  await new Promise((r) => setTimeout(r));
  assert.equal(get(myRestriction), null);
  assert.equal(get(restrictions.peek(OTHER)).size, 1);
});
