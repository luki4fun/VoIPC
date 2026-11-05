// A block silences by volume, through the mixer's one writer. Silencing must never
// come out as a blind toggle, which would unmute somebody muted by hand.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const { clearMixer, setUserVolume, silenceUser, silencedIds, toggleUserMute, userVolumes, volumeOf } = await import("./mixer.ts");

const writes = () => invoked().filter(([c]: [string]) => c === "set_user_volume").length;

test("a block silences somebody audible, and an unblock gives their level back", async () => {
  clearMixer();
  await setUserVolume(1, 0.5);
  await silenceUser(1, true);
  assert.equal(volumeOf(1), 0);
  assert.ok(silencedIds().has(1));
  await silenceUser(1, false);
  assert.equal(volumeOf(1), 0.5);
  assert.ok(!silencedIds().has(1));
});

test("silenceUser does not unmute someone muted by hand", async () => {
  clearMixer();
  await setUserVolume(2, 0.7);
  await toggleUserMute(2);
  assert.equal(volumeOf(2), 0, "muted by hand");
  const before = writes();
  await silenceUser(2, true);
  assert.equal(volumeOf(2), 0, "blocked: still muted");
  assert.ok(silencedIds().has(2), "and known, so it is not asked again");
  await silenceUser(2, false);
  assert.equal(volumeOf(2), 0, "unblocked: still muted, as they chose");
  assert.equal(writes(), before, "the backend was told nothing either");
  // The control: a blind toggle at that point would have brought them back
  await toggleUserMute(2);
  assert.equal(volumeOf(2), 0.7);
});

test("the fader stays a manual override, and an unblock leaves what it chose", async () => {
  clearMixer();
  await silenceUser(3, true);
  assert.equal(volumeOf(3), 0);
  await setUserVolume(3, 0.4);
  await silenceUser(3, false);
  assert.equal(volumeOf(3), 0.4);
});

test("what was silenced goes with the mixer: the ids were that server's", async () => {
  clearMixer();
  await silenceUser(4, true);
  clearMixer();
  assert.equal(silencedIds().size, 0);
  assert.equal(get(userVolumes).size, 0);
  // Somebody with that id on the next server is audible, and stays so
  await silenceUser(4, false);
  assert.equal(volumeOf(4), 1);
});
