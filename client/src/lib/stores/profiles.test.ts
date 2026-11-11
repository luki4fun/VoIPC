// Every profile change goes to everyone connected (relay `profile::tell`, W3-21): a page
// keeps one only for an account it shows, or asked about, so the list does not grow with
// every account on the server.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

await import("./node-stores.mjs");
const { askProfile, clearProfiles, onProfiles, profiles } = await import("./profiles.ts");
const { toHex } = await import("../hex.ts");

const S = "h.example:9987";
const ANN = new Array(16).fill(0xa1);
const ZED = new Array(16).fill(0x2e);
const shown = () => get(profiles.peek(S));

test("a change for an account nobody here asked about is not kept", () => {
  onProfiles(S, [{ account: ZED, name: "Zed" }]);
  assert.equal(shown().has(toHex(ZED)), false);
});

test("an account asked about is kept, and a later change reaches it after a reconnect", () => {
  askProfile(S, toHex(ANN));
  onProfiles(S, [{ account: ANN, name: "Ann" }]);
  assert.equal(shown().get(toHex(ANN))?.name, "Ann");
  // A reconnect forgets what was asked, not what is shown
  clearProfiles(S);
  onProfiles(S, [{ account: ANN, name: "Annie" }, { account: ZED, name: "Zed" }]);
  assert.equal(shown().get(toHex(ANN))?.name, "Annie");
  assert.equal(shown().has(toHex(ZED)), false);
});
