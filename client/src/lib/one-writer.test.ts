// Structural guards for two mistakes that are invisible to any behavioural
// test until somebody notices the UI lying.
//
// These read the source with node:fs and import nothing, so the test runner
// never has to resolve `@tauri-apps/api`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const SRC = new URL("..", import.meta.url).pathname;

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

/** Every source file under client/src. Tests are excluded: they name the very
 *  things they are checking for, so scanning them finds only themselves. */
const files = walk(SRC).filter((f) => /\.(ts|svelte|js)$/.test(f) && !f.endsWith(".test.ts"));

test("exactly one module writes per-user volume", () => {
  // It used to be two: a component-local record in the member list and another
  // in the effects panel, so the same person had two different volumes
  // depending on which control you looked at.
  const writers = files
    .filter((f) => !f.includes("/web/"))
    .filter((f) => readFileSync(f, "utf8").includes('invoke("set_user_volume"'));
  assert.deepEqual(
    writers.map((f) => f.slice(SRC.length)),
    ["lib/stores/mixer.ts"],
    "per-user volume must be written in exactly one place",
  );
});

test("exactly one module writes a lane", () => {
  // Both directions go through stores/mixer.ts, which is what keeps the
  // microphone and an incoming voice on the same four controls.
  for (const cmd of ["set_user_fx", "set_mic_fx"]) {
    const writers = files
      .filter((f) => !f.includes("/web/"))
      .filter((f) => readFileSync(f, "utf8").includes(`invoke("${cmd}"`));
    assert.deepEqual(
      writers.map((f) => f.slice(SRC.length)),
      ["lib/stores/mixer.ts"],
      `${cmd} must be sent from exactly one place`,
    );
  }
});

test("a lane is a lane: one strip design, one set of controls", () => {
  // Four rejections came from the microphone and an incoming voice having
  // different controls, and from reverb and water being "the room" rather than
  // two scalable effects beside muffle. The mixer now renders every lane from
  // one template, so each control appears in the source exactly once. A
  // special case for our own voice puts a second copy in and fails here.
  const mixer = readFileSync(join(SRC, "lib/components/MixerView.svelte"), "utf8");
  const times = (needle: string) => mixer.split(needle).length - 1;
  for (const label of ["Muffle", "Reverb", "Water"]) {
    assert.equal(times(`"${label}"`), 1, `${label} is written ${times(`"${label}"`)} times`);
  }
  assert.equal(times('class="strip"'), 1, "there is more than one strip design");
  assert.equal(times("<select"), 1, "there is more than one effect picker");
  assert.equal(times('class="fader"'), 1, "there is more than one fader");
});

test("nothing is on a room any more", () => {
  // Reverb and water belong to a lane. The commands that put them on a bus are
  // gone from both clients, and so is the language.
  for (const gone of ["set_room_fx", "set_sender_room", "set_sender_effect", "RoomFx", "room_fx"]) {
    const found = files.filter((f) => readFileSync(f, "utf8").includes(gone));
    assert.deepEqual(
      found.map((f) => f.slice(SRC.length)),
      [],
      `${gone} is back`,
    );
  }
});

test("the mixer never places anyone", () => {
  // Distance and placement belong to the virtual room, which already owns them.
  const mixer = readFileSync(join(SRC, "lib/components/MixerView.svelte"), "utf8");
  assert.ok(!mixer.includes("set_user_position"), "the mixer must not place people");
  assert.ok(!mixer.includes("Ignore distance"), "distance belongs to the room view");
});

test("nothing survives of the floating effects panel", () => {
  // Its close button was swallowed by its own drag handler. It is gone; this
  // fails if it comes back.
  for (const name of ["AudioFxPanel", "clampToViewport", "audioFxOpen", "audioFxCards"]) {
    const found = files.filter((f) => readFileSync(f, "utf8").includes(name));
    assert.deepEqual(found, [], `${name} is back`);
  }
});

/** Each named listener in a source, from its name up to the next listener. */
function listenerBody(source: string, event: string): string {
  const start = source.indexOf(`"${event}"`);
  assert.ok(start >= 0, `no listener for ${event}`);
  const end = source.indexOf("listenServer", start);
  return source.slice(start, end < 0 ? undefined : end);
}

test("what a relay lists is held each once before anything draws it", () => {
  // A repeated id stops a keyed each and the whole window with it, in production too, and
  // these three lists draw every member list and channel sidebar. App.svelte cannot load under
  // Node, so this holds the order of the lines, not the window.
  const app = readFileSync(join(SRC, "App.svelte"), "utf8");
  for (const event of ["channel-list", "user-list", "channel-users"]) {
    assert.ok(listenerBody(app, event).includes("eachOnce("), `${event} files its list raw`);
  }
  const raw = 'listenServer<ChannelInfo[]>("channel-list", (server, list) => { channels.of(server).set(list); });';
  assert.ok(!listenerBody(raw, "channel-list").includes("eachOnce("), "the check above cannot see a raw write");
});

test("a device list is held each once before a keyed each draws it", () => {
  // Two devices can go by one name, and the first-run steps come before any window behind them
  const setup = readFileSync(join(SRC, "lib/components/AudioSetup.svelte"), "utf8");
  for (const list of ["$inputDevices", "$outputDevices"]) {
    assert.ok(setup.includes(`{#each eachOnce(${list},`), `${list} is drawn raw`);
  }
});

test("a provider list is held each once before a keyed each draws it", () => {
  // The kinds key their each, one of them on the connect dialog, before any sign-in
  const connect = readFileSync(join(SRC, "lib/components/ConnectDialog.svelte"), "utf8");
  assert.ok(!connect.includes("providers = r.providers"), "ConnectDialog files the kinds raw");
  const prompts = readFileSync(join(SRC, "lib/components/AccountPrompts.svelte"), "utf8");
  assert.ok(!prompts.includes("offered: body.offered"), "AccountPrompts files the kinds raw");
});
