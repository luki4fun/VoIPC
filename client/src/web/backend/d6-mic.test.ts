// Dive 6, the browser's microphone (audio.ts), with the browser's device open stood in for,
// and the voice seat rule (types.ts):
//
//   F7   the relay carrying the call could move the open microphone into another of its rooms
//        unasked;
//   F9   after a device loss, a push-to-talk release and press while the retry was opening
//        the microphone left one capture open that nothing could close;
//   F8   the chosen microphone gone, the retry opened the system's default within a second
//        and said nothing;
//   F10  "Leave voice" closed the microphone only when the relay answered.
//
// audio.ts uses TypeScript that Node's type stripping does not run (parameter properties), so
// this file loads it through `stripTypeScriptTypes` in transform mode, and wasm.ts as a
// stand-in (the end-of-talk packet is all a stop asks of it).

import { mock, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";
import { fileURLToPath } from "node:url";

await import("../../lib/stores/node-stores.mjs");
registerHooks({
  load(url, context, next) {
    if (url.endsWith("/web/backend/wasm.ts")) {
      return { format: "module", source: "export const wasm = () => ({ buildEotPacket: () => new Uint8Array(1) });", shortCircuit: true };
    }
    if (url.endsWith("/web/backend/audio.ts")) {
      const source = stripTypeScriptTypes(readFileSync(fileURLToPath(url), "utf8"), { mode: "transform" });
      return { format: "module", source, shortCircuit: true };
    }
    return next(url, context);
  },
});
const { AudioEngine } = await import("./audio.ts");
const { seatNeedsAsk } = await import("./types.ts");
const { subscribe } = await import("./events.ts");
const { readFileSync: read } = await import("node:fs");

(globalThis as any).AudioEncoder ??= class {};

interface Open {
  /** The device id asked for; undefined is "whatever the system's default is". */
  device: string | undefined;
  cap: { closed: boolean; close(): void; onended: (() => void) | null };
  land(): void;
}

/** An engine in a voice room, with `devices` listed, and every device open held until landed. */
function inRoom(devices: { label: string; deviceId: string }[], chosen: string | null = null) {
  const list = { now: devices };
  Object.defineProperty(navigator, "mediaDevices", {
    value: { enumerateDevices: async () => list.now.map((d) => ({ ...d, kind: "audioinput" })) },
    configurable: true,
  });
  const e = new AudioEngine() as any;
  e.ctx = { channelId: 5, sessionId: 1, nextVoiceSequence: () => 0, sendDatagram: () => {}, emit: () => {} };
  e.audioContext = {};
  e.ensureGraph = async () => e.audioContext;
  e.inputDevice = chosen;
  const opens: Open[] = [];
  e.openDevice = (_ac: unknown, device: string | undefined) =>
    new Promise((resolve) => {
      const cap = { closed: false, onended: null, close() { this.closed = true; } };
      opens.push({ device, cap, land: () => resolve(cap) });
    });
  return { e, opens, list };
}

const flush = async () => {
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
};

/** What the engine said, by event. */
function told() {
  const said: { name: string; payload: any }[] = [];
  const off = [
    subscribe("audio-device-error", (p) => said.push({ name: "error", payload: p })),
    subscribe("audio-device-restored", (p) => said.push({ name: "restored", payload: p })),
  ];
  return { said, stop: () => off.forEach((f) => f()) };
}

async function start(e: any, opens: Open[]): Promise<void> {
  const p = e.startTransmit();
  await flush();
  opens.at(-1)!.land();
  await p;
}

test("F9: a release and a press while the retry opens the device leave no capture open", async () => {
  const { e, opens } = inRoom([{ label: "Mic", deviceId: "m" }]);
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await start(e, opens);
    // The device goes away; the retry comes a second later and its open is slow
    opens[0].cap.onended!();
    mock.timers.tick(1000);
    await flush();
    assert.equal(opens.length, 2, "the retry is opening the device");
    // The key goes up, and down again: a second open, which lands first
    await e.stopTransmit();
    await start(e, opens);
    // The retry's open lands now
    opens[1].land();
    await flush();
    // The key goes up for good
    await e.stopTransmit();
    assert.deepEqual(
      opens.map((o) => o.cap.closed),
      [true, true, true],
      "a microphone is still open with the key up and nothing left to close it",
    );
  } finally {
    mock.timers.reset();
  }
});

test("F8: the chosen microphone gone, the retry opens no other, says so, and takes it back", async () => {
  const headset = { label: "Headset", deviceId: "hs" };
  const builtIn = { label: "Built-in", deviceId: "bi" };
  const { e, opens, list } = inRoom([headset, builtIn], "Headset");
  const { said, stop } = told();
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await start(e, opens);
    assert.equal(opens[0].device, "hs");
    // Unplugged
    list.now = [builtIn];
    opens[0].cap.onended!();
    mock.timers.tick(1000);
    await flush();
    mock.timers.tick(1000);
    await flush();
    assert.deepEqual(opens.map((o) => o.device), ["hs"], "the retry opened another microphone than the one chosen");
    assert.ok(
      said.some((s) => s.name === "error" && /Headset/.test(s.payload.error) && s.payload.retrying),
      `the user is told the chosen one is gone: ${JSON.stringify(said)}`,
    );
    // Plugged back in: the retry takes it, and says so
    list.now = [headset, builtIn];
    mock.timers.tick(1000);
    await flush();
    assert.deepEqual(opens.map((o) => o.device), ["hs", "hs"]);
    opens[1].land();
    await flush();
    assert.equal(e.capture, opens[1].cap);
    assert.ok(said.some((s) => s.name === "restored"));
    await e.stopTransmit();
  } finally {
    mock.timers.reset();
    stop();
  }
});

test("F8: while the chosen one is gone, another chosen in Settings is what the retry opens", async () => {
  const builtIn = { label: "Built-in", deviceId: "bi" };
  const { e, opens, list } = inRoom([{ label: "Headset", deviceId: "hs" }, builtIn], "Headset");
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await start(e, opens);
    list.now = [builtIn];
    opens[0].cap.onended!();
    mock.timers.tick(1000);
    await flush();
    await e.setInputDevice("Built-in");
    mock.timers.tick(1000);
    await flush();
    assert.deepEqual(opens.map((o) => o.device), ["hs", "bi"]);
    opens[1].land();
    await flush();
    await e.stopTransmit();
    assert.ok(opens.every((o) => o.cap.closed));
  } finally {
    mock.timers.reset();
  }
});

test("F8: at a start, a chosen microphone that is not there gives way to the default, and is said", async () => {
  const { e, opens } = inRoom([{ label: "Built-in", deviceId: "bi" }], "Headset");
  const { said, stop } = told();
  try {
    await start(e, opens);
    assert.deepEqual(opens.map((o) => o.device), [undefined], "the default, as the user is starting to talk");
    assert.ok(
      said.some((s) => s.name === "error" && /Headset/.test(s.payload.error) && /default/.test(s.payload.error)),
      `the switch is said: ${JSON.stringify(said)}`,
    );
    await e.stopTransmit();
  } finally {
    stop();
  }
});

test("F8, review R3: each new call says again that the chosen microphone is missing", async () => {
  const { e, opens } = inRoom([{ label: "Built-in", deviceId: "bi" }], "Headset");
  const { said, stop } = told();
  try {
    await start(e, opens);
    await e.stopTransmit();
    // The call ends and another begins
    const ctx = e.ctx;
    e.detach();
    e.attach(ctx);
    await start(e, opens);
    await e.stopTransmit();
    const notices = said.filter((s) => s.name === "error" && /Headset/.test(s.payload.error));
    assert.equal(notices.length, 2, `said once a call: ${JSON.stringify(said)}`);
  } finally {
    // attach starts the engine's timers: let them go
    e.detach();
    stop();
  }
});

test("F8: labels the browser hides until a grant do not make the chosen microphone gone", async () => {
  // Firefox without a kept grant lists devices with no labels until something asks for one
  const { e, opens } = inRoom([], "Headset");
  let granted = false;
  const devices = [{ label: "Headset", deviceId: "hs" }, { label: "Built-in", deviceId: "bi" }];
  Object.defineProperty(navigator, "mediaDevices", {
    value: {
      enumerateDevices: async () => devices.map((d) => ({ ...d, label: granted ? d.label : "", kind: "audioinput" })),
      getUserMedia: async () => {
        granted = true;
        return { getTracks: () => [{ stop() {} }] };
      },
    },
    configurable: true,
  });
  const { said, stop } = told();
  try {
    await start(e, opens);
    assert.deepEqual(opens.map((o) => o.device), ["hs"], "the chosen one, which is there");
    assert.deepEqual(said, [], "and nothing said about it being gone");
    await e.stopTransmit();
  } finally {
    stop();
  }
});

test("F8, the control: with the default chosen, a loss reopens the default, as it always did", async () => {
  const { e, opens } = inRoom([{ label: "Built-in", deviceId: "bi" }]);
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await start(e, opens);
    opens[0].cap.onended!();
    mock.timers.tick(1000);
    await flush();
    assert.deepEqual(opens.map((o) => o.device), [undefined, undefined]);
    opens[1].land();
    await flush();
    assert.equal(e.capture, opens[1].cap);
    await e.stopTransmit();
  } finally {
    mock.timers.reset();
  }
});

test("F10: leaving closes the microphone at once, and nothing opens it before the answer", async () => {
  const { e, opens } = inRoom([{ label: "Mic", deviceId: "m" }]);
  await start(e, opens);
  await e.closeForLeave();
  assert.equal(opens[0].cap.closed, true, "closed before any answer from the relay");
  await assert.rejects(e.startTransmit(), "a press or voice activation before the answer");
  assert.equal(opens.length, 1, "and opened nothing");
  // The relay's answer: the lobby (detach), or a seat somewhere new (onChannelChanged)
  e.onChannelChanged("off");
  await start(e, opens);
  assert.equal(opens.length, 2, "a new seat opens it again");
  await e.closeForLeave();
  e.detach();
  e.ctx = { channelId: 6, sessionId: 1, nextVoiceSequence: () => 0, sendDatagram: () => {}, emit: () => {} };
  await start(e, opens);
  assert.equal(opens.length, 3, "and so does the next call");
  await e.stopTransmit();
});

test("F7: a move to another room needs an ask on the connection carrying the call too", () => {
  // [channel the relay seats us in, this connection holds voice, the room it stands in]
  assert.equal(seatNeedsAsk(2, true, 1), true, "the relay moves the call to a room nobody asked for");
  assert.equal(seatNeedsAsk(2, false, 0), true, "a seat on a connection in no call (0.10.0)");
  assert.equal(seatNeedsAsk(1, true, 1), false, "a list for the room the call stands in");
  assert.equal(seatNeedsAsk(0, true, 1), false, "the lobby: a kick, or the answer to a leave");
  assert.equal(seatNeedsAsk(0, false, 0), false);
});

test("F10 and F7: the browser closes the microphone at a leave, and at a move it refused", () => {
  const commands = read(new URL("./commands.ts", import.meta.url), "utf8");
  assert.match(commands, /join_channel: async[^]*?if \(channel !== 0\) s\.askVoice\(\);[^]*?else if \(session\.voiceSession\(\) === s\) await audio\.closeForLeave\(\);/);
  const session = read(new URL("./session.ts", import.meta.url), "utf8");
  assert.match(session, /if \(seatNeedsAsk\(channelId, voiceOwner === this, this\.channelId\) && !this\.takeVoiceAsk\(\)\) \{\n.*\n\s*if \(voiceOwner === this\) void audio\.closeForLeave\(\);/);
});
