// The group key's rules of the page's own (live.ts): which path a connection takes, and how
// a keyholder's uploads go out. Pure enough to run without wasm or a relay.

import { test } from "node:test";
import assert from "node:assert/strict";
import { GkPump, gkPathAfter, gkPosts, gkRuns, ReadyClock, yieldTask, type GkPath } from "./live.ts";

/** The path after these frames, from a connection's start. */
const pathOf = (...frames: [string, boolean?][]): GkPath =>
  frames.reduce<GkPath>((path, [tag, on]) => gkPathAfter(path, tag, on), "none");

test("a relay that says GroupKeys right after Authenticated picks the path", () => {
  assert.equal(pathOf(["Authenticated"], ["GroupKeys", true]), "on");
  assert.equal(pathOf(["Authenticated"], ["GroupKeys", false]), "off");
  assert.equal(pathOf(["Authenticated"], ["GroupKeys", true], ["ChannelList"]), "on", "later frames change nothing");
});

test("no GroupKeys before the next frame is a relay on the old paths", () => {
  assert.equal(pathOf(["Authenticated"], ["ChannelList"]), "legacy");
  assert.equal(pathOf(["Authenticated"], ["ChannelList"], ["GroupKeys", true]), "legacy", "a late one counts for nothing");
  assert.equal(pathOf(["AuthStep"], ["Account"]), "none", "nothing is decided before the sign-in ends");
  assert.equal(pathOf(["Authenticated"]), "wait");
});

test("off reads kept history under the group key and posts on the old paths", () => {
  assert.deepEqual(
    (["none", "wait", "legacy", "off", "on"] as GkPath[]).map((p) => [p, gkRuns(p), gkPosts(p)]),
    [
      ["none", false, false],
      ["wait", false, false],
      ["legacy", false, false],
      ["off", true, false],
      ["on", true, true],
    ],
  );
});

/** A transport that has written what was queued when told to. */
function fakeHost(frames: number) {
  let left = frames;
  const written: (() => void)[] = [];
  const sent: number[] = [];
  const seen = { asked: 0, over: false, inCall: false, calls: [] as boolean[] };
  const host = {
    nextFrame: (inCall: boolean) => {
      seen.asked++;
      seen.calls.push(inCall);
      if (left === 0) return undefined;
      left--;
      return new Uint8Array([frames - left]);
    },
    send: (frame: Uint8Array) => {
      sent.push(frame[0]);
    },
    writable: () => new Promise<void>((resolve) => written.push(resolve)),
    inCall: () => seen.inCall,
    over: () => seen.over,
  };
  const write = async () => {
    written.shift()?.();
    await yieldTask();
  };
  return { host, sent, seen, write, waiting: () => written.length };
}

test("a keyholder's parts go one at a time, each once the transport wrote what was queued", async () => {
  const { host, sent, seen, write, waiting } = fakeHost(3);
  const pump = new GkPump(host);
  pump.wake();
  pump.wake();
  await yieldTask();
  assert.deepEqual(sent, [], "behind what was queued before");
  assert.equal(waiting(), 1, "however often woken");
  await write();
  assert.deepEqual(sent, [1]);
  await yieldTask();
  assert.deepEqual(sent, [1], "the next waits until the last is written");
  await write();
  assert.deepEqual(sent, [1, 2]);
  await write();
  await write();
  assert.deepEqual(sent, [1, 2, 3]);
  assert.equal(seen.asked, 4, "asked once more, then done");
  pump.wake();
  await write();
  assert.equal(seen.asked, 5, "a later wake asks again");
});

test("an ended connection's pump stops, and asks with the call as it stands", async () => {
  const { host, sent, seen, write } = fakeHost(5);
  seen.inCall = true;
  const pump = new GkPump(host);
  pump.wake();
  await write();
  seen.over = true;
  await write();
  assert.deepEqual(sent, [1]);
  assert.deepEqual(seen.calls, [true]);
});

test("the upload clock ticks only while something waits, and each wait ends once ready", async () => {
  let tick: (() => void) | undefined;
  const runs = { started: 0, stopped: 0 };
  const clock = new ReadyClock((t) => {
    runs.started++;
    tick = t;
    return () => runs.stopped++;
  });
  await clock.until(() => true);
  assert.equal(runs.started, 0, "ready at once: no clock");
  const ready = { a: false, b: false };
  const done: string[] = [];
  void clock.until(() => ready.a).then(() => done.push("a"));
  void clock.until(() => ready.b).then(() => done.push("b"));
  assert.equal(runs.started, 1, "one clock for every wait");
  ready.b = true;
  tick!();
  await yieldTask();
  assert.deepEqual(done, ["b"]);
  assert.equal(runs.stopped, 0, "still one waiting");
  ready.a = true;
  tick!();
  await yieldTask();
  assert.deepEqual(done, ["b", "a"]);
  assert.equal(runs.stopped, 1);
  void clock.until(() => false);
  assert.equal(runs.started, 2, "a later wait starts it again");
});
