import { test } from "node:test";
import assert from "node:assert/strict";
import { asksBundles, ChannelListParts, KeptByAccount, LivePump } from "./live.ts";

test("a channel list past one frame is told whole, at its last frame, and each list on its own", () => {
  const parts = new ChannelListParts<number>();
  assert.equal(parts.take([1, 2], true), null, "the first frame says nothing yet");
  assert.equal(parts.take([3], true), null);
  assert.deepEqual(parts.take([4], false), [1, 2, 3, 4]);
  assert.deepEqual(parts.take([5], false), [5], "the next list starts over");
});

test("a relay that says more for ever stops being kept", () => {
  const parts = new ChannelListParts<number>();
  for (let i = 0; i < 1000; i++) assert.equal(parts.take([i], true), null);
  const whole = parts.take([1000], false);
  assert.equal(whole?.length, 64);
  assert.deepEqual(whole?.slice(0, 2), [0, 1]);
});

test("general asks no bundles, and a room asks only its own", () => {
  assert.equal(asksBundles(0, 0), false, "General, standing in it");
  assert.equal(asksBundles(0, 5), false, "General, seen from a room");
  assert.equal(asksBundles(7, 5), false, "someone else's room");
  assert.equal(asksBundles(5, 5), true, "the room we stand in");
});

/** A session's queue, as a pump sees it: frames written one per `writeMs`. */
function fakeHost(jobFrames: number, writeMs = 2) {
  const frame = new Uint8Array([1]);
  const written: string[] = [];
  const queue: string[] = [];
  let left = jobFrames;
  let most = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const write = () => {
    timer = undefined;
    const next = queue.shift();
    if (next) written.push(next);
    if (queue.length > 0) timer = setTimeout(write, writeMs);
  };
  const push = (what: string) => {
    queue.push(what);
    most = Math.max(most, queue.length);
    if (!timer) timer = setTimeout(write, writeMs);
  };
  const seen = { checked: 0, inCalls: [] as boolean[], ended: false, inCall: false };
  const host = {
    nextFrame: (inCall: boolean) => {
      seen.inCalls.push(inCall);
      if (left === 0) return undefined;
      left--;
      return frame;
    },
    send: () => push("key"),
    queued: () => queue.length,
    inCall: () => seen.inCall,
    checked: () => seen.checked++,
    over: () => seen.ended,
  };
  return { host, written, push, seen, most: () => most, addJob: (n: number) => (left += n) };
}

const until = async (done: () => boolean) => {
  for (let i = 0; i < 2000 && !done(); i++) await new Promise((r) => setTimeout(r, 2));
  assert.ok(done(), "timed out");
};

test("a seat passes a big key job: it waits for one key frame at most", async () => {
  const q = fakeHost(40);
  new LivePump(q.host).wake();
  await until(() => q.written.length >= 3);
  assert.ok(q.most() <= 1, `${q.most()} frames waiting ahead of a seat`);
  q.push("seat");
  await until(() => q.written.includes("seat"));
  const before = q.written.indexOf("seat");
  assert.ok(before < 40, "the seat waited for the whole job");
  await until(() => q.written.filter((w) => w === "key").length === 40);
  assert.ok(q.most() <= 2, "the key frame in the queue, and the seat");
});

test("work that comes while it runs goes too, and two wakes run one loop", async () => {
  const q = fakeHost(3);
  const pump = new LivePump(q.host);
  pump.wake();
  pump.wake();
  await until(() => q.written.length === 1);
  q.addJob(2);
  pump.wake();
  await until(() => q.written.length === 5);
  await until(() => q.seen.checked === 1);
  assert.ok(q.most() <= 1, "two loops would queue two frames");
  // Done: the next wake starts it again
  q.addJob(1);
  pump.wake();
  await until(() => q.written.length === 6);
  await until(() => q.seen.checked === 2);
});

test("a call is told to the frame, and an ended session stops the pump", async () => {
  const q = fakeHost(100);
  const pump = new LivePump(q.host);
  q.seen.inCall = true;
  pump.wake();
  await until(() => q.written.length >= 2);
  assert.ok(q.seen.inCalls.every(Boolean));
  q.seen.ended = true;
  await new Promise((r) => setTimeout(r, 20));
  const stopped = q.seen.inCalls.length;
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(q.seen.inCalls.length, stopped);
});

test("a failing frame does not stop the next wake", async () => {
  const q = fakeHost(2);
  const pump = new LivePump(q.host);
  const real = q.host.nextFrame;
  let thrown = false;
  q.host.nextFrame = (inCall) => {
    if (!thrown) {
      thrown = true;
      throw new Error("the wasm side threw");
    }
    return real(inCall);
  };
  const warn = console.warn;
  console.warn = () => {};
  pump.wake();
  await new Promise((r) => setTimeout(r, 10));
  console.warn = warn;
  pump.wake();
  await until(() => q.written.length === 2);
});

class Held {
  freed = 0;
  free() {
    this.freed++;
  }
}

test("what a connection kept goes to the next of the same account here, once", () => {
  const kept = new KeptByAccount<Held>();
  const one = new Held();
  kept.put("a:1", "ann", one);
  assert.equal(kept.take("b:1", "ann"), undefined, "another server");
  assert.equal(kept.take("a:1", "bob"), undefined, "another account");
  assert.equal(kept.take("a:1", "ann"), one);
  assert.equal(kept.take("a:1", "ann"), undefined, "taken");
  assert.equal(one.freed, 0, "it lives on, in the session that took it");
});

test("a person's disconnect wipes what was kept for that server, and only there", () => {
  const kept = new KeptByAccount<Held>();
  const [here, there] = [new Held(), new Held()];
  kept.put("a:1", "ann", here);
  kept.put("b:1", "ann", there);
  kept.forget("a:1");
  assert.equal(here.freed, 1);
  assert.equal(kept.take("a:1", "ann"), undefined);
  assert.equal(there.freed, 0);
  assert.equal(kept.take("b:1", "ann"), there);
});

test("a newer keep replaces the older, which is freed", () => {
  const kept = new KeptByAccount<Held>();
  const [older, newer] = [new Held(), new Held()];
  kept.put("a:1", "ann", older);
  kept.put("a:1", "ann", newer);
  assert.equal(older.freed, 1);
  assert.equal(kept.take("a:1", "ann"), newer);
});
