// Dive 5, finding F1, at the level of UplinkControl alone (no pacer, no sharer model): a link
// with room whose round trip rises mid-share. video-pacer.ts says "nothing here caps a share
// that the link carries"; these tests fail today because the rise is found as a queue, at the
// rate the share itself was sending. The control is driven as transport.ts drives it: a sample
// per acked frame (WebTransport) or per answered ping (the TCP fallback), `pending` and `rate`
// on the sharer's 33 ms tick.

import { test } from "node:test";
import assert from "node:assert/strict";
import { PROBE_LOST_MS, UPLINK_FLOOR_FRAMES, UPLINK_FLOOR_PROBES, UplinkControl } from "./video-pacer.ts";

const FRAME = 13_000;
const TICK = 33;

/** WebTransport: frames of 13 KB every 33 ms, each acked exactly `rtt(sent at)` after it left. */
function webTransport(rtt: (t: number) => number, ms: number) {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(rtt(0), -5_000);
  c.reset();
  /** Frames out: [left at, acked at]. */
  const out: [number, number][] = [];
  let delivered = 0;
  for (let t = 0; t <= ms; t++) {
    while (out.length > 0 && out[0][1] <= t) {
      const [left] = out.shift()!;
      delivered += FRAME;
      c.sample(t - left, delivered, t);
    }
    if (t % TICK !== 0) continue;
    out.push([t, t + rtt(t)]);
    c.pending(out.map(([left]) => t - left), t);
    c.rate(t);
  }
  return c;
}

/** The TCP fallback: the same video, a ping every 363 ms (the first tick past PROBE_EVERY_MS), its pong `rtt` later. */
function tunnel(rtt: (t: number) => number, ms: number) {
  const c = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  c.base(rtt(0), -5_000);
  c.reset();
  const pings: { at: number; before: number; first: number; pong: number }[] = [];
  let handed = 0;
  let firstSince = NaN;
  let lastPing = -Infinity;
  for (let t = 0; t <= ms; t++) {
    while (pings.length > 0 && pings[0].pong <= t) {
      const p = pings.shift()!;
      c.sample(t - p.at, p.before, t, p.first);
    }
    if (t % TICK !== 0) continue;
    c.pending(pings.filter((p) => t - p.at < PROBE_LOST_MS).map((p) => t - p.at), t);
    c.rate(t);
    if (t - lastPing >= 333) {
      lastPing = t;
      pings.push({ at: t, before: handed, first: firstSince, pong: t + rtt(t) });
      firstSince = NaN;
    }
    handed += FRAME;
    if (Number.isNaN(firstSince)) firstSince = t;
  }
  return c;
}

const RISE_AT = 30_000;

for (const [from, to] of [
  [40, 140],
  [40, 240],
  [150, 400],
]) {
  const rtt = (t: number) => (t < RISE_AT ? from : to);

  test(`d5 F1, WebTransport: a round trip that rises from ${from} to ${to} ms on a link with room is no queue`, () => {
    const c = webTransport(rtt, RISE_AT + 15_000);
    assert.equal(c.finds.length, 0, `every frame was acked a round trip after it left, yet found queued: ${JSON.stringify(c.finds.slice(0, 3))}`);
    assert.ok(!c.paced());
  });

  test(`d5 F1, the TCP fallback: a round trip that rises from ${from} to ${to} ms on a link with room is no queue`, () => {
    const c = tunnel(rtt, RISE_AT + 15_000);
    assert.equal(c.finds.length, 0, `every ping was answered a round trip after it left, yet found queued: ${JSON.stringify(c.finds.slice(0, 3))}`);
    assert.ok(!c.paced());
  });
}

test("d5 F1 control: the same shares with a steady round trip are never found (the harness itself makes no queue)", () => {
  for (const ms of [40, 140, 240, 400]) {
    assert.equal(webTransport(() => ms, 45_000).finds.length, 0, `WebTransport, ${ms} ms`);
    assert.equal(tunnel(() => ms, 45_000).finds.length, 0, `tunnel, ${ms} ms`);
  }
});

// The same, lasting: a round trip that wanders, 2 s at its least and 1 s higher, as a radio
// link's does. The least stays the least, so every higher spell is found again, for the whole
// share. (A stall, nothing crossing and then all at once, is told apart and is no find; this
// is a path that is slower for a second, with every frame still acked in turn.)
for (const [low, high] of [
  [40, 140],
  [40, 110],
  [20, 90],
]) {
  const rtt = (t: number) => (t >= 15_000 && t % 3_000 >= 2_000 ? high : low);

  test(`d5 F1, WebTransport: a round trip of ${low} ms that is ${high} ms for one second in three, on a link with room, is no queue`, () => {
    const c = webTransport(rtt, 75_000);
    assert.equal(c.finds.length, 0, `found queued ${c.finds.length} times in a minute, first ${JSON.stringify(c.finds[0])}`);
  });

  test(`d5 F1, the TCP fallback: a round trip of ${low} ms that is ${high} ms for one second in three, on a link with room, is no queue`, () => {
    const c = tunnel(rtt, 75_000);
    assert.equal(c.finds.length, 0, `found queued ${c.finds.length} times in a minute, first ${JSON.stringify(c.finds[0])}`);
  });
}
