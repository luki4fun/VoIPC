// Dive 5, finding F3, at the level of UplinkControl alone: the TCP fallback on a link with room
// whose pongs do not come back evenly. Nothing queues on the way up: every ping reaches the
// relay a one-way delay after it was sent. Only the way back differs: each pong is late at
// random by up to 100 ms, or pongs are released in batches (a proxy that buffers, a radio that
// sleeps between beacons). In order, as one TCP stream delivers.
//
// The tunnel's control takes the floor of only two pongs, calls a ping pair "at its limit"
// when both pongs were 60 ms late, and then finds a queue at the rate the share itself sends.
// The control is driven as transport.ts wrapSocket drives it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { PROBE_LOST_MS, UPLINK_FLOOR_PROBES, UplinkControl } from "./video-pacer.ts";

const FRAME = 13_000;
const TICK = 33;
const RTT = 40;

/** 13 KB of video every 33 ms, a ping every 363 ms, its pong `RTT + late(due)` after it, never before the pong before it. */
function tunnel(late: (due: number) => number, ms: number) {
  const c = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  c.base(RTT, -5_000);
  c.reset();
  const pings: { at: number; before: number; first: number; pong: number }[] = [];
  let handed = 0;
  let firstSince = NaN;
  let lastPing = -Infinity;
  let lastPong = 0;
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
      const due = t + RTT;
      lastPong = Math.max(lastPong, Math.ceil(due + late(due)));
      pings.push({ at: t, before: handed, first: firstSince, pong: lastPong });
      firstSince = NaN;
    }
    handed += FRAME;
    if (Number.isNaN(firstSince)) firstSince = t;
  }
  return c;
}

/** A fixed pseudo-random sequence in [0, 1). */
function random(seed: number): () => number {
  return () => (seed = (seed * 48271) % 2147483647) / 2147483647;
}

test("d5 F3 control: pongs on time, 50 ms late at random, or in batches every 100 ms are no queue", () => {
  assert.equal(tunnel(() => 0, 120_000).finds.length, 0, "on time");
  const rnd = random(7);
  assert.equal(tunnel(() => rnd() * 50, 120_000).finds.length, 0, "late by up to 50 ms");
  assert.equal(tunnel((due) => 100 - (due % 100), 120_000).finds.length, 0, "batches every 100 ms");
});

for (const upTo of [100, 200, 300]) {
  test(`d5 F3: a link with room, each pong late by up to ${upTo} ms at random, is no queue`, () => {
    const rnd = random(12345);
    const c = tunnel(() => rnd() * upTo, 120_000);
    assert.equal(
      c.finds.length,
      0,
      `found queued ${c.finds.length} times in two minutes, first at ${c.finds[0]?.[0]} ms at ${Math.round((c.finds[0]?.[1] ?? 0) / 1000)} kbit/s (the share's own rate)`,
    );
  });
}

for (const every of [200, 500]) {
  test(`d5 F3: a link with room, the pongs released in batches every ${every} ms, is no queue`, () => {
    const c = tunnel((due) => every - (due % every), 120_000);
    assert.equal(
      c.finds.length,
      0,
      `found queued ${c.finds.length} times in two minutes, first at ${c.finds[0]?.[0]} ms at ${Math.round((c.finds[0]?.[1] ?? 0) / 1000)} kbit/s`,
    );
  });
}
