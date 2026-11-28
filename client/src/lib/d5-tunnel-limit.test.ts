// Dive 5, finding F2, at the level of UplinkControl alone: the TCP fallback's rule that a ping pair
// measures the link "at its limit" only if the link took at least 2/3 of the time between the two
// pings (video-pacer.ts measure(), `span * STEADY_GROW >= now - ms - prev[2]`).
//
// The time between two pings is not the time the share took to hand the bytes: the sharer's own
// gate (share.ts, PACE_GATE_MS) holds the encoder for part of it, exactly because a queue stands
// in the socket. So on a link that is at its limit the whole time, a ping interval in which the
// gate let little through is taken for "a link with room", and since a find needs two such
// measures in a row, a share that hands much and little in turn is never found.
//
// The link here is one queue in send order at 1 Mbit/s with a 40 ms round trip. It is never
// idle and every ping waits 300 ms or more behind video. The control is driven as transport.ts
// wrapSocket drives it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { PROBE_LOST_MS, UPLINK_FLOOR_PROBES, UplinkControl } from "./video-pacer.ts";

const TICK = 33;
const PING_EVERY = 11 * TICK; // the first tick at or past PROBE_EVERY_MS: 363 ms
const RTT = 40;
const BYTES_PER_MS = 125; // 1 Mbit/s

/**
 * `between[k % n]` bytes of video handed between ping k and ping k + 1, a share of them on each
 * tick. Returns the control, the least any ping waited behind video (ms) and whether the link
 * ever stood idle.
 */
function tunnelAtItsLimit(between: number[], ms: number) {
  const c = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  c.base(RTT, -5_000);
  c.reset();
  const pings: { at: number; before: number; first: number; pong: number }[] = [];
  let handed = 0;
  let firstSince = NaN;
  // The share's start: 300 ms of the link's time handed at once, so a queue stands from the first ping on
  let linkDone = 0;
  const hand = (bytes: number, t: number) => {
    if (linkDone < t) idle = true;
    linkDone = Math.max(linkDone, t) + bytes / BYTES_PER_MS;
    handed += bytes;
    if (Number.isNaN(firstSince)) firstSince = t;
  };
  let idle = false;
  let leastWait = Infinity;
  let k = -1;
  hand(300 * BYTES_PER_MS, 0);
  idle = false;
  for (let t = 0; t <= ms; t++) {
    while (pings.length > 0 && pings[0].pong <= t) {
      const p = pings.shift()!;
      leastWait = Math.min(leastWait, t - p.at - RTT);
      c.sample(t - p.at, p.before, t, p.first);
    }
    if (t % TICK !== 0) continue;
    c.pending(pings.filter((p) => t - p.at < PROBE_LOST_MS).map((p) => t - p.at), t);
    c.rate(t);
    if (t % PING_EVERY === 0) {
      k++;
      // A ping's pong comes a round trip after the link is done with all that was handed before it
      pings.push({ at: t, before: handed, first: firstSince, pong: Math.ceil(linkDone + RTT) });
      firstSince = NaN;
    } else {
      hand(between[k % between.length] / 10, t);
    }
  }
  return { c, leastWait, idle };
}

test("d5 F2 control: a link at its limit, the share handing the link's rate between every two pings, is found", () => {
  // 363 ms of the link's time between each two pings
  const s = tunnelAtItsLimit([PING_EVERY * BYTES_PER_MS], 20_000);
  assert.ok(!s.idle && s.leastWait >= 250, `every ping waited ${s.leastWait} ms or more`);
  assert.ok(s.c.finds.length > 0, "found");
  assert.ok(s.c.finds[0][0] < 3_000, `found at ${s.c.finds[0][0]} ms`);
  assert.ok(Math.abs(s.c.finds[0][1] / 1_000_000 - 1) < 0.05, `delivered ${s.c.finds[0][1]}`);
});

test("d5 F2: the same link, the share handing much and little in turn (as its own gate makes it), is found too", () => {
  // 500 ms of the link's time, then 225 ms, between pings 363 ms apart: together what the link
  // carries, so the queue neither grows nor drains. 225 ms is 0.62 of 363 ms: under 2/3.
  const much = 62_590;
  const little = 28_160;
  assert.equal(Math.round((much + little) / BYTES_PER_MS), 2 * PING_EVERY);
  const s = tunnelAtItsLimit([much, little], 60_000);
  assert.ok(!s.idle, "the link never stood idle");
  assert.ok(s.leastWait >= 250, `every ping waited ${s.leastWait} ms or more behind video`);
  assert.ok(
    s.c.finds.length > 0,
    `a minute at the link's limit, every ping ${Math.round(s.leastWait)} ms or more late, and no queue found; paced() ${s.c.paced()}`,
  );
});
