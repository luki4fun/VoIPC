// The browser sharer's send pacing: unpaced while its uplink shows no queue; once it does,
// paced at what the link delivered, a frame's records in order, whole, no faster than the rate
// after a small burst. Time is the caller's (ms), so no clock runs here.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CUT_FACTOR,
  DRAIN_FACTOR,
  DRAIN_MAX_MS,
  MIN_RATE_BPS,
  PACE_BURST_MS,
  PACE_GATE_MS,
  PACE_MIN_BURST,
  PROBE_AFTER_MS,
  PROBE_HOLD_MS,
  PROBE_EVERY_MS,
  PROBE_LOST_MS,
  PROBE_MAX_MS,
  UPLINK_FLOOR_FRAMES,
  UPLINK_FLOOR_PROBES,
  UPLINK_GROW_MS,
  UPLINK_KEPT,
  UPLINK_MARGIN_MS,
  UplinkControl,
  VideoPacer,
  type PacedSlice,
} from "./video-pacer.ts";

/** A frame body: `n` records of `size` bytes each, every byte its record's index. */
function body(n: number, size = 1200): Uint8Array {
  const out = new Uint8Array(n * (2 + size));
  for (let i = 0; i < n; i++) {
    const at = i * (2 + size);
    out[at] = size >> 8;
    out[at + 1] = size & 0xff;
    out.fill(i & 0xff, at + 2, at + 2 + size);
  }
  return out;
}

/** Each slice ends on a record boundary of its frame. */
function wholeRecords(s: PacedSlice<unknown>): boolean {
  let off = 0;
  while (off < s.bytes.length) off += 2 + ((s.bytes[off] << 8) | s.bytes[off + 1]);
  return off === s.bytes.length;
}

const MBIT = 1_000_000;

test("with no rate set a frame goes out whole at once", () => {
  const p = new VideoPacer<string>(0);
  const f = body(10);
  p.push(f, "a");
  const out = p.take(0);
  assert.equal(out.length, 1);
  assert.deepEqual([out[0].first, out[0].last, out[0].bytes.length], [true, true, f.length]);
  assert.ok(p.empty());
});

test("a frame under the burst goes out at once; a big one at the rate, in whole records", () => {
  const p = new VideoPacer<string>(0);
  p.setRate(2 * MBIT, 0); // 250 bytes a ms: the burst is its 40 ms, 10 KB
  const small = body(5); // 6 KB
  p.push(small, "small");
  const now = p.take(0);
  assert.equal(now.length, 1);
  assert.ok(now[0].first && now[0].last, "the small frame went whole");

  // 100 records (120 KB): what the burst left now, the rest at 250 bytes a ms
  const big = body(100);
  p.push(big, "big");
  let sent = 0;
  let t = 0;
  let firstAt = -1;
  let lastAt = -1;
  const slices: PacedSlice<string>[] = [];
  for (; t <= 2000 && !p.empty(); t += 10) {
    for (const s of p.take(t)) {
      assert.ok(wholeRecords(s), "a slice ends on a record boundary");
      if (s.first) firstAt = t;
      if (s.last) lastAt = t;
      sent += s.bytes.length;
      slices.push(s);
    }
    // Never ahead of the bucket: the rate since 0, plus a burst and one record of overdraw
    assert.ok(sent + small.length <= 250 * t + PACE_BURST_MS * 250 + 1202 + 1, `at ${t} ms ${sent} bytes out`);
  }
  assert.equal(sent, big.length);
  assert.equal(firstAt, 0, "it starts on what the burst left");
  // 120 KB + the 6 KB before it, less the 10 KB burst, at 250 B/ms: about 465 ms
  assert.ok(lastAt >= 440 && lastAt <= 500, `last bytes at ${lastAt} ms`);
  // Its bytes in order, nothing twice
  const joined = new Uint8Array(sent);
  let off = 0;
  for (const s of slices) {
    joined.set(s.bytes, off);
    off += s.bytes.length;
  }
  assert.deepEqual(joined, big);
  assert.equal(slices.filter((s) => s.first).length, 1);
  assert.equal(slices.filter((s) => s.last).length, 1);
});

test("frames go out in order: the next one starts only once the one before has ended", () => {
  const p = new VideoPacer<number>(0);
  p.setRate(1 * MBIT, 0);
  for (let i = 0; i < 4; i++) p.push(body(8), i);
  const order: string[] = [];
  for (let t = 0; t <= 1000 && !p.empty(); t += 10) {
    for (const s of p.take(t)) {
      if (s.first) order.push(`open ${s.tag}`);
      if (s.last) order.push(`end ${s.tag}`);
    }
  }
  assert.deepEqual(order, ["open 0", "end 0", "open 1", "end 1", "open 2", "end 2", "open 3", "end 3"]);
});

test("what waits, in ms at the rate, is what the sharer's gate reads", () => {
  const p = new VideoPacer<null>(0);
  p.setRate(8 * MBIT, 0); // 1000 bytes a ms
  assert.equal(p.queuedMs(), 0);
  p.push(body(200), null); // 240.4 KB, 40 KB of it at once
  p.take(0);
  const left = p.queuedBytes();
  assert.ok(left > 195_000 && left < 205_000, `${left} bytes wait`);
  assert.ok(Math.abs(p.queuedMs() - left / 1000) < 1e-9);
  assert.ok(p.queuedMs() > PACE_GATE_MS, "a frame far over the burst holds the encoder back");
  // A rate halved doubles the wait
  p.setRate(4 * MBIT, 0);
  assert.ok(Math.abs(p.queuedMs() - left / 500) < 1e-9);
});

test("over a long run the pacer lets out no more than its rate and one burst", () => {
  const p = new VideoPacer<null>(0);
  const bps = 2_250_000; // a link that delivered 2.6 Mbit/s, at CUT_FACTOR
  p.setRate(bps, 0);
  let sent = 0;
  let skipped = 0;
  // An encoder far over its rate: 15 KB a frame at 30 fps (3.6 Mbit/s), gated as share.ts does
  for (let t = 0; t < 10_000; t += 1) {
    if (t % 33 === 0) {
      if (p.queuedMs() > PACE_GATE_MS) skipped++;
      else p.push(body(12, 1250), null);
    }
    if (t % 10 === 0) for (const s of p.take(t)) sent += s.bytes.length;
  }
  const allowed = (bps / 8000) * 10_000 + Math.max(PACE_MIN_BURST, (bps / 8000) * PACE_BURST_MS);
  assert.ok(sent <= allowed, `${sent} bytes out, ${allowed} allowed`);
  assert.ok(sent >= allowed * 0.9, `the link was fed its rate (${sent} of ${allowed})`);
  assert.ok(skipped > 50, `the gate held the encoder back (${skipped} frames)`);
});

test("an idle bucket refills to its burst, never more", () => {
  const p = new VideoPacer<null>(0);
  p.setRate(1 * MBIT, 0); // 125 bytes a ms, burst 5 KB -> the 4-record floor
  p.push(body(1), null);
  p.take(0);
  // Ten seconds idle: still one burst's worth at once
  p.push(body(20), null);
  let now = 0;
  for (const s of p.take(10_000)) now += s.bytes.length;
  assert.ok(now <= PACE_MIN_BURST + 1202, `${now} bytes at once after idling`);
});

test("a malformed body still goes out, whole, and cannot stall the queue", () => {
  const p = new VideoPacer<null>(0);
  p.setRate(1 * MBIT, 0);
  const junk = new Uint8Array([0, 0, 1, 2, 3, 0, 9]);
  p.push(junk, null);
  p.push(body(1), null);
  let total = 0;
  for (let t = 0; t < 200 && !p.empty(); t += 10) for (const s of p.take(t)) total += s.bytes.length;
  assert.equal(total, junk.length + 1202);
  assert.ok(p.empty());
});

test("clear drops what waits and says whose it was", () => {
  const p = new VideoPacer<string>(0);
  p.setRate(1 * MBIT, 0);
  p.push(body(50), "a");
  p.push(body(5), "b");
  p.take(0);
  assert.deepEqual(p.clear(), ["a", "b"]);
  assert.equal(p.queuedBytes(), 0);
  assert.ok(p.empty());
});

/** Frames at 30 fps, each acked `ms(i)` after it left the pacer; `bytes` each. */
function frames(c: UplinkControl, from: number, n: number, ms: (i: number) => number, bytes = 12_000, sent = { total: 0 }) {
  let t = from;
  for (let i = 0; i < n; i++, t += 33) {
    sent.total += bytes;
    c.sample(ms(i), sent.total, t);
  }
  return t;
}

test("the uplink: unpaced while acks keep to the link's least, near or far", () => {
  for (const least of [1, 45, 300]) {
    const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
    c.base(least, 0);
    const t = frames(c, 1000, 300, (i) => least + (i % 7) * 4);
    assert.equal(c.rate(t), 0, `least ${least} ms`);
    assert.equal(c.queuedAt, 0);
    assert.ok(!c.paced());
  }
});

test("the uplink: a queue is acks past max(2 x the least, the least + 60 ms) frame after frame", () => {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  assert.equal(c.threshold(), 40 + Math.max(UPLINK_MARGIN_MS, 40));
  const sent = { total: 0 };
  // 20 frames on time, then a queue that grows 120 ms a second (a link at 2/3 of the video)
  let t = frames(c, 1000, 20, () => 70, 12_000, sent);
  let queue = 0;
  let foundAt = 0;
  for (let i = 0; i < 60 && c.queuedAt === 0; i++, t += 33) {
    queue += 4;
    sent.total += 8_000; // the link delivers 8 KB of each 12 KB frame
    c.sample(70 + queue, sent.total, t);
    foundAt = queue;
  }
  assert.ok(c.queuedAt > 0, "found");
  // Its floor of eight past 100 (the queue had reached 30 ms past what a frame took on time),
  // and grown UPLINK_GROW_MS since: a longer path is late too, but does not grow
  assert.ok(foundAt >= 30 && foundAt <= 30 + UPLINK_FLOOR_FRAMES * 4 + UPLINK_GROW_MS + 4, `found at ${foundAt} ms of queue`);
  // Drained at half what the link delivered (8 KB / 33 ms ~ 1.94 Mbit/s), then paced at 0.85 of it
  const delivered = (8_000 * 8000) / 33;
  const draining = c.rate(t);
  assert.ok(Math.abs(draining - delivered * DRAIN_FACTOR) / delivered < 0.08, `draining at ${draining}`);
  assert.equal(c.finds.length, 1);
  // Acks back near the least: paced at CUT_FACTOR of what it delivered
  t = frames(c, t, UPLINK_FLOOR_FRAMES, () => 50, 8_000, sent);
  const paced = c.rate(t);
  assert.ok(Math.abs(paced - delivered * CUT_FACTOR) / delivered < 0.08, `paced at ${paced}`);
  assert.ok(c.paced());
});

test("the uplink: a drain that does not end is paced again after DRAIN_MAX_MS, and a queue found again cuts again", () => {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  const sent = { total: 0 };
  // A second on time, then every ack later than the one before (a queue grows): the link
  // delivers 10 KB a frame all along
  let t = frames(c, 1000, 30, () => 50, 10_000, sent);
  t = frames(c, t, 10, (i) => 110 + 30 * i, 10_000, sent);
  assert.ok(c.queuedAt > 0);
  const first = c.queuedAt;
  // Still late (what queued before the cut): no second cut while it drains
  t = frames(c, t, 20, () => 280, 7_000, sent);
  assert.equal(c.finds.length, 1);
  assert.ok(t - first < DRAIN_MAX_MS);
  // Paced once DRAIN_MAX_MS is up, the acks still late
  while (t < first + DRAIN_MAX_MS) t = frames(c, t, 1, () => 280, 6_000, sent);
  const paced = c.rate(t);
  assert.ok(paced > 0 && c.paced());
  // Still queued once paced, and growing: cut again, from what it delivered now
  t = frames(c, t, 10, (i) => 290 + 10 * i, 6_000, sent);
  assert.equal(c.finds.length, 2);
  assert.ok(c.queuedAt > first);
  assert.ok(c.rate(t) < paced, "the second cut is lower");
});

test("the uplink: jitter, resends and a stalled page are no queue", () => {
  let seed = 7;
  const rnd = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
  // The lossy lane: 40 +- 20 ms each way, 5 % of packets lost. A frame of three packets is
  // acked after its slowest, and one in seven waits a resend: a round trip and the loss timer
  const oneWay = () => 20 + rnd() * 40;
  for (let run = 0; run < 5; run++) {
    const j = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
    j.base(42, 0);
    frames(j, 1000, 2000, () => {
      let ms = Math.max(oneWay(), oneWay(), oneWay()) + oneWay();
      if (rnd() < 1 - 0.95 ** 3) ms += 1.125 * 80 + oneWay() + oneWay();
      return ms;
    });
    assert.equal(j.queuedAt, 0, `jitter and resends, run ${run}`);
  }
  // A main thread stalled 400 ms: the acks it held come in one moment, each late by the stall
  const s = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  s.base(1, 0);
  let t = frames(s, 1000, 100, () => 2);
  t += 400;
  for (let i = 0; i < 12; i++) s.sample(400 - i * 33, 1_000_000 + i, t + i * 0.2);
  t = frames(s, t + 10, 100, () => 2);
  assert.equal(s.queuedAt, 0, "late acks all in one moment");
  assert.equal(s.rate(t), 0);
});

test("the uplink over the tunnel: the oldest ping out past PACE_GATE_MS is a queue once pongs measured the link at its limit, steady", () => {
  // Pings every 333 ms, each with 100 KB of video handed just after the one before: answered
  // at once while nothing queues, so each pair measures what the share handed, not a limit
  const c = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  c.base(2, 0);
  let t = 1000;
  let bytes = 0;
  for (let i = 0; i < 10; i++, t += 333) {
    c.pending([0], t);
    bytes += 100_000;
    c.sample(3, bytes, t + 3, t - 330);
    for (let k = 1; k <= 10; k++) c.pending([], t + k * 33);
  }
  assert.equal(c.queuedAt, 0);
  // A ping out past the least + PACE_GATE_MS: no find, as nothing measured the link at its limit
  const sentAt = t;
  for (let k = 0; k <= 40; k++) c.pending([k * 33], sentAt + k * 33);
  assert.equal(c.queuedAt, 0, "a ping out long, the link never measured at its limit");
  // Now the link carries 1.2 Mbit/s behind a queue: each pong 666 ms after its ping, 100 KB
  // (667 ms of it) between each, the pings 333 ms apart and every one answered in turn
  const d = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  d.base(2, 0);
  let pongAt = 2000;
  for (let i = 0; i < 6; i++) {
    pongAt += (100_000 * 8000) / 1_200_000;
    d.sample(pongAt - (1000 + i * 333), (i + 1) * 100_000, pongAt, 1000 + (i - 1) * 333 + 1);
  }
  const at = pongAt;
  assert.ok(d.queuedAt > 0, "found on the pongs");
  assert.ok(Math.abs(d.finds[0][1] / 1_200_000 - 1) < 0.03, `delivered ${d.finds[0][1]}`);
  assert.ok(d.finds[0][0] <= at);
  // A clock that comes late (a stalled page) judges nothing
  const s = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  s.base(2, 0);
  for (let k = 0; k < 30; k++) s.pending([], 1000 + k * 33);
  s.pending([1400, 1067], 1000 + 30 * 33 + 1000);
  assert.equal(s.queuedAt, 0);
});

test("the uplink: paced, the rate rises while the encoder wants more, not while it sends less", () => {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  const sent = { total: 0 };
  let t = frames(c, 1000, 30, () => 50, 10_000, sent);
  frames(c, t, 10, (i) => 110 + 30 * i, 10_000, sent);
  t = c.queuedAt + DRAIN_MAX_MS;
  const start = c.rate(t);
  // Held back until just before the probe: about 5 % a second, compounded
  const heldFor = PROBE_AFTER_MS - 100;
  for (let k = 0; k < heldFor / 10; k++) {
    t += 10;
    c.binding(t);
    c.rate(t);
  }
  const risen = c.rate(t);
  assert.ok(Math.abs(risen / start - 1.05 ** (heldFor / 1000)) < 0.01, `${start} -> ${risen}`);
  // A share whose encoder is under the rate, once the last hold is BINDING_MS old: no rise
  const again = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  again.base(40, 0);
  let u = frames(again, 1000, 30, () => 50, 10_000);
  frames(again, u, 10, (i) => 110 + 30 * i, 10_000, { total: 300_000 });
  u = again.queuedAt + DRAIN_MAX_MS;
  again.binding(u);
  for (let k = 0; k < 60; k++) again.rate((u += 10));
  const held = again.rate(u);
  for (let k = 0; k < 100; k++) again.rate((u += 10));
  assert.equal(Math.round(again.rate(u)), Math.round(held));
});

test("the uplink: a new share starts unpaced; the least stays, and a longer path is learnt", () => {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  const sent = { total: 0 };
  frames(c, frames(c, 1000, 30, () => 50, 12_000, sent), 10, (i) => 110 + 30 * i, 12_000, sent);
  assert.ok(c.paced());
  c.reset();
  assert.ok(!c.paced());
  assert.equal(c.rate(5000), 0);
  assert.equal(c.queuedAt, 0);
  assert.equal(c.least(), 40);
  // The path got longer (120 ms) and stays so: past three windows of 10 s it is the least
  const later = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  later.base(40, 0);
  let t = 31_000;
  for (let i = 0; i < 1200; i++, t += 33) later.base(120 + (i % 3), t);
  assert.equal(later.least(), 120);
  frames(later, t, 100, () => 125);
  assert.equal(later.queuedAt, 0);
});

test("the uplink: never paced under MIN_RATE_BPS, however little got through", () => {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  const sent = { total: 0 };
  frames(c, frames(c, 1000, 30, () => 50, 10, sent), 10, (i) => 200 + 100 * i, 10, sent);
  assert.ok(c.queuedAt > 0);
  assert.equal(c.rate(c.queuedAt), MIN_RATE_BPS);
  assert.equal(c.rate(c.queuedAt + DRAIN_MAX_MS), MIN_RATE_BPS);
});

test("the gate's bound: paced, what waits over PACE_GATE_MS is under a frame's worth past it", () => {
  const p = new VideoPacer<null>(0);
  p.setRate(1_200_000, 0); // 150 bytes a ms
  let skipped = 0;
  let most = 0;
  for (let t = 0; t < 5_000; t += 1) {
    if (t % 33 === 0) {
      if (p.queuedMs() > PACE_GATE_MS) skipped++;
      else p.push(body(12, 1250), null);
      most = Math.max(most, p.queuedMs());
    }
    if (t % 10 === 0) p.take(t);
  }
  assert.ok(skipped > 0);
  assert.ok(most <= PACE_GATE_MS + (12 * 1252) / 150 + 1, `${most} ms waited at most`);
});

test("the uplink: on a small link eight frames out past the threshold find the queue before their acks come back", () => {
  // 30 fps into a link that carries 12 frames a second: acks fall behind
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  const sentAt: number[] = [];
  let acked = 0;
  let found = 0;
  for (let k = 0; k < 60 && c.queuedAt === 0; k++) {
    const now = 1000 + k * 33;
    sentAt.push(now);
    // Acked in order, one every 83 ms, each after 40 ms on the way
    for (; acked < Math.floor((now - 1000 - 40) / 83); acked++) c.sample(now - sentAt[acked], (acked + 1) * 12_000, now);
    c.pending(sentAt.slice(acked).map((t) => now - t), now);
    found = now - 1000;
  }
  assert.ok(c.queuedAt > 0, "found");
  // Eight sent over 100 ms ago and not acked, once three windows showed the link's own rate:
  // well within a second, where a floor of eight acks waits for eight late acks first
  assert.ok(found < 800, `found ${found} ms in`);
  // Measured between acks: a window's ends would cost a frame either way (up to 17 % high)
  assert.ok(Math.abs(c.finds[0][1] / 1_152_000 - 1) < 0.03, `delivered ${c.finds[0][1]}`);
});

test("the uplink: frames out on a far link, or one held by a resend, are no queue", () => {
  // A 300 ms round trip at 30 fps: nine or ten frames out at any time, the eighth-oldest about 70 ms old
  const far = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  far.base(300, 0);
  const sentAt: number[] = [];
  for (let k = 0; k < 600; k++) {
    const now = 1000 + k * 33;
    sentAt.push(now);
    far.pending(sentAt.filter((t) => now - t < 300 + (k % 4) * 5).map((t) => now - t), now);
  }
  assert.equal(far.queuedAt, 0, "far");
  // Lossy: acks after 40-120 ms, one frame in seven 200 ms later for a resend
  let seed = 11;
  const rnd = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
  const lossy = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  lossy.base(42, 0);
  const acks: [number, number][] = [];
  for (let k = 0; k < 2000; k++) {
    const now = 1000 + k * 66;
    acks.push([now, now + 40 + rnd() * 80 + (rnd() < 0.14 ? 200 : 0)]);
    lossy.pending(acks.filter(([, a]) => a > now).map(([t]) => now - t), now);
  }
  assert.equal(lossy.queuedAt, 0, "lossy");
});

/**
 * A share on a modelled link, driven as transport.ts and share.ts drive UplinkControl and
 * VideoPacer, on a 1 ms clock: the encoder makes a `bytes` frame every 1000 / `fps` ms (none
 * while the pacer holds more than PACE_GATE_MS), the pacer lets frames out on its PACE_LOOK_MS
 * clock, the sharer's tick asks `pending` once a frame, and a frame is acked `rttMs` after its
 * last byte crossed the link.
 * - `linkBps(t)`: what the link carries from t on, in order (none: room);
 * - `cwnd`: a new QUIC path's congestion window, bytes; it grows by what is acked (slow start,
 *   doubling each round trip), and frames past it wait in the browser, out of the pacer;
 * - `stall`: from, to (ms): nothing crosses either way; every ack due meanwhile comes at `to`.
 */
interface Link {
  rttMs: number;
  linkBps?: (t: number) => number;
  cwnd?: number;
  stall?: [number, number];
  /** The keepalive's round trips before the share, [ms, at]; by default one of `rttMs`. */
  pongs?: [number, number][];
}
function share(link: Link, ms: number, frameRecords = 10, fps = 30) {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  for (const [rtt, at] of link.pongs ?? [[link.rttMs, -5_000]]) c.base(rtt, at);
  c.reset();
  const pacer = new VideoPacer<number>(0);
  const frame = body(frameRecords, 1300);
  /** Frames out of the pacer and not acked yet: when each left it, oldest first. */
  const outAt = new Map<number, number>();
  const held: number[] = [];
  const acks: [number, number][] = [];
  let cwnd = link.cwnd ?? Infinity;
  let inFlight = 0;
  let linkFree = 0;
  let delivered = 0;
  let next = 0;
  const made: number[] = [];
  /** Each ms whether the pacer's rate was 0 (unpaced). */
  const unpaced: boolean[] = [];
  for (let t = 0; t <= ms; t++) {
    while (acks.length > 0 && acks[0][0] <= t) {
      const f = acks.shift()![1];
      inFlight -= frame.length;
      cwnd += frame.length;
      delivered += frame.length;
      c.sample(t - outAt.get(f)!, delivered, t);
      outAt.delete(f);
    }
    let pushed = false;
    if (t >= next) {
      next += 1000 / fps;
      if (pacer.queuedMs() <= PACE_GATE_MS) {
        pacer.push(frame, made.length);
        made.push(t);
        pushed = true;
      }
      c.pending([...outAt.values()].map((at) => t - at), t);
    }
    if (pushed || t % 10 === 0) {
      const rate = c.rate(t);
      if (rate !== pacer.rateBps()) pacer.setRate(rate, t);
      for (const s of pacer.take(t)) {
        if (!s.last) continue;
        outAt.set(s.tag, t);
        held.push(s.tag);
      }
      if (!pacer.empty()) c.binding(t);
    }
    unpaced.push(pacer.rateBps() === 0);
    while (held.length > 0 && (inFlight === 0 || inFlight + frame.length <= cwnd)) {
      const f = held.shift()!;
      inFlight += frame.length;
      const bps = link.linkBps?.(t) ?? Infinity;
      linkFree = Math.max(t, linkFree) + (Number.isFinite(bps) ? (frame.length * 8000) / bps : 0);
      let due = linkFree + link.rttMs;
      if (link.stall && due > link.stall[0] && due < link.stall[1]) due = link.stall[1];
      acks.push([due, f]);
    }
  }
  const madeIn = (from: number, to: number) => made.filter((t) => t >= from && t < to).length;
  return { c, made, madeIn, unpaced, frameBits: frame.length * 8 };
}

test("the uplink: a new QUIC path's slow start backs frames up, and is no queue of ours", () => {
  // 13 KB frames at 30 fps (3.1 Mbit/s), a link with room, a window of one frame at first:
  // on a 300 ms round trip the first acks take 300-900 ms, frames back up past the eighth
  for (const [rttMs, records] of [
    [300, 10],
    [200, 24],
    [300, 24],
  ]) {
    const s = share({ rttMs, cwnd: 14_000 }, 10_000, records);
    assert.equal(s.c.finds.length, 0, `${rttMs} ms, ${records} records: found ${JSON.stringify(s.c.finds)}`);
    assert.ok(s.unpaced.every(Boolean), "never paced");
    assert.ok(s.madeIn(0, 10_000) >= 295, `${s.madeIn(0, 10_000)} frames made`);
  }
});

test("the uplink: a stall of the path both ways, then every ack at once, is no queue", () => {
  // Wi-Fi-like: a link with room, nothing crossing for a moment. On a 40 ms round trip a 400 or
  // 550 ms stall empties a whole window; on 150 ms (windows of 450 ms) the newest window still
  // holds acks from before, and only STEADY_FALL tells the stall from a queue
  for (const [rttMs, ms] of [
    [40, 400],
    [40, 550],
    [150, 400],
    [150, 1000],
  ]) {
    const s = share({ rttMs, stall: [5_000, 5_000 + ms] }, 10_000);
    assert.equal(s.c.finds.length, 0, `${rttMs} ms, ${ms} ms stall: found ${JSON.stringify(s.c.finds)}`);
    assert.ok(s.unpaced.every(Boolean), "never paced");
  }
});

test("the uplink: a link that carries less than the share is found within a second, at its rate, near or far", () => {
  // 13 KB frames at 30 fps into 2.4 Mbit/s: 40 ms away, and 300 ms away on a new path; and
  // 35 KB frames into 1.2 Mbit/s, where the rate over a window's ends is 17 % high
  for (const link of [
    { rttMs: 40, bps: 2_400_000, records: 10 },
    { rttMs: 40, cwnd: 14_000, bps: 2_400_000, records: 10 },
    { rttMs: 300, cwnd: 14_000, bps: 2_400_000, records: 10 },
    { rttMs: 40, bps: 1_200_000, records: 27 },
  ]) {
    const s = share({ ...link, linkBps: () => link.bps }, 6_000, link.records);
    const what = JSON.stringify(link);
    assert.ok(s.c.finds.length > 0, `${what}: found`);
    const [at, delivered] = s.c.finds[0];
    // Near: three windows of 200 ms of the link's own rate; far: once slow start is over
    assert.ok(at < (link.rttMs === 40 ? 900 : 3_000), `${what}: found at ${at}`);
    // Measured between acks
    assert.ok(Math.abs(delivered / link.bps - 1) < 0.03, `${what}: delivered ${delivered}`);
    // Drained, then paced near what the link carries
    const paced = s.c.rate(s.c.queuedAt + DRAIN_MAX_MS);
    assert.ok(Math.abs(paced / (link.bps * CUT_FACTOR) - 1) < 0.2, `${what}: paced at ${paced}`);
  }
});

test("the uplink: a link a frame takes 300 ms or more to cross is found too, its windows two of its gaps between acks", () => {
  // One ack a frame, 350 ms apart: windows of 200 ms (three round trips of 40 ms) hold one ack
  // or none, so the steady check never passed on them and the share was never paced
  for (const link of [
    { bps: 300_000, records: 10 },
    { bps: 800_000, records: 27 },
  ]) {
    const s = share({ rttMs: 40, linkBps: () => link.bps }, 6_000, link.records);
    const what = JSON.stringify(link);
    assert.ok(s.c.finds.length > 0, `${what}: found`);
    const [at, delivered] = s.c.finds[0];
    assert.ok(at < 3_000, `${what}: found at ${at}`);
    assert.ok(Math.abs(delivered / link.bps - 1) < 0.03, `${what}: delivered ${delivered}`);
    assert.ok(s.unpaced.slice(at + 100).filter((u) => !u).length > 2_000, `${what}: paced from the find`);
  }
});

test("the uplink: its windows come from the shortest round trip the link showed, not the late pings of a busy page", () => {
  // As a lane's run had it: one ping on time 40 s before the share, the rest late, the last
  // 10 s before, and the share's first frames queued on a 1 Mbit/s link: by the time its first
  // ack came, the least of late was the first frame's own 145 ms, three and a half times the round trip
  const late: [number, number][] = [[74, -40_000], [336, -30_000], [1285, -20_000], [1031, -10_500]];
  for (const pongs of [undefined, late]) {
    const s = share({ rttMs: 40, linkBps: () => 1_000_000, pongs }, 3_000);
    assert.ok(s.c.finds.length > 0 && s.c.finds[0][0] < 800, `${pongs ? "late pings" : "on time"}: found at ${s.c.finds[0]?.[0]}`);
  }
});

test("the uplink: once a capped link has room again, a paced share goes unpaced within a few seconds and stays so", () => {
  // 3.1 Mbit/s of video into 2.4 Mbit/s for 15 s, then a link with room
  const lift = 15_000;
  const s = share({ rttMs: 40, linkBps: (t) => (t < lift ? 2_400_000 : 100_000_000) }, 45_000);
  assert.ok(s.c.finds.length >= 2, "the queue found, and found again while the cap held");
  // Unpaced again within the longest wait for a probe, a drain and the probe's hold, and from then on
  const by = lift + PROBE_MAX_MS + DRAIN_MAX_MS + PROBE_HOLD_MS;
  assert.ok(s.unpaced.slice(by).every(Boolean), `paced after ${by} ms`);
  assert.ok(!s.c.paced());
  // ...so the encoder makes every frame again, as an unpaced share does
  assert.ok(s.madeIn(by, 45_000) >= ((45_000 - by) * 30) / 1000 - 2, `${s.madeIn(by, 45_000)} frames made from ${by} ms`);
  // Found while capped only (a probe may meet the last of the queue just after the lift)
  assert.ok(s.c.finds.every(([at]) => at < lift + 1_000), `finds at ${s.c.finds.map(([at]) => at)}`);
});

test("the uplink: a probe that meets the queue again doubles the wait for the next, up to PROBE_MAX_MS; one that holds starts over", () => {
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  // A link that queues whenever the share is unpaced and carries it paced: a frame each 33 ms
  // delivered, acked on time paced, and unpaced each 15 ms later than the one before
  let room = false;
  let delivered = 0;
  let t = 1000;
  let queue = 0;
  const step = () => {
    t += 33;
    delivered += 10_000;
    queue = c.rate(t) === 0 && !room ? queue + 15 : 0;
    c.sample(50 + queue, delivered, t);
  };
  while (t < 2_000) step();
  const waits: number[] = [];
  while (t < 40_000) {
    step();
    const p = c.probes;
    if (p.length > waits.length + 1) waits.push(p[p.length - 1] - p[p.length - 2]);
  }
  // Each probe met the queue at once; the wait paced before the next doubled, the time to
  // find and drain the queue on top
  const waited = (w: number, paced: number) => w - paced >= 0 && w - paced <= DRAIN_MAX_MS;
  assert.ok(c.probes[0] - c.finds[0][0] - PROBE_AFTER_MS <= DRAIN_MAX_MS, `first probe ${c.probes[0] - c.finds[0][0]} ms after the find`);
  assert.ok(waits.length >= 4, `waits ${waits}`);
  assert.ok(waited(waits[0], 2 * PROBE_AFTER_MS), `waits ${waits}`);
  assert.ok(waits.slice(1).every((w) => waited(w, PROBE_MAX_MS)), `waits ${waits}`);
  // The link has room now: the next probe holds, and a queue found later is probed after PROBE_AFTER_MS again
  room = true;
  const from = c.probes.length;
  while (c.probes.length === from) step();
  for (let k = 0; k < (PROBE_HOLD_MS + 500) / 33; k++) step();
  assert.equal(c.rate(t), 0, "held");
  room = false;
  const found = c.finds.length;
  while (c.finds.length === found) {
    t += 33;
    delivered += 10_000;
    c.sample(50 + (queue += 15), delivered, t);
  }
  const at = c.queuedAt;
  while (c.probes.length === from + 1) step();
  assert.ok(c.probes[from + 1] - at <= DRAIN_MAX_MS + PROBE_AFTER_MS + 50, `probed ${c.probes[from + 1] - at} ms after the find`);
});

/**
 * A share over the TCP fallback, driven as transport.ts wrapSocket and share.ts drive
 * UplinkControl and VideoPacer, on a 1 ms clock: one socket in send order whose kernel sends
 * a segment (1448 bytes) while less than its window is out, the window growing by what is
 * acked while it limits (slow start from ten segments); the link `linkBps` (none: room) and a
 * one-way delay of half the round trip. A ping every PROBE_EVERY_MS while video went out in
 * the last second, its pong a round trip after it reached the relay; the sharer's gate counts
 * the pacer's queue and the oldest ping's wait past the least (transport.ts socketWaitMs).
 * Frames at `fps`: a keyframe first and every 4 s, deltas between (none on a still screen).
 */
interface Tunnel {
  rttMs: number;
  linkBps?: number;
  key: number;
  delta: number;
  still?: boolean;
  /** From, to (ms): nothing crosses either way. */
  stall?: [number, number];
}
function tunnel(link: Tunnel, ms: number, fps = 30) {
  const MSS = 1448;
  const c = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  c.base(link.rttMs, -5_000);
  c.reset();
  const pacer = new VideoPacer<null>(0);
  const frame = (n: number) => body(Math.ceil(n / 1282), 1282);
  const KEY = frame(link.key);
  const DELTA = frame(link.delta);
  let sentVideo = 0;
  let firstSince = NaN;
  let lastFrameAt = -Infinity;
  let lastProbeAt = -Infinity;
  const probes: { at: number; before: number; first: number }[] = [];
  // The socket: bytes left of each message, and the ping it is (-1 video)
  const socket: { bytes: number; ping: number }[] = [];
  let cwnd = 10 * MSS;
  let inFlight = 0;
  let linkFree = 0;
  const acks: [number, number][] = [];
  const pongs: [number, number][] = [];
  let lastKeyAt = -Infinity;
  let made = 0;
  /** Each ms: the pacer's rate; and at each look, whether the rate and paced() agreed. */
  const rates: number[] = [];
  const agreed: [number, boolean][] = [];
  const waitMs = (t: number) => {
    const p = probes.find((q) => t - q.at < PROBE_LOST_MS);
    return p ? Math.max(0, t - p.at - c.least()) : 0;
  };
  const letOut = (t: number) => {
    const rate = c.rate(t);
    agreed.push([t, rate > 0 === c.paced()]);
    if (rate !== pacer.rateBps()) pacer.setRate(rate, t);
    for (const s of pacer.take(t)) {
      socket.push({ bytes: s.bytes.length, ping: -1 });
      sentVideo += s.bytes.length;
      if (Number.isNaN(firstSince)) firstSince = t;
    }
    if (!pacer.empty()) c.binding(t);
  };
  const stalled = (t: number) => !!link.stall && t >= link.stall[0] && t < link.stall[1];
  for (let t = 0; t <= ms; t++) {
    const stall = stalled(t);
    while (!stall && acks.length > 0 && acks[0][0] <= t) {
      const b = acks.shift()![1];
      if (2 * inFlight > cwnd) cwnd += b;
      inFlight -= b;
    }
    while (!stall && pongs.length > 0 && pongs[0][0] <= t) {
      const at = pongs.shift()![1];
      const i = probes.findIndex((p) => p.at === at);
      if (i < 0) continue;
      const first = probes.slice(0, i + 1).find((p) => !Number.isNaN(p.first))?.first ?? NaN;
      const p = probes[i];
      probes.splice(0, i + 1);
      c.sample(t - p.at, p.before, t, first);
    }
    if (t % Math.round(1000 / fps) === 0) {
      c.pending(probes.filter((p) => t - p.at < PROBE_LOST_MS).map((p) => t - p.at), t);
      letOut(t);
      if (t - lastFrameAt < 1000 && t - lastProbeAt >= PROBE_EVERY_MS) {
        lastProbeAt = t;
        probes.push({ at: t, before: sentVideo, first: firstSince });
        firstSince = NaN;
        socket.push({ bytes: 40, ping: t });
      }
      const key = t - lastKeyAt >= 4_000;
      if ((key || !link.still) && pacer.queuedMs() + waitMs(t) <= PACE_GATE_MS) {
        if (key) lastKeyAt = t;
        pacer.push(key ? KEY : DELTA, null);
        lastFrameAt = t;
        made++;
        letOut(t);
      }
    } else if (t % 10 === 0) {
      letOut(t);
    }
    rates.push(pacer.rateBps());
    if (stall) linkFree = Math.max(linkFree, t + 1);
    while (!stall && socket.length > 0 && inFlight < cwnd) {
      const m = socket[0];
      const n = Math.min(m.bytes, MSS);
      m.bytes -= n;
      inFlight += n;
      linkFree = Math.max(t, linkFree) + (link.linkBps ? (n * 8000) / link.linkBps : 0);
      acks.push([linkFree + link.rttMs, n]);
      if (m.bytes === 0) {
        socket.shift();
        if (m.ping >= 0) pongs.push([linkFree + link.rttMs, m.ping]);
      }
    }
  }
  return { c, made, rates, agreed };
}

test("the uplink over the tunnel: a far link's TCP slow start is no queue: no find, no pace at the floor", () => {
  // A share's first keyframe from a window of ten segments takes four or five round trips: the
  // pings behind it wait, and the rate their pongs come back at doubles each round trip
  for (const [rttMs, key, delta] of [
    [300, 250_000, 35_000],
    [300, 120_000, 13_000],
    [200, 250_000, 35_000],
    [120, 250_000, 35_000],
  ]) {
    const s = tunnel({ rttMs, key, delta }, 10_000);
    const what = `${rttMs} ms, ${key / 1000} KB keys`;
    assert.equal(s.c.finds.length, 0, `${what}: found ${JSON.stringify(s.c.finds)}`);
    assert.ok(s.rates.every((r) => r === 0), `${what}: paced`);
    // The gate held the encoder while the slow start's queue lasted, and only then
    assert.ok(s.made >= 200, `${what}: ${s.made} frames made`);
    assert.ok(s.made - tunnel({ rttMs, key, delta }, 5_000).made >= 148, `${what}: held after the start`);
  }
});

test("the uplink over the tunnel: pongs with no video between them measure nothing: a still screen on 4 Mbit/s is never paced at the floor", () => {
  // Slides: a keyframe every 4 s and nothing between, so every ping of a burst says the same
  // video went before it, and the rate between their pongs was 0
  for (const [linkBps, rttMs, key] of [
    [4_000_000, 40, 250_000],
    [2_000_000, 60, 120_000],
  ]) {
    const s = tunnel({ rttMs, linkBps, key, delta: 0, still: true }, 25_000);
    const what = `${linkBps / 1e6} Mbit/s, ${rttMs} ms`;
    const low = s.c.finds.filter(([, delivered]) => delivered < linkBps / 2);
    assert.equal(low.length, 0, `${what}: found at ${JSON.stringify(low)}`);
    assert.ok(s.rates.every((r) => r === 0 || r >= (linkBps / 2) * DRAIN_FACTOR), `${what}: paced at ${Math.min(...s.rates.filter(Boolean))}`);
  }
});

test("the uplink over the tunnel: a link that carries less than the share is found at its rate, near or far; a stall is not", () => {
  for (const rttMs of [40, 150, 300]) {
    const s = tunnel({ rttMs, linkBps: 2_000_000, key: 120_000, delta: 13_000 }, 10_000);
    assert.ok(s.c.finds.length > 0, `${rttMs} ms: found`);
    const [at, delivered] = s.c.finds[0];
    assert.ok(at < 6_000, `${rttMs} ms: found at ${at}`);
    assert.ok(Math.abs(delivered / 2_000_000 - 1) < 0.1, `${rttMs} ms: delivered ${delivered}`);
  }
  // Wi-Fi-like on a link with room: nothing crosses for a moment, then everything at once
  for (const [rttMs, ms] of [
    [40, 700],
    [150, 1_000],
  ]) {
    const s = tunnel({ rttMs, key: 120_000, delta: 13_000, stall: [5_000, 5_000 + ms] }, 10_000);
    assert.equal(s.c.finds.length, 0, `${rttMs} ms, ${ms} ms stall: found ${JSON.stringify(s.c.finds)}`);
  }
});

test("the uplink over the tunnel: unpaced again after a probe, the rate stays 0 until a queue is found again", () => {
  // As the review had it: a 300 kbps uplink, the share's first keyframe (180 KB) ahead of three
  // pings, then a still screen. Their pongs came after the probe had set the share free, and a
  // rate set from them then held for good while paced() said no
  const c = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  c.base(40, 0);
  c.reset();
  const t0 = 10_000;
  const pings = [
    { at: t0 + 100, before: 180_000 },
    { at: t0 + 433, before: 182_000 },
    { at: t0 + 766, before: 184_000 },
  ];
  const pongAt = (p: { before: number }) => t0 + (p.before * 8000) / 300_000 + 40;
  let answered = 0;
  for (let t = t0; t < t0 + 30_000; t += 33) {
    while (answered < pings.length && pongAt(pings[answered]) <= t) {
      const p = pings[answered++];
      c.sample(t - p.at, p.before, t, answered === 1 ? t0 : p.at - 330);
    }
    c.pending(pings.slice(answered).filter((p) => p.at <= t && t - p.at < PROBE_LOST_MS).map((p) => t - p.at), t);
    const rate = c.rate(t);
    assert.equal(rate > 0, c.paced(), `at t0 + ${t - t0}: rate ${rate}, paced() ${c.paced()}`);
  }
  // And on a link found and probed again and again, at every ms
  const s = tunnel({ rttMs: 40, linkBps: 2_000_000, key: 120_000, delta: 13_000 }, 20_000);
  assert.ok(s.c.probes.length > 0, "probed");
  const disagree = s.agreed.find(([, ok]) => !ok);
  assert.ok(!disagree, `rate and paced() disagree at ${disagree?.[0]} ms`);
});

test("the uplink: finds and probes keep the last UPLINK_KEPT, for a share of any length", () => {
  // A link too small for the bottom level, an hour of it: found again every few seconds
  const c = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  c.base(40, 0);
  let t = 1000;
  let delivered = 0;
  let found = 0;
  let last = 0;
  let queue = 0;
  while (t < 3_600_000) {
    t += 33;
    delivered += 6_000;
    // Unpaced, each ack 30 ms later than the one before; paced, on time
    queue = c.rate(t) === 0 ? queue + 30 : 0;
    c.sample(50 + queue, delivered, t);
    if (c.queuedAt !== last) {
      last = c.queuedAt;
      found++;
    }
  }
  assert.ok(found > 2 * UPLINK_KEPT, `${found} finds`);
  assert.ok(c.finds.length <= UPLINK_KEPT && c.probes.length <= UPLINK_KEPT, `kept ${c.finds.length} finds, ${c.probes.length} probes`);
  assert.equal(c.finds[c.finds.length - 1][0], Math.round(c.queuedAt), "the newest kept");
  assert.ok(c.probeCount >= c.probes.length && c.probeCount > UPLINK_KEPT, `${c.probeCount} probes counted`);
});
