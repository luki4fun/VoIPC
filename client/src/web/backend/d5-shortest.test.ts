// Dive 5, finding F4, through the real transport.ts (d5-sim.ts). UplinkControl keeps the
// shortest round trip the link ever showed and never lets it age (video-pacer.ts `shortest`);
// the steady check's windows are three of it, so that a new path's slow start, whose acks come
// in bursts a round trip apart, cannot pass for a link's own even rate. On a connection whose
// path was 40 ms once and has been 300 ms for 25 s (the least has long relearnt it), the
// windows are still 200 ms, and a share that starts then has its slow start found as a queue.
//
// The link has room throughout. Its slow start is modelled as in video-pacer.test.ts: a window
// of ten packets that grows by what is acked.

import { test } from "node:test";
import assert from "node:assert/strict";
import { simulate } from "./d5-sim.ts";

const START = 40_000;
const picture = { frameBytes: (_t: number, key: boolean) => (key ? 40_000 : 13_000) };

test("d5 F4 control: a 300 ms path's slow start at the share's start is no queue", async () => {
  const r = await simulate({
    tcp: false,
    link: { bps: () => Infinity, rttMs: () => 300, slowStart: true },
    share: picture,
    startAt: START,
    ms: START + 30_000,
  });
  assert.equal(r.link.uplinkFinds().length, 0);
});

test("d5 F4: the same, on a connection whose path was 40 ms until 25 s before the share", async () => {
  const r = await simulate({
    tcp: false,
    link: { bps: () => Infinity, rttMs: (t) => (t < START - 25_000 ? 40 : 300), slowStart: true },
    share: picture,
    startAt: START,
    ms: START + 30_000,
  });
  const finds = r.link.uplinkFinds();
  assert.equal(
    finds.length,
    0,
    `found queued ${(finds[0]?.[0] - START) / 1000} s into the share at ${Math.round((finds[0]?.[1] ?? 0) / 1000)} kbit/s, the least ${finds[0]?.[3]} ms (relearnt), on a link with room; the ladder went ${r.steps.map((s) => s.level).join(" > ")}`,
  );
});
