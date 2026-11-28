// Dive 5, finding F2, end to end through the real transport.ts (d5-sim.ts: the real transport,
// pacer and ladder rules on a fake clock; the sharer and the link are modelled): a share over
// the TCP fallback on a link too small for it. After each try unpaced, the queue should be
// found again within a second or two (the changelog's 1.3-1.8 s). Instead the share stays
// unpaced for many seconds at a time, because every other ping interval carries less than 2/3
// of the link's time (the sharer's own gate held the encoder) and so does not count.
// Meanwhile only the gate holds video back, and each keyframe goes into the socket whole.
//
// The phase is read from UplinkControl (a private field, read only) by wrapping `rate`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { simulate } from "./d5-sim.ts";
import { UplinkControl } from "../../lib/video-pacer.ts";

const START = 12_000;

/** Runs `sim` and returns, per ms, whether the share was unpaced ("free") then. */
async function withPhases<T>(ms: number, sim: () => Promise<T>): Promise<{ r: T; free: boolean[] }> {
  const P = UplinkControl.prototype as any;
  const rate = P.rate;
  const seen: (boolean | undefined)[] = [];
  P.rate = function (now: number) {
    const v = rate.call(this, now);
    seen[Math.floor(now)] = this.phase === "free";
    return v;
  };
  try {
    const r = await sim();
    const free: boolean[] = [];
    let last = true;
    for (let t = 0; t <= ms; t++) free[t] = last = seen[t] ?? last;
    return { r, free };
  } finally {
    P.rate = rate;
  }
}

function spells(free: boolean[], from: number, to: number) {
  let longest = 0;
  let run = 0;
  let total = 0;
  for (let t = from; t < to; t++) {
    if (free[t]) {
      run++;
      total++;
      longest = Math.max(longest, run);
    } else run = 0;
  }
  return { longest, share: total / (to - from) };
}

for (const [name, rttMs, dropAt] of [
  ["a 20 Mbit/s link that drops to 1 Mbit/s 30 s into the share, 40 ms away", 40, START + 30_000],
  ["a 1 Mbit/s link 300 ms away", 300, 0],
] as const) {
  test(`d5 F2, the TCP fallback: ${name}: a try unpaced meets the queue again within seconds`, async () => {
    const ms = START + 150_000;
    const { r, free } = await withPhases(ms, () =>
      simulate({
        tcp: true,
        link: { bps: (t) => (t >= dropAt ? 1_000_000 : 20_000_000), rttMs: () => rttMs },
        // 720p30 of a moving picture; at the ladder's bottom (15 fps) still 1.56 Mbit/s and its keyframes
        share: { frameBytes: (_t, key) => (key ? 120_000 : 13_000), talkFrom: START },
        startAt: START,
        ms,
      }),
    );
    const finds = r.link.uplinkFinds();
    assert.ok(finds.length > 0, "the queue was found at all");
    // From 20 s after the link was first too small: the start is the changelog's, not this finding's
    const from = Math.max(dropAt, START) + 20_000;
    const { longest, share } = spells(free, from, ms);
    const voice = r.queue.voiceDelays.filter(([t]) => t >= from);
    const late = (rows: number[][]) => Math.round((100 * rows.filter(([, d]) => d > 150 + rttMs / 2).length) / Math.max(1, rows.length));
    const said =
      `unpaced ${Math.round(share * 100)} % of the time, ${(longest / 1000).toFixed(1)} s at a stretch; voice more than 150 ms late: ` +
      `${late(voice.filter(([t]) => free[Math.floor(t)]))} % while unpaced, ${late(voice.filter(([t]) => !free[Math.floor(t)]))} % while paced`;
    // A probe holds after 3 s (PROBE_HOLD_MS); a queue met again is found in under 2 s by the changelog
    assert.ok(longest <= 5_000, `the link never had room, yet the share went ${said}`);
    assert.ok(share <= 0.3, `the link never had room, yet the share went ${said}`);
  });
}
