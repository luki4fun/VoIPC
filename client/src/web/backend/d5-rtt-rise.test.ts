// Dive 5, finding F1, end to end through the real transport.ts (d5-sim.ts: the real transport,
// pacer and ladder rules on a fake clock; the sharer and the link are modelled). A link with
// unlimited room whose round trip rises mid-share: nothing queues anywhere, yet the share is
// found queued again and again, each time at the rate it was itself sending after the cut
// before, and the picture nearly stops for about 20 s. These tests fail today.

import { test } from "node:test";
import assert from "node:assert/strict";
import { fpsIn, simulate } from "./d5-sim.ts";

const START = 12_000;
const RISE_AT = START + 30_000;

for (const tcp of [false, true]) {
  const carrier = tcp ? "the TCP fallback" : "WebTransport";
  for (const [from, to] of [
    [40, 140],
    [40, 240],
  ]) {
    test(`d5 F1, ${carrier}: a link with room whose round trip rises from ${from} to ${to} ms still carries the share at its frame rate`, async () => {
      const r = await simulate({
        tcp,
        link: { bps: () => Infinity, rttMs: (t) => (t < RISE_AT ? from : to) },
        // 720p30 of a moving picture: 13 KB a frame, 3.2 Mbit/s, as the encoder bench had it
        share: { frameBytes: (_t, key) => (key ? 120_000 : 13_000) },
        startAt: START,
        ms: RISE_AT + 60_000,
      });
      const finds = r.link.uplinkFinds();
      const before = fpsIn(r.made, RISE_AT - 10_000, RISE_AT);
      const after = fpsIn(r.made, RISE_AT, RISE_AT + 20_000);
      const worst = Math.max(...r.timeline.backlogMs);
      // The link never held more than the frame just handed to it
      assert.ok(worst < 5, `the link queued ${worst} ms`);
      assert.ok(before > 29, `${before} frames a second before the rise`);
      assert.ok(
        after > 25,
        `${after.toFixed(1)} frames a second in the 20 s after the rise (${before.toFixed(1)} before); found queued ${finds.length} times, ` +
          `paced at ${finds.map((f) => Math.round(f[2] / 1000)).join(", ")} kbit/s; the ladder went ${r.steps.map((s) => s.level).join(" > ")}`,
      );
      assert.equal(finds.length, 0, "found queued on a link that queued nothing");
    });
  }
}

test("d5 F1 control: with a steady round trip the same share is never found, on either carrier", async () => {
  for (const tcp of [false, true]) {
    for (const ms of [40, 240]) {
      const r = await simulate({
        tcp,
        link: { bps: () => Infinity, rttMs: () => ms },
        share: { frameBytes: (_t, key) => (key ? 120_000 : 13_000) },
        startAt: START,
        ms: START + 60_000,
      });
      assert.equal(r.link.uplinkFinds().length, 0, `${tcp ? "tcp" : "wt"} ${ms} ms`);
      assert.ok(fpsIn(r.made, START + 10_000, START + 60_000) > 29);
    }
  }
});

for (const tcp of [false, true]) {
  test(`d5 F1, ${tcp ? "the TCP fallback" : "WebTransport"}: a link with room whose round trip wanders (40 ms for 2 s, 140 ms for 1 s) carries the share at its frame rate`, async () => {
    const from = START + 15_000;
    const ms = START + 90_000;
    const r = await simulate({
      tcp,
      link: { bps: () => Infinity, rttMs: (t) => (t >= from && (t - START) % 3_000 >= 2_000 ? 140 : 40), ordered: true },
      share: { frameBytes: (_t, key) => (key ? 120_000 : 13_000) },
      startAt: START,
      ms,
    });
    const finds = r.link.uplinkFinds();
    const worst = Math.max(...r.timeline.backlogMs);
    assert.ok(worst < 5, `the link queued ${worst} ms`);
    const late = fpsIn(r.made, ms - 30_000, ms);
    assert.ok(
      late > 25,
      `${late.toFixed(1)} frames a second in the share's last 30 s (${fpsIn(r.made, START + 5_000, from).toFixed(1)} before the round trip began to wander); ` +
        `found queued ${finds.length} times; the ladder went ${r.steps.map((s) => s.level).join(" > ")}`,
    );
  });
}
