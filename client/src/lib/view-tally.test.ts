import { test } from "node:test";
import assert from "node:assert/strict";
import { ViewTally } from "./view-tally.ts";

test("a report counts what came, what was drawn and what never came", () => {
  const t = new ViewTally(0);
  t.arrive({ seq: 10, at_ms: 1000 });
  t.arrive({ seq: 11, at_ms: 1033 });
  t.arrive({ seq: 14, at_ms: 1100 }); // 12 and 13 never came
  assert.equal(t.latest(), 14);
  t.paint(11, 1060); // 10 was never drawn: 11 replaced it
  t.paint(14, 1130);
  t.paint(10, 1200); // drawn over already: no second count
  assert.deepEqual(t.take(2000), { span_ms: 2000, arrived: 3, drawn: 2, missing: 2, paint_ms: [27, 30] });
});

test("the next report starts empty, and one with nothing in it is none", () => {
  const t = new ViewTally(0);
  t.arrive({ seq: 1, at_ms: 0 });
  t.take(2000);
  assert.equal(t.take(4000), null);
  t.arrive({ seq: 2, at_ms: 4100 });
  assert.deepEqual(t.take(6000), { span_ms: 2000, arrived: 1, drawn: 0, missing: 0, paint_ms: [] });
});

test("frames a WebView never draws are not kept without end", () => {
  const t = new ViewTally(0);
  for (let seq = 0; seq < 500; seq++) t.arrive({ seq, at_ms: seq });
  t.paint(0, 10); // long gone from the waiting list: not counted
  t.paint(499, 600);
  assert.deepEqual(t.take(1000)?.paint_ms, [101]);
});
