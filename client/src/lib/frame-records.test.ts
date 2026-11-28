import { test } from "node:test";
import assert from "node:assert/strict";
import { GAP, KEY, records } from "./frame-records.ts";

/** A record as view_queue.rs writes it. */
function record(flags: number, seq: number, at: number, data: number[]): number[] {
  const b = new Uint8Array(17);
  const v = new DataView(b.buffer);
  v.setUint32(0, data.length, true);
  v.setUint8(4, flags);
  v.setUint32(5, seq, true);
  v.setBigUint64(9, BigInt(at), true);
  return [...b, ...data];
}

test("a body reads as the frames the app queued, in order", () => {
  const body = new Uint8Array([...record(KEY, 7, 1_763_000_000_123, [1, 2, 3]), ...record(GAP, 8, 1_763_000_000_160, [])]);
  const got = [...records(body)].map((r) => ({ ...r, data: [...r.data] }));
  assert.deepEqual(got, [
    { flags: KEY, seq: 7, at: 1_763_000_000_123, data: [1, 2, 3] },
    { flags: GAP, seq: 8, at: 1_763_000_000_160, data: [] },
  ]);
});

test("a record cut short ends the body", () => {
  const whole = record(0, 1, 0, [9, 9]);
  const body = new Uint8Array([...whole, ...record(0, 2, 0, [5, 5, 5]).slice(0, 19)]);
  assert.equal([...records(body)].length, 1);
});
