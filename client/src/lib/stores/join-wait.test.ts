import { test } from "node:test";
import assert from "node:assert/strict";

const { afterJoin, dropJoinWaits, JOIN_WAIT_MS, joinedNow } = await import("./join-wait.ts");

const S = "h.example:9987";

test("an ask for a channel not joined yet goes on at its join, once", () => {
  const ran: string[] = [];
  afterJoin(S, 7, () => ran.push("seven"), 1000);
  afterJoin(S, 8, () => ran.push("eight"), 1000);
  joinedNow(S, [9], 2000);
  assert.deepEqual(ran, [], "the control: another channel's join");
  joinedNow(S, [7], 3000);
  assert.deepEqual(ran, ["seven"]);
  joinedNow(S, [7, 8], 4000);
  assert.deepEqual(ran, ["seven", "eight"], "each once");
  dropJoinWaits(S);
});

test("one that waited too long, or whose connection went, is let go", () => {
  const ran: string[] = [];
  afterJoin(S, 7, () => ran.push("late"), 0);
  joinedNow(S, [7], JOIN_WAIT_MS + 1);
  afterJoin(S, 7, () => ran.push("cut"), 0);
  dropJoinWaits(S);
  joinedNow(S, [7], 1);
  assert.deepEqual(ran, []);
});
