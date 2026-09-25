// The poke popup rules. Pure functions only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { addPoke, createPoke } from "./pokes.ts";

test("a sender who pokes again replaces their own popup", () => {
  const first = addPoke([], createPoke("a:1", 7, "mallory", "hi"));
  assert.equal(first.fresh, true);
  const again = addPoke(first.list, createPoke("a:1", 7, "mallory", "hi again"));
  assert.equal(again.fresh, false, "no second sound for the same sender");
  assert.deepEqual(
    again.list.map((p) => p.message),
    ["hi again"],
  );
});

test("the same user id on another server is somebody else", () => {
  const one = addPoke([], createPoke("a:1", 7, "alice", "")).list;
  const both = addPoke(one, createPoke("b:1", 7, "bob", ""));
  assert.equal(both.fresh, true);
  assert.equal(both.list.length, 2);
});

test("only the newest popups stay", () => {
  let list: ReturnType<typeof addPoke>["list"] = [];
  for (let id = 1; id <= 8; id++) list = addPoke(list, createPoke("a:1", id, `u${id}`, ""), 5).list;
  assert.deepEqual(
    list.map((p) => p.from_user_id),
    [4, 5, 6, 7, 8],
  );
});
