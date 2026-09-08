// Presets and clamping of the virtual room. Pure functions only — the stores
// themselves are Svelte writables and need no test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { PRESETS, ROOM_EXTENT, clampToRoom, layout } from "./room.ts";
import { upsertById } from "./upsert.ts";

const ids = [7, 3, 11, 5, 9];

test("every preset places each user exactly once", () => {
  for (const preset of PRESETS) {
    const seats = layout(preset.id, ids);
    if (preset.id === "free") {
      assert.equal(seats.size, 0, "free placement seats nobody");
      continue;
    }
    assert.equal(seats.size, ids.length, `${preset.id} lost someone`);
    for (const id of ids) assert.ok(seats.has(id), `${preset.id} forgot ${id}`);
    for (const p of seats.values()) {
      assert.deepEqual(clampToRoom(p), p, `${preset.id} placed someone outside the room`);
    }
  }
});

test("presets are deterministic and independent of the order users arrive in", () => {
  const a = layout("round", ids);
  const b = layout("round", [...ids].reverse());
  assert.deepEqual([...a.entries()].sort(), [...b.entries()].sort());
});

test("nobody stands on anyone else", () => {
  for (const preset of ["round", "classroom", "line"] as const) {
    const seats = [...layout(preset, ids).values()];
    const seen = new Set(seats.map((p) => `${p.x},${p.y}`));
    assert.equal(seen.size, seats.length, `${preset} put two people in one spot`);
  }
});

test("the class room puts the presenter at the front, facing the rest", () => {
  const seats = layout("classroom", ids, 9);
  assert.deepEqual(seats.get(9), { x: 0, y: 6, z: 0 });
  for (const [id, p] of seats) if (id !== 9) assert.ok(p.y < 6);
  // Without a presenter the lowest id (the earliest joiner) takes the front
  assert.deepEqual(layout("classroom", ids).get(3), { x: 0, y: 6, z: 0 });
  // A presenter who is not in the channel does not get a seat of their own
  const orphan = layout("classroom", ids, 42);
  assert.equal(orphan.size, ids.length);
  assert.ok(!orphan.has(42));
});

test("positions are clamped into the room", () => {
  assert.deepEqual(clampToRoom({ x: 99, y: -99, z: 99 }), {
    x: ROOM_EXTENT,
    y: -ROOM_EXTENT,
    z: 5,
  });
  assert.deepEqual(clampToRoom({ x: 1, y: 2, z: 3 }), { x: 1, y: 2, z: 3 });
});

test("upsert replaces instead of duplicating", () => {
  const id = (c: { channel_id: number; name: string }) => c.channel_id;
  const list = [{ channel_id: 1, name: "General" }];
  const added = upsertById(list, { channel_id: 2, name: "Room" }, id);
  assert.equal(added.added, true);
  assert.deepEqual(added.list.map(id), [1, 2]);

  const again = upsertById(added.list, { channel_id: 2, name: "Room (renamed)" }, id);
  assert.equal(again.added, false);
  assert.deepEqual(again.list.map(id), [1, 2], "a repeat must not duplicate the key");
  assert.equal(again.list[1].name, "Room (renamed)", "the newer state wins");
  assert.notEqual(again.list, added.list, "the input array is never mutated");
});
