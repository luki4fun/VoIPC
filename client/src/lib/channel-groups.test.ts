import { test } from "node:test";
import assert from "node:assert/strict";
import { groupChannels, movedBy, movedInCategory, shownOf, cleanLayout } from "./channel-groups.ts";
import type { ChannelInfo, ChannelPlace } from "./types.ts";

const ch = (channel_id: number, text = true) => ({ channel_id, text, name: `c${channel_id}` }) as ChannelInfo;
const at = (channel_id: number, category: number | null): ChannelPlace => ({
  channel_id,
  category,
  kept: false,
  welcome: false,
});

test("with no layout (an older relay) the list is what it always was", () => {
  const groups = groupChannels([ch(2), ch(1), ch(3, false)], { categories: [], channels: [] });
  assert.equal(groups.length, 1);
  assert.equal(groups[0].category, null);
  assert.deepEqual(groups[0].text.map((c) => c.channel_id), [1, 2]);
  assert.deepEqual(groups[0].voice.map((c) => c.channel_id), [3]);
});

test("channels go in their categories, in the layout's order, and the rest stay on top", () => {
  const groups = groupChannels([ch(1), ch(2), ch(3), ch(4, false)], {
    categories: [{ id: 9, name: "Games" }],
    channels: [at(3, 9), at(1, null), at(2, 9), at(4, 9)],
  });
  assert.deepEqual(groups.map((g) => g.category?.name ?? null), [null, "Games"]);
  assert.deepEqual(groups[0].text.map((c) => c.channel_id), [1]);
  assert.deepEqual(groups[1].text.map((c) => c.channel_id), [3, 2]);
  assert.deepEqual(groups[1].voice.map((c) => c.channel_id), [4]);
});

test("a channel the layout does not name follows the ones it does", () => {
  const groups = groupChannels([ch(5), ch(1)], { categories: [], channels: [at(5, null)] });
  assert.deepEqual(groups[0].text.map((c) => c.channel_id), [5, 1]);
});

test("a channel in a category this member is not told of stays visible, on top", () => {
  const groups = groupChannels([ch(1)], { categories: [], channels: [at(1, 4)] });
  assert.deepEqual(groups[0].text.map((c) => c.channel_id), [1]);
});

test("a move stays among the channels of its own category", () => {
  const list = [at(1, 1), at(2, 2), at(3, 1)];
  assert.deepEqual(movedInCategory(list, 3, -1).map((p) => p.channel_id), [3, 2, 1]);
  assert.equal(movedInCategory(list, 1, -1), list, "already first");
  assert.equal(movedInCategory(list, 2, 1), list, "alone there");
  assert.equal(movedInCategory(list, 7, 1), list, "no such channel");
});

test("a move stops at the ends", () => {
  assert.deepEqual(movedBy([1, 2, 3], 0, 1), [2, 1, 3]);
  assert.deepEqual(movedBy([1, 2, 3], 0, -1), [1, 2, 3]);
  assert.deepEqual(movedBy([1, 2, 3], 2, 1), [1, 2, 3]);
});

test("a folded category still shows what is open in it", () => {
  const list = [ch(1), ch(2)];
  assert.deepEqual(shownOf(list, false, () => false), list);
  assert.deepEqual(shownOf(list, true, (c) => c.channel_id === 2).map((c) => c.channel_id), [2]);
});

test("a layout is drawn with one row per id, and no category is null", () => {
  const raw = {
    categories: [
      { id: 1, name: "A" },
      { id: 1, name: "A again" },
      { id: 2, name: "B" },
    ],
    channels: [
      { channel_id: 5, category: undefined, kept: true, welcome: false },
      { channel_id: 6, category: 2, kept: false, welcome: true },
      { channel_id: 5, category: 2, kept: true, welcome: false },
    ],
  } as unknown as Parameters<typeof cleanLayout>[0];
  const clean = cleanLayout(raw);
  assert.deepEqual(clean.categories.map((c) => c.name), ["A", "B"]);
  assert.deepEqual(clean.channels.map((p) => [p.channel_id, p.category]), [[5, null], [6, 2]]);
  assert.deepEqual(cleanLayout({}), { categories: [], channels: [] });
});
