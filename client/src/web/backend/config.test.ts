// The browser's settings: the switch to share history starts off, its one reset, and two
// tabs on one origin. A fake `localStorage`; each load is a fresh copy of the module.

import { test } from "node:test";
import assert from "node:assert/strict";

const stored = new Map<string, string>();
(globalThis as any).localStorage = {
  getItem: (k: string) => stored.get(k) ?? null,
  setItem: (k: string, v: string) => void stored.set(k, v),
  removeItem: (k: string) => void stored.delete(k),
};
const listeners: ((e: { key: string }) => void)[] = [];
(globalThis as any).addEventListener = (name: string, then: (e: { key: string }) => void) => {
  if (name === "storage") listeners.push(then);
};
await import("../../lib/stores/node-stores.mjs");

const KEY = "voipc.settings";
let loads = 0;
const load = () => import(new URL(`./config.ts?load=${++loads}`, import.meta.url).href);
const saved = () => JSON.parse(stored.get(KEY) ?? "null");
const start = (settings: unknown) => {
  stored.clear();
  listeners.length = 0;
  if (settings !== null) stored.set(KEY, JSON.stringify(settings));
};

test("a fresh install starts off and owes no notice", async () => {
  start(null);
  const { getConfig } = await load();
  assert.equal(getConfig().share_channel_history, false);
  assert.equal(getConfig().share_off_notice, false);
  assert.equal(saved(), null, "nothing to keep yet");
});

test("a saved true goes off once with one notice", async () => {
  start({ share_channel_history: true });
  const { getConfig } = await load();
  assert.equal(getConfig().share_channel_history, false);
  assert.equal(getConfig().share_off_notice, true);
  assert.equal(saved().share_channel_history, false, "kept, so a reload does not read it on");
  assert.equal(saved().share_off_once, true);
  const again = await load();
  assert.equal(again.getConfig().share_off_notice, true, "until it is shown");
});

test("a saved false stays off with no notice", async () => {
  start({ share_channel_history: false });
  const { getConfig } = await load();
  assert.equal(getConfig().share_channel_history, false);
  assert.equal(getConfig().share_off_notice, false);
  assert.equal(saved().share_off_once, true);
});

test("turned on after the reset stays on", async () => {
  start({ share_channel_history: true });
  const first = await load();
  first.updateConfig((c: any) => {
    c.share_channel_history = true;
    c.share_off_notice = false;
  });
  const again = await load();
  assert.equal(again.getConfig().share_channel_history, true);
  assert.equal(again.getConfig().share_off_notice, false);
});

test("a switch off in another tab reaches this one", async () => {
  start({ share_channel_history: true, share_off_once: true });
  const { getConfig, onShareMoved } = await load();
  const moved: boolean[] = [];
  onShareMoved((on: boolean) => moved.push(on));
  stored.set(KEY, JSON.stringify({ ...saved(), share_channel_history: false }));
  for (const heard of listeners) heard({ key: "something else" });
  assert.deepEqual(moved, [], "only this key");
  for (const heard of listeners) heard({ key: KEY });
  assert.equal(getConfig().share_channel_history, false);
  assert.deepEqual(moved, [false]);
  for (const heard of listeners) heard({ key: KEY });
  assert.deepEqual(moved, [false], "said once");
});

test("a tab that has not heard yet does not write the switch back on", async () => {
  start({ share_channel_history: true, share_off_once: true });
  const { getConfig, updateConfig, onShareMoved } = await load();
  const moved: boolean[] = [];
  onShareMoved((on: boolean) => moved.push(on));
  // Another tab, whose `storage` event is still on its way
  stored.set(KEY, JSON.stringify({ ...saved(), share_channel_history: false }));
  updateConfig((c: any) => {
    c.open_servers = ["a:1"];
  });
  assert.equal(saved().share_channel_history, false);
  assert.equal(getConfig().share_channel_history, false);
  assert.deepEqual(moved, [false], "and its connections hear of it now");
  assert.deepEqual(saved().open_servers, ["a:1"], "what it did change is kept");
});

test("this tab's own move goes through", async () => {
  start({ share_channel_history: false, share_off_once: true });
  const { updateConfig, onShareMoved } = await load();
  const moved: boolean[] = [];
  onShareMoved((on: boolean) => moved.push(on));
  updateConfig((c: any) => {
    c.share_channel_history = true;
  });
  assert.equal(saved().share_channel_history, true);
  assert.deepEqual(moved, [], "nobody else moved it");
});
