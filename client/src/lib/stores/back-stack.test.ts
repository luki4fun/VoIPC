import { test } from "node:test";
import assert from "node:assert/strict";
import { back, depth, pushLayer } from "./back-stack.ts";

test("back with nothing open is not handled", () => {
  assert.equal(depth(), 0);
  assert.equal(back(), false);
});

test("back closes the topmost layer, then the one under it", () => {
  const closed: string[] = [];
  let offDrawer = () => {};
  let offDialog = () => {};
  offDrawer = pushLayer(() => {
    closed.push("drawer");
    offDrawer();
  });
  offDialog = pushLayer(() => {
    closed.push("dialog");
    offDialog();
  });
  assert.equal(back(), true);
  assert.deepEqual(closed, ["dialog"]);
  assert.equal(back(), true);
  assert.deepEqual(closed, ["dialog", "drawer"]);
  assert.equal(back(), false);
});

test("a layer that must be answered takes the press and closes nothing under it", () => {
  const closed: string[] = [];
  const offDrawer = pushLayer(() => closed.push("drawer"));
  const offQuestion = pushLayer(null);
  assert.equal(back(), true);
  assert.equal(back(), true);
  assert.deepEqual(closed, []);
  offQuestion();
  offDrawer();
  assert.equal(depth(), 0);
});

test("a layer closed some other way leaves the stack", () => {
  const off = pushLayer(() => {});
  assert.equal(depth(), 1);
  off();
  off(); // twice is harmless
  assert.equal(depth(), 0);
});

test("a layer that leaves sends back on to the app, and still closes nothing under it", () => {
  const closed: string[] = [];
  const offDrawer = pushLayer(() => closed.push("drawer"));
  let leaving = true;
  const offGate = pushLayer(null, () => leaving);
  assert.equal(back(), false, "the app goes to the background");
  assert.deepEqual(closed, []);
  // Asked at each press: once it may no longer leave, it takes the press
  leaving = false;
  assert.equal(back(), true);
  assert.deepEqual(closed, []);
  offGate();
  assert.equal(back(), true);
  assert.deepEqual(closed, ["drawer"]);
  offDrawer();
  assert.equal(depth(), 0);
});
