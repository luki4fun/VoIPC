// Push-to-talk opens and closes the microphone in the order the key moved.

import { test } from "node:test";
import assert from "node:assert/strict";
import { transmitOrder } from "./transmit-order.ts";

function backend() {
  const log: string[] = [];
  let release: () => void = () => {};
  let open = false;
  const order = transmitOrder(
    () =>
      new Promise<void>((done) => {
        log.push("open asked");
        release = () => {
          open = true;
          log.push("opened");
          done();
        };
      }),
    async () => {
      if (!open) return;
      open = false;
      log.push("closed");
    },
  );
  return { order, log, finishOpening: () => release(), isOpen: () => open };
}

test("a release while the mic is still opening closes it once it is open", async () => {
  const b = backend();
  const pressed = b.order.start();
  await b.order.stop(); // the quick tap: released before the device answered
  b.finishOpening();
  await pressed;
  assert.equal(b.isOpen(), false);
  assert.deepEqual(b.log, ["open asked", "opened", "closed"]);
});

test("a press held through the open stays open, and closes on release", async () => {
  const b = backend();
  const pressed = b.order.start();
  b.finishOpening();
  await pressed;
  assert.equal(b.isOpen(), true);
  await b.order.stop();
  assert.equal(b.isOpen(), false);
});

test("press, release, press again during one open: still talking", async () => {
  const b = backend();
  const first = b.order.start();
  await b.order.stop();
  const second = b.order.start();
  b.finishOpening();
  await Promise.all([first, second]);
  assert.equal(b.isOpen(), true);
  assert.deepEqual(b.log, ["open asked", "opened"]);
});
