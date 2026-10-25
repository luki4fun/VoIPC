// Which update the connect dialog offers a user a server refused for an older
// protocol. Offering one that still cannot connect would restart the app for
// nothing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { updateFits, type UpdateInfo } from "./update-rules.ts";

const update = (protocol: number | null): UpdateInfo => ({ version: "1.1.0", notes: null, protocol });

test("an update that speaks the server's protocol is offered", () => {
  assert.equal(updateFits(update(12), 12), true);
});

test("one on another protocol is not: versions connect only on the same one", () => {
  assert.equal(updateFits(update(11), 12), false);
  assert.equal(updateFits(update(13), 12), false);
});

test("a feed that does not say is taken at its word", () => {
  assert.equal(updateFits(update(null), 12), true);
});

test("no update, nothing to offer", () => {
  assert.equal(updateFits(null, 12), false);
});
