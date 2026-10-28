// Which update the connect dialog offers a user a server refused for an older
// protocol. Offering one that still cannot connect would restart the app for
// nothing.

import { test } from "node:test";
import assert from "node:assert/strict";
import { protocolWarning, updateFits, updateOffer, updateToast, type UpdateInfo } from "./update-rules.ts";

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

// How an update is offered (1.3.1, design input 5): one on another protocol
// locks the user out of every server that has not updated yet, so it gets no
// toast and a warning in Settings instead.

const next = (protocol: number | null, ours?: number): UpdateInfo => ({ version: "1.4.0", notes: null, protocol, our_protocol: ours });

test("an update on this app's protocol is offered plainly, with a toast", () => {
  assert.equal(updateOffer(next(13, 13)), "plain");
  assert.equal(updateToast(next(13, 13)), "VoIPC 1.4.0 is available: Settings, Updates.");
});

test("one on another protocol gets no toast, only the warning", () => {
  assert.equal(updateOffer(next(14, 13)), "protocol");
  assert.equal(updateToast(next(14, 13)), null);
});

test("a feed or a backend that does not say is taken at its word", () => {
  assert.equal(updateOffer(next(null, 13)), "plain");
  assert.equal(updateOffer(next(14)), "plain", "a backend before 1.3.1 sends no our_protocol");
  assert.equal(updateOffer(null), "none");
  assert.equal(updateToast(null), null);
});

test("the warning names the servers that would refuse the update", () => {
  assert.equal(
    protocolWarning(next(14, 13), ["ivy.l4f.cc"]),
    "VoIPC 1.4.0 speaks protocol 14. ivy.l4f.cc runs protocol 13: after updating, you cannot connect to it until it is updated too.",
  );
  assert.match(protocolWarning(next(14, 13), ["a", "b", "c"]), /a, b and c run protocol 13: .* connect to them until they are updated too\.$/);
  assert.equal(
    protocolWarning(next(14, 13), []),
    "VoIPC 1.4.0 speaks protocol 14. This VoIPC speaks 13: after updating, you can connect only to servers that run 14 too.",
  );
});
