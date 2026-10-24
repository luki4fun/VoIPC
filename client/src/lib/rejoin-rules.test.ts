// What a reconnect may put the user back into.
//
// The case that matters is the silent one: nobody clicked anything, the network
// came back, and the client is deciding on its own where this person now is.

import { test } from "node:test";
import assert from "node:assert/strict";
import { reconnectDelay, resolveRejoin } from "./rejoin-rules.ts";
import type { ChannelInfo } from "./types.ts";

function channel(over: Partial<ChannelInfo> & { channel_id: number; name: string }): ChannelInfo {
  return {
    description: "",
    max_users: 0,
    user_count: 0,
    has_password: false,
    created_by: null,
    proximity: "off",
    hidden: false,
    anonymous: false,
    screen_share: true,
    hide_members: false,
    routed: false,
    text: false,
    auto_join: false,
    ...over,
  };
}

test("a remembered text channel never resolves to a voice channel of the same name", () => {
  // The server was restarted with #general as a voice room. Rejoining it as a
  // text channel would move the user into it: announced to everyone there,
  // handed its media key, and whatever they were sharing torn down — all
  // because their Wi-Fi came back.
  const list = [channel({ channel_id: 1, name: "general" })];
  assert.deepEqual(resolveRejoin(["general"], list, "text"), []);
  // ...and the mirror of it: the room you were standing in is not somewhere to
  // be subscribed to if it is now a text channel.
  const nowText = [channel({ channel_id: 1, name: "general", text: true })];
  assert.deepEqual(resolveRejoin(["general"], nowText, "voice"), []);
});

test("reassigned ids do not matter, because nothing is remembered by id", () => {
  const before = [
    channel({ channel_id: 3, name: "general", text: true }),
    channel({ channel_id: 4, name: "music", text: true }),
  ];
  // Same server, restarted with the two channels the other way round
  const after = [
    channel({ channel_id: 3, name: "music", text: true }),
    channel({ channel_id: 4, name: "general", text: true }),
  ];
  const names = before.map((c) => c.name);
  assert.deepEqual(
    resolveRejoin(names, after, "text").map((c) => c.channel_id),
    [4, 3],
  );
});

test("a channel that is gone is simply not rejoined", () => {
  const list = [channel({ channel_id: 1, name: "general", text: true })];
  assert.deepEqual(
    resolveRejoin(["general", "the-one-that-was-deleted"], list, "text").map((c) => c.name),
    ["general"],
  );
  assert.deepEqual(resolveRejoin([], list, "text"), []);
});

test("reconnects spread out, within half to one and a half times the backoff", () => {
  assert.equal(reconnectDelay(1, () => 0), 500);
  assert.ok(reconnectDelay(1, () => 0.999999) < 1500);
  assert.equal(reconnectDelay(3, () => 0.5), 4000);
  assert.equal(reconnectDelay(40, () => 0.5), 10000, "capped");
  const seen = new Set(Array.from({ length: 20 }, () => Math.round(reconnectDelay(2))));
  assert.ok(seen.size > 1, "not all in step");
});
