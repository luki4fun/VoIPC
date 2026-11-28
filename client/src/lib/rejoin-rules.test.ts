// What a reconnect may put the user back into.
//
// The case that matters is the silent one: nobody clicked anything, the network
// came back, and the client is deciding on its own where this person now is.

import { test } from "node:test";
import assert from "node:assert/strict";
import { connectionLostLine, reconnectDelay, rejoinsVoice, resolveRejoin, roomAtDrop } from "./rejoin-rules.ts";
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

test("a dropped connection is said once, however the transport words it", () => {
  assert.equal(connectionLostLine("Connection lost: connection lost"), "Connection lost");
  assert.equal(connectionLostLine("connection lost"), "Connection lost");
  assert.equal(connectionLostLine("connection lost: timed out"), "Connection lost: timed out");
  assert.equal(connectionLostLine("Server closed connection"), "Connection lost: Server closed connection");
  assert.equal(connectionLostLine("Connection lost (code 1006)"), "Connection lost (code 1006)");
});

test("a big relay's drop spreads the first try over a millisecond each, at most a minute", () => {
  assert.equal(reconnectDelay(1, () => 0, 100_000), 500, "the earliest is unchanged");
  assert.equal(reconnectDelay(1, () => 1, 100_000), 1500 + 60_000);
  assert.equal(reconnectDelay(1, () => 1, 2000), 1500 + 2000);
  assert.equal(reconnectDelay(2, () => 1, 100_000), 3000, "only the first");
});

// Dive 6 F6. Rooms people make live in the relay's memory only, so a restart ends them all
// and frees their names: anyone on that relay could make "team-room" again before the
// reconnect came round, and the app walked the user into it with a live microphone, a
// password room replaced by an open one included. The rule: a reconnect puts the user back
// into voice by itself only in the very room (the same run of the relay, the same id), or in
// one of the relay's own rooms both times; and never into a room without a password in place
// of one that had one, nor without the password the app knew.

const RUN = "0a".repeat(16);
const NEW_RUN = "0b".repeat(16);
const mine = channel({ channel_id: 7, name: "team-room", has_password: true, created_by: 3 });

test("after a restart, a room of the old name that somebody else made is not the room", () => {
  const was = roomAtDrop(mine, RUN);
  // mallory's, open, made first after the restart
  const open = channel({ channel_id: 3, name: "team-room", created_by: 1 });
  assert.equal(rejoinsVoice(was, open, NEW_RUN, true), false, "an open one in place of a password one");
  // ...with a password, at the old id and with the old maker's number: a restart hands
  // both out again from the start, so neither says anything
  const forged = channel({ channel_id: 7, name: "team-room", has_password: true, created_by: 3 });
  assert.equal(rejoinsVoice(was, forged, NEW_RUN, true), false, "another run is another room");
  // ...anonymous, which hides its maker from everybody else: it looks like one of the relay's
  const masked = channel({ channel_id: 3, name: "team-room", has_password: true, anonymous: true });
  assert.equal(rejoinsVoice(was, masked, NEW_RUN, true), false, "a hidden maker is still a maker");
});

test("the very room comes back: the same run, the same id", () => {
  const was = roomAtDrop(mine, RUN);
  // A Wi-Fi roam: the relay kept the room (it outlives an empty spell by 5 minutes)
  assert.equal(rejoinsVoice(was, mine, RUN, true), true);
  // Gone and made again on the same run: a new id, so another room
  assert.equal(rejoinsVoice(was, { ...mine, channel_id: 9 }, RUN, true), false);
  // A relay below protocol 26 says no run: nothing proves it is the same one
  assert.equal(rejoinsVoice(roomAtDrop(mine, ""), mine, "", true), false);
});

test("one of the relay's own rooms comes back by name, after a restart too", () => {
  const lounge = channel({ channel_id: 2, name: "lounge" });
  const was = roomAtDrop(lounge, RUN);
  assert.equal(was.made, false);
  // channels.json reordered: another id, the same room
  assert.equal(rejoinsVoice(was, { ...lounge, channel_id: 4 }, NEW_RUN, false), true);
  assert.equal(rejoinsVoice(roomAtDrop(lounge, ""), lounge, "", false), true, "with no run said either");
  // ...but not one a person made under its name since (the relay's own went from channels.json)
  assert.equal(rejoinsVoice(was, { ...lounge, created_by: 5 }, NEW_RUN, false), false);
  assert.equal(rejoinsVoice(was, { ...lounge, anonymous: true }, NEW_RUN, false), false);
  // An anonymous room the user stood in may have been a person's: not taken by name
  const veiled = channel({ channel_id: 2, name: "lounge", anonymous: true });
  assert.equal(rejoinsVoice(roomAtDrop(veiled, RUN), veiled, NEW_RUN, false), false);
  assert.equal(rejoinsVoice(roomAtDrop(veiled, RUN), veiled, RUN, false), true, "the very room still is");
});

test("never a room without a password in place of one that had one, nor without the password known", () => {
  const locked = channel({ channel_id: 2, name: "board", has_password: true });
  const was = roomAtDrop(locked, RUN);
  assert.equal(rejoinsVoice(was, { ...locked, has_password: false }, RUN, true), false, "the very room, its password gone");
  assert.equal(rejoinsVoice(was, { ...locked, has_password: false }, NEW_RUN, true), false, "the relay's own, its password gone");
  assert.equal(rejoinsVoice(was, locked, RUN, false), false, "no password known: the join could only fail");
  assert.equal(rejoinsVoice(was, locked, NEW_RUN, true), true);
  // A text channel or another name is never it
  assert.equal(rejoinsVoice(was, { ...locked, text: true }, RUN, true), false);
  assert.equal(rejoinsVoice(was, { ...locked, name: "Board" }, RUN, true), false);
});
