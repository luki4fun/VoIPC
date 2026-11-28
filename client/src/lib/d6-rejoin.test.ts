// Dive 6, F6: after a relay restart the reconnect put the user back into whichever voice room
// now carried the old room's name, password room or not, made by anybody: rooms people make
// live in the relay's memory only, so a restart frees their names. Driven through connect.ts's
// own loop, as App.svelte's `connection-lost` handler starts it; the rule is rejoin-rules.ts
// `rejoinsVoice` (its own tests are in rejoin-rules.test.ts).

import { mock, test } from "node:test";
import assert from "node:assert/strict";

const { invoked } = await import("./stores/node-stores.mjs");
const { channelListArrived, connectTo, noteRelayRun, resetServer, startReconnect } = await import("./connect.ts");
const { rememberChannelPassword } = await import("./stores/connection.ts");
const { notifications } = await import("./stores/notifications.ts");
const { roomAtDrop } = await import("./rejoin-rules.ts");
const { get } = await import("svelte/store");

const RUN = "0a".repeat(16);
const NEW_RUN = "0b".repeat(16);

const room = (over: Record<string, unknown>) => ({
  channel_id: 0, name: "General", description: "", max_users: 0, user_count: 0, has_password: false,
  created_by: null, proximity: "off", hidden: false, anonymous: false, screen_share: true, hide_members: false,
  routed: false, text: false, ...over,
}) as any;

/** vic's room: made by vic (user 3), with a password. */
const teamRoom = room({ channel_id: 7, name: "team-room", has_password: true, created_by: 3 });

/**
 * vic stood in `teamRoom` on a relay of run `RUN` when the link dropped; the reconnect's
 * connection says run `runNow` (none: a relay below 26) and pushes `list`. The joins it asked.
 */
async function reconnect(host: string, runNow: string | null, list: any[]): Promise<any[]> {
  (globalThis as any).__answer = (command: string, args: any) => {
    // GroupKeys comes in while the connection signs in, before `connect` answers
    if (command === "connect" && runNow !== null) noteRelayRun(args.address, runNow);
    return command === "connect" ? 7 : undefined;
  };
  const opened = await connectTo({ host, port: 9987, username: "vic#0001", acceptSelfSigned: false });
  assert.ok(opened.ok, JSON.stringify(opened));
  const server = opened.ok ? opened.server : "";
  rememberChannelPassword(server, "team-room", "team-secret");
  noteRelayRun(server, RUN);
  const before = invoked().length;

  mock.timers.enable({ apis: ["setTimeout", "Date"] });
  mock.method(Math, "random", () => 0);
  try {
    // What App.svelte's handler hands over, read before the stores go
    const prevVoice = roomAtDrop(teamRoom, RUN);
    resetServer(server);
    void startReconnect(server, { voice: prevVoice, text: [] }, "lost");
    // The first try comes after 0.5 s; connect answers at once
    mock.timers.tick(600);
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    channelListArrived(server, list);
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    return invoked()
      .slice(before)
      .filter(([command]: [string]) => command === "join_channel")
      .map(([, args]: [string, any]) => args);
  } finally {
    mock.timers.reset();
    mock.restoreAll();
  }
}

test("a restart: the room of the old name that somebody else made is not walked into", async () => {
  // mallory's, open, made first after the restart
  const joins = await reconnect("f6-restart.example", NEW_RUN, [room({}), room({ channel_id: 3, name: "team-room", created_by: 1 })]);
  assert.deepEqual(joins, [], "the reconnect joined the room somebody else made under the old name");
  assert.ok(
    get(notifications).some((n: any) => n.message.includes("Not back in team-room")),
    "and the user is told why the call did not come back",
  );
});

test("a restart: not even at the old id, with a password, under the old maker's number", async () => {
  // A restart hands ids out from the start again, so a script can line all three up
  const joins = await reconnect("f6-forged.example", NEW_RUN, [room({}), teamRoom]);
  assert.deepEqual(joins, []);
});

test("the control: a Wi-Fi roam finds the very room, and goes back in with its password", async () => {
  const joins = await reconnect("f6-roam.example", RUN, [room({}), teamRoom]);
  assert.deepEqual(joins, [{ server: "f6-roam.example:9987", channelId: 7, password: "team-secret" }]);
});

test("a run from before the drop does not pass for the new connection's", async () => {
  // The relay the reconnect reached said no run (below protocol 26): nothing proves it is
  // the run the call dropped on
  const joins = await reconnect("f6-norun.example", null, [room({}), teamRoom]);
  assert.deepEqual(joins, []);
});
