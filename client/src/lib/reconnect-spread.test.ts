// Dive 6, F5: after a drop on a big relay the first reconnect is meant to wait its turn, up to
// a millisecond for each person who was online (rejoin-rules.ts `reconnectDelay`, 1.14). The
// loop read "how many were online" from the channel list, which the handler that starts the
// loop had dropped a line earlier (App.svelte `connection-lost`: `resetServer`, then
// `startReconnect`). The handler now reads the count first and hands it over.

import { mock, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const { invoked } = await import("./stores/node-stores.mjs");
const { connectTo, resetServer, startReconnect } = await import("./connect.ts");
const { channels } = await import("./stores/channels.ts");
const { reconnectDelay } = await import("./rejoin-rules.ts");
const { get } = await import("svelte/store");

const lobby = (online: number) => ({
  channel_id: 0, name: "General", description: "", max_users: 0, user_count: online, has_password: false,
  created_by: null, proximity: "off", hidden: false, anonymous: false, screen_share: false, hide_members: false,
  routed: false, text: false,
});

test("the first reconnect after a drop waits its turn on a relay of 60,000", async () => {
  (globalThis as any).__answer = (command: string) => (command === "connect" ? 7 : undefined);
  const opened = await connectTo({ host: "big.example", port: 9987, username: "ann#0001", acceptSelfSigned: false });
  assert.ok(opened.ok, JSON.stringify(opened));
  const server = opened.ok ? opened.server : "";
  channels.of(server).set([lobby(60_000)] as any);

  // The order the app's own handler runs them in
  const app = readFileSync(new URL("../App.svelte", import.meta.url), "utf8");
  assert.match(app, /const online = get\(channels\.peek\(server\)\)[^\n]*\n\s*resetServer\(server\);\n\s*void startReconnect\(server, \{ voice: prevVoice[^}]*online \}/);

  mock.timers.enable({ apis: ["setTimeout", "Date"] });
  mock.method(Math, "random", () => 0.5);
  try {
    // With 60,000 online and the middle of the spread, the wait is 31 s
    assert.equal(reconnectDelay(1, Math.random, 60_000), 31_000);
    const before = invoked().length;
    const online = get(channels.peek(server)).find((c: any) => c.channel_id === 0)?.user_count ?? 0;
    resetServer(server);
    void startReconnect(server, { voice: null, text: [], online }, "lost");
    mock.timers.tick(5_000);
    await new Promise((r) => setImmediate(r));
    const early = invoked().slice(before).filter(([command]: [string]) => command === "disconnect" || command === "connect");
    assert.deepEqual(early, [], "5 s after the drop the reconnect has already begun");
  } finally {
    mock.timers.reset();
    mock.restoreAll();
  }
});
