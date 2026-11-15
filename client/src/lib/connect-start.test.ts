// What a start with auto-connect opens: the servers that were open, none after the last was
// closed. A Disconnect and then F5 took the person back in as a guest with their account's
// name, through the last server the dialog used (pseudonym review, 1.7).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

await import("./stores/node-stores.mjs");
const { autoConnectList } = await import("./connect.ts");

const server = { name: "h", host: "h.example", port: 9987, username: "ann", accept_self_signed: false };

test("auto-connect opens what was open, and nothing once it was all closed", () => {
  assert.deepEqual(autoConnectList({ auto_connect: true, open_servers: [server] }), [server]);
  assert.deepEqual(autoConnectList({ auto_connect: true, open_servers: [] }), [], "closed by hand: stays closed");
  assert.deepEqual(autoConnectList({ auto_connect: true, open_servers: null }), []);
  assert.deepEqual(autoConnectList({ auto_connect: false, open_servers: [server] }), [], "off is off");
  // The start goes through it, with no other way back to the last server
  const app = readFileSync(new URL("../App.svelte", import.meta.url), "utf8");
  assert.match(app, /withReloadServers\(autoConnectList\(config\)\)/);
  assert.doesNotMatch(app, /name: config\.last_host/);
});
