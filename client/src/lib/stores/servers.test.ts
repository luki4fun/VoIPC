// The rail's list and the server id every command is keyed by.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEntries, serverId, serverKey, serverName } from "./servers.ts";

const saved = [
  { name: "Home", host: "home.example", port: 9987, username: "me", accept_self_signed: false },
  { name: "", host: "Other.example", port: 9000, username: "me", accept_self_signed: true },
];

test("serverId: one server, one id, however it was typed", () => {
  assert.equal(serverId("Example.ORG", 9987), "example.org:9987");
  assert.equal(serverId("  example.org ", 9987), "example.org:9987");
  assert.equal(serverId("::1", 9987), "[::1]:9987");
  assert.equal(serverId("[::1]", 9987), "[::1]:9987", "brackets typed in are not doubled");
  assert.equal(serverId("FE80::1", 443), "[fe80::1]:443");
  assert.equal(serverId("10.0.0.1", 1), "10.0.0.1:1");
});

test("serverKey drops the brackets, so history filed before ids existed still matches", () => {
  assert.equal(serverKey("[::1]:9987"), "::1:9987");
  assert.equal(serverKey("example.org:9987"), "example.org:9987");
  assert.equal(serverKey(""), "");
});

test("serverName prefers the bookmark, else the host", () => {
  assert.equal(serverName("home.example:9987", saved), "Home");
  assert.equal(serverName("other.example:9000", saved), "Other.example", "empty bookmark name");
  assert.equal(serverName("[::1]:9987", saved), "::1");
});

test("open servers come first, in the order opened, then bookmarks not open", () => {
  const entries = buildEntries(
    ["b.example:1", "home.example:9987"],
    new Map([
      ["b.example:1", "connected"],
      ["home.example:9987", "reconnecting"],
    ]),
    saved,
    new Map(),
    "home.example:9987",
    "b.example:1",
  );
  assert.deepEqual(
    entries.map((e) => [e.id, e.state, e.open, e.active, e.inVoice]),
    [
      ["b.example:1", "connected", true, false, true],
      ["home.example:9987", "reconnecting", true, true, false],
      ["other.example:9000", "disconnected", false, false, false],
    ],
  );
  assert.equal(entries[1].name, "Home", "an open server keeps its bookmark's name");
});

test("unread is counted per server, channels and conversations together", () => {
  const entries = buildEntries(
    ["a.example:1", "[::1]:2"],
    new Map(),
    [],
    new Map([
      ["a.example:1/general", 2],
      ["a.example:1/random", 1],
      ["a.example:10/general", 50],
      ["::1:2/general", 4],
    ]),
    "",
    null,
    new Map([["a.example:1", [{ user_id: 3, username: "c", unread: 5 }]]]),
  );
  assert.deepEqual(
    entries.map((e) => e.unread),
    [8, 4],
    "a:10's count is not a:1's, and the IPv6 key has no brackets",
  );
  assert.equal(entries[0].state, "disconnected", "a server without a state reads as disconnected");
});

test("parseHostPort: the one address parser (H5-09)", async () => {
  const { parseHostPort, splitAddress } = await import("../invite.ts");
  assert.deepEqual(parseHostPort("example.com"), { host: "example.com", port: 9987 });
  assert.deepEqual(parseHostPort("example.com", 443), { host: "example.com", port: 443 });
  // A port typed into the host field is the port, not part of the name
  assert.deepEqual(parseHostPort("example.com:1234", 9987), { host: "example.com", port: 1234 });
  assert.deepEqual(parseHostPort("[::1]:9000"), { host: "::1", port: 9000 });
  assert.deepEqual(parseHostPort("[::1]", 443), { host: "::1", port: 443 });
  // Ambiguous or broken: refused, never split at a guess
  assert.equal(parseHostPort("::1"), null, "a bare IPv6 address split into host ':' and port 1");
  assert.equal(parseHostPort("example.com:0"), null);
  assert.equal(parseHostPort("example.com:99999"), null);
  assert.equal(parseHostPort("example.com:12ab"), null);
  assert.equal(parseHostPort(":9987"), null);
  // Every id serverId makes comes back apart
  for (const [host, port] of [["example.org", 9987], ["::1", 1], ["10.0.0.1", 65535]] as const) {
    assert.deepEqual(splitAddress(serverId(host, port)), { host, port });
  }
});
