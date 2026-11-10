// What an admin reply lists reaches a keyed each: each row once, whatever the relay sent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

await import("./node-stores.mjs");
const { adminGate, adminGroups, adminInviteLinks, adminInvites, adminMembers, banTotal, bans, onAdminBans, onAdminReply } = await import("./admin-ui.ts");
const { dropServer } = await import("./scoped.ts");

const S = "h.example:9987";
const reply = (admin: unknown) => onAdminReply(S, { Admin: admin });

test("what an admin reply lists is held each once", () => {
  dropServer(S);
  reply({
    Groups: {
      groups: [
        { name: "crew", scopes: ["a", "a", "b"] },
        { name: "mods", scopes: [] },
        { name: "crew", scopes: ["a", "a", "c"] },
      ],
    },
  });
  const groups = get(adminGroups.peek(S)) as { name: string; scopes: string[] }[];
  assert.deepEqual(groups.map((g) => g.name), ["crew", "mods"]);
  assert.deepEqual(groups[0].scopes, ["a", "c"]);

  reply({ Members: { name: "crew", offset: 0, total: 9, users: [{ name: "ann" }, { name: "bob" }, { name: "ann" }] } });
  const members = get(adminMembers.peek(S)) as unknown as { total: number; users: { name: string }[] };
  assert.deepEqual(members.users.map((u) => u.name), ["ann", "bob"]);
  assert.equal(members.total, 9, "the page count stays the relay's");

  reply({ Invites: { invites: [{ id: 1 }, { id: 2 }, { id: 1 }] } });
  assert.deepEqual((get(adminInvites.peek(S)) as unknown as { id: number }[]).map((i) => i.id), [1, 2]);

  reply({ InviteLinks: { links: [{ id: 7 }, { id: 7 }, { id: 8 }] } });
  assert.deepEqual((get(adminInviteLinks.peek(S)) as unknown as { id: number }[]).map((l) => l.id), [7, 8]);

  reply({ Gate: { channel_id: 4, gate: { groups: [] }, groups: ["crew", "crew", "mods"] } });
  assert.deepEqual((get(adminGate.peek(S)) as unknown as { groups: string[] }).groups, ["crew", "mods"]);
});

test("a whole ban list is held each once, and counted so", () => {
  dropServer(S);
  onAdminBans(S, { bans: [{ id: 1 }, { id: 2 }, { id: 1 }] as never });
  assert.deepEqual(get(bans.peek(S)).map((b) => b.id), [1, 2]);
  assert.equal(get(banTotal.peek(S)), 2);
});

test("distinct rows all stay", () => {
  dropServer(S);
  reply({
    Groups: {
      groups: [
        { name: "crew", scopes: ["a", "b"] },
        { name: "mods", scopes: ["c"] },
      ],
    },
  });
  const groups = get(adminGroups.peek(S)) as { name: string; scopes: string[] }[];
  assert.deepEqual(groups.map((g) => [g.name, g.scopes]), [
    ["crew", ["a", "b"]],
    ["mods", ["c"]],
  ]);
  reply({ Gate: { channel_id: 4, gate: { groups: [] }, groups: ["crew", "mods"] } });
  assert.deepEqual((get(adminGate.peek(S)) as unknown as { groups: string[] }).groups, ["crew", "mods"]);
});
