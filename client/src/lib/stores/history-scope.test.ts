// Whose history a server shows (1.12): a guest's, one per server whatever name it joins with,
// or an account's own. History from before 1.12 goes to the account this device remembers there
// if that is who signs in first, and stays a guest's otherwise.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

await import("./node-stores.mjs");
const {
  adoptGuestHistory,
  channelMessages,
  chatKey,
  chatUnlocked,
  clearedBefore,
  clearServerUnread,
  decideLegacyHistory,
  dmKey,
  dmMessages,
  unreadPerChannel,
} = await import("./chat.ts");
const { forgetHistoryScopes, historyKey, historyScope, inScope, onServer, setHistoryScope } = await import(
  "./history-scope.ts"
);
const { splitChatKey } = await import("../chat-rules.ts");
const { uiPrefs, updateUiPrefs } = await import("./ui-prefs.ts");

const S = "h.example:9987";
const ANN = "a1".repeat(16);
const BOB = "b2".repeat(16);
const msg = (content: string, timestamp: number) => ({ user_id: 5, username: "x", content, timestamp, id: `m${timestamp}` });

function fresh() {
  forgetHistoryScopes();
  channelMessages.set(new Map());
  dmMessages.set(new Map());
  clearedBefore.set(new Map());
  unreadPerChannel.set(new Map());
  updateUiPrefs((p) => {
    p.history_split = [];
    p.read_marks = {};
    p.readers_named = {};
  });
}

test("a guest's history is the server's whatever its name, an account's is its own", () => {
  fresh();
  assert.equal(chatKey(S, "general"), `${S}/general`);
  assert.equal(dmKey(S, "bob#0001"), `${S}/bob#0001`);
  setHistoryScope(S, ANN);
  assert.equal(historyScope(S), ANN);
  assert.equal(chatKey(S, "general"), `${S}~${ANN}/general`);
  setHistoryScope(S, BOB);
  assert.equal(chatKey(S, "general"), `${S}~${BOB}/general`, "another account, another history");
  setHistoryScope(S, null);
  assert.equal(chatKey(S, "general"), `${S}/general`, "a guest again sees the guests' history");
  // Nothing that is not an account id names a scope
  setHistoryScope(S, "../../etc");
  assert.equal(historyKey(S), S);
});

test("a key says whose history it is, and only the one shown is searched", () => {
  fresh();
  assert.deepEqual(splitChatKey(`${S}~${ANN}/team/ops`), { server: S, name: "team/ops", scope: ANN });
  assert.deepEqual(splitChatKey(`${S}/general`), { server: S, name: "general", scope: "" });
  assert.equal(splitChatKey(`${S}~nothex/x`), null);
  setHistoryScope(S, ANN);
  assert.ok(inScope(S, ANN) && !inScope(S, "") && !inScope(S, BOB));
  assert.ok(onServer(`${S}/a`, S) && onServer(`${S}~${BOB}/a`, S) && !onServer(`h.example:99870/a`, S));
});

test("closing a server drops what its connection counted, whoever's history it was", () => {
  fresh();
  unreadPerChannel.set(
    new Map([
      [`${S}/general`, 2],
      [`${S}~${ANN}/general`, 3],
      ["o.example:1/general", 4],
    ]),
  );
  clearServerUnread(S);
  assert.deepEqual([...get(unreadPerChannel).keys()], ["o.example:1/general"]);
});

test("the guest history goes to an account whole, joined with what it has", () => {
  fresh();
  channelMessages.set(
    new Map([
      [`${S}/general`, [msg("old", 1), msg("both", 2)]],
      [`${S}~${ANN}/general`, [msg("both", 2), msg("new", 3)]],
      ["o.example:1/general", [msg("elsewhere", 1)]],
    ]),
  );
  dmMessages.set(new Map([[`${S}/bob`, [msg("hi", 1)]]]));
  clearedBefore.set(new Map([[`${S}/general`, 5], [`${S}~${ANN}/general`, 3]]));
  updateUiPrefs((p) => {
    p.read_marks = { [S]: { general: 9 } };
    p.readers_named = { [S]: { general: ["x"] }, [`${S}~${ANN}`]: { general: ["y"] } };
  });
  adoptGuestHistory(S, ANN);
  const ch = get(channelMessages);
  assert.deepEqual(
    ch.get(`${S}~${ANN}/general`)!.map((m) => m.content),
    ["old", "both", "new"],
    "each once, by time",
  );
  assert.ok(!ch.has(`${S}/general`), "nothing left as a guest's");
  assert.ok(ch.has("o.example:1/general"), "another server's stays");
  assert.ok(get(dmMessages).has(`${S}~${ANN}/bob`));
  assert.equal(get(clearedBefore).get(`${S}~${ANN}/general`), 5, "the later mark");
  const p = get(uiPrefs);
  assert.deepEqual(p.read_marks[`${S}~${ANN}`], { general: 9 });
  assert.equal(p.read_marks[S], undefined);
  assert.deepEqual(p.readers_named[`${S}~${ANN}`].general.sort(), ["x", "y"]);
});

test("history from before 1.12 goes to the remembered account once, and a guest keeps it otherwise", async () => {
  const devices = (list: { server: string; name: string }[]) => {
    (globalThis as { __answer?: (c: string) => unknown }).__answer = (c: string) => (c === "account_devices" ? list : undefined);
  };
  const legacy = () => channelMessages.set(new Map([[`${S}/general`, [msg("before", 1)]]]));
  chatUnlocked.set(true);

  // The remembered account signs in first: it takes it
  fresh();
  legacy();
  devices([{ server: S, name: "ann" }]);
  await decideLegacyHistory(S, { name: "ann", hex: ANN });
  assert.ok(get(channelMessages).has(`${S}~${ANN}/general`));
  assert.ok(get(uiPrefs).history_split.includes(S));
  // Once: a guest's later history stays a guest's
  channelMessages.update((m) => new Map(m).set(`${S}/general`, [msg("guest", 9)]));
  await decideLegacyHistory(S, { name: "ann", hex: ANN });
  assert.ok(get(channelMessages).has(`${S}/general`));

  // Another account signs in first: it stays the guests'
  fresh();
  legacy();
  devices([{ server: S, name: "ann" }]);
  await decideLegacyHistory(S, { name: "bob", hex: BOB });
  assert.ok(get(channelMessages).has(`${S}/general`) && !get(channelMessages).has(`${S}~${BOB}/general`));
  assert.ok(get(uiPrefs).history_split.includes(S));

  // A guest first, or two remembered accounts: the guests'
  for (const [who, list] of [
    [null, [{ server: S, name: "ann" }]],
    [{ name: "ann", hex: ANN }, [{ server: S, name: "ann" }, { server: S, name: "bob" }]],
  ] as const) {
    fresh();
    legacy();
    devices([...list]);
    await decideLegacyHistory(S, who);
    assert.ok(get(channelMessages).has(`${S}/general`), JSON.stringify(who));
  }

  // The archive shut: nothing decided yet
  fresh();
  chatUnlocked.set(false);
  await decideLegacyHistory(S, { name: "ann", hex: ANN });
  assert.ok(!get(uiPrefs).history_split.includes(S));
  chatUnlocked.set(true);
});
