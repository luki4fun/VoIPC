// The lobby on a big relay (protocol 25): pages ask once at a time and stop at the end, a
// search starts over, counts are the relay's, and a decision that needs someone waits for
// one lookup, not more. The backend is a stand-in that writes down what it was asked.
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const { afterLookup, lobby, LOBBY_RETRY_MS, lobbyPage, lookedUp, lookUpNames, moreLobby, resetLobby, searchLobby, searchNames, watchLobby } =
  await import("./lobby.ts");
const { channelRosters, onlineById, setCounts } = await import("./rosters.ts");
const { channels } = await import("./channels.ts");
const { olderRelay } = await import("./relay.ts");
import type { ChannelInfo, UserInfo } from "../types.ts";

let serial = 0;
function server(): string {
  return `lobby${++serial}.example:9987`;
}
const person = (user_id: number, username = `u${user_id}#0001`): UserInfo =>
  ({ user_id, username, channel_id: 0, is_muted: false, is_deafened: false, is_screen_sharing: false, is_admin: false, shares_history: false }) as UserInfo;
const asked = (name: string): any[] =>
  invoked().filter(([command]: [string]) => command === name).map(([, args]: [string, any]) => args);

test.beforeEach(() => {
  invoked().length = 0;
  mock.timers.enable({ apis: ["setTimeout", "Date"], now: 1_000_000_000_000 });
});
test.afterEach(() => mock.timers.reset());

test("pages are asked one at a time, on from where the last ended, and not past the end", () => {
  const s = server();
  moreLobby(s);
  moreLobby(s);
  assert.deepEqual(asked("request_lobby_page"), [{ server: s, after: null, prefix: "" }], "one on its way");
  const next = { section: 65535, name: "u2#0001", user_id: 2 };
  lobbyPage(s, { rows: [person(1), person(2)], next, total: 3, sections: [[65535, 3]] });
  assert.deepEqual([...get(channelRosters.peek(s)).get(0)!.map((u) => u.user_id)], [1, 2]);
  moreLobby(s);
  assert.deepEqual(asked("request_lobby_page")[1].after, next);
  lobbyPage(s, { rows: [person(3)], next: null, total: 3, sections: [[65535, 3]] });
  moreLobby(s);
  assert.equal(asked("request_lobby_page").length, 2, "the end");
  assert.ok(onlineById(s).has(3), "a page's people are who this client knows to be online");
});

test("a page refused while the link is down is asked again after a pause, not in a loop that starves the page", async () => {
  const s = server();
  (globalThis as any).__answer = (command: string) => {
    if (command === "request_lobby_page") throw new Error("not connected");
  };
  // The member list's first-page effect: ask whenever nothing is on its way
  const stop = lobby.of(s).subscribe((l) => {
    if (!l.asked && !l.done && l.next === null && l.total === 0) moreLobby(s);
  });
  try {
    for (let i = 0; i < 50; i++) await Promise.resolve();
    assert.equal(asked("request_lobby_page").length, 1, "one ask, then a pause");
    mock.timers.tick(LOBBY_RETRY_MS);
    for (let i = 0; i < 50; i++) await Promise.resolve();
    assert.equal(asked("request_lobby_page").length, 2, "asked again after the pause");
    // A fresh start (the lobby's rows went) asks at once; the old refusal's pause frees nothing
    delete (globalThis as any).__answer;
    searchLobby(s, "");
    assert.equal(asked("request_lobby_page").length, 3);
    mock.timers.tick(LOBBY_RETRY_MS);
    moreLobby(s);
    assert.equal(asked("request_lobby_page").length, 3, "the fresh ask is still on its way");
  } finally {
    stop();
    delete (globalThis as any).__answer;
  }
});

test("a lobby list on screen is watched by each new session: a page that loads signed in, a reconnect", async () => {
  const s = server();
  const watches = () => asked("watch_lobby").filter((a) => a.server === s);
  // The list shows before the session is up (a reload of a remembered account): refused
  let up = false;
  (globalThis as any).__answer = (command: string) => {
    if (command === "watch_lobby" && !up) throw new Error("not connected");
  };
  try {
    watchLobby(s, true);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.equal(watches().length, 1, "refused, and not asked again at once");
    mock.timers.tick(LOBBY_RETRY_MS);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.equal(watches().length, 2, "asked again after the pause");
    up = true;
    mock.timers.tick(LOBBY_RETRY_MS);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.equal(watches().length, 3, "and taken");
    mock.timers.tick(LOBBY_RETRY_MS * 3);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.equal(watches().length, 3, "once taken, not again");
    // A reconnect: the relay forgot the old session's watch; the new one's lobby list (App.svelte
    // `resetLobby`) is its first word, and it is watched from there, a turn later (the list comes
    // in the read that signed the session in, before the backend lists it)
    resetLobby(s);
    assert.equal(watches().length, 3, "not in the same turn");
    mock.timers.tick(0);
    assert.deepEqual(watches().at(-1), { server: s, on: true });
    assert.equal(watches().length, 4);
    // A page that loads signed in: refused at the list's first showing, then the session's list
    // asks a turn later, not a whole pause later, and the pause's ask does not come on top
    up = false;
    watchLobby(s, true);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    up = true;
    resetLobby(s);
    mock.timers.tick(0);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.equal(watches().length, 6, "refused, then taken a turn after the session's list");
    mock.timers.tick(LOBBY_RETRY_MS * 3);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.equal(watches().length, 6);
    // Off screen: a new session is not asked to watch, and a refused "off" is not asked again
    up = false;
    watchLobby(s, false);
    resetLobby(s);
    mock.timers.tick(LOBBY_RETRY_MS * 3);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    assert.deepEqual(watches().slice(6), [{ server: s, on: false }]);
  } finally {
    delete (globalThis as any).__answer;
  }
});

test("a search starts over with its prefix", () => {
  const s = server();
  lobbyPage(s, { rows: [person(1)], next: null, total: 1, sections: [] });
  searchLobby(s, " An ");
  assert.deepEqual(asked("request_lobby_page").at(-1), { server: s, after: null, prefix: "An" });
  assert.equal(get(lobby.peek(s)).done, false);
});

test("counts are the relay's, the lobby's too", () => {
  const s = server();
  channels.of(s).set([{ channel_id: 0, user_count: 1 } as ChannelInfo, { channel_id: 4, user_count: 2 } as ChannelInfo]);
  setCounts(s, [[0, 100_000]]);
  assert.deepEqual(get(channels.peek(s)).map((c) => c.user_count), [100_000, 2]);
});

test("a decision waits for one lookup of whom it does not know, and goes on at its answer", () => {
  const s = server();
  let ran = 0;
  afterLookup(s, [9], () => ran++);
  assert.equal(ran, 0);
  assert.deepEqual(asked("lookup_users"), [{ server: s, ids: [9], names: [], accounts: [] }]);
  lookedUp(s, [person(9)], []);
  assert.equal(ran, 1);
  // Known now: at once, no ask
  afterLookup(s, [9], () => ran++);
  assert.equal(ran, 2);
  assert.equal(asked("lookup_users").length, 1);
  // No answer: it goes on after three seconds all the same
  afterLookup(s, [10], () => ran++);
  mock.timers.tick(3000);
  assert.equal(ran, 3);
});

test("a relay before 25 holds the lobby whole: nothing is looked up or paged", () => {
  const s = server();
  olderRelay.of(s).set({ protocol: 24, version: "1.13.0" });
  let ran = 0;
  afterLookup(s, [9], () => ran++);
  moreLobby(s);
  lookUpNames(s, ["ann"]);
  assert.equal(ran, 1);
  assert.equal(invoked().length, 0);
});

test("names are looked up unless known or asked in the last minute", () => {
  const s = server();
  lobbyPage(s, { rows: [person(1, "ann")], next: null, total: 1, sections: [] });
  lookUpNames(s, ["ann", "bob", "bob"]);
  assert.deepEqual(asked("lookup_users"), [{ server: s, ids: [], names: ["bob"], accounts: [] }]);
  lookUpNames(s, ["bob"]);
  assert.equal(asked("lookup_users").length, 1, "asked a moment ago");
  mock.timers.tick(61_000);
  lookUpNames(s, ["bob"]);
  assert.equal(asked("lookup_users").length, 2);
});

test("a search for a name being typed adds its rows and leaves the list's place", () => {
  const s = server();
  const next = { section: 65535, name: "u1#0001", user_id: 1 };
  lobbyPage(s, { rows: [person(1)], next, total: 50, sections: [], prefix: "" });
  searchNames(s, "zo");
  searchNames(s, "zo");
  assert.deepEqual(
    asked("request_lobby_page").filter((a) => a.prefix === "zo"),
    [{ server: s, after: null, prefix: "zo" }],
    "once in half a minute",
  );
  lobbyPage(s, { rows: [person(7, "zoe#0001")], next: null, total: 1, sections: [], prefix: "zo" });
  assert.ok(onlineById(s).has(7));
  assert.deepEqual(get(lobby.peek(s)).next, next, "the list goes on from where it was");
  assert.equal(get(lobby.peek(s)).total, 50);
});
