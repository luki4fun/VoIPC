// The join at connect, rosters, the sweep, hand-offs on screen, rings and naming: what the
// live path's stores do, with the backend as a stand-in that writes down what it was asked.
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const { autoJoinTextChannels, forgetAutoJoinAsk, hasNsfwConsent, giveNsfwConsent, isLeft, markKicked } = await import("./channel-ui.ts");
const { channels } = await import("./channels.ts");
const { activeTextChannelId, authorsHere, peerName, joinedTextChannelIds, addChannelMessage, channelMessages, chatKey, dmMessages, noteChannelUnseen, noteNeverOpened, clearChannelUnread, unseenChannels } = await import("./chat.ts");
const { channelRosters, exchangedKey, goneFrom, noteJoin, noteLeft, onlineById, patchRosters, requestAllRosters, setRoster, textSeats } = await import("./rosters.ts");
const { clearSweeps, joinedMade, noteMade, noteMemberGone, onSweepPage, refreshList, setSweepQuiet, startSweeps, sweepForAsker } = await import("./sweep.ts");
const { askSharers, channelOpened, forgetHandOff, handOffAnswered, handOffs, reopenAfterDrop, sharersOf } = await import("./handoff.ts");
const { channelRings, clearRing, flushMarks, forgetRings, lightRing, moveRead, noteLastPost, ringBack, ringForPost } = await import("./marks.ts");
const { networkKnown } = await import("./emotes.ts");
const { openPokeDialog, sendPoke } = await import("./user-menu.ts");
const { askProfile, askProfiles, clearProfiles } = await import("./profiles.ts");
const { clearNoticing, gateNoted, noteReaders, relayWentBack } = await import("./noticing.ts");
const { applyQuiet, clearQuiet, networkChanged, quietChannels, setQuietMode, setWholeHere } = await import("./quiet.ts");
const { uiPrefs } = await import("./ui-prefs.ts");
const { olderRelay } = await import("./relay.ts");
const { serverAddress, userId } = await import("./connection.ts");
const { users } = await import("./users.ts");
const { defaultUiPrefs } = await import("../ui-prefs.ts");
import type { ChannelInfo, UserInfo } from "../types.ts";

let serial = 0;
/** Each test on its own server, as its stores are scoped. */
function server(): string {
  return `s${++serial}.example:9987`;
}

const ch = (id: number, over: Partial<ChannelInfo> = {}): ChannelInfo =>
  ({
    channel_id: id,
    name: `c${id}`,
    log: "",
    text: true,
    auto_join: true,
    has_password: false,
    nsfw: false,
    user_count: 0,
    hidden: false,
    anonymous: false,
    hide_members: false,
    ...over,
  }) as ChannelInfo;
const voice = (id: number, over: Partial<ChannelInfo> = {}) => ch(id, { text: false, auto_join: false, ...over });
const person = (user_id: number, over: Partial<UserInfo> = {}): UserInfo =>
  ({
    user_id,
    username: `u${user_id}#0001`,
    channel_id: 0,
    is_muted: false,
    is_deafened: false,
    is_screen_sharing: false,
    is_admin: false,
    shares_history: false,
    ...over,
  }) as UserInfo;

function asked(name: string): any[] {
  return invoked().filter(([command]: [string]) => command === name).map(([, args]: [string, any]) => args);
}

test.beforeEach(() => {
  invoked().length = 0;
  uiPrefs.set(defaultUiPrefs());
  (globalThis as any).__answer = undefined;
  mock.timers.enable({ apis: ["setTimeout", "Date"], now: 1_000_000_000_000 });
});
test.afterEach(() => mock.timers.reset());

// ── The join ───────────────────────────────────────────────────────────────

test("three hundred channels are one frame, sorted, and nothing again on the next pass", async () => {
  const s = server();
  const list = Array.from({ length: 300 }, (_, i) => ch(300 - i));
  autoJoinTextChannels(s, list);
  autoJoinTextChannels(s, list);
  const frames = asked("join_text_channels");
  assert.equal(frames.length, 1);
  assert.equal(frames[0].channels.length, 300);
  assert.deepEqual(frames[0].channels.slice(0, 2), [1, 2]);
  assert.deepEqual(frames[0].quiet, []);
  assert.equal(asked("join_channel").length, 0);
});

test("a channel made later is asked for alone, and a relay before the live path joins one by one", async () => {
  const s = server();
  autoJoinTextChannels(s, [ch(1)]);
  autoJoinTextChannels(s, [ch(1), ch(2)]);
  assert.deepEqual(asked("join_text_channels").map((f) => f.channels), [[1], [2]]);
  invoked().length = 0;
  const old = server();
  olderRelay.of(old).set({ protocol: 20, version: "1.11.0-rc.1" });
  autoJoinTextChannels(old, [ch(1), ch(2)]);
  assert.equal(asked("join_text_channels").length, 0);
  assert.deepEqual(asked("join_channel").map((a) => a.channelId), [1, 2]);
});

test("a join that did not go out is asked again on the next pass", async () => {
  const s = server();
  (globalThis as any).__answer = () => {
    throw new Error("Not connected");
  };
  const failing = globalThis.console.error;
  globalThis.console.error = () => {};
  autoJoinTextChannels(s, [ch(1)]);
  await Promise.resolve().then(() => {}).then(() => {});
  (globalThis as any).__answer = undefined;
  autoJoinTextChannels(s, [ch(1)]);
  globalThis.console.error = failing;
  assert.equal(asked("join_text_channels").length, 2);
});

test("a kick stays out across connections, an eviction does not, and a gone id comes back", () => {
  const s = server();
  uiPrefs.set(defaultUiPrefs());
  channels.of(s).set([ch(1), ch(2)]);
  autoJoinTextChannels(s, [ch(1), ch(2)]);
  markKicked(s, 1);
  assert.equal(isLeft(s, ch(1)), true);
  // A lost gate deletes the channel from what they see, and regaining it lists it again
  forgetAutoJoinAsk(s, 2);
  invoked().length = 0;
  autoJoinTextChannels(s, [ch(1), ch(2)]);
  assert.deepEqual(asked("join_text_channels").map((f) => f.channels), [[2]]);
});

test("a person's yes to 18+ asks at once, with no change of the list", () => {
  const s = server();
  channels.of(s).set([ch(1, { nsfw: true })]);
  autoJoinTextChannels(s, get(channels.peek(s)));
  assert.equal(asked("join_text_channels").length, 0);
  giveNsfwConsent(s);
  assert.equal(hasNsfwConsent(s), true);
  assert.deepEqual(asked("join_text_channels").map((f) => f.channels), [[1]]);
});

// ── Rosters ────────────────────────────────────────────────────────────────

test("nothing asks about three hundred text channels, and a room still is", () => {
  const s = server();
  channels.of(s).set([...Array.from({ length: 300 }, (_, i) => ch(i + 1)), voice(500)]);
  requestAllRosters(s);
  mock.timers.tick(300);
  assert.deepEqual(asked("request_channel_users").map((a) => a.channelId), [500]);
});

test("a hundred joins with names are one write and no ask; a blank one still asks", () => {
  const s = server();
  channels.of(s).set([voice(500)]);
  setRoster(s, 500, []);
  let writes = 0;
  const stop = channelRosters.of(s).subscribe(() => writes++);
  writes = 0;
  for (let i = 1; i <= 100; i++) noteJoin(s, person(i, { channel_id: 500 }));
  mock.timers.tick(300);
  stop();
  assert.equal(writes, 1);
  assert.equal(get(channelRosters.peek(s)).get(500)!.length, 100);
  assert.equal(get(channels.peek(s))[0].user_count, 100);
  assert.equal(asked("request_channel_users").length, 0);
  noteJoin(s, person(0, { channel_id: 500, username: "" }));
  mock.timers.tick(300);
  assert.deepEqual(asked("request_channel_users").map((a) => a.channelId), [500]);
  assert.equal(get(channels.peek(s))[0].user_count, 101, "the count still moves");
});

test("a leave comes off the list and the count, with no ask", () => {
  const s = server();
  channels.of(s).set([voice(500, { user_count: 2 })]);
  setRoster(s, 500, [person(1, { channel_id: 500 }), person(2, { channel_id: 500 })]);
  noteLeft(s, 500, 2);
  mock.timers.tick(300);
  assert.deepEqual(get(channelRosters.peek(s)).get(500)!.map((u) => u.user_id), [1]);
  assert.equal(asked("request_channel_users").length, 0);
});

test("a flag that comes while the join waits in the batch is on the row the batch writes", () => {
  const s = server();
  channels.of(s).set([voice(500)]);
  setRoster(s, 500, [person(1, { channel_id: 500 })]);
  const flag = (id: number) => get(channelRosters.peek(s)).get(500)!.find((u) => u.user_id === id)?.shares_history;
  // Joined not sharing; the switch goes on 100 ms later, before the 250 ms flush
  noteJoin(s, person(10, { channel_id: 500 }));
  mock.timers.tick(100);
  patchRosters(s, 10, { shares_history: true });
  mock.timers.tick(200);
  assert.equal(flag(10), true, "the join did not put the old flag back");
  // The control: after the flush the patch lands on the row itself
  noteJoin(s, person(11, { channel_id: 500 }));
  mock.timers.tick(300);
  patchRosters(s, 11, { shares_history: true });
  assert.equal(flag(11), true);
  // A channel `where` leaves out keeps the row as it came, queued or not
  noteJoin(s, person(12, { channel_id: 500 }));
  patchRosters(s, 12, { shares_history: true }, (id) => id !== 500);
  mock.timers.tick(300);
  patchRosters(s, 11, { shares_history: false }, (id) => id !== 500);
  assert.equal(flag(12), false);
  assert.equal(flag(11), true);
});

test("a join applies after a list that came before it, and twice counts once", () => {
  const s = server();
  channels.of(s).set([voice(500)]);
  noteJoin(s, person(7, { channel_id: 500 }));
  setRoster(s, 500, [person(1, { channel_id: 500 })]);
  noteJoin(s, person(7, { channel_id: 500 }));
  mock.timers.tick(300);
  assert.deepEqual(get(channelRosters.peek(s)).get(500)!.map((u) => u.user_id), [1, 7]);
});

test("a room's flags are asked for now and then, only on the server on screen", () => {
  const s = server();
  serverAddress.set(s);
  channels.of(s).set([voice(500)]);
  noteJoin(s, person(1, { channel_id: 500 }));
  mock.timers.tick(300);
  noteJoin(s, person(2, { channel_id: 500 }));
  mock.timers.tick(300);
  assert.deepEqual(asked("request_channel_users").map((a) => a.channelId), [500], "at most once per five seconds");
  serverAddress.set("");
  invoked().length = 0;
  mock.timers.tick(6000);
  noteJoin(s, person(3, { channel_id: 500 }));
  mock.timers.tick(300);
  assert.equal(asked("request_channel_users").length, 0, "another server is not drawn");
});

test("who is online is General and the rooms, never a text channel's own list", () => {
  const s = server();
  channels.of(s).set([ch(1), voice(500), voice(0)]);
  channelRosters.of(s).set(
    new Map([
      [0, [person(1)]],
      [500, [person(2)]],
      [1, [person(3)]],
    ]),
  );
  users.of(s).set([person(4)]);
  assert.deepEqual([...onlineById(s).keys()].sort(), [1, 2, 4]);
});

// ── The sweep ──────────────────────────────────────────────────────────────

/** A server following one open channel, two by gate and one by hand. */
function swept(s: string) {
  channels.of(s).set([ch(1), ch(2), ch(3), ch(4, { auto_join: false })]);
  joinedTextChannelIds.of(s).set(new Set([1, 2, 3, 4]));
  textSeats.of(s).set(
    new Map([
      [1, { gated: false, lastPost: 0 }],
      [2, { gated: true, lastPost: 0 }],
      [3, { gated: true, lastPost: 0 }],
      [4, { gated: false, lastPost: 0 }],
    ]),
  );
}

test("the sweep asks every list once, one page at a time, in the first minute", () => {
  const s = server();
  swept(s);
  startSweeps(s, 0.5);
  mock.timers.tick(29_000);
  assert.equal(asked("request_channel_page").length, 0);
  mock.timers.tick(1000);
  assert.deepEqual(asked("request_channel_page"), [{ server: s, channelId: 2, after: 0 }]);
  onSweepPage(s, { channel_id: 2, rows: [person(1)], next: 7 });
  assert.equal(asked("request_channel_page")[1].after, 7, "the next page of the same one");
  onSweepPage(s, { channel_id: 2, rows: [person(8)], next: 0 });
  assert.deepEqual(asked("request_channel_page")[2], { server: s, channelId: 3, after: 0 });
  onSweepPage(s, { channel_id: 3, rows: [], next: 0 });
  assert.deepEqual(asked("request_channel_page")[3], { server: s, channelId: 4, after: 0 });
  onSweepPage(s, { channel_id: 4, rows: [person(2)], next: 0 });
  assert.equal(asked("request_channel_page").length, 4, "an open channel is never asked");
  assert.deepEqual(get(channelRosters.peek(s)).get(2)!.map((u) => u.user_id), [1, 8]);
  clearSweeps(s);
});

test("the next sweep is ten minutes on, whatever is on screen", () => {
  const s = server();
  swept(s);
  channels.of(s).set([ch(2)]);
  startSweeps(s, 0);
  mock.timers.tick(1);
  onSweepPage(s, { channel_id: 2, rows: [], next: 0 });
  invoked().length = 0;
  mock.timers.tick(599_000);
  assert.equal(asked("request_channel_page").length, 0);
  mock.timers.tick(1000);
  assert.equal(asked("request_channel_page").length, 1);
  clearSweeps(s);
});

test("a page's bare ids are who a public list names, and one nobody names is left out", () => {
  const s = server();
  channels.of(s).set([ch(2), voice(0)]);
  joinedTextChannelIds.of(s).set(new Set([2]));
  textSeats.of(s).set(new Map([[2, { gated: true, lastPost: 0 }]]));
  channelRosters.of(s).set(new Map([[0, [person(5)]]]));
  refreshList(s, 2);
  onSweepPage(s, { channel_id: 2, ids: [5, 6], rows: [person(9)], next: 0 });
  assert.deepEqual(get(channelRosters.peek(s)).get(2)!.map((u) => u.user_id).sort(), [5, 9]);
});

test("a quiet channel is not swept: opening it tells the relay anyway", () => {
  const s = server();
  swept(s);
  setSweepQuiet(s, new Set([3]));
  startSweeps(s, 0);
  mock.timers.tick(1);
  onSweepPage(s, { channel_id: 2, rows: [], next: 0 });
  assert.equal(asked("request_channel_page")[1].channelId, 4);
  clearSweeps(s);
});

test("a first sweep with nothing to ask is no sweep: the next comes in a minute, not ten", () => {
  const s = server();
  // Only an open channel at the first join: nothing goes by a list yet
  channels.of(s).set([ch(1)]);
  joinedTextChannelIds.of(s).set(new Set([1]));
  textSeats.of(s).set(new Map([[1, { gated: false, lastPost: 0 }]]));
  startSweeps(s, 0);
  mock.timers.tick(1);
  assert.equal(asked("request_channel_page").length, 0);
  // Then one made by hand is followed, and its list comes within the minute
  channels.of(s).set([ch(1), ch(4, { auto_join: false })]);
  joinedTextChannelIds.of(s).set(new Set([1, 4]));
  mock.timers.tick(60_000);
  assert.deepEqual(asked("request_channel_page").map((a) => a.channelId), [4]);
  // A sweep that asked counts: the next is ten minutes on
  onSweepPage(s, { channel_id: 4, rows: [], next: 0 });
  mock.timers.tick(599_000);
  assert.equal(asked("request_channel_page").length, 1);
  mock.timers.tick(1000);
  assert.equal(asked("request_channel_page").length, 2);
  clearSweeps(s);
});

test("a channel this person made has its list asked at their join, once", () => {
  const s = server();
  channels.of(s).set([ch(4, { auto_join: false }), ch(5, { auto_join: false })]);
  noteMade(s, 4);
  joinedMade(s, [4]);
  assert.deepEqual(asked("request_channel_page"), [{ server: s, channelId: 4, after: 0 }]);
  onSweepPage(s, { channel_id: 4, rows: [person(1)], next: 0 });
  assert.deepEqual(get(channelRosters.peek(s)).get(4)!.map((u) => u.user_id), [1]);
  // Followed again (a reconnect), or one somebody else made: no ask
  joinedMade(s, [4, 5]);
  assert.equal(asked("request_channel_page").length, 1);
  clearSweeps(s);
});

test("a page nobody swept for is not the sweep's", () => {
  const s = server();
  assert.equal(onSweepPage(s, { channel_id: 2, rows: [person(1)], next: 0 }), false);
});

test("MemberGone takes them off at once, and a sweep in flight keeps them off", () => {
  const s = server();
  swept(s);
  channelRosters.of(s).set(new Map([[2, [person(1), person(2)]]]));
  noteMemberGone(s, 2, 2);
  assert.deepEqual(get(channelRosters.peek(s)).get(2)!.map((u) => u.user_id), [1]);
  assert.ok(get(goneFrom.peek(s)).get(2)!.has(2));
  refreshList(s, 2);
  noteMemberGone(s, 2, 1);
  onSweepPage(s, { channel_id: 2, rows: [person(1), person(3)], next: 0 });
  assert.deepEqual(get(channelRosters.peek(s)).get(2)!.map((u) => u.user_id), [3]);
  assert.deepEqual([...get(goneFrom.peek(s)).get(2)!], [1], "gone while it was on its way");
});

test("a sweep clears who it says are gone: whoever it names is there", () => {
  const s = server();
  swept(s);
  noteMemberGone(s, 2, 2);
  refreshList(s, 2);
  onSweepPage(s, { channel_id: 2, rows: [person(2)], next: 0 });
  assert.equal(get(goneFrom.peek(s)).get(2), undefined);
});

test("an unknown asker moves the whole sweep up, and asks no single page", () => {
  const s = server();
  swept(s);
  startSweeps(s, 0.9);
  let retried = 0;
  sweepForAsker(s, () => retried++);
  assert.deepEqual(asked("request_channel_page").map((a) => a.channelId), [2], "the first of all of them, at once");
  onSweepPage(s, { channel_id: 2, rows: [], next: 0 });
  onSweepPage(s, { channel_id: 3, rows: [], next: 0 });
  assert.equal(retried, 0, "not until all are in");
  onSweepPage(s, { channel_id: 4, rows: [], next: 0 });
  assert.equal(retried, 1, "then they are looked at again");
  clearSweeps(s);
});

test("the sweep's budget holds it back, and then there is no answer", () => {
  const s = server();
  channels.of(s).set([ch(2)]);
  joinedTextChannelIds.of(s).set(new Set([2]));
  textSeats.of(s).set(new Map([[2, { gated: true, lastPost: 0 }]]));
  startSweeps(s, 0);
  mock.timers.tick(1);
  onSweepPage(s, { channel_id: 2, rows: Array.from({ length: 100 }, (_, i) => person(i + 1)), next: 0 });
  invoked().length = 0;
  let retried = 0;
  sweepForAsker(s, () => retried++);
  assert.equal(asked("request_channel_page").length, 0, "8.3 KB wants 207 s");
  mock.timers.tick(10_000);
  assert.equal(retried, 0);
  mock.timers.tick(200_000);
  sweepForAsker(s, () => retried++);
  assert.equal(asked("request_channel_page").length, 1);
  clearSweeps(s);
});

test("a person's Refresh asks that channel alone and keeps the schedule", () => {
  const s = server();
  swept(s);
  startSweeps(s, 0.5);
  refreshList(s, 4);
  assert.deepEqual(asked("request_channel_page").map((a) => a.channelId), [4]);
  onSweepPage(s, { channel_id: 4, rows: [], next: 0 });
  assert.equal(asked("request_channel_page").length, 1);
  mock.timers.tick(30_000);
  assert.equal(asked("request_channel_page").length, 2, "the first sweep still comes");
  clearSweeps(s);
});

test("a Refresh under way when a sweep comes due does not lose the schedule", () => {
  const s = server();
  channels.of(s).set([ch(2), ch(3)]);
  joinedTextChannelIds.of(s).set(new Set([2, 3]));
  textSeats.of(s).set(
    new Map([
      [2, { gated: true, lastPost: 0 }],
      [3, { gated: true, lastPost: 0 }],
    ]),
  );
  refreshList(s, 3);
  startSweeps(s, 0);
  mock.timers.tick(1);
  assert.deepEqual(asked("request_channel_page").map((a) => a.channelId), [3], "one page out at a time");
  onSweepPage(s, { channel_id: 3, rows: [], next: 0 });
  assert.deepEqual(asked("request_channel_page").map((a) => a.channelId), [3, 2], "the sweep's own come next");
  onSweepPage(s, { channel_id: 2, rows: [], next: 0 });
  invoked().length = 0;
  mock.timers.tick(600_000);
  assert.equal(asked("request_channel_page").length, 1, "and the next is ten minutes on");
  clearSweeps(s);
});

test("no answer to a page gives up, so the next sweep still comes", () => {
  const s = server();
  channels.of(s).set([ch(2)]);
  joinedTextChannelIds.of(s).set(new Set([2]));
  textSeats.of(s).set(new Map([[2, { gated: true, lastPost: 0 }]]));
  startSweeps(s, 0);
  mock.timers.tick(1);
  mock.timers.tick(30_000);
  invoked().length = 0;
  mock.timers.tick(600_000);
  assert.equal(asked("request_channel_page").length, 1);
  clearSweeps(s);
});

// ── Hand-offs on screen ────────────────────────────────────────────────────

/** An open channel, with these online. */
function openChannel(s: string, online: UserInfo[]) {
  channels.of(s).set([ch(1), voice(0)]);
  joinedTextChannelIds.of(s).set(new Set([1]));
  textSeats.of(s).set(new Map([[1, { gated: false, lastPost: 0 }]]));
  channelRosters.of(s).set(new Map([[0, online]]));
  userId.of(s).set(99);
}
const sharer = (id: number) => person(id, { shares_history: true });
/** The backend's pick: the first three it is passed. */
const picksThree = () => {
  (globalThis as any).__answer = (command: string, args: any) => (command === "request_channel_history" ? args.targetUserIds.slice(0, 3) : undefined);
};
const settled = () => new Promise<void>((resolve) => setImmediate(resolve));

test("a first opening asks those who share and says who it asked; a second asks nothing", async () => {
  const s = server();
  openChannel(s, [sharer(1), sharer(2), sharer(3), sharer(4), person(5), person(99, { shares_history: true })]);
  picksThree();
  channelOpened(s, 1);
  await settled();
  const asks = asked("request_channel_history");
  assert.deepEqual(asks.map((a) => a.targetUserIds), [[1, 2, 3, 4]], "neither a non-sharer nor ourselves");
  assert.deepEqual([...get(handOffs.peek(s)).get(1)!.asked], [1, 2, 3], "the ids it asked, not those it was passed");
  assert.equal(get(handOffs.peek(s)).get(1)!.asking, true);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 1);
});

test("nobody online shares: no ask goes at all", async () => {
  const s = server();
  openChannel(s, [person(1)]);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 0);
});

test("an ask says it is out for five seconds, or until an answer", async () => {
  const s = server();
  openChannel(s, [sharer(1)]);
  picksThree();
  channelOpened(s, 1);
  await settled();
  assert.equal(get(handOffs.peek(s)).get(1)!.asking, true);
  mock.timers.tick(5000);
  assert.equal(get(handOffs.peek(s)).get(1)!.asking, false);
  await askSharers(s, 1, [1]);
  assert.equal(get(handOffs.peek(s)).get(1)!.asking, true);
  handOffAnswered(s, 1);
  assert.equal(get(handOffs.peek(s)).get(1)!.asking, false);
});

test("on mobile data a first opening asks one", async () => {
  const s = server();
  openChannel(s, [sharer(1), sharer(2), sharer(3)]);
  picksThree();
  const real = Object.getOwnPropertyDescriptor(globalThis, "navigator")!;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { connection: { type: "cellular" } } });
  channelOpened(s, 1);
  await settled();
  Object.defineProperty(globalThis, "navigator", real);
  assert.equal(asked("request_channel_history")[0].targetUserIds.length, 1);
});

test("who was asked goes when the channel is left", async () => {
  const s = server();
  openChannel(s, [sharer(1)]);
  picksThree();
  channelOpened(s, 1);
  await settled();
  forgetHandOff(s, 1);
  assert.equal(get(handOffs.peek(s)).has(1), false);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 2);
});

test("a gated channel's sharers go by the sweep, without whoever it just lost", () => {
  const s = server();
  channels.of(s).set([ch(2), voice(0)]);
  textSeats.of(s).set(new Map([[2, { gated: true, lastPost: 0 }]]));
  channelRosters.of(s).set(
    new Map([
      [0, [sharer(1), sharer(2), sharer(3)]],
      [2, [sharer(2), sharer(3)]],
    ]),
  );
  goneFrom.of(s).set(new Map([[2, new Set([3])]]));
  assert.deepEqual(sharersOf(s, 2).map((u) => u.user_id), [2]);
});

test("in an anonymous channel nobody is asked, on opening or by hand, and a ring says what it can", async () => {
  const s = server();
  openChannel(s, [sharer(1), sharer(2)]);
  channels.of(s).set([ch(1, { anonymous: true })]);
  assert.deepEqual(sharersOf(s, 1), [], "an ask would say who it is, by name");
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 0);
  lightRing(s, 1);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 0);
  assert.equal(get(channelRings.peek(s)).get(1), "opened");
});

// ── Rings ──────────────────────────────────────────────────────────────────

test("a ring on opening asks whoever is left, and stays until something is read", async () => {
  const s = server();
  openChannel(s, [sharer(1)]);
  picksThree();
  lightRing(s, 1);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 1);
  assert.equal(get(channelRings.peek(s)).get(1), "lit", "nobody answered yet");
});

test("a ring with nobody left to ask clears on opening, and the pane still says so", async () => {
  const s = server();
  openChannel(s, [person(1)]);
  lightRing(s, 1);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 0);
  assert.equal(get(channelRings.peek(s)).get(1), "opened", "a plain row, and a line in the pane");
  channels.of(s).update((list) => [...list, ch(2)]);
  channelOpened(s, 2);
  assert.equal(get(channelRings.peek(s)).has(1), false, "gone when they look elsewhere");
});

test("a ring lights when the relay's mark is past where they read, and the first sight lights none", () => {
  const s = server();
  channels.of(s).set([ch(1, { log: "c:one" })]);
  noteLastPost(s, 1, 5_000);
  assert.equal(get(channelRings.peek(s)).has(1), false, "first sight: the baseline");
  flushMarks();
  assert.equal(get(uiPrefs).read_marks[s]["c:one"], 5_000);
  noteLastPost(s, 1, 60_000);
  assert.equal(get(channelRings.peek(s)).get(1), "lit");
  noteLastPost(s, 1, 0);
  assert.equal(get(channelRings.peek(s)).get(1), "lit", "a restarted relay takes nothing back");
});

test("where they read moves one way, and survives by the channel's log across a rename", () => {
  const s = server();
  moveRead(s, ch(1, { log: "c:one", name: "old" }), 9_000);
  moveRead(s, ch(1, { log: "c:one", name: "old" }), 4_000);
  flushMarks();
  assert.equal(get(uiPrefs).read_marks[s]["c:one"], 9_000);
  channels.of(s).set([ch(1, { log: "c:one", name: "new" })]);
  noteLastPost(s, 1, 9_000);
  assert.equal(get(channelRings.peek(s)).has(1), false);
});

test("a dot costs one write however many posts come, and opening clears it", () => {
  const s = server();
  let writes = 0;
  const stop = unseenChannels.subscribe(() => writes++);
  writes = 0;
  for (let i = 0; i < 50; i++) noteChannelUnseen(s, "busy", i);
  assert.equal(writes, 1);
  assert.ok(get(unseenChannels).has(chatKey(s, "busy")));
  clearChannelUnread(s, "busy");
  assert.ok(!get(unseenChannels).has(chatKey(s, "busy")));
  stop();
});

test("whoever this app exchanged a key with is on the list from then on, unless they left", () => {
  const s = server();
  channels.of(s).set([ch(2), voice(0)]);
  channelRosters.of(s).set(new Map([[0, [person(5, { shares_history: true })]]]));
  exchangedKey(s, 2, person(7, { channel_id: 2 }));
  assert.deepEqual(get(channelRosters.peek(s)).get(2)!.map((u) => u.user_id), [7]);
  exchangedKey(s, 2, person(5, { channel_id: 2 }));
  assert.equal(get(channelRosters.peek(s)).get(2)![1].shares_history, true, "as the public list has them");
  exchangedKey(s, 2, person(7, { channel_id: 2 }));
  assert.equal(get(channelRosters.peek(s)).get(2)!.length, 2, "once");
  noteMemberGone(s, 2, 7);
  exchangedKey(s, 2, person(7, { channel_id: 2 }));
  assert.deepEqual(get(channelRosters.peek(s)).get(2)!.map((u) => u.user_id), [5], "a late post does not bring them back");
});

// ── Quiet mode ─────────────────────────────────────────────────────────────

/** A server following these, on the live path, with a mode chosen. */
function quietServer(s: string, list: ChannelInfo[], mode: "off" | "mobile" | "always", whole: string[] = []) {
  channels.of(s).set(list);
  joinedTextChannelIds.of(s).set(new Set(list.map((c) => c.channel_id)));
  uiPrefs.update((p) => ({ ...p, quiet_mode: { ...p.quiet_mode, [s]: { mode, whole } } }));
}

test("off changes nothing: everything goes whole in the one frame", () => {
  const s = server();
  quietServer(s, [ch(1), ch(2)], "off");
  joinedTextChannelIds.of(s).set(new Set());
  autoJoinTextChannels(s, get(channels.peek(s)));
  assert.deepEqual(asked("join_text_channels")[0].channels, [1, 2]);
  assert.deepEqual(asked("join_text_channels")[0].quiet, []);
});

test("always: all but what was picked go in quiet, in the same frame, and stay out of the sweep", () => {
  const s = server();
  quietServer(s, [ch(1), ch(2, { log: "c:two" }), ch(3)], "always", ["c:two"]);
  joinedTextChannelIds.of(s).set(new Set());
  autoJoinTextChannels(s, get(channels.peek(s)));
  assert.deepEqual(asked("join_text_channels")[0].channels, [2]);
  assert.deepEqual(asked("join_text_channels")[0].quiet, [1, 3]);
  assert.deepEqual([...get(quietChannels.peek(s))].sort(), [1, 3]);
});

test("on mobile data goes by the network, and off Wi-Fi only then", () => {
  const s = server();
  quietServer(s, [ch(1)], "mobile");
  applyQuiet(s);
  assert.equal(asked("set_quiet").length, 0, "on Wi-Fi nothing is quiet");
  const real = Object.getOwnPropertyDescriptor(globalThis, "navigator")!;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { connection: { type: "cellular" } } });
  applyQuiet(s);
  Object.defineProperty(globalThis, "navigator", real);
  assert.deepEqual(asked("set_quiet")[0], { server: s, channels: [1], quiet: true });
});

test("a network change acts on the mobile data mode only once it has lasted two minutes", () => {
  const s = server();
  quietServer(s, [ch(1)], "mobile");
  const real = Object.getOwnPropertyDescriptor(globalThis, "navigator")!;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { connection: { type: "cellular" } } });
  networkChanged(() => [s]);
  mock.timers.tick(60_000);
  networkChanged(() => [s]);
  mock.timers.tick(119_000);
  assert.equal(asked("set_quiet").length, 0, "the second change started the wait over");
  mock.timers.tick(1000);
  Object.defineProperty(globalThis, "navigator", real);
  assert.equal(asked("set_quiet").length, 1);
});

test("a mode set starts from what this device opened, and the picks change who is quiet", () => {
  const s = server();
  channels.of(s).set([ch(1), ch(2)]);
  joinedTextChannelIds.of(s).set(new Set([1, 2]));
  uiPrefs.update((p) => ({ ...p, opened_channels: { [s]: ["c1"] } }));
  setQuietMode(s, "always");
  assert.deepEqual(get(uiPrefs).quiet_mode[s], { mode: "always", whole: ["c1"] });
  assert.deepEqual(asked("set_quiet")[0], { server: s, channels: [2], quiet: true });
  setWholeHere(s, ch(2), true);
  assert.deepEqual(asked("set_quiet")[1], { server: s, channels: [2], quiet: false });
  setQuietMode(s, "off");
  assert.equal(asked("set_quiet").length, 2, "nothing was quiet any more");
});

test("opening a quiet channel makes it whole, and ten minutes off screen makes it quiet again", () => {
  const s = server();
  quietServer(s, [ch(1)], "always");
  applyQuiet(s);
  invoked().length = 0;
  mock.timers.reset();
  mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000_000_000 });
  channelOpened(s, 1);
  assert.deepEqual(asked("set_quiet")[0], { server: s, channels: [1], quiet: false });
  mock.timers.tick(9 * 60_000);
  assert.equal(asked("set_quiet").length, 1);
  mock.timers.tick(2 * 60_000);
  assert.deepEqual(asked("set_quiet")[1], { server: s, channels: [1], quiet: true });
  clearQuiet(s);
});

test("the channel on screen never goes quiet, and goes by the mode once it has been off screen", () => {
  const s = server();
  mock.timers.reset();
  mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000_000_000 });
  quietServer(s, [ch(1), ch(2)], "off");
  serverAddress.set(s);
  activeTextChannelId.of(s).set(1);
  uiPrefs.update((p) => ({ ...p, quiet_mode: { ...p.quiet_mode, [s]: { mode: "always", whole: [] } } }));
  applyQuiet(s);
  assert.deepEqual(asked("set_quiet")[0], { server: s, channels: [2], quiet: true }, "only the one not on screen");
  assert.deepEqual([...get(quietChannels.peek(s))], [2]);
  mock.timers.tick(30 * 60_000);
  assert.equal(asked("set_quiet").length, 1, "read for half an hour, it stays whole");
  activeTextChannelId.of(s).set(2);
  channelOpened(s, 2);
  invoked().length = 0;
  mock.timers.tick(9 * 60_000);
  assert.equal(asked("set_quiet").length, 0);
  mock.timers.tick(2 * 60_000);
  assert.deepEqual(asked("set_quiet")[0], { server: s, channels: [1], quiet: true }, "now the mode applies");
  serverAddress.set("");
  clearQuiet(s);
});

test("the mobile data choice is offered only where the kind of network can be read", () => {
  const real = Object.getOwnPropertyDescriptor(globalThis, "navigator")!;
  const on = (value: unknown) => Object.defineProperty(globalThis, "navigator", { configurable: true, value });
  try {
    on({ connection: { type: "unknown" } });
    assert.equal(networkKnown(), true, "an Android WebView, which says it once it may");
    on({ connection: { effectiveType: "4g", saveData: false } });
    assert.equal(networkKnown(), false, "WebView2 has the object, with no type on it");
    on({});
    assert.equal(networkKnown(), false, "Firefox has no object at all");
  } finally {
    Object.defineProperty(globalThis, "navigator", real);
  }
});

// ── Back after a dropped connection ────────────────────────────────────────

test("the channel on screen at a drop is back on screen, and it asks nobody", async () => {
  const s = server();
  openChannel(s, [sharer(1)]);
  picksThree();
  reopenAfterDrop(s, ch(1));
  assert.equal(get(activeTextChannelId.peek(s)), 1);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 0, "no click, so no sealed ask");
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 0, "and it counts as opened");
});

test("a ring on the channel put back waits for a click too", async () => {
  const s = server();
  openChannel(s, [sharer(1)]);
  picksThree();
  reopenAfterDrop(s, ch(1));
  lightRing(s, 1);
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 0);
  assert.equal(get(channelRings.peek(s)).get(1), "lit", "and it stays until something is read");
  channelOpened(s, 1);
  await settled();
  assert.equal(asked("request_channel_history").length, 1, "opened again by them, it asks");
});

test("a channel put back that then refuses them does not stay on screen", () => {
  const s = server();
  mock.timers.reset();
  mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000_000_000 });
  channels.of(s).set([ch(1), ch(2)]);
  reopenAfterDrop(s, ch(1));
  assert.equal(get(activeTextChannelId.peek(s)), 1);
  mock.timers.tick(20_000);
  assert.equal(get(activeTextChannelId.peek(s)), null, "never followed: a gate, or no way in");

  joinedTextChannelIds.of(s).set(new Set([2]));
  reopenAfterDrop(s, ch(2));
  mock.timers.tick(20_000);
  assert.equal(get(activeTextChannelId.peek(s)), 2, "followed: it stays");

  const other = server();
  channels.of(other).set([ch(1)]);
  activeTextChannelId.of(other).set(7);
  reopenAfterDrop(other, ch(1));
  assert.equal(get(activeTextChannelId.peek(other)), 7, "something else was opened meanwhile");
});

// ── A ring across a reconnect ──────────────────────────────────────────────

test("a post that never opens leaves where they read alone, so a later mark rings again", () => {
  const s = server();
  channels.of(s).set([ch(1, { log: "c:one" })]);
  moveRead(s, ch(1, { log: "c:one" }), 10_000);
  ringForPost(s, 1, 60_000);
  assert.equal(get(channelRings.peek(s)).get(1), "lit");
  flushMarks();
  assert.equal(get(uiPrefs).read_marks[s]["c:one"], 10_000, "nothing was read");
  channelRings.drop(s);
  noteLastPost(s, 1, 60_000);
  assert.equal(get(channelRings.peek(s)).get(1), "lit", "the app restarted, or the connection did");
});

test("a ring stays across a reconnect even with a post just before it read", () => {
  const s = server();
  channels.of(s).set([ch(1, { log: "c:one" })]);
  moveRead(s, ch(1, { log: "c:one" }), 59_000);
  ringForPost(s, 1, 60_000);
  channelRings.drop(s);
  noteLastPost(s, 1, 60_000);
  assert.equal(get(channelRings.peek(s)).has(1), false, "the mark alone cannot tell, this close");
  ringBack(s, ch(1, { log: "c:one" }));
  assert.equal(get(channelRings.peek(s)).get(1), "lit");
});

test("a ring read is gone for the next connection, and a closed server forgets them", () => {
  const s = server();
  channels.of(s).set([ch(1, { log: "c:one" })]);
  lightRing(s, 1);
  clearRing(s, 1);
  ringBack(s, ch(1, { log: "c:one" }));
  assert.equal(get(channelRings.peek(s)).has(1), false, "read");
  lightRing(s, 1);
  forgetRings(s);
  channelRings.drop(s);
  channels.of(s).set([ch(1, { log: "c:one" })]);
  ringBack(s, ch(1, { log: "c:one" }));
  assert.equal(get(channelRings.peek(s)).has(1), false, "closed");
});

test("a first sight has nowhere to stay, so its ring still comes back", () => {
  const s = server();
  channels.of(s).set([ch(1, { log: "c:one" })]);
  ringForPost(s, 1, 60_000);
  channelRings.drop(s);
  forgetRings(s);
  channels.of(s).set([ch(1, { log: "c:one" })]);
  noteLastPost(s, 1, 60_000);
  assert.equal(get(channelRings.peek(s)).get(1), "lit");
});

// ── A poke from a member's menu ────────────────────────────────────────────

test("a poke with no conversation open knows whom it was for", async () => {
  const s = server();
  serverAddress.set(s);
  openPokeDialog(7, "gina#0001");
  await sendPoke();
  serverAddress.set("");
  assert.equal(peerName(s, 7, "Unknown"), "gina#0001");
  assert.deepEqual(asked("send_poke").at(-1), { server: s, targetUserId: 7, message: "" });
});

// ── Names at connect ───────────────────────────────────────────────────────

test("everyone on this device for this server is asked for at once, sorted, and a draw asks nothing", () => {
  const s = server();
  mock.timers.reset();
  mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000_000_000 });
  channelMessages.update((m) => {
    m.set(chatKey(s, "one"), [
      { user_id: 1, username: "b", content: "x", timestamp: 1, account: "bb" },
      { user_id: 2, username: "z", content: "x", timestamp: 2, account: "ff" },
    ]);
    m.set(chatKey(s, "two"), [
      { user_id: 3, username: "a", content: "x", timestamp: 3, account: "aa" },
      { user_id: 4, username: "c", content: "says it is cc", timestamp: 4, account: "cc", kind: "shared" },
    ]);
    m.set(chatKey(`${s}x`, "another server"), [{ user_id: 9, username: "n", content: "x", timestamp: 9, account: "dd" }]);
    return new Map(m);
  });
  dmMessages.update((m) => new Map(m).set(chatKey(s, "pat"), [{ user_id: 5, username: "pat", content: "x", timestamp: 5, account: "ee" }]));
  assert.deepEqual([...authorsHere(s)].sort(), ["aa", "bb", "ee", "ff"], "none of a shared row's words, or of another server");
  askProfiles(s, authorsHere(s));
  mock.timers.tick(125);
  const pages = asked("profiles_get").filter((a) => a.server === s);
  assert.equal(pages.length, 1);
  assert.deepEqual(pages[0].accounts, [[0xaa], [0xbb], [0xee], [0xff]], "by account, whatever channel they wrote in");
  invoked().length = 0;
  askProfile(s, "bb");
  mock.timers.tick(250);
  assert.equal(asked("profiles_get").length, 0, "the draw finds them asked");
  clearProfiles(s);
});

test("a stranger's sweep page names them with the rest of the sweep", () => {
  const s = server();
  mock.timers.reset();
  mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"], now: 1_000_000_000_000 });
  channels.of(s).set([ch(1, { auto_join: false })]);
  joinedTextChannelIds.of(s).set(new Set([1]));
  refreshList(s, 1);
  onSweepPage(s, { channel_id: 1, rows: [person(5, { account: [0xcc] })], next: 0 });
  mock.timers.tick(125);
  assert.deepEqual(asked("profiles_get").at(-1)?.accounts, [[0xcc]]);
  clearSweeps(s);
  clearProfiles(s);
});

// ── What a relay's pages can make a client hold ────────────────────────────

test("a relay naming a next page for ever stops at the cap, and what came is the list", () => {
  const s = server();
  channels.of(s).set([ch(1, { auto_join: false })]);
  joinedTextChannelIds.of(s).set(new Set([1]));
  refreshList(s, 1);
  invoked().length = 0;
  let pages = 0;
  for (let next = 1; next <= 1000 && asked("request_channel_page").length === pages; next++) {
    onSweepPage(s, { channel_id: 1, rows: [person(next)], next });
    pages++;
  }
  assert.ok(pages <= 256, `${pages} pages`);
  assert.equal(get(channelRosters.peek(s)).get(1)?.length, pages);
  clearSweeps(s);
});

test("a next page that does not move on ends the list", () => {
  const s = server();
  channels.of(s).set([ch(1, { auto_join: false })]);
  joinedTextChannelIds.of(s).set(new Set([1]));
  refreshList(s, 1);
  invoked().length = 0;
  onSweepPage(s, { channel_id: 1, rows: [person(1)], next: 5 });
  assert.equal(asked("request_channel_page").length, 1);
  onSweepPage(s, { channel_id: 1, rows: [person(2)], next: 5 });
  assert.equal(asked("request_channel_page").length, 1, "asked no third time");
  assert.deepEqual(get(channelRosters.peek(s)).get(1)?.map((u) => u.user_id), [1, 2]);
  clearSweeps(s);
});

// ── Naming ─────────────────────────────────────────────────────────────────

const lines = (s: string, name: string) => (get(channelMessages).get(chatKey(s, name)) ?? []).filter((m) => m.kind === "notice");

test("a new reader in a gated channel is named once, and in an open one never", () => {
  const s = server();
  channels.of(s).set([ch(1), ch(2)]);
  textSeats.of(s).set(
    new Map([
      [1, { gated: false, lastPost: 0 }],
      [2, { gated: true, lastPost: 0 }],
    ]),
  );
  const bob = { account: Array(16).fill(1), name: "bob#0001" };
  noteReaders(s, 1, [bob]);
  assert.equal(lines(s, "c1").length, 0, "an open channel watches nobody");
  noteReaders(s, 2, [bob]);
  assert.equal(lines(s, "c2")[0].content, "bob can now read what you write here");
  mock.timers.tick(60_000);
  noteReaders(s, 2, [bob]);
  mock.timers.tick(60_000);
  assert.equal(lines(s, "c2").length, 1, "once ever");
  clearNoticing(s);
});

test("a hand-joined channel names its readers too", () => {
  const s = server();
  channels.of(s).set([ch(4, { auto_join: false })]);
  textSeats.of(s).set(new Map([[4, { gated: false, lastPost: 0 }]]));
  noteReaders(s, 4, [{ name: "guest#0001" }]);
  assert.equal(lines(s, "c4").length, 1);
  clearNoticing(s);
});

test("names in the same minute are one line, past five with the whole list behind it", () => {
  const s = server();
  channels.of(s).set([ch(2)]);
  textSeats.of(s).set(new Map([[2, { gated: true, lastPost: 0 }]]));
  const reader = (i: number) => ({ account: Array(16).fill(i), name: `r${i}#0001` });
  noteReaders(s, 2, [reader(1)]);
  assert.equal(lines(s, "c2").length, 1, "the first at once");
  for (let i = 2; i <= 8; i++) noteReaders(s, 2, [reader(i)]);
  assert.equal(lines(s, "c2").length, 1);
  mock.timers.tick(60_000);
  const second = lines(s, "c2")[1];
  assert.equal(second.content, "r2, r3, r4, r5, r6 and 2 others can now read what you write here");
  assert.deepEqual(second.names, ["r2", "r3", "r4", "r5", "r6", "r7", "r8"]);
  clearNoticing(s);
});

test("someone who quits inside the minute has named nobody: the mark goes when it is said", () => {
  const s = server();
  channels.of(s).set([ch(2)]);
  textSeats.of(s).set(new Map([[2, { gated: true, lastPost: 0 }]]));
  const reader = (i: number) => ({ account: Array(16).fill(i), name: `r${i}` });
  noteReaders(s, 2, [reader(1)]);
  noteReaders(s, 2, [reader(2)]);
  const told = () => get(uiPrefs).readers_named[s]["c2"].length;
  assert.equal(told(), 1);
  clearNoticing(s);
  noteReaders(s, 2, [reader(2)]);
  assert.equal(lines(s, "c2").length, 2, "said on the next connection");
  assert.equal(told(), 2);
  clearNoticing(s);
});

test("a gate that disappears is said, by log or by name, once", () => {
  const s = server();
  const gated = ch(2, { log: "c:two", name: "two" });
  assert.equal(gateNoted(s, gated, true), false, "first seen");
  assert.equal(gateNoted(s, gated, true), false);
  // A relay changing the log along with it is still caught by the name
  assert.equal(gateNoted(s, { ...gated, log: "c:other" }, false), true);
  assert.equal(gateNoted(s, { ...gated, log: "c:other" }, false), false, "said once");
});

test("a relay that goes back to an older protocol is said once it has spoken a newer one", () => {
  const s = server();
  assert.equal(relayWentBack(s, 21), false);
  assert.equal(relayWentBack(s, 21), false);
  assert.equal(relayWentBack(s, 20), true, "the existing way to talk to an old relay, and how one would strip all this");
  assert.equal(relayWentBack(s, 22), false);
});

test("a followed channel never opened keeps a hundred messages, and the usual number once opened", () => {
  const s = server();
  channels.of(s).set([ch(9)]);
  joinedTextChannelIds.of(s).set(new Set([9]));
  const row = (i: number) => ({ user_id: 1, username: "a", content: `${i}`, timestamp: i, id: `m${i}` });
  noteNeverOpened(s, "c9", true);
  for (let i = 1; i <= 120; i++) addChannelMessage(s, "c9", row(i));
  assert.equal(get(channelMessages).get(chatKey(s, "c9"))!.length, 100);
  channelOpened(s, 9);
  for (let i = 121; i <= 140; i++) addChannelMessage(s, "c9", row(i));
  assert.equal(get(channelMessages).get(chatKey(s, "c9"))!.length, 120);
});

test("what a never-opened channel already holds stays: an archive from before is someone's own", () => {
  const s = server();
  const row = (i: number) => ({ user_id: 1, username: "a", content: `${i}`, timestamp: i, id: `m${i}` });
  for (let i = 1; i <= 120; i++) addChannelMessage(s, "old", row(i));
  noteNeverOpened(s, "old", true);
  addChannelMessage(s, "old", row(121));
  assert.equal(get(channelMessages).get(chatKey(s, "old"))!.length, 121);
});

