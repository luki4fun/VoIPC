import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  ACKNOWLEDGEMENT,
  MOVE_FILTERS,
  moveFiltersFor,
  channelDeleteWords,
  canLiftBan,
  NO_UNDO,
  POLICY_URL,
  TOGGLES,
  addUndone,
  beginBlock,
  choicesToSend,
  discordId,
  discordIds,
  earlierStands,
  effectiveOptions,
  estimateLine,
  excludedLine,
  excludedRows,
  expiryText,
  gateHereLine,
  humanBytes,
  idsBackLine,
  undoLeftLine,
  mergeBanPage,
  messagesCame,
  ownPage,
  humanTime,
  moveAccounts,
  moveChip,
  movePostText,
  moveRuns,
  newLinkCode,
  openingOnce,
  optionsToSend,
  planOnce,
  postChannelOf,
  postChannels,
  postable,
  powerRows,
  progressLine,
  runState,
  signedInLine,
  startChoices,
  storedReport,
  toggleBlock,
  undoChain,
  undoSays,
  undoneLine,
  withJoinLine,
  type Plan,
} from "./move-rules.ts";
import type { ImportFacts, ImportOptions, ImportUndoCounts, MoveAccount, MoveRun, PowerRow } from "./types.ts";

// What the dry-run really gives, held to the code by crates/voipc-import's `the_wizards_plan`
const plan: Plan = JSON.parse(readFileSync(join(import.meta.dirname, "../../../testkit/6-mock-discord/plan.json"), "utf8"));

const allOn: ImportOptions = {
  channels: true,
  roles: true,
  permissions: true,
  members: true,
  bans: true,
  emotes: true,
  messages: true,
  threads: true,
  pins: true,
  reactions: true,
  anonymise: true,
  acknowledged: false,
};

const facts = (over: Partial<ImportFacts> = {}): ImportFacts => ({
  backup_here: true,
  max_users: 100,
  online: 0,
  registration: "Open",
  discord_sign_in: true,
  public_url: "https://voipc.example:9987",
  takes_guests: false,
  accounts: 0,
  channel_list_bytes: 0,
  channel_list_limit: 60_000,
  categories: 0,
  max_categories: 200,
  emotes: 0,
  cloud: true,
  ...over,
});

const account = (byte: number, over: Partial<MoveAccount> = {}): MoveAccount => ({
  user: { id: new Array(16).fill(byte), name: `n${byte}`, created_at: 1, totp: false } as MoveAccount["user"],
  state: "Waiting",
  dc_id: "1190000000000001001",
  expires_at: 0,
  ...over,
});

const run = (id: number, over: Partial<MoveRun> = {}): MoveRun => ({
  id,
  guild_id: "1190000000000000001",
  by: "annika",
  started_at: 1_800_000_000,
  finished_at: 1_800_000_100,
  undone_at: null,
  accounts: 2,
  groups: 3,
  clearing: false,
  ...over,
});

const counts = (over: Partial<ImportUndoCounts> = {}): ImportUndoCounts => ({
  channels: 0,
  live_posts: 0,
  groups: 0,
  placeholders: 0,
  claimed_kept: 0,
  archive_rows: 0,
  emotes: 0,
  later_runs: 0,
  ...over,
});

test("a repeated row collapses, so a keyed each cannot throw", () => {
  assert.equal(moveAccounts([account(1), account(1), account(2)]).length, 2);
  const row: PowerRow = { account: new Array(16).fill(1), name: "dan", claimed: true, group: "crew-power", badge: "", scopes: [] };
  assert.equal(powerRows([row, row]).length, 1);
  // One person, two groups: two rows
  assert.equal(powerRows([row, { ...row, group: "other-power" }]).length, 2);
  assert.deepEqual(moveRuns([run(3), run(3), run(4)]).map((r) => r.id), [4, 3], "newest first");
  assert.deepEqual(
    excludedRows([], [["12", false, true, 5], ["12", false, true, 5]]).map((r) => r.id),
    ["12"],
  );
});

test("what comes off Discord twice is one row in the wizard", () => {
  const twice = planOnce({ ...plan, channels: [...plan.channels, plan.channels[0]], roles: [...plan.roles, plan.roles[0]] });
  assert.equal(twice.channels.length, plan.channels.length);
  assert.equal(twice.roles.length, plan.roles.length);
  const guild = { id: "1", name: "Club", admin: true };
  const open = openingOnce({ bot_name: "b", app_id: "1", member_intent: true, content_intent: true, invite: "x", guilds: [guild, guild, { ...guild, id: "2" }] });
  assert.deepEqual(open.guilds.map((g) => g.id), ["1", "2"], "two of one name are two");
});

test("undefined and null come to the same, from either backend", () => {
  // Browser wasm gives undefined for None, the desktop null
  const fromWasm = { ...run(1), finished_at: undefined, undone_at: undefined };
  assert.equal(moveRuns([fromWasm])[0].finished_at, null);
  assert.equal(moveRuns([fromWasm])[0].undone_at, null);
  assert.equal(runState(moveRuns([fromWasm])[0]), "Did not finish");
  const bare = { ...account(1), dc_id: undefined, expires_at: undefined } as unknown as MoveAccount;
  assert.equal(moveAccounts([bare])[0].dc_id, "");
  assert.equal(moveAccounts([bare])[0].expires_at, 0);
});

test("a Discord id stays exact on the way through a page of them", () => {
  const big = "1454987148113234751";
  const rows = excludedRows([], [[big, false, true, 5], ["1454987148113234752", false, true, 5]]);
  assert.deepEqual(rows.map((r) => r.id), [big, "1454987148113234752"]);
  assert.equal(discordId(big), big);
});

test("N of M signed in, the banned being nobody who can", () => {
  assert.equal(signedInLine({ claimed: 412, waiting: 1118 }), "412 of 1,530 signed in");
  assert.equal(signedInLine({ claimed: 0, waiting: 0 }), "0 of 0 signed in");
});

test("when a waiting account goes", () => {
  const now = Date.UTC(2026, 10, 4);
  assert.equal(expiryText(0, now), "Stays until someone removes it");
  assert.equal(expiryText(now / 1000 - 1, now), "Goes at the next sweep");
  assert.match(expiryText(now / 1000 + 86_400, now, "en-US"), /^Goes on 11\/\d+\/2026$/);
});

test("the filter names each state, and a chip goes with what the move knows", () => {
  assert.deepEqual(MOVE_FILTERS.map(([v]) => v), ["All", "Waiting", "Claimed", "Banned"]);
  assert.equal(canLiftBan({ state: "Banned", dc_id: "1003" }), true);
  assert.equal(canLiftBan({ state: "Banned", dc_id: "" }), false, "the id only reaches `*`, who alone may lift it");
  assert.equal(canLiftBan({ state: "Waiting", dc_id: "1003" }), false);
  assert.equal(moveChip("NotImported"), null);
  assert.equal(moveChip("Waiting"), "Waiting to sign in");
  assert.equal(moveChip("Claimed"), "Signed in");
  assert.equal(moveChip("Banned"), "Banned on Discord");
});

test("the Banned filter is for `*` alone", () => {
  assert.deepEqual(moveFiltersFor(true).map(([v]) => v), ["All", "Waiting", "Claimed", "Banned"]);
  assert.deepEqual(moveFiltersFor(false).map(([v]) => v), ["All", "Waiting", "Claimed"]);
});

test("the question before deleting a channel says who may", () => {
  assert.match(channelDeleteWords(true, false), /takes an admin/);
  assert.doesNotMatch(channelDeleteWords(true, false), /anything imported/);
  assert.match(channelDeleteWords(true, true), /anything imported into it from Discord/);
  assert.doesNotMatch(channelDeleteWords(false, true), /Discord/);
});

test("a run says what it is", () => {
  assert.equal(runState(run(1)), "Finished");
  assert.equal(runState(run(1, { finished_at: null })), "Did not finish");
  assert.equal(runState(run(1, { undone_at: 5 })), "Undone");
  assert.equal(runState(run(1, { undone_at: 5, clearing: true })), "Being undone");
});

test("Undo goes newest first, for that guild, past nothing already undone", () => {
  const runs = [run(5), run(4, { guild_id: "other" }), run(3), run(2, { undone_at: 9 }), run(1)];
  assert.deepEqual(undoChain(runs, 3), [5, 3]);
  assert.deepEqual(undoChain(runs, 1), [5, 3, 1], "an undone one in between is not asked for again");
  assert.deepEqual(undoChain(runs, 5), [5]);
  assert.deepEqual(undoChain(runs, 99), []);
  // One left halfway is still to finish, before an older one
  assert.deepEqual(undoChain([run(3, { undone_at: 9, clearing: true }), run(1)], 1), [3, 1]);
});

test("what Undo takes is said before it goes, and adds up over a chain", () => {
  const one = counts({ channels: 412, live_posts: 5, groups: 268, placeholders: 1118, claimed_kept: 412, archive_rows: 2_100_000, emotes: 300 });
  const said = undoSays([one]);
  assert.match(said, /412 channels and everything written in them since \(5 posts\)/);
  assert.match(said, /268 groups/);
  assert.match(said, /1,118 unclaimed accounts/);
  assert.match(said, /about 2,100,000 imported messages/);
  assert.match(said, /300 emotes/);
  assert.match(said, /412 people who claimed keep their accounts and lose those groups/);
  assert.match(undoSays([counts({ claimed_kept: 1 })]), /1 person who claimed keeps their account and loses those groups/);
  assert.match(undoSays([counts({ channels: 1 }), counts({ channels: 2 })]), /3 channels/);
  assert.match(undoSays([counts({ channels: 1 }), counts()]), /That is 2 runs, newest first/);
  assert.match(undoSays([counts()]), /nothing left of it to take/);
});

test("Undo does not promise a copy the server may never have made", () => {
  const said = undoSays([counts()]);
  assert.match(said, /a copy from before the run, if you still have one, has the rest/);
  assert.doesNotMatch(said, /the copy made before the run/, "there is none on Postgres, and only the last two on SQLite");
});

test("an undo says a delta's changes to an earlier run's groups stay, only when one stands", () => {
  assert.doesNotMatch(undoSays([counts()]), /earlier run's groups/);
  assert.match(undoSays([counts()], true), /who holds an earlier run's groups stays, so check your gates afterwards/);
  const runs = [run(5), run(3, { undone_at: 9 }), run(2, { guild_id: "other" }), run(1)];
  assert.equal(earlierStands(runs, 5), true, "run 1 stands");
  assert.equal(earlierStands(runs, 1), false, "the first: nothing before it");
  assert.equal(earlierStands([run(5), run(3, { undone_at: 9 })], 5), false, "one undone stands no more");
  assert.equal(earlierStands([run(5), run(3, { undone_at: 9, clearing: true })], 5), false, "nor one going");
  assert.equal(earlierStands([run(5), run(2, { guild_id: "other" })], 5), false, "another server's says nothing of this one");
  assert.equal(earlierStands(runs, 99), false);
});

test("one call says what it did, and the panel adds them up", () => {
  const reply = { run: 1, more: true, accounts: 500, kept_claimed: 2, groups: 1, groups_kept: ["crew"], channels: 16, emotes: 0, archive_rows: 9 };
  const total = addUndone(addUndone(NO_UNDO, reply), { ...reply, groups_kept: ["crew", "ops"] });
  assert.equal(total.accounts, 1000);
  assert.equal(total.channels, 32);
  assert.deepEqual(total.groups_kept, ["crew", "ops"]);
  assert.match(undoneLine(total), /32 channels, 1,000 accounts, 2 groups, 0 emotes gone/);
  assert.match(undoneLine(total), /a gate elsewhere uses them: crew, ops/);
  assert.equal(NO_UNDO.accounts, 0, "the start is not written to");
});

test("what a person left out says", () => {
  assert.match(excludedLine({ own: true, erase: true }), /stays out for good/);
  assert.match(excludedLine({ own: false, erase: true }), /their posts deleted/);
  assert.match(excludedLine({ own: false, erase: false }), /their posts stay/);
});

test("a stored report that is no report shows nothing rather than failing", () => {
  assert.deepEqual(storedReport('{"counts":{"channels":3,"x":"y"},"notes":["a",1]}'), { counts: [["channels", 3]], notes: ["a"] });
  assert.deepEqual(storedReport("not json"), { counts: [], notes: [] });
  assert.deepEqual(storedReport("null"), { counts: [], notes: [] });
});

// ── The toggles ────────────────────────────────────────────────────────────

test("what needs what, as `plan::effective` has it", () => {
  const off = (key: keyof ImportOptions) => effectiveOptions({ ...allOn, [key]: false });
  assert.equal(off("channels").messages, false, "messages need channels");
  assert.equal(off("channels").permissions, false, "permissions need channels");
  assert.equal(off("channels").threads, false, "and what messages take goes with them");
  assert.equal(off("messages").threads, false);
  assert.equal(off("messages").pins, false);
  assert.equal(off("messages").reactions, false);
  assert.equal(off("messages").channels, true, "the other way it does not");
  assert.equal(off("threads").pins, true);
  assert.equal(off("roles").members, true);
  // The Rust side says the same, in the words this table copies
  const rust = readFileSync(join(import.meta.dirname, "../../../crates/voipc-import/src/plan.rs"), "utf8");
  for (const line of ["o.messages &= o.channels", "o.permissions &= o.channels", "o.threads &= o.messages", "o.pins &= o.messages", "o.reactions &= o.messages"]) {
    assert.ok(rust.includes(line), line);
  }
});

test("a toggle says why it cannot be on", () => {
  assert.equal(toggleBlock("messages", { ...allOn, channels: false }, []), "Needs channels.");
  assert.equal(toggleBlock("permissions", { ...allOn, channels: false }, []), "Needs channels.");
  assert.equal(toggleBlock("threads", { ...allOn, messages: false }, []), "Needs messages.");
  assert.equal(toggleBlock("pins", { ...allOn, channels: false }, []), "Needs messages.");
  assert.equal(toggleBlock("messages", allOn, []), null);
  assert.equal(toggleBlock("messages", allOn, [{ toggle: "messages", text: "Message Content is off" }]), "Message Content is off");
  assert.equal(toggleBlock("roles", allOn, [{ toggle: "messages", text: "x" }]), null);
});

test("every toggle has a row, and the tick is not one of them", () => {
  const keys = TOGGLES.map((t) => t.key).sort();
  assert.deepEqual(keys, Object.keys(allOn).filter((k) => k !== "acknowledged").sort());
  assert.equal(new Set(keys).size, keys.length, "a keyed each goes over them");
});

test("private ticks start off, and the rest as the dry-run says", () => {
  const c = startChoices(plan);
  const staff = plan.channels.find((ch) => ch.name === "staff")!;
  const lounge = plan.channels.find((ch) => ch.name === "lounge" && ch.type === 0)!;
  assert.ok(staff.private);
  assert.ok(!c.messagesOn.has(staff.id), "a private channel's history needs its tick");
  assert.ok(!c.leftOut.has(staff.id));
  assert.ok(c.messagesOn.has(lounge.id));
  // A channel @everyone could see but not read back, too
  const old = plan.channels.find((ch) => ch.name === "old-logs")!;
  assert.ok(!old.private && !c.messagesOn.has(old.id));
  assert.equal(c.options.acknowledged, false);
});

test("a delta starts from last time, and never with the tick given", () => {
  const delta: Plan = {
    ...plan,
    options: { ...allOn, bans: false, acknowledged: true },
    channels: plan.channels.map((ch, i) => (i === 0 ? { ...ch, left_out: true, left_out_why: "Left out last time.", messages_on: false } : ch)),
  };
  const c = startChoices(delta);
  assert.equal(c.options.bans, false);
  assert.equal(c.options.acknowledged, false, "acknowledged always starts false");
  assert.ok(c.leftOut.has(plan.channels[0].id));
});

test("a toggle the dry-run blocks starts off", () => {
  const c = startChoices({ ...plan, blocks: [{ toggle: "messages", text: "Message Content is off" }] });
  assert.equal(c.options.messages, false);
  assert.equal(c.options.roles, true);
});

test("Run stays shut until the tick while messages are on", () => {
  const c = startChoices(plan);
  assert.match(beginBlock(c, plan, facts(), false, false) ?? "", /Tick what copying messages means/);
  assert.equal(beginBlock(c, plan, facts(), true, false), null);
  // With messages off there is nothing to acknowledge
  const off = { ...c, options: { ...c.options, messages: false } };
  assert.equal(beginBlock(off, plan, facts(), false, false), null);
  // Nor when channels are off, which takes messages with them
  const none = { ...c, options: { ...c.options, channels: false } };
  assert.equal(beginBlock(none, plan, facts(), false, false), null);
});

test("what else keeps Run shut", () => {
  const c = startChoices(plan);
  assert.match(beginBlock(c, { ...plan, blocks: [{ toggle: "run", text: "Nobody could claim anything" }] }, facts(), true, true) ?? "", /Nobody could claim/);
  assert.match(beginBlock(c, plan, facts({ running: 3 }), true, true) ?? "", /Another admin/);
  assert.match(beginBlock(c, plan, facts({ cloud: false }), true, true) ?? "", /cloud = true/);
  assert.equal(beginBlock({ ...c, options: { ...c.options, messages: false } }, plan, facts({ cloud: false }), false, false), null);
  // Postgres: the operator says so
  assert.match(beginBlock(c, plan, facts({ backup_here: false }), true, false) ?? "", /copy of the database/);
  assert.equal(beginBlock(c, plan, facts({ backup_here: false }), true, true), null);
  // null and undefined: no run is on
  assert.equal(beginBlock(c, plan, facts({ running: null }), true, false), null);
});

test("what is sent keeps what needs what, and ids as strings", () => {
  const c = startChoices(plan);
  c.options.channels = false;
  const sent = optionsToSend(c, true);
  assert.equal(sent.messages, false);
  assert.equal(sent.acknowledged, true);
  const choices = choicesToSend(startChoices(plan), true);
  assert.ok(choices.messages_on.every((id) => typeof id === "string"));
  assert.ok(Array.isArray(choices.left_out));
  // No number here could hold one of these
  assert.doesNotMatch(JSON.stringify(choices), /:\s*\d{16,}/);
});

test("the acknowledgement says what it must", () => {
  assert.match(ACKNOWLEDGEMENT, /which can read them/);
  assert.match(ACKNOWLEDGEMENT, /scraping our services without our written consent/);
  assert.match(ACKNOWLEDGEMENT, /This is not legal advice/);
});

test("ids typed in a box", () => {
  assert.deepEqual(discordIds("1190000000000001001\n 1190000000000001002,\n\n1190000000000001001"), {
    ids: ["1190000000000001001", "1190000000000001002"],
    bad: [],
  });
  assert.deepEqual(discordIds("dan#1234 12"), { ids: ["12"], bad: ["dan#1234"] });
  // 0 would mean "whoever wrote it" on the relay, and past i64 fits no row
  assert.deepEqual(discordIds("0"), { ids: [], bad: ["0"] });
  assert.deepEqual(discordIds("9223372036854775808"), { ids: [], bad: ["9223372036854775808"] });
  assert.deepEqual(discordIds("9223372036854775807").ids, ["9223372036854775807"]);
  assert.equal(discordId("12 13"), null);
  assert.equal(discordId(""), null);
  assert.equal(discordId("12x"), null);
});

test("sizes, times and progress in words", () => {
  assert.equal(humanBytes(512), "512 bytes");
  assert.equal(humanBytes(1536), "1.5 KiB");
  assert.equal(humanTime(30), "30 seconds");
  assert.equal(humanTime(600), "10 minutes");
  assert.equal(humanTime(7200), "2 hours");
  assert.equal(humanTime(259_200), "3 days");
  assert.match(estimateLine({ messages: 1000, at_least: true, requests: 1, secs_low: 60, secs_high: 120, bytes: 2048 }), /^at least 1,000 messages/);
  assert.equal(progressLine({ phase: "messages", done: 12, total: 40, channel: "lounge" }), "Messages: 12 of 40, lounge");
  assert.equal(progressLine({ phase: "starting", done: 0, total: 0, channel: "" }), "Starting: 0");
});

test("the post says what happened to the messages", () => {
  const text = movePostText("https://voipc.example:9987", { messages: true, members: true });
  assert.match(text, /Join here: https:\/\/voipc\.example:9987/);
  assert.match(text, /your name and groups are waiting/);
  assert.match(text, /Whoever runs that server can read it/);
  assert.match(text, /Direct messages and files do not move/);
  assert.doesNotMatch(text, /New here/);
  assert.ok(postable(text));
  assert.ok(!postable(""));
  assert.ok(postable("x".repeat(2000)));
  assert.ok(!postable("x".repeat(2001)));
});

test("the post says only what this run did", () => {
  const off = movePostText("x", { messages: false, members: true });
  assert.doesNotMatch(off, /message history|can read it/, "no messages came");
  assert.match(off, /your name and groups are waiting/);
  const none = movePostText("x", { messages: true, members: false });
  assert.doesNotMatch(none, /waiting/, "no accounts wait");
  assert.match(none, /Choose \*Continue with Discord\*\./);
  assert.match(none, /can read it/);
});

test("a post's history needs a channel whose messages came", () => {
  const choices = (messages: boolean, leftOut: string[], messagesOn: string[]) =>
    ({ options: { channels: true, messages } as never, leftOut: new Set(leftOut), messagesOn: new Set(messagesOn) });
  assert.ok(messagesCame(choices(true, [], ["1"])));
  assert.ok(messagesCame(choices(true, ["2"], ["1", "2"])), "one left out, one still coming");
  assert.ok(!messagesCame(choices(true, [], [])), "every channel's messages off");
  assert.ok(!messagesCame(choices(true, ["1"], ["1"])), "the only one ticked is left out");
  assert.ok(!messagesCame(choices(false, [], ["1"])), "the toggle off");
  assert.ok(!messagesCame({ options: { channels: false, messages: true } as never, leftOut: new Set(), messagesOn: new Set(["1"]) }), "needs channels");
});

test("a list that stopped says who and how many", () => {
  assert.equal(idsBackLine(null, 3), "3 ids were not sent: they are back in the box.");
  assert.equal(idsBackLine(null, 1), "1 id was not sent: it is back in the box.");
  const refused = { id: "11", reason: "They have opened their account." };
  assert.equal(idsBackLine(refused, 2), "Discord id 11 was refused. They have opened their account. 2 ids were not sent: they are back in the box.");
  assert.equal(idsBackLine(refused, 0), "Discord id 11 was refused. They have opened their account.");
});

test("an undo that stopped says how many runs did not finish, and why if the connection went", () => {
  assert.equal(undoLeftLine({ runs: [5, 3], cut: false }), "Undo stopped with 2 runs not finished. Each run's row says how far it got.");
  assert.equal(undoLeftLine({ runs: [3], cut: true }), "The connection to the server was lost. Undo stopped with 1 run not finished. Each run's row says how far it got.");
});

test("the Users tab asks again when the dashboard's page takes the place of its own", () => {
  const own = ownPage<{ filter: "All" | "Waiting" | "Claimed" | "Banned"; offset: number }>();
  const all = { filter: "All" as const, offset: 100 };
  const dashboards = { filter: "Waiting" as const, offset: 0 };
  assert.equal(own.page(dashboards), null, "nothing asked for yet");
  own.asking(all);
  assert.equal(own.page(dashboards), null, "its own is on its way, and will take the place of that");
  assert.equal(own.page({ ...all }), null, "its own");
  assert.equal(own.page({ ...all }), null, "and again");
  assert.equal(own.page(dashboards), all, "the dashboard's: the same page again");
  // The answer ends it: no loop, however long it goes on
  assert.equal(own.page({ ...all }), null);
  assert.equal(own.page({ ...all }), null);
});

// W2-33
test("the dashboard's first page of a filter is not a search or a later page of it", () => {
  const own = ownPage<{ search: string; offset: number; filter: "All" | "Waiting" }>();
  const searched = { search: "ann", offset: 0, filter: "Waiting" as const };
  own.asking(searched);
  assert.equal(own.mine({ ...searched }), true);
  assert.equal(own.page({ ...searched }), null);
  const dashboards = { search: "", offset: 0, filter: "Waiting" as const };
  assert.equal(own.mine(dashboards), false, "not shown under the search");
  assert.deepEqual(own.page(dashboards), searched, "and asked again");
  const later = { search: "", offset: 50, filter: "Waiting" as const };
  own.asking(later);
  own.page({ ...later });
  assert.equal(own.mine(dashboards), false);
  assert.deepEqual(own.page(dashboards), later);
});

test("asked again once, whatever comes meanwhile, and never for an answer of another filter", () => {
  const own = ownPage<{ filter: "All" | "Waiting" }>();
  own.asking({ filter: "All" });
  own.page({ filter: "All" });
  assert.ok(own.page({ filter: "Waiting" }));
  // A relay that never answers with what was asked for cannot make this go round
  for (let i = 0; i < 5; i++) assert.equal(own.page({ filter: "Waiting" }), null);
});

test("a change of filter asks once: the old filter's answer on its way is no reason to ask again", () => {
  const own = ownPage<{ filter: "All" | "Banned" }>();
  own.asking({ filter: "All" });
  own.asking({ filter: "Banned" });
  assert.equal(own.page({ filter: "All" }), null);
  assert.equal(own.page({ filter: "Banned" }), null);
  // With nothing on its way it would: the control
  assert.ok(own.page({ filter: "All" }));
});

test("while the plain list is shown there is nothing to ask again for", () => {
  const own = ownPage<{ filter: "All" }>();
  own.asking({ filter: "All" });
  own.page({ filter: "All" });
  own.asking(null);
  assert.equal(own.page({ filter: "Waiting" } as never), null);
});

test("the link for newcomers comes and goes, and nothing else of the post moves", () => {
  const link = "https://voipc.example:9987/#join=abc";
  const start = movePostText("x", { messages: true, members: true });
  const edited = start.replace("We are moving to VoIPC.", "We have moved.");
  const withLink = withJoinLine(edited, link);
  assert.match(withLink, /We have moved\./, "the edit stays");
  assert.deepEqual(withLink.split("\n").slice(3, 5), ["Choose *Continue with Discord*: your name and groups are waiting.", `New here? ${link}`]);
  assert.equal(withJoinLine(withLink, null), edited);
  // A newer link takes the place of the last, and one line stays one line
  assert.equal(withJoinLine(withLink, `${link}2`).match(/New here/g)?.length, 1);
  assert.match(withJoinLine(withLink, `${link}2`), /#join=abc2/);
  // Someone took the line it goes under
  assert.equal(withJoinLine("Just this", link), `Just this\nNew here? ${link}`);
});

test("only a code that came after the ask is the new link", () => {
  assert.equal(newLinkCode("old", "old"), null, "left from the Users tab: 10 people for a day, say");
  assert.equal(newLinkCode(null, "old"), null);
  assert.equal(newLinkCode("new", "old"), "new");
  assert.equal(newLinkCode("new", null), "new");
});

test("a post starts where it can go", () => {
  const rules = plan.channels.find((c) => c.name === "general")!;
  const secret = plan.channels.find((c) => c.name === "staff")!;
  assert.equal(postChannelOf({ ...plan, guild: { ...plan.guild, post_channel: rules.id } }), rules.id);
  const first = postChannels(plan)[0].id;
  assert.equal(postChannelOf({ ...plan, guild: { ...plan.guild, post_channel: secret.id } }), first, "not a private one: the picker would be blank, and the post go there");
  assert.equal(postChannelOf({ ...plan, guild: { ...plan.guild, post_channel: null } }), first);
  assert.equal(postChannelOf({ ...plan, channels: [] }), "");
});

test("a row that came in an earlier run does not read as if Discord's gate were the relay's", () => {
  const row = { in_ledger: true, see: { open: false, roles: ["Crew"] }, bot_can_read: true };
  assert.match(gateHereLine(row), /Its gate here stays as it is/);
  // The controls: a new private channel takes the gate worked out, one open on Discord is
  // not the relay's to refuse, and what the bot cannot read does not come anyway
  assert.equal(gateHereLine({ ...row, in_ledger: false }), "");
  assert.equal(gateHereLine({ ...row, see: { open: true, roles: [] } }), "");
  assert.equal(gateHereLine({ ...row, bot_can_read: false }), "");
  for (const ch of plan.channels) assert.equal(gateHereLine(ch), "", ch.name);
});

test("a post goes where people can read it", () => {
  const names = postChannels(plan).map((c) => c.name);
  assert.ok(names.includes("general"));
  assert.ok(names.includes("news"), "an announcement channel is text");
  assert.ok(!names.includes("staff"), "not a private one");
  assert.ok(!names.includes("townhall"), "not a stage");
});

test("a page of bans: offset 0 starts again, the rest go on, each id once", () => {
  const ban = (id: number) => ({ id, account: false, label: `person-${id}`, reason: "", by: "", created_at: 0, expires_in_secs: null });
  const page = (offset: number, bans: ReturnType<typeof ban>[]) => ({ search: "", offset, total: 9, bans });
  const ids = (rows: { id: number }[]) => rows.map((r) => r.id);
  const first = mergeBanPage([], page(0, [ban(1), ban(2)]));
  assert.deepEqual(ids(first), [1, 2]);
  assert.deepEqual(ids(mergeBanPage(first, page(2, [ban(3)]))), [1, 2, 3]);
  // A ban made between two pages moves the list down one, so a row comes twice
  assert.deepEqual(ids(mergeBanPage(first, page(2, [ban(2), ban(3)]))), [1, 2, 3]);
  // And a page can repeat itself
  assert.deepEqual(ids(mergeBanPage([], page(0, [ban(1), ban(1)]))), [1]);
  assert.deepEqual(ids(mergeBanPage(first, page(0, [ban(4)]))), [4], "a new first page replaces");
});

test("the guide prints the acknowledgement word for word, and links the same policy", () => {
  const guide = readFileSync(join(import.meta.dirname, "../../../docs/MOVING.md"), "utf8");
  assert.ok(guide.includes(ACKNOWLEDGEMENT));
  assert.ok(guide.includes(POLICY_URL));
});

test("the guides say what the move and the relay's copies really do", () => {
  const read = (file: string) => readFileSync(join(import.meta.dirname, "../../..", file), "utf8");
  // The guides wrap mid-sentence: an old sentence over two lines would pass as gone
  const flat = (text: string) => text.replace(/\s+/g, " ");
  const [moving, operating, accounts, threats, readme] = ["docs/MOVING.md", "docs/OPERATING.md", "docs/ACCOUNTS.md", "docs/THREAT-MODEL.md", "README.md"].map(read);

  // The notice's own fence, so words elsewhere in the guide cannot pass for it
  const notice = flat(moving.slice(moving.indexOf("## Tell your members first")).split("```")[1]);
  for (const words of ["join dates", "roles", "banned", "names you"]) assert.ok(notice.includes(words), words);

  assert.ok(moving.slice(moving.indexOf("## When you are done")).includes("before-import"));
  assert.ok(flat(moving).includes("Restoring a copy forgets"));
  assert.ok(flat(moving).includes("what they wrote, not what others wrote about them"));
  const timer = operating.slice(operating.indexOf("voipc-backup.service")).split("```")[0];
  assert.match(timer, /before-/, "the sample timer takes the relay's copies too");

  const guides = [moving, operating, accounts, readme].map(flat).join(" ");
  for (const gone of ["holds them until it ages out", "until they age out", "still holds their posts until it ages out", "The full list is in the README", "What it kept is gone"]) {
    assert.ok(!guides.includes(gone), gone);
  }

  // Exactly these two lines, so a rewording cannot pass by leaving the test nothing to check
  const promises = readme.split("\n").filter((l) => /never\*\* stores readable|No server-side message logs/.test(l));
  assert.equal(promises.length, 2);
  for (const line of promises) assert.ok(line.includes("Discord"), line);

  const kept = readme.slice(readme.indexOf("### What a server with accounts keeps"), readme.indexOf("### What your device stores"));
  for (const words of ["display name", "provider's id", "join date"]) assert.ok(kept.includes(words), words);

  const row = threats.split("\n").find((l) => l.includes("about who holds privileges"));
  assert.ok(row?.includes("holders_are_told_on_change_and_to_whoever_arrives"), "who may call on everybody is told");
});
