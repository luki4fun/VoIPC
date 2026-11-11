// The Discord move's store: the wizard's way through, what goes out and in what order,
// and what must never be kept.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const {
  excludedNextPage,
  excludedPage,
  excludeIds,
  excludeOne,
  moveRefresh,
  moveRefused,
  moveStatus,
  moveStepEnded,
  moveUndo,
  moveUndoLeft,
  moveWizard,
  onImportEnded,
  onMoveReply,
  powerAnswer,
  undoCarryOn,
  undoStart,
  wizardBegin,
  wizardCut,
  wizardForget,
  wizardGoOn,
  wizardOpen,
  wizardRead,
  wizardStart,
} = await import("./move.ts");
const { pendingConfirm } = await import("./confirm.ts");
const { adminError, adminRead, codeAskedAgain, isRemoval, lastOp, removalWithCode, stepUp, stepUpCancelled, stepUpSays } = await import("./admin-ops.ts");
const { connectionState } = await import("./connection.ts");
const { dropKept, dropServer } = await import("./scoped.ts");
const { NO_TOKEN } = await import("../move-rules.ts");

const S = "h.example:9987";
const plan = JSON.parse(readFileSync(join(import.meta.dirname, "../../../../testkit/6-mock-discord/plan.json"), "utf8"));

/** The steps sent, numbered (`AdminAsk`, protocol v22) or not. */
const asks = () =>
  invoked()
    .filter(([c]: [string]) => c === "account_request")
    .map(([, a]: [string, { request: { Admin?: { op: unknown }; AdminAsk?: { op: unknown } } }]) => (a.request.AdminAsk ?? a.request.Admin)!.op);
const sent = (cmd: string) => invoked().filter(([c]: [string]) => c === cmd).map(([, a]: [string, unknown]) => a);
const wizard = () => get(moveWizard.peek(S));
const facts = { backup_here: true, cloud: true, public_url: "https://x", discord_sign_in: true };

/** What `invoke` answers, for a test that needs an answer of its own. */
const answers = globalThis as unknown as { __answer?: (command: string, args: { token?: string }) => unknown };

function fresh() {
  dropServer(S);
  dropKept(S);
  invoked().length = 0;
  lastOp.delete(S);
  removalWithCode.delete(S);
  answers.__answer = undefined;
}

const run = (id: number, over: object = {}) => ({
  id,
  guild_id: "1",
  by: "annika",
  started_at: 1,
  finished_at: 2,
  accounts: 0,
  groups: 0,
  clearing: false,
  ...over,
});
const status = (runs: object[]) => ({
  Admin: { MoveStatus: { claimed: 0, waiting: 0, banned: 0, power_waiting: 0, excluded: 0, unclaimed_days: 90, runs } },
});
const undone = (id: number, more: boolean, over: object = {}) => ({
  Admin: { ImportUndone: { run: id, more, accounts: 0, kept_claimed: 0, groups: 0, groups_kept: [], channels: 0, emotes: 0, archive_rows: 0, ...over } },
});
const counts = { channels: 1, live_posts: 0, groups: 0, placeholders: 0, claimed_kept: 0, archive_rows: 0, emotes: 0, later_runs: 0 };

/** Answers the question Undo asks, once it has been put. */
async function answerConfirm(yes: boolean) {
  await new Promise((r) => setTimeout(r, 0));
  const open = get(pendingConfirm);
  assert.ok(open, "the question is up");
  open.resolve(yes, false);
  pendingConfirm.set(null);
  await new Promise((r) => setTimeout(r, 0));
}

test("the token goes to the command and stops there", async () => {
  fresh();
  wizardStart(S);
  await wizardOpen(S, "secret-token");
  assert.deepEqual(sent("import_open"), [{ server: S, token: "secret-token" }]);
  assert.doesNotMatch(JSON.stringify(wizard()), /secret-token/, "not in what the wizard holds");
});

test("a run needs its dry-run, its choices and then the code", async () => {
  fresh();
  wizardStart(S);
  moveWizard.of(S).update((w) => ({ ...w, step: "pick", guild: "1190000000000000001" }));
  wizardRead(S);
  assert.equal(wizard().step, "reading");
  assert.deepEqual(asks(), ["ImportFacts"]);
  // `invoke` is a stand-in that answers nothing, so there is no plan to go on with: as
  // when Discord refuses, the wizard goes back a step
  onMoveReply(S, { Admin: { ImportFacts: { facts } } });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(sent("import_plan"), [{ server: S, guild: "1190000000000000001" }]);
});

function atChoose() {
  moveWizard.of(S).update((w) => ({
    ...w,
    step: "choose",
    guild: "1190000000000000001",
    plan,
    facts: facts as never,
    choices: {
      options: { ...plan.options },
      leftOut: new Set(["1190000000000000210"]),
      messagesOn: new Set(["1190000000000000211"]),
    },
    acknowledged: true,
  }));
}

test("the guild is a string on the wire, and what was left out stays here", async () => {
  fresh();
  atChoose();
  wizardBegin(S);
  const begin = asks()[0] as { ImportBegin: { guild_id: string; options: { acknowledged: boolean } } };
  assert.equal(begin.ImportBegin.guild_id, "1190000000000000001");
  assert.equal(begin.ImportBegin.options.acknowledged, true);
  assert.doesNotMatch(JSON.stringify(begin), /1190000000000000210|1190000000000000211/, "nothing about a channel reaches the relay");
  assert.equal(wizard().step, "beginning");
});

test("ImportBegun is what counts: the run starts on it with the page's choices", async () => {
  fresh();
  atChoose();
  wizardBegin(S);
  onMoveReply(S, { Admin: { ImportBackingUp: { run: 4 } } });
  assert.equal(wizard().step, "beginning");
  assert.equal(wizard().backingUp, true);
  assert.deepEqual(sent("import_run"), [], "a label only");
  onMoveReply(S, { Admin: { ImportBegun: { run: 4, resumed: false, backup: "/srv/voipc.before-import-4" } } });
  await new Promise((r) => setTimeout(r, 0));
  const [call] = sent("import_run") as { run: number; choices: { left_out: string[]; messages_on: string[]; options: { acknowledged: boolean } } }[];
  assert.equal(call.run, 4);
  assert.deepEqual(call.choices.left_out, ["1190000000000000210"]);
  assert.deepEqual(call.choices.messages_on, ["1190000000000000211"]);
  assert.equal(call.choices.options.acknowledged, true);
  assert.equal(wizard().backup, "/srv/voipc.before-import-4");
});

test("an ImportBegun nobody asked for here starts nothing", async () => {
  fresh();
  onMoveReply(S, { Admin: { ImportBegun: { run: 4, resumed: false } } });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(sent("import_run"), []);
  assert.equal(wizard().step, "idle");
});

test("nor does one while the page is still choosing", async () => {
  fresh();
  atChoose();
  onMoveReply(S, { Admin: { ImportBegun: { run: 4, resumed: false } } });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(sent("import_run"), []);
  assert.equal(wizard().step, "choose");
});

test("a refused begin, or a code not given, goes back to the choices", () => {
  fresh();
  atChoose();
  wizardBegin(S);
  onMoveReply(S, { Error: { request: "Admin", reason: "Still clearing the last undo." } });
  assert.equal(wizard().step, "choose");
  wizardBegin(S);
  moveStepEnded(S);
  assert.equal(wizard().step, "choose");
  assert.ok(wizard().plan, "with everything chosen still there");
});

test("going on after a stop keeps the choices, and asks for the tick again", () => {
  fresh();
  atChoose();
  const { choices } = wizard();
  moveWizard.of(S).update((w) => ({ ...w, step: "ended", ended: { run: 4, stopped: "You stopped it.", notes: [] } }));
  wizardGoOn(S);
  assert.equal(wizard().step, "choose");
  assert.equal(wizard().choices, choices);
  assert.equal(wizard().acknowledged, false);
  assert.equal(wizard().ended, null);
});

test("while a run goes the page asks none of what the driver asks", () => {
  fresh();
  moveWizard.of(S).update((w) => ({ ...w, step: "running" }));
  moveRefresh(S);
  moveWizard.of(S).update((w) => ({ ...w, step: "reading" }));
  moveRefresh(S);
  assert.deepEqual(asks(), []);
  moveWizard.of(S).update((w) => ({ ...w, step: "ended" }));
  moveRefresh(S);
  assert.deepEqual(asks(), [
    "MoveStatus",
    { PowerWaiting: { offset: 0 } },
    { MoveAccounts: { search: "", offset: 0, filter: "Waiting" } },
    { MoveExcluded: { after: "" } },
  ]);
});

test("reads leave the step that waits for a code alone", () => {
  fresh();
  excludeOne(S, "5", true, true);
  const out = lastOp.get(S);
  adminError.of(S).set("That code was wrong.");
  moveRefresh(S);
  assert.equal(lastOp.get(S), out, "a StepUp still out answers the step, not a read");
  assert.equal(get(adminError.peek(S)), "That code was wrong.");
});

test("forgetting tells the machine, and leaves nothing here", () => {
  fresh();
  atChoose();
  wizardForget(S);
  assert.deepEqual(sent("import_forget"), [{ server: S }]);
  assert.equal(wizard().step, "idle");
  assert.equal(wizard().plan, null);
  assert.equal(wizard().choices, null);
});

test("ids left out go one at a time, each waiting for the last", () => {
  fresh();
  excludeIds(S, ["11", "12", "13"]);
  assert.deepEqual(asks(), [{ MoveExclude: { dc_id: "11", on: true, erase: true } }], "a StepUp is about the step sent last");
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["11", false, true, 1]], more: false } } });
  assert.deepEqual(asks()[1], { MoveExclude: { dc_id: "12", on: true, erase: true } });
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["11", false, true, 1], ["12", false, true, 1]], more: false } } });
  assert.deepEqual(asks()[2], { MoveExclude: { dc_id: "13", on: true, erase: true } });
  invoked().length = 0;
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [], more: false } } });
  assert.equal(asks()[0], "MoveStatus", "and at the end the dashboard is read afresh");
});

// W2-30
test("a refused read of the left-out list does not take the next exclusion's answer", () => {
  fresh();
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["11", false, true, 1]], more: true } } });
  excludedNextPage(S);
  onMoveReply(S, { Error: { request: "Admin", reason: "Too many requests." } });
  excludeIds(S, ["21"]);
  invoked().length = 0;
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["21", false, true, 1]], more: false } } });
  assert.deepEqual(wizard().leaving, [], "answered, not left at Sending");
  assert.equal(asks()[0], "MoveStatus", "and the dashboard read afresh");
});

test("a refused one stops the rest", () => {
  fresh();
  excludeIds(S, ["11", "12"]);
  onMoveReply(S, { Error: { request: "Admin", reason: "They have opened their account: they can delete it themselves." } });
  invoked().length = 0;
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [], more: false } } });
  assert.deepEqual(asks(), []);
  // And it does not come back with the next person's
  excludeOne(S, "20", true, false);
  invoked().length = 0;
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [], more: false } } });
  assert.ok(!asks().some((op: object) => typeof op === "object" && "MoveExclude" in op), "12 stays unsent");
});

// A wrong code: admin-ui.ts's listener and this store's take the same refusal, in no promised
// order. The first to go sees the code just sent; the other, the prompt it brought back.
const WRONG = { Error: { request: "Admin", reason: "That code is not right." } };
const eitherOrder: [string, (op: object) => void][] = [
  ["this store hears it first", (op) => removalWithCode.set(S, op)],
  ["admin-ui hears it first", (op) => stepUp.of(S).set(op)],
];

for (const [order, heard] of eitherOrder) {
  test(`a wrong code loses nobody from the list to leave out: ${order}`, () => {
    fresh();
    excludeIds(S, ["11", "12", "13"]);
    heard(lastOp.get(S));
    onMoveReply(S, WRONG);
    moveRefused(S); // The panel's effect on the error shown
    removalWithCode.delete(S);
    stepUp.of(S).set(null);
    // The prompt, the right code, and its answer
    onMoveReply(S, { Admin: { MoveExcluded: { ids: [["11", false, true, 1]], more: false } } });
    assert.deepEqual(asks().at(-1), { MoveExclude: { dc_id: "12", on: true, erase: true } }, "the second goes out");
    onMoveReply(S, { Admin: { MoveExcluded: { ids: [["12", false, true, 1]], more: false } } });
    assert.deepEqual(asks().at(-1), { MoveExclude: { dc_id: "13", on: true, erase: true } }, "and the third");
  });

  test(`a wrong code in an undo goes on through the whole chain: ${order}`, async () => {
    fresh();
    onMoveReply(S, status([run(5), run(3)]));
    undoStart(S, 3);
    onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
    onMoveReply(S, { Admin: { ImportUndoPreview: { run: 3, counts } } });
    await answerConfirm(true);
    heard(lastOp.get(S));
    onMoveReply(S, WRONG);
    moveRefused(S);
    removalWithCode.delete(S);
    stepUp.of(S).set(null);
    assert.deepEqual(get(moveUndo.peek(S))?.runs, [5, 3], "still both");
    onMoveReply(S, undone(5, false));
    assert.equal(get(moveUndo.peek(S))?.done, false, "not 'Undone' with the older run standing");
    assert.deepEqual(asks().at(-1), { ImportUndo: { run: 3 } });
  });
}

test("giving up on the prompt a wrong code brought back ends the step", () => {
  fresh();
  excludeIds(S, ["11", "12"]);
  // The wrong code's been said, and the prompt is up
  stepUp.of(S).set(lastOp.get(S));
  assert.ok(codeAskedAgain(S));
  // Its Cancel
  stepUp.of(S).set(null);
  assert.ok(!codeAskedAgain(S));
  moveRefused(S);
  invoked().length = 0;
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [], more: false } } });
  assert.deepEqual(asks(), [], "12 stays unsent");
});

// ── What a list of ids leaves behind when it does not reach its end ───────

const excluded = { Admin: { MoveExcluded: { ids: [], more: false } } };
const CUT_OFF = /connection to the server was lost/;

function boxOf(ids: string[]) {
  atChoose();
  moveWizard.of(S).update((w) => ({ ...w, idBox: ids.join("\n") }));
  excludeIds(S, ids);
}

test("the box keeps its ids until the last has its answer", () => {
  fresh();
  boxOf(["11", "12", "13"]);
  const box = wizard().idBox;
  onMoveReply(S, excluded);
  assert.equal(wizard().idBox, box, "not yet");
  onMoveReply(S, excluded);
  assert.equal(wizard().idBox, box, "nor yet");
  assert.deepEqual(wizard().leaving, ["13"]);
  onMoveReply(S, excluded);
  assert.equal(wizard().idBox, "", "the list has drained");
  assert.deepEqual(wizard().leaving, []);
  assert.equal(wizard().idsSaid, "", "and nothing to say");
});

test("a refusal names who, and the rest go back in the box, counted", () => {
  fresh();
  boxOf(["11", "12", "13", "14"]);
  onMoveReply(S, excluded);
  onMoveReply(S, { Error: { request: "Admin", reason: "They have opened their account: they can delete it themselves." } });
  assert.equal(wizard().idBox, "13\n14", "what went stays out, and so does who was refused: pressing again would hear the same");
  assert.match(wizard().idsSaid, /Discord id 12 was refused\. They have opened their account/);
  assert.match(wizard().idsSaid, /2 ids were not sent/);
  assert.deepEqual(wizard().leaving, []);
  // The next press sends what is in the box, and only that
  invoked().length = 0;
  excludeIds(S, ["13", "14"]);
  assert.equal(wizard().idsSaid, "");
  assert.deepEqual(asks(), [{ MoveExclude: { dc_id: "13", on: true, erase: true } }]);
});

test("the last one refused leaves nothing to count", () => {
  fresh();
  boxOf(["11"]);
  onMoveReply(S, { Error: { request: "Admin", reason: "Only an admin may import." } });
  assert.equal(wizard().idBox, "");
  assert.equal(wizard().idsSaid, "Discord id 11 was refused. Only an admin may import.");
});

test("a code not given puts them all back, the one asked about too", () => {
  fresh();
  boxOf(["11", "12", "13"]);
  stepUp.of(S).set(lastOp.get(S));
  // The prompt's Cancel, and the panel's effect on what it says
  stepUp.of(S).set(null);
  moveRefused(S);
  assert.equal(wizard().idBox, "11\n12\n13");
  assert.match(wizard().idsSaid, /3 ids were not sent/);
  assert.doesNotMatch(wizard().idsSaid, /refused/);
  assert.equal(wizard().error, wizard().idsSaid, "at the top too: the prompt took the panel there");
  assert.deepEqual(wizard().leaving, []);
});

test("Stop is the way out of a list nothing will answer", () => {
  fresh();
  boxOf(["11", "12"]);
  moveStepEnded(S);
  assert.equal(wizard().idBox, "11\n12");
  assert.match(wizard().idsSaid, /2 ids were not sent/);
  // Its answer, if one was on its way, starts nothing
  invoked().length = 0;
  onMoveReply(S, excluded);
  assert.ok(!asks().some((op: object) => typeof op === "object" && "MoveExclude" in op));
  assert.equal(wizard().idBox, "11\n12", "and clears nothing");
});

const cutOrders: [string, () => void][] = [
  ["what the connection held goes first", () => { dropServer(S); wizardCut(S); }],
  ["the wizard hears first", () => { wizardCut(S); dropServer(S); }],
];

for (const [order, cut] of cutOrders) {
  test(`a cut with the code asked for puts them back, and says so: ${order}`, () => {
    fresh();
    boxOf(["11", "12", "13"]);
    stepUp.of(S).set(lastOp.get(S));
    const { choices } = wizard();
    cut();
    assert.equal(wizard().step, "choose");
    assert.equal(wizard().choices, choices);
    assert.equal(wizard().idBox, "11\n12\n13");
    assert.match(wizard().error, CUT_OFF);
    assert.match(wizard().error, /3 ids were not sent/);
    assert.match(wizard().error, /Press Leave them out again/);
    assert.match(wizard().idsSaid, /3 ids were not sent/, "beside the box too");
    assert.deepEqual(wizard().leaving, []);
    assert.deepEqual(sent("import_stop"), [], "nothing is going to stop");
  });

  test(`a cut part way leaves out what had its answer: ${order}`, () => {
    fresh();
    boxOf(["11", "12", "13"]);
    onMoveReply(S, excluded);
    cut();
    assert.equal(wizard().idBox, "12\n13");
    assert.match(wizard().error, /2 ids were not sent/);
  });

  test(`an undo chain cut off says how many runs did not finish: ${order}`, async () => {
    fresh();
    onMoveReply(S, status([run(5), run(3)]));
    undoStart(S, 3);
    onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
    onMoveReply(S, { Admin: { ImportUndoPreview: { run: 3, counts } } });
    await answerConfirm(true);
    onMoveReply(S, undone(5, false));
    invoked().length = 0;
    cut();
    assert.equal(get(moveUndo.peek(S)), null, "nothing will answer it");
    assert.deepEqual(get(moveUndoLeft.peek(S)), { runs: [3], cut: true });
    assert.deepEqual(asks(), [], "nothing is asked of a connection that is not there");
    dropKept(S);
    assert.equal(get(moveUndoLeft.peek(S)), null, "gone when the server is closed");
  });
}

test("a cut with nothing going says nothing of ids, or of an undo", () => {
  fresh();
  atChoose();
  moveWizard.of(S).update((w) => ({ ...w, idBox: "11" }));
  const before = wizard();
  wizardCut(S);
  assert.equal(wizard(), before, "typed and not pressed: still there, and nothing was lost");
  assert.equal(get(moveUndoLeft.peek(S)), null);
});

test("a read's answer does not pass for a step's", () => {
  fresh();
  boxOf(["11", "12"]);
  stepUp.of(S).set(lastOp.get(S));
  // The tab opened again with the prompt up: it reads the list, and nothing has gone
  moveRefresh(S);
  invoked().length = 0;
  onMoveReply(S, excluded);
  assert.deepEqual(asks(), [], "12 waits for 11");
  assert.deepEqual(wizard().leaving, ["11", "12"]);
  stepUp.of(S).set(null);
  onMoveReply(S, excluded);
  assert.deepEqual(asks(), [{ MoveExclude: { dc_id: "12", on: true, erase: true } }], "its own answer moves it on");
});

test("so does one that was out before the step went", () => {
  fresh();
  moveRefresh(S);
  boxOf(["11", "12"]);
  invoked().length = 0;
  onMoveReply(S, excluded);
  assert.deepEqual(wizard().leaving, ["11", "12"]);
  onMoveReply(S, excluded);
  assert.deepEqual(wizard().leaving, ["12"]);
});

/** The number the last `AdminAsk` went with. */
const lastAsk = (): number =>
  (invoked()
    .filter(([c]: [string]) => c === "account_request")
    .at(-1)![1] as { request: { AdminAsk: { ask: number } } }).request.AdminAsk.ask;

// W2-31: a refusal names no step, and before 22 any refusal ended the wizard's begin
test("by its number, another step's refusal leaves the begin waiting, and its own ends it", async () => {
  fresh();
  atChoose();
  wizardBegin(S);
  assert.equal(wizard().step, "beginning");
  const begin = lastAsk();
  adminRead({ Users: { search: "", offset: 0 } }, S);
  const users = lastAsk();
  onMoveReply(S, { Error: { request: "Admin", reason: "Too many requests at once; slow down." }, ask: users });
  assert.equal(wizard().step, "beginning", "the Users tab's, not the begin's");
  onMoveReply(S, { Error: { request: "Admin", reason: "That is not a Discord server's id." }, ask: begin });
  assert.equal(wizard().step, "choose");
  // The control: unnumbered, a relay before 22, any refusal ends it as before
  wizardBegin(S);
  onMoveReply(S, { Error: { request: "Admin", reason: "Too many requests at once; slow down." } });
  assert.equal(wizard().step, "choose");
});

test("by its number, a list read's answer never passes for an exclusion's", () => {
  fresh();
  excludeIds(S, ["11", "12"]);
  const exclude = lastAsk();
  excludedNextPage(S);
  adminRead({ MoveExcluded: { after: "50" } }, S);
  const read = lastAsk();
  invoked().length = 0;
  // The read's answer comes first, numbered: the box still waits for 11's
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["51", false, true, 1]], more: false } }, ask: read });
  assert.deepEqual(wizard().leaving, ["11", "12"]);
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["11", false, true, 1]], more: false } }, ask: exclude });
  assert.deepEqual(asks()[0], { MoveExclude: { dc_id: "12", on: true, erase: true } }, "then the next one goes");
});

test("another person's step ends the list: the prompt is about theirs now", () => {
  fresh();
  boxOf(["11", "12"]);
  stepUp.of(S).set(lastOp.get(S));
  excludeOne(S, "20", true, false);
  assert.equal(wizard().idBox, "11\n12");
  assert.match(wizard().idsSaid, /2 ids were not sent/);
  assert.deepEqual(lastOp.get(S), { MoveExclude: { dc_id: "20", on: true, erase: false } });
  stepUp.of(S).set(null);
  invoked().length = 0;
  onMoveReply(S, excluded);
  assert.equal(asks()[0], "MoveStatus", "its answer reads the dashboard");
  assert.equal(wizard().idBox, "11\n12", "and leaves the box");
});

test("one person's answer leaves what is being typed in the box", () => {
  fresh();
  atChoose();
  moveWizard.of(S).update((w) => ({ ...w, idBox: "11" }));
  excludeOne(S, "20", true, false);
  onMoveReply(S, excluded);
  assert.equal(wizard().idBox, "11");
  assert.equal(wizard().idsSaid, "");
});

test("Run waits for the list", () => {
  fresh();
  boxOf(["11"]);
  invoked().length = 0;
  wizardBegin(S);
  assert.equal(wizard().step, "choose");
  assert.deepEqual(asks(), []);
  onMoveReply(S, excluded);
  wizardBegin(S);
  assert.equal(wizard().step, "beginning", "the control: with the list done, it goes");
});

test("a refused undo says how many runs of the chain did not finish; a finished one says nothing", async () => {
  fresh();
  onMoveReply(S, status([run(5), run(3)]));
  undoStart(S, 3);
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 3, counts } } });
  await answerConfirm(true);
  onMoveReply(S, { Error: { request: "Admin", reason: "Still clearing." } });
  assert.equal(get(moveUndo.peek(S)), null);
  assert.deepEqual(get(moveUndoLeft.peek(S)), { runs: [5, 3], cut: false });
  // Going on takes it back
  undoCarryOn(S, 5);
  assert.equal(get(moveUndoLeft.peek(S)), null);
  onMoveReply(S, undone(5, false));
  assert.equal(get(moveUndo.peek(S))?.done, true);
  assert.equal(get(moveUndoLeft.peek(S)), null, "the control: nothing left to say");
});

test("a wrong code in a chain says nothing yet, and Stop asking says what is left", async () => {
  fresh();
  onMoveReply(S, status([run(5), run(3)]));
  undoStart(S, 3);
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 3, counts } } });
  await answerConfirm(true);
  stepUp.of(S).set(lastOp.get(S));
  onMoveReply(S, WRONG);
  assert.equal(get(moveUndoLeft.peek(S)), null, "it still waits on the code");
  stepUp.of(S).set(null);
  moveStepEnded(S);
  assert.deepEqual(get(moveUndoLeft.peek(S)), { runs: [5, 3], cut: false });
  // Pressing Undo again takes it back
  undoStart(S, 3);
  assert.equal(get(moveUndoLeft.peek(S)), null);
});

test("Stop asking with a run's last answer on its way counts that run out", async () => {
  fresh();
  onMoveReply(S, status([run(5), run(3)]));
  undoStart(S, 3);
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 3, counts } } });
  await answerConfirm(true);
  moveStepEnded(S);
  // More of the same run: no change
  onMoveReply(S, undone(5, true));
  assert.deepEqual(get(moveUndoLeft.peek(S))?.runs, [5, 3]);
  onMoveReply(S, undone(5, false));
  assert.deepEqual(get(moveUndoLeft.peek(S))?.runs, [3], "that one finished");
  onMoveReply(S, undone(3, false));
  assert.equal(get(moveUndoLeft.peek(S)), null, "and there is nothing left to say");
});

// ── A token check, and a token gone ───────────────────────────────────────

const opened = { bot_name: "b", app_id: "1", member_intent: true, content_intent: true, guilds: [{ id: "7", name: "g", admin: true }], invite: "x" };

/** Two checks out, by the token each holds. */
function twoChecks() {
  const held = new Map<string, { yes: (o: unknown) => void; no: (e: string) => void }>();
  answers.__answer = (command, args) =>
    command === "import_open" ? new Promise((yes, no) => held.set(args.token!, { yes, no })) : undefined;
  return held;
}

test("a token check left behind cannot speak for the one after it", async () => {
  fresh();
  const held = twoChecks();
  wizardStart(S);
  const left = wizardOpen(S, "first");
  await new Promise((r) => setTimeout(r, 0));
  wizardForget(S);
  wizardStart(S);
  const latest = wizardOpen(S, "second");
  await new Promise((r) => setTimeout(r, 0));
  // The hub refuses the abandoned one, with the step just where it would have left it
  held.get("first")!.no("That was cancelled.");
  await left;
  assert.equal(wizard().step, "opening", "still waiting for the latest");
  assert.equal(wizard().error, "");
  held.get("second")!.yes(opened);
  await latest;
  assert.equal(wizard().step, "pick", "whose answer counts");
  assert.equal(wizard().guild, "7");
});

test("nor can its yes: the latest's answer is what counts", async () => {
  fresh();
  const held = twoChecks();
  wizardStart(S);
  const left = wizardOpen(S, "first");
  await new Promise((r) => setTimeout(r, 0));
  wizardForget(S);
  wizardStart(S);
  const latest = wizardOpen(S, "second");
  await new Promise((r) => setTimeout(r, 0));
  held.get("first")!.yes(opened);
  await left;
  assert.equal(wizard().step, "opening");
  assert.equal(wizard().opening, null);
  held.get("second")!.no("The token no longer works.");
  await latest;
  assert.equal(wizard().step, "token");
  assert.equal(wizard().error, "The token no longer works.");
});

test("one check left alone still gets its answer", async () => {
  fresh();
  const held = twoChecks();
  wizardStart(S);
  const only = wizardOpen(S, "first");
  await new Promise((r) => setTimeout(r, 0));
  held.get("first")!.yes(opened);
  await only;
  assert.equal(wizard().step, "pick");
});

test("the hub's words for a token gone are these", () => {
  const hub = readFileSync(join(import.meta.dirname, "../../../src-tauri/src/import.rs"), "utf8");
  assert.ok(hub.includes(`const NO_TOKEN: &str = ${JSON.stringify(NO_TOKEN)};`));
});

async function refusedAtRun(reason: string) {
  atChoose();
  moveWizard.of(S).update((w) => ({ ...w, idBox: "99" }));
  answers.__answer = async (command) => {
    if (command === "import_run") throw reason;
  };
  wizardBegin(S);
  onMoveReply(S, { Admin: { ImportBegun: { run: 4, resumed: true } } });
  await new Promise((r) => setTimeout(r, 0));
}

test("past the hour Run goes to the token step: the dry-run and the ticks went with it", async () => {
  fresh();
  await refusedAtRun(NO_TOKEN);
  assert.equal(wizard().step, "token");
  assert.equal(wizard().error, NO_TOKEN);
  assert.equal(wizard().plan, null);
  assert.equal(wizard().choices, null);
  assert.equal(wizard().acknowledged, false);
  assert.equal(wizard().run, null);
  assert.equal(wizard().idBox, "99", "ids not sent stay in their box");
});

test("any other refusal goes back to the choices", async () => {
  fresh();
  await refusedAtRun("One is going already.");
  assert.equal(wizard().step, "choose");
  assert.equal(wizard().error, "One is going already.");
  assert.ok(wizard().plan);
  assert.ok(wizard().choices);
  assert.equal(wizard().run, null);
});

test("past the hour Read it goes to the token step too, and any other refusal to the pick", async () => {
  for (const [reason, step] of [[NO_TOKEN, "token"], ["Discord said no.", "pick"]] as const) {
    fresh();
    answers.__answer = async (command) => {
      if (command === "import_plan") throw reason;
    };
    moveWizard.of(S).update((w) => ({ ...w, step: "pick", guild: "1" }));
    wizardRead(S);
    onMoveReply(S, { Admin: { ImportFacts: { facts } } });
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(wizard().step, step);
    assert.equal(wizard().error, reason);
  }
});

// ── A code out at a cut ────────────────────────────────────────────────────

test("a code out at a cut goes with the connection: a later refusal brings nothing back", async () => {
  fresh();
  const { resetServer } = await import("../connect.ts");
  const undoing = { ImportUndo: { run: 5 } };
  lastOp.set(S, undoing);
  removalWithCode.set(S, undoing);
  assert.ok(codeAskedAgain(S));
  dropServer(S);
  assert.ok(codeAskedAgain(S), "the control: plain maps, which no scoped store's end reaches");
  resetServer(S);
  assert.ok(!lastOp.has(S));
  assert.ok(!removalWithCode.has(S));
  assert.ok(!codeAskedAgain(S));
  // Run, on the new connection, refused: back to the choices, not left waiting on an old undo
  atChoose();
  wizardBegin(S);
  onMoveReply(S, WRONG);
  assert.equal(wizard().step, "choose");
});

test("the same reset leaves another server's alone", async () => {
  fresh();
  const { resetServer } = await import("../connect.ts");
  const OTHER = "o.example:9987";
  removalWithCode.set(OTHER, { ImportUndo: { run: 1 } });
  lastOp.set(OTHER, { ImportUndo: { run: 1 } });
  resetServer(S);
  assert.ok(removalWithCode.has(OTHER));
  assert.ok(lastOp.has(OTHER));
  removalWithCode.delete(OTHER);
  lastOp.delete(OTHER);
});

test("the excluded list reads as a list, paged by id, and a read's own answer asks nothing more", () => {
  fresh();
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["11", false, true, 1]], more: true } } });
  assert.deepEqual(asks(), [], "no refresh for a read: that would go round for ever");
  excludedNextPage(S);
  assert.deepEqual(asks(), [{ MoveExcluded: { after: "11" } }]);
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["12", true, false, 2]], more: false } } });
  assert.deepEqual(get(excludedPage.peek(S))?.rows.map((r: { id: string }) => r.id), ["11", "12"]);
  onMoveReply(S, { Admin: { MoveExcluded: { ids: [["13", false, false, 3]], more: false } } });
  assert.deepEqual(get(excludedPage.peek(S))?.rows.map((r: { id: string }) => r.id), ["13"], "a first page starts over");
});

test("an answer on someone's power brings the count beside the list up to date, once", () => {
  fresh();
  const row = { account: new Array(16).fill(1), name: "dan", claimed: true, group: "crew-power", badge: "", scopes: [] };
  powerAnswer(S, row, true);
  assert.deepEqual(asks(), [{ PowerAnswer: { id: row.account, group: "crew-power", grant: true } }]);
  invoked().length = 0;
  onMoveReply(S, { Admin: { PowerWaiting: { offset: 0, total: 0, rows: [] } } });
  assert.deepEqual(asks(), ["MoveStatus"]);
  invoked().length = 0;
  onMoveReply(S, { Admin: { PowerWaiting: { offset: 0, total: 0, rows: [] } } });
  assert.deepEqual(asks(), [], "a read of the list asks nothing more");
});

test("Undo asks what it takes first, once for the whole chain, then goes newest first", async () => {
  fresh();
  onMoveReply(S, status([run(5), run(3)]));
  undoStart(S, 3);
  assert.deepEqual(asks(), [{ ImportUndoPreview: { run: 5 } }, { ImportUndoPreview: { run: 3 } }]);
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
  assert.equal(get(pendingConfirm), null, "not before all of it is known");
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 3, counts } } });
  invoked().length = 0;
  await answerConfirm(true);
  assert.deepEqual(asks(), [{ ImportUndo: { run: 5 } }]);
  onMoveReply(S, undone(5, true, { channels: 16 }));
  assert.deepEqual(asks()[1], { ImportUndo: { run: 5 } }, "while more");
  onMoveReply(S, undone(5, false, { channels: 2 }));
  assert.deepEqual(asks()[2], { ImportUndo: { run: 3 } }, "then the older one");
  assert.equal(get(moveUndo.peek(S))?.total.channels, 18, "the counts add up");
  invoked().length = 0;
  onMoveReply(S, undone(3, false, { channels: 1 }));
  assert.equal(get(moveUndo.peek(S))?.done, true);
  assert.equal(get(moveUndo.peek(S))?.total.channels, 19);
  assert.equal(asks()[0], "MoveStatus", "and the dashboard is read afresh");
});

test("the question says a delta's group changes stay, for a run with one before it", async () => {
  fresh();
  onMoveReply(S, status([run(5), run(3)]));
  undoStart(S, 5);
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
  await new Promise((r) => setTimeout(r, 0));
  assert.match(get(pendingConfirm).body, /earlier run's groups stays/);
  await answerConfirm(false);
  // The whole chain goes back to the first run: nothing stands before it
  undoStart(S, 3);
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 3, counts } } });
  await new Promise((r) => setTimeout(r, 0));
  assert.doesNotMatch(get(pendingConfirm).body, /earlier run's groups/);
  await answerConfirm(false);
});

test("no to the question sends nothing", async () => {
  fresh();
  onMoveReply(S, status([run(5)]));
  undoStart(S, 5);
  onMoveReply(S, { Admin: { ImportUndoPreview: { run: 5, counts } } });
  invoked().length = 0;
  await answerConfirm(false);
  assert.deepEqual(asks(), []);
  assert.equal(get(moveUndo.peek(S)), null);
});

test("an undo left halfway can go on, and a refusal ends the asking", () => {
  fresh();
  undoCarryOn(S, 5);
  assert.deepEqual(asks(), [{ ImportUndo: { run: 5 } }]);
  invoked().length = 0;
  onMoveReply(S, { Error: { request: "Admin", reason: "That code is not right." } });
  assert.equal(get(moveUndo.peek(S)), null);
  assert.ok(!asks().some((op: object) => typeof op === "object" && "ImportUndo" in op), "nothing more goes");
});

test("Stop asking stops: the reply on its way starts nothing again", () => {
  fresh();
  undoCarryOn(S, 5);
  // The button
  moveStepEnded(S);
  assert.equal(get(moveUndo.peek(S)), null);
  invoked().length = 0;
  onMoveReply(S, undone(5, true, { channels: 16 }));
  assert.equal(get(moveUndo.peek(S)), null, "the callout stays shut");
  assert.ok(!asks().some((op: object) => typeof op === "object" && "ImportUndo" in op), "and nothing more goes");
  assert.equal(asks()[0], "MoveStatus", "the row says how far it got");
  // Carrying on is another press, and it goes on from there
  undoCarryOn(S, 5);
  invoked().length = 0;
  onMoveReply(S, undone(5, true));
  assert.deepEqual(asks(), [{ ImportUndo: { run: 5 } }]);
});

test("the dashboard's runs are clean for a keyed each, from either backend", () => {
  fresh();
  onMoveReply(S, status([run(3), run(3), run(5, { finished_at: undefined })]));
  const held = get(moveStatus.peek(S));
  assert.deepEqual(held?.runs.map((r: { id: number }) => r.id), [5, 3]);
  assert.equal(held?.runs[0].finished_at, null);
});

test("what each step that takes a code says, and that a refused code asks again", () => {
  assert.match(stepUpSays({ ImportBegin: { guild_id: "1", options: plan.options, backup_taken: false } }), /On SQLite the server makes a copy first/);
  assert.match(stepUpSays({ ImportUndo: { run: 1 } }), /goes for good/);
  assert.match(stepUpSays({ ArchiveDelete: { target: { Author: { id: "1" } } } }), /imported posts go for good/);
  assert.match(stepUpSays({ MoveExclude: { dc_id: "1", on: true, erase: true } }), /keeps them out/);
  assert.match(stepUpSays({ MoveExclude: { dc_id: "1", on: false, erase: false } }), /back/);
  assert.match(stepUpSays({ RemovePosts: { name: "dan", window_secs: 0 } }), /of their posts goes for good/);
  assert.equal(stepUpSays({ PowerAnswer: { id: [], group: "x", grant: true } }), "This hands out power.");
  assert.equal(stepUpSays(null), "This hands out power.");
  for (const op of [{ ArchiveDelete: { target: { Author: { id: "1" } } } }, { MoveExclude: { dc_id: "1", on: true, erase: true } }, { ImportUndo: { run: 1 } }, { RemovePosts: { name: "dan", window_secs: 0 } }]) {
    assert.ok(isRemoval(op), JSON.stringify(op));
  }
  assert.ok(!isRemoval({ PowerAnswer: { id: [], group: "x", grant: true } }));
  assert.ok(!isRemoval("MoveStatus"));
  // Only a ban has a ban to say stands
  assert.match(stepUpCancelled({ RemovePosts: { name: "dan", window_secs: 0 } }), /The ban stands/);
  assert.equal(stepUpCancelled({ ArchiveDelete: { target: { Author: { id: "1" } } } }), "Not done: that takes a code.");
});

test("a cut keeps the wizard, and only a person closing the server drops it", () => {
  fresh();
  atChoose();
  const before = wizard();
  dropServer(S);
  assert.equal(wizard(), before, "what a connection held goes, and this stays");
  wizardCut(S);
  assert.equal(wizard(), before, "choosing waits for nobody: nothing to move");
  assert.deepEqual(sent("import_stop"), []);
  dropKept(S);
  assert.equal(wizard().step, "idle");
  assert.equal(wizard().plan, null);
});

test("a person closing the server forgets the token and the wizard, and a cut neither", async () => {
  fresh();
  atChoose();
  const { disconnectServer, resetServer } = await import("../connect.ts");
  resetServer(S);
  assert.equal(wizard().step, "choose");
  assert.deepEqual(sent("import_forget"), [], "a run can go on after a cut");
  await disconnectServer(S, { save: false });
  assert.equal(wizard().step, "idle");
  assert.deepEqual(sent("import_forget"), [{ server: S }]);
  assert.deepEqual(sent("disconnect"), [{ server: S }]);
});

test("a code or a copy cut off goes back to the choices, which say so", () => {
  fresh();
  atChoose();
  wizardBegin(S);
  const { choices } = wizard();
  wizardCut(S);
  assert.equal(wizard().step, "choose", "no ImportBegun will come for it");
  assert.equal(wizard().choices, choices);
  assert.match(wizard().error, /connection to the server was lost/);
  assert.deepEqual(sent("import_stop"), [], "nothing is going to stop");
  wizardBegin(S);
  assert.equal(wizard().error, "", "and pressing Run again clears it");
});

test("a dry-run cut off goes back to the pick, and ends", () => {
  fresh();
  moveWizard.of(S).update((w) => ({ ...w, step: "reading", guild: "1" }));
  wizardCut(S);
  assert.equal(wizard().step, "pick");
  assert.match(wizard().error, /connection to the server was lost/);
  assert.deepEqual(sent("import_stop"), [{ server: S }]);
});

test("a run cut off lands on its end screen, saying so, with what it knows", () => {
  fresh();
  atChoose();
  moveWizard.of(S).update((w) => ({ ...w, step: "running", run: 4 }));
  dropServer(S);
  wizardCut(S);
  assert.deepEqual(sent("import_stop"), [{ server: S }], "its frames have nowhere to go");
  assert.equal(wizard().step, "running", "the driver's end is what says what it did");
  onImportEnded(S, { run: 4, stopped: "Stopped.", notes: ["#a: no room"] });
  assert.equal(wizard().step, "ended");
  assert.match(wizard().ended!.stopped!, /connection to the server was lost/);
  assert.match(wizard().ended!.stopped!, /Go on/);
  assert.deepEqual(wizard().ended!.notes, ["#a: no room"]);
  assert.deepEqual(asks(), [], "nothing is asked of a connection that is not there");
  const { choices } = wizard();
  wizardGoOn(S);
  assert.equal(wizard().step, "choose");
  assert.equal(wizard().choices, choices, "Go on has its choices");
  assert.equal(wizard().cut, false, "and the next run's end is its own");
});

test("the next run's end is its own, after a cut", () => {
  fresh();
  atChoose();
  moveWizard.of(S).update((w) => ({ ...w, step: "running", run: 4 }));
  wizardCut(S);
  onImportEnded(S, { run: 4, stopped: "Stopped.", notes: [] });
  moveWizard.of(S).update((w) => ({ ...w, step: "running", run: 5 }));
  onImportEnded(S, { run: 5, stopped: "You stopped it.", notes: [] });
  assert.equal(wizard().ended!.stopped, "You stopped it.");
});

test("a run that finished as the connection went says it finished", () => {
  fresh();
  moveWizard.of(S).update((w) => ({ ...w, step: "running", run: 4 }));
  wizardCut(S);
  onImportEnded(S, { run: 4, stopped: null, notes: [] });
  assert.equal(wizard().ended!.stopped, null);
});

test("Stop on a live connection says what the importer said, and reads the dashboard afresh", () => {
  fresh();
  connectionState.of(S).set("connected");
  moveWizard.of(S).update((w) => ({ ...w, step: "running", run: 4 }));
  onImportEnded(S, { run: 4, stopped: "Stopped.", notes: [] });
  assert.equal(wizard().ended!.stopped, "Stopped.");
  assert.equal(asks()[0], "MoveStatus");
});

test("nothing of a run is written down", () => {
  const source = readFileSync(join(import.meta.dirname, "move.ts"), "utf8").replace(/^\s*(\/\/|\*|\/\*).*$/gm, "");
  assert.doesNotMatch(source, /localStorage|indexedDB|set_ui_prefs|updateUiPrefs|writeFile/);
  // The wizard's own file holds the token in a field, and clears it before anything else
  const wizardFile = readFileSync(join(import.meta.dirname, "../components/AdminMoveWizard.svelte"), "utf8");
  assert.match(wizardFile, /token = "";\s*if \(t\) void wizardOpen\(server, t\);/);
  assert.doesNotMatch(wizardFile, /console\.(log|warn|error)/);
});
