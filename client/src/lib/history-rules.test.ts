import { test } from "node:test";
import assert from "node:assert/strict";
import { UNOPENED_LINE, answersHandOff, clampedLine, emptyLine, ringLine, shareReachLine, sharersIn, spendServe, type EmptyState, type HandOffAsk } from "./history-rules.ts";

function ask(over: Partial<HandOffAsk> = {}): HandOffAsk & { spent: number } {
  const a = {
    switchOn: true,
    right: true,
    anonymous: false,
    listenOnly: false,
    held: false,
    ours: true,
    swept: false,
    askerOnline: true,
    askerOnSweep: false,
    askerGone: false,
    askerGuest: false,
    metered: false,
    spent: 0,
    spend() {
      a.spent += 1;
      return true;
    },
    ...over,
  };
  return a;
}

test("a hand-off is answered with the switch and the right, in a channel of ours, to someone there", () => {
  const a = ask();
  assert.equal(answersHandOff(a), true);
  assert.equal(a.spent, 1);
  const swept = ask({ swept: true, askerOnline: false, askerOnSweep: true });
  assert.equal(answersHandOff(swept), true, "gated or hand-joined: by the sweep");
});

for (const [why, over] of [
  ["the switch is off", { switchOn: false }],
  ["there is no right here", { right: false }],
  ["the channel is anonymous", { anonymous: true }],
  ["we are listen-only", { listenOnly: true }],
  ["we are held, or wait", { held: true }],
  ["the channel is not ours", { ours: false }],
  ["a stranger asks in an open channel", { askerOnline: false }],
  ["a stranger asks in a gated one", { swept: true, askerOnSweep: false }],
  ["`MemberGone` named the asker", { swept: true, askerOnSweep: true, askerGone: true }],
  ["a guest asks in a gated one", { swept: true, askerOnSweep: true, askerGuest: true }],
  ["on mobile data", { metered: true }],
] as [string, Partial<HandOffAsk>][]) {
  test(`no answer when ${why}, and it costs no budget`, () => {
    const a = ask(over);
    assert.equal(answersHandOff(a), false);
    assert.equal(a.spent, 0, "a refusal spends nothing");
  });
}

test("the bucket has the last word", () => {
  assert.equal(answersHandOff(ask({ spend: () => false })), false);
});

test("the local serve bucket stops a flood, and refills at one per two seconds", () => {
  const budget = { spent: 0, at: 1000 };
  const took = Array.from({ length: 10 }, () => spendServe(budget, 1000));
  assert.deepEqual(took, [true, true, true, true, true, true, false, false, false, false]);
  assert.equal(spendServe(budget, 2999), false, "not quite one back");
  assert.equal(spendServe(budget, 3000), true);
  assert.equal(spendServe(budget, 3000), false);
  // A clock going back gives nothing
  assert.equal(spendServe(budget, 500), false);
  // Idle for long: the burst, and no more
  const later = 60_000;
  assert.equal(Array.from({ length: 10 }, () => spendServe(budget, later)).filter(Boolean).length, 6);
});

const empty = (over: Partial<EmptyState> = {}): EmptyState => ({
  direct: false,
  previewing: false,
  asking: false,
  asked: 0,
  left: 0,
  leftName: null,
  wrote: false,
  seat: false,
  ...over,
});

test("an empty channel says what the app knows, row by row", () => {
  for (const [state, line, button] of [
    [{ asking: true, asked: 3 }, "Asking 3 people for recent messages.", null],
    [{ asked: 3, left: 2 }, "No answer from the 3 people asked.", "Ask others"],
    [{ asked: 3 }, "No answer from the 3 people asked, and nobody else online shares.", null],
    [{ asked: 1 }, "No answer from the person asked, and nobody else online shares.", null],
    [{ left: 1, leftName: "alice" }, "alice shares recent messages.", "Ask"],
    [{ left: 3 }, "3 people here share recent messages.", "Ask"],
    [{ wrote: true }, "People wrote here before. Nobody online shares it, so you read from now on.", null],
    [{}, "Nothing here yet. Start the conversation!", null],
    [{ previewing: true }, "Nothing here yet. Messages will appear here in real-time.", null],
    [{ direct: true }, "No messages yet. Say hi!", null],
  ] as [Partial<EmptyState>, string, string | null][]) {
    const got = emptyLine(empty(state));
    assert.equal(got.line, line, JSON.stringify(state));
    assert.equal(got.button, button, JSON.stringify(state));
  }
});

test("a seat adds one line, but not to a preview or a direct conversation", () => {
  const under = "What people who share kept here opens when their app is next online.";
  for (const state of [{ asking: true, asked: 3 }, { asked: 3, left: 2 }, { asked: 3 }, { left: 3 }, { wrote: true }, {}]) {
    assert.equal(emptyLine(empty({ ...state, seat: true })).under, under, JSON.stringify(state));
    assert.equal(emptyLine(empty(state)).under, null, "control: no seat");
  }
  assert.equal(emptyLine(empty({ previewing: true, seat: true })).under, null);
  assert.equal(emptyLine(empty({ direct: true, seat: true })).under, null);
});

test("no line claims what the app cannot know", () => {
  for (const asking of [true, false]) {
    for (const asked of [0, 1, 3]) {
      for (const left of [0, 1, 3]) {
        for (const wrote of [true, false]) {
          for (const seat of [true, false]) {
            const { line, under } = emptyLine(empty({ asking, asked, left, wrote, seat }));
            const said = `${line} ${under ?? ""}`;
            assert.ok(!/had no copy/i.test(said), said);
            assert.ok(!/\bnobody shares\b/i.test(said), said);
          }
        }
      }
    }
  }
});

const row = (name: string, may: boolean, guest = false) => ({ name, may, guest });

test("Settings names where the switch does nothing, and only then", () => {
  assert.equal(shareReachLine([]), null, "none open");
  assert.equal(shareReachLine([row("Home", true), row("Work", true)]), null, "all allow it");
  assert.equal(
    shareReachLine([row("Home", false)]),
    "Not on this server: none of your groups here holds this privilege. An admin can give it.",
  );
  assert.equal(shareReachLine([row("Home", false, true)]), "Not on this server for a guest.");
  assert.equal(
    shareReachLine([row("Home", false), row("Work", false), row("Lan", true)]),
    "Not on Home or Work: none of your groups there holds this privilege.",
  );
  assert.equal(
    shareReachLine([row("Home", false), row("Lan", true)]),
    "Not on Home: none of your groups there holds this privilege.",
  );
  assert.equal(shareReachLine([row("Home", false, true), row("Lan", true)]), "Not on Home for a guest.");
  assert.equal(
    shareReachLine([row("A", false), row("B", false), row("C", false), row("D", false), row("E", false)]),
    "Not on A, B, C and 2 others: none of your groups there holds this privilege.",
    "at most 3 names",
  );
  assert.equal(shareReachLine([row("Home", false), row("Work", false, true)]), "Not on Home or Work.");
});

test("a guest is never told to sign in", () => {
  for (const line of [shareReachLine([row("Home", false, true)]), shareReachLine([row("Home", false, true), row("Lan", true)])]) {
    assert.ok(line && !/sign in|account/i.test(line), String(line));
  }
});

test("the quiet lines say what cannot be read back, with the relay's number", () => {
  assert.match(UNOPENED_LINE, /can't be opened/);
  assert.equal(clampedLine(10_000), "Only the newest 10,000 messages here are read back.");
  assert.equal(clampedLine(500), "Only the newest 500 messages here are read back.");
});

test("the ring says what an empty channel says, and never 'had no copy'", () => {
  const ring = (over: Partial<EmptyState>) => ringLine({ asking: false, asked: 0, left: 0, leftName: null, ...over });
  assert.deepEqual(ring({ asking: true, asked: 3 }), { line: "Written while you were away. Asking 3 people for recent messages.", button: null });
  assert.deepEqual(ring({ asked: 3, left: 2 }), { line: "Written while you were away. No answer from the 3 people asked.", button: "Ask others" });
  assert.deepEqual(ring({ asked: 1 }), { line: "Written while you were away. No answer from the person asked, and nobody else online shares.", button: null });
  assert.deepEqual(ring({ left: 1, leftName: "alice" }), { line: "Written while you were away. alice shares recent messages.", button: "Ask" });
  assert.deepEqual(ring({ left: 2 }), { line: "Written while you were away. 2 people here share recent messages.", button: "Ask" });
  assert.deepEqual(ring({}), { line: "Written while you were away. Nobody online shares it.", button: null });
});

test("a sharer is someone on the list who says so, not us, and not someone it just lost", () => {
  const rows = [
    { user_id: 1, shares_history: true },
    { user_id: 2, shares_history: true },
    { user_id: 3, shares_history: false },
    { user_id: 4, shares_history: true },
  ];
  assert.deepEqual(sharersIn(rows, 1, new Set([4])).map((u) => u.user_id), [2]);
  assert.deepEqual(sharersIn(rows, 1, undefined).map((u) => u.user_id), [2, 4]);
});
