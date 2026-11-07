// Sharing history with newcomers, as a device decides it and as a person is told.
//
// Pure, so history-rules.test.ts can load it under Node's own test runner.

/** All an ask for recent chat depends on, on the device that was asked. */
export interface HandOffAsk {
  /** This device's switch. */
  switchOn: boolean;
  /** Whether it counts on this server (`shareRight`). */
  right: boolean;
  /** Names inside an archive sit under the ciphertext: the relay cannot mask them. */
  anonymous: boolean;
  /** We may not speak in this channel. */
  listenOnly: boolean;
  /** A text hold of our own: a restriction, or the wait. */
  held: boolean;
  /** The channel is one we are in. */
  ours: boolean;
  /** Gated or hand-joined: who is there goes by the last sweep. */
  swept: boolean;
  /** An open channel's asker is someone online. */
  askerOnline: boolean;
  askerOnSweep: boolean;
  /** `MemberGone` named the asker since that sweep. */
  askerGone: boolean;
  /** A guest gets nothing from a gated channel. */
  askerGuest: boolean;
  metered: boolean;
  /** The local bucket. Called last, so a refusal spends nothing. */
  spend: () => boolean;
}

/** Whether to answer. The one rule, for asks a relay checked and for sealed ones it could
 *  not: a relay's word is never what lets recent chat out. */
export function answersHandOff(a: HandOffAsk): boolean {
  if (!a.switchOn || !a.right) return false;
  if (a.anonymous) return false;
  if (a.listenOnly || a.held) return false;
  if (!a.ours) return false;
  const present = a.swept ? a.askerOnSweep && !a.askerGone && !a.askerGuest : a.askerOnline;
  if (!present) return false;
  if (a.metered) return false;
  return a.spend();
}

/** A device's own budget for answering. A sealed ask passes the relay blind, so this
 *  stands where its serve rate stood. */
export interface ServeBudget {
  spent: number;
  at: number;
}

const SERVE_BURST = 6;
const SERVE_PER_SEC = 0.5;

export function spendServe(budget: ServeBudget, now: number): boolean {
  const refill = (Math.max(0, now - budget.at) / 1000) * SERVE_PER_SEC;
  budget.spent = Math.max(0, budget.spent - refill);
  budget.at = now;
  if (budget.spent + 1 > SERVE_BURST) return false;
  budget.spent += 1;
  return true;
}

/** What an empty channel knows. `wrote`: the relay says someone posted here. */
export interface EmptyState {
  direct: boolean;
  previewing: boolean;
  /** An ask is still out, up to 5 s. */
  asking: boolean;
  /** Sharers asked so far, on this connection, in this channel. */
  asked: number;
  /** Sharers online not yet asked, and one's name for when it is the only one. */
  left: number;
  leftName: string | null;
  wrote: boolean;
  /** We hold a seat here. */
  seat: boolean;
}

export interface EmptyLine {
  line: string;
  button: "Ask" | "Ask others" | null;
  /** A second line, under the first. */
  under: string | null;
}

const people = (n: number) => (n === 1 ? "1 person" : `${n} people`);
const theAsked = (n: number) => (n === 1 ? "the person asked" : `the ${n} people asked`);

const WAITS_FOR_WRITERS = "What people who share kept here opens when their app is next online.";

/** What an empty channel says. Never "had no copy": no answer can also mean out of budget,
 *  on mobile data, or a refusal. Never "nobody shares": only who is online can be seen. */
export function emptyLine(s: EmptyState): EmptyLine {
  if (s.direct) return { line: "No messages yet. Say hi!", button: null, under: null };
  if (s.previewing) return { line: "Nothing here yet. Messages will appear here in real-time.", button: null, under: null };
  const under = s.seat ? WAITS_FOR_WRITERS : null;
  if (s.asking) return { line: `Asking ${people(s.asked)} for recent messages.`, button: null, under };
  if (s.asked > 0) {
    return s.left > 0
      ? { line: `No answer from ${theAsked(s.asked)}.`, button: "Ask others", under }
      : { line: `No answer from ${theAsked(s.asked)}, and nobody else online shares.`, button: null, under };
  }
  if (s.left > 0) {
    const line = s.left === 1 && s.leftName ? `${s.leftName} shares recent messages.` : `${people(s.left)} here share recent messages.`;
    return { line, button: "Ask", under };
  }
  if (s.wrote) return { line: "People wrote here before. Nobody online shares it, so you read from now on.", button: null, under };
  return { line: "Nothing here yet. Start the conversation!", button: null, under };
}

/** Above what a read brought, when some of it has no key here. */
export const UNOPENED_LINE = "Some earlier messages here can't be opened: they were written before you joined, or before many people left.";

/** Above what a read brought, when the channel no longer keeps what this device had not read. */
export function clampedLine(window: number): string {
  return `Only the newest ${window.toLocaleString("en-US")} messages here are read back.`;
}

/** Who on a list shares, ourselves and anyone it has just lost aside. */
export function sharersIn<T extends { user_id: number; shares_history?: boolean }>(
  listed: readonly T[],
  me: number,
  gone: ReadonlySet<number> | undefined,
): T[] {
  return listed.filter((u) => u.shares_history && u.user_id !== me && !gone?.has(u.user_id));
}

/** What a ring knows, in the pane. The same state as an empty channel's, and never "had no
 *  copy": it may mean any of the things `emptyLine` says. */
export function ringLine(s: Pick<EmptyState, "asking" | "asked" | "left" | "leftName">): Omit<EmptyLine, "under"> {
  const away = "Written while you were away.";
  if (s.asking) return { line: `${away} Asking ${people(s.asked)} for recent messages.`, button: null };
  if (s.asked > 0) {
    return s.left > 0
      ? { line: `${away} No answer from ${theAsked(s.asked)}.`, button: "Ask others" }
      : { line: `${away} No answer from ${theAsked(s.asked)}, and nobody else online shares.`, button: null };
  }
  if (s.left > 0) {
    const line = s.left === 1 && s.leftName ? `${s.leftName} shares recent messages.` : `${people(s.left)} here share recent messages.`;
    return { line: `${away} ${line}`, button: "Ask" };
  }
  return { line: `${away} Nobody online shares it.`, button: null };
}

/** An open server, for what Settings says beside the switch. */
export interface ReachRow {
  name: string;
  may: boolean;
  guest: boolean;
}

/** Where the switch does nothing, or null. It is plain text, as a phone shows no hover. */
export function shareReachLine(open: readonly ReachRow[]): string | null {
  const without = open.filter((r) => !r.may);
  if (!without.length) return null;
  if (open.length === 1) {
    return without[0].guest
      ? "Not on this server for a guest."
      : "Not on this server: none of your groups here holds this privilege. An admin can give it.";
  }
  const names = without.slice(0, 3).map((r) => r.name);
  const rest = without.length - names.length;
  const listed =
    rest > 0 ? `${names.join(", ")} and ${rest} other${rest === 1 ? "" : "s"}` : names.length > 1 ? `${names.slice(0, -1).join(", ")} or ${names[names.length - 1]}` : names[0];
  if (without.every((r) => r.guest)) return `Not on ${listed} for a guest.`;
  if (without.some((r) => r.guest)) return `Not on ${listed}.`;
  return `Not on ${listed}: none of your groups there holds this privilege.`;
}
