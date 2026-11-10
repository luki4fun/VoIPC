// Reporting a message (1.10). A report is a direct message to whoever takes reports,
// carrying the message as a forward with a mark on it (envelope.rs `ReportMark`). The
// relay answers who, and sees nothing else of it, unless its file goes too, which shows
// which conversation it came from. Everything here is somebody's word: the label says
// whose, and the one check there is, is against the reader's own copy.

import { cleanText, isWritten, MAX_FWD_NAME } from "./chat-rules.ts";
import { untokenize } from "./emote-rules.ts";
import { toHex } from "./hex.ts";
import { shortName } from "./username.ts";
import type { ChatMessage, Forwarded } from "./types.ts";

/** envelope.rs `MAX_REPORT_WHY`. */
export const MAX_REPORT_WHY = 300;
/** types.rs `MAX_REPORT_TAKERS`. */
const MAX_REPORT_TAKERS = 5;

/** A `ReportTaker` as the backends hand it over: the browser's decoder gives
 *  undefined for None, the desktop null. */
export interface RawTaker {
  user_id?: number | null;
  account?: ArrayLike<number> | null;
  name: string;
}

export interface ReportTaker {
  /** Here now: a report goes to this id. Null: away, a sealed copy waits for `account`. */
  user_id: number | null;
  /** Hex. Null: the admin token, with no account. */
  account: string | null;
  name: string;
}

/** Somebody who must not get a report: its writer, or we ourselves. */
export interface NotATaker {
  user_id?: number;
  account?: string;
  name?: string;
}

function isThem(t: ReportTaker, who: NotATaker): boolean {
  return (
    t.name === who.name ||
    (t.account !== null && t.account === who.account) ||
    (t.user_id !== null && t.user_id === who.user_id)
  );
}

/**
 * The relay's answer as it may be kept and drawn: once each by name, since the
 * dialog's list is keyed by it and a repeat would stop the page; not ourselves; each
 * with somewhere for a report to go.
 */
export function cleanTakers(raw: readonly RawTaker[] | null | undefined, me: NotATaker): ReportTaker[] {
  const seen = new Set<string>();
  const out: ReportTaker[] = [];
  for (const t of raw ?? []) {
    if (typeof t?.name !== "string" || !t.name || seen.has(t.name)) continue;
    const user_id = Number.isSafeInteger(t.user_id) && (t.user_id as number) > 0 ? (t.user_id as number) : null;
    const account = t.account?.length === 16 ? toHex(t.account) : null;
    if (user_id === null && account === null) continue;
    const taker = { user_id, account, name: t.name };
    if (isThem(taker, me)) continue;
    seen.add(t.name);
    out.push(taker);
  }
  return out.slice(0, MAX_REPORT_TAKERS);
}

/** Those who may get a report of what `writer` wrote: never `writer`. */
export function takersFor(takers: readonly ReportTaker[], writer: NotATaker): ReportTaker[] {
  return takers.filter((t) => !isThem(t, writer));
}

/** The label a report of `m` carries. `channel`: where it was written, empty for a
 *  direct message. The name is what the reporter sees, a pseudonym under one. */
export function reportMark(m: Pick<ChatMessage, "username" | "timestamp" | "id">, channel: string, why: string): Forwarded {
  return {
    name: m.username,
    at: m.timestamp,
    report: {
      channel,
      ...(m.id ? { id: m.id } : {}),
      why: cleanText(why.replace(/\s+/g, " "), MAX_REPORT_WHY),
    },
  };
}

/** A forward's label: a report stays one, and says who it came from. The first to
 *  pass it on says so, and those after them leave it. */
export function passedOn(fwd: Forwarded, sender: string): Forwarded {
  return fwd.report && !fwd.report.by ? { ...fwd, report: { ...fwd.report, by: cleanText(sender, MAX_FWD_NAME) } } : fwd;
}

/** Where a report says a message was written. */
export function reportPlace(channel: string, voice: boolean): string {
  if (!channel) return "in a direct message";
  return voice ? `in ${channel}` : `in #${channel}`;
}

/**
 * The line above a report. Whoever sent the message is who it comes from, whatever
 * its mark says: `by` is only that person's word, and only ever shown as such.
 */
export function reportLine(fwd: Forwarded, sender: string, mine: boolean, place: string, when: string): string {
  const writer = shortName(fwd.name);
  const by = fwd.report?.by ? shortName(fwd.report.by) : "";
  const claim = `${writer} wrote this ${place} at ${when}`;
  if (mine) return by ? `You passed on a report from ${by}. They say ${claim}` : `You reported this. You say ${claim}`;
  const from = shortName(sender);
  return by ? `Report passed on by ${from}, who says it came from ${by}. They say ${claim}` : `Report from ${from}. They say ${claim}`;
}

export type ReportCheck = "same" | "differs" | "edited" | "none";

export const REPORT_CHECK: Record<ReportCheck, string> = {
  same: "matches your copy",
  differs: "your copy says otherwise",
  edited: "your copy was edited since",
  none: "you have no copy, nothing proves it",
};

/**
 * A report against the reader's own copy of that channel. A copy a member handed over
 * is their word too, so it counts as none, as does what is left of a message. Ids are
 * the writer's to choose, so one with the right id and another's name is no match.
 * `anonymous`: names in that channel differ by reader, so only the words can tell.
 */
export function reportCheck(
  m: Pick<ChatMessage, "content" | "file" | "fwd">,
  copies: readonly ChatMessage[],
  anonymous = false,
): ReportCheck {
  const report = m.fwd?.report;
  if (!report?.channel || !report.id) return "none";
  const mine = copies.filter((c) => c.id === report.id && c.kind !== "shared" && isWritten(c));
  if (mine.length === 0) return "none";
  const theirs = mine.filter((c) => anonymous || cleanText(c.username, MAX_FWD_NAME) === m.fwd?.name);
  const said = (c: ChatMessage) =>
    untokenize(c.content) === untokenize(m.content) && (!m.file || m.file.hash === c.file?.hash);
  if (theirs.some(said)) return "same";
  return theirs.some((c) => c.edited_at !== undefined) ? "edited" : "differs";
}
