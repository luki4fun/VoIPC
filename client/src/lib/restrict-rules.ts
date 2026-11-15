// Who may not speak for now (protocol 19): the relay's rows as the app keeps them,
// and what it says about them. Pure, for restrict-rules.test.ts.

/** A row off the wire. Browser wasm gives undefined for no end, the desktop null. */
export interface RestrictionRow {
  user_id: number;
  voice: boolean;
  text: boolean;
  direct: boolean;
  expires_in_secs?: number | null;
  by: string;
  reason: string;
  /** What `by`'s own restriction holds (protocol 23); the rest is the new-member wait. */
  by_voice?: boolean;
  by_text?: boolean;
  /** Seconds until the wait ends; none: no wait. */
  wait_in_secs?: number | null;
}

export interface Held {
  voice: boolean;
  text: boolean;
  direct: boolean;
  /** When the row next changes, by this device's clock; null: until someone lifts it. */
  until: number | null;
  /** An account's name or "admin token". Empty: only the new-member wait applies. */
  by: string;
  /** Only the person and holders of `voipc:restrict` are told it. */
  reason: string;
  /** What `by`'s own restriction holds; left out, all of the row is theirs (W3-17). */
  by_voice?: boolean;
  by_text?: boolean;
  /** When the new-member wait ends, by this device's clock; null or left out: `until`. */
  wait?: number | null;
}

/** Whether `by` holds this part themselves, not the wait under them. */
function theirs(h: Held, what: "voice" | "text"): boolean {
  if (!h.by) return false;
  return what === "voice" ? (h.by_voice ?? h.voice) : (h.by_text ?? h.text);
}

/** `had` with `list` in it, each person once: all false lifts. The wire says seconds
 *  from now, since clocks differ. */
export function withRows(had: ReadonlyMap<number, Held>, list: readonly RestrictionRow[], now: number): Map<number, Held> {
  const next = new Map(had);
  for (const r of list) {
    if (!r.voice && !r.text && !r.direct) {
      next.delete(r.user_id);
      continue;
    }
    const secs = r.expires_in_secs ?? null;
    const wait = r.wait_in_secs ?? null;
    next.set(r.user_id, {
      voice: r.voice,
      text: r.text,
      direct: r.direct,
      until: secs === null ? null : now + secs * 1000,
      by: r.by,
      reason: r.reason,
      by_voice: r.by_voice ?? (!!r.by && r.voice),
      by_text: r.by_text ?? (!!r.by && r.text),
      wait: wait === null ? null : now + wait * 1000,
    });
  }
  return next;
}

function clock(until: number, now: number, locale?: string): string {
  const d = new Date(until);
  const time = d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === new Date(now).toDateString()) return time;
  return `${d.toLocaleDateString(locale, { day: "numeric", month: "short" })} ${time}`;
}

function untilWords(until: number | null, now: number, locale?: string): string {
  return until === null ? "until someone lifts it" : `until ${clock(until, now, locale)}`;
}

function fromWords(until: number | null, now: number, locale?: string): string {
  return until === null ? "later" : `from ${clock(until, now, locale)}`;
}

function byWords(by: string): string {
  return by === "admin token" ? "an admin" : `@${by}`;
}

function withReason(words: string, reason: string): string {
  return reason ? `${words}: ${reason}` : words;
}

/** What holds us back, where the composer or the talk button would be. */
export function heldLine(h: Held, what: "voice" | "text" | "direct", now: number, locale?: string): string {
  const waitEnd = h.wait ?? h.until;
  if (!h.by) return `New here: you can ${what === "voice" ? "speak" : "write"} ${fromWords(waitEnd, now, locale)}`;
  // A moderator's restriction never reaches direct messages; the wait is what did
  if (what === "direct") return `New here: you can write direct messages ${fromWords(waitEnd, now, locale)}`;
  // A voice-only mute during the wait: writing is the wait's, with the wait's end (W3-17)
  if (!theirs(h, what)) return `New here: you can ${what === "voice" ? "speak" : "write"} ${fromWords(waitEnd, now, locale)}`;
  const did = what === "voice" && !theirs(h, "text") ? "Muted" : "Timed out";
  return withReason(`${did} by ${byWords(h.by)} ${untilWords(h.until, now, locale)}`, h.reason);
}

/** A mark's title in a member list: who and until when, and why for those told it. */
export function markTitle(h: Held, now: number, locale?: string): string {
  if (!h.by) return `New here: cannot speak or write ${untilWords(h.until, now, locale)}`;
  const voice = theirs(h, "voice");
  const text = theirs(h, "text");
  const did = voice && text ? "Timed out" : voice ? "Muted" : "Cannot post";
  return withReason(`${did} by ${byWords(h.by)} ${untilWords(h.until, now, locale)}`, h.reason);
}

function sameRow(a: Held, b: Held): boolean {
  const near =
    a.until === null || b.until === null
      ? a.until === b.until
      : // The same row told twice lands a moment apart
        Math.abs(a.until - b.until) < 5000;
  return (
    near &&
    a.voice === b.voice &&
    a.text === b.text &&
    a.direct === b.direct &&
    a.by === b.by &&
    a.reason === b.reason &&
    theirs(a, "voice") === theirs(b, "voice") &&
    theirs(a, "text") === theirs(b, "text")
  );
}

/** What to tell the person when their own row changed, or null when it did not. */
export function heldNotice(before: Held | null, after: Held | null, now: number, locale?: string): string | null {
  if (!after) return before ? "You can speak and write on this server again" : null;
  if (before && sameRow(before, after)) return null;
  // What the moderator did, if anyone did: a mute during the wait is told as a mute
  const what = after.by ? (theirs(after, "text") ? "text" : "voice") : after.text ? "text" : "voice";
  return heldLine(after, what, now, locale);
}
