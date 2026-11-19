// What the app says about a channel's group key (docs/GROUP-KEY.md, plan 3h). The Rust side, or
// the browser's backend, sends `gk-*` events per channel with names already blanked as the room
// shows them (anonymous: none; hidden members: only to admins). This folds them into one
// channel's state and turns that into lines. `place` is the channel as the chat names it: `#x`,
// or a voice room's bare name.
// Pure, for gk-rules.test.ts.

import { TOO_LARGE_REASON } from "./chat-rules.ts";

/** `gk-state`. `why`: for "refused" the server's reason; for "held" the check that stopped the
 *  post ("guest", "pin", or "old_counter" with `name` the account whose old key was listed); for
 *  "late" `WAITING` while a post of ours waits, else "". */
export interface GkState {
  channel_id: number;
  state: "ok" | "late" | "held" | "no_keyholder" | "refused";
  why: string;
  name?: string;
}

/** `gk-post-dropped`: a held post given up at `HOLD_MS`. `why`: "no_keyholder", "late",
 *  "unchecked" (its readers did not check out) or "refused" (told by the refusal's own line). */
export interface GkPostDropped {
  channel_id: number;
  why: string;
}

/** `gk-readers`: the new readers a fold showed; `unchecked`, how many more it listed with no name
 *  to show; `older_unnamed`, a tail proof stood for people seated more than 90 days ago. */
export interface GkReaders {
  channel_id: number;
  names: string[];
  unchecked: number;
  older_unnamed: boolean;
}

export interface GkHolder {
  name: string;
  online: boolean;
  kind: string;
}

/** `gk-keyholders`: the group's keyholder set, as it stands. */
export interface GkKeyholders {
  channel_id: number;
  holders: GkHolder[];
}

/** `gk-anew`: a new generation; `by` is "" where the room hides who. */
export interface GkAnew {
  channel_id: number;
  by: string;
}

/** `gk-warning`. A later build may add kinds: one this build does not know says nothing. */
export interface GkWarning {
  channel_id: number;
  kind: string;
  n: number;
}

/** `GkState.why` of "late" while a post of ours waits for the keys. */
export const WAITING = "waiting";

/** One channel's keys, as the chat and the member list show them. */
export interface GkChannel {
  /** null while all is well. */
  state: GkState | null;
  /** Why the last held post was dropped: until the keys are well again or another post waits. */
  dropped: string | null;
  /** New readers since the line was last waved off, over every fold. */
  readers: { names: string[]; more: number } | null;
  older: boolean;
  holders: GkHolder[];
  /** Who made the keys anew, until waved off. */
  anew: string | null;
  /** The latest of each kind, until waved off. */
  warnings: GkWarning[];
}

export function emptyGk(): GkChannel {
  return { state: null, dropped: null, readers: null, older: false, holders: [], anew: null, warnings: [] };
}

export function withState(ch: GkChannel, e: GkState): GkChannel {
  const ok = e.state === "ok";
  // A post waits again, or the keys are well: the drop told of is over
  const over = ok || e.state === "held" || e.why === WAITING;
  return { ...ch, state: ok ? null : e, dropped: over ? null : ch.dropped };
}

export function withDropped(ch: GkChannel, e: GkPostDropped): GkChannel {
  return { ...ch, dropped: e.why };
}

export function withReaders(ch: GkChannel, e: GkReaders): GkChannel {
  // Gathered, not replaced: a fold that came before the first was read must not hide it
  const names = [...(ch.readers?.names ?? [])];
  for (const n of e.names) if (n && !names.includes(n)) names.push(n);
  return {
    ...ch,
    readers: { names, more: (ch.readers?.more ?? 0) + e.unchecked },
    older: ch.older || e.older_unnamed,
  };
}

export function withHolders(ch: GkChannel, e: GkKeyholders): GkChannel {
  return { ...ch, holders: e.holders };
}

export function withAnew(ch: GkChannel, e: GkAnew): GkChannel {
  return { ...ch, anew: e.by };
}

export function withWarning(ch: GkChannel, e: GkWarning): GkChannel {
  return { ...ch, warnings: [...ch.warnings.filter((w) => w.kind !== e.kind), e] };
}

/** Waves off the line `key` names (`GkLine.key`); the state's own line goes only with the state. */
export function dismissed(ch: GkChannel, key: string): GkChannel {
  if (key === "dropped") return { ...ch, dropped: null };
  if (key === "readers") return { ...ch, readers: null };
  if (key === "older") return { ...ch, older: false };
  if (key === "anew") return { ...ch, anew: null };
  return { ...ch, warnings: ch.warnings.filter((w) => `warning:${w.kind}` !== key) };
}

/** "a", "a and b", "a, b and c", "a, b and N more"; null with no name to show. */
export function listNames(names: readonly string[], more = 0): string | null {
  if (names.length === 0) return null;
  const extra = names.length > 3 ? names.length - 2 + more : more;
  const shown = names.length > 3 ? names.slice(0, 2) : names;
  if (extra > 0) return `${shown.join(", ")} and ${extra} more`;
  if (shown.length === 1) return shown[0];
  return `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
}

/** The member list's top line: who holds the keys, those online first. */
export function holdersLine(holders: readonly GkHolder[]): string | null {
  const named = holders.filter((h) => h.name).sort((a, b) => Number(b.online) - Number(a.online));
  const list = listNames(
    named.map((h) => h.name),
    holders.length - named.length,
  );
  return list && `Keys held by ${list}`;
}

export interface GkLine {
  /** What waving it off clears (`dismissed`); "state" cannot be. */
  key: string;
  line: string;
  /** A post of ours waits on it. */
  wait: boolean;
}

const DROPPED: Record<string, (place: string) => string> = {
  no_keyholder: (p) => `Nobody who holds ${p}'s keys is online. Your message was not sent.`,
  late: (p) => `${p}'s keys were late. Your message was not sent.`,
  unchecked: (p) => `Your message to ${p} could not be checked against its readers and was not sent.`,
};

const HELD: Record<string, (name: string) => string> = {
  guest: () => "a guest was listed as a reader.",
  pin: () => "someone's key does not match the one you know.",
  old_counter: (name) => `an old key of ${name} was listed.`,
};

const WARNINGS: Record<string, (place: string, n: number) => string> = {
  unnamed_seats: (p, n) => `This device gave ${p}'s keys to ${n} ${n === 1 ? "person" : "people"} the server then did not list.`,
  old_seat_key: (p) => `An old key of your account was listed in ${p}.`,
  floor_ahead: (p) => `The server's keys for ${p} are older than what this device saw.`,
  entry_swapped: (p) => `Your key-holding entry in ${p} was replaced by a device that is not this one.`,
  leaver_may_hear: () => "Someone who left may still hear this room.",
  gated_opened: (p) => `${p} was closed to listed readers and is now open.`,
};

/** What becomes of our posts here, if anything is to be said: one line at most. */
function postLine(place: string, ch: GkChannel): GkLine | null {
  const s = ch.state;
  // A post past 16 KiB (one that started a kept chain is refused so): the post's, not the keys'
  if (s?.state === "refused" && s.why === TOO_LARGE_REASON) {
    return { key: "state", line: `Your message to ${place} was not sent: one message holds at most 16 KiB.`, wait: false };
  }
  if (s?.state === "refused") {
    return { key: "state", line: `The server refused ${place}'s keys: ${s.why.replace(/\.$/, "")}.`, wait: false };
  }
  const dropped = ch.dropped === null ? undefined : DROPPED[ch.dropped];
  if (dropped) return { key: "dropped", line: dropped(place), wait: false };
  const held = s?.state === "held" ? HELD[s.why] : undefined;
  if (held) return { key: "state", line: `Your message to ${place} is waiting: ${held(s?.name ?? "")}`, wait: true };
  if (s?.state === "late") {
    const waiting = s.why === WAITING;
    return { key: "state", line: `${place}'s keys are late.${waiting ? " Your message is waiting." : ""}`, wait: waiting };
  }
  return null;
}

/** The chat's lines for one channel: what becomes of our posts first, then what to know. */
export function gkLines(place: string, ch: GkChannel): GkLine[] {
  const out: GkLine[] = [];
  const post = postLine(place, ch);
  if (post) out.push(post);
  const readers = ch.readers && listNames(ch.readers.names, ch.readers.more);
  if (readers) out.push({ key: "readers", line: `New readers in ${place}: ${readers}.`, wait: false });
  if (ch.older) {
    out.push({ key: "older", line: `People joined ${place} more than 90 days ago whose names you were not shown.`, wait: false });
  }
  if (ch.anew !== null) {
    out.push({ key: "anew", line: `Keys for ${place} were made anew${ch.anew ? ` by ${ch.anew}` : ""}.`, wait: false });
  }
  for (const w of ch.warnings) {
    const say = WARNINGS[w.kind];
    if (say) out.push({ key: `warning:${w.kind}`, line: say(place, w.n), wait: false });
  }
  return out;
}
