// What happens when two people's copies of a conversation meet.
//
// Chat is fire-and-forget by default: the server keeps nothing, and a newcomer
// only has a channel's past because a member offers it. Several members may
// offer, and they will not hold the same thing — whoever was away has the older
// half, whoever just arrived has only the newest. So history is *merged* rather
// than taken from one peer, and the merge has to be idempotent: asking twice,
// or being handed the same conversation by three people, must not double it.
//
// Two rules do that work:
//
//   - A message carries an id minted by its sender, inside the end-to-end
//     envelope, so every copy of it agrees on what it is. Where both sides have
//     one, the id and its author decide together. Where they do not — anything
//     stored before v9 — the old heuristic still applies: same author, same
//     text, close in time.
//   - A deletion leaves a watermark. Clearing a channel records the newest
//     timestamp that was there, and nothing older is ever merged back in, so
//     what a user deleted stays deleted however often a member re-offers it.
//     Asking for a re-sync is how you take that back, and it is a deliberate
//     act rather than a thing that happens to you.
//
// And one rule about where a message came from: everything that arrives this
// way is somebody's copy of a conversation we were not in, with the author and
// the time written on it by the member who handed it over. There is nothing to
// check that against — identities here are per connection and never stored, so
// there is no key a message could have been signed with — so it is marked
// `shared` and stays marked, however many people pass it on.
//
// Pure, so chat-rules.test.ts can load it under Node's own test runner —
// stores/chat.ts, which owns the state and reaches the backend, cannot.

import { isEmoteReaction } from "./emote-rules.ts";
import type { ChatEvent, ChatMessage, FileRef, Forwarded, Reaction, Reactor } from "./types.ts";
import { authorKey, findTarget } from "./thread-rules.ts";
import { plainText } from "./markdown.ts";

/** Per conversation, in the store and in the archive. */
export const MAX_MESSAGES = 500;
/**
 * How many conversations are kept by default. See [`pruneConversations`].
 *
 * Settable, and 0 means keep everything: what a conversation costs is bounded
 * by `MAX_MESSAGES` either way, and the number of them a person accumulates is
 * their business rather than ours.
 */
export const MAX_CONVERSATIONS = 1000;
/** How much of a shared history is taken, however much was offered. */
export const HISTORY_MAX_MESSAGES = 50;
/**
 * The longest destruction timer anything here honours: 30 days.
 *
 * The same bound `voipc_crypto::MAX_MESSAGE_TTL_SECS` puts on a timer inside a
 * message, applied again where a claim from another client turns into a date we
 * store. A deadline further out than this is not a timer, it is "never" written
 * as a number.
 */
export const MAX_MESSAGE_TTL_SECS = 30 * 24 * 60 * 60;
const HISTORY_MAX_CONTENT = 2000;
/**
 * How far ahead of now a timestamp may be and still be somebody's clock rather
 * than a lie. A day covers any timezone or skew that is not a fault.
 */
const FUTURE_SLACK_MS = 24 * 60 * 60 * 1000;
/**
 * How far apart two identical messages may be and still be taken for one.
 *
 * Absorbs the difference between a sender's local clock and the server's: a
 * message typed while alone is stamped locally, then delivered to a newcomer
 * with the server's time on it.
 */
const SAME_MESSAGE_WINDOW_MS = 120_000;

/**
 * When a message is to be deleted, or `undefined` for one with no timer.
 *
 * This is the whole of the destruction-timer rule, and every message that
 * enters the app goes through it exactly once:
 *
 *   - `claimedTtl` is what the sender put inside the ciphertext, or what a
 *     member re-sharing the message claims. A relay cannot touch the first and
 *     can invent the second, so it is never trusted on its own.
 *   - `policyTtl` is the timer the conversation itself carries: the channel's,
 *     as the server advertises it, or my own for a direct message.
 *   - The answer is the **shorter** of the two, and the policy applies even
 *     when nothing is claimed. That is what closes the obvious way round this:
 *     a member re-sharing a channel's history strips the field, and without the
 *     second half their copy would outlive every other one.
 *
 * Counted from the message's own timestamp rather than from now, so that every
 * copy of one message — the sender's, each receiver's, and every archive it was
 * later shared into — names the same instant and they go together.
 *
 * Stamped once, when a message arrives, and never re-stamped: a channel whose
 * timer is switched on today does not reach back into what people already hold,
 * and an untrusted server cannot use it as a delete button on their archives.
 */
export function expiryFor(
  timestamp: number,
  claimedTtlSecs?: number | null,
  policyTtlSecs?: number | null,
): number | undefined {
  const bound = (t?: number | null) =>
    typeof t === "number" && Number.isFinite(t) && t > 0
      ? Math.min(Math.floor(t), MAX_MESSAGE_TTL_SECS)
      : undefined;
  const claimed = bound(claimedTtlSecs);
  const policy = bound(policyTtlSecs);
  const ttl = claimed === undefined ? policy : policy === undefined ? claimed : Math.min(claimed, policy);
  if (ttl === undefined) return undefined;
  return timestamp + ttl * 1000;
}

/** The earlier of two deadlines; a message with none can still gain one. */
export function soonerExpiry(a?: number, b?: number): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return Math.min(a, b);
}

/** Whether a message's destruction timer has run out. */
export function hasExpired(m: ChatMessage, now = Date.now()): boolean {
  return m.expires_at !== undefined && m.expires_at <= now;
}

/**
 * Drop what is due, from one conversation.
 *
 * Returns the same array when nothing is due, so a sweep over conversations
 * nobody has written in costs one comparison each and no re-render.
 */
export function dropExpired(messages: ChatMessage[], now = Date.now()): ChatMessage[] {
  return messages.some((m) => hasExpired(m, now))
    ? messages.filter((m) => !hasExpired(m, now))
    : messages;
}

/**
 * Could a message really have been written then?
 *
 * Two clocks stamp chat — our own messages carry this machine's, everybody
 * else's carry the server's — and neither is verified. The number matters far
 * beyond the line it is printed on: clearing a channel records the newest
 * timestamp in it as a watermark, and nothing at or below the watermark is ever
 * merged again. One message claiming the year 8000, from a hostile peer or from
 * an honest client with a dead RTC battery, plus one clear, therefore suppresses
 * every future hand-off of that channel for good — with the resync button as
 * the only way back and nothing on screen to suggest it.
 */
export function plausibleTimestamp(t: number, now = Date.now()): boolean {
  return t > 0 && t < now + FUTURE_SLACK_MS;
}

/**
 * Keep only what a shared history may contain.
 *
 * Everything here arrived from another client. It is end-to-end encrypted, so
 * the server did not write it — but the peer did, and a peer can say anything:
 * this is the boundary where their claim becomes our data.
 *
 * Which is why everything that comes out of here is marked `shared`. The
 * `user_id` and `username` on each message are the sharer's word for who wrote
 * it, so a member can hand a newcomer a whole conversation attributed to
 * anybody; nothing signs a message, because identities are per connection and
 * never stored. The mark is what keeps that from being drawn as a first-hand
 * account, and it also means a peer cannot forge one of our own dividers.
 */
export function sanitizeHistory(
  incoming: unknown,
  policyTtlSecs?: number | null,
  now = Date.now(),
): ChatMessage[] {
  const valid: ChatMessage[] = [];
  // A peer's JSON, parsed and handed straight here: `{}` or `null` is as
  // possible as a list, and has nothing to offer
  if (!Array.isArray(incoming)) return valid;
  for (const raw of incoming.slice(-HISTORY_MAX_MESSAGES)) {
    const m = raw as Partial<ChatMessage> | null;
    if (
      !m || typeof m.user_id !== "number" || typeof m.username !== "string" ||
      typeof m.content !== "string" || typeof m.timestamp !== "number" ||
      !plausibleTimestamp(m.timestamp)
    ) continue;
    // Ciphertext the sharer could not open themselves. We hold the same
    // placeholder or the real message; either way theirs is worth nothing, and
    // taking it would spread one member's missing key down the whole chain of
    // people who join later.
    if (m.kind === "undecryptable") continue;
    // A destruction timer survives the hand-off, and the sharer's word for it
    // is only ever the *outer* bound: what the channel says now applies too,
    // including to a copy that arrives claiming no timer at all. So a member
    // cannot keep a message alive past the channel's own answer by stripping
    // the field or by naming a date of their choosing.
    const claimedTtl =
      typeof m.expires_at === "number" && Number.isFinite(m.expires_at)
        ? Math.max(0, Math.round((m.expires_at - m.timestamp) / 1000))
        : undefined;
    const expires_at = expiryFor(m.timestamp, claimedTtl, policyTtlSecs);
    // Already gone. Somebody's copy of a message whose moment has passed is not
    // history, and taking it would put it back on screen everywhere it is
    // shared onward from here.
    if (expires_at !== undefined && expires_at <= now) continue;
    valid.push({
      user_id: m.user_id,
      // A name and its "#0000" tag
      username: m.username.slice(0, 37),
      content: cutText(m.content),
      timestamp: m.timestamp,
      // Whatever it claimed to be. Once hearsay, always hearsay: a message
      // relayed on from here is offered as `shared` again, so passing it round
      // a second time can never launder it back into a first-hand account.
      kind: "shared",
      id: keptId(m.id),
      expires_at,
      // What it answers survives the hand-off: an id, which shows nothing a
      // newcomer does not already hold, and points at nothing they cannot see.
      // Its file too, checked as if it had just arrived: its key is no more
      // than the message itself gives a member.
      ...messageRefs(m),
      // That its writer changed it, which the text already shows: the
      // sharer's word, like the rest. What else events did to it (reactions,
      // a pin) is each reader's own record, and never taken from a peer.
      ...editedAt(m.edited_at, m.timestamp, now),
    });
  }
  return valid;
}

/** Longest message id kept: `voipc_crypto::envelope::MAX_MESSAGE_ID`. */
const MAX_MESSAGE_ID = 64;

/** An id as we keep one: a non-empty string, cut to `MAX_MESSAGE_ID` code
 *  points, as envelope.rs `bounded_id` cuts it, so a live copy and a kept one
 *  of the same id agree (R2-17). */
function keptId(v: unknown): string | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  // No more units than the bound is no more code points either
  return v.length <= MAX_MESSAGE_ID ? v : Array.from(v).slice(0, MAX_MESSAGE_ID).join("");
}

/**
 * The most of a message's text kept where it arrives (D-7): 16 KiB of UTF-8.
 * Twice that is about what a relay passes, and nothing the composer writes
 * comes near it (2000 characters); past `MAX_MARKUP_CHARS` it is drawn as
 * plain text anyway. Applied at every receive point: live, stored, and an
 * edit's new text.
 */
export const MAX_RECEIVED_BYTES = 16 * 1024;
const receivedBuf = new Uint8Array(MAX_RECEIVED_BYTES);

/** `text`, cut to `MAX_RECEIVED_BYTES` at a character's edge. */
export function receivedText(text: string): string {
  // A UTF-16 unit is at most three bytes of UTF-8
  if (text.length * 3 <= MAX_RECEIVED_BYTES) return text;
  const { read } = new TextEncoder().encodeInto(text, receivedBuf);
  return read >= text.length ? text : text.slice(0, read);
}

/**
 * What a system notification says of a message (R2-14). Nothing of one with
 * a destruction timer: the notification centre, or a phone's lock screen,
 * would keep its text after the message is gone. A file without a caption
 * by its name.
 */
export function notificationBody(m: Pick<ChatMessage, "content" | "file" | "expires_at">): string {
  if (m.expires_at !== undefined) return "";
  return plainText(m.content).slice(0, 140) || (m.file ? `Sent a file: ${m.file.name}` : "");
}

/**
 * What a message points at (the message it answers, its thread), the file it
 * carries and where it was forwarded from, as they may be kept: ids bounded
 * like its own, a file checked (`fileRef`), a label checked (`forwarded`), and
 * only the keys that are there, so a plain message stays exactly the object
 * it was.
 */
export function messageRefs(src: {
  reply_to?: unknown;
  thread?: unknown;
  file?: unknown;
  fwd?: unknown;
}): Pick<ChatMessage, "reply_to" | "thread" | "file" | "fwd"> {
  const out: Pick<ChatMessage, "reply_to" | "thread" | "file" | "fwd"> = {};
  const reply = keptId(src.reply_to);
  const thread = keptId(src.thread);
  const file = fileRef(src.file);
  const fwd = forwarded(src.fwd);
  if (reply) out.reply_to = reply;
  if (thread) out.thread = thread;
  if (file) out.file = file;
  if (fwd) out.fwd = fwd;
  return out;
}

/** envelope.rs `MAX_FWD_NAME`. */
const MAX_FWD_NAME = 64;

/** A forwarded message's label as it may be kept (envelope.rs
 *  `Forwarded::checked`): a cleaned name, and a moment JS holds exactly. */
export function forwarded(v: unknown): Forwarded | undefined {
  const f = v as Record<string, unknown> | null;
  if (typeof f?.name !== "string" || within(f.at, 0, Number.MAX_SAFE_INTEGER) === undefined) return undefined;
  return { name: cleanText(f.name, MAX_FWD_NAME) || "someone", at: f.at as number };
}

/** voipc_crypto::file::MAX_FILE_PLAIN, and envelope.rs's bounds on a file. */
const MAX_FILE_PLAIN = 64 * 1024 * 1024;
const MAX_FILE_NAME = 255;
const MAX_FILE_SIDE = 16_384;
const MAX_FILE_DUR = 7 * 24 * 60 * 60;
const HEX64 = /^[0-9a-f]{64}$/;
const MIME = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i;
const PREVIEW_B64 = /^[A-Za-z0-9+/]{1024}$/;
/** Control characters, and those that turn the text's direction (an
 *  `exe.jpg` that reads `gpj.exe`). */
const NAME_JUNK = /[\p{Cc}\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069\ufeff]/gu;

/** A file name as a card shows it (envelope.rs `clean_name`). */
export function cleanFileName(name: string): string {
  return cleanText(name, MAX_FILE_NAME);
}

/** `cleanFileName`, at most `max` characters (envelope.rs `clean`). */
function cleanText(text: string, max: number): string {
  return Array.from(text.replace(NAME_JUNK, "")).slice(0, max).join("").trim();
}

/** A whole number within bounds, else nothing. */
function within(v: unknown, least: number, most: number): number | undefined {
  return Number.isSafeInteger(v) && (v as number) >= least && (v as number) <= most ? (v as number) : undefined;
}

/**
 * A message's file as it may be kept, bounded like envelope.rs `FileRef::checked`:
 * the blob's part as `FileMeta::from_parts` takes it, or no file at all; the
 * name cleaned; the rest dropped where it is out of bounds.
 */
export function fileRef(v: unknown): FileRef | undefined {
  const f = v as Record<string, unknown> | null;
  const blob =
    typeof f?.hash === "string" &&
    HEX64.test(f.hash) &&
    typeof f.key === "string" &&
    HEX64.test(f.key) &&
    within(f.size, 0, MAX_FILE_PLAIN) !== undefined &&
    typeof f.z === "boolean";
  if (!blob) return undefined;
  const out: FileRef = {
    hash: f.hash as string,
    key: f.key as string,
    size: f.size as number,
    z: f.z as boolean,
    name: (typeof f.name === "string" && cleanFileName(f.name)) || "file",
  };
  if (typeof f.mime === "string" && f.mime.length <= 127 && MIME.test(f.mime)) out.mime = f.mime.toLowerCase();
  const w = within(f.w, 1, MAX_FILE_SIDE);
  const h = within(f.h, 1, MAX_FILE_SIDE);
  const dur = within(f.dur, 0, MAX_FILE_DUR);
  if (w !== undefined) out.w = w;
  if (h !== undefined) out.h = h;
  if (dur !== undefined) out.dur = dur;
  if (typeof f.px === "string" && PREVIEW_B64.test(f.px)) out.px = f.px;
  return out;
}

/** The fields the archive has a place of its own for (crypto.rs `ChatMessage`). */
const ARCHIVE_FIELDS = new Set(["user_id", "username", "content", "timestamp", "kind", "id", "expires_at", "account"]);
/** The fields `extra` holds that this version reads back (`fromArchived`). */
const EXTRA_FIELDS = new Set(["reply_to", "thread", "file", "fwd", "edited_at", "reactions", "pin"]);

/**
 * A message as the desktop archive stores it: every field it has no place of
 * its own for folded into one JSON string, `extra` (archive v6). The archive is
 * positional, so a field of its own would be a new file format each time.
 * What a later version kept there and this one does not know goes back as it
 * came (`extra_kept`), under the fields this one wrote.
 */
export function toArchived(m: ChatMessage): ChatMessage & { extra?: string } {
  const { extra_kept, ...known } = m;
  const out: Record<string, unknown> = {};
  let extra: Record<string, unknown> = {};
  try {
    const kept = extra_kept ? JSON.parse(extra_kept) : null;
    if (kept && typeof kept === "object" && !Array.isArray(kept)) extra = kept;
  } catch {
    // Not ours to repair: what this version knows is written either way
  }
  for (const [k, v] of Object.entries(known)) {
    if (v === undefined) continue;
    (ARCHIVE_FIELDS.has(k) ? out : extra)[k] = v;
  }
  if (Object.keys(extra).length > 0) out.extra = JSON.stringify(extra);
  return out as unknown as ChatMessage & { extra?: string };
}

/**
 * And back: only the fields this version knows, each checked as if it had just
 * arrived. A damaged `extra` costs those fields, never the message. The keys
 * it does not know (a later 1.x wrote them) are kept, untouched and unread,
 * for the next save (R2-03): a downgrade destroys nothing.
 */
export function fromArchived(m: ChatMessage & { extra?: string | null }): ChatMessage {
  const { extra, ...rest } = m;
  // serde writes an absent field as null; the front end's shape has no nulls
  for (const k of Object.keys(rest) as (keyof ChatMessage)[]) if (rest[k] === null) delete rest[k];
  if (typeof extra !== "string") return rest;
  try {
    const more = JSON.parse(extra) ?? {};
    const unknown =
      typeof more === "object" && !Array.isArray(more) ? Object.entries(more).filter(([k]) => !EXTRA_FIELDS.has(k)) : [];
    return {
      ...rest,
      ...messageRefs(more),
      ...eventState(more, rest.timestamp),
      ...(unknown.length > 0 ? { extra_kept: JSON.stringify(Object.fromEntries(unknown)) } : {}),
    };
  } catch {
    return rest;
  }
}

/** Whether two messages are the same one, seen twice. */
function sameMessage(a: ChatMessage, b: ChatMessage): boolean {
  // An id is minted by the sender and travels inside the ciphertext, so where
  // both copies have one it is the whole answer — including "these are two
  // different messages that happen to read alike".
  //
  // With the author, though, never on its own: the server cannot see an id but
  // every member can, so one member could note another's, offer a history
  // containing their own message under it, and have whichever copy landed first
  // shadow the real one. An id only identifies a message among that sender's.
  // Between accounts, the account is the author: a user id is new on every
  // connect, so a message from the stored log carries none worth comparing.
  if (a.id && b.id && a.account && b.account) return a.account === b.account && a.id === b.id;
  if (a.id && b.id) return a.user_id === b.user_id && a.id === b.id;
  return (
    a.user_id === b.user_id &&
    a.content === b.content &&
    Math.abs(a.timestamp - b.timestamp) < SAME_MESSAGE_WINDOW_MS
  );
}

/**
 * The newest timestamp in a conversation, or 0 for an empty one.
 *
 * Implausible ones are passed over rather than taken as the newest: this is the
 * only input to the deletion watermark, and a watermark in the far future is
 * one the user can never get out from under by deleting again.
 */
export function newestTimestamp(messages: ChatMessage[], now = Date.now()): number {
  return messages.reduce(
    (newest, m) => (plausibleTimestamp(m.timestamp, now) ? Math.max(newest, m.timestamp) : newest),
    0,
  );
}

/**
 * Keep the most recently active conversations and let the rest go.
 *
 * `MAX_MESSAGES` caps each conversation, but nothing caps how many there are:
 * every channel of every server ever connected to, plus a conversation per
 * person ever messaged, and the whole map is re-serialised and handed across
 * the IPC boundary on every save. The one nobody has written in for months is
 * the one whose loss is not noticed.
 *
 * The deletion watermarks are deliberately not pruned alongside it. One number
 * per key, and outliving the messages is the entire point of them: a channel
 * whose chat has aged out of here is exactly the channel a member would offer
 * to fill back up.
 *
 * `limit` of 0 or less keeps every conversation. Nothing else depends on the
 * count — each conversation is capped at `MAX_MESSAGES`, and a history hand-off
 * at `HISTORY_MAX_MESSAGES` — so the only thing unlimited costs is a larger map
 * to write out on each save.
 */
export function pruneConversations(
  map: Map<string, ChatMessage[]>,
  limit = MAX_CONVERSATIONS,
): Map<string, ChatMessage[]> {
  if (limit <= 0 || map.size <= limit) return map;
  const byRecency = [...map].sort(
    ([, a], [, b]) => newestTimestamp(b) - newestTimestamp(a),
  );
  return new Map(byRecency.slice(0, limit));
}

/**
 * Whether a stored conversation key is one written before 0.9.
 *
 * DMs used to be filed under the two user ids, `"1-2"`. A user id is a counter
 * handed out afresh on every connection and reused as people come and go, so
 * the same key names different pairs of people on different days and on
 * different servers — yesterday's conversation with one person would be shown
 * as this one's with somebody else. There is nothing in the file to say who
 * they really were, so these are dropped rather than re-filed.
 */
export function isLegacyDmKey(key: string): boolean {
  return /^\d+-\d+$/.test(key);
}

/** A conversation as its chat key names it, across servers. */
export interface ChatPlace {
  kind: "channel" | "dm";
  key: string;
  /** `host:port`, as chat keys carry it. */
  server: string;
  name: string;
}

/** `host:port/name`; a channel name may hold a slash of its own. */
export function splitChatKey(key: string): { server: string; name: string } | null {
  const m = /^([^/]+:\d+)\/(.*)$/s.exec(key);
  return m ? { server: m[1], name: m[2] } : null;
}

const byTimestamp = (a: ChatMessage, b: ChatMessage) => a.timestamp - b.timestamp;

export interface MergeResult {
  messages: ChatMessage[];
  /** How many of the offered messages were new to us. */
  added: number;
}

/**
 * Fold one member's shared history into what we already hold.
 *
 * `clearedBefore` is the watermark: anything at or older than it was deleted
 * here on purpose and is not taken back.
 *
 * `sharedBy` names the divider drawn where this hand-off ends. Each sharer
 * gets one — three people filling in three parts of a conversation is the case
 * this exists for, and the reader should see which part came from whom — but
 * asking the same person twice moves their divider rather than adding one.
 */
export function mergeHistory(
  existing: ChatMessage[],
  incoming: ChatMessage[],
  sharedBy: string,
  clearedBefore = 0,
): MergeResult {
  // Dividers are ours, not messages: they never count as a duplicate, and a
  // message is compared against what we already hold plus what this hand-off
  // has already contributed.
  const markers = existing.filter((m) => m.kind === "history-marker");
  const kept = existing.filter((m) => m.kind !== "history-marker");
  const fresh: ChatMessage[] = [];
  let replaced = 0;

  for (const m of incoming) {
    if (m.timestamp <= clearedBefore) continue;
    const seen = kept.findIndex((h) => sameMessage(h, m));
    if (seen !== -1) {
      // Hearsay gives way to the real thing, and never the other way round:
      // where all we had was a member's copy of a message and the message
      // itself turns up, we keep the one we witnessed.
      if (kept[seen].kind === "shared" && m.kind !== "shared") {
        // What this reader saw done to it stays: reactions and a pin are
        // their own record, and the row on screen is the same row
        const { reactions, pin } = kept[seen];
        kept[seen] = succeed(kept[seen], {
          ...m,
          expires_at: soonerExpiry(kept[seen].expires_at, m.expires_at),
          ...(reactions ? { reactions } : {}),
          ...(pin ? { pin } : {}),
        });
        replaced++;
      } else {
        // A copy of a message we already hold may bring its deletion forward
        // and never push it back: two members offering the same conversation
        // cannot between them grant it a longer life than either was given.
        const sooner = soonerExpiry(kept[seen].expires_at, m.expires_at);
        if (sooner !== kept[seen].expires_at) {
          kept[seen] = { ...kept[seen], expires_at: sooner };
          replaced++;
        }
      }
      continue;
    }
    fresh.push(m);
    kept.push(m);
  }
  if (fresh.length === 0) {
    // A divider marks where a hand-off's messages end, so one that brought
    // nothing draws none — but a copy it corrected still has to be written.
    return {
      messages: replaced > 0 ? [...kept, ...markers].sort(byTimestamp) : existing,
      added: 0,
    };
  }

  const marker: ChatMessage = {
    user_id: 0,
    username: "",
    content: `Earlier messages shared by ${sharedBy}`,
    // Sits right after the last message it brought
    timestamp: fresh[fresh.length - 1].timestamp,
    kind: "history-marker",
  };
  // This sharer's previous divider moves; everyone else's stays where it is.
  const others = markers.filter((m) => m.content !== marker.content);
  const messages = [...kept, ...others, marker].sort(byTimestamp);
  if (messages.length > MAX_MESSAGES) {
    messages.splice(0, messages.length - MAX_MESSAGES);
  }
  return { messages, added: fresh.length };
}

// ── Edit, delete, reactions, pins (1.3) ─────────────────────────────────────
//
// Each is an event that names an earlier message of the same conversation by
// its id (envelope.rs `ChatEvent`), and each reader applies it to their own
// copy. Nothing on the wire says who may do what, so the reader checks it
// against who sent the event, as the relay named them:
//
//   - An edit or a delete only from the message's own writer: the same
//     account where both have one, else the same user id and name
//     (`authorKey`), on a message this connection received (`current`). So a
//     guest can change what they wrote only while still connected under that
//     id; after a reconnect, theirs or ours, their messages stay as sent, and
//     a newcomer who is given the old id and types the old name changes none.
//   - A delete also takes a copy a member handed over (`shared`) that names
//     the writer and claims a time before the delete: removing what only
//     claims to be someone's, at their own request, is always safe. An edit
//     does not: a hearsay copy keeps what was handed on.
//   - An edit sets `edited_at` and never touches `expires_at`: a message's
//     moment of deletion is stamped once, on arrival, and nothing extends it.
//   - A delete leaves a tombstone (kind "deleted"): never drawn, never handed
//     on, and found by `mergeHistory` when a copy of the message is offered
//     again, so a hand-off or the stored log cannot bring it back.
//   - Reactions: per person and emoji, the latest event wins; at most
//     `MAX_REACTION_EMOJI` different emoji on one message.
//   - A pin only from one of the channel's managers by the roster's roles,
//     which the caller asks (`canManageAs`, channel-post-rules.ts).

/** Different emoji on one message, at most. */
export const MAX_REACTION_EMOJI = 20;
/** Emoji a message keeps a record of, shown or taken off again. */
const MAX_REACTION_ENTRIES = 2 * MAX_REACTION_EMOJI;
/** People one emoji keeps a record of. */
export const MAX_REACTORS = 50;
/** envelope.rs `MAX_EMOJI_BYTES`. */
const MAX_EMOJI_BYTES = 32;
/** Nothing a reader would see, so two chips that look the same: controls,
 *  spaces, direction marks, U+200C and the text-style selector U+FE0E. The
 *  joiner (U+200D), U+FE0F and the tag characters stay: emoji sequences and
 *  flags are made of them. */
const INVISIBLE = /[\p{Cc}\p{White_Space}‎‏؜‪-‮⁦-⁩﻿\u200c\ufe0e]/u;
/** What makes a grapheme an emoji: a pictograph, a flag's letters, a keycap. */
const EMOJI = /[\p{Extended_Pictographic}\p{Regional_Indicator}⃣]/u;
const graphemes = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/** One emoji: a single grapheme, at most `MAX_EMOJI_BYTES`, nothing invisible. */
/** What a reaction may be: one emoji, or a server emote's `:name:`. */
export function isReaction(v: unknown): v is string {
  return isOneEmoji(v) || (typeof v === "string" && isEmoteReaction(v));
}

export function isOneEmoji(v: unknown): v is string {
  if (typeof v !== "string" || v === "" || INVISIBLE.test(v) || !EMOJI.test(v)) return false;
  if (new TextEncoder().encode(v).length > MAX_EMOJI_BYTES) return false;
  const it = graphemes.segment(v)[Symbol.iterator]();
  return !it.next().done && it.next().done === true;
}

/** An event as it may be acted on (envelope.rs `ChatEvent::checked`, plus the
 *  one-grapheme rule for an emoji), else nothing. */
export function chatEvent(v: unknown): ChatEvent | undefined {
  const e = v as Record<string, unknown> | null;
  const target = keptId(e?.target);
  if (!e || !target) return undefined;
  switch (e.kind) {
    case "edit":
    case "delete":
      return { kind: e.kind, target };
    case "react":
      return typeof e.on === "boolean" && isReaction(e.emoji) ? { kind: "react", target, emoji: e.emoji, on: e.on } : undefined;
    case "pin":
      return typeof e.on === "boolean" ? { kind: "pin", target, on: e.on } : undefined;
  }
  return undefined;
}

/** Who did something, as the receive point names them. */
export type Actor = Pick<ChatMessage, "user_id" | "username" | "account">;

/** An event as it arrived: what, by whom, when, and an edit's new text. */
export interface EventIn {
  event: ChatEvent;
  by: Actor;
  at: number;
  content: string;
}

// A message an event changed is a new object in place of the old one, and the
// screen keys its rows by object: without this, a reaction would tear down
// its row, a loaded picture and the keyboard's place with it. The new object
// carries the first one's key.
const lineage = new WeakMap<ChatMessage, ChatMessage>();

function succeed(prev: ChatMessage, next: ChatMessage): ChatMessage {
  lineage.set(next, lineage.get(prev) ?? prev);
  return next;
}

/** A message's row on screen: the same for every version an event made of it. */
export function rowKey(m: ChatMessage): ChatMessage {
  return lineage.get(m) ?? m;
}

/** Whether `a` and `b` are versions of one message (`rowKey`). */
export function sameRow(a: ChatMessage, b: ChatMessage): boolean {
  return rowKey(a) === rowKey(b);
}

/** A message that is there to be drawn, answered or acted on. */
function isLive(m: ChatMessage): boolean {
  return !!m.id && m.kind !== "history-marker" && m.kind !== "notice" && m.kind !== "deleted" && m.kind !== "undecryptable";
}

/**
 * `list` with `ev` applied, or `list` itself when it changes nothing: a
 * target not here, a sender who may not, an event older than what it would
 * replace. `mayPin`: the sender is one of the channel's managers.
 */
export function applyEvent(
  list: ChatMessage[],
  ev: EventIn,
  opts: {
    mayPin: boolean;
    /** Whether this connection received `m` (a guest's edit or delete takes
     *  only those); every message, where omitted. */
    current?: (m: ChatMessage) => boolean;
  },
): ChatMessage[] {
  const { event, by, at } = ev;
  const current = opts.current ?? (() => true);
  if (!Number.isFinite(at)) return list;
  const replace = (pick: (m: ChatMessage) => boolean, change: (m: ChatMessage) => ChatMessage | null) => {
    let changed = false;
    const next = list.map((m) => {
      if (!pick(m)) return m;
      const made = change(m);
      if (!made) return m;
      changed = true;
      return succeed(m, made);
    });
    return changed ? next : list;
  };
  if (event.kind === "edit" || event.kind === "delete") {
    // Only its writer: every copy of the target they wrote, none of anyone
    // else's; a guest's only from this connection
    const writer = authorKey(by);
    const theirs = (m: ChatMessage) =>
      m.id === event.target && isLive(m) && m.kind !== "shared" && authorKey(m) === writer && (!!by.account || current(m));
    if (event.kind === "delete") {
      // And the hand-off copies that name them, as older than the delete (D-13)
      const named = (m: ChatMessage) =>
        m.id === event.target && m.kind === "shared" && m.username === by.username && m.timestamp <= at;
      return replace((m) => theirs(m) || named(m), (m) => ({
        user_id: m.user_id,
        username: m.username,
        content: "",
        timestamp: m.timestamp,
        id: m.id,
        kind: "deleted",
        ...(m.account ? { account: m.account } : {}),
        ...(m.expires_at !== undefined ? { expires_at: m.expires_at } : {}),
      }));
    }
    return replace(theirs, (m) =>
      m.edited_at !== undefined && at < m.edited_at ? null : { ...m, content: ev.content, edited_at: at },
    );
  }
  // A reaction or a pin goes on the message the id names, as a quote finds it
  const target = findTarget(list.filter(isLive), event.target, at);
  if (!target) return list;
  const on = (m: ChatMessage) => m === target;
  if (event.kind === "pin") {
    if (!opts.mayPin) return list;
    return replace(on, (m) =>
      m.pin && at < m.pin.at ? null : { ...m, pin: { on: event.on, at, by: by.username.slice(0, 64) } },
    );
  }
  const reactions = react(target.reactions ?? [], event.emoji, event.on, authorKey(by), by.username, at);
  return reactions ? replace(on, (m) => ({ ...m, reactions })) : list;
}

/** `reactions` with one person's event for one emoji, or null for no change. */
function react(reactions: Reaction[], emoji: string, on: boolean, key: string, name: string, at: number): Reaction[] | null {
  const shown = (r: Reaction) => r.by.some((b) => b.on);
  const entry = reactions.find((r) => r.emoji === emoji);
  const mine = entry?.by.find((b) => b.key === key);
  if (mine && at < mine.at) return null;
  if (!mine && !on) return null;
  // One more emoji shown: within the limit, and the record within its own
  if (on && !(entry && shown(entry)) && reactions.filter(shown).length >= MAX_REACTION_EMOJI) return null;
  let list = reactions;
  if (!entry && list.length >= MAX_REACTION_ENTRIES) {
    list = list.filter(shown);
    if (list.length >= MAX_REACTION_ENTRIES) return null;
  }
  // One more person: within the limit, after letting go of those who took
  // theirs off (one guest reconnecting under new keys would fill it for good)
  let others = entry?.by ?? [];
  if (!mine && others.length >= MAX_REACTORS) {
    others = others.filter((b) => b.on);
    if (others.length >= MAX_REACTORS) return null;
  }
  const me: Reactor = { key, name: name.slice(0, 64), on, at };
  const by = mine ? others.map((b) => (b === mine ? me : b)) : [...others, me];
  const next: Reaction = { emoji, by };
  return entry ? list.map((r) => (r === entry ? next : r)) : [...list, next];
}

/** One chip under a message: an emoji, how many, whether one is ours, and who. */
export interface ReactionChip {
  emoji: string;
  count: number;
  mine: boolean;
  names: string[];
}

/** The chips under `m`, in the order the emoji first came; `mine` tells our
 *  own `authorKey`. */
export function reactionChips(m: ChatMessage, mine: (key: string) => boolean): ReactionChip[] {
  const out: ReactionChip[] = [];
  for (const r of m.reactions ?? []) {
    const by = r.by.filter((b) => b.on);
    if (by.length > 0) out.push({ emoji: r.emoji, count: by.length, mine: by.some((b) => mine(b.key)), names: by.map((b) => b.name) });
  }
  return out;
}

/** A conversation's pinned messages, the latest pin first. */
export function pinnedOf(list: readonly ChatMessage[]): ChatMessage[] {
  return list.filter((m) => m.pin?.on && isLive(m)).sort((a, b) => b.pin!.at - a.pin!.at);
}

/**
 * A message as a history hand-off offers it: without what events did to it
 * here (reactions, a pin), which is this reader's own record and would only
 * cost the hand-off's budget; the receiver drops them anyway (`sanitizeHistory`).
 * Never with what a later version kept in its archive entry (`extra_kept`).
 * Its text cut to what a receiver takes, before the budget is measured, so one
 * long message cannot push the others out (R2-07).
 */
export function forHandOff(m: ChatMessage): ChatMessage {
  const long = m.content.length > HISTORY_MAX_CONTENT;
  if (!m.reactions && !m.pin && m.extra_kept === undefined && !long) return m;
  const { reactions: _r, pin: _p, extra_kept: _k, ...rest } = m;
  return long ? { ...rest, content: cutText(rest.content) } : rest;
}

/** A text cut to `HISTORY_MAX_CONTENT`, never inside an emote's token (which
 *  would show as its raw start). */
export function cutText(text: string): string {
  const cut = text.slice(0, HISTORY_MAX_CONTENT);
  const open = cut.lastIndexOf("<:");
  return open >= 0 && cut.length < text.length && !cut.slice(open).includes(">") ? cut.slice(0, open) : cut;
}

/** `edited_at` as it may be kept: a plausible moment, not before the message. */
function editedAt(v: unknown, timestamp: number, now = Date.now()): Pick<ChatMessage, "edited_at"> {
  return typeof v === "number" && Number.isFinite(v) && v >= timestamp && plausibleTimestamp(v, now) ? { edited_at: v } : {};
}

/**
 * What events did to a message, as the archive's `extra` holds it, each part
 * checked as if it had just arrived: the edit's moment, the reactions within
 * their limits, the pin. A part that does not check is dropped, never the
 * message.
 */
function eventState(more: Record<string, unknown>, timestamp: number): Pick<ChatMessage, "edited_at" | "reactions" | "pin"> {
  const out: Pick<ChatMessage, "edited_at" | "reactions" | "pin"> = { ...editedAt(more.edited_at, timestamp) };
  const moment = (v: unknown) => typeof v === "number" && Number.isFinite(v) && v > 0;
  if (Array.isArray(more.reactions)) {
    const reactions: Reaction[] = [];
    for (const r of more.reactions.slice(0, MAX_REACTION_ENTRIES)) {
      if (!isReaction(r?.emoji) || !Array.isArray(r.by) || reactions.some((x) => x.emoji === r.emoji)) continue;
      const by: Reactor[] = [];
      for (const b of r.by.slice(0, MAX_REACTORS)) {
        if (typeof b?.key !== "string" || b.key.length > 200 || typeof b.name !== "string" || typeof b.on !== "boolean" || !moment(b.at)) continue;
        if (by.some((x) => x.key === b.key)) continue;
        by.push({ key: b.key, name: b.name.slice(0, 64), on: b.on, at: b.at });
      }
      if (by.length > 0) reactions.push({ emoji: r.emoji, by });
    }
    if (reactions.length > 0) out.reactions = reactions;
  }
  const p = more.pin as Record<string, unknown> | undefined;
  if (p && typeof p.on === "boolean" && moment(p.at) && typeof p.by === "string") {
    out.pin = { on: p.on, at: p.at as number, by: p.by.slice(0, 64) };
  }
  return out;
}
