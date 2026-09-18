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

import type { ChatMessage } from "./types.ts";

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
  incoming: unknown[],
  policyTtlSecs?: number | null,
  now = Date.now(),
): ChatMessage[] {
  const valid: ChatMessage[] = [];
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
      username: m.username.slice(0, 32),
      content: m.content.slice(0, HISTORY_MAX_CONTENT),
      timestamp: m.timestamp,
      // Whatever it claimed to be. Once hearsay, always hearsay: a message
      // relayed on from here is offered as `shared` again, so passing it round
      // a second time can never launder it back into a first-hand account.
      kind: "shared",
      id: typeof m.id === "string" && m.id !== "" ? m.id.slice(0, 64) : undefined,
      expires_at,
    });
  }
  return valid;
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
        kept[seen] = { ...m, expires_at: soonerExpiry(kept[seen].expires_at, m.expires_at) };
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
