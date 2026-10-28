// Replies and threads: what a message answers, and which conversations within
// a conversation hang together.
//
// Only ids travel (`reply_to`, `thread`, inside the end-to-end envelope); the
// messages they point at are looked up here, in the reader's own copy of the
// conversation. Nothing on the wire says "this is a thread": a thread is a
// way of drawing what is already there, so a reader without the first message
// just sees the answers in the main flow.
//
// Pure, so thread-rules.test.ts runs it under Node's own test runner.

import type { ChatMessage } from "./types.ts";

/** Whether a row is a message rather than one of our own dividers, or what
 *  is left of one its writer deleted. */
function isMessage(m: ChatMessage): boolean {
  return m.kind !== "history-marker" && m.kind !== "notice" && m.kind !== "deleted";
}

/** Messages by id, for the lookups below. */
export function indexById(list: readonly ChatMessage[]): Map<string, ChatMessage[]> {
  const index = new Map<string, ChatMessage[]>();
  for (const m of list) {
    if (!m.id || !isMessage(m)) continue;
    const same = index.get(m.id);
    if (same) same.push(m);
    else index.set(m.id, [m]);
  }
  return index;
}

/**
 * The message `id` points at. Ids are the sender's own, and any member can
 * repeat one, so where several carry it the first-hand copy wins over a
 * shared one, and then the earliest: a copy made to impersonate a message can
 * only come after it.
 */
export function findTarget(
  list: readonly ChatMessage[] | Map<string, ChatMessage[]>,
  id: string | undefined,
): ChatMessage | undefined {
  if (!id) return undefined;
  const same = list instanceof Map ? list.get(id) : indexById(list).get(id);
  if (!same || same.length === 0) return undefined;
  return [...same].sort(
    (a, b) => Number(a.kind === "shared") - Number(b.kind === "shared") || a.timestamp - b.timestamp,
  )[0];
}

/** Who wrote a message, as one key: the account where there is one. */
export function authorKey(m: Pick<ChatMessage, "account" | "user_id" | "username">): string {
  return m.account ? `a:${m.account}` : `u:${m.user_id}:${m.username}`;
}

export interface ThreadView {
  /** The main flow: everything not folded into a thread, in order. */
  main: ChatMessage[];
  /** Each thread's first message, and the answers that belong to it, in order. */
  threads: Map<ChatMessage, ChatMessage[]>;
  /** Answers in a thread whose first message is not here: shown in the main flow, labelled. */
  orphans: Set<ChatMessage>;
}

/** Answers from at least this many… */
export const AUTO_THREAD_REPLIES = 3;
/** …written by at least this many people make a busy message a thread. */
export const AUTO_THREAD_AUTHORS = 2;
/** How far a chain of answers is followed: a forged loop ends here. */
const MAX_CHAIN = 64;

/**
 * Sort a conversation into its main flow and its threads.
 *
 * A message sent with `thread` belongs to that thread's first message, if it
 * is here. With `auto` on, a message that has drawn `AUTO_THREAD_REPLIES`
 * answers (counting answers to answers) from `AUTO_THREAD_AUTHORS` people
 * becomes a thread too, and every answer under it moves out of the main flow.
 * Each reader works this out from their own copy, so two people holding
 * different parts of a conversation can see it drawn a little differently.
 */
export function threadView(list: readonly ChatMessage[], opts: { auto: boolean }): ThreadView {
  const index = indexById(list);
  // Messages somebody opened a thread on: each keeps its own, and stays in
  // the main flow itself rather than folding into a thread above it
  const explicitRoots = new Set<ChatMessage>();
  const orphans = new Set<ChatMessage>();
  for (const m of list) {
    if (!isMessage(m) || !m.thread) continue;
    const root = findTarget(index, m.thread);
    if (!root) orphans.add(m);
    else if (root !== m) explicitRoots.add(root);
  }

  // The first message of the conversation-within-a-conversation `m` is part
  // of: up its chain of answers, to a thread's first message or to a message
  // that answers nothing. Itself, for a message that answers nothing.
  const rootOf = (m: ChatMessage): ChatMessage => {
    if (explicitRoots.has(m)) return m;
    let at = m;
    const seen = new Set<ChatMessage>([m]);
    for (let i = 0; i < MAX_CHAIN; i++) {
      if (at !== m && explicitRoots.has(at)) break;
      const up = at.thread ? findTarget(index, at.thread) : at.reply_to ? findTarget(index, at.reply_to) : undefined;
      if (!up || seen.has(up) || !isMessage(up)) break;
      seen.add(up);
      at = up;
    }
    return at;
  };

  const under = new Map<ChatMessage, ChatMessage[]>();
  for (const m of list) {
    if (!isMessage(m) || orphans.has(m)) continue;
    const root = rootOf(m);
    if (root === m) continue;
    const answers = under.get(root);
    if (answers) answers.push(m);
    else under.set(root, [m]);
  }

  const threads = new Map<ChatMessage, ChatMessage[]>();
  const folded = new Set<ChatMessage>();
  for (const [root, answers] of under) {
    const busy =
      answers.length >= AUTO_THREAD_REPLIES && new Set(answers.map(authorKey)).size >= AUTO_THREAD_AUTHORS;
    // With grouping off, only answers sent into a thread leave the main flow
    const members = opts.auto ? answers : answers.filter((a) => a.thread);
    if (members.length === 0 || !(explicitRoots.has(root) || (opts.auto && busy))) continue;
    threads.set(root, members);
    for (const a of members) folded.add(a);
  }
  return { main: list.filter((m) => !folded.has(m)), threads, orphans };
}
