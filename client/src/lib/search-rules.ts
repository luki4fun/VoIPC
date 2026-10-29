// Finding things in the chat this device holds.
//
// Search never leaves the device: it reads the conversations already in
// memory (every server's, with the archive unlocked), so the relay learns
// nothing from it. A message matches when every word typed is somewhere in
// what it reads as (its text without markup) or in its writer's name, with
// case and accents ignored.
//
// Pure, so search-rules.test.ts runs it under Node's own test runner.

import { plainText } from "./markdown.ts";
import type { ChatMessage } from "./types.ts";

/** Lower case, without accents: "Café" finds "cafe" and the other way round. */
export function fold(s: string): string {
  return s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
}

/** The words of a query, folded. */
export function terms(query: string): string[] {
  return fold(query).split(/\s+/).filter((t) => t !== "");
}

/** What a message is searched as, worked out once per message. */
const haystacks = new WeakMap<ChatMessage, string>();
function haystack(m: ChatMessage): string {
  let h = haystacks.get(m);
  if (h === undefined) {
    // The tag is not part of how anybody refers to a person
    const name = m.username.replace(/#\d{4}$/, "");
    // A file's name too: what people remember a file by
    h = fold(`${plainText(m.content)}\n${name}\n${m.file?.name ?? ""}`);
    haystacks.set(m, h);
  }
  return h;
}

/** A message with something worth finding in it: not one of our dividers, not a placeholder. */
function searchable(m: ChatMessage): boolean {
  return m.kind !== "history-marker" && m.kind !== "notice" && m.kind !== "undecryptable" && m.kind !== "deleted";
}

export interface Hit<C> {
  conv: C;
  msg: ChatMessage;
}

/**
 * Every message in `convs` that holds all of `query`'s words, newest first,
 * at most `limit` of them. An empty query finds nothing.
 */
export function searchMessages<C>(
  convs: Iterable<{ conv: C; messages: readonly ChatMessage[] }>,
  query: string,
  limit = 100,
): Hit<C>[] {
  const want = terms(query);
  if (want.length === 0) return [];
  const hits: Hit<C>[] = [];
  for (const { conv, messages } of convs) {
    for (const msg of messages) {
      if (!searchable(msg)) continue;
      const h = haystack(msg);
      if (want.every((t) => h.includes(t))) hits.push({ conv, msg });
    }
  }
  return hits.sort((a, b) => b.msg.timestamp - a.msg.timestamp).slice(0, limit);
}

/** `text` folded, with where each folded character came from in `text`. */
function foldMapped(text: string): { folded: string; from: number[] } {
  let folded = "";
  const from: number[] = [];
  for (let i = 0; i < text.length; ) {
    const ch = String.fromCodePoint(text.codePointAt(i)!);
    const f = fold(ch);
    for (let k = 0; k < f.length; k++) from.push(i);
    folded += f;
    i += ch.length;
  }
  from.push(text.length);
  return { folded, from };
}

/**
 * A stretch of `text` around its first match, cut into pieces, each marked
 * when it is one of `want`: what a result row draws. Matched without case or
 * accents, shown as written.
 */
export function excerpt(text: string, want: string[], width = 120): { v: string; hit: boolean }[] {
  const { folded, from } = foldMapped(text);
  const ranges: [number, number][] = [];
  if (want.length > 0) {
    const pattern = new RegExp(want.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g");
    for (const m of folded.matchAll(pattern)) ranges.push([from[m.index], from[m.index + m[0].length]]);
  }
  const start = Math.max(0, (ranges[0]?.[0] ?? 0) - 30);
  const end = Math.min(text.length, start + width);
  const out: { v: string; hit: boolean }[] = [];
  if (start > 0) out.push({ v: "…", hit: false });
  let at = start;
  for (const [s, e] of ranges) {
    if (s < at || e > end) continue;
    if (s > at) out.push({ v: text.slice(at, s), hit: false });
    out.push({ v: text.slice(s, e), hit: true });
    at = e;
  }
  if (at < end) out.push({ v: text.slice(at, end), hit: false });
  if (end < text.length) out.push({ v: "…", hit: false });
  return out;
}
