// What came from Discord, for the pane (ArchivePane.svelte). Pure, so the tests load it
// under Node. Never `ChatMessage`, never the device's chat history: the relay can read
// these rows and nobody signed them, so they stay in their own list under their label.
//
// A Discord id does not survive a JS number: everything here is a decimal string and
// compares as one. `Number("1454987148113234751")` and `...752` are the same number.

import type { ArchiveRow } from "./types.js";

/** What the pane says of itself, always on screen. */
export const ARCHIVE_LABEL = "Imported from Discord, unverified. This server can read it.";
/** `SearchPane` says nothing is sent anywhere. Here the relay gets the words. */
export const ARCHIVE_SEARCH_HINT = "Search this archive. The server sees what you search.";
export const HIDDEN_LINE = "Only you see this. Whoever runs this server still has it.";

/** A thread's opening row that its author or an operator took back: the way in to the others'
 *  replies stays, under this name (voipc_protocol's `THREAD_TAKEN_BACK`). */
export const THREAD_TAKEN_BACK = "Thread";

/** Rows held at once; past it "Go further back" starts the list again from there. */
export const LIST_CAP = 5_000;
/** Hits shown before a search waits to be asked for more. */
export const SEARCH_HITS = 50;

/** Older first by size, then by digits. Never through `Number`. */
export function compareIds(a: string, b: string): number {
  return a.length - b.length || (a < b ? -1 : a > b ? 1 : 0);
}

/** A row's time as a `Date` can hold it. Past that, `toISOString` throws while the row draws,
 *  with nothing above to catch it. The time is the relay's word and it may say anything. */
const timeHeld = (row: ArchiveRow): ArchiveRow => (Number.isFinite(new Date(row.at_ms).getTime()) ? row : { ...row, at_ms: 0 });

/** What is shown, with a page added: newest first, and each row once, since a repeated
 *  id stops a keyed each and the whole panel with it. The row that came last is kept. */
export function mergeArchiveRows(had: readonly ArchiveRow[], page: readonly ArchiveRow[]): ArchiveRow[] {
  const byId = new Map<string, ArchiveRow>();
  for (const row of [...had, ...page]) byId.set(row.id, timeHeld(row));
  return [...byId.values()].sort((a, b) => compareIds(b.id, a.id));
}

/** The `before` that ends a page at this row, so it is on it: one past it. */
export function idAfter(id: string): string {
  return /^\d+$/.test(id) ? (BigInt(id) + 1n).toString() : "";
}

/** A row's reactions, each emoji once: read only, and a keyed each goes over them. */
export function archiveChips(row: Pick<ArchiveRow, "reactions">): { emoji: string; count: number }[] {
  const byEmoji = new Map<string, number>();
  for (const r of row.reactions) byEmoji.set(r.emoji, (byEmoji.get(r.emoji) ?? 0) + r.count);
  return [...byEmoji].map(([emoji, count]) => ({ emoji, count }));
}

/** The first words of a body, on one line. */
export function firstWords(body: string, chars = 60): string {
  const line = body.replace(/\s+/g, " ").trim();
  const shown = [...line];
  return shown.length <= chars ? line : `${shown.slice(0, chars).join("").trimEnd()}…`;
}

/** "replying to" on a row that answers another: who and what when that row is loaded. */
export function replyLine(row: Pick<ArchiveRow, "reply_to">, loaded: readonly ArchiveRow[]): string {
  const to = loaded.find((r) => r.id === row.reply_to);
  return to && to.body ? `replying to ${to.author}: ${firstWords(to.body)}` : "replying to an earlier message";
}

/** "12 replies, Thread name". */
export function threadOpener(row: Pick<ArchiveRow, "replies" | "thread_name">): string {
  return `${row.replies.toLocaleString("en-US")} ${row.replies === 1 ? "reply" : "replies"}, ${row.thread_name}`;
}

/** How far a search has looked, while it goes. */
export function lookedAt(scanned: number): string {
  return `Looked at ${scanned.toLocaleString("en-US")} ${scanned === 1 ? "message" : "messages"}`;
}

/** A refusal that means "in a moment": wait a second and go on, as the relay's budget
 *  and its two searches at once both allow. */
export function refusedForNow(reason: string): boolean {
  return /too many requests|busy searching/i.test(reason);
}

/** What a page tells of a channel: it has an archive if anything was there to look at,
 *  rows or not. A page of rows nobody may see still has somewhere to go on to. */
export function pageHasArchive(page: { rows: readonly unknown[]; next: string }): boolean {
  return page.rows.length > 0 || page.next !== "";
}

/** A row that opens a thread, as the relay serves it once it was taken back. */
export function takenBack(row: ArchiveRow): ArchiveRow {
  return { ...row, author: "", author_id: "", body: "", reply_to: "", reactions: [], pinned: false, thread_name: THREAD_TAKEN_BACK, mine: false, hidden: false };
}

/** Nothing of anyone's is left on it: no author, and nothing for an operator to delete. */
export function isTakenBack(row: Pick<ArchiveRow, "thread_name" | "author" | "author_id" | "body">): boolean {
  return row.thread_name === THREAD_TAKEN_BACK && !row.author && !row.author_id && !row.body;
}

/** What the rows on screen are after someone's own step on one of them. A row that opens a
 *  thread stays when deleted, as the way in to the replies under it. */
export function afterMine(rows: readonly ArchiveRow[], action: "Hide" | "Show" | "Delete", id: string): ArchiveRow[] {
  if (action === "Delete") return rows.flatMap((r) => (r.id !== id ? [r] : r.thread_name ? [takenBack(r)] : []));
  return rows.map((r) => (r.id === id ? { ...r, hidden: action === "Hide" } : r));
}

/** What an operator's delete came to. They go for readers at once, and from the disk soon after. */
export function archiveDeletedLine(rows: number): string {
  if (rows === 0) return "No imported posts matched: nothing was deleted.";
  return `${rows.toLocaleString("en-US")} imported ${rows === 1 ? "post" : "posts"} deleted.`;
}

/** What Hide all, Show all or Delete all came to: nothing else on screen changes for the first two. */
export function mineDoneLine(action: "Hide" | "Show" | "Delete", rows: number): string {
  const done = action === "Hide" ? "hidden" : action === "Show" ? "shown again" : "deleted";
  return `${rows.toLocaleString("en-US")} of your posts ${done}.`;
}

/** The line in Settings about someone's own rows. */
export function mineLine(rows: number): string {
  if (rows === 0) return "None of your posts came over from Discord.";
  return `${rows.toLocaleString("en-US")} of your posts ${rows === 1 ? "is" : "are"} here from Discord.`;
}
