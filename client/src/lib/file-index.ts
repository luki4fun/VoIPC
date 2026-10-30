// The media manager's list (Settings → Files): every file the chat on this
// device names, on every server and in every conversation, beside what of it
// this device keeps.
//
// One row per message, so a file posted in two places is listed in both; what
// this device keeps is per blob, so removing it removes it for both.
//
// Pure, so file-index.test.ts runs it under Node's own test runner.

import { hasExpired, splitChatKey, type ChatPlace } from "./chat-rules.ts";
import { fold, terms } from "./search-rules.ts";
import type { ChatMessage, FileRef } from "./types.ts";

export type FileKind = "image" | "video" | "audio" | "other";

/** A blob this device keeps (`file_cache_list`). */
export interface CachedBlob {
  hash: string;
  bytes: number;
  /** Unix ms. */
  last_used: number;
}

export interface FileRow {
  file: FileRef;
  msg: ChatMessage;
  place: ChatPlace;
  /** What its message says it is: for sorting files out only. What a loaded
   *  file is shown as comes from its bytes (`file-sniff.ts`). */
  kind: FileKind;
  /** The bytes this device keeps of it; null when it keeps none. */
  local: number | null;
  /** When this device last used its copy (Unix ms); null when it keeps none. */
  used: number | null;
}

export function fileKind(f: FileRef): FileKind {
  const top = f.mime?.split("/")[0];
  return top === "image" || top === "video" || top === "audio" ? top : "other";
}

/** Every file a live message in these conversations carries. */
export function fileRows(
  channels: ReadonlyMap<string, readonly ChatMessage[]>,
  dms: ReadonlyMap<string, readonly ChatMessage[]>,
  cached: readonly CachedBlob[],
  now = Date.now(),
): FileRow[] {
  const kept = new Map(cached.map((c) => [c.hash, c]));
  const out: FileRow[] = [];
  for (const [kind, map] of [["channel", channels], ["dm", dms]] as const) {
    for (const [key, messages] of map) {
      const at = splitChatKey(key);
      if (!at) continue;
      const place: ChatPlace = { kind, key, ...at };
      for (const msg of messages) {
        const file = msg.file;
        if (file && !hasExpired(msg, now)) {
          const copy = kept.get(file.hash);
          out.push({ file, msg, place, kind: fileKind(file), local: copy?.bytes ?? null, used: copy?.last_used ?? null });
        }
      }
    }
  }
  return out;
}

export type FileFilter = "all" | FileKind | "local";
export type FileSort = "date" | "used" | "size" | "name" | "sender";
export type FileGroup = "none" | "server" | "conversation" | "kind";

/** Rows under one heading: a server's `host:port`, a conversation's kind and
 *  key, or a kind; "" when not grouped. */
export interface FileSection {
  id: string;
  rows: FileRow[];
}

const KINDS: FileKind[] = ["image", "video", "audio", "other"];
const byText = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base", numeric: true });
const ORDER: Record<FileSort, (a: FileRow, b: FileRow) => number> = {
  date: () => 0,
  used: (a, b) => (b.used ?? -1) - (a.used ?? -1),
  size: (a, b) => b.file.size - a.file.size,
  name: (a, b) => byText(a.file.name, b.file.name),
  sender: (a, b) => byText(a.msg.username, b.msg.username),
};

/** What a row is found by: its file's name, who sent it (not their tag),
 *  the words that went with it, and where it was posted. */
function haystack(r: FileRow): string {
  const who = r.msg.username.replace(/#\d{4}$/, "");
  return fold(`${r.file.name}\n${who}\n${r.msg.content}\n${r.place.name}\n${r.place.server}`);
}

/**
 * The rows `filter` lets through, of the one conversation `place` names
 * (`"<kind> <key>"`) if it names one, and every word of `query` is found in
 * (case and accents ignored), in `sort`'s order (newest first where it leaves a
 * tie), under `group`'s headings. Headings come in the order of their first
 * row, so they follow the sort too; kinds keep their own order.
 */
export function arrangeFiles(
  rows: readonly FileRow[],
  {
    filter,
    sort,
    group,
    query = "",
    place = "",
  }: { filter: FileFilter; sort: FileSort; group: FileGroup; query?: string; place?: string },
): FileSection[] {
  const words = terms(query);
  const shown = rows.filter(
    (r) =>
      (filter === "all" || (filter === "local" ? r.local !== null : r.kind === filter)) &&
      (!place || `${r.place.kind} ${r.place.key}` === place) &&
      (words.length === 0 || ((h) => words.every((w) => h.includes(w)))(haystack(r))),
  );
  shown.sort((a, b) => ORDER[sort](a, b) || b.msg.timestamp - a.msg.timestamp);
  if (group === "none") return shown.length ? [{ id: "", rows: shown }] : [];
  const sections = new Map<string, FileRow[]>();
  for (const r of shown) {
    const id = group === "server" ? r.place.server : group === "conversation" ? `${r.place.kind} ${r.place.key}` : r.kind;
    const into = sections.get(id);
    if (into) into.push(r);
    else sections.set(id, [r]);
  }
  const out = [...sections].map(([id, rows]) => ({ id, rows }));
  if (group === "kind") out.sort((a, b) => KINDS.indexOf(a.id as FileKind) - KINDS.indexOf(b.id as FileKind));
  return out;
}
