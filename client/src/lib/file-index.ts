// The media manager's list (Settings → Files): every file the chat on this
// device names, on every server and in every conversation, beside what of it
// this device keeps.
//
// One row per message, so a file posted in two places is listed in both; what
// this device keeps is per blob, so removing it removes it for both.
//
// Pure, so file-index.test.ts runs it under Node's own test runner.

import { hasExpired, splitChatKey, type ChatPlace } from "./chat-rules.ts";
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
  const kept = new Map(cached.map((c) => [c.hash, c.bytes]));
  const out: FileRow[] = [];
  for (const [kind, map] of [["channel", channels], ["dm", dms]] as const) {
    for (const [key, messages] of map) {
      const at = splitChatKey(key);
      if (!at) continue;
      const place: ChatPlace = { kind, key, ...at };
      for (const msg of messages) {
        const file = msg.file;
        if (file && !hasExpired(msg, now)) {
          out.push({ file, msg, place, kind: fileKind(file), local: kept.get(file.hash) ?? null });
        }
      }
    }
  }
  return out;
}

export type FileFilter = "all" | FileKind | "local";
export type FileSort = "date" | "size" | "name" | "sender";
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
  size: (a, b) => b.file.size - a.file.size,
  name: (a, b) => byText(a.file.name, b.file.name),
  sender: (a, b) => byText(a.msg.username, b.msg.username),
};

/**
 * The rows `filter` lets through, in `sort`'s order (newest first where it
 * leaves a tie), under `group`'s headings. Headings come in the order of
 * their first row, so they follow the sort too; kinds keep their own order.
 */
export function arrangeFiles(
  rows: readonly FileRow[],
  { filter, sort, group }: { filter: FileFilter; sort: FileSort; group: FileGroup },
): FileSection[] {
  const shown = rows.filter((r) => filter === "all" || (filter === "local" ? r.local !== null : r.kind === filter));
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
