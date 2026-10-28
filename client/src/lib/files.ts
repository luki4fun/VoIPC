// Files in chat, as the rest of the front end reaches them: the same commands
// on the desktop (client/src-tauri/src/files.rs) and in the browser
// (web/backend/files.ts). The bytes never touch the voice connection; the
// key never leaves the message (`ChatMessage.file`).

import { invoke } from "@tauri-apps/api/core";
import { get, writable } from "svelte/store";
import { base64Chunks, referencedHashes, refersTo } from "./file-rules";
import type { FileBlob, FileConv } from "./types";
import type { ChatPlace } from "./chat-rules";
import { accountHex } from "./stores/account";
import { channelMessages, chatKey, chatUnlocked, dmConversations, dmKey, dmMessages } from "./stores/chat";
import { channels } from "./stores/channels";
import { chatHistoryDisabled } from "./stores/settings";
import { users } from "./stores/users";
import { scoped } from "./stores/scoped";
import { isAndroidApp, isWeb } from "./stores/platform";
import { addNotification } from "./stores/notifications";
import { saveName } from "./file-rules";

/** What each relay takes (`Authenticated.files`), from `file-limits`; null
 *  for one that keeps no files, where the composer offers none. */
export const fileLimits = scoped<{ max_bytes: number } | null>(() => null);

/** What `fetchFile` fails with when nobody online had the file in time. */
export const FILE_UNAVAILABLE = "Nobody online has this file";

/** How far a transfer is (`file-progress`): "seeking" while the relay asks
 *  the conversation's members for a file it no longer has. */
export interface FileProgress {
  op: string;
  stage: "up" | "down" | "seeking";
  done: number;
  total: number;
}

/** Transfers under way, by their op id: the cards' and the composer's bars. */
export const fileProgress = writable<Map<string, FileProgress>>(new Map());

/** Transfers this page started and has not finished: a late `file-progress`
 *  after the end brings no bar back. */
const live = new Set<string>();

/** `file-progress` in, from App.svelte. */
export function noteProgress(p: FileProgress): void {
  if (live.has(p.op)) fileProgress.update((m) => new Map(m).set(p.op, p));
}

/** A transfer is over: its bar goes. */
export function forgetProgress(op: string): void {
  live.delete(op);
  fileProgress.update((m) => {
    if (!m.has(op)) return m;
    const next = new Map(m);
    next.delete(op);
    return next;
  });
}

/** A fresh id for a transfer, for `file-progress` and `cancelFile`. */
export function newOp(): string {
  const op = `f${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  live.add(op);
  return op;
}

/** JSON with everything past ASCII escaped: a header carries ASCII only. */
function asciiJson(v: unknown): string {
  return JSON.stringify(v).replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/**
 * Seal `bytes` and store them on `server` for a message in `conv`. What comes
 * back goes in that message's `file`; sending it is the caller's. `compress`
 * deflates the file where that helps (not for images: they are compressed
 * already). `op` names it for `file-progress` and `cancelFile`.
 */
export async function sendFile(server: string, conv: FileConv, bytes: Uint8Array, compress: boolean, op?: string): Promise<FileBlob> {
  const headers = { "x-voipc-file": asciiJson({ server, conv, compress, op }) };
  if (!isAndroidApp) return invoke<FileBlob>("send_file", bytes, { headers });
  // Under the op, so a cancel while it stages lets the bytes go too
  const id = op ?? stageId();
  return invoke<FileBlob>("send_file", {}, { headers: { ...headers, ...(await stage(bytes, id)) } });
}

/**
 * Android's IPC carries no raw request body (Tauri reads one only through a
 * custom protocol the Android WebView lacks), so the bytes go over first in
 * base64 chunks (`file_stage`), and the command names the stage (D2-03).
 */
async function stage(bytes: Uint8Array, id: string): Promise<Record<string, string>> {
  for (const chunk of base64Chunks(bytes)) await invoke("file_stage", { id, chunk });
  return { "x-voipc-staged": id };
}

function stageId(): string {
  return `s${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

/** Loads under way, by server and blob: two messages with one file (or a
 *  second click) share one, rather than fetching and paying for it twice. */
const loading = new Map<string, Promise<Uint8Array>>();

/** The file a message in `conv` carries, opened: from this device's cache, or
 *  from the relay, which may first ask the conversation's members for it. */
export function fetchFile(server: string, conv: FileConv, file: FileBlob, op?: string): Promise<Uint8Array> {
  const key = `${server} ${file.hash}`;
  let load = loading.get(key);
  if (!load) {
    load = invoke<ArrayBuffer>("fetch_file", { server, conv, file, op })
      .then((bytes) => new Uint8Array(bytes))
      .finally(() => loading.delete(key));
    loading.set(key, load);
  }
  return load;
}

export function cancelFile(op: string): Promise<void> {
  return invoke("cancel_file", { op });
}

/**
 * Keep `bytes` where the person chooses, as `name` cleaned for any system
 * (`saveName`). Never opened or run. The browser downloads it; the desktop
 * asks with a save dialog; Android hands it to the system's "save to" picker
 * (MainActivity.kt `saveFile`).
 */
export async function saveFile(bytes: Uint8Array, name: string, mime = "application/octet-stream"): Promise<void> {
  const as = saveName(name);
  if (isWeb) {
    const url = URL.createObjectURL(new Blob([bytes as Uint8Array<ArrayBuffer>], { type: "application/octet-stream" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = as;
    a.click();
    // The download has the bytes once it starts
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    return;
  }
  const headers = { "x-voipc-save": asciiJson(as) };
  const path = isAndroidApp
    ? await invoke<string | null>("save_file", {}, { headers: { ...headers, ...(await stage(bytes, stageId())) } })
    : await invoke<string | null>("save_file", bytes, { headers });
  if (!path) return;
  const bridge = (window as { __VoIPC?: { saveFile?: (path: string, name: string, mime: string) => void } }).__VoIPC;
  // Android: the system's picker asks where, and answers in __voipc_saved
  if (bridge?.saveFile) bridge.saveFile(path, as, mime);
  else addNotification("Saved");
}

// Android's picker answers here (MainActivity.kt `finishSave`): true saved,
// false failed, null backed out of
if (typeof window !== "undefined") {
  (window as { __voipc_saved?: (ok: boolean | null) => void }).__voipc_saved = (ok) => {
    if (ok === true) addNotification("Saved");
    else if (ok === false) addNotification("The file could not be saved", "error");
  };
}

/** The messages of `server`'s conversation `conv`, if it is one here. */
function messagesOf(server: string, conv: FileConv) {
  if ("channel" in conv) {
    const name = get(channels.peek(server)).find((c) => c.channel_id === conv.channel)?.name;
    return name ? get(channelMessages).get(chatKey(server, name)) : undefined;
  }
  // The relay names a direct conversation by user id only while that person
  // is here, and ids are handed out again after a restart: who holds the id
  // now is the online list's to say, never a conversation filed earlier
  const name =
    "direct" in conv
      ? get(users.peek(server)).find((u) => u.user_id === conv.direct)?.username
      : get(dmConversations.peek(server)).find((c) => c.account === conv.account)?.username;
  return name ? get(dmMessages).get(dmKey(server, name)) : undefined;
}

/**
 * How the relay names the conversation at `place` on `server`, to fetch a
 * file of it: a channel by id; a person by user id while someone of that name
 * is here, else by their account (ChatPanel's `fileConvOf`); null where
 * nothing names it now.
 */
export function fileConvAt(server: string, place: ChatPlace): FileConv | null {
  if (place.kind === "channel") {
    const id = get(channels.peek(server)).find((c) => c.name === place.name)?.channel_id;
    return id ? { channel: id } : null;
  }
  const here = get(users.peek(server)).find((u) => u.username === place.name);
  if (here && here.user_id > 0) return { direct: here.user_id };
  const account =
    get(dmConversations.peek(server)).find((c) => c.username === place.name)?.account ??
    (here?.account ? accountHex(here.account) : undefined);
  return account ? { account } : null;
}

/**
 * `file-wanted`: the relay asks `conv` for a blob it no longer has, and this
 * device holds it. Upload it again only if a message there names it, so
 * nobody can learn what this device holds from elsewhere. Silent either way.
 */
export function answerFileWanted(server: string, conv: FileConv, hash: string): void {
  if (!refersTo(messagesOf(server, conv), hash)) return;
  invoke("reseed_file", { server, conv, hash }).catch((e) => console.debug("re-seed refused:", e));
}

/** How long the chat stays still before the cache is checked against it, and
 *  the longest a busy chat puts that off. */
const RETAIN_DELAY_MS = 5_000;
const RETAIN_MAX_WAIT_MS = 60_000;

/**
 * Keep the file cache to the blobs some message here still names, a moment
 * after the chat changes: what a timer, a clear or a purge took, goes from
 * the cache too. Never while the archive is locked, since its messages are
 * not here to count. Returns the stop.
 */
export function startFileRetain(): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let since: number | null = null;
  const run = () => {
    since = null;
    if (!get(chatUnlocked) && !get(chatHistoryDisabled)) return;
    const hashes = referencedHashes([get(channelMessages), get(dmMessages)]);
    invoke("file_cache_retain", { hashes }).catch((e) => console.warn("file cache:", e));
  };
  const schedule = () => {
    clearTimeout(timer);
    since ??= Date.now();
    timer = setTimeout(run, Math.max(0, Math.min(RETAIN_DELAY_MS, since + RETAIN_MAX_WAIT_MS - Date.now())));
  };
  const stops = [channelMessages, dmMessages, chatUnlocked, chatHistoryDisabled].map((s) => s.subscribe(schedule));
  return () => {
    stops.forEach((stop) => stop());
    clearTimeout(timer);
  };
}
