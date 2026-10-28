// Which files the chat on this device still refers to.
//
// A blob stays in this device's cache, and is handed to a member who asks
// for it again (a re-seed), only while a message here names it: a file goes
// when its last message goes (timer, clear, purge), the way the text does.
//
// Pure, so file-rules.test.ts runs it under Node's own test runner.

import type { ChatMessage } from "./types.ts";

/** A message that is still here at `now`: its timer, if any, has not run out. */
function live(m: ChatMessage, now: number): boolean {
  return m.expires_at === undefined || m.expires_at > now;
}

/** Whether a message in `messages` names the blob `hash`. */
export function refersTo(messages: readonly ChatMessage[] | undefined, hash: string, now = Date.now()): boolean {
  return !!messages?.some((m) => m.file?.hash === hash && live(m, now));
}

/** Every blob some message in these conversations names. */
export function referencedHashes(
  maps: readonly ReadonlyMap<string, readonly ChatMessage[]>[],
  now = Date.now(),
): string[] {
  const out = new Set<string>();
  for (const map of maps) {
    for (const messages of map.values()) {
      for (const m of messages) if (m.file && live(m, now)) out.add(m.file.hash);
    }
  }
  return [...out];
}

// ── The preview ─────────────────────────────────────────────────────────

/** The preview's side, in pixels (envelope.rs `PREVIEW_BYTES` = 16×16 RGB). */
export const PREVIEW_SIDE = 16;
const PREVIEW_PIXELS = PREVIEW_SIDE * PREVIEW_SIDE;

/** A 16×16 RGBA drawing as a message carries it: its RGB, base64. */
export function previewOf(rgba: ArrayLike<number>): string {
  let bin = "";
  for (let i = 0; i < PREVIEW_PIXELS; i++) {
    bin += String.fromCharCode(rgba[i * 4] ?? 0, rgba[i * 4 + 1] ?? 0, rgba[i * 4 + 2] ?? 0);
  }
  return btoa(bin);
}

/** And back, as `ImageData` takes it: opaque RGBA. Null for anything that is
 *  not exactly 768 bytes (`fileRef` checks the same). */
export function previewPixels(px: string): Uint8ClampedArray<ArrayBuffer> | null {
  let bin: string;
  try {
    bin = atob(px);
  } catch {
    return null;
  }
  if (bin.length !== PREVIEW_PIXELS * 3) return null;
  const out = new Uint8ClampedArray(PREVIEW_PIXELS * 4);
  for (let i = 0; i < PREVIEW_PIXELS; i++) {
    out[i * 4] = bin.charCodeAt(i * 3);
    out[i * 4 + 1] = bin.charCodeAt(i * 3 + 1);
    out[i * 4 + 2] = bin.charCodeAt(i * 3 + 2);
    out[i * 4 + 3] = 255;
  }
  return out;
}

// ── Sending ─────────────────────────────────────────────────────────────

/** The long side a photo is brought down to when it is sent compressed. */
export const PHOTO_MAX_SIDE = 2560;

/** `w`×`h` brought within `max` on its long side, never up. */
export function fitWithin(w: number, h: number, max: number): { w: number; h: number } {
  const scale = Math.min(1, max / Math.max(w, h));
  return { w: Math.max(1, Math.round(w * scale)), h: Math.max(1, Math.round(h * scale)) };
}

/** `name` with its extension changed to `ext` (a re-encoded picture). */
export function withExtension(name: string, ext: string): string {
  const dot = name.lastIndexOf(".");
  return `${dot > 0 ? name.slice(0, dot) : name}.${ext}`;
}

/** How long the blob of a `body`-byte file is once sealed (file.rs
 *  `sealed_len`): what a relay's cap is held against. */
export function sealedLen(body: number): number {
  return 32 + body + 16 * Math.max(1, Math.ceil(body / 65_536));
}

/** Sizes as people read them. */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

// ── Saving ──────────────────────────────────────────────────────────────

/** What Windows will not have in a name; Linux and Android refuse `/`. */
const NOT_IN_NAME = /[<>:"/\\|?*\p{Cc}\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069\ufeff]/gu;
const RESERVED = /^(con|prn|aux|nul|conin\$|conout\$|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])(\..*)?$/i;
const MAX_SAVE_NAME = 120;

/**
 * A sender's file name as it may be saved on any system: no path in it, none
 * of Windows' reserved names or forbidden characters, no trailing dots or
 * spaces, and not so long that a file system refuses it. The extension is
 * kept where it can be, so the system opens it the way its name says.
 */
export function saveName(name: string): string {
  // Leading dots first: a hidden name, and `.con.txt` must still meet the check
  let n = name.replace(NOT_IN_NAME, "_").trim().replace(/^\.+/, "").replace(/[. ]+$/, "");
  if (RESERVED.test(n)) n = `_${n}`;
  const chars = Array.from(n);
  if (chars.length > MAX_SAVE_NAME) {
    const dot = n.lastIndexOf(".");
    const ext = dot > 0 && n.length - dot <= 16 ? n.slice(dot) : "";
    const base = Array.from(n.slice(0, n.length - ext.length)).slice(0, MAX_SAVE_NAME - ext.length).join("");
    n = base.replace(/[. ]+$/, "") + ext;
  }
  return n || "file";
}

/** Bytes per staged chunk on Android (D2-03): 1 MiB, about 1.4 MB of base64 a call. */
export const STAGE_CHUNK = 1024 * 1024;

/**
 * `bytes` as base64 chunks of at most `size` bytes each, for `file_stage`:
 * Android's IPC carries no raw body, and a Uint8Array would go as a JSON array
 * of numbers, four times the size and more. An empty file is one empty chunk,
 * so its stage exists.
 */
export function base64Chunks(bytes: Uint8Array, size = STAGE_CHUNK): string[] {
  if (bytes.length === 0) return [""];
  const out: string[] = [];
  for (let at = 0; at < bytes.length; at += size) {
    const part = bytes.subarray(at, Math.min(at + size, bytes.length));
    // String.fromCharCode in pieces: one call with a million arguments overflows
    let bin = "";
    for (let i = 0; i < part.length; i += 0x8000) {
      bin += String.fromCharCode(...part.subarray(i, i + 0x8000));
    }
    out.push(btoa(bin));
  }
  return out;
}
