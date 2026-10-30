// An admin's import of emotes and stickers: what was picked (pictures, a
// folder, a .zip or .wastickers), each made ready by the sanitizer
// (`prepare_emote`: what to upload, and the PNG to preview), named, and added
// (`emote_add`). Only the sanitizer's PNG is ever shown of a picked file.

import { invoke } from "@tauri-apps/api/core";
import { asciiJson, invokeWithBytes } from "./files";

/** A body of a JSON head (its length first, 4 bytes little-endian) and the
 *  byte parts it gives the lengths of, in order. */
function unframe<H>(buf: ArrayBuffer, lengths: (head: H) => number[]): { head: H; parts: Uint8Array[] } {
  const all = new Uint8Array(buf);
  const len = new DataView(buf).getUint32(0, true);
  const head = JSON.parse(new TextDecoder().decode(all.subarray(4, 4 + len))) as H;
  let at = 4 + len;
  const parts = lengths(head).map((n) => {
    const part = all.slice(at, at + n);
    at += n;
    return part;
  });
  return { head, parts };
}

/** The files of a .zip or .wastickers, read in memory by the sanitizer's
 *  crate: names only ever name emotes, nothing touches the disk. */
export async function readPack(
  bytes: Uint8Array,
): Promise<{ title: string | null; entries: { name: string; bytes: Uint8Array }[]; skipped: { name: string; why: string }[] }> {
  const buf = await invokeWithBytes<ArrayBuffer>("read_emote_pack", bytes, {});
  const { head, parts } = unframe<{ title: string | null; entries: { name: string; len: number }[]; skipped?: { name: string; why: string }[] }>(
    buf,
    (h) => h.entries.map((e) => e.len),
  );
  return { title: head.title, entries: head.entries.map((e, i) => ({ name: e.name, bytes: parts[i] })), skipped: head.skipped ?? [] };
}

/** One-click import (desktop only, emote_sources.rs): a Discord server's
 *  emojis or stickers, a 7TV set, a Twitch channel's BetterTTV emotes; as a
 *  pack, and what was passed over. */
export async function fetchSource(
  source: "discord" | "7tv" | "bttv",
  id: string,
  token: string,
  stickers: boolean,
): Promise<{ title: string | null; entries: { name: string; bytes: Uint8Array }[]; skipped: { name: string; why: string }[] }> {
  const buf = await invoke<ArrayBuffer>("fetch_emote_source", { source, id, token: token || null, stickers });
  const { head, parts } = unframe<{ title: string | null; entries: { name: string; len: number }[]; skipped: { name: string; why: string }[] }>(
    buf,
    (h) => h.entries.map((e) => e.len),
  );
  return { title: head.title, entries: head.entries.map((e, i) => ({ name: e.name, bytes: parts[i] })), skipped: head.skipped ?? [] };
}

/** How what goes up was made: the sanitizer's own (clean), the file as it
 *  was, or the sanitizer's with frames dropped, or its first frame only. */
export type Made = "clean" | "original" | "trimmed" | "still";

export interface Prepared {
  w: number;
  h: number;
  frames: number;
  how: Made;
  upload: Uint8Array;
  /** The sanitizer's PNG: what the importer shows. */
  preview: Uint8Array;
  still: Uint8Array | null;
}

export async function prepareEmote(bytes: Uint8Array, sticker: boolean, maxBytes: number): Promise<Prepared> {
  const buf = await invokeWithBytes<ArrayBuffer>("prepare_emote", bytes, {
    "x-voipc-prepare": asciiJson({ sticker, max_bytes: maxBytes }),
  });
  const { head, parts } = unframe<{ w: number; h: number; frames: number; how: Made; upload: number; preview: number; still: number }>(
    buf,
    (h) => [h.upload, h.preview, h.still],
  );
  return { w: head.w, h: head.h, frames: head.frames, how: head.how, upload: parts[0], preview: parts[1], still: head.still ? parts[2] : null };
}

/** Add one (admins): done when the server has it. */
export function addEmote(server: string, name: string, sticker: boolean, pack: string, upload: Uint8Array): Promise<void> {
  return invokeWithBytes<void>("emote_add", upload, { "x-voipc-emote": asciiJson({ server, name, sticker, pack }) });
}

/** An emote's file as the server keeps it (admins), checked against its hash:
 *  only ever handed back to `addEmote`, never shown. */
export async function emoteFile(server: string, hash: string): Promise<Uint8Array> {
  return new Uint8Array(await invoke<ArrayBuffer>("emote_file", { server, hash }));
}

export const removeEmote = (server: string, name: string) => invoke("emote_remove", { server, name });
export const renameEmote = (server: string, from: string, to: string) => invoke("emote_rename", { server, from, to });
export const setStickers = (server: string, on: boolean) => invoke("emote_stickers", { server, on });

/** Whether `bytes` are a zip archive (a .wastickers is one). */
export function isArchive(bytes: Uint8Array): boolean {
  return bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}
