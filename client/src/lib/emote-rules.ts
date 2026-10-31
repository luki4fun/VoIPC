// A server's emotes in what people write (protocol v14).
//
// Typed as `:name:`, an emote goes out as `<:name:hash>`: its name and the
// first 32 hex digits of its file's SHA-256 (20 before 1.5), inside the
// message text, which
// is end-to-end encrypted like the rest of it. What the sender saw is what
// every reader sees: a reader shows the picture only while the server lists a
// file of that hash, so an admin who later puts another picture under the
// name cannot change old messages; one renamed still shows. Anything else is
// read as the `:name:` it was. A message that is a sticker's token and
// nothing else is that sticker.
//
// Reactions are `:name:` alone (an emoji field holds 32 bytes): they show the
// server's current picture of that name.
//
// Pure, so emote-rules.test.ts runs it under Node's own test runner.

import { EMOJI_NAMES } from "./emoji.ts";

/** How much of a file's hash a token carries: 128 bits, so no admin or relay
 *  can make two pictures that share it. 1.4 sent 80 (`OLD_TOKEN_HASH`), still
 *  read. */
export const TOKEN_HASH = 32;
const OLD_TOKEN_HASH = 20;

/** `<:name:hash>`: one emote in a message. */
export const EMOTE_TOKEN = /<:([a-z0-9_]{2,30}):([0-9a-f]{32}|[0-9a-f]{20})>/g;

const NAME = /^[a-z0-9_]{2,30}$/;

/** What an emote or sticker the server lists is, here. */
export interface Emote {
  name: string;
  /** Its file's SHA-256, hex. */
  hash: string;
  sticker: boolean;
  pack: string;
  /** Its file's size, in bytes. */
  len: number;
  /** Its shape as the adding admin's app made it; 0 where unknown. Only the
   *  room kept for it before it is drawn. */
  w: number;
  h: number;
}

/** Code (fenced or inline) is left as it was written. shortcut: a rule of
 *  thumb for what marked reads as code (no indented blocks); walk marked's
 *  tokens if a case shows up. */
const CODE = /(```[\s\S]*?(?:```|$)|~~~[\s\S]*?(?:~~~|$)|``[^\n]*?``|`[^`\n]*`)/g;

/**
 * `:name:` for each of `emotes` that is not a sticker turned into its token,
 * and any other `:name:` of an emoji (`EMOJI_NAMES`, `:joy:`) into that
 * emoji: outside code and outside tokens already there (so a forward, or a
 * text sent twice, comes out the same). The server's emote wins a name both
 * have.
 */
export function tokenize(text: string, emotes: readonly Emote[]): string {
  const byName = new Map(emotes.filter((e) => !e.sticker).map((e) => [e.name, e.hash]));
  if (!text.includes(":")) return text;
  const words = (s: string) =>
    s
      .split(EMOTE_TOKEN_SPLIT)
      .map((part, i) =>
        // Odd parts are tokens already
        i % 2 === 1
          ? part
          : // Not after `/`: inside an address it stays as written
            part.replace(/(^|[^a-z0-9_:</]):([a-z0-9_]{2,30}):(?![a-z0-9_:])/g, (all, before: string, name: string) => {
              const hash = byName.get(name);
              if (hash) return `${before}<:${name}:${hash.slice(0, TOKEN_HASH)}>`;
              return Object.hasOwn(EMOJI_NAMES, name) ? `${before}${EMOJI_NAMES[name]}` : all;
            }),
      )
      .join("");
  return text
    .split(CODE)
    .map((part, i) => (i % 2 === 1 ? part : words(part)))
    .join("");
}

/** The same tokens, as one capture each, for `split`. */
const EMOTE_TOKEN_SPLIT = /(<:[a-z0-9_]{2,30}:(?:[0-9a-f]{32}|[0-9a-f]{20})>)/;

/** Tokens back to the `:name:` they were typed as: for an edit box, a copy. */
export function untokenize(text: string): string {
  return text.replace(EMOTE_TOKEN, (_, name: string) => `:${name}:`);
}

/** Each list's emotes by the first 20 hex digits of their hash, made once
 *  per list: a chat full of tokens looks each up without a scan. */
const indexes = new WeakMap<readonly Emote[], Map<string, Emote[]>>();
function byHash(emotes: readonly Emote[]): Map<string, Emote[]> {
  let index = indexes.get(emotes);
  if (!index) {
    index = new Map();
    for (const e of emotes) {
      const k = e.hash.slice(0, OLD_TOKEN_HASH);
      index.set(k, [...(index.get(k) ?? []), e]);
    }
    indexes.set(emotes, index);
  }
  return index;
}

/** The emote or sticker a token's hash (or a whole hash) names, among what
 *  the server lists: the one of the token's name where one file has several.
 *  `sticker`: only of that kind. */
export function emoteOf(hash: string, emotes: readonly Emote[], name?: string, sticker?: boolean): Emote | undefined {
  if (![OLD_TOKEN_HASH, TOKEN_HASH, 64].includes(hash.length)) return undefined;
  const same = (byHash(emotes).get(hash.slice(0, OLD_TOKEN_HASH)) ?? []).filter(
    (e) => e.hash.startsWith(hash) && (sticker === undefined || e.sticker === sticker),
  );
  return same.find((e) => e.name === name) ?? same[0];
}

/** The sticker a message is: its whole text one token of a listed sticker. */
export function stickerOf(content: string, emotes: readonly Emote[]): Emote | undefined {
  const m = /^<:([a-z0-9_]{2,30}):([0-9a-f]{32}|[0-9a-f]{20})>$/.exec(content.trim());
  return m ? emoteOf(m[2], emotes, m[1], true) : undefined;
}

/** A sticker as a message's text. */
export function stickerText(e: Emote): string {
  return `<:${e.name}:${e.hash.slice(0, TOKEN_HASH)}>`;
}

/** "1 emote", "3 emotes and 1 sticker", "no emotes or stickers": counts in
 *  words, for the lines that tell what a server has or what is missing. */
export function countKinds(emotes: number, stickers: number): string {
  const n = (k: number, word: string) => `${k} ${word}${k === 1 ? "" : "s"}`;
  if (!emotes && !stickers) return "no emotes or stickers";
  if (!stickers) return n(emotes, "emote");
  if (!emotes) return n(stickers, "sticker");
  return `${n(emotes, "emote")} and ${n(stickers, "sticker")}`;
}

/** At most this many emotes alone make a message show them big. */
export const JUMBO_MAX = 27;

/** What makes a grapheme an emoji (chat-rules.ts `isOneEmoji`'s rule). */
const PICTOGRAPH = /[\p{Extended_Pictographic}\p{Regional_Indicator}\u20E3]/u;
const graphemes = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/** A message of emotes and emoji and nothing else (spaces aside), few
 *  enough: shown big. */
export function onlyEmotes(content: string): boolean {
  let n = content.match(EMOTE_TOKEN)?.length ?? 0;
  for (const { segment } of graphemes.segment(content.replace(EMOTE_TOKEN, " "))) {
    if (/^\s+$/.test(segment)) continue;
    if (!PICTOGRAPH.test(segment)) return false;
    n++;
  }
  return n > 0 && n <= JUMBO_MAX;
}

/** `:name:` as a reaction: a server emote's. */
export function isEmoteReaction(s: string): boolean {
  return s.startsWith(":") && s.endsWith(":") && NAME.test(s.slice(1, -1));
}

/** A reaction's emote among what the server lists now, by name. */
export function reactionEmote(s: string, emotes: readonly Emote[]): Emote | undefined {
  if (!isEmoteReaction(s)) return undefined;
  const name = s.slice(1, -1);
  return emotes.find((e) => e.name === name && !e.sticker);
}

/** `emotes` with those named in `recent` (newest first) ahead, in its
 *  order, and the rest after them as they were. */
export function byRecent<T extends { name: string }>(emotes: readonly T[], recent: readonly string[]): T[] {
  const at = (e: T) => {
    const i = recent.indexOf(e.name);
    return i < 0 ? recent.length : i;
  };
  return [...emotes].sort((a, b) => at(a) - at(b));
}

/** The emoji the `:` completion offers for `typed` after the server's
 *  emotes: names that start with it, then names that hold it, one per emoji. */
export function completeEmoji(
  typed: string,
  max = 8,
  shown: (emoji: string) => boolean = () => true,
): { name: string; emoji: string }[] {
  const t = typed.toLowerCase();
  const names = Object.keys(EMOJI_NAMES);
  const seen = new Set<string>();
  return [...names.filter((n) => n.startsWith(t)), ...names.filter((n) => !n.startsWith(t) && n.includes(t))]
    .map((name) => ({ name, emoji: EMOJI_NAMES[name] }))
    // `shown`: what this system draws (emoji-support.ts `drawsAsOne`)
    .filter((o) => shown(o.emoji) && !seen.has(o.emoji) && !!seen.add(o.emoji))
    .slice(0, max);
}

/** `list` by pack, the packs by name: the one without a name first. */
export function byPack<T extends { pack: string }>(list: readonly T[]): { key: string; label: string; list: T[] }[] {
  const packs = new Map<string, T[]>();
  for (const e of list) {
    const same = packs.get(e.pack);
    if (same) same.push(e);
    else packs.set(e.pack, [e]);
  }
  return [...packs].sort(([a], [b]) => a.localeCompare(b)).map(([pack, list]) => ({ key: `p:${pack}`, label: pack, list }));
}

/** The names the `:` completion offers for `typed`: those that start with
 *  it first, then those that hold it, each the recently used first, at most
 *  `max`. */
export function completeEmote(typed: string, emotes: readonly Emote[], max = 8, recent: readonly string[] = []): Emote[] {
  const t = typed.toLowerCase();
  const usable = emotes.filter((e) => !e.sticker);
  const starts = usable.filter((e) => e.name.startsWith(t));
  const holds = usable.filter((e) => !e.name.startsWith(t) && e.name.includes(t));
  return [...byRecent(starts, recent), ...byRecent(holds, recent)].slice(0, max);
}

/** An emote name from a file name: its stem in lower case, anything else as
 *  one `_` (not at either end), cut to 30; undefined if under two characters
 *  are left. */
export function nameFrom(file: string): string | undefined {
  const dot = file.lastIndexOf(".");
  const stem = dot > 0 && file.length - dot - 1 <= 5 ? file.slice(0, dot) : file;
  let out = "";
  for (const ch of stem) {
    const c = /^[A-Za-z]$/.test(ch) ? ch.toLowerCase() : ch;
    if (/^[a-z0-9]$/.test(c)) out += c;
    else if (out && !out.endsWith("_")) out += "_";
  }
  out = out.replace(/_+$/, "").slice(0, 30).replace(/_+$/, "");
  return NAME.test(out) ? out : undefined;
}

/** `base`, or `base_2`, `base_3`… cut to fit, the first not `taken`. */
export function uniqueName(base: string, taken: (name: string) => boolean): string | undefined {
  if (!taken(base)) return base;
  for (let n = 2; n < 1000; n++) {
    const tail = `_${n}`;
    const name = `${base.slice(0, 30 - tail.length).replace(/_+$/, "")}${tail}`;
    if (NAME.test(name) && !taken(name)) return name;
  }
  return undefined;
}

/** The most emotes and stickers a server lists (voipc-protocol `MAX_EMOTES`). */
const MAX_EMOTES = 400;

/** A pack label a person may see (voipc-protocol `valid_emote_pack`): one
 *  line, no control, invisible or direction characters, at most 32
 *  characters and 64 bytes. */
export function validPack(p: string): boolean {
  return (
    p.trim() === p &&
    [...p].length <= 32 &&
    new TextEncoder().encode(p).length <= 64 &&
    !/[\p{Cc}\u200B-\u200F\u061C\u202A-\u202E\u2060-\u2069\uFEFF]/u.test(p)
  );
}

/** A relay's list as this app takes it: valid names, hashes and packs only,
 *  the first of each name, at most `MAX_EMOTES`. A hostile relay could send
 *  anything, and a name twice breaks every list keyed by name. */
export function cleanList(emotes: readonly Emote[]): Emote[] {
  const seen = new Set<string>();
  return emotes
    .filter((e) => NAME.test(e.name) && /^[0-9a-f]{64}$/.test(e.hash) && validPack(e.pack) && !seen.has(e.name) && !!seen.add(e.name))
    .slice(0, MAX_EMOTES)
    .map((e) => ({ ...e, len: whole(e.len, 2 ** 32 - 1), ...boxed(e.w, e.h, BOX[e.sticker ? 1 : 0]) }));
}

/** A shape held to its box by one factor, so it keeps its proportions (an
 *  emote made a sticker, or back, is listed with its old shape). */
function boxed(w: unknown, h: unknown, side: number): { w: number; h: number } {
  const [x, y] = [whole(w, Infinity), whole(h, Infinity)];
  // A side missing: no shape to keep, each held on its own
  if (!x || !y) return { w: Math.min(x, side), h: Math.min(y, side) };
  const k = Math.min(1, side / Math.max(x, y));
  return { w: Math.max(1, Math.round(x * k)), h: Math.max(1, Math.round(y * k)) };
}

/** voipc-media's emote and sticker boxes. */
const BOX = [128, 320] as const;

/** `n` as a whole number from 0 to `max`; 0 where it is none. */
function whole(n: unknown, max: number): number {
  return Number.isInteger(n) ? Math.min(Math.max(n as number, 0), max) : 0;
}
