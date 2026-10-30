// A server's emotes in what people write (protocol v14).
//
// Typed as `:name:`, an emote goes out as `<:name:hash>`: its name and the
// first 20 hex digits of its file's SHA-256, inside the message text, which
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

/** How much of a file's hash a token carries: 80 bits. */
export const TOKEN_HASH = 20;

/** `<:name:hash>`: one emote in a message. */
export const EMOTE_TOKEN = /<:([a-z0-9_]{2,30}):([0-9a-f]{20})>/g;

const NAME = /^[a-z0-9_]{2,30}$/;

/** What an emote or sticker the server lists is, here. */
export interface Emote {
  name: string;
  /** Its file's SHA-256, hex. */
  hash: string;
  sticker: boolean;
  pack: string;
}

/** Code (fenced or inline) is left as it was written. */
const CODE = /(```[\s\S]*?(?:```|$)|`[^`\n]*`)/g;

/**
 * `:name:` for each of `emotes` that is not a sticker turned into its token,
 * outside code and outside tokens already there (so a forward, or a text
 * sent twice, comes out the same).
 */
export function tokenize(text: string, emotes: readonly Emote[]): string {
  const byName = new Map(emotes.filter((e) => !e.sticker).map((e) => [e.name, e.hash]));
  if (byName.size === 0 || !text.includes(":")) return text;
  const words = (s: string) =>
    s
      .split(EMOTE_TOKEN_SPLIT)
      .map((part, i) =>
        // Odd parts are tokens already
        i % 2 === 1
          ? part
          : part.replace(/(^|[^a-z0-9_:<]):([a-z0-9_]{2,30}):(?![a-z0-9_:])/g, (all, before: string, name: string) => {
              const hash = byName.get(name);
              return hash ? `${before}<:${name}:${hash.slice(0, TOKEN_HASH)}>` : all;
            }),
      )
      .join("");
  return text
    .split(CODE)
    .map((part, i) => (i % 2 === 1 ? part : words(part)))
    .join("");
}

/** The same tokens, as one capture each, for `split`. */
const EMOTE_TOKEN_SPLIT = /(<:[a-z0-9_]{2,30}:[0-9a-f]{20}>)/;

/** Tokens back to the `:name:` they were typed as: for an edit box, a copy. */
export function untokenize(text: string): string {
  return text.replace(EMOTE_TOKEN, (_, name: string) => `:${name}:`);
}

/** The emote or sticker a token's hash names, among what the server lists:
 *  the one of the token's name where one file has several. */
export function emoteOf(hash: string, emotes: readonly Emote[], name?: string): Emote | undefined {
  if (hash.length !== TOKEN_HASH) return undefined;
  const same = emotes.filter((e) => e.hash.startsWith(hash));
  return same.find((e) => e.name === name) ?? same[0];
}

/** The sticker a message is: its whole text one token of a listed sticker. */
export function stickerOf(content: string, emotes: readonly Emote[]): Emote | undefined {
  const m = /^<:([a-z0-9_]{2,30}):([0-9a-f]{20})>$/.exec(content.trim());
  return m ? emoteOf(m[2], emotes.filter((e) => e.sticker), m[1]) : undefined;
}

/** A sticker as a message's text. */
export function stickerText(e: Emote): string {
  return `<:${e.name}:${e.hash.slice(0, TOKEN_HASH)}>`;
}

/** At most this many emotes alone make a message show them big. */
export const JUMBO_MAX = 27;

/** A message of emotes and nothing else (spaces aside), few enough. */
export function onlyEmotes(content: string): boolean {
  const tokens = content.match(EMOTE_TOKEN);
  return !!tokens && tokens.length <= JUMBO_MAX && content.replace(EMOTE_TOKEN, "").trim() === "";
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

/** The names the `:` completion offers for `typed`: those that start with
 *  it first, then those that hold it, at most `max`. */
export function completeEmote(typed: string, emotes: readonly Emote[], max = 8): Emote[] {
  const t = typed.toLowerCase();
  const usable = emotes.filter((e) => !e.sticker);
  const starts = usable.filter((e) => e.name.startsWith(t));
  const holds = usable.filter((e) => !e.name.startsWith(t) && e.name.includes(t));
  return [...starts, ...holds].slice(0, max);
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
