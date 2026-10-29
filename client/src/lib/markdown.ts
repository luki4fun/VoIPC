// Chat markdown: what a message's text means, as a small tree of our own.
//
// marked does the reading — its lexer, never its HTML renderer — and what it
// finds is copied into a closed set of nodes. The chat draws only those, with
// Svelte, as text and elements of its own choosing: a peer's text never
// becomes HTML anywhere, so there is nothing to sanitise and nothing a
// sanitiser could miss. Raw HTML in a message is shown as the text it is; an
// image is a link, never fetched (fetching would tell the image's host who is
// reading); a link opens the copy popup, which shows where it really goes.
//
// Pure, so markdown.test.ts runs it under Node's own test runner.

import { Marked, type Token, type Tokens, type TokenizerExtension } from "marked";
import { shortName } from "./username.ts";

export type Inline =
  | { t: "text"; v: string }
  | { t: "strong" | "em" | "del" | "spoiler"; c: Inline[] }
  | { t: "code"; v: string }
  | { t: "link"; href: string; c: Inline[] }
  | { t: "br" }
  | { t: "mention"; name: string };

export type Block =
  | { t: "p"; c: Inline[] }
  | { t: "h"; level: 1 | 2 | 3; c: Inline[] }
  | { t: "pre"; lang: string; v: string }
  | { t: "quote"; c: Block[] }
  | { t: "list"; ordered: boolean; start: number; items: Block[][] }
  | { t: "hr" };

export interface ParseOptions {
  /**
   * Names an `@` may point at (members of the conversation, or just our own):
   * `@name` becomes a mention only for one of these, matched without regard to
   * case, longest first. Names may hold spaces, so nothing else could tell
   * where one ends.
   */
  names?: readonly string[];
}

/**
 * Past this a text is not read for markup at all: it is one plain paragraph.
 * Twice what the composer lets anyone type; only a modified client sends
 * more, and marked (and the code colours) take time that grows faster than
 * the text does, on every reader's screen.
 */
export const MAX_MARKUP_CHARS = 4000;
/** Quotes and lists inside each other, at most; a deeper one is its plain text. */
const MAX_BLOCK_DEPTH = 8;
/**
 * Everything drawn inside each other (the blocks above, then bold, italics,
 * strike, spoilers and links), at most: one counter runs through both. The
 * chat draws the tree recursively, and a few hundred levels overflow the
 * stack, which took every message of that conversation down with it.
 */
const MAX_DEPTH = 16;

/**
 * Runs of inline text (each run's token list) in which an opening `||` was
 * already sought to the end without finding its close: every later try in the
 * same run reads a tail of that text, so it fails without reading it again.
 * One unclosed `||` after another cost a read of the rest each, which grew
 * with the square of the text.
 */
const unclosed = new WeakMap<Token[], number>();

/** `||hidden||`: shown when pressed. */
const spoiler: TokenizerExtension = {
  name: "spoiler",
  level: "inline",
  start: (src) => {
    const i = src.indexOf("||");
    return i < 0 ? undefined : i;
  },
  // As /^\|\|(?=\S)([\s\S]*?\S)\|\|/, the first close after a non-space
  tokenizer(src, tokens) {
    if (!src.startsWith("||") || !/\S/.test(src.charAt(2))) return undefined;
    if (src.length <= (unclosed.get(tokens) ?? -1)) return undefined;
    for (let at = src.indexOf("||", 3); at >= 0; at = src.indexOf("||", at + 1)) {
      if (/\S/.test(src[at - 1])) {
        return { type: "spoiler", raw: src.slice(0, at + 2), tokens: this.lexer.inlineTokens(src.slice(2, at)) };
      }
    }
    unclosed.set(tokens, src.length);
    return undefined;
  },
};

const marked = new Marked({ gfm: true, breaks: true, extensions: [spoiler] });

/** Parse a message's text. Never throws: a text marked cannot read is a paragraph of itself. */
export function parse(text: string, opts: ParseOptions = {}): Block[] {
  const names = [...new Set((opts.names ?? []).filter((n) => n !== ""))].sort((a, b) => b.length - a.length);
  if (text.length > MAX_MARKUP_CHARS) return plain(text, names);
  let tokens: Token[];
  try {
    tokens = marked.lexer(text);
  } catch {
    return plain(text, names);
  }
  return blocks(tokens, names, 0);
}

/** A text as one paragraph of what it says, its line breaks kept. */
function plain(text: string, names: string[]): Block[] {
  const c: Inline[] = [];
  text.split("\n").forEach((line, i) => {
    if (i > 0) c.push({ t: "br" });
    c.push(...mentions(line, names));
  });
  return [{ t: "p", c: merge(c) }];
}

/**
 * A container's words without its markup, for one nested too deep to draw.
 * A spoiler in it stays hidden, as in `plainText`. Walks with a list of its
 * own, so no depth can overflow it.
 */
function flat(tok: Token): string {
  const parts: string[] = [];
  const todo: (Tokens.Generic | null)[] = [tok];
  while (todo.length > 0) {
    const t = todo.pop();
    // Between blocks
    if (t == null) parts.push(" ");
    else if (t.type === "spoiler") parts.push("▒▒▒");
    else if (t.type === "list") todo.push(...(t as Tokens.List).items.slice().reverse());
    else if (Array.isArray(t.tokens) && t.tokens.length > 0) todo.push(null, ...t.tokens.slice().reverse());
    else if (t.type === "br" || t.type === "space" || t.type === "hr" || t.type === "def") parts.push(" ");
    else if (t.type === "table") parts.push(t.raw);
    else parts.push(typeof t.text === "string" ? t.text : t.raw);
  }
  return parts.join("").replace(/\s+/g, " ").trim();
}

function blocks(tokens: Token[], names: string[], depth: number): Block[] {
  const out: Block[] = [];
  for (const tok of tokens) {
    switch (tok.type) {
      case "space":
      case "def":
        break;
      case "paragraph":
        out.push({ t: "p", c: inlines((tok as Tokens.Paragraph).tokens, names, depth) });
        break;
      case "heading": {
        const h = tok as Tokens.Heading;
        // Three sizes are plenty in a chat; deeper ones read as the smallest
        out.push({ t: "h", level: Math.min(h.depth, 3) as 1 | 2 | 3, c: inlines(h.tokens, names, depth) });
        break;
      }
      case "code": {
        const c = tok as Tokens.Code;
        out.push({ t: "pre", lang: (c.lang ?? "").trim().split(/\s/)[0].toLowerCase(), v: c.text });
        break;
      }
      case "blockquote":
      case "list":
        if (depth >= MAX_BLOCK_DEPTH) out.push({ t: "p", c: mentions(flat(tok), names) });
        else if (tok.type === "blockquote") out.push({ t: "quote", c: blocks((tok as Tokens.Blockquote).tokens, names, depth + 1) });
        else {
          const l = tok as Tokens.List;
          const start = typeof l.start === "number" ? l.start : 1;
          out.push({ t: "list", ordered: l.ordered, start, items: l.items.map((i) => blocks(i.tokens, names, depth + 1)) });
        }
        break;
      case "hr":
        out.push({ t: "hr" });
        break;
      // A table keeps its columns as written, in the code face
      case "table":
        out.push({ t: "pre", lang: "", v: tok.raw.replace(/\n+$/, "") });
        break;
      // A tight list item's text, which holds inline tokens of its own
      case "text": {
        const tt = tok as Tokens.Text;
        out.push({ t: "p", c: tt.tokens ? inlines(tt.tokens, names, depth) : mentions(tt.text, names) });
        break;
      }
      // Raw HTML, and anything this version does not know: the text as typed
      default:
        out.push({ t: "p", c: mentions(tok.raw.replace(/\n+$/, ""), names) });
    }
  }
  return out;
}

function inlines(tokens: Token[] | undefined, names: string[], depth: number): Inline[] {
  const out: Inline[] = [];
  for (const tok of tokens ?? []) {
    switch (tok.type) {
      case "text":
      case "escape": {
        const tt = tok as Tokens.Text;
        if (tt.tokens) out.push(...inlines(tt.tokens, names, depth));
        else out.push(...mentions(tt.text, names));
        break;
      }
      case "strong":
      case "em":
      case "del":
      case "spoiler":
      case "link":
        if (depth >= MAX_DEPTH) out.push(...mentions(flat(tok), names));
        else if (tok.type === "link") {
          const l = tok as Tokens.Link;
          out.push({ t: "link", href: l.href, c: inlines(l.tokens, names, depth + 1) });
        } else out.push({ t: tok.type, c: inlines((tok as Tokens.Generic).tokens, names, depth + 1) });
        break;
      case "codespan":
        out.push({ t: "code", v: (tok as Tokens.Codespan).text });
        break;
      // Never loaded: the reader decides whether to go and look
      case "image": {
        const img = tok as Tokens.Image;
        const v = img.text || img.href;
        out.push(depth >= MAX_DEPTH ? { t: "text", v } : { t: "link", href: img.href, c: [{ t: "text", v }] });
        break;
      }
      case "br":
        out.push({ t: "br" });
        break;
      default:
        out.push({ t: "text", v: tok.raw });
    }
  }
  return merge(out);
}

/** A text with `@name` for any of `names` cut out as mentions. */
function mentions(text: string, names: string[]): Inline[] {
  if (names.length === 0 || !text.includes("@")) return [{ t: "text", v: text }];
  const out: Inline[] = [];
  let from = 0;
  let at = text.indexOf("@");
  while (at >= 0) {
    // After the start or a non-word character: "a@b" is an address, not a mention
    const before = at === 0 ? "" : text[at - 1];
    // Compared piece by piece, never by places in the whole text lowercased:
    // that can be longer than the text ("İ" is two there)
    const name = /[\p{L}\p{N}_]/u.test(before)
      ? undefined
      : names.find((n) => {
          // Two different ASCII characters first: not this name, and no slice to make
          const [c, d] = [text.charCodeAt(at + 1), n.charCodeAt(0)];
          if (c < 128 && d < 128 && asciiLower(c) !== asciiLower(d)) return false;
          if (text.slice(at + 1, at + 1 + n.length).toLowerCase() !== n.toLowerCase()) return false;
          const next = text[at + 1 + n.length] ?? "";
          return !/[\p{L}\p{N}_#]/u.test(next);
        });
    if (name) {
      if (at > from) out.push({ t: "text", v: text.slice(from, at) });
      out.push({ t: "mention", name });
      from = at + 1 + name.length;
    }
    at = text.indexOf("@", name ? from : at + 1);
  }
  if (from < text.length) out.push({ t: "text", v: text.slice(from) });
  return out;
}

const asciiLower = (c: number) => (c >= 65 && c <= 90 ? c + 32 : c);

/** Neighbouring text nodes as one: fewer nodes to draw, simpler to test. */
function merge(nodes: Inline[]): Inline[] {
  const out: Inline[] = [];
  for (const n of nodes) {
    const last = out.at(-1);
    if (n.t === "text" && last?.t === "text") out[out.length - 1] = { t: "text", v: last.v + n.v };
    else if (n.t !== "text" || n.v !== "") out.push(n);
  }
  return out;
}

/** Characters that draw nothing, or reorder what is drawn around them. */
const UNSEEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/**
 * Where a link goes, as it may be shown: the URL as a browser would read it
 * (an IDN host in punycode, anything else outside ASCII percent-encoded),
 * and when it is no URL, as written with each invisible or reordering
 * character percent-encoded. A U+202E in a link must not turn its tail
 * around where the reader checks where it goes.
 */
export function shownHref(href: string): string {
  let shown = href;
  try {
    shown = new URL(href).href;
  } catch {
    // Not a URL: as written
  }
  return shown.replace(UNSEEN, (c) => encodeURIComponent(c));
}

/**
 * What the link popup says of a link (R2-12): where it goes as `shownHref`
 * writes it (which is also what is copied), the host on its own (a look-alike
 * IDN host shows as the punycode it is), and whether it is a web address at
 * all: a `javascript:` or `data:` link is not one.
 */
export function linkFacts(href: string): { shown: string; host: string; web: boolean } {
  let url: URL | null = null;
  try {
    url = new URL(href);
  } catch {
    // Not a URL
  }
  const web = url !== null && (url.protocol === "http:" || url.protocol === "https:") && url.host !== "";
  return { shown: shownHref(href), host: web ? url!.host : "", web };
}

/**
 * The text a message reads as, without its markup: for a notification, the
 * line that quotes it under a reply, and search. Spoilers stay hidden.
 */
export function plainText(text: string): string {
  const parts: string[] = [];
  const inline = (nodes: Inline[]): string =>
    nodes
      .map((n) => {
        switch (n.t) {
          case "text":
            return n.v;
          case "code":
            return n.v;
          case "br":
            return " ";
          case "mention":
            return `@${n.name}`;
          case "spoiler":
            return "▒▒▒";
          case "link":
            return inline(n.c);
          default:
            return inline(n.c);
        }
      })
      .join("");
  const walk = (bs: Block[]) => {
    for (const b of bs) {
      if (b.t === "p" || b.t === "h") parts.push(inline(b.c));
      else if (b.t === "pre") parts.push(b.v);
      else if (b.t === "quote") walk(b.c);
      else if (b.t === "list") b.items.forEach(walk);
    }
  };
  walk(parse(text));
  return parts.join(" ").replace(/\s+/g, " ").trim();
}

/**
 * The names an `@` may use for `people` (full names, with their tags): each
 * full name, and the short one where only one of them goes by it. Among two
 * guests called alice, `@alice` names neither, so it tints and notifies
 * neither (R2-11).
 */
export function mentionNames(people: readonly string[]): string[] {
  const uses = new Map<string, number>();
  for (const p of new Set(people)) uses.set(shortName(p), (uses.get(shortName(p)) ?? 0) + 1);
  return [...new Set(people.flatMap((p) => (uses.get(shortName(p)) === 1 ? [p, shortName(p)] : [p])))];
}

/** Whether `blocks` mention `name` anywhere outside code. */
export function mentionsName(blocks: Block[], name: string): boolean {
  const want = name.toLowerCase();
  const inline = (nodes: Inline[]): boolean =>
    nodes.some((n) => (n.t === "mention" ? n.name.toLowerCase() === want : "c" in n && inline(n.c)));
  return blocks.some((b) =>
    b.t === "p" || b.t === "h" ? inline(b.c) : b.t === "quote" ? mentionsName(b.c, name) : b.t === "list" && b.items.some((i) => mentionsName(i, name)),
  );
}
