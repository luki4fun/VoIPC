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

/** `||hidden||`: shown when pressed. */
const spoiler: TokenizerExtension = {
  name: "spoiler",
  level: "inline",
  start: (src) => {
    const i = src.indexOf("||");
    return i < 0 ? undefined : i;
  },
  tokenizer(src) {
    const m = /^\|\|(?=\S)([\s\S]*?\S)\|\|/.exec(src);
    if (!m) return undefined;
    return { type: "spoiler", raw: m[0], tokens: this.lexer.inlineTokens(m[1]) };
  },
};

const marked = new Marked({ gfm: true, breaks: true, extensions: [spoiler] });

/** Parse a message's text. Never throws: a text marked cannot read is a paragraph of itself. */
export function parse(text: string, opts: ParseOptions = {}): Block[] {
  const names = [...new Set((opts.names ?? []).filter((n) => n !== ""))].sort((a, b) => b.length - a.length);
  let tokens: Token[];
  try {
    tokens = marked.lexer(text);
  } catch {
    return [{ t: "p", c: mentions(text, names) }];
  }
  return blocks(tokens, names);
}

function blocks(tokens: Token[], names: string[]): Block[] {
  const out: Block[] = [];
  for (const tok of tokens) {
    switch (tok.type) {
      case "space":
      case "def":
        break;
      case "paragraph":
        out.push({ t: "p", c: inlines((tok as Tokens.Paragraph).tokens, names) });
        break;
      case "heading": {
        const h = tok as Tokens.Heading;
        // Three sizes are plenty in a chat; deeper ones read as the smallest
        out.push({ t: "h", level: Math.min(h.depth, 3) as 1 | 2 | 3, c: inlines(h.tokens, names) });
        break;
      }
      case "code": {
        const c = tok as Tokens.Code;
        out.push({ t: "pre", lang: (c.lang ?? "").trim().split(/\s/)[0].toLowerCase(), v: c.text });
        break;
      }
      case "blockquote":
        out.push({ t: "quote", c: blocks((tok as Tokens.Blockquote).tokens, names) });
        break;
      case "list": {
        const l = tok as Tokens.List;
        const start = typeof l.start === "number" ? l.start : 1;
        out.push({ t: "list", ordered: l.ordered, start, items: l.items.map((i) => blocks(i.tokens, names)) });
        break;
      }
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
        out.push({ t: "p", c: tt.tokens ? inlines(tt.tokens, names) : mentions(tt.text, names) });
        break;
      }
      // Raw HTML, and anything this version does not know: the text as typed
      default:
        out.push({ t: "p", c: mentions(tok.raw.replace(/\n+$/, ""), names) });
    }
  }
  return out;
}

function inlines(tokens: Token[] | undefined, names: string[]): Inline[] {
  const out: Inline[] = [];
  for (const tok of tokens ?? []) {
    switch (tok.type) {
      case "text":
      case "escape": {
        const tt = tok as Tokens.Text;
        if (tt.tokens) out.push(...inlines(tt.tokens, names));
        else out.push(...mentions(tt.text, names));
        break;
      }
      case "strong":
      case "em":
      case "del":
      case "spoiler":
        out.push({ t: tok.type, c: inlines((tok as Tokens.Generic).tokens, names) });
        break;
      case "codespan":
        out.push({ t: "code", v: (tok as Tokens.Codespan).text });
        break;
      case "link": {
        const l = tok as Tokens.Link;
        out.push({ t: "link", href: l.href, c: inlines(l.tokens, names) });
        break;
      }
      // Never loaded: the reader decides whether to go and look
      case "image": {
        const img = tok as Tokens.Image;
        out.push({ t: "link", href: img.href, c: [{ t: "text", v: img.text || img.href }] });
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
  const lower = text.toLowerCase();
  let from = 0;
  let at = lower.indexOf("@");
  while (at >= 0) {
    // After the start or a non-word character: "a@b" is an address, not a mention
    const before = at === 0 ? "" : text[at - 1];
    const name = /[\p{L}\p{N}_]/u.test(before)
      ? undefined
      : names.find((n) => {
          if (!lower.startsWith(n.toLowerCase(), at + 1)) return false;
          const next = text[at + 1 + n.length] ?? "";
          return !/[\p{L}\p{N}_#]/u.test(next);
        });
    if (name) {
      if (at > from) out.push({ t: "text", v: text.slice(from, at) });
      out.push({ t: "mention", name });
      from = at + 1 + name.length;
    }
    at = lower.indexOf("@", name ? from : at + 1);
  }
  if (from < text.length) out.push({ t: "text", v: text.slice(from) });
  return out;
}

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

/** Whether `blocks` mention `name` anywhere outside code. */
export function mentionsName(blocks: Block[], name: string): boolean {
  const want = name.toLowerCase();
  const inline = (nodes: Inline[]): boolean =>
    nodes.some((n) => (n.t === "mention" ? n.name.toLowerCase() === want : "c" in n && inline(n.c)));
  return blocks.some((b) =>
    b.t === "p" || b.t === "h" ? inline(b.c) : b.t === "quote" ? mentionsName(b.c, name) : b.t === "list" && b.items.some((i) => mentionsName(i, name)),
  );
}
