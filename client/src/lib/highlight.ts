// Syntax colours for a fenced code block, as a tree of our own.
//
// lowlight runs highlight.js and hands back a syntax tree instead of an HTML
// string, so the code a peer sent stays text all the way to the screen. Its
// many scopes are folded into the five colours a palette defines
// (`--code-*`, theme.ts); everything else stays plain text. Loaded on demand
// (a dynamic import in CodeBlock.svelte), so a chat without code never pays
// for the grammars.

import { common, createLowlight } from "lowlight";
import type { ElementContent } from "hast";

export type CodeKind = "keyword" | "string" | "comment" | "number" | "fn";
/** A run of code, plain or in one of the five colours. */
export type CodeSeg = { v: string } | { k: CodeKind; c: CodeSeg[] };

const lowlight = createLowlight(common);

const KIND: Record<string, CodeKind> = {
  __proto__: null,
  "hljs-keyword": "keyword",
  "hljs-built_in": "keyword",
  "hljs-type": "keyword",
  "hljs-selector-tag": "keyword",
  "hljs-meta": "keyword",
  "hljs-string": "string",
  "hljs-regexp": "string",
  "hljs-symbol": "string",
  "hljs-char": "string",
  "hljs-addition": "string",
  "hljs-comment": "comment",
  "hljs-quote": "comment",
  "hljs-doctag": "comment",
  "hljs-number": "number",
  "hljs-literal": "number",
  "hljs-title": "fn",
  "hljs-section": "fn",
  "hljs-name": "fn",
  "hljs-attr": "fn",
  "hljs-attribute": "fn",
  "hljs-property": "fn",
  "hljs-selector-class": "fn",
  "hljs-selector-id": "fn",
  "hljs-deletion": "fn",
} as unknown as Record<string, CodeKind>;

/**
 * `code` in `lang`'s colours, or null for a language this build has no grammar
 * for (or none named): the block then shows as plain text, which is what it is.
 */
export function highlight(lang: string, code: string): CodeSeg[] | null {
  if (!lang || !lowlight.registered(lang)) return null;
  try {
    return segs(lowlight.highlight(lang, code).children as ElementContent[]);
  } catch {
    return null;
  }
}

function segs(nodes: ElementContent[]): CodeSeg[] {
  const out: CodeSeg[] = [];
  for (const n of nodes) {
    if (n.type === "text") out.push({ v: n.value });
    else if (n.type === "element") {
      const classes = (n.properties?.className ?? []) as string[];
      const kind = classes.map((c) => KIND[c]).find(Boolean);
      const inner = segs(n.children);
      if (kind) out.push({ k: kind, c: inner });
      else out.push(...inner);
    }
  }
  return out;
}
