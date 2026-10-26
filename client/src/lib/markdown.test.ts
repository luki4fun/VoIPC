import { test } from "node:test";
import assert from "node:assert/strict";
import { mentionsName, parse, plainText, type Block } from "./markdown.ts";

/** Every text a tree would put on screen, in order. */
function texts(blocks: Block[]): string {
  return JSON.stringify(blocks);
}

test("raw HTML in a message is shown as the text it is", () => {
  const out = parse('<img src=x onerror="alert(1)"> and <b>bold</b>');
  assert.deepEqual(out, [
    { t: "p", c: [{ t: "text", v: '<img src=x onerror="alert(1)"> and <b>bold</b>' }] },
  ]);
  const block = parse("<div>\n<script>alert(1)</script>\n</div>");
  assert.ok(block.every((b) => b.t === "p"), "a block of HTML is a paragraph of text");
  assert.ok(texts(block).includes("<script>alert(1)</script>"));
});

test("an image is a link to it, never something loaded", () => {
  assert.deepEqual(parse("![cat](https://tracker.example/pixel.png)"), [
    { t: "p", c: [{ t: "link", href: "https://tracker.example/pixel.png", c: [{ t: "text", v: "cat" }] }] },
  ]);
});

test("a masked link keeps where it really goes", () => {
  const [p] = parse("[your bank](https://evil.example/login)");
  assert.deepEqual(p, { t: "p", c: [{ t: "link", href: "https://evil.example/login", c: [{ t: "text", v: "your bank" }] }] });
  const [bare] = parse("see https://example.org/a?b=1&c=2.");
  assert.deepEqual(bare.t === "p" && bare.c[1], { t: "link", href: "https://example.org/a?b=1&c=2", c: [{ t: "text", v: "https://example.org/a?b=1&c=2" }] });
});

test("emphasis, code and spoilers", () => {
  assert.deepEqual(parse("**b** *i* ~~s~~ `x<y>` ||secret||"), [
    {
      t: "p",
      c: [
        { t: "strong", c: [{ t: "text", v: "b" }] },
        { t: "text", v: " " },
        { t: "em", c: [{ t: "text", v: "i" }] },
        { t: "text", v: " " },
        { t: "del", c: [{ t: "text", v: "s" }] },
        { t: "text", v: " " },
        { t: "code", v: "x<y>" },
        { t: "text", v: " " },
        { t: "spoiler", c: [{ t: "text", v: "secret" }] },
      ],
    },
  ]);
  assert.deepEqual(parse("a || b || c")[0], { t: "p", c: [{ t: "text", v: "a || b || c" }] }, "spaced bars are bars");
});

test("a fenced block keeps its language and its text exactly", () => {
  assert.deepEqual(parse("```Rust title\nfn main() { println!(\"<hi>\"); }\n```"), [
    { t: "pre", lang: "rust", v: 'fn main() { println!("<hi>"); }' },
  ]);
  assert.deepEqual(parse("```\nplain\n```"), [{ t: "pre", lang: "", v: "plain" }]);
});

test("one newline is a line break, as people type in a chat", () => {
  assert.deepEqual(parse("one\ntwo"), [{ t: "p", c: [{ t: "text", v: "one" }, { t: "br" }, { t: "text", v: "two" }] }]);
});

test("quotes, lists and headings", () => {
  assert.deepEqual(parse("> quoted"), [{ t: "quote", c: [{ t: "p", c: [{ t: "text", v: "quoted" }] }] }]);
  assert.deepEqual(parse("3. three\n4. four"), [
    {
      t: "list",
      ordered: true,
      start: 3,
      items: [[{ t: "p", c: [{ t: "text", v: "three" }] }], [{ t: "p", c: [{ t: "text", v: "four" }] }]],
    },
  ]);
  assert.deepEqual(parse("##### small"), [{ t: "h", level: 3, c: [{ t: "text", v: "small" }] }]);
  assert.deepEqual(parse("#general is a channel"), [{ t: "p", c: [{ t: "text", v: "#general is a channel" }] }]);
});

test("a mention is one of the names given, and never inside code", () => {
  const names = ["anna", "Big Bob#0042"];
  assert.deepEqual(parse("hi @Anna and @big bob#0042!", { names })[0], {
    t: "p",
    c: [
      { t: "text", v: "hi " },
      { t: "mention", name: "anna" },
      { t: "text", v: " and " },
      { t: "mention", name: "Big Bob#0042" },
      { t: "text", v: "!" },
    ],
  });
  assert.deepEqual(parse("@annabel mail@anna", { names })[0], { t: "p", c: [{ t: "text", v: "@annabel mail@anna" }] });
  const coded = parse("`@anna` and\n```\n@anna\n```", { names });
  assert.equal(mentionsName(coded, "anna"), false);
  assert.equal(mentionsName(parse("> **@anna** look", { names }), "ANNA"), true);
});

test("plain text for a notification or a quote", () => {
  assert.equal(plainText("**Look**: `cargo test` at https://x.org\n> quoted ||spoiler||"), "Look: cargo test at https://x.org quoted ▒▒▒");
  assert.equal(plainText("```js\nlet a = 1;\n```"), "let a = 1;");
  assert.equal(plainText(""), "");
});
