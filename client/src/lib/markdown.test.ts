import { test } from "node:test";
import assert from "node:assert/strict";
import { linkFacts, MAX_EMOTES_SHOWN, MAX_MARKUP_CHARS, mentionNames, mentionsName, parse, plainText, shownHref, type Block, type Inline } from "./markdown.ts";

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

/** How many containers deep a tree is drawn. */
function depthOf(bs: Block[]): number {
  const inl = (ns: Inline[]): number => Math.max(0, ...ns.map((n) => ("c" in n ? 1 + inl(n.c) : 0)));
  return Math.max(
    0,
    ...bs.map((b) =>
      b.t === "quote" ? 1 + depthOf(b.c) : b.t === "list" ? 1 + Math.max(0, ...b.items.map(depthOf)) : b.t === "p" || b.t === "h" ? inl(b.c) : 0,
    ),
  );
}

test("a quote 999 deep is drawn 8 deep at most, with all its text", () => {
  const tree = parse("> ".repeat(999) + "deepx");
  assert.equal(depthOf(tree), 8);
  assert.equal(plainText("> ".repeat(999) + "deepx"), "deepx");
  const list = Array.from({ length: 40 }, (_, i) => `${"  ".repeat(i)}- item${i}`).join("\n");
  const lt = parse(list);
  assert.ok(depthOf(lt) <= 8, `a list 40 deep is drawn ${depthOf(lt)} deep`);
  for (const i of [0, 7, 8, 39]) assert.ok(texts(lt).includes(`item${i}`), `item${i}`);
});

test("bold in bold in quotes is drawn 16 deep at most, all of it counted together", () => {
  const bold = parse("**".repeat(495) + "word" + "**".repeat(495));
  assert.ok(depthOf(bold) <= 16, `drawn ${depthOf(bold)} deep`);
  assert.ok(texts(bold).includes("word"));
  const mixed = parse("> ".repeat(20) + "*_".repeat(20) + "word" + "_*".repeat(20));
  assert.ok(depthOf(mixed) <= 16, `drawn ${depthOf(mixed)} deep`);
  assert.ok(texts(mixed).includes("word"));
  // A spoiler too deep to draw stays hidden
  const deep = parse("> ".repeat(8) + "**".repeat(20) + "||secret||" + "**".repeat(20));
  assert.ok(!texts(deep).includes("secret"));
  assert.ok(texts(deep).includes("▒▒▒"));
  // and a link too deep is its text
  const link = parse("~~".repeat(18) + "[go](https://x.org)" + "~~".repeat(18));
  assert.ok(depthOf(link) <= 16);
  assert.ok(texts(link).includes("go"));
});

test("a text past 4000 characters is one plain paragraph, read in no time", () => {
  for (const text of ["_a".repeat(30000), "*a".repeat(30000), "||a ".repeat(15000), "> ".repeat(30000) + "x"]) {
    const start = performance.now();
    const tree = parse(text, { names: ["anna"] });
    plainText(text);
    const ms = performance.now() - start;
    assert.ok(ms < 200, `${text.slice(0, 4)}…: ${ms.toFixed(0)} ms`);
    assert.equal(tree.length, 1);
    assert.equal(tree[0].t, "p");
    assert.equal(tree[0].t === "p" && tree[0].c.map((n) => (n.t === "text" ? n.v : "")).join(""), text);
  }
  // Its lines and mentions stay
  const long = "@anna look\n" + "x".repeat(4000);
  assert.deepEqual(parse(long, { names: ["anna"] }), [
    { t: "p", c: [{ t: "mention", name: "anna" }, { t: "text", v: " look" }, { t: "br" }, { t: "text", v: "x".repeat(4000) }] },
  ]);
  // Up to the bound it is read as markdown, still quickly
  for (const text of ["_a".repeat(2000), "*a".repeat(2000), "||a ".repeat(1000)]) {
    const start = performance.now();
    parse(text);
    assert.ok(performance.now() - start < 200, text.slice(0, 4));
  }
  assert.equal(parse("**b**".padEnd(4000, " "))[0].t, "p");
  assert.deepEqual((parse("**b**".padEnd(4000, " "))[0] as { c: Inline[] }).c[0], { t: "strong", c: [{ t: "text", v: "b" }] });
});

test("spoilers close where they always did", () => {
  const spoilers = (text: string) => JSON.stringify(parse(text));
  assert.equal(spoilers("||a||"), JSON.stringify([{ t: "p", c: [{ t: "spoiler", c: [{ t: "text", v: "a" }] }] }]));
  // The first close after a non-space; a close after a space is no close
  assert.equal(spoilers("||a |||"), JSON.stringify([{ t: "p", c: [{ t: "spoiler", c: [{ t: "text", v: "a |" }] }] }]));
  assert.equal(spoilers("||a ||b||"), JSON.stringify([{ t: "p", c: [{ t: "spoiler", c: [{ t: "text", v: "a ||b" }] }] }]));
  assert.equal(spoilers("|| a||"), JSON.stringify([{ t: "p", c: [{ t: "text", v: "|| a||" }] }]));
  assert.equal(spoilers("||||"), JSON.stringify([{ t: "p", c: [{ t: "text", v: "||||" }] }]));
  // After an unclosed one, a later one in the same text still closes
  assert.equal(
    spoilers("||a || then ||b|| and **||c||**"),
    JSON.stringify([
      {
        t: "p",
        c: [
          { t: "spoiler", c: [{ t: "text", v: "a || then ||b" }] },
          { t: "text", v: " and " },
          { t: "strong", c: [{ t: "spoiler", c: [{ t: "text", v: "c" }] }] },
        ],
      },
    ]),
  );
  assert.equal(spoilers("x || y\n\n||z||"), JSON.stringify([{ t: "p", c: [{ t: "text", v: "x || y" }] }, { t: "p", c: [{ t: "spoiler", c: [{ t: "text", v: "z" }] }] }]));
});

test("a mention is found where it stands, whatever came before it", () => {
  const names = ["bob"];
  // "İ" is two characters lowercased: places in the lowercased text are not places in the text
  assert.deepEqual(parse("İİİ@bob hi", { names }), [{ t: "p", c: [{ t: "text", v: "İİİ@bob hi" }] }], "drawn as sent");
  assert.deepEqual(parse("İİİ @bob hi", { names }), [
    { t: "p", c: [{ t: "text", v: "İİİ " }, { t: "mention", name: "bob" }, { t: "text", v: " hi" }] },
  ]);
  assert.deepEqual(parse("İyi akşamlar @Bob nasılsın", { names })[0], {
    t: "p",
    c: [{ t: "text", v: "İyi akşamlar " }, { t: "mention", name: "bob" }, { t: "text", v: " nasılsın" }],
  });
  assert.deepEqual(parse("İ@bob", { names }), [{ t: "p", c: [{ t: "text", v: "İ@bob" }] }], "a letter before @ is an address");
  assert.equal(mentionsName(parse("İİİ @bob", { names }), "bob"), true);
  // Names that do not start with a plain letter still match without regard to case
  assert.deepEqual(parse("hi @Ülla and @_x", { names: ["ülla", "_X"] })[0], {
    t: "p",
    c: [{ t: "text", v: "hi " }, { t: "mention", name: "ülla" }, { t: "text", v: " and " }, { t: "mention", name: "_X" }],
  });
  // A text of nothing but @ is quick, with many names
  const many = Array.from({ length: 50 }, (_, i) => `member${i}#${1000 + i}`);
  const start = performance.now();
  parse("@".repeat(60000), { names: many });
  assert.ok(performance.now() - start < 100);
});

test("where a link goes is shown without what hides or turns it", () => {
  const rlo = shownHref("https://evil.com/‮moc.elgoog");
  assert.ok(!rlo.includes("‮"));
  assert.equal(rlo, "https://evil.com/%E2%80%AEmoc.elgoog");
  assert.equal(shownHref("https://аpple.com/login"), "https://xn--pple-43d.com/login", "a look-alike host is punycode");
  assert.equal(shownHref("https://example.org/a?b=1&c=2"), "https://example.org/a?b=1&c=2");
  // Not a URL: as written, the invisible characters made visible
  assert.equal(shownHref("www.x​.org/⁦a"), "www.x%E2%80%8B.org/%E2%81%A6a");
  assert.equal(shownHref("javascript:alert(1)"), "javascript:alert(1)");
  // The link itself keeps its real target, which is what gets copied
  const [p] = parse("[x](https://evil.com/‮moc)");
  assert.deepEqual(p, { t: "p", c: [{ t: "link", href: "https://evil.com/‮moc", c: [{ t: "text", v: "x" }] }] });
});

test("the link popup names a link's host, and says when it is no web address", () => {
  assert.deepEqual(linkFacts("https://аpple.com/login"), {
    shown: "https://xn--pple-43d.com/login",
    host: "xn--pple-43d.com",
    web: true,
  });
  const rlo = linkFacts("https://evil.com/\u202emoc.elgoog");
  assert.equal(rlo.host, "evil.com");
  assert.ok(!rlo.shown.includes("\u202e"), "nothing turns the tail around");
  for (const not of ["javascript:alert(1)", "data:text/html,<b>x</b>", "mailto:a@b.c", "file:///etc/passwd", "no url at all"]) {
    const f = linkFacts(not);
    assert.equal(f.web, false, not);
    assert.equal(f.host, "", not);
  }
  assert.equal(linkFacts("http://example.org:8080/x").host, "example.org:8080");
});

test("a short name is a mention only where one person goes by it (R2-11)", () => {
  assert.deepEqual(mentionNames(["bob#0001", "ann#0002"]), ["bob#0001", "bob", "ann#0002", "ann"]);
  const two = mentionNames(["alice#1234", "alice#5678", "bob#0001"]);
  assert.deepEqual(two, ["alice#1234", "alice#5678", "bob#0001", "bob"]);
  const tree = parse("hi @alice and @alice#5678", { names: two });
  assert.equal(mentionsName(tree, "alice"), false, "@alice names neither alice");
  assert.equal(mentionsName(tree, "alice#5678"), true);
  assert.deepEqual(mentionNames(["ann#0002", "ann#0002"]), ["ann#0002", "ann"], "one person listed twice is one");
});

test("a server emote's token is its own node, outside code, and reads as :name:", () => {
  const tok = `<:pog_2:${"a".repeat(20)}>`;
  assert.deepEqual(parse(`hi ${tok}!`)[0], { t: "p", c: [{ t: "text", v: "hi " }, { t: "emote", name: "pog_2", hash: "a".repeat(20) }, { t: "text", v: "!" }] });
  assert.deepEqual(parse(`**${tok}**`)[0], { t: "p", c: [{ t: "strong", c: [{ t: "emote", name: "pog_2", hash: "a".repeat(20) }] }] });
  assert.deepEqual(parse(`\`${tok}\``)[0], { t: "p", c: [{ t: "code", v: tok }] }, "never in code");
  assert.equal(plainText(`a ${tok} b`), "a :pog_2: b");
  assert.deepEqual(parse(`<:Bad:${"a".repeat(20)}>`)[0], { t: "p", c: [{ t: "text", v: `<:Bad:${"a".repeat(20)}>` }] }, "not a token: text");
});

test("a message draws at most MAX_EMOTES_SHOWN emotes, and emote tokens do not cost it its markup", () => {
  const tok = `<:pog:${"a".repeat(32)}>`;
  const c = (parse(Array(MAX_EMOTES_SHOWN + 50).fill(tok).join(" "))[0] as { c: Inline[] }).c;
  assert.equal(c.filter((n) => n.t === "emote").length, MAX_EMOTES_SHOWN);
  assert.ok(c.some((n) => n.t === "text" && n.v.includes(":pog:")), "the rest stay their names");
  assert.equal((parse(tok)[0] as { c: Inline[] }).c[0].t, "emote", "the count starts again for each message");
  const long = `**bold** ${Array(120).fill(tok).join(" ")}`;
  assert.ok(long.length > MAX_MARKUP_CHARS);
  assert.equal((parse(long)[0] as { c: Inline[] }).c[0].t, "strong", "measured as typed");
});
