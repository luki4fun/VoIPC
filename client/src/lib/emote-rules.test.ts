import { test } from "node:test";
import assert from "node:assert/strict";
import {
  byRecent,
  cleanList,
  completeEmoji,
  completeEmote,
  countKinds,
  emoteOf,
  isEmoteReaction,
  nameFrom,
  uniqueName,
  onlyEmotes,
  reactionEmote,
  stickerOf,
  stickerText,
  tokenize,
  untokenize,
  type Emote,
} from "./emote-rules.ts";

const H = (c: string) => c.repeat(64);
const pog: Emote = { name: "pog", hash: H("a"), sticker: false, pack: "", len: 100, w: 64, h: 32 };
const kekw: Emote = { name: "kekw_2", hash: H("b"), sticker: false, pack: "", len: 100, w: 0, h: 0 };
const cat: Emote = { name: "cat", hash: H("c"), sticker: true, pack: "Cats", len: 100, w: 320, h: 320 };
const ALL = [pog, kekw, cat];
const T = (e: Emote) => `<:${e.name}:${e.hash.slice(0, 32)}>`;
/** A token as 1.4 sent it: 80 bits of the hash. */
const OLD = (e: Emote) => `<:${e.name}:${e.hash.slice(0, 20)}>`;

test(":name: of a listed emote becomes its token, and nothing else does", () => {
  assert.equal(tokenize("so :pog: wow :kekw_2:", ALL), `so ${T(pog)} wow ${T(kekw)}`);
  assert.equal(tokenize(":pog::pog:", ALL), ":pog::pog:", "glued together is not two emotes");
  assert.equal(tokenize(":nope: and :cat:", ALL), ":nope: and 🐱", "unknown stays text; a sticker is not typed, :cat: is the emoji");
  assert.equal(tokenize("10:30:45 and a:pog:b", ALL), "10:30:45 and a:pog:b", "inside words and times");
  assert.equal(tokenize(":pog:", []), ":pog:");
  assert.equal(tokenize("(:pog:)", ALL), `(${T(pog)})`);
});

test("code stays as it was written, and a token is never made twice", () => {
  assert.equal(tokenize("`:pog:` and :pog:", ALL), `\`:pog:\` and ${T(pog)}`);
  assert.equal(tokenize("```\n:pog:\n```\n:pog:", ALL), `\`\`\`\n:pog:\n\`\`\`\n${T(pog)}`);
  assert.equal(tokenize("~~~\n:pog:\n~~~", ALL), "~~~\n:pog:\n~~~");
  assert.equal(tokenize("``a :pog: b``", ALL), "``a :pog: b``");
  assert.equal(tokenize("https://x.org/a/:pog:/b", ALL), "https://x.org/a/:pog:/b", "inside an address");
  const once = tokenize("hi :pog:", ALL);
  assert.equal(tokenize(once, ALL), once, "a forward or a resend comes out the same");
  assert.equal(untokenize(once), "hi :pog:");
});

test("a token shows only while the server lists a file of its hash", () => {
  assert.equal(emoteOf(pog.hash.slice(0, 32), ALL), pog);
  assert.equal(emoteOf(pog.hash.slice(0, 20), ALL), pog, "a 1.4 token still shows");
  assert.equal(emoteOf(pog.hash, ALL), pog, "a whole hash, from a list");
  assert.equal(emoteOf("f".repeat(32), ALL), undefined, "another picture under the name is not this one");
  assert.equal(emoteOf(`${pog.hash.slice(0, 20)}${"f".repeat(12)}`, ALL), undefined, "the 80 bits of 1.4 are not enough now");
  assert.equal(emoteOf(pog.hash.slice(0, 25), ALL), undefined, "a token carries 20 or 32");
  const renamed = { ...pog, name: "poggers" };
  assert.equal(emoteOf(pog.hash.slice(0, 20), [renamed]), renamed, "a renamed emote still shows");
});

test("a sticker is a message that is one sticker's token and nothing else", () => {
  assert.equal(stickerOf(stickerText(cat), ALL), cat);
  assert.equal(stickerOf(OLD(cat), ALL), cat, "a 1.4 sticker still shows");
  assert.equal(emoteOf(cat.hash.slice(0, 32), ALL, "cat", false), undefined, "in text, a sticker's token is not drawn");
  assert.equal(stickerOf(` ${stickerText(cat)}\n`, ALL), cat);
  assert.equal(stickerOf(`look ${stickerText(cat)}`, ALL), undefined);
  assert.equal(stickerOf(T(pog), ALL), undefined, "an emote alone is not a sticker");
  assert.equal(stickerOf(stickerText(cat), [pog]), undefined, "a sticker the server no longer has");
});

test("one file under several names: each token finds its own", () => {
  const lol = { ...pog, name: "lol" };
  const big = { ...pog, name: "big", sticker: true };
  const list = [lol, pog, big];
  assert.equal(emoteOf(pog.hash.slice(0, 20), list, "pog"), pog);
  assert.equal(emoteOf(pog.hash.slice(0, 20), list, "gone"), lol, "a renamed one still shows");
  assert.equal(stickerOf(stickerText(big), list), big, "the sticker, though an emote has its file");
});

test("emotes and emoji alone, few enough, are shown big", () => {
  assert.equal(onlyEmotes(`${T(pog)} ${T(kekw)}`), true);
  assert.equal(onlyEmotes(`${T(pog)} hi`), false);
  assert.equal(onlyEmotes("hi"), false);
  assert.equal(onlyEmotes(T(pog).repeat(28)), false);
  assert.equal(onlyEmotes("😂 👍🏽 ❤️‍🔥 🇩🇪 1️⃣"), true, "skin tones, sequences, flags, keycaps");
  assert.equal(onlyEmotes(`😂 ${T(pog)}`), true, "the two mixed");
  assert.equal(onlyEmotes("😂 lol"), false);
  assert.equal(onlyEmotes("1 2"), false, "digits are not emoji");
  assert.equal(onlyEmotes("😂".repeat(28)), false);
  assert.equal(onlyEmotes("  "), false);
});

test(":joy: and its kind become their emoji when sent, never over a server's emote", () => {
  assert.equal(tokenize("so :joy: :thumbsup:", ALL), "so 😂 👍");
  assert.equal(tokenize("`:joy:`", ALL), "`:joy:`", "not in code");
  const joy = { ...pog, name: "joy" };
  assert.equal(tokenize(":joy:", [joy]), T(joy), "the server's own wins");
  assert.equal(tokenize(":joyy:", ALL), ":joyy:");
  assert.deepEqual(completeEmoji("thumbs").map((o) => o.name), ["thumbsup", "thumbsdown"]);
  assert.deepEqual(completeEmoji("laugh").map((o) => o.emoji), ["😆"], "one per emoji");
  assert.equal(completeEmoji("heart")[0].name, "heart", "what starts with it first");
});

test("a reaction is :name: of a listed emote", () => {
  assert.equal(isEmoteReaction(":pog:"), true);
  for (const bad of [":Pog:", "pog", "::", ":a:", `:${"x".repeat(31)}:`, "👍"]) assert.equal(isEmoteReaction(bad), false, bad);
  assert.equal(reactionEmote(":pog:", ALL), pog);
  assert.equal(reactionEmote(":cat:", ALL), undefined, "no sticker as a reaction");
  assert.equal(reactionEmote(":gone:", ALL), undefined);
});

test("the : completion: names that start with what is typed, then names that hold it", () => {
  const list = [pog, kekw, { ...pog, name: "apog", hash: H("d") }, cat];
  assert.deepEqual(completeEmote("po", list).map((e) => e.name), ["pog", "apog"]);
  assert.deepEqual(completeEmote("ca", list).map((e) => e.name), [], "stickers are not typed");
  assert.equal(completeEmote("", list, 2).length, 2);
  const pogs = { ...pog, name: "pogs", hash: H("e") };
  assert.deepEqual(
    completeEmote("po", [pog, pogs, kekw], 8, ["pogs"]).map((e) => e.name),
    ["pogs", "pog"],
    "the recently used first",
  );
  assert.deepEqual(byRecent([pog, kekw, cat], ["cat", "nope", "pog"]).map((e) => e.name), ["cat", "pog", "kekw_2"]);
});

test("emote names from file names", () => {
  assert.equal(nameFrom("Pog Champ.png"), "pog_champ");
  assert.equal(nameFrom("KEKW.gif"), "kekw");
  assert.equal(nameFrom("icon_123"), "icon_123", "a TeamSpeak icon has no extension");
  assert.equal(nameFrom("--héllo--wörld--.webp"), "h_llo_w_rld");
  assert.equal(nameFrom("a.png"), undefined);
  assert.equal(nameFrom("日本.png"), undefined);
  assert.equal(nameFrom(`${"x".repeat(40)}.png`)?.length, 30);
  assert.equal(nameFrom("v1.2.final.png"), "v1_2_final");
  const taken = (n: string) => ["pog", "pog_2", "y".repeat(30)].includes(n);
  assert.equal(uniqueName("pog", taken), "pog_3");
  assert.equal(uniqueName("new", taken), "new");
  assert.equal(uniqueName("y".repeat(30), taken), `${"y".repeat(28)}_2`);
});

test("a relay's list is taken only as valid, once per name, and bounded", () => {
  const bad = [
    { ...pog, name: "Pog" },
    { ...pog, name: "x y" },
    { ...pog, hash: "zz" },
    { ...pog, pack: "rtl\u202Egnp" },
    { ...pog, pack: "two\nlines" },
  ];
  assert.deepEqual(cleanList([...bad, pog, { ...pog, hash: H("f") }, cat]), [pog, cat], "the first of a name wins");
  const many = Array.from({ length: 450 }, (_, i) => ({ ...pog, name: `e${i}` }));
  assert.equal(cleanList(many).length, 400);
  const odd = cleanList([{ ...pog, w: 9999, h: -3, len: 1.5 }, { ...cat, w: 9999 }, { ...pog, name: "wide", w: 320, h: 160 }]);
  assert.deepEqual(
    odd.map((e) => [e.w, e.h, e.len]),
    [
      [128, 0, 0],
      [320, 10, 100],
      [128, 64, 100],
    ],
    "a shape held to its box",
  );
});

test("counts read as words, one or many, of either kind", () => {
  assert.equal(countKinds(1, 0), "1 emote");
  assert.equal(countKinds(3, 1), "3 emotes and 1 sticker");
  assert.equal(countKinds(0, 2), "2 stickers");
  assert.equal(countKinds(0, 0), "no emotes or stickers");
});

test("emoji completion leaves out what this system cannot draw", () => {
  const all = completeEmoji("heart", 8).map((o) => o.emoji);
  assert.ok(all.includes("❤️‍🔥"), "offered where it is drawn");
  const shown = completeEmoji("heart", 8, (e) => !e.includes("‍")).map((o) => o.emoji);
  assert.ok(!shown.includes("❤️‍🔥") && shown.length > 0, "left out where it would come apart");
});
