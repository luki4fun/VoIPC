import { test } from "node:test";
import assert from "node:assert/strict";
import {
  byRecent,
  completeEmote,
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
const pog: Emote = { name: "pog", hash: H("a"), sticker: false, pack: "" };
const kekw: Emote = { name: "kekw_2", hash: H("b"), sticker: false, pack: "" };
const cat: Emote = { name: "cat", hash: H("c"), sticker: true, pack: "Cats" };
const ALL = [pog, kekw, cat];
const T = (e: Emote) => `<:${e.name}:${e.hash.slice(0, 20)}>`;

test(":name: of a listed emote becomes its token, and nothing else does", () => {
  assert.equal(tokenize("so :pog: wow :kekw_2:", ALL), `so ${T(pog)} wow ${T(kekw)}`);
  assert.equal(tokenize(":pog::pog:", ALL), ":pog::pog:", "glued together is not two emotes");
  assert.equal(tokenize(":nope: and :cat:", ALL), ":nope: and :cat:", "unknown, and a sticker, stay text");
  assert.equal(tokenize("10:30:45 and a:pog:b", ALL), "10:30:45 and a:pog:b", "inside words and times");
  assert.equal(tokenize(":pog:", []), ":pog:");
  assert.equal(tokenize("(:pog:)", ALL), `(${T(pog)})`);
});

test("code stays as it was written, and a token is never made twice", () => {
  assert.equal(tokenize("`:pog:` and :pog:", ALL), `\`:pog:\` and ${T(pog)}`);
  assert.equal(tokenize("```\n:pog:\n```\n:pog:", ALL), `\`\`\`\n:pog:\n\`\`\`\n${T(pog)}`);
  const once = tokenize("hi :pog:", ALL);
  assert.equal(tokenize(once, ALL), once, "a forward or a resend comes out the same");
  assert.equal(untokenize(once), "hi :pog:");
});

test("a token shows only while the server lists a file of its hash", () => {
  assert.equal(emoteOf(pog.hash.slice(0, 20), ALL), pog);
  assert.equal(emoteOf("f".repeat(20), ALL), undefined, "another picture under the name is not this one");
  assert.equal(emoteOf(pog.hash, ALL), undefined, "a token carries exactly 20");
  const renamed = { ...pog, name: "poggers" };
  assert.equal(emoteOf(pog.hash.slice(0, 20), [renamed]), renamed, "a renamed emote still shows");
});

test("a sticker is a message that is one sticker's token and nothing else", () => {
  assert.equal(stickerOf(stickerText(cat), ALL), cat);
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

test("emotes alone, few enough, are shown big", () => {
  assert.equal(onlyEmotes(`${T(pog)} ${T(kekw)}`), true);
  assert.equal(onlyEmotes(`${T(pog)} hi`), false);
  assert.equal(onlyEmotes("hi"), false);
  assert.equal(onlyEmotes(T(pog).repeat(28)), false);
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
