import assert from "node:assert/strict";
import { test } from "node:test";

import { callsOn, hasPower, ownMentionNames, powerTokens, tokensForMe } from "./mention-rules.ts";

const styles = [{ badge: "Mod" }, { badge: "Head Mod" }, { badge: "Mod" }];
const holder = { holder: true, isAdmin: false };
const open = { anonymous: false };
const all = powerTokens(styles);

test("the tokens, one each, a badge under its &", () => {
  assert.deepEqual(all, ["everyone", "here", "&Head Mod", "&Mod"]);
  assert.deepEqual(tokensForMe(["Mod"]), ["everyone", "here", "&Mod"]);
});

test("a token is a word of its own, anywhere but in code and quotes", () => {
  for (const yes of ["@everyone", "hi @here!", "(@everyone)", "@EVERYONE", "**@here**", "ask @&Head Mod now", "@&mod"]) {
    assert.ok(callsOn(yes, all), yes);
  }
  for (const no of [
    "everyone",
    "mail@everyone",
    "@everyoneelse",
    "`@everyone`",
    "```\n@here\n```",
    "> @everyone",
    "> quoted\n> @here",
    "@&Nobody",
    "@&",
  ]) {
    assert.ok(!callsOn(no, all), no);
  }
});

test("a badge reaches its own people, and a role nobody here holds nobody", () => {
  const mine = tokensForMe(["Mod"]);
  assert.ok(callsOn("@&Mod look", mine));
  assert.ok(!callsOn("@&Head Mod look", mine));
});

test("a longer badge is not read as a shorter one", () => {
  const known = powerTokens([{ badge: "Mod" }, { badge: "Mod Team" }]);
  assert.ok(!callsOn("@&Mod Team look", tokensForMe(["Mod"]), known));
  assert.ok(callsOn("@&Mod Team look", tokensForMe(["Mod Team"]), known));
  assert.ok(callsOn("@&Mod look", tokensForMe(["Mod"]), known));
});

test("only a holder, an admin, and never where people have no names", () => {
  assert.ok(hasPower("@everyone", holder, open, all));
  assert.ok(hasPower("@everyone", { holder: false, isAdmin: true }, open, all));
  assert.ok(!hasPower("@everyone", { holder: false, isAdmin: false }, open, all));
  assert.ok(!hasPower("@everyone", holder, { anonymous: true }, all));
  assert.ok(!hasPower("no token", holder, open, all));
});

test("our short name rings where only we go by it, and for both where the list is everyone online", () => {
  assert.deepEqual(ownMentionNames("alex#1234", ["bob#0001"], false).sort(), ["alex", "alex#1234"]);
  assert.deepEqual(ownMentionNames("alex#1234", ["alex#0000", "bob#0001"], false), ["alex#1234"], "the channel's own list");
  assert.deepEqual(ownMentionNames("alex#1234", [], true).sort(), ["alex", "alex#1234"], "whoever else is online");
  assert.deepEqual(ownMentionNames("alex", [], true), ["alex"], "a name with no tag is one name");
});
