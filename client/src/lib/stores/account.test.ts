// The account dialogs come one at a time, and the ones shown only once (a
// new account's recovery key, the recovery codes) are never replaced by
// whatever comes next: it waits behind them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";
import {
  accountPrompt,
  armsSlowly,
  closePrompt,
  dropPair,
  dropPrompts,
  lookedAt,
  lookOver,
  codesTurnedOn,
  pairCodeCame,
  providerDone,
  providerPage,
  providerRefused,
  providerStarted,
  setupRefused,
  setupSent,
  showPrompt,
  takeLook,
  type AccountPrompt,
} from "./account.ts";

const kind = () => get(accountPrompt)?.kind ?? null;

test("a once-only prompt is never replaced: what comes next waits behind it", () => {
  showPrompt({ kind: "recovery", server: "a:1", key: "KEY" });
  showPrompt({ kind: "totp", server: "b:2", retry: false });
  showPrompt({ kind: "totp-setup", server: "a:1", secret: "s", uri: "otpauth://x", sealed: "x", why: "required" });
  assert.equal(kind(), "recovery");
  closePrompt();
  assert.equal(kind(), "totp", "then the others, in order");
  closePrompt();
  assert.equal(kind(), "totp-setup");
  closePrompt();
  assert.equal(kind(), null);
});

test("an ordinary prompt gives way, and a late answer closes only its own", () => {
  const cloud: AccountPrompt = { kind: "cloud", server: "a:1", cloud: false, share: true };
  showPrompt(cloud);
  showPrompt({ kind: "account", server: "a:1" });
  assert.equal(kind(), "account");
  closePrompt(cloud);
  assert.equal(kind(), "account", "the cloud question's answer came late: the panel stays");
  closePrompt();
  assert.equal(kind(), null);
});

test("a server that goes takes its prompts along, but not a once-only one on screen", () => {
  showPrompt({ kind: "recovery-codes", server: "a:1", codes: ["c1"] });
  showPrompt({ kind: "totp", server: "a:1", retry: false });
  showPrompt({ kind: "account", server: "b:2" });
  dropPrompts("a:1");
  assert.equal(kind(), "recovery-codes", "the codes are shown only now");
  closePrompt();
  assert.equal(kind(), "account", "a:1's code prompt went with it");
  dropPrompts("b:2");
  assert.equal(kind(), null);
});

test("a sign-in waiting for its code is not replaced by another server's prompt", () => {
  showPrompt({ kind: "totp", server: "a:1", retry: false });
  showPrompt({ kind: "totp-setup", server: "b:2", secret: "s", uri: "otpauth://x", sealed: "x", why: "required" });
  assert.equal(kind(), "totp", "a:1's sign-in would fail unseen when its wait runs out");
  showPrompt({ kind: "totp", server: "a:1", retry: true });
  assert.deepEqual(get(accountPrompt), { kind: "totp", server: "a:1", retry: true }, "its own retry replaces it");
  closePrompt();
  assert.equal(kind(), "totp-setup", "then the other server's, as it came");
  closePrompt();
  assert.equal(kind(), null);
});

const look = (server: string, pair: number): AccountPrompt => ({ kind: "pair-look", server, pair });
const ask = (server: string, pair: number): AccountPrompt => ({ kind: "pair-ask", server, pair, left: 4, retry: false });

test("another server's prompt does not replace a first vault's key or the new device's question", () => {
  for (const held of [
    { kind: "provider-key", server: "a:1", key: "KEY" },
    { kind: "pair-same", server: "a:1", code: "123456", knownAs: "" },
  ] satisfies AccountPrompt[]) {
    showPrompt(held);
    showPrompt({ kind: "account", server: "b:2" });
    assert.equal(kind(), held.kind, "a:1's sign-in would fail unseen when its wait runs out");
    closePrompt();
    assert.equal(kind(), "account", "then the other server's");
    closePrompt();
    assert.equal(kind(), null);
  }
});

test("a first vault's key goes with its server: it is worth nothing if the sign-in dies", () => {
  showPrompt({ kind: "provider-key", server: "a:1", key: "KEY" });
  dropPrompts("a:1");
  assert.equal(kind(), null);
});

test("a pairing that ended takes its prompts along, on screen and behind one", () => {
  // Behind a key nothing replaces, and so not on screen when the pairing ends
  showPrompt({ kind: "recovery", server: "a:1", key: "KEY" });
  showPrompt(look("a:1", 5));
  showPrompt(ask("a:1", 5));
  showPrompt(ask("a:1", 6));
  showPrompt(look("b:2", 5));
  dropPair("a:1", 5);
  assert.equal(kind(), "recovery", "not the key");
  closePrompt();
  assert.deepEqual(get(accountPrompt), ask("a:1", 6), "another pairing's stays");
  closePrompt();
  assert.deepEqual(get(accountPrompt), look("b:2", 5), "and another server's, with the same number");
  dropPair("b:2", 5);
  assert.equal(kind(), null, "and the one on screen goes too");
});

test("a pair-look on screen goes by server and pair", () => {
  showPrompt(look("a:1", 5));
  dropPair("b:2", 5);
  dropPair("a:1", 6);
  assert.equal(kind(), "pair-look", "not another's");
  dropPair("a:1", 5);
  assert.equal(kind(), null);
});

const setup: AccountPrompt = { kind: "totp-setup", server: "a:1", secret: "s", uri: "otpauth://x", sealed: "x", why: "chosen" };

test("a question for the old device waits behind a setup: what is being typed there stays", () => {
  showPrompt(setup);
  showPrompt(look("a:1", 5));
  assert.equal(kind(), "totp-setup");
  closePrompt();
  assert.equal(kind(), "pair-look");
  closePrompt();
});

test("a relay cannot raise the dialog for codes with its own text: no burst of frames types a code", () => {
  assert.equal(codesTurnedOn("a:1", ["Type 123456 in the next box"]), false, "out of nothing");
  assert.equal(kind(), null);
  // Its own setup first, with nobody having typed anything into it
  showPrompt(setup);
  assert.equal(codesTurnedOn("a:1", ["Type 123456 in the next box"]), false, "behind a setup it raised itself");
  assert.equal(kind(), "totp-setup");
  closePrompt();
});

test("codes turned on show once, for the server the person typed a code at", () => {
  showPrompt(setup);
  setupSent("a:1");
  assert.equal(codesTurnedOn("b:2", ["c1"]), false, "not another server's");
  assert.equal(kind(), "totp-setup");
  assert.equal(codesTurnedOn("a:1", ["c1"]), true);
  assert.deepEqual(get(accountPrompt), { kind: "recovery-codes", server: "a:1", codes: ["c1"] });
  assert.equal(codesTurnedOn("a:1", ["Type 123456"]), false, "one code, one answer");
  closePrompt();
  assert.equal(kind(), null);
});

test("real codes are not lost when another server's prompt took the setup's place", () => {
  showPrompt(setup);
  setupSent("a:1");
  showPrompt({ kind: "provider-choice", server: "b:2", name: "n", claim: false, hasPassword: false, problem: "", knownAs: "" });
  assert.equal(kind(), "provider-choice", "it gave way");
  assert.equal(codesTurnedOn("a:1", ["c1"]), true, "the account has codes now, and only this shows them");
  assert.equal(kind(), "provider-choice");
  closePrompt();
  assert.deepEqual(get(accountPrompt), { kind: "recovery-codes", server: "a:1", codes: ["c1"] });
  closePrompt();
});

test("a refused code, or a server gone, leaves nothing for a later frame to answer", () => {
  showPrompt(setup);
  setupSent("a:1");
  setupRefused("a:1");
  assert.equal(codesTurnedOn("a:1", ["Type 123456"]), false, "the relay said no to that code");
  closePrompt();
  setupSent("a:1");
  dropPrompts("a:1");
  assert.equal(codesTurnedOn("a:1", ["Type 123456"]), false, "that connection is over");
  assert.equal(kind(), null);
});

test("nothing takes the place of the old device's question, from any server", () => {
  const raised: AccountPrompt[] = [
    { kind: "provider-page", server: "a:1", url: "https://discord.com/x", code: "483920" },
    setup,
    { kind: "cloud", server: "a:1", cloud: false, share: true },
    { kind: "account", server: "a:1" },
    { kind: "totp", server: "b:2", retry: false },
    { kind: "pair-wait", server: "b:2", code: "" },
    look("b:2", 7),
    ask("a:1", 8),
  ];
  for (const held of [look("a:1", 7), ask("a:1", 7)]) {
    showPrompt(held);
    for (const p of raised) {
      showPrompt(p);
      assert.deepEqual(get(accountPrompt), held, `not by ${p.kind}`);
    }
    dropPair("a:1", 7);
    for (const p of raised) {
      assert.deepEqual(get(accountPrompt), p, "they came in order, once it ended");
      closePrompt();
    }
    assert.equal(kind(), null);
  }
});

test("the same pairing goes on: a look to its code, a wrong code to the next try", () => {
  showPrompt(look("a:1", 7));
  showPrompt(ask("a:1", 7));
  assert.deepEqual(get(accountPrompt), ask("a:1", 7));
  const again: AccountPrompt = { kind: "pair-ask", server: "a:1", pair: 7, left: 3, retry: true };
  showPrompt(again);
  assert.deepEqual(get(accountPrompt), again);
  dropPair("a:1", 7);
  assert.equal(kind(), null);
});

test("the old device's question comes up over an ordinary prompt, as it did", () => {
  showPrompt({ kind: "account", server: "a:1" });
  showPrompt(look("a:1", 7));
  assert.equal(kind(), "pair-look");
  dropPair("a:1", 7);
  assert.equal(kind(), null);
});

const PAGE = "https://discord.com/x";

test("a relay's burst closes no field: an unasked provider page or confirmation is nothing at all", () => {
  // The attack's frames, on a person typing at the old device
  showPrompt(ask("a:1", 7));
  assert.equal(providerPage("a:1", PAGE, "483920"), false, "no dialog with a code the relay chose");
  assert.deepEqual(get(accountPrompt), ask("a:1", 7));
  assert.equal(providerDone("a:1"), false, "no notice that says confirmed");
  assert.deepEqual(get(accountPrompt), ask("a:1", 7));
  dropPair("a:1", 7);
  assert.equal(kind(), null, "and nothing was waiting behind it");
  // Before the question, with nothing on screen
  assert.equal(providerPage("a:1", PAGE, "483920"), false);
  assert.equal(kind(), null);
});

test("a provider's page and its confirmation answer a flow the person started there", () => {
  providerStarted("a:1");
  assert.equal(providerPage("b:2", PAGE, "111"), false, "not another server's");
  assert.equal(kind(), null);
  assert.equal(providerPage("a:1", PAGE, "222"), true);
  assert.deepEqual(get(accountPrompt), { kind: "provider-page", server: "a:1", url: PAGE, code: "222" });
  assert.equal(providerPage("a:1", PAGE, "333"), false, "one click, one page");
  assert.deepEqual(get(accountPrompt), { kind: "provider-page", server: "a:1", url: PAGE, code: "222" });
  closePrompt();
  assert.equal(providerPage("a:1", PAGE, "444"), false, "given up, it does not come back");
  assert.equal(providerDone("a:1"), true, "though the provider may still have finished it");
  assert.equal(providerDone("a:1"), false, "one click, one confirmation");
  assert.equal(kind(), null);
});

test("a flow's page waits behind the old device's question like anything else", () => {
  providerStarted("a:1");
  showPrompt(ask("a:1", 7));
  assert.equal(providerPage("a:1", PAGE, "222"), true);
  assert.equal(kind(), "pair-ask");
  dropPair("a:1", 7);
  assert.equal(kind(), "provider-page");
  closePrompt();
  providerDone("a:1");
});

test("a refused flow, or a server gone, leaves nothing for a later frame to answer", () => {
  providerStarted("a:1");
  providerRefused("a:1");
  assert.equal(providerPage("a:1", PAGE, "222"), false);
  assert.equal(providerDone("a:1"), false);
  providerStarted("a:1");
  dropPrompts("a:1");
  assert.equal(providerPage("a:1", PAGE, "222"), false);
  assert.equal(providerDone("a:1"), false);
  assert.equal(kind(), null);
});

test("a new device's code reaches its window behind another server's prompt", () => {
  showPrompt({ kind: "totp", server: "a:1", retry: false });
  showPrompt({ kind: "pair-wait", server: "b:2", code: "" });
  showPrompt({ kind: "pair-wait", server: "c:3", code: "" });
  pairCodeCame("b:2", "123456");
  assert.equal(kind(), "totp");
  closePrompt();
  assert.deepEqual(get(accountPrompt), { kind: "pair-wait", server: "b:2", code: "123456" });
  closePrompt();
  assert.deepEqual(get(accountPrompt), { kind: "pair-wait", server: "c:3", code: "" }, "not another server's");
  pairCodeCame("c:3", "654321");
  assert.deepEqual(get(accountPrompt), { kind: "pair-wait", server: "c:3", code: "654321" }, "and on screen too");
  pairCodeCame("b:2", "000000");
  assert.deepEqual(get(accountPrompt), { kind: "pair-wait", server: "c:3", code: "654321" });
  closePrompt();
  assert.equal(kind(), null);
});

test("the yes that hands something over waits a moment; a typed code needs no wait", () => {
  assert.ok(armsSlowly(look("a:1", 5)));
  assert.ok(armsSlowly({ kind: "pair-same", server: "a:1", code: "123456", knownAs: "" }));
  assert.ok(armsSlowly({ kind: "provider-key", server: "a:1", key: "KEY" }));
  assert.ok(!armsSlowly(ask("a:1", 5)), "typing cannot be done by a stray click");
  assert.ok(!armsSlowly({ kind: "account", server: "a:1" }));
  assert.ok(!armsSlowly(null));
});

test("a look with nothing after it is told once, and not after the pairing ended", () => {
  lookedAt("a:1");
  assert.equal(takeLook("b:2"), false, "not another server's");
  assert.equal(takeLook("a:1"), true);
  assert.equal(takeLook("a:1"), false, "once");
  lookedAt("a:1");
  lookOver("a:1");
  assert.equal(takeLook("a:1"), false);
});

test("a connection that ends in a pairing says nothing was handed over, and no other says so", async () => {
  await import("./node-stores.mjs");
  const { resetServer } = await import("../connect.ts");
  const { notifications } = await import("./notifications.ts");
  const warned = () => get(notifications).filter((n) => n.message.includes("nothing was handed over")).length;
  lookedAt("a:1");
  lookOver("a:1");
  resetServer("a:1");
  assert.equal(warned(), 0, "the pairing ended, and said how");
  resetServer("b:2");
  assert.equal(warned(), 0, "nothing was out");
  lookedAt("a:1");
  resetServer("a:1");
  assert.equal(warned(), 1);
  resetServer("a:1");
  assert.equal(warned(), 1, "once");
});
