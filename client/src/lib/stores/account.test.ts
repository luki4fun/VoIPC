// The account dialogs come one at a time, and the ones shown only once (a
// new account's recovery key, the recovery codes) are never replaced by
// whatever comes next: it waits behind them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "svelte/store";
import { accountPrompt, closePrompt, dropPrompts, showPrompt, type AccountPrompt } from "./account.ts";

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
