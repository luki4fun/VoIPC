// The browser's sign-in driver around a stand-in for the wasm machine: the order things
// go in, and what a Cancel reaches. The machine's own rules are voipc_crypto's tests, and
// the whole of it runs in test-provider.mjs.

import { test } from "node:test";
import assert from "node:assert/strict";

(globalThis as any).localStorage = { getItem: () => null, setItem: () => {} };
await import("../../lib/stores/node-stores.mjs");
const { ACCOUNT_STEP_MS, AccountDriver, frameGoesOn } = await import("./account.ts");

const choice = { name: "luki", claim: false, has_password: false, known_as: "" };

/** A driver, the calls its machine got, and what it did to its host. */
function driver(frames: unknown[][]) {
  const calls: string[] = [];
  const signIn = {
    step: () => frames.shift() ?? [],
    midPairing: () => false,
    pairStart: () => (calls.push("pairStart"), new Uint8Array([1])),
    providerClaimKey: () => (calls.push("providerClaimKey"), "THE-KEY"),
    providerClaim: () => (calls.push("providerClaim"), [{ send: new Uint8Array([2]) }]),
    pairSame: (yes: boolean) => {
      calls.push(`pairSame ${yes}`);
      if (!yes) throw new Error("Nothing was opened.");
      return [{ send: new Uint8Array([3]) }];
    },
    free: () => {},
  };
  const host = {
    server: "a:1",
    sent: [] as Uint8Array[],
    emitted: [] as [string, unknown][],
    failed: [] as string[],
    waits: [] as number[],
    sendRaw(p: Uint8Array) {
      this.sent.push(p);
    },
    sendControl() {},
    emit(name: string, data: unknown) {
      this.emitted.push([name, data]);
    },
    replaceSignal() {},
    failAuth(e: Error) {
      this.failed.push(e.message);
    },
    authWait(ms: number) {
      this.waits.push(ms);
    },
  };
  const d = new (AccountDriver as any)(signIn, true, null);
  return { d, host, calls };
}

const tick = () => new Promise((r) => setImmediate(r));
const asked = (host: { emitted: [string, unknown][] }) => host.emitted.at(-1)?.[0];

test("a Cancel reaches a sign-in waiting for the other device, with no prompt up to answer", async () => {
  const { d, host, calls } = driver([[{ providerChoice: choice }]]);
  d.onPayload(host, new Uint8Array());
  d.answerProvider({ kind: "pair" });
  await tick();
  assert.deepEqual(calls, ["pairStart"]);
  assert.equal(host.failed.length, 0);
  d.cancel();
  assert.deepEqual(host.failed, ["Sign-in cancelled."]);
  d.dispose();
});

test("the Cancel is over once the other device answered: the question has its own", async () => {
  const { d, host } = driver([[{ providerChoice: choice }], [{ pairRefused: "Your other device said no." }]]);
  d.onPayload(host, new Uint8Array());
  d.answerProvider({ kind: "pair" });
  await tick();
  d.onPayload(host, new Uint8Array());
  await tick();
  assert.equal(asked(host), "account-provider-choice", "asked again");
  assert.deepEqual(host.emitted.at(-1)?.[1], { ...choice, problem: "Your other device said no." });
  d.answerProvider({ kind: "password" });
  await tick();
  d.cancel();
  assert.equal(host.failed.length, 1, "the password's end and nothing from the wait before it");
  d.dispose();
});

test("no claim goes out before the key was written down", async () => {
  const { d, host, calls } = driver([[{ providerChoice: { ...choice, claim: true } }]]);
  d.onPayload(host, new Uint8Array());
  d.answerProvider({ kind: "claim" });
  await tick();
  assert.equal(asked(host), "account-provider-key");
  assert.deepEqual(host.emitted.at(-1)?.[1], { key: "THE-KEY" });
  assert.deepEqual(calls, ["providerClaimKey"], "nothing has gone");
  assert.equal(host.sent.length, 0);
  d.answerProvider({ kind: "keysaved" });
  await tick();
  assert.deepEqual(calls, ["providerClaimKey", "providerClaim"]);
  assert.equal(host.sent.length, 1);
  d.dispose();
});

test("a Cancel at the key sends no claim", async () => {
  const { d, host, calls } = driver([[{ providerChoice: { ...choice, claim: true } }]]);
  d.onPayload(host, new Uint8Array());
  d.answerProvider({ kind: "claim" });
  await tick();
  d.cancel();
  await tick();
  assert.deepEqual(calls, ["providerClaimKey"]);
  assert.equal(host.failed.length, 1);
  assert.equal(host.sent.length, 0);
  d.dispose();
});

test("the new device's question goes to the machine, and a no ends the sign-in with its reason", async () => {
  for (const yes of [true, false]) {
    const { d, host, calls } = driver([[{ pairSame: { code: "123456", known_as: "" } }]]);
    d.onPayload(host, new Uint8Array());
    assert.equal(asked(host), "account-pair-same");
    assert.deepEqual(host.emitted.at(-1)?.[1], { code: "123456", known_as: "" });
    assert.deepEqual(calls, [], "nothing opens on its own");
    d.answerProvider({ kind: "same", yes });
    await tick();
    assert.deepEqual(calls, [`pairSame ${yes}`]);
    assert.deepEqual(host.failed, yes ? [] : ["Nothing was opened."]);
    assert.equal(host.sent.length, yes ? 1 : 0);
    d.dispose();
  }
});

test("the sign-in's clock runs per step: a whole pairing takes longer than any one of them", async () => {
  const { d, host } = driver([[{ providerChoice: choice }], [{ pairCode: "123456" }], [{ pairSame: { code: "123456", known_as: "" } }]]);
  d.onPayload(host, new Uint8Array());
  assert.equal(host.waits.at(-1)! > 290_000, true, "a person has the prompt's own wait");
  d.answerProvider({ kind: "pair" });
  await tick();
  assert.equal(host.waits.at(-1), ACCOUNT_STEP_MS, "and the relay its step, from the answer on");
  host.waits.length = 0;
  d.onPayload(host, new Uint8Array());
  assert.deepEqual(host.waits, [ACCOUNT_STEP_MS], "started over by the other device's answer");
  d.onPayload(host, new Uint8Array());
  assert.equal(host.waits.at(-1)! > 290_000, true, "and the question has the prompt's");
  d.cancel();
  await tick();
  d.dispose();
});

test("before it is signed in, a connection takes the sign-in's own frames and nothing else", () => {
  for (const words of [{ ChannelError: { reason: "483920" } }, { Disconnected: { reason: "483920" } }, { TextMessage: {} }, { Account: {} }, "Pong"]) {
    assert.equal(frameGoesOn(words, false, false), false, JSON.stringify(words));
    assert.equal(frameGoesOn(words, false, true), false, JSON.stringify(words));
    assert.equal(frameGoesOn(words, true, false), true, "signed in, they are the session's");
  }
  for (const own of [{ Authenticated: {} }, { AuthError: {} }, { AuthStep: {} }, { Refused: {} }]) {
    assert.equal(frameGoesOn(own, false, false), true, JSON.stringify(own));
  }
});

test("during a pairing a refusal does not reach the update panel, and an honest one still does", () => {
  const refused = { Refused: { server_version: "Your code is 483920" } };
  assert.equal(frameGoesOn(refused, false, true), false);
  assert.equal(frameGoesOn(refused, false, false), true);
  assert.equal(frameGoesOn({ Authenticated: {} }, false, true), true, "the machine refuses that one: no vault is open");
  assert.equal(frameGoesOn({ AuthError: {} }, false, true), true, "its handler only ends a sign-in already over");
});

test("the driver reads the machine's state, and nothing once it is over", () => {
  const { d } = driver([]);
  assert.equal(d.midPairing, false);
  d.signIn.midPairing = () => true;
  assert.equal(d.midPairing, true);
  d.dispose();
  assert.equal(d.midPairing, false);
});
