// Relay accounts in the front end: what each open server says about accounts,
// the account this connection signed in with, and the prompts a sign-in needs
// (a code mid-way, a recovery key to write down, a second factor to set up).
// The backends (client/src-tauri/src/account.rs, web/backend/account.ts) emit
// the same events; AccountPrompts.svelte turns them into dialogs.

import { get, writable } from "svelte/store";
import { scoped } from "./scoped.ts";
import type { AccountInfo, RelayAccounts } from "../types.js";
import { toHex } from "../hex.ts";

/** The relay has accounts (from `Authenticated.accounts`), or null. */
export const relayAccounts = scoped<RelayAccounts | null>(() => null);

/** Whether the switch to share history counts on this connection (`share-right`). False until
 *  the backend says, so an ask that beats it is not answered. */
export const shareRight = scoped<boolean>(() => false);

/** The account this connection signed in with, or null for a guest; `cloud`
 *  is its choice to keep messages on the relay (from its vault). */
export const account = scoped<{ name: string; relayId: string; info: AccountInfo; cloud: boolean } | null>(() => null);

/** An account id as the backends print it. */
export const accountHex = (id: number[]) => toHex(id);

/** What the account dialogs show, one at a time. */
export type AccountPrompt =
  /** A sign-in waits for a code; `retry` after a wrong one. */
  | { kind: "totp"; server: string; retry: boolean }
  /** A provider knows this person and nobody here does: choose a name. */
  | { kind: "provider-name"; server: string; suggestion: string; problem: string }
  /** A provider vouched for the person: what opens the account? */
  | { kind: "provider-choice"; server: string; name: string; claim: boolean; hasPassword: boolean; problem: string; knownAs: string }
  /** A first vault's recovery key, with the claim still to go: Cancel leaves nothing. */
  | { kind: "provider-key"; server: string; key: string }
  /** This new device waits for the other one; `code` to type there, once known. */
  | { kind: "pair-wait"; server: string; code: string }
  /** The other device's answer opens, and nothing is open yet: did they type `code` there? */
  | { kind: "pair-same"; server: string; code: string; knownAs: string }
  /** A new device asks this one for the vault's key: is that the person? */
  | { kind: "pair-look"; server: string; pair: number }
  /** They agreed to look: the code the new device shows, typed here. `left`: tries left;
   *  `retry` after a wrong one. */
  | { kind: "pair-ask"; server: string; pair: number; left: number; retry: boolean }
  /** The password and code a provider link or unlink wants. */
  | { kind: "provider-confirm"; server: string; provider: string; action: "link" | "unlink" }
  /** A provider's page to open, with the code to tap there. */
  | { kind: "provider-page"; server: string; url: string; code: string }
  /** A new account's recovery key, shown once; `renewed` for one that
   *  replaced the account's old key (Recovery key: New). */
  | { kind: "recovery"; server: string; key: string; renewed?: boolean }
  /** A new recovery key: the password, a code where codes are on (S-006). */
  | { kind: "recovery-new"; server: string }
  /** Setting up the authenticator app. */
  | { kind: "totp-setup"; server: string; secret: string; uri: string; sealed: string; why: "required" | "chosen" }
  /** Codes are on: the recovery codes, shown once. */
  | { kind: "recovery-codes"; server: string; codes: string[] }
  /** The safety number with someone, to compare with them out of band. */
  | { kind: "safety"; server: string; name: string; number: string }
  /** Keep copies on the server? Asked once per account (the setup), and
   *  shown again from the account panel. `cloud`/`share` are the choices. */
  | { kind: "cloud"; server: string; cloud: boolean; share: boolean }
  /** The account panel. */
  | { kind: "account"; server: string }
  /** A new password: the current one, the new one twice, a code where codes are on. */
  | { kind: "password"; server: string }
  /** Deleting this account's kept messages, or the account itself. */
  | { kind: "delete"; server: string; what: "kept" | "account" };

/** The prompt on screen; set through `showPrompt` / `closePrompt`. */
export const accountPrompt = writable<AccountPrompt | null>(null);

/** Shown once and never again: nothing replaces them while they are open. */
const ONCE: AccountPrompt["kind"][] = ["recovery", "recovery-codes"];
/** A sign-in waiting on the person, which fails unseen when its wait runs out. */
const WAITS: AccountPrompt["kind"][] = ["totp", "provider-name", "provider-choice", "provider-key", "pair-wait", "pair-same"];
/** A yes on these must not catch a click meant for what came before them, and the
 *  relay chooses how fast they come: live only after a moment on screen. */
const ARMED: AccountPrompt["kind"][] = ["pair-look", "pair-same", "provider-key"];
/** What came while a once-only prompt was open, in order. */
const waiting: AccountPrompt[] = [];

/** The old device's questions: is this you, and the code. */
const onOldDevice = (p: AccountPrompt): p is Extract<AccountPrompt, { kind: "pair-look" | "pair-ask" }> =>
  p.kind === "pair-look" || p.kind === "pair-ask";

/** Shows `p` now, or after the prompt that is open where that one must not
 *  go: a once-only one, or another server's sign-in waiting for its code
 *  (which would fail unseen when its wait runs out; 1.0 audit H5-11). */
export function showPrompt(p: AccountPrompt): void {
  const now = get(accountPrompt);
  // The old device's questions also wait behind a setup: a person typing there is not
  // looking for them, and the setup's answer would take their place in turn.
  const behindSetup = now?.kind === "totp-setup" && onOldDevice(p);
  // And nothing takes their place but the same pairing's next: a field gone from under a
  // person typing a code would pass for the code being taken. Ending them is `dropPair`.
  const behindPair = !!now && onOldDevice(now) && !(onOldDevice(p) && p.server === now.server && p.pair === now.pair);
  if (now && (behindSetup || behindPair || ONCE.includes(now.kind) || (WAITS.includes(now.kind) && now.server !== p.server))) waiting.push(p);
  else accountPrompt.set(p);
}

/** Closes the prompt on screen (only `which`, when given: an answer that
 *  came back late must not close another server's), and shows the next. */
export function closePrompt(which?: AccountPrompt): void {
  if (which && get(accountPrompt) !== which) return;
  accountPrompt.set(waiting.shift() ?? null);
}

/** Whether `p`'s yes waits a moment on screen (`ARMED`). */
export const armsSlowly = (p: AccountPrompt | null): boolean => !!p && ARMED.includes(p.kind);

/** A pairing ended: its questions go, on screen and behind a prompt alike. The relay
 *  chooses the numbers, so one left waiting could answer another pairing. */
export function dropPair(server: string, pair: number): void {
  const mine = (p: AccountPrompt) => onOldDevice(p) && p.server === server && p.pair === pair;
  for (let i = waiting.length - 1; i >= 0; i--) {
    if (mine(waiting[i])) waiting.splice(i, 1);
  }
  const now = get(accountPrompt);
  if (now && mine(now)) closePrompt();
}

/** Servers where the person typed a code at a setup of codes, and no answer has come. */
const setups = new Set<string>();
export function setupSent(server: string): void {
  setups.add(server);
}
export function setupRefused(server: string): void {
  setups.delete(server);
}
/** `TotpEnabled`. Its dialog shows text the relay chose and nothing replaces it, so it
 *  answers the person's own code and nothing else, least of all a setup the relay raised
 *  itself. Not tied to the setup being on screen: the codes are real and show only here. */
export function codesTurnedOn(server: string, codes: string[]): boolean {
  if (!setups.delete(server)) return false;
  showPrompt({ kind: "recovery-codes", server, codes });
  return true;
}

/** The code the new device shows, for its window on screen or waiting behind another prompt. */
export function pairCodeCame(server: string, code: string): void {
  const withCode = (p: AccountPrompt | null | undefined) => (p?.kind === "pair-wait" && p.server === server ? { ...p, code } : null);
  const now = withCode(get(accountPrompt));
  if (now) accountPrompt.set(now);
  waiting.forEach((p, i) => (waiting[i] = withCode(p) ?? p));
}

/** Servers where the person started a provider's link or proof, and it has not ended:
 *  `page` once its page was up. */
const providerFlows = new Map<string, "started" | "page">();
export function providerStarted(server: string): void {
  providerFlows.set(server, "started");
}
export function providerRefused(server: string): void {
  providerFlows.delete(server);
}
/** `ProviderBrowser`. Its dialog says "Your code" in the app's words with a code the relay
 *  chose, so it answers the person's own click, once, and nothing else. */
export function providerPage(server: string, url: string, code: string): boolean {
  if (providerFlows.get(server) !== "started") return false;
  providerFlows.set(server, "page");
  showPrompt({ kind: "provider-page", server, url, code });
  return true;
}
/** `ProviderDone`. Its notice says "confirmed", so it too answers only a flow the person
 *  started. A page they gave up on still counts: the provider may have finished it. */
export const providerDone = (server: string): boolean => providerFlows.delete(server);

/** Servers where this device's key went out for a pairing, and the pairing has not ended. */
const looks = new Set<string>();
export function lookedAt(server: string): void {
  looks.add(server);
}
export function lookOver(server: string): void {
  looks.delete(server);
}
/** Whether a look was pending, as the connection ends: the person hears it once. */
export const takeLook = (server: string): boolean => looks.delete(server);

/** A server gone: its prompts go with it, but not a once-only one on screen. */
export function dropPrompts(server: string): void {
  setups.delete(server);
  providerFlows.delete(server);
  for (let i = waiting.length - 1; i >= 0; i--) {
    if (waiting[i].server === server && !ONCE.includes(waiting[i].kind)) waiting.splice(i, 1);
  }
  const now = get(accountPrompt);
  if (now && now.server === server && !ONCE.includes(now.kind)) closePrompt();
}
