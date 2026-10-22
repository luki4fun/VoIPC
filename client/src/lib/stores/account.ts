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

/** The account this connection signed in with, or null for a guest; `cloud`
 *  is its choice to keep messages on the relay (from its vault). */
export const account = scoped<{ name: string; relayId: string; info: AccountInfo; cloud: boolean } | null>(() => null);

/** An account id as the backends print it. */
export const accountHex = (id: number[]) => toHex(id);

/** What the account dialogs show, one at a time. */
export type AccountPrompt =
  /** A sign-in waits for a code; `retry` after a wrong one. */
  | { kind: "totp"; server: string; retry: boolean }
  /** A new account's recovery key, shown once. */
  | { kind: "recovery"; server: string; key: string }
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
  | { kind: "account"; server: string };

/** The prompt on screen; set through `showPrompt` / `closePrompt`. */
export const accountPrompt = writable<AccountPrompt | null>(null);

/** Shown once and never again: nothing replaces them while they are open. */
const ONCE: AccountPrompt["kind"][] = ["recovery", "recovery-codes"];
/** What came while a once-only prompt was open, in order. */
const waiting: AccountPrompt[] = [];

/** Shows `p` now, or after the once-only prompt that is open. */
export function showPrompt(p: AccountPrompt): void {
  const now = get(accountPrompt);
  if (now && ONCE.includes(now.kind)) waiting.push(p);
  else accountPrompt.set(p);
}

/** Closes the prompt on screen (only `which`, when given: an answer that
 *  came back late must not close another server's), and shows the next. */
export function closePrompt(which?: AccountPrompt): void {
  if (which && get(accountPrompt) !== which) return;
  accountPrompt.set(waiting.shift() ?? null);
}

/** A server gone: its prompts go with it, but not a once-only one on screen. */
export function dropPrompts(server: string): void {
  for (let i = waiting.length - 1; i >= 0; i--) {
    if (waiting[i].server === server && !ONCE.includes(waiting[i].kind)) waiting.splice(i, 1);
  }
  const now = get(accountPrompt);
  if (now && now.server === server && !ONCE.includes(now.kind)) closePrompt();
}
