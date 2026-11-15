// Whose chat history a server shows (1.12). A guest's: one per server on this device, whatever
// name and tag it joins with. An account's: only what belongs to that account. The keys say
// which: `host:port/…` is a guest's, `host:port~<account hex>/…` an account's. Unread counts,
// deletion marks, a log's last name, where a person read and whom they named all go by the
// same key, so they follow.

import { writable } from "svelte/store";

import { serverKey } from "./servers.js";

/** `serverKey` -> the account hex its history is filed under now; none for a guest. */
const scopes = new Map<string, string>();

/** Bumped when a server's scope changes: what is drawn from the keys is drawn again. */
export const historyScopes = writable(0);

const ACCOUNT_HEX = /^[0-9a-f]{32}$/;

/** The account a server's history is filed under now, `""` for a guest's. */
export function historyScope(server: string): string {
  return scopes.get(serverKey(server)) ?? "";
}

/** What a server's chat keys start with: `host:port` for a guest, `host:port~<account>` for an
 *  account. `""` for no server. */
export function historyKey(server: string): string {
  const key = serverKey(server);
  if (!key) return "";
  const scope = scopes.get(key);
  return scope ? `${key}~${scope}` : key;
}

/** `historyKey` and the slash after it: what every key of the history shown starts with. */
export function historyPrefix(server: string): string {
  const key = historyKey(server);
  return key ? `${key}/` : "";
}

/** Whether `key` is any of the server's histories, whoever's: what a closed connection's
 *  counts go by. */
export function onServer(key: string, server: string): boolean {
  const k = serverKey(server);
  return !!k && (key.startsWith(`${k}/`) || key.startsWith(`${k}~`));
}

/** Whether a key's scope (`splitChatKey`) is the one its server shows now. */
export function inScope(serverHostPort: string, scope: string): boolean {
  return (scopes.get(serverHostPort) ?? "") === scope;
}

/**
 * The history `server` shows from now: `account` (hex) once it signed in, null for a guest.
 * Set where a connection says who it is: a guest's connect, an account's sign-in. Kept after
 * the connection goes, so what was on screen stays until the next one says otherwise.
 */
export function setHistoryScope(server: string, account: string | null): void {
  const key = serverKey(server);
  if (!key) return;
  const next = account && ACCOUNT_HEX.test(account) ? account : "";
  if ((scopes.get(key) ?? "") === next) return;
  if (next) scopes.set(key, next);
  else scopes.delete(key);
  historyScopes.update((n) => n + 1);
}

/** For the tests. */
export function forgetHistoryScopes(): void {
  scopes.clear();
  historyScopes.update((n) => n + 1);
}
