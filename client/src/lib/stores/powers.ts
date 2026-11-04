// What this account may do on the server on screen (1.7): `$can("voipc:kick")`.
// Its scopes (stores/account.ts) as scopes.ts reads them; admin, by token or
// holding `*`, may do everything. The relay checks every step itself; this
// decides what the app offers.

import { derived, get, type Readable } from "svelte/store";
import { account } from "./account.js";
import { isAdmin } from "./connection.js";
import { canWith } from "../scopes.js";
import { scoped } from "./scoped.js";

export const can: Readable<(scope: string) => boolean> = derived([account, isAdmin], ([$account, $admin]) =>
  canWith($account?.info.scopes ?? [], $admin),
);

/** `can` for a server not on screen. */
export function canOn(server: string, scope: string): boolean {
  return canWith(get(account.peek(server))?.info.scopes ?? [], get(isAdmin.peek(server)))(scope);
}

/** Who may call on everybody on each server, by this connection's user ids. */
export const mentionPower = scoped<Set<number>>(() => new Set());
/** Every badge of our own groups. */
export const myBadges = scoped<string[]>(() => []);

export function onMentionPower(server: string, userIds: number[], on: boolean): void {
  mentionPower.of(server).update((had) => {
    const next = new Set(had);
    for (const id of userIds) {
      if (on) next.add(id);
      else next.delete(id);
    }
    return next;
  });
}
