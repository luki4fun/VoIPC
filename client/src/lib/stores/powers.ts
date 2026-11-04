// What this account may do on the server on screen (1.7): `$can("voipc:kick")`.
// Its scopes (stores/account.ts) as scopes.ts reads them; admin, by token or
// holding `*`, may do everything. The relay checks every step itself; this
// decides what the app offers.

import { derived, get, type Readable } from "svelte/store";
import { account } from "./account.js";
import { isAdmin } from "./connection.js";
import { canWith } from "../scopes.js";

export const can: Readable<(scope: string) => boolean> = derived([account, isAdmin], ([$account, $admin]) =>
  canWith($account?.info.scopes ?? [], $admin),
);

/** `can` for a server not on screen. */
export function canOn(server: string, scope: string): boolean {
  return canWith(get(account.peek(server))?.info.scopes ?? [], get(isAdmin.peek(server)))(scope);
}

