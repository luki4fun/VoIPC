// What this account may do on the server on screen (1.7): `$can("voipc:kick")`.
// Its scopes (stores/account.ts) as scopes.ts reads them; admin, by token or
// holding `*`, may do everything. The relay checks every step itself; this
// decides what the app offers.

import { derived, get, type Readable } from "svelte/store";
import { account, accountHex } from "./account.js";
import { isAdmin, userId, username } from "./connection.js";
import { canWith } from "../scopes.js";
import { cleanTakers, type RawTaker, type ReportTaker } from "../report-rules.js";
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
/**
 * Every account holding a privilege on each server (`ChatMods`), by hex id, here
 * or not: a stored hide must still count once its moderator has gone.
 */
export const chatMods = scoped<ReadonlyMap<string, { hide: boolean; admin: boolean }>>(() => new Map());

export function onChatMods(server: string, mods: readonly { account: number[]; hide: boolean; admin: boolean }[]): void {
  chatMods.of(server).set(new Map(mods.map((m) => [accountHex(m.account), { hide: m.hide, admin: m.admin }])));
}

/** Who takes a report, as last asked. Null: asked, and no answer yet. */
export const reportTakers = scoped<readonly ReportTaker[] | null>(() => null);

export function onReportTakers(server: string, takers: readonly RawTaker[]): void {
  const own = get(account.peek(server));
  const me = { user_id: get(userId.peek(server)), account: own ? accountHex(own.info.id) : undefined, name: get(username.peek(server)) };
  reportTakers.of(server).set(cleanTakers(takers, me));
}

/** What this run reported already: once a message is enough. Kept beside the id the
 *  name of whoever wrote it, since an id is theirs to choose. */
const reported = new Set<string>();
const reportedKey = (server: string, writer: string, id: string) => `${server}\n${writer}\n${id}`;
export const wasReported = (server: string, writer: string, id: string) => reported.has(reportedKey(server, writer, id));
export function noteReported(server: string, writer: string, id: string, on: boolean): void {
  if (on) reported.add(reportedKey(server, writer, id));
  else reported.delete(reportedKey(server, writer, id));
}

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
