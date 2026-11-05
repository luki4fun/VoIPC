// The moderation log's rows, for the panel (AdminModLog.svelte). Pure, so the tests
// load it under Node.

import type { BanInfo, ModRow } from "./types.js";

/** What is shown, with a page added: newest first, and each row once, since a
 *  repeated id stops a keyed each and the whole panel with it. */
export function mergeModRows(had: readonly ModRow[], page: readonly ModRow[]): ModRow[] {
  const byId = new Map<number, ModRow>();
  for (const row of [...had, ...page]) byId.set(row.id, row);
  return [...byId.values()].sort((a, b) => b.id - a.id);
}

/** The words before the row's target, and after it. */
const ACTIONS = new Map<string, [string, string]>([
  ["kick", ["kicked", "from the server"]],
  ["ban", ["banned", ""]],
  ["unban", ["lifted the ban on", ""]],
  ["restrict", ["restricted", ""]],
  ["unrestrict", ["lifted the restriction on", ""]],
  ["channel_kick", ["kicked", "from a channel"]],
  ["channel_delete", ["deleted a channel", ""]],
  ["summon", ["invited", "to a channel"]],
  ["profile_reset", ["cleared the profile of", ""]],
  ["remove_posts", ["removed the posts of", ""]],
  ["hide", ["hid a message of", ""]],
  ["unhide", ["showed again a message of", ""]],
  ["import", ["began a move from Discord", ""]],
  ["import_done", ["finished a move from Discord", ""]],
  ["import_undo", ["undid a move from Discord", ""]],
  ["import_exclude", ["left someone out of the move from Discord", ""]],
  ["import_include", ["let someone back into the move from Discord", ""]],
  ["power_grant", ["gave", "what they could do on Discord"]],
  ["power_drop", ["said no to", "keeping what they could do on Discord"]],
  ["unclaimed_expired", ["removed accounts nobody signed in to", ""]],
  ["archive_delete", ["deleted posts imported from Discord", ""]],
]);

/** An action in words, around its target. One this app does not know yet shows as
 *  the relay names it. */
export function modAction(action: string): [string, string] {
  return ACTIONS.get(action) ?? [action, ""];
}

const IN_A_CHANNEL = new Set(["channel_kick", "channel_delete", "summon", "hide", "unhide"]);

/** Where it happened, or null for what is server-wide. The relay says no channel
 *  both for those and for one this reader cannot see. */
export function modPlace(row: Pick<ModRow, "action" | "channel">): string | null {
  if (row.channel != null) return `#${row.channel}`;
  return IN_A_CHANNEL.has(row.action) ? "a channel you cannot see" : null;
}

/** How far back a removal can go, as `window_secs`, for a holder of the ban
 *  privilege; an admin may also ask for all that is kept (0). */
export function removalWindows(admin: boolean): [number, string][] {
  const each: [number, string][] = [
    [3600, "Last hour"],
    [86_400, "Last 24 hours"],
    [604_800, "Last 7 days"],
  ];
  return admin ? [...each, [0, "Everything kept"]] : each;
}

/** What removing does, said before it is done. `account`: the person has one here.
 *  `imported`: the relay can hold posts brought from Discord (protocol 20). */
export function removalHint(account: boolean, imported = false): string {
  if (!account) return "A guest has nothing kept here: this only asks devices to hide what they hold.";
  const kept =
    "Deletes what this server keeps of their channel messages, not direct messages. It cannot delete copies on people's devices: those are hidden with your name on them, and anyone can still show them. A limited window can bring back an older message they deleted or edited, for devices reading the log anew: their delete or edit goes, and the older text stays. It does not undo when the ban ends.";
  return imported ? `${kept} This also takes their posts imported from Discord in that time span, counted by when they were written.` : kept;
}

/** Whether removing from this row of Active bans reaches an account. The relay goes
 *  by the name, so an address row counts too when that name also has an account row.
 *  The list can be a part: account rows come first, and a search finds both by that
 *  name, so that row is here by the time this one is. */
export function removalReachesAccount(
  row: Pick<BanInfo, "account" | "label">,
  bans: readonly Pick<BanInfo, "account" | "label">[],
): boolean {
  return row.account || bans.some((b) => b.account && b.label === row.label);
}

/** What it came to. */
export function removalDone(entries: number): string {
  const kept = entries === 1 ? "1 kept message" : `${entries} kept messages`;
  return `${entries === 0 ? "Nothing kept to delete" : `${kept} deleted`}; copies on devices are hidden, not erased`;
}
