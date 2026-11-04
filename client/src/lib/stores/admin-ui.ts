// The server-admin token login, the active-bans list, and (1.7) the
// accounts, groups, invites and channel gates of a relay with accounts.
//
// State and commands only; the markup is AdminDialogs.svelte, mounted once by
// App.svelte. Lifted out of the status bar because the modern layout has no
// status bar — it shows the same shield in its voice panel — and because an
// admin dialog is not something to have two copies of.

import { derived, get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { fromServer, listenServer } from "../connect.js";
import { serverAddress } from "./connection.js";
import { can } from "./powers.js";
import { relayAccounts } from "./account.js";
import { olderRelay } from "./relay.js";
import { community, moderation } from "../relay-rules.js";
import { mergeModRows, removalDone } from "../modlog-rules.js";
import { addNotification } from "./notifications.js";
import { scoped } from "./scoped.js";
import { PANEL_SCOPES } from "../scopes.js";
import type { AdminOp, AdminReply, BanInfo } from "../types.js";
import {
  adminError,
  adminGate,
  adminGroups,
  adminInvites,
  adminMembers,
  adminModLog,
  adminOp,
  adminInviteLinks,
  isRemoval,
  inviteLinkCode,
  adminUser,
  adminUsers,
  inviteCode,
  lastOp,
  stepUp,
} from "./admin-ops.js";

export const showAdminLogin = writable(false);
export const showAdminPanel = writable(false);
export const adminToken = writable("");
/** Each server's ban list; the dialogs show the one on screen. */
export const bans = scoped<BanInfo[]>(() => []);

/** Whoever holds one of the panel's privileges (or is admin) opens it. */
export const panelAllowed = derived(
  [can, relayAccounts, olderRelay],
  ([$can, $accounts, $older]) =>
    PANEL_SCOPES.some((s) => $can(s)) ||
    // The Channels tab, which an older relay has not got: without it a moderator
    // would open a panel with nothing in it
    (!!$accounts && community($older?.protocol ?? null) && $can("voipc:channels")) ||
    // And the Moderation log tab, for someone holding that and no more
    (!!$accounts && moderation($older?.protocol ?? null) && $can("voipc:modlog")),
);

// A login that succeeds arrives back as `admin-status`, which App.svelte routes
// into `isAdmin`; losing the privileges closes the panel with them — and so
// does looking at a server where we hold none.
panelAllowed.subscribe((allowed) => {
  if (allowed) showAdminLogin.set(false);
  else showAdminPanel.set(false);
});

// The login is for the server on screen when it is submitted: a token typed
// for one must not go to another because the view moved while it was up.
serverAddress.subscribe(() => {
  showAdminLogin.set(false);
  adminToken.set("");
});

listenServer<{ bans: BanInfo[] }>("admin-bans", (server, data) => bans.of(server).set(data.bans));

export async function submitAdminLogin(): Promise<void> {
  const server = get(serverAddress);
  const token = get(adminToken).trim();
  adminToken.set("");
  if (!token) return;
  try {
    await invoke("admin_login", { server, token });
  } catch (e) {
    addNotification(`Admin login failed: ${e}`, "error");
  }
}

export function openAdminPanel(): void {
  showAdminPanel.set(true);
  if (!get(can)("voipc:bans")) return;
  invoke("admin_list_bans", { server: get(serverAddress) }).catch((e: unknown) =>
    addNotification(`Could not load bans: ${e}`, "error"),
  );
}

/** Clear what a scoped admin store shows, on the server on screen. */
export function clearShown(store: { of(server: string): { set(v: null): void } }): void {
  store.of(get(serverAddress)).set(null);
}

export async function unban(id: number): Promise<void> {
  try {
    await invoke("admin_unban", { server: get(serverAddress), id });
  } catch (e) {
    addNotification(`Unban failed: ${e}`, "error");
  }
}

/** Ban an account by name, online or not; `durationSecs` 0 = permanent. `removal`:
 *  how far back its posts go too (`RemovePosts`), the moment the ban is made. */
export async function banAccount(name: string, reason: string, durationSecs: number, removal: number | null = null): Promise<void> {
  const server = get(serverAddress);
  try {
    await invoke("admin_ban_account", { server, name: name.trim(), reason, durationSecs });
    if (removal !== null) void adminOp({ RemovePosts: { name: name.trim(), window_secs: removal } }, null, server);
  } catch (e) {
    addNotification(`Ban failed: ${e}`, "error");
  }
}

/** How long a ban has left, for the list. */
export function expiry(ban: BanInfo): string {
  if (ban.expires_in_secs === null) return "permanent";
  const s = ban.expires_in_secs;
  if (s >= 3600) return `${Math.ceil(s / 3600)} h left`;
  if (s >= 60) return `${Math.ceil(s / 60)} min left`;
  return `${s} s left`;
}

// ── Accounts, groups, invites, gates (1.7) ─────────────────────────────────
//
// The stores and `adminOp` live in admin-ops.ts, which channel-ui.ts reads
// too (a channel's gate) without the import cycle through connect.ts.

export * from "./admin-ops.js";

/**
 * The removal a code was just sent for, per server. Its checks came before the code
 * was asked for, so a refusal now is that code: from the ban dialog there is no button
 * to press again, and a moderator may have no ban list to do it from.
 */
const removalWithCode = new Map<string, AdminOp>();

/** The step that asked for a code, sent again with it. */
export function submitStepUp(code: string): void {
  const server = get(serverAddress);
  const op = get(stepUp.of(server));
  stepUp.of(server).set(null);
  if (!op || !code.trim()) return;
  if (isRemoval(op)) removalWithCode.set(server, op);
  void adminOp(op, code.trim(), server);
}

listenServer<unknown>("account-reply", (server, raw) => {
  const r = raw as { Admin?: AdminReply; Error?: { request: string; reason: string } };
  if (r.Error?.request === "Admin") {
    adminError.of(server).set(r.Error.reason);
    const again = removalWithCode.get(server);
    if (again) {
      removalWithCode.delete(server);
      stepUp.of(server).set(again);
    }
    // Asked from elsewhere (a channel's gate): nowhere else to show it
    if (!get(showAdminPanel) || server !== get(serverAddress)) {
      addNotification(`${fromServer(server)}${r.Error.reason}`, "warning");
    }
    return;
  }
  const a = r.Admin;
  if (!a) return;
  if (a === "StepUp") {
    stepUp.of(server).set(lastOp.get(server) ?? null);
    return;
  }
  if ("Users" in a) adminUsers.of(server).set(a.Users);
  else if ("User" in a) adminUser.of(server).set(a.User);
  else if ("Groups" in a) adminGroups.of(server).set(a.Groups.groups);
  else if ("Members" in a) adminMembers.of(server).set(a.Members);
  else if ("Invites" in a) adminInvites.of(server).set(a.Invites.invites);
  else if ("InviteCode" in a) inviteCode.of(server).set(a.InviteCode.code);
  else if ("InviteLinks" in a) adminInviteLinks.of(server).set(a.InviteLinks.links);
  else if ("InviteLinkCode" in a) inviteLinkCode.of(server).set(a.InviteLinkCode.code);
  else if ("Gate" in a) adminGate.of(server).set(a.Gate);
  else if ("PostsRemoved" in a) {
    removalWithCode.delete(server);
    stepUp.of(server).set(null);
    addNotification(`${fromServer(server)}${removalDone(a.PostsRemoved.entries)}`, "info");
  }
  else if ("ModLog" in a) {
    const { before, rows, more, keep_days } = a.ModLog;
    adminModLog.of(server).update((had) => ({
      rows: mergeModRows(before === 0 ? [] : (had?.rows ?? []), rows),
      more,
      keep_days,
    }));
  }
});
