// The server-admin token login and the active-bans list.
//
// State and commands only; the markup is AdminDialogs.svelte, mounted once by
// App.svelte. Lifted out of the status bar because the modern layout has no
// status bar — it shows the same shield in its voice panel — and because an
// admin dialog is not something to have two copies of.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { listenServer } from "../connect.js";
import { isAdmin, serverAddress } from "./connection.js";
import { addNotification } from "./notifications.js";
import { scoped } from "./scoped.js";
import type { BanInfo } from "../types.js";

export const showAdminLogin = writable(false);
export const showAdminPanel = writable(false);
export const adminToken = writable("");
/** Each server's ban list; the dialogs show the one on screen. */
export const bans = scoped<BanInfo[]>(() => []);

// A login that succeeds arrives back as `admin-status`, which App.svelte routes
// into `isAdmin`; losing admin closes the panel with it — and so does looking
// at a server we are not admin on.
isAdmin.subscribe((admin) => {
  if (admin) showAdminLogin.set(false);
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
  invoke("admin_list_bans", { server: get(serverAddress) }).catch((e: unknown) =>
    addNotification(`Could not load bans: ${e}`, "error"),
  );
}

export async function unban(id: number): Promise<void> {
  try {
    await invoke("admin_unban", { server: get(serverAddress), id });
  } catch (e) {
    addNotification(`Unban failed: ${e}`, "error");
  }
}

/** Ban an account by name, online or not; `durationSecs` 0 = permanent. */
export async function banAccount(name: string, reason: string, durationSecs: number): Promise<void> {
  try {
    await invoke("admin_ban_account", { server: get(serverAddress), name: name.trim(), reason, durationSecs });
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
