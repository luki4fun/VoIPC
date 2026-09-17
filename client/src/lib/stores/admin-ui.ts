// The server-admin token login and the active-bans list.
//
// State and commands only; the markup is AdminDialogs.svelte, mounted once by
// App.svelte. Lifted out of the status bar because the Discord layout has no
// status bar — it shows the same shield in its voice panel — and because an
// admin dialog is not something to have two copies of.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import { isAdmin } from "./connection.js";
import { addNotification } from "./notifications.js";
import type { BanInfo } from "../types.js";

export const showAdminLogin = writable(false);
export const showAdminPanel = writable(false);
export const adminToken = writable("");
export const bans = writable<BanInfo[]>([]);

// A login that succeeds arrives back as `admin-status`, which App.svelte routes
// into `isAdmin`; losing admin closes the panel with it.
isAdmin.subscribe((admin) => {
  if (admin) showAdminLogin.set(false);
  else showAdminPanel.set(false);
});

listen<{ bans: BanInfo[] }>("admin-bans", (e) => bans.set(e.payload.bans));

export async function submitAdminLogin(): Promise<void> {
  const token = get(adminToken).trim();
  adminToken.set("");
  if (!token) return;
  try {
    await invoke("admin_login", { token });
  } catch (e) {
    addNotification(`Admin login failed: ${e}`, "error");
  }
}

export function openAdminPanel(): void {
  showAdminPanel.set(true);
  invoke("admin_list_bans").catch((e: unknown) =>
    addNotification(`Could not load bans: ${e}`, "error"),
  );
}

export async function unban(ip: string): Promise<void> {
  try {
    await invoke("admin_unban", { ip });
  } catch (e) {
    addNotification(`Unban failed: ${e}`, "error");
  }
}

/** How long a ban has left, for the list. */
export function expiry(ban: BanInfo): string {
  if (ban.expires_in_secs === null) return "until server restart";
  const s = ban.expires_in_secs;
  if (s >= 3600) return `${Math.ceil(s / 3600)} h left`;
  if (s >= 60) return `${Math.ceil(s / 60)} min left`;
  return `${s} s left`;
}
