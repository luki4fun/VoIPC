// The member context menu, and the two dialogs it opens.
//
// State and actions only; the markup is UserContextMenu.svelte, which App.svelte
// mounts once for every layout. Both member lists open the same menu, so kick,
// ban, poke and invite exist in exactly one place however many lists there are.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { currentChannelId, voice } from "./channels.js";
import { serverAddress, userId } from "./connection.js";
import { addNotification } from "./notifications.js";
import { displayChannelId } from "./roster.js";
import { currentFrame, watchingUserId } from "./screenshare.js";
import type { UserInfo } from "../types.js";

export interface UserMenu {
  user: UserInfo;
  x: number;
  y: number;
  /** From the "Online" group: somebody in no voice channel, not a member of
   *  the channel on screen — so they can be invited to ours, never kicked
   *  from the one on screen. */
  idle: boolean;
}

export const userMenu = writable<UserMenu | null>(null);

/** Right-click or ⋮ on a member row. Never on yourself. */
export function openUserMenu(user: UserInfo, x: number, y: number, idle = false): void {
  if (user.user_id === get(userId)) return;
  userMenu.set({ user, x, y, idle });
}

// Its actions go to the server on screen, and the member it was opened on is
// somebody on the server that was on screen then: a switch in between (a
// bookmark finishing its connect, a server dropping out) closes it.
serverAddress.subscribe(() => userMenu.set(null));

export function closeUserMenu(): void {
  userMenu.set(null);
}

/** Nudge the menu back on screen once its size is known. */
export function repositionUserMenu(width: number, height: number): void {
  userMenu.update((menu) => {
    if (!menu) return menu;
    let { x, y } = menu;
    if (x + width > window.innerWidth) x = window.innerWidth - width - 8;
    if (y + height > window.innerHeight) y = window.innerHeight - height - 8;
    return x === menu.x && y === menu.y ? menu : { ...menu, x, y };
  });
}

// ── Actions ────────────────────────────────────────────────────────────────
//
// The menu is opened on a member of the server on screen, and an action runs
// straight from its click — so "the server on screen" is the member's server.
// The two dialogs below outlive the click and remember theirs.

export async function kickUser(targetUserId: number): Promise<void> {
  try {
    await invoke("kick_user", {
      server: get(serverAddress),
      channelId: get(displayChannelId),
      userId: targetUserId,
    });
  } catch (e) {
    console.error("Failed to kick user:", e);
  }
}

export async function inviteUser(targetUserId: number): Promise<void> {
  try {
    await invoke("send_invite", {
      server: get(serverAddress),
      channelId: get(currentChannelId),
      targetUserId,
    });
  } catch (e) {
    console.error("Failed to invite user:", e);
  }
}

export async function watchUser(targetUserId: number): Promise<void> {
  // Screen shares ride on the voice connection; an id on another server is
  // somebody else there.
  if (get(voice)?.server !== get(serverAddress)) return;
  try {
    await invoke("watch_screen_share", { sharerUserId: targetUserId });
    watchingUserId.set(targetUserId);
    currentFrame.set(null);
  } catch (e: any) {
    addNotification(e.toString(), "error");
  }
}

// ── Poke ───────────────────────────────────────────────────────────────────

export const pokeTarget = writable<{ userId: number; username: string; server: string } | null>(
  null,
);
export const pokeMessage = writable("");

export function openPokeDialog(targetUserId: number, targetUsername: string): void {
  pokeTarget.set({ userId: targetUserId, username: targetUsername, server: get(serverAddress) });
  pokeMessage.set("");
}

export function cancelPoke(): void {
  pokeTarget.set(null);
  pokeMessage.set("");
}

export async function sendPoke(): Promise<void> {
  const target = get(pokeTarget);
  if (!target) return;
  const message = get(pokeMessage);
  cancelPoke();
  try {
    await invoke("send_poke", { server: target.server, targetUserId: target.userId, message });
  } catch (e) {
    console.error("Failed to poke user:", e);
  }
}

// ── Server kick and ban ────────────────────────────────────────────────────
//
// Both ask for a reason first: the person on the other end is told it, and
// "you were kicked" with no reason is how a moderator gets an angry DM.

export interface AdminAction {
  kind: "kick" | "ban";
  userId: number;
  username: string;
  durationSecs: number;
  label: string;
  server: string;
}

export const adminAction = writable<AdminAction | null>(null);
export const adminReason = writable("");

export function openAdminAction(
  user: UserInfo,
  kind: "kick" | "ban",
  durationSecs: number,
  label: string,
): void {
  adminAction.set({
    kind,
    userId: user.user_id,
    username: user.username,
    durationSecs,
    label,
    server: get(serverAddress),
  });
  adminReason.set("");
}

export function cancelAdminAction(): void {
  adminAction.set(null);
  adminReason.set("");
}

export async function confirmAdminAction(): Promise<void> {
  const action = get(adminAction);
  if (!action) return;
  const reason = get(adminReason);
  cancelAdminAction();
  try {
    if (action.kind === "kick") {
      await invoke("admin_kick", { server: action.server, userId: action.userId, reason });
    } else {
      await invoke("admin_ban", {
        server: action.server,
        userId: action.userId,
        reason,
        durationSecs: action.durationSecs,
      });
    }
  } catch (e) {
    addNotification(`Admin action failed: ${e}`, "error");
  }
}
