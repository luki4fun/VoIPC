// The member context menu, and the two dialogs it opens.
//
// State and actions only; the markup is UserContextMenu.svelte, which App.svelte
// mounts once for every layout. Both member lists open the same menu, so kick,
// ban, poke and invite exist in exactly one place however many lists there are.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { adminOp } from "./admin-ops.js";
import { attachDm } from "./chat.js";
import { currentChannelId, voice } from "./channels.js";
import { serverAddress, userId } from "./connection.js";
import { addNotification } from "./notifications.js";
import { confirmAction } from "./confirm.js";
import { displayChannelId } from "./roster.js";
import { currentFrame, previewStage, watchingUserId } from "./screenshare.js";
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
    // And never off the top or the left: a menu taller than a short window
    // (or a zoomed one) starts at the edge and scrolls (UserContextMenu)
    x = Math.max(8, x);
    y = Math.max(8, y);
    return x === menu.x && y === menu.y ? menu : { ...menu, x, y };
  });
}

// ── Actions ────────────────────────────────────────────────────────────────
//
// The menu is opened on a member of the server on screen, and an action runs
// straight from its click — so "the server on screen" is the member's server.
// The two dialogs below outlive the click and remember theirs.

/** Out of the channel on screen — asked first, as a kick from the server is. */
export async function kickUser(targetUserId: number, name = "them"): Promise<void> {
  const server = get(serverAddress);
  const channelId = get(displayChannelId);
  const ok = await confirmAction({
    title: `Remove ${name} from this channel?`,
    body: `${name} is moved out of the channel. They stay on the server and can come back unless the channel keeps them out.`,
    confirm: "Remove",
    danger: true,
  });
  if (!ok) return;
  try {
    await invoke("kick_user", { server, channelId, userId: targetUserId });
  } catch (e) {
    console.error("Failed to kick user:", e);
    addNotification(`Could not remove ${name} from the channel: ${e}`, "error");
  }
}

/** Asked first. Cleared, the person may pick another: there is nothing to take back.
 *  The server is the one on screen now: the view may move while the question is up.
 *  Whether it was said yes to. */
export async function clearProfile(id: number[], server = get(serverAddress)): Promise<boolean> {
  const yes = await confirmAction({
    title: "Clear this person's display name and picture?",
    body: "They can pick others.",
    confirm: "Clear them",
    danger: true,
  });
  if (yes) await adminOp({ ProfileReset: { id, name: true, picture: true } }, null, server);
  return yes;
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
    addNotification(`The invite was not sent: ${e}`, "error");
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

/** One click on a LIVE marker: watch that share — or, on our own, open the
 *  preview of what we send. */
export function openShare(sharerUserId: number): void {
  if (sharerUserId === get(userId)) previewStage.set(true);
  else void watchUser(sharerUserId);
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
  // Our own copy files under whom it is for, with no conversation open to say it
  attachDm(target.server, target.username, target.userId);
  try {
    await invoke("send_poke", { server: target.server, targetUserId: target.userId, message });
  } catch (e) {
    console.error("Failed to poke user:", e);
  }
}

// ── Server kick, ban, mute and timeout ─────────────────────────────────────
//
// All ask for a reason first: the person on the other end is told it, and
// "you were kicked" with no reason is how a moderator gets an angry DM.

export interface AdminAction {
  kind: "kick" | "ban" | "mute" | "timeout";
  userId: number;
  username: string;
  label: string;
  server: string;
  /** Signed in with an account, which a ban can cover too. */
  hasAccount: boolean;
}

export const adminAction = writable<AdminAction | null>(null);
export const adminReason = writable("");
/** How long a ban or restriction goes for; 0: for good, or until lifted. */
export const adminDuration = writable(0);
/** "Ban the account too", for a user with one; on by default. */
export const adminBanAccount = writable(true);
/** How far back a ban also removes their posts, as `window_secs`; null: it does not. */
export const adminRemovePosts = writable<number | null>(null);

export function openAdminAction(
  user: UserInfo,
  kind: AdminAction["kind"],
  durationSecs: number,
  label: string,
): void {
  adminAction.set({
    kind,
    userId: user.user_id,
    username: user.username,
    label,
    server: get(serverAddress),
    hasAccount: !!user.account,
  });
  adminReason.set("");
  adminDuration.set(durationSecs);
  adminBanAccount.set(true);
  adminRemovePosts.set(null);
}

export function cancelAdminAction(): void {
  adminAction.set(null);
  adminReason.set("");
}

export async function confirmAdminAction(): Promise<void> {
  const action = get(adminAction);
  if (!action) return;
  const reason = get(adminReason);
  const durationSecs = get(adminDuration);
  const removal = get(adminRemovePosts);
  cancelAdminAction();
  try {
    if (action.kind === "kick") {
      await invoke("admin_kick", { server: action.server, userId: action.userId, reason });
    } else if (action.kind === "ban") {
      await invoke("admin_ban", {
        server: action.server,
        userId: action.userId,
        reason,
        durationSecs,
        // Nothing kept can go without the account's own ban
        account: action.hasAccount && (get(adminBanAccount) || removal !== null),
      });
      // A step of its own: a ban's shape on the wire is released. Requests on a
      // connection are handled in order, so the relay reads this with the ban made.
      if (removal !== null) {
        void adminOp({ RemovePosts: { name: action.username, window_secs: removal } }, null, action.server);
      }
    } else {
      await invoke("admin_restrict", {
        server: action.server,
        userId: action.userId,
        voice: true,
        text: action.kind === "timeout",
        durationSecs,
        reason,
      });
    }
  } catch (e) {
    addNotification(`Admin action failed: ${e}`, "error");
  }
}

/** Ends a moderator's mute or timeout. The wait for new members stays. */
export async function liftRestriction(targetUserId: number): Promise<void> {
  try {
    await invoke("admin_restrict", {
      server: get(serverAddress),
      userId: targetUserId,
      voice: false,
      text: false,
      durationSecs: 0,
      reason: "",
    });
  } catch (e) {
    addNotification(`Admin action failed: ${e}`, "error");
  }
}
