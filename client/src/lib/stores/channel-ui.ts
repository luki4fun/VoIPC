// Creating, joining and configuring a channel: the state behind the sidebar's
// forms and dialogs, and every command they send.
//
// Lifted out of ChannelList when a second sidebar appeared. The rows differ
// between layouts — the classic list previews on a click and joins on a double
// click, Discord's joins on the first — but everything under them is the same
// three dialogs and the same five commands, and a second copy of the channel
// settings dialog is a second place for the options to drift out of order.
//
// The markup is ChannelDialogs.svelte (the overlays, mounted once by App.svelte)
// and ChannelCreateForm.svelte (inline, because it belongs in the sidebar it
// was opened from).

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { channels, currentChannelId, previewChannelId, previewUsers } from "./channels.js";
import { channelPasswords, isAdmin, serverAddress, userId } from "./connection.js";
import { activeDmUserId, clearChannelUnread, closeDm } from "./chat.js";
import { addNotification } from "./notifications.js";
import { buildInviteLink, splitAddress } from "../invite.js";
import type { ProximityMode } from "../spatial.js";
import type { ChannelInfo } from "../types.js";

// ── Create ─────────────────────────────────────────────────────────────────

export const showCreateForm = writable(false);
export const newChannelName = writable("");
export const newChannelPassword = writable("");
export const newChannelProximity = writable<ProximityMode>("off");
export const newChannelAnonymous = writable(false);

function resetCreateForm(): void {
  newChannelName.set("");
  newChannelPassword.set("");
  newChannelProximity.set("off");
  newChannelAnonymous.set(false);
  showCreateForm.set(false);
}

export const cancelCreate = resetCreateForm;

export async function createChannel(): Promise<void> {
  const name = get(newChannelName).trim();
  if (!name) return;
  const password = get(newChannelPassword);
  try {
    await invoke("create_channel", {
      name,
      password: password || null,
      proximity: get(newChannelProximity),
      anonymous: get(newChannelAnonymous),
    });
    if (password) channelPasswords.update((m) => new Map(m).set(name, password));
    resetCreateForm();
  } catch (e) {
    console.error("Failed to create channel:", e);
    addNotification(`Failed to create channel: ${e}`, "error");
  }
}

// ── Preview and join ───────────────────────────────────────────────────────

/**
 * Show who is in a channel without joining it.
 *
 * Puts a `request_channel_users` on the wire every time, so anything that calls
 * it on hover has to debounce — otherwise a pointer crossing the sidebar sends
 * one request per row on the way past.
 */
export function previewChannel(channelId: number): void {
  // Always exit DM mode when picking a channel
  if (get(activeDmUserId) !== null) closeDm();

  if (channelId === get(currentChannelId)) {
    // Picking our own channel clears the preview and shows its chat
    previewChannelId.set(null);
    previewUsers.set([]);
    return;
  }
  previewChannelId.set(channelId);
  const name = get(channels).find((c) => c.channel_id === channelId)?.name;
  if (name) clearChannelUnread(name);
  invoke("request_channel_users", { channelId }).catch((e: unknown) =>
    console.error("Failed to request channel users:", e),
  );
}

/**
 * Join a channel, or ask for its password first.
 *
 * The password branch is why both layouts call this rather than `join_channel`:
 * the Discord sidebar joins on a single click, and without it that click would
 * fire a join the server refuses.
 */
export async function joinChannel(channelId: number, hasPassword: boolean): Promise<void> {
  if (hasPassword && channelId !== get(currentChannelId)) {
    passwordPromptChannelId.set(channelId);
    passwordPromptInput.set("");
    return;
  }
  try {
    await invoke("join_channel", { channelId, password: null });
  } catch (e) {
    console.error("Failed to join channel:", e);
    addNotification(`Failed to join channel: ${e}`, "error");
  }
}

// ── Password prompt (joining) ──────────────────────────────────────────────

export const passwordPromptChannelId = writable<number | null>(null);
export const passwordPromptInput = writable("");

export function cancelPasswordPrompt(): void {
  passwordPromptChannelId.set(null);
  passwordPromptInput.set("");
}

export async function submitPasswordJoin(): Promise<void> {
  const channelId = get(passwordPromptChannelId);
  if (channelId === null) return;
  const password = get(passwordPromptInput);
  try {
    await invoke("join_channel", { channelId, password: password || null });
    const name = get(channels).find((c) => c.channel_id === channelId)?.name;
    if (name && password) channelPasswords.update((m) => new Map(m).set(name, password));
    cancelPasswordPrompt();
  } catch (e) {
    console.error("Failed to join channel:", e);
    addNotification(`Failed to join channel: ${e}`, "error");
  }
}

// ── Invite link ────────────────────────────────────────────────────────────

/** Shown for manual copying when the clipboard is blocked. */
export const inviteLinkPopup = writable<string | null>(null);

export async function copyInviteLink(): Promise<void> {
  const channel = get(channels).find((c) => c.channel_id === get(currentChannelId));
  if (!channel || channel.channel_id === 0) return;
  const { host, port } = splitAddress(get(serverAddress));
  // The password rides along only when this session knows it — it created the
  // channel, or joined with it.
  const password = channel.has_password ? (get(channelPasswords).get(channel.name) ?? null) : null;
  const link = buildInviteLink(host, port, channel.name, password);
  if (channel.has_password && !password) {
    addNotification(
      "This session does not know the channel password — the link will ask the joiner for it",
      "warning",
    );
  }
  try {
    await navigator.clipboard.writeText(link);
    addNotification("Invite link copied", "info", 2500);
  } catch {
    inviteLinkPopup.set(link);
  }
}

// ── Channel settings ───────────────────────────────────────────────────────
//
// The server lets the creator, or any admin, change these. Channels that came
// from channels.json have no creator, so those are admin-only.

export const passwordEditChannelId = writable<number | null>(null);
export const passwordEditInput = writable("");
/** Does the edited channel have a password right now? */
export const passwordEditHasPassword = writable(false);
/** Explicit "remove the password"; an empty field alone means "leave it". */
export const passwordEditRemove = writable(false);
export const settingsProximity = writable<ProximityMode>("off");
export const settingsHidden = writable(false);
export const settingsAnonymous = writable(false);
export const settingsScreenShare = writable(true);
export const settingsHideMembers = writable(false);
export const settingsRouted = writable(false);

/** The channel as it was when the dialog opened, so only changes are sent. */
let settingsBefore: ChannelInfo | null = null;

export function canEditChannel(channel: {
  channel_id: number;
  created_by: number | null;
}): boolean {
  return channel.channel_id !== 0 && (channel.created_by === get(userId) || get(isAdmin));
}

export function openChannelSettings(channelId: number, e?: Event): void {
  e?.stopPropagation();
  const channel = get(channels).find((c) => c.channel_id === channelId);
  passwordEditChannelId.set(channelId);
  // Leave the input empty — an empty field keeps the current password
  passwordEditInput.set("");
  passwordEditRemove.set(false);
  passwordEditHasPassword.set(channel?.has_password ?? false);
  settingsProximity.set(channel?.proximity ?? "off");
  settingsHidden.set(channel?.hidden ?? false);
  settingsAnonymous.set(channel?.anonymous ?? false);
  settingsScreenShare.set(channel?.screen_share ?? true);
  settingsHideMembers.set(channel?.hide_members ?? false);
  settingsRouted.set(channel?.routed ?? false);
  settingsBefore = channel ?? null;
}

export function cancelChannelSettings(): void {
  passwordEditChannelId.set(null);
  passwordEditInput.set("");
  passwordEditRemove.set(false);
}

export async function submitChannelSettings(): Promise<void> {
  const channelId = get(passwordEditChannelId);
  if (channelId === null) return;
  const before = get(channels).find((c) => c.channel_id === channelId)?.proximity ?? "off";
  const remove = get(passwordEditRemove);
  const password = get(passwordEditInput);
  const proximity = get(settingsProximity);
  try {
    // Only touch the password when the user actually asked to: saving this
    // dialog to change the proximity mode must not drop it
    if (remove || password) {
      await invoke("set_channel_password", { channelId, password: remove ? null : password });
      const name = get(channels).find((c) => c.channel_id === channelId)?.name;
      if (name) {
        channelPasswords.update((m) => {
          const next = new Map(m);
          if (remove) next.delete(name);
          else next.set(name, password);
          return next;
        });
      }
    }
    if (proximity !== before) {
      await invoke("set_channel_proximity", { channelId, proximity });
    }
    // Only what actually changed; null leaves an option alone
    const was = settingsBefore;
    const now = {
      hidden: get(settingsHidden),
      anonymous: get(settingsAnonymous),
      screenShare: get(settingsScreenShare),
      hideMembers: get(settingsHideMembers),
      routed: get(settingsRouted),
    };
    const changed = <T>(value: T, then: T | undefined) => (value === then ? null : value);
    if (
      was &&
      (now.hidden !== was.hidden ||
        now.anonymous !== was.anonymous ||
        now.screenShare !== was.screen_share ||
        now.hideMembers !== was.hide_members ||
        now.routed !== was.routed)
    ) {
      await invoke("set_channel_options", {
        channelId,
        hidden: changed(now.hidden, was.hidden),
        anonymous: changed(now.anonymous, was.anonymous),
        screenShare: changed(now.screenShare, was.screen_share),
        hideMembers: changed(now.hideMembers, was.hide_members),
        routed: changed(now.routed, was.routed),
      });
    }
    cancelChannelSettings();
  } catch (e) {
    console.error("Failed to change channel settings:", e);
    addNotification(`Failed to change channel settings: ${e}`, "error");
  }
}
