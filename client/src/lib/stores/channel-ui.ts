// Creating, joining and configuring a channel: the state behind the sidebar's
// forms and dialogs, and every command they send.
//
// Lifted out of ChannelList when a second sidebar appeared. The rows differ
// between layouts — the classic list previews on a click and joins on a double
// click, the modern one joins on the first — but everything under them is the same
// three dialogs and the same five commands, and a second copy of the channel
// settings dialog is a second place for the options to drift out of order.
//
// The markup is ChannelDialogs.svelte (the overlays, mounted once by App.svelte)
// and ChannelCreateForm.svelte (inline, because it belongs in the sidebar it
// was opened from).

import { derived, get, writable, type Readable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { channels, currentChannelId, previewChannelId, previewUsers } from "./channels.js";
import {
  channelPassword,
  forgetChannelPassword,
  isAdmin,
  rememberChannelPassword,
  serverAddress,
  serverKey,
  userId,
} from "./connection.js";
import {
  activeDmUserId,
  activeTextChannelId,
  clearChannelUnread,
  closeDm,
  joinedTextChannelIds,
  openTextChannel,
} from "./chat.js";
import { addNotification } from "./notifications.js";
import { showChatPane } from "./platform.js";
import { updateUiPrefs, uiPrefs } from "./ui-prefs.js";
import { buildInviteLink, splitAddress } from "../invite.js";
import type { ProximityMode } from "../spatial.js";
import type { ChannelInfo } from "../types.js";

// ── Create ─────────────────────────────────────────────────────────────────

export const showCreateForm = writable(false);
export const newChannelName = writable("");
export const newChannelPassword = writable("");
export const newChannelProximity = writable<ProximityMode>("off");
export const newChannelAnonymous = writable(false);
/** A text channel rather than a voice room. */
export const newChannelText = writable(false);

function resetCreateForm(): void {
  newChannelName.set("");
  newChannelPassword.set("");
  newChannelProximity.set("off");
  newChannelAnonymous.set(false);
  newChannelText.set(false);
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
      text: get(newChannelText),
    });
    if (password) rememberChannelPassword(name, password);
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
 * the modern sidebar joins on a single click, and without it that click would
 * fire a join the server refuses.
 */
export async function joinChannel(channelId: number, hasPassword: boolean): Promise<boolean> {
  const alreadyIn =
    channelId === get(currentChannelId) || get(joinedTextChannelIds).has(channelId);
  if (hasPassword && !alreadyIn) {
    passwordPromptChannelId.set(channelId);
    passwordPromptInput.set("");
    // Asked, not joined: the caller must not act as though we were in it
    return false;
  }
  try {
    await invoke("join_channel", { channelId, password: null });
    // Asking to be in a text channel undoes having walked out of it. Only a
    // text channel: the list is of names, and a voice room may share one.
    if (isTextChannel(channelId)) forgetLeft(channelId);
    return true;
  } catch (e) {
    console.error("Failed to join channel:", e);
    addNotification(`Failed to join channel: ${e}`, "error");
    return false;
  }
}

// ── Text channels ──────────────────────────────────────────────────────────
//
// A text channel is a subscription: joining one does not cost you the voice
// channel you stand in, and several can be open at once. That is why leaving
// needs its own command — `join_channel(0)`, which is how you leave a voice
// channel, means "stand in the lobby" and says nothing about a subscription.

/**
 * One click on a channel row, in either sidebar.
 *
 * A click looks; it never enters. A text channel we are in opens its chat, one
 * we are not in is previewed read-only with the pane's own button as the way
 * in, and a voice channel is previewed — its members and its recent chat,
 * without moving. **Entering a voice channel is a double click** (`joinChannel`,
 * wired to `ondblclick` by both sidebars), because joining announces you to
 * everybody there, takes your voice with you, and undoes having walked out of a
 * text channel — too much to happen by brushing a row on the way past.
 *
 * Clicking the voice channel you are already in is how you ask for its chat.
 */
export async function selectChannel(channel: ChannelInfo): Promise<void> {
  if (channel.text) {
    if (!get(joinedTextChannelIds).has(channel.channel_id)) {
      previewChannel(channel.channel_id);
      showChatPane();
      return;
    }
    openTextChannel(channel.channel_id);
    clearChannelUnread(channel.name);
    // On a phone the channel list is a tab of its own in one layout and a
    // drawer over the chat in the other: picking a channel to read has to show
    // the chat in both, or the tap looks like it did nothing.
    showChatPane();
    return;
  }
  if (channel.channel_id === get(currentChannelId)) {
    // Back to where we stand, from whatever we were reading: the pane and the
    // member list both follow the preview, so clicking our own channel has to
    // clear it or there is no way back to our own members.
    previewChannelId.set(null);
    previewUsers.set([]);
    openTextChannel(null);
    showChatPane();
    return;
  }
  previewChannel(channel.channel_id);
  showChatPane();
}

/**
 * Enter a text channel: the deliberate step a click no longer takes.
 *
 * The button in the chat pane is the only way here, so re-entering a channel
 * the user walked out of is something they asked for by name.
 */
export async function joinTextChannel(channel: ChannelInfo): Promise<void> {
  // A password prompt opens instead of a join; the pane follows once the
  // password goes through, not while the dialog is still up.
  if (!(await joinChannel(channel.channel_id, channel.has_password))) return;
  openJoinedTextChannel(channel.channel_id, channel.name);
}

/** Show a text channel we have just entered, and drop the preview of it. */
function openJoinedTextChannel(channelId: number, name: string): void {
  previewChannelId.set(null);
  previewUsers.set([]);
  openTextChannel(channelId);
  clearChannelUnread(name);
  showChatPane();
}

/** Walk out of a text channel, and remember it for the next connect. */
export async function leaveTextChannel(channelId: number): Promise<void> {
  const name = channelName(channelId);
  try {
    await invoke("leave_channel", { channelId });
    rememberLeft(channelId);
    // Stay on the channel rather than dropping the user somewhere else: the
    // pane turns read-only and offers the way back in, which is what tells
    // them the leave went through.
    if (get(activeTextChannelId) === channelId) {
      openTextChannel(null);
      previewChannel(channelId);
    }
    addNotification(`Left #${name ?? channelId} — click it to read, rejoin to write`, "info", 4000);
  } catch (e) {
    console.error("Failed to leave channel:", e);
    addNotification(`Failed to leave channel: ${e}`, "error");
  }
}

/**
 * The auto-joins already asked for on this connection.
 *
 * The caller is an effect over the channel list, and the list is rewritten
 * every time a roster reply reconciles a member count — so on connect it
 * re-fires once per reply, while `joinedTextChannelIds` is still empty because
 * the server has not answered the first join yet. Every auto-join channel is
 * then asked for again on every pass: twenty redundant joins out of a budget of
 * fifty a second, each one a global broadcast on the server.
 */
const autoJoinAsked = new Set<number>();

/** A connection's auto-joins die with it. */
export function clearAutoJoined(): void {
  autoJoinAsked.clear();
}

/**
 * Join the text channels this server asks every client into.
 *
 * Skipped for one the user left, and for a password-protected one — we hold no
 * password to offer, and a prompt nobody asked for on every connect is worse
 * than joining it by hand.
 */
export function autoJoinTextChannels(list: ChannelInfo[]): void {
  const joined = get(joinedTextChannelIds);
  for (const channel of list) {
    if (!channel.text || !channel.auto_join) continue;
    if (channel.has_password || joined.has(channel.channel_id)) continue;
    if (autoJoinAsked.has(channel.channel_id) || isLeft(channel.name)) continue;
    autoJoinAsked.add(channel.channel_id);
    invoke("join_channel", { channelId: channel.channel_id, password: null }).catch(
      (e: unknown) => {
        // Put it back, so the next pass tries again: re-firing was also the
        // safety net for a join sent a moment too early, and only the ones
        // that went through should stop it.
        autoJoinAsked.delete(channel.channel_id);
        console.error("Failed to auto-join text channel:", e);
      },
    );
  }
}

// ── The list of text channels this user walked out of ──────────────────────
//
// Kept per server, by name: a user-created channel's id is not stable across a
// restart, and two servers' `#general` are not the same room.

/**
 * The names on this server's list, for the sidebars to draw the difference
 * between a channel nobody ever joined and one this user walked out of.
 */
export const leftTextChannelNames: Readable<Set<string>> = derived(
  [uiPrefs, serverAddress],
  ([$prefs, $address]) => {
    const { host, port } = splitAddress($address);
    return new Set($address ? ($prefs.left_text_channels[`${host}:${port}`] ?? []) : []);
  },
);

export function isLeft(channelName: string): boolean {
  return get(leftTextChannelNames).has(channelName);
}

// ── Destruction timers ─────────────────────────────────────────────────────

/**
 * A channel's destruction timer in seconds, as the server advertises it;
 * 0 is off.
 *
 * Read fresh rather than remembered: it is the channel's answer, the server
 * announces every change of it, and a message takes the one in force when it
 * arrives.
 */
export function channelMessageTtl(channelId: number): number {
  return get(channels).find((c) => c.channel_id === channelId)?.message_ttl_secs ?? 0;
}

/** The timer this user set for their messages to one person; 0 is off. */
export function dmMessageTtl(peerName: string): number {
  const key = serverKey();
  if (!key) return 0;
  return get(uiPrefs).dm_timers[`${key}/${peerName}`] ?? 0;
}

/** Set, or with 0 clear, the timer for messages written to one person. */
export function setDmMessageTtl(peerName: string, secs: number): void {
  const key = serverKey();
  if (!key) return;
  updateUiPrefs((p) => {
    if (secs > 0) p.dm_timers[`${key}/${peerName}`] = secs;
    else delete p.dm_timers[`${key}/${peerName}`];
  });
}

function channelName(channelId: number): string | undefined {
  return get(channels).find((c) => c.channel_id === channelId)?.name;
}

/** Whether an id names a text channel, per the list the server sent. */
export function isTextChannel(channelId: number): boolean {
  return get(channels).some((c) => c.channel_id === channelId && c.text);
}

function rememberLeft(channelId: number): void {
  const key = serverKey();
  const name = channelName(channelId);
  if (!key || !name) return;
  updateUiPrefs((p) => {
    const list = p.left_text_channels[key] ?? [];
    if (!list.includes(name)) p.left_text_channels[key] = [...list, name];
  });
}

function forgetLeft(channelId: number): void {
  const key = serverKey();
  const name = channelName(channelId);
  if (!key || !name) return;
  updateUiPrefs((p) => {
    const list = p.left_text_channels[key];
    if (!list?.includes(name)) return;
    const next = list.filter((n) => n !== name);
    if (next.length > 0) p.left_text_channels[key] = next;
    else delete p.left_text_channels[key];
  });
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
    const channel = get(channels).find((c) => c.channel_id === channelId);
    if (channel && password) rememberChannelPassword(channel.name, password);
    if (channel?.text) forgetLeft(channelId);
    cancelPasswordPrompt();
    // A text channel was picked to be read: show it, now that we are in it
    if (channel?.text) openJoinedTextChannel(channelId, channel.name);
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
  const password = channel.has_password ? channelPassword(channel.name) : null;
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
/** Seconds a message written here lives; 0 is no timer. */
export const settingsMessageTtl = writable(0);
/** The edited channel is a text channel: the voice options do not apply. */
export const settingsIsText = writable(false);

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
  settingsMessageTtl.set(channel?.message_ttl_secs ?? 0);
  settingsIsText.set(channel?.text ?? false);
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
        if (remove) forgetChannelPassword(name);
        else rememberChannelPassword(name, password);
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
      messageTtlSecs: get(settingsMessageTtl),
    };
    const changed = <T>(value: T, then: T | undefined) => (value === then ? null : value);
    if (
      was &&
      (now.hidden !== was.hidden ||
        now.anonymous !== was.anonymous ||
        now.screenShare !== was.screen_share ||
        now.hideMembers !== was.hide_members ||
        now.routed !== was.routed ||
        now.messageTtlSecs !== was.message_ttl_secs)
    ) {
      await invoke("set_channel_options", {
        channelId,
        hidden: changed(now.hidden, was.hidden),
        anonymous: changed(now.anonymous, was.anonymous),
        screenShare: changed(now.screenShare, was.screen_share),
        hideMembers: changed(now.hideMembers, was.hide_members),
        routed: changed(now.routed, was.routed),
        messageTtlSecs: changed(now.messageTtlSecs, was.message_ttl_secs),
      });
    }
    cancelChannelSettings();
  } catch (e) {
    console.error("Failed to change channel settings:", e);
    addNotification(`Failed to change channel settings: ${e}`, "error");
  }
}
