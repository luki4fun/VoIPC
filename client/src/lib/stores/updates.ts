// The desktop auto-updater's state on this side (1.0, B6). The backend
// (updater.rs) chooses the feed, checks the signature and installs; this only
// asks it, and only in the NSIS and AppImage builds that update themselves.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import { isWeb } from "./platform.js";
import { flushChatSave } from "./chat.js";
import type { UpdateInfo } from "../update-rules.js";

/** This build installs its own updates (else: the download page). */
export const updatesSupported = writable(false);
/** The "Check for updates" setting (default on). */
export const checkUpdates = writable(true);
/** What the last check found. */
export const availableUpdate = writable<UpdateInfo | null>(null);
/** What the updater is doing now. */
export const updateBusy = writable<"checking" | "installing" | null>(null);

/** Read what the backend knows; the app calls this once at start. */
export async function initUpdates(): Promise<void> {
  if (isWeb) return;
  try {
    updatesSupported.set(await invoke<boolean>("updates_supported"));
    const config = await invoke<{ check_updates?: boolean }>("load_config");
    checkUpdates.set(config.check_updates !== false);
    availableUpdate.set(await invoke<UpdateInfo | null>("pending_update"));
  } catch {
    updatesSupported.set(false);
  }
}

/** Look at the feed now. Nothing when this build cannot update itself or
 *  checking is switched off. */
export async function checkForUpdate(): Promise<UpdateInfo | null> {
  if (!get(updatesSupported) || !get(checkUpdates) || get(updateBusy)) return get(availableUpdate);
  updateBusy.set("checking");
  try {
    const found = await invoke<UpdateInfo | null>("check_for_update");
    availableUpdate.set(found);
    return found;
  } catch {
    return get(availableUpdate);
  } finally {
    updateBusy.set(null);
  }
}

/** Download, verify and install, then restart. Resolves only on failure,
 *  with what went wrong (the backend refuses during a call). */
export async function installUpdate(): Promise<string> {
  updateBusy.set("installing");
  try {
    await flushChatSave();
    await invoke("install_update");
    return "";
  } catch (e) {
    return String(e);
  } finally {
    updateBusy.set(null);
  }
}

export async function setCheckUpdates(enabled: boolean): Promise<void> {
  checkUpdates.set(enabled);
  if (enabled) updateBusy.set("checking");
  try {
    await invoke("set_check_updates", { enabled });
    if (enabled) availableUpdate.set(await invoke<UpdateInfo | null>("pending_update"));
  } finally {
    updateBusy.set(null);
  }
}
