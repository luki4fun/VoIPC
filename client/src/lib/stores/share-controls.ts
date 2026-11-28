// Whether this device may start or stop a share of its own, and the two actions: one answer
// for the voice bar (ScreenShareControls) and the stream view's header (StreamStage), which
// covers the voice bar in a narrow window (1.13, D9).

import { invoke } from "@tauri-apps/api/core";
import { derived } from "svelte/store";
import { voice, voiceChannel } from "./channels.js";
import { voiceListenOnly } from "./channel-ui.js";
import { voiceRestriction } from "./restrictions.js";
import { isSharingScreen, pickerSwitchMode, showSourcePicker, viewerCount } from "./screenshare.js";
import { addNotification } from "./notifications.js";
import { isWeb } from "./platform.js";

/** The browser shares through WebCodecs + getDisplayMedia; a browser without them (or a
 *  mobile one) keeps the controls hidden. */
export const canShare: boolean =
  !isWeb ||
  (typeof VideoEncoder !== "undefined" &&
    typeof VideoFrame !== "undefined" &&
    typeof navigator !== "undefined" &&
    !!navigator.mediaDevices?.getDisplayMedia);

/**
 * Whether the share controls show: in a voice channel (a share goes to the one we are in, on
 * whichever server that is) that lets us share. A channel can switch sharing off, its gate
 * can leave us listening only, and a moderator or the wait can hold our voice (the server
 * refuses them all too). Switching sharing off mid-share must not strand the sharer, so the
 * controls (Stop) stay while they still send.
 */
export const shareControlsShown = derived(
  [voice, voiceChannel, voiceListenOnly, voiceRestriction, isSharingScreen],
  ([$voice, $channel, $listenOnly, $restriction, $sharing]) => {
    if ($voice === null || !canShare) return false;
    const off =
      $channel?.screen_share === false ||
      (!!$channel && $listenOnly.has($channel.channel_id)) ||
      !!$restriction?.voice;
    return !off || $sharing;
  },
);

/** The source picker, for a new share. */
export function openSharePicker(): void {
  pickerSwitchMode.set(false);
  showSourcePicker.set(true);
}

export async function stopSharing(): Promise<void> {
  try {
    await invoke("stop_screen_share");
    isSharingScreen.set(false);
    viewerCount.set(0);
  } catch (e: any) {
    addNotification(e.toString(), "error");
  }
}
