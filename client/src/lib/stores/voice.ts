import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { currentChannelId } from "./channels.js";
import { isTransmitting, setSelfDeafened, setSelfMuted } from "./connection.js";
import { noiseSuppression } from "./settings.js";

export type VoiceMode = "ptt" | "vad" | "always_on";

/** Current voice activation mode. */
export const voiceMode = writable<VoiceMode>("ptt");

/** VAD threshold in dB (typically -60 to 0). */
export const vadThreshold = writable<number>(-40);

/** Current audio input level in dB. Updated periodically from backend. */
export const audioLevel = writable<number>(-96);

/** Whether speakerphone is enabled (Android only). Defaults to true. */
export const speakerMode = writable<boolean>(true);

// ── Actions ────────────────────────────────────────────────────────────────
//
// Opening the microphone, muting and deafening, from one place.
//
// These lived in VoiceControls until a second layout needed them: its voice
// buttons are in a user panel in the corner, and there is no bar. Copying the
// four functions into it would have been two writers for the same four pieces
// of state, which is the bug class the mixer had — so they moved here instead,
// the way stores/mixer.ts is the single writer for volume and effects.
//
// Everything that opens a microphone now goes through here: the voice bar, the
// phone's push-to-talk button, the window key handlers in VoiceKeys.svelte, the
// tray menu and the OS-wide hotkeys.

/** Voice is off in the General lobby, so nothing may open the microphone there. */
function voiceDisabled(): boolean {
  return get(currentChannelId) === 0;
}

export async function startTransmit(): Promise<void> {
  if (voiceDisabled()) return;
  try {
    await invoke("start_transmit");
    isTransmitting.set(true);
  } catch (e) {
    console.error("Failed to start transmit:", e);
  }
}

export async function stopTransmit(): Promise<void> {
  if (!get(isTransmitting)) return;
  try {
    await invoke("stop_transmit");
    isTransmitting.set(false);
  } catch (e) {
    console.error("Failed to stop transmit:", e);
  }
}

export async function toggleMute(): Promise<void> {
  try {
    // setSelfMuted, not isMuted.set: the server deliberately skips echoing a
    // mute back to the session that caused it, so our own row in the member
    // list has to be patched here or it stays stale until the next UserList.
    setSelfMuted(await invoke<boolean>("toggle_mute"));
  } catch (e) {
    console.error("Failed to toggle mute:", e);
  }
}

export async function toggleDeafen(): Promise<void> {
  try {
    setSelfDeafened(await invoke<boolean>("toggle_deafen"));
  } catch (e) {
    console.error("Failed to toggle deafen:", e);
  }
}

export async function toggleNoiseSuppression(): Promise<void> {
  try {
    noiseSuppression.set(await invoke<boolean>("toggle_noise_suppression"));
  } catch (e) {
    console.error("Failed to toggle noise suppression:", e);
  }
}

/** Android only: route playback to the loudspeaker instead of the earpiece. */
export function toggleSpeaker(): void {
  const next = !get(speakerMode);
  try {
    (window as any).__VoIPC?.setSpeakerphone(next);
    speakerMode.set(next);
  } catch (e) {
    console.error("Failed to toggle speaker:", e);
  }
}

export async function setVoiceMode(mode: VoiceMode): Promise<void> {
  voiceMode.set(mode);
  try {
    await invoke("set_voice_mode", { mode });
  } catch (e) {
    console.error("Failed to set voice mode:", e);
  }
  // Reset transmit state on a mode change: if the key was held across the
  // switch its release event never arrives, because the handler it would have
  // reached is no longer registered.
  await stopTransmit();
}
