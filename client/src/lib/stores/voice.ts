import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { voice, voiceServer } from "./channels.js";
import { isMuted, isTransmitting, setSelfDeafened, setSelfMuted } from "./connection.js";
import { clearMixer } from "./mixer.js";
import { addNotification } from "./notifications.js";
import { resetRoom } from "./room.js";
import { resetScreenShareState } from "./screenshare.js";
import { noiseSuppression } from "./settings.js";
import { speakingUsers } from "./users.js";
import { transmitOrder } from "../transmit-order.js";

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

/** In no voice channel on any server, nothing may open the microphone. */
function voiceDisabled(): boolean {
  return get(voice) === null;
}

/**
 * Leave the voice channel and stay on the server: the lobby, channel 0, is
 * where the server keeps everyone who is in no voice channel.
 *
 * The one writer of that join. Every "leave voice" there is — the voice panel,
 * the classic voice bar, the phone's call notification — comes here, so none
 * of them can forget the guard: joining the lobby from the lobby is not a
 * no-op on the server, which announces a leave and a join again and spends a
 * join token on it.
 */
export async function leaveVoice(): Promise<void> {
  const seat = get(voice);
  if (!seat) return;
  try {
    await invoke("join_channel", { server: seat.server, channelId: 0, password: null });
  } catch (e) {
    addNotification(`Could not leave the voice channel: ${e}`, "error");
  }
}

// Everything that belongs to the call rather than to a server goes when the
// call ends or moves to another server: the room, the mixer's lanes (keyed by
// that server's user ids), the screen shares, who is speaking. The microphone
// too — the backend stopped the capture, and `isTransmitting` going false is
// also what lets VoiceKeys re-open it on the new server in voice-activation
// or always-open mode. Recent speakers are roster.ts's, on the same store.
let lastVoiceServer: string | null = null;
voiceServer.subscribe((server) => {
  if (server === lastVoiceServer) return;
  lastVoiceServer = server;
  isTransmitting.set(false);
  resetRoom();
  clearMixer();
  resetScreenShareState();
  speakingUsers.set(new Set());
});

// Opens and closes in the order asked (see transmit-order.ts): a key released
// while the device is still opening closes it once it is open.
const transmit = transmitOrder(
  async () => {
    try {
      await invoke("start_transmit");
      isTransmitting.set(true);
    } catch (e) {
      console.error("Failed to start transmit:", e);
    }
  },
  async () => {
    if (!get(isTransmitting)) return;
    try {
      await invoke("stop_transmit");
      isTransmitting.set(false);
    } catch (e) {
      console.error("Failed to stop transmit:", e);
    }
  },
);

export async function startTransmit(): Promise<void> {
  // Muted, both backends treat a start as done without opening anything, and
  // `isTransmitting` would then claim a microphone nobody opened — so voice
  // activation, which waits for it to go false, never opened it after unmute
  if (voiceDisabled() || get(isMuted)) return;
  return transmit.start();
}

export function stopTransmit(): Promise<void> {
  return transmit.stop();
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
