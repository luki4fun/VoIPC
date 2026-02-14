import { writable } from "svelte/store";

export type VoiceMode = "ptt" | "vad" | "always_on";

/** Current voice activation mode. */
export const voiceMode = writable<VoiceMode>("ptt");

/** VAD threshold in dB (typically -60 to 0). */
export const vadThreshold = writable<number>(-40);

/** Current audio input level in dB. Updated periodically from backend. */
export const audioLevel = writable<number>(-96);
