// Notification cues for the web client. The desktop app plays user-chosen
// files; a browser has no file access and ships no assets, so the cues are
// short synthesised tones: one pitch pattern per event, ~120 ms each note.

import type { SoundSettings } from "../../lib/stores/settings";

/** [frequency Hz, onset ms] per note. */
const CUES: Record<string, [number, number][]> = {
  channel_switch: [[660, 0], [880, 90]],
  user_joined: [[523, 0], [784, 110]],
  user_left: [[784, 0], [523, 110]],
  disconnected: [[440, 0], [330, 140], [220, 280]],
  direct_message: [[880, 0], [1175, 80]],
  channel_message: [[988, 0]],
  poke: [[1047, 0], [1047, 140], [1319, 280]],
};

let ctx: AudioContext | null = null;
let gestureArmed = false;

/** Autoplay policy: a context created without a gesture stays suspended
 *  until the first click/key. */
function armResumeOnGesture(ac: AudioContext): void {
  if (gestureArmed) return;
  gestureArmed = true;
  const handler = () => {
    window.removeEventListener("pointerdown", handler, true);
    window.removeEventListener("keydown", handler, true);
    gestureArmed = false;
    ac.resume().catch(() => {});
  };
  window.addEventListener("pointerdown", handler, true);
  window.addEventListener("keydown", handler, true);
}

/**
 * Play the cue for `name`. With `sounds` given, a disabled event stays silent
 * (play_notification_sound); pass null to preview regardless.
 */
export function playCue(name: string, sounds: SoundSettings | null): void {
  const cue = CUES[name];
  if (!cue) throw `Unknown sound event: ${name}`;
  if (sounds && !sounds[name as keyof SoundSettings]?.enabled) return;
  if (typeof AudioContext === "undefined") return;
  try {
    ctx ??= new AudioContext();
    if (ctx.state !== "running") {
      ctx.resume().catch(() => {});
      armResumeOnGesture(ctx);
    }
    const t0 = ctx.currentTime;
    for (const [freq, at] of cue) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = freq;
      const start = t0 + at / 1000;
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(0.18, start + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.12);
      osc.connect(gain).connect(ctx.destination);
      osc.start(start);
      osc.stop(start + 0.13);
    }
  } catch (e) {
    console.warn("sound cue failed:", e);
  }
}
