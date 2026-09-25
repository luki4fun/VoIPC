import { invoke } from "@tauri-apps/api/core";

/** When each cue last played (performance.now()). */
const lastPlayed = new Map<string, number>();

/**
 * Play a notification sound by event name. The backend checks enabled/path.
 *
 * At most once a second per cue: every chat message, DM and poke asks for
 * one, and the desktop backend opens a fresh output stream on the call's own
 * device for each — a peer posting at the relay's 50 messages a second would
 * otherwise have fifty of them open at once.
 */
function playSound(name: string) {
  const now = performance.now();
  if (now - (lastPlayed.get(name) ?? -Infinity) < 1000) return;
  lastPlayed.set(name, now);
  invoke("play_notification_sound", { name }).catch(() => {});
}

export function playChannelSwitchSound() { playSound("channel_switch"); }
export function playUserJoinedSound() { playSound("user_joined"); }
export function playUserLeftSound() { playSound("user_left"); }
export function playDisconnectedSound() { playSound("disconnected"); }
export function playDirectMessageSound() { playSound("direct_message"); }
export function playChannelMessageSound() { playSound("channel_message"); }
export function playPokeSound() { playSound("poke"); }
