import { invoke } from "@tauri-apps/api/core";

/** Play a notification sound by event name. The backend checks enabled/path. */
function playSound(name: string) {
  invoke("play_notification_sound", { name }).catch(() => {});
}

export function playChannelSwitchSound() { playSound("channel_switch"); }
export function playUserJoinedSound() { playSound("user_joined"); }
export function playUserLeftSound() { playSound("user_left"); }
export function playDisconnectedSound() { playSound("disconnected"); }
export function playDirectMessageSound() { playSound("direct_message"); }
export function playChannelMessageSound() { playSound("channel_message"); }
export function playPokeSound() { playSound("poke"); }
