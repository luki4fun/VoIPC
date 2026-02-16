import { writable } from "svelte/store";

export const inputDevice = writable<string>("");
export const outputDevice = writable<string>("");
export const volume = writable<number>(1.0);
export const pttKey = writable<string>("Space");
export const pttHoldMode = writable<boolean>(true);
export const noiseSuppression = writable<boolean>(true);

// Connection persistence
export const rememberConnection = writable<boolean>(false);
export const lastHost = writable<string>("localhost");
export const lastPort = writable<number>(9987);
export const lastUsername = writable<string>("");
export const lastAcceptSelfSigned = writable<boolean>(false);

// QoL
export const autoConnect = writable<boolean>(false);

// Sound settings
export interface SoundEntry {
  enabled: boolean;
  path: string | null;
}

export interface SoundSettings {
  channel_switch: SoundEntry;
  user_joined: SoundEntry;
  user_left: SoundEntry;
  disconnected: SoundEntry;
  direct_message: SoundEntry;
  channel_message: SoundEntry;
  poke: SoundEntry;
}

export function defaultSoundSettings(): SoundSettings {
  return {
    channel_switch: { enabled: true, path: null },
    user_joined: { enabled: true, path: null },
    user_left: { enabled: true, path: null },
    disconnected: { enabled: true, path: null },
    direct_message: { enabled: true, path: null },
    channel_message: { enabled: true, path: null },
    poke: { enabled: true, path: null },
  };
}

export const soundSettings = writable<SoundSettings>(defaultSoundSettings());

export interface AppConfig {
  input_device: string | null;
  output_device: string | null;
  volume: number;
  noise_suppression: boolean;
  voice_mode: string;
  vad_threshold_db: number;
  ptt_key: string;
  ptt_hold_mode: boolean;
  muted: boolean;
  deafened: boolean;
  remember_connection: boolean;
  last_host: string | null;
  last_port: number | null;
  last_username: string | null;
  last_accept_self_signed: boolean | null;
  sounds: SoundSettings;
  auto_connect: boolean;
  chat_history_path: string | null;
}
