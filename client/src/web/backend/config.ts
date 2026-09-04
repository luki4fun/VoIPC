// Persistent user configuration for the web client: the AppConfig of
// client/src-tauri/src/config.rs (same field names and defaults), kept in
// localStorage instead of settings.json.

import { defaultSoundSettings, type AppConfig } from "../../lib/stores/settings";

const STORAGE_KEY = "voipc.settings";

export function defaultConfig(): AppConfig {
  // The connect dialog is pre-filled with the origin the page came from.
  const loc = typeof location !== "undefined" ? location : null;
  return {
    input_device: null,
    output_device: null,
    volume: 1.0,
    input_gain: 1.0,
    noise_suppression: true,
    voice_mode: "ptt",
    vad_threshold_db: -40.0,
    ptt_key: "Space",
    ptt_hold_mode: true,
    mute_key: null,
    deafen_key: null,
    muted: false,
    deafened: false,
    remember_connection: false,
    last_host: loc?.hostname || null,
    last_port: loc ? Number(loc.port) || 9987 : null,
    last_username: null,
    last_accept_self_signed: null,
    saved_servers: [],
    sounds: defaultSoundSettings(),
    auto_connect: false,
    share_channel_history: true,
    chat_history_path: null,
    // The browser has no encrypted chat vault: chat stays in memory.
    chat_history_disabled: true,
  };
}

function load(): AppConfig {
  const defaults = defaultConfig();
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaults;
    const saved = JSON.parse(raw);
    if (!saved || typeof saved !== "object") return defaults;
    return { ...defaults, ...saved, sounds: { ...defaults.sounds, ...(saved.sounds ?? {}) } };
  } catch (e) {
    console.warn("Could not load settings, using defaults:", e);
    return defaults;
  }
}

let config: AppConfig = load();

function save(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch (e) {
    console.warn("Failed to save config:", e);
  }
}

/** The live config. Hand copies to the frontend, never this object. */
export function getConfig(): AppConfig {
  return config;
}

/** Apply `change` to the config and persist it. */
export function updateConfig(change: (c: AppConfig) => void): void {
  change(config);
  save();
}

/** Back to defaults; the stored copy is removed. */
export function resetConfig(): void {
  config = defaultConfig();
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // nothing stored
  }
}
