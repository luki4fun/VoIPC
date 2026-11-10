// Persistent user configuration for the web client: the AppConfig of
// client/src-tauri/src/config.rs (same field names and defaults), kept in
// localStorage instead of settings.json.

import { defaultServer, defaultSoundSettings, type AppConfig } from "../../lib/stores/settings";

const STORAGE_KEY = "voipc.settings";

export function defaultConfig(): AppConfig {
  // Baked-in default if the build set one, else the origin that served the page.
  const server = defaultServer();
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
    last_host: server.host,
    last_port: server.port,
    last_username: null,
    last_accept_self_signed: null,
    saved_servers: [],
    // The servers open when the page last saved them, reconnected on startup
    open_servers: [],
    screen_share_codec: "h264",
    spatial_audio: true,
    screen_audio_spatial: true,
    mic_effect: "none",
    mic_muffle: 0,
    mic_reverb: 0,
    mic_water: 0,
    audio_setup_version: 0,
    sounds: defaultSoundSettings(),
    auto_connect: false,
    share_channel_history: false,
    share_off_once: true,
    share_off_notice: false,
    max_conversations: 1000,
    // Null, not `{}`: the state the appearance blob starts in (see config.rs).
    // The first-run picker keys on `layout_asked_version`, 0 either way.
    ui_prefs: null,
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
    if (!saved || typeof saved !== "object") throw new Error("not an object");
    const loaded: AppConfig = { ...defaults, ...saved, sounds: { ...defaults.sounds, ...(saved.sounds ?? {}) } };
    // As config.rs `share_off_once`: the switch used to start on, so a saved `true`
    // cannot say whether anyone chose it. Once: off, with a notice if it was on.
    if (saved.share_off_once !== true) {
      loaded.share_off_notice = saved.share_channel_history === true;
      loaded.share_channel_history = false;
      loaded.share_off_once = true;
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(loaded));
      } catch {
        // It runs again next time, which only keeps the switch off
      }
    }
    return loaded;
  } catch (e) {
    // Kept aside rather than overwritten by the next save, which would take
    // the remembered servers with it
    console.warn("Could not load settings, using defaults (the old ones are kept as voipc.settings.unreadable):", e);
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) localStorage.setItem(`${STORAGE_KEY}.unreadable`, raw);
    } catch {
      // storage unavailable: nothing to keep
    }
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
  const before = config.share_channel_history;
  change(config);
  // Unless this is what moved it, the switch stays as stored: this tab may not have heard
  // yet that another turned it off, and writing it back would turn it on for the next load.
  if (config.share_channel_history === before) adoptStoredShare();
  save();
}

let shareMoved: (on: boolean) => void = () => {};

/** What to do when another tab of this browser moves the switch. */
export function onShareMoved(then: (on: boolean) => void): void {
  shareMoved = then;
}

function adoptStoredShare(): void {
  let stored: unknown;
  try {
    stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null")?.share_channel_history;
  } catch {
    return;
  }
  if (typeof stored !== "boolean" || stored === config.share_channel_history) return;
  config.share_channel_history = stored;
  shareMoved(stored);
}

// Two tabs on one origin share this one setting
globalThis.addEventListener?.("storage", (e) => {
  if ((e as StorageEvent).key === STORAGE_KEY) adoptStoredShare();
});

/** Back to defaults; the stored copy is removed. */
export function resetConfig(): void {
  config = defaultConfig();
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // nothing stored
  }
}
