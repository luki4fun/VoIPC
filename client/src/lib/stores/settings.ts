import { writable } from "svelte/store";
import { MAX_CONVERSATIONS } from "../chat-rules.js";

export const inputDevice = writable<string>("");
export const outputDevice = writable<string>("");
export const volume = writable<number>(1.0);
export const inputGain = writable<number>(1.0);
export const pttKey = writable<string>("Space");
export const muteKey = writable<string>("");
export const deafenKey = writable<string>("");
export const chatHistoryDisabled = writable<boolean>(false);
export const pttHoldMode = writable<boolean>(true);
export const noiseSuppression = writable<boolean>(true);

/**
 * Server the connect dialog starts with when nothing was remembered.
 *
 * A build can bake one in with `VITE_DEFAULT_SERVER=host[:port]` (see
 * BUILDING.md) — that is how a demo build points at a public relay while the
 * normal release ships with localhost. In the browser the page's own origin
 * wins when no default was baked in: the server that served the page is the
 * one to connect to.
 *
 * Only the browser build may read the origin. The app's webview serves the UI
 * from an origin of its own (`http://tauri.localhost` on Android and Windows),
 * which is not a server anyone can connect to — hence the `__WEB__` check
 * rather than sniffing the protocol.
 */
export function defaultServer(): { host: string; port: number } {
  const baked = import.meta.env?.VITE_DEFAULT_SERVER?.trim();
  if (baked) {
    const parsed = parseHostPort(baked);
    if (parsed) return parsed;
    console.warn(`ignoring malformed VITE_DEFAULT_SERVER: ${baked}`);
  }
  if (__WEB__ && typeof location !== "undefined" && location.hostname) {
    return { host: location.hostname, port: Number(location.port) || 9987 };
  }
  return { host: "localhost", port: 9987 };
}

/** "host", "host:port" or "[v6::addr]:port" — port defaults to 9987. */
function parseHostPort(value: string): { host: string; port: number } | null {
  const bracketed = value.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) {
    return { host: bracketed[1], port: bracketed[2] ? Number(bracketed[2]) : 9987 };
  }
  const parts = value.split(":");
  if (parts.length === 1) return parts[0] ? { host: parts[0], port: 9987 } : null;
  if (parts.length === 2 && parts[0]) {
    const port = Number(parts[1]);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) return { host: parts[0], port };
  }
  return null; // bare IPv6 without brackets, empty host, junk port
}

const initialServer = defaultServer();

// Connection persistence
export const rememberConnection = writable<boolean>(false);
export const lastHost = writable<string>(initialServer.host);
export const lastPort = writable<number>(initialServer.port);
export const lastUsername = writable<string>("");
export const lastAcceptSelfSigned = writable<boolean>(false);

// QoL
export const autoConnect = writable<boolean>(false);
/** Answer newcomers' requests for recent channel chat (E2E, pairwise). */
export const shareChannelHistory = writable<boolean>(true);
/**
 * How many conversations the archive keeps: channels and people together,
 * across every server. 0 keeps all of them.
 */
export const maxConversations = writable<number>(MAX_CONVERSATIONS);
/** Codec for our own screen share: "h264" (every viewer) or "h265" (desktop viewers). */
export const screenShareCodec = writable<string>("h264");

// Proximity chat (receive side; both are per-client preferences)
/** Render voices positionally in proximity channels. */
export const spatialAudio = writable<boolean>(true);
/** Place a screen share's audio at its sharer's position. */
export const screenAudioSpatial = writable<boolean>(true);

// Audio effects
//
// A lane is a lane: our own microphone on the way out, or one other person's
// voice on the way in. Both carry the same four controls — an effect, and
// muffle, reverb and water at 0-10 each — and both live in stores/mixer.ts,
// which is the single writer for all of them. Nothing about a lane is kept
// here, so there is no second copy to drift.
/** Play our own microphone back to us while the mic test runs (session-only). */
export const micMonitor = writable<boolean>(false);

/**
 * What this build's first-run audio setup covers. Bumped when a later release
 * adds a step worth asking everybody about again; a saved version below it
 * mounts the wizard once.
 */
export const AUDIO_SETUP_VERSION = 1;

/** Which first-run audio setup this user has been through; 0 means never. */
export const audioSetupVersion = writable<number>(0);

/** Settings → "Run audio setup again" asked for it, whatever the version says. */
export const audioSetupRequested = writable<boolean>(false);

/**
 * The audio setup is on screen. VoiceControls reads it: in voice-activation or
 * always-open mode it re-opens the microphone the instant anything stops it,
 * which would fight the wizard's own microphone test for the device.
 */
export const audioSetupOpen = writable<boolean>(false);

// Saved servers for the connect dialog
export interface SavedServer {
  name: string;
  host: string;
  port: number;
  username: string;
  accept_self_signed: boolean;
}

export const savedServers = writable<SavedServer[]>([]);

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
  input_gain: number;
  noise_suppression: boolean;
  voice_mode: string;
  vad_threshold_db: number;
  ptt_key: string;
  ptt_hold_mode: boolean;
  mute_key: string | null;
  deafen_key: string | null;
  muted: boolean;
  deafened: boolean;
  remember_connection: boolean;
  last_host: string | null;
  last_port: number | null;
  last_username: string | null;
  last_accept_self_signed: boolean | null;
  saved_servers: SavedServer[];
  /** Codec for our own screen share: "h264" (default) or "h265". */
  screen_share_codec: string;
  /** Render voices positionally in proximity channels. */
  spatial_audio: boolean;
  /** Place a screen share's audio at its sharer's position. */
  screen_audio_spatial: boolean;
  /** Our own microphone's lane: an effect, plus three levels at 0-10. */
  mic_effect: string;
  mic_muffle: number;
  mic_reverb: number;
  mic_water: number;
  /** Which first-run audio setup the user has been through; 0 = never. */
  audio_setup_version: number;
  sounds: SoundSettings;
  auto_connect: boolean;
  share_channel_history: boolean;
  /** Conversations the archive keeps; 0 = all of them. */
  max_conversations: number;
  /**
   * Appearance preferences, opaque to the backend and owned entirely by
   * `stores/ui-prefs.ts` — see the `ui_prefs` field in config.rs for why this
   * one setting is a blob when every other is its own command. `null` means
   * nothing has been chosen yet; the first-run layout picker itself keys on
   * `layout_asked_version`, which is 0 either way.
   */
  ui_prefs: Record<string, unknown> | null;
  chat_history_path: string | null;
  chat_history_disabled: boolean;
}
