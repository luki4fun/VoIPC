import { writable } from "svelte/store";

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
 */
export function defaultServer(): { host: string; port: number } {
  const baked = import.meta.env?.VITE_DEFAULT_SERVER?.trim();
  if (baked) {
    const parsed = parseHostPort(baked);
    if (parsed) return parsed;
    console.warn(`ignoring malformed VITE_DEFAULT_SERVER: ${baked}`);
  }
  const loc = typeof location !== "undefined" && location.protocol.startsWith("http") ? location : null;
  if (loc?.hostname) return { host: loc.hostname, port: Number(loc.port) || 9987 };
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
/** Codec for our own screen share: "h264" (every viewer) or "h265" (desktop viewers). */
export const screenShareCodec = writable<string>("h264");

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
  sounds: SoundSettings;
  auto_connect: boolean;
  share_channel_history: boolean;
  chat_history_path: string | null;
  chat_history_disabled: boolean;
}
