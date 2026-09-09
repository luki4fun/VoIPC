// invoke() dispatcher of the web client. Each entry mirrors the Tauri command
// of the same name in client/src-tauri/src/commands.rs: same arguments
// (camelCase, as the components pass them), same ClientMessage on the wire,
// same local side effects and error strings. Commands that only make sense
// with a native process (screen-share sending, the chat vault, sound files,
// global hotkeys) are stubs.

import { audio } from "./audio";
import { video } from "./video";
import { share } from "./share";
import { getConfig, resetConfig, updateConfig } from "./config";
import * as session from "./session";
import { playCue } from "./sounds";
import type { SavedServer, SoundSettings } from "../../lib/stores/settings";
import type { ProximityMode } from "../../lib/spatial";

type Args = Record<string, unknown>;
type Handler = (args: Args) => unknown;

/** Rust commands fail with Err(String); components format rejections with String(e). */
function fail(msg: string): never {
  throw msg;
}

function need(): session.Session {
  return session.activeSession() ?? fail("Not connected");
}

function str(v: unknown, name: string): string {
  return typeof v === "string" ? v : fail(`invalid ${name}`);
}

function optStr(v: unknown, name: string): string | null {
  return v == null ? null : str(v, name);
}

function num(v: unknown, name: string): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fail(`invalid ${name}`);
}

function u32(v: unknown, name: string): number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 0xffff_ffff ? v : fail(`invalid ${name}`);
}

function bool(v: unknown, name: string): boolean {
  return typeof v === "boolean" ? v : fail(`invalid ${name}`);
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, v));
}

/** Proximity mode as the protocol spells it; absent or "off" means non-positional. */
function proximityMode(v: unknown): ProximityMode {
  if (v == null) return "off";
  const s = str(v, "proximity");
  return s === "off" || s === "2d" || s === "3d" ? s : fail(`unknown proximity mode: ${s}`);
}

/** A position in metres: [x, y, z], or null to remove a placement. */
function position(v: unknown, name: string): [number, number, number] | null {
  if (v == null) return null;
  if (!Array.isArray(v) || v.length !== 3) fail(`invalid ${name}`);
  const [x, y, z] = v.map((c) => num(c, name));
  return [x, y, z];
}

const byteLength = (s: string) => new TextEncoder().encode(s).length;

/** JS KeyboardEvent.code values accepted as hotkeys (commands.rs is_valid_key_code). */
const VALID_KEY_CODES = new Set<string>([
  "Space", "Tab", "Escape", "CapsLock",
  ..."ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("").map((c) => `Key${c}`),
  ..."0123456789".split("").map((d) => `Digit${d}`),
  ...Array.from({ length: 12 }, (_, i) => `F${i + 1}`),
  "ShiftLeft", "ShiftRight", "ControlLeft", "ControlRight", "AltLeft", "AltRight",
  "Backquote", "Minus", "Equal", "BracketLeft", "BracketRight", "Backslash",
  "Semicolon", "Quote", "Comma", "Period", "Slash",
]);

/** commands.rs parse_ptt_binding: "Ctrl+Space" / "KeyV" must name a supported key. */
function isValidBinding(binding: string): boolean {
  let code = "";
  for (const part of binding.split("+")) {
    if (part !== "Ctrl" && part !== "Alt" && part !== "Shift") code = part;
  }
  return VALID_KEY_CODES.has(code);
}

/** set_mute_key / set_deafen_key: empty string unbinds. */
function setToggleKey(field: "mute_key" | "deafen_key", keyCode: unknown): void {
  const binding = str(keyCode, "keyCode");
  if (binding !== "" && !isValidBinding(binding)) fail(`Unsupported key binding: ${binding}`);
  updateConfig((c) => {
    c[field] = binding === "" ? null : binding;
  });
}

const WEB_NO_CHAT_HISTORY = "Chat history is not available in the web client";

const handlers: Record<string, Handler> = {
  // ── connection ──
  connect: ({ address, username }) => {
    const addr = str(address, "address");
    const name = str(username, "username");
    if (addr.length === 0 || addr.length > 253) fail("address must be 1-253 characters");
    if (name.length === 0 || byteLength(name) > 32) fail("username must be 1-32 characters");
    return session.connect(addr, name);
  },
  disconnect: () => session.disconnect(),
  ping: () => need().sendControl({ Ping: { timestamp: Date.now() } }),
  get_platform: () => "web",

  // ── channels ──
  join_channel: ({ channelId, password }) => {
    const s = need();
    const channel = u32(channelId, "channelId");
    s.clearWatching();
    s.sendControl({ JoinChannel: { channel_id: channel, password: optStr(password, "password") } });
  },
  create_channel: ({ name, password, proximity, anonymous }) => {
    const channelName = str(name, "name");
    if (channelName.length === 0 || byteLength(channelName) > 128) fail("channel name must be 1-128 characters");
    const pw = optStr(password, "password");
    if (pw !== null && byteLength(pw) > 128) fail("password too long");
    need().sendControl({
      CreateChannel: {
        name: channelName,
        password: pw,
        proximity: proximityMode(proximity),
        anonymous: anonymous == null ? false : bool(anonymous, "anonymous"),
      },
    });
  },
  set_channel_password: ({ channelId, password }) =>
    need().sendControl({
      SetChannelPassword: { channel_id: u32(channelId, "channelId"), password: optStr(password, "password") },
    }),
  set_channel_proximity: ({ channelId, proximity }) =>
    need().sendControl({
      SetChannelProximity: {
        channel_id: u32(channelId, "channelId"),
        proximity: proximityMode(proximity),
      },
    }),
  // null leaves an option as it is, so the dialog only sends what changed
  set_channel_options: ({ channelId, hidden, anonymous, screenShare, hideMembers }) => {
    const flag = (v: unknown, name: string) => (v == null ? null : bool(v, name));
    need().sendControl({
      SetChannelOptions: {
        channel_id: u32(channelId, "channelId"),
        hidden: flag(hidden, "hidden"),
        anonymous: flag(anonymous, "anonymous"),
        screen_share: flag(screenShare, "screenShare"),
        hide_members: flag(hideMembers, "hideMembers"),
      },
    });
  },
  kick_user: ({ channelId, userId }) =>
    need().sendControl({ KickUser: { channel_id: u32(channelId, "channelId"), user_id: u32(userId, "userId") } }),
  request_channel_users: ({ channelId }) =>
    need().sendControl({ RequestChannelUsers: { channel_id: u32(channelId, "channelId") } }),
  send_invite: ({ channelId, targetUserId }) =>
    need().sendControl({
      SendInvite: { channel_id: u32(channelId, "channelId"), target_user_id: u32(targetUserId, "targetUserId") },
    }),
  accept_invite: ({ channelId }) => {
    const s = need();
    s.clearWatching();
    s.sendControl({ AcceptInvite: { channel_id: u32(channelId, "channelId") } });
  },
  decline_invite: ({ channelId }) =>
    need().sendControl({ DeclineInvite: { channel_id: u32(channelId, "channelId") } }),

  // ── chat ──
  send_poke: ({ targetUserId, message }) =>
    need().sendPoke(u32(targetUserId, "targetUserId"), str(message, "message")),
  send_channel_message: ({ content }) => need().sendChannelMessage(str(content, "content")),
  send_direct_message: ({ targetUserId, content }) =>
    need().sendDirectMessage(u32(targetUserId, "targetUserId"), str(content, "content")),
  send_channel_history: ({ channelId, targetUserId, messages }) => {
    if (!Array.isArray(messages)) fail("invalid messages");
    need().sendChannelHistory(u32(channelId, "channelId"), u32(targetUserId, "targetUserId"), messages);
  },

  // ── moderation (admin token session) ──
  admin_login: ({ token }) => need().sendControl({ AdminLogin: { token: str(token, "token") } }),
  admin_kick: ({ userId, reason }) =>
    need().sendControl({ AdminKick: { user_id: u32(userId, "userId"), reason: str(reason, "reason") } }),
  admin_ban: ({ userId, reason, durationSecs }) =>
    need().sendControl({
      AdminBan: {
        user_id: u32(userId, "userId"),
        reason: str(reason, "reason"),
        duration_secs: u32(durationSecs, "durationSecs"),
      },
    }),
  admin_unban: ({ ip }) => need().sendControl({ AdminUnban: { ip: str(ip, "ip") } }),
  admin_list_bans: () => need().sendControl("AdminListBans"),

  // ── voice ──
  start_transmit: async () => {
    const s = need();
    if (s.channelId === 0) fail("Voice is disabled in the General lobby");
    await audio.startTransmit();
  },
  stop_transmit: async () => {
    need();
    await audio.stopTransmit();
  },
  toggle_mute: async () => {
    need();
    const muted = await audio.toggleMute(); // also tells the server
    updateConfig((c) => {
      c.muted = muted;
    });
    return muted;
  },
  toggle_deafen: async () => {
    need();
    const deafened = await audio.toggleDeafen(); // also tells the server
    updateConfig((c) => {
      c.deafened = deafened;
    });
    return deafened;
  },
  toggle_noise_suppression: async () => {
    const enabled = await audio.toggleNoiseSuppression();
    updateConfig((c) => {
      c.noise_suppression = enabled;
    });
    return enabled;
  },
  set_input_gain: ({ gain }) => {
    const value = clamp(num(gain, "gain"), 0, 4);
    updateConfig((c) => {
      c.input_gain = value;
    });
    audio.setInputGain(value);
  },
  set_volume: ({ volume }) => {
    const value = clamp(num(volume, "volume"), 0, 1);
    updateConfig((c) => {
      c.volume = value;
    });
    audio.setVolume(value);
  },
  set_user_volume: ({ userId, volume }) => {
    need();
    audio.setUserVolume(u32(userId, "userId"), clamp(num(volume, "volume"), 0, 2));
  },
  set_user_position: ({ userId, pos, range, volume, muffle, direct }) => {
    need();
    audio.setUserPosition(u32(userId, "userId"), position(pos, "pos"), {
      range: range == null ? undefined : num(range, "range"),
      volume: volume == null ? undefined : num(volume, "volume"),
      muffle: muffle == null ? undefined : u32(muffle, "muffle"),
      direct: direct == null ? undefined : bool(direct, "direct"),
    });
  },
  set_own_position: ({ pos, fwd }) => {
    need();
    const p = position(pos, "pos") ?? fail("invalid pos");
    let facing: [number, number] | undefined;
    if (fwd != null) {
      if (!Array.isArray(fwd) || fwd.length !== 2) fail("invalid fwd");
      facing = [num(fwd[0], "fwd"), num(fwd[1], "fwd")];
    }
    audio.setOwnPosition(p, facing);
  },
  set_position_sync: ({ enabled }) => {
    need();
    audio.setPositionSync(bool(enabled, "enabled"));
  },
  clear_positions: () => {
    need();
    audio.clearPositions();
  },
  // A browser page cannot host a socket, so the game SDK is desktop-only
  get_sdk_status: () => ({ available: false, enabled: false, port: 0, origins: [] }),
  set_sdk_config: () => fail("The game SDK needs the desktop app"),
  set_spatial_setting: ({ key, value }) => {
    const enabled = bool(value, "value");
    const name = str(key, "key");
    if (name !== "spatial_audio" && name !== "screen_audio_spatial") {
      fail(`Unknown spatial setting: ${name}`);
    }
    updateConfig((c) => {
      if (name === "spatial_audio") c.spatial_audio = enabled;
      else c.screen_audio_spatial = enabled;
    });
    audio.setSpatialSetting(name, enabled);
  },
  get_user_volume: ({ userId }) => {
    need();
    return audio.getUserVolume(u32(userId, "userId"));
  },
  set_voice_mode: async ({ mode }) => {
    const value = str(mode, "mode");
    updateConfig((c) => {
      c.voice_mode = value;
    });
    await audio.setVoiceMode(value);
  },
  set_vad_threshold: ({ thresholdDb }) => {
    const value = num(thresholdDb, "thresholdDb");
    updateConfig((c) => {
      c.vad_threshold_db = value;
    });
    audio.setVadThreshold(value);
  },
  get_audio_level: () => {
    need();
    return audio.getAudioLevel();
  },
  get_input_devices: () => audio.getInputDevices(),
  get_output_devices: () => audio.getOutputDevices(),
  set_input_device: async ({ deviceName }) => {
    const name = str(deviceName, "deviceName");
    updateConfig((c) => {
      c.input_device = name;
    });
    await audio.setInputDevice(name);
  },
  set_output_device: async ({ deviceName }) => {
    const name = str(deviceName, "deviceName");
    updateConfig((c) => {
      c.output_device = name;
    });
    await audio.setOutputDevice(name);
  },
  start_mic_test: () => audio.startMicTest(),
  stop_mic_test: () => audio.stopMicTest(),
  // No session needed: the audio graph stands on its own, like the mic test
  start_spatial_test: ({ mode }) => {
    const m = proximityMode(mode);
    if (m === "off") fail("Pick 2d or 3d");
    return audio.startSpatialTest(m);
  },
  stop_spatial_test: () => audio.stopSpatialTest(),
  get_voice_stats: () => {
    need();
    return audio.getVoiceStats();
  },
  get_screen_audio_status: () => {
    need();
    return audio.getScreenAudioStatus();
  },

  // ── screen share ──
  watch_screen_share: ({ sharerUserId }) => need().watchScreenShare(u32(sharerUserId, "sharerUserId")),
  stop_watching_screen_share: () => need().stopWatchingScreenShare(),
  request_keyframe: ({ sharerUserId }) =>
    need().sendControl({ RequestKeyframe: { sharer_user_id: u32(sharerUserId, "sharerUserId") } }),
  get_screen_share_stats: () => {
    need();
    // [frames_sent, bytes_sent] from our own share, the rest from the viewer
    const [, , recv, dropped, bytesRecv, resolution] = video.getStats();
    const [sent, bytesSent] = share.getStats();
    return [sent, bytesSent, recv, dropped, bytesRecv, resolution];
  },
  // The browser opens its own source picker, so sourceType/sourceId are unused
  start_screen_share: ({ resolution, fps }) => {
    need();
    return share.start(u32(resolution, "resolution"), u32(fps, "fps"));
  },
  // getDisplayMedia has no switch: the button is hidden on web, and stopping
  // first would leave the share down if the user then cancelled the picker.
  switch_screen_share_source: () =>
    fail("Switching the source is not available in the browser — stop sharing and share again"),
  stop_screen_share: () => share.stop(),
  // The browser's picker enumerates sources itself
  enumerate_displays: () => [],
  enumerate_windows: () => [],
  start_screen_capture: ({ resolution, fps }) =>
    share.startEncoding(u32(resolution, "resolution"), u32(fps, "fps")),
  stop_screen_capture: () => share.stopEncoding(),
  set_keyframe_requested: () => share.requestKeyframe(),
  toggle_screen_audio: () => share.toggleAudio(),
  // Browsers pick their own codec (H.264 where they can encode it, else VP9)
  set_screen_share_codec: () => {},

  // ── chat history (no vault in the browser: chat stays in memory) ──
  save_chat_messages: () => {},
  clear_chat_history: () => {},
  get_chat_history_status: () => ({ path_configured: false, current_path: "", file_exists: false }),
  browse_chat_history_directory: () => null,
  unlock_chat_history: () => fail(WEB_NO_CHAT_HISTORY),
  create_chat_history: () => fail(WEB_NO_CHAT_HISTORY),
  delete_chat_history: () => fail(WEB_NO_CHAT_HISTORY),
  set_chat_history_path: () => fail(WEB_NO_CHAT_HISTORY),
  check_path_status: () => fail(WEB_NO_CHAT_HISTORY),
  set_chat_history_disabled: ({ disabled }) => {
    const value = bool(disabled, "disabled");
    updateConfig((c) => {
      c.chat_history_disabled = value;
    });
  },

  // ── notification sounds: synthesised cues (no file access in the browser) ──
  play_notification_sound: ({ name }) => playCue(str(name, "name"), getConfig().sounds),
  // The settings panel passes the event name where the desktop passes a file path
  preview_sound: ({ path }) => playCue(str(path, "path"), null),
  browse_sound_file: () => null,
  set_sound_settings: ({ settings }) => {
    if (!settings || typeof settings !== "object") fail("invalid settings");
    updateConfig((c) => {
      c.sounds = settings as SoundSettings;
    });
  },

  // ── persistent config ──
  load_config: () => {
    const config = getConfig();
    audio.applySettings(config);
    return structuredClone(config);
  },
  save_connection_info: ({ host, port, username, acceptSelfSigned, remember }) => {
    const keep = bool(remember, "remember");
    const entry = keep
      ? {
          host: str(host, "host"),
          port: u32(port, "port"),
          username: str(username, "username"),
          accept_self_signed: bool(acceptSelfSigned, "acceptSelfSigned"),
        }
      : null;
    updateConfig((c) => {
      c.remember_connection = keep;
      c.last_host = entry?.host ?? null;
      c.last_port = entry?.port ?? null;
      c.last_username = entry?.username ?? null;
      c.last_accept_self_signed = entry?.accept_self_signed ?? null;
      if (!keep) c.auto_connect = false;
    });
  },
  save_server: ({ name, host, port, username, acceptSelfSigned }) => {
    const entry: SavedServer = {
      name: str(name, "name"),
      host: str(host, "host"),
      port: u32(port, "port"),
      username: str(username, "username"),
      accept_self_signed: bool(acceptSelfSigned, "acceptSelfSigned"),
    };
    updateConfig((c) => {
      const i = c.saved_servers.findIndex((s) => s.host === entry.host && s.port === entry.port);
      if (i >= 0) c.saved_servers[i] = entry;
      else c.saved_servers.push(entry);
    });
    return structuredClone(getConfig().saved_servers);
  },
  remove_server: ({ host, port }) => {
    const h = str(host, "host");
    const p = u32(port, "port");
    updateConfig((c) => {
      c.saved_servers = c.saved_servers.filter((s) => !(s.host === h && s.port === p));
    });
    return structuredClone(getConfig().saved_servers);
  },
  reset_config: () => {
    resetConfig();
    audio.applySettings(getConfig());
  },
  set_config_bool: ({ key, value }) => {
    const enabled = bool(value, "value");
    updateConfig((c) => {
      switch (key) {
        case "auto_connect":
          c.auto_connect = enabled;
          break;
        case "remember_connection":
          c.remember_connection = enabled;
          break;
        case "share_channel_history":
          c.share_channel_history = enabled;
          break;
        default:
          fail(`Unknown config key: ${key}`);
      }
    });
  },
  set_ptt_key: ({ keyCode }) => {
    const binding = str(keyCode, "keyCode");
    if (!isValidBinding(binding)) fail(`Unsupported key binding: ${binding}`);
    updateConfig((c) => {
      c.ptt_key = binding;
    });
  },
  set_mute_key: ({ keyCode }) => setToggleKey("mute_key", keyCode),
  set_deafen_key: ({ keyCode }) => setToggleKey("deafen_key", keyCode),
  set_ptt_hold_mode: ({ holdMode }) => {
    const value = bool(holdMode, "holdMode");
    updateConfig((c) => {
      c.ptt_hold_mode = value;
    });
  },
  // Browser certificate trust applies; there is no TOFU pin to forget.
  forget_server_pin: () => true,
};

/** Run one invoke() command. Unknown commands reject with an Error, failed ones with a string. */
export async function dispatch(cmd: string, args: Args): Promise<unknown> {
  const handler = Object.hasOwn(handlers, cmd) ? handlers[cmd] : undefined;
  if (!handler) throw new Error(`unknown command: ${cmd}`);
  try {
    return await handler(args);
  } catch (e) {
    throw e instanceof Error ? e.message : e;
  }
}
