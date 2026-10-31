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
import { forgetDevice, listDevices } from "./devices";
import { wasm } from "./wasm";
import { forgetRelayId, type AccountArgs } from "./account";
import { playCue } from "./sounds";
import type { SavedServer, SoundSettings } from "../../lib/stores/settings";
import type { ProximityMode } from "../../lib/spatial";
import { FX_NONE, effectFromId } from "./worklets/mixer-worklet.js";
import { toHex } from "../../lib/hex";
import * as files from "./files";
import * as emotes from "./emotes";
import { fileRef } from "../../lib/chat-rules";
import type { ChatEvent, Forwarded } from "../../lib/types";

type Args = Record<string, unknown>;
type Handler = (args: Args) => unknown;

/** Rust commands fail with Err(String); components format rejections with String(e). */
function fail(msg: string): never {
  throw msg;
}

/** A server-scoped command's connection: `server` is the id connect was given. */
function need(server: unknown): session.Session {
  const id = str(server, "server");
  return session.sessionFor(id) ?? fail(`Not connected to ${id}`);
}

/** An account command's connection and its account (account.rs `signed_in`). */
function needAccount(server: unknown): { s: session.Session; account: NonNullable<session.Session["account"]> } {
  const s = session.sessionFor(str(server, "server")) ?? fail("Not connected to that server");
  return { s, account: s.account ?? fail("Not signed in to an account on that server") };
}

/** A voice-scoped command's connection: the one whose voice channel we are in. */
function voice(): session.Session {
  return session.voiceSession() ?? fail("Not in a voice channel");
}

function str(v: unknown, name: string): string {
  return typeof v === "string" ? v : fail(`invalid ${name}`);
}

function optStr(v: unknown, name: string): string | null {
  return v == null ? null : str(v, name);
}

function strs(v: unknown, name: string): string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? v : fail(`invalid ${name}`);
}

/** What a message answers, its thread, its file, where it was forwarded
 *  from, or the event it is, as the front end names them. One that would
 *  arrive as something else is refused (commands.rs `checked_extras`): the
 *  wasm envelope checks a label and an event as a reader will, and throws. */
function refs(replyTo: unknown, thread: unknown, file: unknown, fwd?: unknown, event?: unknown) {
  return {
    replyTo: optStr(replyTo, "replyTo"),
    thread: optStr(thread, "thread"),
    file: file == null ? null : (fileRef(file) ?? fail("invalid file")),
    fwd: fwd == null ? null : (fwd as Forwarded),
    event: event == null ? null : (event as ChatEvent),
  };
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

/** The `account` argument of `connect`: checked here, the trust boundary for a web build. */
function accountArgs(raw: unknown): AccountArgs | undefined {
  if (raw === undefined || raw === null) return undefined;
  const a = raw as Record<string, unknown>;
  switch (a.kind) {
    case "login":
      return { kind: "login", password: str(a.password, "password") };
    case "register":
      return { kind: "register", password: str(a.password, "password"), invite: a.invite == null ? null : str(a.invite, "invite") };
    case "device":
      return { kind: "device" };
    case "reset":
      return { kind: "reset", recovery: str(a.recovery, "recovery"), password: str(a.password, "password") };
    default:
      fail("unknown account sign-in");
  }
}

/**
 * A lane's effect id: any preset, plus "none". The preset table is the single
 * source of truth on both sides, so adding a chain does not mean remembering
 * to widen a validator. For a web build this handler *is* the trust boundary,
 * not a mirror of the Rust one.
 */
function laneEffect(effect: unknown): string {
  const name = str(effect, "effect");
  if (name !== "none" && effectFromId(name) === FX_NONE) fail(`Unknown effect: ${name}`);
  return name;
}

const handlers: Record<string, Handler> = {
  // ── connection ──
  connect: ({ address, username, account }) => {
    const addr = str(address, "address");
    const name = str(username, "username");
    if (addr.length === 0 || addr.length > 253) fail("address must be 1-253 characters");
    // 32 for the name and 5 for its "#0000" tag; the server checks each part
    if (name.length === 0 || byteLength(name) > 37) fail("username must be 1-32 characters");
    return session.connect(addr, name, accountArgs(account));
  },

  // ── accounts (client/src-tauri/src/account.rs) ──
  // Asked mid-sign-in, before the session is listed.
  account_totp: ({ server, code, recovery }) => {
    const s = session.sessionOrSigningIn(str(server, "server"));
    if (!s?.account) fail("No sign-in is waiting for a code.");
    s.account.answerTotp(str(code, "code"), recovery === true);
  },
  account_cancel: ({ server }) => {
    session.sessionOrSigningIn(str(server, "server"))?.account?.cancel();
  },
  account_request: ({ server, request }) => needAccount(server).s.sendControl({ Account: request }),
  account_password_change: ({ server, old, new: next, totp, recovery }) => {
    const { s, account } = needAccount(server);
    const opt = (v: unknown, name: string) => (v == null ? null : str(v, name));
    return account.passwordChange(s, str(old, "old"), str(next, "new"), opt(totp, "totp"), opt(recovery, "recovery"));
  },
  // updater.rs `third_party_notices`: the bundle carries it beside index.html
  third_party_notices: async () => {
    try {
      const r = await fetch("/THIRD-PARTY-NOTICES.txt");
      // A server that answers every path with the page is no notices file
      if (!r.ok || (r.headers.get("content-type") ?? "").includes("html")) return null;
      const text = await r.text();
      return text.trim() ? text : null;
    } catch {
      return null;
    }
  },
  account_recovery_key_new: ({ server, password, totp, recovery }) => {
    const { s, account } = needAccount(server);
    const opt = (v: unknown, name: string) => (v == null ? null : str(v, name));
    return account.recoveryKeyNew(s, str(password, "password"), opt(totp, "totp"), opt(recovery, "recovery"));
  },
  forget_relay_id: ({ server }) => forgetRelayId(str(server, "server")),
  account_devices: async () =>
    (await listDevices()).map((d) => ({
      server: d.server,
      name: d.name,
      relay_id: toHex(d.relay_id),
    })),
  forget_device: ({ server, name }) => forgetDevice(str(server, "server"), str(name, "name")),
  account_prefs: ({ server }) => needAccount(server).account.prefs() ?? fail("Not signed in to an account on that server"),
  send_kept_dm: ({ server, account, content, ttlSecs, replyTo, thread, file, fwd, event }) =>
    need(server).sendKeptDm(
      str(account, "account"),
      str(content, "content"),
      ttlSecs == null ? undefined : u32(ttlSecs, "ttlSecs"),
      refs(replyTo, thread, file, fwd, event),
    ),
  account_enter: ({ server, conv }) => {
    const { s, account } = needAccount(server);
    account.enter(s, str(conv, "conv"));
  },
  account_purge: ({ server, conv }) => {
    const { s, account } = needAccount(server);
    account.purge(s, conv == null ? null : str(conv, "conv"));
  },
  account_delete: ({ server, password, totp, recovery }) => {
    const { s, account } = needAccount(server);
    const opt = (v: unknown, name: string) => (v == null ? null : str(v, name));
    return account.deleteAccount(s, str(password, "password"), opt(totp, "totp"), opt(recovery, "recovery"));
  },
  account_leave: ({ server, conv }) => {
    const { s, account } = needAccount(server);
    account.leave(s, str(conv, "conv"), true);
  },
  account_set_prefs: ({ server, prefs }) => {
    const { s, account } = needAccount(server);
    const p = prefs as Record<string, unknown>;
    account.setPrefs(s, bool(p?.cloud, "cloud"), bool(p?.asked, "asked"));
  },
  safety_number: ({ server, userId }) => need(server).safetyNumber(u32(userId, "userId")),
  qr_svg: ({ text }) => {
    const t = str(text, "text");
    if (!t.startsWith("otpauth://") || t.length > 512) fail("not an authenticator link");
    return wasm().qrSvg(t) ?? fail("could not draw the code");
  },
  disconnect: ({ server }) => session.disconnect(str(server, "server")),
  // A page load starts with no sessions anyway; this is here for the desktop
  // backend's sake, where a reloaded page can find connections still open.
  disconnect_all: async () => {
    await Promise.all(session.allSessions().map((s) => s.end(true)));
  },
  ping: ({ server }) => need(server).sendControl({ Ping: { timestamp: Date.now() } }),
  get_platform: () => "web",

  // ── channels ──
  join_channel: ({ server, channelId, password }) => {
    const s = need(server);
    const channel = u32(channelId, "channelId");
    // Subscribing to a text channel is not a move, so it costs no share and no
    // viewer: only a voice join does (session.ts onUserList tears down the rest).
    if (!s.isTextChannel(channel)) {
      s.clearWatching();
      if (channel !== 0) s.askVoice();
    }
    s.sendControl({ JoinChannel: { channel_id: channel, password: optStr(password, "password") } });
  },
  leave_channel: ({ server, channelId }) =>
    need(server).sendControl({ LeaveChannel: { channel_id: u32(channelId, "channelId") } }),
  create_channel: ({ server, name, password, proximity, anonymous, text }) => {
    const channelName = str(name, "name");
    if (channelName.length === 0 || byteLength(channelName) > 128) fail("channel name must be 1-128 characters");
    const pw = optStr(password, "password");
    if (pw !== null && byteLength(pw) > 128) fail("password too long");
    const isText = text == null ? false : bool(text, "text");
    const s = need(server);
    // The server seats the creator in a new voice channel
    if (!isText) s.askVoice();
    s.sendControl({
      CreateChannel: {
        name: channelName,
        password: pw,
        proximity: proximityMode(proximity),
        anonymous: anonymous == null ? false : bool(anonymous, "anonymous"),
        text: isText,
      },
    });
  },
  set_channel_password: ({ server, channelId, password }) =>
    need(server).sendControl({
      SetChannelPassword: { channel_id: u32(channelId, "channelId"), password: optStr(password, "password") },
    }),
  set_channel_proximity: ({ server, channelId, proximity }) =>
    need(server).sendControl({
      SetChannelProximity: {
        channel_id: u32(channelId, "channelId"),
        proximity: proximityMode(proximity),
      },
    }),
  // null leaves an option as it is, so the dialog only sends what changed
  // `options`: voipc_protocol ChannelOptions, the names as on the wire.
  set_channel_options: ({ server, channelId, options }) => {
    const o = (options ?? {}) as Record<string, unknown>;
    const flag = (name: string) => (o[name] == null ? null : bool(o[name], name));
    const secs = (name: string) => (o[name] == null ? null : u32(o[name], name));
    need(server).sendControl({
      SetChannelOptions: {
        channel_id: u32(channelId, "channelId"),
        options: {
          hidden: flag("hidden"),
          anonymous: flag("anonymous"),
          screen_share: flag("screen_share"),
          hide_members: flag("hide_members"),
          routed: flag("routed"),
          message_ttl_secs: secs("message_ttl_secs"),
          announce: flag("announce"),
          slow_mode_secs: secs("slow_mode_secs"),
          nsfw: flag("nsfw"),
        },
      },
    });
  },
  kick_user: ({ server, channelId, userId }) =>
    need(server).sendControl({ KickUser: { channel_id: u32(channelId, "channelId"), user_id: u32(userId, "userId") } }),
  request_channel_users: ({ server, channelId }) =>
    need(server).sendControl({ RequestChannelUsers: { channel_id: u32(channelId, "channelId") } }),
  send_invite: ({ server, channelId, targetUserId }) =>
    need(server).sendControl({
      SendInvite: { channel_id: u32(channelId, "channelId"), target_user_id: u32(targetUserId, "targetUserId") },
    }),
  accept_invite: ({ server, channelId }) => {
    const s = need(server);
    s.clearWatching();
    s.askVoice();
    s.sendControl({ AcceptInvite: { channel_id: u32(channelId, "channelId") } });
  },
  decline_invite: ({ server, channelId }) =>
    need(server).sendControl({ DeclineInvite: { channel_id: u32(channelId, "channelId") } }),

  // ── chat ──
  send_poke: ({ server, targetUserId, message }) =>
    need(server).sendPoke(u32(targetUserId, "targetUserId"), str(message, "message")),
  send_channel_message: ({ server, content, channelId, ttlSecs, replyTo, thread, file, fwd, event }) =>
    need(server).sendChannelMessage(
      str(content, "content"),
      channelId == null ? undefined : u32(channelId, "channelId"),
      ttlSecs == null ? undefined : u32(ttlSecs, "ttlSecs"),
      refs(replyTo, thread, file, fwd, event),
    ),
  send_direct_message: ({ server, targetUserId, content, ttlSecs, replyTo, thread, file, fwd, event }) =>
    need(server).sendDirectMessage(
      u32(targetUserId, "targetUserId"),
      str(content, "content"),
      ttlSecs == null ? undefined : u32(ttlSecs, "ttlSecs"),
      refs(replyTo, thread, file, fwd, event),
    ),
  // ── Files (files.ts; client/src-tauri/src/files.rs) ──
  send_file: ({ body, headers }) => {
    const raw = (headers as Record<string, unknown> | undefined)?.["x-voipc-file"];
    let meta: Args;
    try {
      meta = JSON.parse(str(raw, "x-voipc-file"));
    } catch {
      fail("send_file needs its x-voipc-file header");
    }
    if (!(body instanceof Uint8Array)) fail("send_file takes the file's bytes");
    const s = need(meta.server);
    if (!s.files) fail(`Not connected to ${meta.server}`);
    return files.sendFile(s.files, files.parseConv(meta.conv), body, bool(meta.compress, "compress"), optStr(meta.op, "op") ?? undefined);
  },
  fetch_file: ({ server, conv, file, op }) =>
    files.fetchFile(
      session.sessionFor(str(server, "server"))?.files ?? null,
      str(server, "server"),
      files.parseConv(conv),
      files.parseFileArg(file),
      optStr(op, "op") ?? undefined,
    ),
  file_image: ({ server, conv, file, profile, op, still }) =>
    files.fileImage(
      session.sessionFor(str(server, "server"))?.files ?? null,
      str(server, "server"),
      files.parseConv(conv),
      files.parseFileArg(file),
      num(profile, "profile"),
      optStr(op, "op") ?? undefined,
      still === true,
    ),
  cancel_file: ({ op }) => files.cancel(str(op, "op")),
  forward_file: ({ server, conv, hash, op }) => {
    const s = need(server);
    if (!s.files) fail("This server keeps no files");
    return files.forwardFile(s.files, files.parseConv(conv), str(hash, "hash"), op == null ? undefined : str(op, "op"));
  },
  reseed_file: ({ server, conv, hash }) => {
    const s = need(server);
    const h = str(hash, "hash");
    if (s.files && /^[0-9a-f]{64}$/.test(h)) files.reseedFile(s.files, files.parseConv(conv), h);
  },
  file_cache_list: () => files.cacheList(),
  file_cache_retain: ({ hashes }) => {
    if (!Array.isArray(hashes)) fail("invalid hashes");
    files.cacheRetain(new Set(hashes.filter((h): h is string => typeof h === "string")));
  },
  // ── Emotes (emotes.ts; client/src-tauri/src/emotes.rs) ──
  emote_image: ({ server, hash, sticker, still, fetchOnly, len }) => {
    const e = need(server).emotes;
    if (!e) fail("this server has no emotes");
    return e.image(str(hash, "hash"), bool(sticker, "sticker"), bool(still, "still"), fetchOnly === true, Number.isInteger(len) ? Number(len) : 0);
  },
  emote_file: async ({ server, hash }) => {
    const e = need(server).emotes;
    if (!e) fail("this server has no emotes");
    return (await e.file(str(hash, "hash"))).buffer;
  },
  emote_seed: ({ body, headers }) => {
    let meta: Args;
    try {
      meta = JSON.parse(str((headers as Record<string, unknown> | undefined)?.["x-voipc-seed"], "x-voipc-seed"));
    } catch {
      fail("emote_seed needs its x-voipc-seed header");
    }
    if (!(body instanceof Uint8Array)) fail("emote_seed takes the pictures' bytes");
    const n = num(meta.preview, "preview");
    if (n <= 0 || n > body.length) fail("emote_seed: no preview");
    return emotes.seed(str(meta.hash, "hash"), bool(meta.sticker, "sticker"), body.slice(0, n), n < body.length ? body.slice(n) : null);
  },
  emote_cache_size: () => emotes.cacheSize(),
  emote_missing: ({ items }) =>
    emotes.missing(
      (Array.isArray(items) ? items : []).map((i: { hash?: unknown; sticker?: unknown }) => ({ hash: str(i?.hash, "hash"), sticker: i?.sticker === true })),
    ),
  emote_cache_clear: () => emotes.cacheClear(),
  emote_cache_retain: ({ keep }) =>
    emotes.retain(Array.isArray(keep) ? keep.filter((h): h is string => typeof h === "string") : []),
  prepare_emote: ({ body, headers }) => {
    let meta: Args;
    try {
      meta = JSON.parse(str((headers as Record<string, unknown> | undefined)?.["x-voipc-prepare"], "x-voipc-prepare"));
    } catch {
      fail("prepare_emote needs its x-voipc-prepare header");
    }
    if (!(body instanceof Uint8Array)) fail("prepare_emote takes the picture's bytes");
    return emotes.prepareEmote(files.sanitizeImage, files.stripImage, body, bool(meta.sticker, "sticker"), num(meta.max_bytes, "max_bytes"));
  },
  read_emote_pack: async ({ body }) => {
    if (!(body instanceof Uint8Array)) fail("read_emote_pack takes the archive's bytes");
    return emotes.packAnswer(await files.readPack(body));
  },
  emote_add: ({ body, headers }) => {
    let meta: Args;
    try {
      meta = JSON.parse(str((headers as Record<string, unknown> | undefined)?.["x-voipc-emote"], "x-voipc-emote"));
    } catch {
      fail("emote_add needs its x-voipc-emote header");
    }
    if (!(body instanceof Uint8Array)) fail("emote_add takes the picture's bytes");
    const e = need(meta.server).emotes;
    if (!e) fail("this server has no emotes");
    const side = (v: unknown) => (Number.isInteger(v) ? Math.min(Math.max(Number(v), 0), 65_535) : 0);
    return e.add(str(meta.name, "name"), bool(meta.sticker, "sticker"), str(meta.pack, "pack"), body, side(meta.w), side(meta.h));
  },
  emote_remove: ({ server, names }) => need(server).emotes?.remove(strs(names, "names")),
  emote_move: ({ server, names, pack, sticker }) =>
    need(server).emotes?.move(strs(names, "names"), optStr(pack, "pack"), sticker == null ? null : bool(sticker, "sticker")),
  emote_rename: ({ server, from, to }) => need(server).emotes?.rename(str(from, "from"), str(to, "to")),
  emote_stickers: ({ server, on }) => need(server).emotes?.setStickers(bool(on, "on")),
  file_cache_remove: ({ hashes }) => {
    if (!Array.isArray(hashes)) fail("invalid hashes");
    files.cacheRemove(hashes.filter((h): h is string => typeof h === "string"));
  },
  // The tab keeps files in its memory, at a size of its own (files.ts CACHE_CAP)
  set_file_cache_mb: () => fail("The browser's file cache has a fixed size"),
  send_channel_history: ({ server, channelId, targetUserId, messages }) => {
    if (!Array.isArray(messages)) fail("invalid messages");
    need(server).sendChannelHistory(u32(channelId, "channelId"), u32(targetUserId, "targetUserId"), messages);
  },
  request_channel_history: ({ server, channelId, targetUserIds }) => {
    if (!Array.isArray(targetUserIds)) fail("invalid targetUserIds");
    need(server).requestChannelHistory(
      u32(channelId, "channelId"),
      targetUserIds.map((id) => u32(id, "targetUserIds")),
    );
  },
  set_history_sharing: ({ enabled }) => {
    // To every server, and none is not a failure: the flag goes out again on
    // the next connect, from the config the settings toggle has already written.
    const on = bool(enabled, "enabled");
    for (const s of session.allSessions()) {
      s.sendControl({ SetHistorySharing: { enabled: on } });
      // The same consent hands our older keys to who joins a channel's log.
      s.account?.setShare(on);
    }
  },

  // ── moderation (admin token session) ──
  admin_login: ({ server, token }) => need(server).sendControl({ AdminLogin: { token: str(token, "token") } }),
  admin_kick: ({ server, userId, reason }) =>
    need(server).sendControl({ AdminKick: { user_id: u32(userId, "userId"), reason: str(reason, "reason") } }),
  admin_ban: ({ server, userId, reason, durationSecs, account }) =>
    need(server).sendControl({
      AdminBan: {
        user_id: u32(userId, "userId"),
        reason: str(reason, "reason"),
        duration_secs: u32(durationSecs, "durationSecs"),
        account: account === true,
      },
    }),
  admin_ban_account: ({ server, name, reason, durationSecs }) =>
    need(server).sendControl({
      AdminBanAccount: { name: str(name, "name"), reason: str(reason, "reason"), duration_secs: u32(durationSecs, "durationSecs") },
    }),
  admin_unban: ({ server, id }) => {
    if (!Number.isSafeInteger(id) || (id as number) < 0) fail("id must be a ban's id");
    return need(server).sendControl({ AdminUnban: { id } });
  },
  admin_list_bans: ({ server }) => need(server).sendControl("AdminListBans"),

  // ── voice ──
  start_transmit: async () => {
    const s = voice();
    if (s.channelId === 0) fail("Join a voice channel first");
    await audio.startTransmit();
  },
  // Never fails: whichever session transmits is the voice session, if any
  stop_transmit: () => audio.stopTransmit(),
  // Mute and deafen are one flag across servers, voice or not: every server
  // shows them next to our name.
  toggle_mute: async () => {
    const muted = await audio.toggleMute();
    for (const s of session.allSessions()) s.sendControl({ SetMuted: { muted } });
    updateConfig((c) => {
      c.muted = muted;
    });
    return muted;
  },
  toggle_deafen: async () => {
    const deafened = await audio.toggleDeafen();
    for (const s of session.allSessions()) s.sendControl({ SetDeafened: { deafened } });
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
    voice();
    audio.setUserVolume(u32(userId, "userId"), clamp(num(volume, "volume"), 0, 2));
  },
  set_user_position: ({ userId, pos, range, volume, muffle, direct }) => {
    voice();
    audio.setUserPosition(u32(userId, "userId"), position(pos, "pos"), {
      range: range == null ? undefined : num(range, "range"),
      volume: volume == null ? undefined : num(volume, "volume"),
      muffle: muffle == null ? undefined : u32(muffle, "muffle"),
      direct: direct == null ? undefined : bool(direct, "direct"),
    });
  },
  set_own_position: ({ pos, fwd }) => {
    voice();
    const p = position(pos, "pos") ?? fail("invalid pos");
    let facing: [number, number] | undefined;
    if (fwd != null) {
      if (!Array.isArray(fwd) || fwd.length !== 2) fail("invalid fwd");
      facing = [num(fwd[0], "fwd"), num(fwd[1], "fwd")];
    }
    audio.setOwnPosition(p, facing);
  },
  set_position_sync: ({ enabled }) => {
    voice();
    audio.setPositionSync(bool(enabled, "enabled"));
  },
  clear_positions: () => {
    voice();
    audio.clearPositions();
  },
  // A browser page cannot host a socket, so the game SDK is desktop-only
  get_sdk_status: () => ({
    available: false,
    enabled: false,
    port: 0,
    origins: [],
    beaconAllowed: false,
    transmitAllowed: false,
    mumblelink: false,
  }),
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
    voice();
    return audio.getUserVolume(u32(userId, "userId"));
  },
  // Audio effects. Validated here as well as in the Rust command: for a web
  // build this handler *is* the trust boundary, not a mirror of one.
  set_user_fx: ({ userId, effect, muffle, reverb, water }) => {
    voice();
    audio.setUserFx(
      u32(userId, "userId"),
      laneEffect(effect),
      clamp(num(muffle, "muffle"), 0, 10),
      clamp(num(reverb, "reverb"), 0, 10),
      clamp(num(water, "water"), 0, 10),
    );
  },
  get_source_levels: () => {
    voice();
    return audio.getSourceLevels();
  },
  get_user_fx: ({ userId }) => {
    voice();
    return audio.getUserFx(u32(userId, "userId"));
  },
  // Our own microphone's lane: the same four controls, the same validation.
  // No session needed: a preference, settable while disconnected, like the others.
  set_mic_fx: ({ effect, muffle, reverb, water }) => {
    const name = laneEffect(effect);
    const mu = clamp(num(muffle, "muffle"), 0, 10);
    const rv = clamp(num(reverb, "reverb"), 0, 10);
    const wt = clamp(num(water, "water"), 0, 10);
    updateConfig((c) => {
      c.mic_effect = name;
      c.mic_muffle = mu;
      c.mic_reverb = rv;
      c.mic_water = wt;
    });
    audio.setMicFx(name, mu, rv, wt);
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
    voice();
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
  start_mic_test: ({ monitor }) => audio.startMicTest(monitor == null ? false : bool(monitor, "monitor")),
  stop_mic_test: () => audio.stopMicTest(),
  start_output_test: () => audio.startOutputTest(),
  stop_output_test: () => audio.stopOutputTest(),
  // The browser gates the microphone, so unlike the desktop this really asks —
  // and unlike everywhere else in this file, it lets the refusal through.
  request_microphone: () => audio.requestMicrophone(),
  can_pick_output: () => audio.canPickOutput(),
  set_audio_setup_version: ({ version }) => {
    const v = u32(version, "version");
    updateConfig((c) => {
      c.audio_setup_version = v;
    });
  },
  // No session needed: the audio graph stands on its own, like the mic test
  start_spatial_test: ({ mode }) => {
    const m = proximityMode(mode);
    if (m === "off") fail("Pick 2d or 3d");
    return audio.startSpatialTest(m);
  },
  stop_spatial_test: () => audio.stopSpatialTest(),
  get_voice_stats: () => {
    voice();
    return audio.getVoiceStats();
  },
  // Web only (the self-test asks it): native voice is decoded in Rust
  get_voice_decoder: () => audio.voiceDecoder(),
  get_screen_audio_status: () => {
    voice();
    return audio.getScreenAudioStatus();
  },

  // ── screen share ──
  watch_screen_share: ({ sharerUserId }) => voice().watchScreenShare(u32(sharerUserId, "sharerUserId")),
  stop_watching_screen_share: () => voice().stopWatchingScreenShare(),
  get_screen_share_stats: () => {
    voice();
    // [frames_sent, bytes_sent] from our own share, the rest from the viewer
    const [, , recv, dropped, bytesRecv, resolution] = video.getStats();
    const [sent, bytesSent] = share.getStats();
    return [sent, bytesSent, recv, dropped, bytesRecv, resolution];
  },
  // The browser opens its own source picker, so sourceType/sourceId are unused
  start_screen_share: ({ resolution, fps }) => {
    voice();
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
  save_server: ({ name, host, port, username, acceptSelfSigned, account }) => {
    const entry: SavedServer = {
      name: str(name, "name"),
      host: str(host, "host"),
      port: u32(port, "port"),
      username: str(username, "username"),
      accept_self_signed: bool(acceptSelfSigned, "acceptSelfSigned"),
      account: account === true,
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
  // The servers open right now, reconnected on the next start. Entries arrive
  // in the stored shape (snake_case), unlike save_server's arguments.
  save_open_servers: ({ servers }) => {
    if (!Array.isArray(servers)) fail("invalid servers");
    const list = servers.map((v: unknown): SavedServer => {
      if (v === null || typeof v !== "object") fail("invalid servers");
      const s = v as Record<string, unknown>;
      return {
        name: str(s.name, "name"),
        host: str(s.host, "host"),
        port: u32(s.port, "port"),
        username: str(s.username, "username"),
        accept_self_signed: bool(s.accept_self_signed, "accept_self_signed"),
        account: s.account === true,
      };
    });
    updateConfig((c) => {
      c.open_servers = list;
    });
  },
  reset_config: () => {
    resetConfig();
    audio.applySettings(getConfig());
  },
  // The appearance blob, stored verbatim. Same contract as set_ui_prefs in
  // commands.rs, including refusing anything that is not an object.
  set_ui_prefs: ({ prefs }) => {
    if (prefs === null || typeof prefs !== "object" || Array.isArray(prefs)) {
      fail("ui_prefs must be an object");
    }
    updateConfig((c) => {
      c.ui_prefs = prefs as Record<string, unknown>;
    });
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
  set_config_u32: ({ key, value }) => {
    const n = u32(value, "value");
    updateConfig((c) => {
      switch (key) {
        case "max_conversations":
          c.max_conversations = n;
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
