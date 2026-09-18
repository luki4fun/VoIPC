// The connection: a port of client/src-tauri/src/network.rs (connect,
// server message dispatch, Signal Protocol orchestration, RTT keepalive)
// and of the chat/poke commands that need the Signal state, minus native
// I/O. Media packets are handed to audio.ts / video.ts, which see this
// session through the SessionContext interface.

import { emit } from "./events";
import { getConfig } from "./config";
import { loadWasm, wasm, type MediaKeys, type PreKeyBundleData, type SignalClient } from "./wasm";
import { connect as openTransport, type Transport } from "./transport";
import type { SessionContext } from "./types";
import type { ChannelInfo } from "../../lib/types";
import type { ProximityMode } from "../../lib/spatial";
import { audio } from "./audio";
import { video } from "./video";
import { share } from "./share";

/** Bound for the authentication response (network.rs CONNECT_TIMEOUT). */
const AUTH_TIMEOUT_MS = 10_000;
/** Datagram keepalive period: measures RTT (a dead QUIC path closes the transport). */
const KEEPALIVE_MS = 10_000;
/** Queued chat messages older than this are dropped instead of sent. */
const PENDING_MESSAGE_TTL_MS = 60_000;
/** voipc_protocol::voice::VOICE_HEADER_SIZE */
const VOICE_HEADER_SIZE = 9;

type PendingTarget = { kind: "channel"; channelId: number } | { kind: "direct"; targetUserId: number };

/** A message waiting for encryption to become available (app_state.rs PendingMessage). */
interface PendingMessage {
  target: PendingTarget;
  /** The id this message was shown under; the copy that goes out keeps it. */
  id: string;
  content: string;
  /**
   * The destruction timer this message was written under, in seconds.
   *
   * Kept with the message rather than read again when the queue drains: the
   * timer belongs to what the user wrote, and a channel whose policy changed
   * while their message sat here must not silently rewrite it.
   */
  ttlSecs?: number;
  queuedAt: number;
}

// The message envelope, the history payload and how many members are asked
// for recent chat all come from the WASM bridge now. They used to be written
// out again here, and the two copies had already drifted on the payload's
// version tag without anybody noticing, because nothing read it.

/** Fields of a decoded ServerMessage variant. */
type Body = Record<string, any>;

const utf8 = new TextEncoder();
/** Lossy like String::from_utf8_lossy. */
const utf8Decoder = new TextDecoder();

const toBytes = (v: number[] | Uint8Array): Uint8Array => (v instanceof Uint8Array ? v : Uint8Array.from(v));

/** Milliseconds since the Unix epoch truncated to u32: the ping sequence. */
const nowU32 = () => Date.now() >>> 0;

let current: Session | null = null;
/** Connects run one after another (network.rs connect_lock). */
let connectQueue: Promise<unknown> = Promise.resolve();

/** The live session, or null when disconnected. */
export function activeSession(): Session | null {
  return current;
}

/** Connect and authenticate. Resolves with our user id. */
export function connect(address: string, username: string): Promise<number> {
  const run = connectQueue.then(() => doConnect(address, username));
  connectQueue = run.catch(() => {});
  return run;
}

/** Idempotent: sends Disconnect, closes the transport and drops all Signal state. */
export async function disconnect(): Promise<void> {
  await current?.end(true);
}

async function doConnect(address: string, username: string): Promise<number> {
  // Tear down any existing connection first (e.g. after a page reload race)
  if (current) await current.end(true);

  const { host, port } = parseAddress(address);
  const api = await loadWasm();
  // Fresh Signal identity per connection: ephemeral by design, and the
  // server reassigns user ids on restart (network.rs connect_to_server).
  const session = new Session(api.newSignalClient(), username);
  try {
    session.transport = await openTransport(host, port, {
      onControl: (payload) => session.onControl(payload),
      onDatagram: (bytes) => session.onDatagram(bytes),
      onVideoPacket: (bytes) => session.onVideoPacket(bytes),
      onClosed: (reason) => session.onTransportClosed(reason),
    });
    const authenticated = session.awaitAuthentication();
    const { identity_key, prekey_bundle } = session.signal.bundle();
    session.sendControl({
      Authenticate: {
        username,
        protocol_version: api.protocolVersion(),
        app_version: api.appVersion(),
        identity_key,
        prekey_bundle,
      },
    });
    await authenticated;
    // The transport can close between Authenticated and this continuation
    if (session.isEnded) throw new Error("Server closed connection during authentication");
  } catch (e) {
    await session.end(false);
    throw e;
  }
  current = session;
  session.start();
  return session.userId;
}

/** Port of network.rs parse_address; the port defaults to 9987. */
function parseAddress(address: string): { host: string; port: number } {
  let host: string;
  let portStr: string | null;
  if (address.startsWith("[")) {
    // IPv6: [::1]:9987
    const end = address.indexOf("]");
    if (end < 0) throw new Error("Invalid IPv6 address format, expected [host]:port");
    host = address.slice(1, end);
    const rest = address.slice(end + 1);
    if (rest === "") portStr = null;
    else if (rest.startsWith(":")) portStr = rest.slice(1);
    else throw new Error("Invalid IPv6 address format, expected [host]:port");
  } else {
    const colon = address.lastIndexOf(":");
    host = colon < 0 ? address : address.slice(0, colon);
    portStr = colon < 0 ? null : address.slice(colon + 1);
  }
  let port = 9987;
  if (portStr !== null) {
    if (!/^\d{1,5}$/.test(portStr) || Number(portStr) > 65535) throw new Error("Invalid port number");
    port = Number(portStr);
  }
  if (host === "") throw new Error("Host cannot be empty");
  return { host, port };
}

export class Session implements SessionContext {
  sessionId = 0;
  /** Current channel (0 = General). Set locally on join_channel, confirmed by UserList. */
  channelId = 0;
  /** The channel's media keys: what we encrypt with, and the generation
   *  before it so a re-key does not silence packets already in flight. */
  readonly mediaKeys: MediaKeys;
  userId = 0;
  transport: Transport | null = null;
  /** The sharer we are watching (0 = none). */
  watchingUserId = 0;
  /** The channel list as last received — the source of each channel's proximity mode. */
  private channels: ChannelInfo[] = [];

  // Pairwise session tracking (app_state.rs SignalState). Keys are user ids.
  private readonly establishedSessions = new Set<number>();
  private readonly pendingSessions = new Set<number>();
  private pendingMessages: PendingMessage[] = [];
  // Everything per-channel — who is in it, who holds our sender key, which
  // channels owe a rotation, who still owes us history — lives in the Signal
  // client, which is the same `voipc_crypto::ChannelKeying` the native client
  // keeps. It used to be written out again here, and the two disagreed about
  // when a rotation happens.

  /** Voice sequence: never restarts within a connection (AES-GCM nonce = session_id ‖ sequence). */
  private voiceSequence = 0;
  /** Same rule for our own share's frames and screen audio (SHARE_FRAME_ID / SHARE_AUDIO_SEQ). */
  private videoFrameId = 0;
  private screenAudioSequence = 0;
  private auth: { resolve(): void; reject(e: Error): void } | null = null;
  private keepalive: ReturnType<typeof setInterval> | undefined;
  /** Control messages waiting for the budget; see `drainControl`. */
  private readonly controlQueue: Uint8Array[] = [];
  /**
   * Four fifths of what the server accepts. The fifth is for the difference
   * between two clocks and for the keepalives not counted here.
   */
  private readonly controlRate = wasm().controlMsgsPerSec() * 0.8;
  private controlTokens = this.controlRate;
  private controlLast = Date.now();
  private controlTimer: ReturnType<typeof setTimeout> | undefined;
  private attached = false;
  private ended = false;

  constructor(readonly signal: SignalClient, readonly username: string) {
    this.mediaKeys = wasm().newMediaKeys();
  }

  get isEnded(): boolean {
    return this.ended;
  }

  /** A channel's proximity mode, "off" for one we have never seen. */
  proximityOf(channelId: number): ProximityMode {
    return this.channels.find((c) => c.channel_id === channelId)?.proximity ?? "off";
  }

  /** Never mutates in place: the array must not be shared with anything emitted. */
  private upsertChannel(channel: ChannelInfo): void {
    const known = this.channels.some((c) => c.channel_id === channel.channel_id);
    this.channels = known
      ? this.channels.map((c) => (c.channel_id === channel.channel_id ? channel : c))
      : [...this.channels, channel];
  }

  // ── SessionContext ──

  nextVoiceSequence(): number {
    const seq = this.voiceSequence;
    this.voiceSequence = (seq + 1) >>> 0;
    return seq;
  }

  nextVideoFrameId(): number {
    const id = this.videoFrameId;
    this.videoFrameId = (id + 1) >>> 0;
    return id;
  }

  nextScreenAudioSequence(): number {
    const seq = this.screenAudioSequence;
    this.screenAudioSequence = (seq + 1) >>> 0;
    return seq;
  }

  sendDatagram(bytes: Uint8Array): void {
    this.transport?.sendDatagram(bytes);
  }

  sendVideoFrame(body: Uint8Array): boolean {
    return this.transport?.sendVideoFrame(body) ?? false;
  }

  sendControl(msg: unknown): void {
    if (!this.transport) return;
    let payload: Uint8Array;
    try {
      payload = wasm().encodeClientMsg(msg);
    } catch (e) {
      console.error("failed to encode client message:", e);
      return;
    }
    this.controlQueue.push(payload);
    this.drainControl();
  }

  /**
   * Let out as many queued control messages as the budget allows, and arrange
   * to be called again for the rest (network.rs ControlPacer).
   *
   * The server charges a token per frame before it decodes one and drops a
   * frame that cannot pay, without saying so. An honest client reaches that
   * rate on a busy connect — a pre-key bundle request per person, then a
   * sender key per person per channel — and what it would lose there is the
   * one thing it cannot afford to: a key that never arrives is a member who
   * cannot read the channel, with nothing on screen to say why.
   */
  private drainControl(): void {
    if (!this.transport) {
      this.controlQueue.length = 0;
      return;
    }
    const now = Date.now();
    this.controlTokens = Math.min(
      this.controlRate,
      this.controlTokens + ((now - this.controlLast) / 1000) * this.controlRate,
    );
    this.controlLast = now;
    while (this.controlQueue.length > 0 && this.controlTokens >= 1) {
      this.controlTokens -= 1;
      this.transport.sendControl(this.controlQueue.shift()!);
    }
    if (this.controlQueue.length > 0 && this.controlTimer === undefined) {
      const waitMs = Math.ceil(((1 - this.controlTokens) / this.controlRate) * 1000);
      this.controlTimer = setTimeout(() => {
        this.controlTimer = undefined;
        this.drainControl();
      }, waitMs);
    }
  }

  // ── lifecycle ──

  awaitAuthentication(): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.auth = null;
        reject(new Error("Timed out waiting for the authentication response"));
      }, AUTH_TIMEOUT_MS);
      this.auth = {
        resolve: () => {
          clearTimeout(timer);
          this.auth = null;
          resolve();
        },
        reject: (e) => {
          clearTimeout(timer);
          this.auth = null;
          reject(e);
        },
      };
    });
  }

  /** After Authenticated (network.rs:263-330, 540-565). */
  start(): void {
    audio.attach(this);
    video.attach(this);
    share.attach(this);
    this.attached = true;

    // First ping: gives the UI an RTT reading right away.
    this.sendPing();

    // Notify the server of persisted mute/deafen state
    if (audio.muted) this.sendControl({ SetMuted: { muted: true } });
    if (audio.deafened) this.sendControl({ SetDeafened: { deafened: true } });
    // ...and whether we answer requests for recent chat, so the people here
    // can see who asking would reach.
    if (getConfig().share_channel_history) this.sendControl({ SetHistorySharing: { enabled: true } });

    // RTT probe only: media and control share one QUIC connection, so a dead
    // path surfaces as connection-lost instead of a separate watchdog.
    this.keepalive = setInterval(() => this.sendPing(), KEEPALIVE_MS);
  }

  /** Ping datagram whose sequence carries the send time (echoed in the Pong). */
  private sendPing(): void {
    this.sendDatagram(wasm().buildPingPacket(this.sessionId, nowU32()));
  }

  /** Tear down: stop media, optionally send Disconnect, close, drop Signal state. */
  async end(sendDisconnect: boolean): Promise<void> {
    if (this.ended) return;
    this.ended = true;
    if (current === this) current = null;
    clearInterval(this.keepalive);
    if (this.attached) {
      this.attached = false;
      audio.detach();
      video.detach();
      share.detach();
    }
    if (sendDisconnect) {
      // Whatever was still waiting for the pacer is moot now, and the goodbye
      // is not: it goes out ahead of the queue rather than behind it.
      this.controlQueue.length = 0;
      this.sendControl("Disconnect");
    }
    // After the goodbye, so a queue that was over budget cannot leave a timer
    // running against a transport that is about to close.
    clearTimeout(this.controlTimer);
    this.controlTimer = undefined;
    this.controlQueue.length = 0;
    if (this.transport) await this.transport.close();
    this.mediaKeys.free();
    this.signal.free();
  }

  onTransportClosed(reason: string): void {
    if (this.auth) {
      // doConnect ends the session
      this.auth.reject(new Error(reason));
      return;
    }
    if (this.ended) return;
    emit("connection-lost", { reason });
    void this.end(false);
  }

  // ── inbound ──

  onControl(payload: Uint8Array): void {
    let msg: unknown;
    try {
      msg = wasm().decodeServerMsg(payload);
    } catch (e) {
      console.warn("failed to decode server message:", e);
      return;
    }
    try {
      this.handleServerMessage(msg);
    } catch (e) {
      console.error("server message handler failed:", e);
    }
  }

  onVideoPacket(bytes: Uint8Array): void {
    if (this.attached) video.onVideoPacket(bytes);
  }

  /** network.rs udp_receiver_task dispatch by packet type. Plaintext media types are never accepted. */
  onDatagram(bytes: Uint8Array): void {
    switch (bytes[0]) {
      case 0x05:
        if (this.attached) audio.onVoicePacket(bytes);
        break;
      case 0x02:
        if (this.attached) audio.onEotPacket(bytes);
        break;
      case 0x15:
        if (this.attached) audio.onScreenAudioPacket(bytes);
        break;
      case 0x06:
        if (this.attached) audio.onPositionPacket(bytes);
        break;
      case 0x04:
        this.onPong(bytes);
        break;
      case 0x03: {
        // Ping from the server: reply with a Pong
        if (bytes.length < VOICE_HEADER_SIZE) break;
        const pong = bytes.slice();
        pong[0] = 0x04;
        this.sendDatagram(pong);
        break;
      }
      default:
        break;
    }
  }

  /** Echo of our keepalive ping: the sequence field carries our send time. */
  private onPong(bytes: Uint8Array): void {
    let sent: number;
    try {
      sent = wasm().parseVoiceHeader(bytes).sequence;
    } catch {
      return;
    }
    const rtt = (nowU32() - sent) >>> 0;
    // Guard against clock weirdness producing huge values
    if (rtt < 60_000) emit("latency-update", { ms: rtt });
  }

  /** network.rs handle_server_message. */
  private handleServerMessage(msg: unknown): void {
    let tag: string;
    let b: Body = {};
    if (typeof msg === "string") {
      tag = msg;
    } else {
      const entries = Object.entries(msg as Record<string, Body>);
      if (entries.length !== 1) return;
      [tag, b] = entries[0];
    }

    switch (tag) {
      case "Authenticated":
        this.userId = b.user_id;
        this.sessionId = b.session_id;
        this.auth?.resolve();
        break;
      case "AuthError":
        this.auth?.reject(new Error(`Authentication failed: ${b.reason}`));
        break;
      case "ChannelList":
        // Our own copy: the emitted array ends up in the UI's store
        this.channels = [...b.channels];
        emit("channel-list", b.channels);
        break;
      case "UserList":
        this.onUserList(b.channel_id, b.users);
        break;
      case "UserJoined": {
        // Pairwise sessions are needed in every channel (DMs, pokes)
        if (b.user.user_id !== this.userId) this.requestPrekeyBundlesForUsers([b.user]);
        // Somebody joined a channel we are in. Nobody else hands them our
        // sender key: a text channel does not move us, so we get no UserList
        // of our own, and waiting for them to key us first only works while
        // they hold no session with us (network.rs UserJoined).
        if (b.user.user_id !== this.userId && this.signal.inChannel(this.channelId, b.user.channel_id)) {
          this.signal.addMember(b.user.channel_id, b.user.user_id);
          if (this.establishedSessions.has(b.user.user_id)) {
            this.distributeSenderKeyToUser(b.user.channel_id, b.user.user_id);
          }
        }
        emit("user-joined", b.user);
        break;
      }
      case "UserLeft": {
        const uid: number = b.user_id;
        // Leaving a text channel is not leaving the server: the person is
        // still online and still someone we DM. Only that channel's keys go.
        if (this.isTextChannel(b.channel_id)) {
          this.signal.dropMember(b.channel_id, uid);
          if (uid === this.userId) {
            // Our own chain there goes with the subscription: leaving it
            // behind is what let a re-join write on the key every former
            // member still had.
            this.signal.forgetChannel(this.userId, b.channel_id);
          } else if (this.signal.isTextChannel(b.channel_id)) {
            // They keep the chain key they were given; our next message here
            // starts a fresh one they cannot read.
            this.signal.noteStale(b.channel_id);
          }
          emit("user-left", { user_id: uid, channel_id: b.channel_id });
          break;
        }
        // The pairwise session stays: it is per person and per connection, not
        // per room. They are still someone we DM and may still be in text
        // channels with us. Dropping it made their next appearance anywhere
        // run X3DH a second time — two session states for one person — and
        // made us skip handing them our sender key next door.
        // Only the channel they left: walking out of a voice room says nothing
        // about the text channels we still share with them, and forgetting
        // those keys leaves both sides unreadable with nothing left to re-key.
        this.signal.dropMember(b.channel_id, uid);
        if (uid !== this.userId && b.channel_id === this.channelId) {
          this.signal.noteStale(b.channel_id);
          // Their copy of the room's media key stops working from the next
          // generation on, if we are the one elected to mint it.
          this.rotateMediaKeyIfMinter(b.channel_id);
        }
        audio.onUserLeft(uid);
        emit("user-left", { user_id: uid, channel_id: b.channel_id });
        break;
      }
      case "UserMuted":
        emit("user-muted", { user_id: b.user_id, muted: b.muted });
        break;
      case "UserDeafened":
        emit("user-deafened", { user_id: b.user_id, deafened: b.deafened });
        break;
      case "UserHistorySharing":
        emit("user-history-sharing", { user_id: b.user_id, enabled: b.enabled });
        break;
      case "Ping":
        // Reply to the server keepalive to prevent the idle disconnect
        this.sendControl({ Ping: { timestamp: b.timestamp } });
        break;
      case "Pong":
        // Displayed latency comes from the UDP keepalive RTT (see network.rs)
        break;
      case "ServerShutdown":
        emit("connection-lost", { reason: `Server shutdown: ${b.reason}` });
        break;
      case "MovedToChannel":
        break;
      case "ChannelCreated":
        this.upsertChannel(b.channel);
        emit("channel-created", b.channel);
        break;
      case "ChannelDeleted":
        this.channels = this.channels.filter((c) => c.channel_id !== b.channel_id);
        this.signal.forgetChannel(this.userId, b.channel_id);
        emit("channel-deleted", { channel_id: b.channel_id });
        break;
      case "ChannelError":
        emit("channel-error", { reason: b.reason });
        break;
      case "ChannelUpdated":
        this.upsertChannel(b.channel);
        // The mode of the channel we are in may have just changed
        audio.setProximityMode(this.proximityOf(this.channelId));
        emit("channel-updated", b.channel);
        break;
      case "Kicked":
        emit("kicked", { channel_id: b.channel_id, reason: b.reason });
        break;
      case "ChannelUsers":
        emit("channel-users", { channel_id: b.channel_id, users: b.users });
        break;
      case "InviteReceived":
        emit("invite-received", {
          channel_id: b.channel_id,
          channel_name: b.channel_name,
          invited_by: b.invited_by,
        });
        break;
      case "InviteAccepted":
        emit("invite-accepted", { channel_id: b.channel_id, user_id: b.user_id });
        break;
      case "InviteDeclined":
        emit("invite-declined", { channel_id: b.channel_id, user_id: b.user_id });
        break;
      case "PokeReceived":
        this.onPokeReceived(b.from_user_id, b.from_username, toBytes(b.ciphertext), b.message_type);
        break;
      case "ScreenShareStarted":
        // Our own share was accepted; anyone else's is news for the UI
        if (b.user_id === this.userId) share.onStarted();
        emit("screenshare-started", { user_id: b.user_id, username: b.username, resolution: b.resolution });
        break;
      case "ScreenShareStopped":
        emit("screenshare-stopped", { user_id: b.user_id });
        break;
      case "WatchingScreenShare":
        emit("watching-screenshare", { sharer_user_id: b.sharer_user_id, codec: b.codec });
        video
          .startWatching(b.sharer_user_id, b.codec)
          .catch((e) => console.error("failed to start watching:", e));
        break;
      case "StoppedWatchingScreenShare":
        emit("stopped-watching-screenshare", { reason: b.reason });
        video.stopWatching();
        break;
      case "ViewerCountChanged":
        emit("viewer-count-changed", { viewer_count: b.viewer_count });
        break;
      case "KeyframeRequested":
        // A viewer needs an IDR now. The event exists for parity with the
        // native client, whose UI relays it back through set_keyframe_requested.
        share.requestKeyframe();
        emit("keyframe-requested");
        break;
      case "VideoLossReported":
        // A viewer of our share lost frames: step the encoder down
        share.onLossReport(b.frames_dropped);
        break;
      case "ScreenShareError":
        // A refused StartScreenShare (already sharing, General lobby) must also
        // tear down the capture the browser already granted us.
        share.onServerError();
        emit("screenshare-error", { reason: b.reason });
        break;
      case "PreKeyBundle":
        this.onPrekeyBundle(b.user_id, b.bundle);
        break;
      case "PreKeyBundleUnavailable":
        // Remove from pending so we don't loop
        this.pendingSessions.delete(b.user_id);
        break;
      case "IdentityKeyChanged":
        emit("identity-key-changed", { user_id: b.user_id, new_identity_key: b.new_identity_key });
        break;
      case "EncryptedDirectChatMessage":
        this.onEncryptedDirectMessage(
          b.from_user_id,
          b.from_username,
          b.to_user_id,
          toBytes(b.ciphertext),
          b.message_type,
          Number(b.timestamp),
        );
        break;
      case "EncryptedChannelChatMessage":
        this.onEncryptedChannelMessage(
          b.channel_id,
          b.user_id,
          b.username,
          toBytes(b.ciphertext),
          Number(b.timestamp),
        );
        break;
      case "SenderKeyReceived":
        this.onSenderKeyReceived(b.channel_id, b.from_user_id, toBytes(b.distribution_message), b.message_type);
        break;
      case "MediaKeyReceived":
        this.onMediaKeyReceived(b.channel_id, b.from_user_id, toBytes(b.encrypted_media_key), b.message_type);
        break;
      case "AdminStatus":
        emit("admin-status", { user_id: b.user_id, is_admin: b.is_admin });
        break;
      case "AdminError":
        emit("admin-error", { reason: b.reason });
        break;
      case "AdminBans":
        emit("admin-bans", {
          bans: (b.bans as { ip: string; expires_in_secs?: bigint | number }[]).map((x) => ({
            ip: x.ip,
            expires_in_secs: x.expires_in_secs == null ? null : Number(x.expires_in_secs),
          })),
        });
        break;
      case "Disconnected":
        // The server closes the session right after; the UI must not auto-reconnect
        emit("server-disconnected", { reason: b.reason });
        break;
      case "ChannelHistoryRequested":
        emit("channel-history-requested", { channel_id: b.channel_id, from_user_id: b.from_user_id });
        break;
      case "ChannelHistoryReceived":
        this.onChannelHistoryReceived(
          b.channel_id,
          b.from_user_id,
          b.from_username,
          toBytes(b.ciphertext),
          b.message_type,
        );
        break;
      default:
        console.warn("unhandled server message:", tag);
    }
  }

  /** The members of a roster worth asking for recent chat: the ones who say
   *  they share it, ourselves excluded, and of those the few the shared
   *  picker chooses (channel_state.rs history_sources). */
  private historySources(users: { user_id: number; shares_history?: boolean }[]): Uint32Array {
    const sharers = Uint32Array.from(
      users.filter((u) => u.user_id !== this.userId && u.shares_history).map((u) => u.user_id),
    );
    return wasm().pickHistorySources(sharers);
  }

  /** Whether a channel id names a text channel, per the list the server sent. */
  isTextChannel(channelId: number): boolean {
    return this.channels.some((c) => c.channel_id === channelId && c.text);
  }

  private onUserList(channelId: number, users: { user_id: number; shares_history?: boolean }[]): void {
    // A text channel is a subscription, not a move: nothing below applies —
    // no media key, no room, no share, and we stay where we stand.
    if (this.isTextChannel(channelId)) {
      const newly = this.signal.joinTextChannel(channelId);
      // Who a sender key may go to here, and who one may come from — both
      // directions ask (distributeSenderKeyToUser, onSenderKeyReceived).
      this.signal.setMembers(channelId, Uint32Array.from(users.map((u) => u.user_id)));
      if (newly) {
        this.signal.resetChannel(this.userId, channelId);
        this.signal.wantHistoryFrom(channelId, this.historySources(users));
      }
      this.requestPrekeyBundlesForUsers(users);
      // A voice channel gets its sender keys through the join dance; here
      // nobody moved, so we key up with the members we already have a session
      // with ourselves.
      for (const user of users) {
        if (user.user_id !== this.userId && this.establishedSessions.has(user.user_id)) {
          this.distributeSenderKeyToUser(channelId, user.user_id);
        }
      }
      emit("user-list", { channel_id: channelId, users });
      return;
    }

    // Server-initiated moves (create_channel auto-join, kicks, invites) land here
    const oldChannel = this.channelId;
    this.channelId = channelId;
    // The room we left is not ours to key any more; the one we joined is
    // The room we left is not ours to key any more: roster, the record of who
    // holds our chain there, and the chain itself — the same as walking out of
    // a text channel.
    if (oldChannel !== channelId) this.signal.forgetChannel(this.userId, oldChannel);
    this.signal.setMembers(channelId, Uint32Array.from(users.map((u) => u.user_id)));
    if (oldChannel !== channelId) {
      // The new channel's key comes from an existing member over Signal,
      // or we generate one if alone (below, once the user list is known)
      this.mediaKeys.clear();
      this.signal.resetChannel(this.userId, channelId);
      this.signal.wantHistoryFrom(channelId, this.historySources(users));
      if (this.watchingUserId !== 0) {
        this.watchingUserId = 0;
        this.sendControl("StopWatchingScreenShare");
        emit("screen-share-force-stopped");
        video.stopWatching();
      }
      // Our own share belonged to the old channel's members and its media key
      if (share.sharing) share.stop();
      audio.onChannelChanged(this.proximityOf(channelId));
    }

    // Pairwise sessions are needed in every channel (DMs, pokes), not just for channel chat
    this.requestPrekeyBundlesForUsers(users);

    // Media keys never touch the server: the first member generates one,
    // everyone else receives it from a member over a pairwise Signal session
    // Which member mints it is the same election that picks who re-keys after
    // somebody leaves: the lowest user id in the roster. "Whoever is alone
    // here" was the old rule, but two people arriving in the same instant each
    // see the other in their first roster, so neither is alone and the channel
    // ends up with no key at all. Ids only increase, so a newcomer never mints
    // over a key that already exists.
    if (
      channelId !== 0 &&
      !this.mediaKeys.hasChannel(channelId) &&
      this.signal.mediaKeyMinter(channelId) === this.userId
    ) {
      this.mintMediaKey(channelId, 0);
    }

    emit("user-list", { channel_id: channelId, users });
  }

  // ── E2E helpers (network.rs request_prekey_bundles_for_users .. drain_pending_channel_messages) ──

  private requestPrekeyBundlesForUsers(users: { user_id: number }[]): void {
    for (const user of users) {
      const uid = user.user_id;
      // 0 is nobody: a join or leave in a channel that hides who is in it
      // reaches outsiders as a count, without a person attached.
      if (uid === 0 || uid === this.userId) continue;
      if (this.establishedSessions.has(uid) || this.pendingSessions.has(uid)) continue;
      this.pendingSessions.add(uid);
      this.sendControl({ RequestPreKeyBundle: { target_user_id: uid } });
    }
  }

  /** Establish the pairwise session, then hand over our sender key (and media key) for the current channel. */
  private onPrekeyBundle(remoteUserId: number, bundle: PreKeyBundleData): void {
    try {
      this.signal.establishSession(remoteUserId, bundle);
    } catch (e) {
      console.warn(`failed to establish E2E session with ${remoteUserId}:`, e);
      this.pendingSessions.delete(remoteUserId);
      return;
    }
    this.pendingSessions.delete(remoteUserId);
    this.establishedSessions.add(remoteUserId);

    this.drainPendingDms(remoteUserId);

    // The channel we stand in and every text channel we are in; the server
    // drops a distribution for a channel either of us is not in.
    for (const channelId of [this.channelId, ...this.signal.textChannels()]) {
      if (channelId !== 0) this.distributeSenderKeyToUser(channelId, remoteUserId);
    }
  }

  private distributeSenderKeyToUser(channelId: number, targetUserId: number): void {
    // The server relays a distribution only between two members of the channel
    // it names and drops the rest; recording one of those as distributed makes
    // reciprocation skip a member who never received anything.
    if (!this.signal.isMember(channelId, targetUserId)) return;
    let encrypted: { ciphertext: Uint8Array; message_type: number };
    try {
      const distribution = this.signal.createSenderKeyDistribution(this.userId, channelId);
      encrypted = this.signal.encrypt(targetUserId, distribution);
    } catch (e) {
      console.warn(`failed to distribute sender key to ${targetUserId}:`, e);
      return;
    }
    this.sendControl({
      DistributeSenderKey: {
        channel_id: channelId,
        target_user_id: targetUserId,
        distribution_message: encrypted.ciphertext,
        message_type: encrypted.message_type,
      },
    });
    this.distributeMediaKeyToUser(channelId, targetUserId);
    this.signal.recordDistributed(channelId, targetUserId);
  }

  /** Send our media key for `channelId` over the pairwise session, if we hold one. */
  private distributeMediaKeyToUser(channelId: number, targetUserId: number): void {
    if (!this.mediaKeys.hasChannel(channelId)) return;
    const bytes = this.mediaKeys.toBytes();
    if (!bytes) return;
    try {
      const { ciphertext, message_type } = this.signal.encrypt(targetUserId, bytes);
      this.sendControl({
        DistributeMediaKey: {
          channel_id: channelId,
          target_user_id: targetUserId,
          encrypted_media_key: ciphertext,
          message_type,
        },
      });
    } catch (e) {
      console.warn(`failed to distribute media key to ${targetUserId}:`, e);
    }
  }

  /** Mint a generation of our own and tell the UI, if it superseded. */
  private mintMediaKey(channelId: number, keyId: number): boolean {
    try {
      if (!this.mediaKeys.generate(channelId, keyId, this.userId)) return false;
    } catch (e) {
      console.error("media key generation failed:", e);
      return false;
    }
    emit("media-key-installed", { channel_id: channelId, key_id: keyId });
    return true;
  }

  /**
   * Mint the channel's next media key and hand it to whoever is left, if we
   * are the one elected to (network.rs rotate_media_key_if_minter).
   *
   * A member who walks out keeps the key of the room they were in, so the key
   * does not outlive the membership it was given for. Nobody is asked who does
   * it: every member elects the lowest remaining user id from the roster they
   * hold, and `MediaKeys.install` settles a tie the same way everywhere.
   */
  private rotateMediaKeyIfMinter(channelId: number): void {
    if (this.signal.mediaKeyMinter(channelId) !== this.userId) return;
    // The one after ours, or the channel's first where we hold none — the
    // member who held it has left and nobody else is going to send one. Same
    // answer as the desktop client, from the same Rust (media_keys.rs
    // next_generation), because this is the rule the two used to disagree on.
    const nextId = this.mediaKeys.nextGeneration(channelId);
    if (!this.mintMediaKey(channelId, nextId)) return;
    for (const uid of this.signal.othersIn(channelId, this.userId)) {
      this.distributeMediaKeyToUser(channelId, uid);
    }
  }

  /** Install a member's media key if it supersedes what we hold for the channel we are in. */
  private onMediaKeyReceived(channelId: number, fromUserId: number, ciphertext: Uint8Array, messageType: number): void {
    // The same check the sender key makes, and for a bigger prize: this is the
    // key our microphone encrypts under. The server relays a media key only
    // between two members of the channel it names — but the server is the
    // adversary here, so without this anybody who can open a pairwise session
    // with us hands us the key we then speak under.
    if (!this.signal.sharesChannelWith(this.channelId, channelId, fromUserId)) {
      console.warn(`media key from ${fromUserId} for channel ${channelId}: not a member, dropped`);
      return;
    }
    let plaintext: Uint8Array;
    try {
      plaintext = this.signal.decrypt(fromUserId, ciphertext, messageType);
    } catch (e) {
      console.warn(`media key from ${fromUserId} rejected:`, e);
      return;
    }
    // A PreKeySignalMessage establishes the session on our side as well
    if (messageType === 1) this.markEstablished(fromUserId);
    if (channelId !== this.channelId) return;
    try {
      // `install` decides: a key for another channel is refused outright, a
      // later generation wins, and within one generation the lower minter
      // does — so two members who disagreed about the roster for a moment
      // converge instead of going deaf to each other.
      if (this.mediaKeys.install(plaintext, this.channelId)) {
        emit("media-key-installed", { channel_id: channelId, key_id: this.mediaKeys.keyId ?? 0 });
      }
    } catch (e) {
      console.warn(`media key from ${fromUserId} rejected:`, e);
    }
  }

  /** Decrypt pairwise, process the distribution, reciprocate, drain queued channel messages. */
  private onSenderKeyReceived(channelId: number, fromUserId: number, ciphertext: Uint8Array, messageType: number): void {
    // The mirror of the check distributeSenderKeyToUser makes outbound. The
    // server relays a distribution only between two members — but the server
    // is the adversary here, and without this a stranger with a colluding
    // relay installs a key for a channel they were never in and writes to it.
    if (!this.signal.sharesChannelWith(this.channelId, channelId, fromUserId)) {
      console.warn(`sender key from ${fromUserId} for channel ${channelId}: not a member, dropped`);
      return;
    }
    try {
      const plaintext = this.signal.decrypt(fromUserId, ciphertext, messageType);
      this.signal.processSenderKeyDistribution(fromUserId, channelId, plaintext);
    } catch (e) {
      console.warn(`failed to process sender key from ${fromUserId}:`, e);
      return;
    }
    if (messageType === 1) this.markEstablished(fromUserId);
    this.signal.recordReceived(channelId, fromUserId);

    if (!this.signal.hasDistributed(channelId, fromUserId)) {
      this.distributeSenderKeyToUser(channelId, fromUserId);
    }
    this.drainPendingChannelMessages(channelId);

    // A member whose sender key arrives holds a pairwise session with us (they
    // just used it), so this is the moment to ask them for recent chat — once
    // each, for as many sharers as we lined up.
    if (channelId !== 0 && this.signal.takeHistoryWanted(channelId, fromUserId)) {
      this.sendControl({ RequestChannelHistory: { channel_id: channelId, target_user_id: fromUserId } });
    }
  }

  /** Recent channel chat for a newcomer, pairwise-encrypted (commands.rs send_channel_history). */
  sendChannelHistory(channelId: number, targetUserId: number, messages: unknown[]): void {
    // The channel travels inside the ciphertext, not only on the envelope the
    // server writes (envelope.rs history_payload).
    const payload = wasm().historyPayload(channelId, JSON.stringify(messages));
    if (payload.length > wasm().maxRelayCiphertext()) throw new Error("history payload too large");
    const { ciphertext, message_type } = this.signal.encrypt(targetUserId, payload);
    this.sendControl({
      SendChannelHistory: { channel_id: channelId, target_user_id: targetUserId, ciphertext, message_type },
    });
  }

  private onChannelHistoryReceived(
    channelId: number,
    fromUserId: number,
    fromUsername: string,
    ciphertext: Uint8Array,
    messageType: number,
  ): void {
    // A conversation from somebody the roster does not put in that channel
    // with us is not history, it is an injection: we would file it, show it
    // and hand it to the next newcomer as `shared`.
    if (!this.signal.sharesChannelWith(this.channelId, channelId, fromUserId)) {
      console.warn(`channel history from ${fromUserId} for channel ${channelId}: not a member, dropped`);
      return;
    }
    let messages: unknown[];
    try {
      const plaintext = this.signal.decrypt(fromUserId, ciphertext, messageType);
      messages = JSON.parse(wasm().openHistoryPayload(channelId, plaintext));
    } catch (e) {
      console.warn(`channel history from ${fromUserId} rejected:`, e);
      return;
    }
    if (messageType === 1) this.markEstablished(fromUserId);
    emit("channel-history-received", {
      channel_id: channelId,
      from_user_id: fromUserId,
      from_username: fromUsername,
      messages,
    });
  }

  private markEstablished(userId: number): void {
    this.establishedSessions.add(userId);
    this.pendingSessions.delete(userId);
  }

  /** Take the queued messages for `matches`, dropping those older than the TTL. */
  private takePending(
    matches: (t: PendingTarget) => boolean,
  ): { id: string; content: string; ttlSecs?: number }[] {
    const now = Date.now();
    const send: { id: string; content: string; ttlSecs?: number }[] = [];
    const remaining: PendingMessage[] = [];
    let expired = 0;
    for (const m of this.pendingMessages) {
      if (!matches(m.target)) remaining.push(m);
      else if (now - m.queuedAt < PENDING_MESSAGE_TTL_MS) send.push({ id: m.id, content: m.content, ttlSecs: m.ttlSecs });
      else expired++;
    }
    if (expired > 0) console.warn(`dropped ${expired} expired pending messages`);
    this.pendingMessages = remaining;
    return send;
  }

  private drainPendingDms(targetUserId: number): void {
    for (const { id, content, ttlSecs } of this.takePending((t) => t.kind === "direct" && t.targetUserId === targetUserId)) {
      try {
        const { ciphertext, message_type } = this.signal.encrypt(
          targetUserId,
          wasm().envelope(id, content, ttlSecs),
        );
        this.sendControl({ SendEncryptedDirectMessage: { target_user_id: targetUserId, ciphertext, message_type } });
      } catch (e) {
        console.warn(`failed to encrypt queued DM to ${targetUserId}:`, e);
      }
    }
  }

  private drainPendingChannelMessages(channelId: number): void {
    const pending = this.takePending((t) => t.kind === "channel" && t.channelId === channelId);
    if (pending.length === 0) return;
    // Written before we had anybody to send them to, and somebody may have
    // left the channel in between — in which case our chain is stale and the
    // leaver can still read along it. Sending is what costs a rotation, and
    // this is a send (network.rs drain_pending_channel_messages).
    this.rotateSenderKeyIfStale(channelId);
    for (const { id, content, ttlSecs } of pending) {
      try {
        const ciphertext = this.signal.groupEncrypt(
          this.userId,
          channelId,
          wasm().envelope(id, content, ttlSecs),
        );
        this.sendControl({ SendEncryptedChannelMessage: { channel_id: channelId, ciphertext } });
      } catch (e) {
        console.warn(`failed to encrypt queued channel message for ${channelId}:`, e);
      }
    }
  }

  private onEncryptedDirectMessage(
    fromUserId: number,
    fromUsername: string,
    toUserId: number,
    ciphertext: Uint8Array,
    messageType: number,
    timestamp: number,
  ): void {
    // The server echoes our own DMs back; the sender emits locally and
    // decrypting our own ciphertext would corrupt the ratchet.
    if (fromUserId === this.userId) return;
    const event = { from_user_id: fromUserId, from_username: fromUsername, to_user_id: toUserId, timestamp, encrypted: true };
    try {
      const plaintext = this.signal.decrypt(fromUserId, ciphertext, messageType);
      if (messageType === 1) this.markEstablished(fromUserId);
      // A DM carries the same envelope a channel message does since 0.9.0;
      // anything else reads as the text itself.
      const { id, text, ttl_secs } = wasm().openEnvelope(plaintext);
      emit("direct-chat-message", { ...event, content: text, message_id: id, ttl_secs });
    } catch (e) {
      console.warn(`failed to decrypt direct message from ${fromUserId}:`, e);
      emit("direct-chat-message", {
        ...event,
        content: "[encrypted message — decryption failed]",
        decryption_failed: true,
      });
    }
  }

  private onEncryptedChannelMessage(
    channelId: number,
    userId: number,
    username: string,
    ciphertext: Uint8Array,
    timestamp: number,
  ): void {
    // Our own message, echoed back: the local copy was shown when it was sent,
    // and a second one only has our own sender chain to decrypt with.
    if (userId === this.userId) return;
    const event = { channel_id: channelId, user_id: userId, username, timestamp, encrypted: true };
    // A message for a channel we are not in has no business being shown, let
    // alone stored under that channel's name. The ciphertext is bound to its
    // channel too (group.rs decrypt_group_message); this is the cheap half.
    if (!this.signal.inChannel(this.channelId, channelId)) {
      console.warn(`dropped a message for channel ${channelId}, which we are not in`);
      return;
    }
    try {
      const plaintext = this.signal.groupDecrypt(userId, channelId, ciphertext);
      const { id, text, ttl_secs } = wasm().openEnvelope(plaintext);
      // What the sender says this message's life is; the store takes the
      // shorter of it and the channel's own timer (expiryFor, chat-rules.ts).
      emit("channel-chat-message", { ...event, content: text, message_id: id, ttl_secs });
    } catch (e) {
      console.warn(`failed to decrypt channel message from ${userId}:`, e);
      emit("channel-chat-message", {
        ...event,
        content: "[encrypted message — decryption failed]",
        decryption_failed: true,
      });
    }
  }

  private onPokeReceived(fromUserId: number, fromUsername: string, ciphertext: Uint8Array, messageType: number): void {
    let message = "";
    try {
      const plaintext = this.signal.decrypt(fromUserId, ciphertext, messageType);
      if (messageType === 1) this.markEstablished(fromUserId);
      message = utf8Decoder.decode(plaintext);
    } catch (e) {
      console.warn(`failed to decrypt poke from ${fromUserId}:`, e);
    }
    emit("poke-received", { from_user_id: fromUserId, from_username: fromUsername, message });
    // Also inject the poke as a DM so it appears in chat history
    if (message !== "") {
      emit("direct-chat-message", {
        from_user_id: fromUserId,
        from_username: fromUsername,
        to_user_id: this.userId,
        content: `[Poke] ${message}`,
        timestamp: Date.now(),
      });
    }
  }

  // ── commands that need the Signal state (commands.rs) ──

  /**
   * join_channel / accept_invite: clear the viewer state before the server
   * moves us. Channel id, media key and sender-key state switch only when the
   * server confirms the move (UserList), so a rejected join (wrong password,
   * channel full) leaves the current channel's voice working.
   */
  clearWatching(): void {
    this.watchingUserId = 0;
  }

  watchScreenShare(sharerUserId: number): void {
    this.sendControl({ WatchScreenShare: { sharer_user_id: sharerUserId } });
    this.watchingUserId = sharerUserId;
  }

  /** No-op if not watching. */
  stopWatchingScreenShare(): void {
    if (this.watchingUserId === 0) return;
    this.stopWatching();
    video.stopWatching();
  }

  /** SessionContext: used by the video module when it gives up on a stream. */
  stopWatching(): void {
    if (this.watchingUserId === 0) return;
    this.sendControl("StopWatchingScreenShare");
    this.watchingUserId = 0;
  }

  /** Poke: pairwise-encrypted; fails without a Signal session to the target. */
  sendPoke(targetUserId: number, message: string): void {
    let encrypted: { ciphertext: Uint8Array; message_type: number };
    try {
      encrypted = this.signal.encrypt(targetUserId, utf8.encode(message));
    } catch (e) {
      throw new Error(`poke encryption failed: ${errorText(e)}`);
    }
    this.sendControl({
      SendPoke: { target_user_id: targetUserId, ciphertext: encrypted.ciphertext, message_type: encrypted.message_type },
    });
    // Emit the poke as a local DM for the sender's chat history
    if (message !== "") {
      emit("direct-chat-message", {
        from_user_id: this.userId,
        from_username: this.username,
        to_user_id: targetUserId,
        content: `[Poke] ${message}`,
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Rotate our own sender key for a channel somebody has left, and hand the
   * new one to the members still there (network.rs rotate_sender_key_if_stale).
   *
   * Before sending rather than on the leave itself, so an idle member never
   * pays for it: only whoever writes next does.
   */
  private rotateSenderKeyIfStale(channelId: number): void {
    // The chain is forgotten before the target list is read, not after: in a
    // two-person channel the one member who held our key is also the one who
    // left, and returning early on that empty list without forgetting is how
    // the next person to join was handed the chain the leaver still had.
    for (const targetUserId of this.signal.takeRotationTargets(this.userId, channelId)) {
      this.distributeSenderKeyToUser(channelId, targetUserId);
    }
  }

  /** Sender-key encrypted channel message; queued until a sender key was distributed. */
  sendChannelMessage(content: string, channelId = this.channelId, ttlSecs?: number): void {
    if (channelId === 0) throw new Error("Chat is not available in the lobby");

    this.rotateSenderKeyIfStale(channelId);

    // The id travels inside the ciphertext, so our own echo and every
    // receiver's copy file the message under the same one.
    const messageId = wasm().newMessageId();
    let ciphertext: Uint8Array | null = null;
    if (this.signal.anyoneHoldsOurKey(channelId)) {
      try {
        ciphertext = this.signal.groupEncrypt(
          this.userId,
          channelId,
          wasm().envelope(messageId, content, ttlSecs),
        );
      } catch (e) {
        console.info("group encryption not ready, queueing message:", e);
      }
    }
    const event = {
      channel_id: channelId,
      user_id: this.userId,
      username: this.username,
      content,
      timestamp: Date.now(),
      message_id: messageId,
      ttl_secs: ttlSecs ?? null,
    };
    if (ciphertext) {
      this.sendControl({ SendEncryptedChannelMessage: { channel_id: channelId, ciphertext } });
      // The server excludes us from the encrypted broadcast: show it locally
      emit("channel-chat-message", { ...event, encrypted: true });
    } else {
      // Sent once sender key distribution completes; shown immediately as pending
      this.pendingMessages.push({ target: { kind: "channel", channelId }, id: messageId, content, ttlSecs, queuedAt: Date.now() });
      emit("channel-chat-message", { ...event, pending: true });
    }
  }

  /**
   * Ask named members for a channel's recent chat (commands.rs
   * request_channel_history): the user asking again, after clearing a channel
   * by accident or because somebody who was away is here now.
   */
  requestChannelHistory(channelId: number, targetUserIds: number[]): void {
    // A pairwise session is all an answer needs — history travels over that,
    // not over the channel's group key, and asking for the group key here
    // would block the one repair a member has when keying went wrong.
    const reachable = Uint32Array.from(targetUserIds.filter((uid) => this.establishedSessions.has(uid)));
    const targets = wasm().pickHistorySources(reachable);
    if (targets.length === 0) throw new Error("nobody here can share that history yet");
    for (const target_user_id of targets) {
      this.sendControl({ RequestChannelHistory: { channel_id: channelId, target_user_id } });
    }
  }

  /** Pairwise-encrypted DM; queued until the Signal session exists. */
  sendDirectMessage(targetUserId: number, content: string, ttlSecs?: number): void {
    // The same envelope a channel message uses since 0.9.0: a DM had nowhere to
    // put a destruction timer while it was raw text, and this also gives it the
    // id it never had. `openEnvelope` reads plain text as text, so a peer that
    // sends the old shape still arrives.
    const messageId = wasm().newMessageId();
    let encrypted: { ciphertext: Uint8Array; message_type: number } | null = null;
    if (this.establishedSessions.has(targetUserId)) {
      try {
        encrypted = this.signal.encrypt(targetUserId, wasm().envelope(messageId, content, ttlSecs));
      } catch (e) {
        console.info("pairwise encryption not ready, queueing DM:", e);
      }
    }
    const event = {
      from_user_id: this.userId,
      from_username: this.username,
      to_user_id: targetUserId,
      content,
      timestamp: Date.now(),
      message_id: messageId,
      ttl_secs: ttlSecs ?? null,
    };
    if (encrypted) {
      this.sendControl({
        SendEncryptedDirectMessage: {
          target_user_id: targetUserId,
          ciphertext: encrypted.ciphertext,
          message_type: encrypted.message_type,
        },
      });
      // The server echo cannot be decrypted by the sender (ratchet advanced): show it locally
      emit("direct-chat-message", { ...event, encrypted: true });
    } else {
      this.pendingMessages.push({ target: { kind: "direct", targetUserId }, id: messageId, content, ttlSecs, queuedAt: Date.now() });
      emit("direct-chat-message", { ...event, pending: true });
    }
  }
}


function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
