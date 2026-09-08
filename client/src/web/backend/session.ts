// The connection: a port of client/src-tauri/src/network.rs (connect,
// server message dispatch, Signal Protocol orchestration, RTT keepalive)
// and of the chat/poke commands that need the Signal state, minus native
// I/O. Media packets are handed to audio.ts / video.ts, which see this
// session through the SessionContext interface.

import { emit } from "./events";
import { loadWasm, wasm, type MediaKey, type PreKeyBundleData, type SignalClient } from "./wasm";
import { connect as openTransport, type Transport } from "./transport";
import type { SessionContext } from "./types";
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
  content: string;
  queuedAt: number;
}

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
  mediaKey: MediaKey | null = null;
  userId = 0;
  transport: Transport | null = null;
  /** The sharer we are watching (0 = none). */
  watchingUserId = 0;

  // Signal tracking state (app_state.rs SignalState). Keys are user ids.
  private readonly establishedSessions = new Set<number>();
  private readonly pendingSessions = new Set<number>();
  /** channel_id -> users we sent our sender key to. */
  private readonly senderKeyDistributed = new Map<number, Set<number>>();
  /** channel_id -> users whose sender key we received. */
  private readonly senderKeyReceived = new Map<number, Set<number>>();
  private pendingMessages: PendingMessage[] = [];
  /** Channel we entered with members already in it: ask the first member
   *  whose sender key arrives for recent chat (once per entry). */
  private historyWanted = 0;

  /** Voice sequence: never restarts within a connection (AES-GCM nonce = session_id ‖ sequence). */
  private voiceSequence = 0;
  /** Same rule for our own share's frames and screen audio (SHARE_FRAME_ID / SHARE_AUDIO_SEQ). */
  private videoFrameId = 0;
  private screenAudioSequence = 0;
  private auth: { resolve(): void; reject(e: Error): void } | null = null;
  private keepalive: ReturnType<typeof setInterval> | undefined;
  private attached = false;
  private ended = false;

  constructor(readonly signal: SignalClient, readonly username: string) {}

  get isEnded(): boolean {
    return this.ended;
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
    this.transport.sendControl(payload);
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
    if (sendDisconnect) this.sendControl("Disconnect");
    if (this.transport) await this.transport.close();
    this.setMediaKey(null);
    this.signal.free();
  }

  /** Replace the installed key. audio/video read ctx.mediaKey synchronously per packet, so the old one has no users left. */
  private setMediaKey(key: MediaKey | null): void {
    const old = this.mediaKey;
    this.mediaKey = key;
    old?.free();
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
        emit("channel-list", b.channels);
        break;
      case "UserList":
        this.onUserList(b.channel_id, b.users);
        break;
      case "UserJoined":
        // Pairwise sessions are needed in every channel (DMs, pokes)
        if (b.user.user_id !== this.userId) this.requestPrekeyBundlesForUsers([b.user]);
        emit("user-joined", b.user);
        break;
      case "UserLeft": {
        const uid: number = b.user_id;
        this.pendingSessions.delete(uid);
        this.establishedSessions.delete(uid);
        for (const set of this.senderKeyDistributed.values()) set.delete(uid);
        for (const set of this.senderKeyReceived.values()) set.delete(uid);
        emit("user-left", { user_id: uid, channel_id: b.channel_id });
        break;
      }
      case "UserMuted":
        emit("user-muted", { user_id: b.user_id, muted: b.muted });
        break;
      case "UserDeafened":
        emit("user-deafened", { user_id: b.user_id, deafened: b.deafened });
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
        emit("channel-created", b.channel);
        break;
      case "ChannelDeleted":
        emit("channel-deleted", { channel_id: b.channel_id });
        break;
      case "ChannelError":
        emit("channel-error", { reason: b.reason });
        break;
      case "ChannelUpdated":
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
        // A viewer needs an IDR now; the UI relays this too (App.svelte)
        share.requestKeyframe();
        emit("keyframe-requested");
        break;
      case "VideoLossReported":
        // A viewer of our share lost frames: step the encoder down
        share.onLossReport(b.frames_dropped);
        break;
      case "ScreenShareError":
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

  private onUserList(channelId: number, users: { user_id: number }[]): void {
    // Server-initiated moves (create_channel auto-join, kicks, invites) land here
    const oldChannel = this.channelId;
    this.channelId = channelId;
    if (oldChannel !== channelId) {
      // The new channel's key comes from an existing member over Signal,
      // or we generate one if alone (below, once the user list is known)
      this.setMediaKey(null);
      this.senderKeyDistributed.delete(channelId);
      this.senderKeyReceived.delete(channelId);
      this.historyWanted = users.length > 1 ? channelId : 0;
      if (this.watchingUserId !== 0) {
        this.watchingUserId = 0;
        this.sendControl("StopWatchingScreenShare");
        emit("screen-share-force-stopped");
        video.stopWatching();
      }
      // Our own share belonged to the old channel's members and its media key
      if (share.sharing) share.stop();
      audio.onChannelChanged();
    }

    // Pairwise sessions are needed in every channel (DMs, pokes), not just for channel chat
    this.requestPrekeyBundlesForUsers(users);

    // Media keys never touch the server: the first member generates one,
    // everyone else receives it from a member over a pairwise Signal session
    const alone = users.length === 1 && users[0].user_id === this.userId;
    if (channelId !== 0 && alone && this.mediaKey?.channelId !== channelId) {
      try {
        this.installMediaKey(wasm().generateMediaKey(channelId, 0));
      } catch (e) {
        console.error("media key generation failed:", e);
      }
    }

    emit("user-list", { channel_id: channelId, users });
  }

  // ── E2E helpers (network.rs request_prekey_bundles_for_users .. drain_pending_channel_messages) ──

  private requestPrekeyBundlesForUsers(users: { user_id: number }[]): void {
    for (const user of users) {
      const uid = user.user_id;
      if (uid === this.userId || this.establishedSessions.has(uid) || this.pendingSessions.has(uid)) continue;
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

    if (this.channelId !== 0) this.distributeSenderKeyToUser(this.channelId, remoteUserId);
  }

  private distributeSenderKeyToUser(channelId: number, targetUserId: number): void {
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
    getOrCreate(this.senderKeyDistributed, channelId).add(targetUserId);
  }

  /** Send our media key for `channelId` over the pairwise session, if we hold one. */
  private distributeMediaKeyToUser(channelId: number, targetUserId: number): void {
    const key = this.mediaKey;
    if (!key || key.channelId !== channelId) return;
    try {
      const { ciphertext, message_type } = this.signal.encrypt(targetUserId, key.toBytes());
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

  private installMediaKey(key: MediaKey): void {
    this.setMediaKey(key);
    emit("media-key-installed", { channel_id: key.channelId, key_id: key.keyId });
  }

  /** Install a member's media key if it is for our current channel and not older than what we hold. */
  private onMediaKeyReceived(channelId: number, fromUserId: number, ciphertext: Uint8Array, messageType: number): void {
    let key: MediaKey;
    try {
      key = wasm().mediaKeyFromBytes(this.signal.decrypt(fromUserId, ciphertext, messageType));
    } catch (e) {
      console.warn(`media key from ${fromUserId} rejected:`, e);
      return;
    }
    // A PreKeySignalMessage establishes the session on our side as well
    if (messageType === 1) this.markEstablished(fromUserId);

    const held = this.mediaKey;
    const forCurrentChannel = key.channelId === channelId && channelId === this.channelId;
    const newer = !held || held.channelId !== channelId || key.keyId >= held.keyId;
    if (forCurrentChannel && newer) this.installMediaKey(key);
    else key.free();
  }

  /** Decrypt pairwise, process the distribution, reciprocate, drain queued channel messages. */
  private onSenderKeyReceived(channelId: number, fromUserId: number, ciphertext: Uint8Array, messageType: number): void {
    try {
      const plaintext = this.signal.decrypt(fromUserId, ciphertext, messageType);
      this.signal.processSenderKeyDistribution(fromUserId, channelId, plaintext);
    } catch (e) {
      console.warn(`failed to process sender key from ${fromUserId}:`, e);
      return;
    }
    if (messageType === 1) this.markEstablished(fromUserId);
    getOrCreate(this.senderKeyReceived, channelId).add(fromUserId);

    if (!this.senderKeyDistributed.get(channelId)?.has(fromUserId)) {
      this.distributeSenderKeyToUser(channelId, fromUserId);
    }
    this.drainPendingChannelMessages(channelId);

    // Newcomer: the first member whose sender key arrives holds a pairwise
    // session with us (they just used it), so ask them for recent chat
    if (channelId !== 0 && this.historyWanted === channelId) {
      this.historyWanted = 0;
      this.sendControl({ RequestChannelHistory: { channel_id: channelId, target_user_id: fromUserId } });
    }
  }

  /** Recent channel chat for a newcomer, pairwise-encrypted (commands.rs send_channel_history). */
  sendChannelHistory(channelId: number, targetUserId: number, messages: unknown[]): void {
    const payload = utf8.encode(JSON.stringify({ v: 1, messages }));
    if (payload.length > 60 * 1024) throw new Error("history payload too large");
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
    let messages: unknown;
    try {
      const plaintext = this.signal.decrypt(fromUserId, ciphertext, messageType);
      messages = JSON.parse(utf8Decoder.decode(plaintext))?.messages;
    } catch (e) {
      console.warn(`channel history from ${fromUserId} rejected:`, e);
      return;
    }
    if (messageType === 1) this.markEstablished(fromUserId);
    if (!Array.isArray(messages)) return;
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
  private takePending(matches: (t: PendingTarget) => boolean): string[] {
    const now = Date.now();
    const send: string[] = [];
    const remaining: PendingMessage[] = [];
    let expired = 0;
    for (const m of this.pendingMessages) {
      if (!matches(m.target)) remaining.push(m);
      else if (now - m.queuedAt < PENDING_MESSAGE_TTL_MS) send.push(m.content);
      else expired++;
    }
    if (expired > 0) console.warn(`dropped ${expired} expired pending messages`);
    this.pendingMessages = remaining;
    return send;
  }

  private drainPendingDms(targetUserId: number): void {
    for (const content of this.takePending((t) => t.kind === "direct" && t.targetUserId === targetUserId)) {
      try {
        const { ciphertext, message_type } = this.signal.encrypt(targetUserId, utf8.encode(content));
        this.sendControl({ SendEncryptedDirectMessage: { target_user_id: targetUserId, ciphertext, message_type } });
      } catch (e) {
        console.warn(`failed to encrypt queued DM to ${targetUserId}:`, e);
      }
    }
  }

  private drainPendingChannelMessages(channelId: number): void {
    for (const content of this.takePending((t) => t.kind === "channel" && t.channelId === channelId)) {
      try {
        const ciphertext = this.signal.groupEncrypt(this.userId, channelId, utf8.encode(content));
        this.sendControl({ SendEncryptedChannelMessage: { ciphertext } });
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
      emit("direct-chat-message", { ...event, content: utf8Decoder.decode(plaintext) });
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
    const event = { channel_id: channelId, user_id: userId, username, timestamp, encrypted: true };
    try {
      const plaintext = this.signal.groupDecrypt(userId, channelId, ciphertext);
      emit("channel-chat-message", { ...event, content: utf8Decoder.decode(plaintext) });
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

  /** Sender-key encrypted channel message; queued until a sender key was distributed. */
  sendChannelMessage(content: string): void {
    const channelId = this.channelId;
    if (channelId === 0) throw new Error("Chat is not available in the lobby");

    let ciphertext: Uint8Array | null = null;
    if ((this.senderKeyDistributed.get(channelId)?.size ?? 0) > 0) {
      try {
        ciphertext = this.signal.groupEncrypt(this.userId, channelId, utf8.encode(content));
      } catch (e) {
        console.info("group encryption not ready, queueing message:", e);
      }
    }
    const event = { channel_id: channelId, user_id: this.userId, username: this.username, content, timestamp: Date.now() };
    if (ciphertext) {
      this.sendControl({ SendEncryptedChannelMessage: { ciphertext } });
      // The server excludes us from the encrypted broadcast: show it locally
      emit("channel-chat-message", { ...event, encrypted: true });
    } else {
      // Sent once sender key distribution completes; shown immediately as pending
      this.pendingMessages.push({ target: { kind: "channel", channelId }, content, queuedAt: Date.now() });
      emit("channel-chat-message", { ...event, pending: true });
    }
  }

  /** Pairwise-encrypted DM; queued until the Signal session exists. */
  sendDirectMessage(targetUserId: number, content: string): void {
    let encrypted: { ciphertext: Uint8Array; message_type: number } | null = null;
    if (this.establishedSessions.has(targetUserId)) {
      try {
        encrypted = this.signal.encrypt(targetUserId, utf8.encode(content));
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
      this.pendingMessages.push({ target: { kind: "direct", targetUserId }, content, queuedAt: Date.now() });
      emit("direct-chat-message", { ...event, pending: true });
    }
  }
}

function getOrCreate(map: Map<number, Set<number>>, key: number): Set<number> {
  let set = map.get(key);
  if (!set) {
    set = new Set();
    map.set(key, set);
  }
  return set;
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
