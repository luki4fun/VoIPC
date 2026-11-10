// The connection: a port of client/src-tauri/src/network.rs (connect,
// server message dispatch, Signal Protocol orchestration, RTT keepalive)
// and of the chat/poke commands that need the Signal state, minus native
// I/O. Media packets are handed to audio.ts / video.ts, which see this
// session through the SessionContext interface.
//
// One Session per server, keyed by the id the UI connected with. The media
// modules are single (one mic, one mixer, one viewer), so they serve exactly
// one of them: the voice session, the one whose voice channel we are in.

import { emit as emitEvent } from "./events";
import { getConfig } from "./config";
import { loadWasm, wasm, type KeptPins, type KeptSessions, type LiveOut, type MediaKeys, type MessageRefs, type PreKeyBundleData, type Sealed, type SignalClient } from "./wasm";
import { ACCOUNT_STEP_MS, AccountDriver, frameGoesOn, type AccountArgs, type AccountHost } from "./account";
import { connect as openTransport, type Transport } from "./transport";
import type { SessionContext } from "./types";
import type { ChannelInfo } from "../../lib/types";
import { parseHostPort } from "../../lib/invite";
import type { ProximityMode } from "../../lib/spatial";
import { audio } from "./audio";
import { video } from "./video";
import { share } from "./share";
import { Files, originOf, sanitizeImage } from "./files";
import { Emotes, emoteLimitsOf } from "./emotes";
import { motionOf } from "./media";
import { postsMarks } from "./posts-marks";
import { asksBundles, ChannelListParts, KeptByAccount, LivePump } from "./live";

/** Bound for the authentication response (network.rs CONNECT_TIMEOUT). */
const AUTH_TIMEOUT_MS = 10_000;
/** Datagram keepalive period: measures RTT (a dead QUIC path closes the transport). */
const KEEPALIVE_MS = 10_000;
/** The live path's clock (`ChannelKeying::live_tick`). */
const LIVE_TICK_MS = 1_000;
/** Queued chat messages older than this are dropped instead of sent. */
const PENDING_MESSAGE_TTL_MS = 60_000;
/** voipc_protocol::voice::VOICE_HEADER_SIZE */
const VOICE_HEADER_SIZE = 9;

type PendingTarget =
  | { kind: "channel"; channelId: number }
  | { kind: "direct"; targetUserId: number }
  // On the live path nothing opens a session with someone before there is something to say
  | { kind: "poke"; targetUserId: number };

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
  /** What it answers and the thread it belongs to; kept for the same reason. */
  refs?: MessageRefs;
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

/** A list of bans: u64s may arrive as BigInt, plain numbers for the UI (types.ts BanInfo). */
function banRows(bans: unknown): unknown[] {
  return (
    bans as {
      id: bigint | number;
      account: boolean;
      label: string;
      reason: string;
      by: string;
      created_at: bigint | number;
      expires_in_secs?: bigint | number | null;
    }[]
  ).map((x) => ({
    id: Number(x.id),
    account: x.account,
    label: x.label,
    reason: x.reason,
    by: x.by,
    created_at: Number(x.created_at),
    expires_in_secs: x.expires_in_secs == null ? null : Number(x.expires_in_secs),
  }));
}

/** Milliseconds since the Unix epoch truncated to u32: the ping sequence. */
const nowU32 = () => Date.now() >>> 0;
/** How long an ask for a voice seat stays good (network.rs VOICE_ASK_TTL_MS). */
const VOICE_ASK_TTL_MS = 10_000;

/** Live sessions by server id: the exact `address` the UI connected with. */
const sessions = new Map<string, Session>();
/** What an account's last connection to a server kept for its next. */
const keptSessions = new KeptByAccount<KeptSessions>();
const keptPins = new KeptByAccount<KeptPins>();
/** On mobile data, as the front end last said. */
let metered = false;
/**
 * Connects to one server run one after another (network.rs connect_lock);
 * per id, so a server that takes its full auth timeout holds up no other.
 */
const connectQueues = new Map<string, Promise<unknown>>();
/**
 * The session the media modules are attached to, or null when we are in no
 * voice channel anywhere. Stored rather than derived from `channelId !== 0`:
 * during a switch the old server keeps its channel id until its own UserList
 * arrives, and for that round trip both would claim voice.
 */
let voiceOwner: Session | null = null;

/** The session for a server id, or null when not connected to it. */
export function sessionFor(server: string): Session | null {
  return sessions.get(server) ?? null;
}

/** Sessions still signing in (not in `sessions` until Authenticated): an
 *  account's code prompt answers to one of these. */
const signingIn = new Map<string, Session>();

/** The session that is listed, or still signing in, for `server`. */
export function sessionOrSigningIn(server: string): Session | null {
  return sessions.get(server) ?? signingIn.get(server) ?? null;
}

// A test build's way to hand a session a frame no honest relay sends (test-provider.mjs),
// to see which frames came and what went, and to cut a link (test-community.mjs).
const heard: [string, number | undefined][] = [];
const said: unknown[] = [];
if (__SELFTEST__) {
  const page = window as unknown as { __voipc_frame: unknown; __voipc_heard: unknown; __voipc_said: unknown; __voipc_cut: unknown };
  page.__voipc_said = said;
  page.__voipc_frame = (server: string, payload: number[]) => {
    const bytes = Uint8Array.from(payload);
    sessionOrSigningIn(server)?.onControl(bytes);
    return wasm().decodeServerMsg(bytes);
  };
  page.__voipc_heard = heard;
  page.__voipc_cut = (server: string) => sessionFor(server)?.onTransportClosed("a test cut the link");
}

/** The session whose voice channel we are in, or null. */
export function voiceSession(): Session | null {
  return voiceOwner;
}

export function allSessions(): Session[] {
  return [...sessions.values()];
}

/** Connect and authenticate (as a guest, or to `account`). Resolves with our user id. */
export function connect(address: string, username: string, account?: AccountArgs): Promise<number> {
  const run = (connectQueues.get(address) ?? Promise.resolve()).then(() => doConnect(address, username, account));
  const tail = run.catch(() => {});
  connectQueues.set(address, tail);
  void tail.then(() => {
    if (connectQueues.get(address) === tail) connectQueues.delete(address);
  });
  return run;
}

/** Idempotent, and an id we are not connected to is fine: sends Disconnect,
 *  closes the transport and drops all Signal state of that one server.
 *  `keepSessions`: a reconnect clearing the way, not a person leaving. */
export async function disconnect(server: string, keepSessions = false): Promise<void> {
  // A person leaving: new pins go now, or they would be new again next time
  if (!keepSessions) await sessions.get(server)?.savePins();
  await sessions.get(server)?.end(true);
  if (!keepSessions) forgetKept(server);
}

/** What accounts kept here goes: a person's leave, or a device forgotten. */
export function forgetKept(server: string): void {
  keptSessions.forget(server);
  keptPins.forget(server);
}

/** On mobile data or not: a large key job asks first, and fewer sessions open at once. */
export function setMetered(on: boolean): void {
  metered = on;
  for (const s of sessions.values()) s.signal.liveSetMetered(on);
}

/** Hand the media modules to `s`, detaching them from the previous owner. */
function attachVoice(s: Session): void {
  detachVoice();
  voiceOwner = s;
  audio.attach(s);
  video.attach(s);
  share.attach(s);
}

function detachVoice(): void {
  if (!voiceOwner) return;
  voiceOwner = null;
  audio.detach();
  video.detach();
  share.detach();
}

/**
 * `s` confirmed a voice channel: it is the voice session now, whoever held
 * voice before. The latest confirmation wins, so a join the UI did not start
 * (create-channel auto-join, an accepted invite) moves voice too. This is the
 * only place the backend leaves voice on its own.
 */
function takeVoice(s: Session): void {
  const previous = voiceOwner;
  if (previous === s) return;
  // No await inside: the capture closes and the EOT goes out to the old room
  // before the media modules move.
  void audio.stopTransmit();
  // Moved before the leave: detaching stops a share of ours there, and a
  // StopScreenShare that arrives after the leave is answered with an error.
  attachVoice(s);
  // ponytail: sent once, no retry. A server that refuses the leave keeps us
  // listed in its room, but our audio there is already closed here; the join
  // budget (channel_budget + 4, refilling 2/s) makes a refusal unlikely.
  previous?.sendControl({ JoinChannel: { channel_id: 0, password: null } });
}

async function doConnect(address: string, username: string, account?: AccountArgs): Promise<number> {
  // Replaces only this server's connection (e.g. after a page reload race);
  // every other server stays as it is.
  await sessions.get(address)?.end(true);

  const { host, port } = parseAddress(address);
  const api = await loadWasm();
  const driver = account ? await AccountDriver.create(address, username, account) : null;
  // Fresh Signal identity per connection: ephemeral by design, and the
  // server reassigns user ids on restart (network.rs connect_to_server). An
  // account's identity replaces this one during its sign-in.
  const session = new Session(address, api.newSignalClient(), username);
  session.account = driver;
  signingIn.set(address, session);
  try {
    session.transport = await openTransport(host, port, {
      onControl: (payload) => session.onControl(payload),
      onDatagram: (bytes) => session.onDatagram(bytes),
      onVideoPacket: (bytes) => session.onVideoPacket(bytes),
      onClosed: (reason) => session.onTransportClosed(reason),
    });
    const authenticated = session.awaitAuthentication(driver ? ACCOUNT_STEP_MS : AUTH_TIMEOUT_MS);
    if (driver) {
      session.sendRaw(driver.first());
    } else {
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
    }
    await authenticated;
    // The transport can close between Authenticated and this continuation
    if (session.isEnded) throw new Error("Server closed connection during authentication");
  } catch (e) {
    await session.end(false);
    throw e;
  } finally {
    if (signingIn.get(address) === session) signingIn.delete(address);
  }
  sessions.set(address, session);
  session.start();
  session.account?.afterConnect(session);
  return session.userId;
}

/** A question for the relay at `address` that ends with its answer, on a
 *  connection of its own (account.rs `account_provider_ask`). */
export async function askRelay(address: string, ask: unknown): Promise<unknown> {
  const { host, port } = parseAddress(address);
  const api = await loadWasm();
  return new Promise((resolve, reject) => {
    let transport: Transport | undefined;
    let over = false;
    const end = (go: () => void) => {
      if (over) return;
      over = true;
      clearTimeout(timer);
      transport?.close();
      go();
    };
    const timer = setTimeout(() => end(() => reject(new Error("The server did not answer."))), AUTH_TIMEOUT_MS);
    openTransport(host, port, {
      onControl: (payload) => {
        const [tag, body] = Object.entries(api.decodeServerMsg(payload) as Record<string, any>)[0] ?? ["", null];
        if (tag === "AuthError") return end(() => reject(new Error(body.reason)));
        // Another protocol: an older relay has no providers
        if (tag === "Refused") return end(() => resolve({ providers: [] }));
        if (tag !== "AuthStep") return;
        const [step, b] = typeof body === "string" ? [body, null] : (Object.entries(body)[0] as [string, any]);
        if (step === "Providers") end(() => resolve({ providers: b.kinds }));
        else if (step === "OpenBrowser") end(() => resolve({ url: b.url, code: b.code, ticket: Array.from(b.ticket as number[]) }));
        else if (step === "ProviderReady") end(() => resolve({ ready: true }));
        else if (step === "ProviderPending") end(() => resolve({ ready: false }));
      },
      onDatagram: () => {},
      onVideoPacket: () => {},
      onClosed: (reason) => end(() => reject(new Error(reason))),
    }).then(
      (t) => {
        if (over) return t.close();
        transport = t;
        t.sendControl(api.providerAsk(ask));
      },
      (e) => end(() => reject(e)),
    );
  });
}

/** network.rs parse_address's rules: the port defaults to 9987. */
function parseAddress(address: string): { host: string; port: number } {
  const parsed = parseHostPort(address);
  if (!parsed) throw new Error("Invalid address, expected host:port or [IPv6]:port");
  return parsed;
}

export class Session implements SessionContext, AccountHost {
  sessionId = 0;
  /** Current voice channel (0 = none: the server parks us there). Confirmed by UserList. */
  channelId = 0;
  /** The channel's media keys: what we encrypt with, and the generation
   *  before it so a re-key does not silence packets already in flight. */
  readonly mediaKeys: MediaKeys;
  userId = 0;
  /** Whether a guest's switch counts here. An account's session keeps its own. */
  private guestMayShare = false;
  transport: Transport | null = null;
  /** The sharer we are watching (0 = none). */
  watchingUserId = 0;
  /** The channel list as last received — the source of each channel's proximity mode. */
  private channels: ChannelInfo[] = [];
  /** A list too long for one frame, until its last. */
  private readonly channelParts = new ChannelListParts<ChannelInfo>();
  /** Frames that wait for the pages of pins (`voipc_crypto::waits_for_pins`), in order. */
  private pinHeld: { msg: unknown; payload: Uint8Array }[] = [];

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
  private auth: { resolve(): void; reject(e: Error): void; wait(ms: number): void } | null = null;
  /** Authenticated came and was taken: until then only the sign-in's frames count (`frameGoesOn`). */
  private signedIn = false;
  /** The account this connection signs in to; null for a guest. */
  account: AccountDriver | null = null;
  /** This connection's file transfers, from Authenticated on (files.ts). */
  files: Files | null = null;
  emotes: Emotes | null = null;
  /** The safety number with `userId` (account_session.rs safety_number). Nobody has met
   *  anyone until they write, and Verify is to work with anyone online: a person's own
   *  click, so their bundle is asked for, and comes through the pin check. */
  safetyNumber(userId: number): string {
    if (!this.account) throw new Error("Sign in to an account to verify people");
    const live = this.signal.identityOf(userId);
    try {
      const number = this.account.safetyNumber(userId, this.signal.bundle().identity_key, live);
      this.account.verified(this, userId);
      return number;
    } catch (e) {
      if (live !== undefined || !this.account.isAccount(userId)) throw e;
      if (!this.pendingSessions.has(userId)) {
        this.pendingSessions.add(userId);
        this.sendControl({ RequestPreKeyBundle: { target_user_id: userId } });
      }
      throw new Error("Asked for their key. Try again in a moment.");
    }
  }

  /** The identities the Signal stores took in for the last message, against
   *  the pins as a fetched bundle is (account.rs check_seen). Taken on every
   *  connection, so a guest's list does not grow. */
  private checkSeen(): void {
    const seen = this.signal.takeSeen();
    for (const { user_id, key } of seen) {
      // A session kept from before that disagrees with the pin is no use to anyone
      if (this.account?.checkIdentity(this, user_id, key)) this.signal.liveDropKeptSession(user_id);
    }
  }

  /** A pairwise decrypt, with the identity it took in (a session the peer
   *  opened, which no bundle check sees) checked against the pins before
   *  anything it decrypted is shown: a changed key is warned of no later
   *  than its first message (S-012; network.rs `check_seen_now`). */
  private decrypt(fromUserId: number, ciphertext: Uint8Array, messageType: number): Uint8Array {
    try {
      return this.signal.decrypt(fromUserId, ciphertext, messageType);
    } finally {
      this.checkSeen();
    }
  }
  private keepalive: ReturnType<typeof setInterval> | undefined;
  private liveClock: ReturnType<typeof setInterval> | undefined;
  /** Key frames, one in the queue at a time (live.ts). */
  private readonly live = new LivePump({
    nextFrame: (inCall) => this.signal.liveNextFrame(inCall),
    send: (frame) => this.sendRaw(frame),
    queued: () => this.controlQueue.length + (this.transport?.controlBacklog() ?? 0),
    inCall: () => this.inCall(),
    // A wrap in a session kept from before names its peer's identity only now
    checked: () => this.checkSeen(),
    over: () => this.ended,
  });
  /** The new-member wait holds our direct messages, so a sealed ask would be refused:
   *  history is asked by the plain frames meanwhile. */
  private directHeld = false;
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
  private ended = false;
  /**
   * When we last asked this server for a voice seat (Date.now(), 0 = never):
   * a join, a voice channel's creation, an accepted invite. Only such an ask
   * lets this server take voice (network.rs `take_voice_ask`).
   */
  private voiceAskedAt = 0;

  constructor(
    /** The server id: the address the UI connected with, verbatim. */
    readonly server: string,
    public signal: SignalClient,
    public username: string,
  ) {
    this.mediaKeys = wasm().newMediaKeys();
  }

  get isEnded(): boolean {
    return this.ended;
  }

  /** Voice is on, on any server (files.ts paces transfers then). */
  inCall(): boolean {
    return voiceOwner !== null;
  }

  /** Whether the switch to share history counts on this connection. */
  mayShare(): boolean {
    return this.account ? this.account.mayShare() : this.guestMayShare;
  }

  /** A per-connection event: the payload it always had, tagged with its server. */
  emit(name: string, data: unknown = null): void {
    emitEvent(name, { server: this.server, data });
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

  sendVideoFrame(body: Uint8Array, key: boolean): boolean {
    return this.transport?.sendVideoFrame(body, key) ?? false;
  }

  videoBacklog(): number {
    return this.transport?.videoBacklog() ?? 0;
  }

  /** An already encoded control payload (the account sign-in makes its own). */
  sendRaw(payload: Uint8Array): void {
    if (!this.transport) return;
    this.controlQueue.push(payload);
    this.drainControl();
  }

  replaceSignal(client: SignalClient): void {
    this.signal.free();
    this.signal = client;
  }

  failAuth(e: Error): void {
    this.auth?.reject(e);
  }

  authWait(ms: number): void {
    this.auth?.wait(ms);
    // A moment past that clock, whose reason is the one to show
    this.transport?.allowQuiet(ms + 1_000);
  }

  sendControl(msg: unknown): void {
    if (!this.transport) return;
    if (__SELFTEST__) said.push(msg);
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

  awaitAuthentication(timeoutMs = AUTH_TIMEOUT_MS): Promise<void> {
    return new Promise((resolve, reject) => {
      const expired = () => {
        this.auth = null;
        this.account?.cancel();
        reject(new Error("Timed out waiting for the authentication response"));
      };
      let timer = setTimeout(expired, timeoutMs);
      this.auth = {
        wait: (ms) => {
          clearTimeout(timer);
          timer = setTimeout(expired, ms);
        },
        resolve: () => {
          clearTimeout(timer);
          this.auth = null;
          this.transport?.allowQuiet(0);
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

  /**
   * After Authenticated (network.rs:263-330, 540-565). Media attaches later,
   * when this server confirms a voice channel (onUserList).
   */
  start(): void {
    // First ping: gives the UI an RTT reading right away.
    this.sendPing();

    // Notify the server of persisted mute/deafen state
    if (audio.muted) this.sendControl({ SetMuted: { muted: true } });
    if (audio.deafened) this.sendControl({ SetDeafened: { deafened: true } });
    // ...and whether we answer requests for recent chat, so the people here
    // can see who asking would reach. A switch that does not count here reads as
    // off: the relay is not told it is on.
    this.sendControl({ SetHistorySharing: { enabled: getConfig().share_channel_history && this.mayShare() } });
    this.liveClock = setInterval(() => this.liveTick(), LIVE_TICK_MS);

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
    if (sessions.get(this.server) === this) sessions.delete(this.server);
    clearInterval(this.keepalive);
    clearInterval(this.liveClock);
    this.files?.close();
    this.emotes?.close();
    if (voiceOwner === this) detachVoice();
    if (sendDisconnect && this.transport) {
      // Whatever was still waiting for the pacer is moot now, and the goodbye
      // is not: it goes out ahead of the queue, and past the pacer too — over
      // budget it was queued, and the queue is cleared just below.
      this.controlQueue.length = 0;
      try {
        this.transport.sendControl(wasm().encodeClientMsg("Disconnect"));
      } catch (e) {
        console.warn("could not send the goodbye:", e);
      }
    }
    // After the goodbye, so a queue that was over budget cannot leave a timer
    // running against a transport that is about to close.
    clearTimeout(this.controlTimer);
    this.controlTimer = undefined;
    this.controlQueue.length = 0;
    if (this.transport) await this.transport.close();
    this.mediaKeys.free();
    // Posts that waited showed as sent. By name: the page has forgotten this connection's ids
    for (const { channel_id, expired } of this.signal.liveEnd()) {
      const name = this.channels.find((c) => c.channel_id === channel_id)?.name;
      this.emit("channel-undelivered", { channel_id, expired, name });
    }
    // An account's sessions, for its next connection to this server (network.rs
    // `keep_sessions`). A guest has nothing to go by, and nothing goes on.
    const account = this.signedIn ? this.account?.accountHex() : null;
    if (account) {
      keptSessions.put(this.server, account, this.signal.liveKeepSessions());
      const pins = this.account?.keepPins();
      if (pins) keptPins.put(this.server, account, pins);
    }
    this.signal.free();
    this.account?.dispose();
  }

  /** What pins were not saved yet, before a person's leave ends this. */
  async savePins(): Promise<void> {
    await this.account?.savePins(this);
  }

  onTransportClosed(reason: string): void {
    if (this.auth) {
      // doConnect ends the session
      this.auth.reject(new Error(reason));
      return;
    }
    if (this.ended) return;
    this.emit("connection-lost", { reason });
    void this.end(false);
  }

  // ── inbound ──

  onControl(payload: Uint8Array): void {
    this.account?.onPayload(this, payload);
    let msg: unknown;
    try {
      msg = wasm().decodeServerMsg(payload);
    } catch (e) {
      console.warn("failed to decode server message:", e);
      return;
    }
    if (!frameGoesOn(msg, this.signedIn, this.account?.midPairing ?? false)) return;
    if (__SELFTEST__) {
      const [tag, b] = typeof msg === "string" ? [msg, null] : Object.entries(msg as Record<string, Body>)[0];
      heard.push([tag, b?.channel_id ?? b?.user?.channel_id]);
    }
    if (this.signedIn && this.signal.liveHoldsFrame(payload)) {
      if (this.pinHeld.length >= wasm().pinHeldMost()) this.pinHeld.shift();
      this.pinHeld.push({ msg, payload });
      return;
    }
    try {
      this.handleServerMessage(msg, payload);
    } catch (e) {
      console.error("server message handler failed:", e);
    }
    this.checkSeen();
    // A session a queued ask waited for may have come up
    if (!this.ended && this.signal.liveHasWork()) this.live.wake();
  }

  onVideoPacket(bytes: Uint8Array): void {
    if (this === voiceOwner) video.onVideoPacket(bytes);
  }

  /**
   * network.rs udp_receiver_task dispatch by packet type. Plaintext media
   * types are never accepted, and media only from the voice session: the
   * media modules decrypt with *its* keys and mix by *its* session ids.
   */
  onDatagram(bytes: Uint8Array): void {
    switch (bytes[0]) {
      case 0x05:
        if (this === voiceOwner) audio.onVoicePacket(bytes);
        break;
      case 0x02:
        if (this === voiceOwner) audio.onEotPacket(bytes);
        break;
      case 0x15:
        if (this === voiceOwner) audio.onScreenAudioPacket(bytes);
        break;
      case 0x06:
        if (this === voiceOwner) audio.onPositionPacket(bytes);
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
    if (rtt < 60_000) this.emit("latency-update", { ms: rtt, tcp: this.transport?.tcp ?? false });
  }

  /** network.rs handle_server_message. */
  private handleServerMessage(msg: unknown, payload: Uint8Array): void {
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
        // libsignal binds both parties' ids into every pairwise message
        this.signal.setOwnUserId(b.user_id);
        this.signal.liveStart();
        this.signal.liveSetMetered(metered);
        this.files = new Files(this, originOf(this.server), b.files ? Number(b.files.max_bytes) : null, b.files ? motionOf(b.files) : null);
        this.emotes = new Emotes(
          this,
          originOf(this.server),
          b.emotes ? { token: String(b.emotes.token), ...emoteLimitsOf(b.emotes) } : null,
          sanitizeImage,
        );
        // network.rs emits the same, for the composer
        this.emit("file-limits", b.files ? { max_bytes: Number(b.files.max_bytes) } : null);
        this.emit(
          "emote-limits",
          b.emotes ? emoteLimitsOf(b.emotes) : null,
        );
        if (!this.account) {
          // A guest holds no privileges, so where there are accounts their switch does not count
          this.guestMayShare = wasm().guestMayShare(!!b.accounts);
          this.emit("share-right", { may: this.guestMayShare });
        }
        if (b.accounts) this.emit("relay-accounts", b.accounts);
        // An account sign-in ends signed in to that account, or not at all
        // (account.rs sign_in waits for exactly this).
        if (this.account) {
          if (!b.account) {
            this.failAuth(new Error("The server did not sign this account in."));
            break;
          }
          try {
            this.account.onAuthenticated(this, b.account);
            // A provider's sign-in only knows now who it is
            this.username = b.account.name;
            // What the last connection of this account here kept. A guest keeps nothing.
            const hex = this.account.accountHex() ?? "";
            const kept = keptSessions.take(this.server, hex);
            if (kept) this.signal.liveAdoptKept(kept);
            const pins = keptPins.take(this.server, hex);
            if (pins) this.account.adoptPins(pins);
            // No key job until what it checks against is here
            if (!this.account.pinsIn()) this.signal.liveWaitForPins();
          } catch (e) {
            this.failAuth(e instanceof Error ? e : new Error(String(e)));
            break;
          }
        }
        this.signedIn = true;
        this.auth?.resolve();
        break;
      case "AuthStep":
        // The account sign-in reads these from the raw payload (onControl);
        // a guest only ever gets this one. connect.ts looks for the words.
        if (!this.account && typeof b === "object" && "AccountRequired" in b) {
          this.failAuth(new Error("This server needs an account: sign in or create one."));
        }
        break;
      case "Account":
        this.account?.onReply(this, b);
        // The pages of pins came in: the key jobs that waited for them, then the rest
        if (this.account?.takePinsIn()) {
          this.runLive(this.signal.livePinsIn(this.channelId));
          for (const held of this.pinHeld.splice(0)) {
            try {
              this.handleServerMessage(held.msg, held.payload);
            } catch (e) {
              console.error("a frame that waited for the pins failed:", e);
            }
            this.checkSeen();
          }
        }
        break;
      case "AuthError":
        this.auth?.reject(new Error(`Authentication failed: ${b.reason}`));
        break;
      case "Refused":
        // Another protocol: the facts for the "update" panel, and the text,
        // which says "version mismatch" (connect.ts stops reconnecting on it)
        this.emit("update-needed", {
          code: b.code,
          server_protocol: b.server_protocol,
          server_version: b.server_version,
          our_protocol: wasm().protocolVersion(),
          our_version: wasm().appVersion(),
        });
        this.auth?.reject(new Error(b.text));
        break;
      case "Profiles":
        this.emit("profiles", b.profiles);
        break;
      case "ProfilePicture":
        this.emit("profile-picture", { hash: b.hash, image: b.image });
        break;
      case "ServerProfile":
        this.emit("server-profile", { name: b.name, description: b.description, icon: b.icon });
        break;
      case "MentionPower":
        this.emit("mention-power", { user_ids: b.user_ids, on: b.on });
        break;
      case "MyBadges":
        this.emit("my-badges", b.badges);
        break;
      case "Restrictions": {
        const own = (b.list as { user_id: number; direct: boolean }[]).find((row) => row.user_id === this.userId);
        if (own) this.directHeld = own.direct;
        this.emit("restrictions", { list: b.list });
        break;
      }
      case "ChatMods":
        this.emit("chat-mods", { mods: b.mods });
        break;
      case "PostsHidden":
        this.emit("posts-hidden", { marks: postsMarks(b.marks) });
        break;
      case "ReportTakers":
        this.account?.noteTakers(b.takers);
        this.emit("report-takers", { takers: b.takers });
        break;
      case "GroupStyles":
        this.emit("group-styles", b.groups);
        break;
      case "ChannelLayout":
        this.emit("channel-layout", { categories: b.categories, channels: b.channels });
        break;
      case "ChannelList":
        // Our own copy: the emitted array ends up in the UI's store
        this.channels = [...b.channels];
        this.emit("channel-list", b.channels);
        break;
      // A list too long for one frame. The front end hears it at its end, whole, so a reader
      // of `channel-list` needs to know of no frames.
      case "ChannelListMore": {
        const whole = this.channelParts.take(b.channels as ChannelInfo[], b.more);
        if (whole) {
          this.channels = [...whole];
          this.emit("channel-list", whole);
        }
        break;
      }
      case "UserList": {
        this.noteRows(b.users);
        // In a channel with a log: keep it (with cloud copies on), and read
        // what it kept since last time.
        const log = this.channels.find((c) => c.channel_id === b.channel_id)?.log;
        if (log) this.account?.enter(this, log);
        this.onUserList(b.channel_id, b.users);
        break;
      }
      case "UserJoined": {
        this.noteRows([b.user]);
        // Somebody joined the room we stand in: a key dance to do. A text channel's key
        // goes to who a check named, never because a relay said someone joined.
        if (b.user.user_id !== this.userId && asksBundles(b.user.channel_id, this.channelId)) {
          this.requestPrekeyBundlesForUsers([b.user]);
          this.signal.addMember(b.user.channel_id, b.user.user_id);
          if (this.establishedSessions.has(b.user.user_id)) {
            this.distributeSenderKeyToUser(b.user.channel_id, b.user.user_id);
          }
        }
        this.emit("user-joined", b.user);
        break;
      }
      case "UserUpdated":
        this.noteRows([b.user]);
        this.emit("user-updated", b.user);
        break;
      case "ListenOnly":
        this.emit("listen-only", { channel_id: b.channel_id, on: b.on });
        break;
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
            // Out of the channel's log too: the relay took us out of it
            // (1.0, D10), and a rejoin keeps it again
            const log = this.channels.find((c) => c.channel_id === b.channel_id)?.log;
            if (log) this.account?.leave(this, log, false);
          }
          this.emit("user-left", { user_id: uid, channel_id: b.channel_id });
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
        // Channel 0 has no key to rotate: nobody there is in voice
        if (uid !== this.userId && b.channel_id === this.channelId && b.channel_id !== 0) {
          this.signal.noteStale(b.channel_id);
          // Their copy of the room's media key stops working from the next
          // generation on, if we are the one elected to mint it.
          this.rotateMediaKeyIfMinter(b.channel_id);
        }
        // Only the voice session's ids are the mixer's: another server's user
        // with the same number is somebody else.
        if (this === voiceOwner) audio.onUserLeft(uid);
        this.emit("user-left", { user_id: uid, channel_id: b.channel_id });
        break;
      }
      case "UserMuted":
        this.emit("user-muted", { user_id: b.user_id, muted: b.muted });
        break;
      case "UserDeafened":
        this.emit("user-deafened", { user_id: b.user_id, deafened: b.deafened });
        break;
      case "UserHistorySharing":
        this.emit("user-history-sharing", { user_id: b.user_id, enabled: b.enabled });
        break;
      case "Ping":
        // Reply to the server keepalive to prevent the idle disconnect
        this.sendControl({ Ping: { timestamp: b.timestamp } });
        break;
      case "Pong":
        // Displayed latency comes from the UDP keepalive RTT (see network.rs)
        break;
      case "ServerShutdown":
        this.emit("connection-lost", { reason: `Server shutdown: ${b.reason}` });
        break;
      case "MovedToChannel":
        break;
      case "ChannelCreated":
        this.upsertChannel(b.channel);
        this.emit("channel-created", b.channel);
        break;
      case "ChannelDeleted":
        this.channels = this.channels.filter((c) => c.channel_id !== b.channel_id);
        this.signal.forgetChannel(this.userId, b.channel_id);
        this.emit("channel-deleted", { channel_id: b.channel_id });
        break;
      case "ChannelError":
        this.emit("channel-error", { reason: b.reason });
        break;
      case "ChannelUpdated":
        this.upsertChannel(b.channel);
        // The mode of the channel we are in may have just changed. Only for
        // the voice session: a background server would switch off the spatial
        // audio of the call we are actually in.
        if (this === voiceOwner) audio.setProximityMode(this.proximityOf(this.channelId));
        this.emit("channel-updated", b.channel);
        break;
      case "Kicked":
        this.emit("kicked", { channel_id: b.channel_id, reason: b.reason });
        break;
      case "ChannelUsers":
        // Who is which account, also of people in rooms we are not in: a
        // direct message to them is kept only if we know.
        this.noteRows(b.users);
        this.emit("channel-users", { channel_id: b.channel_id, users: b.users });
        break;
      case "InviteReceived":
        this.emit("invite-received", {
          channel_id: b.channel_id,
          channel_name: b.channel_name,
          invited_by: b.invited_by,
        });
        break;
      case "InviteAccepted":
        this.emit("invite-accepted", { channel_id: b.channel_id, user_id: b.user_id });
        break;
      case "InviteDeclined":
        this.emit("invite-declined", { channel_id: b.channel_id, user_id: b.user_id });
        break;
      case "PokeReceived":
        this.onPokeReceived(b.from_user_id, b.from_username, toBytes(b.ciphertext), b.message_type);
        break;
      // The share and the viewer below are the voice session's; anything
      // another server says about them is late news for a share it no longer has.
      case "ScreenShareStarted":
        // Our own share was accepted; anyone else's is news for the UI
        if (b.user_id === this.userId && this === voiceOwner) share.onStarted();
        this.emit("screenshare-started", { user_id: b.user_id, username: b.username, resolution: b.resolution });
        break;
      case "ScreenShareStopped":
        this.emit("screenshare-stopped", { user_id: b.user_id });
        break;
      case "WatchingScreenShare":
        this.emit("watching-screenshare", { sharer_user_id: b.sharer_user_id, codec: b.codec });
        if (this === voiceOwner) {
          video
            .startWatching(b.sharer_user_id, b.codec)
            .catch((e) => console.error("failed to start watching:", e));
        }
        break;
      case "StoppedWatchingScreenShare":
        this.emit("stopped-watching-screenshare", { reason: b.reason });
        if (this === voiceOwner) video.stopWatching();
        break;
      case "ViewerCountChanged":
        this.emit("viewer-count-changed", { viewer_count: b.viewer_count });
        break;
      case "KeyframeRequested":
        // A viewer needs an IDR now
        if (this === voiceOwner) share.requestKeyframe();
        break;
      case "VideoLossReported":
        // A viewer of our share lost frames: step the encoder down
        if (this === voiceOwner) share.onLossReport(b.frames_dropped);
        break;
      case "ScreenShareError":
        // A refused StartScreenShare (already sharing, not in voice) must also
        // tear down the capture the browser already granted us.
        if (this === voiceOwner) share.onServerError();
        this.emit("screenshare-error", { reason: b.reason });
        break;
      case "PreKeyBundle":
        // Their identity against the one first seen for their account.
        this.account?.checkIdentity(this, b.user_id, b.bundle.identity_key);
        this.onPrekeyBundle(b.user_id, b.bundle);
        break;
      // The live path's frames: `ChannelKeying` says what each comes to. During a key job
      // `PreKeysLow` waits for its end: a refill per 50 hellos is a fifth on top of its upload.
      case "PreKeysLow":
      case "TextJoined":
      case "KeysOwed":
      case "SessionAsked":
      case "SessionHello":
      case "TextKeyReceived":
      case "KeyWanted":
      case "ChannelPage":
      case "ChannelMarks":
      case "Evicted":
      case "ChannelExits":
      case "TextPost":
        this.liveFrame(payload);
        break;
      case "MemberGone": {
        // Our chain there ends at our next post, whatever the relay says after this.
        const log = this.channels.find((c) => c.channel_id === b.channel_id)?.log;
        if (log) this.account?.memberGone(log, b.user_id);
        this.liveFrame(payload);
        break;
      }
      case "PreKeyBundleUnavailable": {
        // Remove from pending so we don't loop
        this.pendingSessions.delete(b.user_id);
        this.signal.liveNoBundle(b.user_id);
        // What waited for that session is going nowhere, and looks sent. It
        // need not mean they left: the request may be what was refused.
        const before = this.pendingMessages.length;
        this.pendingMessages = this.pendingMessages.filter(
          (m) => !((m.target.kind === "direct" || m.target.kind === "poke") && m.target.targetUserId === b.user_id),
        );
        const expired = before - this.pendingMessages.length;
        if (expired > 0) this.emit("dm-undelivered", { user_id: b.user_id, expired, kept: this.account?.keptFor(b.user_id) ?? false });
        break;
      }
      case "DirectMessageUndelivered":
        // About a hand-off: nobody wrote anything to anyone
        if (this.signal.liveUndeliveredWasSealed(b.target_user_id)) break;
        // Between two accounts with cloud copies on, it went into the stored log
        // as well (sendDirectMessage): they read it when they are back.
        this.emit("dm-undelivered", {
          user_id: b.target_user_id,
          kept: this.account?.keptFor(b.target_user_id) ?? false,
        });
        break;
      case "IdentityKeyChanged":
        this.emit("identity-key-changed", { user_id: b.user_id, new_identity_key: b.new_identity_key });
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
        this.emit("admin-status", { user_id: b.user_id, is_admin: b.is_admin, own: b.user_id === this.userId });
        break;
      case "AdminError":
        this.emit("admin-error", { reason: b.reason });
        break;
      case "AdminBans":
        this.emit("admin-bans", { bans: banRows(b.bans) });
        break;
      case "AdminBansPaged":
        this.emit("admin-bans-page", { search: b.search, offset: b.offset, total: b.total, bans: banRows(b.bans) });
        break;
      case "Disconnected":
        // The server closes the session right after; the UI must not auto-reconnect
        this.emit("server-disconnected", { reason: b.reason });
        break;
      case "ChannelHistoryRequested":
        this.emit("channel-history-requested", { channel_id: b.channel_id, from_user_id: b.from_user_id });
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
      case "FileUploadReady":
      case "FileStored":
      case "FileReady":
      case "FileRefused":
      case "FileWanted":
      case "FileSeeking":
      case "FileUnavailable":
        this.files?.onMessage(tag, b);
        break;
      case "EmoteList":
      case "EmoteTicket":
      case "EmoteError":
        this.emotes?.onMessage(tag, b);
        break;
      default:
        console.warn("unhandled server message:", tag);
    }
  }

  /** The rows of a list: who is which account, for the pins, and a bare id in `KeysOwed`
   *  goes by these. A first sight is checked against the pins. */
  private noteRows(users: unknown[]): void {
    this.account?.noteRoster(this, users);
    try {
      for (const row of this.signal.liveNoteRows(users)) {
        if (row.identity) this.account?.checkIdentity(this, row.user_id, row.identity);
      }
    } catch (e) {
      console.warn("could not read a list's rows:", e);
    }
  }

  /** One frame of the live path, through `ChannelKeying`, and whatever it says to do. */
  private liveFrame(payload: Uint8Array): void {
    const out = this.signal.liveFrame(this.channelId, payload);
    // Channels newly followed: keep their logs, all in one frame, and read what they kept.
    const logOf = (channelId: number) => this.channels.find((c) => c.channel_id === channelId)?.log;
    for (const channelId of out.gated) {
      const log = logOf(channelId);
      if (log) this.account?.noteGatedLog(log);
    }
    const logs = [...out.entered].map(logOf);
    this.account?.enterMany(this, logs.filter((log): log is string => !!log));
    this.runLive(out);
  }

  /** What the live path asked for: the pins checked first, then its frames and events
   *  (network.rs run_live). */
  private runLive(out: LiveOut): void {
    this.account?.noteGatedPeople(out.gated_people);
    for (const seen of out.seen) {
      this.account?.notePerson(this, seen.user_id, seen.account, seen.name);
      if (seen.identity) this.account?.checkIdentity(this, seen.user_id, seen.identity);
    }
    for (const { user_id, key } of out.check) this.account?.checkIdentity(this, user_id, key);
    for (const frame of out.send) this.sendRaw(frame);
    for (const { name, payload } of out.emit) this.emit(name, payload);
    for (const userId of out.made) this.markEstablished(userId);
    for (const userId of out.gone) this.establishedSessions.delete(userId);
    if (out.work) this.live.wake();
  }

  /** A second's work: posts and rounds that ran out, and old session keys going. */
  private liveTick(): void {
    if (this.ended) return;
    try {
      this.runLive(this.signal.liveTick());
    } catch (e) {
      console.warn("the live path's tick failed:", e);
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
    // no media key, no room, no share, and we stay where we stand. No key work
    // starts from a list either: only who it names, and only so it can be drawn.
    if (this.isTextChannel(channelId)) {
      this.emit("user-list", { channel_id: channelId, users });
      return;
    }

    // A voice seat we did not ask this server for is refused, before anything
    // here changes: taking voice ends the call on whichever server had it and
    // opens the microphone into a room whose members, and so whose media key,
    // this server chooses. One that already carries our voice may still move
    // us between its own rooms. Mirrors network.rs handle_server_message.
    if (channelId !== 0 && voiceOwner !== this && !this.takeVoiceAsk()) {
      console.warn(`${this.server} seated us in voice channel ${channelId} unasked; leaving it`);
      this.sendControl({ JoinChannel: { channel_id: 0, password: null } });
      this.emit("channel-error", {
        reason: "The server put you in a voice channel you did not join — you were taken out of it again",
      });
      return;
    }

    // Server-initiated moves (create_channel auto-join, kicks, invites) land here
    const oldChannel = this.channelId;
    this.channelId = channelId;
    // Before the move below, so what it does to the media lands on this
    // session's freshly attached modules.
    const tookVoice = channelId !== 0 && voiceOwner !== this;
    if (tookVoice) takeVoice(this);
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
      const anonymous = this.channels.find((c) => c.channel_id === channelId)?.anonymous;
      this.signal.wantHistoryFrom(channelId, anonymous ? new Uint32Array() : this.historySources(users));
      if (this.watchingUserId !== 0) {
        this.watchingUserId = 0;
        this.sendControl("StopWatchingScreenShare");
        this.emit("screen-share-force-stopped");
        if (this === voiceOwner) video.stopWatching();
      }
      // Our own share belonged to the old channel's members and its media key
      if (this === voiceOwner && share.sharing) share.stop();
    }
    // A fresh attach starts flat, so the room's mode is set even when the
    // channel id itself did not change.
    if (this === voiceOwner && (tookVoice || oldChannel !== channelId)) {
      audio.onChannelChanged(this.proximityOf(channelId));
    }
    // Out of voice, a kick included: close the mic. VAD and always-on would
    // otherwise keep capturing in a channel that carries no media.
    if (channelId === 0 && this === voiceOwner) {
      void audio.stopTransmit();
      detachVoice();
    }

    // Only a room has a key dance to do; General's list costs nothing, and anyone in it
    // gets a session when there is something to say to them.
    if (asksBundles(channelId, channelId)) this.requestPrekeyBundlesForUsers(users);

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

    this.emit("user-list", { channel_id: channelId, users });
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

  /** Establish the pairwise session, then hand over our sender key (and media key) for the room we stand in. */
  private onPrekeyBundle(remoteUserId: number, bundle: PreKeyBundleData): void {
    const queued = this.pendingMessages.some(
      (m) =>
        (m.target.kind === "direct" || m.target.kind === "poke") &&
        m.target.targetUserId === remoteUserId &&
        Date.now() - m.queuedAt < PENDING_MESSAGE_TTL_MS,
    );
    if (!queued && !this.signal.liveBundleWanted(remoteUserId, this.channelId)) {
      // Verify's, or what it was for has run out: its identity is what counted, and went past
      // the pins. Nothing to send means no session (`live_bundle_wanted`).
      this.pendingSessions.delete(remoteUserId);
      this.drainPendingDms(remoteUserId);
      return;
    }
    try {
      this.signal.establishSession(remoteUserId, bundle);
    } catch (e) {
      console.warn(`failed to establish E2E session with ${remoteUserId}:`, e);
      this.pendingSessions.delete(remoteUserId);
      return;
    }
    this.markEstablished(remoteUserId);

    // A text channel's key goes to who a check named, and a session opening names nobody
    if (this.channelId !== 0) this.distributeSenderKeyToUser(this.channelId, remoteUserId);
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
    this.emit("media-key-installed", { channel_id: channelId, key_id: keyId });
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
    // Channel 0 carries no media, so it never gets a key to rotate
    if (channelId === 0 || this.signal.mediaKeyMinter(channelId) !== this.userId) return;
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
      plaintext = this.decrypt(fromUserId, ciphertext, messageType);
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
        this.emit("media-key-installed", { channel_id: channelId, key_id: this.mediaKeys.keyId ?? 0 });
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
      const plaintext = this.decrypt(fromUserId, ciphertext, messageType);
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

  /** Recent channel chat for a newcomer, pairwise-encrypted (commands.rs send_channel_history).
   *  `sealed`: the ask came as a direct message, so the answer goes the same way. */
  sendChannelHistory(channelId: number, targetUserId: number, messages: unknown[], sealed: boolean): void {
    if (this.signal.livePinsOut()) throw new Error("the pins are not in yet");
    if (sealed) {
      this.sendRaw(this.signal.liveSealAnswer(channelId, targetUserId, JSON.stringify(messages)));
      return;
    }
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
    // and hand it to the next newcomer as `shared`. No roster says who is in a
    // text channel: there it has to be somebody we asked, lately.
    const welcome = this.signal.isTextChannel(channelId)
      ? this.signal.liveAnswerWanted(channelId, fromUserId)
      : this.signal.sharesChannelWith(this.channelId, channelId, fromUserId);
    if (!welcome) {
      console.warn(`channel history from ${fromUserId} for channel ${channelId}: not a member, dropped`);
      return;
    }
    let messages: unknown[];
    try {
      const plaintext = this.decrypt(fromUserId, ciphertext, messageType);
      messages = JSON.parse(wasm().openHistoryPayload(channelId, plaintext));
    } catch (e) {
      console.warn(`channel history from ${fromUserId} rejected:`, e);
      return;
    }
    if (messageType === 1) this.markEstablished(fromUserId);
    this.emit("channel-history-received", {
      channel_id: channelId,
      from_user_id: fromUserId,
      from_username: fromUsername,
      messages,
    });
  }

  private markEstablished(userId: number): void {
    this.establishedSessions.add(userId);
    this.pendingSessions.delete(userId);
    this.signal.liveSessionUp(userId);
    // The session they opened is the one what we queued for them waited for
    this.drainPendingDms(userId);
  }

  /**
   * Take the queued messages for `matches`, dropping those older than the TTL.
   * `undelivered` is the event that says so: they were shown as sent (H4-10).
   */
  private takePending(
    matches: (t: PendingTarget) => boolean,
    undelivered: [string, Record<string, number>],
  ): { target: PendingTarget; id: string; content: string; ttlSecs?: number; refs?: MessageRefs }[] {
    const now = Date.now();
    const send: { target: PendingTarget; id: string; content: string; ttlSecs?: number; refs?: MessageRefs }[] = [];
    const remaining: PendingMessage[] = [];
    let expired = 0;
    for (const m of this.pendingMessages) {
      if (!matches(m.target)) remaining.push(m);
      else if (now - m.queuedAt < PENDING_MESSAGE_TTL_MS) send.push({ target: m.target, id: m.id, content: m.content, ttlSecs: m.ttlSecs, refs: m.refs });
      else expired++;
    }
    if (expired > 0) {
      console.warn(`dropped ${expired} expired pending messages`);
      this.emit(undelivered[0], { ...undelivered[1], expired });
    }
    this.pendingMessages = remaining;
    return send;
  }

  private drainPendingDms(targetUserId: number): void {
    const waiting = this.takePending((t) => (t.kind === "direct" || t.kind === "poke") && t.targetUserId === targetUserId, [
      "dm-undelivered",
      { user_id: targetUserId },
    ]);
    for (const { target, id, content, ttlSecs, refs } of waiting) {
      try {
        if (target.kind === "poke") {
          this.sendPokeNow(targetUserId, content);
          continue;
        }
        const { ciphertext, message_type } = this.signal.encrypt(
          targetUserId,
          wasm().envelope(id, content, ttlSecs, refs),
        );
        this.sendControl({ SendEncryptedDirectMessage: { target_user_id: targetUserId, ciphertext, message_type } });
      } catch (e) {
        console.warn(`failed to encrypt queued DM to ${targetUserId}:`, e);
      }
    }
  }

  private drainPendingChannelMessages(channelId: number): void {
    const pending = this.takePending((t) => t.kind === "channel" && t.channelId === channelId, [
      "channel-undelivered",
      { channel_id: channelId },
    ]);
    if (pending.length === 0) return;
    // Written before we had anybody to send them to, and somebody may have
    // left the channel in between — in which case our chain is stale and the
    // leaver can still read along it. Sending is what costs a rotation, and
    // this is a send (network.rs drain_pending_channel_messages).
    this.rotateSenderKeyIfStale(channelId);
    for (const { id, content, ttlSecs, refs } of pending) {
      try {
        const ciphertext = this.signal.groupEncrypt(
          this.userId,
          channelId,
          wasm().envelope(id, content, ttlSecs, refs),
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
      const plaintext = this.decrypt(fromUserId, ciphertext, messageType);
      if (messageType === 1) this.markEstablished(fromUserId);
      // A history hand-off, before anything could show it: no line, no toast, no copy,
      // and no window flashing at the person who was only asked.
      const sealed = wasm().openSealed(plaintext);
      if (sealed) {
        this.routeSealed(sealed, fromUserId, fromUsername);
        return;
      }
      this.account?.noteDirect(fromUserId);
      // A DM carries the same envelope a channel message does since 0.9.0;
      // anything else reads as the text itself.
      const { id, text, ttl_secs, reply_to, thread, file, fwd, event: done } = wasm().openEnvelope(plaintext);
      this.emit("direct-chat-message", { ...event, content: text, message_id: id, ttl_secs, reply_to, thread, file, fwd, event: done });
    } catch (e) {
      console.warn(`failed to decrypt direct message from ${fromUserId}:`, e);
      this.emit("direct-chat-message", {
        ...event,
        content: "[encrypted message — decryption failed]",
        decryption_failed: true,
      });
    }
  }

  /** A hand-off that came as a direct message, into what the relay-checked frames come to.
   *  An ask goes to the front end, whose one rule decides (`answersHandOff`); an answer is
   *  taken only from someone we asked. */
  private routeSealed(sealed: Sealed, fromUserId: number, fromUsername: string): void {
    if ("ask" in sealed) {
      this.emit("channel-history-requested", { channel_id: sealed.ask, from_user_id: fromUserId, sealed: true });
    } else if ("answer" in sealed && this.signal.liveAnswerWanted(sealed.answer, fromUserId)) {
      this.emit("channel-history-received", {
        channel_id: sealed.answer,
        from_user_id: fromUserId,
        from_username: fromUsername,
        messages: sealed.messages,
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
      const { id, text, ttl_secs, reply_to, thread, file, fwd, event: done } = wasm().openEnvelope(plaintext);
      // What the sender says this message's life is; the store takes the
      // shorter of it and the channel's own timer (expiryFor, chat-rules.ts).
      this.emit("channel-chat-message", { ...event, content: text, message_id: id, ttl_secs, reply_to, thread, file, fwd, event: done });
    } catch (e) {
      console.warn(`failed to decrypt channel message from ${userId}:`, e);
      this.emit("channel-chat-message", {
        ...event,
        content: "[encrypted message — decryption failed]",
        decryption_failed: true,
      });
    }
  }

  private onPokeReceived(fromUserId: number, fromUsername: string, ciphertext: Uint8Array, messageType: number): void {
    let message = "";
    try {
      const plaintext = this.decrypt(fromUserId, ciphertext, messageType);
      if (messageType === 1) this.markEstablished(fromUserId);
      message = utf8Decoder.decode(plaintext);
    } catch (e) {
      console.warn(`failed to decrypt poke from ${fromUserId}:`, e);
    }
    this.emit("poke-received", { from_user_id: fromUserId, from_username: fromUsername, message });
    // Also inject the poke as a DM so it appears in chat history
    if (message !== "") {
      this.emit("direct-chat-message", {
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

  /** We are about to ask this server for a voice seat; before the request, so its answer cannot beat it. */
  askVoice(): void {
    this.voiceAskedAt = Date.now();
  }

  /** Whether the seat just given was asked for lately; one ask pays for one seat. */
  private takeVoiceAsk(): boolean {
    const at = this.voiceAskedAt;
    this.voiceAskedAt = 0;
    return at !== 0 && Date.now() - at < VOICE_ASK_TTL_MS;
  }

  watchScreenShare(sharerUserId: number): void {
    this.sendControl({ WatchScreenShare: { sharer_user_id: sharerUserId } });
    this.watchingUserId = sharerUserId;
  }

  /** No-op if not watching. */
  stopWatchingScreenShare(): void {
    if (this.watchingUserId === 0) return;
    this.stopWatching();
    if (this === voiceOwner) video.stopWatching();
  }

  /** SessionContext: used by the video module when it gives up on a stream. */
  stopWatching(): void {
    if (this.watchingUserId === 0) return;
    this.sendControl("StopWatchingScreenShare");
    this.watchingUserId = 0;
  }

  private sendPokeNow(targetUserId: number, message: string): void {
    const { ciphertext, message_type } = this.signal.encrypt(targetUserId, utf8.encode(message));
    this.sendControl({ SendPoke: { target_user_id: targetUserId, ciphertext, message_type } });
  }

  /** Poke: pairwise-encrypted. Nothing opened a session with them yet, and one kept from
   *  before is a key's alone: it waits, as a direct message does, for one both ends hold. */
  sendPoke(targetUserId: number, message: string): void {
    if (this.establishedSessions.has(targetUserId)) {
      try {
        this.sendPokeNow(targetUserId, message);
      } catch (e) {
        throw new Error(`poke encryption failed: ${errorText(e)}`);
      }
    } else {
      this.pendingMessages.push({ target: { kind: "poke", targetUserId }, id: "", content: message, queuedAt: Date.now() });
      this.requestPrekeyBundlesForUsers([{ user_id: targetUserId }]);
    }
    // Emit the poke as a local DM for the sender's chat history
    if (message !== "") {
      this.emit("direct-chat-message", {
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

  /** A direct message for an account that is away (hex id): kept in the
   *  stored log only, which is the one way it reaches them. Returns its id. */
  sendKeptDm(accountHex: string, content: string, ttlSecs?: number, refs?: MessageRefs): string {
    if (!this.account) throw new Error("Not signed in to an account on that server");
    const messageId = wasm().newMessageId();
    // A report kept for this one message: the dialog asked. Anything else needs
    // cloud copies on.
    const once = !!refs?.fwd?.report;
    this.account.keptDm(this, accountHex, wasm().envelope(messageId, content, ttlSecs, refs), ttlSecs, once);
    return messageId;
  }

  /** Sender-key encrypted channel message; queued until a sender key was distributed. */
  sendChannelMessage(content: string, channelId = this.channelId, ttlSecs?: number, refs?: MessageRefs): void {
    if (channelId === 0) throw new Error("Chat is not available in the lobby");

    this.rotateSenderKeyIfStale(channelId);

    // The id travels inside the ciphertext, so our own echo and every
    // receiver's copy file the message under the same one.
    const messageId = wasm().newMessageId();
    // A channel with a log keeps it for its members too (cloud copies on),
    // whether or not anybody is here to read it now.
    const log = this.channels.find((c) => c.channel_id === channelId)?.log;
    if (log) this.account?.outgoingChannel(this, log, wasm().envelope(messageId, content, ttlSecs, refs), ttlSecs);
    const event = {
      channel_id: channelId,
      user_id: this.userId,
      username: this.username,
      content,
      timestamp: Date.now(),
      message_id: messageId,
      ttl_secs: ttlSecs ?? null,
      reply_to: refs?.replyTo ?? null,
      thread: refs?.thread ?? null,
      file: refs?.file ?? null,
      fwd: refs?.fwd ?? null,
      event: refs?.event ?? null,
    };
    // In a text channel the keys follow the post (`ChannelKeying::live_post`). Our own row
    // shows it as sent: the check and the keys are the app's to do, and
    // `channel-undelivered` says so if they cannot be.
    if (this.isTextChannel(channelId)) {
      this.runLive(this.signal.livePost(channelId, wasm().envelope(messageId, content, ttlSecs, refs)));
      this.emit("channel-chat-message", { ...event, encrypted: true });
      return;
    }
    let ciphertext: Uint8Array | null = null;
    if (this.signal.anyoneHoldsOurKey(channelId)) {
      try {
        ciphertext = this.signal.groupEncrypt(
          this.userId,
          channelId,
          wasm().envelope(messageId, content, ttlSecs, refs),
        );
      } catch (e) {
        console.info("group encryption not ready, queueing message:", e);
      }
    }
    if (ciphertext) {
      this.sendControl({ SendEncryptedChannelMessage: { channel_id: channelId, ciphertext } });
      // The server excludes us from the encrypted broadcast: show it locally
      this.emit("channel-chat-message", { ...event, encrypted: true });
    } else {
      // Sent once sender key distribution completes; shown immediately as pending
      this.pendingMessages.push({ target: { kind: "channel", channelId }, id: messageId, content, ttlSecs, refs, queuedAt: Date.now() });
      this.emit("channel-chat-message", { ...event, pending: true });
    }
  }

  /**
   * Ask named members for a channel's recent chat (commands.rs
   * request_channel_history): the user asking again, after clearing a channel
   * by accident or because somebody who was away is here now. Who was asked.
   */
  requestChannelHistory(channelId: number, targetUserIds: number[]): number[] {
    if (this.channels.find((c) => c.channel_id === channelId)?.anonymous) throw new Error("an anonymous channel shares no history");
    const text = this.isTextChannel(channelId);
    // Sealed: the relay sees "R wrote to S", not for which channel. It goes when a session
    // both ends hold is up, opened for it if need be. Under the new-member wait a direct
    // message is refused, so there the plain frames below ask whoever already has a session.
    if (text && !this.directHeld) {
      const asked = this.signal.liveAskHistory(channelId, Uint32Array.from(targetUserIds));
      if (asked.length === 0) throw new Error("nobody here can share that history yet");
      this.live.wake();
      return [...asked];
    }
    // A pairwise session is all an answer needs — history travels over that,
    // not over the channel's group key, and asking for the group key here
    // would block the one repair a member has when keying went wrong.
    const reachable = Uint32Array.from(targetUserIds.filter((uid) => this.establishedSessions.has(uid)));
    const targets = wasm().pickHistorySources(reachable);
    if (targets.length === 0) throw new Error("nobody here can share that history yet");
    for (const target_user_id of targets) {
      if (text) this.signal.liveNoteAsked(channelId, target_user_id);
      this.sendControl({ RequestChannelHistory: { channel_id: channelId, target_user_id } });
    }
    return [...targets];
  }

  /** Follow these text channels, whole or quiet, in one frame. It tells nobody, and a gate or
   *  a channel that is not there comes back in `TextJoined`'s `refused`, in the same words. */
  joinTextChannels(channels: number[], quiet: number[]): void {
    const sorted = (ids: number[]) => [...new Set(ids)].sort((a, b) => a - b);
    this.signal.liveSetQuiet(Uint32Array.from(quiet), true);
    this.sendControl({ JoinTextChannels: { channels: sorted(channels), quiet: sorted(quiet) } });
  }

  /** Take followed channels whole or quiet: going quiet is no exit, and whole again is
   *  answered like a join. */
  setQuiet(channels: number[], quiet: boolean): void {
    this.signal.liveSetQuiet(Uint32Array.from(channels), quiet);
    this.sendControl({ SetQuiet: { channels, quiet } });
  }

  /** A person's answer to `key-job-ask`: go on with it, or drop what waits behind it. */
  keyJobAnswer(channelId: number, go: boolean): void {
    this.runLive(this.signal.liveAnswerJob(channelId, go));
  }

  /** Pairwise-encrypted DM; queued until the Signal session exists. */
  sendDirectMessage(targetUserId: number, content: string, ttlSecs?: number, refs?: MessageRefs): void {
    // The same envelope a channel message uses since 0.9.0: a DM had nowhere to
    // put a destruction timer while it was raw text, and this also gives it the
    // id it never had. `openEnvelope` reads plain text as text, so a peer that
    // sends the old shape still arrives.
    const messageId = wasm().newMessageId();
    // Between two accounts, and with cloud copies on, it is kept for them too.
    this.account?.outgoingDm(this, targetUserId, wasm().envelope(messageId, content, ttlSecs, refs), ttlSecs);
    let encrypted: { ciphertext: Uint8Array; message_type: number } | null = null;
    if (this.establishedSessions.has(targetUserId)) {
      try {
        encrypted = this.signal.encrypt(targetUserId, wasm().envelope(messageId, content, ttlSecs, refs));
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
      reply_to: refs?.replyTo ?? null,
      thread: refs?.thread ?? null,
      file: refs?.file ?? null,
      fwd: refs?.fwd ?? null,
      event: refs?.event ?? null,
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
      this.emit("direct-chat-message", { ...event, encrypted: true });
    } else {
      this.pendingMessages.push({ target: { kind: "direct", targetUserId }, id: messageId, content, ttlSecs, refs, queuedAt: Date.now() });
      this.emit("direct-chat-message", { ...event, pending: true });
      // Rosters only start one with people our rooms told us of
      this.requestPrekeyBundlesForUsers([{ user_id: targetUserId }]);
    }
  }
}


function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
