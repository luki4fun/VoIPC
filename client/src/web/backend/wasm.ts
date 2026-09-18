// Typed facade over the wasm-pack output of crates/voipc-web (protocol codec,
// Signal Protocol, media crypto, video reassembly). This is the ONLY module
// that imports the generated package, so the rest of the web backend compiles
// against these interfaces even before `npm run build:wasm` has run.
//
// Contract (must match crates/voipc-web/src/lib.rs exactly):
//  - Messages are plain JS objects in serde's externally-tagged form:
//      { JoinChannel: { channel_id: 1, password: null } }   struct variant
//      "Disconnect"                                          unit variant
//    Decoded `Vec<u8>` fields are `number[]`; when building messages either
//    `number[]` or `Uint8Array` is accepted. Decoded `u64` fields are `bigint`;
//    when building, a JS number or bigint is accepted.
//  - All calls are synchronous. Failures throw an Error with a message.

export interface SignalClient {
  /** { identity_key: number[], prekey_bundle: PreKeyBundleData } for Authenticate. */
  bundle(): { identity_key: number[]; prekey_bundle: PreKeyBundleData };
  /** X3DH with a peer's bundle (as decoded from ServerMessage.PreKeyBundle.bundle). */
  establishSession(userId: number, bundle: PreKeyBundleData): void;
  encrypt(userId: number, plaintext: Uint8Array): { ciphertext: Uint8Array; message_type: number };
  decrypt(userId: number, ciphertext: Uint8Array, messageType: number): Uint8Array;
  createSenderKeyDistribution(ownUserId: number, channelId: number): Uint8Array;
  processSenderKeyDistribution(fromUserId: number, channelId: number, bytes: Uint8Array): void;
  groupEncrypt(ownUserId: number, channelId: number, plaintext: Uint8Array): Uint8Array;
  groupDecrypt(fromUserId: number, channelId: number, ciphertext: Uint8Array): Uint8Array;

  // Channel membership and sender-key bookkeeping — the same
  // voipc_crypto::ChannelKeying the native client uses, so both answer
  // "may I install this key / show this message / hand over this history"
  // from one implementation rather than two that drift.
  inChannel(ownChannel: number, channelId: number): boolean;
  sharesChannelWith(ownChannel: number, channelId: number, userId: number): boolean;
  isMember(channelId: number, userId: number): boolean;
  isTextChannel(channelId: number): boolean;
  textChannels(): Uint32Array;
  setMembers(channelId: number, userIds: Uint32Array): void;
  addMember(channelId: number, userId: number): void;
  dropMember(channelId: number, userId: number): void;
  /** Everybody in the channel except us. */
  othersIn(channelId: number, ownUserId: number): Uint32Array;
  /** Subscribe to a text channel; `true` if it is new to us. */
  joinTextChannel(channelId: number): boolean;
  resetChannel(ownUserId: number, channelId: number): void;
  forgetChannel(ownUserId: number, channelId: number): void;
  noteStale(channelId: number): void;
  /**
   * If a rotation is pending, perform it and return who needs the new key.
   * The chain is forgotten whether or not anybody is left to tell — returning
   * early on an empty set is what once left a two-person channel writing on
   * the key the member who left still had.
   */
  takeRotationTargets(ownUserId: number, channelId: number): Uint32Array;
  recordDistributed(channelId: number, userId: number): void;
  hasDistributed(channelId: number, userId: number): boolean;
  anyoneHoldsOurKey(channelId: number): boolean;
  recordReceived(channelId: number, userId: number): void;
  wantHistoryFrom(channelId: number, userIds: Uint32Array): void;
  /** Whether we were still waiting to ask this member; consumes the intent. */
  takeHistoryWanted(channelId: number, userId: number): boolean;
  /** The lowest remaining member: who mints the channel's next media key. */
  mediaKeyMinter(channelId: number): number | undefined;

  free(): void;
  [Symbol.dispose](): void;
}

/**
 * The media keys held for the channel we are in: the one we encrypt with, the
 * one before it, and our own nonce prefix.
 *
 * Two generations because a member leaving re-keys the channel and a packet
 * already in flight still names the one before — dropping those would be an
 * audible gap on every leave.
 */
export interface MediaKeys {
  /** Mint a generation of our own: first member, or elected to re-key. */
  generate(channelId: number, keyId: number, minter: number): boolean;
  /**
   * Install a key received over a Signal session; `true` if it superseded.
   *
   * `ownChannel` is the room we are in: the channel named inside a key is its
   * sender's claim, and one for anywhere else is refused rather than kept.
   */
  install(bytes: Uint8Array, ownChannel: number): boolean;
  /** The generation after the one we hold. Wraps — `keyId` is a counter. */
  nextKeyId(): number | undefined;
  /**
   * The generation to mint next for a channel: the one after ours, or the
   * channel's first where we hold no key for it. What the member elected to
   * mint asks after somebody leaves.
   */
  nextGeneration(channelId: number): number;
  /** The key we encrypt with, to hand to another member. */
  toBytes(): Uint8Array | undefined;
  hasChannel(channelId: number): boolean;
  clear(): void;
  readonly channelId: number | undefined;
  readonly keyId: number | undefined;
  free(): void;
  // wasm-bindgen generates this on every exported class
  [Symbol.dispose](): void;
}

export interface VideoAssembler {
  /**
   * Feed one encrypted video fragment packet (0x13/0x14). Returns the
   * reassembled frame when complete. Throws on decrypt failure.
   */
  push(keys: MediaKeys, channelId: number, bytes: Uint8Array): {
    frame?: Uint8Array;
    is_keyframe: boolean;
    timestamp: number;
    frame_dropped: boolean;
  };
  reset(): void;
  free(): void;
  [Symbol.dispose](): void;
}

export interface PreKeyBundleData {
  registration_id: number;
  device_id: number;
  identity_key: number[];
  signed_prekey_id: number;
  signed_prekey: number[];
  signed_prekey_signature: number[];
  prekeys: { id: number; public_key: number[] }[];
}

/** Header of an unencrypted voice-family packet: EOT 0x02, Ping 0x03, Pong 0x04. */
export interface VoicePacketHeader {
  packet_type: number;
  session_id: number;
  sequence: number;
}

/** A decrypted voice packet (0x05). */
export interface DecryptedVoice extends VoicePacketHeader {
  opus: Uint8Array;
}

/** A peer's position in metres (x/y ground plane, z up). */
export interface DecryptedPosition {
  session_id: number;
  x: number;
  y: number;
  z: number;
}

export interface ScreenAudioInfo {
  session_id: number;
  sequence: number;
  timestamp: number;
  opus: Uint8Array;
}

export interface WasmApi {
  protocolVersion(): number;
  appVersion(): string;
  /** postcard bytes of a ClientMessage, WITHOUT the u32 length prefix. */
  encodeClientMsg(msg: unknown): Uint8Array;
  /** Decodes postcard bytes (without length prefix) into a ServerMessage object. */
  decodeServerMsg(bytes: Uint8Array): unknown;
  /** Fresh ephemeral identity + registration id + signed pre-key 1 + 100 one-time pre-keys. */
  newSignalClient(): SignalClient;
  newMediaKeys(): MediaKeys;
  newVideoAssembler(): VideoAssembler;
  /** Largest opaque blob the relay will re-wrap and forward. */
  maxRelayCiphertext(): number;
  /**
   * Of the members who offer a channel's recent chat, the few actually asked —
   * picked at random, so a whole server reconnecting does not aim every
   * request at the same two or three people.
   */
  pickHistorySources(sharers: Uint32Array): Uint32Array;
  /** Control messages a second one connection may send (we stay under it). */
  controlMsgsPerSec(): number;
  /** A fresh message id: 16 random bytes, hex. */
  newMessageId(): string;
  /** Packs a channel message so it carries an id the server never sees. */
  /** Pack a message with its id and, where the conversation has one, its
   * destruction timer in seconds — both inside the ciphertext. */
  envelope(id: string, text: string, ttlSecs?: number): Uint8Array;
  openEnvelope(plaintext: Uint8Array): { id: string | null; text: string; ttl_secs: number | null };
  /**
   * Packs recent chat with the channel bound inside the ciphertext. The
   * messages travel as JSON text: a chat message has no fixed shape on this
   * boundary, and the JS-value path loses a shapeless object in both
   * directions without saying so.
   */
  historyPayload(channelId: number, messagesJson: string): Uint8Array;
  /** The messages as JSON text. Throws when the payload names a different
   *  channel than the server said it arrived in. */
  openHistoryPayload(channelId: number, payload: Uint8Array): string;
  /** Encrypted voice packet (0x05); AAD channel id comes from the key. */
  buildVoicePacket(keys: MediaKeys, sessionId: number, sequence: number, opus: Uint8Array): Uint8Array;
  buildEotPacket(sessionId: number, sequence: number): Uint8Array;
  buildPingPacket(sessionId: number, sequence: number): Uint8Array;
  /** Header of an EOT/Ping/Pong packet (0x02/0x03/0x04); throws on voice packets. */
  parseVoiceHeader(bytes: Uint8Array): VoicePacketHeader;
  /** Decrypts an encrypted voice packet (0x05); throws on any other type or on failed authentication. */
  decryptVoicePacket(keys: MediaKeys, channelId: number, bytes: Uint8Array): DecryptedVoice;
  /** Encrypted position beacon (0x06) carrying our own position, in metres. */
  buildPositionPacket(
    keys: MediaKeys,
    sessionId: number,
    sequence: number,
    x: number,
    y: number,
    z: number,
  ): Uint8Array;
  /** Decrypts a position beacon (0x06); throws on any other type or on failed authentication. */
  decryptPositionPacket(keys: MediaKeys, channelId: number, bytes: Uint8Array): DecryptedPosition;
  /** Encrypted screen-share audio packet (0x15). Throws on failure. */
  parseScreenAudioPacket(keys: MediaKeys, channelId: number, bytes: Uint8Array): ScreenAudioInfo;
  /** Encrypted screen-share audio packet (0x15) for one Opus frame we captured. */
  buildScreenAudioPacket(
    keys: MediaKeys,
    sessionId: number,
    sequence: number,
    timestamp: number,
    opus: Uint8Array,
  ): Uint8Array;
  /**
   * One encoded video frame as the body of its per-frame stream: encrypted
   * fragments, each behind a u16 big-endian length. Throws when the frame needs
   * more than 255 fragments (~316 KB) — the caller must lower the bitrate
   * instead of sending a frame the viewers cannot reassemble.
   */
  buildVideoFrameStream(
    keys: MediaKeys,
    sessionId: number,
    frameId: number,
    timestamp: number,
    isKeyframe: boolean,
    frame: Uint8Array,
  ): Uint8Array;
}

let api: WasmApi | null = null;

/** Loads and instantiates the wasm module once. */
export async function loadWasm(): Promise<WasmApi> {
  if (api) return api;
  // Generated by `npm run build:wasm` (wasm-pack --target web).
  // @ts-ignore — the package only exists after the wasm build
  const mod = await import("../../lib/wasm/voipc_web.js");
  await mod.default();
  api = {
    protocolVersion: () => mod.protocolVersion(),
    appVersion: () => mod.appVersion(),
    encodeClientMsg: (m) => mod.encodeClientMsg(m),
    decodeServerMsg: (b) => mod.decodeServerMsg(b),
    newSignalClient: () => new mod.SignalClient(),
    newMediaKeys: () => new mod.MediaKeys(),
    newVideoAssembler: () => new mod.VideoAssembler(),
    maxRelayCiphertext: () => mod.maxRelayCiphertext(),
    pickHistorySources: (s) => mod.pickHistorySources(s),
    controlMsgsPerSec: () => mod.controlMsgsPerSec(),
    newMessageId: () => mod.newMessageId(),
    envelope: (id, text, ttlSecs) => mod.envelope(id, text, ttlSecs),
    openEnvelope: (p) => mod.openEnvelope(p),
    historyPayload: (c, m) => mod.historyPayload(c, m),
    openHistoryPayload: (c, p) => mod.openHistoryPayload(c, p),
    buildVoicePacket: (keys, s, q, o) => mod.buildVoicePacket(keys, s, q, o),
    buildEotPacket: (s, q) => mod.buildEotPacket(s, q),
    buildPingPacket: (s, q) => mod.buildPingPacket(s, q),
    parseVoiceHeader: (b) => mod.parseVoiceHeader(b),
    decryptVoicePacket: (keys, c, b) => mod.decryptVoicePacket(keys, c, b),
    buildPositionPacket: (keys, s, q, x, y, z) => mod.buildPositionPacket(keys, s, q, x, y, z),
    decryptPositionPacket: (keys, c, b) => mod.decryptPositionPacket(keys, c, b),
    parseScreenAudioPacket: (keys, c, b) => mod.parseScreenAudioPacket(keys, c, b),
    buildScreenAudioPacket: (keys, s, q, t, o) => mod.buildScreenAudioPacket(keys, s, q, t, o),
    buildVideoFrameStream: (keys, s, f, t, k, d) => mod.buildVideoFrameStream(keys, s, f, t, k, d),
  };
  return api;
}

/** The loaded API; throws if `loadWasm()` has not completed. */
export function wasm(): WasmApi {
  if (!api) throw new Error("wasm not loaded");
  return api;
}
