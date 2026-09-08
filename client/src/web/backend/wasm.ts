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
  free(): void;
  [Symbol.dispose](): void;
}

export interface MediaKey {
  toBytes(): Uint8Array;
  readonly channelId: number;
  readonly keyId: number;
  free(): void;
  // wasm-bindgen generates this on every exported class
  [Symbol.dispose](): void;
}

export interface VideoAssembler {
  /**
   * Feed one encrypted video fragment packet (0x13/0x14). Returns the
   * reassembled frame when complete. Throws on decrypt failure.
   */
  push(key: MediaKey, bytes: Uint8Array): {
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
  generateMediaKey(channelId: number, keyId: number): MediaKey;
  mediaKeyFromBytes(bytes: Uint8Array): MediaKey;
  newVideoAssembler(): VideoAssembler;
  /** Encrypted voice packet (0x05); AAD channel id comes from the key. */
  buildVoicePacket(key: MediaKey, sessionId: number, sequence: number, opus: Uint8Array): Uint8Array;
  buildEotPacket(sessionId: number, sequence: number): Uint8Array;
  buildPingPacket(sessionId: number, sequence: number): Uint8Array;
  /** Header of an EOT/Ping/Pong packet (0x02/0x03/0x04); throws on voice packets. */
  parseVoiceHeader(bytes: Uint8Array): VoicePacketHeader;
  /** Decrypts an encrypted voice packet (0x05); throws on any other type or on failed authentication. */
  decryptVoicePacket(key: MediaKey, bytes: Uint8Array): DecryptedVoice;
  /** Encrypted screen-share audio packet (0x15). Throws on failure. */
  parseScreenAudioPacket(key: MediaKey, bytes: Uint8Array): ScreenAudioInfo;
  /** Encrypted screen-share audio packet (0x15) for one Opus frame we captured. */
  buildScreenAudioPacket(
    key: MediaKey,
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
    key: MediaKey,
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
    generateMediaKey: (c, k) => mod.MediaKey.generate(c, k),
    mediaKeyFromBytes: (b) => mod.MediaKey.fromBytes(b),
    newVideoAssembler: () => new mod.VideoAssembler(),
    buildVoicePacket: (key, s, q, o) => mod.buildVoicePacket(key, s, q, o),
    buildEotPacket: (s, q) => mod.buildEotPacket(s, q),
    buildPingPacket: (s, q) => mod.buildPingPacket(s, q),
    parseVoiceHeader: (b) => mod.parseVoiceHeader(b),
    decryptVoicePacket: (key, b) => mod.decryptVoicePacket(key, b),
    parseScreenAudioPacket: (key, b) => mod.parseScreenAudioPacket(key, b),
    buildScreenAudioPacket: (key, s, q, t, o) => mod.buildScreenAudioPacket(key, s, q, t, o),
    buildVideoFrameStream: (key, s, f, t, k, d) => mod.buildVideoFrameStream(key, s, f, t, k, d),
  };
  return api;
}

/** The loaded API; throws if `loadWasm()` has not completed. */
export function wasm(): WasmApi {
  if (!api) throw new Error("wasm not loaded");
  return api;
}
