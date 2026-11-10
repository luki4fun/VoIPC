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

import type { ChatEvent, FileRef, Forwarded } from "../../lib/types";

export interface SignalClient {
  /** { identity_key: number[], prekey_bundle: PreKeyBundleData } for Authenticate. */
  bundle(): { identity_key: number[]; prekey_bundle: PreKeyBundleData };
  /** Our user id from Authenticated: every pairwise message is bound to it. */
  setOwnUserId(userId: number): void;
  /** PQXDH with a peer's bundle (as decoded from ServerMessage.PreKeyBundle.bundle). */
  establishSession(userId: number, bundle: PreKeyBundleData): void;
  encrypt(userId: number, plaintext: Uint8Array): { ciphertext: Uint8Array; message_type: number };
  decrypt(userId: number, ciphertext: Uint8Array, messageType: number): Uint8Array;
  /** Identities the stores took in since the last call (a session a peer opened among them). */
  takeSeen(): { user_id: number; key: Uint8Array }[];
  /** The identity key the session with `userId` runs on. */
  identityOf(userId: number): Uint8Array | undefined;
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
  setMembers(channelId: number, userIds: Uint32Array): void;
  addMember(channelId: number, userId: number): void;
  dropMember(channelId: number, userId: number): void;
  /** Everybody in the channel except us. */
  othersIn(channelId: number, ownUserId: number): Uint32Array;
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

  // Text channels: voipc_crypto::channel_state's live path, written once for both backends.
  // The page sends and emits what `LiveOut` says, as network.rs does.
  liveStart(): void;
  liveSetMetered(metered: boolean): void;
  liveSetQuiet(channels: Uint32Array, quiet: boolean): void;
  /** Takes over what an earlier connection of this account kept. */
  liveAdoptKept(kept: KeptSessions): void;
  /** What this connection hands to the next: before `free`, which takes the stores. */
  liveKeepSessions(): KeptSessions;
  /** The pages of pins are out: no key job until `livePinsIn`. */
  liveWaitForPins(): void;
  /** They came in: what waited for them. */
  livePinsIn(ownChannel: number): LiveOut;
  /** The rows of a list: those it is news of, with the identity their session runs on. */
  liveNoteRows(users: unknown): { user_id: number; identity: number[] | null }[];
  /** A frame of the live path, as its postcard bytes. */
  liveFrame(ownChannel: number, payload: Uint8Array): LiveOut;
  /** A post in a text channel, as `envelope` packed it. Throws why it cannot go. */
  livePost(channelId: number, payload: Uint8Array): LiveOut;
  /** Each second. */
  liveTick(): LiveOut;
  /** The next key frame's postcard bytes, if one may go now. */
  liveNextFrame(inCall: boolean): Uint8Array | undefined;
  liveHasWork(): boolean;
  /** A session with this user that both ends hold came up. */
  liveSessionUp(userId: number): void;
  /** A kept session whose peer's key disagrees with their pin goes. */
  liveDropKeptSession(userId: number): boolean;
  liveNoBundle(userId: number): void;
  /** Ask for a channel's recent chat, sealed. Of `targets`, who was picked. */
  liveAskHistory(channelId: number, targets: Uint32Array): Uint32Array;
  /** An answer sealed in the session the ask came through, as postcard bytes. */
  liveSealAnswer(channelId: number, target: number, messagesJson: string): Uint8Array;
  /** Whether an answer from `from` is one we asked for, which it uses up. */
  liveAnswerWanted(channelId: number, from: number): boolean;
  /** A plain ask went for this channel (the new-member wait refuses a sealed one). */
  liveNoteAsked(channelId: number, from: number): void;
  /** Whether the relay's "not delivered" is about a hand-off, which nobody is to see. */
  liveUndeliveredWasSealed(target: number): boolean;
  /** A person's answer to `key-job-ask`. */
  liveAnswerJob(channelId: number, go: boolean): LiveOut;
  /** Whether the pages of pins are still out. */
  livePinsOut(): boolean;
  /** Whether this frame, as its postcard bytes, is held until they are in. */
  liveHoldsFrame(payload: Uint8Array): boolean;
  /** A bundle came: whether the live path has something to send over a session with them. */
  liveBundleWanted(userId: number, ownRoom: number): boolean;
  /** The connection ends: the posts that waited, per channel. */
  liveEnd(): { channel_id: number; expired: number }[];

  free(): void;
  [Symbol.dispose](): void;
}

/** What the page does after a call on the live path (voipc_crypto::LiveOut). */
export interface LiveOut {
  /** Postcard bytes of each frame to send. */
  send: Uint8Array[];
  /** Front-end events, to emit as they are. */
  emit: { name: string; payload: unknown }[];
  /** People seen for the first time, or under another account: for the pin check. */
  seen: { user_id: number; account: number[] | null; name: string; identity: number[] | null }[];
  /** An identity someone showed, for the pin check: a bundle's. */
  check: { user_id: number; key: number[] }[];
  /** A direct message may use a session with these now. */
  made: Uint32Array;
  /** And no longer with these. */
  gone: Uint32Array;
  /** Text channels newly followed: their logs are ours to keep. */
  entered: Uint32Array;
  /** Text channels with a gate, and accounts met in one: for what their pins may take up. */
  gated: Uint32Array;
  gated_people: number[][];
  /** `liveNextFrame` has something to send. */
  work: boolean;
}

/** Sessions with accounts, between one connection and the next. */
export interface KeptSessions {
  free(): void;
}

/** An account's pins, between one connection and the next. */
export interface KeptPins {
  free(): void;
}

/** A direct message that is really a history hand-off (voipc_crypto::Sealed). */
export type Sealed = { ask: number } | { answer: number; messages: unknown[] } | { unreadable: true };

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

/** What a message points at: the message it answers and its thread, by id,
 *  the file it carries, and where it was forwarded from; or, instead of all
 *  of these, the event it is (an edit, a delete, a reaction, a pin). */
export interface MessageRefs {
  replyTo?: string | null;
  thread?: string | null;
  file?: FileRef | null;
  fwd?: Forwarded | null;
  event?: ChatEvent | null;
}

export interface PreKeyBundleData {
  registration_id: number;
  device_id: number;
  identity_key: number[];
  signed_prekey_id: number;
  signed_prekey: number[];
  signed_prekey_signature: number[];
  prekeys: { id: number; public_key: number[] }[];
  /** The signed Kyber1024 last-resort pre-key (protocol 12). */
  kyber_prekey_id: number;
  kyber_prekey: number[];
  kyber_prekey_signature: number[];
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

/** How a connection signs in to a relay account (crates/voipc-web/src/account.rs). */
export type AccountMethod =
  | { kind: "login"; password: string }
  | { kind: "register"; password: string; invite?: string | null }
  | { kind: "device"; device_id: number[]; device_key: number[]; relay_id: number[]; dek: number[] }
  | { kind: "reset"; recovery: string; password: string }
  | { kind: "provider"; ticket: number[] };

/** One step of a sign-in: a payload to send, "build the keys now", "ask for
 *  a code", "stretch the password with this salt", or "the reset went through". */
export type SignInStep = {
  send?: Uint8Array;
  keys?: true;
  needTotp?: true;
  stretch?: string;
  resetDone?: true;
  providerPending?: true;
  providerSignup?: { suggestion: string; problem: string };
  providerChoice?: { name: string; claim: boolean; has_password: boolean; known_as: string };
  pairCode?: string;
  pairSame?: { code: string; known_as: string };
  pairRefused?: string;
};

/**
 * An account sign-in: voipc_crypto::account::SignIn, the same steps the
 * desktop client runs. Payloads are postcard bytes without the length prefix.
 */
export interface AccountSignIn {
  /** The Authenticate payload to open with. */
  first(): Uint8Array;
  /** What this browser knows of relay ids: this address's (hex), and
   *  `[hex, address]` of the others. */
  expectRelay(here: string | undefined, elsewhere: [string, string][]): void;
  /** One server payload in; throws the reason when the sign-in fails. */
  step(payload: Uint8Array): SignInStep[];
  /** PBKDF2 of the password with the salt a `stretch` step named. */
  stretched(master: Uint8Array): SignInStep[];
  /** The Signal client for the account's identity (which stays in wasm). */
  signalClient(): SignalClient;
  /** The Keys payload, from the new Signal client's prekey_bundle. */
  keys(prekeyBundle: PreKeyBundleData): Uint8Array;
  totp(code: string): Uint8Array;
  recovery(code: string): Uint8Array;
  /** The accounts this browser remembers on this relay, with their vault keys. */
  rememberedHere(known: [string, number[]][]): void;
  /** The name for `providerSignup`. Runs the proof of work. */
  providerSignup(name: string): Uint8Array;
  /** "First time here": the recovery key's text, to show before anything goes. */
  providerClaimKey(): string;
  /** The person has seen the key: the claim goes. */
  providerClaim(): SignInStep[];
  /** The recovery key as shown; throws why not, and the choice stays open. */
  providerRecovery(key: string): SignInStep[];
  /** From the ask until the person's answer: the relay's words stay off the screen. */
  midPairing(): boolean;
  /** Ask another device of this account: the payload to send. */
  pairStart(): Uint8Array;
  /** The answer to `pairSame`; throws why a no ends the sign-in. */
  pairSame(yes: boolean): SignInStep[];
  /** After Authenticated: where this browser kept the log's read cursors. */
  finish(): { relay_id: Uint8Array; name: string };
  /** After finish: the account's session, from the AccountInfo in
   *  Authenticated, what this browser kept of the log last time, whether
   *  joiners of a channel's log get older keys, and whether this sign-in was
   *  with the password. */
  startSession(info: unknown, memory: string | null, share: boolean, passwordBased: boolean): { session: AccountSession; actions: AccountActions };
  free(): void;
}

/** What the account session asks the page to do (voipc_crypto::account_session::Actions). */
export interface AccountActions {
  send: Uint8Array[];
  /** Front-end events, to emit as they are. */
  emit: { name: string; payload: unknown }[];
  /** The relay remembers this browser now: keep its key (devices.ts). */
  remember?: { relay_id: number[]; name: string; device_id: number[]; device_key: number[]; dek: number[] };
  /** The log's read cursors moved: `voipc.cursors.<key>` keeps this JSON (log-memory.ts).
   *  `named`: who was named, when that moved, kept apart (log-named.ts). */
  memory?: { key: string; json: string; named?: string };
}

/** What follows a sign-in — the stored log, the pins, remembering this
 *  browser — as the desktop client runs it too (voipc_crypto::account_session). */
export interface AccountSession {
  /** Once the session is listed. */
  afterConnect(): AccountActions;
  /** Every couple of seconds while connected: reads refused for now go on. */
  tick(): AccountActions;
  /** A decoded AccountReply. */
  onReply(reply: unknown): AccountActions;
  /** The users of a UserList, UserJoined or ChannelUsers, for the pins. */
  noteRoster(users: unknown): AccountActions;
  /** The people of a ReportTakers, for the pins. */
  noteTakers(takers: unknown): void;
  /** An identity a user showed (a bundle, or a session they opened). */
  checkIdentity(userId: number, key: Uint8Array): AccountActions;
  outgoingDm(userId: number, envelope: Uint8Array, sentAt: number, ttlSecs?: number | null): AccountActions;
  /** A direct message for an account that is away (its hex id); throws why not.
   *  `once`: a report, kept whatever cloud copies say. */
  keptDm(accountHex: string, envelope: Uint8Array, sentAt: number, ttlSecs: number | null | undefined, once: boolean): AccountActions;
  outgoingChannel(log: string, envelope: Uint8Array, sentAt: number, ttlSecs?: number | null): AccountActions;
  /** In a channel with log `conv`: keep it, and read what it kept. */
  enter(conv: string): AccountActions;
  readNow(conv: string): AccountActions;
  enterMany(convs: string[]): AccountActions;
  memberGone(conv: string, userId: number): void;
  /** What an earlier connection of this account kept, before `pinsIn`. */
  adoptPins(kept: KeptPins): void;
  keepPins(): KeptPins | undefined;
  /** Whether the pages of pins are in; if not, the page holds the key jobs. */
  pinsIn(): boolean;
  /** Once, when pages that were out have come in. */
  takePinsIn(): boolean;
  /** Whatever pins were not saved yet, now: the person is leaving. */
  flushPins(): AccountActions;
  pinsSaved(): boolean;
  noteDirect(userId: number): void;
  noteGatedPeople(accounts: number[][]): void;
  noteGatedLog(conv: string): void;
  /** The person opened their safety number: their pin is kept, and goes now. */
  verified(userId: number): AccountActions;
  /** Out of channel log `conv`; with `tell`, asks the relay to take us out. */
  leave(conv: string, tell: boolean): AccountActions;
  /** Delete what this account wrote to the stored logs, in `conv` or (null) everywhere. */
  purge(conv: string | null): AccountActions;
  /** Delete this account, from its stretched password. */
  deleteAccount(master: Uint8Array | null, totp?: string | null, recovery?: string | null): AccountActions;
  /** Link a provider, or prove it's you with one you have linked. */
  providerStart(kind: string, link: boolean, master: Uint8Array | null, totp?: string | null, recovery?: string | null): AccountActions;
  providerUnlink(kind: string, master: Uint8Array | null, totp?: string | null, recovery?: string | null): AccountActions;
  /** The person agreed to look at `account-pair-look`. */
  pairLook(pair: number): AccountActions;
  /** What the person typed at `account-pair-ask`: the session compares it. */
  pairAnswer(pair: number, code: string): AccountActions;
  /** The person said no, at either question. */
  pairDecline(pair: number): AccountActions;
  /** Whether a DM to this user that did not arrive is kept for them all the same. */
  keptFor(userId: number): boolean;
  /** One person a live frame named, as a row of a roster does. */
  notePerson(userId: number, account: Uint8Array | undefined, name: string): AccountActions;
  /** The account this session is of: what kept sessions go by. */
  accountId(): Uint8Array;
  /** Throws why there is none. `live`: the key the session with them runs on. */
  isAccount(userId: number): boolean;
  safetyNumber(userId: number, ownKey: Uint8Array, live?: Uint8Array): string;
  cloud(): boolean;
  asked(): boolean;
  setPrefs(cloud: boolean, asked: boolean): AccountActions;
  setBlocked(key: string, label: string, on: boolean): AccountActions;
  setShare(share: boolean): void;
  mayShare(): boolean;
  /** The PBKDF2 salt for this account's passwords. */
  kdfSalt(): string;
  /** A new password, from the stretched old and new ones. */
  passwordChange(oldMaster: Uint8Array, newMaster: Uint8Array, totp?: string | null, recovery?: string | null): AccountActions;
  /** A new recovery key, from the stretched password: the actions, and the
   *  key's text to show once `RecoveryKeyChanged` answers. */
  recoveryKeyNew(master: Uint8Array | null, totp?: string | null, recovery?: string | null): AccountActions & { key: string };
  free(): void;
}

/** A file sealed for sending (`sealFile`). */
export interface SealedFile {
  /** The blob id, 64 hex digits: all the relay learns of the file. */
  hash: string;
  /**
   * 64 hex digits. `key`, `size` and `z` travel only inside the end-to-end
   * message, in the same form `openFile` takes them back.
   */
  key: string;
  /** The file's own length, before any deflate. */
  size: number;
  /** Whether the blob holds the file deflated. */
  z: boolean;
  /** What the relay keeps. */
  blob: Uint8Array;
}

/**
 * The `name` of an Error from `sealFile`/`openFile`. `NotThisFile` means the
 * bytes in hand are not the blob the message names: fetch again. Every other
 * means the sender's file itself will never open.
 */
export type FileErrorName = "TooLarge" | "NotThisFile" | "WrongKey" | "Sealed" | "Malformed";

// wasm-bindgen copies a byte argument into wasm memory before Rust sees it,
// so `sealFile`'s and `openFile`'s own size checks came after an allocation
// as large as whatever they were handed (S-024). The same limits, checked on
// this side of the copy; every caller goes through these (file-worker.ts too).

/** voipc_crypto::file::MAX_FILE_PLAIN */
export const MAX_FILE_PLAIN = 64 * 1024 * 1024;

/** voipc_crypto::file::sealed_len: the blob a body of `body` bytes seals
 *  into (the commitment, the body, a tag per 64 KiB chunk). */
export function sealedLen(body: number): number {
  const chunks = body === 0 ? 1 : Math.ceil(body / (64 * 1024));
  return 32 + body + chunks * 16;
}

/** voipc_crypto::file::MAX_FILE_BLOB: the longest blob that opens. */
export const MAX_FILE_BLOB = sealedLen(MAX_FILE_PLAIN);

function fileError(name: FileErrorName, message: string): Error {
  const e = new Error(message);
  e.name = name;
  return e;
}

/** Throws what `sealFile` would for `plain`, before it is copied. */
export function checkSealInput(plain: Uint8Array): void {
  if (plain.length > MAX_FILE_PLAIN) throw fileError("TooLarge", "the file is larger than 64 MiB");
}

/** Throws what `openFile` would for a message's `size` and a `blob` longer
 *  than any file seals into, before the blob is copied. */
export function checkOpenInput(size: number, blob: Uint8Array): void {
  if (size > MAX_FILE_PLAIN) throw fileError("TooLarge", "the file is larger than 64 MiB");
  if (blob.length > MAX_FILE_BLOB) throw fileError("Malformed", "the file is malformed");
}

export interface WasmApi {
  protocolVersion(): number;
  guestMayShare(hasAccounts: boolean): boolean;
  appVersion(): string;
  /** postcard bytes of a ClientMessage, WITHOUT the u32 length prefix. */
  encodeClientMsg(msg: unknown): Uint8Array;
  /** Decodes postcard bytes (without length prefix) into a ServerMessage object. */
  decodeServerMsg(bytes: Uint8Array): unknown;
  /** Fresh ephemeral identity + registration id + signed pre-key 1 + 100 one-time pre-keys. */
  newSignalClient(): SignalClient;
  /** The PBKDF2 rounds a password is stretched with. */
  kdfRounds(): number;
  /** Throws why the name cannot be an account name. */
  newAccountSignIn(name: string, method: AccountMethod): AccountSignIn;
  /** `Authenticate` for a question about providers. */
  providerAsk(ask: unknown): Uint8Array;
  /** Whether `url` is a provider's own page: the relay names it. */
  providerPageOk(url: string): boolean;
  /** An account name as the relay stores it; throws why not. */
  normalizeAccountName(raw: string): string;
  /** An otpauth:// link as an SVG QR code, drawn locally. */
  qrSvg(text: string): string | undefined;
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
  pinHeldMost(): number;
  /** A fresh message id: 16 random bytes, hex. */
  newMessageId(): string;
  /** Pack a message with its id, its destruction timer in seconds where the
   * conversation has one, and what it answers — all inside the ciphertext. */
  envelope(id: string, text: string, ttlSecs?: number, refs?: MessageRefs): Uint8Array;
  openEnvelope(plaintext: Uint8Array): {
    id: string | null;
    text: string;
    ttl_secs: number | null;
    reply_to: string | null;
    thread: string | null;
    file: FileRef | null;
    fwd: Forwarded | null;
    event: ChatEvent | null;
  };
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
  /** A direct message's plaintext, if it is a hand-off, before anything could show it. */
  openSealed(plaintext: Uint8Array): Sealed | undefined;
  /**
   * Seals a file under a fresh key: a key commitment, then AES-256-GCM over
   * 64 KiB chunks. With `compress`, it is deflated first where that saves a
   * tenth or more. Throws (`TooLarge`) above 64 MiB.
   */
  sealFile(plain: Uint8Array, compress: boolean): SealedFile;
  /**
   * The file out of a blob, checked against what its message claims. Throws
   * an Error named by `FileErrorName`: `NotThisFile` when the blob is not the
   * one `hash` names; `WrongKey`, `Sealed` or `Malformed` when it is not
   * sealed under `key`, was altered or cut short, or is not a file of `size`
   * bytes.
   */
  openFile(hash: string, key: string, size: number, z: boolean, blob: Uint8Array): Uint8Array;
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
/**
 * The module, compiled once here: each file worker (files.ts) instantiates
 * its own from it. Fetching it again there would download all 2.6 MB once
 * more wherever the page's certificate was accepted by hand, since browsers
 * cache nothing from such a page.
 */
let compiled: WebAssembly.Module | null = null;

/** Loads and instantiates the wasm module once. */
export async function loadWasm(): Promise<WasmApi> {
  if (api) return api;
  // Generated by `npm run build:wasm` (wasm-pack --target web).
  // @ts-ignore — the package only exists after the wasm build
  const mod = await import("../../lib/wasm/voipc_web.js");
  const res = await fetch(new URL("../../lib/wasm/voipc_web_bg.wasm", import.meta.url));
  if (!res.ok) throw new Error(`could not load the app's wasm (HTTP ${res.status})`);
  // Streaming needs the wasm type; a host that labels it otherwise still works
  const module = res.headers.get("content-type")?.startsWith("application/wasm")
    ? await WebAssembly.compileStreaming(res)
    : await WebAssembly.compile(await res.arrayBuffer());
  await mod.default({ module_or_path: module });
  compiled = module;
  api = {
    protocolVersion: () => mod.protocolVersion(),
    guestMayShare: (hasAccounts) => mod.guestMayShare(hasAccounts),
    appVersion: () => mod.appVersion(),
    encodeClientMsg: (m) => mod.encodeClientMsg(m),
    decodeServerMsg: (b) => mod.decodeServerMsg(b),
    newSignalClient: () => new mod.SignalClient(),
    kdfRounds: () => mod.kdfRounds(),
    newAccountSignIn: (name, method) => new mod.AccountSignIn(name, method),
    providerAsk: (ask) => mod.providerAsk(ask),
    providerPageOk: (url) => mod.providerPageOk(url),
    normalizeAccountName: (raw) => mod.normalizeAccountName(raw),
    qrSvg: (text) => mod.qrSvg(text),
    newMediaKeys: () => new mod.MediaKeys(),
    newVideoAssembler: () => new mod.VideoAssembler(),
    maxRelayCiphertext: () => mod.maxRelayCiphertext(),
    pickHistorySources: (s) => mod.pickHistorySources(s),
    controlMsgsPerSec: () => mod.controlMsgsPerSec(),
    pinHeldMost: () => mod.pinHeldMost(),
    newMessageId: () => mod.newMessageId(),
    envelope: (id, text, ttlSecs, refs) =>
      mod.envelope(
        id,
        text,
        ttlSecs,
        refs?.replyTo ?? undefined,
        refs?.thread ?? undefined,
        refs?.file ? JSON.stringify(refs.file) : undefined,
        refs?.fwd ? JSON.stringify(refs.fwd) : undefined,
        refs?.event ? JSON.stringify(refs.event) : undefined,
      ),
    openEnvelope: (p) => mod.openEnvelope(p),
    historyPayload: (c, m) => mod.historyPayload(c, m),
    openHistoryPayload: (c, p) => mod.openHistoryPayload(c, p),
    openSealed: (p) => mod.openSealed(p),
    sealFile: (p, c) => {
      checkSealInput(p);
      return mod.sealFile(p, c);
    },
    openFile: (h, k, s, z, b) => {
      checkOpenInput(s, b);
      return mod.openFile(h, k, s, z, b);
    },
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

/** The compiled module, for a worker to instantiate; throws if `loadWasm()`
 *  has not completed. */
export function wasmModule(): WebAssembly.Module {
  if (!compiled) throw new Error("wasm not loaded");
  return compiled;
}

/** The loaded API; throws if `loadWasm()` has not completed. */
export function wasm(): WasmApi {
  if (!api) throw new Error("wasm not loaded");
  return api;
}
