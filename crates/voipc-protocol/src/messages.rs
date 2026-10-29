//! A note on `#[serde(default)]` in the wire types: it only helps JSON
//! callers (the browser builds messages as JS objects and may leave a field
//! out). On the wire, postcard is positional, so it never lets an older and a
//! newer layout read each other: every layout change is a protocol bump, which
//! `tests/golden.rs` enforces.

use serde::{Deserialize, Serialize};

use crate::types::*;

/// Messages sent from client to server over the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Initial authentication. First message on the control stream.
    Authenticate {
        username: String,
        /// Protocol version for forward compatibility.
        protocol_version: u32,
        /// Application version (e.g. "0.1.0"). Must match server version.
        #[serde(default)]
        app_version: String,
        /// Client's long-term identity public key (32-byte Curve25519).
        #[serde(default)]
        identity_key: Option<Vec<u8>>,
        /// Initial pre-key bundle for other users to establish sessions.
        #[serde(default)]
        prekey_bundle: Option<PreKeyBundleData>,
        /// Sign in to a relay account (protocol v11); `None` is a guest. An
        /// account's keys come later, in `AuthContinue::Keys`: a new device
        /// only has its identity once it has opened the vault.
        #[serde(default)]
        account: Option<AccountStart>,
    },

    /// Request to join a specific channel (with optional password).
    ///
    /// A voice channel is a move: the user leaves the one they were in. A text
    /// channel is a subscription, added to whatever they are already in.
    JoinChannel {
        channel_id: ChannelId,
        password: Option<String>,
    },

    /// Unsubscribe from a text channel (protocol v9). Leaving a voice channel
    /// is still `JoinChannel { channel_id: 0 }`; this is refused for one.
    LeaveChannel { channel_id: ChannelId },

    /// Create a new channel.
    CreateChannel {
        name: String,
        password: Option<String>,
        /// Positional audio mode. A server with proximity chat disabled
        /// refuses anything but Off with a ChannelError.
        #[serde(default)]
        proximity: ProximityMode,
        /// Members see each other under random pseudonyms (protocol v7).
        #[serde(default)]
        anonymous: bool,
        /// A text channel rather than a voice room (protocol v9).
        #[serde(default)]
        text: bool,
    },

    /// Client is disconnecting gracefully.
    Disconnect,

    /// Client toggled their mute state (informational for other users).
    SetMuted { muted: bool },

    /// Client toggled their deafen state (informational for other users).
    SetDeafened { deafened: bool },

    /// Client will (or will no longer) answer requests for recent channel chat
    /// (protocol v9). Sent once after authenticating and on every change, the
    /// same way mute and deafen are.
    SetHistorySharing { enabled: bool },

    /// Request the full channel list.
    RequestChannelList,

    /// Ping for latency measurement.
    Ping { timestamp: u64 },

    /// Change the password of a channel (creator only).
    SetChannelPassword {
        channel_id: ChannelId,
        password: Option<String>,
    },

    /// Change the positional audio mode of a channel (creator or admin;
    /// persistent channels admin only). Answered with ChannelUpdated or
    /// ChannelError.
    SetChannelProximity {
        channel_id: ChannelId,
        proximity: ProximityMode,
    },

    /// Change the other channel options (creator or admin; persistent
    /// channels admin only). `None` leaves an option as it is. Answered with
    /// ChannelUpdated or ChannelError.
    SetChannelOptions {
        channel_id: ChannelId,
        options: ChannelOptions,
    },

    /// Kick a user from a channel (creator only).
    KickUser {
        channel_id: ChannelId,
        user_id: UserId,
    },

    /// The people this client wants to hear, by user id, in a channel whose
    /// `routed` flag is on. `None` (the default everywhere else) means "all of
    /// them", which is how every channel behaved before protocol v8.
    ///
    /// This is the one message that tells the relay anything about who hears
    /// whom, and it is self-declared: it saves bandwidth and decoders in a
    /// channel a game has spread over a map. It is **not** a security
    /// boundary — a patched client simply asks for everyone. The enforcing
    /// half is the game server's own `POST /game/v1/routes`.
    SetAudioFilter { allow: Option<Vec<UserId>> },

    /// Request the user list of a channel without joining it (preview).
    RequestChannelUsers { channel_id: ChannelId },

    /// Invite a user to your channel (creator only).
    SendInvite {
        channel_id: ChannelId,
        target_user_id: UserId,
    },

    /// Accept a pending channel invite.
    AcceptInvite { channel_id: ChannelId },

    /// Decline a pending channel invite.
    DeclineInvite { channel_id: ChannelId },

    /// Start sharing screen. Server notifies channel but sharer waits for viewers.
    StartScreenShare {
        /// Capture source identifier (display/window id from enumeration).
        source: String,
        /// Desired resolution height: 480, 720, or 1080.
        resolution: u16,
        /// Codec every frame of this share is encoded with. postcard is
        /// positional, so this is not an optional field on the wire — client
        /// and server of the same protocol version always agree on it.
        codec: VideoCodec,
    },

    /// Stop sharing screen.
    StopScreenShare,

    /// Start watching a specific user's screen share (one at a time).
    WatchScreenShare { sharer_user_id: UserId },

    /// Stop watching the current screen share.
    StopWatchingScreenShare,

    /// Request a keyframe from the sharer (on join or after packet loss).
    RequestKeyframe { sharer_user_id: UserId },

    // ── E2E Encryption messages ───────────────────────────────────────
    /// Request another user's pre-key bundle for session establishment.
    RequestPreKeyBundle { target_user_id: UserId },

    /// Upload replenished one-time pre-keys to the server.
    UploadPreKeys { prekeys: Vec<OneTimePreKey> },

    /// Send an encrypted direct message using Signal Protocol.
    SendEncryptedDirectMessage {
        target_user_id: UserId,
        /// Signal Protocol ciphertext.
        ciphertext: Vec<u8>,
        /// 1 = PreKeySignalMessage, 2 = SignalMessage.
        message_type: u8,
    },

    /// Send an encrypted channel message using Sender Keys.
    SendEncryptedChannelMessage {
        /// The channel to send to (protocol v9). A user can be in several text
        /// channels at once, so the server can no longer infer it from the
        /// session; it checks membership instead.
        channel_id: ChannelId,
        /// SenderKeyMessage ciphertext.
        ciphertext: Vec<u8>,
    },

    /// Distribute a sender key to a channel member (for group encryption).
    /// The distribution_message is pairwise-encrypted via the Signal session.
    DistributeSenderKey {
        channel_id: ChannelId,
        target_user_id: UserId,
        /// Pairwise-encrypted SenderKeyDistributionMessage.
        distribution_message: Vec<u8>,
        /// 1 = PreKeySignalMessage, 2 = SignalMessage.
        #[serde(default)]
        message_type: u8,
    },

    /// Distribute a media encryption key to a channel member.
    DistributeMediaKey {
        channel_id: ChannelId,
        target_user_id: UserId,
        /// `MediaKey::to_bytes()` encrypted with the pairwise Signal session.
        encrypted_media_key: Vec<u8>,
        /// 1 = PreKeySignalMessage, 2 = SignalMessage.
        message_type: u8,
    },

    /// Poke another user (like TeamSpeak). Shows a popup + sound on their end.
    /// Message is encrypted with the pairwise Signal session.
    SendPoke {
        target_user_id: UserId,
        ciphertext: Vec<u8>,
        message_type: u8,
    },

    // ── Moderation (admin token session) ─────────────────────────────
    /// Turn this session into a server admin with the server's admin token.
    AdminLogin { token: String },

    /// Disconnect a user from the server (admin only).
    AdminKick { user_id: UserId, reason: String },

    /// Disconnect a user and ban their address; with `account`, their account
    /// too, where they signed in with one (admin or moderator; a moderator
    /// bans people without a role only). `duration_secs` 0 = permanent.
    AdminBan {
        user_id: UserId,
        reason: String,
        duration_secs: u32,
        account: bool,
    },

    /// Lift a ban, by its `BanInfo.id` (admin only).
    AdminUnban { id: u64 },

    /// Request the list of active bans (admin only).
    AdminListBans,

    /// Ban an account by name, online or not (admin only). `duration_secs` 0
    /// = permanent.
    AdminBanAccount {
        name: String,
        reason: String,
        duration_secs: u32,
    },

    // ── Channel history hand-off (E2E) ───────────────────────────────
    /// Ask a channel member to share recent channel chat with us.
    RequestChannelHistory {
        channel_id: ChannelId,
        target_user_id: UserId,
    },

    /// Recent channel chat for a newcomer, encrypted with the pairwise
    /// Signal session (JSON `{ v, messages: [...] }` inside).
    SendChannelHistory {
        channel_id: ChannelId,
        target_user_id: UserId,
        ciphertext: Vec<u8>,
        /// 1 = PreKeySignalMessage, 2 = SignalMessage.
        message_type: u8,
    },

    // ── Screen share congestion control ──────────────────────────────
    /// A viewer saw frame loss in the last reporting window (~2 s). Relayed
    /// to the sharer, which lowers bitrate/fps instead of storming keyframes.
    VideoLossReport {
        sharer_user_id: UserId,
        frames_dropped: u32,
        frames_received: u32,
    },

    // ── Accounts (protocol v11) ──────────────────────────────────────
    /// The client's next step of an account sign-in, answering an `AuthStep`.
    AuthContinue(AuthContinue),

    /// Managing the signed-in account: device keys, codes, the vault.
    Account(AccountRequest),

    // ── Files (protocol v13) ─────────────────────────────────────────
    // Only the negotiation travels here; the bytes go over HTTPS
    // (`PUT`/`GET /f/v1/<hash>` on the TLS port) with the ticket it hands out.
    /// Store the `size`-byte blob of a sealed file under its id, `hash`, for a
    /// message in `conv`. Answered with `FileUploadReady` (upload it),
    /// `FileStored` (the relay has it already) or `FileRefused`; or, while
    /// another member's upload of it is under way, with nothing yet:
    /// `FileStored` when that lands, `FileUploadReady` if it passes to you. A
    /// member answering `FileWanted` sends this too.
    FileUpload {
        conv: FileConv,
        size: u64,
        hash: [u8; 32],
    },

    /// Fetch the blob `hash` of a message in `conv`. Answered with
    /// `FileReady`, with `FileSeeking` and later `FileReady` or
    /// `FileUnavailable`, or with `FileRefused`.
    FileFetch { conv: FileConv, hash: [u8; 32] },

    /// Give up an upload or a fetch of `hash`: its ticket is spent, and an
    /// upload slot passes to the next member waiting with the same file.
    FileCancel { hash: [u8; 32] },
}

/// The client's side of an account sign-in, between `Authenticate` and
/// `Authenticated`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthContinue {
    /// The secret derived from the password (32 bytes), never the password.
    Secret {
        auth_secret: Vec<u8>,
    },
    /// A new account: the secret, the solved proof of work (empty where an
    /// invite stands in for it), and the vault the client just made.
    Register {
        auth_secret: Vec<u8>,
        altcha: String,
        ts: String,
        vault: Vec<VaultBlob>,
    },
    /// The device key's signature over the challenge.
    DeviceSig {
        signature: Vec<u8>,
    },
    Totp {
        code: String,
    },
    Recovery {
        code: String,
    },
    /// The account's identity and this connection's pre-keys. A different
    /// identity than the one on record is refused unless `reset_identity`:
    /// then everyone who knew the old one is told it changed.
    Keys {
        identity_key: Vec<u8>,
        prekey_bundle: PreKeyBundleData,
        reset_identity: bool,
    },
    /// The answer to `ResetChallenge`: the identity's signature over the
    /// challenge (`voipc-reset/v1|<relay>|<name>|<challenge>`), the reset
    /// key's (`voipc-reset/v2|…`, the key only the recovery key derives:
    /// `voipc_crypto::account::reset_key`), the new password's secret and its
    /// `slot.pass` (the same vault key under the new password), and the second
    /// factor when the account has one. An account with a `slot.reset` is
    /// checked by the reset key alone; one made before 1.3 by the identity.
    Reset {
        signature: Vec<u8>,
        key_signature: Vec<u8>,
        auth_secret: Vec<u8>,
        pass_slot: Vec<u8>,
        totp: Option<String>,
        recovery_code: Option<String>,
    },
}

/// Account management after sign-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountRequest {
    /// A challenge for remembering this device (needs a recent sign-in).
    DeviceChallenge,
    /// `public_key` is Ed25519; the signature is over the challenge.
    DeviceAdd {
        device_id: Vec<u8>,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
    TotpSetup,
    TotpEnable {
        sealed: String,
        code: String,
    },
    /// Write one vault item; `expect` is the version it replaces, 0 for new.
    VaultPut {
        k: String,
        v: Vec<u8>,
        expect: i64,
    },

    // ── The stored-message log (voipc_crypto::log) ──
    /// This account's log key (33 bytes) and its identity's signature over it.
    LogKeyPublish {
        logkey: Vec<u8>,
        sig: Vec<u8>,
    },
    /// Other accounts' identity and log keys (at most 64 at a time).
    LogKeys {
        accounts: Vec<[u8; 16]>,
    },
    /// One of our epoch keys for `conv`, wrapped to each member (and to us).
    EpochPut {
        conv: String,
        epoch: u32,
        wraps: Vec<WrapIn>,
    },
    /// Every wrap for us in `conv`.
    WrapsFetch {
        conv: String,
    },
    /// A sealed entry for `conv` under our epoch `epoch`. `ttl_secs` is the
    /// message's own timer, for when the relay may drop it.
    LogAppend {
        conv: String,
        epoch: u32,
        ct: Vec<u8>,
        ttl_secs: Option<u32>,
    },
    /// Entries of `conv` after sequence number `after`, a page at a time.
    LogFetch {
        conv: String,
        after: i64,
    },
    /// The conversations with entries for us, and their newest entry.
    LogIndex,
    /// Become a stored member of a channel's log (`ChannelInfo::log`): the
    /// accounts its writers wrap their keys to. Only while in the channel.
    LogJoin {
        conv: String,
    },
    /// Stop being one.
    LogLeave {
        conv: String,
    },
    /// The stored members of `conv` (we must be one), with their keys.
    LogMembers {
        conv: String,
    },

    // ── The account (1.0) ──
    /// A new password: the old one's secret (the relay checks it), the new
    /// one's, its `slot.pass` (the same vault key), and the second factor when
    /// the account has one. Every other session and remembered device ends.
    PasswordChange {
        old_secret: Vec<u8>,
        new_secret: Vec<u8>,
        pass_slot: Vec<u8>,
        totp: Option<String>,
        recovery_code: Option<String>,
    },
    /// Delete what this account wrote to the stored logs, in `conv` or (None)
    /// everywhere, and the keys it handed out for it. What others wrote stays.
    LogPurge {
        conv: Option<String>,
    },
    /// Delete this account: the password's secret, and the second factor when
    /// it has one. `AccountDeleted` answers, then the relay closes the
    /// connection.
    DeleteAccount {
        secret: Vec<u8>,
        totp: Option<String>,
        recovery_code: Option<String>,
    },
    /// A new recovery key: the password's secret, the vault key under the
    /// new recovery key (`slot.recovery`), the new reset key (`slot.reset`),
    /// and the second factor when the account has one. The old recovery key
    /// stops working. `RecoveryKeyChanged` answers.
    RecoveryKeyNew {
        secret: Vec<u8>,
        recovery_slot: Vec<u8>,
        reset_key: Vec<u8>,
        totp: Option<String>,
        recovery_code: Option<String>,
    },
}

/// The relay's side of an account sign-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthStep {
    /// Derive the secret with this relay id (and solve `pow` to register).
    Salt {
        relay_id: [u8; 16],
        pow: Option<PowChallenge>,
    },
    /// Sign this with the device key.
    DeviceChallenge {
        relay_id: [u8; 16],
        challenge: String,
    },
    /// A code from the authenticator app, or a recovery code.
    NeedTotp,
    /// The account's vault, to open on this device; then send `Keys`.
    Vault { blobs: Vec<VaultBlob> },
    /// This relay takes no guests. Sent before the connection closes.
    AccountRequired { registration: Registration },
    /// A reset (`AccountStart::Reset`): sign this with the identity key. The
    /// vault's recovery slot and identity item come with it, never the
    /// password slot (which would let anyone guess the password offline).
    /// `second_factor`: send a code or a recovery code with the answer.
    ResetChallenge {
        relay_id: [u8; 16],
        challenge: Vec<u8>,
        blobs: Vec<VaultBlob>,
        second_factor: bool,
    },
    /// The password is reset; sign in with the new one. Every other device
    /// and session of the account was signed out.
    ResetDone,
}

/// Answers to `AccountRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountReply {
    DeviceChallenge {
        challenge: String,
    },
    DeviceAdded,
    TotpSetup {
        secret: String,
        uri: String,
        sealed: String,
    },
    /// Codes are on; the recovery codes are shown once.
    TotpEnabled {
        recovery_codes: Vec<String>,
    },
    VaultStored {
        k: String,
        version: i64,
    },
    /// Someone wrote item `k` since `expect`: here it is now (`None`: gone).
    VaultConflict {
        k: String,
        blob: Option<VaultBlob>,
    },
    /// The account changed (scopes, codes on).
    Info(AccountInfo),
    /// `request` names what was refused.
    Error {
        request: String,
        reason: String,
    },
    LogKeyStored,
    /// Accounts without a published log key are left out.
    LogKeysFound {
        keys: Vec<LogKeyInfo>,
    },
    EpochStored {
        conv: String,
        epoch: u32,
    },
    Wraps {
        conv: String,
        wraps: Vec<WrapOut>,
    },
    LogAppended {
        conv: String,
        seq: i64,
        server_at: u64,
    },
    /// `more`: there is another page after the last of these. `owed`: the
    /// writers here who have not yet answered our joining (their entries
    /// we cannot open yet may still become readable).
    LogPage {
        conv: String,
        entries: Vec<LogEntry>,
        more: bool,
        owed: Vec<[u8; 16]>,
    },
    LogConvs {
        convs: Vec<(String, i64)>,
    },
    LogJoined {
        conv: String,
    },
    LogLeft {
        conv: String,
    },
    LogMembersFound {
        conv: String,
        members: Vec<LogKeyInfo>,
    },
    /// Not appended: our epoch for `conv` is not wrapped to exactly its
    /// members any more (somebody joined or left). Mint another and resend.
    LogRekey {
        conv: String,
    },
    /// Accounts that joined `conv` since we last wrapped our keys there. They
    /// wait for our answer: our older keys too, if we share with joiners.
    LogPending {
        conv: String,
        joiners: Vec<[u8; 16]>,
    },
    /// Somebody wrapped a key to us in `conv`.
    LogNews {
        conv: String,
    },
    /// The password changed (`PasswordChange`). This device's key was
    /// forgotten with every other: remember it again if it was remembered.
    PasswordChanged,
    /// `LogPurge` done: `entries` of ours deleted.
    LogPurged {
        conv: Option<String>,
        entries: u64,
    },
    /// The account is gone; the connection closes.
    AccountDeleted,
    /// `RecoveryKeyNew` done: only the new recovery key resets the password.
    RecoveryKeyChanged,
}

/// A wrapped epoch key for one member (`AccountRequest::EpochPut`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapIn {
    pub recipient: [u8; 16],
    pub wrapped: Vec<u8>,
}

/// A wrapped epoch key for us, from `owner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapOut {
    pub owner: [u8; 16],
    pub epoch: u32,
    pub wrapped: Vec<u8>,
}

/// An account's keys as the relay has them; the client checks the
/// signature against the identity it pinned before using `logkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogKeyInfo {
    pub account: [u8; 16],
    /// The account's name, for filing what it wrote.
    pub name: String,
    pub identity: Vec<u8>,
    pub logkey: Vec<u8>,
    pub sig: Vec<u8>,
}

/// One stored message, still sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: i64,
    pub sender: [u8; 16],
    pub epoch: u32,
    /// When the relay filed it (Unix ms).
    pub server_at: u64,
    pub ct: Vec<u8>,
}

/// Messages sent from server to client over the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Authentication succeeded. Media travels on the same QUIC connection
    /// (datagrams + per-frame streams), so there is nothing else to set up.
    Authenticated {
        user_id: UserId,
        session_id: SessionId,
        /// The relay has accounts (protocol v11); `None` when it has none.
        #[serde(default)]
        accounts: Option<RelayAccounts>,
        /// The account this connection signed in with.
        #[serde(default)]
        account: Option<AccountInfo>,
        /// The relay keeps files (protocol v13); `None` when it does not.
        #[serde(default)]
        files: Option<FileLimits>,
    },

    /// Authentication failed.
    AuthError { reason: String },

    /// Full channel list (sent on connect and on request).
    ChannelList { channels: Vec<ChannelInfo> },

    /// A user joined a channel.
    UserJoined { user: UserInfo },

    /// A user left a channel.
    UserLeft {
        user_id: UserId,
        channel_id: ChannelId,
    },

    /// Full user list for a channel (sent when client joins a channel).
    UserList {
        channel_id: ChannelId,
        users: Vec<UserInfo>,
    },

    /// A user changed their mute state.
    UserMuted { user_id: UserId, muted: bool },

    /// A user changed their deafen state.
    UserDeafened { user_id: UserId, deafened: bool },

    /// A user started or stopped answering requests for recent channel chat
    /// (protocol v9). Broadcast to everyone, not just one channel: a text
    /// channel's subscribers are standing in voice channels of their own.
    UserHistorySharing { user_id: UserId, enabled: bool },

    /// Server-initiated keepalive ping. Client should reply with ClientMessage::Ping.
    Ping { timestamp: u64 },

    /// Pong response for latency measurement.
    Pong { timestamp: u64 },

    /// Server is shutting down.
    ServerShutdown { reason: String },

    /// Client was moved to a different channel.
    MovedToChannel { channel_id: ChannelId },

    /// A new channel was created.
    ChannelCreated { channel: ChannelInfo },

    /// A channel was deleted.
    ChannelDeleted { channel_id: ChannelId },

    /// Error response for channel operations.
    ChannelError { reason: String },

    /// A channel's info was updated (e.g. password changed).
    ChannelUpdated { channel: ChannelInfo },

    /// You were kicked from a channel.
    Kicked {
        channel_id: ChannelId,
        reason: String,
    },

    /// Response to RequestChannelUsers — preview user list (does not imply join).
    ChannelUsers {
        channel_id: ChannelId,
        users: Vec<UserInfo>,
    },

    /// You received a channel invite.
    InviteReceived {
        channel_id: ChannelId,
        channel_name: String,
        invited_by: String,
    },

    /// A user accepted your channel invite.
    InviteAccepted {
        channel_id: ChannelId,
        user_id: UserId,
    },

    /// A user declined your channel invite.
    InviteDeclined {
        channel_id: ChannelId,
        user_id: UserId,
    },

    /// A user in your channel started screen sharing.
    ScreenShareStarted {
        user_id: UserId,
        username: String,
        resolution: u16,
    },

    /// A user in your channel stopped screen sharing.
    ScreenShareStopped { user_id: UserId },

    /// Confirmation that you are now watching a user's screen share. Carries the
    /// share's codec: this is the only message a late joiner gets before frames
    /// arrive (`ScreenShareStarted` went out before they clicked watch).
    WatchingScreenShare {
        sharer_user_id: UserId,
        codec: VideoCodec,
    },

    /// You stopped watching a screen share.
    StoppedWatchingScreenShare { reason: String },

    /// Your viewer count changed (sharer only). 0 = stop capture, 1+ = start capture.
    ViewerCountChanged { viewer_count: u32 },

    /// A viewer requested a keyframe (sharer only).
    KeyframeRequested,

    /// Error response for screen share operations.
    ScreenShareError { reason: String },

    // ── E2E Encryption messages ───────────────────────────────────────
    /// Pre-key bundle response for session establishment.
    PreKeyBundle {
        user_id: UserId,
        bundle: PreKeyBundleData,
    },

    /// Pre-key bundle not available (user offline or keys exhausted).
    PreKeyBundleUnavailable { user_id: UserId },

    /// A remote user's identity key changed (trust-on-first-use warning).
    IdentityKeyChanged {
        user_id: UserId,
        new_identity_key: Vec<u8>,
    },

    /// An encrypted direct message was received (relayed by server).
    EncryptedDirectChatMessage {
        from_user_id: UserId,
        from_username: String,
        to_user_id: UserId,
        ciphertext: Vec<u8>,
        message_type: u8,
        timestamp: u64,
    },

    /// An encrypted channel message was received.
    EncryptedChannelChatMessage {
        channel_id: ChannelId,
        user_id: UserId,
        username: String,
        ciphertext: Vec<u8>,
        timestamp: u64,
    },

    /// A sender key distribution message was received (pairwise-encrypted).
    SenderKeyReceived {
        channel_id: ChannelId,
        from_user_id: UserId,
        distribution_message: Vec<u8>,
        /// 1 = PreKeySignalMessage, 2 = SignalMessage.
        #[serde(default)]
        message_type: u8,
    },

    /// A media encryption key was received (peer-to-peer, encrypted via Signal).
    /// The server relays it blind; it never holds media keys.
    MediaKeyReceived {
        channel_id: ChannelId,
        from_user_id: UserId,
        encrypted_media_key: Vec<u8>,
        /// 1 = PreKeySignalMessage, 2 = SignalMessage.
        message_type: u8,
    },

    /// Another user poked you. Message is E2E encrypted ciphertext.
    PokeReceived {
        from_user_id: UserId,
        from_username: String,
        ciphertext: Vec<u8>,
        message_type: u8,
    },

    // ── Moderation ───────────────────────────────────────────────────
    /// A user's admin status changed (broadcast to everyone; the admin's own
    /// client sees its login confirmed this way).
    AdminStatus { user_id: UserId, is_admin: bool },

    /// An admin command was refused.
    AdminError { reason: String },

    /// Active IP bans (admin only; reply to AdminListBans and after changes).
    AdminBans { bans: Vec<BanInfo> },

    /// The server is closing this connection (kick or ban). Clients must not
    /// auto-reconnect.
    Disconnected { reason: String },

    // ── Channel history hand-off ─────────────────────────────────────
    /// A newcomer asks you for recent chat of the channel you share.
    ChannelHistoryRequested {
        channel_id: ChannelId,
        from_user_id: UserId,
    },

    /// Recent channel chat from a member (pairwise-encrypted).
    ChannelHistoryReceived {
        channel_id: ChannelId,
        from_user_id: UserId,
        from_username: String,
        ciphertext: Vec<u8>,
        /// 1 = PreKeySignalMessage, 2 = SignalMessage.
        message_type: u8,
    },

    // ── Screen share congestion control ──────────────────────────────
    /// One of your viewers reported frame loss (sharer only).
    VideoLossReported {
        viewer_user_id: UserId,
        frames_dropped: u32,
        frames_received: u32,
    },

    // ── Direct messages ──────────────────────────────────────────────
    /// A direct message found nobody to deliver it to: that user has left the
    /// server (protocol v10). User ids are never handed out twice, so they are
    /// not coming back under this one.
    DirectMessageUndelivered { target_user_id: UserId },

    // ── Accounts (protocol v11) ──────────────────────────────────────
    /// The next step of an account sign-in.
    AuthStep(AuthStep),

    /// An answer to an `AccountRequest`, or news about the account.
    Account(AccountReply),

    // ── Pre-keys (protocol v12) ──────────────────────────────────────
    /// The relay has handed out all but `remaining` of your one-time pre-keys:
    /// send more with `UploadPreKeys`.
    PreKeysLow { remaining: u32 },

    /// The connection is refused, in a form every later version can read: this
    /// variant's index and fields never change (protocol v12, frozen). `code`
    /// is a number, not an enum, so a newer relay's new reason still decodes.
    /// Sent only to clients of protocol 12 or later; older ones get `AuthError`.
    Refused {
        code: u16,
        server_protocol: u32,
        server_version: String,
        text: String,
    },

    // ── Files (protocol v13) ─────────────────────────────────────────
    /// Upload the blob: `PUT /f/v1/<hash>?offset=N` in chunks of at most
    /// 1 MiB, each with `Authorization: Bearer <ticket>`, each starting where
    /// the last ended. The ticket lasts ten minutes from the last chunk of
    /// 64 KiB or more (an hour at most), or until this connection ends. Size
    /// chunks to the link; a chunk cut off without an answer is sent again
    /// from the same offset, smaller.
    FileUploadReady { hash: [u8; 32], ticket: String },

    /// The relay has the blob, checked against its id.
    FileStored { hash: [u8; 32] },

    /// Download the blob: `GET /f/v1/<hash>` with `Range` (at most 1 MiB per
    /// request) and `Authorization: Bearer <ticket>`. `size` is the blob's.
    FileReady {
        hash: [u8; 32],
        ticket: String,
        size: u64,
    },

    /// An upload or a fetch is refused. `code` is for programs (`FILE_*`
    /// below: under 100 the same request gets the same answer, from 100 a
    /// later one may not); `reason` is for people.
    FileRefused {
        hash: [u8; 32],
        code: u16,
        reason: String,
    },

    /// A member asked for a blob the relay no longer has. Upload it again
    /// (`FileUpload`) if you hold it and a message in `conv`, as you name it,
    /// refers to it. In a channel it names no one, so who asked stays
    /// unknown; a direct conversation's `conv` names its other party.
    FileWanted { conv: FileConv, hash: [u8; 32] },

    /// The blob has gone; its conversations' members online are being asked
    /// for it. `FileReady` follows once one has uploaded it, or
    /// `FileUnavailable` when nobody started within a minute, or
    /// `FileRefused` (a budget) when it lands.
    FileSeeking { hash: [u8; 32] },

    /// Nobody online had the blob in time.
    FileUnavailable { hash: [u8; 32] },
}

/// `FileRefused.code`, final for this hash: not in a conversation of the
/// asker's (or no such conversation).
pub const FILE_NOT_HERE: u16 = 1;
/// The relay keeps no files.
pub const FILE_OFF: u16 = 2;
/// Larger than this relay takes.
pub const FILE_TOO_LARGE: u16 = 3;
/// Posted in too many places.
pub const FILE_PLACES: u16 = 4;
/// The uploaded bytes are not the blob the hash names.
pub const FILE_MISMATCH: u16 = 5;
/// From here on a later try may succeed. Too many at once: slow down.
pub const FILE_RATE: u16 = 100;
/// The asker's hourly upload or download budget is spent.
pub const FILE_BUDGET: u16 = 101;
/// The relay is busy: no space, or other uploads first.
pub const FILE_BUSY: u16 = 102;
/// The upload stalled.
pub const FILE_STALLED: u16 = 103;
/// The upload took too long.
pub const FILE_EXPIRED: u16 = 104;
/// The relay could not store the blob.
pub const FILE_FAILED: u16 = 105;

/// `Refused.code`: the client speaks another protocol version.
/// `server_protocol` above the client's means the client must update.
pub const REFUSED_VERSION: u16 = 1;
/// The first protocol version that decodes `ServerMessage::Refused`.
pub const FIRST_STRUCTURED_REFUSAL: u32 = 12;
