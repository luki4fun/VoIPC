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
    },

    /// Request to join a specific channel (with optional password).
    JoinChannel {
        channel_id: ChannelId,
        password: Option<String>,
    },

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
    },

    /// Client is disconnecting gracefully.
    Disconnect,

    /// Client toggled their mute state (informational for other users).
    SetMuted { muted: bool },

    /// Client toggled their deafen state (informational for other users).
    SetDeafened { deafened: bool },

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
        #[serde(default)]
        hidden: Option<bool>,
        #[serde(default)]
        anonymous: Option<bool>,
        #[serde(default)]
        screen_share: Option<bool>,
        #[serde(default)]
        hide_members: Option<bool>,
    },

    /// Kick a user from a channel (creator only).
    KickUser {
        channel_id: ChannelId,
        user_id: UserId,
    },

    /// Request the user list of a channel without joining it (preview).
    RequestChannelUsers {
        channel_id: ChannelId,
    },

    /// Invite a user to your channel (creator only).
    SendInvite {
        channel_id: ChannelId,
        target_user_id: UserId,
    },

    /// Accept a pending channel invite.
    AcceptInvite {
        channel_id: ChannelId,
    },

    /// Decline a pending channel invite.
    DeclineInvite {
        channel_id: ChannelId,
    },

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

    /// Disconnect a user and ban their IP (admin only).
    /// `duration_secs` 0 = until the server restarts.
    AdminBan {
        user_id: UserId,
        reason: String,
        duration_secs: u32,
    },

    /// Lift an IP ban (admin only).
    AdminUnban { ip: String },

    /// Request the list of active bans (admin only).
    AdminListBans,

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
}

/// Messages sent from server to client over the control stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Authentication succeeded. Media travels on the same QUIC connection
    /// (datagrams + per-frame streams), so there is nothing else to set up.
    Authenticated {
        user_id: UserId,
        session_id: SessionId,
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
}
