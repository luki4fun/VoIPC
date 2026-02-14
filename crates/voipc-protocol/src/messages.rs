use serde::{Deserialize, Serialize};

use crate::types::*;

/// Messages sent from client to server over the TCP control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Initial authentication. Sent immediately after TLS handshake.
    Authenticate {
        username: String,
        /// Protocol version for forward compatibility.
        protocol_version: u32,
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

    /// Send a chat message to the sender's current channel.
    SendChannelMessage { content: String },

    /// Send a direct message to another user.
    SendDirectMessage {
        target_user_id: UserId,
        content: String,
    },

    /// Start sharing screen. Server notifies channel but sharer waits for viewers.
    StartScreenShare {
        /// Capture source identifier (display/window id from enumeration).
        source: String,
        /// Desired resolution height: 480, 720, or 1080.
        resolution: u16,
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
        /// Media key encrypted with the pairwise Signal session.
        encrypted_media_key: Vec<u8>,
    },
}

/// Messages sent from server to client over the TCP control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Authentication succeeded.
    Authenticated {
        user_id: UserId,
        session_id: SessionId,
        /// Server UDP port for voice traffic.
        udp_port: u16,
        /// Token the client must include in every UDP voice packet.
        udp_token: u64,
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

    /// A chat message in a channel.
    ChannelChatMessage {
        channel_id: ChannelId,
        user_id: UserId,
        username: String,
        content: String,
        timestamp: u64,
    },

    /// A direct message between two users.
    DirectChatMessage {
        from_user_id: UserId,
        from_username: String,
        to_user_id: UserId,
        content: String,
        timestamp: u64,
    },

    /// A user in your channel started screen sharing.
    ScreenShareStarted {
        user_id: UserId,
        username: String,
        resolution: u16,
    },

    /// A user in your channel stopped screen sharing.
    ScreenShareStopped { user_id: UserId },

    /// Confirmation that you are now watching a user's screen share.
    WatchingScreenShare { sharer_user_id: UserId },

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
    MediaKeyReceived {
        channel_id: ChannelId,
        from_user_id: UserId,
        encrypted_media_key: Vec<u8>,
    },

    /// Server-issued media encryption key for a channel (sent over TLS).
    /// Used when Signal sessions are not established for peer-to-peer key exchange.
    ChannelMediaKey {
        channel_id: ChannelId,
        key_id: u16,
        key_bytes: Vec<u8>,
    },
}
