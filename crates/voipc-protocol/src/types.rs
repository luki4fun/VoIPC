//! A note on `#[serde(default)]` in the wire types: it only helps JSON
//! callers (the browser builds messages as JS objects and may leave a field
//! out). On the wire, postcard is positional, so it never lets an older and a
//! newer layout read each other: every layout change is a protocol bump, which
//! `tests/golden.rs` enforces.

use serde::{Deserialize, Serialize};

/// Unique user identifier assigned by the server upon connection.
pub type UserId = u32;

/// Channel identifier. Channel 0 is always the root/lobby.
pub type ChannelId = u32;

/// Opaque session token issued after authentication,
/// used to correlate UDP packets to a TCP session.
pub type SessionId = u32;

/// Sequence number for voice packets, monotonically increasing per sender.
pub type SequenceNumber = u32;

/// Information about a connected user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: UserId,
    pub username: String,
    pub channel_id: ChannelId,
    pub is_muted: bool,
    #[serde(default)]
    pub is_deafened: bool,
    #[serde(default)]
    pub is_screen_sharing: bool,
    /// Logged in with the server's admin token.
    #[serde(default)]
    pub is_admin: bool,
    /// This user answers a newcomer's request for recent channel chat
    /// (protocol v9). The one thing about chat the server is told, and only so
    /// that a member list can say who a history request would reach — the
    /// server already sees every request and every reply go past.
    #[serde(default)]
    pub shares_history: bool,
    /// The relay account this user signed in with (protocol v11), or `None`
    /// for a guest. Peers show a verified mark for it, and key what they
    /// remember about a person (an identity, a message id) by it instead of by
    /// the user id, which is new on every connect.
    #[serde(default)]
    pub account: Option<[u8; 16]>,
    /// Holds the moderator role (kick, ban, any channel's settings).
    #[serde(default)]
    pub is_moderator: bool,
}

// ── Accounts (protocol v11) ──────────────────────────────────────────────

/// Who may make an account on a relay that has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Registration {
    /// Anyone, behind a proof of work the client solves.
    Open,
    /// With a code from an admin, which may be bound to one name.
    Invite,
    /// Only with a code an admin made for that name.
    Closed,
}

/// What a relay with accounts tells every client in `Authenticated`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAccounts {
    /// Guests are refused; everybody signs in.
    pub required: bool,
    pub registration: Registration,
    /// Members may keep an encrypted copy of their messages here.
    pub cloud: bool,
    /// The relay's own id: the client derives its keys from it, so they
    /// survive the relay moving to another address.
    pub relay_id: [u8; 16],
}

/// What a relay with a file cache tells every client in `Authenticated`
/// (protocol v13). `None` there means the relay keeps no files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLimits {
    /// Largest blob it takes, in bytes: the sealed file, not the file.
    pub max_bytes: u64,
}

/// The conversation a file was posted in (protocol v13), named as the client
/// sending the message sees it. The relay checks every upload and fetch
/// against it, and asks that conversation's members when a blob has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileConv {
    /// A text channel.
    Channel(ChannelId),
    /// A direct conversation with this user, who is online.
    Direct(UserId),
    /// A kept direct conversation with this account, which may be away.
    Account([u8; 16]),
}

/// How a client means to sign in, in `Authenticate.account`. The account name
/// is `Authenticate.username`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountStart {
    /// With the password (the secret derived from it).
    Login,
    /// A new account; `invite` is the code from an invite link.
    Register { invite: Option<String> },
    /// With the key this device was given at an earlier sign-in.
    DeviceKey { device_id: Vec<u8> },
    /// A forgotten password, set anew with the recovery key (1.0): the
    /// account proves itself with its identity key, which only the vault's
    /// recovery slot opens. It ends in `AuthStep::ResetDone`, not a sign-in.
    Reset,
}

/// The sign-up proof of work: an ALTCHA challenge (JSON) and the relay's
/// signed timestamp, both handed back with the solution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    pub altcha: String,
    pub ts: String,
}

/// One item of the account's vault as the relay keeps it: ciphertext the
/// client made, under a key the relay never sees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBlob {
    pub k: String,
    pub v: Vec<u8>,
    /// Compare-and-set version; 0 = new.
    pub version: i64,
}

/// The signed-in account, in `Authenticated` and after it changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub id: [u8; 16],
    pub name: String,
    /// What the account may do right now (`*`, `voipc:moderate`, …).
    pub scopes: Vec<String>,
    /// It holds a role whose rights wait for a second factor: the client
    /// asks the user to set one up.
    pub needs_2fa: bool,
    pub totp_enabled: bool,
}

/// An active ban, as shown to admins. An address ban shows the name it was
/// given under, never the address (the relay keeps a keyed hash of it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanInfo {
    /// What `AdminUnban` lifts.
    pub id: u64,
    /// An account ban; else an address ban (an IPv4 address, or an IPv6 /64).
    pub account: bool,
    /// The account's name, or the name the user went by when banned.
    pub label: String,
    pub reason: String,
    /// Who banned: an account's name, "admin token" or "server shell".
    pub by: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Seconds until the ban expires; None = permanent.
    pub expires_in_secs: Option<u64>,
}

/// Video codec of a screen share, chosen by the sharer and fixed for the life
/// of the share. H.264 is the default because every viewer decodes it (browsers
/// included); H.265 is smaller but browsers expose no HEVC decoder on Linux and
/// Firefox none at all. VP8/VP9 exist because a Firefox sharer cannot encode
/// H.264 (Bugzilla 1918769) — no client encodes them natively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum VideoCodec {
    #[default]
    H264 = 0,
    H265 = 1,
    Vp8 = 2,
    Vp9 = 3,
}

impl VideoCodec {
    /// For passing the codec through an `AtomicU8`; unknown values read as H264.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::H265,
            2 => Self::Vp8,
            3 => Self::Vp9,
            _ => Self::H264,
        }
    }
}

/// Information about a screen capture source (display or window).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSourceInfo {
    pub id: String,
    pub name: String,
    /// "display" or "window"
    pub source_type: String,
}

// ── E2E Encryption types ──────────────────────────────────────────────

/// A pre-key bundle for X3DH key agreement, sent during authentication
/// and returned when requesting another user's keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundleData {
    pub registration_id: u32,
    pub device_id: u32,
    /// 32-byte Curve25519 identity public key.
    pub identity_key: Vec<u8>,
    pub signed_prekey_id: u32,
    /// 32-byte Curve25519 public key.
    pub signed_prekey: Vec<u8>,
    /// 64-byte XEdDSA signature by the identity key over the signed pre-key.
    pub signed_prekey_signature: Vec<u8>,
    /// Batch of one-time pre-keys.
    pub prekeys: Vec<OneTimePreKey>,
    /// The signed Kyber1024 last-resort pre-key (protocol v12): every session
    /// start is post-quantum (PQXDH).
    pub kyber_prekey_id: u32,
    /// 1569 bytes: a type byte, then the Kyber1024 public key.
    pub kyber_prekey: Vec<u8>,
    /// 64-byte XEdDSA signature by the identity key over `kyber_prekey`.
    pub kyber_prekey_signature: Vec<u8>,
}

/// A single one-time pre-key's public portion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    /// 32-byte Curve25519 public key.
    pub public_key: Vec<u8>,
}

/// Positional ("proximity") audio mode of a channel. Rendering happens on
/// each client; the server only stores the mode and relays the encrypted
/// position beacons of members who sync their position.
///
/// Coordinates are metres: x/y is the ground plane, z is up. `TwoD` ignores
/// z for distance; `ThreeD` uses all three axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProximityMode {
    #[default]
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "2d")]
    TwoD,
    #[serde(rename = "3d")]
    ThreeD,
}

/// Information about a channel/room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub channel_id: ChannelId,
    pub name: String,
    pub description: String,
    /// Maximum users allowed (0 = unlimited).
    pub max_users: u32,
    /// Current number of users in this channel.
    pub user_count: u32,
    /// Whether a password is required to join.
    pub has_password: bool,
    /// User who created this channel (None for the permanent General channel).
    pub created_by: Option<UserId>,
    /// Positional audio mode (protocol v6).
    #[serde(default)]
    pub proximity: ProximityMode,
    /// Not listed in the sidebar for non-admins (protocol v7). Joining by id
    /// still works, so invite links and the game SDK's join-by-name keep
    /// working — this hides the room, it does not lock it.
    #[serde(default)]
    pub hidden: bool,
    /// Members are shown to each other under a random pseudonym. The server
    /// substitutes it in every message; admins see the real names.
    #[serde(default)]
    pub anonymous: bool,
    /// Whether screen sharing is allowed here. Default true, so a channel
    /// from an older config keeps working.
    #[serde(default = "default_true")]
    pub screen_share: bool,
    /// Non-admins do not see the member list, only whoever is speaking.
    #[serde(default)]
    pub hide_members: bool,
    /// A text channel (protocol v9): joining it is a subscription, not a move.
    /// Several can be joined at once, and joining one leaves the voice channel
    /// the user stands in alone. No voice, no screen share, no proximity.
    #[serde(default)]
    pub text: bool,
    /// Clients join this text channel on connect unless the user left it
    /// before (which the client remembers). A hint only — the server never
    /// joins anybody by itself.
    #[serde(default)]
    pub auto_join: bool,
    /// Seconds a message written here is meant to live; 0 (the default) is no
    /// timer at all (protocol v9).
    ///
    /// The server neither stores chat nor enforces this — it cannot, the
    /// messages are end-to-end encrypted and it keeps none of them. This is the
    /// channel saying what it expects, which each client stamps on what it
    /// sends and applies to what it keeps. A client takes the shorter of this
    /// and what a message itself claims, so a relay that raises the number
    /// cannot make anybody's copy outlive what its sender intended.
    #[serde(default)]
    pub message_ttl_secs: u32,
    /// The relay forwards voice only to the people who should hear it, instead
    /// of to everyone in the channel (protocol v8).
    ///
    /// Off everywhere by default, and it is the **only** state in which the
    /// relay is told anything about who hears whom. It exists for channels a
    /// game drives, where "everyone in the channel" can be hundreds of players
    /// spread over a map; everywhere else fanning out to the whole channel
    /// costs nothing and tells the server nothing. A client entering one is
    /// told, in as many words, what it now shares.
    #[serde(default)]
    pub routed: bool,
    /// An announcement channel (protocol v11): only its managers — the
    /// creator, admins and moderators — may post, and the relay refuses
    /// everybody else's messages. Text channels only.
    #[serde(default)]
    pub announce: bool,
    /// Slow mode (protocol v11): a member may post once per this many seconds;
    /// 0 is off. Enforced by the relay, which sees who posts where and when
    /// but nothing of what; the channel's managers are exempt.
    #[serde(default)]
    pub slow_mode_secs: u32,
    /// Marked 18+ (protocol v11). The relay only carries the flag: each client
    /// asks its user for consent before joining or showing the channel.
    #[serde(default)]
    pub nsfw: bool,
    /// The stored-message log this channel keeps for accounts that ask for
    /// one (protocol v11): `c:<uid>`. Empty where there is none — a relay
    /// without accounts or without storage, a temporary channel, and one that
    /// is anonymous or hides its members (a log's members see each other).
    #[serde(default)]
    pub log: String,
}

/// The options a `SetChannelOptions` asks for; `None` leaves one as it is.
/// One struct from the settings dialog to the relay's checks (protocol v11),
/// so a new option is a field here and one in `ChannelInfo`, not one per layer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOptions {
    #[serde(default)]
    pub hidden: Option<bool>,
    #[serde(default)]
    pub anonymous: Option<bool>,
    #[serde(default)]
    pub screen_share: Option<bool>,
    #[serde(default)]
    pub hide_members: Option<bool>,
    /// Have the relay forward voice only to whoever should hear it
    /// (protocol v8). See `ChannelInfo::routed`.
    #[serde(default)]
    pub routed: Option<bool>,
    /// Seconds a message written here is meant to live; 0 turns the timer
    /// off (protocol v9). See `ChannelInfo::message_ttl_secs`.
    #[serde(default)]
    pub message_ttl_secs: Option<u32>,
    /// Only the channel's managers may post (protocol v11; text channels
    /// only). See `ChannelInfo::announce`.
    #[serde(default)]
    pub announce: Option<bool>,
    /// One post per this many seconds per member, 0 = off (protocol v11).
    /// See `ChannelInfo::slow_mode_secs`.
    #[serde(default)]
    pub slow_mode_secs: Option<u32>,
    /// Mark the channel 18+ (protocol v11). See `ChannelInfo::nsfw`.
    #[serde(default)]
    pub nsfw: Option<bool>,
}

/// An empty channel with every option off, but screen sharing on (as an
/// older peer's message reads too): what a literal fills in with
/// `..Default::default()`, so a new field is one edit, not one per site.
impl Default for ChannelInfo {
    fn default() -> Self {
        ChannelInfo {
            channel_id: 0,
            name: String::new(),
            description: String::new(),
            max_users: 0,
            user_count: 0,
            has_password: false,
            created_by: None,
            proximity: ProximityMode::default(),
            hidden: false,
            anonymous: false,
            screen_share: true,
            hide_members: false,
            text: false,
            auto_join: false,
            message_ttl_secs: 0,
            routed: false,
            announce: false,
            slow_mode_secs: 0,
            nsfw: false,
            log: String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_info_roundtrip() {
        let info = UserInfo {
            user_id: 42,
            username: "alice".into(),
            channel_id: 1,
            is_muted: true,
            is_deafened: true,
            is_screen_sharing: false,
            is_admin: true,
            shares_history: true,
            account: None,
            is_moderator: false,
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: UserInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.user_id, 42);
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.channel_id, 1);
        assert!(decoded.is_muted);
        assert!(decoded.is_deafened);
        assert!(!decoded.is_screen_sharing);
    }

    #[test]
    fn channel_info_roundtrip() {
        let info = ChannelInfo {
            channel_id: 5,
            name: "Test".into(),
            description: "desc".into(),
            max_users: 10,
            user_count: 3,
            has_password: true,
            created_by: Some(1),
            proximity: ProximityMode::TwoD,
            hidden: true,
            anonymous: true,
            screen_share: false,
            hide_members: true,
            routed: true,
            text: true,
            auto_join: true,
            message_ttl_secs: 3600,
            announce: true,
            slow_mode_secs: 30,
            nsfw: true,
            log: "c:abc".into(),
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: ChannelInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.channel_id, 5);
        assert_eq!(decoded.name, "Test");
        assert_eq!(decoded.max_users, 10);
        assert!(decoded.has_password);
        assert_eq!(decoded.created_by, Some(1));
        assert_eq!(decoded.proximity, ProximityMode::TwoD);
        assert!(decoded.hidden && decoded.anonymous && decoded.hide_members);
        assert!(!decoded.screen_share);
        assert!(decoded.announce && decoded.nsfw);
        assert_eq!(decoded.slow_mode_secs, 30);
    }

    #[test]
    fn channel_options_default_to_an_ordinary_room() {
        // A channels.json entry that names none of them, and an older config
        // reaching a newer server, must both give a plain public channel that
        // still allows screen sharing.
        let info: ChannelInfo = serde_json::from_str(
            r#"{"channel_id":1,"name":"X","description":"","max_users":0,
                "user_count":0,"has_password":false,"created_by":null}"#,
        )
        .unwrap();
        assert!(!info.hidden && !info.anonymous && !info.hide_members);
        assert!(
            info.screen_share,
            "sharing must stay on unless switched off"
        );
        assert_eq!(info.proximity, ProximityMode::Off);
        assert!(!info.announce && !info.nsfw && info.slow_mode_secs == 0);
    }

    #[test]
    fn proximity_mode_json_names() {
        assert_eq!(
            serde_json::to_string(&ProximityMode::Off).unwrap(),
            "\"off\""
        );
        assert_eq!(
            serde_json::to_string(&ProximityMode::TwoD).unwrap(),
            "\"2d\""
        );
        assert_eq!(
            serde_json::to_string(&ProximityMode::ThreeD).unwrap(),
            "\"3d\""
        );
        let m: ProximityMode = serde_json::from_str("\"3d\"").unwrap();
        assert_eq!(m, ProximityMode::ThreeD);
        assert!(serde_json::from_str::<ProximityMode>("\"4d\"").is_err());
    }

    #[test]
    fn user_info_default_screen_sharing() {
        // Serialize a UserInfo without is_screen_sharing, verify default is false
        let info = UserInfo {
            user_id: 1,
            username: "bob".into(),
            channel_id: 0,
            is_muted: false,
            is_deafened: false,
            is_screen_sharing: false,
            is_admin: false,
            shares_history: false,
            account: None,
            is_moderator: false,
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: UserInfo = postcard::from_bytes(&bytes).unwrap();
        assert!(!decoded.is_screen_sharing);
    }
}
