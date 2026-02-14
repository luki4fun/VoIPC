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
    /// 64-byte Ed25519 signature over the signed pre-key.
    pub signed_prekey_signature: Vec<u8>,
    /// Batch of one-time pre-keys.
    pub prekeys: Vec<OneTimePreKey>,
}

/// A single one-time pre-key's public portion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    /// 32-byte Curve25519 public key.
    pub public_key: Vec<u8>,
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
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: ChannelInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.channel_id, 5);
        assert_eq!(decoded.name, "Test");
        assert_eq!(decoded.max_users, 10);
        assert!(decoded.has_password);
        assert_eq!(decoded.created_by, Some(1));
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
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: UserInfo = postcard::from_bytes(&bytes).unwrap();
        assert!(!decoded.is_screen_sharing);
    }
}
