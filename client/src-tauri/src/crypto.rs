use std::collections::HashMap;
use std::num::NonZeroU32;

use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM, Nonce, Aad};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"VOIP";
/// Archive format. v1 stored `kind` with `skip_serializing_if`, which postcard
/// (positional, no field names) cannot read back — every v1 file holding a
/// message failed to load. v2 writes every field, always. v3 adds the moment a
/// message is to be deleted.
///
/// A new field is a new version for the same reason: postcard writes no names,
/// so a v2 file read as v3 runs off the end of the first message and into the
/// next one's bytes.
const VERSION: u8 = 0x03;
const VERSION_V2: u8 = 0x02;
const VERSION_V1: u8 = 0x01;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + 4; // 53
const PBKDF2_ITERATIONS: u32 = 600_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub user_id: u32,
    pub username: String,
    pub content: String,
    pub timestamp: u64,
    /// None/"text" = a message; "history-marker" = the divider after shared
    /// history; other values are placeholders (future attachment types).
    ///
    /// No `skip_serializing_if`: postcard is positional, so a field that is
    /// sometimes absent cannot be read back. That was the v1 bug.
    #[serde(default)]
    pub kind: Option<String>,
    /// Minted by the sender inside the end-to-end envelope, so every copy of a
    /// message carries the same one. What lets history from several members be
    /// merged without duplicates. `None` for anything stored before v9.
    #[serde(default)]
    pub id: Option<String>,
    /// When this message is to be deleted, as a Unix millisecond timestamp.
    /// `None` is a message with no destruction timer.
    ///
    /// An absolute moment rather than the timer it came from, and stamped once
    /// when the message arrives: every copy of a message works out the same
    /// instant from the same timestamp, so it goes everywhere at once — and a
    /// channel whose timer changes afterwards does not reach back into what is
    /// already stored.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct ChatArchive {
    pub channels: HashMap<String, Vec<ChatMessage>>,
    pub dms: HashMap<String, Vec<ChatMessage>>,
    /// Chat key → the newest timestamp the user deleted there. Anything older
    /// offered by a member is not merged back in, so clearing a channel stays
    /// cleared; asking for a re-sync drops the entry.
    #[serde(default)]
    pub cleared: HashMap<String, u64>,
}

/// A v2 message: everything but the destruction deadline.
#[derive(Deserialize)]
struct V2ChatMessage {
    user_id: u32,
    username: String,
    content: String,
    timestamp: u64,
    kind: Option<String>,
    id: Option<String>,
}

#[derive(Deserialize, Default)]
struct V2ChatArchive {
    channels: HashMap<String, Vec<V2ChatMessage>>,
    dms: HashMap<String, Vec<V2ChatMessage>>,
    cleared: HashMap<String, u64>,
}

impl From<V2ChatMessage> for ChatMessage {
    fn from(m: V2ChatMessage) -> Self {
        Self {
            user_id: m.user_id,
            username: m.username,
            content: m.content,
            timestamp: m.timestamp,
            kind: m.kind,
            id: m.id,
            // Written before destruction timers existed, so nothing here is
            // under one. A timer a channel sets now applies to what arrives
            // after it, not to this.
            expires_at: None,
        }
    }
}

/// A v1 message: the four fields that were always written. A v1 archive that
/// ever stored a `kind` (only history dividers did) was already unreadable —
/// postcard cannot tell an omitted field from the next message's first byte.
#[derive(Deserialize)]
struct LegacyChatMessage {
    user_id: u32,
    username: String,
    content: String,
    timestamp: u64,
}

#[derive(Deserialize, Default)]
struct LegacyChatArchive {
    channels: HashMap<String, Vec<LegacyChatMessage>>,
    dms: HashMap<String, Vec<LegacyChatMessage>>,
}

impl From<LegacyChatMessage> for ChatMessage {
    fn from(m: LegacyChatMessage) -> Self {
        Self {
            user_id: m.user_id,
            username: m.username,
            content: m.content,
            timestamp: m.timestamp,
            kind: None,
            id: None,
            expires_at: None,
        }
    }
}

/// Now, as a Unix millisecond timestamp — the clock a destruction deadline is
/// compared against.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Drop every message whose destruction deadline has passed, and every
/// conversation left empty by it. Returns how many messages went.
///
/// Called where the archive is read and where it is written, so a message that
/// came due while the app was closed is never shown and never written back out.
/// The front end sweeps the same messages on screen; this is the copy on disk.
pub fn drop_expired(map: &mut HashMap<String, Vec<ChatMessage>>, now: u64) -> usize {
    let mut dropped = 0;
    map.retain(|_, msgs| {
        let before = msgs.len();
        msgs.retain(|m| m.expires_at.is_none_or(|at| at > now));
        dropped += before - msgs.len();
        !msgs.is_empty()
    });
    dropped
}

/// Read an older archive's messages as current ones. Generic over the shape,
/// because there are two of them now and there will be more.
fn convert<T: Into<ChatMessage>>(map: HashMap<String, Vec<T>>) -> HashMap<String, Vec<ChatMessage>> {
    map.into_iter()
        .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
        .collect()
}

/// Derive a 256-bit AES-GCM key from a password and salt using PBKDF2-HMAC-SHA256.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> LessSafeKey {
    let mut key_bytes = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        salt,
        password.as_bytes(),
        &mut key_bytes,
    );
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).expect("valid key length");
    LessSafeKey::new(unbound)
}

/// Encrypt a ChatArchive into the full binary file format.
pub fn encrypt_archive(
    archive: &ChatArchive,
    key: &LessSafeKey,
    salt: &[u8; SALT_LEN],
) -> anyhow::Result<Vec<u8>> {
    let rng = SystemRandom::new();

    // Serialize archive with postcard
    let plaintext = postcard::to_allocvec(archive)
        .map_err(|e| anyhow::anyhow!("serialization failed: {e}"))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("RNG failed"))?;

    // Build AAD from magic + version
    let mut aad_bytes = [0u8; 5];
    aad_bytes[..4].copy_from_slice(MAGIC);
    aad_bytes[4] = VERSION;

    // Encrypt in-place (ring appends the 16-byte tag)
    let mut in_out = plaintext;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    key.seal_in_place_append_tag(nonce, Aad::from(&aad_bytes), &mut in_out)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    // Build file: header + encrypted payload (includes tag)
    let payload_len = in_out.len() as u32;
    let mut file_data = Vec::with_capacity(HEADER_LEN + in_out.len());
    file_data.extend_from_slice(MAGIC);
    file_data.push(VERSION);
    file_data.extend_from_slice(salt);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&payload_len.to_be_bytes());
    file_data.extend_from_slice(&in_out);

    Ok(file_data)
}

/// Decrypt a file's contents back into a ChatArchive.
/// Returns the archive, the salt (for future saves), and the derived key.
pub fn decrypt_archive(
    file_data: &[u8],
    password: &str,
) -> anyhow::Result<(ChatArchive, [u8; SALT_LEN], LessSafeKey)> {
    if file_data.len() < HEADER_LEN {
        anyhow::bail!("file too short");
    }

    // Validate magic + version
    if &file_data[0..4] != MAGIC {
        anyhow::bail!("invalid file format");
    }
    let version = file_data[4];
    if version != VERSION && version != VERSION_V2 && version != VERSION_V1 {
        anyhow::bail!("unsupported file version");
    }

    // Extract salt, nonce, payload length
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&file_data[5..5 + SALT_LEN]);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&file_data[37..37 + NONCE_LEN]);

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&file_data[49..53]);
    let payload_len = u32::from_be_bytes(len_bytes) as usize;

    // Subtracting rather than adding: `HEADER_LEN + payload_len` wraps on a
    // 32-bit target — armv7 Android is one — and a wrapped sum passes this
    // check and then panics on the slice below.
    if file_data.len() - HEADER_LEN < payload_len {
        anyhow::bail!("file truncated");
    }

    // Derive key
    let key = derive_key(password, &salt);

    // Decrypt (ring verifies the tag and strips it)
    let mut ciphertext = file_data[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut aad_bytes = [0u8; 5];
    aad_bytes[..4].copy_from_slice(MAGIC);
    aad_bytes[4] = version;

    let plaintext = key
        .open_in_place(nonce, Aad::from(&aad_bytes), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("incorrect password or corrupted file"))?;

    // Deserialize. An older file is read through the shape it was written with
    // and written back as the current version on the next save.
    let archive = if version == VERSION_V2 {
        let v2: V2ChatArchive = postcard::from_bytes(plaintext)
            .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
        ChatArchive {
            channels: convert(v2.channels),
            dms: convert(v2.dms),
            cleared: v2.cleared,
        }
    } else if version == VERSION_V1 {
        let legacy: LegacyChatArchive = postcard::from_bytes(plaintext).map_err(|_| {
            anyhow::anyhow!(
                "this history file was written by a version that could not read it back \
                 (it stored a shared-history divider); its messages cannot be recovered"
            )
        })?;
        ChatArchive {
            channels: convert(legacy.channels),
            dms: convert(legacy.dms),
            cleared: HashMap::new(),
        }
    } else {
        postcard::from_bytes(plaintext)
            .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?
    };

    Ok((archive, salt, key))
}

/// Check if file data starts with a valid VOIP header.
pub fn has_valid_header(file_data: &[u8]) -> bool {
    file_data.len() >= HEADER_LEN
        && &file_data[0..4] == MAGIC
        && (file_data[4] == VERSION || file_data[4] == VERSION_V2 || file_data[4] == VERSION_V1)
}

/// Generate a fresh random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt).expect("RNG failed");
    salt
}

// ── The channel-message envelope ────────────────────────────────────────
//
// Lives in `voipc-crypto` so the browser build uses the same bytes: the two
// implementations had already drifted on the version tag before anybody
// noticed, because nothing read it.
pub use voipc_crypto::envelope::{envelope, new_message_id, open_envelope};

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(content: &str, kind: Option<&str>) -> ChatMessage {
        ChatMessage {
            user_id: 1,
            username: "alice".into(),
            content: content.into(),
            timestamp: 1_700_000_000_000,
            kind: kind.map(str::to_string),
            id: None,
            expires_at: None,
        }
    }

    /// The v1 bug: ordinary messages (`kind: None`) could not be read back, so
    /// unlocking a vault that had ever held one failed.
    #[test]
    fn an_archive_of_ordinary_messages_survives_a_round_trip() {
        let salt = generate_salt();
        let key = derive_key("hunter2", &salt);
        let mut archive = ChatArchive::default();
        archive
            .channels
            .insert("localhost:9987/general".into(), vec![msg("hello", None), msg("there", None)]);
        archive
            .channels
            .insert("localhost:9987/off".into(), vec![msg("shared", Some("history-marker"))]);
        archive.dms.insert("1-2".into(), vec![msg("psst", None)]);
        archive.cleared.insert("localhost:9987/gone".into(), 42);

        let file = encrypt_archive(&archive, &key, &salt).unwrap();
        assert!(has_valid_header(&file));
        let (back, back_salt, _) = decrypt_archive(&file, "hunter2").unwrap();

        assert_eq!(back_salt, salt);
        assert_eq!(back.channels["localhost:9987/general"].len(), 2);
        assert_eq!(back.channels["localhost:9987/general"][1].content, "there");
        assert_eq!(
            back.channels["localhost:9987/off"][0].kind.as_deref(),
            Some("history-marker")
        );
        assert_eq!(back.dms["1-2"][0].content, "psst");
        assert_eq!(back.cleared["localhost:9987/gone"], 42);
        assert!(decrypt_archive(&file, "wrong").is_err());
    }

    /// A file written by 0.8 and earlier: four fields per message, no `kind`.
    #[test]
    fn a_v1_archive_still_opens() {
        #[derive(Serialize)]
        struct V1Message {
            user_id: u32,
            username: String,
            content: String,
            timestamp: u64,
        }
        #[derive(Serialize)]
        struct V1Archive {
            channels: HashMap<String, Vec<V1Message>>,
            dms: HashMap<String, Vec<V1Message>>,
        }

        let mut channels = HashMap::new();
        channels.insert(
            "general".to_string(),
            vec![V1Message {
                user_id: 7,
                username: "bob".into(),
                content: "from the old days".into(),
                timestamp: 1_600_000_000_000,
            }],
        );
        let plaintext = postcard::to_allocvec(&V1Archive {
            channels,
            dms: HashMap::new(),
        })
        .unwrap();

        // Rebuild a v1 file around it: same header, version byte 1
        let salt = generate_salt();
        let key = derive_key("pw", &salt);
        let mut aad = [0u8; 5];
        aad[..4].copy_from_slice(MAGIC);
        aad[4] = VERSION_V1;
        let mut in_out = plaintext;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0u8; NONCE_LEN]),
            Aad::from(&aad),
            &mut in_out,
        )
        .unwrap();
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.push(VERSION_V1);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&[0u8; NONCE_LEN]);
        file.extend_from_slice(&(in_out.len() as u32).to_be_bytes());
        file.extend_from_slice(&in_out);

        assert!(has_valid_header(&file));
        let (archive, _, _) = decrypt_archive(&file, "pw").unwrap();
        assert_eq!(archive.channels["general"][0].content, "from the old days");
        assert!(archive.channels["general"][0].id.is_none());
        assert!(archive.cleared.is_empty());
    }

    #[test]
    fn an_envelope_carries_its_id_and_survives_a_sender_that_sends_none() {
        let id = new_message_id();
        assert_eq!(id.len(), 32);
        assert_ne!(id, new_message_id());

        let m = open_envelope(&envelope(&id, "hello \u{1F600}", None));
        assert_eq!(m.id.as_deref(), Some(id.as_str()));
        assert_eq!(m.text, "hello \u{1F600}");

        // A pre-v9 sender: raw text, no id, still shown
        let m = open_envelope(b"plain old message");
        assert!(m.id.is_none());
        assert_eq!(m.text, "plain old message");

        // JSON that is not one of ours is text too, not a dropped message
        let m = open_envelope(b"{\"hello\":1}");
        assert!(m.id.is_none());
        assert_eq!(m.text, "{\"hello\":1}");
    }

    /// A v2 archive is everything written between the format fix and
    /// destruction timers, so it has to keep opening — and what it holds has no
    /// deadline, because a timer set now applies to what arrives after it.
    #[test]
    fn a_v2_archive_still_opens_and_its_messages_have_no_deadline() {
        #[derive(Serialize)]
        struct V2Message {
            user_id: u32,
            username: String,
            content: String,
            timestamp: u64,
            kind: Option<String>,
            id: Option<String>,
        }
        #[derive(Serialize)]
        struct V2Archive {
            channels: HashMap<String, Vec<V2Message>>,
            dms: HashMap<String, Vec<V2Message>>,
            cleared: HashMap<String, u64>,
        }

        let mut channels = HashMap::new();
        channels.insert(
            "host:9987/general".to_string(),
            vec![V2Message {
                user_id: 7,
                username: "bob".into(),
                content: "written before timers".into(),
                timestamp: 1_600_000_000_000,
                kind: None,
                id: Some("abc".into()),
            }],
        );
        let mut cleared = HashMap::new();
        cleared.insert("host:9987/general".to_string(), 1_500_000_000_000u64);
        let plaintext = postcard::to_allocvec(&V2Archive {
            channels,
            dms: HashMap::new(),
            cleared,
        })
        .unwrap();

        let salt = generate_salt();
        let key = derive_key("pw", &salt);
        let mut aad = [0u8; 5];
        aad[..4].copy_from_slice(MAGIC);
        aad[4] = VERSION_V2;
        let mut in_out = plaintext;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0u8; NONCE_LEN]),
            Aad::from(&aad),
            &mut in_out,
        )
        .unwrap();
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.push(VERSION_V2);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&[0u8; NONCE_LEN]);
        file.extend_from_slice(&(in_out.len() as u32).to_be_bytes());
        file.extend_from_slice(&in_out);

        assert!(has_valid_header(&file));
        let (archive, _, _) = decrypt_archive(&file, "pw").unwrap();
        let msg = &archive.channels["host:9987/general"][0];
        assert_eq!(msg.content, "written before timers");
        assert_eq!(msg.id.as_deref(), Some("abc"));
        assert!(msg.expires_at.is_none());
        // The watermark a v2 file carries is not lost on the way through
        assert_eq!(archive.cleared["host:9987/general"], 1_500_000_000_000);
    }

    #[test]
    fn a_message_past_its_deadline_is_not_kept() {
        let now = now_ms();
        let msg = |expires_at| ChatMessage {
            user_id: 1,
            username: "alice".into(),
            content: "hi".into(),
            timestamp: now - 1000,
            kind: None,
            id: None,
            expires_at,
        };
        let mut map = HashMap::new();
        map.insert("a".to_string(), vec![msg(Some(now - 1)), msg(None)]);
        // A conversation of nothing but expired messages goes with them.
        map.insert("b".to_string(), vec![msg(Some(now - 60_000))]);
        map.insert("c".to_string(), vec![msg(Some(now + 60_000))]);

        assert_eq!(drop_expired(&mut map, now), 2);
        assert_eq!(map["a"].len(), 1, "the one with no timer stays");
        assert!(!map.contains_key("b"), "an emptied conversation is dropped too");
        assert_eq!(map["c"].len(), 1, "one still in its life stays");
    }
}
