use std::collections::HashMap;
use std::num::NonZeroU32;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
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
/// next one's bytes. v4 adds the sender's account to a message and the
/// devices remembered by relays with accounts. v5 adds, per account, the
/// newest generation of each vault item this device has seen (1.0). v6 adds
/// `extra` to a message (1.2): one JSON string for every per-message field the
/// chat has gained since, so a new one no longer needs a new version. v7 adds, per account,
/// the bucket lists this device has named to its user (protocol 21). v8 is v7's layout with an
/// account's history under keys of its own (`host:port~<account>/…`, 1.12): a build from
/// before would take those for keys from before 0.9 and file them as a guest's channels, so
/// it must refuse the file, as it refuses any newer one, and leave it alone.
const VERSION: u8 = 0x08;
const VERSION_V7: u8 = 0x07;
const VERSION_V6: u8 = 0x06;
const VERSION_V5: u8 = 0x05;
const VERSION_V4: u8 = 0x04;
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
    /// The sender's relay account (hex), for one who had one: with the
    /// message id, what names a message across connects. `None` for a guest.
    #[serde(default)]
    pub account: Option<String>,
    /// Every newer per-message field (what it answers, its thread, …) as the
    /// front end's JSON: kept, never read here. Positional postcard made each
    /// new field a new format; one string that holds them all ends that.
    #[serde(default)]
    pub extra: Option<String>,
}

/// A device a relay with accounts remembers: its key stands in for the
/// password and the second factor there, and the vault's DEK kept with it
/// opens the account's vault without the password. Lives only inside this
/// encrypted archive (and only in memory while the archive is switched off).
#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceRecord {
    /// The address it was remembered at (`host:port`, as the connection's id).
    pub server: String,
    pub relay_id: [u8; 16],
    /// The account name, normalised.
    pub name: String,
    pub device_id: [u8; 16],
    /// Ed25519, PKCS#8.
    pub device_key: Vec<u8>,
    pub dek: [u8; 32],
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ChatArchive {
    pub channels: HashMap<String, Vec<ChatMessage>>,
    pub dms: HashMap<String, Vec<ChatMessage>>,
    /// Chat key → the newest timestamp the user deleted there. Anything older
    /// offered by a member is not merged back in, so clearing a channel stays
    /// cleared; asking for a re-sync drops the entry.
    #[serde(default)]
    pub cleared: HashMap<String, u64>,
    #[serde(default)]
    pub devices: Vec<DeviceRecord>,
    /// What this device keeps of each account's stored-message log (how far
    /// it has read, who it has named as readers): `"<relay hex>|<account name>"`.
    #[serde(default)]
    pub cursors: HashMap<String, voipc_crypto::sync::LogMemory>,
}

impl std::fmt::Debug for ChatArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatArchive")
            .field("channels", &self.channels.len())
            .field("dms", &self.dms.len())
            .field("devices", &self.devices.len())
            .finish_non_exhaustive()
    }
}

/// v4's log memory: everything but the vault generations.
#[derive(Deserialize)]
struct V4LogMemory {
    cursors: HashMap<String, i64>,
    readers: HashMap<String, Vec<[u8; 16]>>,
}

#[derive(Deserialize)]
struct V4ChatArchive {
    channels: HashMap<String, Vec<V4ChatMessage>>,
    dms: HashMap<String, Vec<V4ChatMessage>>,
    cleared: HashMap<String, u64>,
    devices: Vec<DeviceRecord>,
    cursors: HashMap<String, V4LogMemory>,
}

/// v5 and v6's log memory: everything but the lists named.
#[derive(Deserialize)]
struct V5LogMemory {
    cursors: HashMap<String, i64>,
    readers: HashMap<String, Vec<[u8; 16]>>,
    vault_gens: HashMap<String, u64>,
}

impl V5LogMemory {
    fn now(self) -> voipc_crypto::sync::LogMemory {
        voipc_crypto::sync::LogMemory {
            cursors: self.cursors,
            readers: self.readers,
            vault_gens: self.vault_gens,
            named: HashMap::new(),
        }
    }
}

/// v6: today's archive with v5's log memory.
#[derive(Deserialize)]
struct V6ChatArchive {
    channels: HashMap<String, Vec<ChatMessage>>,
    dms: HashMap<String, Vec<ChatMessage>>,
    cleared: HashMap<String, u64>,
    devices: Vec<DeviceRecord>,
    cursors: HashMap<String, V5LogMemory>,
}

/// v5: v6 with v4's messages.
#[derive(Deserialize)]
struct V5ChatArchive {
    channels: HashMap<String, Vec<V4ChatMessage>>,
    dms: HashMap<String, Vec<V4ChatMessage>>,
    cleared: HashMap<String, u64>,
    devices: Vec<DeviceRecord>,
    cursors: HashMap<String, V5LogMemory>,
}

/// A v4 and v5 message: everything but `extra`.
#[derive(Deserialize)]
struct V4ChatMessage {
    user_id: u32,
    username: String,
    content: String,
    timestamp: u64,
    kind: Option<String>,
    id: Option<String>,
    expires_at: Option<u64>,
    account: Option<String>,
}

impl From<V4ChatMessage> for ChatMessage {
    fn from(m: V4ChatMessage) -> Self {
        Self {
            user_id: m.user_id,
            username: m.username,
            content: m.content,
            timestamp: m.timestamp,
            kind: m.kind,
            id: m.id,
            expires_at: m.expires_at,
            account: m.account,
            extra: None,
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
fn convert<T: Into<ChatMessage>>(
    map: HashMap<String, Vec<T>>,
) -> HashMap<String, Vec<ChatMessage>> {
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
    let plaintext =
        postcard::to_allocvec(archive).map_err(|e| anyhow::anyhow!("serialization failed: {e}"))?;

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
/// The format version comes back too: an older file gets a one-time copy
/// before it is first written in the new one (`unlock_chat_history`).
pub fn decrypt_archive(
    file_data: &[u8],
    password: &str,
) -> anyhow::Result<(ChatArchive, [u8; SALT_LEN], LessSafeKey, u8)> {
    if file_data.len() < HEADER_LEN {
        anyhow::bail!("file too short");
    }

    // Validate magic + version
    if &file_data[0..4] != MAGIC {
        anyhow::bail!("invalid file format");
    }
    let version = file_data[4];
    if version > VERSION {
        anyhow::bail!("this chat history was saved by a newer VoIPC; update to open it");
    }
    // v1 to v3 predate 0.12, and no 1.x promises to open them
    // (docs/COMPATIBILITY.md §4): such a file is refused and left alone
    if ![VERSION, VERSION_V7, VERSION_V6, VERSION_V5, VERSION_V4].contains(&version) {
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
    let archive = if version == VERSION_V6 {
        let v6: V6ChatArchive = postcard::from_bytes(plaintext)
            .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
        ChatArchive {
            channels: v6.channels,
            dms: v6.dms,
            cleared: v6.cleared,
            devices: v6.devices,
            cursors: v6.cursors.into_iter().map(|(k, m)| (k, m.now())).collect(),
        }
    } else if version == VERSION_V5 {
        let v5: V5ChatArchive = postcard::from_bytes(plaintext)
            .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
        ChatArchive {
            channels: convert(v5.channels),
            dms: convert(v5.dms),
            cleared: v5.cleared,
            devices: v5.devices,
            cursors: v5.cursors.into_iter().map(|(k, m)| (k, m.now())).collect(),
        }
    } else if version == VERSION_V4 {
        let v4: V4ChatArchive = postcard::from_bytes(plaintext)
            .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;
        ChatArchive {
            channels: convert(v4.channels),
            dms: convert(v4.dms),
            cleared: v4.cleared,
            devices: v4.devices,
            cursors: v4
                .cursors
                .into_iter()
                .map(|(k, m)| {
                    (
                        k,
                        voipc_crypto::sync::LogMemory {
                            cursors: m.cursors,
                            readers: m.readers,
                            vault_gens: HashMap::new(),
                            named: HashMap::new(),
                        },
                    )
                })
                .collect(),
        }
    } else {
        postcard::from_bytes(plaintext)
            .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?
    };

    Ok((archive, salt, key, version))
}

/// What a chat history path holds. A newer or unreadable file is never taken
/// for "no file": the setup would otherwise offer to create one over it.
#[derive(Debug, PartialEq, Eq)]
pub enum FileKind {
    Missing,
    /// A history this version opens (its format version).
    Ours(u8),
    /// Written by a newer VoIPC.
    Newer,
    /// Not a VoIPC history, or damaged.
    Unreadable,
}

pub fn file_kind(path: &std::path::Path) -> FileKind {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileKind::Missing,
        Err(_) => FileKind::Unreadable,
        Ok(data) => kind_of(&data),
    }
}

fn kind_of(data: &[u8]) -> FileKind {
    if data.len() < HEADER_LEN || &data[0..4] != MAGIC {
        FileKind::Unreadable
    } else if data[4] > VERSION {
        FileKind::Newer
    } else if [VERSION, VERSION_V7, VERSION_V6, VERSION_V5, VERSION_V4].contains(&data[4]) {
        FileKind::Ours(data[4])
    } else {
        FileKind::Unreadable
    }
}

/// The format version this build writes.
pub const ARCHIVE_VERSION: u8 = VERSION;

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
pub use voipc_crypto::envelope::{envelope_with, new_message_id, open_envelope, Extras};

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
            account: None,
            extra: None,
        }
    }

    /// The v1 bug: ordinary messages (`kind: None`) could not be read back, so
    /// unlocking a vault that had ever held one failed.
    #[test]
    fn an_archive_of_ordinary_messages_survives_a_round_trip() {
        let salt = generate_salt();
        let key = derive_key("hunter2", &salt);
        let mut archive = ChatArchive::default();
        archive.channels.insert(
            "localhost:9987/general".into(),
            vec![msg("hello", None), msg("there", None)],
        );
        archive.channels.insert(
            "localhost:9987/off".into(),
            vec![msg("shared", Some("history-marker"))],
        );
        archive.dms.insert("1-2".into(), vec![msg("psst", None)]);
        archive.cleared.insert("localhost:9987/gone".into(), 42);

        let file = encrypt_archive(&archive, &key, &salt).unwrap();
        assert!(matches!(kind_of(&file), FileKind::Ours(_)));
        let (back, back_salt, _, _) = decrypt_archive(&file, "hunter2").unwrap();

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

    #[test]
    fn an_envelope_carries_its_id_and_survives_a_sender_that_sends_none() {
        let id = new_message_id();
        assert_eq!(id.len(), 32);
        assert_ne!(id, new_message_id());

        let m = open_envelope(&voipc_crypto::envelope::envelope(
            &id,
            "hello \u{1F600}",
            None,
        ));
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

    /// A remembered device survives the archive's round trip, and clearing
    /// the chat does not take it.
    #[test]
    fn a_remembered_device_round_trips() {
        let mut archive = ChatArchive::default();
        archive.devices.push(DeviceRecord {
            server: "voice.example:9987".into(),
            relay_id: [1; 16],
            name: "luki".into(),
            device_id: [2; 16],
            device_key: vec![3; 83],
            dek: [4; 32],
        });
        let mut m = msg("hi", None);
        m.account = Some("ab".repeat(16));
        archive.channels.insert("k".into(), vec![m]);
        let salt = generate_salt();
        let key = derive_key("pw", &salt);
        let file = encrypt_archive(&archive, &key, &salt).unwrap();
        assert_eq!(file[4], VERSION);
        let (back, _, _, _) = decrypt_archive(&file, "pw").unwrap();
        assert_eq!(back.devices.len(), 1);
        assert_eq!(
            (back.devices[0].name.as_str(), back.devices[0].dek),
            ("luki", [4; 32])
        );
        assert_eq!(
            back.channels["k"][0].account.as_deref(),
            Some("ab".repeat(16).as_str())
        );
    }

    /// v6: whatever the front end keeps in `extra` comes back as it went in.
    #[test]
    fn a_message_keeps_its_extra_fields() {
        let salt = generate_salt();
        let key = derive_key("pw", &salt);
        let mut archive = ChatArchive::default();
        let mut reply = msg("agreed", None);
        reply.extra = Some(r#"{"reply_to":"m1","thread":"m1"}"#.into());
        archive
            .channels
            .insert("k".into(), vec![msg("plain", None), reply]);
        let file = encrypt_archive(&archive, &key, &salt).unwrap();
        assert_eq!(file[4], VERSION);
        let (back, ..) = decrypt_archive(&file, "pw").unwrap();
        let extras: Vec<_> = back.channels["k"]
            .iter()
            .map(|m| m.extra.as_deref())
            .collect();
        assert_eq!(extras, [None, Some(r#"{"reply_to":"m1","thread":"m1"}"#)]);
    }

    /// What every version since 1.3.1 wrote (v6) opens, its messages and how far it read
    /// whole, with no list named yet: the first seal from it reads the list and names them.
    #[test]
    fn a_v6_archive_opens_with_nothing_named() {
        #[derive(Serialize)]
        struct V6Memory {
            cursors: HashMap<String, i64>,
            readers: HashMap<String, Vec<[u8; 16]>>,
            vault_gens: HashMap<String, u64>,
        }
        #[derive(Serialize)]
        struct V6 {
            channels: HashMap<String, Vec<ChatMessage>>,
            dms: HashMap<String, Vec<ChatMessage>>,
            cleared: HashMap<String, u64>,
            devices: Vec<DeviceRecord>,
            cursors: HashMap<String, V6Memory>,
        }
        let v6 = V6 {
            channels: HashMap::new(),
            dms: HashMap::new(),
            cleared: [("k".to_string(), 3)].into(),
            devices: Vec::new(),
            cursors: [(
                "r|luki".to_string(),
                V6Memory {
                    cursors: [("d:x".to_string(), 7)].into(),
                    readers: [("c:y".to_string(), vec![[1; 16]])].into(),
                    vault_gens: [("item.pins".to_string(), 2)].into(),
                },
            )]
            .into(),
        };
        let salt = generate_salt();
        let key = derive_key("pw", &salt);
        let mut aad = [0u8; 5];
        aad[..4].copy_from_slice(MAGIC);
        aad[4] = VERSION_V6;
        let mut sealed = postcard::to_allocvec(&v6).unwrap();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0u8; NONCE_LEN]),
            Aad::from(&aad),
            &mut sealed,
        )
        .unwrap();
        let mut file = MAGIC.to_vec();
        file.push(VERSION_V6);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&[0u8; NONCE_LEN]);
        file.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        file.extend_from_slice(&sealed);
        assert_eq!(kind_of(&file), FileKind::Ours(VERSION_V6));
        let (archive, _, _, version) = decrypt_archive(&file, "pw").unwrap();
        assert_eq!(version, VERSION_V6);
        assert_eq!(archive.cleared["k"], 3);
        let memory = &archive.cursors["r|luki"];
        assert_eq!(memory.cursors["d:x"], 7);
        assert_eq!(memory.readers["c:y"], vec![[1; 16]]);
        assert_eq!(memory.vault_gens["item.pins"], 2);
        assert!(memory.named.is_empty());
    }

    /// What 0.12 wrote (v4) opens, with no vault generations yet; a newer
    /// file is told apart from a damaged one and never opened as this one.
    #[test]
    fn a_v4_archive_opens_and_a_newer_one_is_refused() {
        #[derive(Serialize)]
        struct V4Memory {
            cursors: HashMap<String, i64>,
            readers: HashMap<String, Vec<[u8; 16]>>,
        }
        /// A message as v4 and v5 wrote it: no `extra`
        #[derive(Serialize)]
        struct V4Message {
            user_id: u32,
            username: String,
            content: String,
            timestamp: u64,
            kind: Option<String>,
            id: Option<String>,
            expires_at: Option<u64>,
            account: Option<String>,
        }
        #[derive(Serialize)]
        struct V4 {
            channels: HashMap<String, Vec<V4Message>>,
            dms: HashMap<String, Vec<V4Message>>,
            cleared: HashMap<String, u64>,
            devices: Vec<DeviceRecord>,
            cursors: HashMap<String, V4Memory>,
        }
        let memory = V4Memory {
            cursors: [("d:x".to_string(), 7)].into(),
            readers: HashMap::new(),
        };
        let old = V4Message {
            user_id: 1,
            username: "alice".into(),
            content: "from 0.12".into(),
            timestamp: 1_700_000_000_000,
            kind: None,
            id: None,
            expires_at: None,
            account: None,
        };
        let v4 = V4 {
            channels: HashMap::new(),
            dms: [("k".to_string(), vec![old])].into(),
            cleared: HashMap::new(),
            devices: Vec::new(),
            cursors: [("r|luki".to_string(), memory)].into(),
        };
        let seal = |version: u8, plaintext: Vec<u8>| {
            let salt = generate_salt();
            let key = derive_key("pw", &salt);
            let mut aad = [0u8; 5];
            aad[..4].copy_from_slice(MAGIC);
            aad[4] = version;
            let mut in_out = plaintext;
            key.seal_in_place_append_tag(
                Nonce::assume_unique_for_key([0u8; NONCE_LEN]),
                Aad::from(&aad),
                &mut in_out,
            )
            .unwrap();
            let mut file = MAGIC.to_vec();
            file.push(version);
            file.extend_from_slice(&salt);
            file.extend_from_slice(&[0u8; NONCE_LEN]);
            file.extend_from_slice(&(in_out.len() as u32).to_be_bytes());
            file.extend_from_slice(&in_out);
            file
        };
        let file = seal(VERSION_V4, postcard::to_allocvec(&v4).unwrap());
        assert_eq!(kind_of(&file), FileKind::Ours(VERSION_V4));
        let (archive, _, _, version) = decrypt_archive(&file, "pw").unwrap();
        assert_eq!(version, VERSION_V4);
        assert_eq!(archive.dms["k"][0].content, "from 0.12");
        assert_eq!(archive.cursors["r|luki"].cursors["d:x"], 7);
        assert!(archive.cursors["r|luki"].vault_gens.is_empty());

        // 1.11's v7 is today's layout: it opens as it is, and is told older (a copy is kept)
        let mut today = ChatArchive::default();
        today.channels.insert("h:1/general".into(), vec![]);
        let v7 = seal(VERSION_V7, postcard::to_allocvec(&today).unwrap());
        assert_eq!(kind_of(&v7), FileKind::Ours(VERSION_V7));
        let (archive, _, _, version) = decrypt_archive(&v7, "pw").unwrap();
        assert_eq!(version, VERSION_V7);
        assert!(version < ARCHIVE_VERSION);
        assert!(archive.channels.contains_key("h:1/general"));

        let newer = seal(VERSION + 1, vec![1, 2, 3]);
        assert_eq!(kind_of(&newer), FileKind::Newer);
        assert!(decrypt_archive(&newer, "pw")
            .unwrap_err()
            .to_string()
            .contains("newer VoIPC"));
        assert_eq!(
            kind_of(b"not a history file at all, but long enough to have a header ......."),
            FileKind::Unreadable
        );
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
            account: None,
            extra: None,
        };
        let mut map = HashMap::new();
        map.insert("a".to_string(), vec![msg(Some(now - 1)), msg(None)]);
        // A conversation of nothing but expired messages goes with them.
        map.insert("b".to_string(), vec![msg(Some(now - 60_000))]);
        map.insert("c".to_string(), vec![msg(Some(now + 60_000))]);

        assert_eq!(drop_expired(&mut map, now), 2);
        assert_eq!(map["a"].len(), 1, "the one with no timer stays");
        assert!(
            !map.contains_key("b"),
            "an emptied conversation is dropped too"
        );
        assert_eq!(map["c"].len(), 1, "one still in its life stays");
    }
}
