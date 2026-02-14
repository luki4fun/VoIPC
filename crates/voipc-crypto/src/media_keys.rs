//! Symmetric AES-256-GCM encryption for voice/video media packets.
//!
//! Media encryption uses per-channel symmetric keys that are
//! distributed to channel members via pairwise Signal sessions.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// AES-256-GCM authentication tag size.
pub const GCM_TAG_SIZE: usize = 16;

/// Key ID size in packet header.
pub const KEY_ID_SIZE: usize = 2;

/// Total encryption overhead per packet.
pub const ENCRYPTION_OVERHEAD: usize = KEY_ID_SIZE + GCM_TAG_SIZE;

/// A per-channel symmetric key for media encryption.
#[derive(Clone, Serialize, Deserialize)]
pub struct MediaKey {
    /// Incrementing key identifier (for key rotation transitions).
    pub key_id: u16,
    /// 256-bit AES-GCM key.
    pub key_bytes: [u8; 32],
    /// Which channel this key belongs to.
    pub channel_id: u32,
}

impl MediaKey {
    /// Generate a fresh random media key.
    pub fn generate(channel_id: u32, key_id: u16) -> anyhow::Result<Self> {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;
        Ok(Self {
            key_id,
            key_bytes,
            channel_id,
        })
    }

    /// Create an AES-256-GCM key from the raw bytes.
    fn to_aead_key(&self) -> anyhow::Result<LessSafeKey> {
        let unbound = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| anyhow::anyhow!("invalid key"))?;
        Ok(LessSafeKey::new(unbound))
    }

    /// Serialize this key for transmission (encrypted by pairwise Signal session).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 + 4);
        buf.extend_from_slice(&self.key_id.to_be_bytes());
        buf.extend_from_slice(&self.key_bytes);
        buf.extend_from_slice(&self.channel_id.to_be_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 38 {
            anyhow::bail!("media key data too short");
        }
        let key_id = u16::from_be_bytes([data[0], data[1]]);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[2..34]);
        let channel_id = u32::from_be_bytes([data[34], data[35], data[36], data[37]]);
        Ok(Self {
            key_id,
            key_bytes,
            channel_id,
        })
    }
}

/// Construct a unique 12-byte nonce from packet metadata.
/// Nonce = session_id(4) || sequence_or_frame_id(4) || fragment_info(4)
fn build_nonce(session_id: u32, sequence: u32, extra: u32) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..4].copy_from_slice(&session_id.to_be_bytes());
    nonce_bytes[4..8].copy_from_slice(&sequence.to_be_bytes());
    nonce_bytes[8..12].copy_from_slice(&extra.to_be_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}

/// Maximum sequence number before a key rotation MUST occur.
/// At ~50 packets/sec (20ms voice frames), this is ~24 hours.
/// After this, nonce uniqueness cannot be guaranteed under the same key.
pub const MAX_SEQUENCE_BEFORE_ROTATION: u32 = u32::MAX - 1000;

/// Encrypt media data (voice or video payload) with AES-256-GCM.
///
/// Returns the ciphertext with appended 16-byte authentication tag.
/// The nonce is constructed deterministically from session_id and sequence,
/// which must be unique per packet (guaranteed by monotonic sequence numbers).
///
/// `aad_context` binds channel_id and packet type to the ciphertext,
/// preventing cross-channel replay and packet type swapping.
pub fn media_encrypt(
    key: &MediaKey,
    session_id: u32,
    sequence: u32,
    extra: u32,
    aad_context: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if sequence >= MAX_SEQUENCE_BEFORE_ROTATION {
        anyhow::bail!(
            "sequence number {} exceeds rotation threshold — media key must be rotated",
            sequence
        );
    }

    let aead_key = key.to_aead_key()?;
    let nonce = build_nonce(session_id, sequence, extra);

    let mut in_out = plaintext.to_vec();
    aead_key
        .seal_in_place_append_tag(nonce, Aad::from(aad_context), &mut in_out)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    Ok(in_out)
}

/// Decrypt media data encrypted with AES-256-GCM.
///
/// Input is ciphertext with appended 16-byte authentication tag.
/// Returns the plaintext on success, or an error if authentication fails.
///
/// `aad_context` must match the value used during encryption.
pub fn media_decrypt(
    key: &MediaKey,
    session_id: u32,
    sequence: u32,
    extra: u32,
    aad_context: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < GCM_TAG_SIZE {
        anyhow::bail!("ciphertext too short for GCM tag");
    }

    let aead_key = key.to_aead_key()?;
    let nonce = build_nonce(session_id, sequence, extra);

    let mut in_out = ciphertext.to_vec();
    let plaintext = aead_key
        .open_in_place(nonce, Aad::from(aad_context), &mut in_out)
        .map_err(|_| anyhow::anyhow!("decryption failed: invalid key or tampered data"))?;

    Ok(plaintext.to_vec())
}

/// Build AAD context bytes for media encryption.
/// Binds the channel_id and packet_type to the ciphertext, preventing
/// cross-channel replay attacks and packet type confusion.
pub fn build_aad(channel_id: u32, packet_type: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5);
    aad.extend_from_slice(&channel_id.to_be_bytes());
    aad.push(packet_type);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = MediaKey::generate(1, 0).unwrap();
        let plaintext = b"hello voice data";
        let session_id = 42;
        let sequence = 100;
        let aad = build_aad(1, 0x01);

        let encrypted =
            media_encrypt(&key, session_id, sequence, 0, &aad, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(encrypted.len(), plaintext.len() + GCM_TAG_SIZE);

        let decrypted =
            media_decrypt(&key, session_id, sequence, 0, &aad, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = MediaKey::generate(1, 0).unwrap();
        let key2 = MediaKey::generate(1, 1).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let encrypted = media_encrypt(&key1, 1, 1, 0, &aad, plaintext).unwrap();
        let result = media_decrypt(&key2, 1, 1, 0, &aad, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = MediaKey::generate(1, 0).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let encrypted = media_encrypt(&key, 1, 1, 0, &aad, plaintext).unwrap();
        // Wrong sequence number
        let result = media_decrypt(&key, 1, 2, 0, &aad, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_data_fails() {
        let key = MediaKey::generate(1, 0).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let mut encrypted = media_encrypt(&key, 1, 1, 0, &aad, plaintext).unwrap();
        encrypted[0] ^= 0xFF; // flip a byte
        let result = media_decrypt(&key, 1, 1, 0, &aad, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = MediaKey::generate(1, 0).unwrap();
        let plaintext = b"secret";
        let aad1 = build_aad(1, 0x01);
        let aad2 = build_aad(2, 0x01); // different channel

        let encrypted = media_encrypt(&key, 1, 1, 0, &aad1, plaintext).unwrap();
        let result = media_decrypt(&key, 1, 1, 0, &aad2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_exceeds_rotation_threshold() {
        let key = MediaKey::generate(1, 0).unwrap();
        let plaintext = b"secret";
        let aad = build_aad(1, 0x01);

        let result = media_encrypt(&key, 1, MAX_SEQUENCE_BEFORE_ROTATION, 0, &aad, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn media_key_serialization_roundtrip() {
        let key = MediaKey::generate(42, 7).unwrap();
        let bytes = key.to_bytes();
        let restored = MediaKey::from_bytes(&bytes).unwrap();
        assert_eq!(restored.key_id, 7);
        assert_eq!(restored.channel_id, 42);
        assert_eq!(restored.key_bytes, key.key_bytes);
    }
}
