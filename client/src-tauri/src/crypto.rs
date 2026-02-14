use std::collections::HashMap;
use std::num::NonZeroU32;

use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM, Nonce, Aad};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"VOIP";
const VERSION: u8 = 0x01;
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
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct ChatArchive {
    pub channels: HashMap<String, Vec<ChatMessage>>,
    pub dms: HashMap<String, Vec<ChatMessage>>,
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
    if file_data[4] != VERSION {
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

    if file_data.len() < HEADER_LEN + payload_len {
        anyhow::bail!("file truncated");
    }

    // Derive key
    let key = derive_key(password, &salt);

    // Decrypt (ring verifies the tag and strips it)
    let mut ciphertext = file_data[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut aad_bytes = [0u8; 5];
    aad_bytes[..4].copy_from_slice(MAGIC);
    aad_bytes[4] = VERSION;

    let plaintext = key
        .open_in_place(nonce, Aad::from(&aad_bytes), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("incorrect password or corrupted file"))?;

    // Deserialize
    let archive: ChatArchive = postcard::from_bytes(plaintext)
        .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;

    Ok((archive, salt, key))
}

/// Check if file data starts with a valid VOIP header.
pub fn has_valid_header(file_data: &[u8]) -> bool {
    file_data.len() >= HEADER_LEN && &file_data[0..4] == MAGIC && file_data[4] == VERSION
}

/// Generate a fresh random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt).expect("RNG failed");
    salt
}
