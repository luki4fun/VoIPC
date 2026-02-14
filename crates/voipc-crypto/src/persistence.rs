//! Encrypted persistence for Signal Protocol state.
//!
//! Reuses the same PBKDF2 + AES-256-GCM pattern as chat history encryption
//! (see client/src-tauri/src/crypto.rs) to protect identity keys,
//! session state, and pre-keys on disk.

use std::num::NonZeroU32;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};

use crate::stores::SignalStores;

const MAGIC: &[u8; 4] = b"VSIG"; // "VoIPC SIGnal"
const VERSION: u8 = 0x01;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + 4; // 53 bytes
const PBKDF2_ITERATIONS: u32 = 600_000;

/// Derive a 256-bit AES-GCM key from password and salt.
fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> LessSafeKey {
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

/// Encrypt Signal stores to a binary blob for disk storage.
///
/// File format: [VSIG magic(4)] [version(1)] [salt(32)] [nonce(12)] [length(4)] [encrypted payload + tag(16)]
pub fn encrypt_stores(stores: &SignalStores, password: &str) -> anyhow::Result<Vec<u8>> {
    let rng = SystemRandom::new();

    // Serialize stores
    let plaintext = postcard::to_allocvec(stores)
        .map_err(|e| anyhow::anyhow!("serialization failed: {e}"))?;

    // Generate salt and nonce
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("RNG failed"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("RNG failed"))?;

    // Derive key and encrypt
    let key = derive_key(password, &salt);
    let mut in_out = plaintext;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut aad_bytes = [0u8; 5];
    aad_bytes[..4].copy_from_slice(MAGIC);
    aad_bytes[4] = VERSION;

    key.seal_in_place_append_tag(nonce, Aad::from(&aad_bytes), &mut in_out)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    // Build file
    let payload_len = in_out.len() as u32;
    let mut file_data = Vec::with_capacity(HEADER_LEN + in_out.len());
    file_data.extend_from_slice(MAGIC);
    file_data.push(VERSION);
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&payload_len.to_be_bytes());
    file_data.extend_from_slice(&in_out);

    Ok(file_data)
}

/// Decrypt Signal stores from a binary blob.
pub fn decrypt_stores(file_data: &[u8], password: &str) -> anyhow::Result<SignalStores> {
    if file_data.len() < HEADER_LEN {
        anyhow::bail!("file too short");
    }

    if &file_data[0..4] != MAGIC {
        anyhow::bail!("invalid file format (expected VSIG header)");
    }
    if file_data[4] != VERSION {
        anyhow::bail!("unsupported file version");
    }

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

    let key = derive_key(password, &salt);

    let mut ciphertext = file_data[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut aad_bytes = [0u8; 5];
    aad_bytes[..4].copy_from_slice(MAGIC);
    aad_bytes[4] = VERSION;

    let plaintext = key
        .open_in_place(nonce, Aad::from(&aad_bytes), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("incorrect password or corrupted file"))?;

    let stores: SignalStores = postcard::from_bytes(plaintext)
        .map_err(|e| anyhow::anyhow!("deserialization failed: {e}"))?;

    Ok(stores)
}

/// Check if file data starts with a valid VSIG header.
pub fn has_valid_header(file_data: &[u8]) -> bool {
    file_data.len() >= HEADER_LEN && &file_data[0..4] == MAGIC && file_data[4] == VERSION
}
