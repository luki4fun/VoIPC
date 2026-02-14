//! Identity key generation and serialization.
//!
//! Each VoIPC client has a long-term Curve25519 identity key pair
//! generated on first launch and persisted across sessions.

use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A serializable wrapper around libsignal's IdentityKeyPair.
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableIdentityKeyPair {
    /// 32-byte Curve25519 public key.
    pub public_key: Vec<u8>,
    /// 32-byte Curve25519 private key.
    pub private_key: Vec<u8>,
}

impl SerializableIdentityKeyPair {
    /// Convert to libsignal's IdentityKeyPair.
    pub fn to_identity_key_pair(&self) -> anyhow::Result<IdentityKeyPair> {
        // Reconstruct from the stored bytes
        let key_pair = KeyPair::from_public_and_private(&self.public_key, &self.private_key)?;
        Ok(IdentityKeyPair::new(
            IdentityKey::new(key_pair.public_key),
            key_pair.private_key,
        ))
    }

    /// Create from a libsignal IdentityKeyPair.
    pub fn from_identity_key_pair(pair: &IdentityKeyPair) -> Self {
        Self {
            public_key: pair.public_key().serialize().to_vec(),
            private_key: pair.private_key().serialize().to_vec(),
        }
    }
}

/// Generate a fresh identity key pair.
pub fn generate_identity_key_pair() -> IdentityKeyPair {
    IdentityKeyPair::generate(&mut OsRng)
}

/// Serialize an IdentityKey's public key to bytes (for protocol messages).
pub fn identity_key_to_bytes(key: &IdentityKey) -> Vec<u8> {
    key.serialize().to_vec()
}

/// Deserialize an IdentityKey from bytes (from protocol messages).
pub fn identity_key_from_bytes(bytes: &[u8]) -> anyhow::Result<IdentityKey> {
    Ok(IdentityKey::decode(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_roundtrip() {
        let pair = generate_identity_key_pair();
        let serializable = SerializableIdentityKeyPair::from_identity_key_pair(&pair);
        let restored = serializable.to_identity_key_pair().unwrap();
        assert_eq!(
            pair.public_key().serialize(),
            restored.public_key().serialize()
        );
    }

    #[test]
    fn public_key_serialization() {
        let pair = generate_identity_key_pair();
        let bytes = identity_key_to_bytes(pair.identity_key());
        let restored = identity_key_from_bytes(&bytes).unwrap();
        assert_eq!(pair.public_key().serialize(), restored.serialize());
    }
}
