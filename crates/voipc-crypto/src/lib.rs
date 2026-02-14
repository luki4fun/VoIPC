//! VoIPC cryptographic layer — Signal Protocol integration and media encryption.
//!
//! This crate provides:
//! - Identity key management (Curve25519 via libsignal)
//! - Pre-key bundle generation and processing
//! - Pairwise session establishment (X3DH + Double Ratchet)
//! - Group encryption via Sender Keys
//! - Symmetric AES-256-GCM encryption for voice/video media
//! - Encrypted persistence of Signal Protocol state

pub mod group;
pub mod identity;
pub mod media_keys;
pub mod persistence;
pub mod prekey;
pub mod session;
pub mod stores;

// Re-export key types for convenience
pub use identity::{generate_identity_key_pair, SerializableIdentityKeyPair};
pub use media_keys::{MediaKey, build_aad, media_decrypt, media_encrypt, MAX_SEQUENCE_BEFORE_ROTATION};
pub use prekey::PreKeySet;
pub use stores::SignalStores;
