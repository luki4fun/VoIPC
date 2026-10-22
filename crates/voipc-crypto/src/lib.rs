//! VoIPC cryptographic layer — Signal Protocol integration and media encryption.
//!
//! This crate provides:
//! - Identity key management (Curve25519 via libsignal)
//! - Pre-key bundle generation and processing
//! - Pairwise session establishment (X3DH + Double Ratchet)
//! - Group encryption via Sender Keys
//! - Symmetric AES-256-GCM encryption for voice/video media
//!
//! Signal state is deliberately not persisted: a guest's identity is new on
//! every connect (nothing to fingerprint or link across sessions). An
//! account's identity lives in its vault (`account`), and peers pin it.

pub mod account;
pub mod account_session;
mod aead;
pub mod channel_state;
pub mod envelope;
pub mod group;
pub mod identity;
pub mod log;
pub mod sync;
pub mod media_keys;
pub mod prekey;
pub mod session;
pub mod stores;
pub mod time;

// Re-export key types for convenience
pub use channel_state::{history_sources, pick_history_sources, ChannelKeying, HISTORY_SOURCES};
pub use envelope::{
    envelope, history_payload, new_message_id, open_envelope, open_history_payload, Message,
    MAX_MESSAGE_TTL_SECS,
};
pub use identity::{generate_identity_key_pair, SerializableIdentityKeyPair};
pub use media_keys::{MediaKey, MediaKeyRing, build_aad, media_decrypt, media_encrypt, MAX_SEQUENCE_BEFORE_ROTATION};
pub use prekey::PreKeySet;
pub use stores::SignalStores;
