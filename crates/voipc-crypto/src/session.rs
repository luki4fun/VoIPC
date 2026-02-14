//! Pairwise session establishment and message encryption/decryption.
//!
//! Uses X3DH key agreement to establish sessions, then the Double Ratchet
//! algorithm for ongoing message encryption with forward secrecy.

use std::time::SystemTime;

use libsignal_protocol::{
    message_decrypt, message_decrypt_prekey, message_encrypt, process_prekey_bundle,
    CiphertextMessageType, IdentityKey, PreKeyBundle, PreKeyId, ProtocolAddress, PublicKey,
    SessionStore, SignedPreKeyId,
};
use rand::rngs::OsRng;

use crate::stores::SignalStores;

/// Build a ProtocolAddress for a VoIPC user.
/// We use "user_<id>" as the name and device_id = 1 (single device).
pub fn user_address(user_id: u32) -> ProtocolAddress {
    ProtocolAddress::new(format!("user_{}", user_id), 1.into())
}

/// Process a remote user's pre-key bundle to establish a session.
pub async fn establish_session(
    stores: &mut SignalStores,
    remote_user_id: u32,
    registration_id: u32,
    device_id: u32,
    identity_key_bytes: &[u8],
    signed_prekey_id: u32,
    signed_prekey_bytes: &[u8],
    signed_prekey_signature: &[u8],
    one_time_prekey_id: Option<u32>,
    one_time_prekey_bytes: Option<&[u8]>,
) -> anyhow::Result<()> {
    let address = user_address(remote_user_id);
    let identity_key = IdentityKey::decode(identity_key_bytes)?;
    let signed_prekey = PublicKey::deserialize(signed_prekey_bytes)?;

    let prekey = match (one_time_prekey_id, one_time_prekey_bytes) {
        (Some(id), Some(bytes)) => Some((PreKeyId::from(id), PublicKey::deserialize(bytes)?)),
        _ => None,
    };

    let bundle = PreKeyBundle::new(
        registration_id,
        device_id.into(),
        prekey,
        SignedPreKeyId::from(signed_prekey_id),
        signed_prekey,
        signed_prekey_signature.to_vec(),
        identity_key,
    )?;

    process_prekey_bundle(
        &address,
        &mut stores.session,
        &mut stores.identity,
        &bundle,
        SystemTime::now(),
        &mut OsRng,
    )
    .await?;

    Ok(())
}

/// Encrypt a plaintext message for a specific user using their established session.
/// Returns (ciphertext, message_type) where message_type indicates PreKey vs normal.
pub async fn encrypt_message(
    stores: &mut SignalStores,
    remote_user_id: u32,
    plaintext: &[u8],
) -> anyhow::Result<(Vec<u8>, u8)> {
    let address = user_address(remote_user_id);

    let ciphertext = message_encrypt(
        plaintext,
        &address,
        &mut stores.session,
        &mut stores.identity,
        SystemTime::now(),
    )
    .await?;

    let msg_type = match ciphertext.message_type() {
        CiphertextMessageType::PreKey => 1u8,
        CiphertextMessageType::Whisper => 2u8,
        _ => 0u8,
    };

    Ok((ciphertext.serialize().to_vec(), msg_type))
}

/// Decrypt a message from a specific user.
pub async fn decrypt_message(
    stores: &mut SignalStores,
    remote_user_id: u32,
    ciphertext: &[u8],
    message_type: u8,
) -> anyhow::Result<Vec<u8>> {
    let address = user_address(remote_user_id);

    let plaintext = match message_type {
        1 => {
            // PreKey message (first message in a session)
            let msg = libsignal_protocol::PreKeySignalMessage::try_from(ciphertext)?;
            message_decrypt_prekey(
                &msg,
                &address,
                &mut stores.session,
                &mut stores.identity,
                &mut stores.prekey,
                &mut stores.signed_prekey,
                &mut stores.kyber,
                &mut OsRng,
            )
            .await?
        }
        2 => {
            // Normal Signal message (established session)
            let msg = libsignal_protocol::SignalMessage::try_from(ciphertext)?;
            let ciphertext_msg = libsignal_protocol::CiphertextMessage::SignalMessage(msg);
            message_decrypt(
                &ciphertext_msg,
                &address,
                &mut stores.session,
                &mut stores.identity,
                &mut stores.prekey,
                &mut stores.signed_prekey,
                &mut stores.kyber,
                &mut OsRng,
            )
            .await?
        }
        _ => anyhow::bail!("unknown message type: {}", message_type),
    };

    Ok(plaintext)
}

/// Check if we have an established session with a user.
pub async fn has_session(stores: &SignalStores, remote_user_id: u32) -> bool {
    let address = user_address(remote_user_id);
    let result: Result<Option<libsignal_protocol::SessionRecord>, _> = SessionStore::load_session(
        &stores.session,
        &address,
    )
    .await;
    result.ok().flatten().is_some()
}

