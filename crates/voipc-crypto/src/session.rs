//! Pairwise session establishment and message encryption/decryption.
//!
//! Uses X3DH key agreement to establish sessions, then the Double Ratchet
//! algorithm for ongoing message encryption with forward secrecy.

use libsignal_protocol::{
    message_decrypt, message_decrypt_prekey, message_encrypt, process_prekey_bundle,
    CiphertextMessageType, IdentityKey, PreKeyBundle, PreKeyId, ProtocolAddress, PublicKey,
    SignedPreKeyId,
};
use rand::rngs::OsRng;

use crate::stores::SignalStores;

/// Build a ProtocolAddress for a VoIPC user.
/// We use "user_<id>" as the name and device_id = 1 (single device).
pub fn user_address(user_id: u32) -> ProtocolAddress {
    ProtocolAddress::new(format!("user_{}", user_id), 1.into())
}

/// The user id back from a `user_address` name.
pub fn user_of(address_name: &str) -> Option<u32> {
    address_name.strip_prefix("user_")?.parse().ok()
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
        crate::time::now(),
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
        crate::time::now(),
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
                &stores.signed_prekey,
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
                &stores.signed_prekey,
                &mut stores.kyber,
                &mut OsRng,
            )
            .await?
        }
        _ => anyhow::bail!("unknown message type: {}", message_type),
    };

    Ok(plaintext)
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    /// In-memory stores are ready on the first poll (as in group.rs).
    fn ready<T>(fut: impl Future<Output = T>) -> T {
        match Box::pin(fut).as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("in-memory stores never pend"),
        }
    }

    /// A session the peer opens (their PreKey message) stores their identity
    /// without a bundle of theirs ever passing the pin check: the stores tell
    /// the host (`take_seen`), which checks it like a fetched bundle.
    #[test]
    fn a_session_the_peer_opens_is_handed_to_the_pin_check() {
        let (alice, bob) = (1u32, 2u32);
        let (alice_key, bob_key) = (crate::generate_identity_key_pair(), crate::generate_identity_key_pair());
        let mut a = SignalStores::new(&alice_key, 1001);
        let mut b = SignalStores::new(&bob_key, 1002);
        let set = ready(crate::prekey::generate_prekeys(&mut b, &bob_key, 1, 1)).unwrap();
        let otk = &set.one_time_prekeys[0];
        ready(establish_session(
            &mut a,
            bob,
            set.registration_id,
            set.device_id,
            &bob_key.public_key().serialize(),
            set.signed_prekey_id,
            &set.signed_prekey_public,
            &set.signed_prekey_signature,
            Some(otk.id),
            Some(&otk.public_key),
        ))
        .unwrap();
        let seen = a.identity.take_seen();
        assert_eq!(seen, vec![(bob, bob_key.public_key().serialize().to_vec())], "the bundle's identity, for the outgoing check");
        assert!(a.identity.take_seen().is_empty(), "handed over once");

        let (ct, kind) = ready(encrypt_message(&mut a, bob, b"hi")).unwrap();
        assert!(b.identity.take_seen().is_empty());
        assert_eq!(ready(decrypt_message(&mut b, alice, &ct, kind)).unwrap(), b"hi");
        assert_eq!(b.identity.take_seen(), vec![(alice, alice_key.public_key().serialize().to_vec())], "the session alice opened");
        assert_eq!(b.identity.identity_of(alice), Some(&alice_key.public_key().serialize()[..]), "the key that session runs on");
    }
}
