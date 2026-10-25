//! Pairwise session establishment and message encryption/decryption.
//!
//! Uses X3DH key agreement to establish sessions, then the Double Ratchet
//! algorithm for ongoing message encryption with forward secrecy.

use anyhow::Context;
use libsignal_protocol::{
    kem, message_decrypt, message_decrypt_prekey, message_encrypt, process_prekey_bundle,
    CiphertextMessageType, DeviceId, IdentityKey, PreKeyBundle, PreKeyId, ProtocolAddress,
    PublicKey, SignedPreKeyId,
};
use voipc_protocol::types::PreKeyBundleData;

use crate::stores::SignalStores;

/// Build a ProtocolAddress for a VoIPC user.
/// We use "user_<id>" as the name and device_id = 1 (single device).
pub fn user_address(user_id: u32) -> ProtocolAddress {
    ProtocolAddress::new(
        format!("user_{}", user_id),
        DeviceId::new(1).expect("1 is a device id"),
    )
}

/// The user id back from a `user_address` name.
pub fn user_of(address_name: &str) -> Option<u32> {
    address_name.strip_prefix("user_")?.parse().ok()
}

/// Our own address: libsignal binds it into every message, so it must be the
/// id the relay gave us on this connection.
fn own_address(stores: &SignalStores) -> anyhow::Result<ProtocolAddress> {
    anyhow::ensure!(stores.own_user_id != 0, "our user id is not known yet");
    Ok(user_address(stores.own_user_id))
}

/// Start a session from a peer's pre-key bundle (PQXDH), using its first
/// one-time key if the relay handed one out.
pub async fn establish_session(
    stores: &mut SignalStores,
    remote_user_id: u32,
    b: &PreKeyBundleData,
) -> anyhow::Result<()> {
    let address = user_address(remote_user_id);
    let local = own_address(stores)?;
    let one_time = match b.prekeys.first() {
        Some(k) => Some((PreKeyId::from(k.id), PublicKey::deserialize(&k.public_key)?)),
        None => None,
    };
    // The relay picks the device id; one it made up is an error, not a panic
    let device_id = u8::try_from(b.device_id)
        .ok()
        .and_then(|d| DeviceId::new(d).ok())
        .context("invalid device id in bundle")?;
    let bundle = PreKeyBundle::new(
        b.registration_id,
        device_id,
        one_time,
        SignedPreKeyId::from(b.signed_prekey_id),
        PublicKey::deserialize(&b.signed_prekey)?,
        b.signed_prekey_signature.clone(),
        b.kyber_prekey_id.into(),
        kem::PublicKey::deserialize(&b.kyber_prekey)?,
        b.kyber_prekey_signature.clone(),
        IdentityKey::decode(&b.identity_key)?,
    )?;
    process_prekey_bundle(
        &address,
        &local,
        &mut stores.session,
        &mut stores.identity,
        &bundle,
        crate::time::now(),
        &mut crate::rng(),
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
    let local = own_address(stores)?;

    let ciphertext = message_encrypt(
        plaintext,
        &address,
        &local,
        &mut stores.session,
        &mut stores.identity,
        crate::time::now(),
        &mut crate::rng(),
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
    let local = own_address(stores)?;

    let plaintext = match message_type {
        1 => {
            // PreKey message (first message in a session)
            let msg = libsignal_protocol::PreKeySignalMessage::try_from(ciphertext)?;
            message_decrypt_prekey(
                &msg,
                &address,
                &local,
                &mut stores.session,
                &mut stores.identity,
                &mut stores.prekey,
                &stores.signed_prekey,
                &mut stores.kyber,
                &mut crate::rng(),
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
                &local,
                &mut stores.session,
                &mut stores.identity,
                &mut stores.prekey,
                &stores.signed_prekey,
                &mut stores.kyber,
                &mut crate::rng(),
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
        match Box::pin(fut)
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("in-memory stores never pend"),
        }
    }

    /// A session start that used no one-time key (the relay ran out) rests on
    /// the Kyber last-resort key: replaying its first message must not open a
    /// second session, even after the first one is gone.
    #[test]
    fn a_replayed_session_start_on_the_last_resort_key_is_refused() {
        let (alice, bob) = (1u32, 2u32);
        let (alice_key, bob_key) = (
            crate::generate_identity_key_pair(),
            crate::generate_identity_key_pair(),
        );
        let mut a = SignalStores::new(&alice_key, 1001);
        let mut b = SignalStores::new(&bob_key, 1002);
        (a.own_user_id, b.own_user_id) = (alice, bob);
        crate::prekey::generate_prekeys(&mut b, &bob_key).unwrap();
        let mut bundle = crate::prekey::bundle(&b).unwrap();
        bundle.prekeys.clear();
        ready(establish_session(&mut a, bob, &bundle)).unwrap();

        let (ct, kind) = ready(encrypt_message(&mut a, bob, b"hi")).unwrap();
        assert_eq!(kind, 1, "a PreKey message");
        assert_eq!(
            ready(decrypt_message(&mut b, alice, &ct, kind)).unwrap(),
            b"hi"
        );
        b.session.sessions.clear();
        let err = ready(decrypt_message(&mut b, alice, &ct, kind))
            .unwrap_err()
            .to_string();
        assert!(err.contains("reused base key"), "{err}");
    }

    /// A session the peer opens (their PreKey message) stores their identity
    /// without a bundle of theirs ever passing the pin check: the stores tell
    /// the host (`take_seen`), which checks it like a fetched bundle.
    #[test]
    fn a_session_the_peer_opens_is_handed_to_the_pin_check() {
        let (alice, bob) = (1u32, 2u32);
        let (alice_key, bob_key) = (
            crate::generate_identity_key_pair(),
            crate::generate_identity_key_pair(),
        );
        let mut a = SignalStores::new(&alice_key, 1001);
        let mut b = SignalStores::new(&bob_key, 1002);
        (a.own_user_id, b.own_user_id) = (alice, bob);
        crate::prekey::generate_prekeys(&mut b, &bob_key).unwrap();
        let bundle = crate::prekey::bundle(&b).unwrap();
        ready(establish_session(&mut a, bob, &bundle)).unwrap();
        let seen = a.identity.take_seen();
        assert_eq!(
            seen,
            vec![(bob, bob_key.public_key().serialize().to_vec())],
            "the bundle's identity, for the outgoing check"
        );
        assert!(a.identity.take_seen().is_empty(), "handed over once");

        let (ct, kind) = ready(encrypt_message(&mut a, bob, b"hi")).unwrap();
        assert!(b.identity.take_seen().is_empty());
        assert_eq!(
            ready(decrypt_message(&mut b, alice, &ct, kind)).unwrap(),
            b"hi"
        );
        assert_eq!(
            b.identity.take_seen(),
            vec![(alice, alice_key.public_key().serialize().to_vec())],
            "the session alice opened"
        );
        assert_eq!(
            b.identity.identity_of(alice),
            Some(&alice_key.public_key().serialize()[..]),
            "the key that session runs on"
        );
    }
}
