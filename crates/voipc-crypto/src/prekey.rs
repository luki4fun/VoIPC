//! Pre-keys: what a peer needs to start a session with us without us being
//! there (PQXDH). One signed Curve25519 key, one signed Kyber1024 last-resort
//! key, and one-time Curve25519 keys the relay hands out one per session.
//! All of them are new on every connect, like the stores that hold them.
//!
//! A reader opens the session in a text channel, and past the one-time pool a
//! hello rests on the signed and the last-resort key alone. Those are in the
//! writer's memory, and so would be everything a thief with the relay's
//! recordings needs to open each wrap back to the connection's start. So they are
//! renewed after each key job, and the old ones go a minute later.

use anyhow::Context;
use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyRecord, PreKeyId, PreKeyRecord,
    SignedPreKeyRecord, Timestamp,
};
use serde::{Deserialize, Serialize};
use voipc_protocol::messages::ClientMessage;
use voipc_protocol::types::{OneTimePreKey, PreKeyBundleData};

use crate::stores::SignalStores;

/// One-time pre-keys at connect.
pub const INITIAL_PREKEY_COUNT: u32 = 100;
/// One-time pre-keys sent when the relay says it runs low (`PreKeysLow`).
pub const PREKEY_REFILL_COUNT: u32 = 50;

/// How long a renewed signed and last-resort key stay: a hello already on its way
/// rests on them, and a round lives this long too.
pub const OLD_KEYS_KEPT_MS: u64 = 60_000;

/// Session keys renewed at `at`, which go `OLD_KEYS_KEPT_MS` later.
#[derive(Serialize, Deserialize)]
pub struct RetiringKeys {
    signed: u32,
    kyber: u32,
    at: u64,
}

/// A new signed pre-key and Kyber last-resort key under these ids, which a bundle
/// offers from now on.
fn new_session_keys(
    stores: &mut SignalStores,
    identity: &IdentityKeyPair,
    signed_id: u32,
    kyber_id: u32,
) -> anyhow::Result<()> {
    let now = Timestamp::from_epoch_millis(crate::time::now_millis());
    let signed = KeyPair::generate(&mut crate::rng());
    let signature = identity
        .private_key()
        .calculate_signature(&signed.public_key.serialize(), &mut crate::rng())?;
    let record = SignedPreKeyRecord::new(signed_id.into(), now, &signed, &signature);
    stores
        .signed_prekey
        .signed_prekeys
        .insert(signed_id, record.serialize()?);
    stores.signed_prekey.current = signed_id;

    // Built by hand rather than `KyberPreKeyRecord::generate`, which reads
    // SystemTime: that panics on wasm32
    let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut crate::rng());
    let signature = identity
        .private_key()
        .calculate_signature(&kyber.public_key.serialize(), &mut crate::rng())?;
    let record = KyberPreKeyRecord::new(kyber_id.into(), now, &kyber, &signature);
    stores.kyber.keys.insert(kyber_id, record.serialize()?);
    stores.kyber.current = kyber_id;
    Ok(())
}

/// The signed pre-key, the Kyber last-resort key and `INITIAL_PREKEY_COUNT`
/// one-time keys, into fresh stores.
pub fn generate_prekeys(
    stores: &mut SignalStores,
    identity: &IdentityKeyPair,
) -> anyhow::Result<()> {
    new_session_keys(stores, identity, 1, 1)?;
    more_prekeys(stores, INITIAL_PREKEY_COUNT)?;
    Ok(())
}

/// A new signed pre-key and Kyber last-resort key, and the frame that tells the relay.
/// The old ones answer a hello for `OLD_KEYS_KEPT_MS` more (`retire_session_keys`).
pub fn renew_session_keys(stores: &mut SignalStores, now: u64) -> anyhow::Result<ClientMessage> {
    let identity = stores
        .identity
        .key_pair
        .to_identity_key_pair()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let (old_signed, old_kyber) = (stores.signed_prekey.current, stores.kyber.current);
    let signed_id = old_signed
        .checked_add(1)
        .context("signed pre-key ids exhausted")?;
    let kyber_id = old_kyber
        .checked_add(1)
        .context("Kyber pre-key ids exhausted")?;
    new_session_keys(stores, &identity, signed_id, kyber_id)?;
    stores.retiring.push(RetiringKeys {
        signed: old_signed,
        kyber: old_kyber,
        at: now,
    });
    let bundle = bundle(stores)?;
    Ok(ClientMessage::RenewSessionKeys {
        signed_prekey_id: bundle.signed_prekey_id,
        signed_prekey: bundle.signed_prekey,
        signed_prekey_signature: bundle.signed_prekey_signature,
        kyber_prekey_id: bundle.kyber_prekey_id,
        kyber_prekey: bundle.kyber_prekey,
        kyber_prekey_signature: bundle.kyber_prekey_signature,
    })
}

/// Deletes the renewed keys whose minute is up, and what was noted of their use.
pub fn retire_session_keys(stores: &mut SignalStores, now: u64) {
    let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut stores.retiring)
        .into_iter()
        .partition(|old| now.saturating_sub(old.at) >= OLD_KEYS_KEPT_MS);
    stores.retiring = kept;
    for old in gone {
        stores.signed_prekey.signed_prekeys.remove(&old.signed);
        stores.kyber.keys.remove(&old.kyber);
        stores
            .kyber
            .used
            .retain(|(kyber, _, _)| *kyber != old.kyber);
    }
}

/// `count` new one-time keys, stored, and their public halves for the relay.
/// Ids only ever grow, so a key the relay still holds never names a new one.
pub fn more_prekeys(stores: &mut SignalStores, count: u32) -> anyhow::Result<Vec<OneTimePreKey>> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        stores.prekey.next_id = stores.prekey.next_id.max(1);
        let id = stores.prekey.next_id;
        stores.prekey.next_id = id.checked_add(1).context("pre-key ids exhausted")?;
        let pair = KeyPair::generate(&mut crate::rng());
        stores.prekey.prekeys.insert(
            id,
            PreKeyRecord::new(PreKeyId::from(id), &pair).serialize()?,
        );
        out.push(OneTimePreKey {
            id,
            public_key: pair.public_key.serialize().to_vec(),
        });
    }
    Ok(out)
}

/// What `Authenticate` (and an account's `Keys` step) carries, read back from
/// the stores so one-time keys an earlier session used are not offered again.
pub fn bundle(stores: &SignalStores) -> anyhow::Result<PreKeyBundleData> {
    let signed = stores
        .signed_prekey
        .signed_prekeys
        .get(&stores.signed_prekey.current)
        .context("signed pre-key missing")?;
    let signed = SignedPreKeyRecord::deserialize(signed)?;
    let kyber = stores
        .kyber
        .keys
        .get(&stores.kyber.current)
        .context("Kyber pre-key missing")?;
    let kyber = KyberPreKeyRecord::deserialize(kyber)?;
    let prekeys = stores
        .prekey
        .prekeys
        .iter()
        .map(|(&id, bytes)| {
            Ok(OneTimePreKey {
                id,
                public_key: PreKeyRecord::deserialize(bytes)?
                    .public_key()?
                    .serialize()
                    .to_vec(),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(PreKeyBundleData {
        registration_id: stores.identity.registration_id,
        device_id: 1,
        identity_key: stores.identity.key_pair.public_key.clone(),
        signed_prekey_id: stores.signed_prekey.current,
        signed_prekey: signed.public_key()?.serialize().to_vec(),
        signed_prekey_signature: signed.signature()?,
        prekeys,
        kyber_prekey_id: stores.kyber.current,
        kyber_prekey: kyber.public_key()?.serialize().to_vec(),
        kyber_prekey_signature: kyber.signature()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{decrypt_message, encrypt_message, establish_session};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    fn ready<T>(fut: impl Future<Output = T>) -> T {
        match Box::pin(fut)
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("in-memory stores never pend"),
        }
    }

    fn device(id: u32) -> (SignalStores, IdentityKeyPair) {
        let identity = crate::generate_identity_key_pair();
        let mut stores = SignalStores::new(&identity, 1000 + id);
        generate_prekeys(&mut stores, &identity).unwrap();
        stores.own_user_id = id;
        (stores, identity)
    }

    /// What a thief of the writer's memory holds, with nothing of the sessions it has
    /// since: its identity and the pre-keys still there, and no replay marks to get in
    /// the way. A hello recorded on the wire then opens exactly if its keys are still here.
    fn thief_of(w: &SignalStores, identity: &IdentityKeyPair) -> SignalStores {
        let mut t = SignalStores::new(identity, w.identity.registration_id);
        t.own_user_id = w.own_user_id;
        t.signed_prekey.signed_prekeys = w.signed_prekey.signed_prekeys.clone();
        t.signed_prekey.current = w.signed_prekey.current;
        t.kyber.keys = w.kyber.keys.clone();
        t.kyber.current = w.kyber.current;
        t
    }

    /// The attack this renewal answers. Past the one-time pool a reader's hello rests on
    /// the signed and the last-resort key alone, so while those stay in the writer's
    /// memory a thief with the relay's recordings re-derives each session and opens each
    /// wrap. Once they have gone, the same recording opens nothing.
    #[test]
    fn a_stolen_writer_opens_no_wrap_from_before_the_last_key_change() {
        let (mut writer, writer_key) = device(1);
        let (mut reader, _) = device(2);
        let mut bundle = bundle(&writer).unwrap();
        bundle.prekeys.clear();
        ready(establish_session(&mut reader, 1, &bundle)).unwrap();
        let (hello, kind) = ready(encrypt_message(&mut reader, 1, b"hello")).unwrap();
        assert_eq!(kind, 1);
        ready(decrypt_message(&mut writer, 2, &hello, kind)).unwrap();

        // Before the change the recording still opens: the control
        let mut before = thief_of(&writer, &writer_key);
        assert!(ready(decrypt_message(&mut before, 2, &hello, kind)).is_ok());

        renew_session_keys(&mut writer, 1_000).unwrap();
        let mut in_the_minute = thief_of(&writer, &writer_key);
        assert!(
            ready(decrypt_message(&mut in_the_minute, 2, &hello, kind)).is_ok(),
            "the old keys stay for a hello on its way"
        );
        retire_session_keys(&mut writer, 1_000 + OLD_KEYS_KEPT_MS);
        let mut after = thief_of(&writer, &writer_key);
        assert!(ready(decrypt_message(&mut after, 2, &hello, kind)).is_err());
    }

    #[test]
    fn a_renewed_bundle_offers_the_new_keys_and_a_hello_on_them_opens() {
        let (mut writer, _) = device(1);
        let (mut reader, _) = device(2);
        let old = bundle(&writer).unwrap();
        let frame = renew_session_keys(&mut writer, 0).unwrap();
        let new = bundle(&writer).unwrap();
        assert_ne!(new.signed_prekey_id, old.signed_prekey_id);
        assert_ne!(new.signed_prekey, old.signed_prekey);
        assert_ne!(new.kyber_prekey_id, old.kyber_prekey_id);
        assert_ne!(new.kyber_prekey, old.kyber_prekey);
        let ClientMessage::RenewSessionKeys {
            signed_prekey_id,
            kyber_prekey,
            ..
        } = frame
        else {
            panic!("not the frame that tells the relay");
        };
        assert_eq!(signed_prekey_id, new.signed_prekey_id);
        assert_eq!(kyber_prekey, new.kyber_prekey);

        ready(establish_session(&mut reader, 1, &new)).unwrap();
        let (hello, kind) = ready(encrypt_message(&mut reader, 1, b"hello")).unwrap();
        assert_eq!(
            ready(decrypt_message(&mut writer, 2, &hello, kind)).unwrap(),
            b"hello"
        );
    }

    /// A bundle handed out just before the renewal still works for the minute.
    #[test]
    fn a_hello_on_the_old_keys_opens_until_they_go() {
        let (mut writer, _) = device(1);
        let (mut reader, _) = device(2);
        let old = bundle(&writer).unwrap();
        renew_session_keys(&mut writer, 0).unwrap();
        ready(establish_session(&mut reader, 1, &old)).unwrap();
        let (hello, kind) = ready(encrypt_message(&mut reader, 1, b"hello")).unwrap();
        retire_session_keys(&mut writer, OLD_KEYS_KEPT_MS - 1);
        assert_eq!(
            ready(decrypt_message(&mut writer, 2, &hello, kind)).unwrap(),
            b"hello"
        );
        assert!(!writer.kyber.used.is_empty());
        retire_session_keys(&mut writer, OLD_KEYS_KEPT_MS);
        assert!(writer.kyber.used.is_empty(), "the marks go with the key");
        assert!(writer.retiring.is_empty());
    }
}
