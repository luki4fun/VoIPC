//! Signal Protocol state for one browser session: an ephemeral identity,
//! pre-keys and the in-memory stores, mirroring the native client's
//! initialization and bundle extraction (client/src-tauri/src/network.rs).
//! Plain Rust so it is testable on the host; lib.rs wraps it for JS.

use std::future::Future;

use anyhow::Context;
use futures_util::FutureExt;
use libsignal_protocol::{GenericSignedPreKey, PreKeyRecord, SignedPreKeyId, SignedPreKeyStore};
use serde::Serialize;
use voipc_crypto::prekey::INITIAL_PREKEY_COUNT;
use voipc_crypto::{group, session, SignalStores};
use voipc_protocol::types::{OneTimePreKey, PreKeyBundleData};

/// Drives a libsignal future to completion. Every store is in memory, so the
/// future is ready on the first poll; anything else is a programming error.
fn run<F: Future>(fut: F) -> F::Output {
    fut.now_or_never().expect("in-memory stores never pend")
}

/// What `ClientMessage::Authenticate` carries for E2E encryption.
#[derive(Serialize)]
pub struct AuthBundle {
    pub identity_key: Vec<u8>,
    pub prekey_bundle: PreKeyBundleData,
}

pub struct SignalCore {
    stores: SignalStores,
}

impl SignalCore {
    /// Fresh identity, random registration id, signed pre-key 1 and
    /// `INITIAL_PREKEY_COUNT` one-time pre-keys with ids starting at 1.
    pub fn new() -> anyhow::Result<Self> {
        let identity_key_pair = voipc_crypto::generate_identity_key_pair();
        let registration_id: u32 = rand::Rng::gen(&mut rand::thread_rng());
        let mut stores = SignalStores::new(&identity_key_pair, registration_id);
        run(voipc_crypto::prekey::generate_prekeys(
            &mut stores,
            &identity_key_pair,
            1,
            INITIAL_PREKEY_COUNT,
        ))
        .context("failed to generate prekeys")?;
        Ok(Self { stores })
    }

    /// Identity key and pre-key bundle, read back from the stores so one-time
    /// pre-keys consumed by earlier sessions are not advertised again.
    pub fn bundle(&self) -> anyhow::Result<AuthBundle> {
        let identity_key = self.stores.identity.key_pair.public_key.clone();

        let signed = run(self
            .stores
            .signed_prekey
            .get_signed_pre_key(SignedPreKeyId::from(1u32)))
        .context("signed pre-key 1 missing")?;
        let signed_prekey = signed.public_key()?.serialize().to_vec();
        let signed_prekey_signature = signed.signature()?;

        let mut prekeys = Vec::with_capacity(self.stores.prekey.prekeys.len());
        for (&id, bytes) in &self.stores.prekey.prekeys {
            let public_key = PreKeyRecord::deserialize(bytes)?
                .public_key()?
                .serialize()
                .to_vec();
            prekeys.push(OneTimePreKey { id, public_key });
        }

        Ok(AuthBundle {
            prekey_bundle: PreKeyBundleData {
                registration_id: self.stores.identity.registration_id,
                device_id: 1,
                identity_key: identity_key.clone(),
                signed_prekey_id: 1,
                signed_prekey,
                signed_prekey_signature,
                prekeys,
            },
            identity_key,
        })
    }

    /// X3DH with a peer's bundle, using its first one-time pre-key if any.
    pub fn establish_session(
        &mut self,
        user_id: u32,
        bundle: &PreKeyBundleData,
    ) -> anyhow::Result<()> {
        let one_time = bundle.prekeys.first();
        run(session::establish_session(
            &mut self.stores,
            user_id,
            bundle.registration_id,
            bundle.device_id,
            &bundle.identity_key,
            bundle.signed_prekey_id,
            &bundle.signed_prekey,
            &bundle.signed_prekey_signature,
            one_time.map(|p| p.id),
            one_time.map(|p| p.public_key.as_slice()),
        ))
    }

    /// Returns (ciphertext, message_type) with 1 = PreKey, 2 = Whisper.
    pub fn encrypt(&mut self, user_id: u32, plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, u8)> {
        run(session::encrypt_message(&mut self.stores, user_id, plaintext))
    }

    pub fn decrypt(
        &mut self,
        user_id: u32,
        ciphertext: &[u8],
        message_type: u8,
    ) -> anyhow::Result<Vec<u8>> {
        run(session::decrypt_message(
            &mut self.stores,
            user_id,
            ciphertext,
            message_type,
        ))
    }

    pub fn create_sender_key_distribution(
        &mut self,
        own_user_id: u32,
        channel_id: u32,
    ) -> anyhow::Result<Vec<u8>> {
        run(group::create_distribution_message(
            &mut self.stores,
            own_user_id,
            channel_id,
        ))
    }

    pub fn process_sender_key_distribution(
        &mut self,
        from_user_id: u32,
        channel_id: u32,
        distribution: &[u8],
    ) -> anyhow::Result<()> {
        run(group::process_distribution_message(
            &mut self.stores,
            from_user_id,
            channel_id,
            distribution,
        ))
    }

    pub fn group_encrypt(
        &mut self,
        own_user_id: u32,
        channel_id: u32,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        run(group::encrypt_group_message(
            &mut self.stores,
            own_user_id,
            channel_id,
            plaintext,
        ))
    }

    pub fn group_decrypt(
        &mut self,
        from_user_id: u32,
        channel_id: u32,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        run(group::decrypt_group_message(
            &mut self.stores,
            from_user_id,
            channel_id,
            ciphertext,
        ))
    }
}
