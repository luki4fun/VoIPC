//! Signal Protocol state for one browser session: an ephemeral identity,
//! pre-keys and the in-memory stores, mirroring the native client's
//! initialization and bundle extraction (client/src-tauri/src/network.rs).
//! Plain Rust so it is testable on the host; lib.rs wraps it for JS.

use std::future::Future;

use futures_util::FutureExt;
use serde::Serialize;
use voipc_crypto::prekey::{self, PREKEY_REFILL_COUNT};
use voipc_crypto::{group, session, ChannelKeying, SignalStores};
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
    /// Who is in which channel and which of them hold which of our keys. The
    /// native client keeps the same struct beside the same stores; sharing it
    /// is what stops the two drifting, as they did over rotation.
    pub keying: ChannelKeying,
}

impl SignalCore {
    /// Fresh identity, random registration id and fresh pre-keys
    /// (`voipc_crypto::prekey::generate_prekeys`).
    pub fn new() -> anyhow::Result<Self> {
        Self::with_identity(&voipc_crypto::generate_identity_key_pair())
    }

    /// The same, for an account's identity from its vault: only the identity
    /// outlives the connection, the pre-keys and stores are new every time.
    pub fn with_identity(identity_key_pair: &libsignal_protocol::IdentityKeyPair) -> anyhow::Result<Self> {
        let registration_id: u32 = rand::random();
        let mut stores = SignalStores::new(identity_key_pair, registration_id);
        prekey::generate_prekeys(&mut stores, identity_key_pair)?;
        Ok(Self {
            stores,
            keying: ChannelKeying::default(),
        })
    }

    /// Identity key and pre-key bundle for Authenticate.
    pub fn bundle(&self) -> anyhow::Result<AuthBundle> {
        let prekey_bundle = prekey::bundle(&self.stores)?;
        Ok(AuthBundle { identity_key: prekey_bundle.identity_key.clone(), prekey_bundle })
    }

    /// Our user id from `Authenticated`: every pairwise message is bound to it.
    pub fn set_own_user_id(&mut self, user_id: u32) {
        self.stores.own_user_id = user_id;
    }

    /// More one-time pre-keys for `UploadPreKeys`, when the relay runs low.
    pub fn more_prekeys(&mut self) -> anyhow::Result<Vec<OneTimePreKey>> {
        prekey::more_prekeys(&mut self.stores, PREKEY_REFILL_COUNT)
    }

    /// PQXDH with a peer's bundle, using its one-time pre-key if any.
    pub fn establish_session(
        &mut self,
        user_id: u32,
        bundle: &PreKeyBundleData,
    ) -> anyhow::Result<()> {
        run(session::establish_session(&mut self.stores, user_id, bundle))
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

    /// Start a channel's group keying from nothing, chain included.
    /// `(user id, identity key)` for each identity the stores took in since
    /// the last call: a session a peer opened among them.
    pub fn take_seen(&mut self) -> Vec<(u32, Vec<u8>)> {
        self.stores.identity.take_seen()
    }

    /// The identity key the session with `user_id` runs on, if there is one.
    pub fn identity_of(&self, user_id: u32) -> Option<Vec<u8>> {
        self.stores.identity.identity_of(user_id).map(<[u8]>::to_vec)
    }

    pub fn reset_channel(&mut self, own_user_id: u32, channel_id: u32) {
        self.keying
            .reset_channel(Some(&mut self.stores), own_user_id, channel_id);
    }

    /// Leave a channel entirely: keys, roster and anything still wanted.
    pub fn forget_channel(&mut self, own_user_id: u32, channel_id: u32) {
        self.keying
            .forget_channel(Some(&mut self.stores), own_user_id, channel_id);
    }

    /// If a rotation is pending, perform it and return who needs the new key.
    pub fn take_rotation_targets(&mut self, own_user_id: u32, channel_id: u32) -> Vec<u32> {
        self.keying
            .take_rotation_targets(Some(&mut self.stores), own_user_id, channel_id)
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
