//! Handing the vault's key to a new device of the same account, through a relay
//! that must learn nothing and must not sit in the middle.
//!
//! 1. The new device commits to an ephemeral key: `SHA-256(label | key | blind)`.
//! 2. A device of the account answers with a random nonce.
//! 3. The new device reveals the key and the blind.
//! 4. Both show a six-digit code from all of the above, and the person compares.
//! 5. On a yes, the old device wraps the DEK to the ephemeral key.
//!
//! The commitment is what makes six digits enough: a relay swapping in a key of
//! its own has to choose it before it knows the nonce, so it gets one guess at
//! the code for each time the person agrees to look at one.

use hkdf::Hkdf;
use libsignal_protocol::{KeyPair, PublicKey};
use sha2::{Digest, Sha256};
use voipc_protocol::conv::hex;
use zeroize::Zeroizing;

use crate::aead::random;

const COMMIT: &[u8] = b"voipc/pair/v1|commit|";
const CODE: &[u8] = b"voipc/pair/v1|code|";

pub const NONCE_LEN: usize = 32;
pub const BLIND_LEN: usize = 32;
const COMMITMENT_LEN: usize = 32;
/// `ephemeral public (33) | iv (12) | sealed DEK + tag (48)`.
const WRAPPED_LEN: usize = 33 + 12 + 48;

fn commit(ephemeral: &[u8], blind: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(COMMIT)
        .chain_update(ephemeral)
        .chain_update(blind)
        .finalize()
        .to_vec()
}

/// What both devices show. Six digits, from all that passed between them.
pub fn code(commitment: &[u8], nonce: &[u8], ephemeral: &[u8]) -> String {
    let d = Sha256::new()
        .chain_update(CODE)
        .chain_update(commitment)
        .chain_update(nonce)
        .chain_update(ephemeral)
        .finalize();
    let n = u64::from_be_bytes(d[..8].try_into().expect("8 bytes"));
    format!("{:06}", n % 1_000_000)
}

/// Whether the reveal is what was committed to.
pub fn reveal_ok(commitment: &[u8], ephemeral: &[u8], blind: &[u8]) -> bool {
    commitment.len() == COMMITMENT_LEN
        && blind.len() == BLIND_LEN
        && PublicKey::deserialize(ephemeral).is_ok()
        && commit(ephemeral, blind) == commitment
}

fn context(relay_id: &[u8; 16], name: &str, commitment: &[u8]) -> String {
    format!(
        "voipc/pair/v1|wrap|{}|{}|{}",
        hex(relay_id),
        name.trim().to_ascii_lowercase(),
        hex(commitment)
    )
}

fn kek(shared: &[u8], salt: &[u8], ctx: &str) -> Option<Zeroizing<[u8; 32]>> {
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), shared)
        .expand(ctx.as_bytes(), &mut *k)
        .ok()?;
    Some(k)
}

/// The old device's side, once the person said yes.
pub fn wrap_dek(
    ephemeral: &[u8],
    dek: &[u8; 32],
    relay_id: &[u8; 16],
    name: &str,
    commitment: &[u8],
) -> Option<Vec<u8>> {
    let them = PublicKey::deserialize(ephemeral).ok()?;
    let own = KeyPair::generate(&mut crate::rng());
    let shared = Zeroizing::new(own.private_key.calculate_agreement(&them).ok()?.to_vec());
    let own_public = own.public_key.serialize();
    let salt = [&own_public[..], ephemeral].concat();
    let ctx = context(relay_id, name, commitment);
    let k = kek(&shared, &salt, &ctx)?;
    let (iv, ct) = crate::aead::seal(&k, &ctx, dek);
    Some([&own_public[..], &iv[..], &ct].concat())
}

/// The new device's side.
pub struct PairRequest {
    pair: KeyPair,
    blind: [u8; BLIND_LEN],
    commitment: Vec<u8>,
}

impl PairRequest {
    #[allow(clippy::new_without_default)]
    pub fn new() -> PairRequest {
        let pair = KeyPair::generate(&mut crate::rng());
        let blind = random::<BLIND_LEN>();
        let commitment = commit(&pair.public_key.serialize(), &blind);
        PairRequest {
            pair,
            blind,
            commitment,
        }
    }

    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }

    /// `(ephemeral, blind)`, for after the other device's nonce.
    pub fn reveal(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.pair.public_key.serialize().to_vec(),
            self.blind.to_vec(),
        )
    }

    pub fn code(&self, nonce: &[u8]) -> String {
        code(&self.commitment, nonce, &self.pair.public_key.serialize())
    }

    pub fn open(&self, wrapped: &[u8], relay_id: &[u8; 16], name: &str) -> Option<[u8; 32]> {
        if wrapped.len() != WRAPPED_LEN {
            return None;
        }
        let them = PublicKey::deserialize(&wrapped[..33]).ok()?;
        let shared = Zeroizing::new(self.pair.private_key.calculate_agreement(&them).ok()?.to_vec());
        let salt = [&wrapped[..33], &self.pair.public_key.serialize()[..]].concat();
        let ctx = context(relay_id, name, &self.commitment);
        let k = kek(&shared, &salt, &ctx)?;
        crate::aead::open(&k, &ctx, &wrapped[33..45], &wrapped[45..])?
            .try_into()
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: [u8; 16] = [0x22; 16];

    /// From Python's hashlib, not from this code: a client that changes these
    /// shows a different code from the device it is pairing with.
    #[test]
    fn commitment_and_code_known_answers() {
        let ephemeral: Vec<u8> = std::iter::once(5).chain(0..32).collect();
        let blind: Vec<u8> = (32..64).collect();
        let nonce: Vec<u8> = (64..96).collect();
        let c = commit(&ephemeral, &blind);
        assert_eq!(
            hex(&c),
            "6be93527d45f7eaf302e6e87ca360713c26244942db53fe11768e4ede014261a"
        );
        assert_eq!(code(&c, &nonce, &ephemeral), "069008");
    }

    #[test]
    fn the_key_reaches_the_device_that_committed() {
        let new = PairRequest::new();
        let (ephemeral, blind) = new.reveal();
        assert!(reveal_ok(new.commitment(), &ephemeral, &blind));
        let nonce = random::<NONCE_LEN>();
        assert_eq!(
            new.code(&nonce),
            code(new.commitment(), &nonce, &ephemeral),
            "both devices show the same"
        );
        let dek = [9u8; 32];
        let wrapped = wrap_dek(&ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), Some(dek));
    }

    /// The relay's way in: keep the commitment it was shown and reveal a key of
    /// its own. It cannot, and with a commitment of its own the code differs.
    #[test]
    fn a_swapped_key_is_caught() {
        let new = PairRequest::new();
        let relays = PairRequest::new();
        let (theirs, blind) = relays.reveal();
        assert!(
            !reveal_ok(new.commitment(), &theirs, &blind),
            "another key under this commitment"
        );
        let nonce = random::<NONCE_LEN>();
        assert_ne!(new.code(&nonce), relays.code(&nonce));
    }

    #[test]
    fn a_wrap_is_bound_to_relay_account_and_request() {
        let new = PairRequest::new();
        let (ephemeral, _) = new.reveal();
        let dek = [9u8; 32];
        let wrapped = wrap_dek(&ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(new.open(&wrapped, &[0x23; 16], "luki"), None);
        assert_eq!(new.open(&wrapped, &RELAY, "lukas"), None);
        let other = wrap_dek(&ephemeral, &dek, &RELAY, "luki", &[0; 32]).unwrap();
        assert_eq!(new.open(&other, &RELAY, "luki"), None);
        let mut altered = wrapped.clone();
        altered[50] ^= 1;
        assert_eq!(new.open(&altered, &RELAY, "luki"), None);
        assert_eq!(new.open(&wrapped[1..], &RELAY, "luki"), None);
    }

    #[test]
    fn a_malformed_reveal_is_refused() {
        let new = PairRequest::new();
        let (ephemeral, blind) = new.reveal();
        assert!(!reveal_ok(new.commitment(), &[], &blind));
        assert!(!reveal_ok(new.commitment(), &ephemeral, &[]));
        assert!(!reveal_ok(&[], &ephemeral, &blind));
    }
}
