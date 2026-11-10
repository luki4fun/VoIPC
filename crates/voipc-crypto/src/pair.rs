//! Handing the vault's key to a new device of the same account, through a relay
//! that must learn nothing and must not sit in the middle.
//!
//! 1. The new device commits to an ephemeral key: `SHA-256(label | key | blind)`.
//! 2. A device of the account asks the person whether to look, and sends nothing
//!    before that yes.
//! 3. On that yes it answers with a fresh key of its own, in `PairNonce.nonce`.
//! 4. The new device takes one answer, reveals the key and the blind, and shows a
//!    six-digit code from all of the above, so the code covers both keys.
//! 5. The person types that code on the old device. The old device never shows it:
//!    it works the code out itself and compares.
//! 6. If they are the same, it wraps the DEK to the ephemeral key, from the key it
//!    answered with.
//! 7. The new device refuses a wrap from any other key, and opens nothing until the
//!    person says they typed the code there.
//!
//! The commitment is what makes six digits enough: a relay swapping in a key of its
//! own has to choose it before it knows the old device's key, and its own answer to
//! the new device before it knows the ephemeral key. So it gets one draw at the code
//! for each request the new device makes while a look is open: the old device's code
//! stays the same for a look, and the relay compares the two itself. A relay running
//! the new device alone, with a DEK of its own, gets as far as step 7 and a question
//! about a code nobody typed. Only `COMMIT` stays at v1: a mixed pair then gets as far as two different
//! codes, not a silent decline.
//!
//! What none of this reaches: a relay running its own side knows its own code, and
//! the old device takes it if the person types it. Only the person can tell where a
//! code came from, so the new device shows no text of the relay's during a pairing,
//! and the old device says where the code belongs.

use hkdf::Hkdf;
pub use libsignal_protocol::KeyPair;
use libsignal_protocol::PublicKey;
use sha2::{Digest, Sha256};
use voipc_protocol::conv::hex;
use zeroize::Zeroizing;

use crate::aead::random;

const COMMIT: &[u8] = b"voipc/pair/v1|commit|";
const CODE: &[u8] = b"voipc/pair/v2|code|";

/// `PairNonce.nonce`: the answering device's key, raw.
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
        "voipc/pair/v2|wrap|{}|{}|{}",
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

/// The key a device of the account answers an ask with: the pair, and its public
/// key's 32 raw bytes for `PairNonce`.
pub fn answer_key() -> (KeyPair, Vec<u8>) {
    let own = KeyPair::generate(&mut crate::rng());
    let raw = own.public_key.public_key_bytes().to_vec();
    (own, raw)
}

/// The old device's side, once the code typed there matched.
pub fn wrap_dek(
    own: &KeyPair,
    ephemeral: &[u8],
    dek: &[u8; 32],
    relay_id: &[u8; 16],
    name: &str,
    commitment: &[u8],
) -> Option<Vec<u8>> {
    let them = PublicKey::deserialize(ephemeral).ok()?;
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
    /// The one answer this request takes: as it came, and as a key.
    answer: Option<(Vec<u8>, PublicKey)>,
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
            answer: None,
        }
    }

    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }

    /// `(ephemeral, blind)`, for after the other device's answer.
    pub fn reveal(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.pair.public_key.serialize().to_vec(),
            self.blind.to_vec(),
        )
    }

    /// The other device's answer, and the code to show. `None` for a second one or
    /// one that is no key: the ephemeral key is public after the first reveal, so a
    /// second answer could be ground to any code.
    pub fn take_answer(&mut self, nonce: &[u8]) -> Option<String> {
        if self.answer.is_some() {
            return None;
        }
        let key = PublicKey::from_djb_public_key_bytes(nonce).ok()?;
        self.answer = Some((nonce.to_vec(), key));
        self.shown()
    }

    /// The code the one answer made.
    pub fn shown(&self) -> Option<String> {
        let (nonce, _) = self.answer.as_ref()?;
        Some(code(
            &self.commitment,
            nonce,
            &self.pair.public_key.serialize(),
        ))
    }

    /// Only a wrap from the key this request took as its answer: the code covers it.
    pub fn open(&self, wrapped: &[u8], relay_id: &[u8; 16], name: &str) -> Option<[u8; 32]> {
        let (_, them) = self.answer.as_ref()?;
        if wrapped.len() != WRAPPED_LEN || wrapped[..33] != them.serialize()[..] {
            return None;
        }
        let shared = Zeroizing::new(
            self.pair
                .private_key
                .calculate_agreement(them)
                .ok()?
                .to_vec(),
        );
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
    /// shows a different code from the device it is pairing with. The v1 code of
    /// the same input was 069008, so a mixed pair differs too.
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
        assert_eq!(code(&c, &nonce, &ephemeral), "462247");
    }

    /// A request that took `answer`, and that answer's key.
    fn answered() -> (PairRequest, KeyPair) {
        let mut new = PairRequest::new();
        let (own, raw) = answer_key();
        new.take_answer(&raw).unwrap();
        (new, own)
    }

    #[test]
    fn the_key_reaches_the_device_that_committed() {
        let mut new = PairRequest::new();
        let (ephemeral, blind) = new.reveal();
        assert!(reveal_ok(new.commitment(), &ephemeral, &blind));
        let (own, raw) = answer_key();
        assert_eq!(
            new.take_answer(&raw).unwrap(),
            code(new.commitment(), &raw, &ephemeral),
            "both devices work out the same"
        );
        let dek = [9u8; 32];
        let wrapped = wrap_dek(&own, &ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), Some(dek));
    }

    /// The relay's way in: keep the commitment it was shown and reveal a key of
    /// its own. It cannot, and with a commitment of its own the code differs.
    #[test]
    fn a_swapped_key_is_caught() {
        let (new, _) = answered();
        let relays = PairRequest::new();
        let (theirs, blind) = relays.reveal();
        assert!(
            !reveal_ok(new.commitment(), &theirs, &blind),
            "another key under this commitment"
        );
        let (_, raw) = answer_key();
        let mut new2 = PairRequest::new();
        let mut relays2 = PairRequest::new();
        assert_ne!(new2.take_answer(&raw), relays2.take_answer(&raw));
    }

    /// W1-2: the ephemeral key is public after the first reveal, so a second
    /// answer could be ground offline to any code the relay likes.
    #[test]
    fn a_request_takes_one_answer() {
        let (mut new, _) = answered();
        let shown = new.shown().unwrap();
        let (_, other) = answer_key();
        assert_eq!(new.take_answer(&other), None, "another answer");
        let same = new.answer.as_ref().unwrap().0.clone();
        assert_eq!(new.take_answer(&same), None, "the same answer again");
        assert_eq!(new.shown().unwrap(), shown, "the code on screen stands");
    }

    #[test]
    fn an_answer_that_is_no_key_is_not_taken() {
        let mut new = PairRequest::new();
        assert_eq!(new.take_answer(&[1, 2, 3]), None);
        assert_eq!(new.shown(), None);
        // The control: a good key is still taken after that
        let (_, raw) = answer_key();
        assert!(new.take_answer(&raw).is_some());
    }

    /// W1-3: the relay can always make a wrap to the ephemeral key, from a key of
    /// its own. The code covers the key the wrap must come from.
    #[test]
    fn a_wrap_from_any_key_but_the_answer_does_not_open() {
        let (new, own) = answered();
        let (ephemeral, _) = new.reveal();
        let dek = [9u8; 32];
        let (relays, _) = answer_key();
        let forged = wrap_dek(&relays, &ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(new.open(&forged, &RELAY, "luki"), None);
        // The control, so it was the key and nothing else about the wrap
        let good = wrap_dek(&own, &ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(new.open(&good, &RELAY, "luki"), Some(dek));
    }

    #[test]
    fn a_wrap_before_any_answer_does_not_open() {
        let new = PairRequest::new();
        let (ephemeral, _) = new.reveal();
        let (relays, _) = answer_key();
        let wrapped = wrap_dek(
            &relays,
            &ephemeral,
            &[9; 32],
            &RELAY,
            "luki",
            new.commitment(),
        )
        .unwrap();
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), None);
    }

    /// Built by hand as the last version's wrap was: its context, a key of its own.
    /// A mixed pair must fail here, not open.
    #[test]
    fn a_wrap_from_the_last_candidate_does_not_open() {
        let (new, own) = answered();
        let (ephemeral, _) = new.reveal();
        let them = PublicKey::deserialize(&ephemeral).unwrap();
        let shared = Zeroizing::new(own.private_key.calculate_agreement(&them).unwrap().to_vec());
        let own_public = own.public_key.serialize();
        let salt = [&own_public[..], &ephemeral[..]].concat();
        let ctx = format!(
            "voipc/pair/v1|wrap|{}|luki|{}",
            hex(&RELAY),
            hex(new.commitment())
        );
        let k = kek(&shared, &salt, &ctx).unwrap();
        let (iv, ct) = crate::aead::seal(&k, &ctx, &[9u8; 32]);
        let wrapped = [&own_public[..], &iv[..], &ct].concat();
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), None);
    }

    #[test]
    fn a_wrap_is_bound_to_relay_account_and_request() {
        let (new, own) = answered();
        let (ephemeral, _) = new.reveal();
        let dek = [9u8; 32];
        let wrapped = wrap_dek(&own, &ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(new.open(&wrapped, &[0x23; 16], "luki"), None);
        assert_eq!(new.open(&wrapped, &RELAY, "lukas"), None);
        let other = wrap_dek(&own, &ephemeral, &dek, &RELAY, "luki", &[0; 32]).unwrap();
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
