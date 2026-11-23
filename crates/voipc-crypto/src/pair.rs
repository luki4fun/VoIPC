//! Handing the vault's key to a new device of the same account, through a relay
//! that must learn nothing and must not sit in the middle.
//!
//! 1. The new device commits to an ephemeral key: `SHA-256(label | key | blind)`. The key is
//!    an X25519 key and a Kyber1024 key together (`EPHEMERAL_LEN`).
//! 2. A device of the account asks the person whether to look, and sends nothing
//!    before that yes.
//! 3. On that yes it answers with a fresh key of its own, in `PairNonce.nonce`.
//! 4. The new device takes one answer, reveals the key and the blind, and shows a
//!    six-digit code from all of the above, so the code covers both keys.
//! 5. The person types that code on the old device. The old device never shows it:
//!    it works the code out itself and compares.
//! 6. If they are the same, it wraps the DEK to the ephemeral key, from the key it
//!    answered with: a Kyber1024 encapsulation to the committed Kyber key and the X25519 of
//!    the two X25519 keys, both in the KEK, as a hybrid welcome is (GROUP-KEY §3.2). Every
//!    frame of this passes through the relay, so with X25519 alone whoever breaks it later
//!    would open the DEK from a recording, and with it the vault, `item.kept` and every
//!    kept copy under the group key.
//! 7. The new device refuses a wrap from any other key, and opens nothing until the
//!    person says they typed the code there.
//!
//! The commitment is what makes six digits enough: a relay swapping in a key of its
//! own has to choose it before it knows the old device's key, and its own answer to
//! the new device before it knows the ephemeral key. So it gets one draw at the code
//! for each request the new device makes while a look is open: the old device's code
//! stays the same for a look, and the relay compares the two itself. A relay running
//! the new device alone, with a DEK of its own, gets as far as step 7 and a question
//! about a code nobody typed.
//!
//! Only `COMMIT` stays at v1. A device of the X25519-only version (v2) paired with one of
//! this: this one's new device reveals a key that one takes (libsignal reads the first 33
//! bytes) and the two show different codes, so it wraps nothing; that one's new device reveals
//! a key of 33 bytes, which this one refuses at once. Neither ever sends the DEK, and a wrap
//! of the old shape opens nothing here.
//!
//! What none of this reaches: a relay running its own side knows its own code, and
//! the old device takes it if the person types it. Only the person can tell where a
//! code came from, so the new device shows no text of the relay's during a pairing,
//! and the old device says where the code belongs.

use hkdf::Hkdf;
pub use libsignal_protocol::KeyPair;
use libsignal_protocol::{kem, PublicKey};
use sha2::{Digest, Sha256};
use voipc_protocol::conv::hex;
use voipc_protocol::gk::{KEM_CT_BYTES, KEM_PUBLIC_BYTES};
use zeroize::Zeroizing;

use crate::aead::random;

const COMMIT: &[u8] = b"voipc/pair/v1|commit|";
const CODE: &[u8] = b"voipc/pair/v3|code|";

/// `PairNonce.nonce`: the answering device's key, raw.
pub const NONCE_LEN: usize = 32;
pub const BLIND_LEN: usize = 32;
const COMMITMENT_LEN: usize = 32;
/// `ser(X25519 public)` as libsignal makes it: the type byte and 32.
const DH_LEN: usize = 33;
/// `PairReveal.ephemeral`: `ser(X25519 public) (33) | ser(Kyber1024 public) (1569)`.
pub const EPHEMERAL_LEN: usize = DH_LEN + KEM_PUBLIC_BYTES;
/// `PairApprove.wrapped`: `answering device's public (33) | ser(ct_q) (1569) | iv (12) |
/// sealed DEK + tag (48)`.
pub const WRAPPED_LEN: usize = DH_LEN + KEM_CT_BYTES + 12 + 48;
/// The relay's first protocol that carries a wrap of this size (`PairApprove`): one before
/// drops it, so a pairing there would only time out.
pub const PAIR_PQ_SINCE: u32 = 26;

/// What an app says, and sends nothing, when asked to pair through a relay before
/// `PAIR_PQ_SINCE`.
pub const PAIR_NEEDS_NEWER: &str = "Your other device can hand the key over only on a server \
     that runs VoIPC 1.14 or later. Use your recovery key or password here.";

/// Whether a pairing can go through a relay at `protocol`: `Err` with what to say if not.
/// The X25519-only wrap that would fit an older one is never made: the DEK and the kept keys
/// it opens never change, so one wrap a quantum computer opens later opens every kept copy.
pub fn pairs_on(protocol: u32) -> Result<(), &'static str> {
    if protocol < PAIR_PQ_SINCE {
        return Err(PAIR_NEEDS_NEWER);
    }
    Ok(())
}

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

/// An ephemeral key as revealed: its X25519 half and its Kyber1024 half, each checked, and
/// nothing more or less.
fn ephemeral_keys(ephemeral: &[u8]) -> Option<(PublicKey, kem::PublicKey)> {
    if ephemeral.len() != EPHEMERAL_LEN {
        return None;
    }
    let (dh, q) = ephemeral.split_at(DH_LEN);
    let dh = PublicKey::deserialize(dh).ok()?;
    let q = kem::PublicKey::deserialize(q).ok()?;
    (q.key_type() == kem::KeyType::Kyber1024).then_some((dh, q))
}

/// Whether the reveal is what was committed to, and a key of the hybrid shape.
pub fn reveal_ok(commitment: &[u8], ephemeral: &[u8], blind: &[u8]) -> bool {
    commitment.len() == COMMITMENT_LEN
        && blind.len() == BLIND_LEN
        && ephemeral_keys(ephemeral).is_some()
        && commit(ephemeral, blind) == commitment
}

fn context(relay_id: &[u8; 16], name: &str, commitment: &[u8]) -> String {
    format!(
        "voipc/pair/v3|wrap|{}|{}|{}",
        hex(relay_id),
        name.trim().to_ascii_lowercase(),
        hex(commitment)
    )
}

/// The KEK: `HKDF(salt, ss_q | ss_x, ctx)`, the salt binding every public value. Opening it
/// takes both Kyber1024 and X25519 broken.
fn kek(
    (ss_q, ss_x): (&[u8], &[u8]),
    (ct_q, answering, ephemeral): (&[u8], &[u8], &[u8]),
    ctx: &str,
) -> Option<Zeroizing<[u8; 32]>> {
    let salt = Sha256::new()
        .chain_update(ct_q)
        .chain_update(answering)
        .chain_update(ephemeral)
        .finalize();
    let ikm = Zeroizing::new([ss_q, ss_x].concat());
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &ikm)
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

/// The old device's side, once the code typed there matched. `None` for an ephemeral key
/// that is not of the hybrid shape: the DEK never goes under X25519 alone.
pub fn wrap_dek(
    own: &KeyPair,
    ephemeral: &[u8],
    dek: &[u8; 32],
    relay_id: &[u8; 16],
    name: &str,
    commitment: &[u8],
) -> Option<Vec<u8>> {
    let (them, q) = ephemeral_keys(ephemeral)?;
    let (ss_q, ct_q) = q.encapsulate(&mut crate::rng()).ok()?;
    let ss_q = Zeroizing::new(ss_q.into_vec());
    let ss_x = Zeroizing::new(own.private_key.calculate_agreement(&them).ok()?.to_vec());
    let own_public = own.public_key.serialize();
    let ctx = context(relay_id, name, commitment);
    let k = kek((&ss_q, &ss_x), (&ct_q, &own_public, ephemeral), &ctx)?;
    let (iv, ct) = crate::aead::seal(&k, &ctx, dek);
    Some([&own_public[..], &ct_q[..], &iv[..], &ct].concat())
}

/// The new device's side.
pub struct PairRequest {
    pair: KeyPair,
    kem: kem::KeyPair,
    /// What is committed to and revealed: both public halves, as `EPHEMERAL_LEN`.
    ephemeral: Vec<u8>,
    blind: [u8; BLIND_LEN],
    commitment: Vec<u8>,
    /// The one answer this request takes: as it came, and as a key.
    answer: Option<(Vec<u8>, PublicKey)>,
}

impl PairRequest {
    #[allow(clippy::new_without_default)]
    pub fn new() -> PairRequest {
        let mut rng = crate::rng();
        let pair = KeyPair::generate(&mut rng);
        let kem = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let ephemeral = [
            &pair.public_key.serialize()[..],
            &kem.public_key.serialize()[..],
        ]
        .concat();
        let blind = random::<BLIND_LEN>();
        let commitment = commit(&ephemeral, &blind);
        PairRequest {
            pair,
            kem,
            ephemeral,
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
        (self.ephemeral.clone(), self.blind.to_vec())
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
        Some(code(&self.commitment, nonce, &self.ephemeral))
    }

    /// Only a wrap from the key this request took as its answer: the code covers it. And
    /// only of the hybrid shape, to the Kyber key committed to.
    pub fn open(&self, wrapped: &[u8], relay_id: &[u8; 16], name: &str) -> Option<[u8; 32]> {
        let (_, them) = self.answer.as_ref()?;
        if wrapped.len() != WRAPPED_LEN || wrapped[..DH_LEN] != them.serialize()[..] {
            return None;
        }
        let (answering, rest) = wrapped.split_at(DH_LEN);
        let (ct_q, sealed) = rest.split_at(KEM_CT_BYTES);
        let ss_q = self.kem.secret_key.decapsulate(&Box::from(ct_q)).ok()?;
        let ss_q = Zeroizing::new(ss_q.into_vec());
        let ss_x = Zeroizing::new(
            self.pair
                .private_key
                .calculate_agreement(them)
                .ok()?
                .to_vec(),
        );
        let ctx = context(relay_id, name, &self.commitment);
        let k = kek((&ss_q, &ss_x), (ct_q, answering, &self.ephemeral), &ctx)?;
        crate::aead::open(&k, &ctx, &sealed[..12], &sealed[12..])?
            .try_into()
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: [u8; 16] = [0x22; 16];

    /// From Python's hashlib, not from this code: a client that changes these
    /// shows a different code from the device it is pairing with. The v2 code of the
    /// same input (X25519 only) was 462247 and the v1 code 069008, so a mixed pair
    /// differs too.
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
        assert_eq!(code(&c, &nonce, &ephemeral), "289052");
    }

    /// The KEK of the X25519-only versions: `HKDF(own public | ephemeral, X25519, ctx)`.
    fn classic_kek(shared: &[u8], salt: &[u8], ctx: &str) -> Zeroizing<[u8; 32]> {
        let mut k = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(salt), shared)
            .expand(ctx.as_bytes(), &mut *k)
            .unwrap();
        k
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

    /// Built by hand as the last versions' wraps were: their contexts, X25519 alone, from
    /// the key this request took. A mixed pair must fail here, not open.
    #[test]
    fn a_wrap_from_the_last_candidates_does_not_open() {
        let (new, own) = answered();
        let (ephemeral, _) = new.reveal();
        let them = PublicKey::deserialize(&ephemeral[..DH_LEN]).unwrap();
        let shared = Zeroizing::new(own.private_key.calculate_agreement(&them).unwrap().to_vec());
        let own_public = own.public_key.serialize();
        for (v, salted) in [("v1", &ephemeral[..DH_LEN]), ("v2", &ephemeral[..])] {
            let salt = [&own_public[..], salted].concat();
            let ctx = format!(
                "voipc/pair/{v}|wrap|{}|luki|{}",
                hex(&RELAY),
                hex(new.commitment())
            );
            let k = classic_kek(&shared, &salt, &ctx);
            let (iv, ct) = crate::aead::seal(&k, &ctx, &[9u8; 32]);
            let wrapped = [&own_public[..], &iv[..], &ct].concat();
            assert_eq!(wrapped.len(), 33 + 12 + 48);
            assert_eq!(new.open(&wrapped, &RELAY, "luki"), None, "{v}");
        }
    }

    /// The other half of a mixed pair: a device of the X25519-only version reveals a key of
    /// 33 bytes. It is refused at the reveal, and no wrap is ever made to it.
    #[test]
    fn a_reveal_of_the_x25519_only_shape_is_refused_and_gets_no_wrap() {
        let pair = KeyPair::generate(&mut crate::rng());
        let classic = pair.public_key.serialize().to_vec();
        let blind = [7u8; BLIND_LEN];
        let commitment = commit(&classic, &blind);
        assert!(!reveal_ok(&commitment, &classic, &blind));
        let (own, _) = answer_key();
        assert_eq!(
            wrap_dek(&own, &classic, &[9; 32], &RELAY, "luki", &commitment),
            None
        );
        // Nor the hybrid shape with anything after it, or of another key type in its place
        let new = PairRequest::new();
        let (ephemeral, blind) = new.reveal();
        let longer = [&ephemeral[..], &[0]].concat();
        assert!(!reveal_ok(&commit(&longer, &blind), &longer, &blind));
        let mut other = ephemeral.clone();
        other[DH_LEN] ^= 0x40;
        assert!(!reveal_ok(&commit(&other, &blind), &other, &blind));
        assert!(wrap_dek(&own, &other, &[9; 32], &RELAY, "luki", &commitment).is_none());
        // The control: the shape it makes is taken
        assert!(reveal_ok(new.commitment(), &ephemeral, &blind));
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
        for at in [50, DH_LEN + KEM_CT_BYTES + 3, wrapped.len() - 1] {
            let mut altered = wrapped.clone();
            altered[at] ^= 1;
            assert_eq!(new.open(&altered, &RELAY, "luki"), None, "byte {at}");
        }
        assert_eq!(new.open(&wrapped[1..], &RELAY, "luki"), None);
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), Some(dek), "the control");
    }

    /// RV g4 review (pair.rs:105): every frame of a pairing passes through the relay, so
    /// whoever breaks X25519 and recorded it holds both X25519 private keys. The vault's key
    /// must not open from those and the public bytes alone: it opens `item.kept`, and with it
    /// every kept copy under the group key.
    #[test]
    fn a_pairing_wrap_does_not_open_from_the_x25519_keys_alone() {
        let (new, own) = answered();
        let (ephemeral, _) = new.reveal();
        let dek = [9u8; 32];
        let wrapped = wrap_dek(&own, &ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), Some(dek), "the control");
        // The attacker: the X25519 secret of the two keys, and every byte the relay carried
        let x = Zeroizing::new(
            new.pair
                .private_key
                .calculate_agreement(&own.public_key)
                .unwrap()
                .to_vec(),
        );
        let own_public = own.public_key.serialize();
        let salt = [&own_public[..], &ephemeral[..]].concat();
        for ctx in [
            context(&RELAY, "luki", new.commitment()),
            format!(
                "voipc/pair/v2|wrap|{}|luki|{}",
                hex(&RELAY),
                hex(new.commitment())
            ),
        ] {
            let k = classic_kek(&x, &salt, &ctx);
            let sealed = &wrapped[wrapped.len() - 60..];
            assert_eq!(
                crate::aead::open(&k, &ctx, &sealed[..12], &sealed[12..]),
                None,
                "X25519 alone opened the vault's key"
            );
        }
        assert_eq!(
            ephemeral.len(),
            33 + crate::log::KEM_PUBLIC_BYTES,
            "the new device commits to a Kyber1024 key as well"
        );
    }

    /// And what it takes beside the X25519 keys: the Kyber1024 secret of the key committed
    /// to. The same request with another Kyber key in its place opens nothing.
    #[test]
    fn a_pairing_wrap_needs_the_committed_kyber_key_too() {
        let (mut new, own) = answered();
        let (ephemeral, _) = new.reveal();
        let dek = [9u8; 32];
        let wrapped = wrap_dek(&own, &ephemeral, &dek, &RELAY, "luki", new.commitment()).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_LEN);
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), Some(dek), "the control");
        new.kem = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut crate::rng());
        assert_eq!(new.open(&wrapped, &RELAY, "luki"), None);
    }

    /// A relay before 26 drops a wrap of this size: the app asks nothing there, and says so.
    #[test]
    fn a_pairing_goes_only_through_a_relay_that_carries_its_wrap() {
        assert_eq!(pairs_on(PAIR_PQ_SINCE - 1), Err(PAIR_NEEDS_NEWER));
        assert_eq!(pairs_on(PAIR_PQ_SINCE), Ok(()));
        assert_eq!(pairs_on(voipc_protocol::codec::PROTOCOL_VERSION), Ok(()));
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
