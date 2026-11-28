//! AES-256-GCM under a random 96-bit nonce, and the random bytes for it: the
//! one seal the account vault (`account`) and the stored-message log (`log`)
//! both use.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRandom::new().fill(&mut b).expect("RNG failed");
    b
}

/// `plaintext` sealed under `key`, bound to `aad`: the nonce and the
/// ciphertext with its tag.
pub(crate) fn seal(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let iv = random::<12>();
    (iv, seal_in_place(key, aad, iv, plaintext))
}

/// `seal` at a nonce the caller chose: only for known-answer vectors, which
/// fix every input. Two seals under one key and nonce give the key away, so
/// no build but the tests has it.
#[cfg(test)]
pub(crate) fn seal_at(key: &[u8; 32], aad: &str, iv: [u8; 12], plaintext: &[u8]) -> Vec<u8> {
    seal_in_place(key, aad, iv, plaintext)
}

fn seal_in_place(key: &[u8; 32], aad: &str, iv: [u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("32-byte key"));
    let mut buf = plaintext.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(iv),
        Aad::from(aad.as_bytes()),
        &mut buf,
    )
    .expect("seal");
    buf
}

/// `None` for another key, another `aad`, or bytes that were changed.
///
/// The plaintext comes back in the very buffer it was opened in, so a caller
/// that wraps it in `Zeroizing` wipes the only copy (the tag past its end
/// too). On a failed open ring has zeroed what it decrypted.
pub(crate) fn open(key: &[u8; 32], aad: &str, iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(iv).ok()?;
    let mut buf = ct.to_vec();
    let n = k
        .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf)
        .ok()?
        .len();
    buf.truncate(n);
    Some(buf)
}
