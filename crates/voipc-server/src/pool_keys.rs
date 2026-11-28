//! What an edge and its core make from the secret they share (`[pool] edges` on the core,
//! `secret` in the edge's edge.toml): the proof an edge links with, and the tickets the core
//! hands viewers for that edge. The core uses this in `pool.rs`, the edge in `edge.rs`, and
//! both must agree on every byte, so a change here is a change of the pool wire and bumps
//! `voipc_protocol::pool::POOL_VERSION`.
//!
//! Each purpose has a key of its own, an HMAC of the secret under the purpose's label, so
//! nothing made for one passes for the other. Every check is `ring::hmac::verify`, which
//! takes as long however much of a tag is right.

// The pool and the edge role are the slices after this one.
#![cfg_attr(not(test), allow(dead_code))]

use ring::hmac;
use voipc_crypto::bind::BIND_LEN;
use voipc_protocol::pool::{
    decode_ticket_body, encode_ticket_body, TicketBody, MAX_TICKET_BYTES, TICKET_TAG_BYTES,
};
use voipc_protocol::types::SessionId;

const PROOF_LABEL: &[u8] = b"voipc-edge proof v1";
const TICKET_LABEL: &[u8] = b"voipc-edge ticket v1";

/// How long a ticket is good for after the core made it, on the core's clock. The app
/// connects within seconds of its `WatchAt`; an edge keeps a redeemed slot this long.
pub(crate) const TICKET_TTL_MS: u64 = 30_000;

fn derive(secret: &str, label: &[u8]) -> hmac::Key {
    let root = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::Key::new(hmac::HMAC_SHA256, hmac::sign(&root, label).as_ref())
}

/// The key an edge proves itself with.
pub(crate) fn proof_key(secret: &str) -> hmac::Key {
    derive(secret, PROOF_LABEL)
}

/// The key the core seals this edge's tickets with.
pub(crate) fn ticket_key(secret: &str) -> hmac::Key {
    derive(secret, TICKET_LABEL)
}

fn proof_input(binding: &[u8; BIND_LEN], name: &str) -> Vec<u8> {
    [PROOF_LABEL, binding, name.as_bytes()].concat()
}

/// What an edge sends in its `Hello`, bound to the exporter of the TLS session it goes
/// on (`web::quic_binding`) and to its name: good on that connection and for that name
/// only, so a copy of it is worth nothing.
pub(crate) fn proof(key: &hmac::Key, binding: &[u8; BIND_LEN], name: &str) -> [u8; 32] {
    hmac::sign(key, &proof_input(binding, name))
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 is 32 bytes")
}

/// The core's check of a `Hello`'s proof, against the exporter of the connection it came
/// on.
pub(crate) fn proof_ok(
    key: &hmac::Key,
    binding: &[u8; BIND_LEN],
    name: &str,
    proof: &[u8; 32],
) -> bool {
    hmac::verify(key, &proof_input(binding, name), proof).is_ok()
}

/// A ticket's body for `share` on the edge link `link`, numbered `slot`, made at
/// `core_ms` on the core's clock.
pub(crate) fn mint(link: u64, share: SessionId, slot: u64, core_ms: u64) -> TicketBody {
    TicketBody {
        link,
        share,
        slot,
        expires_ms: core_ms.saturating_add(TICKET_TTL_MS),
    }
}

/// Whether a ticket is past its time at `core_ms` on the core's clock.
pub(crate) fn expired(body: &TicketBody, core_ms: u64) -> bool {
    body.expires_ms <= core_ms
}

/// `postcard(body) ‖ tag`: what the app is given and passes on to the edge.
pub(crate) fn seal(key: &hmac::Key, body: &TicketBody) -> Vec<u8> {
    let mut ticket = encode_ticket_body(body).expect("four integers always encode");
    let tag = hmac::sign(key, &ticket);
    ticket.extend_from_slice(tag.as_ref());
    ticket
}

/// Why a ticket was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// Longer than any ticket (`MAX_TICKET_BYTES`): refused unread.
    TooLong,
    /// Too short to hold a body and its tag.
    TooShort,
    /// The tag is not this key's over these bytes: made up, changed, or for another edge.
    BadTag,
    /// The tag is good, but the body does not read whole as this pool version's.
    Malformed,
}

/// The body of a ticket sealed with `key`. Its link, time and slot are not looked at
/// here: the edge checks those against what it knows.
pub(crate) fn open(key: &hmac::Key, ticket: &[u8]) -> Result<TicketBody, Why> {
    if ticket.len() > MAX_TICKET_BYTES {
        return Err(Why::TooLong);
    }
    let body_len = ticket.len().saturating_sub(TICKET_TAG_BYTES);
    if body_len == 0 {
        return Err(Why::TooShort);
    }
    let (body, tag) = ticket.split_at(body_len);
    hmac::verify(key, body, tag).map_err(|_| Why::BadTag)?;
    decode_ticket_body(body).map_err(|_| Why::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "edge-one-secret-of-at-least-32-chars";
    const OTHER: &str = "edge-two-secret-of-at-least-32-chars";
    const BINDING: [u8; BIND_LEN] = {
        let mut b = [0u8; BIND_LEN];
        let mut i = 0;
        while i < BIND_LEN {
            b[i] = i as u8;
            i += 1;
        }
        b
    };

    fn body() -> TicketBody {
        mint(1, 2, 3, 4)
    }

    #[test]
    fn a_proof_holds_for_its_secret_its_connection_and_its_name() {
        let key = proof_key(SECRET);
        let proof = proof(&key, &BINDING, "e1");
        assert!(proof_ok(&proof_key(SECRET), &BINDING, "e1", &proof));
        assert!(
            !proof_ok(&proof_key(OTHER), &BINDING, "e1", &proof),
            "another secret's key took it"
        );
    }

    #[test]
    fn a_proof_made_on_another_connection_fails() {
        let key = proof_key(SECRET);
        let proof = proof(&key, &BINDING, "e1");
        let mut elsewhere = BINDING;
        elsewhere[31] ^= 1;
        assert!(!proof_ok(&key, &elsewhere, "e1", &proof));
    }

    #[test]
    fn a_proof_for_another_name_fails() {
        let key = proof_key(SECRET);
        let proof = proof(&key, &BINDING, "e1");
        for name in ["e2", "e", "e1 ", "E1", ""] {
            assert!(!proof_ok(&key, &BINDING, name, &proof), "{name:?}");
        }
    }

    #[test]
    fn a_ticket_opens_to_what_was_sealed() {
        let key = ticket_key(SECRET);
        let ticket = seal(&key, &body());
        assert!(ticket.len() <= MAX_TICKET_BYTES);
        assert_eq!(open(&key, &ticket), Ok(body()));
    }

    #[test]
    fn a_tampered_ticket_fails() {
        let key = ticket_key(SECRET);
        let ticket = seal(&key, &body());
        for at in 0..ticket.len() {
            for bit in 0..8 {
                let mut changed = ticket.clone();
                changed[at] ^= 1 << bit;
                assert_eq!(
                    open(&key, &changed),
                    Err(Why::BadTag),
                    "byte {at} bit {bit}"
                );
            }
        }
        // Cut short, or a byte more on either end
        assert_eq!(open(&key, &ticket[..ticket.len() - 1]), Err(Why::BadTag));
        assert_eq!(
            open(&key, &[ticket.clone(), vec![0]].concat()),
            Err(Why::BadTag)
        );
        assert_eq!(
            open(&key, &[vec![0], ticket.clone()].concat()),
            Err(Why::BadTag)
        );
        assert_eq!(open(&key, &ticket[..TICKET_TAG_BYTES]), Err(Why::TooShort));
        assert_eq!(open(&key, &[]), Err(Why::TooShort));
    }

    #[test]
    fn a_ticket_of_another_edge_fails() {
        let theirs = seal(&ticket_key(OTHER), &body());
        assert_eq!(open(&ticket_key(SECRET), &theirs), Err(Why::BadTag));
    }

    #[test]
    fn a_proof_is_no_ticket_and_a_ticket_no_proof() {
        // The same secret, the same bytes: each purpose's key gives its own tag
        let bytes = encode_ticket_body(&body()).unwrap();
        let proof_tag = hmac::sign(&proof_key(SECRET), &bytes);
        let forged = [bytes.clone(), proof_tag.as_ref().to_vec()].concat();
        assert_eq!(open(&ticket_key(SECRET), &forged), Err(Why::BadTag));
        let ticket_tag: [u8; 32] = hmac::sign(&ticket_key(SECRET), &proof_input(&BINDING, "e1"))
            .as_ref()
            .try_into()
            .unwrap();
        assert!(!proof_ok(&proof_key(SECRET), &BINDING, "e1", &ticket_tag));
    }

    #[test]
    fn a_ticket_expires_30_s_after_it_was_made() {
        let made_at = 1_000;
        let body = mint(1, 2, 3, made_at);
        assert!(!expired(&body, made_at));
        assert!(!expired(&body, made_at + TICKET_TTL_MS - 1));
        assert!(expired(&body, made_at + TICKET_TTL_MS));
        assert!(expired(&body, u64::MAX));
        // A clock near its end does not wrap a ticket back to good
        assert!(!expired(&mint(1, 2, 3, u64::MAX - 1), u64::MAX - 1));
    }

    #[test]
    fn a_ticket_too_long_or_with_a_body_too_long_fails() {
        let key = ticket_key(SECRET);
        assert_eq!(open(&key, &[0; MAX_TICKET_BYTES + 1]), Err(Why::TooLong));
        // Sealed as a later pool version might: a field more after the body. The tag
        // holds, the body does not read whole.
        let mut longer = encode_ticket_body(&body()).unwrap();
        longer.push(9);
        let tag = hmac::sign(&key, &longer);
        let ticket = [longer, tag.as_ref().to_vec()].concat();
        assert_eq!(open(&key, &ticket), Err(Why::Malformed));
    }

    /// A core and an edge of different builds must agree. The bytes below come from
    /// Python's `hmac` over the construction in the doc, not from this code.
    #[test]
    fn proof_and_ticket_bytes_never_change_within_pool_v1() {
        assert_eq!(
            voipc_protocol::pool::POOL_VERSION,
            1,
            "a new pool version may change these"
        );
        let proof = proof(&proof_key(SECRET), &BINDING, "e1");
        assert_eq!(
            hex::encode(proof),
            "f5476178f9825305709c8f35b6e68043bf269f37702f084454dc80393764ba7f"
        );
        let ticket = seal(&ticket_key(SECRET), &mint(1, 2, 3, 4));
        assert_eq!(
            hex::encode(ticket),
            "010203b4ea01\
             8052cc02dff6e0caee7e74f9e9ccbe9a80491eba4fc61a5effbfb96e128a7343"
        );
    }
}
