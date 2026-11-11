//! A sign-in bound to the connection it travels on (protocol v22).
//!
//! Each side reads an exporter (RFC 5705, `EXPORTER_LABEL`, 32 bytes) from its own TLS 1.3
//! session: the app from its QUIC or TCP connection, the relay from its end of the same one.
//! Every proof a sign-in sends ends in that value (`|tls|…`). A server that passes a sign-in
//! on to another relay holds two TLS sessions, one with the app and one with the relay, and
//! the two values differ: what the app signed does not check out at the relay, and the
//! provider codes (`provider_code`) on the app and the relay's page do not match.
//!
//! A browser cannot read its TLS session. Its proofs end in `|web`, which an app never
//! makes: a forwarder gets one only from a browser that connected to it (THREAT-MODEL).

use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use voipc_protocol::conv::hex;

/// The exporter's label. No context.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-voipc-bind";
/// The exporter's length.
pub const BIND_LEN: usize = 32;

/// What a proof is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// This connection's exporter.
    Tls([u8; BIND_LEN]),
    /// A browser's: nothing it can read.
    Web,
}

impl Binding {
    /// The wire's `web`.
    pub fn web(&self) -> bool {
        matches!(self, Binding::Web)
    }

    /// The relay's side: what a proof that says `web` is bound to, on a connection whose
    /// exporter is `ours`. None: a `tls` proof on a connection without one, which nothing
    /// checks out against.
    pub fn claimed(web: bool, ours: Option<[u8; BIND_LEN]>) -> Option<Binding> {
        if web {
            Some(Binding::Web)
        } else {
            ours.map(Binding::Tls)
        }
    }
}

/// `kind|relay|name|hex(part)…|tls|hex(exporter)` or `…|web`. Hex keeps every field free
/// of the separator.
pub(crate) fn message(
    kind: &str,
    relay_id: &[u8; 16],
    name: &str,
    parts: &[&[u8]],
    b: &Binding,
) -> Vec<u8> {
    let mut m = format!(
        "{kind}|{}|{}",
        hex(relay_id),
        name.trim().to_ascii_lowercase()
    );
    for p in parts {
        m.push('|');
        m.push_str(&hex(p));
    }
    match b {
        Binding::Tls(x) => {
            m.push_str("|tls|");
            m.push_str(&hex(x));
        }
        Binding::Web => m.push_str("|web"),
    }
    m.into_bytes()
}

pub(crate) fn ed25519_ok(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    public_key.len() == 32
        && UnparsedPublicKey::new(&ED25519, public_key)
            .verify(msg, signature)
            .is_ok()
}

/// What a device key signs beside l4f's message: the device and the challenge, bound.
pub(crate) fn devkey_message(
    relay_id: &[u8; 16],
    device_id: &[u8],
    challenge: &str,
    b: &Binding,
) -> Vec<u8> {
    message(
        "voipc-devkey/v1",
        relay_id,
        "",
        &[device_id, challenge.as_bytes()],
        b,
    )
}

/// The relay's check of a device key's `bind`, against the key l4f keeps for `device_id`.
pub fn devkey_ok(
    public_key: &[u8],
    relay_id: &[u8; 16],
    device_id: &[u8],
    challenge: &str,
    b: &Binding,
    signature: &[u8],
) -> bool {
    ed25519_ok(
        public_key,
        &devkey_message(relay_id, device_id, challenge, b),
        signature,
    )
}

/// What the login key signs: the relay's challenge for this account, bound.
pub(crate) fn login_message(
    relay_id: &[u8; 16],
    name: &str,
    challenge: &str,
    b: &Binding,
) -> Vec<u8> {
    message("voipc-login/v1", relay_id, name, &[challenge.as_bytes()], b)
}

/// The relay's check of a login key's answer, against the key it keeps for the account.
pub fn login_ok(
    public_key: &[u8],
    relay_id: &[u8; 16],
    name: &str,
    challenge: &str,
    b: &Binding,
    signature: &[u8],
) -> bool {
    ed25519_ok(
        public_key,
        &login_message(relay_id, name, challenge, b),
        signature,
    )
}

/// What the identity signs over a new login key, and the slot that comes with it.
pub(crate) fn login_key_message(
    relay_id: &[u8; 16],
    name: &str,
    login_key: &[u8],
    pass_slot: Option<&[u8]>,
    b: &Binding,
) -> Vec<u8> {
    let slot: &[u8] = pass_slot.unwrap_or_default();
    let has: &[u8] = if pass_slot.is_some() { b"slot" } else { b"-" };
    message(
        "voipc-login-key/v1",
        relay_id,
        name,
        &[login_key, has, slot],
        b,
    )
}

/// What a reset signs, by the identity (`kind` v3) or the reset key (v4).
pub(crate) fn reset_message(
    kind: &str,
    relay_id: &[u8; 16],
    name: &str,
    challenge: &[u8],
    login_key: &[u8],
    b: &Binding,
) -> Vec<u8> {
    message(kind, relay_id, name, &[challenge, login_key], b)
}

/// The six digits a provider's sign-in shows on the app and on the relay's page. Each side
/// derives them from its own exporter: through a forwarder they differ. Six, because a
/// forwarder knows both exporters and could start flows at the relay until the two agree.
pub fn provider_code(exporter: &[u8; BIND_LEN], ticket: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"voipc-provider-code/v1|");
    h.update(exporter);
    h.update(b"|");
    h.update(ticket);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: [u8; 16] = [7; 16];

    #[test]
    fn a_message_names_what_it_is_bound_to() {
        let tls = message("k", &RELAY, " Luki ", &[b"ab"], &Binding::Tls([1; 32]));
        let web = message("k", &RELAY, "luki", &[b"ab"], &Binding::Web);
        let tls = String::from_utf8(tls).unwrap();
        assert_eq!(
            tls,
            format!("k|{}|luki|6162|tls|{}", "07".repeat(16), "01".repeat(32))
        );
        assert_eq!(
            String::from_utf8(web).unwrap(),
            format!("k|{}|luki|6162|web", "07".repeat(16))
        );
        // Another exporter is another message
        assert_ne!(
            message("k", &RELAY, "luki", &[b"ab"], &Binding::Tls([1; 32])),
            message("k", &RELAY, "luki", &[b"ab"], &Binding::Tls([2; 32]))
        );
    }

    #[test]
    fn a_relay_checks_a_tls_proof_only_with_its_own_exporter() {
        assert_eq!(Binding::claimed(true, None), Some(Binding::Web));
        assert_eq!(Binding::claimed(true, Some([3; 32])), Some(Binding::Web));
        assert_eq!(
            Binding::claimed(false, Some([3; 32])),
            Some(Binding::Tls([3; 32]))
        );
        assert_eq!(Binding::claimed(false, None), None);
    }

    #[test]
    fn a_provider_code_is_six_digits_and_differs_across_sessions() {
        let a = provider_code(&[1; 32], &[9; 32]);
        assert_eq!(a.len(), 6);
        assert!(a.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(a, provider_code(&[1; 32], &[9; 32]));
        // Over many sessions, the codes spread out: a forwarder cannot pick one
        let codes: std::collections::BTreeSet<_> = (0..200u8)
            .map(|i| provider_code(&[i; 32], &[9; 32]))
            .collect();
        assert!(codes.len() > 195, "{}", codes.len());
    }
}
