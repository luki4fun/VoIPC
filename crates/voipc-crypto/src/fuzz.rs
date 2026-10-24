//! Fuzz targets: bytes another account or the relay controls, through the
//! parsers in front of each AEAD and signature check. `fuzz/fuzz_targets/
//! <name>.rs` calls `fuzz_<name>` under cargo-fuzz; the test below replays
//! `fuzz/regressions/<name>/*` on stable, so an input that once crashed stays
//! a test. Keys are fixed, so a crash replays the same way.

use crate::account::{self, Pins, Vault};
use crate::log::{self, LogKey};
use crate::{envelope, MediaKey};
use voipc_protocol::types::VaultBlob;

const RELAY: [u8; 16] = [0x5a; 16];

/// What a channel member sends inside a Signal message: chat envelopes,
/// history payloads (JSON) and media keys.
pub fn fuzz_envelope(data: &[u8]) {
    let _ = envelope::open_envelope(data);
    let _ = envelope::open_history_payload(1, data);
    let _ = MediaKey::from_bytes(data);
}

/// Keys and pins out of vault items, and a typed recovery key.
pub fn fuzz_keys(data: &[u8]) {
    let _ = LogKey::from_bytes(data);
    let _ = Pins::from_bytes(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = account::recovery_parse(text);
    }
}

/// Kept entries and epoch-key wraps from the relay: the first byte splits the
/// input into the sender's published log key and the sealed bytes.
pub fn fuzz_log(data: &[u8]) {
    let own = LogKey::from_bytes(&[0x11; 32]).expect("a fixed private key");
    let (sender_logkey, sealed) = match data.split_first() {
        Some((&n, rest)) => rest.split_at((n as usize).min(rest.len())),
        None => (&[][..], data),
    };
    let _ = log::open_entry(&[7; 32], "c:fuzz", &[1; 16], 1, sender_logkey, sealed);
    let _ = log::unwrap(&own, data, "c:fuzz", &[1; 16], 1, &[2; 16]);
    let _ = log::self_unwrap(&own, data, "c:fuzz", &[2; 16], 1);
}

/// Vault blobs as the relay hands them out: a slot opened with a fixed vault
/// key (no password stretching per input), and an item under a fixed DEK.
pub fn fuzz_vault(data: &[u8]) {
    let blobs: Vec<VaultBlob> = ["slot.pass", "item.fuzz"]
        .iter()
        .map(|k| VaultBlob { k: (*k).into(), v: data.to_vec(), version: 0 })
        .collect();
    let _ = Vault::open_with_password(RELAY, "fuzz", &blobs, &[7; 32]);
    let _ = Vault::from_dek(RELAY, "fuzz", [7; 32]).open_item(&blobs, "item.fuzz");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Edge inputs, a valid one, and every file in fuzz/regressions/<target>/.
    fn replay(target: &str, valid: &[u8], f: fn(&[u8])) {
        for input in [&[][..], &[0xff; 64], &[0; 64], valid] {
            f(input);
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/regressions")
            .join(target);
        for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            f(&std::fs::read(file.path()).unwrap());
        }
    }

    #[test]
    fn the_fuzz_targets_replay_on_stable() {
        let vault = Vault::from_dek(RELAY, "fuzz", [7; 32]);
        replay("envelope", br#"{"v":1,"kind":"chat","text":"hi"}"#, fuzz_envelope);
        replay("keys", &[0x11; 32], fuzz_keys);
        replay("log", &[33; 64], fuzz_log);
        replay("vault", &vault.seal_item("item.fuzz", 1, b"payload").v, fuzz_vault);
    }
}
