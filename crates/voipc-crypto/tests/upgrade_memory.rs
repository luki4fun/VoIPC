//! The browser keeps each account's log memory as JSON in localStorage
//! (`voipc.cursors.<relay hex>|<name>`). `fixtures/0.12.0/log_memory.json` was
//! written once by 0.12.0's voipc-crypto (2026-10-23, from 49bf256) and is
//! never regenerated: it must read, every field kept, or a browser that
//! upgrades reads its kept messages again from the start.

use voipc_crypto::sync::LogMemory;

#[test]
fn a_0_12_log_memory_still_reads() {
    let memory: LogMemory =
        serde_json::from_str(include_str!("fixtures/0.12.0/log_memory.json")).unwrap();
    assert_eq!(memory.cursors.get("d:0101"), Some(&5));
    assert_eq!(memory.readers.get("c:abcd"), Some(&vec![[2u8; 16]]));
    assert!(memory.vault_gens.is_empty());
}

/// 1.11 added the bucket lists a device has named (`named`); its JSON, written
/// once by 1.11's voipc-crypto (`fixtures/1.11.0/`, see its README).
#[test]
fn a_1_11_log_memory_still_reads() {
    let memory: LogMemory =
        serde_json::from_str(include_str!("fixtures/1.11.0/log_memory.json")).unwrap();
    assert_eq!(memory.cursors.get("c:abcd"), Some(&9));
    assert_eq!(memory.readers.get("c:abcd"), Some(&vec![[2u8; 16]]));
    assert_eq!(memory.vault_gens.get("item.pins"), Some(&7));
    assert_eq!(memory.vault_gens.get("pins.0"), Some(&2));
    assert_eq!(memory.named.get("c:abcd"), Some(&vec![[0x3cu8; 32]]));
}
