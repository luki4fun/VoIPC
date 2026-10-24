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
