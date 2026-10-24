//! Vault slots and items as the relay hands them out.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_crypto::fuzz::fuzz_vault(data);
});
