//! Log keys and pins out of vault items, and a typed recovery key.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_crypto::fuzz::fuzz_keys(data);
});
