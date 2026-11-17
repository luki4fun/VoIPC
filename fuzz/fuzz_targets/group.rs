//! The group key's openers, header decoder and Merkle path check, under fixed keys.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_crypto::fuzz::fuzz_group(data);
});
