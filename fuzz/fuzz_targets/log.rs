//! Kept entries and epoch-key wraps from the relay, under fixed keys.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_crypto::fuzz::fuzz_log(data);
});
