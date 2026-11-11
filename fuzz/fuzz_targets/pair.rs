//! What a pairing's frames carry, from the relay or the other device.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_crypto::fuzz::fuzz_pair(data);
});
