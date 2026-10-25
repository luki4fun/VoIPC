//! What a channel member sends inside a Signal message: chat, history, media keys.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_crypto::fuzz::fuzz_envelope(data);
});
