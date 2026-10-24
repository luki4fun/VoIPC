//! Peer Opus packets through the native decoder.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_audio::fuzz::fuzz_opus(data);
});
