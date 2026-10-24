//! A sender's sequence numbers in any order, through the jitter buffer.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_audio::fuzz::fuzz_jitter(data);
});
