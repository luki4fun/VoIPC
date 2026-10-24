//! Client and server messages, and the frames around them (relay ↔ client).
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_protocol::fuzz::fuzz_codec(data);
});
