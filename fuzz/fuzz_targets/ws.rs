//! The TCP fallback's WebSocket frames, decoder and upgrade request.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_protocol::fuzz::fuzz_ws(data);
});
