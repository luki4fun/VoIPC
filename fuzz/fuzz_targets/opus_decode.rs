//! The browser's Opus decoder (rusty-opus in the mixer worklet) on arbitrary
//! packets in every mode: a peer controls these bytes, and the decoder is new.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_opus_wasm::fuzz_decode(data);
});
