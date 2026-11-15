//! An older relay's messages, through compat, for each protocol the app still talks to.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_protocol::fuzz::fuzz_compat(data);
});
