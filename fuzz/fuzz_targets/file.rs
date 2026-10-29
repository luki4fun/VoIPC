//! File blobs from the relay, and the sizes and deflate flags their messages
//! claim, under a fixed key.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_crypto::fuzz::fuzz_file(data);
});
