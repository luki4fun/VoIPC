//! A viewer's record stream, grouped into frames and reassembled.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_protocol::fuzz::fuzz_video_assembly(data);
});
