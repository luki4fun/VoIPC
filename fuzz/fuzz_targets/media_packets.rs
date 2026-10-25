//! Voice, position, video and screen-audio packets as the relay forwards them.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_protocol::fuzz::fuzz_media_packets(data);
});
