//! What a game mod sends over the SDK socket, and a MumbleLink block.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_audio::fuzz::fuzz_game(data);
});
