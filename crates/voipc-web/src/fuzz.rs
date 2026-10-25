//! Fuzz target: media packets as the relay hands them to the browser, through
//! the wasm crate's parsers and its video reassembly. `fuzz/fuzz_targets/
//! web_media.rs` calls it under cargo-fuzz; the test below replays
//! `fuzz/regressions/web_media/*` on stable.

use crate::media::{self, VideoAssemblerCore};
use voipc_crypto::{MediaKey, MediaKeyRing};

/// One fixed key installed, so the decrypting paths are reached; the input is
/// one packet for every parser, then the same bytes cut into video fragments.
pub fn fuzz_web_media(data: &[u8]) {
    let mut keys = MediaKeyRing::default();
    keys.install(MediaKey::new(1, 1, 7, [9; 32]), 1);
    let _ = media::parse_voice_packet(Some(&keys), 1, data);
    let _ = media::parse_voice_packet(None, 1, data);
    let _ = media::parse_position_packet(&keys, 1, data);
    let _ = media::parse_screen_audio_packet(&keys, 1, data);
    let mut video = VideoAssemblerCore::new();
    for chunk in data.chunks(data.first().map_or(1, |&b| b.max(16) as usize)) {
        let _ = video.push(&keys, 1, chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fuzz_target_replays_on_stable() {
        for input in [&[][..], &[0xff; 64], &[0; 64], &[0x05; 300]] {
            fuzz_web_media(input);
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/regressions/web_media");
        for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            fuzz_web_media(&std::fs::read(file.path()).unwrap());
        }
    }
}
