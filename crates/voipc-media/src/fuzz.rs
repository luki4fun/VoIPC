//! Fuzz target: any bytes as a picture in every profile, and as a pack.
//! `fuzz/fuzz_targets/media.rs` calls it under cargo-fuzz; the test below
//! replays `fuzz/regressions/media/*` on stable.

use crate::{read_pack, sanitize, Profile};

pub fn fuzz_media(data: &[u8]) {
    for p in [Profile::Emote, Profile::Sticker, Profile::Photo] {
        if let Ok(clean) = sanitize(data, p) {
            // What this writes is read back the same
            let again = sanitize(&clean.png, p).expect("its own output reads");
            assert_eq!((again.w, again.h), (clean.w, clean.h));
        }
    }
    if let Ok(pack) = read_pack(data) {
        for e in pack.entries.iter().take(4) {
            let _ = sanitize(&e.bytes, Profile::Emote);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fuzz_target_replays_on_stable() {
        for input in [
            &[][..],
            &[0xff; 64],
            &[0; 64],
            b"\x89PNG\r\n\x1a\n",
            b"GIF89a",
            b"RIFF\0\0\0\0WEBP",
            b"PK\x05\x06",
        ] {
            fuzz_media(input);
        }
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions/media");
        for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            fuzz_media(&std::fs::read(file.path()).unwrap());
        }
    }
}
