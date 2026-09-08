//! A native viewer must decode what a browser sharer encodes.
//!
//! Firefox cannot encode H.264 through WebCodecs (Bugzilla 1918769), so a
//! Firefox sharer sends VP9 (VP8 as the fallback). Those come off WebCodecs as
//! bare frames — no container, no out-of-band configuration — which is exactly
//! what the fragments carry and what `Decoder` is handed. This pins that the
//! FFmpeg decoders accept them.
//!
//! The fixtures are real WebCodecs output, captured once from Firefox 155
//! (`VideoEncoder`, 64x64, `latencyMode: "realtime"`, first frame a keyframe).
//! Format: `[u32 BE length][frame]`, repeated.

#![cfg(not(target_os = "android"))]

use voipc_protocol::types::VideoCodec;
use voipc_video::decoder::Decoder;

fn frames(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= data.len() {
        let len = u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        assert!(off + len <= data.len(), "truncated fixture");
        out.push(&data[off..off + len]);
        off += len;
    }
    out
}

fn decodes(codec: VideoCodec, fixture: &[u8]) {
    let frames = frames(fixture);
    assert_eq!(frames.len(), 6, "{codec:?}: unexpected fixture");

    let mut decoder = Decoder::new(codec).unwrap();
    let mut decoded = 0;
    for (i, frame) in frames.iter().enumerate() {
        let out = decoder
            .decode(frame)
            .unwrap_or_else(|e| panic!("{codec:?}: frame {i} failed to decode: {e}"));
        for f in out {
            assert_eq!((f.width, f.height), (64, 64));
            // A frame of zeros would mean the decoder accepted the packet and
            // produced nothing usable — the failure this test exists to catch.
            assert!(
                f.i420_data.iter().any(|&b| b != 0),
                "{codec:?}: frame {i} decoded to all zeros"
            );
            decoded += 1;
        }
    }
    assert!(decoded >= 5, "{codec:?}: only {decoded} of 6 frames came out");
}

#[test]
fn decodes_firefox_vp9() {
    decodes(VideoCodec::Vp9, include_bytes!("data/firefox-vp9.bin"));
}

#[test]
fn decodes_firefox_vp8() {
    decodes(VideoCodec::Vp8, include_bytes!("data/firefox-vp8.bin"));
}
