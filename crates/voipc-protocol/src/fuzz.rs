//! Fuzz targets: bytes a peer or the relay controls, through every parser of
//! this crate. `fuzz/fuzz_targets/<name>.rs` calls `fuzz_<name>` under
//! cargo-fuzz; the test below replays `fuzz/regressions/<name>/*` on stable,
//! so an input that once crashed stays a test.

use crate::{codec, video, voice, ws};
use bytes::BytesMut;

/// Client and server messages, and the length-prefixed frames around them.
pub fn fuzz_codec(data: &[u8]) {
    let _ = codec::decode_client_msg(data);
    let _ = codec::decode_server_msg(data);
    let mut buf = BytesMut::from(data);
    loop {
        let before = buf.len();
        match codec::try_decode_frame(&mut buf) {
            Ok(Some(_)) => assert!(
                buf.len() < before,
                "a frame was read without consuming bytes"
            ),
            _ => break,
        }
    }
}

/// Voice, position, video and screen-audio packets as the relay forwards them.
pub fn fuzz_media_packets(data: &[u8]) {
    if let Ok(p) = voice::VoicePacket::from_bytes(data) {
        p.to_bytes();
    }
    let _ = voice::PositionPayload::from_bytes(data);
    if let Ok(p) = video::VideoPacket::from_bytes(data) {
        p.to_bytes();
    }
    if let Ok(p) = video::ScreenShareAudioPacket::from_bytes(data) {
        p.to_bytes();
    }
    for record in video::stream_records(data) {
        assert!(record.len() <= video::MAX_STREAM_RECORD_SIZE);
    }
}

/// A viewer's side of a share: length-prefixed records off a QUIC stream, in
/// two reads (so a record split across reads is covered), grouped by frame
/// and reassembled.
pub fn fuzz_video_assembly(data: &[u8]) {
    let mut reader = video::RecordReader::default();
    let mut grouper = video::FrameGrouper::default();
    let mut assembler = video::FrameAssembler::new();
    let cut = data.first().map_or(0, |&b| b as usize % (data.len() + 1));
    for part in [&data[..cut], &data[cut..]] {
        for record in reader.push(part) {
            let _ = grouper.place(&record);
            if let Ok(packet) = video::VideoPacket::from_bytes(&record) {
                if let Some((frame, _)) = assembler.add_fragment(&packet).frame {
                    assert!(
                        frame.len()
                            <= video::MAX_FRAGMENTS_PER_FRAME * video::MAX_VIDEO_PACKET_SIZE
                    );
                }
            }
        }
    }
}

/// The TCP fallback's WebSocket: a frame in either direction, the decoder
/// that strings frames into messages, and the upgrade request.
pub fn fuzz_ws(data: &[u8]) {
    const MAX: usize = 64 * 1024;
    for from_client in [true, false] {
        if let Ok(Some((_, used))) = ws::parse_frame(data, from_client, MAX) {
            assert!(used <= data.len());
        }
        let mut decoder = ws::Decoder::new(from_client, MAX);
        decoder.feed(data);
        while let Ok(Some(_)) = decoder.next() {}
    }
    let head = &data[..data.len().min(8192)];
    if let Some(end) = ws::find_header_end(head) {
        if let Ok(text) = std::str::from_utf8(&head[..end]) {
            let _ = ws::parse_upgrade(text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Edge inputs, a valid one, and every file in fuzz/regressions/<target>/.
    fn replay(target: &str, valid: &[u8], f: fn(&[u8])) {
        for input in [&[][..], &[0xff; 64], &[0; 64], valid] {
            f(input);
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/regressions")
            .join(target);
        for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            f(&std::fs::read(file.path()).unwrap());
        }
    }

    #[test]
    fn the_fuzz_targets_replay_on_stable() {
        let packets =
            video::fragment_frame(&[7; 3000], true, 1, 2, 3, video::MAX_VIDEO_PAYLOAD_SIZE);
        let records: Vec<u8> = packets
            .iter()
            .flat_map(|p| {
                let b = p.to_bytes();
                [(b.len() as u16).to_be_bytes().to_vec(), b].concat()
            })
            .collect();
        let ping = codec::encode_client_msg(&crate::messages::ClientMessage::Ping { timestamp: 1 })
            .unwrap();
        replay("codec", &ping, fuzz_codec);
        replay(
            "media_packets",
            &voice::VoicePacket::voice(1, 2, vec![1, 2, 3]).to_bytes(),
            fuzz_media_packets,
        );
        replay("video_assembly", &records, fuzz_video_assembly);
        replay(
            "ws",
            b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            fuzz_ws,
        );
    }
}
