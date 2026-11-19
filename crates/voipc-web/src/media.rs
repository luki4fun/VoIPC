//! Media packet helpers: AES-256-GCM voice, screen audio and video on top of
//! the voipc-protocol wire structs. Headers, nonces and AAD come from the
//! shared crates; this file only mirrors the native client's send and receive
//! paths (client/src-tauri/src/network.rs) so both ends agree byte for byte.
//! Plaintext media types are never produced and are rejected on receive.
//!
//! A received packet's key is looked up by its sender (`MediaKeyRing::get_for`): in a room
//! under the group epoch key each sender has its own, derived from the seat the room's roster
//! gives its session id and its stream id (spec §3.10); otherwise it is the room's, by the
//! generation the packet names, as before.

use anyhow::{bail, Context};
use voipc_crypto::{build_aad, media_decrypt, media_encrypt, MediaKey, MediaKeyRing};
use voipc_protocol::video::{
    fragment_frame, FrameAssembler, ScreenShareAudioPacket, VideoPacket, VideoPacketType,
    MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE, MAX_FRAGMENTS_PER_FRAME,
};
use voipc_protocol::voice::{PositionPayload, VoicePacket, VoicePacketType};

/// Packet type bytes that tag the AAD (and through it the nonce) per stream.
const ENCRYPTED_VOICE: u8 = VoicePacketType::EncryptedOpusVoice as u8;
const ENCRYPTED_SCREEN_AUDIO: u8 = VideoPacketType::EncryptedScreenShareAudio as u8;
const POSITION: u8 = VoicePacketType::Position as u8;

/// Encrypted voice packet (0x05) for one Opus frame.
pub fn build_voice_packet(
    keys: &MediaKeyRing,
    session_id: u32,
    sequence: u32,
    opus: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = keys.current().context("no media key for this channel")?;
    let stream = keys.stream_id();
    let aad = build_aad(key.channel_id, ENCRYPTED_VOICE, session_id);
    let encrypted = media_encrypt(key, stream, sequence, 0, &aad, opus)?;
    Ok(
        VoicePacket::encrypted_voice(session_id, sequence, key.key_id, stream, encrypted)
            .to_bytes(),
    )
}

pub fn build_eot_packet(session_id: u32, sequence: u32) -> Vec<u8> {
    VoicePacket::end_of_transmission(session_id, sequence).to_bytes()
}

pub fn build_ping_packet(session_id: u32, sequence: u32) -> Vec<u8> {
    VoicePacket::ping(session_id, sequence).to_bytes()
}

pub struct VoiceInfo {
    pub packet_type: u8,
    pub session_id: u32,
    pub sequence: u32,
    /// Decrypted Opus frame; present for encrypted voice only.
    pub opus: Option<Vec<u8>>,
}

/// The key a received packet names: its sender's (`session_id`, `stream`) under the group key,
/// else the room's; by the generation `key_id` names either way, so a rotation does not drop
/// what was already in flight.
fn key_for(
    keys: &mut MediaKeyRing,
    channel_id: u32,
    session_id: u32,
    stream: u32,
    key_id: u16,
) -> anyhow::Result<&MediaKey> {
    keys.get_for(channel_id, session_id, stream, key_id)
        .context("no media key for that generation")
}

/// Parses a voice-family packet. 0x02 (EOT), 0x03 (ping) and 0x04 (pong) are
/// header only; 0x05 is decrypted with `key`. Plaintext voice is rejected.
pub fn parse_voice_packet(
    keys: Option<&mut MediaKeyRing>,
    channel_id: u32,
    bytes: &[u8],
) -> anyhow::Result<VoiceInfo> {
    let packet = VoicePacket::from_bytes(bytes)?;
    let opus = match packet.packet_type {
        VoicePacketType::EncryptedOpusVoice => {
            let keys = keys.context("encrypted voice but no media key")?;
            let key = key_for(
                keys,
                channel_id,
                packet.session_id,
                packet.stream_id,
                packet.key_id,
            )?;
            let aad = build_aad(key.channel_id, ENCRYPTED_VOICE, packet.session_id);
            Some(media_decrypt(
                key,
                packet.stream_id,
                packet.sequence,
                0,
                &aad,
                &packet.opus_data,
            )?)
        }
        VoicePacketType::EndOfTransmission | VoicePacketType::Ping | VoicePacketType::Pong => None,
        VoicePacketType::OpusVoice => bail!("plaintext voice packet rejected"),
        VoicePacketType::Position => bail!("position packet is not voice"),
    };
    Ok(VoiceInfo {
        packet_type: packet.packet_type as u8,
        session_id: packet.session_id,
        sequence: packet.sequence,
        opus,
    })
}

/// Encrypted position beacon (0x06). Same shape as the native client's
/// `network::send_position`: the channel key, its own sequence counter and a
/// packet-type byte in the AAD that keeps positions in their own nonce domain.
pub fn build_position_packet(
    keys: &MediaKeyRing,
    session_id: u32,
    sequence: u32,
    x: f32,
    y: f32,
    z: f32,
) -> anyhow::Result<Vec<u8>> {
    let key = keys.current().context("no media key for this channel")?;
    let stream = keys.stream_id();
    let aad = build_aad(key.channel_id, POSITION, session_id);
    let payload = PositionPayload { x, y, z };
    let encrypted = media_encrypt(key, stream, sequence, 0, &aad, &payload.to_bytes())?;
    Ok(VoicePacket::position(session_id, sequence, key.key_id, stream, encrypted).to_bytes())
}

pub struct PositionInfo {
    pub session_id: u32,
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

/// Decrypts a position beacon (0x06); any other packet type is an error.
pub fn parse_position_packet(
    keys: &mut MediaKeyRing,
    channel_id: u32,
    bytes: &[u8],
) -> anyhow::Result<PositionInfo> {
    let packet = VoicePacket::from_bytes(bytes)?;
    if packet.packet_type != VoicePacketType::Position {
        bail!("not a position packet");
    }
    let key = key_for(
        keys,
        channel_id,
        packet.session_id,
        packet.stream_id,
        packet.key_id,
    )?;
    let aad = build_aad(key.channel_id, POSITION, packet.session_id);
    let plaintext = media_decrypt(
        key,
        packet.stream_id,
        packet.sequence,
        0,
        &aad,
        &packet.opus_data,
    )?;
    let payload = PositionPayload::from_bytes(&plaintext)?;
    Ok(PositionInfo {
        session_id: packet.session_id,
        x: payload.x,
        y: payload.y,
        z: payload.z,
    })
}

/// Encrypted screen-share audio packet (0x15) for one Opus frame — the send
/// side of [`parse_screen_audio_packet`], mirroring the native sharer's
/// `AudioProcessor` (client/src-tauri/src/screenshare/mod.rs).
pub fn build_screen_audio_packet(
    keys: &MediaKeyRing,
    session_id: u32,
    sequence: u32,
    timestamp: u32,
    opus: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = keys.current().context("no media key for this channel")?;
    let stream = keys.stream_id();
    let aad = build_aad(key.channel_id, ENCRYPTED_SCREEN_AUDIO, session_id);
    let encrypted = media_encrypt(key, stream, sequence, 0, &aad, opus)?;
    Ok(ScreenShareAudioPacket::new_encrypted(
        session_id, sequence, timestamp, key.key_id, stream, encrypted,
    )
    .to_bytes())
}

/// One encoded video frame as the body of a per-frame stream: fragmented,
/// each fragment encrypted, each prefixed with its `u16` big-endian length —
/// what the server's `RecordReader` expects and what the native sharer writes
/// (client/src-tauri/src/screenshare/mod.rs `send_encoded_frames`).
///
/// Fails for a frame that needs more than 255 fragments (~316 KB) instead of
/// truncating it: a truncated frame would leave every viewer's decoder stuck.
pub fn build_video_frame_stream(
    keys: &MediaKeyRing,
    session_id: u32,
    frame_id: u32,
    timestamp: u32,
    is_keyframe: bool,
    frame: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let needed = frame.len().div_ceil(MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE);
    if needed > MAX_FRAGMENTS_PER_FRAME {
        bail!(
            "frame of {} bytes needs {needed} fragments, more than the {MAX_FRAGMENTS_PER_FRAME} the wire format allows",
            frame.len()
        );
    }

    let key = keys.current().context("no media key for this channel")?;
    let stream = keys.stream_id();
    let packet_type = if is_keyframe { 0x14u8 } else { 0x13u8 };
    let aad = build_aad(key.channel_id, packet_type, session_id);
    let mut out = Vec::with_capacity(frame.len() + needed * 64);
    for pkt in fragment_frame(
        frame,
        is_keyframe,
        session_id,
        frame_id,
        timestamp,
        MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE,
    ) {
        let encrypted = media_encrypt(
            key,
            stream,
            frame_id,
            pkt.fragment_index as u32,
            &aad,
            &pkt.payload,
        )?;
        let bytes = VideoPacket::encrypted_fragment(
            is_keyframe,
            session_id,
            frame_id,
            pkt.fragment_index,
            pkt.fragment_count,
            timestamp,
            key.key_id,
            stream,
            encrypted,
        )
        .to_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

pub struct ScreenAudioInfo {
    pub session_id: u32,
    pub sequence: u32,
    /// Milliseconds since the share started (same clock as video timestamps).
    pub timestamp: u32,
    pub opus: Vec<u8>,
}

/// Parses and decrypts an encrypted screen-share audio packet (0x15).
pub fn parse_screen_audio_packet(
    keys: &mut MediaKeyRing,
    channel_id: u32,
    bytes: &[u8],
) -> anyhow::Result<ScreenAudioInfo> {
    let packet = ScreenShareAudioPacket::from_bytes(bytes)?;
    if !packet.encrypted {
        bail!("plaintext screen audio packet rejected");
    }
    let key = key_for(
        keys,
        channel_id,
        packet.session_id,
        packet.stream_id,
        packet.key_id,
    )?;
    let aad = build_aad(key.channel_id, ENCRYPTED_SCREEN_AUDIO, packet.session_id);
    let opus = media_decrypt(
        key,
        packet.stream_id,
        packet.sequence,
        0,
        &aad,
        &packet.opus_data,
    )?;
    Ok(ScreenAudioInfo {
        session_id: packet.session_id,
        sequence: packet.sequence,
        timestamp: packet.timestamp,
        opus,
    })
}

pub struct VideoPush {
    /// The reassembled frame when this fragment completed one.
    pub frame: Option<Vec<u8>>,
    /// The completed frame's flag, or the fragment's while still assembling.
    pub is_keyframe: bool,
    /// The fragment's timestamp: milliseconds since the share started.
    pub timestamp: u32,
    /// An earlier frame was lost (incomplete or missing entirely); the caller
    /// should request a keyframe.
    pub frame_dropped: bool,
}

/// Reassembles encrypted video fragments (0x13/0x14) into whole frames.
#[derive(Default)]
pub struct VideoAssemblerCore {
    assembler: FrameAssembler,
    /// Sharer session the fragments belong to; a change resets the assembler.
    current_session: Option<u32>,
}

impl VideoAssemblerCore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(
        &mut self,
        keys: &mut MediaKeyRing,
        channel_id: u32,
        bytes: &[u8],
    ) -> anyhow::Result<VideoPush> {
        let mut packet = VideoPacket::from_bytes(bytes)?;
        let packet_type = packet.packet_type;
        if !matches!(
            packet_type,
            VideoPacketType::EncryptedVideoFragment
                | VideoPacketType::EncryptedVideoKeyframeFragment
        ) {
            bail!(
                "not an encrypted video fragment: 0x{:02x}",
                packet_type as u8
            );
        }

        // Nonce: the sender's own stream id, frame id as the sequence,
        // fragment index as the extra; the AAD binds the channel and the exact
        // packet type byte.
        let key = key_for(
            keys,
            channel_id,
            packet.session_id,
            packet.stream_id,
            packet.key_id,
        )?;
        let aad = build_aad(key.channel_id, packet_type as u8, packet.session_id);
        packet.payload = media_decrypt(
            key,
            packet.stream_id,
            packet.frame_id,
            packet.fragment_index as u32,
            &aad,
            &packet.payload,
        )?;

        if self.current_session != Some(packet.session_id) {
            self.assembler.reset();
            self.current_session = Some(packet.session_id);
        }

        let result = self.assembler.add_fragment(&packet);
        let (frame, is_keyframe) = match result.frame {
            Some((data, is_keyframe)) => (Some(data), is_keyframe),
            None => (None, packet_type.is_keyframe()),
        };
        Ok(VideoPush {
            frame,
            is_keyframe,
            timestamp: packet.timestamp,
            frame_dropped: result.frame_dropped,
        })
    }

    pub fn reset(&mut self) {
        self.assembler.reset();
        self.current_session = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voipc_crypto::group_key::MemberId;
    use voipc_crypto::group_state::VoiceKeys;
    use voipc_protocol::video::stream_records;

    const ROOM: u32 = 7;

    /// User `own`'s ring in a room under the group key, as `gkVoiceInto` fills it: one
    /// epoch, users 1, 2 and 3 seated by their connections' pairs.
    fn seated(own: u32) -> MediaKeyRing {
        let seat = |u: u32| (u, MemberId::Conn(u), [u as u8; 8]);
        let keys = VoiceKeys {
            channel_id: ROOM,
            group: format!("r:{}:{ROOM}", "ab".repeat(16)),
            gen: [1; 16],
            epochs: vec![(1, [1; 32], [2; 32].into())],
            own: (MemberId::Conn(own), [own as u8; 8]),
            seats: (1..=3).map(seat).collect(),
            switch_at: 0,
            new_generation: true,
        };
        let mut ring = MediaKeyRing::default();
        assert!(ring.install_gk(&keys, ROOM));
        ring
    }

    /// Every kind of packet alice (user 1) sends, as the page builds them.
    fn sent_by(alice: &MediaKeyRing) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            build_voice_packet(alice, 1, 10, b"voice").unwrap(),
            build_position_packet(alice, 1, 11, 1.0, 2.0, 3.0).unwrap(),
            build_screen_audio_packet(alice, 1, 12, 40, b"share audio").unwrap(),
            build_video_frame_stream(alice, 1, 13, 50, true, &[9; 3000]).unwrap(),
        )
    }

    /// Whether `ring` opens every one of them.
    fn opens_all(ring: &mut MediaKeyRing, packets: &(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)) -> bool {
        let (voice, position, audio, video) = packets;
        let mut assembler = VideoAssemblerCore::new();
        let frame = stream_records(video)
            .into_iter()
            .map(|r| assembler.push(ring, ROOM, r).ok().and_then(|p| p.frame))
            .last()
            .flatten();
        parse_voice_packet(Some(ring), ROOM, voice)
            .is_ok_and(|v| v.opus.as_deref() == Some(b"voice"))
            && parse_position_packet(ring, ROOM, position).is_ok_and(|p| (p.x, p.z) == (1.0, 3.0))
            && parse_screen_audio_packet(ring, ROOM, audio).is_ok_and(|a| a.opus == b"share audio")
            && frame.is_some_and(|f| f == [9; 3000])
    }

    /// Spec §3.10: under the group key a receiver opens voice, beacons, share audio and video
    /// with the key it derives for the sender, from the seat the roster gives the packet's
    /// session id and its stream id. A sender the roster does not seat opens nothing.
    #[test]
    fn under_the_group_key_each_packet_opens_with_its_senders_own_key() {
        let alice = seated(1);
        let packets = sent_by(&alice);
        assert!(opens_all(&mut seated(2), &packets));
        assert!(opens_all(&mut seated(3), &packets));

        // Carol holds the epoch key, but nobody's roster seats her
        let mut carol = seated(4);
        let not_seated = sent_by(&carol);
        let mut bob = seated(2);
        let (voice, ..) = &not_seated;
        assert!(parse_voice_packet(Some(&mut bob), ROOM, voice).is_err());
        assert!(!opens_all(&mut bob, &not_seated));
        assert!(
            opens_all(&mut carol, &packets),
            "while she holds the room's epoch key"
        );
    }

    /// With no group key (no `GroupKeys`, or the switch off) a packet opens with the room's
    /// key by its generation, as before; and a ring under the group key opens no packet of
    /// the old kind.
    #[test]
    fn outside_the_group_key_packets_open_with_the_rooms_key_as_before() {
        let old = |key_id| {
            let mut ring = MediaKeyRing::default();
            assert!(ring.install(MediaKey::new(ROOM, key_id, 1, [5; 32]), ROOM));
            ring
        };
        let packets = sent_by(&old(3));
        assert!(opens_all(&mut old(3), &packets));
        assert!(!opens_all(&mut old(4), &packets), "another generation");
        assert!(!opens_all(&mut seated(2), &packets));
        assert!(!opens_all(&mut old(1), &sent_by(&seated(1))));
    }
}
