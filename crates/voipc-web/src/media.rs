//! Media packet helpers: AES-256-GCM voice, screen audio and video on top of
//! the voipc-protocol wire structs. Headers, nonces and AAD come from the
//! shared crates; this file only mirrors the native client's send and receive
//! paths (client/src-tauri/src/network.rs) so both ends agree byte for byte.
//! Plaintext media types are never produced and are rejected on receive.

use anyhow::{bail, Context};
use voipc_crypto::{build_aad, media_decrypt, media_encrypt, MediaKey};
use voipc_protocol::video::{
    FrameAssembler, ScreenShareAudioPacket, VideoPacket, VideoPacketType,
};
use voipc_protocol::voice::{VoicePacket, VoicePacketType};

/// Packet type bytes that tag the AAD (and through it the nonce) per stream.
const ENCRYPTED_VOICE: u8 = VoicePacketType::EncryptedOpusVoice as u8;
const ENCRYPTED_SCREEN_AUDIO: u8 = VideoPacketType::EncryptedScreenShareAudio as u8;

/// Encrypted voice packet (0x05) for one Opus frame.
pub fn build_voice_packet(
    key: &MediaKey,
    session_id: u32,
    sequence: u32,
    opus: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let aad = build_aad(key.channel_id, ENCRYPTED_VOICE);
    let encrypted = media_encrypt(key, session_id, sequence, 0, &aad, opus)?;
    Ok(VoicePacket::encrypted_voice(session_id, sequence, key.key_id, encrypted).to_bytes())
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

/// Parses a voice-family packet. 0x02 (EOT), 0x03 (ping) and 0x04 (pong) are
/// header only; 0x05 is decrypted with `key`. Plaintext voice is rejected.
pub fn parse_voice_packet(key: Option<&MediaKey>, bytes: &[u8]) -> anyhow::Result<VoiceInfo> {
    let packet = VoicePacket::from_bytes(bytes)?;
    let opus = match packet.packet_type {
        VoicePacketType::EncryptedOpusVoice => {
            let key = key.context("encrypted voice but no media key")?;
            let aad = build_aad(key.channel_id, ENCRYPTED_VOICE);
            Some(media_decrypt(
                key,
                packet.session_id,
                packet.sequence,
                0,
                &aad,
                &packet.opus_data,
            )?)
        }
        VoicePacketType::EndOfTransmission | VoicePacketType::Ping | VoicePacketType::Pong => {
            None
        }
        VoicePacketType::OpusVoice => bail!("plaintext voice packet rejected"),
    };
    Ok(VoiceInfo {
        packet_type: packet.packet_type as u8,
        session_id: packet.session_id,
        sequence: packet.sequence,
        opus,
    })
}

pub struct ScreenAudioInfo {
    pub session_id: u32,
    pub sequence: u32,
    /// Milliseconds since the share started (same clock as video timestamps).
    pub timestamp: u32,
    pub opus: Vec<u8>,
}

/// Parses and decrypts an encrypted screen-share audio packet (0x15).
pub fn parse_screen_audio_packet(key: &MediaKey, bytes: &[u8]) -> anyhow::Result<ScreenAudioInfo> {
    let packet = ScreenShareAudioPacket::from_bytes(bytes)?;
    if !packet.encrypted {
        bail!("plaintext screen audio packet rejected");
    }
    let aad = build_aad(key.channel_id, ENCRYPTED_SCREEN_AUDIO);
    let opus = media_decrypt(
        key,
        packet.session_id,
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
    /// The reassembled H.265 frame when this fragment completed one.
    pub frame: Option<Vec<u8>>,
    /// The completed frame's flag, or the fragment's while still assembling.
    pub is_keyframe: bool,
    /// The fragment's timestamp: milliseconds since the share started.
    pub timestamp: u32,
    /// An earlier frame was lost (incomplete or missing entirely); the caller
    /// should request a keyframe.
    pub frame_dropped: bool,
}

/// Reassembles encrypted video fragments (0x13/0x14) into H.265 frames.
pub struct VideoAssemblerCore {
    assembler: FrameAssembler,
    /// Sharer session the fragments belong to; a change resets the assembler.
    current_session: Option<u32>,
}

impl VideoAssemblerCore {
    pub fn new() -> Self {
        Self {
            assembler: FrameAssembler::new(),
            current_session: None,
        }
    }

    pub fn push(&mut self, key: &MediaKey, bytes: &[u8]) -> anyhow::Result<VideoPush> {
        let mut packet = VideoPacket::from_bytes(bytes)?;
        let packet_type = packet.packet_type;
        if !matches!(
            packet_type,
            VideoPacketType::EncryptedVideoFragment
                | VideoPacketType::EncryptedVideoKeyframeFragment
        ) {
            bail!("not an encrypted video fragment: 0x{:02x}", packet_type as u8);
        }

        // Nonce: session id, frame id as the sequence, fragment index as the
        // extra; the AAD binds the channel and the exact packet type byte.
        let aad = build_aad(key.channel_id, packet_type as u8);
        packet.payload = media_decrypt(
            key,
            packet.session_id,
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
