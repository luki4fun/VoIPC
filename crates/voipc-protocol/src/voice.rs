use crate::error::ProtocolError;

/// Voice packet types carried as QUIC datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VoicePacketType {
    /// Normal Opus-encoded voice data.
    OpusVoice = 0x01,
    /// Client stopped transmitting (PTT released).
    EndOfTransmission = 0x02,
    /// Media-path ping for latency measurement.
    Ping = 0x03,
    /// Pong response.
    Pong = 0x04,
    /// AES-256-GCM encrypted Opus voice data.
    EncryptedOpusVoice = 0x05,
    /// AES-256-GCM encrypted listener position ([`PositionPayload`]), sent by
    /// members of a proximity channel who share their position.
    Position = 0x06,
}

impl VoicePacketType {
    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x01 => Ok(Self::OpusVoice),
            0x02 => Ok(Self::EndOfTransmission),
            0x03 => Ok(Self::Ping),
            0x04 => Ok(Self::Pong),
            0x05 => Ok(Self::EncryptedOpusVoice),
            0x06 => Ok(Self::Position),
            other => Err(ProtocolError::UnknownPacketType(other)),
        }
    }
}

/// Header size: 1 (type) + 4 (session_id) + 4 (sequence) = 9 bytes.
pub const VOICE_HEADER_SIZE: usize = 9;

/// Header size for encrypted voice: standard header + 2 (key_id) = 11 bytes.
/// Position packets (0x06) use the same header.
pub const ENCRYPTED_VOICE_HEADER_SIZE: usize = 11;

/// Plaintext size of a position beacon: x, y, z as f32 = 12 bytes.
pub const POSITION_PAYLOAD_SIZE: usize = 12;

/// Wire size of an encrypted position packet: header + payload + GCM tag.
pub const POSITION_PACKET_SIZE: usize = ENCRYPTED_VOICE_HEADER_SIZE + POSITION_PAYLOAD_SIZE + 16;

/// Maximum voice packet size (well under the QUIC datagram limit).
/// Encrypted packets add 18 bytes overhead (2 key_id + 16 GCM tag).
pub const MAX_VOICE_PACKET_SIZE: usize = 512;

/// Opus audio parameters.
pub const OPUS_SAMPLE_RATE: u32 = 48_000;
pub const OPUS_CHANNELS: u32 = 1; // mono
pub const OPUS_FRAME_SIZE: usize = 960; // 20ms at 48kHz
pub const OPUS_BITRATE: i32 = 48_000; // 48 kbps

/// A voice packet transmitted as a media datagram.
///
/// Wire format (unencrypted):
/// ```text
/// [type: u8] [session_id: u32 BE] [sequence: u32 BE] [opus_data: variable]
/// ```
///
/// Wire format (encrypted, type 0x05):
/// ```text
/// [0x05: u8] [session_id: u32 BE] [sequence: u32 BE] [key_id: u16 BE] [encrypted_opus + 16-byte GCM tag]
/// ```
#[derive(Debug, Clone)]
pub struct VoicePacket {
    pub packet_type: VoicePacketType,
    pub session_id: u32,
    pub sequence: u32,
    pub opus_data: Vec<u8>,
    /// Media encryption key ID (only used for EncryptedOpusVoice).
    pub key_id: u16,
}

impl VoicePacket {
    /// Create a new voice data packet.
    pub fn voice(session_id: u32, sequence: u32, opus_data: Vec<u8>) -> Self {
        Self {
            packet_type: VoicePacketType::OpusVoice,
            session_id,
            sequence,
            opus_data,
            key_id: 0,
        }
    }

    /// Create an encrypted voice data packet.
    pub fn encrypted_voice(
        session_id: u32,
        sequence: u32,
        key_id: u16,
        encrypted_data: Vec<u8>,
    ) -> Self {
        Self {
            packet_type: VoicePacketType::EncryptedOpusVoice,
            session_id,
            sequence,
            opus_data: encrypted_data,
            key_id,
        }
    }

    /// Create an encrypted position beacon.
    pub fn position(session_id: u32, sequence: u32, key_id: u16, encrypted_data: Vec<u8>) -> Self {
        Self {
            packet_type: VoicePacketType::Position,
            session_id,
            sequence,
            opus_data: encrypted_data,
            key_id,
        }
    }

    /// Create an end-of-transmission packet (PTT released).
    pub fn end_of_transmission(session_id: u32, sequence: u32) -> Self {
        Self {
            packet_type: VoicePacketType::EndOfTransmission,
            session_id,
            sequence,
            opus_data: Vec::new(),
            key_id: 0,
        }
    }

    /// Create a ping packet.
    pub fn ping(session_id: u32, sequence: u32) -> Self {
        Self {
            packet_type: VoicePacketType::Ping,
            session_id,
            sequence,
            opus_data: Vec::new(),
            key_id: 0,
        }
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        if matches!(
            self.packet_type,
            VoicePacketType::EncryptedOpusVoice | VoicePacketType::Position
        ) {
            // Encrypted format: header + key_id(2) + encrypted data
            let mut buf =
                Vec::with_capacity(ENCRYPTED_VOICE_HEADER_SIZE + self.opus_data.len());
            buf.push(self.packet_type as u8);
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.sequence.to_be_bytes());
            buf.extend_from_slice(&self.key_id.to_be_bytes());
            buf.extend_from_slice(&self.opus_data);
            buf
        } else {
            // Standard format
            let mut buf = Vec::with_capacity(VOICE_HEADER_SIZE + self.opus_data.len());
            buf.push(self.packet_type as u8);
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.sequence.to_be_bytes());
            buf.extend_from_slice(&self.opus_data);
            buf
        }
    }

    /// Deserialize from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < VOICE_HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                expected: VOICE_HEADER_SIZE,
                got: data.len(),
            });
        }

        let packet_type = VoicePacketType::from_byte(data[0])?;
        let session_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let sequence = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);

        if matches!(
            packet_type,
            VoicePacketType::EncryptedOpusVoice | VoicePacketType::Position
        ) {
            if data.len() < ENCRYPTED_VOICE_HEADER_SIZE {
                return Err(ProtocolError::PacketTooShort {
                    expected: ENCRYPTED_VOICE_HEADER_SIZE,
                    got: data.len(),
                });
            }
            let key_id = u16::from_be_bytes([data[9], data[10]]);
            let opus_data = data[ENCRYPTED_VOICE_HEADER_SIZE..].to_vec();
            Ok(Self {
                packet_type,
                session_id,
                sequence,
                opus_data,
                key_id,
            })
        } else {
            let opus_data = data[VOICE_HEADER_SIZE..].to_vec();
            Ok(Self {
                packet_type,
                session_id,
                sequence,
                opus_data,
                key_id: 0,
            })
        }
    }
}

/// Plaintext of a [`VoicePacketType::Position`] packet: the sender's position
/// in metres (x/y ground plane, z up), little-endian f32.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PositionPayload {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl PositionPayload {
    pub fn to_bytes(&self) -> [u8; POSITION_PAYLOAD_SIZE] {
        let mut buf = [0u8; POSITION_PAYLOAD_SIZE];
        buf[0..4].copy_from_slice(&self.x.to_le_bytes());
        buf[4..8].copy_from_slice(&self.y.to_le_bytes());
        buf[8..12].copy_from_slice(&self.z.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < POSITION_PAYLOAD_SIZE {
            return Err(ProtocolError::PacketTooShort {
                expected: POSITION_PAYLOAD_SIZE,
                got: data.len(),
            });
        }
        let f = |i: usize| f32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let (x, y, z) = (f(0), f(4), f(8));
        if !x.is_finite() || !y.is_finite() || !z.is_finite() {
            return Err(ProtocolError::InvalidPosition);
        }
        Ok(Self { x, y, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_voice_packet() {
        let original = VoicePacket::voice(42, 100, vec![1, 2, 3, 4, 5]);
        let bytes = original.to_bytes();
        let decoded = VoicePacket::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.packet_type, VoicePacketType::OpusVoice);
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(decoded.opus_data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn roundtrip_encrypted_voice_packet() {
        let original = VoicePacket::encrypted_voice(42, 100, 7, vec![9, 8, 7]);
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), ENCRYPTED_VOICE_HEADER_SIZE + 3);
        let decoded = VoicePacket::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.packet_type, VoicePacketType::EncryptedOpusVoice);
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(decoded.key_id, 7);
        assert_eq!(decoded.opus_data, vec![9, 8, 7]);
    }

    #[test]
    fn roundtrip_eot_packet() {
        let original = VoicePacket::end_of_transmission(7, 55);
        let bytes = original.to_bytes();
        let decoded = VoicePacket::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.packet_type, VoicePacketType::EndOfTransmission);
        assert_eq!(decoded.session_id, 7);
        assert_eq!(decoded.sequence, 55);
        assert!(decoded.opus_data.is_empty());
    }

    #[test]
    fn packet_too_short() {
        let result = VoicePacket::from_bytes(&[0x01, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_packet_type() {
        let data = [0xFF, 0, 0, 0, 1, 0, 0, 0, 1];
        let result = VoicePacket::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_ping_packet() {
        let original = VoicePacket::ping(10, 99);
        let bytes = original.to_bytes();
        let decoded = VoicePacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.packet_type, VoicePacketType::Ping);
        assert_eq!(decoded.session_id, 10);
        assert_eq!(decoded.sequence, 99);
        assert!(decoded.opus_data.is_empty());
    }

    #[test]
    fn voice_packet_max_sequence() {
        let original = VoicePacket::voice(1, u32::MAX, vec![42]);
        let bytes = original.to_bytes();
        let decoded = VoicePacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sequence, u32::MAX);
    }

    #[test]
    fn voice_packet_empty_data() {
        let original = VoicePacket::voice(1, 0, vec![]);
        let bytes = original.to_bytes();
        let decoded = VoicePacket::from_bytes(&bytes).unwrap();
        assert!(decoded.opus_data.is_empty());
        assert_eq!(decoded.packet_type, VoicePacketType::OpusVoice);
    }

    #[test]
    fn voice_packet_type_all_valid() {
        assert_eq!(VoicePacketType::from_byte(0x01).unwrap(), VoicePacketType::OpusVoice);
        assert_eq!(VoicePacketType::from_byte(0x02).unwrap(), VoicePacketType::EndOfTransmission);
        assert_eq!(VoicePacketType::from_byte(0x03).unwrap(), VoicePacketType::Ping);
        assert_eq!(VoicePacketType::from_byte(0x04).unwrap(), VoicePacketType::Pong);
        assert_eq!(VoicePacketType::from_byte(0x05).unwrap(), VoicePacketType::EncryptedOpusVoice);
        assert_eq!(VoicePacketType::from_byte(0x06).unwrap(), VoicePacketType::Position);
    }

    #[test]
    fn voice_packet_type_invalid() {
        assert!(VoicePacketType::from_byte(0x00).is_err());
        assert!(VoicePacketType::from_byte(0x07).is_err());
        assert!(VoicePacketType::from_byte(0xFF).is_err());
    }

    #[test]
    fn roundtrip_position_packet() {
        // 12-byte payload + 16-byte GCM tag, as the sender produces
        let payload = PositionPayload { x: 1.5, y: -2.25, z: 0.75 };
        let ciphertext = [payload.to_bytes().to_vec(), vec![0u8; 16]].concat();
        let bytes = VoicePacket::position(42, 9, 3, ciphertext).to_bytes();
        assert_eq!(bytes.len(), POSITION_PACKET_SIZE);

        let decoded = VoicePacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.packet_type, VoicePacketType::Position);
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.sequence, 9);
        assert_eq!(decoded.key_id, 3);
        assert_eq!(
            PositionPayload::from_bytes(&decoded.opus_data).unwrap(),
            payload
        );
    }

    #[test]
    fn position_payload_rejects_short_and_non_finite() {
        assert!(PositionPayload::from_bytes(&[0u8; 11]).is_err());
        let mut buf = PositionPayload { x: 0.0, y: 0.0, z: 0.0 }.to_bytes();
        buf[0..4].copy_from_slice(&f32::NAN.to_le_bytes());
        assert!(PositionPayload::from_bytes(&buf).is_err());
        buf[0..4].copy_from_slice(&f32::INFINITY.to_le_bytes());
        assert!(PositionPayload::from_bytes(&buf).is_err());
    }

    #[test]
    fn voice_packet_to_bytes_size() {
        let data = vec![1, 2, 3, 4, 5];
        let pkt = VoicePacket::voice(1, 1, data.clone());
        assert_eq!(pkt.to_bytes().len(), VOICE_HEADER_SIZE + data.len());
    }
}
