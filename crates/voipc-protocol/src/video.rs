use crate::error::ProtocolError;

/// Video packet types (0x10-0x1F range, separate from voice 0x01-0x05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VideoPacketType {
    /// Fragment of a delta frame.
    VideoFragment = 0x10,
    /// Fragment of a keyframe (IDR).
    VideoKeyframeFragment = 0x11,
    /// Screen share audio (Opus-encoded desktop audio).
    ScreenShareAudio = 0x12,
    /// AES-256-GCM encrypted delta frame fragment.
    EncryptedVideoFragment = 0x13,
    /// AES-256-GCM encrypted keyframe fragment.
    EncryptedVideoKeyframeFragment = 0x14,
    /// AES-256-GCM encrypted screen share audio.
    EncryptedScreenShareAudio = 0x15,
}

impl VideoPacketType {
    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x10 => Ok(Self::VideoFragment),
            0x11 => Ok(Self::VideoKeyframeFragment),
            0x12 => Ok(Self::ScreenShareAudio),
            0x13 => Ok(Self::EncryptedVideoFragment),
            0x14 => Ok(Self::EncryptedVideoKeyframeFragment),
            0x15 => Ok(Self::EncryptedScreenShareAudio),
            other => Err(ProtocolError::UnknownPacketType(other)),
        }
    }

    pub fn is_keyframe(self) -> bool {
        matches!(
            self,
            Self::VideoKeyframeFragment | Self::EncryptedVideoKeyframeFragment
        )
    }

    pub fn is_encrypted(self) -> bool {
        matches!(
            self,
            Self::EncryptedVideoFragment
                | Self::EncryptedVideoKeyframeFragment
                | Self::EncryptedScreenShareAudio
        )
    }

    /// Get the encrypted version of this packet type.
    pub fn to_encrypted(self) -> Self {
        match self {
            Self::VideoFragment => Self::EncryptedVideoFragment,
            Self::VideoKeyframeFragment => Self::EncryptedVideoKeyframeFragment,
            Self::ScreenShareAudio => Self::EncryptedScreenShareAudio,
            other => other,
        }
    }
}

/// Header size: 1 (type) + 4 (session_id) + 4 (frame_id)
///            + 1 (fragment_index) + 1 (fragment_count) + 4 (timestamp) = 15 bytes.
pub const VIDEO_HEADER_SIZE: usize = 15;

/// Encrypted header: standard header + 2 (key_id) = 17 bytes.
pub const ENCRYPTED_VIDEO_HEADER_SIZE: usize = 17;

/// Maximum total video packet size. Fragments travel on QUIC streams, but
/// keeping them at 1280 bytes bounds per-fragment loss and matches the
/// assembler's 255-fragment ceiling (~316 KB per frame).
pub const MAX_VIDEO_PACKET_SIZE: usize = 1280;

/// Maximum payload per unencrypted video fragment.
pub const MAX_VIDEO_PAYLOAD_SIZE: usize = MAX_VIDEO_PACKET_SIZE - VIDEO_HEADER_SIZE;

/// Maximum payload per encrypted video fragment.
/// Accounts for encrypted header (17 bytes) + AES-256-GCM tag (16 bytes) appended to payload.
pub const MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE: usize =
    MAX_VIDEO_PACKET_SIZE - ENCRYPTED_VIDEO_HEADER_SIZE - 16;

/// Maximum fragments per frame (u8 max).
pub const MAX_FRAGMENTS_PER_FRAME: usize = 255;

/// A single video packet (fragment).
///
/// Wire format:
/// ```text
/// [type: u8] [session_id: u32 BE] [frame_id: u32 BE]
/// [fragment_index: u8] [fragment_count: u8] [timestamp: u32 BE] [payload: variable]
/// ```
#[derive(Debug, Clone)]
pub struct VideoPacket {
    pub packet_type: VideoPacketType,
    pub session_id: u32,
    pub frame_id: u32,
    pub fragment_index: u8,
    pub fragment_count: u8,
    pub timestamp: u32,
    pub payload: Vec<u8>,
    /// Media encryption key ID (only used for encrypted packet types).
    pub key_id: u16,
}

impl VideoPacket {
    /// Create a video fragment packet.
    pub fn fragment(
        is_keyframe: bool,
        session_id: u32,
        frame_id: u32,
        fragment_index: u8,
        fragment_count: u8,
        timestamp: u32,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            packet_type: if is_keyframe {
                VideoPacketType::VideoKeyframeFragment
            } else {
                VideoPacketType::VideoFragment
            },
            session_id,
            frame_id,
            fragment_index,
            fragment_count,
            timestamp,
            payload,
            key_id: 0,
        }
    }

    /// Create an encrypted video fragment packet.
    pub fn encrypted_fragment(
        is_keyframe: bool,
        session_id: u32,
        frame_id: u32,
        fragment_index: u8,
        fragment_count: u8,
        timestamp: u32,
        key_id: u16,
        encrypted_payload: Vec<u8>,
    ) -> Self {
        Self {
            packet_type: if is_keyframe {
                VideoPacketType::EncryptedVideoKeyframeFragment
            } else {
                VideoPacketType::EncryptedVideoFragment
            },
            session_id,
            frame_id,
            fragment_index,
            fragment_count,
            timestamp,
            payload: encrypted_payload,
            key_id,
        }
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.packet_type.is_encrypted() {
            let mut buf =
                Vec::with_capacity(ENCRYPTED_VIDEO_HEADER_SIZE + self.payload.len());
            buf.push(self.packet_type as u8);
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.frame_id.to_be_bytes());
            buf.push(self.fragment_index);
            buf.push(self.fragment_count);
            buf.extend_from_slice(&self.timestamp.to_be_bytes());
            buf.extend_from_slice(&self.key_id.to_be_bytes());
            buf.extend_from_slice(&self.payload);
            buf
        } else {
            let mut buf = Vec::with_capacity(VIDEO_HEADER_SIZE + self.payload.len());
            buf.push(self.packet_type as u8);
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.frame_id.to_be_bytes());
            buf.push(self.fragment_index);
            buf.push(self.fragment_count);
            buf.extend_from_slice(&self.timestamp.to_be_bytes());
            buf.extend_from_slice(&self.payload);
            buf
        }
    }

    /// Deserialize from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < VIDEO_HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                expected: VIDEO_HEADER_SIZE,
                got: data.len(),
            });
        }

        let packet_type = VideoPacketType::from_byte(data[0])?;
        let session_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let frame_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
        let fragment_index = data[9];
        let fragment_count = data[10];
        let timestamp = u32::from_be_bytes([data[11], data[12], data[13], data[14]]);

        // Reject packets where fragment_index >= fragment_count
        if fragment_count > 0 && fragment_index >= fragment_count {
            return Err(ProtocolError::InvalidFragmentIndex {
                index: fragment_index,
                count: fragment_count,
            });
        }

        if packet_type.is_encrypted() {
            if data.len() < ENCRYPTED_VIDEO_HEADER_SIZE {
                return Err(ProtocolError::PacketTooShort {
                    expected: ENCRYPTED_VIDEO_HEADER_SIZE,
                    got: data.len(),
                });
            }
            let key_id = u16::from_be_bytes([data[15], data[16]]);
            let payload = data[ENCRYPTED_VIDEO_HEADER_SIZE..].to_vec();
            Ok(Self {
                packet_type,
                session_id,
                frame_id,
                fragment_index,
                fragment_count,
                timestamp,
                payload,
                key_id,
            })
        } else {
            let payload = data[VIDEO_HEADER_SIZE..].to_vec();
            Ok(Self {
                packet_type,
                session_id,
                frame_id,
                fragment_index,
                fragment_count,
                timestamp,
                payload,
                key_id: 0,
            })
        }
    }
}

/// Fragment an encoded video frame into multiple video packets.
///
/// Use `MAX_VIDEO_PAYLOAD_SIZE` for unencrypted packets or
/// `MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE` when encryption will be applied
/// (to leave room for the GCM tag and key_id header).
pub fn fragment_frame(
    encoded_data: &[u8],
    is_keyframe: bool,
    session_id: u32,
    frame_id: u32,
    timestamp: u32,
    max_payload: usize,
) -> Vec<VideoPacket> {
    let chunks: Vec<&[u8]> = encoded_data.chunks(max_payload).collect();
    if chunks.len() > MAX_FRAGMENTS_PER_FRAME {
        tracing::warn!(
            frame_id,
            total_chunks = chunks.len(),
            max = MAX_FRAGMENTS_PER_FRAME,
            "frame exceeds max fragments, truncating"
        );
    }
    let fragment_count = chunks.len().min(MAX_FRAGMENTS_PER_FRAME) as u8;

    chunks
        .into_iter()
        .enumerate()
        .take(MAX_FRAGMENTS_PER_FRAME)
        .map(|(i, chunk)| {
            VideoPacket::fragment(
                is_keyframe,
                session_id,
                frame_id,
                i as u8,
                fragment_count,
                timestamp,
                chunk.to_vec(),
            )
        })
        .collect()
}

/// Result of feeding a video fragment into the assembler.
pub struct FragmentResult {
    /// Assembled frame data and keyframe flag, if a complete frame was assembled.
    pub frame: Option<(Vec<u8>, bool)>,
    /// Whether an incomplete previous frame was discarded to start assembling a new one.
    /// When true, the caller should request a keyframe to recover decoder state.
    pub frame_dropped: bool,
}

/// Reassembles video frame fragments back into complete encoded frames.
pub struct FrameAssembler {
    current_frame_id: Option<u32>,
    fragments: Vec<Option<Vec<u8>>>,
    fragment_count: u8,
    received_count: u8,
    is_keyframe: bool,
    has_received_keyframe: bool,
    /// Tracks the last successfully completed frame_id so we can detect gaps
    /// where entire frames were lost (no fragments arrived at all).
    last_completed_frame_id: Option<u32>,
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self {
            current_frame_id: None,
            fragments: Vec::new(),
            fragment_count: 0,
            received_count: 0,
            is_keyframe: false,
            has_received_keyframe: false,
            last_completed_frame_id: None,
        }
    }

    /// Feed a video packet into the assembler.
    /// Returns a `FragmentResult` indicating whether a complete frame is ready
    /// and whether an incomplete frame was discarded (signaling potential decoder corruption).
    pub fn add_fragment(&mut self, packet: &VideoPacket) -> FragmentResult {
        let frame_id = packet.frame_id;
        let mut frame_dropped = false;

        // Reject zero-fragment packets — they'd produce empty frames
        if packet.fragment_count == 0 {
            return FragmentResult { frame: None, frame_dropped: false };
        }

        // New frame arrived — discard any incomplete previous frame
        if self.current_frame_id != Some(frame_id) {
            if let Some(cur) = self.current_frame_id {
                // Wraparound-safe: treat frames within 1000 behind current as old
                let behind = cur.wrapping_sub(frame_id);
                if behind > 0 && behind < 1000 {
                    // Old/out-of-order frame, ignore
                    return FragmentResult { frame: None, frame_dropped: false };
                }
                // We were assembling a frame that never completed — signal loss
                if self.received_count > 0 && self.received_count < self.fragment_count {
                    frame_dropped = true;
                }
            }
            self.current_frame_id = Some(frame_id);
            self.fragment_count = packet.fragment_count;
            self.received_count = 0;
            self.is_keyframe = packet.packet_type.is_keyframe();
            self.fragments.clear();
            self.fragments
                .resize(packet.fragment_count as usize, None);
        }

        let idx = packet.fragment_index as usize;
        if idx >= self.fragments.len() {
            return FragmentResult { frame: None, frame_dropped };
        }

        // Don't double-count
        if self.fragments[idx].is_none() {
            self.received_count += 1;
        }
        self.fragments[idx] = Some(packet.payload.clone());

        // Mark keyframe if any fragment says so
        if packet.packet_type.is_keyframe() {
            self.is_keyframe = true;
        }

        // Check if frame is complete
        if self.received_count == self.fragment_count {
            let mut frame_data = Vec::new();
            for frag in &self.fragments {
                if let Some(data) = frag {
                    frame_data.extend_from_slice(data);
                }
            }
            let is_keyframe = self.is_keyframe;
            if is_keyframe {
                self.has_received_keyframe = true;
            }

            // Free fragment payloads immediately to avoid holding ~50-100KB
            self.fragments.clear();

            // Only emit if we've seen at least one keyframe
            if self.has_received_keyframe {
                // Detect frame_id gaps: if we skipped one or more frame_ids entirely
                // (no fragments arrived at all), those frames were lost in transit.
                if let Some(prev) = self.last_completed_frame_id {
                    if frame_id.wrapping_sub(prev) > 1 {
                        frame_dropped = true;
                    }
                }
                self.last_completed_frame_id = Some(frame_id);
                self.current_frame_id = None;
                return FragmentResult {
                    frame: Some((frame_data, is_keyframe)),
                    frame_dropped,
                };
            }
        }

        FragmentResult { frame: None, frame_dropped }
    }

    /// Reset the assembler state (e.g., when switching what we're watching).
    pub fn reset(&mut self) {
        self.current_frame_id = None;
        self.fragments.clear();
        self.fragment_count = 0;
        self.received_count = 0;
        self.is_keyframe = false;
        self.has_received_keyframe = false;
        self.last_completed_frame_id = None;
    }
}

// ── Per-frame streams ────────────────────────────────────────────────────

/// Largest `[u16 len][packet]` record on a per-frame stream.
pub const MAX_STREAM_RECORD_SIZE: usize = 1500;

/// Splits a per-frame stream (`[u16 BE len][packet]`, repeated) into its
/// packets; stops at the first empty, oversized or truncated record.
pub fn stream_records(data: &[u8]) -> Vec<&[u8]> {
    let mut records = Vec::new();
    let mut off = 0;
    while off + 2 <= data.len() {
        let len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if len == 0 || len > MAX_STREAM_RECORD_SIZE || off + len > data.len() {
            break;
        }
        records.push(&data[off..off + len]);
        off += len;
    }
    records
}

/// Incremental version of [`stream_records`]: fragments are handed on as soon
/// as they arrive instead of after the whole frame stream, so neither the
/// server nor a viewer holds a frame for the time it takes to transmit it.
#[derive(Default)]
pub struct RecordReader {
    buf: Vec<u8>,
    broken: bool,
}

impl RecordReader {
    /// Feed the bytes just read and get every record completed by them. An
    /// empty or oversized length prefix breaks the reader: the record boundaries
    /// are lost, so nothing more comes out of it.
    pub fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        if self.broken {
            return records;
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 2 {
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if len == 0 || len > MAX_STREAM_RECORD_SIZE {
                self.broken = true;
                self.buf.clear();
                break;
            }
            if self.buf.len() < 2 + len {
                break; // the rest of this record is still in flight
            }
            records.push(self.buf[2..2 + len].to_vec());
            self.buf.drain(..2 + len);
        }
        records
    }

    /// Whether a malformed length prefix ended this stream's records.
    pub fn is_broken(&self) -> bool {
        self.broken
    }
}

/// Where a video fragment goes: a new per-frame stream or the current one,
/// and whether that stream is complete after it.
#[derive(Debug, PartialEq, Eq)]
pub struct Placement {
    pub new_frame: bool,
    pub last: bool,
}

/// Groups video fragments into per-frame QUIC streams by `frame_id`, reading
/// only `frame_id` (bytes 5..9) and `fragment_count` (byte 10) of the header.
/// A frame's stream is complete once `fragment_count` fragments were placed,
/// or as soon as a different `frame_id` shows up. Used by the server bridge
/// and the native sharer alike.
#[derive(Default)]
pub struct FrameGrouper {
    /// (frame_id, fragments placed) of the open stream.
    current: Option<(u32, u8)>,
}

impl FrameGrouper {
    /// `None` for packets too short to carry a video header (dropped).
    pub fn place(&mut self, packet: &[u8]) -> Option<Placement> {
        if packet.len() < VIDEO_HEADER_SIZE {
            return None;
        }
        let frame_id = u32::from_be_bytes([packet[5], packet[6], packet[7], packet[8]]);
        let count = packet[10];
        let (new_frame, placed) = match self.current {
            Some((id, placed)) if id == frame_id => (false, placed.saturating_add(1)),
            _ => (true, 1),
        };
        let last = count != 0 && placed >= count;
        self.current = if last { None } else { Some((frame_id, placed)) };
        Some(Placement { new_frame, last })
    }
}

// ── Screen share audio packet ────────────────────────────────────────────

/// Header size: 1 (type) + 4 (session_id) + 4 (sequence) + 4 (timestamp) = 13 bytes.
pub const SCREEN_AUDIO_HEADER_SIZE: usize = 13;

/// Encrypted screen audio header: standard + 2 (key_id) = 15 bytes.
pub const ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE: usize = 15;

/// A screen share audio packet.
///
/// Carries Opus-encoded desktop audio from the screen sharer to viewers.
/// Routed by the server like video packets (only to viewers, not the whole channel).
///
/// Wire format:
/// ```text
/// [0x12: u8] [session_id: u32 BE] [sequence: u32 BE] [timestamp: u32 BE] [opus_data: variable]
/// ```
#[derive(Debug, Clone)]
pub struct ScreenShareAudioPacket {
    pub session_id: u32,
    /// Monotonic sequence number for ordering / loss detection.
    pub sequence: u32,
    /// Milliseconds since screen share started (same clock domain as video timestamps).
    pub timestamp: u32,
    pub opus_data: Vec<u8>,
    /// Whether this packet is encrypted (type 0x15).
    pub encrypted: bool,
    /// Media encryption key ID (only used when encrypted).
    pub key_id: u16,
}

impl ScreenShareAudioPacket {
    pub fn new(session_id: u32, sequence: u32, timestamp: u32, opus_data: Vec<u8>) -> Self {
        Self {
            session_id,
            sequence,
            timestamp,
            opus_data,
            encrypted: false,
            key_id: 0,
        }
    }

    pub fn new_encrypted(
        session_id: u32,
        sequence: u32,
        timestamp: u32,
        key_id: u16,
        encrypted_data: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            sequence,
            timestamp,
            opus_data: encrypted_data,
            encrypted: true,
            key_id,
        }
    }

    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.encrypted {
            let mut buf =
                Vec::with_capacity(ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE + self.opus_data.len());
            buf.push(VideoPacketType::EncryptedScreenShareAudio as u8);
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.sequence.to_be_bytes());
            buf.extend_from_slice(&self.timestamp.to_be_bytes());
            buf.extend_from_slice(&self.key_id.to_be_bytes());
            buf.extend_from_slice(&self.opus_data);
            buf
        } else {
            let mut buf = Vec::with_capacity(SCREEN_AUDIO_HEADER_SIZE + self.opus_data.len());
            buf.push(VideoPacketType::ScreenShareAudio as u8);
            buf.extend_from_slice(&self.session_id.to_be_bytes());
            buf.extend_from_slice(&self.sequence.to_be_bytes());
            buf.extend_from_slice(&self.timestamp.to_be_bytes());
            buf.extend_from_slice(&self.opus_data);
            buf
        }
    }

    /// Deserialize from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < SCREEN_AUDIO_HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                expected: SCREEN_AUDIO_HEADER_SIZE,
                got: data.len(),
            });
        }

        let packet_type = data[0];

        // Reject packets that aren't screen share audio types
        if packet_type != VideoPacketType::ScreenShareAudio as u8
            && packet_type != VideoPacketType::EncryptedScreenShareAudio as u8
        {
            return Err(ProtocolError::UnknownPacketType(packet_type));
        }

        let session_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let sequence = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
        let timestamp = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

        if packet_type == VideoPacketType::EncryptedScreenShareAudio as u8 {
            if data.len() < ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE {
                return Err(ProtocolError::PacketTooShort {
                    expected: ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE,
                    got: data.len(),
                });
            }
            let key_id = u16::from_be_bytes([data[13], data[14]]);
            let opus_data = data[ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE..].to_vec();
            Ok(Self {
                session_id,
                sequence,
                timestamp,
                opus_data,
                encrypted: true,
                key_id,
            })
        } else {
            let opus_data = data[SCREEN_AUDIO_HEADER_SIZE..].to_vec();
            Ok(Self {
                session_id,
                sequence,
                timestamp,
                opus_data,
                encrypted: false,
                key_id: 0,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_video_packet() {
        let original = VideoPacket::fragment(true, 42, 1, 0, 3, 1000, vec![1, 2, 3, 4, 5]);
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), VIDEO_HEADER_SIZE + 5);
        let decoded = VideoPacket::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.packet_type, VideoPacketType::VideoKeyframeFragment);
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.frame_id, 1);
        assert_eq!(decoded.fragment_index, 0);
        assert_eq!(decoded.fragment_count, 3);
        assert_eq!(decoded.timestamp, 1000);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn roundtrip_encrypted_video_packet() {
        let original =
            VideoPacket::encrypted_fragment(false, 42, 9, 1, 2, 77, 5, vec![1, 2, 3]);
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), ENCRYPTED_VIDEO_HEADER_SIZE + 3);
        let decoded = VideoPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.packet_type, VideoPacketType::EncryptedVideoFragment);
        assert_eq!(decoded.frame_id, 9);
        assert_eq!(decoded.fragment_index, 1);
        assert_eq!(decoded.fragment_count, 2);
        assert_eq!(decoded.timestamp, 77);
        assert_eq!(decoded.key_id, 5);
        assert_eq!(decoded.payload, vec![1, 2, 3]);
    }

    #[test]
    fn packet_too_short() {
        let result = VideoPacket::from_bytes(&[0x10, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn fragment_and_reassemble() {
        // Create a frame larger than one fragment
        let frame_data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let packets = fragment_frame(&frame_data, true, 1, 0, 500, MAX_VIDEO_PAYLOAD_SIZE);

        assert!(packets.len() > 1);
        assert_eq!(packets[0].fragment_count, packets.len() as u8);

        let mut assembler = FrameAssembler::new();
        let mut result = FragmentResult { frame: None, frame_dropped: false };
        for pkt in &packets {
            result = assembler.add_fragment(pkt);
        }

        assert!(!result.frame_dropped);
        let (reassembled, is_keyframe) = result.frame.expect("frame should be complete");
        assert!(is_keyframe);
        assert_eq!(reassembled, frame_data);
    }

    #[test]
    fn assembler_discards_incomplete_on_new_frame() {
        let mut assembler = FrameAssembler::new();

        // First, send a complete keyframe so has_received_keyframe is set
        let pkt = VideoPacket::fragment(true, 1, 0, 0, 1, 0, vec![10, 20]);
        let result = assembler.add_fragment(&pkt);
        assert!(result.frame.is_some()); // keyframe completes
        assert!(!result.frame_dropped);

        // Send only 1 of 2 fragments for frame 1 (incomplete delta)
        let pkt = VideoPacket::fragment(false, 1, 1, 0, 2, 100, vec![1, 2, 3]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_none());
        assert!(!r.frame_dropped);

        // Now send a complete single-fragment frame 2 — should discard frame 1
        let pkt = VideoPacket::fragment(false, 1, 2, 0, 1, 200, vec![4, 5, 6]);
        let result = assembler.add_fragment(&pkt);
        assert!(result.frame_dropped); // frame 1 was incomplete
        let (data, is_kf) = result.frame.expect("frame 2 should complete");
        assert!(!is_kf);
        assert_eq!(data, vec![4, 5, 6]);
    }

    #[test]
    fn assembler_waits_for_keyframe() {
        let mut assembler = FrameAssembler::new();

        // Send a delta frame first — should be silently dropped since no keyframe yet
        let pkt = VideoPacket::fragment(false, 1, 0, 0, 1, 0, vec![1, 2, 3]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_none());

        // Now send a keyframe
        let pkt = VideoPacket::fragment(true, 1, 1, 0, 1, 100, vec![4, 5, 6]);
        let result = assembler.add_fragment(&pkt);
        assert!(result.frame.is_some());
    }

    #[test]
    fn fragment_frame_single() {
        let data = vec![1u8; 100]; // well under MAX_VIDEO_PAYLOAD_SIZE
        let packets = fragment_frame(&data, false, 1, 0, 0, MAX_VIDEO_PAYLOAD_SIZE);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].fragment_index, 0);
        assert_eq!(packets[0].fragment_count, 1);
        assert_eq!(packets[0].payload, data);
    }

    #[test]
    fn fragment_frame_exact_mtu() {
        let data = vec![0u8; MAX_VIDEO_PAYLOAD_SIZE];
        let packets = fragment_frame(&data, true, 1, 0, 0, MAX_VIDEO_PAYLOAD_SIZE);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].to_bytes().len(), MAX_VIDEO_PACKET_SIZE);
    }

    #[test]
    fn fragment_frame_two() {
        let data = vec![0u8; MAX_VIDEO_PAYLOAD_SIZE + 1];
        let packets = fragment_frame(&data, false, 1, 0, 0, MAX_VIDEO_PAYLOAD_SIZE);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].fragment_index, 0);
        assert_eq!(packets[1].fragment_index, 1);
        assert_eq!(packets[0].fragment_count, 2);
        assert_eq!(packets[1].fragment_count, 2);
    }

    #[test]
    fn fragment_frame_consistent_count() {
        let data = vec![0u8; MAX_VIDEO_PAYLOAD_SIZE * 5 + 100];
        let packets = fragment_frame(&data, true, 1, 0, 0, MAX_VIDEO_PAYLOAD_SIZE);
        let expected_count = packets.len() as u8;
        for pkt in &packets {
            assert_eq!(pkt.fragment_count, expected_count);
        }
    }

    #[test]
    fn assembler_out_of_order() {
        let mut assembler = FrameAssembler::new();
        // 3-fragment keyframe, arrive out of order: 2, 0, 1
        let pkt2 = VideoPacket::fragment(true, 1, 0, 2, 3, 0, vec![30]);
        let pkt0 = VideoPacket::fragment(true, 1, 0, 0, 3, 0, vec![10]);
        let pkt1 = VideoPacket::fragment(true, 1, 0, 1, 3, 0, vec![20]);

        assert!(assembler.add_fragment(&pkt2).frame.is_none());
        assert!(assembler.add_fragment(&pkt0).frame.is_none());
        let result = assembler.add_fragment(&pkt1);
        let (data, is_kf) = result.frame.expect("should complete");
        assert!(is_kf);
        assert_eq!(data, vec![10, 20, 30]); // reassembled in index order
    }

    #[test]
    fn assembler_duplicate_fragment() {
        let mut assembler = FrameAssembler::new();
        let pkt0 = VideoPacket::fragment(true, 1, 0, 0, 2, 0, vec![10]);
        let pkt1 = VideoPacket::fragment(true, 1, 0, 1, 2, 0, vec![20]);

        assert!(assembler.add_fragment(&pkt0).frame.is_none());
        // Send pkt0 again — should not break received_count
        assert!(assembler.add_fragment(&pkt0).frame.is_none());
        let result = assembler.add_fragment(&pkt1);
        assert!(result.frame.is_some()); // still completes with 2 unique fragments
    }

    #[test]
    fn assembler_old_frame_ignored() {
        let mut assembler = FrameAssembler::new();
        // Complete keyframe 0 to set has_received_keyframe
        let pkt = VideoPacket::fragment(true, 1, 0, 0, 1, 0, vec![10]);
        assert!(assembler.add_fragment(&pkt).frame.is_some());

        // Start assembling frame 5 (partial — 1 of 2 fragments)
        let pkt = VideoPacket::fragment(false, 1, 5, 0, 2, 0, vec![50]);
        assert!(assembler.add_fragment(&pkt).frame.is_none());

        // Now try frame 3 (older than current_frame_id=5) — should be ignored
        let pkt = VideoPacket::fragment(false, 1, 3, 0, 1, 0, vec![30]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_none());
        assert!(!r.frame_dropped); // old frame ignored, not a drop
    }

    #[test]
    fn assembler_reset() {
        let mut assembler = FrameAssembler::new();
        // Send partial frame
        let pkt = VideoPacket::fragment(true, 1, 0, 0, 2, 0, vec![10]);
        assembler.add_fragment(&pkt);
        assembler.reset();

        // After reset, needs keyframe again
        let pkt = VideoPacket::fragment(false, 1, 1, 0, 1, 0, vec![20]);
        assert!(assembler.add_fragment(&pkt).frame.is_none()); // no keyframe yet

        let pkt = VideoPacket::fragment(true, 1, 2, 0, 1, 0, vec![30]);
        assert!(assembler.add_fragment(&pkt).frame.is_some()); // keyframe works
    }

    #[test]
    fn assembler_detects_frame_id_gap() {
        let mut assembler = FrameAssembler::new();

        // Complete keyframe frame 0
        let pkt = VideoPacket::fragment(true, 1, 0, 0, 1, 0, vec![10]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_some());
        assert!(!r.frame_dropped);

        // Complete delta frame 1 (sequential — no gap)
        let pkt = VideoPacket::fragment(false, 1, 1, 0, 1, 100, vec![20]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_some());
        assert!(!r.frame_dropped); // frame 0→1, no gap

        // Frame 2 is entirely lost (no fragments arrive at all)

        // Complete delta frame 3 — should detect the gap (frame 2 missing)
        let pkt = VideoPacket::fragment(false, 1, 3, 0, 1, 300, vec![40]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_some());
        assert!(r.frame_dropped); // frame 1→3, gap detected
    }

    // ── FrameGrouper tests ──

    fn grouper_fragment(frame_id: u32, index: u8, count: u8) -> Vec<u8> {
        let mut packet = vec![0x13u8; 5]; // type + session_id
        packet.extend_from_slice(&frame_id.to_be_bytes());
        packet.push(index);
        packet.push(count);
        packet.extend_from_slice(&[0u8; 4]); // timestamp
        packet.push(index); // payload marker
        packet
    }

    /// Applies placements the way the stream writers do and returns the
    /// records of every stream that was opened.
    fn group(packets: &[Vec<u8>]) -> Vec<Vec<Vec<u8>>> {
        let mut grouper = FrameGrouper::default();
        let mut streams: Vec<Vec<Vec<u8>>> = Vec::new();
        for packet in packets {
            let place = grouper.place(packet).unwrap();
            if place.new_frame {
                streams.push(Vec::new());
            }
            streams.last_mut().unwrap().push(packet.clone());
        }
        streams
    }

    #[test]
    fn grouper_matches_real_packets() {
        // The grouper's hand-parsed offsets must agree with VideoPacket::to_bytes
        let pkt = VideoPacket::encrypted_fragment(true, 7, 0x01020304, 0, 1, 9, 3, vec![1]);
        let mut grouper = FrameGrouper::default();
        assert_eq!(
            grouper.place(&pkt.to_bytes()),
            Some(Placement { new_frame: true, last: true })
        );
    }

    #[test]
    fn grouper_finishes_on_fragment_count() {
        let mut grouper = FrameGrouper::default();
        assert_eq!(
            grouper.place(&grouper_fragment(1, 0, 2)),
            Some(Placement { new_frame: true, last: false })
        );
        assert_eq!(
            grouper.place(&grouper_fragment(1, 1, 2)),
            Some(Placement { new_frame: false, last: true })
        );
        // The frame is closed: a late duplicate opens a new stream
        assert_eq!(
            grouper.place(&grouper_fragment(1, 1, 2)),
            Some(Placement { new_frame: true, last: false })
        );
    }

    #[test]
    fn grouper_interleaved_frames_become_two_streams() {
        // Frame 7 is cut short by frame 8 arriving, frame 8 completes by count
        let streams = group(&[
            grouper_fragment(7, 0, 3),
            grouper_fragment(7, 1, 3),
            grouper_fragment(8, 0, 2),
            grouper_fragment(8, 1, 2),
        ]);
        assert_eq!(
            streams,
            vec![
                vec![grouper_fragment(7, 0, 3), grouper_fragment(7, 1, 3)],
                vec![grouper_fragment(8, 0, 2), grouper_fragment(8, 1, 2)],
            ]
        );
        // Frame 7's straggler starts a stream of its own
        let mut grouper = FrameGrouper::default();
        for packet in [grouper_fragment(7, 0, 3), grouper_fragment(8, 0, 1)] {
            grouper.place(&packet);
        }
        assert_eq!(
            grouper.place(&grouper_fragment(7, 2, 3)),
            Some(Placement { new_frame: true, last: false })
        );
    }

    #[test]
    fn grouper_short_packets_are_dropped() {
        assert_eq!(FrameGrouper::default().place(&[0x13; VIDEO_HEADER_SIZE - 1]), None);
    }

    #[test]
    fn stream_records_stop_at_truncation_or_oversize() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&[1, 2, 3]);
        data.extend_from_slice(&5u16.to_be_bytes());
        data.extend_from_slice(&[4, 5]); // truncated
        assert_eq!(stream_records(&data), vec![&[1u8, 2, 3][..]]);

        let mut oversized = Vec::new();
        oversized.extend_from_slice(&((MAX_STREAM_RECORD_SIZE + 1) as u16).to_be_bytes());
        oversized.extend_from_slice(&[0; 2000]);
        assert!(stream_records(&oversized).is_empty());
        assert!(stream_records(&[]).is_empty());
    }

    // ── RecordReader tests ──

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn record_reader_handles_splits_anywhere() {
        // Length prefix split across two pushes
        let mut reader = RecordReader::default();
        let data = record(&[1, 2, 3]);
        assert!(reader.push(&data[..1]).is_empty());
        assert_eq!(reader.push(&data[1..]), vec![vec![1u8, 2, 3]]);

        // Record body split across pushes, second record arrives with the tail
        let mut reader = RecordReader::default();
        let mut data = record(&[4, 5, 6, 7]);
        data.extend_from_slice(&record(&[8]));
        assert!(reader.push(&data[..4]).is_empty());
        assert_eq!(
            reader.push(&data[4..]),
            vec![vec![4u8, 5, 6, 7], vec![8u8]]
        );

        // Many records in one push
        let mut reader = RecordReader::default();
        let mut data = Vec::new();
        for i in 0..5u8 {
            data.extend_from_slice(&record(&[i; 3]));
        }
        assert_eq!(reader.push(&data).len(), 5);
    }

    #[test]
    fn record_reader_stops_on_bad_length() {
        // Oversized length: broken, and it stays broken
        let mut reader = RecordReader::default();
        let mut data = ((MAX_STREAM_RECORD_SIZE + 1) as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&[0; 2000]);
        assert!(reader.push(&data).is_empty());
        assert!(reader.is_broken());
        assert!(reader.push(&record(&[1, 2, 3])).is_empty());

        // Zero length, after a good record
        let mut reader = RecordReader::default();
        let mut data = record(&[9]);
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&record(&[10]));
        assert_eq!(reader.push(&data), vec![vec![9u8]]);
        assert!(reader.is_broken());
    }

    #[test]
    fn record_reader_matches_stream_records() {
        let mut data = Vec::new();
        for payload in [&[1u8, 2, 3][..], &[4][..], &[5, 6][..]] {
            data.extend_from_slice(&record(payload));
        }
        data.extend_from_slice(&9u16.to_be_bytes()); // truncated tail: neither emits it
        data.extend_from_slice(&[7, 8]);

        let expected: Vec<Vec<u8>> = stream_records(&data)
            .into_iter()
            .map(|r| r.to_vec())
            .collect();
        assert_eq!(RecordReader::default().push(&data), expected);
    }

    // ── ScreenShareAudioPacket tests ──

    #[test]
    fn roundtrip_screen_audio_packet() {
        let original = ScreenShareAudioPacket::new(42, 100, 5000, vec![1, 2, 3, 4, 5]);
        let bytes = original.to_bytes();
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes.len(), SCREEN_AUDIO_HEADER_SIZE + 5);

        let decoded = ScreenShareAudioPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(decoded.timestamp, 5000);
        assert_eq!(decoded.opus_data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn roundtrip_encrypted_screen_audio_packet() {
        let original = ScreenShareAudioPacket::new_encrypted(42, 100, 5000, 9, vec![1, 2]);
        let bytes = original.to_bytes();
        assert_eq!(bytes[0], 0x15);
        assert_eq!(bytes.len(), ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE + 2);
        let decoded = ScreenShareAudioPacket::from_bytes(&bytes).unwrap();
        assert!(decoded.encrypted);
        assert_eq!(decoded.key_id, 9);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(decoded.timestamp, 5000);
        assert_eq!(decoded.opus_data, vec![1, 2]);
    }

    #[test]
    fn screen_audio_packet_too_short() {
        let result = ScreenShareAudioPacket::from_bytes(&[0x12, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn screen_audio_packet_type_0x12() {
        assert_eq!(
            VideoPacketType::from_byte(0x12).unwrap(),
            VideoPacketType::ScreenShareAudio
        );
    }

    #[test]
    fn screen_audio_not_keyframe() {
        assert!(!VideoPacketType::ScreenShareAudio.is_keyframe());
    }

    #[test]
    fn screen_audio_packet_empty_data() {
        let original = ScreenShareAudioPacket::new(1, 0, 0, vec![]);
        let bytes = original.to_bytes();
        let decoded = ScreenShareAudioPacket::from_bytes(&bytes).unwrap();
        assert!(decoded.opus_data.is_empty());
        assert_eq!(bytes.len(), SCREEN_AUDIO_HEADER_SIZE);
    }

    // ── Edge case tests (audit fixes) ──

    #[test]
    fn video_packet_rejects_invalid_fragment_index() {
        // fragment_index=5 >= fragment_count=3 → InvalidFragmentIndex
        let mut pkt = VideoPacket::fragment(false, 1, 0, 0, 3, 0, vec![1, 2]);
        pkt.fragment_index = 5;
        pkt.fragment_count = 3;
        let bytes = pkt.to_bytes();
        let err = VideoPacket::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidFragmentIndex { index: 5, count: 3 }));
    }

    #[test]
    fn video_packet_allows_zero_fragment_count() {
        // fragment_count=0 with fragment_index=0 passes from_bytes (assembler rejects it)
        let mut pkt = VideoPacket::fragment(false, 1, 0, 0, 1, 0, vec![1]);
        pkt.fragment_count = 0;
        pkt.fragment_index = 0;
        let bytes = pkt.to_bytes();
        assert!(VideoPacket::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn assembler_rejects_zero_fragment_count() {
        let mut assembler = FrameAssembler::new();
        let mut pkt = VideoPacket::fragment(true, 1, 0, 0, 1, 0, vec![1]);
        pkt.fragment_count = 0;
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_none());
        assert!(!r.frame_dropped);
    }

    #[test]
    fn assembler_frame_id_wraparound_gap_detection() {
        let mut assembler = FrameAssembler::new();

        // Complete keyframe at frame_id = u32::MAX - 1
        let pkt = VideoPacket::fragment(true, 1, u32::MAX - 1, 0, 1, 0, vec![10]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_some());

        // Complete frame at u32::MAX (sequential, no gap)
        let pkt = VideoPacket::fragment(false, 1, u32::MAX, 0, 1, 100, vec![20]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_some());
        assert!(!r.frame_dropped);

        // Complete frame at 0 (wrapped, sequential, no gap)
        let pkt = VideoPacket::fragment(false, 1, 0, 0, 1, 200, vec![30]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_some());
        assert!(!r.frame_dropped);

        // Complete frame at 2 (gap: frame 1 missing)
        let pkt = VideoPacket::fragment(false, 1, 2, 0, 1, 400, vec![50]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_some());
        assert!(r.frame_dropped);
    }

    #[test]
    fn assembler_old_frame_wraparound() {
        let mut assembler = FrameAssembler::new();

        // Complete keyframe at frame_id 5
        let pkt = VideoPacket::fragment(true, 1, 5, 0, 1, 0, vec![10]);
        assert!(assembler.add_fragment(&pkt).frame.is_some());

        // Start assembling frame 10
        let pkt = VideoPacket::fragment(false, 1, 10, 0, 2, 100, vec![20]);
        assert!(assembler.add_fragment(&pkt).frame.is_none());

        // Frame u32::MAX arrives (behind by 11 in wrapping terms) — should be ignored as old
        let pkt = VideoPacket::fragment(false, 1, u32::MAX, 0, 1, 50, vec![99]);
        let r = assembler.add_fragment(&pkt);
        assert!(r.frame.is_none());
        assert!(!r.frame_dropped);
    }

    #[test]
    fn screen_audio_rejects_wrong_packet_type() {
        // Build a valid-length packet but with video fragment type (0x10)
        let mut buf = vec![0u8; SCREEN_AUDIO_HEADER_SIZE + 5];
        buf[0] = 0x10; // VideoFragment, not ScreenShareAudio
        let err = ScreenShareAudioPacket::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, ProtocolError::UnknownPacketType(0x10)));
    }

    #[test]
    fn screen_audio_accepts_both_types() {
        let unenc = ScreenShareAudioPacket::new(1, 0, 0, vec![1, 2, 3]);
        let bytes = unenc.to_bytes();
        assert!(ScreenShareAudioPacket::from_bytes(&bytes).is_ok());

        let enc = ScreenShareAudioPacket::new_encrypted(1, 0, 0, 42, vec![1, 2, 3]);
        let bytes = enc.to_bytes();
        assert!(ScreenShareAudioPacket::from_bytes(&bytes).is_ok());
    }
}
