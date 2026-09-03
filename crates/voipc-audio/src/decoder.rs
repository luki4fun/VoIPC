use anyhow::Result;
use audiopus::coder::Decoder as OpusDecoder;
use audiopus::packet::Packet;
use audiopus::{Channels, MutSignals, SampleRate};
use voipc_protocol::voice::OPUS_FRAME_SIZE;

/// Wraps the Opus decoder. One decoder instance per remote user.
pub struct Decoder {
    inner: OpusDecoder,
}

impl Decoder {
    pub fn new() -> Result<Self> {
        let decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono)?;
        Ok(Self { inner: decoder })
    }

    fn decode_inner(&mut self, opus_data: Option<&[u8]>, fec: bool) -> Result<Vec<f32>> {
        let mut output = vec![0.0f32; OPUS_FRAME_SIZE];
        let packet = opus_data.map(Packet::try_from).transpose()?;
        let signals = MutSignals::try_from(&mut output)?;
        let samples = self.inner.decode_float(packet, signals, fec)?;
        output.truncate(samples);
        Ok(output)
    }

    /// Decode an Opus packet into PCM f32 samples.
    ///
    /// Returns exactly `OPUS_FRAME_SIZE` (960) samples.
    pub fn decode(&mut self, opus_data: &[u8]) -> Result<Vec<f32>> {
        self.decode_inner(Some(opus_data), false)
    }

    /// Recover a lost frame from the in-band FEC data carried by the
    /// packet that follows it. Falls back to PLC quality if the packet
    /// carries no FEC. The packet must still be decoded normally afterwards
    /// for its own frame.
    pub fn decode_fec(&mut self, next_opus_data: &[u8]) -> Result<Vec<f32>> {
        self.decode_inner(Some(next_opus_data), true)
    }

    /// Decode a lost packet (packet loss concealment).
    ///
    /// Opus will generate comfort noise / interpolation.
    pub fn decode_lost(&mut self) -> Result<Vec<f32>> {
        self.decode_inner(None, false)
    }
}
