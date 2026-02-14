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

    /// Decode an Opus packet into PCM f32 samples.
    ///
    /// Returns exactly `OPUS_FRAME_SIZE` (960) samples.
    pub fn decode(&mut self, opus_data: &[u8]) -> Result<Vec<f32>> {
        let mut output = vec![0.0f32; OPUS_FRAME_SIZE];
        let packet = Packet::try_from(opus_data)?;
        let signals = MutSignals::try_from(&mut output)?;
        let samples = self.inner.decode_float(Some(packet), signals, false)?;
        output.truncate(samples);
        Ok(output)
    }

    /// Decode a lost packet (packet loss concealment).
    ///
    /// Opus will generate comfort noise / interpolation.
    pub fn decode_lost(&mut self) -> Result<Vec<f32>> {
        let mut output = vec![0.0f32; OPUS_FRAME_SIZE];
        let signals = MutSignals::try_from(&mut output)?;
        let samples = self.inner.decode_float(None, signals, false)?;
        output.truncate(samples);
        Ok(output)
    }
}
