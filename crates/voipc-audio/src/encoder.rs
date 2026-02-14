use anyhow::Result;
use audiopus::coder::Encoder as OpusEncoder;
use audiopus::{Application, Channels, SampleRate, Signal};
use voipc_protocol::voice::{OPUS_BITRATE, OPUS_FRAME_SIZE, OPUS_SAMPLE_RATE};

/// Wraps the Opus encoder with our application-specific settings.
pub struct Encoder {
    inner: OpusEncoder,
}

impl Encoder {
    /// Create a new Opus encoder configured for voice communication.
    pub fn new() -> Result<Self> {
        let mut encoder = OpusEncoder::new(
            SampleRate::Hz48000,
            Channels::Mono,
            Application::Voip,
        )?;

        encoder.set_bitrate(audiopus::Bitrate::BitsPerSecond(OPUS_BITRATE))?;
        encoder.set_inband_fec(true)?;
        encoder.set_packet_loss_perc(15)?;
        encoder.set_signal(Signal::Voice)?;
        encoder.set_dtx(true)?;

        Ok(Self { inner: encoder })
    }

    /// Create a new Opus encoder configured for desktop/screen share audio.
    ///
    /// Uses `Application::Audio` mode (optimized for music and mixed content)
    /// rather than `Voip` mode. Mono 48kHz at the specified bitrate.
    pub fn new_screen_audio(bitrate: i32) -> Result<Self> {
        let mut encoder = OpusEncoder::new(
            SampleRate::Hz48000,
            Channels::Mono,
            Application::Audio,
        )?;

        encoder.set_bitrate(audiopus::Bitrate::BitsPerSecond(bitrate))?;

        Ok(Self { inner: encoder })
    }

    /// Encode a frame of PCM f32 samples into Opus.
    ///
    /// `pcm` must contain exactly `OPUS_FRAME_SIZE` (960) samples.
    /// Returns the encoded Opus data.
    pub fn encode(&mut self, pcm: &[f32]) -> Result<Vec<u8>> {
        assert_eq!(
            pcm.len(),
            OPUS_FRAME_SIZE,
            "PCM frame must be exactly {} samples",
            OPUS_FRAME_SIZE
        );

        // Opus output buffer — 512 bytes handles higher bitrates (e.g. 64kbps screen audio)
        let mut output = vec![0u8; 512];
        let len = self.inner.encode_float(pcm, &mut output)?;
        output.truncate(len);
        Ok(output)
    }

    /// Returns the expected number of input samples per frame.
    pub fn frame_size(&self) -> usize {
        OPUS_FRAME_SIZE
    }

    /// Returns the expected sample rate.
    pub fn sample_rate(&self) -> u32 {
        OPUS_SAMPLE_RATE
    }
}
