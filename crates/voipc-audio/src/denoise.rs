use nnnoiseless::DenoiseState;

/// RNNoise-based noise suppressor for voice audio.
///
/// Processes 480-sample frames at 48kHz. Input must be f32 in [-1.0, 1.0] range.
/// Internally scales to i16 range for RNNoise, then scales back.
const RNNOISE_FRAME_SIZE: usize = 480;

pub struct Denoiser {
    state: Box<DenoiseState>,
    enabled: bool,
    /// Input buffer scaled to i16 range for RNNoise.
    input_buf: [f32; RNNOISE_FRAME_SIZE],
    /// Output buffer from RNNoise.
    output_buf: [f32; RNNOISE_FRAME_SIZE],
}

impl Denoiser {
    pub fn new() -> Self {
        Self {
            state: DenoiseState::new(),
            enabled: true,
            input_buf: [0.0; RNNOISE_FRAME_SIZE],
            output_buf: [0.0; RNNOISE_FRAME_SIZE],
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Process audio samples in-place. Samples are f32 in [-1.0, 1.0].
    /// Handles any buffer size by processing in 480-sample chunks.
    /// Leftover samples (< 480) are processed by zero-padding.
    pub fn process(&mut self, samples: &mut [f32]) {
        if !self.enabled || samples.is_empty() {
            return;
        }

        let mut offset = 0;
        while offset < samples.len() {
            let remaining = samples.len() - offset;
            let chunk_len = remaining.min(RNNOISE_FRAME_SIZE);

            // Scale to i16 range for RNNoise
            for i in 0..chunk_len {
                self.input_buf[i] = samples[offset + i] * 32767.0;
            }
            // Zero-pad if less than full frame
            for i in chunk_len..RNNOISE_FRAME_SIZE {
                self.input_buf[i] = 0.0;
            }

            self.state.process_frame(&mut self.output_buf, &self.input_buf);

            // Scale back to [-1.0, 1.0] range
            for i in 0..chunk_len {
                samples[offset + i] = self.output_buf[i] / 32767.0;
            }

            offset += chunk_len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denoise_silence_stays_silent() {
        let mut denoiser = Denoiser::new();
        let mut samples = vec![0.0f32; 960];
        denoiser.process(&mut samples);
        for &s in &samples {
            assert!(s.abs() < 0.01, "expected near-silence, got {}", s);
        }
    }

    #[test]
    fn denoise_disabled_passthrough() {
        let mut denoiser = Denoiser::new();
        denoiser.set_enabled(false);
        let original = vec![0.5f32; 960];
        let mut samples = original.clone();
        denoiser.process(&mut samples);
        assert_eq!(samples, original);
    }

    #[test]
    fn denoise_odd_buffer_size() {
        // Should handle buffers not evenly divisible by 480
        let mut denoiser = Denoiser::new();
        let mut samples = vec![0.0f32; 500];
        denoiser.process(&mut samples); // should not panic
    }
}
