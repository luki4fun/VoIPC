//! Echo cancellation for the desktop microphone (H3-02).
//!
//! Without it, everybody on loudspeakers sends the call back to the others.
//! The canceller is sonora's port of WebRTC's audio processing: AEC3, then
//! AGC2 for the level. Noise suppression stays RNNoise's, which runs after
//! this: RNNoise is non-linear and would break the echo model if it ran first.
//!
//! The mixer hands over what it plays ([`EchoReference`]); the capture thread
//! owns the canceller and feeds it that reference before each microphone
//! frame, so nothing in the mixer waits on the canceller. Android does not use
//! this: its own voice-communication preset cancels the echo there.

use std::collections::VecDeque;
use std::sync::Mutex;

/// One APM frame: 10 ms at 48 kHz.
const APM_FRAME: usize = 480;
/// The most reference kept while nobody takes it: half a second, oldest first
/// out. More than the playback cushion and the device latency together, which
/// is the delay the canceller has to find.
const REFERENCE_MAX: usize = 48_000 / 2;

/// What the speakers play, for the canceller to subtract: the mixer's output
/// as it goes to the device, mono, 48 kHz.
#[derive(Default)]
pub struct EchoReference {
    buf: Mutex<VecDeque<f32>>,
}

impl EchoReference {
    /// Add one mixed frame (interleaved stereo), downmixed to mono.
    pub fn push_stereo(&self, interleaved: &[f32]) {
        let mut buf = self.buf.lock().unwrap_or_else(|p| p.into_inner());
        buf.extend(
            interleaved
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[l, r]| 0.5 * (l + r)),
        );
        let over = buf.len().saturating_sub(REFERENCE_MAX);
        buf.drain(..over);
    }

    /// Forget what was played before a capture starts: that is not what its
    /// microphone will hear.
    pub fn clear(&self) {
        self.buf.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }

    /// Fill `out` with the oldest reference, and silence where there is none.
    fn take(&self, out: &mut [f32]) {
        let mut buf = self.buf.lock().unwrap_or_else(|p| p.into_inner());
        for s in out.iter_mut() {
            *s = buf.pop_front().unwrap_or(0.0);
        }
    }
}

/// The capture side: AEC3 and AGC2 over the microphone, 10 ms at a time.
pub struct EchoCanceller {
    apm: sonora::AudioProcessing,
    render: [f32; APM_FRAME],
    render_out: [f32; APM_FRAME],
    capture_out: [f32; APM_FRAME],
}

impl Default for EchoCanceller {
    fn default() -> Self {
        Self::new()
    }
}

impl EchoCanceller {
    pub fn new() -> Self {
        use sonora::config::{EchoCanceller as Aec3, GainController2};
        let config = sonora::Config {
            echo_canceller: Some(Aec3::default()),
            gain_controller2: Some(GainController2::default()),
            ..Default::default()
        };
        Self {
            apm: sonora::AudioProcessing::builder()
                .config(config)
                .capture_config(sonora::StreamConfig::new(48_000, 1))
                .render_config(sonora::StreamConfig::new(48_000, 1))
                .build(),
            render: [0.0; APM_FRAME],
            render_out: [0.0; APM_FRAME],
            capture_out: [0.0; APM_FRAME],
        }
    }

    /// Cancel the echo in one capture frame (a multiple of 10 ms), in place.
    /// A chunk the canceller refuses is left as it was.
    pub fn process(&mut self, reference: &EchoReference, frame: &mut [f32]) {
        for chunk in frame.as_chunks_mut::<APM_FRAME>().0 {
            reference.take(&mut self.render);
            let _ = self
                .apm
                .process_render_f32(&[&self.render], &mut [&mut self.render_out]);
            if self
                .apm
                .process_capture_f32(&[chunk], &mut [&mut self.capture_out])
                .is_ok()
            {
                chunk.copy_from_slice(&self.capture_out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn energy(x: &[f32]) -> f64 {
        x.iter().map(|&s| (s as f64) * (s as f64)).sum::<f64>()
    }

    #[test]
    fn what_the_speakers_play_is_taken_out_of_the_microphone() {
        // Far end only: noise played, and heard back 40 ms later at half level.
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        let mut noise = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            ((rng >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 0.4
        };
        let total = 48_000 * 4;
        let far: Vec<f32> = (0..total).map(|_| noise()).collect();
        let delay = 48 * 40;
        let mic: Vec<f32> = (0..total)
            .map(|i| {
                if i >= delay {
                    far[i - delay] * 0.5
                } else {
                    0.0
                }
            })
            .collect();

        let reference = EchoReference::default();
        let mut aec = EchoCanceller::new();
        let mut out = mic.clone();
        for k in 0..total / 960 {
            let played: Vec<f32> = far[k * 960..(k + 1) * 960]
                .iter()
                .flat_map(|&s| [s, s])
                .collect();
            reference.push_stereo(&played);
            aec.process(&reference, &mut out[k * 960..(k + 1) * 960]);
        }
        // The last second, once AEC3 has found the delay
        let tail = total - 48_000..total;
        let erle = 10.0 * (energy(&mic[tail.clone()]) / energy(&out[tail]).max(1e-12)).log10();
        assert!(erle > 20.0, "echo only reduced by {erle:.1} dB");
    }

    #[test]
    fn the_reference_is_bounded_and_runs_out_into_silence() {
        let r = EchoReference::default();
        r.push_stereo(&vec![0.5; 2 * (REFERENCE_MAX + 100)]);
        assert_eq!(r.buf.lock().unwrap().len(), REFERENCE_MAX);
        r.clear();
        let mut out = [1.0f32; 4];
        r.take(&mut out);
        assert_eq!(out, [0.0; 4]);
    }
}
