/// Voice Activity Detector using RMS-based amplitude detection.
///
/// Designed for real-time use in the audio capture loop (20ms frames at 48kHz).
/// Supports configurable threshold in dB with hold time to avoid choppy cutoffs.
pub struct VoiceActivityDetector {
    /// Threshold in dB (e.g. -40.0). Samples above this are considered voice.
    threshold_db: f32,
    /// Hold time in frames (how many silent frames before releasing).
    /// At 20ms per frame, 15 frames = 300ms hold.
    hold_frames: u32,
    /// Counter of consecutive silent frames.
    silent_count: u32,
    /// Whether voice is currently detected (includes hold period).
    active: bool,
    /// Most recent RMS level in dB.
    current_level_db: f32,
}

impl VoiceActivityDetector {
    /// Create a new VAD with the given threshold and hold time.
    ///
    /// `threshold_db`: Gate threshold in dB (typically -60 to 0). Default: -40.
    /// `hold_ms`: How long to keep transmitting after voice stops, in milliseconds.
    /// `frame_duration_ms`: Duration of each audio frame in milliseconds (typically 20).
    pub fn new(threshold_db: f32, hold_ms: u32, frame_duration_ms: u32) -> Self {
        let hold_frames = if frame_duration_ms > 0 {
            hold_ms / frame_duration_ms
        } else {
            15
        };
        Self {
            threshold_db,
            hold_frames,
            silent_count: hold_frames + 1, // Start in silent state
            active: false,
            current_level_db: -96.0,
        }
    }

    /// Process a frame of f32 PCM samples and return whether voice is detected.
    ///
    /// Returns `true` if the audio level is above the threshold or within the
    /// hold period after voice was last detected.
    pub fn process(&mut self, samples: &[f32]) -> bool {
        let rms = compute_rms(samples);
        let db = amplitude_to_db(rms);
        self.current_level_db = db;

        if db >= self.threshold_db {
            // Voice detected
            self.silent_count = 0;
            self.active = true;
        } else {
            // Silence — increment counter
            self.silent_count = self.silent_count.saturating_add(1);
            if self.silent_count > self.hold_frames {
                self.active = false;
            }
            // During hold period, active stays true
        }

        self.active
    }

    /// Get the current audio level in dB (updated each `process` call).
    pub fn current_level_db(&self) -> f32 {
        self.current_level_db
    }

    /// Set the threshold in dB.
    pub fn set_threshold_db(&mut self, db: f32) {
        self.threshold_db = db.clamp(-96.0, 0.0);
    }

    /// Get the current threshold in dB.
    pub fn threshold_db(&self) -> f32 {
        self.threshold_db
    }
}

/// Compute RMS (root mean square) of f32 PCM samples.
fn compute_rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum_sq: f32 = samples.iter().map(|&s| s * s).sum();
    (sum_sq / samples.len() as f32).sqrt()
}

/// Convert linear amplitude to decibels. Returns -96.0 for silence.
fn amplitude_to_db(amplitude: f32) -> f32 {
    if amplitude <= 0.0 {
        -96.0
    } else {
        let db = 20.0 * amplitude.log10();
        db.max(-96.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_is_not_detected() {
        let mut vad = VoiceActivityDetector::new(-40.0, 300, 20);
        let silence = vec![0.0f32; 960];
        assert!(!vad.process(&silence));
    }

    #[test]
    fn loud_signal_is_detected() {
        let mut vad = VoiceActivityDetector::new(-40.0, 300, 20);
        // 0.1 amplitude = -20 dB, well above -40 threshold
        let loud = vec![0.1f32; 960];
        assert!(vad.process(&loud));
    }

    #[test]
    fn hold_time_works() {
        let mut vad = VoiceActivityDetector::new(-40.0, 60, 20);
        // hold_frames = 60/20 = 3

        let loud = vec![0.1f32; 960];
        let silence = vec![0.0f32; 960];

        // Activate
        assert!(vad.process(&loud));

        // 3 silent frames should still be active (hold period)
        assert!(vad.process(&silence)); // silent_count=1
        assert!(vad.process(&silence)); // silent_count=2
        assert!(vad.process(&silence)); // silent_count=3

        // 4th silent frame should deactivate
        assert!(!vad.process(&silence)); // silent_count=4 > hold_frames=3
    }

    #[test]
    fn threshold_change() {
        let mut vad = VoiceActivityDetector::new(-40.0, 300, 20);
        // 0.001 amplitude = -60 dB, below -40 threshold
        let quiet = vec![0.001f32; 960];
        assert!(!vad.process(&quiet));

        // Lower threshold to -70 dB — now it should detect
        vad.set_threshold_db(-70.0);
        assert!(vad.process(&quiet));
    }

    #[test]
    fn db_conversion() {
        assert!((amplitude_to_db(1.0) - 0.0).abs() < 0.01);
        assert!((amplitude_to_db(0.1) - (-20.0)).abs() < 0.01);
        assert!((amplitude_to_db(0.01) - (-40.0)).abs() < 0.01);
        assert_eq!(amplitude_to_db(0.0), -96.0);
    }
}
