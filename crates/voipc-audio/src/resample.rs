/// Streaming resampler for devices that can't run 48kHz.
///
/// A windowed-sinc filter (the speex resampler, as a pure-Rust port), not
/// linear interpolation: that one put the THD+N of a 10 kHz tone at −20 dB,
/// which a 44.1 kHz Windows device, or screen audio at another rate, played
/// back both ways (H3-11). Stateful across calls, so chunk boundaries join
/// seamlessly; every call consumes all of its input.
pub struct Resampler {
    /// `None` when both rates are the same: then it passes samples through.
    state: Option<speexdsp_resampler::State>,
    /// Output samples per input sample, to size the output.
    ratio: f64,
}

/// The speex quality, 0–10. 8 keeps the image of a 44.1↔48 kHz voice or
/// game sound below −90 dB at a fraction of a core.
const QUALITY: usize = 8;

impl Resampler {
    pub fn new(rate_in: u32, rate_out: u32) -> Self {
        let state = (rate_in != rate_out).then(|| {
            let mut st =
                speexdsp_resampler::State::new(1, rate_in as usize, rate_out as usize, QUALITY)
                    .expect("the speex state is never refused");
            // Start on the first sample rather than after the filter's run-in
            st.skip_zeros();
            st
        });
        Self {
            state,
            ratio: rate_out as f64 / rate_in as f64,
        }
    }

    pub fn process(&mut self, input: &[f32], output: &mut Vec<f32>) {
        let Some(st) = self.state.as_mut() else {
            output.extend_from_slice(input);
            return;
        };
        let mut input = input;
        while !input.is_empty() {
            let start = output.len();
            let room = (input.len() as f64 * self.ratio).ceil() as usize + 16;
            output.resize(start + room, 0.0);
            let (used, written) = st
                .process_float(0, input, &mut output[start..])
                .unwrap_or((input.len(), 0));
            output.truncate(start + written);
            if used == 0 && written == 0 {
                break;
            }
            input = &input[used..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Output samples still inside the filter at quality 8.
    const FILTER_DELAY: u64 = 100;

    #[test]
    fn identity_ratio_passes_through() {
        let mut r = Resampler::new(48_000, 48_000);
        let input: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let mut out = Vec::new();
        r.process(&input, &mut out);
        assert_eq!(out, input);
    }

    #[test]
    fn upsample_length_ratio() {
        let mut r = Resampler::new(44_100, 48_000);
        let input = vec![0.0f32; 4410]; // 100ms
        let mut out = Vec::new();
        r.process(&input, &mut out);
        // 100ms at 48kHz = 4800 samples, less what is still in the filter
        assert!(
            (out.len() as i64 - 4800).unsigned_abs() <= FILTER_DELAY,
            "len = {}",
            out.len()
        );
    }

    #[test]
    fn downsample_length_ratio() {
        let mut r = Resampler::new(48_000, 44_100);
        let input = vec![0.0f32; 4800];
        let mut out = Vec::new();
        r.process(&input, &mut out);
        assert!(
            (out.len() as i64 - 4410).unsigned_abs() <= FILTER_DELAY,
            "len = {}",
            out.len()
        );
    }

    #[test]
    fn continuity_across_chunks() {
        // A tone resampled in one call must equal the same tone in many calls.
        let input: Vec<f32> = (0..4800).map(|i| (i as f32 * 0.05).sin() * 0.5).collect();
        let mut whole = Vec::new();
        Resampler::new(44_100, 48_000).process(&input, &mut whole);

        let mut r = Resampler::new(44_100, 48_000);
        let mut chunked = Vec::new();
        for chunk in input.chunks(160) {
            r.process(chunk, &mut chunked);
        }
        assert!(whole.len().abs_diff(chunked.len()) <= 2);
        for (a, b) in whole.iter().zip(chunked.iter()) {
            assert!((a - b).abs() < 1e-4, "{a} vs {b}");
        }
    }

    #[test]
    fn a_long_stream_keeps_the_rate() {
        // No drift: past the filter's fixed delay, each second of 44.1 kHz in
        // 10 ms chunks is exactly a second at 48 kHz
        let mut r = Resampler::new(44_100, 48_000);
        let mut out = Vec::new();
        let mut second = || {
            for _ in 0..100 {
                r.process(&[0.1f32; 441], &mut out);
            }
            out.len()
        };
        let one = second();
        let two = second();
        assert!((two - one).abs_diff(48_000) <= 1, "{}", two - one);
    }
}
