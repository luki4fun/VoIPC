/// Streaming linear-interpolation resampler for devices that can't run 48kHz.
///
/// Stateful across calls: the last input sample is carried over so chunk
/// boundaries interpolate seamlessly.
// ponytail: linear interp; swap for rubato if voice quality complaints arrive
pub struct LinearResampler {
    /// Input samples advanced per output sample (rate_in / rate_out).
    step: f64,
    /// Fractional read position; 0.0 = `prev`, 1.0 = first sample of `input`.
    pos: f64,
    /// Last sample of the previous input chunk.
    prev: f32,
    primed: bool,
}

impl LinearResampler {
    pub fn new(rate_in: u32, rate_out: u32) -> Self {
        Self {
            step: rate_in as f64 / rate_out as f64,
            pos: 0.0,
            prev: 0.0,
            primed: false,
        }
    }

    /// Convert `input` and append the resampled samples to `output`.
    pub fn process(&mut self, input: &[f32], output: &mut Vec<f32>) {
        if input.is_empty() {
            return;
        }
        if !self.primed {
            self.primed = true;
            self.prev = input[0];
            self.pos = 1.0; // start exactly on the first real sample
        }
        loop {
            let p = self.pos;
            let sample = if p < 1.0 {
                self.prev + (input[0] - self.prev) * p as f32
            } else {
                let i = (p - 1.0) as usize;
                let frac = (p - 1.0) - i as f64;
                if i + 1 < input.len() {
                    input[i] + (input[i + 1] - input[i]) * frac as f32
                } else if i + 1 == input.len() && frac == 0.0 {
                    input[i]
                } else {
                    break; // need the next chunk to interpolate further
                }
            };
            output.push(sample);
            self.pos += self.step;
        }
        self.prev = input[input.len() - 1];
        self.pos -= input.len() as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_ratio_passes_through() {
        let mut r = LinearResampler::new(48_000, 48_000);
        let input: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let mut out = Vec::new();
        r.process(&input, &mut out);
        assert_eq!(out, input);
        // and stays identical on the next chunk
        out.clear();
        r.process(&input, &mut out);
        assert_eq!(out, input);
    }

    #[test]
    fn upsample_length_ratio() {
        let mut r = LinearResampler::new(44_100, 48_000);
        let input = vec![0.0f32; 4410]; // 100ms
        let mut out = Vec::new();
        r.process(&input, &mut out);
        // 100ms at 48kHz = 4800 samples (± a couple at the chunk edge)
        assert!((out.len() as i64 - 4800).unsigned_abs() <= 2, "len = {}", out.len());
    }

    #[test]
    fn downsample_length_ratio() {
        let mut r = LinearResampler::new(48_000, 44_100);
        let input = vec![0.0f32; 4800];
        let mut out = Vec::new();
        r.process(&input, &mut out);
        assert!((out.len() as i64 - 4410).unsigned_abs() <= 2, "len = {}", out.len());
    }

    #[test]
    fn continuity_across_chunks() {
        // A ramp resampled in one call must equal the same ramp in many calls.
        let input: Vec<f32> = (0..1000).map(|i| (i as f32 * 0.01).sin()).collect();
        let mut whole = Vec::new();
        LinearResampler::new(44_100, 48_000).process(&input, &mut whole);

        let mut r = LinearResampler::new(44_100, 48_000);
        let mut chunked = Vec::new();
        for chunk in input.chunks(160) {
            r.process(chunk, &mut chunked);
        }
        // Chunked output can be a couple samples shorter (tail awaits next chunk)
        assert!(whole.len() - chunked.len() <= 2);
        for (a, b) in whole.iter().zip(chunked.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }
}
