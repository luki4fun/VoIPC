use voipc_protocol::voice::OPUS_FRAME_SIZE;

/// Mixes multiple decoded audio streams into a single output buffer.
///
/// Each input is a slice of `OPUS_FRAME_SIZE` f32 samples from a different user.
/// Output is the sum of all inputs, clamped to [-1.0, 1.0].
pub fn mix_streams(streams: &[&[f32]]) -> Vec<f32> {
    let mut output = vec![0.0f32; OPUS_FRAME_SIZE];
    mix_into(&mut output, streams.iter().map(|s| (*s, 1.0)));
    output
}

/// Like [`mix_streams`], but each stream carries its own gain.
pub fn mix_streams_weighted(streams: &[(&[f32], f32)]) -> Vec<f32> {
    let mut output = vec![0.0f32; OPUS_FRAME_SIZE];
    mix_into(&mut output, streams.iter().copied());
    output
}

/// Sum gain-weighted streams into `output` (assumed zeroed), clamping to [-1.0, 1.0].
pub fn mix_into<'a>(output: &mut [f32], streams: impl Iterator<Item = (&'a [f32], f32)>) {
    for (stream, gain) in streams {
        let len = stream.len().min(output.len());
        for i in 0..len {
            output[i] += stream[i] * gain;
        }
    }

    // Clamp to prevent distortion
    for sample in output.iter_mut() {
        *sample = sample.clamp(-1.0, 1.0);
    }
}

/// State one spatial source carries between frames: where its gains and its
/// muffle filter were left, so the next frame ramps on from there.
#[derive(Debug, Clone, Copy)]
pub struct SourceMixState {
    pub gain_l: f32,
    pub gain_r: f32,
    lowpass: f32,
    /// Cleared until the first frame: that one jumps to its target instead of
    /// ramping down from unity, or a muted or distant speaker bursts at full
    /// volume every time their source is created.
    primed: bool,
}

impl Default for SourceMixState {
    fn default() -> Self {
        Self {
            gain_l: 1.0,
            gain_r: 1.0,
            lowpass: 0.0,
            primed: false,
        }
    }
}

/// Accumulate one mono frame into an interleaved stereo buffer, ramping the
/// gains linearly from where the previous frame left them to `target`.
///
/// A step in gain is a click, so gains never jump: one 20 ms frame is the
/// ramp, which sits inside the 5–20 ms that is inaudible. `lp_a` is the
/// one-pole coefficient for occlusion; 1.0 bypasses the filter but still
/// carries its state, so switching the filter on mid-stream does not pop.
///
/// `out` is `2 * pcm.len()` samples: `[l0, r0, l1, r1, …]`.
pub fn mix_source_stereo(
    out: &mut [f32],
    pcm: &[f32],
    state: &mut SourceMixState,
    target: (f32, f32),
    lp_a: f32,
) {
    let n = pcm.len().min(out.len() / 2);
    if n == 0 {
        state.gain_l = target.0;
        state.gain_r = target.1;
        return;
    }
    if !state.primed {
        state.gain_l = target.0;
        state.gain_r = target.1;
        state.primed = true;
    }

    let step_l = (target.0 - state.gain_l) / n as f32;
    let step_r = (target.1 - state.gain_r) / n as f32;
    let (mut gl, mut gr) = (state.gain_l, state.gain_r);
    let a = lp_a.clamp(0.0, 1.0);
    let mut lp = state.lowpass;

    for i in 0..n {
        lp += a * (pcm[i] - lp);
        let s = if a >= 1.0 { pcm[i] } else { lp };
        out[2 * i] += s * gl;
        out[2 * i + 1] += s * gr;
        gl += step_l;
        gr += step_r;
    }

    state.gain_l = target.0;
    state.gain_r = target.1;
    state.lowpass = lp;
}

/// Clamp a mixed buffer to [-1.0, 1.0]. Call once after every source has been
/// accumulated (per-source clamping would distort each stream separately).
pub fn clamp(buf: &mut [f32]) {
    for sample in buf.iter_mut() {
        *sample = sample.clamp(-1.0, 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_two_streams() {
        let a = vec![0.5f32; OPUS_FRAME_SIZE];
        let b = vec![0.3f32; OPUS_FRAME_SIZE];

        let mixed = mix_streams(&[&a, &b]);
        assert!((mixed[0] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn mix_clamps() {
        let a = vec![0.8f32; OPUS_FRAME_SIZE];
        let b = vec![0.8f32; OPUS_FRAME_SIZE];

        let mixed = mix_streams(&[&a, &b]);
        assert_eq!(mixed[0], 1.0); // clamped
    }

    #[test]
    fn mix_empty() {
        let mixed = mix_streams(&[]);
        assert_eq!(mixed.len(), OPUS_FRAME_SIZE);
        assert_eq!(mixed[0], 0.0);
    }

    #[test]
    fn mix_single_stream() {
        let a = vec![0.5f32; OPUS_FRAME_SIZE];
        let mixed = mix_streams(&[&a]);
        assert!((mixed[0] - 0.5).abs() < 1e-6);
        assert!((mixed[OPUS_FRAME_SIZE - 1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn mix_many_streams() {
        let streams: Vec<Vec<f32>> = (0..10).map(|_| vec![0.1f32; OPUS_FRAME_SIZE]).collect();
        let refs: Vec<&[f32]> = streams.iter().map(|s| s.as_slice()).collect();
        let mixed = mix_streams(&refs);
        assert!((mixed[0] - 1.0).abs() < 1e-5);
    }

    #[test]
    fn mix_negative_clamps() {
        let a = vec![-0.8f32; OPUS_FRAME_SIZE];
        let b = vec![-0.8f32; OPUS_FRAME_SIZE];
        let mixed = mix_streams(&[&a, &b]);
        assert_eq!(mixed[0], -1.0); // clamped to -1.0
    }

    #[test]
    fn mix_output_length() {
        let a = vec![0.1f32; 100]; // shorter than OPUS_FRAME_SIZE
        let mixed = mix_streams(&[&a]);
        assert_eq!(mixed.len(), OPUS_FRAME_SIZE);
    }

    #[test]
    fn weighted_mix_applies_gains() {
        let a = vec![0.5f32; OPUS_FRAME_SIZE];
        let b = vec![0.5f32; OPUS_FRAME_SIZE];
        let mixed = mix_streams_weighted(&[(&a, 0.5), (&b, 2.0)]);
        assert!((mixed[0] - 1.0).abs() < 1e-6); // 0.25 + 1.0, clamped to 1.0
        let mixed = mix_streams_weighted(&[(&a, 0.5), (&b, 0.2)]);
        assert!((mixed[0] - 0.35).abs() < 1e-6);
    }

    #[test]
    fn weighted_mix_zero_gain_is_silent() {
        let a = vec![0.9f32; OPUS_FRAME_SIZE];
        let mixed = mix_streams_weighted(&[(&a, 0.0)]);
        assert_eq!(mixed[0], 0.0);
    }

    // ── stereo / spatial mixing ─────────────────────────────────────────

    #[test]
    fn stereo_mix_writes_left_to_even_right_to_odd() {
        let pcm = vec![1.0f32; 4];
        let mut out = vec![0.0f32; 8];
        let mut st = SourceMixState {
            gain_l: 0.25,
            gain_r: 0.75,
            ..Default::default()
        };
        mix_source_stereo(&mut out, &pcm, &mut st, (0.25, 0.75), 1.0);
        for i in 0..4 {
            assert!((out[2 * i] - 0.25).abs() < 1e-6, "left {i} = {}", out[2 * i]);
            assert!((out[2 * i + 1] - 0.75).abs() < 1e-6);
        }
    }

    #[test]
    fn stereo_mix_ramps_from_the_previous_gains() {
        let pcm = vec![1.0f32; 10];
        let mut out = vec![0.0f32; 20];
        // Already playing at unity (the first frame primes instead of ramping)
        let mut st = SourceMixState {
            primed: true,
            ..Default::default()
        };
        mix_source_stereo(&mut out, &pcm, &mut st, (0.0, 0.0), 1.0);

        // Starts at the old gain, walks down monotonically, ends at the target
        assert!((out[0] - 1.0).abs() < 1e-6);
        for i in 1..10 {
            assert!(out[2 * i] < out[2 * (i - 1)], "not monotonic at {i}");
        }
        assert!(out[18] < 0.15);
        assert_eq!((st.gain_l, st.gain_r), (0.0, 0.0));

        // The next frame starts where this one ended: silence stays silent
        let mut out2 = vec![0.0f32; 20];
        mix_source_stereo(&mut out2, &pcm, &mut st, (0.0, 0.0), 1.0);
        assert!(out2.iter().all(|&s| s == 0.0));
    }

    #[test]
    fn a_new_source_starts_at_its_target_gain() {
        // A locally muted (or far away) speaker must not burst at full volume
        // for the first 20 ms every time their source is created.
        let pcm = vec![1.0f32; 8];
        let mut out = vec![0.0f32; 16];
        let mut st = SourceMixState::default();
        mix_source_stereo(&mut out, &pcm, &mut st, (0.0, 0.0), 1.0);
        assert!(out.iter().all(|&s| s == 0.0), "first frame was not silent: {out:?}");

        // And a quiet target is reached immediately, not after a ramp
        let mut out2 = vec![0.0f32; 16];
        let mut st2 = SourceMixState::default();
        mix_source_stereo(&mut out2, &pcm, &mut st2, (0.1, 0.1), 1.0);
        assert!((out2[0] - 0.1).abs() < 1e-6, "first sample = {}", out2[0]);
    }

    #[test]
    fn stereo_mix_accumulates_sources() {
        let pcm = vec![0.5f32; 4];
        let mut out = vec![0.0f32; 8];
        let mut a = SourceMixState::default();
        let mut b = SourceMixState::default();
        mix_source_stereo(&mut out, &pcm, &mut a, (1.0, 1.0), 1.0);
        mix_source_stereo(&mut out, &pcm, &mut b, (1.0, 1.0), 1.0);
        assert!((out[0] - 1.0).abs() < 1e-6);
        assert!((out[1] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn bypass_coefficient_is_bit_exact_passthrough() {
        let pcm: Vec<f32> = (0..64).map(|i| (i as f32 * 0.03).sin()).collect();
        let mut out = vec![0.0f32; 128];
        let mut st = SourceMixState::default();
        mix_source_stereo(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0);
        for (i, &s) in pcm.iter().enumerate() {
            assert_eq!(out[2 * i], s, "sample {i} was altered");
        }
    }

    #[test]
    fn muffle_coefficient_low_passes() {
        // Alternating ±1 is Nyquist: a low-pass must shrink it hard.
        let pcm: Vec<f32> = (0..64).map(|i| if i % 2 == 0 { 1.0 } else { -1.0 }).collect();
        let mut out = vec![0.0f32; 128];
        let mut st = SourceMixState::default();
        mix_source_stereo(&mut out, &pcm, &mut st, (1.0, 1.0), 0.045);
        let peak = out.iter().skip(20).fold(0.0f32, |m, s| m.max(s.abs()));
        assert!(peak < 0.1, "peak {peak} — filter did not attenuate");
    }

    #[test]
    fn stereo_mix_handles_a_short_or_empty_frame() {
        let mut out = vec![0.0f32; 4];
        let mut st = SourceMixState::default();
        // pcm longer than the buffer: only what fits is written
        mix_source_stereo(&mut out, &vec![1.0f32; 10], &mut st, (1.0, 1.0), 1.0);
        assert_eq!(out.len(), 4);
        // empty pcm still moves the gains to the target (no ramp to replay)
        mix_source_stereo(&mut out, &[], &mut st, (0.0, 0.0), 1.0);
        assert_eq!((st.gain_l, st.gain_r), (0.0, 0.0));
    }

    #[test]
    fn clamp_bounds_the_mix() {
        let mut buf = vec![-2.0, -0.5, 0.5, 2.0];
        clamp(&mut buf);
        assert_eq!(buf, vec![-1.0, -0.5, 0.5, 1.0]);
    }
}
