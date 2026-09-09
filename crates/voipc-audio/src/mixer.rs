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

use crate::spatial::Effect;

// ── Radio and phone chain ────────────────────────────────────────────────
//
// Two cascaded one-pole high-passes at 300 Hz and two low-passes at 3.4 kHz:
// the telephone band, 12 dB per octave on each side. A biquad would have
// steeper skirts, but this is four floats of state and no new dependency.
// ponytail: one-pole cascade, swap in a biquad if the skirts ever matter.

/// One-pole high-pass coefficient: exp(-2π·300/48000).
const FX_HP_R: f32 = 0.961_49;
/// One-pole low-pass coefficient: 1 - exp(-2π·3400/48000).
const FX_LP_A: f32 = 0.359_22;
/// Radio: soft-clip drive before the band-limit, so it sounds pushed.
const RADIO_DRIVE: f32 = 2.5;
/// Radio hiss, added before the band-limit so it is shaped like the voice.
const RADIO_HISS: f32 = 0.03;
/// Squelch burst at the start and end of a transmission: 10 ms of noise.
const SQUELCH_SAMPLES: u16 = 480;
const SQUELCH_GAIN: f32 = 0.25;
/// Frames (20 ms) with nothing to play before a radio counts as finished.
/// A VAD sender sends no end-of-transmission between phrases, so silence is
/// the only signal; 200 ms is what a real radio's squelch tail sounds like.
pub const FX_IDLE_FRAMES: u8 = 10;

/// State one spatial source carries between frames: where its gains and its
/// filters were left, so the next frame ramps on from there.
#[derive(Debug, Clone, Copy)]
pub struct SourceMixState {
    pub gain_l: f32,
    pub gain_r: f32,
    lowpass: f32,
    /// Cleared until the first frame: that one jumps to its target instead of
    /// ramping down from unity, or a muted or distant speaker bursts at full
    /// volume every time their source is created.
    primed: bool,
    /// `[x1, y1, x2, y2]` of the two high-pass stages.
    hp: [f32; 4],
    /// Second low-pass stage; `lowpass` is the first (and the muffle filter).
    lowpass2: f32,
    /// xorshift32 state for the hiss. Deterministic, so a test can pin it.
    noise: u32,
    /// Squelch samples still to render.
    burst: u16,
    /// This source is mid-transmission, so an end burst is owed.
    talking: bool,
    /// Consecutive frames with nothing to play.
    idle: u8,
}

impl Default for SourceMixState {
    fn default() -> Self {
        Self {
            gain_l: 1.0,
            gain_r: 1.0,
            lowpass: 0.0,
            primed: false,
            hp: [0.0; 4],
            lowpass2: 0.0,
            // Any non-zero seed; xorshift is stuck at zero
            noise: 0x2545_f491,
            burst: 0,
            talking: false,
            idle: 0,
        }
    }
}

/// Uniform noise in [-1, 1), from a 32-bit xorshift.
#[inline]
fn white(seed: &mut u32) -> f32 {
    let mut x = *seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *seed = x;
    (x >> 8) as f32 * (2.0 / (1u32 << 24) as f32) - 1.0
}

/// One sample through the chain. `a` is the first low-pass coefficient (the
/// muffle filter, or the band-limit for radio and phone).
///
/// Every filter state advances even when the effect is off, so switching one
/// on mid-stream does not pop — the same reason the muffle filter does.
#[inline]
fn fx_sample(st: &mut SourceMixState, x: f32, a: f32, fx: Effect) -> f32 {
    let mut x = x;
    if fx == Effect::Radio {
        let d = x * RADIO_DRIVE;
        x = d / (1.0 + d.abs()) + RADIO_HISS * white(&mut st.noise);
    }
    if st.burst > 0 {
        let env = st.burst as f32 / SQUELCH_SAMPLES as f32;
        st.burst -= 1;
        x += SQUELCH_GAIN * env * white(&mut st.noise);
    }
    // Two one-pole high-pass stages
    let h1 = FX_HP_R * (st.hp[1] + x - st.hp[0]);
    st.hp[0] = x;
    st.hp[1] = h1;
    let h2 = FX_HP_R * (st.hp[3] + h1 - st.hp[2]);
    st.hp[2] = h1;
    st.hp[3] = h2;

    let input = if fx == Effect::None { x } else { h2 };
    st.lowpass += a * (input - st.lowpass);
    let first = if a >= 1.0 { input } else { st.lowpass };
    st.lowpass2 += FX_LP_A * (first - st.lowpass2);
    if fx == Effect::None {
        first
    } else {
        st.lowpass2
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
    mix_source_fx(out, pcm, state, target, lp_a, Effect::None);
}

/// [`mix_source_stereo`] with an effect chain. A radio opens its squelch on
/// the first frame of a transmission; [`mix_source_stop`] closes it.
pub fn mix_source_fx(
    out: &mut [f32],
    pcm: &[f32],
    state: &mut SourceMixState,
    target: (f32, f32),
    lp_a: f32,
    fx: Effect,
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
    state.idle = 0;
    if fx == Effect::Radio && !state.talking {
        state.burst = SQUELCH_SAMPLES;
    }
    state.talking = fx != Effect::None;

    let step_l = (target.0 - state.gain_l) / n as f32;
    let step_r = (target.1 - state.gain_r) / n as f32;
    let (mut gl, mut gr) = (state.gain_l, state.gain_r);
    // Radio and phone are never muffled (they are not in the room), so the
    // first stage runs at the band-limit instead of the muffle cutoff.
    let a = match fx {
        Effect::None => lp_a.clamp(0.0, 1.0),
        _ => lp_a.clamp(0.0, 1.0).min(FX_LP_A),
    };

    for i in 0..n {
        let s = fx_sample(state, pcm[i], a, fx);
        out[2 * i] += s * gl;
        out[2 * i + 1] += s * gr;
        gl += step_l;
        gr += step_r;
    }

    state.gain_l = target.0;
    state.gain_r = target.1;
}

/// Nothing to play for this source this frame.
///
/// Counts the pause and, once it is long enough (or the sender said so with an
/// end-of-transmission), closes a radio transmission with a squelch burst at
/// the gains the source was left at. Returns whether anything was written; an
/// empty `out` (deafened) drops the burst rather than owing it.
pub fn mix_source_stop(
    out: &mut [f32],
    state: &mut SourceMixState,
    fx: Effect,
    ended: bool,
) -> bool {
    if state.talking {
        state.idle = state.idle.saturating_add(1);
        if ended || state.idle >= FX_IDLE_FRAMES {
            state.talking = false;
            state.idle = 0;
            if fx == Effect::Radio {
                state.burst = SQUELCH_SAMPLES;
            }
        }
    }
    let n = (state.burst as usize).min(out.len() / 2);
    if n == 0 {
        state.burst = 0;
        return false;
    }
    let (gl, gr) = (state.gain_l, state.gain_r);
    for i in 0..n {
        let s = fx_sample(state, 0.0, FX_LP_A, fx);
        out[2 * i] += s * gl;
        out[2 * i + 1] += s * gr;
    }
    true
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

    // ── Radio and phone chain ───────────────────────────────────────────

    /// Runs `frames` frames of a sine through the chain and returns the left
    /// channel, skipping the first frames so the filters have settled.
    fn through(hz: f32, amp: f32, fx: Effect, frames: usize, skip: usize) -> Vec<f32> {
        let mut st = SourceMixState::default();
        let mut kept = Vec::new();
        for f in 0..frames {
            let pcm: Vec<f32> = (0..960)
                .map(|i| {
                    let n = (f * 960 + i) as f32;
                    amp * (2.0 * core::f32::consts::PI * hz * n / 48_000.0).sin()
                })
                .collect();
            let mut out = vec![0.0f32; 1920];
            mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, fx);
            if f >= skip {
                kept.extend(out.iter().step_by(2));
            }
        }
        kept
    }

    fn rms_db(samples: &[f32]) -> f32 {
        let mean = samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32;
        20.0 * mean.sqrt().log10()
    }

    #[test]
    fn phone_passes_the_voice_band_and_cuts_the_edges() {
        let reference = rms_db(&through(1_000.0, 0.1, Effect::None, 6, 2));
        let mid = rms_db(&through(1_000.0, 0.1, Effect::Phone, 6, 2));
        let low = rms_db(&through(100.0, 0.1, Effect::Phone, 6, 2));
        let high = rms_db(&through(6_000.0, 0.1, Effect::Phone, 6, 2));
        assert!((mid - reference).abs() < 3.0, "1 kHz moved by {} dB", mid - reference);
        assert!(reference - low > 15.0, "100 Hz only cut by {} dB", reference - low);
        assert!(reference - high > 9.0, "6 kHz only cut by {} dB", reference - high);
    }

    #[test]
    fn radio_hisses_only_while_playing() {
        // Silence in, so everything heard is the effect itself
        let hiss = through(0.0, 0.0, Effect::Radio, 6, 2);
        let level = rms_db(&hiss);
        assert!((-48.0..=-30.0).contains(&level), "hiss at {level} dBFS");
        assert!(hiss.iter().all(|s| s.is_finite()));

        // Once it stops, the squelch closes and then there is nothing
        let mut st = SourceMixState::default();
        let mut out = vec![0.0f32; 1920];
        mix_source_fx(&mut out, &[0.0; 960], &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        assert!(mix_source_stop(&mut out, &mut st, Effect::Radio, true), "no end burst");
        let mut quiet = vec![0.0f32; 1920];
        assert!(!mix_source_stop(&mut quiet, &mut st, Effect::Radio, true));
        assert!(quiet.iter().all(|&s| s == 0.0), "a closed radio still made noise");
    }

    #[test]
    fn radio_squelch_opens_once_and_closes_after_a_pause() {
        let mut st = SourceMixState::default();
        let pcm = [0.0f32; 960];
        let energy = |b: &[f32]| b.iter().map(|s| s * s).sum::<f32>();

        let mut first = vec![0.0f32; 1920];
        mix_source_fx(&mut first, &pcm, &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        let mut second = vec![0.0f32; 1920];
        mix_source_fx(&mut second, &pcm, &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        assert!(
            energy(&first) > 4.0 * energy(&second),
            "the opening burst is not louder than the hiss"
        );

        // A VAD sender goes quiet without saying so: the squelch waits
        let mut out = vec![0.0f32; 1920];
        for frame in 1..FX_IDLE_FRAMES {
            assert!(
                !mix_source_stop(&mut out, &mut st, Effect::Radio, false),
                "closed after only {frame} idle frames"
            );
        }
        assert!(mix_source_stop(&mut out, &mut st, Effect::Radio, false), "never closed");
        // Speaking again opens it again
        let mut again = vec![0.0f32; 1920];
        mix_source_fx(&mut again, &pcm, &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        assert!(energy(&again) > 4.0 * energy(&second));
    }

    #[test]
    fn a_deafened_stop_drops_the_burst() {
        let mut st = SourceMixState::default();
        mix_source_fx(&mut vec![0.0f32; 1920], &[0.0; 960], &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        // Deafened: no buffer to write into, so the burst is dropped, not owed
        assert!(!mix_source_stop(&mut [], &mut st, Effect::Radio, true));
        let mut out = vec![0.0f32; 1920];
        assert!(!mix_source_stop(&mut out, &mut st, Effect::Radio, true));
        assert!(out.iter().all(|&s| s == 0.0));
    }

    #[test]
    fn the_noise_is_deterministic_and_bounded() {
        let a = through(0.0, 0.0, Effect::Radio, 4, 0);
        let b = through(0.0, 0.0, Effect::Radio, 4, 0);
        assert_eq!(a, b, "two fresh sources must sound the same");
        assert!(a.iter().all(|s| s.is_finite() && s.abs() <= 1.0));
        let mut seed = 12345u32;
        for _ in 0..10_000 {
            let v = white(&mut seed);
            assert!((-1.0..1.0).contains(&v), "white() returned {v}");
        }
    }

    #[test]
    fn an_effect_starts_without_a_click() {
        // The first frame must not step: a 1 kHz sine moves 0.065 per sample
        let first = through(1_000.0, 0.5, Effect::Phone, 1, 0);
        let step = first
            .windows(2)
            .map(|w| (w[1] - w[0]).abs())
            .fold(0.0f32, f32::max);
        assert!(step < 0.2, "biggest step {step}");
    }

    #[test]
    fn effects_never_produce_nan_and_switching_off_restores_the_plain_path() {
        for fx in [Effect::None, Effect::Phone, Effect::Radio] {
            let mut st = SourceMixState::default();
            for f in 0..50 {
                let pcm: Vec<f32> = (0..960)
                    .map(|i| if (f + i) % 2 == 0 { 1.0 } else { -1.0 })
                    .collect();
                let mut out = vec![0.0f32; 1920];
                mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, fx);
                assert!(out.iter().all(|s| s.is_finite()), "{fx:?} produced a NaN");
            }
        }

        // Radio, then plain: after one frame the plain path is bit-exact again
        let mut st = SourceMixState::default();
        let pcm: Vec<f32> = (0..960).map(|i| (i as f32 * 0.03).sin()).collect();
        mix_source_fx(&mut vec![0.0f32; 1920], &pcm, &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        let mut out = vec![0.0f32; 1920];
        mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, Effect::None);
        for (i, &s) in pcm.iter().enumerate() {
            assert_eq!(out[2 * i], s, "sample {i} was altered after the effect ended");
        }
    }

    #[test]
    fn clamp_bounds_the_mix() {
        let mut buf = vec![-2.0, -0.5, 0.5, 2.0];
        clamp(&mut buf);
        assert_eq!(buf, vec![-1.0, -0.5, 0.5, 1.0]);
    }
}
