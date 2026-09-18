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
// bernd: one-pole cascade, swap in a biquad if the skirts ever matter.

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
    /// Sample-and-hold value and countdown for the bit-crusher.
    crush_hold: f32,
    crush_i: u8,
    /// Magic-circle oscillator state for the ring modulator.
    ring_u: f32,
    ring_v: f32,
    /// RMS of this source's last frame, post-effect and pre-fader, for the
    /// mixer's level meters. Pre-fader on purpose: a post-fader meter reads
    /// zero for exactly the muted person you opened the mixer to find.
    pub level: f32,
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
            crush_hold: 0.0,
            crush_i: 0,
            // The oscillator starts on the unit circle, not at the origin
            ring_u: 1.0,
            ring_v: 0.0,
            level: 0.0,
        }
    }
}

// ── The preset library ───────────────────────────────────────────────────
//
// One chain, driven by a table. Every entry below is data, so a new voice is a
// row rather than a branch — which is the whole reason "not every radio has the
// same quality" is answerable at all.
//
// Coefficients, not hertz. The two original constants above are rounded
// decimals: computing `FX_LP_A` back from 3400 Hz gives 0.359213505 against the
// literal 0.359_22, a difference of 6.5e-6 — six times the tolerance the
// cross-language golden vector is pinned at. Radio and Phone therefore reuse
// the literals verbatim and stay bit-identical.

/// What a preset is a flavour of. Only used to say "several grades of each".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FxFamily {
    Radio,
    Phone,
    Colour,
}

/// One chain's whole parameter set.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FxPreset {
    /// The SDK `mode`, the command argument and the `<option value>`: one string.
    pub id: &'static str,
    pub label: &'static str,
    pub family: FxFamily,
    /// One-pole high-pass coefficient, `exp(-2π·fc/48000)`, both stages.
    pub hp_r: f32,
    /// One-pole low-pass coefficient, `1 - exp(-2π·fc/48000)`, both stages.
    pub lp_a: f32,
    /// Soft-clip drive; 0 is off, 1 is barely there, 6 is a megaphone.
    pub drive: f32,
    /// Steady hiss, added before the band-limit so it is shaped like the voice.
    pub noise: f32,
    /// Occasional crackle, for something worn out.
    pub crackle: f32,
    /// Open and close with a squelch burst.
    pub squelch: bool,
    /// Sample-and-hold decimation, in samples; 0 or 1 is off.
    pub crush_hold: u8,
    /// Quantisation step; 0 is off. Keep it under `noise` or it eats the hiss.
    pub crush_step: f32,
    /// Ring modulator, as `2·sin(π·f/48000)`; 0 is off.
    pub ring_k: f32,
    /// Makeup gain, so switching preset is not also a volume change.
    pub gain: f32,
}

/// A chain with nothing switched on: the shape every preset starts from.
const PLAIN: FxPreset = FxPreset {
    id: "none",
    label: "No effect",
    family: FxFamily::Colour,
    hp_r: FX_HP_R,
    lp_a: FX_LP_A,
    drive: 0.0,
    noise: 0.0,
    crackle: 0.0,
    squelch: false,
    crush_hold: 0,
    crush_step: 0.0,
    ring_k: 0.0,
    gain: 1.0,
};

/// Every chain, indexed by `Effect as usize - 1`.
pub const PRESETS: [FxPreset; 13] = [
    // The two originals, untouched, so the golden vector still holds.
    FxPreset { id: "phone", label: "Phone (legacy)", family: FxFamily::Phone, ..PLAIN },
    FxPreset { id: "radio", label: "Radio", family: FxFamily::Radio,
               drive: RADIO_DRIVE, noise: RADIO_HISS, squelch: true, ..PLAIN },
    // Radios. What separates them is band, push and hiss: a CB is narrow and
    // driven hard, an aviation set is hissy, a police set is a little digital.
    FxPreset { id: "cb", label: "CB radio", family: FxFamily::Radio,
               hp_r: 0.948_987, lp_a: 0.297_724, drive: 4.0, noise: 0.030,
               squelch: true, gain: 0.80, ..PLAIN },
    FxPreset { id: "walkie", label: "Walkie-talkie", family: FxFamily::Radio,
               hp_r: 0.942_796, lp_a: 0.288_471, drive: 3.0, noise: 0.022,
               squelch: true, ..PLAIN },
    FxPreset { id: "aviation", label: "Aviation radio", family: FxFamily::Radio,
               hp_r: 0.955_219, lp_a: 0.279_096, drive: 2.0, noise: 0.045,
               squelch: true, gain: 1.25, ..PLAIN },
    FxPreset { id: "police", label: "Police radio", family: FxFamily::Radio,
               hp_r: 0.948_987, lp_a: 0.324_768, drive: 3.5, noise: 0.018,
               squelch: true, crush_hold: 3, crush_step: 1.0 / 128.0, gain: 0.85, ..PLAIN },
    // Phones. A landline is clean and loud, a mobile is codec-y, bad VoIP is
    // what a congested link does to a voice.
    FxPreset { id: "landline", label: "Landline", family: FxFamily::Phone,
               drive: 0.8, noise: 0.004, gain: 2.30, ..PLAIN },
    FxPreset { id: "mobile", label: "Mobile", family: FxFamily::Phone,
               hp_r: 0.967_805, lp_a: 0.375_772, drive: 1.2, noise: 0.006,
               crush_hold: 3, crush_step: 1.0 / 128.0, gain: 1.55, ..PLAIN },
    FxPreset { id: "badvoip", label: "Bad VoIP", family: FxFamily::Phone,
               hp_r: 0.974_160, lp_a: 0.391_902, drive: 1.5, noise: 0.010,
               crush_hold: 6, crush_step: 1.0 / 48.0, gain: 1.20, ..PLAIN },
    FxPreset { id: "intercom", label: "Intercom", family: FxFamily::Phone,
               hp_r: 0.955_219, lp_a: 0.342_216, drive: 2.0, noise: 0.012,
               gain: 1.15, ..PLAIN },
    // Colour: not a device, just a voice that is not yours.
    FxPreset { id: "megaphone", label: "Megaphone", family: FxFamily::Colour,
               hp_r: 0.936_646, lp_a: 0.324_768, drive: 6.0, gain: 0.65, ..PLAIN },
    FxPreset { id: "gramophone", label: "Gramophone", family: FxFamily::Colour,
               hp_r: 0.974_160, lp_a: 0.324_768, drive: 1.5, noise: 0.012,
               crackle: 0.05, crush_hold: 2, crush_step: 1.0 / 160.0, gain: 1.20, ..PLAIN },
    FxPreset { id: "robot", label: "Robot", family: FxFamily::Colour,
               hp_r: 0.974_160, drive: 1.5, ring_k: 0.007_854, gain: 1.70, ..PLAIN },
];

/// The parameters for a chain, or `None` for no effect at all.
pub fn preset(fx: Effect) -> Option<&'static FxPreset> {
    let i = fx as usize;
    if i == 0 {
        None
    } else {
        PRESETS.get(i - 1)
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
fn fx_sample(st: &mut SourceMixState, x: f32, a: f32, p: Option<&FxPreset>) -> f32 {
    let mut x = x;
    // Chain order is load-bearing and must not be shuffled:
    //   drive → noise → crackle → ring → squelch → HP×2 → crush → LP1 → LP2
    // Every stage is behind its own guard so a preset that asks for none of
    // them does not touch the noise generator — one stray call there shifts the
    // xorshift stream and breaks the golden vector for every preset at once.
    if let Some(p) = p {
        if p.drive > 0.0 {
            let d = x * p.drive;
            x = d / (1.0 + d.abs());
        }
        if p.noise > 0.0 {
            x += p.noise * white(&mut st.noise);
        }
        if p.crackle > 0.0 {
            // Reuses the same generator: a rare loud sample, not a hiss
            let w = white(&mut st.noise);
            if w.abs() > 0.995 {
                x += p.crackle * w * 8.0;
            }
        }
        if p.ring_k > 0.0 {
            // Magic-circle oscillator: a sine without calling sin() per sample
            st.ring_u -= p.ring_k * st.ring_v;
            st.ring_v += p.ring_k * st.ring_u;
            x *= st.ring_v;
        }
    }
    if st.burst > 0 {
        let env = st.burst as f32 / SQUELCH_SAMPLES as f32;
        st.burst -= 1;
        x += SQUELCH_GAIN * env * white(&mut st.noise);
    }
    // Two one-pole high-pass stages
    let hp_r = p.map_or(FX_HP_R, |p| p.hp_r);
    let h1 = hp_r * (st.hp[1] + x - st.hp[0]);
    st.hp[0] = x;
    st.hp[1] = h1;
    let h2 = hp_r * (st.hp[3] + h1 - st.hp[2]);
    st.hp[2] = h1;
    st.hp[3] = h2;

    let mut input = if p.is_none() { x } else { h2 };
    // Bit-crush between the high-passes and the band-limit: after the low-pass
    // its images would land above 3.4 kHz where nothing is left to filter them.
    if let Some(p) = p {
        if p.crush_hold > 1 {
            if st.crush_i == 0 {
                st.crush_hold = input;
                st.crush_i = p.crush_hold;
            }
            st.crush_i -= 1;
            input = st.crush_hold;
        }
        if p.crush_step > 0.0 {
            input = (input / p.crush_step).round() * p.crush_step;
        }
    }
    st.lowpass += a * (input - st.lowpass);
    let first = if a >= 1.0 { input } else { st.lowpass };
    let lp_a = p.map_or(FX_LP_A, |p| p.lp_a);
    st.lowpass2 += lp_a * (first - st.lowpass2);
    if p.is_none() {
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
    let p = preset(fx);
    // The makeup gain rides the same ramp as everything else, so switching
    // preset mid-sentence changes the voice without stepping the level. It has
    // to be folded in *before* priming, or the very first frame of every preset
    // with a makeup ramps down to it from unity instead of starting there.
    let makeup = p.map_or(1.0, |p| p.gain);
    let target = (target.0 * makeup, target.1 * makeup);
    if !state.primed {
        state.gain_l = target.0;
        state.gain_r = target.1;
        state.primed = true;
    }
    state.idle = 0;
    if p.is_some_and(|p| p.squelch) && !state.talking {
        state.burst = SQUELCH_SAMPLES;
    }
    state.talking = fx != Effect::None;

    let step_l = (target.0 - state.gain_l) / n as f32;
    let step_r = (target.1 - state.gain_r) / n as f32;
    let (mut gl, mut gr) = (state.gain_l, state.gain_r);
    // An effected voice is never muffled on top of its own band-limit (it is
    // not in the room), so the first stage runs at the band-limit instead.
    let a = match p {
        None => lp_a.clamp(0.0, 1.0),
        Some(p) => lp_a.clamp(0.0, 1.0).min(p.lp_a),
    };

    let mut sum = 0.0f32;
    for i in 0..n {
        let s = fx_sample(state, pcm[i], a, p);
        sum += s * s;
        out[2 * i] += s * gl;
        out[2 * i + 1] += s * gr;
        gl += step_l;
        gr += step_r;
    }
    // Pre-fader, but after the makeup, so a loud preset does not read quiet
    state.level = (sum / n as f32).sqrt() * makeup;

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
    let p = preset(fx);
    if state.talking {
        state.idle = state.idle.saturating_add(1);
        if ended || state.idle >= FX_IDLE_FRAMES {
            state.talking = false;
            state.idle = 0;
            if p.is_some_and(|p| p.squelch) {
                state.burst = SQUELCH_SAMPLES;
            }
        }
    }
    // Nothing played, so the meter reads nothing — otherwise every strip
    // freezes at its last value the moment the room goes quiet.
    state.level = 0.0;
    let n = (state.burst as usize).min(out.len() / 2);
    if n == 0 {
        state.burst = 0;
        return false;
    }
    let (gl, gr) = (state.gain_l, state.gain_r);
    let lp_a = p.map_or(FX_LP_A, |p| p.lp_a);
    for i in 0..n {
        let s = fx_sample(state, 0.0, lp_a, p);
        out[2 * i] += s * gl;
        out[2 * i + 1] += s * gr;
    }
    true
}

/// Reverb and water over one interleaved stereo frame, in place.
///
/// `had_input` says whether anything was written into `out` this frame; a
/// reverb tail has to keep the mixer awake after the last speaker stops, so
/// the return value is "something is still audible", not "I did something".
///
/// At level 0 on both this is a bit-exact bypass: `out` is not touched at all.
pub fn apply_reverb_water(
    out: &mut [f32],
    st: &mut ReverbWaterState,
    underwater: u8,
    reverb: u8,
    had_input: bool,
) -> bool {
    reverb_water(out, 2, st, underwater, reverb, had_input)
}

/// The same two effects over a mono buffer: one lane before it is panned, or
/// our own microphone on its way out. One caveat worth knowing: a reverb tail
/// is never silence, so on the way out it keeps Opus from dropping frames
/// between phrases, exactly as a radio's hiss does.
pub fn apply_reverb_water_mono(
    out: &mut [f32],
    st: &mut ReverbWaterState,
    underwater: u8,
    reverb: u8,
    had_input: bool,
) -> bool {
    reverb_water(out, 1, st, underwater, reverb, had_input)
}

/// Everything one lane's audio passes through, and the state it carries.
///
/// A lane is a lane: our own microphone on the way out, or one other person on
/// the way in. Both get the same controls — an effect, and three scalable ones
/// (muffle, reverb, water) — so there is no "room" that lives somewhere else
/// and behaves by its own rules.
///
/// Order is effect first, then the room: a radio in a cave is a radio, in a
/// cave. The panning and the volume ramp come last, on the way into the mix.
pub struct SourceChain {
    /// Filters, hiss and squelch. Public because the spatial test drives it.
    pub mix: SourceMixState,
    room: ReverbWaterState,
    /// One lane's mono frame between the effect and the pan. Grown once.
    scratch: Vec<f32>,
}

impl Default for SourceChain {
    fn default() -> Self {
        Self {
            mix: SourceMixState::default(),
            room: ReverbWaterState::default(),
            scratch: Vec::new(),
        }
    }
}

impl SourceChain {
    /// Render one frame of this lane into the interleaved stereo mix.
    ///
    /// `lp_a` is the muffle coefficient, `fx` the effect, and the two levels
    /// the lane's own reverb and water. Gains ramp across the frame, so
    /// nothing here steps.
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &mut self,
        out: &mut [f32],
        pcm: &[f32],
        target: (f32, f32),
        lp_a: f32,
        fx: Effect,
        underwater: u8,
        reverb: u8,
    ) {
        let n = pcm.len().min(out.len() / 2);
        if n == 0 {
            self.mix.gain_l = target.0;
            self.mix.gain_r = target.1;
            return;
        }
        self.scratch.clear();
        self.scratch.extend_from_slice(&pcm[..n]);
        self.effect_pass(fx, lp_a);
        apply_reverb_water_mono(&mut self.scratch, &mut self.room, underwater, reverb, true);

        let makeup = preset(fx).map_or(1.0, |p| p.gain);
        let target = (target.0 * makeup, target.1 * makeup);
        if !self.mix.primed {
            self.mix.gain_l = target.0;
            self.mix.gain_r = target.1;
            self.mix.primed = true;
        }
        let step_l = (target.0 - self.mix.gain_l) / n as f32;
        let step_r = (target.1 - self.mix.gain_r) / n as f32;
        let (mut gl, mut gr) = (self.mix.gain_l, self.mix.gain_r);
        let mut sum = 0.0f32;
        for i in 0..n {
            let s = self.scratch[i];
            sum += s * s;
            out[2 * i] += s * gl;
            out[2 * i + 1] += s * gr;
            gl += step_l;
            gr += step_r;
        }
        // Pre-fader but after the makeup: a muted or distant lane still shows
        // a level, which is exactly the lane you opened the mixer to find, and
        // a loud preset must not read quiet.
        self.mix.level = (sum / n as f32).sqrt() * makeup;
        self.mix.gain_l = target.0;
        self.mix.gain_r = target.1;
    }

    /// Render one frame of our own microphone, in place and mono, on its way
    /// out. The same chain in the same order as a lane coming in.
    pub fn render_mono(&mut self, buf: &mut [f32], fx: Effect, lp_a: f32, underwater: u8, reverb: u8) {
        self.scratch.clear();
        self.scratch.extend_from_slice(buf);
        self.effect_pass(fx, lp_a);
        apply_reverb_water_mono(&mut self.scratch, &mut self.room, underwater, reverb, true);
        let makeup = preset(fx).map_or(1.0, |p| p.gain);
        for (dst, &s) in buf.iter_mut().zip(self.scratch.iter()) {
            *dst = (s * makeup).clamp(-1.0, 1.0);
        }
    }

    /// The effect, over `self.scratch`, in place.
    fn effect_pass(&mut self, fx: Effect, lp_a: f32) {
        let p = preset(fx);
        if p.is_some_and(|p| p.squelch) && !self.mix.talking {
            self.mix.burst = SQUELCH_SAMPLES;
        }
        self.mix.talking = fx != Effect::None;
        self.mix.idle = 0;
        let a = match p {
            None => lp_a.clamp(0.0, 1.0),
            Some(p) => lp_a.clamp(0.0, 1.0).min(p.lp_a),
        };
        for i in 0..self.scratch.len() {
            self.scratch[i] = fx_sample(&mut self.mix, self.scratch[i], a, p);
        }
    }

    /// Nothing to play this frame: close a radio's squelch, and keep the
    /// reverb tail running so it is not cut off mid-decay. Returns whether
    /// anything was written.
    pub fn stop(
        &mut self,
        out: &mut [f32],
        fx: Effect,
        ended: bool,
        underwater: u8,
        reverb: u8,
    ) -> bool {
        let owed = mix_source_stop_len(&mut self.mix, fx, ended);
        let n = out.len() / 2;
        if n == 0 {
            self.mix.burst = 0;
            return false;
        }
        // What is actually still ringing, not what is switched on: a lane sat
        // at reverb 10 with nobody talking has an empty bank, and asking the
        // settings instead would run it for ever.
        if owed == 0 && self.room.tail == 0 {
            return false;
        }
        self.scratch.clear();
        self.scratch.resize(n, 0.0);
        if owed > 0 {
            let lp_a = preset(fx).map_or(FX_LP_A, |p| p.lp_a);
            let p = preset(fx);
            for i in 0..n.min(owed) {
                self.scratch[i] = fx_sample(&mut self.mix, 0.0, lp_a, p);
            }
        }
        let ringing =
            apply_reverb_water_mono(&mut self.scratch, &mut self.room, underwater, reverb, owed > 0);
        let (gl, gr) = (self.mix.gain_l, self.mix.gain_r);
        let mut wrote = false;
        for i in 0..n {
            if self.scratch[i] != 0.0 {
                out[2 * i] += self.scratch[i] * gl;
                out[2 * i + 1] += self.scratch[i] * gr;
                wrote = true;
            }
        }
        self.mix.level = 0.0;
        wrote || ringing
    }
}

/// How many squelch samples this frame owes, advancing the idle counter.
/// Split out of [`mix_source_stop`] so [`SourceChain`] can reuse the rule.
fn mix_source_stop_len(state: &mut SourceMixState, fx: Effect, ended: bool) -> usize {
    let p = preset(fx);
    if state.talking {
        state.idle = state.idle.saturating_add(1);
        if ended || state.idle >= FX_IDLE_FRAMES {
            state.talking = false;
            state.idle = 0;
            if p.is_some_and(|p| p.squelch) {
                state.burst = SQUELCH_SAMPLES;
            }
        }
    }
    state.burst as usize
}

/// Clamp a mixed buffer to [-1.0, 1.0]. Call once after every source has been
/// accumulated (per-source clamping would distort each stream separately).
pub fn clamp(buf: &mut [f32]) {
    for sample in buf.iter_mut() {
        *sample = sample.clamp(-1.0, 1.0);
    }
}

// ── Reverb and water ─────────────────────────────────────────────────────
//
// Two scalable effects, 0–10 each, exactly like muffle. They belong to a lane:
// one person's voice on the way in, or our own microphone on the way out. Every
// lane carries its own pair and its own delay lines, so "put that one person in
// a cave" and "put my own voice in a cave" are the same operation on different
// lanes rather than two different concepts.
//
// The reverb is Freeverb with four combs instead of eight — Schroeder's comb
// bank into two series allpasses, damped inside the feedback path. Half the
// combs is half the ringing modes and half the memory, and with speech nobody
// hears the difference.
// bernd: four combs, add the other four if a cathedral ever sounds grainy.

/// Cutoff (Hz) → one-pole coefficient at 48 kHz.
pub fn one_pole_a(fc: f32) -> f32 {
    1.0 - (-2.0 * core::f32::consts::PI * fc / 48_000.0).exp()
}

/// Underwater cutoff (Hz) at level 10. Below the muffle filter's 350 Hz *and*
/// two poles instead of one, so submerged does not sound like a wall.
const UW_FC_MIN: f32 = 230.0;
/// Cutoff (Hz) per level, index 0 being bypass.
///
/// A table rather than a formula, because nothing convenient is linear here.
/// Interpolating the cutoff geometrically (which is what shipped, from 22 kHz)
/// spends the first half of the slider above the voice band, where a voice has
/// nothing: measured, steps 1 to 5 moved a 1 kHz tone by 0.83, 0.86, 0.93, 1.11
/// and 1.49 dB, so the control read as an on/off switch. These cutoffs are
/// solved backwards from the two-pole response instead, for an even step at
/// 1 kHz — which is the only thing that makes every notch of the slider count.
const UW_FC: [f32; 11] = [
    0.0, 1688.0, 1103.0, 828.0, 657.0, 537.0, 446.0, 374.0, 317.0, 269.0, UW_FC_MIN,
];
/// Attenuation (dB) at full submersion, reached along [`UW_CUT_CURVE`].
const UW_CUT_DB: f32 = 6.0;
/// The level cut is curved rather than linear, so the early steps change the
/// tone (which is what "underwater" is) before they change the loudness.
const UW_CUT_CURVE: f32 = 2.0;

/// Freeverb's combs 1, 3, 5 and 7, scaled from 44.1 to 48 kHz. The wide spread
/// decorrelates better than four adjacent ones.
const REVERB_COMB: [usize; 4] = [1215, 1390, 1548, 1695];
/// Freeverb's two series allpasses, same scaling.
const REVERB_ALLPASS: [usize; 2] = [605, 480];
/// One-pole damping inside each comb's feedback path: without it the tail
/// keeps its highs and rings metallically.
const REVERB_DAMP_FC: f32 = 4_000.0;
/// Comb feedback runs from `MIN` (short room) to `MIN + SPAN` (cathedral).
const REVERB_FB_MIN: f32 = 0.70;
const REVERB_FB_SPAN: f32 = 0.22;
/// Send into the comb bank, normalised by the bank's own broadband power gain
/// so the wet level stays put when the room size (and with it the feedback)
/// moves.
///
/// This replaces a flat 0.015 copied from Freeverb's `fixedgain`, which belongs
/// to an eight-comb bank with a different normalisation. Carrying a constant
/// across topologies put the wet path 35 dB under the dry — measured at −34.8 dB
/// at reverb 3, i.e. inaudible at every setting. A comb bank's *broadband* gain
/// is nothing like its DC gain of 1/(1 - feedback), which is what that reasoning
/// got wrong.
const REVERB_NORM: f32 = 0.70;

#[inline]
fn reverb_in(fb: f32) -> f32 {
    REVERB_NORM * ((1.0 - fb * fb) / 4.0).sqrt()
}

/// How much the dry path is trimmed at a given reverb level, so a room full of
/// talkers keeps its headroom instead of living on [`clamp`].
///
/// A named function because it is the only thing a test can pin it by: the trim
/// scales the wet send and the dry path alike, so it is invisible to any
/// wet-to-dry ratio, and four talkers do not clip with or without it, so it is
/// invisible to any clipping check too.
fn dry_trim(reverb: u8) -> f32 {
    let r = reverb.min(crate::spatial::MAX_REVERB) as f32 / crate::spatial::MAX_REVERB as f32;
    let wet = REVERB_WET_MAX * r.powf(REVERB_WET_CURVE);
    (1.0 - wet * wet).sqrt()
}
/// Wet gain at level 10. This is the one loudness knob — retune it, not the
/// topology, if the room ever swamps or vanishes.
const REVERB_WET_MAX: f32 = 0.47;
/// The wet level rises faster than linearly with the slider, so a small room
/// stays subtle while a cathedral is unmistakable.
const REVERB_WET_CURVE: f32 = 1.35;
/// Frames (20 ms) of tail rendered after the last source went quiet. Must
/// exceed the longest RT60 above, or a tail is cut mid-decay.
const REVERB_TAIL_FRAMES: u16 = 150;

/// A fixed-length delay line. Reads the oldest sample, then overwrites it.
#[derive(Debug)]
struct Delay {
    buf: Box<[f32]>,
    i: usize,
}

impl Delay {
    fn new(len: usize) -> Self {
        Self {
            buf: vec![0.0; len].into_boxed_slice(),
            i: 0,
        }
    }

    #[inline]
    fn read(&self) -> f32 {
        self.buf[self.i]
    }

    #[inline]
    fn write(&mut self, v: f32) {
        self.buf[self.i] = v;
        self.i += 1;
        if self.i == self.buf.len() {
            self.i = 0;
        }
    }

    fn clear(&mut self) {
        self.buf.fill(0.0);
        self.i = 0;
    }
}

/// What one lane's reverb and water carry between frames. One per lane; about
/// 22 kB of delay line, allocated once.
#[derive(Debug)]
pub struct ReverbWaterState {
    comb: [Delay; 4],
    /// Damping state inside each comb's feedback path.
    damp: [f32; 4],
    allpass: [Delay; 2],
    /// Two cascaded one-poles per channel: `[l1, l2, r1, r2]`.
    uw: [f32; 4],
    /// Underwater attenuation, ramped across the frame.
    gain: f32,
    /// Reverb send, ramped across the frame.
    wet: f32,
    /// Cleared until the first frame, so it jumps to its target instead of
    /// ramping — the same rule a source's gains follow.
    primed: bool,
    /// Frames of tail still owed after the last source went quiet.
    pub(crate) tail: u16,
    /// Whether anything has been written into the delay lines since the last
    /// [`ReverbWaterState::clear`]. A lane with nothing switched on is the common
    /// case and there are as many of these as there are people talking, so the
    /// bypass path must not wipe 22 kB per lane per frame.
    dirty: bool,
    /// Whether the comb bank has been fed since it was last wiped. Separate
    /// from `dirty` because a lane that is only underwater keeps filtering while
    /// its bank is idle, and wiping 22 kB every frame is exactly what this is
    /// here to avoid.
    bank_live: bool,
}

impl Default for ReverbWaterState {
    fn default() -> Self {
        Self {
            comb: [
                Delay::new(REVERB_COMB[0]),
                Delay::new(REVERB_COMB[1]),
                Delay::new(REVERB_COMB[2]),
                Delay::new(REVERB_COMB[3]),
            ],
            damp: [0.0; 4],
            allpass: [Delay::new(REVERB_ALLPASS[0]), Delay::new(REVERB_ALLPASS[1])],
            uw: [0.0; 4],
            gain: 1.0,
            wet: 0.0,
            primed: false,
            tail: 0,
            dirty: false,
            bank_live: false,
        }
    }
}

impl ReverbWaterState {
    /// Forget the comb bank, which is what a reverb tail lives in.
    fn clear_bank(&mut self) {
        for c in self.comb.iter_mut() {
            c.clear();
        }
        for a in self.allpass.iter_mut() {
            a.clear();
        }
        self.damp = [0.0; 4];
        self.tail = 0;
        self.bank_live = false;
    }

    /// Forget every delay line. Called when the room is fully off, so turning
    /// it back on cannot replay a second of stale speech.
    fn clear(&mut self) {
        self.clear_bank();
        self.uw = [0.0; 4];
        self.dirty = false;
    }
}

/// One lane's reverb and water over one frame, in place.
///
/// `stride` is 2 for an interleaved stereo buffer and 1 for a mono one — every
/// lane is mono until it is panned, and the microphone is mono all the way out.
/// Everything else is identical, so what you put on your own voice and what you
/// put on somebody else's is the same processing.
fn reverb_water(
    out: &mut [f32],
    stride: usize,
    st: &mut ReverbWaterState,
    underwater: u8,
    reverb: u8,
    had_input: bool,
) -> bool {
    let u = underwater.min(crate::spatial::MAX_UNDERWATER) as f32
        / crate::spatial::MAX_UNDERWATER as f32;
    let r = reverb.min(crate::spatial::MAX_REVERB) as f32 / crate::spatial::MAX_REVERB as f32;
    let level = underwater.min(crate::spatial::MAX_UNDERWATER) as usize;
    let a = if level == 0 {
        1.0
    } else {
        one_pole_a(UW_FC[level])
    };
    let wet_t = REVERB_WET_MAX * r.powf(REVERB_WET_CURVE);
    let gain_t = 10f32.powf(-UW_CUT_DB * u.powf(UW_CUT_CURVE) / 20.0) * dry_trim(reverb);

    // Nothing on, nothing left ringing: leave the mix exactly as it was.
    if a >= 1.0 && wet_t == 0.0 && st.gain == 1.0 && st.wet == 0.0 && st.tail == 0 {
        if st.dirty {
            st.clear();
        }
        return false;
    }

    if !st.primed {
        st.gain = gain_t;
        st.wet = wet_t;
        st.primed = true;
    }

    let n = out.len() / stride;
    if n == 0 {
        st.gain = gain_t;
        st.wet = wet_t;
        return st.tail > 0;
    }

    let fb = REVERB_FB_MIN + REVERB_FB_SPAN * r;
    let rev_in = reverb_in(fb);
    let damp_a = one_pole_a(REVERB_DAMP_FC);
    let step_gain = (gain_t - st.gain) / n as f32;
    let step_wet = (wet_t - st.wet) / n as f32;
    let (mut gain, mut wet) = (st.gain, st.wet);
    // The send this frame starts at, so a wet path ramping down to zero still
    // counts while it is audible.
    let was_wet = st.wet;
    // With no wet path and nothing still ringing, the bank's output is
    // multiplied by zero: skip it rather than feed it. That is the whole cost
    // of a lane somebody once put reverb on, or of a lane that is only
    // underwater, and it is four combs and two allpasses per sample.
    let run_reverb = wet_t > 0.0 || was_wet > 0.0 || st.tail > 0;
    if !run_reverb && st.bank_live {
        // Once, on the way down: a reverb switched on later starts in an empty
        // room rather than replaying what the lane was saying a second ago.
        st.clear_bank();
    }

    for i in 0..n {
        // Underwater first: two cascaded one-poles per channel, then the cut.
        // The filters advance even at bypass, so switching on cannot pop.
        let (l_in, r_in) = if stride == 2 {
            (out[2 * i], out[2 * i + 1])
        } else {
            (out[i], out[i])
        };
        st.uw[0] += a * (l_in - st.uw[0]);
        st.uw[1] += a * (st.uw[0] - st.uw[1]);
        st.uw[2] += a * (r_in - st.uw[2]);
        st.uw[3] += a * (st.uw[2] - st.uw[3]);
        let (l, r) = if a >= 1.0 {
            (l_in, r_in)
        } else {
            (st.uw[1], st.uw[3])
        };
        let (l, r) = (l * gain, r * gain);

        // The reverb hears the room through the water, which is what a cave
        // with a flooded floor should sound like — and one branch fewer.
        let mut w = 0.0;
        if run_reverb {
            let mono = 0.5 * (l + r) * rev_in;
            for k in 0..4 {
                let y = st.comb[k].read();
                st.damp[k] += damp_a * (y - st.damp[k]);
                st.comb[k].write(mono + st.damp[k] * fb);
                w += y;
            }
            for k in 0..2 {
                let b = st.allpass[k].read();
                st.allpass[k].write(w + b * 0.5);
                w = b - w;
            }
        }

        if stride == 2 {
            out[2 * i] = l + w * wet;
            out[2 * i + 1] = r + w * wet;
        } else {
            out[i] = l + w * wet;
        }
        gain += step_gain;
        wet += step_wet;
    }

    st.gain = gain_t;
    st.wet = wet_t;
    st.dirty = true;
    st.bank_live |= run_reverb;
    // Input only counts as *reverb* input while there is a wet path to put it
    // into. Counting every frame that carried audio re-armed the tail for ever,
    // so a lane whose reverb was once turned up and then back to zero never
    // reached the bypass above again: it ran four combs and two allpasses per
    // sample for the rest of its life, and the microphone's lane — rendered
    // every 20 ms whether or not anything is switched on — for the rest of the
    // session.
    st.tail = if had_input && (wet_t > 0.0 || was_wet > 0.0) {
        REVERB_TAIL_FRAMES
    } else {
        st.tail.saturating_sub(1)
    };
    // "Still audible" is the tail alone, never the settings: a lane with the
    // reverb turned up is *configured* to ring, but a bank fed nothing for
    // REVERB_TAIL_FRAMES has nothing left in it. Answering "yes" from the
    // settings kept the mixer awake for ever and ran the comb bank on
    // subnormals through every silence. Zero the lines on the way out, so the
    // next voice starts in an empty room rather than in a denormal one.
    //
    // Not while audio is still flowing through the water, though: wiping the
    // water filters mid-stream is a click, and with the reverb off the tail sits
    // at zero for ever, so it would be a click on every frame.
    if st.tail == 0 && (!had_input || (wet_t == 0.0 && a >= 1.0)) {
        st.clear();
    }
    st.tail > 0
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

    // ── Reverb and water ────────────────────────────────────────────────

    /// Runs a sine through [`apply_reverb_water`] and returns the left channel.
    /// `feed` frames carry signal, the rest are silence, so a tail can be
    /// heard on its own.
    fn room_through(hz: f32, underwater: u8, reverb: u8, frames: usize, feed: usize) -> Vec<f32> {
        let mut st = ReverbWaterState::default();
        let mut kept = Vec::new();
        for f in 0..frames {
            let mut out = vec![0.0f32; 1920];
            let live = f < feed;
            if live {
                for i in 0..960 {
                    let n = (f * 960 + i) as f32;
                    let s = 0.25 * (2.0 * core::f32::consts::PI * hz * n / 48_000.0).sin();
                    out[2 * i] = s;
                    out[2 * i + 1] = s;
                }
            }
            apply_reverb_water(&mut out, &mut st, underwater, reverb, live);
            kept.extend(out.iter().step_by(2));
        }
        kept
    }

    const MAX_UW: u8 = crate::spatial::MAX_UNDERWATER;

    #[test]
    fn underwater_cuts_the_highs_and_level_zero_is_a_bit_exact_bypass() {
        // The level cut applies at every frequency, so what says "low-pass" is
        // the tilt between a high tone and a low one, not either cut alone.
        let cut = |hz: f32| {
            rms_db(&room_through(hz, 0, 0, 6, 6)[2 * 960..])
                - rms_db(&room_through(hz, MAX_UW, 0, 6, 6)[2 * 960..])
        };
        let (low, high) = (cut(200.0), cut(6_000.0));
        assert!(high - low > 15.0, "tilt of only {} dB", high - low);
        // The low end keeps the deliberate 8 dB cut and little more
        assert!(low < 13.0, "200 Hz cut by {low} dB");

        // Level 0 on both must not touch the buffer at all
        let mut st = ReverbWaterState::default();
        let pcm: Vec<f32> = (0..1920).map(|i| (i as f32 * 0.03).sin()).collect();
        let mut out = pcm.clone();
        assert!(!apply_reverb_water(&mut out, &mut st, 0, 0, true));
        assert_eq!(out, pcm, "an idle room altered the mix");
    }

    #[test]
    fn reverb_rings_after_the_speaker_stops_and_then_stops_itself() {
        // Long enough to reach steady state: a comb bank at this feedback
        // takes a few hundred ms to fill, so a short feed is still *rising*
        // when the input stops.
        let tail = room_through(400.0, 0, 8, 60, 20);
        let energy = |frame: usize| {
            tail[frame * 960..(frame + 1) * 960]
                .iter()
                .map(|s| s * s)
                .sum::<f32>()
        };
        assert!(energy(21) > 1e-6, "nothing rang after the speaker stopped");
        assert!(energy(55) < 0.5 * energy(21), "the tail did not decay");
        assert!(
            tail.iter().all(|s| s.is_finite() && s.abs() <= 4.0),
            "runaway feedback"
        );

        // And it eventually goes back to sleep
        let mut st = ReverbWaterState::default();
        let mut out = vec![0.0f32; 1920];
        apply_reverb_water(&mut out, &mut st, 0, 8, true);
        let mut closed = false;
        for _ in 0..(REVERB_TAIL_FRAMES + 2) {
            out.iter_mut().for_each(|s| *s = 0.0);
            if !apply_reverb_water(&mut out, &mut st, 0, 0, false) {
                closed = true;
                break;
            }
        }
        assert!(closed, "the room never went idle again");
    }

    #[test]
    fn a_lane_left_switched_on_still_goes_quiet() {
        // The real shape of the bug the test above misses: nobody turns the
        // reverb *off* when a speaker stops talking, so the level stays at 8
        // for every one of these frames. Answering "still audible" from the
        // level rather than from the tail kept the mixer awake for ever, and
        // the comb bank then ran on subnormals through every silence.
        let mut st = ReverbWaterState::default();
        let mut out = vec![0.0f32; 1920];
        for (i, s) in out.iter_mut().enumerate() {
            *s = (i as f32 * 0.03).sin();
        }
        assert!(apply_reverb_water(&mut out, &mut st, 3, 8, true));

        let mut closed = None;
        for frame in 0..(REVERB_TAIL_FRAMES + 2) {
            out.iter_mut().for_each(|s| *s = 0.0);
            // Same levels as while they were talking — that is the point
            if !apply_reverb_water(&mut out, &mut st, 3, 8, false) {
                closed = Some(frame);
                break;
            }
        }
        assert_eq!(
            closed,
            Some(REVERB_TAIL_FRAMES - 1),
            "a lane with the reverb up never stopped ringing"
        );
        // Exactly zero, not merely small: a bank left holding 1e-38 costs a
        // denormal penalty on every sample it is fed afterwards.
        assert!(
            st.comb.iter().all(|c| c.buf.iter().all(|&s| s == 0.0)),
            "the comb bank was left holding a tail"
        );
        assert!(st.allpass.iter().all(|a| a.buf.iter().all(|&s| s == 0.0)));
        assert_eq!(st.uw, [0.0; 4], "the water filters kept their state");
    }

    #[test]
    fn a_reverb_turned_back_down_stops_costing_anything() {
        // The tail was re-armed by any frame carrying audio, wet or not, so a
        // lane somebody once put reverb on ran four combs and two allpasses per
        // sample for the rest of its life — and the microphone's lane, which is
        // rendered every 20 ms whether or not anything is switched on, for the
        // rest of the session.
        let src: Vec<f32> = (0..960).map(|i| 0.2 * (i as f32 * 0.03).sin()).collect();
        let mut st = ReverbWaterState::default();
        for _ in 0..5 {
            let mut buf = src.clone();
            assert!(apply_reverb_water_mono(&mut buf, &mut st, 0, 8, true));
        }
        // Back to zero, with the speaker still talking
        let mut closed = None;
        for f in 0..REVERB_TAIL_FRAMES + 2 {
            let mut buf = src.clone();
            if !apply_reverb_water_mono(&mut buf, &mut st, 0, 0, true) {
                closed = Some(f);
                break;
            }
        }
        let closed = closed.expect("a lane with the reverb back at zero never went quiet");
        assert!(closed <= REVERB_TAIL_FRAMES, "it took {closed} frames");
        // …and from there it is the bit-exact bypass again
        let mut buf = src.clone();
        assert!(!apply_reverb_water_mono(&mut buf, &mut st, 0, 0, true));
        assert_eq!(buf, src, "a lane with nothing on is not a bypass");
        for c in st.comb.iter() {
            assert!(c.buf.iter().all(|s| *s == 0.0), "a comb kept its tail");
        }
    }

    #[test]
    fn underwater_alone_keeps_filtering_for_ever() {
        // The reverb's tail rule must not wipe the water filters mid-stream: a
        // lane that is only submerged has no tail, so a shared "wipe when the
        // tail runs out" would reset its poles on every frame — a click at
        // every frame boundary, for as long as the lane is underwater.
        let src: Vec<f32> = (0..960).map(|i| 0.2 * (i as f32 * 0.3).sin()).collect();
        let mut st = ReverbWaterState::default();
        let mut last = Vec::new();
        for _ in 0..REVERB_TAIL_FRAMES + 10 {
            last = src.clone();
            apply_reverb_water_mono(&mut last, &mut st, 8, 0, true);
        }
        // Still filtering (a 2.3 kHz tone against a 317 Hz cutoff is gone), and
        // the filter is in its steady state rather than starting from zero
        let energy: f32 = last.iter().map(|s| s * s).sum();
        let dry: f32 = src.iter().map(|s| s * s).sum();
        assert!(energy < dry * 0.2, "the water stopped filtering: {energy} vs {dry}");
        assert!(st.uw.iter().any(|s| *s != 0.0), "the water filters were wiped mid-stream");
    }

    #[test]
    fn a_silent_lane_with_its_reverb_up_stops_asking_to_be_mixed() {
        // The same rule one layer up, where the mixer actually reads it:
        // `SourceChain::stop` must stop claiming the frame once the bank is
        // empty, or `voice_mixer_task` never takes its early-out.
        let mut chain = SourceChain::default();
        let pcm: Vec<f32> = (0..960).map(|i| (i as f32 * 0.03).sin()).collect();
        let mut out = vec![0.0f32; 1920];
        chain.render(&mut out, &pcm, (1.0, 1.0), 1.0, Effect::None, 0, 8);

        let mut closed = None;
        for frame in 0..(REVERB_TAIL_FRAMES + 2) {
            out.iter_mut().for_each(|s| *s = 0.0);
            if !chain.stop(&mut out, Effect::None, true, 0, 8) {
                closed = Some(frame);
                break;
            }
        }
        // One frame later than the bank goes idle: the frame that drains the
        // last of the tail still writes those samples, so it still counts.
        assert_eq!(closed, Some(REVERB_TAIL_FRAMES), "the lane never went quiet");
    }

    #[test]
    fn the_room_is_deterministic() {
        let a = room_through(300.0, 4, 6, 5, 3);
        let b = room_through(300.0, 4, 6, 5, 3);
        assert_eq!(a, b, "two fresh rooms must sound the same");
    }

    #[test]
    fn a_mono_sender_pass_is_bit_exact_when_off_and_still_advances_its_filters() {
        // The sender chain: mix at unity into a scratch, read the even samples
        // back. With Effect::None it must not alter one bit.
        let mut st = SourceMixState::default();
        let mut scratch = vec![0.0f32; 1920];
        for f in 0..2 {
            let pcm: Vec<f32> = (0..960)
                .map(|i| ((f * 960 + i) as f32 * 0.01).sin() * 0.5)
                .collect();
            scratch.fill(0.0);
            mix_source_fx(&mut scratch, &pcm, &mut st, (1.0, 1.0), 1.0, Effect::None);
            for (i, &s) in pcm.iter().enumerate() {
                assert_eq!(scratch[2 * i], s, "frame {f} sample {i} was altered");
            }
        }
        assert!(st.lowpass != 0.0, "the filters did not advance while off");
    }

    #[test]
    fn an_empty_stop_rearms_the_opening_squelch() {
        // The sender calls mix_source_fx every frame, so `talking` would never
        // fall by itself and a VAD sender would squelch exactly once.
        let mut st = SourceMixState::default();
        let mut scratch = vec![0.0f32; 1920];
        let energy = |b: &[f32]| b.iter().step_by(2).map(|s| s * s).sum::<f32>();

        scratch.fill(0.0);
        mix_source_fx(&mut scratch, &[0.0; 960], &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        let first = energy(&scratch);

        // Off air: clears `talking` without owing a burst
        assert!(!mix_source_stop(&mut [], &mut st, Effect::Radio, true));
        scratch.fill(0.0);
        mix_source_fx(&mut scratch, &[0.0; 960], &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        let second = energy(&scratch);

        scratch.fill(0.0);
        mix_source_fx(&mut scratch, &[0.0; 960], &mut st, (1.0, 1.0), 1.0, Effect::Radio);
        let third = energy(&scratch);

        assert!(second > 4.0 * third, "the squelch did not re-open");
        assert!(first > 4.0 * third, "the first burst is missing");
    }


    /// Sample indices the golden vector pins, chosen around the squelch edge
    /// (480) and the frame boundaries (960, 1920).
    pub(crate) const GOLDEN_IDX: [usize; 12] =
        [0, 1, 2, 479, 480, 481, 959, 960, 1439, 1440, 1919, 2879];

    /// Three frames of a 200 Hz half-amplitude sine through a fresh radio.
    /// Deterministic: the xorshift seed is fixed, so the hiss is too.
    fn golden_radio_pass() -> Vec<f32> {
        let mut st = SourceMixState::default();
        let mut out = vec![0.0f32; 1920];
        let mut all: Vec<f32> = Vec::new();
        for f in 0..3 {
            let pcm: Vec<f32> = (0..960)
                .map(|i| {
                    let n = (f * 960 + i) as f32;
                    0.5 * (2.0 * core::f32::consts::PI * 200.0 * n / 48_000.0).sin()
                })
                .collect();
            out.iter_mut().for_each(|s| *s = 0.0);
            mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, Effect::Radio);
            all.extend(out.iter().step_by(2));
        }
        all
    }

    #[test]
    fn the_radio_chain_matches_the_browser_golden_vector() {
        // The same twelve numbers are asserted in client/src/lib/audio-fx.test.ts,
        // so the Rust mixer and the browser worklet cannot drift apart: this
        // test and `npm test` fail together. Generated by running this chain
        // once, exactly as the spatial golden table was made.
        const GOLDEN: [f32; 12] = [
            0.0054195, -0.0201902, 0.0135253, 0.2030956, 0.2106600, 0.2191669, 0.1964534,
            0.2025039, 0.1896579, 0.2002891, 0.1951476, 0.1954625,
        ];
        let all = golden_radio_pass();
        for (k, &i) in GOLDEN_IDX.iter().enumerate() {
            assert!(
                (all[i] - GOLDEN[k]).abs() < 1e-6,
                "sample {i}: {} is not {}",
                all[i],
                GOLDEN[k]
            );
        }
    }


    // ── Reverb and water, measured rather than assumed ─────────────────
    //
    // The first version of these tests asserted "energy > 1e-6" against a value
    // of 3.8e-3, while the reverb sat 35 dB below anything a person can hear.
    // Every assertion here is a dB ratio, and each one is annotated with what it
    // read on that broken build.

    /// A deterministic band-limited noise source, the shape of speech.
    ///
    /// Not a tone: a single frequency can sit in a comb null, and a 400 Hz tone
    /// reads 17 dB quieter through this same reverb than broadband material
    /// does. The ladder below would be meaningless measured that way.
    fn speechlike(n: usize) -> Vec<f32> {
        let mut seed = 0x1234_5678u32;
        let (mut lp, mut hp) = (0.0f32, 0.0f32);
        (0..n)
            .map(|_| {
                lp += one_pole_a(3_400.0) * (white(&mut seed) - lp);
                hp += one_pole_a(150.0) * (lp - hp);
                (lp - hp) * 0.35
            })
            .collect()
    }

    fn rms(v: &[f32]) -> f32 {
        (v.iter().map(|s| s * s).sum::<f32>() / v.len() as f32).sqrt()
    }

    /// Wet level relative to dry, in dB, through the real [`apply_reverb_water`].
    ///
    /// The dry path is deterministic, so the wet path can be recovered exactly
    /// by subtracting it — no spectral analysis needed.
    fn wet_over_dry_db(reverb: u8) -> f32 {
        let mut st = ReverbWaterState::default();
        let src = speechlike(48_000 * 3);
        let trim = dry_trim(reverb);
        let (mut dry, mut wet) = (Vec::new(), Vec::new());
        for (f, chunk) in src.chunks(960).enumerate() {
            let mut out = vec![0.0f32; chunk.len() * 2];
            for (i, &x) in chunk.iter().enumerate() {
                out[2 * i] = x;
                out[2 * i + 1] = x;
            }
            apply_reverb_water(&mut out, &mut st, 0, reverb, true);
            if f >= 50 {
                // Settled: the bank takes a few hundred ms to fill
                for (i, &x) in chunk.iter().enumerate() {
                    dry.push(x);
                    wet.push(out[2 * i] - x * trim);
                }
            }
        }
        20.0 * (rms(&wet) / rms(&dry)).log10()
    }

    #[test]
    fn the_reverb_is_loud_enough_to_hear() {
        // Generated from this crate, not from a simulation of it. The shipped
        // version measured -34.8 / -27.7 / -20.9 here, so it fails by about
        // 15 dB — roughly 12 dB outside the tolerance band.
        for (level, want) in [(3u8, -18.5), (6, -11.2), (10, -7.5)] {
            let got = wet_over_dry_db(level);
            assert!(
                (got - want as f32).abs() < 2.5,
                "reverb {level}: {got:.1} dB, expected about {want:.1} dB"
            );
        }
    }

    #[test]
    fn every_reverb_step_is_a_step() {
        // A shape guard, NOT the catcher: this passes on the broken build too,
        // because there the level was wrong and the shape was fine. If anyone
        // points at this as proof the reverb works, they are wrong — the test
        // above is the one that fails.
        //
        // The wet LEVEL saturates towards the top, by construction: the send is
        // normalised by the comb bank's gain, which rises with the feedback, so
        // the last rungs add tail rather than loudness. That is the right
        // trade — a cathedral is not a louder room, it is a longer one — so the
        // level requirement is only asked of the lower half, and
        // `the_room_gets_longer_as_it_gets_bigger` covers the rest.
        let mut prev = f32::NEG_INFINITY;
        for level in 1..=10u8 {
            let db = wet_over_dry_db(level);
            let want = if level <= 6 { 1.0 } else { 0.0 };
            assert!(
                db > prev + want,
                "reverb {level}: {db:.2} dB is not above {prev:.2}"
            );
            prev = db;
        }
    }

    #[test]
    fn the_room_gets_longer_as_it_gets_bigger() {
        // What carries the top half of the slider, where the wet level has
        // flattened out: how long the tail rings after everyone stops.
        let tail_frames = |level: u8| {
            let mut st = ReverbWaterState::default();
            let src = speechlike(48_000);
            for chunk in src.chunks(960) {
                let mut out = vec![0.0f32; chunk.len() * 2];
                for (i, &x) in chunk.iter().enumerate() {
                    out[2 * i] = x;
                    out[2 * i + 1] = x;
                }
                apply_reverb_water(&mut out, &mut st, 0, level, true);
            }
            // Silence in; count frames until the tail is 40 dB down
            let mut out = vec![0.0f32; 1920];
            out.iter_mut().for_each(|s| *s = 0.0);
            apply_reverb_water(&mut out, &mut st, 0, level, false);
            let first = rms(&out).max(1e-9);
            for frame in 1..500 {
                let mut out = vec![0.0f32; 1920];
                apply_reverb_water(&mut out, &mut st, 0, level, false);
                if rms(&out) < first * 0.01 {
                    return frame;
                }
            }
            500
        };
        let (small, big) = (tail_frames(3), tail_frames(10));
        assert!(
            big > small * 2,
            "a cathedral ({big} frames) should ring far longer than a room ({small})"
        );
    }

    #[test]
    fn the_room_keeps_its_headroom() {
        // The trim is invisible to every ratio test (it scales wet and dry
        // alike) and to every clipping test (four talkers do not clip either
        // way), so this is its only tripwire. It reads the FIRST sample of a
        // fresh room, where the delay lines are still empty and the output is
        // therefore the dry path alone.
        let mut st = ReverbWaterState::default();
        let mut out = vec![0.0f32; 1920];
        out[0] = 0.5;
        out[1] = 0.5;
        apply_reverb_water(&mut out, &mut st, 0, 10, true);
        assert!(
            (out[0] / 0.5 - dry_trim(10)).abs() < 1e-6,
            "the dry path is not trimmed: {}",
            out[0] / 0.5
        );
        assert!(dry_trim(10) < 0.90, "trim {} buys no headroom", dry_trim(10));
        assert_eq!(dry_trim(0), 1.0, "a dry room must not touch the level");

        // And four people in a cathedral stay inside the rails before `clamp`
        let mut st = ReverbWaterState::default();
        let src = speechlike(48_000);
        for chunk in src.chunks(960) {
            let mut out = vec![0.0f32; chunk.len() * 2];
            for (i, &x) in chunk.iter().enumerate() {
                // four decorrelated talkers, each near -6 dBFS
                let sum = 4.0 * x;
                out[2 * i] = sum;
                out[2 * i + 1] = sum;
            }
            apply_reverb_water(&mut out, &mut st, 0, 10, true);
            assert!(out.iter().all(|s| s.is_finite()), "the room produced a NaN");
        }
    }

    #[test]
    fn the_mono_room_is_the_same_room() {
        // The microphone gets the same room the listener hears, so "I am in a
        // cave" sounds the same whichever side renders it. Same input, one
        // buffer mono and one interleaved stereo: the left channels must agree.
        let mut mono_st = ReverbWaterState::default();
        let mut stereo_st = ReverbWaterState::default();
        let src = speechlike(960 * 20);
        for chunk in src.chunks(960) {
            let mut mono: Vec<f32> = chunk.to_vec();
            let mut stereo = vec![0.0f32; chunk.len() * 2];
            for (i, &x) in chunk.iter().enumerate() {
                stereo[2 * i] = x;
                stereo[2 * i + 1] = x;
            }
            let a = apply_reverb_water_mono(&mut mono, &mut mono_st, 4, 7, true);
            let b = apply_reverb_water(&mut stereo, &mut stereo_st, 4, 7, true);
            assert_eq!(a, b, "the two paths disagreed about being audible");
            for (i, &m) in mono.iter().enumerate() {
                assert!(
                    (m - stereo[2 * i]).abs() < 1e-6,
                    "sample {i}: mono {m}, stereo {}",
                    stereo[2 * i]
                );
            }
        }
    }

    #[test]
    fn every_underwater_step_is_audible() {
        // The complaint this catches: on the shipped curve the first five steps
        // moved a 1 kHz tone by 0.83, 0.86, 0.93, 1.11 and 1.49 dB, so the
        // bottom half of the slider did nothing you could hear. Eight of the
        // ten levels failed this range.
        let level_db = |lv: u8| rms_db(&room_through(1_000.0, lv, 0, 6, 6)[2 * 960..]);
        let mut prev = level_db(0);
        let mut total = 0.0;
        for lv in 1..=10u8 {
            let db = level_db(lv);
            let step = prev - db;
            assert!(
                (1.5..=4.5).contains(&step),
                "underwater {lv}: step of {step:.2} dB is not a usable notch"
            );
            total += step;
            prev = db;
        }
        assert!(total > 24.0, "the whole slider only spans {total:.1} dB");
    }

    // ── The preset library ──────────────────────────────────────────────

    #[test]
    fn the_preset_table_has_several_grades_of_each() {
        // The complaint this catches: two effects, one flavour each. On the
        // build that was rejected this read 1 and 1.
        let count = |f: FxFamily| PRESETS.iter().filter(|p| p.family == f).count();
        assert!(count(FxFamily::Radio) >= 4, "only {} radios", count(FxFamily::Radio));
        assert!(count(FxFamily::Phone) >= 4, "only {} phones", count(FxFamily::Phone));
    }

    #[test]
    fn the_table_and_the_enum_agree() {
        assert_eq!(PRESETS.len(), crate::spatial::EFFECTS.len());
        for (i, p) in PRESETS.iter().enumerate() {
            let fx = Effect::from_u8(i as u8 + 1);
            assert_eq!(preset(fx), Some(p), "{} is not at its own index", p.id);
        }
        assert_eq!(preset(Effect::None), None);
        // Ids are what the wire, the config and the UI all agree on
        for (i, p) in PRESETS.iter().enumerate() {
            assert!(!p.id.is_empty() && p.id != "none" && p.id != "direct");
            assert!(
                PRESETS.iter().skip(i + 1).all(|q| q.id != p.id),
                "{} appears twice",
                p.id
            );
        }
    }

    #[test]
    fn a_silent_preset_does_not_touch_the_rng() {
        // One unguarded noise call anywhere in the chain shifts the xorshift
        // stream and breaks the golden vector for every preset at once, so each
        // stage sits behind its own guard. This is the cheapest tripwire for it.
        for p in PRESETS.iter().filter(|p| p.noise == 0.0 && p.crackle == 0.0 && !p.squelch) {
            let mut st = SourceMixState::default();
            let seed = st.noise;
            for i in 0..960 {
                fx_sample(&mut st, (i as f32 * 0.01).sin(), p.lp_a, Some(p));
            }
            assert_eq!(st.noise, seed, "{} disturbed the noise generator", p.id);
        }
    }

    #[test]
    fn every_preset_is_bounded_and_finite() {
        for fx in crate::spatial::EFFECTS {
            let mut st = SourceMixState::default();
            for f in 0..50 {
                let pcm: Vec<f32> = (0..960)
                    .map(|i| if (f + i) % 2 == 0 { 1.0 } else { -1.0 })
                    .collect();
                let mut out = vec![0.0f32; 1920];
                mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, fx);
                assert!(
                    out.iter().all(|s| s.is_finite() && s.abs() <= 8.0),
                    "{} went out of range",
                    fx.id()
                );
            }
        }
    }

    #[test]
    fn the_presets_are_loudness_matched() {
        // Switching voice should not be a volume change. Phone is the one
        // deliberate exception: it is the original chain, kept bit-identical
        // for the golden vector, which is why Landline exists beside it.
        let level = |fx: Effect| {
            let mut st = SourceMixState::default();
            let mut kept = Vec::new();
            for f in 0..8 {
                let pcm: Vec<f32> = (0..960)
                    .map(|i| {
                        let n = (f * 960 + i) as f32;
                        0.3 * (2.0 * core::f32::consts::PI * 220.0 * n / 48_000.0).sin()
                    })
                    .collect();
                let mut out = vec![0.0f32; 1920];
                mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, fx);
                if f >= 4 {
                    kept.extend(out.iter().step_by(2));
                }
            }
            rms_db(&kept)
        };
        let reference = level(Effect::Radio);
        for fx in crate::spatial::EFFECTS {
            if fx == Effect::Phone {
                continue;
            }
            let d = level(fx) - reference;
            assert!(d.abs() < 6.0, "{} is {d:+.1} dB off Radio", fx.id());
        }
    }

    /// One level per preset, generated from this crate and asserted again in
    /// client/src/lib/audio-fx.test.ts against the same numbers.
    ///
    /// Thirteen presets in two languages is exactly where a typo hides, and a
    /// level is sensitive to every part of the chain: a wrong coefficient, a
    /// missing stage, a reordered one, or a makeup gain that drifted.
    pub(crate) const PRESET_PINS: [(&str, f32); 13] = [
        ("phone", -19.68),
        ("radio", -17.43),
        ("cb", -20.65),
        ("walkie", -21.58),
        ("aviation", -18.52),
        ("police", -20.66),
        ("landline", -16.83),
        ("mobile", -15.60),
        ("badvoip", -14.39),
        ("intercom", -19.26),
        ("megaphone", -23.27),
        ("gramophone", -14.38),
        ("robot", -14.35),
    ];

    /// A 200 Hz half-amplitude tone through one preset, four frames, left channel.
    /// Shared with the browser suite, which runs the identical signal.
    pub(crate) fn preset_pass(fx: Effect) -> Vec<f32> {
        let mut st = SourceMixState::default();
        let mut kept = Vec::new();
        for f in 0..4 {
            let pcm: Vec<f32> = (0..960)
                .map(|i| {
                    let n = (f * 960 + i) as f32;
                    0.5 * (2.0 * core::f32::consts::PI * 200.0 * n / 48_000.0).sin()
                })
                .collect();
            let mut out = vec![0.0f32; 1920];
            mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, fx);
            kept.extend(out.iter().step_by(2));
        }
        kept
    }

    #[test]
    fn every_preset_matches_its_browser_pin() {
        for (i, fx) in crate::spatial::EFFECTS.into_iter().enumerate() {
            let (id, want) = PRESET_PINS[i];
            assert_eq!(fx.id(), id, "the pin table is out of order");
            let got = rms_db(&preset_pass(fx));
            assert!(
                (got - want).abs() < 0.5,
                "{id}: {got:.2} dB, pinned at {want:.2}"
            );
        }
    }

    #[test]
    fn print_preset_pins() {
        for fx in crate::spatial::EFFECTS {
            let mut st = SourceMixState::default();
            let mut kept = Vec::new();
            for f in 0..4 {
                let pcm: Vec<f32> = (0..960)
                    .map(|i| {
                        let n = (f * 960 + i) as f32;
                        0.5 * (2.0 * core::f32::consts::PI * 200.0 * n / 48_000.0).sin()
                    })
                    .collect();
                let mut out = vec![0.0f32; 1920];
                mix_source_fx(&mut out, &pcm, &mut st, (1.0, 1.0), 1.0, fx);
                kept.extend(out.iter().step_by(2));
            }
            println!("PIN {} {:.4}", fx.id(), rms_db(&kept));
        }
    }

    #[test]
    fn clamp_bounds_the_mix() {
        let mut buf = vec![-2.0, -0.5, 0.5, 2.0];
        clamp(&mut buf);
        assert_eq!(buf, vec![-1.0, -0.5, 0.5, 1.0]);
    }

    // ── One lane, two directions ─────────────────────────────────────────

    #[test]
    fn your_own_voice_and_somebody_elses_go_through_the_same_lane() {
        // Four rejected builds came from the microphone and an incoming voice
        // having different controls. There is one chain; this measures that
        // both directions run it, in the same order, with the same numbers.
        //
        // Quiet source on purpose: [`SourceChain::render_mono`] clamps its own
        // output and the mixer clamps only after summing, so anything loud
        // enough to clip would compare two clamps rather than two chains.
        let src: Vec<f32> = (0..960).map(|i| 0.18 * (i as f32 * 0.021).sin()).collect();
        let (fx, muffle, reverb, water) = (Effect::Radio, 4u8, 6u8, 3u8);
        let lp_a = crate::spatial::muffle_lp_a(muffle);

        // Four frames, and compare the last: the shortest comb is 1215 samples,
        // so over a single 20 ms frame the reverb has contributed exactly
        // nothing to either side and the comparison quietly proves less than it
        // says it does.
        let mut out = Vec::new();
        let mut mic = SourceChain::default();
        let mut stereo = Vec::new();
        let mut incoming = SourceChain::default();
        for _ in 0..4 {
            out = src.clone();
            mic.render_mono(&mut out, fx, lp_a, water, reverb);
            stereo = vec![0.0f32; src.len() * 2];
            incoming.render(&mut stereo, &src, (1.0, 1.0), lp_a, fx, water, reverb);
        }

        let mut worst = 0.0f32;
        for i in 0..src.len() {
            worst = worst.max((stereo[2 * i] - out[i]).abs());
        }
        assert!(worst < 1e-6, "the two directions differ by {worst:e}");
        assert!(rms_db(&out) > -40.0, "the comparison ran on silence");
    }

    #[test]
    fn every_scalable_effect_reaches_the_microphone() {
        // Each of the three has to change what goes out on its own, with the
        // other two off. A control that only works on the way in is the bug
        // that was rejected twice.
        //
        // Low and high together: muffle and water are filters, so a bass-only
        // probe would show them doing nothing and prove the wrong thing. Four
        // frames, because the shortest comb is 1215 samples: over a single
        // 20 ms frame the reverb has not come back yet.
        let src: Vec<f32> = (0..960)
            .map(|i| 0.14 * ((i as f32 * 0.026).sin() + (i as f32 * 0.39).sin()))
            .collect();
        let run = |muffle: u8, reverb: u8, water: u8| {
            let mut chain = SourceChain::default();
            let lp_a = if muffle > 0 {
                crate::spatial::muffle_lp_a(muffle)
            } else {
                1.0
            };
            let mut last = Vec::new();
            for _ in 0..4 {
                last = src.clone();
                chain.render_mono(&mut last, Effect::None, lp_a, water, reverb);
            }
            last
        };

        let plain = run(0, 0, 0);
        assert_eq!(plain, src, "a lane with nothing on is not a bypass");
        let reference = rms_db(&plain);
        for (name, one) in [
            ("muffle", run(6, 0, 0)),
            ("reverb", run(0, 6, 0)),
            ("water", run(0, 0, 6)),
        ] {
            let delta: Vec<f32> = one.iter().zip(&plain).map(|(a, b)| a - b).collect();
            let db = rms_db(&delta) - reference;
            // Measured: muffle -5.4 dB, reverb -17.5, water -1.1. This is a
            // "does it reach the microphone at all" guard — the loudness
            // ladders are `every_underwater_step_is_audible` and
            // `the_reverb_is_loud_enough_to_hear`.
            assert!(db > -24.0, "{name} changed the outgoing voice by only {db:.1} dB");
        }
    }
}
