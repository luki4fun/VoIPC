//! Positional ("proximity") audio: turns a listener pose and a source
//! placement into the stereo gains one mono voice stream is mixed with.
//!
//! Coordinates are metres, x/y is the ground plane and z is up, matching the
//! game coordinate systems the SDK feeds us and the top-down room view.
//!
//! The maths is the one every other implementation converged on:
//! - distance: Web Audio's `inverse` model, which is also FMOD's and
//!   TeamSpeak 3's, plus a linear fade over the last stretch so a source
//!   crossing the cull radius does not click
//! - direction: the constant-power pan law of Web Audio's `StereoPannerNode`
//! - near field: Mumble's "bloom" — a source closer than [`REF_DIST`] collapses
//!   toward the centre, because nobody can localise a whisper in their ear and
//!   two avatars standing on each other would otherwise make the pan spin
//! - occlusion: one-pole low-pass whose cutoff is interpolated logarithmically
//!   from the muffle level, plus a volume cut (the Wwise approach)
//!
//! This file is mirrored in TypeScript at `client/src/lib/spatial.ts`; the
//! golden-value tests at the bottom are asserted in both.

use voipc_protocol::types::ProximityMode;

/// Distance (m) inside which a source plays at full volume.
pub const REF_DIST: f32 = 1.5;
/// Steepness of the inverse distance curve (1.0 = physical).
pub const ROLLOFF: f32 = 1.0;
/// Default distance (m) at which a source falls silent.
pub const DEFAULT_RANGE: f32 = 20.0;
/// Fraction of the range over which the tail fades to zero.
const FADE_FRACTION: f32 = 0.15;
/// Maximum pan. Speech hard-panned to 1.0 is fatiguing on headphones and
/// disappears for anyone with one earbud.
pub const WIDTH: f32 = 0.85;
/// Near-field omni blend (Mumble's bloom).
pub const BLOOM: f32 = 0.5;
/// Cutoff (Hz) of the muffle low-pass at full intensity.
const MUFFLE_FC_MIN: f32 = 350.0;
/// Cutoff (Hz) at zero intensity — above the audio band, i.e. bypass.
const MUFFLE_FC_MAX: f32 = 22_000.0;
/// Volume cut at full muffle, in dB.
const MUFFLE_CUT_DB: f32 = 15.0;
/// Highest muffle level the SDK may send (0 = clear, 10 = through a wall).
pub const MAX_MUFFLE: u8 = 10;

const SAMPLE_RATE: f32 = 48_000.0;

/// Where the listener is and which way they face.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Listener {
    pub pos: [f32; 3],
    /// Unit forward vector in the x/y plane. The room view uses `[0.0, 1.0]`
    /// (screen up), so panning is screen-relative there.
    pub fwd: [f32; 2],
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            pos: [0.0; 3],
            fwd: [0.0, 1.0],
        }
    }
}

/// Where one other user is, and how they should be rendered.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Source {
    pub pos: [f32; 3],
    /// Distance (m) at which this source falls silent.
    pub range: f32,
    /// Per-source volume, 0..2 (the SDK's volume override).
    pub volume: f32,
    /// Occlusion, 0 (clear) to [`MAX_MUFFLE`] (through a wall).
    pub muffle: u8,
    /// Render flat instead of positionally — radio, phone, megaphone,
    /// spectators. Distance and direction are ignored, `volume` still applies.
    pub direct: bool,
}

impl Default for Source {
    fn default() -> Self {
        Self {
            pos: [0.0; 3],
            range: DEFAULT_RANGE,
            volume: 1.0,
            muffle: 0,
            direct: false,
        }
    }
}

/// What the mixer applies to one source's frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Gains {
    pub l: f32,
    pub r: f32,
    /// One-pole low-pass coefficient; 1.0 means bypass.
    pub lp_a: f32,
}

/// A source that is not placed anywhere sounds exactly as it did before
/// proximity chat existed: centred, full volume, unfiltered.
pub const FLAT: Gains = Gains {
    l: 1.0,
    r: 1.0,
    lp_a: 1.0,
};

const SILENT: Gains = Gains {
    l: 0.0,
    r: 0.0,
    lp_a: 1.0,
};

/// Stereo gains for one source. `src` is `None` for a user nobody has placed.
///
/// A source dead centre comes out at unity on both channels rather than the
/// −3 dB a constant-power law would give, so switching a channel to proximity
/// does not make everyone quieter.
pub fn gains(mode: ProximityMode, lis: &Listener, src: Option<&Source>) -> Gains {
    let Some(s) = src else { return FLAT };
    if mode == ProximityMode::Off {
        return FLAT;
    }
    if s.direct {
        return Gains {
            l: s.volume,
            r: s.volume,
            lp_a: 1.0,
        };
    }

    let dz = if mode == ProximityMode::ThreeD {
        s.pos[2] - lis.pos[2]
    } else {
        0.0
    };
    let d = [s.pos[0] - lis.pos[0], s.pos[1] - lis.pos[1], dz];
    let dist = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();

    let range = s.range.max(0.01);
    let attenuation = REF_DIST / (REF_DIST + ROLLOFF * (dist.max(REF_DIST) - REF_DIST));
    let fade = ((range - dist) / (FADE_FRACTION * range)).clamp(0.0, 1.0);
    let g = attenuation * fade;
    if g <= 0.0 {
        return SILENT;
    }

    // Lateral offset in the listener's frame: +1 fully right, -1 fully left.
    let right = [lis.fwd[1], -lis.fwd[0]];
    let lat = if dist > 1e-3 {
        (d[0] * right[0] + d[1] * right[1]) / dist
    } else {
        0.0
    };
    let bloom = (BLOOM * (1.0 - dist / REF_DIST)).clamp(0.0, 1.0);
    let pan = (lat * WIDTH * (1.0 - bloom)).clamp(-1.0, 1.0);
    let angle = (pan + 1.0) * 0.5 * core::f32::consts::FRAC_PI_2;

    let m = s.muffle.min(MAX_MUFFLE) as f32 / MAX_MUFFLE as f32;
    let volume = g * s.volume * 10f32.powf(-MUFFLE_CUT_DB * m / 20.0) * core::f32::consts::SQRT_2;
    let lp_a = if m == 0.0 {
        1.0
    } else {
        let fc = MUFFLE_FC_MAX.powf(1.0 - m) * MUFFLE_FC_MIN.powf(m);
        1.0 - (-2.0 * core::f32::consts::PI * fc / SAMPLE_RATE).exp()
    };

    Gains {
        l: volume * angle.cos(),
        r: volume * angle.sin(),
        lp_a,
    }
}

// ── The settings panel's spatial test ────────────────────────────────────
//
// A synthetic voice orbits the listener so anyone can check that their
// headphones (and this mixer) pan and attenuate the way proximity chat will,
// without needing a second person. Mirrored in spatial.ts, and the trajectory
// is part of the golden table both sides assert.

/// Orbit radius (m) of the test voice.
pub const TEST_RADIUS: f32 = 3.0;
/// Seconds per revolution: front → right → behind → left.
pub const TEST_ORBIT_SECS: f32 = 8.0;
/// In 3D the voice also climbs this far above the listener, and sinks as far below.
pub const TEST_HEIGHT: f32 = 4.0;
/// Seconds for one full height sweep (up, back, down, back).
pub const TEST_HEIGHT_SECS: f32 = 16.0;

/// Where the test voice is `t` seconds in, relative to a listener at the
/// origin facing +y. 2D stays at ear level; 3D adds the height sweep, so the
/// same orbit gets quieter as the voice climbs or sinks.
pub fn test_source(mode: ProximityMode, t: f32) -> Source {
    let theta = core::f32::consts::TAU * t / TEST_ORBIT_SECS;
    let z = if mode == ProximityMode::ThreeD {
        TEST_HEIGHT * (core::f32::consts::TAU * t / TEST_HEIGHT_SECS).sin()
    } else {
        0.0
    };
    Source {
        pos: [
            TEST_RADIUS * theta.sin(),
            TEST_RADIUS * theta.cos(),
            z,
        ],
        ..Source::default()
    }
}

/// Fundamental (Hz) of the synthetic voice.
pub const TEST_VOICE_HZ: f32 = 180.0;
/// Harmonic amplitudes, fundamental first; normalised by their sum.
const TEST_VOICE_HARMONICS: [f64; 5] = [1.0, 0.5, 0.35, 0.2, 0.1];
/// Scale of the finished signal: peak ≈ 0.35 (−9 dBFS).
const TEST_VOICE_GAIN: f64 = 0.5;
/// Syllable rate (Hz) of the amplitude envelope — it sounds like speech, not a tone.
const TEST_VOICE_SYLLABLES_HZ: f64 = 4.0;
/// Samples of speech per second; the remaining 250 ms are the pause between
/// sentences. The envelope is zero at both edges, so the gate never clicks.
const TEST_VOICE_ON_SAMPLES: u64 = 36_000;

/// One sample of the synthetic voice. Deterministic and exactly periodic per
/// second (every component divides 1 s), so a mixer that keys it by its running
/// sample count stays click-free across frames, restarts and mode switches.
pub fn test_voice_sample(n: u64) -> f32 {
    let k = n % 48_000;
    if k >= TEST_VOICE_ON_SAMPLES {
        return 0.0;
    }
    let t = k as f64 / 48_000.0;
    let env = 0.5 - 0.5 * (core::f64::consts::TAU * TEST_VOICE_SYLLABLES_HZ * t).cos();
    let (mut tone, mut sum) = (0.0, 0.0);
    for (i, a) in TEST_VOICE_HARMONICS.iter().enumerate() {
        tone += a * (core::f64::consts::TAU * (i + 1) as f64 * TEST_VOICE_HZ as f64 * t).sin();
        sum += a;
    }
    (TEST_VOICE_GAIN * env * tone / sum) as f32
}

/// Fill `out` with consecutive samples starting at sample index `first`.
pub fn test_voice_frame(first: u64, out: &mut [f32]) {
    for (i, s) in out.iter_mut().enumerate() {
        *s = test_voice_sample(first + i as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(x: f32, y: f32) -> Source {
        Source {
            pos: [x, y, 0.0],
            ..Source::default()
        }
    }

    fn close(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-3
    }

    // ── The golden table, mirrored in client/src/lib/spatial.ts ──────────

    #[test]
    fn unplaced_and_off_are_flat() {
        let lis = Listener::default();
        assert_eq!(gains(ProximityMode::TwoD, &lis, None), FLAT);
        assert_eq!(gains(ProximityMode::Off, &lis, Some(&at(5.0, 0.0))), FLAT);
    }

    #[test]
    fn centre_is_unity_on_both_channels() {
        let g = gains(ProximityMode::TwoD, &Listener::default(), Some(&at(0.0, 0.0)));
        assert!(close(g.l, 1.0), "l = {}", g.l);
        assert!(close(g.r, 1.0), "r = {}", g.r);
        assert_eq!(g.lp_a, 1.0);
    }

    #[test]
    fn five_metres_right_pans_right_and_attenuates() {
        let g = gains(ProximityMode::TwoD, &Listener::default(), Some(&at(5.0, 0.0)));
        // inverse model at 5 m with ref 1.5: 1.5 / (1.5 + 3.5) = 0.3
        let power = (g.l * g.l + g.r * g.r).sqrt() / core::f32::consts::SQRT_2;
        assert!(close(power, 0.3), "power = {power}");
        assert!(g.r > g.l * 5.0, "l = {}, r = {}", g.l, g.r);
    }

    #[test]
    fn left_mirrors_right() {
        let lis = Listener::default();
        let r = gains(ProximityMode::TwoD, &lis, Some(&at(5.0, 0.0)));
        let l = gains(ProximityMode::TwoD, &lis, Some(&at(-5.0, 0.0)));
        assert!(close(l.l, r.r) && close(l.r, r.l));
    }

    #[test]
    fn facing_rotates_the_pan() {
        // Facing +x, a source at +x is straight ahead → centred
        let lis = Listener {
            pos: [0.0; 3],
            fwd: [1.0, 0.0],
        };
        let g = gains(ProximityMode::TwoD, &lis, Some(&at(5.0, 0.0)));
        assert!(close(g.l, g.r), "l = {}, r = {}", g.l, g.r);
        // Facing +x, a source at +y is on the listener's left
        let g = gains(ProximityMode::TwoD, &lis, Some(&at(0.0, 5.0)));
        assert!(g.l > g.r * 5.0, "l = {}, r = {}", g.l, g.r);
        // and one at -y on their right
        let g = gains(ProximityMode::TwoD, &lis, Some(&at(0.0, -5.0)));
        assert!(g.r > g.l * 5.0, "l = {}, r = {}", g.l, g.r);
    }

    #[test]
    fn gain_decreases_with_distance_and_reaches_zero_at_range() {
        let lis = Listener::default();
        let mut last = f32::MAX;
        for step in 0..=40 {
            let d = step as f32 * 0.5;
            let g = gains(ProximityMode::TwoD, &lis, Some(&at(0.0, d)));
            let power = (g.l * g.l + g.r * g.r).sqrt();
            assert!(power <= last + 1e-6, "gain rose at {d} m");
            last = power;
        }
        // Silent at and beyond the range, and already fading before it
        let inside = gains(ProximityMode::TwoD, &lis, Some(&at(0.0, DEFAULT_RANGE - 1.0)));
        assert!(inside.l > 0.0 && inside.l < 0.05);
        for d in [DEFAULT_RANGE, DEFAULT_RANGE + 10.0] {
            assert_eq!(gains(ProximityMode::TwoD, &lis, Some(&at(0.0, d))), SILENT);
        }
    }

    #[test]
    fn bloom_centres_very_close_sources() {
        let lis = Listener::default();
        let far = gains(ProximityMode::TwoD, &lis, Some(&at(1.4, 0.0)));
        let near = gains(ProximityMode::TwoD, &lis, Some(&at(0.2, 0.0)));
        let spread = |g: Gains| (g.r - g.l).abs();
        assert!(spread(near) < spread(far), "near source should be more centred");
    }

    #[test]
    fn two_d_ignores_height_three_d_does_not() {
        let lis = Listener::default();
        let above = Source {
            pos: [0.0, 0.0, 100.0],
            ..Source::default()
        };
        let flat_2d = gains(ProximityMode::TwoD, &lis, Some(&above));
        assert!(close(flat_2d.l, 1.0) && close(flat_2d.r, 1.0));
        assert_eq!(gains(ProximityMode::ThreeD, &lis, Some(&above)), SILENT);
    }

    #[test]
    fn direct_sources_bypass_geometry() {
        let g = gains(
            ProximityMode::ThreeD,
            &Listener::default(),
            Some(&Source {
                pos: [500.0, 500.0, 500.0],
                volume: 0.8,
                direct: true,
                ..Source::default()
            }),
        );
        assert_eq!(g, Gains { l: 0.8, r: 0.8, lp_a: 1.0 });
    }

    #[test]
    fn muffle_cuts_volume_and_lowers_the_cutoff() {
        let lis = Listener::default();
        let clear = gains(ProximityMode::TwoD, &lis, Some(&at(0.0, 0.0)));
        let walled = gains(
            ProximityMode::TwoD,
            &lis,
            Some(&Source {
                muffle: MAX_MUFFLE,
                ..at(0.0, 0.0)
            }),
        );
        // −15 dB
        assert!(close(walled.l / clear.l, 10f32.powf(-0.75)));
        // one-pole coefficient for 350 Hz at 48 kHz
        assert!(close(walled.lp_a, 0.0450), "lp_a = {}", walled.lp_a);
        // A muffle over the maximum is clamped, not extrapolated
        let over = gains(
            ProximityMode::TwoD,
            &lis,
            Some(&Source { muffle: 200, ..at(0.0, 0.0) }),
        );
        assert_eq!(over, walled);
    }

    #[test]
    fn volume_scales_the_result() {
        let lis = Listener::default();
        let unity = gains(ProximityMode::TwoD, &lis, Some(&at(3.0, 1.0)));
        let half = gains(
            ProximityMode::TwoD,
            &lis,
            Some(&Source { volume: 0.5, ..at(3.0, 1.0) }),
        );
        assert!(close(half.l, unity.l * 0.5) && close(half.r, unity.r * 0.5));
    }

    #[test]
    fn a_zero_range_source_is_silent_not_nan() {
        let g = gains(
            ProximityMode::TwoD,
            &Listener::default(),
            Some(&Source { range: 0.0, ..at(1.0, 0.0) }),
        );
        assert_eq!(g, SILENT);
    }

    // ── The spatial test, mirrored in spatial.ts checkGoldenValues() ─────

    fn power(g: Gains) -> f32 {
        (g.l * g.l + g.r * g.r).sqrt() / core::f32::consts::SQRT_2
    }

    fn test_gains(mode: ProximityMode, t: f32) -> Gains {
        gains(mode, &Listener::default(), Some(&test_source(mode, t)))
    }

    #[test]
    fn test_orbit_is_a_smooth_periodic_three_metre_circle() {
        for step in 0..=64 {
            let t = step as f32 * 0.25;
            for mode in [ProximityMode::TwoD, ProximityMode::ThreeD] {
                let p = test_source(mode, t).pos;
                assert!(close(p[0].hypot(p[1]), TEST_RADIUS), "radius at {t}");
                if mode == ProximityMode::TwoD {
                    assert_eq!(p[2], 0.0, "2d must stay at ear level");
                } else {
                    assert!(p[2].abs() <= TEST_HEIGHT + 1e-3, "height at {t}");
                }
                // One mixer frame apart: no jump a listener could hear as a click
                let q = test_source(mode, t + 0.02).pos;
                let step_m = ((q[0] - p[0]).powi(2) + (q[1] - p[1]).powi(2) + (q[2] - p[2]).powi(2)).sqrt();
                assert!(step_m < 0.1, "jump of {step_m} m at {t}");
                // Both cycles close after TEST_HEIGHT_SECS
                let r = test_source(mode, t + TEST_HEIGHT_SECS).pos;
                assert!(close(p[0], r[0]) && close(p[1], r[1]) && close(p[2], r[2]));
            }
        }
    }

    #[test]
    fn test_orbit_runs_front_right_behind_left() {
        let quarters = [(0.0, 0.0, 3.0), (2.0, 3.0, 0.0), (4.0, 0.0, -3.0), (6.0, -3.0, 0.0)];
        for (t, x, y) in quarters {
            let p = test_source(ProximityMode::TwoD, t).pos;
            assert!(close(p[0], x) && close(p[1], y), "t = {t}: {p:?}");
        }
        // and it comes back round
        let p = test_source(ProximityMode::TwoD, TEST_ORBIT_SECS).pos;
        assert!(close(p[0], 0.0) && close(p[1], 3.0));
    }

    #[test]
    fn three_d_test_sweeps_height() {
        for (t, z) in [(0.0, 0.0), (4.0, TEST_HEIGHT), (8.0, 0.0), (12.0, -TEST_HEIGHT)] {
            let p = test_source(ProximityMode::ThreeD, t).pos;
            assert!(close(p[2], z), "t = {t}: z = {}", p[2]);
        }
    }

    #[test]
    fn test_pan_flips_at_the_quarters() {
        for mode in [ProximityMode::TwoD, ProximityMode::ThreeD] {
            // In 3D the quarters are also 2.8 m up, i.e. 45° above the ear, so
            // the lateral share of the distance — and the pan with it — is smaller
            let ratio = if mode == ProximityMode::ThreeD { 2.5 } else { 5.0 };
            let right = test_gains(mode, 2.0);
            assert!(right.r > right.l * ratio, "{mode:?} at t=2: {right:?}");
            let left = test_gains(mode, 6.0);
            assert!(left.l > left.r * ratio, "{mode:?} at t=6: {left:?}");
            for t in [0.0, 4.0] {
                let g = test_gains(mode, t);
                assert!((g.l - g.r).abs() < 1e-3, "{mode:?} at t={t} not centred: {g:?}");
            }
            for step in 1..7 {
                let t = 0.5 * step as f32;
                let g = test_gains(mode, t);
                assert!(g.r > g.l, "{mode:?} at t={t} should lean right");
                let g = test_gains(mode, t + 4.0);
                assert!(g.l > g.r, "{mode:?} at t={} should lean left", t + 4.0);
            }
        }
    }

    #[test]
    fn two_d_test_power_is_constant_three_d_dips_with_height() {
        // 3 m with ref 1.5 → 0.5, and the pan law is constant-power
        for step in 0..=32 {
            let t = step as f32 * 0.25;
            assert!(close(power(test_gains(ProximityMode::TwoD, t)), 0.5), "2d power at {t}");
            let p3 = power(test_gains(ProximityMode::ThreeD, t));
            assert!(p3 <= 0.5 + 1e-3 && p3 > 0.25, "3d power {p3} at {t}");
        }
        // Quietest at the top and the bottom of the sweep: 5 m away
        for t in [4.0, 12.0] {
            assert!(close(power(test_gains(ProximityMode::ThreeD, t)), 0.3), "3d power at {t}");
        }
        let mut last = f32::MAX;
        for step in 0..=8 {
            let p = power(test_gains(ProximityMode::ThreeD, step as f32 * 0.5));
            assert!(p <= last + 1e-6, "3d power rose while climbing");
            last = p;
        }
    }

    #[test]
    fn test_voice_is_bounded_smooth_periodic_and_pauses() {
        let mut peak: f32 = 0.0;
        let mut prev = test_voice_sample(0);
        for n in 0..48_000u64 {
            let s = test_voice_sample(n);
            assert!(s.is_finite());
            peak = peak.max(s.abs());
            assert!((s - prev).abs() < 0.03, "step of {} at {n}", s - prev);
            prev = s;
        }
        assert!(peak > 0.3 && peak <= 0.5, "peak {peak}");
        // The wrap back to sample 0 is a step too
        assert!((test_voice_sample(0) - test_voice_sample(47_999)).abs() < 0.03);
        for n in [TEST_VOICE_ON_SAMPLES, 40_000, 47_999] {
            assert_eq!(test_voice_sample(n), 0.0, "should be silent at {n}");
        }
        assert_eq!(test_voice_sample(1234), test_voice_sample(49_234));

        let mut frame = [0.0f32; 960];
        test_voice_frame(960, &mut frame);
        for (i, s) in frame.iter().enumerate() {
            assert_eq!(*s, test_voice_sample(960 + i as u64));
        }
    }

    #[test]
    fn test_voice_matches_the_typescript_pins() {
        // Same three samples are asserted in client/src/lib/spatial.test.ts
        assert!((test_voice_sample(6017) - -0.0577201).abs() < 1e-5);
        assert!((test_voice_sample(18_500) - 0.0877542).abs() < 1e-5);
        assert_eq!(test_voice_sample(40_000), 0.0);
    }

    #[test]
    fn test_voice_through_the_mixer_lands_on_the_right() {
        use crate::mixer::{mix_source_stereo, SourceMixState};
        let mut pcm = [0.0f32; 960];
        // Mid-syllable, so the frame carries real signal
        test_voice_frame(17_000, &mut pcm);
        let g = test_gains(ProximityMode::TwoD, 2.0);
        let mut out = vec![0.0f32; 1920];
        let mut st = SourceMixState::default();
        mix_source_stereo(&mut out, &pcm, &mut st, (g.l, g.r), g.lp_a);
        let energy = |offset: usize| out.iter().skip(offset).step_by(2).map(|s| s * s).sum::<f32>();
        let (l, r) = (energy(0), energy(1));
        assert!(r > l * 25.0, "left {l}, right {r}");
    }
}
