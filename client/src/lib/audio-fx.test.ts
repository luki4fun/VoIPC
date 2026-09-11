// The browser half of the effect chain: the preset library, reverb and water,
// and the sender pass. The code under test lives in the mixer worklet —
// importing it here at all is half the point, because it proves the file loads
// off the audio thread, which is what lets one copy of the DSP serve the
// worklet, the sender path and this test.
//
// Every relationship asserted here is asserted in
// crates/voipc-audio/src/mixer.rs too, so the Rust mixer and the browser
// worklet cannot drift apart: `cargo test -p voipc-audio` and `npm test` fail
// together.
//
// House rule, learned the hard way: assert a dB ratio, never "energy above an
// epsilon". The first version of these tests passed while the reverb sat 35 dB
// below anything a person can hear.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FX_NONE,
  FX_PHONE,
  FX_RADIO,
  PRESETS,
  ReverbWater,
  applySenderFx,
  dryTrim,
  effectFromId,
  fxSample,
  fxStart,
  fxStop,
  newFxState,
  onePoleA,
  preset,
  white,
} from "../web/backend/worklets/mixer-worklet.js";
import { muffleLpA } from "./spatial.ts";

const FRAME = 960;

function rmsDb(samples: number[]): number {
  const mean = samples.reduce((a, s) => a + s * s, 0) / samples.length;
  return 20 * Math.log10(Math.sqrt(mean));
}

function rms(samples: number[]): number {
  return Math.sqrt(samples.reduce((a, s) => a + s * s, 0) / samples.length);
}

/**
 * Band-limited noise shaped like speech, from the same xorshift and the same
 * two filters as `speechlike` in crates/voipc-audio/src/mixer.rs — so the two
 * suites measure the reverb with the *same* signal and can share its numbers.
 *
 * Not a tone: a single frequency can sit in a comb null, and a 400 Hz tone
 * reads 17 dB quieter through this reverb than broadband material does.
 */
function speechlike(n: number): number[] {
  const st = { noise: 0x1234_5678 };
  let lp = 0;
  let hp = 0;
  const a1 = onePoleA(3_400);
  const a2 = onePoleA(150);
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    lp += a1 * (white(st) - lp);
    hp += a2 * (lp - hp);
    out.push((lp - hp) * 0.35);
  }
  return out;
}

/** Runs a sine through one preset's chain, the way the mixer does. */
function through(hz: number, amp: number, fx: number, frames: number, skip: number): number[] {
  const st = newFxState();
  const p = preset(fx);
  const a = p ? p.lpA : 1;
  const makeup = p ? p.gain : 1;
  const kept: number[] = [];
  // The mixer opens the transmission before the first sample (a radio owes its
  // squelch burst here), and `preset_pass` in crates/voipc-audio/src/mixer.rs
  // does the same — without it the two languages measure different chains.
  fxStart(st, fx);
  for (let f = 0; f < frames; f++) {
    for (let i = 0; i < FRAME; i++) {
      const n = f * FRAME + i;
      const s = fxSample(st, amp * Math.sin((2 * Math.PI * hz * n) / 48000), a, p) * makeup;
      if (f >= skip) kept.push(s);
    }
  }
  return kept;
}

/** Runs a sine through one lane's reverb and water, left channel per frame. */
function laneThrough(
  hz: number,
  underwater: number,
  reverb: number,
  frames: number,
  feed: number,
): number[][] {
  const space = new ReverbWater();
  const out: number[][] = [];
  for (let f = 0; f < frames; f++) {
    const l = new Float32Array(FRAME);
    const r = new Float32Array(FRAME);
    const live = f < feed;
    if (live) {
      for (let i = 0; i < FRAME; i++) {
        const n = f * FRAME + i;
        l[i] = 0.25 * Math.sin((2 * Math.PI * hz * n) / 48000);
        r[i] = l[i];
      }
    }
    space.apply(l, r, underwater, reverb, live);
    out.push([...l]);
  }
  return out;
}

// ── The preset library ───────────────────────────────────────────────────

test("there are several grades of radio and of phone", () => {
  // The complaint this catches: two effects, one flavour each. On the build
  // that was rejected this read 1 and 1.
  const count = (family: string) => PRESETS.filter((p) => p.family === family).length;
  assert.ok(count("radio") >= 4, `only ${count("radio")} radios`);
  assert.ok(count("phone") >= 4, `only ${count("phone")} phones`);
});

test("every preset matches the level pinned in Rust", () => {
  // The same thirteen numbers are asserted in crates/voipc-audio/src/mixer.rs
  // (PRESET_PINS). Thirteen presets in two languages is exactly where a typo
  // hides, and a level is sensitive to every part of the chain: a wrong
  // coefficient, a missing stage, a reordered one, a drifted makeup gain.
  const PINS: [string, number][] = [
    ["phone", -19.68],
    ["radio", -17.43],
    ["cb", -20.65],
    ["walkie", -21.58],
    ["aviation", -18.52],
    ["police", -20.66],
    ["landline", -16.83],
    ["mobile", -15.60],
    ["badvoip", -14.39],
    ["intercom", -19.26],
    ["megaphone", -23.27],
    ["gramophone", -14.38],
    ["robot", -14.35],
  ];
  assert.equal(PINS.length, PRESETS.length, "the pin table lost a preset");
  PINS.forEach(([id, want], i) => {
    assert.equal(PRESETS[i].id, id, "the pin table is out of order");
    const got = rmsDb(through(200, 0.5, i + 1, 4, 0));
    assert.ok(Math.abs(got - want) < 0.5, `${id}: ${got.toFixed(2)} dB, pinned at ${want}`);
  });
});

test("effect ids round-trip and anything unknown renders plainly", () => {
  PRESETS.forEach((p, i) => assert.equal(effectFromId(p.id), i + 1));
  for (const name of ["none", "", "direct", "spatial", "telepathy"]) {
    assert.equal(effectFromId(name), FX_NONE, `${name} was not refused`);
  }
  // 0, 1 and 2 are pinned: the desktop stores them in a config and an atomic
  assert.equal(PRESETS[FX_PHONE - 1].id, "phone");
  assert.equal(PRESETS[FX_RADIO - 1].id, "radio");
  assert.equal(preset(FX_NONE), null);
});

test("a silent preset does not touch the noise generator", () => {
  // One unguarded call shifts the xorshift stream and changes every preset at
  // once, so each stage sits behind its own guard.
  for (const p of PRESETS.filter((p) => !p.noise && !p.crackle && !p.squelch)) {
    const st = newFxState();
    const seed = st.noise;
    for (let i = 0; i < FRAME; i++) fxSample(st, Math.sin(i * 0.01), p.lpA, p);
    assert.equal(st.noise, seed, `${p.id} disturbed the noise generator`);
  }
});

test("phone passes the voice band and cuts the edges", () => {
  const reference = rmsDb(through(1000, 0.1, FX_NONE, 6, 2));
  const mid = rmsDb(through(1000, 0.1, FX_PHONE, 6, 2));
  const low = rmsDb(through(100, 0.1, FX_PHONE, 6, 2));
  const high = rmsDb(through(6000, 0.1, FX_PHONE, 6, 2));
  assert.ok(Math.abs(mid - reference) < 3, `1 kHz moved by ${mid - reference} dB`);
  assert.ok(reference - low > 15, `100 Hz only cut by ${reference - low} dB`);
  assert.ok(reference - high > 9, `6 kHz only cut by ${reference - high} dB`);
});

test("an off chain is bit-exact and still advances its filters", () => {
  const st = newFxState();
  for (let i = 0; i < 200; i++) {
    const x = Math.sin(i * 0.03) * 0.5;
    assert.equal(fxSample(st, x, 1, null), x, `sample ${i} was altered`);
  }
  assert.notEqual(st.lowpass, 0, "the filters did not advance while off");
});

test("a radio hisses only while it is playing", () => {
  const hiss = through(0, 0, FX_RADIO, 6, 2);
  const level = rmsDb(hiss);
  assert.ok(level > -48 && level < -30, `hiss at ${level} dBFS`);
  assert.ok(hiss.every(Number.isFinite));
});

test("the squelch opens once per transmission", () => {
  const st = newFxState();
  const p = preset(FX_RADIO);
  const energy = () => {
    let sum = 0;
    for (let i = 0; i < FRAME; i++) {
      const s = fxSample(st, 0, p.lpA, p);
      sum += s * s;
    }
    return sum;
  };
  const pcm = new Float32Array(FRAME);
  applySenderFx(pcm, FX_RADIO, st, true);
  const first = pcm.reduce((a, s) => a + s * s, 0);
  const quiet = energy();
  assert.ok(first > 4 * quiet, "no opening burst");

  pcm.fill(0);
  applySenderFx(pcm, FX_RADIO, st, true);
  assert.ok(pcm.reduce((a, s) => a + s * s, 0) < 4 * quiet, "it squelched twice");

  pcm.fill(0);
  applySenderFx(pcm, FX_RADIO, st, false);
  pcm.fill(0);
  applySenderFx(pcm, FX_RADIO, st, true);
  assert.ok(pcm.reduce((a, s) => a + s * s, 0) > 4 * quiet, "the squelch did not re-open");
});

test("a stop owes a closing burst and then nothing", () => {
  const st = newFxState();
  const pcm = new Float32Array(FRAME);
  applySenderFx(pcm, FX_RADIO, st, true);
  assert.ok(fxStop(st, FX_RADIO, true) > 0, "no closing burst owed");
  st.burst = 0;
  assert.equal(fxStop(st, FX_RADIO, true), 0, "a closed radio still owed one");
});

// ── Reverb and water, which are effects like any other ───────────────────

test("every underwater step is audible", () => {
  // The complaint this catches: on the shipped curve the first five steps moved
  // a 1 kHz tone by 0.83, 0.86, 0.93, 1.11 and 1.49 dB, so the bottom half of
  // the slider did nothing you could hear.
  const levelDb = (lv: number) => rmsDb(laneThrough(1000, lv, 0, 6, 6).slice(2).flat());
  let prev = levelDb(0);
  let total = 0;
  for (let lv = 1; lv <= 10; lv++) {
    const db = levelDb(lv);
    const step = prev - db;
    assert.ok(step >= 1.5 && step <= 4.5, `underwater ${lv}: step of ${step.toFixed(2)} dB`);
    total += step;
    prev = db;
  }
  assert.ok(total > 24, `the whole slider only spans ${total.toFixed(1)} dB`);
});

test("underwater 0 does not touch the mix", () => {
  const space = new ReverbWater();
  const l = Float32Array.from({ length: FRAME }, (_, i) => Math.sin(i * 0.03));
  const r = Float32Array.from(l);
  const before = Float32Array.from(l);
  assert.equal(space.apply(l, r, 0, 0, true), false);
  assert.deepEqual([...l], [...before], "an idle lane altered the mix");
});

test("the reverb is loud enough to hear, at the levels Rust measures", () => {
  // The catcher for "reverb does nothing". The shipped build measured about
  // 35 dB below dry — inaudible at every setting — while its test asserted
  // only that the energy was above 1e-6, against a value of 3.8e-3.
  //
  // Same excitation, same estimator and the same three numbers as
  // `the_reverb_is_loud_enough_to_hear` in crates/voipc-audio/src/mixer.rs, so
  // this is a cross-language pin rather than two suites agreeing to differ:
  // it was measured on its own noise, against targets 2.5 dB away, inside a
  // ±4 dB band — which is wide enough for the browser to drift audibly with
  // nothing failing.
  const wetOverDryDb = (reverb: number) => {
    const space = new ReverbWater();
    const src = speechlike(48_000 * 3);
    // The trim scales dry and wet alike, so the wet path is recoverable exactly
    const trim = dryTrim(reverb);
    const dry: number[] = [];
    const wet: number[] = [];
    for (let f = 0; f * FRAME < src.length; f++) {
      const chunk = src.slice(f * FRAME, (f + 1) * FRAME);
      const l = Float32Array.from(chunk);
      const r = Float32Array.from(chunk);
      space.apply(l, r, 0, reverb, true);
      if (f >= 50) {
        // Settled: the bank takes a few hundred ms to fill
        for (let i = 0; i < chunk.length; i++) {
          dry.push(chunk[i]);
          wet.push(l[i] - chunk[i] * trim);
        }
      }
    }
    return 20 * Math.log10(rms(wet) / rms(dry));
  };
  for (const [level, want] of [[3, -18.5], [6, -11.2], [10, -7.5]] as [number, number][]) {
    const got = wetOverDryDb(level);
    assert.ok(
      Math.abs(got - want) < 0.5,
      `reverb ${level}: ${got.toFixed(2)} dB, Rust measures ${want}`,
    );
  }
});

test("the reverb rings after the speaker stops, then stops itself", () => {
  const frames = laneThrough(400, 0, 8, 60, 20);
  const energy = (f: number) => frames[f].reduce((a, s) => a + s * s, 0);
  assert.ok(energy(21) > 1e-6, "nothing rang after the speaker stopped");
  assert.ok(energy(55) < 0.5 * energy(21), "the tail did not decay");
  assert.ok(frames.flat().every((s) => Number.isFinite(s) && Math.abs(s) <= 4), "runaway feedback");
});

test("two fresh lanes sound the same", () => {
  assert.deepEqual(laneThrough(300, 4, 6, 5, 3), laneThrough(300, 4, 6, 5, 3));
});

test("a lane left switched on still goes quiet", () => {
  // Nobody turns the reverb off when a speaker stops talking, so the level
  // stays where the user put it for every one of these frames. Answering
  // "still audible" from the level rather than from the tail kept the mixer
  // awake for ever and ran the comb bank on subnormals through every silence.
  // The Rust suite asserts the same rule in `a_lane_left_switched_on_still_goes_quiet`.
  const space = new ReverbWater();
  const l = Float32Array.from({ length: FRAME }, (_, i) => Math.sin(i * 0.03));
  const r = Float32Array.from(l);
  assert.equal(space.apply(l, r, 3, 8, true), true);

  let closed = -1;
  for (let f = 0; f < 200; f++) {
    l.fill(0);
    r.fill(0);
    // Same levels as while they were talking — that is the point
    if (!space.apply(l, r, 3, 8, false)) {
      closed = f;
      break;
    }
  }
  assert.ok(closed >= 0, "a lane with the reverb up never stopped ringing");
  // Exactly zero, not merely small: a bank left holding 1e-38 costs a denormal
  // penalty on every sample fed through it afterwards.
  for (const c of space.comb) assert.ok(c.every((s) => s === 0), "a comb kept its tail");
  for (const a of space.allpass) assert.ok(a.every((s) => s === 0), "an allpass kept its tail");
  assert.deepEqual(space.uw, [0, 0, 0, 0], "the water filters kept their state");
});

// ── One lane, two directions ─────────────────────────────────────────────

test("your own voice and somebody else's go through the same lane", () => {
  // The complaint this catches: the microphone and an incoming voice having
  // different controls, and reverb and water living somewhere other than
  // beside muffle. There is one chain; this measures that both directions run
  // it, in the same order, with the same numbers.
  //
  // Quiet source on purpose: the sender clamps its own output and the mixer
  // clamps only after summing, so anything loud enough to clip would compare
  // two different clamps rather than two chains.
  const src = Float32Array.from({ length: FRAME }, (_, i) => 0.18 * Math.sin(i * 0.021));
  const fx = FX_RADIO;
  const p = preset(fx);
  assert.ok(p, "radio is missing from the table");
  const [muffle, reverb, water] = [4, 6, 3];
  const lpA = muffleLpA(muffle);

  // Going out: one call, which is the whole lane.
  const out = Float32Array.from(src);
  applySenderFx(out, fx, newFxState(), true, lpA, new ReverbWater(), water, reverb);

  // Coming in: what the mixer does per source — effect, then this lane's
  // reverb and water, then the makeup that rides the pan's gain ramp.
  const st = newFxState();
  const space = new ReverbWater();
  fxStart(st, fx);
  const inn = Float32Array.from(src);
  const a = Math.min(lpA, p.lpA);
  for (let i = 0; i < inn.length; i++) inn[i] = fxSample(st, inn[i], a, p);
  space.applyMono(inn, water, reverb, true);
  for (let i = 0; i < inn.length; i++) inn[i] *= p.gain;

  let worst = 0;
  for (let i = 0; i < inn.length; i++) worst = Math.max(worst, Math.abs(inn[i] - out[i]));
  assert.ok(worst < 1e-6, `the two directions differ by ${worst.toExponential(2)}`);
  assert.ok(rmsDb([...out]) > -40, "the comparison ran on silence");
});

test("every scalable effect reaches the microphone as well", () => {
  // Each of the three has to change what goes out on its own, with the other
  // two off. A control that only works on the way in is the bug that was
  // rejected twice.
  // Low and high together: muffle and water are filters, so a bass-only probe
  // would show them doing nothing and prove the wrong thing.
  const src = Float32Array.from(
    { length: FRAME },
    (_, i) => 0.14 * (Math.sin(i * 0.026) + Math.sin(i * 0.39)),
  );
  // Four frames, because the shortest comb is 1215 samples long: over a single
  // 20 ms frame the reverb has not come back yet and would read as silence.
  const run = (muffle: number, reverb: number, water: number) => {
    const st = newFxState();
    const space = new ReverbWater();
    let last: number[] = [];
    for (let f = 0; f < 4; f++) {
      const pcm = Float32Array.from(src);
      applySenderFx(pcm, FX_NONE, st, true, muffleLpA(muffle), space, water, reverb);
      last = [...pcm];
    }
    return last;
  };
  const plain = run(0, 0, 0);
  assert.deepEqual(plain, [...src], "a lane with nothing on is not a bypass");
  const ref = rmsDb(plain);
  for (const [name, one] of [
    ["muffle", run(6, 0, 0)],
    ["reverb", run(0, 6, 0)],
    ["water", run(0, 0, 6)],
  ] as [string, number[]][]) {
    // Measured: muffle -5.4 dB, reverb -17.5, water -1.1, all relative to the
    // untouched voice. This is a "does it reach the microphone at all" guard —
    // the loudness ladders live in the two tests above it.
    const diff = rmsDb(one.map((v, i) => v - plain[i])) - ref;
    assert.ok(diff > -24, `${name} changed the outgoing voice by only ${diff.toFixed(1)} dB`);
  }
});
