// Mixer worklet: the playback half of the voice pipeline, a port of the native
// voice mixer (client/src-tauri/src/network.rs voice_mixer_task) and the
// per-source jitter buffer (crates/voipc-audio/src/jitter.rs).
//
// The main thread decodes each Opus packet as it arrives and posts the PCM
// with its sequence number; this worklet keeps one JitterBuffer of decoded
// frames per source, pulls one 20 ms frame per source on the audio clock,
// sums them with per-user gain, clamps, and honors deafen.
//
// bernd: a lost frame is 20 ms of silence. The native client decodes the
// next packet's in-band FEC or runs Opus PLC; WebCodecs exposes neither, so
// the upgrade path is a wasm Opus decoder driven from inside this worklet.

// @ts-nocheck — AudioWorkletGlobalScope (currentTime, registerProcessor,
// AudioWorkletProcessor) is not in the DOM lib, and this file only became
// visible to tsc when audio.ts started importing its pure functions. The DSP
// here is covered by client/src/lib/audio-fx.test.ts instead.

// Importable off the audio thread — the sender chain in audio.ts and the Node
// tests both pull the pure functions out of this file, so there is exactly one
// JS copy of the DSP. These three globals only exist inside an
// AudioWorkletGlobalScope, and `??=` never assigns when we really are in one.
globalThis.AudioWorkletProcessor ??= class {};
globalThis.registerProcessor ??= () => {};
globalThis.currentTime ??= 0;

const FRAME = 960;
const LOST = Symbol("lost");

// ── The effect chain, mirrored from crates/voipc-audio/src/mixer.rs ──────
//
// Same constants, same order, same state names. The Rust suite and the Node
// suite assert the same golden vector, so the two cannot drift apart unnoticed.

/** One-pole high-pass coefficient: exp(-2π·300/48000). */
const FX_HP_R = 0.96149;
/** One-pole low-pass coefficient: 1 - exp(-2π·3400/48000). */
export const FX_LP_A = 0.35922;
const RADIO_DRIVE = 2.5;
const RADIO_HISS = 0.03;
const SQUELCH_SAMPLES = 480;
const SQUELCH_GAIN = 0.25;
/** Frames (20 ms) with nothing to play before a radio counts as finished. */
const FX_IDLE_FRAMES = 10;

/** Effect ids, matching the Rust `Effect` discriminants exactly. 0/1/2 are
 *  pinned: they are stored in configs and in an atomic on the desktop side. */
export const FX_NONE = 0;
export const FX_PHONE = 1;
export const FX_RADIO = 2;

/** The shape every preset starts from: nothing switched on. */
const PLAIN = {
  id: "none", label: "No effect", family: "colour",
  hpR: FX_HP_R, lpA: FX_LP_A, drive: 0, noise: 0, crackle: 0,
  squelch: false, crushHold: 0, crushStep: 0, ringK: 0, gain: 1,
};

/**
 * Every chain, indexed by effect id minus one — the same thirteen rows, in the
 * same order, with the same numbers as `PRESETS` in
 * crates/voipc-audio/src/mixer.rs. The Rust suite and the Node suite assert the
 * same golden vector for all of them, which is what stops the two drifting.
 */
export const PRESETS = [
  { ...PLAIN, id: "phone", label: "Phone (legacy)", family: "phone" },
  { ...PLAIN, id: "radio", label: "Radio", family: "radio",
    drive: RADIO_DRIVE, noise: RADIO_HISS, squelch: true },
  { ...PLAIN, id: "cb", label: "CB radio", family: "radio",
    hpR: 0.948987, lpA: 0.297724, drive: 4.0, noise: 0.03, squelch: true, gain: 0.8 },
  { ...PLAIN, id: "walkie", label: "Walkie-talkie", family: "radio",
    hpR: 0.942796, lpA: 0.288471, drive: 3.0, noise: 0.022, squelch: true },
  { ...PLAIN, id: "aviation", label: "Aviation radio", family: "radio",
    hpR: 0.955219, lpA: 0.279096, drive: 2.0, noise: 0.045, squelch: true, gain: 1.25 },
  { ...PLAIN, id: "police", label: "Police radio", family: "radio",
    hpR: 0.948987, lpA: 0.324768, drive: 3.5, noise: 0.018, squelch: true,
    crushHold: 3, crushStep: 1 / 128, gain: 0.85 },
  { ...PLAIN, id: "landline", label: "Landline", family: "phone",
    drive: 0.8, noise: 0.004, gain: 2.3 },
  { ...PLAIN, id: "mobile", label: "Mobile", family: "phone",
    hpR: 0.967805, lpA: 0.375772, drive: 1.2, noise: 0.006,
    crushHold: 3, crushStep: 1 / 128, gain: 1.55 },
  { ...PLAIN, id: "badvoip", label: "Bad VoIP", family: "phone",
    hpR: 0.97416, lpA: 0.391902, drive: 1.5, noise: 0.01,
    crushHold: 6, crushStep: 1 / 48, gain: 1.2 },
  { ...PLAIN, id: "intercom", label: "Intercom", family: "phone",
    hpR: 0.955219, lpA: 0.342216, drive: 2.0, noise: 0.012, gain: 1.15 },
  { ...PLAIN, id: "megaphone", label: "Megaphone", family: "colour",
    hpR: 0.936646, lpA: 0.324768, drive: 6.0, gain: 0.65 },
  { ...PLAIN, id: "gramophone", label: "Gramophone", family: "colour",
    hpR: 0.97416, lpA: 0.324768, drive: 1.5, noise: 0.012, crackle: 0.05,
    crushHold: 2, crushStep: 1 / 160, gain: 1.2 },
  { ...PLAIN, id: "robot", label: "Robot", family: "colour",
    hpR: 0.97416, drive: 1.5, ringK: 0.007854, gain: 1.7 },
];

/** The parameters for an effect id, or null for no effect at all. */
export function preset(fx) {
  return fx > 0 && fx <= PRESETS.length ? PRESETS[fx - 1] : null;
}

/** The effect id a name refers to; anything unknown renders plainly. */
export function effectFromId(id) {
  const i = PRESETS.findIndex((p) => p.id === id);
  return i < 0 ? FX_NONE : i + 1;
}

/** Cutoff (Hz) → one-pole coefficient at 48 kHz (mixer.rs `one_pole_a`). */
export function onePoleA(fc) {
  return 1 - Math.exp((-2 * Math.PI * fc) / 48000);
}

const UW_FC_MIN = 230;
/** Solved backwards from the two-pole response for an even step at 1 kHz --
 *  see the note on UW_FC in crates/voipc-audio/src/mixer.rs. */
const UW_FC = [0, 1688, 1103, 828, 657, 537, 446, 374, 317, 269, UW_FC_MIN];
const UW_CUT_DB = 6;
const UW_CUT_CURVE = 2.0;
const REVERB_COMB = [1215, 1390, 1548, 1695];
const REVERB_ALLPASS = [605, 480];
const REVERB_DAMP_FC = 4000;
const REVERB_FB_MIN = 0.7;
const REVERB_FB_SPAN = 0.22;
/** Normalised by the comb bank's own broadband power gain — see the note in
 *  crates/voipc-audio/src/mixer.rs on why a flat 0.015 was 35 dB too quiet. */
const REVERB_NORM = 0.7;
const reverbIn = (fb) => REVERB_NORM * Math.sqrt((1 - fb * fb) / 4);
const REVERB_WET_MAX = 0.47;
const REVERB_WET_CURVE = 1.35;
/** How much the dry path is trimmed, so a room full of talkers keeps headroom.
 *  Exported because it is the only handle a cross-language test has on it: the
 *  trim scales the wet send and the dry path alike, so it cancels out of every
 *  wet-to-dry ratio. Mirrors `dry_trim` in crates/voipc-audio/src/mixer.rs. */
export const dryTrim = (reverb) => {
  const r = Math.min(Math.max(reverb, 0), MAX_ROOM) / MAX_ROOM;
  const wet = REVERB_WET_MAX * r ** REVERB_WET_CURVE;
  return Math.sqrt(1 - wet * wet);
};
const REVERB_TAIL_FRAMES = 150;
const MAX_ROOM = 10;

/** Everything one source's effect chain carries between frames. */
export function newFxState() {
  return {
    lowpass: 0,
    lowpass2: 0,
    hp: [0, 0, 0, 0],
    noise: 0x2545f491,
    burst: 0,
    talking: false,
    idle: 0,
    crushHold: 0,
    crushI: 0,
    // The oscillator starts on the unit circle, not at the origin
    ringU: 1,
    ringV: 0,
    level: 0,
  };
}

/** Uniform noise in [-1, 1), from a 32-bit xorshift (mixer.rs `white`). */
export function white(st) {
  let x = st.noise;
  x ^= (x << 13) >>> 0;
  x >>>= 0;
  x ^= x >>> 17;
  x ^= (x << 5) >>> 0;
  x >>>= 0;
  st.noise = x;
  return (x >>> 8) * (2 / (1 << 24)) - 1;
}

/**
 * One sample through the chain (mixer.rs `fx_sample`). `a` is the first
 * low-pass coefficient: the muffle filter, or the band-limit for an effect.
 *
 * Every filter state advances even when the effect is off, so switching one on
 * mid-stream cannot pop.
 */
export function fxSample(st, x, a, p) {
  // Chain order is load-bearing and must not be shuffled:
  //   drive -> noise -> crackle -> ring -> squelch -> HP x2 -> crush -> LP1 -> LP2
  // Every stage sits behind its own guard so a preset that asks for none of them
  // does not touch the noise generator: one stray call shifts the xorshift
  // stream and breaks the golden vector for every preset at once.
  if (p) {
    if (p.drive > 0) {
      const d = x * p.drive;
      x = d / (1 + Math.abs(d));
    }
    if (p.noise > 0) x += p.noise * white(st);
    if (p.crackle > 0) {
      const w = white(st);
      if (Math.abs(w) > 0.995) x += p.crackle * w * 8;
    }
    if (p.ringK > 0) {
      // Magic-circle oscillator: a sine without calling Math.sin per sample
      st.ringU -= p.ringK * st.ringV;
      st.ringV += p.ringK * st.ringU;
      x *= st.ringV;
    }
  }
  if (st.burst > 0) {
    const env = st.burst / SQUELCH_SAMPLES;
    st.burst -= 1;
    x += SQUELCH_GAIN * env * white(st);
  }
  const hpR = p ? p.hpR : FX_HP_R;
  const h1 = hpR * (st.hp[1] + x - st.hp[0]);
  st.hp[0] = x;
  st.hp[1] = h1;
  const h2 = hpR * (st.hp[3] + h1 - st.hp[2]);
  st.hp[2] = h1;
  st.hp[3] = h2;

  let input = p ? h2 : x;
  // Bit-crush between the high-passes and the band-limit: after the low-pass
  // its images would land above 3.4 kHz with nothing left to filter them.
  if (p) {
    if (p.crushHold > 1) {
      if (st.crushI === 0) {
        st.crushHold = input;
        st.crushI = p.crushHold;
      }
      st.crushI -= 1;
      input = st.crushHold;
    }
    if (p.crushStep > 0) input = Math.round(input / p.crushStep) * p.crushStep;
  }
  st.lowpass += a * (input - st.lowpass);
  const first = a >= 1 ? input : st.lowpass;
  const lpA = p ? p.lpA : FX_LP_A;
  st.lowpass2 += lpA * (first - st.lowpass2);
  return p ? st.lowpass2 : first;
}

/**
 * Nothing to play for this source (mixer.rs `mix_source_stop`). Counts the
 * pause and, once it is long enough — or the sender said so — closes a radio
 * transmission with a squelch burst. Returns how many samples it owes.
 */
export function fxStop(st, fx, ended) {
  if (st.talking) {
    st.idle = Math.min(st.idle + 1, 255);
    if (ended || st.idle >= FX_IDLE_FRAMES) {
      st.talking = false;
      st.idle = 0;
      if (preset(fx)?.squelch) st.burst = SQUELCH_SAMPLES;
    }
  }
  // Nothing played, so the meter reads nothing: otherwise every strip freezes
  // at its last value the moment the room goes quiet.
  st.level = 0;
  return st.burst;
}

/** Open the squelch on the first frame of a transmission (mixer.rs:190-194). */
export function fxStart(st, fx) {
  if (preset(fx)?.squelch && !st.talking) st.burst = SQUELCH_SAMPLES;
  st.talking = fx !== FX_NONE;
  st.idle = 0;
}

/**
 * One lane's reverb and water: two scalable effects, 0-10 each, exactly like
 * muffle. Every lane has its own — one person's voice coming in, or our own
 * microphone going out. Port of `ReverbWaterState` / `apply_reverb_water`.
 */
export class ReverbWater {
  constructor() {
    this.comb = REVERB_COMB.map((n) => new Float32Array(n));
    this.combI = [0, 0, 0, 0];
    this.damp = [0, 0, 0, 0];
    this.allpass = REVERB_ALLPASS.map((n) => new Float32Array(n));
    this.apI = [0, 0];
    this.uw = [0, 0, 0, 0];
    this.gain = 1;
    this.wet = 0;
    this.primed = false;
    this.tail = 0;
    // Whether anything has been written into the delay lines. A lane with
    // nothing switched on is the common case and there is one of these per
    // talker, so the bypass path must not wipe 22 kB per lane per frame.
    this.dirty = false;
    // Whether the comb bank has been fed since it was last wiped. Separate
    // from `dirty`, because a lane that is only underwater keeps filtering
    // while its bank sits idle.
    this.bankLive = false;
  }

  /** Forget the comb bank, which is where a reverb tail lives. */
  clearBank() {
    for (const c of this.comb) c.fill(0);
    for (const a of this.allpass) a.fill(0);
    this.combI = [0, 0, 0, 0];
    this.apI = [0, 0];
    this.damp = [0, 0, 0, 0];
    this.tail = 0;
    this.bankLive = false;
  }

  clear() {
    this.clearBank();
    this.uw = [0, 0, 0, 0];
    this.dirty = false;
  }

  /**
   * In place over one frame of separate left/right buffers. `hadInput` says
   * whether any source was mixed this frame; the return value is "something is
   * still audible", because a tail outlives the voice that caused it.
   */
  /**
   * Over a mono buffer: a lane before it is panned, or our own microphone on
   * its way out. Mirrors `apply_reverb_water_mono` in
   * crates/voipc-audio/src/mixer.rs, and the Rust suite asserts the two paths
   * agree sample for sample.
   */
  applyMono(buf, underwater, reverb, hadInput) {
    return this.apply(buf, buf, underwater, reverb, hadInput);
  }

  apply(left, right, underwater, reverb, hadInput) {
    const u = Math.min(Math.max(underwater, 0), MAX_ROOM) / MAX_ROOM;
    const r = Math.min(Math.max(reverb, 0), MAX_ROOM) / MAX_ROOM;
    const level = Math.min(Math.max(Math.round(underwater), 0), MAX_ROOM);
    const a = level === 0 ? 1 : onePoleA(UW_FC[level]);
    const wetT = REVERB_WET_MAX * r ** REVERB_WET_CURVE;
    const gainT = 10 ** ((-UW_CUT_DB * u ** UW_CUT_CURVE) / 20) * dryTrim(reverb);

    if (a >= 1 && wetT === 0 && this.gain === 1 && this.wet === 0 && this.tail === 0) {
      if (this.dirty) this.clear();
      return false;
    }
    if (!this.primed) {
      this.gain = gainT;
      this.wet = wetT;
      this.primed = true;
    }

    const n = Math.min(left.length, right.length);
    const fb = REVERB_FB_MIN + REVERB_FB_SPAN * r;
    const revIn = reverbIn(fb);
    const dampA = onePoleA(REVERB_DAMP_FC);
    const stepGain = (gainT - this.gain) / n;
    const stepWet = (wetT - this.wet) / n;
    let gain = this.gain;
    let wet = this.wet;
    // The send this frame starts at, so a wet path ramping down to zero still
    // counts while it is audible.
    const wasWet = this.wet;
    // With no wet path and nothing still ringing, the bank's output is
    // multiplied by zero: skip it rather than feed it. Mirrors `run_reverb` in
    // crates/voipc-audio/src/mixer.rs.
    const runReverb = wetT > 0 || wasWet > 0 || this.tail > 0;
    if (!runReverb && this.bankLive) this.clearBank();

    for (let i = 0; i < n; i++) {
      const lIn = left[i];
      const rIn = right[i];
      this.uw[0] += a * (lIn - this.uw[0]);
      this.uw[1] += a * (this.uw[0] - this.uw[1]);
      this.uw[2] += a * (rIn - this.uw[2]);
      this.uw[3] += a * (this.uw[2] - this.uw[3]);
      const l = (a >= 1 ? lIn : this.uw[1]) * gain;
      const rr = (a >= 1 ? rIn : this.uw[3]) * gain;

      let w = 0;
      if (runReverb) {
        const mono = 0.5 * (l + rr) * revIn;
        for (let k = 0; k < 4; k++) {
          const buf = this.comb[k];
          const y = buf[this.combI[k]];
          this.damp[k] += dampA * (y - this.damp[k]);
          buf[this.combI[k]] = mono + this.damp[k] * fb;
          this.combI[k] = (this.combI[k] + 1) % buf.length;
          w += y;
        }
        for (let k = 0; k < 2; k++) {
          const buf = this.allpass[k];
          const b = buf[this.apI[k]];
          buf[this.apI[k]] = w + b * 0.5;
          this.apI[k] = (this.apI[k] + 1) % buf.length;
          w = b - w;
        }
      }

      left[i] = l + w * wet;
      right[i] = rr + w * wet;
      gain += stepGain;
      wet += stepWet;
    }

    this.gain = gainT;
    this.wet = wetT;
    this.dirty = true;
    this.bankLive = this.bankLive || runReverb;
    // Input counts as *reverb* input only while there is a wet path to put it
    // into, or a lane somebody once put reverb on would re-arm its tail on
    // every frame and never go quiet again.
    this.tail =
      hadInput && (wetT > 0 || wasWet > 0) ? REVERB_TAIL_FRAMES : Math.max(0, this.tail - 1);
    // "Still audible" is the tail alone, never the settings: a lane with the
    // reverb turned up is *configured* to ring, but a bank fed nothing for
    // REVERB_TAIL_FRAMES has nothing left in it. Zero the lines on the way
    // out, so the next voice starts in an empty room — though not while audio
    // is still flowing through the water, where wiping the filters mid-stream
    // would be a click on every frame. Mirrors `reverb_water`.
    if (this.tail === 0 && (!hadInput || (wetT === 0 && a >= 1))) this.clear();
    return this.tail > 0;
  }
}

/**
 * Our own microphone's lane, in place: effect, then muffle, then reverb and
 * water — the same four controls, in the same order, that an incoming lane is
 * rendered with. Port of `SourceChain::render_mono`.
 *
 * Runs on every captured frame whether or not we are transmitting, so the
 * filters and the reverb tail stay warm through a pause — frozen state steps
 * and clicks on the first frame after the gate re-opens. With nothing switched
 * on the whole thing is a bit-exact bypass, so running it always costs nothing.
 * `onAir` false also closes the transmission, so the next one opens a fresh
 * squelch.
 *
 * `room` is this lane's own delay lines, or null where there is nowhere to keep
 * them. The makeup gain lands after the room, exactly as it does on the way in,
 * where it rides the pan's ramp.
 *
 * @param {Float32Array} pcm
 * @param {number} fx
 * @param {ReturnType<typeof newFxState>} st
 * @param {boolean} onAir
 * @param {number} [muffleA]
 * @param {ReverbWater | null} [room]
 * @param {number} [water]
 * @param {number} [reverb]
 */
export function applySenderFx(pcm, fx, st, onAir, muffleA = 1, room = null, water = 0, reverb = 0) {
  if (!onAir) {
    fxStop(st, fx, true);
    st.burst = 0; // nowhere to render a closing burst; the listener renders it
  } else {
    fxStart(st, fx);
  }
  // The band-limit is the first stage for an effect, exactly as the mixer
  // clamps it — with a bypass here the chain would be one pole short of the
  // desktop's.
  const p = preset(fx);
  const a = Math.min(p ? p.lpA : 1, muffleA);
  const makeup = p ? p.gain : 1;
  for (let i = 0; i < pcm.length; i++) pcm[i] = fxSample(st, pcm[i], a, p);
  if (room) room.applyMono(pcm, water, reverb, true);
  for (let i = 0; i < pcm.length; i++) {
    const s = pcm[i] * makeup;
    pcm[i] = s > 1 ? 1 : s < -1 ? -1 : s;
  }
}

// jitter.rs constants (time in seconds on the audio clock)
const MAX_PLC_RUN = 50;
const MAX_LATE_DISCARDS = 25;
const MIN_TARGET_DELAY = 2;
const MAX_TARGET_DELAY = 8;
const MAX_BUFFER_CAP = 32;
const DECAY_QUIET = 10;
const GROW_COOLDOWN = 1;

// network.rs: sources with no packets for this long are dropped
const SOURCE_IDLE_PRUNE = 60;
// How often the played/lost counters are reported (in pulled frames; 25 = 500 ms)
const STATS_INTERVAL_FRAMES = 25;
/** Meters refresh every 3 frames (60 ms): fast enough to follow speech. */
const LEVEL_INTERVAL_FRAMES = 3;

const wrapSub = (a, b) => (a - b) >>> 0;
const wrapAdd1 = (a) => (a + 1) >>> 0;

/** Port of jitter.rs `JitterBuffer` holding decoded PCM instead of Opus. */
class JitterBuffer {
  constructor(targetDelay) {
    /** Sorted by sequence ascending (like the BTreeMap): [{seq, pcm}] */
    this.entries = [];
    this.nextSeq = null;
    this.targetDelay = targetDelay;
    this.buffering = true;
    this.maxBuffer = Math.min(targetDelay * 4, MAX_BUFFER_CAP);
    this.lateDiscards = 0;
    this.lastChange = null;
  }

  noteTrouble() {
    if (!(this.lastChange !== null && currentTime - this.lastChange < GROW_COOLDOWN)) {
      this.targetDelay = Math.min(this.targetDelay + 1, MAX_TARGET_DELAY);
    }
    this.lastChange = currentTime;
    this.maxBuffer = Math.min(this.targetDelay * 4, MAX_BUFFER_CAP);
  }

  maybeDecay() {
    if (
      this.targetDelay > MIN_TARGET_DELAY &&
      (this.lastChange === null || currentTime - this.lastChange >= DECAY_QUIET)
    ) {
      this.targetDelay -= 1;
      this.lastChange = currentTime;
      this.maxBuffer = Math.min(this.targetDelay * 4, MAX_BUFFER_CAP);
    }
  }

  push(seq, pcm) {
    if (this.nextSeq !== null) {
      const distance = wrapSub(this.nextSeq, seq);
      if (distance > 0 && distance < 1000) {
        this.lateDiscards += 1;
        if (this.lateDiscards >= MAX_LATE_DISCARDS) {
          // Sustained lateness = sender restarted its counter. Resync.
          this.lateDiscards = 0;
          this.nextSeq = null;
          this.buffering = true;
        } else {
          if (distance <= MAX_PLC_RUN) this.noteTrouble();
          return;
        }
      } else {
        this.lateDiscards = 0;
      }
    }

    // Sorted insert; a duplicate sequence replaces the stored frame
    let i = this.entries.length;
    while (i > 0 && this.entries[i - 1].seq > seq) i--;
    if (i > 0 && this.entries[i - 1].seq === seq) {
      this.entries[i - 1].pcm = pcm;
    } else {
      this.entries.splice(i, 0, { seq, pcm });
    }

    // Fast-forward past dropped frames instead of playing a run of silence
    while (this.entries.length > this.maxBuffer) {
      this.entries.shift();
      this.nextSeq = this.entries.length ? this.entries[0].seq : null;
    }
  }

  /** Float32Array when the next frame is available, LOST for a gap, null while buffering/idle. */
  pop() {
    if (this.buffering) {
      if (this.entries.length >= this.targetDelay) {
        this.buffering = false;
        this.nextSeq = this.entries[0].seq;
      } else {
        return null;
      }
    }
    const next = this.nextSeq;
    if (next === null) return null;

    const idx = this.entries.findIndex((e) => e.seq === next);
    if (idx >= 0) {
      const [e] = this.entries.splice(idx, 1);
      this.nextSeq = wrapAdd1(next);
      return e.pcm;
    }
    if (this.entries.length > 0) {
      const smallest = this.entries[0].seq;
      if (wrapSub(smallest, next) > MAX_PLC_RUN) {
        // Discontinuity too large to conceal: skip to the buffered data
        this.nextSeq = smallest;
        return LOST;
      }
      this.nextSeq = wrapAdd1(next);
      return LOST;
    }
    // Underrun: re-arm buffering, keep nextSeq so stragglers are discarded
    this.buffering = true;
    this.maybeDecay();
    return null;
  }

  /** EndOfTransmission: clear, keeping the learned delay. */
  reset() {
    this.entries.length = 0;
    this.nextSeq = null;
    this.buffering = true;
    this.lateDiscards = 0;
    this.maybeDecay();
  }

  get isEmpty() {
    return this.entries.length === 0;
  }
}

class MixerProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    /** source key -> { jitter, eotReceived, lastActivity } */
    this.sources = new Map();
    /** user id -> gain (absent = 1.0) */
    this.userVolumes = new Map();
    /** source key -> [gainL, gainR, lowpass coefficient] from the spatial mixer */
    this.spatial = new Map();
    /**
     * user id -> one lane's controls, as the listener set them:
     * [effect id, muffle coefficient, reverb, water].
     */
    this.userFx = new Map();
    /**
     * A game saying the listener is standing somewhere: while one drives, it
     * overrides every incoming lane's own reverb and water. Null otherwise.
     */
    this.sdkRoom = null;
    this.deafened = false;
    this.mixL = new Float32Array(FRAME);
    this.mixR = new Float32Array(FRAME);
    /** One lane's mono frame, between its effect and the pan. */
    this.laneScratch = new Float32Array(FRAME);
    this.mixPos = FRAME; // nothing buffered yet
    this.framesPlayed = 0;
    this.framesLost = 0;
    this.lastReported = [0, 0];
    this.pullsSinceReport = 0;
    this.levelFrames = 0;
    this.port.onmessage = (e) => this.onMessage(e.data);
  }

  onMessage(m) {
    switch (m.type) {
      case "frame": {
        let src = this.sources.get(m.source);
        if (!src) {
          src = {
            jitter: new JitterBuffer(2),
            eotReceived: false,
            lastActivity: 0,
            // Where this source's gains were left last frame
            gainL: 1,
            gainR: 1,
            // First frame jumps to its target instead of ramping down from
            // unity, or a muted or distant speaker bursts at full volume
            primed: false,
            // Where its filters, hiss and squelch were left (SourceMixState)
            fx: newFxState(),
            // This lane's own reverb and water, with its own delay lines
            room: new ReverbWater(),
          };
          this.sources.set(m.source, src);
        }
        src.jitter.push(m.sequence, m.pcm);
        src.eotReceived = false;
        src.lastActivity = currentTime;
        break;
      }
      case "eot": {
        // Reset happens once the buffered tail has drained (see pullFrame)
        const src = this.sources.get(m.source);
        if (src) src.eotReceived = true;
        break;
      }
      case "user-volume":
        if (m.gain === 1) this.userVolumes.delete(m.userId);
        else this.userVolumes.set(m.userId, m.gain);
        break;
      // One incoming lane: an effect, a muffle coefficient, and its own reverb
      // and water — the same four controls our own microphone has. Ignored
      // while a game drives the mix; the main thread simply stops sending.
      case "user-fx":
        if (m.fx === FX_NONE && m.lpA >= 1 && !m.reverb && !m.water) {
          this.userFx.delete(m.userId);
        } else {
          this.userFx.set(m.userId, [m.fx, m.lpA, m.reverb | 0, m.water | 0]);
        }
        break;
      // A game placing the listener somewhere: while it drives, every incoming
      // lane is rendered through this instead of its own.
      case "sdk-room":
        this.sdkRoom = m.on ? [m.water | 0, m.reverb | 0] : null;
        break;
      // Bulk spatial update: [[sourceKey, gainL, gainR, lowpassCoefficient], …]
      // for every placed source. Keys absent from the list render flat.
      case "spatial":
        this.spatial.clear();
        for (const [key, l, r, lpA] of m.gains) this.spatial.set(key, [l, r, lpA]);
        break;
      case "spatial-clear":
        this.spatial.clear();
        break;
      case "deafen":
        this.deafened = !!m.value;
        break;
      case "clear":
        this.sources.clear();
        this.spatial.clear();
        break;
      case "reset":
        this.sources.clear();
        this.userVolumes.clear();
        this.userFx.clear();
        this.spatial.clear();
        this.framesPlayed = 0;
        this.framesLost = 0;
        this.lastReported = [0, 0];
        break;
    }
  }

  /** Pull one 20 ms frame from every source and mix into this.mixL/mixR. */
  pullFrame() {
    this.mixL.fill(0);
    this.mixR.fill(0);
    let mixed = false;
    for (const [key, src] of this.sources) {
      if (currentTime - src.lastActivity >= SOURCE_IDLE_PRUNE) {
        this.sources.delete(key);
        continue;
      }
      // Screen-share audio is never a radio, exactly as on the desktop
      const isScreenAudio = (key & 0x80000000) !== 0;
      const chosen = isScreenAudio ? undefined : this.userFx.get(key);
      const fx = chosen ? chosen[0] : FX_NONE;
      const fxp = preset(fx);
      // A game puts every lane where it says the listener is; otherwise each
      // lane carries its own. [water, reverb].
      const room =
        this.sdkRoom && !isScreenAudio
          ? this.sdkRoom
          : [chosen ? chosen[3] : 0, chosen ? chosen[2] : 0];
      // Nothing to play: a radio closes its squelch, at once on an
      // end-of-transmission and after a pause otherwise. Without this a
      // browser radio would squelch open once and never close.
      const drained = src.eotReceived && src.jitter.isEmpty;
      if (drained) {
        src.jitter.reset();
        src.eotReceived = false;
      }
      const r = drained ? null : src.jitter.pop();
      if (r === null || r === LOST) {
        if (r === LOST) this.framesLost++; // bernd: silence instead of FEC/PLC
        // A lost packet is not a pause: the speaker is still talking, we simply
        // did not receive that frame. Counting it as idle closed a radio's
        // squelch a fifth of a second into a loss burst and opened it again on
        // the next packet that arrived, so a listener heard two bursts in the
        // middle of a sentence that a desktop listener hears whole.
        const owed = r === LOST ? src.fx.burst : fxStop(src.fx, fx, drained);
        if (r === LOST) src.fx.level = 0;
        if (this.deafened) {
          src.fx.burst = 0; // deafened drops the burst rather than owing it
          src.fx.level = 0;
          continue;
        }
        // A reverb tail outlives the voice that caused it, so the lane's room
        // keeps running here even with nothing left to play — the *tail*, never
        // the settings. A lane sitting at reverb 6 with nobody talking has an
        // empty bank, and asking the settings ran four combs and a 27 kB wipe
        // per lane per frame for as long as the source lived. Same rule as
        // `SourceChain::stop` in crates/voipc-audio/src/mixer.rs.
        if (owed > 0 || src.room.tail > 0) {
          const tail = this.laneScratch;
          tail.fill(0);
          for (let i = 0; i < Math.min(owed, FRAME); i++) {
            tail[i] = fxSample(src.fx, 0, fxp ? fxp.lpA : FX_LP_A, fxp);
          }
          src.room.applyMono(tail, room[0], room[1], owed > 0);
          for (let i = 0; i < FRAME; i++) {
            this.mixL[i] += tail[i] * src.gainL;
            this.mixR[i] += tail[i] * src.gainR;
          }
          mixed = true;
        }
        src.fx.level = 0;
        continue;
      }
      this.framesPlayed++;
      if (this.deafened) continue; // popped so the buffer keeps flowing
      // Screen-audio sources (high bit set) follow their sharer's volume
      const gain = this.userVolumes.get(key & 0x7fffffff) ?? 1;
      // Spatial placement, if any: [gainL, gainR, lowpass coefficient].
      // Gains ramp across the frame — a step would click.
      const placement = this.spatial.get(key);
      const targetL0 = gain * (placement ? placement[0] : 1);
      const targetR0 = gain * (placement ? placement[1] : 1);
      // The listener's own muffle is the filter only, never a level cut, and
      // a radio is never muffled on top of its own band-limit.
      let lpA = Math.min(placement ? placement[2] : 1, chosen ? chosen[1] : 1);
      if (fxp) lpA = Math.min(lpA, fxp.lpA);
      // The makeup rides the same ramp as everything else, so switching preset
      // mid-sentence changes the voice without stepping the level.
      const makeup = fxp ? fxp.gain : 1;
      const targetL = targetL0 * makeup;
      const targetR = targetR0 * makeup;
      const n = Math.min(r.length, FRAME);
      if (!src.primed) {
        src.gainL = targetL;
        src.gainR = targetR;
        src.primed = true;
      }
      fxStart(src.fx, fx);
      const stepL = (targetL - src.gainL) / n;
      const stepR = (targetR - src.gainR) / n;
      let gl = src.gainL;
      let gr = src.gainR;
      // Effect, then this lane's room, then the pan: a radio in a cave is a
      // radio, in a cave.
      const lane = this.laneScratch.subarray(0, n);
      for (let i = 0; i < n; i++) lane[i] = fxSample(src.fx, r[i], lpA, fxp);
      src.room.applyMono(lane, room[0], room[1], true);
      let sum = 0;
      for (let i = 0; i < n; i++) {
        const s = lane[i];
        sum += s * s;
        this.mixL[i] += s * gl;
        this.mixR[i] += s * gr;
        gl += stepL;
        gr += stepR;
      }
      // Pre-fader, but after the makeup: a loud preset must not read quiet
      src.fx.level = Math.sqrt(sum / n) * makeup;
      src.gainL = targetL;
      src.gainR = targetR;
      mixed = true;
    }
    if (mixed) {
      for (let i = 0; i < FRAME; i++) {
        const l = this.mixL[i];
        const r = this.mixR[i];
        this.mixL[i] = l > 1 ? 1 : l < -1 ? -1 : l;
        this.mixR[i] = r > 1 ? 1 : r < -1 ? -1 : r;
      }
    }
    // Meters get their own cadence: the packet counters below are happy at
    // 500 ms, a meter at 500 ms looks broken.
    if (++this.levelFrames >= LEVEL_INTERVAL_FRAMES) {
      this.levelFrames = 0;
      const levels = [];
      for (const [key, src] of this.sources) {
        if ((key & 0x80000000) === 0) levels.push([key, src.fx.level]);
      }
      this.port.postMessage({ type: "levels", levels });
    }
    if (++this.pullsSinceReport >= STATS_INTERVAL_FRAMES) {
      this.pullsSinceReport = 0;
      if (this.lastReported[0] !== this.framesPlayed || this.lastReported[1] !== this.framesLost) {
        this.lastReported = [this.framesPlayed, this.framesLost];
        this.port.postMessage({ type: "stats", played: this.framesPlayed, lost: this.framesLost });
      }
    }
  }

  process(_inputs, outputs) {
    const out = outputs[0];
    if (!out || out.length === 0) return true;
    const left = out[0];
    const right = out.length > 1 ? out[1] : null;
    let o = 0;
    while (o < left.length) {
      if (this.mixPos >= FRAME) {
        this.pullFrame();
        this.mixPos = 0;
      }
      const take = Math.min(FRAME - this.mixPos, left.length - o);
      if (right) {
        left.set(this.mixL.subarray(this.mixPos, this.mixPos + take), o);
        right.set(this.mixR.subarray(this.mixPos, this.mixPos + take), o);
      } else {
        // Mono destination: the downmix, so a placed voice is still audible
        for (let i = 0; i < take; i++) {
          left[o + i] = 0.5 * (this.mixL[this.mixPos + i] + this.mixR[this.mixPos + i]);
        }
      }
      this.mixPos += take;
      o += take;
    }
    // Any further channels (surround) get the downmix
    for (let c = 2; c < out.length; c++) {
      for (let i = 0; i < left.length; i++) out[c][i] = 0.5 * (left[i] + right[i]);
    }
    return true;
  }
}

registerProcessor("voipc-mixer", MixerProcessor);
