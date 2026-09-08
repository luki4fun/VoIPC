// Positional ("proximity") audio, the browser half.
//
// A line-for-line port of crates/voipc-audio/src/spatial.rs — the two must
// agree, or the same room sounds different depending on which client you are
// on. `SPATIAL_GOLDEN` below is the shared check: the same cases are asserted
// in the Rust unit tests and, in the browser, by the end-to-end self-test.
//
// Coordinates are metres, x/y is the ground plane and z is up.

export type ProximityMode = "off" | "2d" | "3d";

/** Distance (m) inside which a source plays at full volume. */
export const REF_DIST = 1.5;
/** Steepness of the inverse distance curve (1.0 = physical). */
export const ROLLOFF = 1.0;
/** Default distance (m) at which a source falls silent. */
export const DEFAULT_RANGE = 20.0;
/** Fraction of the range over which the tail fades to zero. */
const FADE_FRACTION = 0.15;
/** Maximum pan; speech hard-panned to 1.0 is fatiguing and vanishes on one earbud. */
export const WIDTH = 0.85;
/** Near-field omni blend (Mumble's bloom). */
export const BLOOM = 0.5;
const MUFFLE_FC_MIN = 350;
const MUFFLE_FC_MAX = 22_000;
const MUFFLE_CUT_DB = 15;
/** Highest muffle level the SDK may send (0 = clear, 10 = through a wall). */
export const MAX_MUFFLE = 10;

const SAMPLE_RATE = 48_000;

export interface Listener {
  pos: [number, number, number];
  /** Unit forward vector in the x/y plane; the room view uses [0, 1]. */
  fwd: [number, number];
}

export interface Source {
  pos: [number, number, number];
  /** Distance (m) at which this source falls silent. */
  range: number;
  /** Per-source volume, 0..2. */
  volume: number;
  /** Occlusion, 0 (clear) to MAX_MUFFLE (through a wall). */
  muffle: number;
  /** Render flat: radio, phone, megaphone, spectators. */
  direct: boolean;
}

export interface Gains {
  l: number;
  r: number;
  /** One-pole low-pass coefficient; 1.0 means bypass. */
  lpA: number;
}

/** A source nobody placed sounds exactly as it did before proximity chat. */
export const FLAT: Gains = { l: 1, r: 1, lpA: 1 };
const SILENT: Gains = { l: 0, r: 0, lpA: 1 };

export function defaultListener(): Listener {
  return { pos: [0, 0, 0], fwd: [0, 1] };
}

export function defaultSource(pos: [number, number, number]): Source {
  return { pos, range: DEFAULT_RANGE, volume: 1, muffle: 0, direct: false };
}

/**
 * Stereo gains for one source; `src` is null for a user nobody has placed.
 * A source dead centre comes out at unity on both channels, so switching a
 * channel to proximity does not make everyone quieter.
 */
export function gains(mode: ProximityMode, lis: Listener, src: Source | null): Gains {
  if (!src) return FLAT;
  if (mode === "off") return FLAT;
  if (src.direct) return { l: src.volume, r: src.volume, lpA: 1 };

  const dz = mode === "3d" ? src.pos[2] - lis.pos[2] : 0;
  const d: [number, number, number] = [src.pos[0] - lis.pos[0], src.pos[1] - lis.pos[1], dz];
  const dist = Math.sqrt(d[0] * d[0] + d[1] * d[1] + d[2] * d[2]);

  const range = Math.max(src.range, 0.01);
  const attenuation = REF_DIST / (REF_DIST + ROLLOFF * (Math.max(dist, REF_DIST) - REF_DIST));
  const fade = clamp((range - dist) / (FADE_FRACTION * range), 0, 1);
  const g = attenuation * fade;
  if (g <= 0) return SILENT;

  // Lateral offset in the listener's frame: +1 fully right, -1 fully left.
  const right: [number, number] = [lis.fwd[1], -lis.fwd[0]];
  const lat = dist > 1e-3 ? (d[0] * right[0] + d[1] * right[1]) / dist : 0;
  const bloom = clamp(BLOOM * (1 - dist / REF_DIST), 0, 1);
  const pan = clamp(lat * WIDTH * (1 - bloom), -1, 1);
  const angle = ((pan + 1) * 0.5 * Math.PI) / 2;

  const m = Math.min(src.muffle, MAX_MUFFLE) / MAX_MUFFLE;
  const volume = g * src.volume * Math.pow(10, (-MUFFLE_CUT_DB * m) / 20) * Math.SQRT2;
  const lpA =
    m === 0
      ? 1
      : 1 - Math.exp((-2 * Math.PI * Math.pow(MUFFLE_FC_MAX, 1 - m) * Math.pow(MUFFLE_FC_MIN, m)) / SAMPLE_RATE);

  return { l: volume * Math.cos(angle), r: volume * Math.sin(angle), lpA };
}

function clamp(v: number, lo: number, hi: number): number {
  return v < lo ? lo : v > hi ? hi : v;
}

// ── The settings panel's spatial test (mirrors spatial.rs) ───────────────
//
// A synthetic voice orbits the listener, so anyone can check that their
// headphones (and this mixer) pan and attenuate the way proximity chat will,
// without needing a second person in the channel.

/** Orbit radius (m) of the test voice. */
export const TEST_RADIUS = 3;
/** Seconds per revolution: front → right → behind → left. */
export const TEST_ORBIT_SECS = 8;
/** In 3D the voice climbs this far above the listener, and sinks as far below. */
export const TEST_HEIGHT = 4;
/** Seconds for one full height sweep. */
export const TEST_HEIGHT_SECS = 16;

/** Where the test voice is `t` seconds in, for a listener at the origin facing +y. */
export function testSource(mode: ProximityMode, t: number): Source {
  const theta = (2 * Math.PI * t) / TEST_ORBIT_SECS;
  const z = mode === "3d" ? TEST_HEIGHT * Math.sin((2 * Math.PI * t) / TEST_HEIGHT_SECS) : 0;
  return defaultSource([TEST_RADIUS * Math.sin(theta), TEST_RADIUS * Math.cos(theta), z]);
}

/** Fundamental (Hz) of the synthetic voice. */
export const TEST_VOICE_HZ = 180;
const TEST_VOICE_HARMONICS = [1, 0.5, 0.35, 0.2, 0.1];
const TEST_VOICE_GAIN = 0.5;
const TEST_VOICE_SYLLABLES_HZ = 4;
const TEST_VOICE_ON_SAMPLES = 36_000;

/** One sample of the synthetic voice; exactly periodic per second. */
export function testVoiceSample(n: number): number {
  const k = n % SAMPLE_RATE;
  if (k >= TEST_VOICE_ON_SAMPLES) return 0;
  const t = k / SAMPLE_RATE;
  const env = 0.5 - 0.5 * Math.cos(2 * Math.PI * TEST_VOICE_SYLLABLES_HZ * t);
  let tone = 0;
  let sum = 0;
  TEST_VOICE_HARMONICS.forEach((a, i) => {
    tone += a * Math.sin(2 * Math.PI * (i + 1) * TEST_VOICE_HZ * t);
    sum += a;
  });
  return (TEST_VOICE_GAIN * env * tone) / sum;
}

/** One 20 ms frame (960 samples) starting at sample index `first`. */
export function testVoiceFrame(first: number, length = 960): Float32Array {
  const out = new Float32Array(length);
  for (let i = 0; i < length; i++) out[i] = testVoiceSample(first + i);
  return out;
}

const TEST_SECTORS = [
  "in front of you",
  "front right",
  "on your right",
  "behind right",
  "behind you",
  "behind left",
  "on your left",
  "front left",
];

/** Where the test voice is, in words: "on your right, 3.0 m away, 2.8 m above you". */
export function testLabel(mode: ProximityMode, t: number): string {
  const [x, y, z] = testSource(mode, t).pos;
  const sector = Math.round((((Math.atan2(x, y) * 180) / Math.PI + 360) % 360) / 45) % 8;
  const where = `${TEST_SECTORS[sector]}, ${Math.hypot(x, y, z).toFixed(1)} m away`;
  if (mode !== "3d") return where;
  const height =
    Math.abs(z) < 0.5
      ? "at ear level"
      : z > 0
        ? `${z.toFixed(1)} m above you`
        : `${(-z).toFixed(1)} m below you`;
  return `${where}, ${height}`;
}

/**
 * Cases that must produce the same numbers here and in the Rust mixer.
 * Returns the first mismatch, or null when the port is faithful.
 */
export function checkGoldenValues(): string | null {
  const lis = defaultListener();
  const near = (a: number, b: number) => Math.abs(a - b) < 1e-3;
  const at = (x: number, y: number) => defaultSource([x, y, 0]);

  const centre = gains("2d", lis, at(0, 0));
  if (!near(centre.l, 1) || !near(centre.r, 1)) return `centre ${centre.l}/${centre.r} != 1/1`;

  if (gains("2d", lis, null) !== FLAT) return "unplaced must be flat";
  if (gains("off", lis, at(5, 0)) !== FLAT) return "off channels must be flat";

  const right = gains("2d", lis, at(5, 0));
  const power = Math.sqrt(right.l * right.l + right.r * right.r) / Math.SQRT2;
  if (!near(power, 0.3)) return `5 m attenuation ${power} != 0.3`;
  if (!(right.r > right.l * 5)) return `5 m right did not pan right (${right.l}/${right.r})`;

  const left = gains("2d", lis, at(-5, 0));
  if (!near(left.l, right.r) || !near(left.r, right.l)) return "left/right are not mirrored";

  const out = gains("2d", lis, at(0, DEFAULT_RANGE));
  if (out.l !== 0 || out.r !== 0) return "a source at the range must be silent";

  const above = { ...defaultSource([0, 0, 100]) };
  const flat2d = gains("2d", lis, above);
  if (!near(flat2d.l, 1) || !near(flat2d.r, 1)) return "2d must ignore height";
  const in3d = gains("3d", lis, above);
  if (in3d.l !== 0) return "3d must not ignore height";

  const direct = gains("3d", lis, { ...defaultSource([500, 500, 500]), volume: 0.8, direct: true });
  if (!near(direct.l, 0.8) || !near(direct.r, 0.8)) return "direct sources must bypass geometry";

  const walled = gains("2d", lis, { ...at(0, 0), muffle: MAX_MUFFLE });
  if (!near(walled.l / centre.l, Math.pow(10, -0.75))) return "muffle volume cut is wrong";
  if (!near(walled.lpA, 0.045)) return `muffle cutoff ${walled.lpA} != 0.045`;

  return checkTestGoldenValues();
}

/**
 * The spatial test's own golden table, asserted the same way in spatial.rs.
 * Kept here so the browser end-to-end run covers it too.
 */
function checkTestGoldenValues(): string | null {
  const lis = defaultListener();
  const near = (a: number, b: number) => Math.abs(a - b) < 1e-3;
  const at = (mode: ProximityMode, t: number) => gains(mode, lis, testSource(mode, t));
  const power = (g: Gains) => Math.sqrt(g.l * g.l + g.r * g.r) / Math.SQRT2;
  const modes: ProximityMode[] = ["2d", "3d"];

  for (let step = 0; step <= 64; step++) {
    const t = step * 0.25;
    for (const mode of modes) {
      const p = testSource(mode, t).pos;
      if (!near(Math.hypot(p[0], p[1]), TEST_RADIUS)) return `test orbit radius at ${t}`;
      if (mode === "2d" && p[2] !== 0) return "2d test must stay at ear level";
      if (Math.abs(p[2]) > TEST_HEIGHT + 1e-3) return `test height at ${t}`;
      const q = testSource(mode, t + 0.02).pos;
      if (Math.hypot(q[0] - p[0], q[1] - p[1], q[2] - p[2]) >= 0.1) return `test jumped at ${t}`;
      const r = testSource(mode, t + TEST_HEIGHT_SECS).pos;
      if (!near(p[0], r[0]) || !near(p[1], r[1]) || !near(p[2], r[2])) return "test is not periodic";
    }
  }

  const quarters: [number, number, number][] = [
    [0, 0, 3],
    [2, 3, 0],
    [4, 0, -3],
    [6, -3, 0],
  ];
  for (const [t, x, y] of quarters) {
    const p = testSource("2d", t).pos;
    if (!near(p[0], x) || !near(p[1], y)) return `test quarter at ${t}: ${p[0]}/${p[1]}`;
  }
  for (const [t, z] of [[0, 0], [4, TEST_HEIGHT], [8, 0], [12, -TEST_HEIGHT]]) {
    if (!near(testSource("3d", t).pos[2], z)) return `3d test height at ${t}`;
  }

  for (const mode of modes) {
    const ratio = mode === "3d" ? 2.5 : 5;
    const right = at(mode, 2);
    if (!(right.r > right.l * ratio)) return `${mode} test does not pan right at t=2`;
    const left = at(mode, 6);
    if (!(left.l > left.r * ratio)) return `${mode} test does not pan left at t=6`;
    for (const t of [0, 4]) {
      const g = at(mode, t);
      if (Math.abs(g.l - g.r) >= 1e-3) return `${mode} test not centred at t=${t}`;
    }
  }

  for (let step = 0; step <= 32; step++) {
    const t = step * 0.25;
    if (!near(power(at("2d", t)), 0.5)) return `2d test power at ${t}`;
    const p3 = power(at("3d", t));
    if (p3 > 0.5 + 1e-3 || p3 <= 0.25) return `3d test power ${p3} at ${t}`;
  }
  for (const t of [4, 12]) {
    if (!near(power(at("3d", t)), 0.3)) return `3d test power at ${t}`;
  }

  let peak = 0;
  let prev = testVoiceSample(0);
  for (let n = 0; n < SAMPLE_RATE; n++) {
    const s = testVoiceSample(n);
    if (!Number.isFinite(s)) return `test voice sample ${n} is not finite`;
    peak = Math.max(peak, Math.abs(s));
    if (Math.abs(s - prev) >= 0.03) return `test voice steps at ${n}`;
    prev = s;
  }
  if (!(peak > 0.3 && peak <= 0.5)) return `test voice peak ${peak}`;
  if (testVoiceSample(40_000) !== 0) return "test voice must pause";
  if (testVoiceSample(1234) !== testVoiceSample(1234 + SAMPLE_RATE)) return "test voice not periodic";
  // The pins spatial.rs asserts
  if (!near(testVoiceSample(6017), -0.0577201)) return "test voice pin 6017";
  if (!near(testVoiceSample(18_500), 0.0877542)) return "test voice pin 18500";

  return null;
}
