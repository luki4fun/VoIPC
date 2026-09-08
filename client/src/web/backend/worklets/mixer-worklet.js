// Mixer worklet: the playback half of the voice pipeline, a port of the native
// voice mixer (client/src-tauri/src/network.rs voice_mixer_task) and the
// per-source jitter buffer (crates/voipc-audio/src/jitter.rs).
//
// The main thread decodes each Opus packet as it arrives and posts the PCM
// with its sequence number; this worklet keeps one JitterBuffer of decoded
// frames per source, pulls one 20 ms frame per source on the audio clock,
// sums them with per-user gain, clamps, and honors deafen.
//
// ponytail: a lost frame is 20 ms of silence. The native client decodes the
// next packet's in-band FEC or runs Opus PLC; WebCodecs exposes neither, so
// the upgrade path is a wasm Opus decoder driven from inside this worklet.

const FRAME = 960;
const LOST = Symbol("lost");

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
    this.deafened = false;
    this.mixL = new Float32Array(FRAME);
    this.mixR = new Float32Array(FRAME);
    this.mixPos = FRAME; // nothing buffered yet
    this.framesPlayed = 0;
    this.framesLost = 0;
    this.lastReported = [0, 0];
    this.pullsSinceReport = 0;
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
            // Where this source's gains and muffle filter were left last frame
            gainL: 1,
            gainR: 1,
            lowpass: 0,
            // First frame jumps to its target instead of ramping down from
            // unity, or a muted or distant speaker bursts at full volume
            primed: false,
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
      if (src.eotReceived && src.jitter.isEmpty) {
        src.jitter.reset();
        src.eotReceived = false;
        continue;
      }
      const r = src.jitter.pop();
      if (r === null) continue;
      if (r === LOST) {
        this.framesLost++;
        continue; // ponytail: silence instead of FEC/PLC
      }
      this.framesPlayed++;
      if (this.deafened) continue; // popped so the buffer keeps flowing
      // Screen-audio sources (high bit set) follow their sharer's volume
      const gain = this.userVolumes.get(key & 0x7fffffff) ?? 1;
      // Spatial placement, if any: [gainL, gainR, lowpass coefficient].
      // Gains ramp across the frame — a step would click.
      const placement = this.spatial.get(key);
      const targetL = gain * (placement ? placement[0] : 1);
      const targetR = gain * (placement ? placement[1] : 1);
      const lpA = placement ? placement[2] : 1;
      const n = Math.min(r.length, FRAME);
      if (!src.primed) {
        src.gainL = targetL;
        src.gainR = targetR;
        src.primed = true;
      }
      const stepL = (targetL - src.gainL) / n;
      const stepR = (targetR - src.gainR) / n;
      let gl = src.gainL;
      let gr = src.gainR;
      let lp = src.lowpass;
      for (let i = 0; i < n; i++) {
        lp += lpA * (r[i] - lp);
        const s = lpA >= 1 ? r[i] : lp;
        this.mixL[i] += s * gl;
        this.mixR[i] += s * gr;
        gl += stepL;
        gr += stepR;
      }
      src.gainL = targetL;
      src.gainR = targetR;
      src.lowpass = lp;
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
