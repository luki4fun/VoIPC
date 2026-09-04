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
    this.deafened = false;
    this.mix = new Float32Array(FRAME);
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
          src = { jitter: new JitterBuffer(2), eotReceived: false, lastActivity: 0 };
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
      case "deafen":
        this.deafened = !!m.value;
        break;
      case "clear":
        this.sources.clear();
        break;
      case "reset":
        this.sources.clear();
        this.userVolumes.clear();
        this.framesPlayed = 0;
        this.framesLost = 0;
        this.lastReported = [0, 0];
        break;
    }
  }

  /** Pull one 20 ms frame from every source and mix into this.mix. */
  pullFrame() {
    this.mix.fill(0);
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
      const n = Math.min(r.length, FRAME);
      for (let i = 0; i < n; i++) this.mix[i] += r[i] * gain;
      mixed = true;
    }
    if (mixed) {
      for (let i = 0; i < FRAME; i++) {
        const s = this.mix[i];
        this.mix[i] = s > 1 ? 1 : s < -1 ? -1 : s;
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
    const ch0 = out[0];
    let o = 0;
    while (o < ch0.length) {
      if (this.mixPos >= FRAME) {
        this.pullFrame();
        this.mixPos = 0;
      }
      const take = Math.min(FRAME - this.mixPos, ch0.length - o);
      ch0.set(this.mix.subarray(this.mixPos, this.mixPos + take), o);
      this.mixPos += take;
      o += take;
    }
    for (let c = 1; c < out.length; c++) out[c].set(ch0);
    return true;
  }
}

registerProcessor("voipc-mixer", MixerProcessor);
