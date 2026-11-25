// The browser sharer's send pacing (web/backend/transport.ts, share.ts). Pure, so Node can
// test it; the transport drives it on a clock a hidden tab does not clamp.
//
// Why: a browser's video encoder keeps to no rate. WebCodecs has no VBV, and Chromium's
// software H.264 encoder (OpenH264) sends what the picture costs whatever the bitrate asked,
// in every bitrateMode, "constant" too: on the lanes' moving picture 3.2 Mbit/s at 720p30 with
// 1.8 or 3.0 asked, 8.4 at 1080p30 with 3 or 5 (encoder bench, 2026-11-24). Whatever it made
// went to the link at once, so a share started on a small uplink filled it for the seconds
// before a viewer's loss report came back, and voice waited behind it (capped-link lane: voice
// one way 50 -> 340-650 ms). A fixed cap at a multiple of the level's bitrate fixes that link
// and throttles every other one: a link with room carries the 8.4.
//
// So nothing here caps a share that the link carries. The uplink is measured instead
// (UplinkControl): each frame's time from leaving the pacer to the peer's ack of it on
// WebTransport, a ping through the tunnel on the TCP fallback. Only once that time rises
// past the link's least by a queue's worth, while the link delivers at a steady rate of its
// own, does the pacer start pacing, at that rate, lower for a moment to drain what queued; from then on it follows the link
// up, slowly, while the encoder wants more, and after a spell with no queue it lets the share
// go unpaced again, to see whether the link still needs it. The sharer skips encoding a frame
// while more than PACE_GATE_MS waits in the pacer (share.ts), so an encoder over the link's
// rate sends fewer frames, never broken ones: what is queued always goes out whole.
//
// A queue of ours is frames backing up while the link delivers at a steady rate, its own.
// Frames back up in two other ways that are no queue of ours, and on WebTransport each
// frame's ack shows which: a new QUIC path's slow start (on a 300 ms round trip the first
// frames' acks take 660-900 ms, the rate they come back at doubling each round trip), and a
// stall of the path, as Wi-Fi has (no acks for a moment, then all at once).
//
// On the TCP fallback the socket is one queue in send order that no counter here shows; a
// ping through it waits behind every byte handed before it. The rate it delivers comes from
// the pings' pongs, each pair with video handed between them (TUNNEL_MEASURE_MS), and a TCP
// slow start shows there as on QUIC: a share's first keyframe takes four or five round trips
// from a window of ten segments, the rate doubling each. What waits ahead of the oldest ping
// still out counts for the sharer's gate as the pacer's own queue does (transport.ts), so
// voice waits behind little more than PACE_GATE_MS of video before anything is found, and a
// slow start only holds the encoder while it lasts.

/** The bucket holds this much of the rate: a small frame goes at once. */
export const PACE_BURST_MS = 40;
/** ...and never less than four records (a fragment and its length). */
export const PACE_MIN_BURST = 4 * (2 + 1282);
/** How often the clock looks while something waits. */
export const PACE_LOOK_MS = 10;
/**
 * The sharer encodes no new frame while more than this much of the rate waits: what video
 * may lag at most when the encoder is over the link, and room for a keyframe a few times a
 * delta's size without skipping the frames behind it. Unpaced, nothing waits in the pacer; on
 * the TCP fallback what waits in the socket ahead of the oldest ping still out counts too.
 */
export const PACE_GATE_MS = 100;

/**
 * The uplink is queued when the floor of its last few delay samples is past the least by
 * max(the least, UPLINK_MARGIN_MS, JITTER_MARGIN x the samples' jitter) (network.rs
 * `congested` reads QUIC's RTT the same way, with max(the least, 100 ms)). A queue makes every
 * sample late, one after another, and each a little later than the one before; a lost packet
 * makes one frame late by its resend, jitter one sample here and there, so the floor of a few
 * rises with a queue only, and past a margin the link's own wobble does not reach.
 */
export const UPLINK_MARGIN_MS = 60;
/** The jitter is the mean gap between one sample and the next (RFC 3550's, gain 1/16). */
export const JITTER_MARGIN = 2;
/**
 * ...and those samples came in over this long at least: a busy main thread resolves every
 * ack it held back in one moment, each late by the stall, and that is no queue.
 */
export const UPLINK_SPREAD_MS = 100;
/** Samples the floor is taken over: a frame's ack on WebTransport (a quarter second at 30 fps;
 *  in a model of the lossy lane, one frame in seven waiting a resend, six late in a row came by)... */
export const UPLINK_FLOOR_FRAMES = 8;
/** ...a ping's pong through the tunnel on the TCP fallback; a ping every PROBE_EVERY_MS while video goes. */
export const UPLINK_FLOOR_PROBES = 2;
export const PROBE_EVERY_MS = 333;
/** A ping out this long is taken as dropped (by the relay, which may): it times nothing. */
export const PROBE_LOST_MS = 2000;
/**
 * The tunnel's delivered rate: one measure per answered ping with video handed since the ping
 * answered before it, those bytes over the time the link was busy with them (from the later of
 * the ping before's pong and when the first of them could have crossed and been answered, the
 * least after it was handed, to this pong); no video between, no measure. A find there needs
 * the measures from the newest one a round trip or more before the newest on, that one no
 * older than this: each of the link at its limit (both its pings waited past the least by
 * UPLINK_MARGIN_MS, and the link took at least 1 / STEADY_GROW of the time the share took to
 * hand the bytes: a slow start's burst, or a link with room, carries them faster), and the
 * newest within STEADY_FALL..STEADY_GROW of the one a round trip before it (a slow start
 * doubles it each round trip; a stall's pongs come late, then in one moment).
 */
export const TUNNEL_MEASURE_MS = 2000;
/**
 * On WebTransport a queue is found only while the link's delivery is steady: over the last
 * STEADY_WINDOWS windows of max(STEADY_WINDOW_MS, STEADY_LEASTS x the shortest round trip the
 * link has shown, STEADY_GAPS x the link's own gap between acks) each, every one delivered
 * something and no less than STEADY_FALL times the one before (a stall: three windows, so a
 * stall as long as two of them still shows against the first), and the newest no more than
 * STEADY_GROW times the one before it (slow start grows it
 * each round trip; three round trips a window, so its bursts a round trip apart cannot line up
 * as steady). The shortest ever, not the least of late: the keepalive's pings before a share
 * come seconds apart and often late (a busy page), and the share's first frames waited behind
 * one another, so the least of late can be 3-5 times the round trip just as the share starts,
 * and windows that long wait out a small link's queue. The tunnel's pings come too rarely for
 * windows this short (TUNNEL_MEASURE_MS). The gap between acks is the median of those of the
 * last UPLINK_FLOOR_FRAMES acks whose frame left before the ack before it came, once at least
 * STEADY_MIN_GAPS are: a small link acks one frame a gap apart (300 ms for a 13 KB frame at
 * 350 kbps), and a window has to hold more than one of them.
 */
export const STEADY_WINDOW_MS = 200;
export const STEADY_LEASTS = 3;
export const STEADY_GAPS = 2;
export const STEADY_MIN_GAPS = 4;
export const STEADY_WINDOWS = 3;
export const STEADY_GROW = 1.5;
export const STEADY_FALL = 0.5;
/** On a queue found, the rate is the link's delivered rate times this... */
export const CUT_FACTOR = 0.85;
/** ...after this much of it, until the queue has drained (DRAIN_MAX_MS at most). */
export const DRAIN_FACTOR = 0.5;
export const DRAIN_MAX_MS = 1000;
/** Paced and held back, the rate rises this much a second up to the delivered rate, then slower. */
export const RISE_PER_S = 0.05;
export const RISE_PAST_PER_S = 0.02;
/** Held back means the pacer kept something this recently. */
export const BINDING_MS = 500;
/** Never paced slower than this. */
export const MIN_RATE_BPS = 200_000;
/**
 * Paced this long with no queue found, the share goes unpaced again (a probe): a queue that
 * came and went, or a link that grew, need no pacing, and the rise is slow. A probe that finds
 * the queue again within PROBE_HOLD_MS doubles the wait before the next, up to PROBE_MAX_MS;
 * one that holds that long starts the wait over.
 */
export const PROBE_AFTER_MS = 2000;
export const PROBE_HOLD_MS = 3000;
export const PROBE_MAX_MS = 8000;
/** The least is the least of the last few windows of this long, so a path that got longer is learnt. */
export const LEAST_WINDOW_MS = 10_000;
const LEAST_WINDOWS = 3;
/** Finds and probes kept for the self-test: a share on a small link finds every few seconds. */
export const UPLINK_KEPT = 64;

type Phase = "free" | "drain" | "paced";

/**
 * Whether the uplink queues, and the pacer's rate from that (transport.ts feeds it, share.ts
 * reads `queuedAt` as loss). Unpaced (`rate` 0) until a queue is found, and again after a
 * spell with none (PROBE_AFTER_MS).
 */
export class UplinkControl {
  /** Least sample of each LEAST_WINDOW_MS, newest last. */
  private leasts: { from: number; least: number }[] = [];
  /** The shortest sample this link ever gave (ms), for the steady check's windows. */
  private shortest = Infinity;
  /** The last samples: [ms, at]. */
  private recent: [number, number][] = [];
  private jitter = 0;
  private lastSample = NaN;
  /** When `pending` was last asked, to tell a late clock (a stalled page) from a queue. */
  private pendingAt = -Infinity;
  private pendingGap = 0;
  /** [at, bytes delivered so far] of this share's samples, for the steady check, oldest first... */
  private acked: [number, number][] = [];
  /** ...and the bytes delivered so far before the first of them. */
  private ackedBefore = 0;
  private lastDelivered = 0;
  /** When the last frame was acked, and the gaps the link set between the last acks (NaN: none). */
  private lastAckAt = -Infinity;
  private gaps: number[] = [];
  /** The tunnel's last answered ping of this share: [pong at, video handed before it, sent at, round trip]... */
  private answered: [number, number, number, number] | null = null;
  /** ...and its measures (TUNNEL_MEASURE_MS), newest last. */
  private measures: { at: number; bps: number; busy: boolean }[] = [];
  private phase: Phase = "free";
  private rateBps = 0;
  /** The delivered rate when the queue was last found, and the rate to pace at once drained. */
  private found = 0;
  private drainUntil = 0;
  private lastRise = 0;
  private boundAt = -Infinity;
  /** When the share was last paced again after a drain. */
  private pacedAt = 0;
  /** How long paced with no queue found before the next probe. */
  private probeWait = PROBE_AFTER_MS;
  /** When the last probe went unpaced, 0 once it held or found the queue again. */
  private probeAt = 0;
  /** When the uplink was last found queued (ms), 0 never. */
  queuedAt = 0;
  /** When each probe of this share went unpaced, the last UPLINK_KEPT (self-test)... */
  readonly probes: number[] = [];
  /** ...and how many there were. */
  probeCount = 0;
  /**
   * Each time it was, the last UPLINK_KEPT (self-test): [at, delivered bits per second, the
   * rate it paces at once drained, the least (ms), the floor that was past the threshold, 1 if
   * it was what was out].
   */
  readonly finds: number[][] = [];

  private readonly floorOf: number;
  private readonly steady: boolean;

  /**
   * @param floorOf samples the floor is taken over (UPLINK_FLOOR_FRAMES or UPLINK_FLOOR_PROBES)
   * @param steady a find needs the link's delivery steady (STEADY_*): each frame's ack on
   *   WebTransport, not the tunnel's pings
   */
  constructor(floorOf: number, steady: boolean) {
    this.floorOf = floorOf;
    this.steady = steady;
  }

  /** A share starts: unpaced again, its link not judged yet. What the link's least is stays. */
  reset(): void {
    this.recent = [];
    this.acked = [];
    this.ackedBefore = this.lastDelivered;
    this.lastAckAt = -Infinity;
    this.gaps = [];
    this.answered = null;
    this.measures = [];
    this.pendingAt = -Infinity;
    this.lastSample = NaN;
    this.phase = "free";
    this.rateBps = 0;
    this.found = 0;
    this.boundAt = -Infinity;
    this.probeWait = PROBE_AFTER_MS;
    this.probeAt = 0;
    this.queuedAt = 0;
    this.finds.length = 0;
    this.probes.length = 0;
    this.probeCount = 0;
  }

  /** The least the link has shown lately (ms), Infinity before any sample. */
  least(): number {
    return this.leasts.reduce((m, w) => Math.min(m, w.least), Infinity);
  }

  /** Past this, a floor of samples is a queue. */
  threshold(): number {
    const least = this.least();
    return least + Math.max(UPLINK_MARGIN_MS, least, JITTER_MARGIN * this.jitter);
  }

  /**
   * Past this, what is still out is a queue. Neither the jitter nor twice the least has a say:
   * `floorOf` frames out and that old is a backlog of as many frames already, which no wobble
   * makes, and on a small link the least is a frame's own time on the wire (140-180 ms for a
   * 15 KB frame at 1.5 Mbit/s), which twice over would wait out most of the queue. On the
   * tunnel, the oldest ping still out past PACE_GATE_MS: video waits in the socket ahead of it
   * longer than the sharer's gate lets more in behind, and its measures say whether that is
   * the link's limit or a slow start.
   */
  pendingThreshold(): number {
    return this.least() + (this.steady ? UPLINK_MARGIN_MS : PACE_GATE_MS);
  }

  /** A round trip that waited on no video of ours (a ping with nothing shared): the least only. */
  base(ms: number, now: number): void {
    this.noteLeast(ms, now);
  }

  /**
   * One delay sample: a frame from leaving the pacer to its ack, or a ping through the tunnel.
   * `deliveredBytes`: the video the link has delivered so far in all, this one's included.
   * `firstAt` (the tunnel's): when the first of the video handed since the ping answered
   * before this one went to the socket, NaN if none did.
   */
  sample(ms: number, deliveredBytes: number, now: number, firstAt = NaN): void {
    this.noteLeast(ms, now);
    if (!Number.isNaN(this.lastSample)) this.jitter += (Math.abs(ms - this.lastSample) - this.jitter) / 16;
    this.lastSample = ms;
    this.lastDelivered = deliveredBytes;
    if (this.steady) {
      // A gap the link set: this frame left before the one before it was acked
      this.gaps.push(now - ms < this.lastAckAt ? now - this.lastAckAt : NaN);
      if (this.gaps.length >= UPLINK_FLOOR_FRAMES) this.gaps.shift();
      this.lastAckAt = now;
      this.acked.push([now, deliveredBytes]);
      // Kept over the windows, and a second more for a least that grew
      const keep = STEADY_WINDOWS * this.steadyWindow() + 1000;
      while (this.acked.length > 1 && this.acked[0][0] < now - keep) this.ackedBefore = this.acked.shift()![1];
    } else {
      this.measure(ms, deliveredBytes, now, firstAt);
    }
    this.recent.push([ms, now]);
    if (this.recent.length > this.floorOf) this.recent.shift();
    if (this.recent.length < this.floorOf || now - this.recent[0][1] < UPLINK_SPREAD_MS) return;
    this.judge(Math.min(...this.recent.map(([m]) => m)), this.threshold(), now, 0);
  }

  /**
   * What is still out with no answer, oldest first, in ms: frames not acked yet, pings not
   * answered (the tunnel's cannot be lost on the way, only dropped, and one answered says every
   * older one was). A queue that grows faster than answers come back shows here first: on a
   * small link few come back a second. Judged as a floor of the `floorOf` oldest frames (one
   * resend holds one frame back, not eight), or by the tunnel's oldest ping (pendingThreshold),
   * never on a clock that came late, as a stalled page's does.
   */
  pending(agesOldestFirst: number[], now: number): void {
    const gap = now - this.pendingAt;
    const late = gap > Math.max(150, 2 * this.pendingGap);
    this.pendingAt = now;
    if (gap < 1000) this.pendingGap = gap;
    const n = this.steady ? this.floorOf : 1;
    if (late || agesOldestFirst.length < n) return;
    const floor = agesOldestFirst[n - 1];
    const threshold = this.pendingThreshold();
    if (floor > threshold) this.judge(floor, threshold, now, 1);
  }

  /** The pacer held video back at `now`: the encoder wants more than the rate. */
  binding(now: number): void {
    this.boundAt = now;
  }

  /** The pacer's rate at `now`, bits per second; 0 unpaced. */
  rate(now: number): number {
    if (this.phase === "drain" && now >= this.drainUntil) this.paceAgain(now);
    if (this.phase === "paced" && now - this.pacedAt >= this.probeWait) {
      // No queue found for that long: unpaced again, to see whether the link still needs it
      this.phase = "free";
      this.rateBps = 0;
      this.probeAt = now;
      this.probes.push(Math.round(now));
      if (this.probes.length > UPLINK_KEPT) this.probes.shift();
      this.probeCount++;
    } else if (this.phase === "paced") {
      const dt = Math.max(0, now - this.lastRise) / 1000;
      this.lastRise = now;
      if (now - this.boundAt < BINDING_MS) {
        const rise = this.rateBps < this.found ? RISE_PER_S : RISE_PAST_PER_S;
        this.rateBps *= 1 + rise * dt;
      }
    } else if (this.phase === "free" && this.probeAt > 0 && now - this.probeAt >= PROBE_HOLD_MS) {
      // The probe held: the link carries the share unpaced
      this.probeAt = 0;
      this.probeWait = PROBE_AFTER_MS;
    }
    return this.rateBps;
  }

  /** Whether video is paced now (a queue was found and no probe since has held). */
  paced(): boolean {
    return this.phase !== "free";
  }

  private judge(floor: number, threshold: number, now: number, out: number): void {
    if (this.phase === "drain") {
      // Drained once a floor is back near the least
      if (floor <= this.least() + (threshold - this.least()) / 2) this.paceAgain(now);
      return;
    }
    if (floor <= threshold) return;
    // Queued: what the link delivered meanwhile is what it carries
    const measured = this.steady ? this.steadyBps(now) : this.tunnelBps(now);
    // Slow start, a stall, or nothing measured yet: frames back up, but not behind a link that
    // carries less than they. On the tunnel the sharer's gate holds what waits meanwhile.
    if (Number.isNaN(measured)) return;
    const rate = Math.max(MIN_RATE_BPS, measured);
    if (this.probeAt > 0) {
      // The probe found the queue again: the next one waits longer
      this.probeWait = now - this.probeAt < PROBE_HOLD_MS ? Math.min(2 * this.probeWait, PROBE_MAX_MS) : PROBE_AFTER_MS;
      this.probeAt = 0;
    }
    this.found = rate;
    this.phase = "drain";
    this.drainUntil = now + DRAIN_MAX_MS;
    this.rateBps = Math.max(MIN_RATE_BPS, rate * DRAIN_FACTOR);
    this.queuedAt = now;
    this.recent = [];
    this.finds.push([Math.round(now), Math.round(rate), Math.round(rate * CUT_FACTOR), Math.round(this.least()), Math.round(floor), out]);
    if (this.finds.length > UPLINK_KEPT) this.finds.shift();
  }

  private paceAgain(now: number): void {
    this.phase = "paced";
    this.rateBps = Math.max(MIN_RATE_BPS, this.found * CUT_FACTOR);
    this.lastRise = now;
    this.pacedAt = now;
  }

  /** Each of the steady check's windows (ms): Infinity before any sample. */
  private steadyWindow(): number {
    const gaps = this.gaps.filter((g) => !Number.isNaN(g)).sort((a, b) => a - b);
    const gap = gaps.length >= STEADY_MIN_GAPS ? gaps[gaps.length >> 1] : 0;
    return Math.max(STEADY_WINDOW_MS, STEADY_LEASTS * this.shortest, STEADY_GAPS * gap);
  }

  /** Bytes delivered so far by `at`, as this share's samples said. */
  private ackedBy(at: number): number {
    let bytes = this.ackedBefore;
    for (const [t, b] of this.acked) {
      if (t > at) break;
      bytes = b;
    }
    return bytes;
  }

  /**
   * If the link's delivery is steady (STEADY_*), what it delivers in bits per second: from the
   * first ack to the last over the newest window, or the newest two while a window is shorter
   * than 2 x STEADY_WINDOW_MS. Else NaN.
   */
  private steadyBps(now: number): number {
    const w = this.steadyWindow();
    if (!Number.isFinite(w)) return NaN;
    let before = NaN;
    let bytes = this.ackedBy(now - STEADY_WINDOWS * w);
    for (let k = STEADY_WINDOWS - 1; k >= 0; k--) {
      const next = this.ackedBy(now - k * w);
      const got = next - bytes;
      bytes = next;
      // Growth only between the last two: the first may have begun before this share's first ack
      if (got <= 0 || got < STEADY_FALL * before || (k === 0 && got > STEADY_GROW * before)) return NaN;
      before = got;
    }
    const from = now - Math.max(w, 2 * STEADY_WINDOW_MS);
    const first = this.acked.find(([t]) => t > from)!;
    const last = this.acked[this.acked.length - 1];
    // Between acks, so the window's ends cost no frame either way
    if (last[0] - first[0] >= w / 2) return ((last[1] - first[1]) * 8000) / (last[0] - first[0]);
    return ((last[1] - this.ackedBy(from)) * 8000) / (now - from);
  }

  /** The tunnel's pong of a ping `ms` ago, `bytes` of video handed before it: a measure if any came between. */
  private measure(ms: number, bytes: number, now: number, firstAt: number): void {
    const prev = this.answered;
    this.answered = [now, bytes, now - ms, ms];
    if (!prev || bytes <= prev[1] || Number.isNaN(firstAt)) return;
    const least = this.least();
    const span = now - Math.max(prev[0], firstAt + least);
    if (span <= 0) return;
    // The link at its limit: both pings waited behind a queue, so it carried these bytes back to
    // back, and it took about as long as the share took to hand them (not a slow start's burst)
    const queued = (rtt: number) => rtt > least + UPLINK_MARGIN_MS;
    const busy = queued(prev[3]) && queued(ms) && span * STEADY_GROW >= now - ms - prev[2];
    this.measures.push({ at: now, bps: ((bytes - prev[1]) * 8000) / span, busy });
    if (this.measures.length > 6) this.measures.shift();
  }

  /** If the tunnel's measures are steady (TUNNEL_MEASURE_MS), the newest; else NaN. */
  private tunnelBps(now: number): number {
    const m = this.measures;
    // The newest against the newest a round trip or more before it: a slow start doubles over one
    const b = m[m.length - 1];
    let i = m.length - 2;
    while (i > 0 && b.at - m[i].at < this.least()) i--;
    const a = m[i];
    if (!a || b.at - a.at < this.least() || a.at < now - TUNNEL_MEASURE_MS) return NaN;
    if (!m.slice(i).every((x) => x.busy)) return NaN;
    if (b.bps > STEADY_GROW * a.bps || b.bps < STEADY_FALL * a.bps) return NaN;
    return b.bps;
  }

  private noteLeast(ms: number, now: number): void {
    this.shortest = Math.min(this.shortest, ms);
    const last = this.leasts[this.leasts.length - 1];
    if (!last || now - last.from >= LEAST_WINDOW_MS) {
      this.leasts.push({ from: now, least: ms });
      if (this.leasts.length > LEAST_WINDOWS) this.leasts.shift();
    } else if (ms < last.least) {
      last.least = ms;
    }
  }
}

/** A run of one frame's records, due now. */
export interface PacedSlice<T> {
  tag: T;
  bytes: Uint8Array;
  /** The frame's first bytes: open its stream. */
  first: boolean;
  /** The frame's last bytes: finish its stream. */
  last: boolean;
}

interface Queued<T> {
  tag: T;
  body: Uint8Array;
  /** Bytes of it let out so far (always a record boundary). */
  off: number;
}

/** Length of the record at `off` with its 2-byte prefix, or what is left of a malformed body. */
function recordEnd(body: Uint8Array, off: number): number {
  if (off + 2 > body.length) return body.length;
  const len = (body[off] << 8) | body[off + 1];
  return Math.min(body.length, off + 2 + Math.max(1, len));
}

/**
 * A token bucket that lets a frame's records out, in order, oldest frame first, a few at a
 * time: a big frame spreads over time instead of landing on the link at once. Rate 0 lets
 * everything out at once, as an unpaced share sends it.
 */
export class VideoPacer<T> {
  private queue: Queued<T>[] = [];
  private queued = 0;
  /** Bytes per ms now; 0 lets everything out at once. */
  private rate = 0;
  private tokens = 0;
  private at: number;

  constructor(now: number) {
    this.at = now;
  }

  /** The rate from now on, in bits per second (0: unpaced). */
  setRate(bitsPerSecond: number, now: number): void {
    this.refill(now);
    const unpaced = this.rate === 0;
    this.rate = Math.max(0, bitsPerSecond) / 8000;
    // A first rate starts with a full bucket
    this.tokens = unpaced ? this.burst() : Math.min(this.tokens, this.burst());
  }

  /** The rate now, bits per second. */
  rateBps(): number {
    return this.rate * 8000;
  }

  /** A frame's `[u16 len][packet]…` records, behind every frame already queued. */
  push(body: Uint8Array, tag: T): void {
    this.queue.push({ tag, body, off: 0 });
    this.queued += body.length;
  }

  /** Bytes queued and not let out yet. */
  queuedBytes(): number {
    return this.queued;
  }

  /** How long the queue takes at the rate. */
  queuedMs(): number {
    return this.rate > 0 ? this.queued / this.rate : 0;
  }

  empty(): boolean {
    return this.queue.length === 0;
  }

  /** Everything due by `now`: whole records, a slice per frame, in order. */
  take(now: number): PacedSlice<T>[] {
    this.refill(now);
    const out: PacedSlice<T>[] = [];
    while (this.queue.length > 0 && (this.rate === 0 || this.tokens > 0)) {
      const q = this.queue[0];
      const start = q.off;
      let end = start;
      // Records while tokens last: one may take the bucket below zero, the next refill pays it back
      while (end < q.body.length && (this.rate === 0 || this.tokens > 0)) {
        const next = this.rate === 0 ? q.body.length : recordEnd(q.body, end);
        if (this.rate > 0) this.tokens -= next - end;
        end = next;
      }
      q.off = end;
      this.queued -= end - start;
      const last = end >= q.body.length;
      out.push({ tag: q.tag, bytes: q.body.subarray(start, end), first: start === 0, last });
      if (last) this.queue.shift();
    }
    return out;
  }

  /** Drop every queued frame (the link closed); returns their tags. */
  clear(): T[] {
    const tags = this.queue.map((q) => q.tag);
    this.queue = [];
    this.queued = 0;
    return tags;
  }

  private burst(): number {
    return Math.max(PACE_MIN_BURST, this.rate * PACE_BURST_MS);
  }

  private refill(now: number): void {
    const dt = Math.max(0, now - this.at);
    this.at = now;
    if (this.rate > 0) this.tokens = Math.min(this.burst(), this.tokens + dt * this.rate);
  }
}
