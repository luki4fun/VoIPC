// Dive 5's simulator (review only, no product code): a browser share on a modelled link, on a
// fake clock. Real code under test: transport.ts (wrapSession, wrapSocket and their glue),
// lib/video-pacer.ts (UplinkControl, VideoPacer) and lib/share-rules.ts (the ladder, the
// keyframe rule, the capture pacing). Modelled here: the sharer (a port of share.ts
// ShareSender's encode path, line references in the comments), the encoder's frame sizes, and
// the link (one queue in send order at a rate, a round trip, optionally TCP's slow start).
//
// The clock steps 1 ms. Workers (the sharer's tick and the pace clock) are a stand-in driven by
// that clock, so a throttled worker can be modelled too.

import { connect, type Transport } from "./transport.ts";
import { PACE_GATE_MS } from "../../lib/video-pacer.ts";
import { LEVELS, START_LEVEL, nextLevel, paceFrame, shouldForceKey, type LadderChange } from "../../lib/share-rules.ts";

let clock = 0;
/** The sim's time, ms. */
export const simNow = () => clock;

// ── Workers on the sim's clock ──────────────────────────────────────────────

/** How late a worker's timer may fire at most (0: on time); a hidden tab's clamp if workers had one. */
let workerClampMs = 0;

class FakeWorker {
  static all = new Set<FakeWorker>();
  onmessage: ((e: unknown) => void) | null = null;
  private interval = 0;
  next = Infinity;
  constructor() {
    FakeWorker.all.add(this);
  }
  postMessage(msg: { type: string; intervalMs?: number }) {
    if (msg.type === "start") {
      this.interval = Math.max(1, Math.round(msg.intervalMs ?? 1));
      this.next = clock + this.interval;
    } else if (msg.type === "stop") {
      this.next = Infinity;
    }
  }
  terminate() {
    this.next = Infinity;
    FakeWorker.all.delete(this);
  }
  /** Fires if due, once for every tick missed (a worker's messages queue up behind a busy page); true if it did. */
  run(): boolean {
    if (clock < this.next) return false;
    let n = 0;
    while (this.next <= clock && n < 200) {
      this.next = workerClampMs > 0 ? Math.ceil((this.next + 1) / workerClampMs) * workerClampMs : this.next + this.interval;
      n++;
      this.onmessage?.(0);
    }
    if (this.next <= clock) this.next = clock + this.interval;
    return true;
  }
}

// ── The link ────────────────────────────────────────────────────────────────

export interface LinkShape {
  /** What the link carries from `t` on, bits per second (Infinity: room). */
  bps: (t: number) => number;
  /** The round trip at `t`, ms: half up, half down unless `downMs` says. */
  rttMs: (t: number) => number;
  /** Extra wait on the way back at `t` (a downlink queue, a proxy that batches), ms. */
  downExtraMs?: (t: number) => number;
  /** What comes back comes in the order it was sent (one TCP stream), however long each waited. */
  ordered?: boolean;
  /** TCP: slow start from ten segments (the tunnel only). */
  slowStart?: boolean;
  /** TCP: what the kernel takes before `bufferedAmount` shows anything, bytes. */
  sndbuf?: number;
  /** Whether the relay answers the ping sent at `t` (false: dropped). */
  answers?: (t: number) => boolean;
  /** From, to: nothing crosses either way, and what was due comes at `to`. */
  stalls?: [number, number][];
}

type Item = { bytes: number; left: number; kind: "video" | "voice" | "ping" | "keep"; at: number; stamp: number; done?: () => void };

class LinkQueue {
  readonly q: Item[] = [];
  queuedBytes = 0;
  /** Bytes the link may still send this ms, carried over. */
  private credit = 0;
  /** TCP's window. */
  cwnd = Infinity;
  inFlight = 0;
  private acks: [number, number][] = [];
  /** What arrives back at the sharer: [at, fn]. */
  readonly back: [number, () => void][] = [];
  voiceDelays: [number, number][] = [];
  shape: LinkShape;
  constructor(shape: LinkShape) {
    this.shape = shape;
    if (shape.slowStart) this.cwnd = 10 * 1448;
  }
  /** Video bytes handed to the link so far. */
  handed = 0;
  push(item: Item) {
    this.q.push(item);
    this.queuedBytes += item.bytes;
    if (item.kind === "video") this.handed += item.bytes;
  }
  private lastBack = 0;
  /** When something due back at `due` reaches the sharer. */
  private backAt(due: number): number {
    let at = due + (this.shape.downExtraMs?.(due) ?? 0);
    if (this.shape.ordered) at = this.lastBack = Math.max(at, this.lastBack);
    return at;
  }
  private stalled(t: number): number {
    for (const [a, b] of this.shape.stalls ?? []) if (t >= a && t < b) return b;
    return 0;
  }
  /** How long what is queued now takes to cross, ms. */
  backlogMs(t: number): number {
    const bps = this.shape.bps(t);
    return Number.isFinite(bps) ? (this.queuedBytes * 8000) / bps : 0;
  }
  step(t: number, onPong: (stamp: number, keep: boolean, sentAt: number) => void) {
    const stall = this.stalled(t);
    if (!stall) {
      while (this.acks.length > 0 && this.acks[0][0] <= t) {
        const b = this.acks.shift()![1];
        if (2 * this.inFlight > this.cwnd) this.cwnd += b;
        this.inFlight -= b;
      }
      const bps = this.shape.bps(t);
      this.credit = Number.isFinite(bps) ? Math.min(this.credit + bps / 8000, Math.max(bps / 8000, 3000)) : Infinity;
      while (this.q.length > 0 && this.credit > 0 && this.inFlight < this.cwnd) {
        const m = this.q[0];
        const n = Math.min(m.left, this.credit, Number.isFinite(this.cwnd) ? 1448 : Infinity);
        m.left -= n;
        this.credit -= n;
        this.queuedBytes -= n;
        const rtt = this.shape.rttMs(t);
        if (Number.isFinite(this.cwnd)) {
          this.inFlight += n;
          this.acks.push([t + rtt, n]);
        }
        if (m.left > 0) break;
        this.q.shift();
        if (m.kind === "voice") this.voiceDelays.push([m.at, t + rtt / 2 - m.at]);
        else if (m.kind === "ping" || m.kind === "keep") {
          if (this.shape.answers?.(m.at) ?? true) {
            const { stamp, kind, at } = m;
            this.back.push([this.backAt(t + rtt), () => onPong(stamp, kind === "keep", at)]);
          }
        } else if (m.done) {
          this.back.push([this.backAt(t + rtt), m.done]);
        }
      }
      if (this.q.length === 0 && Number.isFinite(this.credit)) this.credit = Math.min(this.credit, bps / 8000);
    }
    // What comes back, in the order it was due (a stall holds it)
    if (!stall) {
      this.back.sort((a, b) => a[0] - b[0]);
      while (this.back.length > 0 && this.back[0][0] <= t) this.back.shift()![1]();
    }
  }
}

// ── Stand-ins for the browser's two carriers ────────────────────────────────

let live: LinkQueue;
/** What the next `send` on the socket is. */
let sending: { kind: Item["kind"]; stamp: number } = { kind: "video", stamp: 0 };
/** Runs `send` with what it sends tagged; everything else on the socket is video (the pacer's). */
function tagged(kind: Item["kind"], stamp: number, send: () => void): void {
  sending = { kind, stamp };
  try {
    send();
  } finally {
    sending = { kind: "video", stamp: 0 };
  }
}

class SimSocket {
  static last: SimSocket;
  binaryType = "";
  onopen: (() => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onmessage: ((ev: { data: ArrayBuffer }) => void) | null = null;
  constructor() {
    SimSocket.last = this;
    queueMicrotask(() => this.onopen?.());
  }
  get bufferedAmount(): number {
    return Math.max(0, live.queuedBytes - (live.shape.sndbuf ?? 128 * 1024));
  }
  send(data: Uint8Array) {
    // A WebSocket frame's header and mask, and TLS's share of a record
    const bytes = data.length + 8;
    live.push({ bytes, left: bytes, kind: sending.kind, at: clock, stamp: sending.stamp });
  }
  close() {}
}

class SimWebTransport {
  static last: SimWebTransport;
  ready = Promise.resolve();
  closed = new Promise<void>(() => {});
  datagrams = {
    readable: new ReadableStream(),
    writable: {
      getWriter: () => ({
        write: async (data: Uint8Array) => {
          live.push({ bytes: data.length + 30, left: data.length + 30, kind: sending.kind, at: clock, stamp: sending.stamp });
        },
      }),
    },
  };
  incomingUnidirectionalStreams = new ReadableStream();
  constructor() {
    SimWebTransport.last = this;
  }
  close() {}
  async createBidirectionalStream() {
    return { readable: new ReadableStream<Uint8Array>(), writable: new WritableStream() };
  }
  async createUnidirectionalStream() {
    let last: Item | null = null;
    return {
      getWriter: () => ({
        write: async (data: Uint8Array) => {
          last = { bytes: data.length, left: data.length, kind: "video", at: clock, stamp: 0 };
          live.push(last);
        },
        // Resolves once the relay acked the frame's last byte
        close: () =>
          new Promise<void>((resolve) => {
            if (!last || last.left === 0) live.back.push([clock + live.shape.rttMs(clock), resolve]);
            else last.done = resolve;
          }),
      }),
    };
  }
}

// Node's own (this file is not a test file, so the page's types have no setImmediate)
const settle = () => new Promise((r) => (globalThis as any).setImmediate(r));

// ── The sharer (a port of share.ts ShareSender's encode path) ───────────────

export interface ShareShape {
  fps?: number;
  /** A frame's bytes: `key`, at `t`, at ladder `level`. */
  frameBytes: (t: number, key: boolean, level: number) => number;
  /** Whether the screen changes at `t` (false: a still screen, no captured frames). */
  moving?: (t: number) => boolean;
  /** How long the encoder takes over a frame, ms. */
  encodeMs?: (key: boolean) => number;
  /** A viewer asks for a keyframe at these times. */
  keyAsks?: number[];
  /** The keepalive's period (session.ts KEEPALIVE_MS; a tab hidden five minutes: 60 000). */
  keepaliveMs?: (t: number) => number;
  /** Voice packets every 20 ms from here on (none: no voice). */
  talkFrom?: number;
}

export interface SimOptions {
  tcp: boolean;
  link: LinkShape;
  share: ShareShape;
  /** The video starts here (ms); the session is up from 0, its keepalive answering. */
  startAt?: number;
  ms: number;
  /** A hidden tab's clamp on worker timers, if workers had one (ms). */
  workerClampMs?: number;
  /** The page's main thread runs nothing from, to. */
  busy?: [number, number][];
  /** Called every ms after the step. */
  each?: (t: number, s: SimState) => void;
}

export interface SimState {
  link: Transport;
  queue: LinkQueue;
  /** The pacer's rate each 100 ms, bits per second (0 unpaced). */
  level: number;
  made: number[];
  skipped: number[];
  refused: number[];
  keys: number[];
  steps: { at: number; level: number; change: LadderChange }[];
  voiceSent: number;
  voiceDropped: number;
}

const RECORD = 1280;
const bodies = new Map<number, Uint8Array>();
/** A frame body of about `bytes`: records of 1280 bytes, as wasm builds them. */
function bodyOf(bytes: number): Uint8Array {
  const n = Math.max(1, Math.ceil(bytes / RECORD));
  let body = bodies.get(n);
  if (!body) {
    body = new Uint8Array(n * (2 + RECORD));
    for (let i = 0; i < n; i++) {
      body[i * (2 + RECORD)] = RECORD >> 8;
      body[i * (2 + RECORD) + 1] = RECORD & 0xff;
    }
    bodies.set(n, body);
  }
  return body;
}

/** share.ts MAX_FRAME_BYTES */
const MAX_FRAME_BYTES = 255 * (1280 - 17 - 16);
/** share.ts UPLINK_STEP_HOLD_MS */
const UPLINK_STEP_HOLD_MS = 1000;

export async function simulate(o: SimOptions): Promise<SimState & { timeline: Timeline }> {
  const g = globalThis as any;
  clock = 0;
  workerClampMs = o.workerClampMs ?? 0;
  // Not node:test's mock: it keeps every call, and a long run makes millions
  const realNow = Object.getOwnPropertyDescriptor(performance, "now");
  Object.defineProperty(performance, "now", { value: () => clock, configurable: true, writable: true });
  const queue = new LinkQueue(o.link);
  live = queue;
  for (const w of FakeWorker.all) if (w.next !== Infinity) throw new Error("a worker of the run before still ticks");
  g.Worker = FakeWorker;
  g.location = { search: o.tcp ? "?transport=tcp" : "" };
  g.WebTransport = o.tcp ? undefined : SimWebTransport;
  g.WebSocket = SimSocket;
  g.fetch = async () => new Response(JSON.stringify({ port: 1, hash: "00".repeat(32), tcp: o.tcp }));
  const link = await connect("127.0.0.1", 1, { onControl() {}, onDatagram() {}, onVideoPacket() {}, onClosed() {} });
  await settle();

  const sh = o.share;
  const fps = sh.fps ?? 30;
  const startAt = o.startAt ?? 12_000;
  const s: SimState = { link, queue, level: START_LEVEL, made: [], skipped: [], refused: [], keys: [], steps: [], voiceSent: 0, voiceDropped: 0 };

  // share.ts state
  let encoding = false;
  let level = START_LEVEL;
  let levelChangedAt = 0;
  let lastChange: LadderChange = "start";
  let lossAt = 0;
  let sentSinceStart = true;
  let uplinkSeenAt = 0;
  let keyframeRequested = false;
  let lastKeyAt = -Infinity;
  let lastKeyForcedAt = -Infinity;
  let dropDeltasUntilKey = false;
  let dueUs = -Infinity;
  let haveFrame = false;
  let lastFrameEncoded = true;
  let lastArrivalAt = 0;
  let lastTs = 0;
  /** The encoder: chunks on their way out, [done at, key, level]. */
  const encoderQueue: [number, boolean, number][] = [];
  let encoderFree = 0;
  let tick: FakeWorker | null = null;
  let stamp = 1;
  let keepStamp = 1_000_000;
  let nextKeep = 0;
  let nextCapture = startAt;
  let nextVoice = sh.talkFrom ?? Infinity;
  const keyAsks = [...(sh.keyAsks ?? [])];

  const currentFps = () => Math.max(1, Math.round(fps / LEVELS[level][1]));
  const setLevel = (l: number, change: LadderChange) => {
    level = l;
    s.level = l;
    lastChange = change;
    levelChangedAt = clock;
    if (change === "start") sentSinceStart = false;
    s.steps.push({ at: clock, level: l, change });
  };
  // share.ts:539 wantKey
  const wantKey = () =>
    shouldForceKey(keyframeRequested, clock - Math.max(lastKeyAt, lastKeyForcedAt), clock - lastKeyForcedAt, link.videoBacklog());
  // share.ts:665 adapt
  const adapt = () => {
    const queuedAt = link.uplinkQueuedAt();
    if (queuedAt > uplinkSeenAt) {
      uplinkSeenAt = queuedAt;
      lossAt = Math.max(lossAt, queuedAt);
      const hold = lastChange === "start" ? 0 : UPLINK_STEP_HOLD_MS;
      if (level < LEVELS.length - 1 && clock - levelChangedAt >= hold) {
        setLevel(level + 1, "down");
        return;
      }
    }
    const lossAge = lossAt === 0 ? Number.MAX_SAFE_INTEGER : clock - lossAt;
    const since = lastChange === "start" && !sentSinceStart ? 0 : clock - levelChangedAt;
    const next = nextLevel(level, lossAge, since, lastChange);
    if (next === level) return;
    setLevel(next, next < level ? "up" : "down");
  };
  // share.ts:482 encode
  const encode = () => {
    adapt();
    // encoder.encodeQueueSize > 2
    if (encoderQueue.length > 2) return;
    if (link.videoQueuedMs() > PACE_GATE_MS) {
      s.skipped.push(clock);
      return;
    }
    const key = wantKey();
    lastFrameEncoded = true;
    if (key) {
      keyframeRequested = false;
      lastKeyForcedAt = clock;
    }
    encoderFree = Math.max(encoderFree, clock) + (sh.encodeMs?.(key) ?? (key ? 20 : 6));
    encoderQueue.push([encoderFree, key, level]);
  };
  // share.ts:729 onEncodedChunk
  const onChunk = (key: boolean, lvl: number) => {
    if (!encoding) return;
    if (dropDeltasUntilKey && !key) return;
    const bytes = sh.frameBytes(clock, key, lvl);
    if (bytes > MAX_FRAME_BYTES) {
      lossAt = clock;
      dropDeltasUntilKey = true;
      if (level < LEVELS.length - 1) setLevel(level + 1, "down");
      keyframeRequested = true;
      return;
    }
    const sent = link.sendVideoFrame(bodyOf(bytes), key);
    if (!sent) {
      s.refused.push(clock);
      lossAt = clock;
      dropDeltasUntilKey = true;
      keyframeRequested = true;
      return;
    }
    if (key) {
      lastKeyAt = clock;
      dropDeltasUntilKey = false;
      s.keys.push(clock);
    }
    if (!sentSinceStart) {
      sentSinceStart = true;
      if (lastChange === "start") levelChangedAt = clock;
    }
    s.made.push(clock);
  };
  // share.ts:463 onFrame
  const onFrame = (tsUs: number) => {
    haveFrame = true;
    lastFrameEncoded = false;
    lastArrivalAt = clock;
    lastTs = tsUs;
    const due = paceFrame(dueUs, tsUs, 1e6 / currentFps());
    if (due === null) return;
    dueUs = due;
    encode();
  };
  // share.ts:426 onTick, session.ts:643 uplinkTick
  const onTick = () => {
    if (!encoding) return;
    if (link.uplinkTick()) {
      const st = stamp++;
      tagged("ping", st, () => link.sendProbe(new Uint8Array(9), st));
    }
    const sinceArrival = clock - lastArrivalAt;
    if (!haveFrame || sinceArrival < 1000 / currentFps()) return;
    if (lastFrameEncoded && !wantKey()) return;
    encode();
  };
  // share.ts:281 startEncoding
  const startEncoding = () => {
    encoding = true;
    keyframeRequested = true;
    haveFrame = false;
    lastFrameEncoded = true;
    lastArrivalAt = 0;
    dueUs = -Infinity;
    lastKeyAt = -Infinity;
    lastKeyForcedAt = -Infinity;
    dropDeltasUntilKey = false;
    link.uplinkReset();
    uplinkSeenAt = 0;
    if (level <= START_LEVEL) setLevel(START_LEVEL, "start");
    else levelChangedAt = clock;
    tick = new FakeWorker();
    tick.onmessage = onTick;
    tick.postMessage({ type: "start", intervalMs: 1000 / fps });
  };

  const onPong = (st: number, keep: boolean, sentAt: number) => {
    // session.ts:943 onPong: the keepalive's round trip is whole ms of the wall clock
    void keep;
    link.uplinkPong(st, Math.round(clock - sentAt));
  };

  const timeline = new Timeline();
  const busyUntil = (t: number) => {
    for (const [a, b] of o.busy ?? []) if (t >= a && t < b) return b;
    return 0;
  };
  for (let t = 0; t <= o.ms; t++) {
    clock = t;
    const busy = busyUntil(t);
    // The link runs whatever the page does; what comes back waits for the page
    if (busy) {
      const held: [number, () => void][] = [];
      queue.step(t, (st, keep, at) => held.push([busy, () => onPong(st, keep, at)]));
      // Anything due back now is held to the end of the busy spell
      queue.back.push(...held);
      for (const b of queue.back) if (b[0] <= t) b[0] = busy;
      timeline.note(t, link, queue, s);
      continue;
    }
    let ran = false;
    const before = queue.back.length;
    queue.step(t, onPong);
    if (queue.back.length !== before) ran = true;
    if (!o.tcp && ran) await settle();
    if (t >= nextKeep) {
      nextKeep = t + (sh.keepaliveMs?.(t) ?? 10_000);
      tagged("keep", keepStamp++, () => link.sendDatagram(new Uint8Array(9)));
      ran = true;
    }
    if (t === startAt) startEncoding();
    while (keyAsks.length > 0 && keyAsks[0] <= t) {
      keyAsks.shift();
      keyframeRequested = true;
    }
    if (t >= nextVoice) {
      nextVoice += 20;
      s.voiceSent++;
      const had = queue.q.length;
      tagged("voice", 0, () => link.sendDatagram(new Uint8Array(80)));
      if (o.tcp && queue.q.length === had) s.voiceDropped++;
    }
    // The capture track: a frame per interval while the screen changes (MediaStreamTrackProcessor)
    if (encoding && t >= nextCapture) {
      nextCapture += 1000 / fps;
      if (sh.moving?.(t) ?? true) onFrame(Math.round((t - startAt) * 1000));
    }
    while (encoderQueue.length > 0 && encoderQueue[0][0] <= t) {
      const [, key, lvl] = encoderQueue.shift()!;
      onChunk(key, lvl);
      ran = true;
    }
    for (const w of [...FakeWorker.all]) if (w.run()) ran = true;
    if (!o.tcp && ran) await settle();
    timeline.note(t, link, queue, s);
    o.each?.(t, s);
  }
  void lastTs;
  await link.close();
  tick && (tick as FakeWorker).terminate();
  // The pace clock is the module's own and outlives this link: one last tick, whatever the time,
  // lets it see the link closed and stop, so the next run starts it afresh
  for (const w of [...FakeWorker.all]) w.onmessage?.(0);
  if (realNow) Object.defineProperty(performance, "now", realNow);
  else delete (performance as any).now;
  return { ...s, timeline };
}

/** What the share did, in buckets of 100 ms. */
export class Timeline {
  /** The pacer's rate is not readable from outside: paced is told by `videoQueuedMs` and finds. */
  readonly backlogMs: number[] = [];
  readonly queuedMs: number[] = [];
  /** Video handed to the link in each bucket, as bits per second. */
  readonly handedBps: number[] = [];
  private handedBefore = 0;
  private worst = 0;
  private worstQ = 0;
  note(t: number, link: Transport, queue: LinkQueue, _s: SimState) {
    this.worst = Math.max(this.worst, queue.backlogMs(t));
    this.worstQ = Math.max(this.worstQ, link.videoQueuedMs());
    if (t % 100 === 99) {
      this.backlogMs.push(Math.round(this.worst));
      this.queuedMs.push(Math.round(this.worstQ));
      this.handedBps.push(Math.round((queue.handed - this.handedBefore) * 80));
      this.handedBefore = queue.handed;
      this.worst = 0;
      this.worstQ = 0;
    }
  }
}

/** Frames made per second over [from, to). */
export function fpsIn(made: number[], from: number, to: number): number {
  return (made.filter((t) => t >= from && t < to).length * 1000) / (to - from);
}
