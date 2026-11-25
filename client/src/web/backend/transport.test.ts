// How long the link waits for a server gone quiet, on both carriers, and a viewer's link
// to a media edge. A stand-in for each: the browsers themselves run in test-provider.mjs,
// and through an edge in test-web.sh EDGE=1.

import { afterEach, beforeEach, mock, test } from "node:test";
import assert from "node:assert/strict";
import { connect, openEdgeView, type EdgeViewCodec, type Transport } from "./transport.ts";
import { CUT_FACTOR, PACE_GATE_MS, PROBE_LOST_MS } from "../../lib/video-pacer.ts";

const USUAL = 150_000;

/** One empty control frame from the server. */
const FRAME = new Uint8Array(4);

class FakeSocket {
  static last: FakeSocket;
  binaryType = "";
  bufferedAmount = 0;
  onopen: (() => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onmessage: ((ev: { data: ArrayBuffer }) => void) | null = null;
  constructor() {
    FakeSocket.last = this;
    queueMicrotask(() => this.onopen?.());
  }
  send() {}
  close() {}
}

class FakeWebTransport {
  static last: FakeWebTransport;
  control!: ReadableStreamDefaultController<Uint8Array>;
  ready = Promise.resolve();
  closed = new Promise<void>(() => {});
  datagrams = { readable: new ReadableStream(), writable: new WritableStream() };
  incomingUnidirectionalStreams = new ReadableStream();
  constructor() {
    FakeWebTransport.last = this;
  }
  close() {}
  async createBidirectionalStream() {
    const readable = new ReadableStream<Uint8Array>({ start: (c) => void (this.control = c) });
    return { readable, writable: new WritableStream() };
  }
}

test("WebTransport: a control frame counts until the stream has taken it", async () => {
  let release = () => {};
  const held = new Promise<void>((r) => void (release = r));
  const realWire = FakeWebTransport.prototype.createBidirectionalStream;
  FakeWebTransport.prototype.createBidirectionalStream = async function () {
    const { readable } = await realWire.call(this);
    return { readable, writable: new WritableStream({ write: () => held }) };
  };
  try {
    const { link } = await open({ WebTransport: FakeWebTransport, search: "", tcp: false });
    assert.equal(link.controlBacklog(), 0);
    link.sendControl(new Uint8Array(1));
    assert.equal(link.controlBacklog(), 1);
    release();
    await settle();
    assert.equal(link.controlBacklog(), 0);
  } finally {
    FakeWebTransport.prototype.createBidirectionalStream = realWire;
  }
});

test("the TCP fallback: a control frame's backlog is what voice would not go behind", async () => {
  const { link } = await open({ WebTransport: undefined, search: "?transport=tcp", tcp: true });
  FakeSocket.last.bufferedAmount = 64 * 1024;
  assert.equal(link.controlBacklog(), 0, "video and voice share this queue, and it may never be empty");
  FakeSocket.last.bufferedAmount = 64 * 1024 + 1;
  assert.equal(link.controlBacklog(), 1);
});

/** A frame body of `n` records of 1200 bytes, each filled with `fill`. */
function frameOf(n: number, fill = 0): Uint8Array {
  const record = [1200 >> 8, 1200 & 0xff, ...new Array(1200).fill(fill)];
  return Uint8Array.from(Array.from({ length: n }, () => record).flat());
}

/** WebTransport's video streams, held: what each was written, and its close to answer (the ack). */
function holdStreams() {
  const written: number[][] = [];
  const writes: number[] = [];
  const acks: (() => void)[] = [];
  (FakeWebTransport.prototype as any).createUnidirectionalStream = async function () {
    const frame = written.length;
    written.push([]);
    writes.push(0);
    return new WritableStream<Uint8Array>({
      write: (chunk) => {
        written[frame].push(...chunk);
        writes[frame]++;
      },
      close: () => new Promise<void>((r) => void (acks[frame] = r)),
    });
  };
  return { written, writes, acks, done: () => delete (FakeWebTransport.prototype as any).createUnidirectionalStream };
}

test("WebTransport: while the link shows no queue a frame goes out at once, whole, in one write", async () => {
  const streams = holdStreams();
  try {
    const { link } = await open({ WebTransport: FakeWebTransport, search: "", tcp: false });
    link.uplinkPong(1, 40);
    const big = frameOf(90, 3);
    assert.ok(link.sendVideoFrame(big, true));
    assert.ok(link.sendVideoFrame(frameOf(1, 7), false));
    assert.equal(link.videoQueuedMs(), 0, "nothing waits: unpaced");
    for (let i = 0; i < 5; i++) await settle();
    assert.deepEqual(streams.writes, [1, 1]);
    assert.deepEqual(streams.written[0], [...big]);
    assert.equal(link.videoBacklog(), 2, "in flight until acked");
    streams.acks.forEach((ack) => ack());
    for (let i = 0; i < 5; i++) await settle();
    assert.equal(link.videoBacklog(), 0);
    assert.equal(link.uplinkQueuedAt(), 0);
  } finally {
    streams.done();
  }
});

test("WebTransport: frames acked late one after another pace what follows; a big frame then goes in slices, in order, whole", async () => {
  let clock = 10_000;
  const now = mock.method(performance, "now", () => clock);
  const streams = holdStreams();
  try {
    const { link } = await open({ WebTransport: FakeWebTransport, search: "", tcp: false });
    link.uplinkPong(1, 40); // the keepalive, nothing shared yet: the link's least
    // Frames of 12 KB at 30 fps, each acked 200 ms after it went: a queue
    for (let i = 0; i < 20 && link.uplinkQueuedAt() === 0; i++) {
      assert.ok(link.sendVideoFrame(frameOf(10, i), i === 0));
      for (let k = 0; k < 3; k++) await settle();
      clock += 33;
      const due = i - 6; // the frame sent 200 ms ago
      if (due >= 0) {
        streams.acks[due]();
        for (let k = 0; k < 3; k++) await settle();
      }
    }
    assert.ok(link.uplinkQueuedAt() > 0, "the queue was found");
    const [[, delivered, paced]] = link.uplinkFinds();
    assert.ok(delivered > 2_000_000 && delivered < 4_000_000, `delivered ${delivered} bps`);
    assert.ok(Math.abs(paced - delivered * 0.85) < 2, "paced at 0.85 of it once drained");
    // Paced now: a 108 KB frame waits for the pacer and goes in more than one write
    const first = streams.written.length;
    const big = frameOf(90, 5);
    assert.ok(link.sendVideoFrame(big, true));
    assert.ok(link.sendVideoFrame(frameOf(2, 9), false));
    assert.ok(link.videoQueuedMs() > 100, `${link.videoQueuedMs()} ms wait`);
    for (let k = 0; k < 400 && link.videoQueuedMs() > 0; k++) {
      clock += 10;
      link.uplinkTick();
      await settle();
    }
    for (let k = 0; k < 5; k++) await settle();
    assert.equal(link.videoQueuedMs(), 0);
    assert.deepEqual(streams.written[first], [...big], "whole, in order");
    assert.deepEqual(streams.written[first + 1], [...frameOf(2, 9)]);
    assert.ok(streams.writes[first] >= 2, `in ${streams.writes[first]} slices`);
    streams.acks.forEach((ack) => ack());
    for (let k = 0; k < 5; k++) await settle();
  } finally {
    streams.done();
    now.mock.restore();
  }
});

test("the TCP fallback: a delta goes while the socket's own backlog is 64 KiB at most, a keyframe 512 KiB", async () => {
  const { link } = await open({ WebTransport: undefined, search: "?transport=tcp", tcp: true });
  FakeSocket.last.bufferedAmount = 64 * 1024;
  assert.ok(link.sendVideoFrame(frameOf(60), false), "60 records go, nothing else is counted");
  assert.ok(link.sendVideoFrame(frameOf(60), false), "...and the next: the socket's backlog is what counts");
  FakeSocket.last.bufferedAmount = 64 * 1024 + 1;
  assert.ok(!link.sendVideoFrame(frameOf(1), false));
  assert.ok(link.sendVideoFrame(frameOf(1), true));
  FakeSocket.last.bufferedAmount = 512 * 1024 + 1;
  assert.ok(!link.sendVideoFrame(frameOf(1), true));
});

test("the TCP fallback: while video goes out a ping times the socket; behind a link at its limit its pongs measure it, and a queue paces video at that rate", async () => {
  let clock = 10_000;
  const now = mock.method(performance, "now", () => clock);
  try {
    const { link } = await open({ WebTransport: undefined, search: "?transport=tcp", tcp: true });
    const sent: Uint8Array[] = [];
    FakeSocket.last.send = (b: Uint8Array) => void sent.push(b);
    link.uplinkPong(1, 2); // the keepalive with nothing shared: 2 ms
    assert.equal(link.uplinkTick(), false, "no video, no ping");
    assert.ok(link.sendVideoFrame(frameOf(5), true));
    assert.equal(link.uplinkTick(), true, "a ping is due");
    // It goes even past the backlog sendDatagram drops voice behind
    FakeSocket.last.bufferedAmount = 200_000;
    link.sendProbe(Uint8Array.of(3, 0, 0, 0, 1, 0, 0, 0, 7), 7);
    assert.deepEqual([...sent[sent.length - 1]], [3, 0, 0, 0, 1, 0, 0, 0, 7]);
    FakeSocket.last.bufferedAmount = 0;
    assert.equal(link.uplinkTick(), false, "not again within PROBE_EVERY_MS");
    clock += 5;
    assert.equal(link.uplinkPong(7, 5), true, "its Pong is the probe's, not the latency shown");
    assert.equal(link.uplinkQueuedAt(), 0);
    // Then a link that carries 1 Mbit/s, one queue in send order, 1 ms each way: a ping's pong
    // comes once all before it crossed. Video every 33 ms (1.45 Mbit/s) while the sharer's gate
    // lets it, a ping whenever one is due
    let linkDone = clock;
    let ping = -1;
    const pongs: [number, number][] = [];
    FakeSocket.last.send = (b: Uint8Array) => {
      linkDone = Math.max(linkDone, clock) + (b.length * 8000) / 1_000_000;
      if (ping >= 0) pongs.push([linkDone + 2, ping]);
      ping = -1;
    };
    let stamp = 100;
    let gated = 0;
    for (let t = 0; t < 8_000 && link.uplinkQueuedAt() === 0; t++) {
      clock++;
      while (pongs.length > 0 && pongs[0][0] <= clock) link.uplinkPong(pongs.shift()![1], 0);
      if (t % 33 !== 0) continue;
      if (link.videoQueuedMs() > PACE_GATE_MS) gated++;
      else link.sendVideoFrame(frameOf(5), false);
      if (link.uplinkTick()) {
        ping = stamp;
        link.sendProbe(Uint8Array.of(3), stamp++);
      }
    }
    assert.ok(link.uplinkQueuedAt() > 0, "found");
    assert.ok(gated > 0, "the gate held the encoder before");
    const [, delivered, paced] = link.uplinkFinds()[0];
    assert.ok(Math.abs(delivered / 1_000_000 - 1) < 0.1, `delivered ${delivered}`);
    assert.ok(Math.abs(paced / (CUT_FACTOR * 1_000_000) - 1) < 0.1, `paced at ${paced}`);
    // Paced: a big frame waits for the pacer
    assert.ok(link.sendVideoFrame(frameOf(60), true));
    assert.ok(link.videoQueuedMs() > 0);
    for (let k = 0; k < 2000 && link.videoQueuedMs() > 0; k++) {
      clock += 10;
      while (pongs.length > 0 && pongs[0][0] <= clock) link.uplinkPong(pongs.shift()![1], 0);
      link.uplinkTick();
    }
    assert.equal(link.videoQueuedMs(), 0);
  } finally {
    now.mock.restore();
  }
});

test("the TCP fallback: video waiting in the socket ahead of a ping holds the sharer's gate, before any rate is found", async () => {
  let clock = 10_000;
  const now = mock.method(performance, "now", () => clock);
  try {
    const { link } = await open({ WebTransport: undefined, search: "?transport=tcp", tcp: true });
    link.uplinkPong(1, 20); // the keepalive: the link's least is 20 ms
    // A share's first keyframe, 240 KB, all of it in the socket at once, and a ping behind it
    link.uplinkReset();
    assert.ok(link.sendVideoFrame(frameOf(200), true));
    assert.equal(link.uplinkTick(), true);
    link.sendProbe(Uint8Array.of(3), 50);
    clock += 100;
    assert.equal(link.videoQueuedMs(), 80, "out 100 ms: 80 past the least");
    assert.ok(link.videoQueuedMs() <= PACE_GATE_MS, "a frame may go");
    clock += 50;
    assert.ok(link.videoQueuedMs() > PACE_GATE_MS, "out 150 ms: the encoder waits");
    assert.equal(link.uplinkQueuedAt(), 0, "and nothing is found: nothing measured the link");
    // Its pong: nothing waits ahead of a ping any more
    link.uplinkPong(50, 0);
    assert.equal(link.videoQueuedMs(), 0);
    // A ping the relay dropped holds it no longer than PROBE_LOST_MS
    assert.ok(link.sendVideoFrame(frameOf(5), false));
    clock += 400;
    link.sendProbe(Uint8Array.of(3), 51);
    clock += PROBE_LOST_MS - 1;
    assert.ok(link.videoQueuedMs() > PACE_GATE_MS);
    clock += 1;
    assert.equal(link.videoQueuedMs(), 0);
    // Nor does one from before a new share's video started
    link.sendProbe(Uint8Array.of(3), 52);
    clock += 500;
    link.uplinkReset();
    assert.equal(link.videoQueuedMs(), 0);
  } finally {
    now.mock.restore();
  }
});

test("the TCP fallback: a ping whose pong never came times nothing past PROBE_LOST_MS, nor once a new share's video starts", async () => {
  let clock = 10_000;
  const now = mock.method(performance, "now", () => clock);
  try {
    const { link } = await open({ WebTransport: undefined, search: "?transport=tcp", tcp: true });
    link.uplinkPong(1, 2);
    let stamp = 100;
    const ping = (answered: boolean) => {
      const s = stamp++;
      link.sendProbe(Uint8Array.of(3), s);
      if (answered) link.uplinkPong(s, 1);
    };
    // 6 s of video, each ping answered at once
    for (let k = 0; k < 180; k++) {
      clock += 33;
      link.sendVideoFrame(frameOf(5), false);
      if (link.uplinkTick()) ping(true);
    }
    assert.equal(link.uplinkQueuedAt(), 0);
    // Two pings the relay dropped, then a still screen: no frames, the sharer's tick goes on
    for (let sent = 0; sent < 2; ) {
      clock += 33;
      link.sendVideoFrame(frameOf(5), false);
      if (link.uplinkTick()) (ping(false), sent++);
    }
    for (let k = 0; k < 300; k++) {
      clock += 33;
      link.uplinkTick();
    }
    // Found once they were out past the threshold, and once more paced after the drain; then
    // they are PROBE_LOST_MS old and time nothing (round 2 found again every second)
    assert.ok(link.uplinkFinds().length <= 2, `${link.uplinkFinds().length} finds over 10 s of a still screen`);
    // Two more dropped just before a new share's video starts: its link is judged afresh
    for (let sent = 0; sent < 2; ) {
      clock += 33;
      link.sendVideoFrame(frameOf(5), false);
      if (link.uplinkTick()) (ping(false), sent++);
    }
    clock += 200;
    link.uplinkReset();
    for (let k = 0; k < 30; k++) {
      clock += 33;
      link.sendVideoFrame(frameOf(5), false);
      if (link.uplinkTick()) ping(true);
    }
    assert.equal(link.uplinkQueuedAt(), 0, "nothing from before the share");
  } finally {
    now.mock.restore();
  }
});

const carriers = [
  {
    name: "WebTransport",
    wire: { WebTransport: FakeWebTransport, search: "", tcp: false },
    says: () => FakeWebTransport.last.control.enqueue(FRAME),
  },
  {
    name: "the TCP fallback",
    wire: { WebTransport: undefined, search: "?transport=tcp", tcp: true },
    says: () => FakeSocket.last.onmessage?.({ data: new Uint8Array([0, ...FRAME]).buffer }),
  },
];

/** Lets the stream readers run: the timers are mocked, this is not one of them. */
const settle = () => new Promise((r) => setImmediate(r));

async function open(wire: (typeof carriers)[number]["wire"]): Promise<{ link: Transport; closed: () => string | null }> {
  const g = globalThis as any;
  g.location = { search: wire.search };
  g.WebTransport = wire.WebTransport;
  g.WebSocket = FakeSocket;
  g.fetch = async () => new Response(JSON.stringify({ port: 1, hash: "00".repeat(32), tcp: wire.tcp }));
  let reason: string | null = null;
  const link = await connect("127.0.0.1", 1, {
    onControl: () => {},
    onDatagram: () => {},
    onVideoPacket: () => {},
    onClosed: (r) => void (reason = r),
  });
  await settle();
  return { link, closed: () => reason };
}

beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
afterEach(() => mock.timers.reset());

for (const { name, wire, says } of carriers) {
  test(`${name}: a server gone quiet ends the link after the usual bound`, async () => {
    const { closed } = await open(wire);
    mock.timers.tick(USUAL - 1);
    assert.equal(closed(), null);
    mock.timers.tick(1);
    assert.match(closed() ?? "", /no data from server/);
  });

  test(`${name}: a person's wait holds the link for that long, and no longer`, async () => {
    const { link, closed } = await open(wire);
    link.allowQuiet(291_000);
    mock.timers.tick(291_000 - 1);
    assert.equal(closed(), null, "the sign-in promised a person this long");
    mock.timers.tick(1);
    assert.match(closed() ?? "", /no data from server/);
  });

  test(`${name}: each wait counts from when it starts, not from the server's last word`, async () => {
    const { link, closed } = await open(wire);
    link.allowQuiet(291_000);
    // 100 s at the choice, and then the relay's own two minutes at the other device
    mock.timers.tick(100_000);
    link.allowQuiet(151_000);
    mock.timers.tick(151_000 - 1);
    assert.equal(closed(), null);
    mock.timers.tick(1);
    assert.match(closed() ?? "", /no data from server/);
  });

  test(`${name}: what the server says in a wait leaves the wait as long`, async () => {
    const { link, closed } = await open(wire);
    link.allowQuiet(291_000);
    mock.timers.tick(10_000);
    says();
    await settle();
    mock.timers.tick(291_000 - 1);
    assert.equal(closed(), null);
    mock.timers.tick(1);
    assert.match(closed() ?? "", /no data from server/);
  });

  test(`${name}: past the sign-in the usual bound is back, whatever the last wait was`, async () => {
    const { link, closed } = await open(wire);
    link.allowQuiet(291_000);
    link.allowQuiet(0);
    mock.timers.tick(USUAL - 1);
    assert.equal(closed(), null);
    mock.timers.tick(1);
    assert.match(closed() ?? "", /no data from server/);
  });

  test(`${name}: a wait on a closed link starts nothing`, async () => {
    const { link, closed } = await open(wire);
    const closing = link.close();
    mock.timers.tick(500);
    await closing;
    link.allowQuiet(291_000);
    mock.timers.tick(291_000);
    assert.equal(closed(), null, "close() does not report itself");
  });
}

// ── The edge link (protocol 26) ──────────────────────────────────────────────

/**
 * `ViewerMsg::Hello { ticket: [1, 2, 3] }` with its length prefix, as golden.rs pins it
 * (`what_says_wrong_pool_version_never_changes`). The app has it from wasm, whose bytes
 * voipc-web's `a_viewer_hello_from_wasm_is_the_native_one` holds to the native ones:
 * here it is what the stand-in codec gives, and what must go out unchanged.
 */
const FROZEN_HELLO = "000000050003010203";
/** `EdgeViewMsg::Ready`, framed. */
const READY = "0000000100";

const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** `EdgeViewMsg::Ended { reason }`, framed. */
const ended = (reason: string) => {
  const text = new TextEncoder().encode(reason);
  const body = Uint8Array.of(1, text.length, ...text);
  return Uint8Array.of(0, 0, 0, body.length, ...body);
};

class FakeEdge {
  static last: FakeEdge;
  url: string;
  options: { serverCertificateHashes: { algorithm: string; value: Uint8Array }[] };
  answer!: ReadableStreamDefaultController<Uint8Array>;
  datagramsIn!: ReadableStreamDefaultController<Uint8Array>;
  streamsIn!: ReadableStreamDefaultController<ReadableStream<Uint8Array>>;
  written: string[] = [];
  closedByApp = false;
  ready: Promise<void> = Promise.resolve();
  end = () => {};
  closed = new Promise<void>((r) => void (this.end = r));
  datagrams = {
    readable: new ReadableStream<Uint8Array>({ start: (c) => void (this.datagramsIn = c) }),
    writable: new WritableStream(),
  };
  incomingUnidirectionalStreams = new ReadableStream<ReadableStream<Uint8Array>>({
    start: (c) => void (this.streamsIn = c),
  });
  constructor(url: string, options: FakeEdge["options"]) {
    FakeEdge.last = this;
    this.url = url;
    this.options = options;
  }
  close() {
    this.closedByApp = true;
  }
  async createBidirectionalStream() {
    const readable = new ReadableStream<Uint8Array>({ start: (c) => void (this.answer = c) });
    const writable = new WritableStream<Uint8Array>({ write: (chunk) => void this.written.push(toHex(chunk)) });
    return { readable, writable };
  }
}

/** Stands in for wasm's pool codec, and writes down what it was given. */
function standInCodec() {
  const tickets: number[][] = [];
  const decoded: string[] = [];
  const codec: EdgeViewCodec = {
    encodeViewerHello: (ticket) => {
      tickets.push([...ticket]);
      return fromHex(FROZEN_HELLO);
    },
    decodeEdgeViewMsg: (bytes) => {
      decoded.push(toHex(bytes));
      if (bytes.length === 1 && bytes[0] === 0) return "Ready";
      if (bytes[0] === 1) return { Ended: { reason: new TextDecoder().decode(bytes.subarray(2, 2 + bytes[1])) } };
      throw new Error("not an EdgeViewMsg");
    },
  };
  return { codec, tickets, decoded };
}

/** An edge view opening against a FakeEdge, and what its handlers were told. */
async function openEdge(host = "edge-1.example.org", ready?: Promise<void>) {
  const g = globalThis as any;
  g.WebTransport = class extends FakeEdge {
    ready = ready ?? Promise.resolve();
  };
  const told = { video: [] as string[], audio: [] as string[], closed: [] as string[] };
  const stand = standInCodec();
  let outcome: "open" | Error | null = null;
  const opening = openEdgeView(
    host,
    9991,
    [Array(32).fill(0xab), new Uint8Array(32).fill(0xcd)],
    [1, 2, 3],
    {
      onVideoPacket: (b) => void told.video.push(toHex(b)),
      onDatagram: (b) => void told.audio.push(toHex(b)),
      onClosed: (r) => void told.closed.push(r),
    },
    stand.codec,
  );
  opening.then(
    () => void (outcome = "open"),
    (e) => void (outcome = e),
  );
  await settle();
  return { opening, told, ...stand, edge: () => FakeEdge.last, outcome: () => outcome };
}

test("an edge view writes the frozen ViewerHello bytes, and is open at the edge's Ready", async () => {
  const t = await openEdge("2001:db8::7");
  const edge = t.edge();
  assert.equal(edge.url, "https://[2001:db8::7]:9991/voipc-view", "an IPv6 host goes in brackets");
  assert.deepEqual(
    edge.options.serverCertificateHashes.map((h) => [h.algorithm, toHex(h.value)]),
    [
      ["sha-256", "ab".repeat(32)],
      ["sha-256", "cd".repeat(32)],
    ],
    "trusting only the edge's certificates",
  );
  assert.deepEqual(t.tickets, [[1, 2, 3]]);
  assert.deepEqual(edge.written, [FROZEN_HELLO], "the hello as wasm built it: no second prefix, nothing else");
  assert.equal(t.outcome(), null, "not open before the Ready");
  edge.answer.enqueue(fromHex(READY));
  await settle();
  assert.equal(t.outcome(), "open");
  assert.deepEqual(t.decoded, ["00"], "the edge's answer reaches wasm without its prefix");
  assert.equal(edge.closedByApp, false);
});

test("an edge that answers Ended instead of Ready refuses the view", async () => {
  const t = await openEdge();
  t.edge().answer.enqueue(ended("ticket refused"));
  await settle();
  assert.match(String(t.outcome()), /ticket refused/);
  assert.equal(t.edge().closedByApp, true);
  assert.deepEqual(t.told.closed, [], "a refused view was never open, so it does not end");
});

test("each step of an edge connect has 5 s", async () => {
  // The handshake
  const slow = await openEdge("edge-1.example.org", new Promise(() => {}));
  mock.timers.tick(5_000 - 1);
  await settle();
  assert.equal(slow.outcome(), null);
  mock.timers.tick(1);
  await settle();
  assert.match(String(slow.outcome()), /handshake/);

  // The hello's Ready
  const quiet = await openEdge();
  mock.timers.tick(5_000 - 1);
  await settle();
  assert.equal(quiet.outcome(), null);
  mock.timers.tick(1);
  await settle();
  assert.match(String(quiet.outcome()), /Ready/);
  assert.equal(quiet.edge().closedByApp, true);
  // A Ready after that opens nothing
  quiet.edge().answer.enqueue(fromHex(READY));
  await settle();
  assert.match(String(quiet.outcome()), /Ready/);
});

test("past its Ready the edge's records and screen audio come through, and its end is told once", async () => {
  const t = await openEdge();
  const edge = t.edge();
  edge.answer.enqueue(fromHex(READY));
  await settle();
  // One frame's stream: [u16 length][packet] records, as from the relay
  edge.streamsIn.enqueue(
    new ReadableStream({
      start: (c) => {
        c.enqueue(Uint8Array.of(0, 3, 0x13, 1, 2, 0, 2, 0x14, 9));
        c.close();
      },
    }),
  );
  edge.datagramsIn.enqueue(Uint8Array.of(0x15, 7));
  await settle();
  assert.deepEqual(t.told.video, ["130102", "1409"]);
  assert.deepEqual(t.told.audio, ["1507"]);
  edge.answer.enqueue(ended("share ended"));
  await settle();
  edge.end();
  await settle();
  assert.equal(t.told.closed.length, 1);
  assert.match(t.told.closed[0], /share ended/);
  assert.equal(edge.closedByApp, true);
});

test("an edge view the app closes reports nothing", async () => {
  const t = await openEdge();
  t.edge().answer.enqueue(fromHex(READY));
  await settle();
  const link = await t.opening;
  link.close();
  assert.equal(t.edge().closedByApp, true);
  t.edge().end();
  await settle();
  assert.deepEqual(t.told.closed, []);
});
