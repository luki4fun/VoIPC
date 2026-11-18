// How long the link waits for a server gone quiet, on both carriers, and a viewer's link
// to a media edge. A stand-in for each: the browsers themselves run in test-provider.mjs,
// and through an edge in test-web.sh EDGE=1.

import { afterEach, beforeEach, mock, test } from "node:test";
import assert from "node:assert/strict";
import { connect, openEdgeView, type EdgeViewCodec, type Transport } from "./transport.ts";

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
