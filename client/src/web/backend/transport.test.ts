// How long the link waits for a server gone quiet, on both carriers. A stand-in for each:
// the browsers themselves run in test-provider.mjs.

import { afterEach, beforeEach, mock, test } from "node:test";
import assert from "node:assert/strict";
import { connect, type Transport } from "./transport.ts";

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
