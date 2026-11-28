// The browser viewer's edge link on a clock the test turns: when it connects, what of
// it reaches the viewer, and when it tells the relay the edge failed. The link itself
// is a stand-in (transport.test.ts has openEdgeView); test-web.sh EDGE=1 runs it all.

import { test } from "node:test";
import assert from "node:assert/strict";
import { EDGE_CONNECT_SPACING_MS, EDGE_ENDED_GRACE_MS, EdgeView, type Clock, type EdgeViewEvent } from "./edge-view.ts";
import { EDGE_SILENT_MS, type EdgeTarget } from "../../lib/share-rules.ts";
import type { EdgeViewHandlers } from "./transport.ts";

const ALICE = 7;

class FakeClock implements Clock {
  private t = 0;
  private next = 1;
  private readonly timers = new Map<number, { at: number; fn: () => void }>();
  now = () => this.t;
  setTimeout = (fn: () => void, ms: number) => {
    const id = this.next++;
    this.timers.set(id, { at: this.t + ms, fn });
    return id;
  };
  clearTimeout = (id: unknown) => void this.timers.delete(id as number);
  /** Runs every timer due within `ms`, each at its own time. */
  tick(ms: number): void {
    const end = this.t + ms;
    for (;;) {
      let due: [number, { at: number; fn: () => void }] | undefined;
      for (const entry of this.timers) if (entry[1].at <= end && (!due || entry[1].at < due[1].at)) due = entry;
      if (!due) break;
      this.timers.delete(due[0]);
      this.t = due[1].at;
      due[1].fn();
    }
    this.t = end;
  }
}

/** One connect the view started: its target, its handlers, and how it ends. */
interface Opened {
  view: EdgeTarget;
  handlers: EdgeViewHandlers;
  ready(): Promise<void>;
  refuse(why: string): Promise<void>;
  closed: boolean;
}

/** An edge view over a fake clock and a stand-in session that writes down what it was asked. */
function setup(opts: { tunnel?: boolean } = {}) {
  const clock = new FakeClock();
  const opened: Opened[] = [];
  const failed: [number, bigint | number, number][] = [];
  const video: Uint8Array[] = [];
  const audio: Uint8Array[] = [];
  const states: EdgeViewEvent[] = [];
  /** Whether the next record completes a frame that decrypts. */
  let completes = true;
  const view = new EdgeView(
    {
      open: (target, handlers) =>
        new Promise((resolve, reject) => {
          const o: Opened = {
            view: target,
            handlers,
            closed: false,
            ready: async () => {
              resolve({ close: () => void (o.closed = true) });
              await settle();
            },
            refuse: async (why) => {
              reject(new Error(why));
              await settle();
            },
          };
          opened.push(o);
        }),
      edgeFailed: (sharer, placement) => void failed.push([sharer, placement, clock.now()]),
      video: (bytes) => (video.push(bytes), completes),
      datagram: (bytes) => void audio.push(bytes),
      tunnel: () => opts.tunnel ?? false,
      state: (e) => void states.push(e),
    },
    clock,
  );
  return {
    clock,
    view,
    opened,
    failed,
    video,
    audio,
    states,
    completeFrames: (on: boolean) => void (completes = on),
  };
}

const settle = () => new Promise((r) => setImmediate(r));

const target = (host = "edge-1.example.org"): EdgeTarget => ({
  host,
  port: 9991,
  cert_hashes: [Array(32).fill(1)],
  ticket: [1, 2, 3],
});

/** A packet of `type` from `sender`, as the relay and its edges carry them. */
const packet = (type: number, sender = ALICE) => Uint8Array.of(type, sender >>> 24, (sender >>> 16) & 255, (sender >>> 8) & 255, sender & 255, 9, 9);

/** On an edge that said Ready, at the clock's start. */
async function onEdge() {
  const t = setup();
  t.view.watchAt(ALICE, 1n, target());
  await t.opened[0].ready();
  return t;
}

test("silent 10 s leads to EdgeFailed once, again after 10 s more", async () => {
  const t = await onEdge();
  t.clock.tick(EDGE_SILENT_MS - 1);
  assert.deepEqual(t.failed, []);
  t.clock.tick(1);
  assert.deepEqual(t.failed, [[ALICE, 1n, EDGE_SILENT_MS]], "the placement of the WatchAt in force");
  // The relay ignores it (the share itself is silent): once more 10 s later, no sooner
  t.clock.tick(EDGE_SILENT_MS - 1);
  assert.equal(t.failed.length, 1);
  t.clock.tick(1);
  assert.deepEqual(t.failed.at(-1), [ALICE, 1n, 2 * EDGE_SILENT_MS]);
  assert.ok(t.states.some((s) => s.state === "failed"));
});

test("a whole decrypted frame keeps a working edge quiet", async () => {
  const t = await onEdge();
  // A keyframe every 4 s, as a still screen sends
  for (let s = 0; s < 60; s += 4) {
    t.clock.tick(4_000);
    t.opened[0].handlers.onVideoPacket(packet(0x13));
  }
  assert.deepEqual(t.failed, []);
  assert.equal(t.video.length, 15);
});

test("records that make no frame do not keep it quiet", async () => {
  const t = await onEdge();
  t.completeFrames(false);
  for (let s = 0; s < 10; s++) {
    t.opened[0].handlers.onVideoPacket(packet(0x14));
    t.clock.tick(1_000);
  }
  assert.equal(t.video.length, 10, "they still go to the viewer");
  assert.equal(t.failed.length, 1, "an edge forwarding garbage, or fragments that never complete, trips it");
});

test("datagrams alone do not keep it quiet", async () => {
  const t = await onEdge();
  for (let s = 0; s < 10; s++) {
    t.opened[0].handlers.onDatagram(packet(0x15));
    t.clock.tick(1_000);
  }
  assert.equal(t.audio.length, 10, "the screen audio plays meanwhile");
  assert.equal(t.failed.length, 1);
});

test("only the watched sharer's video and screen audio pass", async () => {
  const t = await onEdge();
  const h = t.opened[0].handlers;
  h.onVideoPacket(packet(0x13, ALICE + 1));
  h.onVideoPacket(packet(0x05));
  h.onVideoPacket(Uint8Array.of(0x13, 0, 0));
  h.onDatagram(packet(0x05));
  h.onDatagram(packet(0x02));
  h.onDatagram(packet(0x15, ALICE + 1));
  assert.deepEqual([t.video.length, t.audio.length], [0, 0]);
  h.onVideoPacket(packet(0x13));
  h.onVideoPacket(packet(0x14));
  h.onDatagram(packet(0x15));
  assert.deepEqual([t.video.length, t.audio.length], [2, 1]);
});

test("an Ended without a core word leads to EdgeFailed after 5 s", async () => {
  const t = await onEdge();
  t.clock.tick(2_000);
  t.opened[0].handlers.onClosed("The edge ended the view: core lost");
  t.clock.tick(EDGE_ENDED_GRACE_MS - 1);
  assert.deepEqual(t.failed, [], "the relay usually moves us first");
  t.clock.tick(1);
  assert.deepEqual(t.failed, [[ALICE, 1n, 2_000 + EDGE_ENDED_GRACE_MS]]);
  // Still no word: again every 10 s
  t.clock.tick(EDGE_SILENT_MS);
  assert.equal(t.failed.length, 2);
  assert.deepEqual(
    t.states.map((s) => s.state),
    ["connecting", "ready", "closed", "failed", "failed"],
  );
});

test("a WatchAt or a stop within the 5 s after an Ended says nothing", async () => {
  for (const word of ["move", "stop"]) {
    const t = await onEdge();
    t.opened[0].handlers.onClosed("The edge ended the view: revoked");
    t.clock.tick(EDGE_ENDED_GRACE_MS - 1);
    if (word === "move") t.view.watchAt(ALICE, 2n, target("edge-2.example.org"));
    else t.view.close();
    t.clock.tick(60_000);
    assert.deepEqual(t.failed.filter(([, p]) => p === 1n), [], word);
  }
});

test("a WatchAt within 5 s waits", async () => {
  const t = setup();
  t.view.watchAt(ALICE, 1n, target());
  await t.opened[0].ready();
  t.clock.tick(2_000);
  t.view.watchAt(ALICE, 2n, target("edge-2.example.org"));
  assert.equal(t.opened[0].closed, true, "the edge it moved off is left at once");
  assert.equal(t.opened.length, 1, "the next connect waits its turn");
  t.clock.tick(EDGE_CONNECT_SPACING_MS - 2_000 - 1);
  assert.equal(t.opened.length, 1);
  t.clock.tick(1);
  assert.equal(t.opened.length, 2);
  assert.equal(t.opened[1].view.host, "edge-2.example.org");
  // A third while the second waits: only the latest connects, still one per 5 s
  t.view.watchAt(ALICE, 3n, target("edge-3.example.org"));
  t.view.watchAt(ALICE, 4n, target("edge-4.example.org"));
  t.clock.tick(EDGE_CONNECT_SPACING_MS);
  assert.deepEqual(
    t.opened.map((o) => o.view.host),
    ["edge-1.example.org", "edge-2.example.org", "edge-4.example.org"],
  );
  // No watchdog while it waits: nothing was failed in all this
  assert.deepEqual(t.failed, []);
});

test("a closed generation's callback is dropped", async () => {
  const t = setup();
  t.view.watchAt(ALICE, 1n, target());
  await t.opened[0].ready();
  const old = t.opened[0].handlers;
  t.view.close();
  assert.equal(t.opened[0].closed, true);
  old.onVideoPacket(packet(0x13));
  old.onDatagram(packet(0x15));
  old.onClosed("The edge closed the connection");
  t.clock.tick(60_000);
  assert.deepEqual([t.video.length, t.audio.length, t.failed.length], [0, 0, 0]);

  // A connect still out when the view moved on: its Ready closes it, its records go nowhere
  t.view.watchAt(ALICE, 2n, target("edge-2.example.org"));
  const late = t.opened[1];
  t.view.watchAt(ALICE, 3n, target("edge-3.example.org"));
  await late.ready();
  assert.equal(late.closed, true, "a link that opened after the view moved on is closed again");
  late.handlers.onVideoPacket(packet(0x13));
  late.handlers.onClosed("The edge closed the connection");
  t.clock.tick(EDGE_ENDED_GRACE_MS);
  assert.deepEqual([t.video.length, t.failed.length], [0, 0]);
});

test("a connect, hello or Ready that fails tells the relay at once", async () => {
  const t = setup();
  t.view.watchAt(ALICE, 5n, target());
  t.clock.tick(4_000);
  await t.opened[0].refuse("The edge ended the view: ticket refused");
  assert.deepEqual(t.failed, [[ALICE, 5n, 4_000]]);
  assert.match(t.states.at(-1)?.reason ?? "", /ticket refused/);
  t.clock.tick(EDGE_SILENT_MS);
  assert.equal(t.failed.length, 2, "and again while the relay does not answer");
});

test("an EdgeView the app cannot use, or a connection on the TCP fallback, fails at once", () => {
  const t = setup();
  t.view.watchAt(ALICE, 1n, { ...target(), port: 0 });
  assert.deepEqual(t.failed, [[ALICE, 1n, 0]]);
  assert.equal(t.opened.length, 0, "it connects nowhere");

  const tunnel = setup({ tunnel: true });
  tunnel.view.watchAt(ALICE, 1n, target());
  assert.deepEqual(tunnel.failed, [[ALICE, 1n, 0]]);
  assert.equal(tunnel.opened.length, 0);
});

test("back on the relay, the edge is left and nothing more is said", async () => {
  const t = await onEdge();
  t.view.close();
  assert.equal(t.opened[0].closed, true);
  assert.equal(t.view.sharer, 0);
  t.clock.tick(60_000);
  assert.deepEqual(t.failed, []);
  assert.deepEqual(
    t.states.map((s) => s.state),
    ["connecting", "ready", "closed"],
  );
});
