// Link to the server's browser bridge (crates/voipc-server/src/web.rs).
//
// WebTransport first: one bidirectional stream carries the control channel in
// the native TCP framing (u32 big-endian length prefix + postcard payload),
// QUIC datagrams carry raw media packets, and each server->client
// unidirectional stream is one video frame as a sequence of
// [u16 big-endian length][packet] records.
//
// When something on the way drops UDP and the server has its TCP fallback on
// (`/wt.json` says `tcp`), the same session runs through a WebSocket on the
// page's own port instead (crates/voipc-server/src/tunnel.rs): every binary
// message is either 0x00 + a chunk of the control byte stream, or one media
// packet exactly as it would travel as a datagram or video record. QUIC gets a
// head start, then the two race. Encoding and decoding of the payloads is the
// session's job either way.
//
// A viewer the relay placed on a media edge (protocol 26) also opens a second
// WebTransport session, to the edge, for that share's frames alone
// (`openEdgeView`): it shows the ticket the relay sent and gets the same video
// streams and screen-audio datagrams as from the relay. The edge has no TCP
// fallback.
//
// A sharer's frames go out as they come while the link carries them, on either carrier. Once
// its uplink queues (lib/video-pacer.ts UplinkControl: a frame's ack on WebTransport, a ping
// through the tunnel), they go out paced at what the link delivers, a big frame spread over
// time, until a spell with no queue lets them go as they come again; voice and control never
// wait behind the pacer. Its clock is a worker's, as a hidden tab clamps the page's own timers.

import {
  PACE_LOOK_MS,
  PROBE_EVERY_MS,
  PROBE_LOST_MS,
  UPLINK_FLOOR_FRAMES,
  UPLINK_FLOOR_PROBES,
  UplinkControl,
  VideoPacer,
} from "../../lib/video-pacer.ts";
import { ReadyClock } from "./live.ts";
import { traceWriteStage, traceWriteStart } from "./share-trace.ts";

/** A test build's trace (share-trace.ts); Node's tests of this module define no __SELFTEST__. */
const TRACED = typeof __SELFTEST__ !== "undefined" && __SELFTEST__;

/** Same bound as voipc_protocol::codec::MAX_MSG_SIZE. */
const MAX_MSG_SIZE = 65_536;
/** Largest per-frame video stream we buffer (a 1080p keyframe is well under 1 MiB). */
const MAX_FRAME_STREAM_BYTES = 8 * 1024 * 1024;
/** Same bound as voipc_protocol::video::MAX_STREAM_RECORD_SIZE. */
const MAX_STREAM_RECORD_SIZE = 1500;
/** Bound for each connect phase, like network.rs CONNECT_TIMEOUT. */
const CONNECT_TIMEOUT_MS = 10_000;
/** The server pings every 60 s on the control channel; two missed pings plus margin. */
const IDLE_TIMEOUT_MS = 150_000;
/**
 * Video frames allowed to be in flight at once while sharing. About a second
 * at 30 fps, matching the native sender's queue depth (network.rs): past it the
 * uplink is the bottleneck and dropping a frame beats growing a backlog.
 */
const MAX_FRAMES_IN_FLIGHT = 30;
/**
 * Slots past the cap that only a keyframe may take. Deltas stop at the cap, so
 * the keyframe that ends a drop always has room (native: must_block).
 */
const KEY_RESERVE = 4;
/**
 * How long WebTransport has the connect to itself before the TCP fallback joins
 * the race (native: transport.rs TCP_HEAD_START). With UDP blocked it never
 * finishes, and this is what that costs every connect.
 */
const TCP_HEAD_START_MS = 2_000;
/** Where an app fetches a share from a media edge (voipc_protocol::pool::VIEW_PATH). */
const VIEW_PATH = "/voipc-view";
/** Bound for each step of an edge connect: the handshake, then the hello and its Ready. */
const EDGE_STEP_MS = 5_000;
/** Control bytes per tunnel message (the server takes up to 64 KiB + the tag). */
const TUNNEL_CONTROL_CHUNK = 16 * 1024;
/**
 * A WebSocket is one queue in send order, where QUIC sent datagrams ahead of
 * video. So a delta frame goes out only while little is queued, or the voice
 * behind it waits for the whole backlog.
 */
const TUNNEL_MAX_DELTA_BACKLOG = 64 * 1024;
/** ...and a keyframe, which ends a drop, while a little more is. */
const TUNNEL_MAX_KEY_BACKLOG = 512 * 1024;

/**
 * Lets out what `letOut` has due now, and looks again on the pace clock until nothing waits:
 * one look per tick for a transport, however many frames wait.
 */
function paceOn(letOut: () => boolean): () => void {
  let waiting = false;
  const look = () => {
    const done = letOut();
    if (done) waiting = false;
    return done;
  };
  return () => {
    if (letOut() || waiting) return;
    waiting = true;
    void paceClock.until(look);
  };
}

/**
 * The pacers' one clock: a worker's while any frame waits (worklets/tick-worker.js), since a
 * sharer's tab is mostly hidden and a hidden tab clamps its own timers to a second. A frame
 * taken also goes out at once as far as the bucket allows, so the ticks only spread the rest.
 */
let paceTicks: Worker | undefined;
const paceClock = new ReadyClock((tick) => {
  if (typeof Worker === "undefined") {
    const timer = setInterval(tick, PACE_LOOK_MS);
    return () => clearInterval(timer);
  }
  paceTicks ??= new Worker(new URL("./worklets/tick-worker.js", import.meta.url), { type: "module" });
  paceTicks.onmessage = tick;
  paceTicks.postMessage({ type: "start", intervalMs: PACE_LOOK_MS });
  return () => paceTicks?.postMessage({ type: "stop" });
});

export interface TransportHandlers {
  /** One complete control frame payload (postcard ServerMessage, no length prefix). */
  onControl(payload: Uint8Array): void;
  /** One raw media datagram (byte 0 = packet type). */
  onDatagram(bytes: Uint8Array): void;
  /** One raw video packet (0x13/0x14) from a per-frame unidirectional stream. */
  onVideoPacket(bytes: Uint8Array): void;
  /** The session ended for any reason other than close(); called at most once. */
  onClosed(reason: string): void;
}

export interface Transport {
  /** Whether this is the TCP fallback (a WebSocket) rather than WebTransport. */
  readonly tcp: boolean;
  /** Frame and queue one control payload (postcard ClientMessage). */
  sendControl(payload: Uint8Array): void;
  /** Control frames not written out yet (only ever compared to 0). */
  controlBacklog(): number;
  sendDatagram(bytes: Uint8Array): void;
  /**
   * Write one encoded video frame on a unidirectional stream of its own, the
   * shape the server relays (see `pump_video_in` in voipc-server/src/web.rs).
   * `body` is the wasm-built `[u16 len][packet]…` record sequence.
   *
   * Returns false when the frame was dropped because too many earlier frames
   * are still in flight — our uplink is the bottleneck, and the caller should
   * count that as loss and ask its encoder for a keyframe. A keyframe (`key`)
   * may use a few reserved slots past that point.
   *
   * Taken frames go out whole and in order: as they come, or paced once the uplink queued.
   */
  sendVideoFrame(body: Uint8Array, key: boolean): boolean;
  /** Frames whose stream has not finished writing (only ever compared to 0). */
  videoBacklog(): number;
  /**
   * How long the video still waiting for the pacer takes to go out, in ms (0 unpaced); on the
   * TCP fallback with what waits in the socket ahead of the oldest ping still out.
   */
  videoQueuedMs(): number;
  /** When our own uplink was last found queued (performance.now() ms), 0 never. */
  uplinkQueuedAt(): number;
  /** A share's video starts: unpaced, its link judged afresh (UplinkControl.reset). */
  uplinkReset(): void;
  /**
   * The sharer's clock, a worker's: judges what is still out and applies the pacer's rate.
   * True when a ping is due through this link to time it (`sendProbe`): the TCP fallback,
   * whose queue is the socket's and shows in no ack.
   */
  uplinkTick(): boolean;
  /** A ping (`Ping` datagram) to time the uplink with; `stamp` is the sequence its Pong echoes. */
  sendProbe(bytes: Uint8Array, stamp: number): void;
  /** A Pong came back after `rttMs`: true if it was a probe's; else the keepalive's (the
   *  link's least, if no video was on the way). */
  uplinkPong(stamp: number, rttMs: number): boolean;
  /** Each time this share found its uplink queued (self-test): UplinkControl.finds. */
  uplinkFinds(): number[][];
  /**
   * The server may say nothing for this long from now on, as a sign-in waiting on a person:
   * none of its pings run yet. Never under the usual bound, so 0 puts that back.
   */
  allowQuiet(ms: number): void;
  /** Flush queued control frames and close the session. onClosed is not called. */
  close(): Promise<void>;
}

/** What comes of an edge link (`openEdgeView`), from its Ready on. */
export interface EdgeViewHandlers {
  /** One raw video packet (0x13/0x14), as `TransportHandlers.onVideoPacket`. */
  onVideoPacket(bytes: Uint8Array): void;
  /** One raw media datagram, as `TransportHandlers.onDatagram`. */
  onDatagram(bytes: Uint8Array): void;
  /** The edge ended the link (its `Ended`, or a close); at most once, never after close(). */
  onClosed(reason: string): void;
}

export interface EdgeViewLink {
  /** Leave the edge; onClosed is not called. */
  close(): void;
}

/** The pool messages a viewer speaks, from wasm (`WasmApi`): never written out here. */
export interface EdgeViewCodec {
  /** `ViewerMsg::Hello { ticket }`, with its length prefix. */
  encodeViewerHello(ticket: Uint8Array): Uint8Array;
  /** An `EdgeViewMsg` from its postcard bytes (no length prefix): `"Ready"` or `{ Ended: { reason } }`. */
  decodeEdgeViewMsg(bytes: Uint8Array): unknown;
}

interface BridgeInfo {
  port: number;
  hash: Uint8Array<ArrayBuffer>;
  /** The server has its TCP fallback on. */
  tcp: boolean;
}

type Opened = { tcp: false; wt: WebTransport } | { tcp: true; ws: WebSocket };

/**
 * Fetch the bridge port + certificate hash from the server's page port and
 * open the session: WebTransport, or the TCP fallback when that does not get
 * through. `?transport=tcp` skips WebTransport, to test the fallback.
 */
export async function connect(host: string, port: number, handlers: TransportHandlers): Promise<Transport> {
  const urlHost = host.includes(":") ? `[${host}]` : host;
  const origin = `https://${urlHost}:${port}`;
  const info = await fetchBridgeInfo(origin);

  const noWebTransport = typeof WebTransport === "undefined";
  if (noWebTransport || new URLSearchParams(location.search).get("transport") === "tcp") {
    if (!info.tcp) {
      throw new Error(
        noWebTransport
          ? "This browser has no WebTransport support (VoIPC needs Chrome 97+, Edge 98+, Firefox 130+ or Safari 26.4+)"
          : `${origin} has no TCP fallback (its operator can turn on tcp_fallback)`,
      );
    }
    return wrapSocket(await openSocket(urlHost, port), handlers);
  }

  if (!info.tcp) return wrapSession(await openQuic(urlHost, origin, info), handlers);

  let opened: Opened;
  try {
    opened = await firstOpen(
      openQuic(urlHost, origin, info).then((wt): Opened => ({ tcp: false, wt })),
      () => openSocket(urlHost, port).then((ws): Opened => ({ tcp: true, ws })),
    );
  } catch (e) {
    // Both failed: QUIC's reason (UDP blocked, most likely) and the tunnel's
    const [quicError, tcpError] = e instanceof AggregateError ? e.errors : [e, e];
    throw new Error(`${message(quicError)} TCP fallback: ${message(tcpError)}`);
  }
  return opened.tcp ? wrapSocket(opened.ws, handlers) : wrapSession(opened.wt, handlers);
}

/**
 * QUIC alone for TCP_HEAD_START_MS, or until it fails; then the tunnel too,
 * and the first to open wins. One that opens after the winner is closed again.
 * Rejects with an AggregateError of both reasons, QUIC's first.
 */
async function firstOpen(quic: Promise<Opened>, startTcp: () => Promise<Opened>): Promise<Opened> {
  const early = await Promise.race([
    quic.then(
      () => "open",
      () => "failed",
    ),
    new Promise((resolve) => setTimeout(() => resolve("slow"), TCP_HEAD_START_MS)),
  ]);
  if (early === "open") return quic;
  const attempts = [quic, startTcp()];
  const winner = await Promise.any(attempts);
  for (const attempt of attempts) {
    attempt.then(
      (other) => {
        if (other !== winner) closeOpened(other);
      },
      () => {},
    );
  }
  return winner;
}

function closeOpened(opened: Opened): void {
  try {
    if (opened.tcp) opened.ws.close();
    else opened.wt.close();
  } catch {
    // already closed
  }
}

/** The WebTransport handshake, retried once with a fresh certificate hash. */
async function openQuic(urlHost: string, origin: string, info: BridgeInfo): Promise<WebTransport> {
  try {
    return await openSession(urlHost, info.port, "/voipc", [info.hash], CONNECT_TIMEOUT_MS);
  } catch {
    // The bridge certificate rotates every 7 days: a hash fetched just before
    // a rotation is stale by the time the handshake runs. Refetch once.
    const fresh = await fetchBridgeInfo(origin);
    try {
      return await openSession(urlHost, fresh.port, "/voipc", [fresh.hash], CONNECT_TIMEOUT_MS);
    } catch (e) {
      // Getting here means /wt.json came back over TCP, so the server is up and
      // reachable — only the UDP/QUIC path failed. The browser keeps the real
      // reason (blocked port, path MTU) in its own console and out of this
      // error, so name the two causes worth checking.
      throw new Error(
        `WebTransport handshake with ${urlHost}:${fresh.port} failed: ${message(e)}. ` +
          `The server answered on TCP, so UDP port ${fresh.port} is either blocked, ` +
          `or the path cannot carry a 1278-byte packet — a VPN with a small MTU does that. ` +
          `The browser console has the exact reason (ERR_MSG_TOO_BIG means the MTU).`,
      );
    }
  }
}

/** The session over an open WebTransport: its control stream, datagrams and video streams. */
async function wrapSession(wt: WebTransport, handlers: TransportHandlers): Promise<Transport> {
  let bidi: WebTransportBidirectionalStream;
  try {
    bidi = await withTimeout(wt.createBidirectionalStream(), CONNECT_TIMEOUT_MS, "Timed out opening the control stream");
  } catch (e) {
    wt.close();
    throw e;
  }
  const controlWriter = (bidi.writable as WritableStream<Uint8Array>).getWriter();
  const datagramWriter = (wt.datagrams.writable as WritableStream<Uint8Array>).getWriter();

  let closed = false;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  let idleMs = IDLE_TIMEOUT_MS;
  /** Frames whose stream has not finished writing (send-side backpressure), the paced included. */
  let framesInFlight = 0;
  /** A frame on its way: its stream's writer once open, its writes so far in order, and when
   *  its last bytes left the pacer (0 not yet). */
  type Paced = {
    writer: Promise<WritableStreamDefaultWriter<Uint8Array> | null>;
    writes: Promise<void>;
    traced: number[] | null;
    bytes: number;
    outAt: number;
  };
  const pacer = new VideoPacer<Paced>(performance.now());
  // Each frame's ack measures what the link delivers: a find needs it steady
  const uplink = new UplinkControl(UPLINK_FLOOR_FRAMES, true);
  /** Frames out of the pacer and not acked yet, oldest first. */
  const out = new Set<Paced>();
  /** Video the peer acked so far, bytes. */
  let delivered = 0;
  /** When a frame last came to be sent. */
  let lastFrameAt = -Infinity;
  /** Whatever the pacer has due now goes to its streams; true once nothing waits. */
  const letOut = (): boolean => {
    if (closed) return true;
    const now = performance.now();
    const rate = uplink.rate(now);
    if (rate !== pacer.rateBps()) {
      if (TRACED && rate === 0 && uplink.paced() === false && uplink.probeCount > 0) {
        console.info(`uplink probe ${uplink.probeCount}: unpaced again after ${Math.round(pacer.rateBps() / 1000)} kbps`);
      }
      pacer.setRate(rate, now);
    }
    for (const slice of pacer.take(now)) {
      const frame = slice.tag;
      if (slice.last) {
        frame.outAt = now;
        out.add(frame);
      }
      if (slice.first) {
        frame.writer = (wt.createUnidirectionalStream() as Promise<WritableStream<Uint8Array>>).then(
          (stream) => {
            if (TRACED && frame.traced) traceWriteStage(frame.traced, 1);
            return stream.getWriter();
          },
          // Stream refused: the frame is lost, the viewers ask for a keyframe
          () => null,
        );
      }
      frame.writes = frame.writes.then(async () => {
        try {
          const writer = await frame.writer;
          if (!writer) return;
          await writer.write(slice.bytes);
          if (slice.last) {
            if (TRACED && frame.traced) traceWriteStage(frame.traced, 2);
            // Resolves once the peer acked all of it: a round trip, and whatever queue is on
            // the way, ours in the browser included
            await writer.close();
            const acked = performance.now();
            delivered += frame.bytes;
            uplink.sample(acked - frame.outAt, delivered, acked);
            if (TRACED && frame.traced) traceWriteStage(frame.traced, 3);
          }
        } catch {
          // Stream reset: the frame is lost, the viewers ask for a keyframe. The
          // session's own error handling reports a dead link.
          frame.writer = Promise.resolve(null);
        }
      });
      if (slice.last) {
        void frame.writes.finally(() => {
          framesInFlight--;
          out.delete(frame);
        });
      }
    }
    if (!pacer.empty()) uplink.binding(now);
    return pacer.empty();
  };
  const pace = paceOn(letOut);
  /** Control frames handed to the stream and not taken yet. */
  let controlInFlight = 0;

  const finish = (reason: string) => {
    if (closed) return;
    closed = true;
    clearTimeout(watchdog);
    try {
      wt.close();
    } catch {
      // already closed
    }
    handlers.onClosed(reason);
  };
  const armWatchdog = () => {
    clearTimeout(watchdog);
    watchdog = setTimeout(() => finish("Connection timed out (no data from server)"), idleMs);
  };

  wt.closed.then(
    () => finish("Server closed connection"),
    (e) => finish(`Read error: ${message(e)}`),
  );
  void readControl(bidi.readable, controlFramer(handlers.onControl, finish), armWatchdog, finish);
  void readDatagrams(wt.datagrams.readable, handlers);
  void readVideoStreams(wt.incomingUnidirectionalStreams, handlers);
  armWatchdog();

  return {
    tcp: false,
    sendControl(payload) {
      if (closed) return;
      const frame = new Uint8Array(4 + payload.length);
      new DataView(frame.buffer).setUint32(0, payload.length);
      frame.set(payload, 4);
      controlInFlight++;
      controlWriter
        .write(frame)
        .catch((e) => finish(`Write error: ${message(e)}`))
        .finally(() => controlInFlight--);
    },
    controlBacklog: () => controlInFlight,
    sendDatagram(bytes) {
      if (closed) return;
      datagramWriter.write(bytes).catch(() => {
        // Dropped: datagrams are unreliable by design.
      });
    },
    sendVideoFrame(body, key) {
      if (closed) return false;
      // A frame goes out whole or not at all: a half-written frame would
      // stall every viewer's assembler until the next keyframe.
      if (framesInFlight >= MAX_FRAMES_IN_FLIGHT + (key ? KEY_RESERVE : 0)) return false;
      framesInFlight++;
      const traced = TRACED ? traceWriteStart(body.length) : null;
      lastFrameAt = performance.now();
      pacer.push(body, { writer: Promise.resolve(null), writes: Promise.resolve(), traced, bytes: body.length, outAt: 0 });
      pace();
      return true;
    },
    videoBacklog: () => framesInFlight,
    videoQueuedMs: () => pacer.queuedMs(),
    uplinkQueuedAt: () => uplink.queuedAt,
    uplinkReset() {
      if (TRACED) console.info(`uplink reset: least ${uplink.least()} ms`);
      uplink.reset();
    },
    uplinkTick() {
      if (closed) return false;
      const now = performance.now();
      // On a small link few frames a second come back: what is still out shows a queue first
      uplink.pending([...out].map((f) => now - f.outAt), now);
      pace();
      return false;
    },
    // Frames' acks time this link: a ping has nothing to add
    sendProbe() {},
    uplinkPong(_stamp, rttMs) {
      // The datagram path's round trip, with no video of ours on the way: the link's least
      if (TRACED) console.info(`uplink pong ${rttMs} ms, ${Math.round(performance.now() - lastFrameAt)} ms after video`);
      if (performance.now() - lastFrameAt > 2000) uplink.base(rttMs, performance.now());
      return false;
    },
    uplinkFinds: () => uplink.finds,
    allowQuiet(ms) {
      if (closed) return;
      idleMs = Math.max(ms, IDLE_TIMEOUT_MS);
      armWatchdog();
    },
    async close() {
      if (closed) return;
      closed = true;
      clearTimeout(watchdog);
      // Closing the send side flushes queued frames (the Disconnect message)
      // before the session goes away.
      try {
        await withTimeout(controlWriter.close(), 500, "flush");
      } catch {
        // best effort
      }
      try {
        wt.close();
      } catch {
        // already closed
      }
    },
  };
}

/** Open the TCP fallback's WebSocket on the page port (not the wt.json port: that one is UDP). */
function openSocket(urlHost: string, port: number): Promise<WebSocket> {
  const url = `wss://${urlHost}:${port}/voipc`;
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error(`Timed out opening ${url}`));
    }, CONNECT_TIMEOUT_MS);
    ws.onopen = () => {
      clearTimeout(timer);
      ws.onopen = ws.onclose = null;
      resolve(ws);
    };
    // The browser tells a page nothing about why: an error event, then a
    // close with code 1006. Its console has the reason.
    ws.onclose = (ev) => {
      clearTimeout(timer);
      reject(new Error(`Could not open ${url} (code ${ev.code}) — the browser console has the reason`));
    };
  });
}

/**
 * The session over the TCP fallback's WebSocket. It keeps the WebTransport
 * semantics the session relies on: whole frames or none, loss reported as a
 * refused frame, and the Disconnect going out before the close.
 */
function wrapSocket(ws: WebSocket, handlers: TransportHandlers): Transport {
  let closed = false;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  let idleMs = IDLE_TIMEOUT_MS;

  const finish = (reason: string) => {
    if (closed) return;
    closed = true;
    clearTimeout(watchdog);
    try {
      ws.close();
    } catch {
      // already closed
    }
    handlers.onClosed(reason);
  };
  const armWatchdog = () => {
    clearTimeout(watchdog);
    watchdog = setTimeout(() => finish("Connection timed out (no data from server)"), idleMs);
  };
  const pushControl = controlFramer(handlers.onControl, finish);
  // A frame's packets, one message each as the relay forwards them, as the pacer lets them out
  const pacer = new VideoPacer<null>(performance.now());
  // The socket is one queue in send order, and the kernel's part of it shows in no counter
  // here: a ping through it waits behind every byte sent before, so its round trip is that queue
  const uplink = new UplinkControl(UPLINK_FLOOR_PROBES, false);
  /** Video handed to the socket so far, bytes... */
  let sentVideo = 0;
  /** ...and when the first of it since the last ping was (NaN: none yet). */
  let firstSince = NaN;
  let lastFrameAt = -Infinity;
  let lastProbeAt = -Infinity;
  /**
   * Pings out and not answered, oldest first: their stamp, when, the video sent before them,
   * and when the first of the video sent since the ping before them went (NaN: none).
   */
  const probes: { stamp: number; at: number; before: number; first: number }[] = [];
  /** Pings sent before this share's video started time no queue of this share (uplinkReset). */
  let probesFrom = -Infinity;
  /** The pings still out that time this share's link: sent since its video started, not given up. */
  const timing = (now: number) => probes.filter((p) => p.at >= probesFrom && now - p.at < PROBE_LOST_MS);
  /**
   * How long the oldest ping still out has waited past the link's least: video waits in the
   * socket ahead of it that long at least, which counts for the sharer's gate as the pacer's
   * own queue does. Before anything is found (a slow start, a link that carries less), it
   * keeps voice from going behind more than PACE_GATE_MS of video, rate or no rate.
   */
  const socketWaitMs = (now: number) => {
    const oldest = timing(now)[0];
    return oldest ? Math.max(0, now - oldest.at - uplink.least()) : 0;
  };
  const letOut = (): boolean => {
    if (closed) {
      pacer.clear();
      return true;
    }
    const now = performance.now();
    const rate = uplink.rate(now);
    if (rate !== pacer.rateBps()) {
      if (TRACED && rate === 0 && uplink.paced() === false && uplink.probeCount > 0) {
        console.info(`uplink probe ${uplink.probeCount}: unpaced again after ${Math.round(pacer.rateBps() / 1000)} kbps`);
      }
      pacer.setRate(rate, now);
    }
    for (const { bytes } of pacer.take(now)) {
      let off = 0;
      while (off + 2 <= bytes.length) {
        const len = (bytes[off] << 8) | bytes[off + 1];
        off += 2;
        if (len === 0 || off + len > bytes.length) break;
        send(bytes.subarray(off, off + len));
        off += len;
        sentVideo += len;
        if (Number.isNaN(firstSince)) firstSince = now;
      }
    }
    if (!pacer.empty()) uplink.binding(now);
    return pacer.empty();
  };
  const pace = paceOn(letOut);

  ws.onmessage = (ev: MessageEvent<ArrayBuffer>) => {
    armWatchdog();
    const bytes = new Uint8Array(ev.data);
    if (bytes.length === 0) return;
    if (bytes[0] === 0x00) pushControl(bytes.subarray(1));
    else if (bytes[0] === 0x13 || bytes[0] === 0x14) handlers.onVideoPacket(bytes);
    else handlers.onDatagram(bytes);
  };
  ws.onclose = (ev) => finish(ev.code === 1000 ? "Server closed connection" : `Connection lost (code ${ev.code})`);
  armWatchdog();

  const send = (data: Uint8Array) => {
    try {
      ws.send(data);
    } catch (e) {
      finish(`Write error: ${message(e)}`);
    }
  };

  return {
    tcp: true,
    // Past what voice still goes behind: video and voice share this queue, so it may
    // never be quite empty during a share
    controlBacklog: () => (ws.bufferedAmount > TUNNEL_MAX_DELTA_BACKLOG ? 1 : 0),
    sendControl(payload) {
      if (closed) return;
      const framed = new Uint8Array(4 + payload.length);
      new DataView(framed.buffer).setUint32(0, payload.length);
      framed.set(payload, 4);
      // A control message may be 64 KiB: tagged chunks of the byte stream
      for (let off = 0; off < framed.length; off += TUNNEL_CONTROL_CHUNK) {
        const chunk = framed.subarray(off, off + TUNNEL_CONTROL_CHUNK);
        const message = new Uint8Array(1 + chunk.length);
        message.set(chunk, 1);
        send(message);
      }
    },
    sendDatagram(bytes) {
      // A WebSocket cannot send voice ahead of the video queued before it,
      // so behind more than a delta's backlog it is dropped instead — late
      // voice is lost voice, as on UDP
      if (!closed && ws.bufferedAmount <= TUNNEL_MAX_DELTA_BACKLOG) send(bytes);
    },
    sendVideoFrame(body, key) {
      if (closed) return false;
      // The socket's own backlog only: what the pacer holds is bounded in time by the sharer
      // (PACE_GATE_MS), and counted in bytes it refused deltas on a link with room
      if (ws.bufferedAmount > (key ? TUNNEL_MAX_KEY_BACKLOG : TUNNEL_MAX_DELTA_BACKLOG)) return false;
      lastFrameAt = performance.now();
      pacer.push(body, null);
      pace();
      return true;
    },
    videoBacklog: () => (ws.bufferedAmount > 0 || !pacer.empty() ? 1 : 0),
    videoQueuedMs: () => pacer.queuedMs() + socketWaitMs(performance.now()),
    uplinkQueuedAt: () => uplink.queuedAt,
    uplinkReset() {
      uplink.reset(sentVideo);
      probesFrom = performance.now();
    },
    uplinkTick() {
      if (closed) return false;
      const now = performance.now();
      // A ping or its pong the relay dropped is not coming: past PROBE_LOST_MS it times nothing
      // (a queue that long was found while it was younger). Kept to know its pong if it comes.
      uplink.pending(
        timing(now).map((p) => now - p.at),
        now,
      );
      pace();
      // Timed while video goes out, not over a still screen
      return now - lastFrameAt < 1000 && now - lastProbeAt >= PROBE_EVERY_MS;
    },
    sendProbe(bytes, stamp) {
      if (closed) return;
      // Never dropped behind a backlog, as sendDatagram drops voice: the backlog is what it times
      lastProbeAt = performance.now();
      probes.push({ stamp, at: lastProbeAt, before: sentVideo, first: firstSince });
      firstSince = NaN;
      if (probes.length > 16) probes.shift();
      send(bytes);
    },
    uplinkPong(stamp, rttMs) {
      const now = performance.now();
      const i = probes.findIndex((p) => p.stamp === stamp);
      if (i < 0) {
        // The keepalive's: with no video of ours ahead of it, the link's least
        if (now - lastFrameAt > 2000) uplink.base(rttMs, now);
        return false;
      }
      const probe = probes[i];
      // Answered in order: any older one is not coming (the relay may drop a ping). Each ping
      // since the one answered before says when video first went after the ping before it.
      const first = probes.slice(0, i + 1).find((p) => !Number.isNaN(p.first))?.first ?? NaN;
      probes.splice(0, i + 1);
      if (probe.at >= probesFrom) uplink.sample(now - probe.at, probe.before, now, first);
      return true;
    },
    uplinkFinds: () => uplink.finds,
    allowQuiet(ms) {
      if (closed) return;
      idleMs = Math.max(ms, IDLE_TIMEOUT_MS);
      armWatchdog();
    },
    async close() {
      if (closed) return;
      closed = true;
      clearTimeout(watchdog);
      // Messages already queued (the Disconnect) go out ahead of the Close
      ws.onclose = null;
      ws.close(1000);
    },
  };
}

/**
 * Fetch a share from a media edge: a WebTransport session to its `/voipc-view`,
 * trusting only a certificate of `hashes` (the relay named them with the edge),
 * then the viewer's hello with `ticket`. Resolves at the edge's `Ready`; rejects
 * when the handshake, the hello or the Ready fails or takes longer than its 5 s.
 *
 * From then on the edge's video streams and datagrams come as from the relay.
 * The app sends it nothing more: keyframe asks and loss reports go to the
 * relay. No watchdog here: what counts as a silent edge is the caller's
 * (edge-view.ts), by whole decrypted frames rather than bytes.
 */
export async function openEdgeView(
  host: string,
  port: number,
  hashes: ArrayLike<number>[],
  ticket: ArrayLike<number>,
  handlers: EdgeViewHandlers,
  codec: EdgeViewCodec,
): Promise<EdgeViewLink> {
  const urlHost = host.includes(":") ? `[${host}]` : host;
  // Copies: the decoded message is the relay's, and the hashes must be plain buffers
  const pins = hashes.map((h) => Uint8Array.from(h));
  const wt = await openSession(urlHost, port, VIEW_PATH, pins, EDGE_STEP_MS);

  let closed = false;
  let ready = false;
  let answered: { resolve(): void; reject(e: Error): void } = { resolve() {}, reject() {} };
  const readyAt = new Promise<void>((resolve, reject) => void (answered = { resolve, reject }));
  // Nobody waits on it once the hello step has given up
  readyAt.catch(() => {});

  const finish = (reason: string) => {
    if (closed) return;
    closed = true;
    try {
      wt.close();
    } catch {
      // already closed
    }
    if (ready) handlers.onClosed(reason);
    else answered.reject(new Error(reason));
  };
  const onFrame = (payload: Uint8Array) => {
    if (closed) return;
    let msg: unknown;
    try {
      msg = codec.decodeEdgeViewMsg(payload);
    } catch {
      return finish("The edge sent something this app cannot read");
    }
    if (msg === "Ready" && !ready) {
      ready = true;
      void readDatagrams(wt.datagrams.readable, handlers);
      void readVideoStreams(wt.incomingUnidirectionalStreams, handlers);
      answered.resolve();
      return;
    }
    const ended = (msg as { Ended?: { reason?: unknown } } | null)?.Ended;
    finish(ended ? `The edge ended the view: ${String(ended.reason)}` : "The edge said something out of turn");
  };

  wt.closed.then(
    () => finish("The edge closed the connection"),
    (e) => finish(`The edge's connection failed: ${message(e)}`),
  );
  try {
    await withTimeout(
      (async () => {
        const bidi: WebTransportBidirectionalStream = await wt.createBidirectionalStream();
        void readControl(bidi.readable, controlFramer(onFrame, finish), () => {}, finish, "The edge closed the view");
        // Its send side stays open: an edge may take a finished stream for a viewer gone
        const writer = (bidi.writable as WritableStream<Uint8Array>).getWriter();
        await writer.write(codec.encodeViewerHello(Uint8Array.from(ticket)));
        await readyAt;
      })(),
      EDGE_STEP_MS,
      "Timed out waiting for the edge's Ready",
    );
  } catch (e) {
    finish(message(e));
    throw e;
  }
  return {
    close() {
      if (closed) return;
      closed = true;
      try {
        wt.close();
      } catch {
        // already closed
      }
    },
  };
}

async function fetchBridgeInfo(origin: string): Promise<BridgeInfo> {
  let res: Response;
  try {
    res = await fetch(`${origin}/wt.json`, { cache: "no-store", signal: AbortSignal.timeout(CONNECT_TIMEOUT_MS) });
  } catch (e) {
    throw new Error(
      `Could not reach ${origin} (${message(e)}) — is the server's certificate trusted by this browser?`,
    );
  }
  if (!res.ok) throw new Error(`${origin}/wt.json returned HTTP ${res.status}`);
  let json: { port?: unknown; hash?: unknown; tcp?: unknown };
  try {
    json = await res.json();
  } catch {
    throw new Error(`Invalid wt.json from ${origin}`);
  }
  const { port, hash, tcp } = json ?? {};
  if (
    typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535 ||
    typeof hash !== "string" || !/^[0-9a-f]{64}$/i.test(hash)
  ) {
    throw new Error(`Invalid wt.json from ${origin}`);
  }
  // Absent on a server from before the fallback
  return { port, hash: hexToBytes(hash), tcp: tcp === true };
}

/** A WebTransport session to `path`, trusting only a certificate of these hashes. */
async function openSession(
  urlHost: string,
  port: number,
  path: string,
  hashes: Uint8Array<ArrayBuffer>[],
  timeoutMs: number,
): Promise<WebTransport> {
  const wt = new WebTransport(`https://${urlHost}:${port}${path}`, {
    serverCertificateHashes: hashes.map((value) => ({ algorithm: "sha-256", value })),
  });
  // A failed handshake also rejects `closed`; the caller attaches the real handler.
  wt.closed.catch(() => {});
  try {
    await withTimeout(wt.ready, timeoutMs, "Timed out in WebTransport handshake");
  } catch (e) {
    wt.close();
    throw e;
  }
  return wt;
}

/** Control-stream bytes in, whole control payloads out (u32 BE length prefix). */
function controlFramer(
  onFrame: (payload: Uint8Array) => void,
  finish: (reason: string) => void,
): (chunk: Uint8Array) => void {
  let buf: Uint8Array = new Uint8Array(0);
  return (chunk) => {
    buf = buf.length === 0 ? chunk : concat(buf, chunk);
    let off = 0;
    while (buf.length - off >= 4) {
      const len = readU32(buf, off);
      if (len > MAX_MSG_SIZE) {
        finish(`Protocol error: message too large (${len} bytes)`);
        return;
      }
      if (buf.length - off < 4 + len) break;
      onFrame(buf.subarray(off + 4, off + 4 + len));
      off += 4 + len;
    }
    if (off > 0) buf = buf.slice(off);
  };
}

async function readControl(
  readable: ReadableStream,
  pushControl: (chunk: Uint8Array) => void,
  armWatchdog: () => void,
  finish: (reason: string) => void,
  closedReason = "Server closed connection",
): Promise<void> {
  const reader = (readable as ReadableStream<Uint8Array>).getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        finish(closedReason);
        return;
      }
      armWatchdog();
      pushControl(value);
    }
  } catch (e) {
    finish(`Read error: ${message(e)}`);
  }
}

async function readDatagrams(readable: ReadableStream, handlers: Pick<TransportHandlers, "onDatagram">): Promise<void> {
  const reader = (readable as ReadableStream<Uint8Array>).getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      if (value.length > 0) handlers.onDatagram(value);
    }
  } catch {
    // Session closed; `closed` reports the reason.
  }
}

async function readVideoStreams(streams: ReadableStream, handlers: Pick<TransportHandlers, "onVideoPacket">): Promise<void> {
  const reader = (streams as ReadableStream<ReadableStream<Uint8Array>>).getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      // Frames are read one after another so packets reach the assembler in order.
      await readVideoFrame(value, handlers);
    }
  } catch {
    // Session closed; `closed` reports the reason.
  }
}

/** Packets are handed on as they arrive: waiting for the frame's FIN would add
 *  its whole transmission time to the latency (voipc_protocol::video::RecordReader). */
async function readVideoFrame(
  stream: ReadableStream<Uint8Array>,
  handlers: Pick<TransportHandlers, "onVideoPacket">,
): Promise<void> {
  const reader = stream.getReader();
  let pending: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      total += value.length;
      if (total > MAX_FRAME_STREAM_BYTES) {
        await reader.cancel();
        return;
      }
      const data = pending.length === 0 ? value : concat(pending, value);
      let off = 0;
      while (off + 2 <= data.length) {
        const len = (data[off] << 8) | data[off + 1];
        if (len === 0 || len > MAX_STREAM_RECORD_SIZE) {
          await reader.cancel(); // record boundaries are lost, the frame is junk
          return;
        }
        if (off + 2 + len > data.length) break; // the rest is still in flight
        handlers.onVideoPacket(data.subarray(off + 2, off + 2 + len));
        off += 2 + len;
      }
      pending = off === 0 ? data : data.slice(off);
    }
  } catch {
    // Stream reset by the server: the frame is lost, the assembler requests a keyframe.
  }
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(what)), ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

function readU32(buf: Uint8Array, off: number): number {
  return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
