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
   */
  sendVideoFrame(body: Uint8Array, key: boolean): boolean;
  /** Frames whose stream has not finished writing (only ever compared to 0). */
  videoBacklog(): number;
  /** Flush queued control frames and close the session. onClosed is not called. */
  close(): Promise<void>;
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
    return await openSession(urlHost, info);
  } catch {
    // The bridge certificate rotates every 7 days: a hash fetched just before
    // a rotation is stale by the time the handshake runs. Refetch once.
    const fresh = await fetchBridgeInfo(origin);
    try {
      return await openSession(urlHost, fresh);
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
  /** Frames whose stream has not finished writing (send-side backpressure). */
  let framesInFlight = 0;

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
    watchdog = setTimeout(() => finish("Connection timed out (no data from server)"), IDLE_TIMEOUT_MS);
  };

  wt.closed.then(
    () => finish("Server closed connection"),
    (e) => finish(`Read error: ${message(e)}`),
  );
  void readControl(bidi.readable, controlFramer(handlers, finish), armWatchdog, finish);
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
      controlWriter.write(frame).catch((e) => finish(`Write error: ${message(e)}`));
    },
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
      void (async () => {
        try {
          const stream: WritableStream<Uint8Array> = await wt.createUnidirectionalStream();
          const writer = stream.getWriter();
          await writer.write(body);
          await writer.close();
        } catch {
          // Stream refused or reset: the frame is lost, the viewers ask for a
          // keyframe. The session's own error handling reports a dead link.
        } finally {
          framesInFlight--;
        }
      })();
      return true;
    },
    videoBacklog: () => framesInFlight,
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
    watchdog = setTimeout(() => finish("Connection timed out (no data from server)"), IDLE_TIMEOUT_MS);
  };
  const pushControl = controlFramer(handlers, finish);

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
      if (ws.bufferedAmount > (key ? TUNNEL_MAX_KEY_BACKLOG : TUNNEL_MAX_DELTA_BACKLOG)) return false;
      // One message per packet, as the relay forwards them
      let off = 0;
      while (off + 2 <= body.length) {
        const len = (body[off] << 8) | body[off + 1];
        off += 2;
        if (len === 0 || off + len > body.length) break;
        send(body.subarray(off, off + len));
        off += len;
      }
      return true;
    },
    videoBacklog: () => (ws.bufferedAmount > 0 ? 1 : 0),
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

async function openSession(urlHost: string, info: BridgeInfo): Promise<WebTransport> {
  const wt = new WebTransport(`https://${urlHost}:${info.port}/voipc`, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: info.hash }],
  });
  // A failed handshake also rejects `closed`; the caller attaches the real handler.
  wt.closed.catch(() => {});
  try {
    await withTimeout(wt.ready, CONNECT_TIMEOUT_MS, "Timed out in WebTransport handshake");
  } catch (e) {
    wt.close();
    throw e;
  }
  return wt;
}

/** Control-stream bytes in, whole control payloads out (u32 BE length prefix). */
function controlFramer(
  handlers: TransportHandlers,
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
      handlers.onControl(buf.subarray(off + 4, off + 4 + len));
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
): Promise<void> {
  const reader = (readable as ReadableStream<Uint8Array>).getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        finish("Server closed connection");
        return;
      }
      armWatchdog();
      pushControl(value);
    }
  } catch (e) {
    finish(`Read error: ${message(e)}`);
  }
}

async function readDatagrams(readable: ReadableStream, handlers: TransportHandlers): Promise<void> {
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

async function readVideoStreams(streams: ReadableStream, handlers: TransportHandlers): Promise<void> {
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
async function readVideoFrame(stream: ReadableStream<Uint8Array>, handlers: TransportHandlers): Promise<void> {
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
