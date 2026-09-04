// WebTransport link to the server's browser bridge (crates/voipc-server/src/web.rs).
// One bidirectional stream carries the control channel in the native TCP
// framing (u32 big-endian length prefix + postcard payload), QUIC datagrams
// carry raw media packets, and each server->client unidirectional stream is
// one video frame as a sequence of [u16 big-endian length][packet] records.
// Encoding and decoding of the payloads is the session's job.

/** Same bound as voipc_protocol::codec::MAX_MSG_SIZE. */
const MAX_MSG_SIZE = 65_536;
/** Largest per-frame video stream we buffer (a 1080p keyframe is well under 1 MiB). */
const MAX_FRAME_STREAM_BYTES = 8 * 1024 * 1024;
/** Bound for each connect phase, like network.rs CONNECT_TIMEOUT. */
const CONNECT_TIMEOUT_MS = 10_000;
/** The server pings every 60 s on the control channel; two missed pings plus margin. */
const IDLE_TIMEOUT_MS = 150_000;

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
  /** Frame and queue one control payload (postcard ClientMessage). */
  sendControl(payload: Uint8Array): void;
  sendDatagram(bytes: Uint8Array): void;
  /** Flush queued control frames and close the session. onClosed is not called. */
  close(): Promise<void>;
}

interface BridgeInfo {
  port: number;
  hash: Uint8Array<ArrayBuffer>;
}

/** Fetch the bridge port + certificate hash from the page origin and open the session. */
export async function connect(host: string, port: number, handlers: TransportHandlers): Promise<Transport> {
  if (typeof WebTransport === "undefined") {
    throw new Error(
      "This browser has no WebTransport support (VoIPC needs Chrome 97+, Edge 98+, Firefox 130+ or Safari 26.4+)",
    );
  }
  const urlHost = host.includes(":") ? `[${host}]` : host;
  const origin = `https://${urlHost}:${port}`;

  let info = await fetchBridgeInfo(origin);
  let wt: WebTransport;
  try {
    wt = await openSession(urlHost, info);
  } catch {
    // The bridge certificate rotates every 7 days: a hash fetched just before
    // a rotation is stale by the time the handshake runs. Refetch once.
    info = await fetchBridgeInfo(origin);
    try {
      wt = await openSession(urlHost, info);
    } catch (e) {
      throw new Error(`WebTransport handshake with ${urlHost}:${info.port} failed: ${message(e)}`);
    }
  }

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
  void readControl(bidi.readable, handlers, armWatchdog, finish);
  void readDatagrams(wt.datagrams.readable, handlers);
  void readVideoStreams(wt.incomingUnidirectionalStreams, handlers);
  armWatchdog();

  return {
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
  let json: { port?: unknown; hash?: unknown };
  try {
    json = await res.json();
  } catch {
    throw new Error(`Invalid wt.json from ${origin}`);
  }
  const { port, hash } = json ?? {};
  if (
    typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535 ||
    typeof hash !== "string" || !/^[0-9a-f]{64}$/i.test(hash)
  ) {
    throw new Error(`Invalid wt.json from ${origin}`);
  }
  return { port, hash: hexToBytes(hash) };
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

async function readControl(
  readable: ReadableStream,
  handlers: TransportHandlers,
  armWatchdog: () => void,
  finish: (reason: string) => void,
): Promise<void> {
  const reader = (readable as ReadableStream<Uint8Array>).getReader();
  let buf: Uint8Array = new Uint8Array(0);
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        finish("Server closed connection");
        return;
      }
      armWatchdog();
      buf = buf.length === 0 ? value : concat(buf, value);
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

async function readVideoFrame(stream: ReadableStream<Uint8Array>, handlers: TransportHandlers): Promise<void> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_FRAME_STREAM_BYTES) {
        await reader.cancel();
        return;
      }
      chunks.push(value);
    }
  } catch {
    // Stream reset by the server: the frame is lost, the assembler requests a keyframe.
    return;
  }
  const data = chunks.length === 1 ? chunks[0] : concatAll(chunks, total);
  let off = 0;
  while (off + 2 <= data.length) {
    const len = (data[off] << 8) | data[off + 1];
    off += 2;
    if (len === 0 || off + len > data.length) break; // truncated record
    handlers.onVideoPacket(data.subarray(off, off + len));
    off += len;
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

function concatAll(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
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
