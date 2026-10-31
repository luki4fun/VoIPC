// Files in chat, the transfer half: the browser's port of
// client/src-tauri/src/files.rs, with the same rules and the same events.
//
// The control stream negotiates (FileUpload, FileFetch; the relay's answers
// come in through Files.onMessage). The bytes go over fetch() to `/f/v1/` on
// the relay's page origin, never over the WebTransport session or the
// tunnel, where voice and video would queue behind a file. Sealing and opening
// run in a Worker of their own, one per file, ended afterwards: a 10 MB seal
// takes a third of a second, which on the main thread would stall the voice
// being sent, and the wasm memory a big file grows goes with the worker.
//
// The cache is in memory (256 MB, least recently used out first), so it lasts
// as long as the tab. The front end drops what no message refers to any more
// (file_cache_retain), as it does on the desktop.

import { mediaModule, type Motion, type Pack, type Sanitized } from "./media";
import { fileRef } from "../../lib/chat-rules";
import { Asks, asksAgain } from "../../lib/file-rules";
import { toHex } from "../../lib/hex";
import { parseHostPort } from "../../lib/invite";
import { wasmModule } from "./wasm";

const KIB = 1024;
const MIB = 1024 * 1024;
/** The relay's largest chunk, either way. */
const MAX_CHUNK = MIB;
/** The smallest chunk: the least that keeps an upload's ticket sliding. */
const MIN_CHUNK = 64 * KIB;
const FIRST_CHUNK = 256 * KIB;
/** The chunk while in a call: the floor (files.rs `CALL_CHUNK`, which says
 *  what was measured). */
const CALL_CHUNK = MIN_CHUNK;
/** The longest pause after a chunk while in a call (files.rs `CALL_GAP_MAX`). */
const CALL_GAP_MAX_MS = 10_000;
/** What one chunk should take. The relay gives a request body 60 s. */
const CHUNK_TIME_MS = 15_000;
const REQUEST_TIME_MS = 90_000;
/** How long a transfer goes on trying with nothing moving before it gives
 *  up: past the 60 s the relay may still be reading a chunk whose sender left. */
const STALL_TIME_MS = 2 * 60_000;
/** Silence after a request before it is sent again: the relay drops what a
 *  full queue cannot take, and answers a request sent again as it did the first. */
const REPLY_WAIT_MS = 60_000;
/** The same while the relay asks members for the file: each ask may reach them all again. */
const SEEK_RESEND_MS = 5 * 60_000;
/** After a refusal that may pass later (`asksAgain`), before asking again. */
const RATE_PAUSE_MS = 5_000;
const UPLOAD_WAIT_MS = 10 * 60_000;
const FETCH_WAIT_MS = 2 * 60_000;
const SEEK_WAIT_MS = 65 * 60_000;
const CACHE_CAP = 256 * MIB;
const RETAIN_GRACE_MS = 10 * 60_000;
/** voipc_crypto::file::MAX_FILE_PLAIN */
const MAX_FILE_PLAIN = 64 * MIB;
/** voipc_crypto::file::MAX_FILE_BLOB: MAX_FILE_PLAIN sealed, a tag per 64 KiB. */
const MAX_FILE_BLOB = 32 + MAX_FILE_PLAIN + (MAX_FILE_PLAIN / (64 * KIB)) * 16;

const CLOSED = "the connection to the server ended";
const CANCELLED = "cancelled";
const FILES_OFF = "this server keeps no files";
/** What fetch_file fails with when nobody online had the file in time. */
export const UNAVAILABLE = "Nobody online has this file";

/** A conversation as the front end names it (files.rs `Conv`). */
export type Conv = { channel: number } | { direct: number } | { account: string };

/** What a file message says about its blob (files.rs `FileArg`). */
export interface FileArg {
  hash: string;
  key: string;
  size: number;
  z: boolean;
}

/** Fields of a decoded ServerMessage variant. */
type Body = Record<string, any>;

/** What a session lends its file side. */
export interface FileHost {
  sendControl(msg: unknown): void;
  emit(name: string, data: unknown): void;
  /** Voice is on, on any server: transfers then yield to it. */
  inCall(): boolean;
}

function fromHex(hex: string, len: number): number[] {
  if (hex.length !== len * 2 || !/^[0-9a-f]*$/.test(hex)) throw new Error("invalid id");
  return Array.from({ length: len }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}

/** As the protocol spells it: `{Channel: id}`, `{Account: [16 bytes]}`. */
function wireConv(c: Conv): unknown {
  if ("channel" in c) return { Channel: c.channel };
  if ("direct" in c) return { Direct: c.direct };
  return { Account: fromHex(c.account, 16) };
}

function convOf(w: Body): Conv | null {
  if (typeof w?.Channel === "number") return { channel: w.Channel };
  if (typeof w?.Direct === "number") return { direct: w.Direct };
  if (Array.isArray(w?.Account)) return { account: toHex(w.Account) };
  return null;
}

/** Strict: the front end's `conv`, before anything is sent. */
export function parseConv(v: unknown): Conv {
  const c = v as Record<string, unknown> | null;
  const id = (x: unknown) => typeof x === "number" && Number.isInteger(x) && x >= 0 && x <= 0xffff_ffff;
  if (c && id(c.channel)) return { channel: c.channel as number };
  if (c && id(c.direct)) return { direct: c.direct as number };
  if (c && typeof c.account === "string" && /^[0-9a-f]{32}$/.test(c.account)) return { account: c.account };
  throw new Error("invalid conv");
}

/** The front end's `file`, checked as FileMeta::from_parts checks it. */
export function parseFileArg(v: unknown): FileArg {
  return fileRef(v) ?? fail("invalid file");
}

/** The relay's page origin for `server` (`host:port`), where `/f/` lives. */
export function originOf(server: string): string {
  const parsed = parseHostPort(server);
  if (!parsed) throw new Error("Invalid address");
  const host = parsed.host.includes(":") ? `[${parsed.host}]` : parsed.host;
  return `https://${host}:${parsed.port}`;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const fail = (why: string): never => {
  throw new Error(why);
};
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** The caller's signal, plus the one request's own deadline. */
function within(signal: AbortSignal | undefined): AbortSignal {
  const deadline = AbortSignal.timeout(REQUEST_TIME_MS);
  return signal ? AbortSignal.any([signal, deadline]) : deadline;
}

/** Chunk sizes for the link at hand (files.rs `Pace`). */
export class Pace {
  chunk = FIRST_CHUNK;

  /** `bytes` went through in `ms`: aim the next chunk at CHUNK_TIME_MS. */
  took(bytes: number, ms: number): void {
    // A last short chunk says little about the link
    if (bytes < MIN_CHUNK) return;
    const rate = bytes / Math.max(ms, 1);
    this.chunk = Math.min(MAX_CHUNK, Math.max(MIN_CHUNK, Math.floor(rate * CHUNK_TIME_MS)));
  }

  /** A request was cut off with no answer: smaller next time. */
  cut(): void {
    this.chunk = Math.max(MIN_CHUNK, Math.floor(this.chunk / 2));
  }

  /** The next chunk's size: in a call, CALL_CHUNK. */
  next(inCall: boolean): number {
    return inCall ? CALL_CHUNK : this.chunk;
  }
}

/**
 * In a call, pause after a chunk for as long as it took: the file gets half
 * the link at most, and the queue in front of the link drains in between
 * (files.rs `yield_to_voice`). Never past CALL_GAP_MAX_MS: the relay passes
 * an upload 30 s idle to a member queued behind it. shortcut: the pacing
 * factor is a fixed ½; upgrade to delay-based if a measurement says so.
 */
export async function yieldToVoice(inCall: boolean, chunkStarted: number): Promise<void> {
  if (inCall) await sleep(Math.min(performance.now() - chunkStarted, CALL_GAP_MAX_MS));
}

/** Pauses between tries that move nothing on: from half a second, doubling
 *  to 8 s, until nothing has moved for STALL_TIME_MS (files.rs `Patience`). */
class Patience {
  private since = Date.now();
  private tries = 0;

  constructor(private readonly signal?: AbortSignal) {}

  moved(): void {
    this.since = Date.now();
    this.tries = 0;
  }

  /** Wait before the next try, or give up with `why`. */
  async wait(why: string): Promise<void> {
    if (Date.now() - this.since >= STALL_TIME_MS) throw new Error(why);
    await sleep(500 * 2 ** Math.min(this.tries++, 4));
    if (this.signal?.aborted) throw new Error(CANCELLED);
  }
}

/** `bytes a-b/total`. */
export function contentRange(v: string | null): [number, number, number] | null {
  const m = v?.trim().match(/^bytes (\d+)-(\d+)\/(\d+)$/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** A blob's turn: its transfer's answers, until it is released. */
class Turn {
  private readonly queue: { tag: string; b: Body }[] = [];
  private wake: (() => void) | null = null;
  private closed = false;
  /** Tell the relay the transfer is given up when it ends unfinished. */
  armed = true;
  readonly done: Promise<void>;
  finish!: () => void;

  constructor(readonly hash: string) {
    this.done = new Promise((resolve) => (this.finish = resolve));
  }

  push(m: { tag: string; b: Body }): void {
    this.queue.push(m);
    this.wake?.();
  }

  close(): void {
    this.closed = true;
    this.wake?.();
  }

  /** The next answer to `ask`, which goes again after each `every` ms of
   *  silence until `giveUp` (Date.now()). */
  async next(resend: () => void, every: number, giveUp: number, signal?: AbortSignal): Promise<{ tag: string; b: Body }> {
    for (;;) {
      const m = this.queue.shift();
      if (m) return m;
      if (this.closed) throw new Error(CLOSED);
      if (signal?.aborted) throw new Error(CANCELLED);
      const silent = await new Promise<boolean>((resolve) => {
        const done = (silent: boolean) => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          this.wake = null;
          resolve(silent);
        };
        const onAbort = () => done(false);
        const timer = setTimeout(() => done(true), every);
        signal?.addEventListener("abort", onAbort, { once: true });
        this.wake = () => done(false);
      });
      if (!silent) continue;
      if (Date.now() >= giveUp) throw new Error("the server did not answer in time");
      resend();
    }
  }
}

/** The file side of one session. */
export class Files {
  private readonly turns = new Map<string, Turn>();
  private closed = false;

  constructor(
    private readonly host: FileHost,
    private readonly origin: string,
    /** Authenticated.files.max_bytes; null when the relay keeps no files. */
    private readonly maxBytes: number | null,
    /** How a moving picture posted here is kept (`motionOf`). */
    readonly motion: Motion | null = null,
  ) {}

  /** A file message from the relay. */
  onMessage(tag: string, b: Body): void {
    if (!Array.isArray(b?.hash)) return;
    const hash = toHex(b.hash);
    if (tag === "FileWanted") {
      // Only for a blob held here; the front end decides whether a message
      // in that conversation refers to it
      const conv = convOf(b.conv);
      if (conv && cache.has(hash)) this.host.emit("file-wanted", { conv, hash });
      return;
    }
    this.turns.get(hash)?.push({ tag, b });
  }

  /** The session has ended: every transfer on it fails now. */
  close(): void {
    this.closed = true;
    for (const t of this.turns.values()) t.close();
  }

  private async turn(hash: string, signal?: AbortSignal): Promise<Turn> {
    for (;;) {
      if (this.closed) throw new Error(CLOSED);
      if (signal?.aborted) throw new Error(CANCELLED);
      const busy = this.turns.get(hash);
      if (!busy) break;
      await new Promise<void>((resolve) => {
        const stop = () => {
          signal?.removeEventListener("abort", stop);
          resolve();
        };
        signal?.addEventListener("abort", stop, { once: true });
        void busy.done.then(stop);
      });
    }
    const t = new Turn(hash);
    this.turns.set(hash, t);
    return t;
  }

  private release(t: Turn): void {
    if (t.armed && !this.closed) this.host.sendControl({ FileCancel: { hash: fromHex(t.hash, 32) } });
    if (this.turns.get(t.hash) === t) this.turns.delete(t.hash);
    t.finish();
  }

  private progress(op: string | undefined, stage: string, done: number, total: number): void {
    if (op) this.host.emit("file-progress", { op, stage, done, total });
  }

  private limit(): number {
    if (this.maxBytes === null) throw new Error(FILES_OFF);
    return this.maxBytes;
  }

  /** Store `blob` on the relay for a message in `conv`. */
  async upload(conv: Conv, hash: string, blob: Uint8Array, op?: string, signal?: AbortSignal): Promise<void> {
    const max = this.limit();
    if (blob.length > max) {
      throw new Error(`the file is larger than this server takes (${Math.floor(max / 1_000_000)} MB at most)`);
    }
    const turn = await this.turn(hash, signal);
    try {
      const ask = () =>
        this.host.sendControl({ FileUpload: { conv: wireConv(conv), size: blob.length, hash: fromHex(hash, 32) } });
      for (const asks = new Asks(); asks.next(); ) {
        ask();
        const giveUp = Date.now() + UPLOAD_WAIT_MS;
        for (;;) {
          const { tag, b } = await turn.next(ask, REPLY_WAIT_MS, giveUp, signal);
          if (tag === "FileStored") {
            turn.armed = false;
            return;
          }
          if (tag === "FileRefused" && asksAgain(Number(b.code))) {
            await sleep(RATE_PAUSE_MS);
            break;
          }
          // Still armed: a late refusal of an earlier ask, and the cancel
          // frees what the latest one started (files.rs Turn::done)
          if (tag === "FileRefused") throw new Error(String(b.reason));
          if (tag === "FileUploadReady") {
            // The relay says FileStored too; nothing waits for it
            if ((await this.put(String(b.ticket), hash, blob, op, signal)) === "stored") {
              turn.armed = false;
              return;
            }
            break;
          }
        }
      }
      throw new Error("the server kept ending the upload");
    } finally {
      this.release(turn);
    }
  }

  /** The blob `hash` of a message in `conv`, as the relay has it (checked
   *  against its id when it is opened). */
  async fetch(conv: Conv, hash: string, op?: string, signal?: AbortSignal): Promise<Uint8Array> {
    this.limit();
    const turn = await this.turn(hash, signal);
    try {
      let have: { buf: Uint8Array; n: number } | null = null;
      const ask = () => this.host.sendControl({ FileFetch: { conv: wireConv(conv), hash: fromHex(hash, 32) } });
      for (const asks = new Asks(); asks.next(); ) {
        ask();
        let giveUp = Date.now() + FETCH_WAIT_MS;
        let every = REPLY_WAIT_MS;
        for (;;) {
          const { tag, b } = await turn.next(ask, every, giveUp, signal);
          if (tag === "FileReady") {
            const size = Number(b.size);
            if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_FILE_BLOB) {
              throw new Error("the server offers more bytes than any file has");
            }
            if (!have || have.buf.length !== size) have = { buf: new Uint8Array(size), n: 0 };
            const before = have.n;
            if ((await this.get(String(b.ticket), hash, have, op, signal)) === "all") {
              turn.armed = false;
              return have.buf;
            }
            // A ticket that brought bytes costs no ask
            if (have.n > before) asks.moved();
            break;
          }
          if (tag === "FileSeeking") {
            this.progress(op, "seeking", 0, 0);
            // The relay ends the wait itself
            giveUp = Date.now() + SEEK_WAIT_MS;
            every = SEEK_RESEND_MS;
          } else if (tag === "FileUnavailable") {
            throw new Error(UNAVAILABLE);
          } else if (tag === "FileRefused" && asksAgain(Number(b.code))) {
            await sleep(RATE_PAUSE_MS);
            break;
          } else if (tag === "FileRefused") {
            throw new Error(String(b.reason));
          }
        }
      }
      throw new Error("the server kept ending the download");
    } finally {
      this.release(turn);
    }
  }

  /** Upload `blob` in chunks with `ticket`. */
  private async put(
    ticket: string,
    hash: string,
    blob: Uint8Array,
    op: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<"stored" | "gone"> {
    const url = `${this.origin}/f/v1/${hash}`;
    const pace = new Pace();
    const patience = new Patience(signal);
    let offset = 0;
    for (;;) {
      // Everything is there but the relay has not said stored: asking again
      // gets FileStored, or a new upload
      if (offset >= blob.length) return "gone";
      const call = this.host.inCall();
      const end = Math.min(offset + pace.next(call), blob.length);
      const started = performance.now();
      let res: Response;
      try {
        res = await fetch(`${url}?offset=${offset}`, {
          method: "PUT",
          headers: { authorization: `Bearer ${ticket}` },
          body: blob.subarray(offset, end) as Uint8Array<ArrayBuffer>,
          cache: "no-store",
          signal: within(signal),
        });
      } catch (e) {
        if (signal?.aborted) throw new Error(CANCELLED);
        pace.cut();
        await patience.wait(`the upload was cut off (${message(e)})`);
        continue;
      }
      void res.body?.cancel();
      switch (res.status) {
        case 201:
          return "stored";
        case 204:
        case 409: {
          const raw = res.headers.get("upload-offset");
          const next = raw === null ? NaN : Number(raw);
          if (!Number.isSafeInteger(next) || next < 0 || next > blob.length) {
            throw new Error("the server sent a bad upload offset");
          }
          if (res.status === 204) pace.took(next - offset, performance.now() - started);
          if (next === offset) {
            // Our last chunk is still being read there
            await patience.wait("the upload does not move");
          } else {
            patience.moved();
            await yieldToVoice(call, started);
          }
          offset = next;
          this.progress(op, "up", offset, blob.length);
          break;
        }
        case 404:
          return "gone";
        case 429:
          await patience.wait("the server is too busy");
          break;
        case 413:
          throw new Error("the file is larger than this server takes");
        case 422:
          throw new Error("the server says the bytes are not this file");
        default:
          throw new Error(`the server refused the upload (${res.status})`);
      }
    }
  }

  /** Download the blob with `ticket` into `have`, from where it stops. */
  private async get(
    ticket: string,
    hash: string,
    have: { buf: Uint8Array; n: number },
    op: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<"all" | "gone"> {
    const url = `${this.origin}/f/v1/${hash}`;
    const size = have.buf.length;
    const pace = new Pace();
    const patience = new Patience(signal);
    while (have.n < size) {
      const start = have.n;
      const call = this.host.inCall();
      const end = Math.min(start + pace.next(call), size) - 1;
      const started = performance.now();
      let res: Response;
      let body: Uint8Array | null = null;
      try {
        res = await fetch(url, {
          headers: { authorization: `Bearer ${ticket}`, range: `bytes=${start}-${end}` },
          cache: "no-store",
          signal: within(signal),
        });
        if (res.status === 206) body = new Uint8Array(await res.arrayBuffer());
        else void res.body?.cancel();
      } catch (e) {
        if (signal?.aborted) throw new Error(CANCELLED);
        pace.cut();
        await patience.wait(`the download was cut off (${message(e)})`);
        continue;
      }
      if (body) {
        const n = body.length;
        const sent = contentRange(res.headers.get("content-range"));
        if (n === 0 || !sent || sent[0] !== start || sent[1] !== start + n - 1 || sent[2] !== size || start + n - 1 > end) {
          throw new Error("the server sent other bytes than asked for");
        }
        have.buf.set(body, start);
        have.n += n;
        pace.took(n, performance.now() - started);
        patience.moved();
        this.progress(op, "down", have.n, size);
        if (have.n < size) await yieldToVoice(call, started);
        continue;
      }
      switch (res.status) {
        case 404:
          return "gone";
        case 429:
          await patience.wait("the server is too busy");
          break;
        default:
          throw new Error(`the server refused the download (${res.status})`);
      }
    }
    return "all";
  }
}

// ── Cancel ──────────────────────────────────────────────────────────────

/** Transfers the front end can cancel, by the id it gave them. */
const ops = new Map<string, AbortController>();

async function cancellable<T>(op: string | undefined, work: (signal?: AbortSignal) => Promise<T>): Promise<T> {
  if (!op) return work();
  const ctl = new AbortController();
  ops.set(op, ctl);
  try {
    return await work(ctl.signal);
  } finally {
    if (ops.get(op) === ctl) ops.delete(op);
  }
}

export function cancel(op: string): void {
  ops.get(op)?.abort();
}

// ── Cache ───────────────────────────────────────────────────────────────

/** Blob id → blob. Map order is use order: the first is the least recent. */
const cache = new Map<string, { blob: Uint8Array; lastUsed: number }>();
let cacheBytes = 0;

function cacheGet(hash: string): Uint8Array | undefined {
  const kept = cache.get(hash);
  if (!kept) return undefined;
  cache.delete(hash);
  kept.lastUsed = Date.now();
  cache.set(hash, kept);
  return kept.blob;
}

function cacheDelete(hash: string): void {
  const kept = cache.get(hash);
  if (!kept) return;
  cache.delete(hash);
  cacheBytes -= kept.blob.length;
}

/** Keep `blob`, then let the least recently used go past the cap (never `blob`). */
function cachePut(hash: string, blob: Uint8Array): void {
  cacheDelete(hash);
  cache.set(hash, { blob, lastUsed: Date.now() });
  cacheBytes += blob.length;
  for (const h of cache.keys()) {
    if (cacheBytes <= CACHE_CAP) break;
    if (h !== hash) cacheDelete(h);
  }
}

/** The blobs this tab keeps, and the most it keeps (bytes). */
export function cacheList(): { cap: number; entries: { hash: string; bytes: number; last_used: number }[] } {
  return { cap: CACHE_CAP, entries: [...cache].map(([hash, k]) => ({ hash, bytes: k.blob.length, last_used: k.lastUsed })) };
}

/** Let go of these blobs now: the media manager's "remove". */
export function cacheRemove(hashes: readonly string[]): void {
  for (const h of hashes) cacheDelete(h);
}

/** Let go of every blob but `keep` that has not been used for a while. */
export function cacheRetain(keep: Set<string>): void {
  const now = Date.now();
  for (const [hash, k] of [...cache]) {
    if (!keep.has(hash) && now - k.lastUsed >= RETAIN_GRACE_MS) cacheDelete(hash);
  }
}

// ── Seal and open, in a worker ──────────────────────────────────────────

/** The whole of `bytes` as an ArrayBuffer, as Tauri hands a raw answer over. */
function whole(bytes: Uint8Array): ArrayBuffer {
  const exact = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
  return (exact ? bytes.buffer : bytes.slice().buffer) as ArrayBuffer;
}

/** Workers at once: each holds a wasm instance of some three times its file. */
const MAX_WORKERS = 2;
/** Jobs that read a picture (or a pack of them) somebody else made, and how
 *  long one may take. */
const PICTURE_JOBS = new Set(["image", "sanitize", "pack", "strip"]);
const PICTURE_TIME_MS = 30_000;
let workers = 0;
const waitingForWorker: (() => void)[] = [];

/**
 * One job in a fresh worker, which is ended afterwards. Its input is copied,
 * never moved, except what `give` names: a buffer nobody else holds, which
 * the worker hands back in `back`. The caller's bytes (the cache's, the
 * page's) stay theirs.
 */
async function inWorker<T>(job: Record<string, unknown>, give?: Uint8Array): Promise<T> {
  if (workers >= MAX_WORKERS) await new Promise<void>((r) => waitingForWorker.push(r));
  workers++;
  const worker = new Worker(new URL("./file-worker.ts", import.meta.url), { type: "module" });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await new Promise<T>((resolve, reject) => {
      // A picture's budgets bound its work, and this bounds whatever they
      // miss: ended, the worker frees its place for the next job
      if (PICTURE_JOBS.has(String(job.op))) timer = setTimeout(() => reject(new Error("the picture took too long to read")), PICTURE_TIME_MS);
      worker.onmessage = (e: MessageEvent) => {
        const { ok, error } = e.data ?? {};
        if (!error) return resolve(ok as T);
        const err = new Error(String(error.message));
        err.name = String(error.name);
        reject(err);
      };
      worker.onerror = (e) => reject(new Error(e.message || "the file worker failed"));
      worker.onmessageerror = () => reject(new Error("the file worker's answer did not arrive"));
      worker.postMessage({ module: wasmModule(), ...job, give }, give ? [give.buffer] : []);
    });
  } finally {
    clearTimeout(timer);
    worker.terminate();
    workers--;
    waitingForWorker.shift()?.();
  }
}

interface Sealed extends FileArg {
  blob: Uint8Array;
}

/** Open `blob`: copied (a cached one stays the cache's), or moved and given
 *  back (one just fetched: no copy of up to 64 MiB on this thread). */
function openInWorker(file: FileArg, blob: Uint8Array, move = false): Promise<{ plain: Uint8Array; blob: Uint8Array }> {
  return move
    ? inWorker({ op: "open", ...file }, blob)
    : inWorker<{ plain: Uint8Array }>({ op: "open", ...file, blob }).then(({ plain }) => ({ plain, blob }));
}

// ── The commands ────────────────────────────────────────────────────────

/** send_file: seal `plain`, store it on the relay for a message in `conv`,
 *  keep the blob; the message is the front end's to send. */
export async function sendFile(
  files: Files,
  conv: Conv,
  plain: Uint8Array,
  compress: boolean,
  op?: string,
): Promise<FileArg> {
  if (plain.length > MAX_FILE_PLAIN) throw new Error("the file is larger than 64 MiB");
  // A cancel while it seals counts too
  const sealed = await cancellable(op, async (signal) => {
    const sealed = await inWorker<Sealed>({ op: "seal", plain, compress });
    if (signal?.aborted) throw new Error(CANCELLED);
    await files.upload(conv, sealed.hash, sealed.blob, op, signal);
    return sealed;
  });
  cachePut(sealed.hash, sealed.blob);
  return { hash: sealed.hash, key: sealed.key, size: sealed.size, z: sealed.z };
}

/** fetch_file: the file a message names, opened, from the cache or else the
 *  relay. `files` is null when `server` is not connected. */
export async function fetchFile(
  files: Files | null,
  server: string,
  conv: Conv,
  file: FileArg,
  op?: string,
): Promise<ArrayBuffer> {
  const kept = cacheGet(file.hash);
  if (kept) {
    try {
      return whole((await openInWorker(file, kept)).plain);
    } catch (e) {
      // Only bytes that are not the blob go, to be fetched again. Any other
      // error is the message's (a key, size or deflate flag that do not open
      // this blob): the copy stays for the messages that name it rightly,
      // so one that copies a real file's id cannot make us drop it (R3-02)
      if ((e as Error)?.name !== "NotThisFile") throw e;
      console.debug("a cached file is not its blob, fetching it again:", message(e));
      cacheDelete(file.hash);
    }
  }
  if (!files) throw new Error(`Not connected to ${server}`);
  const fetched = await cancellable(op, (signal) => files.fetch(conv, file.hash, op, signal));
  const { plain, blob } = await openInWorker(file, fetched, true);
  cachePut(file.hash, blob);
  return whole(plain);
}

/** file_image: a picture file as the PNG it may be shown as, opened and
 *  sanitized in one worker job (media.ts): its own bytes never reach the page.
 *  Fetched first where this tab does not keep it. Framed as the desktop
 *  app's (files.rs `file_image`): a JSON head saying why a moving picture
 *  stands still when it does, its length first, then the PNG. */
export async function fileImage(
  files: Files | null,
  server: string,
  conv: Conv,
  file: FileArg,
  profile: number,
  op?: string,
  still = false,
): Promise<ArrayBuffer> {
  // The first frame alone where the person wants nothing to move
  // A copy: what is kept here stays the cache's
  const pick = (m: Sanitized) => framePicture((still && m.still) || m.png, stilledOf(m));
  const motion = files?.motion ?? null;
  const key = `${file.hash}:${file.key}-${profile}-${motion?.side}-${motion?.keepMb}`;
  const hit = made.get(key);
  if (hit) {
    made.delete(key);
    made.set(key, hit);
    return pick(hit);
  }
  let blob = cacheGet(file.hash);
  if (!blob) {
    await fetchFile(files, server, conv, file, op);
    blob = cacheGet(file.hash);
    if (!blob) throw new Error("The file is not on this device");
  }
  const media = await mediaModule();
  const out = await inWorker<Sanitized>({ op: "image", ...file, blob, profile, media, motion });
  made.set(key, out);
  let bytes = [...made.values()].reduce((n, m) => n + m.png.length + (m.still?.length ?? 0), 0);
  for (const [k, m] of made) {
    if (bytes <= MADE_BYTES || made.size <= 1) break;
    made.delete(k);
    bytes -= m.png.length + (m.still?.length ?? 0);
  }
  return pick(out);
}

/** Why a moving picture stands still, when it does (voipc-media
 *  `Clean::stilled`, set exactly when `trimmed` left it one frame): the
 *  crate's own words where the worker hands them on, else its words for a
 *  frame too big. */
function stilledOf(m: Sanitized & { stilled?: string | null }): string | null {
  return m.stilled || (m.frames === 1 && m.trimmed ? "the animation is too big to play here" : null);
}

/** `png` behind a JSON head of `{ stilled }`, its length first (4 bytes
 *  little-endian): what `file_image` answers, here as in the desktop app. */
function framePicture(png: Uint8Array, stilled: string | null): ArrayBuffer {
  const head = new TextEncoder().encode(JSON.stringify({ stilled }));
  const out = new Uint8Array(4 + head.length + png.length);
  new DataView(out.buffer).setUint32(0, head.length, true);
  out.set(head, 4);
  out.set(png, 4 + head.length);
  return out.buffer;
}

/** Chat pictures made lately, by file and how (files.rs `file_image`'s
 *  twin): cards come and go as a channel scrolls, and making one again is a
 *  decrypt and a sanitize. Oldest first. */
const made = new Map<string, Sanitized>();
const MADE_BYTES = 64 << 20;

/** Any picture `bytes` (one picked from this device, an emote's) as `profile`,
 *  sanitized in a worker. */
export async function sanitizeImage(bytes: Uint8Array, profile: number, maxOut = 0): Promise<Sanitized> {
  return inWorker<Sanitized>({ op: "sanitize", bytes, profile, maxOut, media: await mediaModule() });
}

/** Any picture `bytes` without their metadata, in a worker (voipc-media `strip`). */
export async function stripImage(bytes: Uint8Array): Promise<Uint8Array> {
  return inWorker<Uint8Array>({ op: "strip", bytes, media: await mediaModule() });
}

/** The files of a .zip or .wastickers an admin picked, read in a worker. */
export async function readPack(bytes: Uint8Array): Promise<Pack> {
  return inWorker({ op: "pack", bytes, media: await mediaModule() });
}

/** forward_file: post the file this tab holds as `hash` in `conv` too (a
 *  forward): the same blob, with the same key, registered for that
 *  conversation. The relay keeps one copy and answers at once while it has
 *  it; else the copy kept here goes up (files.rs `forward_file`). */
export async function forwardFile(files: Files, conv: Conv, hash: string, op?: string): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("invalid hash");
  const blob = cacheGet(hash);
  if (!blob) throw new Error("The file is not on this device");
  await cancellable(op, (signal) => files.upload(conv, hash, blob, op, signal));
}

/** One re-seed at a time, across every server, the others in line (files.rs
 *  `reseed_file`); past this many waiting, a relay's asks are let go. */
const MAX_RESEEDS_WAITING = 16;
let reseeds = Promise.resolve();
let reseedsWaiting = 0;

/** reseed_file: the front end found a message in `conv` that refers to the
 *  blob the relay asked for. Silent. */
export function reseedFile(files: Files, conv: Conv, hash: string): void {
  if (!cache.has(hash) || reseedsWaiting >= MAX_RESEEDS_WAITING) return;
  reseedsWaiting++;
  reseeds = reseeds.then(async () => {
    reseedsWaiting--;
    try {
      await sleep(Math.random() * 2000);
      const blob = cacheGet(hash);
      if (blob) await files.upload(conv, hash, blob);
    } catch (e) {
      console.debug("re-seed of a file ended:", message(e));
    }
  });
}
