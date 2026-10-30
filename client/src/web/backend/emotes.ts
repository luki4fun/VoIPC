// The server's emotes and stickers (protocol v14) in the browser: the twin of
// client/src-tauri/src/emotes.rs. Each file is fetched once with this
// session's bearer, checked against its hash, sanitized in a worker (media.ts)
// and kept in IndexedDB only as the PNG written for it, under the sanitizer's
// version: a decoder fix makes every one again.

import { toHex } from "../../lib/hex";
import type { FileHost } from "./files";
import { mediaModule, type Pack, type Sanitized } from "./media";

// The worker runner and the sanitize job live with the file worker's (files.ts)
type Sanitize = (bytes: Uint8Array, profile: number, maxOut?: number) => Promise<Sanitized>;

type Body = any; // eslint-disable-line @typescript-eslint/no-explicit-any

interface Wait {
  name: string;
  hash: string;
  done: (ticket: string | null) => void;
  fail: (e: Error) => void;
}

const ANSWER_MS = 30_000;

export interface EmoteAccess {
  token: string;
  max_emote_bytes: number;
  max_sticker_bytes: number;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>)));
}

function fromHex(h: string): number[] {
  return Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(i * 2, i * 2 + 2), 16));
}

// ── The cache ────────────────────────────────────────────────────────────

const DB = "voipc-emotes";
const PNGS = "png";
let version: Promise<number> | null = null;

/** crates/voipc-media `SANITIZER_VERSION`, from the module itself. */
function sanitizerVersion(): Promise<number> {
  version ??= mediaModule().then((m) => {
    const x = new WebAssembly.Instance(m, {}).exports as { media_version(): number };
    return x.media_version();
  });
  version.catch(() => (version = null));
  return version;
}

let db: Promise<IDBDatabase | null> | null = null;

/** The store, or null where this browser keeps none (a private window): then
 *  each emote is made again once per page. */
function store(): Promise<IDBDatabase | null> {
  db ??= new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(PNGS);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return db;
}

const memory = new Map<string, Uint8Array>();

async function cacheGet(key: string): Promise<Uint8Array | null> {
  const hit = memory.get(key);
  if (hit) return hit;
  const d = await store();
  if (!d) return null;
  return new Promise((resolve) => {
    const r = d.transaction(PNGS).objectStore(PNGS).get(key);
    r.onsuccess = () => resolve(r.result instanceof Uint8Array ? r.result : null);
    r.onerror = () => resolve(null);
  });
}

async function cachePut(key: string, png: Uint8Array): Promise<void> {
  memory.set(key, png);
  const d = await store();
  d?.transaction(PNGS, "readwrite").objectStore(PNGS).put(png, key);
}

/** emote_cache_retain, in the browser: this tab's hashes stay in memory,
 *  and only an older sanitizer's PNGs leave IndexedDB. Other tabs of this
 *  origin share it, with servers of their own; the browser evicts the rest. */
export async function retain(keep: string[]): Promise<void> {
  const v = await sanitizerVersion();
  for (const k of [...memory.keys()]) if (!keep.includes(k.split("-")[0])) memory.delete(k);
  const ok = (key: string) => key.includes(`-${v}-`);
  const d = await store();
  if (!d) return;
  const os = d.transaction(PNGS, "readwrite").objectStore(PNGS);
  const keys = await new Promise<IDBValidKey[]>((resolve) => {
    const r = os.getAllKeys();
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => resolve([]);
  });
  for (const k of keys) if (typeof k === "string" && !ok(k)) os.delete(k);
}

// ── One session's emotes ─────────────────────────────────────────────────

export class Emotes {
  private waits: Wait[] = [];

  constructor(
    private readonly host: FileHost,
    private readonly origin: string,
    readonly access: EmoteAccess | null,
    private readonly sanitize: Sanitize,
  ) {}

  /** An emote message from the relay. */
  onMessage(tag: string, b: Body): void {
    if (tag === "EmoteList") {
      const emotes = (Array.isArray(b?.emotes) ? b.emotes : []).map((e: Body) => ({
        name: String(e.name),
        hash: toHex(e.hash),
        sticker: !!e.sticker,
        pack: String(e.pack ?? ""),
      }));
      // An add the relay answered with the list: it had the file
      for (const e of emotes) this.answer((w) => w.name === e.name && w.hash === e.hash, (w) => w.done(null));
      this.host.emit("emote-list", { stickers: !!b?.stickers, emotes });
    } else if (tag === "EmoteTicket") {
      const hash = toHex(b.hash);
      this.answer((w) => w.hash === hash, (w) => w.done(String(b.ticket)));
    } else if (tag === "EmoteError") {
      const name = String(b?.name ?? "");
      const reason = String(b?.reason ?? "refused");
      if (!this.answer((w) => w.name === name, (w) => w.fail(new Error(reason)))) {
        this.host.emit("emote-error", { name, reason });
      }
    }
  }

  close(): void {
    for (const w of this.waits.splice(0)) w.fail(new Error("the connection to the server ended"));
  }

  private answer(pick: (w: Wait) => boolean, act: (w: Wait) => void): boolean {
    const at = this.waits.findIndex(pick);
    if (at < 0) return false;
    act(this.waits.splice(at, 1)[0]);
    return true;
  }

  private url(hash: string): string {
    return `${this.origin}/e/v1/${hash}`;
  }

  /** emote_image: the PNG an emote may be shown as (its still, with `still`). */
  async image(hash: string, sticker: boolean, still: boolean): Promise<ArrayBuffer> {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("invalid hash");
    const base = `${hash}-${await sanitizerVersion()}-${sticker ? "s" : "e"}`;
    const kept = (still ? await cacheGet(`${base}-still`) : null) ?? (await cacheGet(base));
    if (kept) return kept.slice().buffer as ArrayBuffer;
    const out = await this.sanitize(await this.file(hash), sticker ? 1 : 0);
    // The still first: a PNG kept means its still is too
    if (out.still) await cachePut(`${base}-still`, out.still);
    await cachePut(base, out.png);
    return ((still && out.still) || out.png).slice().buffer as ArrayBuffer;
  }

  /** emote_file: an emote's file as the server keeps it, checked against its
   *  hash. Never shown: sanitized first, or handed back to emote_add. */
  async file(hash: string): Promise<Uint8Array> {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("invalid hash");
    if (!this.access) throw new Error("this server has no emotes");
    // As long as the app's own request may take (files.rs REQUEST_TIME): a
    // stalled answer must not hold one of the few loading places for good
    const res = await fetch(this.url(hash), {
      headers: { Authorization: `Bearer ${this.access.token}` },
      signal: AbortSignal.timeout(90_000),
    });
    if (!res.ok) throw new Error(`the server would not give the emote (${res.status})`);
    const body = new Uint8Array(await res.arrayBuffer());
    if ((await sha256(body)) !== hash) throw new Error("the server gave another file than the emote's");
    return body;
  }

  /** emote_add: what prepare_emote said to upload, added as `name`. */
  async add(name: string, sticker: boolean, pack: string, bytes: Uint8Array): Promise<void> {
    const hash = await sha256(bytes);
    this.host.sendControl({ EmoteAdd: { emote: { name, hash: fromHex(hash), sticker, pack }, len: bytes.length } });
    // Its answer comes as a later message, so waiting from here misses none
    const ticket = await new Promise<string | null>((done, fail) => {
      const wait = { name, hash, done, fail };
      this.waits.push(wait);
      // This add's own wait: a retry of the same name and file has its own
      setTimeout(() => this.answer((w) => w === wait, () => fail(new Error("the server did not answer"))), ANSWER_MS);
    });
    if (ticket === null) return;
    const res = await fetch(this.url(hash), {
      method: "PUT",
      headers: { Authorization: `Bearer ${ticket}` },
      body: bytes as Uint8Array<ArrayBuffer>,
    });
    if (res.status !== 201) throw new Error((await res.text()) || `refused (${res.status})`);
  }

  remove(name: string): void {
    this.host.sendControl({ EmoteRemove: { name } });
  }

  rename(from: string, to: string): void {
    this.host.sendControl({ EmoteRename: { from, to } });
  }

  setStickers(on: boolean): void {
    this.host.sendControl({ EmoteStickers: { on } });
  }
}

/** prepare_emote, in the browser: the same answer as the desktop's (a JSON
 *  head, then the upload, the preview and its still). See emotes.rs. */
export async function prepareEmote(sanitize: Sanitize, src: Uint8Array, sticker: boolean, maxBytes: number): Promise<ArrayBuffer> {
  const profile = sticker ? 1 : 0;
  const full = await sanitize(src, profile);
  let upload: Uint8Array;
  let how: string;
  if (full.png.length <= maxBytes && !full.trimmed) [upload, how] = [full.png, "clean"];
  else if (src.length <= maxBytes) [upload, how] = [src, "original"];
  else {
    const fit = await sanitize(src, profile, maxBytes);
    [upload, how] = [fit.png, fit.frames > 1 ? "trimmed" : "still"];
  }
  const still = full.still ?? new Uint8Array();
  const head = new TextEncoder().encode(
    JSON.stringify({ w: full.w, h: full.h, frames: full.frames, how, upload: upload.length, preview: full.png.length, still: still.length }),
  );
  const out = new Uint8Array(4 + head.length + upload.length + full.png.length + still.length);
  new DataView(out.buffer).setUint32(0, head.length, true);
  let at = 4;
  for (const part of [head, upload, full.png, still]) {
    out.set(part, at);
    at += part.length;
  }
  return out.buffer;
}

/** read_emote_pack's answer, as the desktop's: a JSON head (the title, and
 *  each file's name and length), then the files back to back. */
export function packAnswer(pack: Pack): ArrayBuffer {
  const head = new TextEncoder().encode(
    JSON.stringify({ title: pack.title, entries: pack.entries.map((e) => ({ name: e.name, len: e.bytes.length })), skipped: pack.skipped }),
  );
  const out = new Uint8Array(4 + head.length + pack.entries.reduce((n, e) => n + e.bytes.length, 0));
  new DataView(out.buffer).setUint32(0, head.length, true);
  out.set(head, 4);
  let at = 4 + head.length;
  for (const e of pack.entries) {
    out.set(e.bytes, at);
    at += e.bytes.length;
  }
  return out.buffer;
}
