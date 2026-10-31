// The server's emotes and stickers (protocol v14) in the browser: the twin of
// client/src-tauri/src/emotes.rs. Each file is fetched once with this
// session's bearer, checked against its hash, sanitized in a worker (media.ts)
// and kept in IndexedDB only as the PNG written for it, under the sanitizer's
// version: a decoder fix makes every one again.

import { toHex } from "../../lib/hex";
import { yieldToVoice, type FileHost } from "./files";
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
/** How long one request about an emote's file may take (files.rs REQUEST_TIME). */
const REQUEST_MS = 90_000;
/** How long a picture no open server lists stays in IndexedDB. */
const UNLISTED_KEPT_MS = 30 * 24 * 3600 * 1000;

export interface EmoteLimits {
  max_emote_bytes: number;
  max_sticker_bytes: number;
  max_total_bytes: number;
  max_items: number;
}

export interface EmoteAccess extends EmoteLimits {
  token: string;
}

/** `Authenticated.emotes`' numbers (network.rs emits the same). */
export function emoteLimitsOf(b: Body): EmoteLimits {
  return {
    max_emote_bytes: Number(b.max_emote_bytes),
    max_sticker_bytes: Number(b.max_sticker_bytes),
    max_total_bytes: Number(b.max_total_bytes),
    max_items: Number(b.max_items),
  };
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

/** Where this browser keeps no IndexedDB (a private window): the PNGs made
 *  this page, which would otherwise be made again for every view. */
const memory = new Map<string, Uint8Array>();

/** A PNG as kept: with when a list last named it (1.4 kept the PNG alone). */
interface Kept {
  png: Uint8Array;
  at: number;
}
const pngOf = (v: unknown): Uint8Array | null => (v instanceof Uint8Array ? v : v && (v as Kept).png instanceof Uint8Array ? (v as Kept).png : null);

async function cacheGet(key: string): Promise<Uint8Array | null> {
  const d = await store();
  if (!d) return memory.get(key) ?? null;
  return new Promise((resolve) => {
    const r = d.transaction(PNGS).objectStore(PNGS).get(key);
    r.onsuccess = () => resolve(pngOf(r.result));
    r.onerror = () => resolve(null);
  });
}

async function cachePut(key: string, png: Uint8Array): Promise<void> {
  const d = await store();
  if (d) d.transaction(PNGS, "readwrite").objectStore(PNGS).put({ png, at: Date.now() } satisfies Kept, key);
  else memory.set(key, png);
}

/** emote_cache_retain, in the browser: what this tab's servers list is kept,
 *  from now on; an older sanitizer's PNGs go; any other once unlisted for
 *  `UNLISTED_KEPT_MS` (other tabs of this origin share the store, and renew
 *  their own servers' this way). */
export async function retain(keep: string[]): Promise<void> {
  const v = await sanitizerVersion();
  const listed = new Set(keep);
  for (const k of [...memory.keys()]) if (!listed.has(k.split("-")[0])) memory.delete(k);
  const d = await store();
  if (!d) return;
  const os = d.transaction(PNGS, "readwrite").objectStore(PNGS);
  const now = Date.now();
  const r = os.openCursor();
  r.onsuccess = () => {
    const c = r.result;
    if (!c) return;
    const key = String(c.key);
    const png = pngOf(c.value);
    const at = (c.value as Partial<Kept>)?.at ?? 0;
    if (!key.includes(`-${v}-`) || !png) c.delete();
    else if (listed.has(key.split("-")[0])) c.update({ png, at: now } satisfies Kept);
    else if (now - at > UNLISTED_KEPT_MS) c.delete();
    c.continue();
  };
}

/** emote_missing: which of `items` this browser has made nothing of yet, as
 *  `hash|s` or `hash|e`. */
export async function missing(items: { hash: string; sticker: boolean }[]): Promise<string[]> {
  const v = await sanitizerVersion();
  const out: string[] = [];
  for (const { hash, sticker } of items) {
    if (!(await cacheGet(`${hash}-${v}-${sticker ? "s" : "e"}`))) out.push(`${hash}|${sticker ? "s" : "e"}`);
  }
  return out;
}

/** emote_cache_size: what the PNGs kept here take (this origin's, every tab's). */
export async function cacheSize(): Promise<number> {
  let n = [...memory.values()].reduce((sum, p) => sum + p.length, 0);
  const d = await store();
  if (!d) return n;
  return new Promise((resolve) => {
    const r = d.transaction(PNGS).objectStore(PNGS).openCursor();
    r.onsuccess = () => {
      const c = r.result;
      if (!c) return resolve(n);
      n += pngOf(c.value)?.length ?? 0;
      c.continue();
    };
    r.onerror = () => resolve(n);
  });
}

/** emote_cache_clear: all of them gone, to be made again when next shown. */
export async function cacheClear(): Promise<void> {
  memory.clear();
  const d = await store();
  d?.transaction(PNGS, "readwrite").objectStore(PNGS).clear();
}

/** emote_seed: this admin's own import's preview and still, kept as if
 *  fetched (emotes.rs `emote_seed`). */
export async function seed(hash: string, sticker: boolean, png: Uint8Array, still: Uint8Array | null): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("invalid hash");
  const base = `${hash}-${await sanitizerVersion()}-${sticker ? "s" : "e"}`;
  if (await cacheGet(base)) return;
  if (still) await cachePut(`${base}-still`, still);
  await cachePut(base, png);
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
        len: Number(e.len),
        w: Number(e.w),
        h: Number(e.h),
      }));
      // An add the relay answered with the list: it had the file
      for (const e of emotes) this.answer((w) => w.name === e.name && w.hash === e.hash, (w) => w.done(null));
      this.host.emit("emote-list", { stickers: !!b?.stickers, emotes });
    } else if (tag === "EmoteTicket") {
      const hash = toHex(b.hash);
      const name = String(b.name);
      this.answer((w) => w.hash === hash && w.name === name, (w) => w.done(String(b.ticket)));
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

  /** emote_image: the PNG an emote may be shown as (its still, with `still`);
   *  with `fetchOnly`, only made into the cache, and nothing is answered. */
  async image(hash: string, sticker: boolean, still: boolean, fetchOnly = false, len = 0): Promise<ArrayBuffer> {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("invalid hash");
    const base = `${hash}-${await sanitizerVersion()}-${sticker ? "s" : "e"}`;
    const kept = (still && !fetchOnly ? await cacheGet(`${base}-still`) : null) ?? (await cacheGet(base));
    if (kept) return fetchOnly ? new ArrayBuffer(0) : (kept.slice().buffer as ArrayBuffer);
    const out = await this.sanitize(await this.file(hash, sticker, len), sticker ? 1 : 0);
    // The still first: a PNG kept means its still is too
    if (out.still) await cachePut(`${base}-still`, out.still);
    await cachePut(base, out.png);
    return fetchOnly ? new ArrayBuffer(0) : (((still && out.still) || out.png).slice().buffer as ArrayBuffer);
  }

  /** emote_file: an emote's file as the server keeps it, checked against its
   *  hash. Never shown: sanitized first, or handed back to emote_add. */
  async file(hash: string, sticker?: boolean, len = 0): Promise<Uint8Array> {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("invalid hash");
    if (!this.access) throw new Error("this server has no emotes");
    const { max_emote_bytes: emote, max_sticker_bytes: stickers } = this.access;
    // Its size where the list said it, else the most its kind may be
    const cap = len > 0 ? len : sticker === false ? emote : sticker ? stickers : Math.max(emote, stickers);
    const [call, started] = [this.host.inCall(), performance.now()];
    // As long as the app's own request may take (files.rs REQUEST_TIME): a
    // stalled answer must not hold one of the few loading places for good
    const res = await fetch(this.url(hash), {
      headers: { Authorization: `Bearer ${this.access.token}` },
      signal: AbortSignal.timeout(REQUEST_MS),
    });
    if (!res.ok) throw new Error(`the server would not give the emote (${res.status})`);
    const body = await capped(res, cap);
    if ((await sha256(body)) !== hash) throw new Error("the server gave another file than the emote's");
    // A server's emotes are many files at once: in a call they give way to
    // voice as a file's chunks do
    await yieldToVoice(call, started);
    return body;
  }

  /** emote_add: what prepare_emote said to upload, added as `name`, `w` × `h`
   *  as it made it. */
  async add(name: string, sticker: boolean, pack: string, bytes: Uint8Array, w = 0, h = 0): Promise<void> {
    const hash = await sha256(bytes);
    this.host.sendControl({ EmoteAdd: { emote: { name, hash: fromHex(hash), sticker, pack, len: bytes.length, w, h } } });
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
      signal: AbortSignal.timeout(REQUEST_MS),
    });
    if (res.status !== 201) throw new Error((await res.text()) || `refused (${res.status})`);
  }

  remove(names: string[]): void {
    this.host.sendControl({ EmoteRemove: { names } });
  }

  move(names: string[], pack: string | null, sticker: boolean | null): void {
    this.host.sendControl({ EmoteMove: { names, pack, sticker } });
  }

  rename(from: string, to: string): void {
    this.host.sendControl({ EmoteRename: { from, to } });
  }

  setStickers(on: boolean): void {
    this.host.sendControl({ EmoteStickers: { on } });
  }
}

/** An answer's body, refused once past `cap` bytes (native reads at most a
 *  chunk): a hostile relay cannot fill the tab's memory. */
async function capped(res: Response, cap: number): Promise<Uint8Array> {
  if (Number(res.headers.get("content-length") ?? 0) > cap) {
    void res.body?.cancel();
    throw new Error("the server gave more than an emote may be");
  }
  const parts: Uint8Array[] = [];
  let n = 0;
  const reader = res.body!.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > cap) {
      void reader.cancel();
      throw new Error("the server gave more than an emote may be");
    }
    parts.push(value);
  }
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** prepare_emote, in the browser: the same answer as the desktop's (a JSON
 *  head, then the upload, the preview and its still). See emotes.rs. */
export async function prepareEmote(
  sanitize: Sanitize,
  strip: (bytes: Uint8Array) => Promise<Uint8Array>,
  src: Uint8Array,
  sticker: boolean,
  maxBytes: number,
): Promise<ArrayBuffer> {
  const profile = sticker ? 1 : 0;
  const full = await sanitize(src, profile);
  // The file as it is goes without its metadata: emotes are readable by every
  // member. Where that cannot be (a turned JPEG), it is made again
  const bare = full.stilled || (full.png.length <= maxBytes && !full.trimmed) ? null : await strip(src).catch(() => null);
  let upload: Uint8Array;
  let how: string;
  // Too long to move (shown as its first frame): that frame goes up, never the
  // whole animation every member would stop too
  if (full.stilled) [upload, how] = full.png.length <= maxBytes ? [full.png, "still"] : [(await sanitize(src, profile, maxBytes)).png, "still"];
  else if (full.png.length <= maxBytes && !full.trimmed) [upload, how] = [full.png, "clean"];
  else if (bare && bare.length <= maxBytes) [upload, how] = [bare, "original"];
  else {
    const fit = await sanitize(src, profile, maxBytes);
    [upload, how] = [fit.png, fit.frames > 1 ? "trimmed" : "still"];
  }
  const still = full.still ?? new Uint8Array();
  const head = new TextEncoder().encode(
    JSON.stringify({ w: full.w, h: full.h, frames: full.frames, how, upload: upload.length, preview: full.png.length, still: still.length, stilled: full.stilled }),
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
