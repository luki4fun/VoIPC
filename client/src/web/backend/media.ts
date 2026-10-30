// The picture sanitizer (crates/voipc-media-wasm) for the browser: a picture
// somebody else made is decoded by it, inside a file worker, and only the PNG
// it writes reaches the page. The browser's own decoders never see the file.
//
// The page fetches and compiles the module once, the first time a picture is
// shown (`mediaModule`); each worker instantiates its own from it (`sanitizeIn`,
// `readPackIn`), and is ended afterwards with whatever the module held.

let compiled: Promise<WebAssembly.Module> | null = null;

/** The module, compiled once; fetched only when a picture is first shown. */
export function mediaModule(): Promise<WebAssembly.Module> {
  compiled ??= (async () => {
    const res = await fetch(new URL("../../lib/wasm/voipc_media.wasm", import.meta.url));
    if (!res.ok) throw new Error(`could not load the picture reader (HTTP ${res.status})`);
    return WebAssembly.compile(await res.arrayBuffer());
  })();
  compiled.catch(() => (compiled = null));
  return compiled;
}

/** How a moving chat picture is kept (voipc-media `Motion`): a server's
 *  `FileLimits.animation_side` and `animation_mb`. */
export interface Motion {
  side: number;
  keepMb: number;
}

/** A relay's numbers held to voipc-protocol's `ANIMATION_SIDE` and
 *  `ANIMATION_MB`, as the desktop app holds them: a relay cannot lift them. */
export function motionOf(limits: { animation_side?: unknown; animation_mb?: unknown }): Motion {
  const held = (v: unknown, lo: number, hi: number, d: number) => {
    const n = Number(v);
    return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.floor(n))) : d;
  };
  return { side: held(limits.animation_side, 256, 2560, 1024), keepMb: held(limits.animation_mb, 16, 512, 128) };
}

interface Exports {
  memory: WebAssembly.Memory;
  media_input(len: number): number;
  media_sanitize(profile: number, maxOut: number, side: number, keepMb: number): number;
  media_strip(): number;
  media_png(): number;
  media_png_len(): number;
  media_still(): number;
  media_still_len(): number;
  media_meta(i: number): number;
  media_error(): number;
  media_error_len(): number;
  media_read_pack(): number;
  media_pack_title(): number;
  media_pack_title_len(): number;
  media_skip_count(): number;
  media_skip_name(i: number): number;
  media_skip_name_len(i: number): number;
  media_skip_why(i: number): number;
  media_skip_why_len(i: number): number;
  media_entry_name(i: number): number;
  media_entry_name_len(i: number): number;
  media_entry_bytes(i: number): number;
  media_entry_bytes_len(i: number): number;
}

/** What `sanitizeIn` gives back: the PNG, and for a moving picture its first
 *  frame alone. */
export interface Sanitized {
  png: Uint8Array;
  still: Uint8Array | null;
  w: number;
  h: number;
  frames: number;
  trimmed: boolean;
}

function instance(module: WebAssembly.Module, input: Uint8Array): Exports {
  const x = new WebAssembly.Instance(module, {}).exports as unknown as Exports;
  const at = x.media_input(input.length);
  new Uint8Array(x.memory.buffer, at, input.length).set(input);
  return x;
}

/** A copy out of the instance's memory: it goes with the worker. */
const copy = (x: Exports, at: number, len: number) => new Uint8Array(x.memory.buffer, at, len).slice();
const text = (x: Exports, at: number, len: number) => new TextDecoder().decode(copy(x, at, len));

/** `bytes` as `profile` (0 emote, 1 sticker, 2 photo); `maxOut` 0 is the
 *  profile's own cap. Throws the reason it is not shown. */
export function sanitizeIn(module: WebAssembly.Module, bytes: Uint8Array, profile: number, maxOut = 0, motion?: Motion | null): Sanitized {
  const x = instance(module, bytes);
  if (x.media_sanitize(profile, maxOut, motion?.side ?? 0, motion?.keepMb ?? 0) !== 0) throw new Error(text(x, x.media_error(), x.media_error_len()));
  const stillLen = x.media_still_len();
  return {
    png: copy(x, x.media_png(), x.media_png_len()),
    still: stillLen > 0 ? copy(x, x.media_still(), stillLen) : null,
    w: x.media_meta(0),
    h: x.media_meta(1),
    frames: x.media_meta(2),
    trimmed: x.media_meta(3) === 1,
  };
}

/** `bytes` without their metadata (voipc-media `strip`), in a worker's
 *  instance; throws why not (a turned JPEG, a file not as its format says). */
export function stripIn(module: WebAssembly.Module, bytes: Uint8Array): Uint8Array {
  const x = instance(module, bytes);
  if (x.media_strip() !== 0) throw new Error(text(x, x.media_error(), x.media_error_len()));
  return copy(x, x.media_png(), x.media_png_len());
}

/** A .zip or .wastickers read: its pictures, and what was set aside with why. */
export interface Pack {
  title: string | null;
  entries: { name: string; bytes: Uint8Array }[];
  skipped: { name: string; why: string }[];
}

/** The files of a .zip or .wastickers, in memory. Throws why it is refused. */
export function readPackIn(module: WebAssembly.Module, bytes: Uint8Array): Pack {
  const x = instance(module, bytes);
  const n = x.media_read_pack();
  if (n === 0xffffffff) throw new Error(text(x, x.media_error(), x.media_error_len()));
  const title = text(x, x.media_pack_title(), x.media_pack_title_len());
  const entries = [];
  for (let i = 0; i < n; i++) {
    entries.push({
      name: text(x, x.media_entry_name(i), x.media_entry_name_len(i)),
      bytes: copy(x, x.media_entry_bytes(i), x.media_entry_bytes_len(i)),
    });
  }
  const skipped = [];
  for (let i = 0; i < x.media_skip_count(); i++) {
    skipped.push({ name: text(x, x.media_skip_name(i), x.media_skip_name_len(i)), why: text(x, x.media_skip_why(i), x.media_skip_why_len(i)) });
  }
  return { title: title || null, entries, skipped };
}
