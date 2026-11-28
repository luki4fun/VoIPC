// Test builds only (every call site sits behind `if (__SELFTEST__)`, so a release bundle
// carries none of it): when the sharer handed each video frame to the link and how big it
// was, when each voice packet left one browser and reached the other, and how late the main
// thread ran meanwhile. The capped-link lane prints it (selftest.ts), to show which frames
// voice lost its packets behind.

/** Wall clock with sub-ms resolution: two browsers on one machine read the same one. */
export const traceNow = (): number => performance.timeOrigin + performance.now();

/** Rows kept of each kind: a lane's first seconds of a share, and its whole talk. */
const MOST = 2400;

/** Each frame the sharer had out of its encoder: [at, bytes, key, level, sent, in flight, paced ms]. */
export const traceFrames: number[][] = [];
/** Each frame the transport wrote: [handed, stream open, written, closed, bytes]. */
export const traceWrites: number[][] = [];
/** Each voice packet this page sent: [sequence, at]. */
export const traceVoiceOut: number[][] = [];
/** Each voice packet this page received: [session, sequence, at]. */
export const traceVoiceIn: number[][] = [];
/** The main thread ran this late (ms, 25 and more) at: [at, late]. */
export const traceLag: number[][] = [];

const push = (rows: number[][], row: number[]) => {
  if (rows.length < MOST) rows.push(row);
};

export function traceFrame(bytes: number, key: boolean, level: number, sent: boolean, inFlight: number, pacedMs = 0): void {
  push(traceFrames, [Math.round(traceNow() * 10) / 10, bytes, key ? 1 : 0, level, sent ? 1 : 0, inFlight, Math.round(pacedMs)]);
}

/** A frame's write, stage by stage; `row` is what `traceWriteStart` gave. */
export function traceWriteStart(bytes: number): number[] {
  const row = [Math.round(traceNow() * 10) / 10, 0, 0, 0, bytes];
  push(traceWrites, row);
  return row;
}
export function traceWriteStage(row: number[], stage: 1 | 2 | 3): void {
  row[stage] = Math.round(traceNow() * 10) / 10;
}

/** A voice packet (type 0x05) going out or coming in: its header says who and which. */
export function traceVoice(bytes: Uint8Array, out: boolean): void {
  if (bytes.length < 9 || bytes[0] !== 0x05) return;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const session = dv.getUint32(1);
  const seq = dv.getUint32(5);
  const at = Math.round(traceNow() * 10) / 10;
  if (out) push(traceVoiceOut, [seq, at]);
  else push(traceVoiceIn, [session, seq, at]);
}

let lagTimer: ReturnType<typeof setInterval> | null = null;
/** From now on, note each time a 10 ms timer came 25 ms or more late. */
export function traceLagStart(): void {
  if (lagTimer !== null) return;
  let last = performance.now();
  lagTimer = setInterval(() => {
    const now = performance.now();
    const late = now - last - 10;
    last = now;
    if (late >= 25) push(traceLag, [Math.round(traceNow()), Math.round(late)]);
  }, 10);
}
