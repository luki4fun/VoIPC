// The body of a pull from the app's frame queue (client/src-tauri/src/view_queue.rs): one
// record per frame, `[u32 len][u8 flags][u32 seq][u64 assembled_ms]` little-endian, then
// `len` bytes of the frame.

export const HEADER = 17;
/** A keyframe. */
export const KEY = 1;
/** A frame went missing just before this one. */
export const GAP = 2;

export interface FrameRecord {
  flags: number;
  seq: number;
  /** Wall-clock ms when the app had it whole. */
  at: number;
  data: Uint8Array<ArrayBuffer>;
}

/** The frames in a body, in order; a record cut short ends it. */
export function* records(body: Uint8Array<ArrayBuffer>): Generator<FrameRecord> {
  const v = new DataView(body.buffer, body.byteOffset, body.byteLength);
  let p = 0;
  while (p + HEADER <= body.length) {
    const len = v.getUint32(p, true);
    if (p + HEADER + len > body.length) return;
    yield {
      flags: v.getUint8(p + 4),
      seq: v.getUint32(p + 5, true),
      at: Number(v.getBigUint64(p + 9, true)),
      data: body.subarray(p + HEADER, p + HEADER + len),
    };
    p += HEADER + len;
  }
}
