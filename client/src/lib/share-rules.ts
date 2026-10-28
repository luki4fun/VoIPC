// Pure rules of the browser screen sharer (web/backend/share.ts) and viewer
// (web/backend/video.ts), here so Node can test them. Each mirrors the native
// side: client/src-tauri/src/screenshare/mod.rs, or voipc-video.

/** voipc_video::KEYFRAME_INTERVAL_SECS, in ms: the periodic IDR, a safety net. */
export const KEYFRAME_INTERVAL_MS = 4000;
/** Least time between two keyframes forced into an uplink that is backed up. */
const FORCED_KEY_SPACING_MS = 1000;

/**
 * Pacing on the capture clock (mod.rs encode_at): the deadline a frame stamped
 * `tsUs` sets for the next one, or null when it is held back (the sharer's tick
 * encodes it if nothing newer comes). A quarter interval early still counts as
 * on time, and the deadline steps by one interval rather than from the frame,
 * so the average rate holds while single frames wobble. A clock that went back
 * by over a second is a new clock.
 */
export function paceFrame(dueUs: number, tsUs: number, intervalUs: number): number | null {
  if (dueUs - tsUs > 1_000_000) return tsUs;
  if (tsUs + intervalUs / 4 < dueUs) return null;
  return Math.max(dueUs + intervalUs, tsUs);
}

/**
 * Whether the next frame is encoded as a keyframe: asked for, or the periodic
 * one is due. An IDR is the largest thing we send, and one per frame into a
 * full uplink is a keyframe storm, so while frames are backed up keys are
 * spaced out (native: must_block makes a key wait).
 */
export function shouldForceKey(
  asked: boolean,
  sinceKeyMs: number,
  sinceForcedMs: number,
  backlog: number,
): boolean {
  if (!asked && sinceKeyMs < KEYFRAME_INTERVAL_MS) return false;
  return backlog === 0 || sinceForcedMs >= FORCED_KEY_SPACING_MS;
}

/**
 * voipc_video::MAX_DECODE_PIXELS: the largest picture the desktop viewer
 * decodes. Every share resolution (1080p at most) fits, either way up.
 */
export const MAX_DECODE_PIXELS = 2048 * 2048;

/**
 * Whether a decoded frame is larger than any VoIPC viewer shows, in the
 * pixels it holds or in the size it asks to be drawn at (the canvas is sized
 * to that). Only a modified sharer sends one (S-044).
 */
export function frameTooLarge(f: {
  codedWidth: number;
  codedHeight: number;
  displayWidth: number;
  displayHeight: number;
}): boolean {
  return f.codedWidth * f.codedHeight > MAX_DECODE_PIXELS || f.displayWidth * f.displayHeight > MAX_DECODE_PIXELS;
}
