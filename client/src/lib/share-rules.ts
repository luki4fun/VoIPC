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
 * Quality ladder (mod.rs LEVELS): bitrate scale and fps divisor per level.
 * Level 0 is the configured quality.
 */
export const LEVELS: readonly (readonly [number, number])[] = [
  [1.0, 1],
  [0.6, 1],
  [0.4, 2],
  [0.25, 2],
];
/** Where a share's video starts: one level below its quality (mod.rs START_LEVEL). */
export const START_LEVEL = 1;
const LOSS_RECENT_MS = 2_000;
const STEP_DOWN_HOLD_MS = 3_000;
const STEP_UP_AFTER_MS = 30_000;
/** Loss-free time from the start of a share's video before its first climb. */
const FIRST_CLIMB_MS = 5_000;

/** The ladder's last change: the share's video starting, a climb, or a step down. */
export type LadderChange = "start" | "up" | "down";

/**
 * mod.rs next_level, verbatim. A share's video starts at START_LEVEL: started
 * at full quality, it overloaded a small uplink for the seconds before the
 * first loss report came back, and voice lost frames meanwhile (capped-link
 * lane, 2026-11-23). The first climb comes once the link has carried the start
 * FIRST_CLIMB_MS with no loss at all (the sharers count that from the first
 * frame out). Once a loss came after the start, climbs wait STEP_UP_AFTER_MS of
 * quiet, as every later climb does. A climb that meets loss goes back at once,
 * without the hold, so a link too small for the level above pays one loss
 * report for trying it.
 */
export function nextLevel(
  level: number,
  lossAgeMs: number,
  sinceChangeMs: number,
  last: LadderChange,
): number {
  const max = LEVELS.length - 1;
  if (lossAgeMs < LOSS_RECENT_MS) {
    if (level >= max) return level;
    return last === "up" || sinceChangeMs >= STEP_DOWN_HOLD_MS ? level + 1 : level;
  }
  if (level === 0) return level;
  if (last === "start" && lossAgeMs >= sinceChangeMs) {
    // No loss since the video started (any loss is older than the start)
    return sinceChangeMs >= FIRST_CLIMB_MS ? level - 1 : level;
  }
  return lossAgeMs >= STEP_UP_AFTER_MS && sinceChangeMs >= STEP_UP_AFTER_MS ? level - 1 : level;
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

// ── Watching through a media edge (protocol 26, 1.15) ──────────────────────
// The relay may send a viewer to an edge for a big share (ServerMessage::WatchAt).
// Native mirror: client/src-tauri/src/edge_view.rs.

/**
 * How long a viewer on an edge waits for a complete, decrypted frame of the share
 * before it tells the relay the edge failed (`EdgeFailed`). A still screen still
 * sends a keyframe every KEYFRAME_INTERVAL_MS, so this is more than two of them.
 */
export const EDGE_SILENT_MS = 10_000;
/** voipc_protocol::pool::MAX_CERT_HASHES: an edge's certificate and those it rotates to. */
export const MAX_EDGE_CERT_HASHES = 4;
/** voipc_protocol::pool::MAX_TICKET_BYTES: the longest ticket an app passes on. */
export const MAX_EDGE_TICKET_BYTES = 256;

/** Bytes as wasm decodes them (`number[]`), or already copied. */
type Bytes = ArrayLike<number>;

/** `WatchAt.edge` as wasm decodes it (voipc_protocol::types::EdgeView). */
export interface EdgeTarget {
  /** A DNS name or a bare IP literal: an IPv6 one has no brackets. */
  host: string;
  port: number;
  /** SHA-256 of the edge's certificates, newest first. */
  cert_hashes: Bytes[];
  /** Opaque: shown to the edge as it came. */
  ticket: Bytes;
}

/**
 * Whether the viewer tells the relay its edge failed, from silence alone: no
 * complete, decrypted frame of the share for EDGE_SILENT_MS since `sinceMediaMs`,
 * the latest of that frame, the edge's Ready and the last `EdgeFailed`. So a
 * relay that does not answer (it ignores a share that itself sends nothing) is
 * told again after another 10 s, and no more often. Records, screen audio and
 * frames that fail to decrypt never move `sinceMediaMs`, which is how an edge
 * that forwards only those still trips this.
 *
 * `settled`: the link is past its setup, which has bounds of its own and fails
 * at once; false while it connects, or waits its turn to.
 */
export function edgeFailedDue(nowMs: number, sinceMediaMs: number, settled: boolean): boolean {
  return settled && nowMs - sinceMediaMs >= EDGE_SILENT_MS;
}

/**
 * Whether what the relay named is an edge the app connects to at all. Anything
 * else counts as a failed edge: the app says so at once and connects nowhere.
 * The relay chooses the host, so this is not trust in it, only the shape a
 * connect needs: a host name or IP, a port, 1 to 4 hashes of 32 bytes and a
 * ticket no longer than any relay seals.
 */
export function validEdgeView(v: unknown): v is EdgeTarget {
  if (typeof v !== "object" || v === null) return false;
  const { host, port, cert_hashes, ticket } = v as Record<string, unknown>;
  return (
    typeof host === "string" &&
    validHost(host) &&
    typeof port === "number" &&
    Number.isInteger(port) &&
    port >= 1 &&
    port <= 65535 &&
    Array.isArray(cert_hashes) &&
    cert_hashes.length >= 1 &&
    cert_hashes.length <= MAX_EDGE_CERT_HASHES &&
    cert_hashes.every((h) => isBytes(h, 32, 32)) &&
    isBytes(ticket, 0, MAX_EDGE_TICKET_BYTES)
  );
}

/**
 * Whether a loss summary steps a share down (`VideoLossSummary`, above 8
 * viewers): at least half of the viewers reported loss lately, as one viewer
 * on a bad link is that viewer's problem, not the share's. With no count, a
 * single report is enough. network.rs majority_reached, the same numbers.
 */
export function lossMajority(reporters: number, viewers: number): boolean {
  return reporters >= Math.max(1, Math.ceil(viewers / 2));
}

/** Between `least` and `most` bytes, each a whole number 0-255. */
function isBytes(v: unknown, least: number, most: number): boolean {
  if (!(v instanceof Uint8Array) && !Array.isArray(v)) return false;
  if (v.length < least || v.length > most) return false;
  return v instanceof Uint8Array || v.every((b) => Number.isInteger(b) && b >= 0 && b <= 255);
}

/** A DNS name, an IPv4 literal or an IPv6 one without brackets; ASCII only. */
function validHost(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  if (host.includes(":")) return validIpv6(host);
  const labels = host.split(".");
  // All numbers is an IPv4 literal or nothing: a name's last label is never a number
  if (labels.every((l) => /^\d+$/.test(l))) return validIpv4(labels);
  if (/^\d+$/.test(labels[labels.length - 1])) return false;
  return labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(l));
}

function validIpv4(parts: string[]): boolean {
  // No leading zeros: some readers take them for octal
  return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

function validIpv6(host: string): boolean {
  // Only address characters, so nothing can close the brackets early; the URL
  // parser then knows the rest of the grammar
  if (!/^[0-9a-f:.]+$/i.test(host)) return false;
  try {
    new URL(`https://[${host}]/`);
    return true;
  } catch {
    return false;
  }
}
