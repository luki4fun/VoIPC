// The native viewers' half of the `share view:` line (view-tally.ts): each window that draws
// a share counts its own frames and reports every 2 s while they come.

import { invoke } from "@tauri-apps/api/core";
import { ViewTally, type SharedFrame } from "./view-tally.js";

const REPORT_MS = 2000;

let tally: ViewTally | null = null;
let timer: ReturnType<typeof setInterval> | null = null;
/** What a WebView that decodes the share itself drew last, `(width << 16) | height`. */
let resolution = 0;

function report(): void {
  const r = tally?.take(performance.now());
  if (!r) {
    // Nothing came for a whole report: watching ended, or the sharer is still
    if (timer !== null) clearInterval(timer);
    timer = null;
    tally = null;
    resolution = 0;
    return;
  }
  invoke("report_view_timing", { report: { ...r, resolution } }).catch(() => {});
}

/** A `screenshare-frame` event: the picture to show, its arrival noted. */
export function frameArrived(payload: SharedFrame | string): string {
  if (typeof payload === "string") return payload;
  frameCame(payload.seq, payload.at_ms);
  return payload.url;
}

/** A frame reached this WebView: its number, and the wall-clock ms it left the app at. */
export function frameCame(seq: number, atMs: number): void {
  if (!tally) {
    tally = new ViewTally(performance.now());
    timer = setInterval(report, REPORT_MS);
  }
  tally.arrive({ seq, at_ms: atMs });
}

/** Frame `seq` was drawn to a canvas just now (native-view.ts draws in an animation frame). */
export function frameDrawn(seq: number): void {
  tally?.paint(seq, Date.now());
}

/** The size of what the canvas shows, for the stats. */
export function setViewResolution(packed: number): void {
  resolution = packed >>> 0;
}

/** The number of the newest frame that arrived, for a draw that starts now; -1 for none. */
export function latestFrame(): number {
  return tally?.latest() ?? -1;
}

/** Frame `seq` loaded into its `<img>`: on screen at the next animation frame. */
export function framePainted(seq: number): void {
  if (seq < 0) return;
  requestAnimationFrame(() => tally?.paint(seq, Date.now()));
}
