// What the WebView does with a watched share's frames (1.13): how many reached it, how many
// it drew, the numbers that never came, and each drawn frame's time from emit to paint. The
// app's `share view:` log line joins it (client/src-tauri/src/view_timing.rs). No imports:
// view-timing.ts sends it.

/** A shown frame as the app sends it (screenshare/mod.rs `SharedFrame`). The browser's own
 *  viewer sends the bare word "canvas" instead. */
export interface SharedFrame {
  url: string;
  seq: number;
  /** Wall-clock ms at emit, by the same device's clock as `Date.now()` here. */
  at_ms: number;
}

/** What `report_view_timing` takes (view_timing.rs `ViewReport`). */
export interface ViewReport {
  span_ms: number;
  arrived: number;
  drawn: number;
  missing: number;
  paint_ms: number[];
  /** `(width << 16) | height` of a canvas the WebView decodes to; 0 for the <img>. */
  resolution?: number;
}

/** Paint times kept between two reports: 2 s at 60 fps is 120. */
const MOST_PAINTS = 512;
/** Frames waiting for their paint: a WebView that draws none must not grow it. */
const MOST_WAITING = 64;

export class ViewTally {
  private lastSeq = -1;
  /** Emit times of frames that came and are not drawn yet, oldest first. */
  private waiting = new Map<number, number>();
  private arrived = 0;
  private drawn = 0;
  private missing = 0;
  private paintMs: number[] = [];
  private since: number;

  constructor(now: number) {
    this.since = now;
  }

  arrive(f: { seq: number; at_ms: number }): void {
    if (this.lastSeq >= 0 && f.seq > this.lastSeq + 1) this.missing += f.seq - this.lastSeq - 1;
    this.lastSeq = Math.max(this.lastSeq, f.seq);
    this.arrived++;
    this.waiting.set(f.seq, f.at_ms);
    if (this.waiting.size > MOST_WAITING) this.waiting.delete(this.waiting.keys().next().value!);
  }

  /** The newest frame's number: the one a draw that starts now shows. */
  latest(): number {
    return this.lastSeq;
  }

  /** Frame `seq` is on screen at wall-clock `nowMs`. Frames before it were never drawn. */
  paint(seq: number, nowMs: number): void {
    const at = this.waiting.get(seq);
    if (at === undefined) return;
    for (const k of this.waiting.keys()) {
      if (k > seq) break;
      this.waiting.delete(k);
    }
    this.drawn++;
    if (this.paintMs.length < MOST_PAINTS) this.paintMs.push(Math.max(0, nowMs - at));
  }

  /** What came since the last report, which starts the next; null when nothing came. */
  take(now: number): ViewReport | null {
    const span = now - this.since;
    this.since = now;
    if (this.arrived === 0) return null;
    const r: ViewReport = {
      span_ms: Math.max(0, Math.round(span)),
      arrived: this.arrived,
      drawn: this.drawn,
      missing: this.missing,
      paint_ms: this.paintMs,
    };
    this.arrived = this.drawn = this.missing = 0;
    this.paintMs = [];
    return r;
  }
}
