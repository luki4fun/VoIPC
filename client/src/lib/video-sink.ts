// One WebCodecs viewer for both clients (1.13): decodes a share's frames in order and draws
// the newest to a <canvas> once per animation frame. The browser feeds it from its wasm
// assembler (web/backend/video.ts), the apps from the frames their Rust side puts together
// (native-view.ts, view_queue.rs). Where frames come from, and how a keyframe is asked for,
// is the feeder's; the decoder's rules are here.
//
// Render suppression, as in network.rs: after a loss or a decode error the reference chain
// is broken, so the last good picture stays until a keyframe submitted after that point
// comes out of the decoder.

import { frameTooLarge } from "./share-rules.js";

export type ShareCodec = "H264" | "H265" | "Vp8" | "Vp9";

/**
 * WebCodecs codec strings to try per share codec, best first. Every stream is Annex B
 * (H.264/H.265) or raw frames (VP8/VP9) with the parameter sets in band, so no
 * `description` is needed. H.264: High/Main/Baseline at level 5.1, then 4.2 for decoders
 * that refuse the higher level. H.265: both the hev1 and hvc1 spellings, since some
 * browsers advertise only one.
 */
const CODEC_CANDIDATES: Record<ShareCodec, string[]> = {
  H264: ["avc1.640033", "avc1.4d0033", "avc1.420033", "avc1.64002a", "avc1.4d002a"],
  H265: ["hev1.1.6.L153.B0", "hvc1.1.6.L153.B0", "hev1.1.6.L120.B0", "hvc1.1.6.L120.B0"],
  Vp8: ["vp8"],
  Vp9: ["vp09.00.51.08", "vp09.00.10.08"],
};

/** Chunks the decoder may hold before deltas stop going in: about 130 ms at 30 fps. */
const MAX_DECODE_QUEUE = 4;
/** Decode errors in a row, with no frame in between, before giving up. */
const MAX_DECODE_FAILURES = 3;

/** The codec string this WebView decodes `share` with, or null. */
export async function probeCodec(share: ShareCodec): Promise<string | null> {
  if (typeof VideoDecoder === "undefined") return null;
  for (const codec of CODEC_CANDIDATES[share] ?? []) {
    try {
      const r = await VideoDecoder.isConfigSupported({ codec, optimizeForLatency: true });
      if (r.supported) return codec;
    } catch {
      // try the next profile
    }
  }
  return null;
}

/** Every share codec this WebView decodes. */
export async function decodableCodecs(): Promise<ShareCodec[]> {
  const all: ShareCodec[] = ["H264", "H265", "Vp8", "Vp9"];
  const ok = await Promise.all(all.map((c) => probeCodec(c)));
  return all.filter((_, i) => ok[i] !== null);
}

export interface SinkHost {
  /** The sharer's keyframe is needed (the feeder rate-limits its asks). */
  requestKeyframe(): void;
  /** The sink cannot go on: the decoder fails on every keyframe, or a picture is too large. */
  failed(why: "unsupported" | "too-large"): void;
  /** A picture is on the canvas: its chunk's timestamp and its size. */
  drawn(timestamp: number, width: number, height: number): void;
}

export class VideoSink {
  private decoder: VideoDecoder | null = null;
  private canvas: HTMLCanvasElement | null = null;
  /** A fresh decoder must see a key chunk first (WebCodecs refuses deltas). */
  private needKeyframe = true;
  private suppressRender = false;
  private resumeAtTimestamp = Infinity;
  private decodeFailures = 0;
  /** The latest decoded picture, for the next animation frame. */
  private pendingFrame: VideoFrame | null = null;
  private rafScheduled = false;
  private closed = false;
  /** (width << 16) | height of the last picture decoded. */
  resolution = 0;

  constructor(
    private readonly host: SinkHost,
    private readonly codec: string,
  ) {
    this.openDecoder();
  }

  /** Waiting for a keyframe: none decoded since the start, a loss, or an error. */
  get waitingForKey(): boolean {
    return this.needKeyframe || this.suppressRender;
  }

  setCanvas(canvas: HTMLCanvasElement | null): void {
    this.canvas = canvas;
    if (canvas && this.pendingFrame) this.scheduleDraw();
  }

  /** A frame went missing before the next one: hold the picture until a keyframe. */
  lost(): void {
    this.suppress();
    this.host.requestKeyframe();
  }

  /** One whole frame, in order. `timestamp` in µs, rising. */
  push(data: AllowSharedBufferSource, key: boolean, timestamp: number): void {
    const dec = this.decoder;
    if (this.closed || !dec) return;
    if (this.needKeyframe && !key) {
      this.host.requestKeyframe();
      return;
    }
    // A decoder at or below real time otherwise grows its queue forever and the picture
    // drifts seconds behind the voice. A delta waits for a keyframe; a keyframe starts over
    // on an empty queue.
    if (dec.decodeQueueSize > MAX_DECODE_QUEUE) {
      if (!key) {
        this.suppress();
        this.needKeyframe = true;
        this.host.requestKeyframe();
        return;
      }
      dec.reset();
      dec.configure({ codec: this.codec, optimizeForLatency: true });
    }
    try {
      dec.decode(new EncodedVideoChunk({ type: key ? "key" : "delta", timestamp, data }));
      if (key) {
        this.needKeyframe = false;
        if (this.suppressRender) this.resumeAtTimestamp = timestamp;
      }
    } catch (e) {
      this.onDecodeError(e instanceof Error ? e : new Error(String(e)));
    }
  }

  close(): void {
    this.closed = true;
    this.closeDecoder();
    this.pendingFrame?.close();
    this.pendingFrame = null;
    const c = this.canvas?.getContext("2d");
    if (c && this.canvas) c.clearRect(0, 0, this.canvas.width, this.canvas.height);
  }

  private openDecoder(): void {
    this.closeDecoder();
    const dec = new VideoDecoder({
      output: (frame) => this.onDecoded(frame),
      error: (e) => this.onDecodeError(e),
    });
    dec.configure({ codec: this.codec, optimizeForLatency: true });
    this.decoder = dec;
    this.needKeyframe = true;
  }

  private closeDecoder(): void {
    const dec = this.decoder;
    this.decoder = null;
    if (dec && dec.state !== "closed") {
      try {
        dec.close();
      } catch {
        // already closed
      }
    }
  }

  private suppress(): void {
    this.suppressRender = true;
    this.resumeAtTimestamp = Infinity;
  }

  private onDecodeError(e: Error): void {
    if (this.closed) return;
    console.warn(`${this.codec} decode error:`, e.message);
    // A decoder that probed fine and still fails on every keyframe will never show
    // anything: say so instead of a viewer that waits forever
    if (++this.decodeFailures >= MAX_DECODE_FAILURES) {
      this.close();
      this.host.failed("unsupported");
      return;
    }
    this.suppress();
    this.host.requestKeyframe();
    // A WebCodecs decoder is closed after an error: a fresh one waits for the next keyframe
    try {
      this.openDecoder();
    } catch (err) {
      console.warn(`${this.codec} decoder creation failed:`, err);
    }
  }

  private onDecoded(frame: VideoFrame): void {
    if (this.closed) {
      frame.close();
      return;
    }
    // Over the desktop viewer's cap: nothing VoIPC sends is this big
    if (frameTooLarge(frame)) {
      console.warn(`share frame ${frame.codedWidth}x${frame.codedHeight} (shown ${frame.displayWidth}x${frame.displayHeight}) is over the decode cap`);
      frame.close();
      this.close();
      this.host.failed("too-large");
      return;
    }
    this.decodeFailures = 0;
    if (this.suppressRender) {
      if (frame.timestamp < this.resumeAtTimestamp) {
        frame.close(); // a corrupted delta from before the keyframe
        return;
      }
      this.suppressRender = false;
      console.info("render resumed after keyframe");
    }
    this.resolution = (((frame.displayWidth & 0xffff) << 16) | (frame.displayHeight & 0xffff)) >>> 0;
    this.pendingFrame?.close();
    this.pendingFrame = frame;
    this.scheduleDraw();
  }

  private scheduleDraw(): void {
    if (this.rafScheduled || !this.canvas) return;
    this.rafScheduled = true;
    requestAnimationFrame(() => {
      this.rafScheduled = false;
      this.drawPending();
    });
  }

  private drawPending(): void {
    const frame = this.pendingFrame;
    const canvas = this.canvas;
    if (!frame || !canvas) return;
    this.pendingFrame = null;
    try {
      const w = frame.displayWidth;
      const h = frame.displayHeight;
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
      }
      canvas.getContext("2d")?.drawImage(frame, 0, 0, w, h);
      this.host.drawn(frame.timestamp, w, h);
    } finally {
      frame.close();
    }
  }
}
