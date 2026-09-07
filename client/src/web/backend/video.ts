// Screen-share viewer: encrypted H.265 fragments -> wasm VideoAssembler ->
// WebCodecs VideoDecoder -> <canvas>. Port of the receive side of
// client/src-tauri/src/network.rs (the video arm of udp_receiver_task and
// video_decode_render_task). Sending a screen share from the browser is out
// of scope, so the sender stats stay 0.

import { emit } from "./events";
import { wasm } from "./wasm";
import type { VideoAssembler } from "./wasm";
import type { SessionContext, VideoApi } from "./types";

/** HEVC Main, level 5.1 then 4.0 — the stream is Annex B with in-band VPS/SPS/PPS.
 *  Both prefixes are tried: some browsers only advertise the hvc1 spelling. */
const HEVC_CODECS = [
  "hev1.1.6.L153.B0",
  "hvc1.1.6.L153.B0",
  "hev1.1.6.L120.B0",
  "hvc1.1.6.L120.B0",
];
const UNSUPPORTED_REASON =
  "This browser cannot decode H.265 video — use Chrome/Edge on Windows/macOS, Safari 17+, or the desktop app";
const KEYFRAME_REQUEST_INTERVAL_MS = 1_000;
/** Loss-report window: dropped/received frame counts sent to the sharer via the server. */
const LOSS_REPORT_INTERVAL_MS = 2_000;

export class VideoViewer implements VideoApi {
  private ctx: SessionContext | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private decoder: VideoDecoder | null = null;
  private codec = "";
  private assembler: VideoAssembler | null = null;
  private sharerUserId = 0;
  private watching = false;
  /** A fresh decoder must see a key chunk first (WebCodecs rejects deltas). */
  private needKeyframe = true;
  /**
   * Render suppression (network.rs): after loss or a decode error the
   * reference chain is broken, so hold the last good frame until the
   * keyframe submitted at `resumeAtTimestamp` comes out of the decoder.
   */
  private suppressRender = false;
  private resumeAtTimestamp = Infinity;
  private lastKeyframeRequest = -Infinity;
  /** Latest decoded frame awaiting the next animation frame. */
  private pendingFrame: VideoFrame | null = null;
  private rafScheduled = false;
  private firstFrameShown = false;
  private framesReceived = 0;
  private framesDropped = 0;
  private bytesReceived = 0;
  private resolution = 0;
  /** Current loss-report window (transport loss only, not decrypt failures). */
  private windowDropped = 0;
  private windowReceived = 0;
  private lossReportTimer: ReturnType<typeof setInterval> | null = null;

  attach(ctx: SessionContext): void {
    this.ctx = ctx;
  }

  detach(): void {
    this.stopWatching();
    this.ctx = null;
  }

  async startWatching(sharerUserId: number): Promise<void> {
    this.stopWatching();
    this.sharerUserId = sharerUserId;
    this.watching = true;
    this.framesReceived = 0;
    this.framesDropped = 0;
    this.bytesReceived = 0;
    this.resolution = 0;
    this.firstFrameShown = false;

    const codec = await this.probeCodec();
    if (!this.watching || this.sharerUserId !== sharerUserId) return; // stopped meanwhile
    if (!codec) {
      this.watching = false;
      this.sharerUserId = 0;
      emit("screenshare-error", { reason: UNSUPPORTED_REASON });
      this.ctx?.stopWatching();
      emit("stopped-watching-screenshare", { reason: "unsupported" });
      return;
    }
    this.codec = codec;
    this.assembler = wasm().newVideoAssembler();
    this.openDecoder();
    this.windowDropped = 0;
    this.windowReceived = 0;
    this.lossReportTimer = setInterval(() => this.sendLossReport(), LOSS_REPORT_INTERVAL_MS);
  }

  stopWatching(): void {
    this.watching = false;
    this.sharerUserId = 0;
    if (this.lossReportTimer !== null) {
      clearInterval(this.lossReportTimer);
      this.lossReportTimer = null;
    }
    this.windowDropped = 0;
    this.windowReceived = 0;
    this.closeDecoder();
    this.assembler?.free();
    this.assembler = null;
    this.pendingFrame?.close();
    this.pendingFrame = null;
    this.suppressRender = false;
    const c = this.canvas?.getContext("2d");
    if (c && this.canvas) c.clearRect(0, 0, this.canvas.width, this.canvas.height);
  }

  onVideoPacket(bytes: Uint8Array): void {
    if (!this.watching || !this.decoder || !this.assembler) return;
    this.bytesReceived += bytes.length;
    const key = this.ctx?.mediaKey;
    if (!key) return; // encrypted video without a key is dropped
    let r;
    try {
      r = this.assembler.push(key, bytes);
    } catch (e) {
      console.warn("video decryption failed:", e);
      this.framesDropped++;
      return;
    }
    if (r.frame_dropped) {
      // Incomplete frame: hold rendering and ask the sharer for a keyframe
      this.framesDropped++;
      this.windowDropped++;
      this.suppress();
      this.requestKeyframe();
    }
    if (!r.frame) return;
    this.framesReceived++;
    this.windowReceived++;
    if (this.needKeyframe && !r.is_keyframe) {
      this.requestKeyframe();
      return;
    }
    const timestamp = r.timestamp * 1000; // ms -> µs
    try {
      this.decoder.decode(
        new EncodedVideoChunk({ type: r.is_keyframe ? "key" : "delta", timestamp, data: r.frame }),
      );
      if (r.is_keyframe) {
        this.needKeyframe = false;
        if (this.suppressRender) this.resumeAtTimestamp = timestamp;
      }
    } catch (e) {
      this.onDecodeError(e instanceof Error ? e : new Error(String(e)));
    }
  }

  getStats(): [number, number, number, number, number, number] {
    return [0, 0, this.framesReceived, this.framesDropped, this.bytesReceived, this.resolution];
  }

  setCanvas(canvas: HTMLCanvasElement | null): void {
    this.canvas = canvas;
    if (canvas && this.pendingFrame) this.scheduleDraw();
  }

  private async probeCodec(): Promise<string | null> {
    if (typeof VideoDecoder === "undefined") return null;
    for (const codec of HEVC_CODECS) {
      try {
        const r = await VideoDecoder.isConfigSupported({ codec, optimizeForLatency: true });
        if (r.supported) return codec;
      } catch {
        // try the next profile
      }
    }
    return null;
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

  /** Hold rendering until a keyframe submitted after this point is decoded. */
  private suppress(): void {
    this.suppressRender = true;
    this.resumeAtTimestamp = Infinity;
  }

  private onDecodeError(e: Error): void {
    if (!this.watching) return;
    console.warn("H.265 decode error:", e.message);
    this.suppress();
    this.requestKeyframe();
    // A WebCodecs decoder is closed after an error; build a fresh one that
    // waits for the next keyframe
    try {
      this.openDecoder();
    } catch (err) {
      console.warn("H.265 decoder creation failed:", err);
    }
  }

  private onDecoded(frame: VideoFrame): void {
    if (!this.watching) {
      frame.close();
      return;
    }
    if (this.suppressRender) {
      if (frame.timestamp < this.resumeAtTimestamp) {
        frame.close(); // corrupted delta from before the keyframe
        return;
      }
      this.suppressRender = false;
      console.info("render resumed after keyframe");
    }
    this.resolution = (((frame.displayWidth & 0xffff) << 16) | (frame.displayHeight & 0xffff)) >>> 0;
    // Keep only the latest frame per animation frame
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
      if (!this.firstFrameShown) {
        // Flips the viewer from "Waiting for video stream..." to the canvas
        this.firstFrameShown = true;
        emit("screenshare-frame", "canvas");
      }
    } finally {
      frame.close();
    }
  }

  private requestKeyframe(): void {
    const c = this.ctx;
    if (!c || this.sharerUserId === 0) return;
    const now = performance.now();
    if (now - this.lastKeyframeRequest < KEYFRAME_REQUEST_INTERVAL_MS) return;
    this.lastKeyframeRequest = now;
    c.sendControl({ RequestKeyframe: { sharer_user_id: this.sharerUserId } });
  }

  /** Every LOSS_REPORT_INTERVAL_MS: tell the sharer about lost frames (only when there were any). */
  private sendLossReport(): void {
    const dropped = this.windowDropped;
    const received = this.windowReceived;
    this.windowDropped = 0;
    this.windowReceived = 0;
    const c = this.ctx;
    if (!c || !this.watching || this.sharerUserId === 0 || dropped === 0) return;
    c.sendControl({
      VideoLossReport: { sharer_user_id: this.sharerUserId, frames_dropped: dropped, frames_received: received },
    });
  }
}

export const video: VideoApi = new VideoViewer();

// The only bridge from the Svelte layer to the web backend: the viewer
// component hands over its <canvas> (components never import src/web).
if (typeof window !== "undefined") {
  (window as unknown as { __voipc_web: unknown }).__voipc_web = {
    setVideoCanvas: (canvas: HTMLCanvasElement | null) => video.setCanvas(canvas),
  };
}
