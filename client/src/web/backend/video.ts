// Screen-share viewer: encrypted fragments -> wasm VideoAssembler -> the shared WebCodecs
// sink (lib/video-sink.ts) -> <canvas>. Port of the receive side of
// client/src-tauri/src/network.rs (the video arm of udp_receiver_task). Sharing our own screen
// lives in share.ts, which fills in the sender half of getStats().

import { probeCodec, VideoSink, type SinkHost } from "../../lib/video-sink";
import { emit } from "./events";
import { share } from "./share";
import { wasm } from "./wasm";
import type { VideoAssembler } from "./wasm";
import type { SessionContext, VideoApi, VideoCodec } from "./types";

/** What to tell the user when their browser has no decoder for this share. */
function unsupportedReason(codec: VideoCodec): string {
  if (codec === "H265") {
    return "This browser cannot decode H.265 video — ask the sharer to switch to H.264 in Settings, or use the desktop app";
  }
  return `This browser cannot decode the ${codec} video this share uses — try another browser or the desktop app`;
}
const KEYFRAME_REQUEST_INTERVAL_MS = 1_000;
/** Loss-report window: dropped/received frame counts sent to the sharer via the server. */
const LOSS_REPORT_INTERVAL_MS = 2_000;

export class VideoViewer implements VideoApi, SinkHost {
  private ctx: SessionContext | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private sink: VideoSink | null = null;
  /** Codec of the share we are watching, from WatchingScreenShare. */
  private shareCodec: VideoCodec = "H264";
  private assembler: VideoAssembler | null = null;
  private sharerUserId = 0;
  private watching = false;
  /**
   * Bumped by every start and stop. Two starts for the same sharer while the
   * codec probe is out (a double click) both got past the check below, and
   * the second overwrote the first's assembler and loss-report timer, which
   * nothing could free or clear after that.
   */
  private watchGen = 0;
  private lastKeyframeRequest = -Infinity;
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

  async startWatching(sharerUserId: number, codec: VideoCodec): Promise<void> {
    this.stopWatching();
    this.sharerUserId = sharerUserId;
    this.shareCodec = codec;
    this.watching = true;
    this.framesReceived = 0;
    this.framesDropped = 0;
    this.bytesReceived = 0;
    this.resolution = 0;
    this.firstFrameShown = false;

    const gen = this.watchGen;
    const decoderCodec = await probeCodec(codec);
    if (gen !== this.watchGen) return; // stopped, or started again, meanwhile
    if (!decoderCodec) return this.unsupported();
    this.assembler = wasm().newVideoAssembler();
    this.sink = new VideoSink(this, decoderCodec);
    this.sink.setCanvas(this.canvas);
    this.windowDropped = 0;
    this.windowReceived = 0;
    this.lossReportTimer = setInterval(() => this.sendLossReport(), LOSS_REPORT_INTERVAL_MS);
    // Ask at once rather than wait for the next periodic IDR, which is up to
    // four seconds of a blank viewer.
    this.requestKeyframe();
  }

  stopWatching(): void {
    this.watchGen++;
    this.watching = false;
    this.sharerUserId = 0;
    if (this.lossReportTimer !== null) {
      clearInterval(this.lossReportTimer);
      this.lossReportTimer = null;
    }
    this.windowDropped = 0;
    this.windowReceived = 0;
    // A fresh watch must be able to ask for its keyframe right away, even if
    // the previous one asked less than KEYFRAME_REQUEST_INTERVAL_MS ago.
    // The resolution stays: it is the last thing we decoded, and the native
    // client keeps reporting it too until the next share replaces it.
    this.lastKeyframeRequest = -Infinity;
    this.sink?.close();
    this.sink = null;
    this.assembler?.free();
    this.assembler = null;
  }

  onVideoPacket(bytes: Uint8Array): void {
    const sink = this.sink;
    if (!this.watching || !sink || !this.assembler) return;
    this.bytesReceived += bytes.length;
    const c = this.ctx;
    if (!c?.mediaKeys.hasChannel(c.channelId)) return; // no key: the fragment is dropped
    let r;
    try {
      r = this.assembler.push(c.mediaKeys, c.channelId, bytes);
    } catch (e) {
      console.warn("video decryption failed:", e);
      this.framesDropped++;
      return;
    }
    if (r.frame_dropped) {
      // Incomplete frame: hold rendering and ask the sharer for a keyframe
      this.framesDropped++;
      this.windowDropped++;
      sink.lost();
    }
    // Asked before the early return: the assembler hides every delta until
    // the first keyframe without flagging a drop, and the server rate-limits
    // keyframe relays and relies on the client asking again.
    if (sink.waitingForKey && !r.is_keyframe) this.requestKeyframe();
    if (!r.frame) return;
    this.framesReceived++;
    this.windowReceived++;
    sink.push(r.frame, r.is_keyframe, r.timestamp * 1000); // ms -> µs
  }

  getStats(): [number, number, number, number, number, number] {
    return [0, 0, this.framesReceived, this.framesDropped, this.bytesReceived, this.resolution];
  }

  setCanvas(canvas: HTMLCanvasElement | null): void {
    this.canvas = canvas;
    this.sink?.setCanvas(canvas);
  }

  // ── SinkHost ──────────────────────────────────────────────────────────────

  failed(why: "unsupported" | "too-large"): void {
    if (!this.watching) return;
    if (why === "unsupported") return this.unsupported();
    // Not "screenshare-error", which also ends a share of our own
    const c = this.ctx;
    c?.stopWatching();
    c?.emit("stopped-watching-screenshare", { reason: "its picture is larger than VoIPC shows" });
    this.stopWatching();
  }

  drawn(_timestamp: number, width: number, height: number): void {
    this.resolution = (((width & 0xffff) << 16) | (height & 0xffff)) >>> 0;
    if (!this.firstFrameShown) {
      // Flips the viewer from "Waiting for video stream..." to the canvas.
      // Bare, like the native frame event: there is only one viewer.
      this.firstFrameShown = true;
      emit("screenshare-frame", "canvas");
    }
  }

  requestKeyframe(): void {
    const c = this.ctx;
    if (!c || this.sharerUserId === 0) return;
    const now = performance.now();
    if (now - this.lastKeyframeRequest < KEYFRAME_REQUEST_INTERVAL_MS) return;
    this.lastKeyframeRequest = now;
    c.sendControl({ RequestKeyframe: { sharer_user_id: this.sharerUserId } });
  }

  /** No decoder here for this share, or one that fails on every keyframe: say so and stop. */
  private unsupported(): void {
    const c = this.ctx;
    const codec = this.shareCodec;
    this.stopWatching();
    c?.emit("screenshare-error", { reason: unsupportedReason(codec) });
    c?.stopWatching();
    c?.emit("stopped-watching-screenshare", { reason: "unsupported" });
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

// The only bridge from the Svelte layer to the web backend (components never
// import src/web): the viewer component hands over its <canvas>, and the
// sharer's preview borrows the stream being captured.
if (typeof window !== "undefined") {
  (window as unknown as { __voipc_web: unknown }).__voipc_web = {
    setVideoCanvas: (canvas: HTMLCanvasElement | null) => video.setCanvas(canvas),
    shareStream: (): MediaStream | null => share.previewStream,
  };
}
