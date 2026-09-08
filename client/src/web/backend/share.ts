// Sharing our own screen from the browser: getDisplayMedia -> WebCodecs
// VideoEncoder -> wasm fragment+encrypt -> one WebTransport stream per frame.
// The send-side mirror of video.ts, and a port of the native sharer
// (client/src-tauri/src/screenshare/mod.rs): same bitrate table, same keyframe
// cadence, same quality ladder, same packet bytes on the wire.
//
// Codec: Chromium encodes H.264, which every viewer decodes. Firefox cannot
// (Bugzilla 1918769 — isConfigSupported says yes and the encoder then refuses),
// so it falls back to VP9, which every viewer also decodes. The codec is picked
// by actually encoding a frame, never by asking, and is fixed for the share.

import { emit } from "./events";
import { wasm } from "./wasm";
import type { SessionContext, ShareApi, VideoCodec } from "./types";
import { audio } from "./audio";

/** Encoder candidates in preference order: first one that really encodes wins. */
const ENCODER_CANDIDATES: { codec: VideoCodec; webCodec: string }[] = [
  // High profile, level 5.1 — what Chromium uses for a 1080p screen share.
  { codec: "H264", webCodec: "avc1.640033" },
  { codec: "H264", webCodec: "avc1.4d0033" },
  { codec: "Vp9", webCodec: "vp09.00.10.08" },
  { codec: "Vp8", webCodec: "vp8" },
];

/** Bitrate per resolution, kbps — voipc_video::Resolution::bitrate_kbps_at. */
const BITRATE_KBPS: Record<number, number> = { 480: 1500, 720: 3000, 1080: 5000 };
/** voipc_video::Resolution: the width that goes with each share height. */
const WIDTH_FOR_HEIGHT: Record<number, number> = { 480: 854, 720: 1280, 1080: 1920 };
/** voipc_video::KEYFRAME_INTERVAL_SECS — periodic IDR as a safety net. */
const KEYFRAME_INTERVAL_SECS = 4;
/**
 * Largest frame the wire format carries: 255 fragments of
 * MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE (1280 - 17 - 16) bytes. WebCodecs has no
 * VBV, so a busy keyframe can exceed it; we drop that frame and lower the
 * bitrate instead of sending something no viewer can reassemble.
 */
const MAX_FRAME_BYTES = 255 * (1280 - 17 - 16);

/** Quality ladder, identical to screenshare/mod.rs LEVELS. */
const LEVELS: [number, number][] = [
  [1.0, 1],
  [0.6, 1],
  [0.4, 2],
  [0.25, 2],
];
const LOSS_RECENT_MS = 2_000;
const STEP_DOWN_HOLD_MS = 3_000;
const STEP_UP_AFTER_MS = 30_000;

/** screenshare/mod.rs next_level, verbatim. */
export function nextLevel(level: number, lossAgeMs: number, sinceChangeMs: number): number {
  const max = LEVELS.length - 1;
  if (lossAgeMs < LOSS_RECENT_MS) {
    return sinceChangeMs >= STEP_DOWN_HOLD_MS && level < max ? level + 1 : level;
  }
  if (lossAgeMs >= STEP_UP_AFTER_MS && sinceChangeMs >= STEP_UP_AFTER_MS && level > 0) {
    return level - 1;
  }
  return level;
}

export class ShareSender implements ShareApi {
  private ctx: SessionContext | null = null;
  private stream: MediaStream | null = null;
  private videoEl: HTMLVideoElement | null = null;
  private encoder: VideoEncoder | null = null;
  private worker: Worker | null = null;

  private codec: VideoCodec = "H264";
  private webCodec = "";
  private width = 0;
  private height = 0;
  private fps = 30;
  private baseBitrateKbps = 3000;

  private _sharing = false;
  private encoding = false;
  private audioEnabled = true;
  private startedAt = 0;
  private frameCounter = 0;
  private framesSinceKeyframe = 0;
  private keyframeRequested = false;
  private lastTickAt = 0;

  // Quality ladder
  private level = 0;
  private levelChangedAt = 0;
  private lossAt = 0;

  private framesSent = 0;
  private bytesSent = 0;

  get available(): boolean {
    return (
      typeof VideoEncoder !== "undefined" &&
      typeof VideoFrame !== "undefined" &&
      typeof navigator !== "undefined" &&
      !!navigator.mediaDevices?.getDisplayMedia
    );
  }

  get sharing(): boolean {
    return this._sharing;
  }

  attach(ctx: SessionContext): void {
    this.ctx = ctx;
  }

  detach(): void {
    this.stop();
    this.ctx = null;
  }

  async start(resolution: number, fps: number): Promise<void> {
    if (!this.available) throw new Error("This browser cannot share a screen (no WebCodecs encoder)");
    const ctx = this.ctx;
    if (!ctx) throw new Error("Not connected");
    if (ctx.channelId === 0) throw new Error("Screen sharing is disabled in the General lobby");
    if (this._sharing) throw new Error("Already screen sharing");

    this.height = resolution in WIDTH_FOR_HEIGHT ? resolution : 720;
    this.width = WIDTH_FOR_HEIGHT[this.height];
    this.fps = Math.min(60, Math.max(1, Math.round(fps) || 30));
    // +50% at 60 fps, like Resolution::bitrate_kbps_at
    const base = BITRATE_KBPS[this.height] ?? 3000;
    this.baseBitrateKbps = this.fps >= 60 ? Math.round((base * 3) / 2) : base;

    // The browser's own picker. Must be the first await after the user's click:
    // getDisplayMedia needs the transient activation that click granted.
    const stream = await navigator.mediaDevices.getDisplayMedia({
      video: {
        width: { ideal: this.width },
        height: { ideal: this.height },
        frameRate: { ideal: this.fps },
      },
      audio: true,
    });

    let picked: { codec: VideoCodec; webCodec: string } | null = null;
    try {
      picked = await this.pickCodec();
    } catch (e) {
      stopStream(stream);
      throw e;
    }
    if (!picked) {
      stopStream(stream);
      throw new Error("This browser could not encode video in any codec VoIPC supports");
    }
    this.codec = picked.codec;
    this.webCodec = picked.webCodec;

    this.stream = stream;
    // The user pressed the browser's own "Stop sharing" bar: end the share and
    // tell the UI, which resets its own sharing state on this event.
    for (const track of stream.getTracks()) {
      track.addEventListener("ended", () => {
        if (!this._sharing) return;
        this.stop();
        emit("screen-share-force-stopped");
      });
    }

    this._sharing = true;
    this.startedAt = performance.now();
    this.framesSent = 0;
    this.bytesSent = 0;
    this.level = 0;
    this.levelChangedAt = performance.now();
    this.lossAt = 0;

    ctx.sendControl({
      StartScreenShare: { source: "browser", resolution: this.height, codec: this.codec },
    });
    console.info(`screen share started: ${this.width}x${this.height}@${this.fps} ${this.codec}`);

    // Desktop audio, when the browser gave us a track (Chromium for tab and
    // system audio; Firefox on Linux offers none — the UI shows "no signal").
    const audioTrack = stream.getAudioTracks()[0];
    if (audioTrack && this.audioEnabled) audio.startScreenAudio(stream);
  }

  stop(): void {
    if (!this._sharing) return;
    this._sharing = false;
    this.stopEncoding();
    audio.stopScreenAudio();
    if (this.stream) stopStream(this.stream);
    this.stream = null;
    this.videoEl?.pause();
    this.videoEl = null;
    this.ctx?.sendControl("StopScreenShare");
  }

  startEncoding(resolution: number, fps: number): void {
    if (!this._sharing || this.encoding || !this.stream) return;
    // The picker's values win; a later start_screen_capture repeats them.
    if (resolution in WIDTH_FOR_HEIGHT) {
      this.height = resolution;
      this.width = WIDTH_FOR_HEIGHT[resolution];
    }
    if (fps > 0) this.fps = Math.min(60, Math.max(1, Math.round(fps)));

    const video = document.createElement("video");
    video.autoplay = true;
    video.muted = true;
    video.playsInline = true;
    video.srcObject = this.stream;
    void video.play().catch((e) => console.warn("share preview play failed:", e));
    this.videoEl = video;

    this.encoding = true;
    this.frameCounter = 0;
    this.framesSinceKeyframe = 0;
    this.keyframeRequested = true; // the first frame of a share is always an IDR
    this.lastTickAt = 0;
    this.openEncoder(this.currentBitrate());
    this.startTicking();
  }

  stopEncoding(): void {
    this.encoding = false;
    this.worker?.postMessage({ type: "stop" });
    this.worker?.terminate();
    this.worker = null;
    this.closeEncoder();
    this.videoEl = null;
  }

  requestKeyframe(): void {
    this.keyframeRequested = true;
  }

  onLossReport(framesDropped: number): void {
    if (framesDropped > 0) this.lossAt = performance.now();
  }

  toggleAudio(): boolean {
    this.audioEnabled = !this.audioEnabled;
    const track = this.stream?.getAudioTracks()[0];
    if (this.audioEnabled && track && this._sharing) audio.startScreenAudio(this.stream!);
    else audio.stopScreenAudio();
    return this.audioEnabled;
  }

  getStats(): [number, number] {
    return [this.framesSent, this.bytesSent];
  }

  // ── internals ──

  /**
   * Encode one frame with each candidate until one produces a chunk.
   * `isConfigSupported` alone is not enough: Firefox answers true for H.264 and
   * the encoder then fails, so the probe has to do a real encode.
   */
  private async pickCodec(): Promise<{ codec: VideoCodec; webCodec: string } | null> {
    const canvas = document.createElement("canvas");
    canvas.width = 64;
    canvas.height = 64;
    const c2d = canvas.getContext("2d");
    if (c2d) {
      c2d.fillStyle = "#808080";
      c2d.fillRect(0, 0, 64, 64);
    }
    for (const candidate of ENCODER_CANDIDATES) {
      const config: VideoEncoderConfig = {
        codec: candidate.webCodec,
        width: 64,
        height: 64,
        bitrate: 200_000,
        framerate: 30,
        latencyMode: "realtime",
        ...(candidate.codec === "H264" ? { avc: { format: "annexb" as const } } : {}),
      };
      try {
        const support = await VideoEncoder.isConfigSupported(config);
        if (!support.supported) continue;
      } catch {
        continue;
      }
      if (await trialEncode(config)) return candidate;
      console.info(`${candidate.webCodec}: reported as supported but could not encode`);
    }
    return null;
  }

  private currentBitrate(): number {
    const [scale] = LEVELS[this.level];
    return Math.max(100_000, Math.round(this.baseBitrateKbps * scale * 1000));
  }

  private currentFps(): number {
    const [, divisor] = LEVELS[this.level];
    return Math.max(1, Math.round(this.fps / divisor));
  }

  private openEncoder(bitrate: number): void {
    this.closeEncoder();
    const encoder = new VideoEncoder({
      output: (chunk) => this.onEncodedChunk(chunk),
      error: (e) => {
        console.warn("video encode error:", e.message);
        this.closeEncoder();
      },
    });
    encoder.configure({
      codec: this.webCodec,
      width: this.width,
      height: this.height,
      bitrate,
      framerate: this.currentFps(),
      latencyMode: "realtime",
      ...(this.codec === "H264" ? { avc: { format: "annexb" as const } } : {}),
    });
    this.encoder = encoder;
  }

  private closeEncoder(): void {
    const enc = this.encoder;
    this.encoder = null;
    if (enc && enc.state !== "closed") {
      try {
        enc.close();
      } catch {
        // already closed
      }
    }
  }

  private startTicking(): void {
    const worker = new Worker(new URL("./worklets/tick-worker.js", import.meta.url), {
      type: "module",
    });
    worker.onmessage = () => this.onTick();
    worker.postMessage({ type: "start", intervalMs: 1000 / this.fps });
    this.worker = worker;
  }

  /** One frame: pace, adapt, capture, encode. */
  private onTick(): void {
    if (!this.encoding || !this.videoEl) return;
    const now = performance.now();

    // The ladder can halve the frame rate; skip ticks instead of retiming the
    // worker so a level change costs nothing.
    const minInterval = 1000 / this.currentFps() - 2;
    if (this.lastTickAt !== 0 && now - this.lastTickAt < minInterval) return;
    this.lastTickAt = now;

    this.adapt();

    const encoder = this.encoder;
    if (!encoder || encoder.state !== "configured") return;
    // A backlog in the encoder means we cannot keep up: skip this frame.
    if (encoder.encodeQueueSize > 2) return;
    if (this.videoEl.readyState < 2) return; // no frame decoded yet

    const keyFrame =
      this.keyframeRequested ||
      this.framesSinceKeyframe >= KEYFRAME_INTERVAL_SECS * this.currentFps();

    let frame: VideoFrame;
    try {
      frame = new VideoFrame(this.videoEl, { timestamp: Math.round((now - this.startedAt) * 1000) });
    } catch (e) {
      console.warn("could not capture a frame:", e);
      return;
    }
    try {
      encoder.encode(frame, { keyFrame });
      this.keyframeRequested = false;
      this.framesSinceKeyframe = keyFrame ? 0 : this.framesSinceKeyframe + 1;
    } catch (e) {
      console.warn("encode failed:", e);
    } finally {
      frame.close();
    }
  }

  /** Step the quality ladder when the loss picture changed (mod.rs adapt). */
  private adapt(): void {
    const now = performance.now();
    const lossAge = this.lossAt === 0 ? Number.MAX_SAFE_INTEGER : now - this.lossAt;
    const next = nextLevel(this.level, lossAge, now - this.levelChangedAt);
    if (next === this.level) return;
    this.level = next;
    this.levelChangedAt = now;
    const bitrate = this.currentBitrate();
    const fps = this.currentFps();
    try {
      // Reconfiguring keeps the stream going; the next frame is a keyframe.
      this.encoder?.configure({
        codec: this.webCodec,
        width: this.width,
        height: this.height,
        bitrate,
        framerate: fps,
        latencyMode: "realtime",
        ...(this.codec === "H264" ? { avc: { format: "annexb" as const } } : {}),
      });
      this.keyframeRequested = true;
      console.info(`screen share quality level ${next}: ${Math.round(bitrate / 1000)} kbps, ${fps} fps`);
    } catch (e) {
      console.warn("could not apply the new quality level:", e);
    }
  }

  private onEncodedChunk(chunk: EncodedVideoChunk): void {
    const ctx = this.ctx;
    if (!ctx || !this.encoding) return;
    const key = ctx.mediaKey;
    if (!key) return; // no key yet: never send plaintext (screenshare/mod.rs)

    if (chunk.byteLength > MAX_FRAME_BYTES) {
      // No VBV in WebCodecs: this frame would need more fragments than the
      // wire format has. Drop it and encode the next one smaller.
      console.warn(`dropping a ${chunk.byteLength}-byte frame: over the fragment limit`);
      this.lossAt = performance.now();
      this.lowerBitrate();
      return;
    }

    const data = new Uint8Array(chunk.byteLength);
    chunk.copyTo(data);
    const frameId = ctx.nextVideoFrameId();
    const timestamp = Math.round(performance.now() - this.startedAt);
    let body: Uint8Array;
    try {
      body = wasm().buildVideoFrameStream(
        key,
        ctx.sessionId,
        frameId,
        timestamp,
        chunk.type === "key",
        data,
      );
    } catch (e) {
      console.warn(`video encryption failed (frame ${frameId}):`, e);
      return;
    }
    if (!ctx.sendVideoFrame(body)) {
      // Our uplink is the bottleneck: the ladder treats it as loss, like the
      // native sender's full video channel does.
      this.lossAt = performance.now();
      this.keyframeRequested = true;
      return;
    }
    this.framesSent++;
    this.bytesSent += body.length;
    this.frameCounter++;
  }

  /** Emergency step down after an oversized frame (outside the ladder's timing). */
  private lowerBitrate(): void {
    if (this.level < LEVELS.length - 1) {
      this.level++;
      this.levelChangedAt = performance.now();
    }
    try {
      this.encoder?.configure({
        codec: this.webCodec,
        width: this.width,
        height: this.height,
        bitrate: this.currentBitrate(),
        framerate: this.currentFps(),
        latencyMode: "realtime",
        ...(this.codec === "H264" ? { avc: { format: "annexb" as const } } : {}),
      });
    } catch {
      // keep the current configuration
    }
    this.keyframeRequested = true;
  }
}

/** Configure, encode one frame, and see whether anything comes out. */
async function trialEncode(config: VideoEncoderConfig): Promise<boolean> {
  let chunks = 0;
  let failed = false;
  let encoder: VideoEncoder;
  try {
    encoder = new VideoEncoder({
      output: () => {
        chunks++;
      },
      error: () => {
        failed = true;
      },
    });
    encoder.configure(config);
  } catch {
    return false;
  }
  try {
    const canvas = document.createElement("canvas");
    canvas.width = config.width;
    canvas.height = config.height;
    const frame = new VideoFrame(canvas, { timestamp: 0 });
    encoder.encode(frame, { keyFrame: true });
    frame.close();
    await Promise.race([encoder.flush(), sleep(1000)]);
  } catch {
    failed = true;
  }
  try {
    if (encoder.state !== "closed") encoder.close();
  } catch {
    // already closed by the error
  }
  return chunks > 0 && !failed;
}

function stopStream(stream: MediaStream): void {
  for (const track of stream.getTracks()) track.stop();
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const share: ShareApi = new ShareSender();
