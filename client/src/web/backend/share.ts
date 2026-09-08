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
//
// Frame source: MediaStreamTrackProcessor where it exists (Chromium), which
// reads the capture track directly and keeps running while the tab is hidden —
// which is where a sharer's tab lives. Firefox has no such API, so it draws
// from a <video> element on a Worker clock; page timers are throttled in a
// hidden tab but a worker's are not.

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
/** Consecutive encoder failures before the share gives up and tells the user. */
const MAX_ENCODER_FAILURES = 3;

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

/** Chromium reads the capture track directly; Firefox goes through a <video>. */
function hasTrackProcessor(): boolean {
  return typeof (globalThis as { MediaStreamTrackProcessor?: unknown }).MediaStreamTrackProcessor
    !== "undefined";
}

export class ShareSender implements ShareApi {
  private ctx: SessionContext | null = null;
  private stream: MediaStream | null = null;
  private videoEl: HTMLVideoElement | null = null;
  private encoder: VideoEncoder | null = null;
  private worker: Worker | null = null;
  /** Cancels the MediaStreamTrackProcessor read loop (Chromium path). */
  private frameReader: ReadableStreamDefaultReader<VideoFrame> | null = null;

  private codec: VideoCodec = "H264";
  private webCodec = "";
  /** Size the encoder is configured for — the captured frames', not the request. */
  private width = 0;
  private height = 0;
  /** Share height as announced to the server (480/720/1080). */
  private shareHeight = 720;
  private fps = 30;
  private baseBitrateKbps = 3000;

  private _sharing = false;
  /** Set before the first await in start(), so a second call cannot race in. */
  private starting = false;
  /** StartScreenShare was sent; cleared once the server confirms or refuses. */
  private announced = false;
  private encoding = false;
  private audioEnabled = true;
  private startedAt = 0;
  private framesSinceKeyframe = 0;
  private keyframeRequested = false;
  private lastFrameAt = 0;
  private encoderFailures = 0;
  /** Timestamp of the first encoded chunk; wire timestamps are relative to it. */
  private firstChunkUs: number | null = null;

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
    if (this._sharing || this.starting) throw new Error("Already screen sharing");

    // Claimed before the first await: the picker can stay open for a long time,
    // and a second Start (or a channel change) must not slip in behind it.
    this.starting = true;
    const channelAtStart = ctx.channelId;
    this.setQuality(resolution, fps);

    let stream: MediaStream;
    let picked: { codec: VideoCodec; webCodec: string } | null;
    try {
      // The browser's own picker. Must be the first await after the user's
      // click: getDisplayMedia needs the transient activation that click gave.
      stream = await navigator.mediaDevices.getDisplayMedia({
        video: {
          width: { ideal: this.width },
          height: { ideal: this.height },
          frameRate: { ideal: this.fps },
        },
        audio: true,
      });
    } catch (e) {
      this.starting = false;
      throw e;
    }

    try {
      picked = await this.pickCodec();
    } catch (e) {
      stopStream(stream);
      this.starting = false;
      throw e;
    }
    // The session may have ended, moved channel, or been stopped while the
    // picker was open — do not announce a share on it.
    if (!this.starting || this.ctx !== ctx || ctx.channelId !== channelAtStart) {
      stopStream(stream);
      this.starting = false;
      throw new Error("Screen sharing was cancelled");
    }
    if (!picked) {
      stopStream(stream);
      this.starting = false;
      throw new Error("This browser could not encode video in any codec VoIPC supports");
    }
    this.codec = picked.codec;
    this.webCodec = picked.webCodec;

    this.stream = stream;
    // The user pressed the browser's own "Stop sharing" bar: end the share and
    // tell the UI, which resets its own sharing state on this event. Only the
    // video track ends the share; an ending audio track is the audio path's.
    for (const track of stream.getVideoTracks()) {
      track.addEventListener("ended", () => {
        if (!this._sharing) return;
        this.stop();
        emit("screen-share-force-stopped");
      });
    }

    this._sharing = true;
    this.starting = false;
    this.announced = true;
    this.startedAt = performance.now();
    this.framesSent = 0;
    this.bytesSent = 0;
    this.level = 0;
    this.levelChangedAt = performance.now();
    this.lossAt = 0;

    ctx.sendControl({
      StartScreenShare: { source: "browser", resolution: this.shareHeight, codec: this.codec },
    });
    console.info(`screen share started: ${this.shareHeight}p@${this.fps} ${this.codec}`);

    // Desktop audio, when the browser gave us a track (Chromium for tab and
    // system audio; Firefox on Linux offers none — the UI shows "no signal").
    const audioTrack = stream.getAudioTracks()[0];
    if (audioTrack && this.audioEnabled) audio.startScreenAudio(stream);
  }

  stop(): void {
    // Cancels a start that is still waiting on the picker or the codec probe.
    this.starting = false;
    if (!this._sharing) return;
    this._sharing = false;
    this.announced = false;
    this.audioEnabled = true;
    this.stopEncoding();
    audio.stopScreenAudio();
    if (this.stream) stopStream(this.stream);
    this.stream = null;
    this.ctx?.sendControl("StopScreenShare");
  }

  /** ScreenShareStarted for our own user: the server accepted the share. */
  onStarted(): void {
    this.announced = false;
  }

  /**
   * ScreenShareError. The server refuses a share (already sharing, General
   * lobby) after we have already opened the capture, so tear it down instead of
   * leaving the browser's sharing bar up with nothing behind it. Errors that
   * arrive later belong to watching, not to our share.
   */
  onServerError(): void {
    if (!this.announced || !this._sharing) return;
    this.stop();
    emit("screen-share-force-stopped");
  }

  startEncoding(resolution: number, fps: number): void {
    if (!this._sharing || this.encoding || !this.stream) return;
    // The picker's values win; a later start_screen_capture repeats them.
    this.setQuality(resolution, fps);

    this.encoding = true;
    this.framesSinceKeyframe = 0;
    this.keyframeRequested = true; // the first frame of a share is always an IDR
    this.lastFrameAt = 0;
    this.encoderFailures = 0;
    this.firstChunkUs = null;
    // The encoder opens on the first frame, whose size is the one that counts.
    this.closeEncoder();

    const track = this.stream.getVideoTracks()[0];
    if (track && hasTrackProcessor()) this.readTrack(track);
    else this.readVideoElement();
  }

  stopEncoding(): void {
    this.encoding = false;
    this.worker?.postMessage({ type: "stop" });
    this.worker?.terminate();
    this.worker = null;
    void this.frameReader?.cancel().catch(() => {});
    this.frameReader = null;
    this.closeEncoder();
    if (this.videoEl) {
      this.videoEl.pause();
      this.videoEl.srcObject = null;
      this.videoEl = null;
    }
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

  /** Resolution preset and frame rate, with the bitrate that goes with them. */
  private setQuality(resolution: number, fps: number): void {
    this.shareHeight = resolution in WIDTH_FOR_HEIGHT ? resolution : 720;
    // Requested capture size; the encoder follows the frames we actually get.
    this.height = this.shareHeight;
    this.width = WIDTH_FOR_HEIGHT[this.shareHeight];
    this.fps = Math.min(60, Math.max(1, Math.round(fps) || 30));
    // +50% at 60 fps, like Resolution::bitrate_kbps_at
    const base = BITRATE_KBPS[this.shareHeight] ?? 3000;
    this.baseBitrateKbps = this.fps >= 60 ? Math.round((base * 3) / 2) : base;
  }

  /**
   * Chromium: frames straight off the capture track. Not throttled when the
   * tab is hidden, and no <video> decode in between.
   * ponytail: runs on the main thread; move the reader into a worker if a
   * hidden tab ever starves it.
   */
  private readTrack(track: MediaStreamTrack): void {
    type Processor = new (init: { track: MediaStreamTrack }) => {
      readable: ReadableStream<VideoFrame>;
    };
    const Ctor = (globalThis as unknown as { MediaStreamTrackProcessor: Processor })
      .MediaStreamTrackProcessor;
    const reader = new Ctor({ track }).readable.getReader();
    this.frameReader = reader;
    void (async () => {
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) return;
          if (!this.encoding) {
            value.close();
            return;
          }
          this.onFrame(value);
        }
      } catch {
        // Cancelled by stopEncoding, or the track ended.
      }
    })();
  }

  /** Firefox: a hidden <video> sampled on a worker clock. */
  private readVideoElement(): void {
    const video = document.createElement("video");
    video.autoplay = true;
    video.muted = true;
    video.playsInline = true;
    video.srcObject = this.stream;
    void video.play().catch((e) => console.warn("share preview play failed:", e));
    this.videoEl = video;

    const worker = new Worker(new URL("./worklets/tick-worker.js", import.meta.url), {
      type: "module",
    });
    worker.onmessage = () => this.onTick();
    worker.postMessage({ type: "start", intervalMs: 1000 / this.fps });
    this.worker = worker;
  }

  /** One worker tick: grab the current <video> frame and hand it to the encoder. */
  private onTick(): void {
    const video = this.videoEl;
    if (!this.encoding || !video || video.readyState < 2) return;
    let frame: VideoFrame;
    try {
      frame = new VideoFrame(video, {
        timestamp: Math.round((performance.now() - this.startedAt) * 1000),
      });
    } catch (e) {
      console.warn("could not capture a frame:", e);
      return;
    }
    this.onFrame(frame);
  }

  /** Pace, adapt, encode. Closes `frame` in every path. */
  private onFrame(frame: VideoFrame): void {
    try {
      if (!this.encoding) return;
      const now = performance.now();
      // The ladder can halve the frame rate, and a capture track can deliver
      // faster than we asked: drop anything that comes in too early.
      const minInterval = 1000 / this.currentFps() - 2;
      if (this.lastFrameAt !== 0 && now - this.lastFrameAt < minInterval) return;
      this.lastFrameAt = now;

      this.adapt();

      // The first frame decides the encoder's size (the browser rarely gives
      // exactly the size we asked for), and a resized window or a renegotiated
      // capture rebuilds it. The *visible* size, not the coded one: a capture
      // track pads its buffers to the codec's macroblock grid, and encoding at
      // the padded size ships the padding to every viewer.
      const sizeChanged =
        frame.displayWidth !== this.width || frame.displayHeight !== this.height;
      if (!this.encoder || sizeChanged) {
        if (this.encoder && sizeChanged) {
          console.info(`share source is now ${frame.displayWidth}x${frame.displayHeight}`);
        }
        this.width = frame.displayWidth;
        this.height = frame.displayHeight;
        this.openEncoder();
      }
      const encoder = this.encoder;
      if (!encoder || encoder.state !== "configured") return;
      // A backlog in the encoder means we cannot keep up: skip this frame.
      if (encoder.encodeQueueSize > 2) return;

      const keyFrame =
        this.keyframeRequested ||
        this.framesSinceKeyframe >= KEYFRAME_INTERVAL_SECS * this.currentFps();
      try {
        encoder.encode(frame, { keyFrame });
        this.keyframeRequested = false;
        this.framesSinceKeyframe = keyFrame ? 0 : this.framesSinceKeyframe + 1;
      } catch (e) {
        console.warn("encode failed:", e);
      }
    } finally {
      frame.close();
    }
  }

  private currentBitrate(): number {
    const [scale] = LEVELS[this.level];
    return Math.max(100_000, Math.round(this.baseBitrateKbps * scale * 1000));
  }

  private currentFps(): number {
    const [, divisor] = LEVELS[this.level];
    return Math.max(1, Math.round(this.fps / divisor));
  }

  private encoderConfig(): VideoEncoderConfig {
    return {
      codec: this.webCodec,
      width: this.width,
      height: this.height,
      bitrate: this.currentBitrate(),
      framerate: this.currentFps(),
      latencyMode: "realtime",
      ...(this.codec === "H264" ? { avc: { format: "annexb" as const } } : {}),
    };
  }

  private openEncoder(): void {
    this.closeEncoder();
    const encoder = new VideoEncoder({
      output: (chunk) => this.onEncodedChunk(chunk),
      error: (e) => this.onEncoderError(e),
    });
    try {
      encoder.configure(this.encoderConfig());
    } catch (e) {
      this.onEncoderError(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    this.encoder = encoder;
    this.keyframeRequested = true;
  }

  /**
   * A WebCodecs encoder is closed after an error. Rebuild it, like the native
   * sharer rebuilds its encoder on every ladder step; give up (and tell the
   * user) once it keeps failing, instead of leaving a share that sends nothing
   * while the UI still says "Sharing".
   */
  private onEncoderError(e: Error): void {
    console.warn("video encode error:", e.message);
    this.closeEncoder();
    if (!this.encoding) return;
    if (++this.encoderFailures >= MAX_ENCODER_FAILURES) {
      emit("screenshare-error", {
        reason: `Screen sharing stopped: the video encoder failed (${e.message})`,
      });
      this.stop();
      emit("screen-share-force-stopped");
      return;
    }
    this.openEncoder();
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

  /** Apply the current level to the running encoder (bitrate and frame rate). */
  private reconfigure(): void {
    if (!this.encoder || this.encoder.state !== "configured") return;
    try {
      this.encoder.configure(this.encoderConfig());
      this.keyframeRequested = true;
    } catch (e) {
      console.warn("could not apply the new quality level:", e);
    }
  }

  /**
   * Encode one frame with each candidate until one produces a chunk.
   * `isConfigSupported` alone is not enough: Firefox answers true for H.264 and
   * the encoder then fails, so the probe has to do a real encode.
   */
  private async pickCodec(): Promise<{ codec: VideoCodec; webCodec: string } | null> {
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

  /** Step the quality ladder when the loss picture changed (mod.rs adapt). */
  private adapt(): void {
    const now = performance.now();
    const lossAge = this.lossAt === 0 ? Number.MAX_SAFE_INTEGER : now - this.lossAt;
    const next = nextLevel(this.level, lossAge, now - this.levelChangedAt);
    if (next === this.level) return;
    this.level = next;
    this.levelChangedAt = now;
    this.reconfigure();
    console.info(
      `screen share quality level ${next}: ${Math.round(this.currentBitrate() / 1000)} kbps, ${this.currentFps()} fps`,
    );
  }

  private onEncodedChunk(chunk: EncodedVideoChunk): void {
    const ctx = this.ctx;
    if (!ctx || !this.encoding) return;
    // A chunk came out, so this encoder works — reset the failure count.
    this.encoderFailures = 0;
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
    // Milliseconds since the first frame, from the frame's own clock — a
    // capture track's timestamps start at an arbitrary origin.
    if (this.firstChunkUs === null) this.firstChunkUs = chunk.timestamp;
    const timestamp = Math.max(0, Math.round((chunk.timestamp - this.firstChunkUs) / 1000));
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
  }

  /** Emergency step down after an oversized frame (outside the ladder's timing). */
  private lowerBitrate(): void {
    if (this.level < LEVELS.length - 1) {
      this.level++;
      this.levelChangedAt = performance.now();
    }
    this.reconfigure();
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
