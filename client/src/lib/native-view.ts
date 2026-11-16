// The apps' WebCodecs viewer (1.13; Android, decision D1): pulls the frames the Rust side put
// together (client/src-tauri/src/view_queue.rs) over the app's own URI scheme, one pull in
// flight, and hands them to a VideoSink that draws to the stream view's <canvas>. A
// `watching-screenshare` event that says `view: "webview"` starts it. A WebView that cannot
// decode that share after all hands it back to the native decoder (`view_fallback`), whose
// JPEG pictures the <img> shows as before.

import { convertFileSrc, invoke } from "@tauri-apps/api/core";
import { writable } from "svelte/store";
import { decodableCodecs, probeCodec, VideoSink, type ShareCodec, type SinkHost } from "./video-sink.js";
import { frameCame, frameDrawn, setViewResolution } from "./view-timing.js";
import { GAP, KEY, records } from "./frame-records.js";

/** Pulls that failed in a row before the share goes back to the native decoder. */
const MOST_FAILED_PULLS = 3;

/** The stream view draws to its canvas: a watch through the WebView is on. */
export const canvasView = writable(false);

let canvas: HTMLCanvasElement | null = null;
let current: Pull | null = null;

/** The stream view's canvas, or null when it goes. */
export function setNativeCanvas(c: HTMLCanvasElement | null): void {
  canvas = c;
  current?.sink?.setCanvas(c);
}

/** Tells the app which codecs this WebView decodes: its watches of those come here. */
export async function offerWebViewDecoding(): Promise<void> {
  const codecs = await decodableCodecs();
  await invoke("set_view_decoder", { codecs }).catch((e) => console.warn("set_view_decoder:", e));
}

export interface PullEvents {
  /** The first picture is on the canvas. */
  first(): void;
  /** The share cannot be shown: its picture is larger than VoIPC shows. */
  tooLarge(): void;
}

/** A watch through the WebView: `gen` from its `watching-screenshare` event. */
export function startPull(gen: number, codec: ShareCodec, events: PullEvents): void {
  stopPull();
  current = new Pull(gen, codec, events);
  void current.run();
}

export function stopPull(): void {
  current?.stop();
  current = null;
  canvasView.set(false);
}

class Pull implements SinkHost {
  sink: VideoSink | null = null;
  private stopped = false;
  private shown = false;

  constructor(
    private readonly gen: number,
    private readonly codec: ShareCodec,
    private readonly events: PullEvents,
  ) {}

  stop(): void {
    this.stopped = true;
    this.sink?.close();
    this.sink = null;
  }

  async run(): Promise<void> {
    const name = await probeCodec(this.codec);
    if (this.stopped) return;
    if (!name) return this.fallBack("no WebCodecs decoder for it here");
    this.sink = new VideoSink(this, name);
    this.sink.setCanvas(canvas);
    canvasView.set(true);
    const base = convertFileSrc("next", "voipcframe");
    let failed = 0;
    while (!this.stopped && this.sink) {
      let r: Response;
      try {
        r = await fetch(`${base}?gen=${this.gen}&key=${this.sink.waitingForKey ? 1 : 0}`, { cache: "no-store" });
      } catch (e) {
        if (++failed >= MOST_FAILED_PULLS) return this.fallBack(`its frames do not come through: ${e}`);
        await new Promise((ok) => setTimeout(ok, 100));
        continue;
      }
      failed = 0;
      if (r.status === 410) {
        // This watch is over (stopped, or another began)
        this.stop();
        if (current === this) {
          current = null;
          canvasView.set(false);
        }
        return;
      }
      if (r.status !== 200) continue; // 204: the app waited for a frame already
      const body = new Uint8Array(await r.arrayBuffer());
      for (const f of records(body)) {
        if (this.stopped || !this.sink) return;
        if (f.flags & GAP) this.sink.lost();
        frameCame(f.seq, f.at);
        // Rising within a watch: the queue numbers every frame it takes
        this.sink.push(f.data, (f.flags & KEY) !== 0, f.seq * 1000);
      }
    }
  }

  /** The native decoder takes this share over from its next keyframe. */
  private fallBack(why: string): void {
    console.warn(`share view: back to the native decoder, ${why}`);
    this.stop();
    if (current === this) canvasView.set(false);
    invoke("view_fallback").catch(() => {});
  }

  requestKeyframe(): void {
    // The next pull says so (`key=1` while the sink waits for one); the app asks the sharer
  }

  failed(why: "unsupported" | "too-large"): void {
    if (why === "too-large") {
      this.stop();
      this.events.tooLarge();
    } else {
      this.fallBack("its decoder fails on every keyframe");
    }
  }

  drawn(timestamp: number, width: number, height: number): void {
    frameDrawn(Math.round(timestamp / 1000));
    setViewResolution(((width & 0xffff) << 16) | (height & 0xffff));
    if (!this.shown) {
      this.shown = true;
      this.events.first();
    }
  }
}
