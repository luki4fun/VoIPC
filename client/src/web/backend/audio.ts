// Web audio pipeline. Capture: microphone -> GainNode (input gain) -> capture
// worklet (20 ms frames + level) -> VAD -> WebCodecs Opus encoder -> encrypted
// voice datagrams. Playback: voice / screen-audio datagrams -> one WebCodecs
// Opus decoder per source -> mixer worklet (jitter buffer + mix) -> master
// gain -> speakers.
//
// Port of the voice parts of client/src-tauri/src/network.rs
// (spawn_capture_encode_task, voice_mixer_task, udp_receiver_task) and the
// voice commands in client/src-tauri/src/commands.rs. Every event name and
// payload matches what the Rust backend emits.

import { emit } from "./events";
import { wasm } from "./wasm";
import type { AudioApi, SessionContext } from "./types";
import {
  DEFAULT_RANGE,
  FLAT,
  MAX_MUFFLE,
  defaultListener,
  defaultSource,
  gains as spatialGains,
  testSource,
  testVoiceFrame,
  type Gains,
  type Listener,
  type ProximityMode,
  type Source as SpatialSource,
} from "../../lib/spatial";

const SAMPLE_RATE = 48_000;
const FRAME_US = 20_000;
/** Set on the mixer key of screen-share audio sources (network.rs SCREEN_AUDIO_FLAG). */
const SCREEN_AUDIO_FLAG = 0x8000_0000;
/** Decoders with no packets for this long are dropped (mirrors the mixer). */
const SOURCE_IDLE_PRUNE_MS = 60_000;
const SPEAKING_TIMEOUT_MS = 500;
const SPEAKING_SWEEP_MS = 300;
/** "Waiting for media key" warning after this long without a key. */
const KEY_MISSING_WARN_MS = 2_000;
/** vad.rs: 300 ms hold / 20 ms frames. */
const VAD_HOLD_FRAMES = 15;
const CAPTURE_RESTART_MS = 1_000;
const MIC_TEST_EMIT_MS = 45;
/**
 * Mixer key of the settings panel's spatial test: above any session id and
 * clear of SCREEN_AUDIO_FLAG, so it collides with no real source.
 */
const SPATIAL_TEST_KEY = 0x7fff_fffe;
/** Frames kept queued ahead of the worklet (its jitter buffer wants 2 to start). */
const SPATIAL_TEST_LEAD = 3;
const SPATIAL_TEST_TICK_MS = 20;

/** How often we look at our position while syncing it (network.rs beacon). */
const POSITION_TICK_MS = 100;
/** Re-announce even an unmoved position this often, so late joiners converge. */
const POSITION_KEEPALIVE_MS = 1_000;

type VoiceMode = "ptt" | "vad" | "always_on";

/** The settings panel's spatial test while it runs (app_state.rs SpatialTest). */
interface SpatialTest {
  mode: ProximityMode;
  /** Wall clock the orbit started: what the gains and the panel's label use. */
  startedMs: number;
  /** Audio clock at the same moment: what frame scheduling uses. */
  startedAt: number;
  sample: number;
  sequence: number;
  posted: number;
  timer: ReturnType<typeof setInterval>;
}
type AudioDeviceInfo = { name: string; is_default: boolean };

interface CaptureFrame {
  /** Transferred from the worklet, so always backed by a plain ArrayBuffer. */
  pcm: Float32Array<ArrayBuffer>;
  levelDb: number;
}

/** One remote audio stream: its decoder and the sequences awaiting output. */
interface Source {
  decoder: AudioDecoder;
  /** Sequence numbers of chunks submitted to the decoder, in order. */
  pending: number[];
  lastActivity: number;
}

/** A finite number in [lo, hi], or `fallback` (commands.rs does the same). */
function finite(v: number | undefined, fallback: number, lo: number, hi: number): number {
  const n = v == null || !Number.isFinite(v) ? fallback : v;
  return Math.min(Math.max(n, lo), hi);
}

function describeError(e: unknown): string {
  if (e instanceof DOMException) {
    if (e.name === "NotAllowedError") return "Microphone access denied";
    if (e.name === "NotFoundError") return "No microphone found";
    if (e.name === "NotReadableError") return "Microphone is in use by another application";
  }
  return e instanceof Error ? e.message : String(e);
}

function fallbackDeviceName(kind: MediaDeviceKind, index: number): string {
  return `${kind === "audioinput" ? "Microphone" : "Speaker"} ${index + 1}`;
}

/** Microphone -> gain -> capture worklet, delivering 20 ms mono frames. */
class Capture {
  onended: (() => void) | null = null;

  private constructor(
    private readonly stream: MediaStream,
    private readonly source: MediaStreamAudioSourceNode,
    private readonly gainNode: GainNode,
    private readonly node: AudioWorkletNode,
    /** Whether closing may stop the stream's tracks (false: it is borrowed). */
    private readonly ownsStream = true,
  ) {}

  static async open(
    ac: AudioContext,
    deviceId: string | undefined,
    noiseSuppression: boolean,
    gain: number,
    onFrame: (f: CaptureFrame) => void,
  ): Promise<Capture> {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: {
        deviceId: deviceId ? { exact: deviceId } : undefined,
        channelCount: 1,
        echoCancellation: true,
        noiseSuppression,
        autoGainControl: true,
      },
    });
    const source = ac.createMediaStreamSource(stream);
    const gainNode = ac.createGain();
    gainNode.gain.value = gain;
    const node = new AudioWorkletNode(ac, "voipc-capture", {
      numberOfInputs: 1,
      numberOfOutputs: 1,
      channelCount: 1,
      channelCountMode: "explicit",
    });
    source.connect(gainNode);
    gainNode.connect(node);
    // The worklet outputs silence; connecting it makes the graph pull it.
    node.connect(ac.destination);
    node.port.onmessage = (e: MessageEvent<CaptureFrame>) => onFrame(e.data);
    const cap = new Capture(stream, source, gainNode, node);
    for (const t of stream.getAudioTracks()) t.onended = () => cap.onended?.();
    return cap;
  }

  /**
   * Same 20 ms frames, but from a stream we already have: the desktop audio
   * getDisplayMedia handed us while sharing. The stream belongs to the caller,
   * so `close()` leaves its tracks running.
   */
  static fromStream(
    ac: AudioContext,
    stream: MediaStream,
    onFrame: (f: CaptureFrame) => void,
  ): Capture {
    const source = ac.createMediaStreamSource(stream);
    const gainNode = ac.createGain();
    const node = new AudioWorkletNode(ac, "voipc-capture", {
      numberOfInputs: 1,
      numberOfOutputs: 1,
      channelCount: 1,
      channelCountMode: "explicit",
    });
    source.connect(gainNode);
    gainNode.connect(node);
    node.connect(ac.destination);
    node.port.onmessage = (e: MessageEvent<CaptureFrame>) => onFrame(e.data);
    const cap = new Capture(stream, source, gainNode, node, false);
    for (const t of stream.getAudioTracks()) t.onended = () => cap.onended?.();
    return cap;
  }

  setGain(gain: number): void {
    this.gainNode.gain.value = gain;
  }

  setNoiseSuppression(on: boolean): void {
    for (const t of this.stream.getAudioTracks()) {
      t.applyConstraints({ noiseSuppression: on }).catch(() => {});
    }
  }

  close(): void {
    this.onended = null;
    this.node.port.onmessage = null;
    this.source.disconnect();
    this.gainNode.disconnect();
    this.node.disconnect();
    for (const t of this.stream.getTracks()) {
      t.onended = null;
      if (this.ownsStream) t.stop();
    }
  }
}

export class AudioEngine implements AudioApi {
  private ctx: SessionContext | null = null;

  // Persisted settings (applySettings / setters)
  private _muted = false;
  private _deafened = false;
  private volume = 1;
  private inputGain = 1;
  private noiseSuppression = true;
  private voiceMode: VoiceMode = "ptt";
  private vadThresholdDb = -40;
  private inputDevice: string | null = null;
  private outputDevice: string | null = null;

  // Audio graph (created lazily; resumed from user-gesture paths)
  private audioContext: AudioContext | null = null;
  private graphReady: Promise<void> | null = null;
  private mixer: AudioWorkletNode | null = null;
  private masterGain: GainNode | null = null;
  private gestureArmed = false;

  // Transmit
  private transmitting = false;
  private capture: Capture | null = null;
  private captureRestartTimer: ReturnType<typeof setTimeout> | null = null;
  private encoder: AudioEncoder | null = null;
  private encodeTimestampUs = 0;
  private vadSilentCount = VAD_HOLD_FRAMES + 1;
  private vadActive = false;
  private levelDb = -96;
  private keyMissingSince: number | null = null;
  private keyMissingEmitted = false;
  /** A browser without an Opus decoder is reported once, not per packet. */
  private noDecoderEmitted = false;

  // Mic test
  private micTestActive = false;
  private micTest: Capture | null = null;
  private lastMicLevelEmit = 0;

  // Playback
  private sources = new Map<number, Source>();
  private userVolumes = new Map<number, number>();
  private framesPlayed = 0;
  private framesLost = 0;
  private screenAudioRecv = 0;
  private screenAudioSent = 0;
  /** Desktop-audio capture while sharing our screen (share.ts drives it). */
  private screenCapture: Capture | null = null;
  private screenEncoder: AudioEncoder | null = null;
  /** Set while the audio graph is coming up for a share (start is async). */
  private screenAudioStarting = false;
  /** An encoder that failed is not rebuilt every 20 ms; reported once instead. */
  private screenEncoderFailed = false;
  private screenEncodeTimestampUs = 0;
  /** session_id -> last voice packet time (edge-triggered speaking indicator). */
  private speaking = new Map<number, number>();
  private sweepTimer: ReturnType<typeof setInterval> | null = null;

  // Proximity chat. Mirrors SpatialState in client/src-tauri/src/app_state.rs:
  // positions are local, only "sync my position" puts ours on the wire.
  private proximity: ProximityMode = "off";
  private spatialEnabled = true;
  private screenAudioSpatial = true;
  private positionSync = false;
  private listener: Listener = defaultListener();
  private positions = new Map<number, SpatialSource>();
  private positionSequence = 0;
  private beaconTimer: ReturnType<typeof setInterval> | null = null;
  /** Our position moved since the last beacon. */
  private positionDirty = false;
  private positionSentAt = 0;
  private spatialTest: SpatialTest | null = null;

  get muted(): boolean {
    return this._muted;
  }

  get deafened(): boolean {
    return this._deafened;
  }

  // ── Session lifecycle ────────────────────────────────────────────────

  attach(ctx: SessionContext): void {
    this.ctx = ctx;
    this.framesPlayed = 0;
    this.framesLost = 0;
    this.screenAudioRecv = 0;
    this.screenAudioSent = 0;
    this.keyMissingSince = null;
    this.keyMissingEmitted = false;
    this.noDecoderEmitted = false;
    this.userVolumes.clear();
    this.clearPositions();
    this.positionSync = false;
    this.proximity = "off";
    this.mixer?.port.postMessage({ type: "reset" });
    if (!this.sweepTimer) {
      this.sweepTimer = setInterval(() => this.sweep(), SPEAKING_SWEEP_MS);
    }
    if (!this.beaconTimer) {
      this.beaconTimer = setInterval(() => this.sendPositionBeacon(), POSITION_TICK_MS);
    }
    this.ensureGraph().catch((e) => {
      emit("audio-device-error", { error: describeError(e) });
    });
  }

  detach(): void {
    this.ctx = null;
    this.transmitting = false;
    this.stopCapture();
    this.stopScreenAudio();
    this.dropSources();
    this.mixer?.port.postMessage({ type: "clear" });
    this.speaking.clear();
    this.clearPositions();
    this.positionSync = false;
    this.proximity = "off";
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
    if (this.beaconTimer) {
      clearInterval(this.beaconTimer);
      this.beaconTimer = null;
    }
  }

  /**
   * A channel switch. `proximity` is the new channel's mode; leaving a
   * proximity channel drops every placement, so a stale layout can never
   * leak into the next channel.
   */
  onChannelChanged(proximity: ProximityMode = "off"): void {
    this.dropSources();
    this.mixer?.port.postMessage({ type: "clear" });
    this.positionSync = false;
    this.clearPositions();
    this.setProximityMode(proximity);
  }

  /**
   * The current channel's proximity mode changed (an admin or the creator
   * switched it). Turning it off drops every placement.
   */
  setProximityMode(proximity: ProximityMode): void {
    if (proximity === this.proximity) return;
    this.proximity = proximity;
    if (proximity === "off") {
      this.positionSync = false;
      this.clearPositions();
    }
    this.pushSpatialGains();
    // Same payload shape as network.rs, channel included
    emit("proximity-mode", { channel_id: this.ctx?.channelId ?? 0, mode: proximity });
  }

  // ── Incoming media ───────────────────────────────────────────────────

  onVoicePacket(bytes: Uint8Array): void {
    const c = this.ctx;
    if (!c || !c.mediaKey) return; // never feed undecryptable audio anywhere
    let info;
    try {
      info = wasm().decryptVoicePacket(c.mediaKey, bytes);
    } catch (e) {
      console.warn("voice decryption failed:", e);
      return;
    }
    this.feedSource(info.session_id, info.sequence, info.opus);
    // Edge-triggered: only the first packet of a burst emits speaking:true;
    // the sweep and the EOT branch emit speaking:false and clear the entry.
    if (!this.speaking.has(info.session_id)) {
      emit("user-speaking", { user_id: info.session_id, speaking: true });
    }
    this.speaking.set(info.session_id, performance.now());
  }

  onEotPacket(bytes: Uint8Array): void {
    let info;
    try {
      info = wasm().parseVoiceHeader(bytes);
    } catch {
      return;
    }
    // The mixer resets the jitter buffer once the buffered tail drained
    this.mixer?.port.postMessage({ type: "eot", source: info.session_id });
    this.speaking.delete(info.session_id);
    emit("user-speaking", { user_id: info.session_id, speaking: false });
  }

  onScreenAudioPacket(bytes: Uint8Array): void {
    const c = this.ctx;
    if (!c || !c.mediaKey) return;
    let info;
    try {
      info = wasm().parseScreenAudioPacket(c.mediaKey, bytes);
    } catch (e) {
      console.warn("screen audio decryption failed:", e);
      return;
    }
    this.feedSource((info.session_id | SCREEN_AUDIO_FLAG) >>> 0, info.sequence, info.opus);
    this.screenAudioRecv++;
  }

  private feedSource(key: number, sequence: number, opus: Uint8Array): void {
    if (typeof AudioDecoder === "undefined") {
      // Silence would look like everyone else being quiet: say why, once.
      if (!this.noDecoderEmitted) {
        this.noDecoderEmitted = true;
        emit("audio-device-error", {
          error: "This browser has no WebCodecs audio decoder (needs Chrome/Edge 94+, Firefox 130+ or Safari 17+)",
        });
      }
      return;
    }
    let src = this.sources.get(key);
    if (!src) {
      src = this.createSource(key);
      this.sources.set(key, src);
    }
    src.lastActivity = performance.now();
    if (src.decoder.state !== "configured") return;
    // ponytail: packets are decoded on arrival, so a reordered packet reaches
    // the Opus decoder out of order (the jitter buffer reorders the PCM).
    src.pending.push(sequence);
    try {
      src.decoder.decode(
        new EncodedAudioChunk({ type: "key", timestamp: sequence * FRAME_US, data: opus }),
      );
    } catch (e) {
      src.pending.pop();
      console.warn(`Opus decode submit failed for source ${key.toString(16)}:`, e);
    }
  }

  private createSource(key: number): Source {
    const src: Source = { decoder: null as unknown as AudioDecoder, pending: [], lastActivity: 0 };
    src.decoder = new AudioDecoder({
      output: (data) => {
        const sequence = src.pending.shift();
        if (sequence === undefined || !this.mixer) {
          data.close();
          return;
        }
        const pcm = new Float32Array(data.numberOfFrames);
        const opts: AudioDataCopyToOptions = { planeIndex: 0 };
        if (data.format !== "f32" && data.format !== "f32-planar") opts.format = "f32-planar";
        try {
          data.copyTo(pcm, opts);
        } finally {
          data.close();
        }
        this.mixer.port.postMessage({ type: "frame", source: key, sequence, pcm }, [pcm.buffer]);
      },
      error: (e) => {
        console.warn(`Opus decode error from source ${key.toString(16)}: ${e.message}`);
        // The decoder is closed now; the next packet creates a fresh one
        this.sources.delete(key);
      },
    });
    src.decoder.configure({ codec: "opus", sampleRate: SAMPLE_RATE, numberOfChannels: 1 });
    return src;
  }

  private dropSources(): void {
    for (const src of this.sources.values()) {
      try {
        src.decoder.close();
      } catch {
        // already closed
      }
    }
    this.sources.clear();
  }

  /** 300 ms sweep: speaking timeouts (network.rs) and idle decoder pruning. */
  private sweep(): void {
    const now = performance.now();
    for (const [userId, t] of this.speaking) {
      if (now - t > SPEAKING_TIMEOUT_MS) {
        this.speaking.delete(userId);
        emit("user-speaking", { user_id: userId, speaking: false });
      }
    }
    for (const [key, src] of this.sources) {
      if (now - src.lastActivity >= SOURCE_IDLE_PRUNE_MS) {
        this.sources.delete(key);
        try {
          src.decoder.close();
        } catch {
          // already closed
        }
      }
    }
  }

  // ── Audio graph ──────────────────────────────────────────────────────

  /** Creates the AudioContext, loads the worklets and builds the mixer once. */
  private async ensureGraph(): Promise<AudioContext> {
    if (!this.audioContext) {
      this.audioContext = new AudioContext({ sampleRate: SAMPLE_RATE });
    }
    const ac = this.audioContext;
    if (!this.graphReady) {
      this.graphReady = (async () => {
        await ac.audioWorklet.addModule(new URL("./worklets/capture-worklet.js", import.meta.url));
        await ac.audioWorklet.addModule(new URL("./worklets/mixer-worklet.js", import.meta.url));
        const master = ac.createGain();
        master.gain.value = this.volume;
        master.connect(ac.destination);
        const mixer = new AudioWorkletNode(ac, "voipc-mixer", {
          numberOfInputs: 0,
          numberOfOutputs: 1,
          // Stereo: proximity chat places voices left/right. A non-spatial
          // channel writes the same samples to both, as before.
          outputChannelCount: [2],
        });
        mixer.port.onmessage = (e: MessageEvent<{ type: string; played: number; lost: number }>) => {
          if (e.data?.type === "stats") {
            this.framesPlayed = e.data.played;
            this.framesLost = e.data.lost;
          }
        };
        mixer.connect(master);
        mixer.port.postMessage({ type: "deafen", value: this._deafened });
        for (const [userId, gain] of this.userVolumes) {
          mixer.port.postMessage({ type: "user-volume", userId, gain });
        }
        this.mixer = mixer;
        this.pushSpatialGains(mixer);
        this.masterGain = master;
        await this.applyOutputDevice();
      })().catch((e) => {
        this.graphReady = null;
        throw e;
      });
    }
    await this.graphReady;
    // Autoplay policy: only succeeds from a user gesture; never block on it
    if (ac.state !== "running") {
      ac.resume().catch(() => {});
      this.armResumeOnGesture(ac);
    }
    return ac;
  }

  /** Auto-connect reaches attach() without a click: resume on the first gesture. */
  private armResumeOnGesture(ac: AudioContext): void {
    if (this.gestureArmed) return;
    this.gestureArmed = true;
    const handler = () => {
      window.removeEventListener("pointerdown", handler, true);
      window.removeEventListener("keydown", handler, true);
      this.gestureArmed = false;
      ac.resume().catch(() => {});
    };
    window.addEventListener("pointerdown", handler, true);
    window.addEventListener("keydown", handler, true);
  }

  private async findDeviceId(kind: MediaDeviceKind, name: string | null): Promise<string | undefined> {
    if (!name || !navigator.mediaDevices?.enumerateDevices) return undefined;
    const list = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === kind);
    const idx = list.findIndex((d, i) => (d.label || fallbackDeviceName(kind, i)) === name);
    return idx >= 0 ? list[idx].deviceId : undefined;
  }

  private async applyOutputDevice(): Promise<void> {
    const ac = this.audioContext as (AudioContext & { setSinkId?: (id: string) => Promise<void> }) | null;
    // AudioContext.setSinkId is Chromium-only; elsewhere the default output is used
    if (!ac || typeof ac.setSinkId !== "function") return;
    const id = await this.findDeviceId("audiooutput", this.outputDevice);
    try {
      await ac.setSinkId(id === undefined || id === "default" ? "" : id);
    } catch (e) {
      console.warn("setSinkId failed:", e);
    }
  }

  private async openCapture(ac: AudioContext, onFrame: (f: CaptureFrame) => void): Promise<Capture> {
    const deviceId = await this.findDeviceId("audioinput", this.inputDevice);
    return Capture.open(ac, deviceId, this.noiseSuppression, this.inputGain, onFrame);
  }

  // ── Transmit ─────────────────────────────────────────────────────────

  async startTransmit(): Promise<void> {
    const c = this.ctx;
    if (!c) throw new Error("Not connected");
    if (this.transmitting) return;
    if (c.channelId === 0) throw new Error("Voice is disabled in the General lobby");
    if (this._muted) return;
    this.transmitting = true;
    try {
      const ac = await this.ensureGraph();
      if (typeof AudioEncoder === "undefined") {
        throw new Error(
          "This browser has no WebCodecs audio encoder (needs Chrome/Edge 94+, Firefox 130+ or Safari 17+)",
        );
      }
      const cap = await this.openCapture(ac, (f) => this.onCaptureFrame(f));
      if (!this.transmitting) {
        cap.close(); // released while the device was opening
        return;
      }
      cap.onended = () => this.onCaptureEnded();
      this.capture = cap;
    } catch (e) {
      // Like the native capture task: report and give up this transmission
      this.transmitting = false;
      this.stopCapture();
      emit("audio-device-error", { error: describeError(e) });
    }
  }

  async stopTransmit(): Promise<void> {
    const c = this.ctx;
    if (!c) throw new Error("Not connected");
    if (!this.transmitting) return;
    this.transmitting = false;
    this.stopCapture();
    // Tell the others we stopped talking (clears their speaking indicator)
    c.sendDatagram(wasm().buildEotPacket(c.sessionId, c.nextVoiceSequence()));
  }

  private stopCapture(): void {
    if (this.captureRestartTimer) {
      clearTimeout(this.captureRestartTimer);
      this.captureRestartTimer = null;
    }
    this.capture?.close();
    this.capture = null;
    if (this.encoder) {
      try {
        this.encoder.close();
      } catch {
        // already closed
      }
      this.encoder = null;
    }
  }

  /** The device went away (unplugged): report and retry every second. */
  private onCaptureEnded(): void {
    if (!this.transmitting) return;
    console.warn("capture device error — attempting recovery");
    emit("audio-device-error", { error: "capture device error" });
    this.capture?.close();
    this.capture = null;
    const retry = async () => {
      this.captureRestartTimer = null;
      if (!this.transmitting || !this.audioContext) return;
      try {
        const cap = await this.openCapture(this.audioContext, (f) => this.onCaptureFrame(f));
        if (!this.transmitting) {
          cap.close();
          return;
        }
        cap.onended = () => this.onCaptureEnded();
        this.capture = cap;
        emit("audio-device-restored");
      } catch (e) {
        console.warn("capture restart failed (retrying):", e);
        this.captureRestartTimer = setTimeout(retry, CAPTURE_RESTART_MS);
      }
    };
    this.captureRestartTimer = setTimeout(retry, CAPTURE_RESTART_MS);
  }

  private ensureEncoder(): AudioEncoder {
    if (this.encoder && this.encoder.state === "configured") return this.encoder;
    const enc = new AudioEncoder({
      output: (chunk) => this.onEncodedChunk(chunk),
      error: (e) => {
        // The encoder is closed now; the next frame configures a new one
        console.warn("Opus encode error:", e.message);
        if (this.encoder === enc) this.encoder = null;
      },
    });
    enc.configure({
      codec: "opus",
      sampleRate: SAMPLE_RATE,
      numberOfChannels: 1,
      bitrate: 48_000,
      opus: {
        application: "voip",
        frameDuration: FRAME_US,
        useinbandfec: true,
        packetlossperc: 15,
        usedtx: true,
      } as OpusEncoderConfig, // `application` is missing from the TS DOM lib
    });
    this.encoder = enc;
    this.encodeTimestampUs = 0;
    return enc;
  }

  /** One 20 ms frame from the capture worklet (VAD, gating, encode). */
  private onCaptureFrame({ pcm, levelDb }: CaptureFrame): void {
    this.levelDb = levelDb;
    // vad.rs: RMS gate with a 300 ms hold
    if (levelDb >= this.vadThresholdDb) {
      this.vadSilentCount = 0;
      this.vadActive = true;
    } else if (++this.vadSilentCount > VAD_HOLD_FRAMES) {
      this.vadActive = false;
    }
    if (!this.transmitting) return;
    const shouldSend = this.voiceMode === "vad" ? this.vadActive : true;
    if (!shouldSend || this._muted) return;

    const enc = this.ensureEncoder();
    const data = new AudioData({
      format: "f32",
      sampleRate: SAMPLE_RATE,
      numberOfFrames: pcm.length,
      numberOfChannels: 1,
      timestamp: this.encodeTimestampUs,
      data: pcm,
    });
    this.encodeTimestampUs += FRAME_US;
    try {
      enc.encode(data);
    } catch (e) {
      console.warn("Opus encode failed:", e);
    } finally {
      data.close();
    }
  }

  private onEncodedChunk(chunk: EncodedAudioChunk): void {
    const c = this.ctx;
    if (!c || !this.transmitting || this._muted) return;
    // The sequence lives on the connection and never restarts within a
    // session: a restart would reuse AES-GCM nonces under the channel key.
    const sequence = c.nextVoiceSequence();
    const key = c.mediaKey;
    if (!key) {
      // Never fall back to plaintext: drop the frame while the channel's
      // media key is on its way, and warn the UI once if it drags on.
      const now = performance.now();
      if (this.keyMissingSince === null) this.keyMissingSince = now;
      if (!this.keyMissingEmitted && now - this.keyMissingSince > KEY_MISSING_WARN_MS) {
        this.keyMissingEmitted = true;
        console.warn("no media key for 2s — voice frames are being dropped");
        emit("media-key-missing");
      }
      return;
    }
    this.keyMissingSince = null;
    this.keyMissingEmitted = false;
    const opus = new Uint8Array(chunk.byteLength);
    chunk.copyTo(opus);
    try {
      c.sendDatagram(wasm().buildVoicePacket(key, c.sessionId, sequence, opus));
    } catch (e) {
      // Skip the frame (the sequence is consumed; receivers see a gap)
      console.warn(`voice encryption failed (seq ${sequence}):`, e);
    }
  }

  // ── Mute / deafen / settings ─────────────────────────────────────────

  async toggleMute(): Promise<boolean> {
    const c = this.ctx;
    if (!c) throw new Error("Not connected");
    this._muted = !this._muted;
    c.sendControl({ SetMuted: { muted: this._muted } });
    return this._muted;
  }

  async toggleDeafen(): Promise<boolean> {
    const c = this.ctx;
    if (!c) throw new Error("Not connected");
    this._deafened = !this._deafened;
    this.mixer?.port.postMessage({ type: "deafen", value: this._deafened });
    c.sendControl({ SetDeafened: { deafened: this._deafened } });
    return this._deafened;
  }

  async toggleNoiseSuppression(): Promise<boolean> {
    this.noiseSuppression = !this.noiseSuppression;
    this.capture?.setNoiseSuppression(this.noiseSuppression);
    this.micTest?.setNoiseSuppression(this.noiseSuppression);
    return this.noiseSuppression;
  }

  setInputGain(gain: number): void {
    this.inputGain = Math.min(Math.max(gain, 0), 4);
    this.capture?.setGain(this.inputGain);
    this.micTest?.setGain(this.inputGain);
  }

  setVolume(volume: number): void {
    this.volume = Math.min(Math.max(volume, 0), 1);
    if (this.masterGain) this.masterGain.gain.value = this.volume;
  }

  setUserVolume(userId: number, volume: number): void {
    const gain = Math.min(Math.max(volume, 0), 2);
    if (gain === 1) this.userVolumes.delete(userId);
    else this.userVolumes.set(userId, gain);
    this.mixer?.port.postMessage({ type: "user-volume", userId, gain });
  }

  getUserVolume(userId: number): number {
    return this.userVolumes.get(userId) ?? 1;
  }

  // ── Proximity chat ───────────────────────────────────────────────────

  /** Place another user, or remove their placement when `pos` is null. */
  setUserPosition(
    userId: number,
    pos: [number, number, number] | null,
    opts?: { range?: number; volume?: number; muffle?: number; direct?: boolean },
  ): void {
    if (!pos) {
      this.positions.delete(userId);
    } else {
      // A NaN would make every gain NaN and, through the worklet's filter
      // state, silence that source for good (commands.rs rejects it too)
      if (!pos.every(Number.isFinite)) return;
      this.positions.set(userId, {
        pos,
        range: finite(opts?.range, DEFAULT_RANGE, 0.01, Number.MAX_VALUE),
        volume: finite(opts?.volume, 1, 0, 2),
        muffle: Math.min(Math.max(opts?.muffle ?? 0, 0), MAX_MUFFLE),
        direct: opts?.direct ?? false,
      });
    }
    this.pushSpatialGains();
  }

  /** Move ourselves, and share the position when syncing is on. */
  setOwnPosition(pos: [number, number, number], fwd?: [number, number]): void {
    if (!pos.every(Number.isFinite)) return;
    const f = fwd ?? [0, 1];
    const len = Math.hypot(f[0], f[1]);
    this.listener = {
      pos,
      fwd: Number.isFinite(len) && len > 1e-6 ? [f[0] / len, f[1] / len] : [0, 1],
    };
    this.pushSpatialGains();
    // The beacon tick sends it within 100 ms. Sending here would put one
    // datagram on the wire per pointer event, ten times what the server relays.
    this.positionDirty = true;
  }

  /** Start or stop sharing our own position with the channel. */
  setPositionSync(enabled: boolean): void {
    this.positionSync = enabled;
    if (enabled) {
      // Everyone else's placement was our local guess until now
      this.positions.clear();
      this.pushSpatialGains();
      this.positionDirty = true;
    }
  }

  /**
   * Forget every placement (room reset, or a game disconnecting). Goes
   * through the normal push, which sends an empty list — a `spatial-clear`
   * would also drop the settings panel's test for a frame.
   */
  clearPositions(): void {
    this.positions.clear();
    this.listener = defaultListener();
    this.pushSpatialGains();
  }

  setSpatialSetting(key: string, value: boolean): void {
    if (key === "spatial_audio") this.spatialEnabled = value;
    else if (key === "screen_audio_spatial") this.screenAudioSpatial = value;
    this.pushSpatialGains();
  }

  /** A peer shared their position (encrypted position beacon, type 0x06). */
  onPositionPacket(bytes: Uint8Array): void {
    const c = this.ctx;
    if (!c || !c.mediaKey) return;
    // While we are not syncing, our own layout of the room is authoritative
    if (!this.positionSync) return;
    let info;
    try {
      info = wasm().decryptPositionPacket(c.mediaKey, bytes);
    } catch {
      return;
    }
    const existing = this.positions.get(info.session_id);
    const pos: [number, number, number] = [info.x, info.y, info.z];
    this.positions.set(info.session_id, existing ? { ...existing, pos } : defaultSource(pos));
    this.pushSpatialGains();
    emit("user-position", { user_id: info.session_id, x: info.x, y: info.y, z: info.z });
  }

  /** Drop a user's placement (they left the channel). */
  onUserLeft(userId: number): void {
    if (this.positions.delete(userId)) this.pushSpatialGains();
  }

  private sendPositionBeacon(): void {
    // Unreliable datagrams, and members who join later missed every earlier
    // one — the keepalive is what makes the room converge.
    if (!this.positionSync || this.proximity === "off") return;
    const now = performance.now();
    if (!this.positionDirty && now - this.positionSentAt < POSITION_KEEPALIVE_MS) return;
    this.positionDirty = false;
    this.positionSentAt = now;
    this.sendPosition(this.listener.pos);
  }

  private sendPosition(pos: [number, number, number]): void {
    const c = this.ctx;
    if (!c || !c.mediaKey) return;
    try {
      const packet = wasm().buildPositionPacket(
        c.mediaKey,
        c.sessionId,
        this.positionSequence++,
        pos[0],
        pos[1],
        pos[2],
      );
      c.sendDatagram(packet);
    } catch (e) {
      console.error("failed to send position:", e);
    }
  }

  /**
   * Recompute every source's stereo gains and hand them to the worklet. An
   * empty list clears the worklet's map, so this is also how placements are
   * dropped — the settings panel's test keeps its own gains through that.
   */
  private pushSpatialGains(mixer: AudioWorkletNode | null = this.mixer): void {
    if (!mixer) return;
    const entries: [number, number, number, number][] = [];
    const push = (key: number, g: Gains) => entries.push([key, g.l, g.r, g.lpA]);
    if (this.proximity !== "off" && this.spatialEnabled) {
      for (const [userId, src] of this.positions) {
        const g = spatialGains(this.proximity, this.listener, src);
        push(userId, g);
        // A share's audio follows its sharer, unless the viewer turned that off
        push((userId | SCREEN_AUDIO_FLAG) >>> 0, this.screenAudioSpatial ? g : FLAT);
      }
    }
    // The test has its own mode and runs in any channel, the lobby included
    const test = this.spatialTest;
    if (test) {
      const t = (performance.now() - test.startedMs) / 1000;
      push(
        SPATIAL_TEST_KEY,
        this.spatialEnabled
          ? spatialGains(test.mode, defaultListener(), testSource(test.mode, t))
          : FLAT,
      );
    }
    mixer.port.postMessage({ type: "spatial", gains: entries });
  }

  // ── The settings panel's spatial test ────────────────────────────────

  /**
   * A synthetic voice orbits the listener through the real worklet, so what
   * the user hears is what proximity chat does. No session needed: the audio
   * graph stands on its own, like the mic test.
   */
  async startSpatialTest(mode: ProximityMode): Promise<void> {
    if (mode === "off") throw new Error("Pick 2d or 3d");
    const ac = await this.ensureGraph();
    const previous = this.spatialTest;
    if (previous) clearInterval(previous.timer);
    // Switching modes keeps the generator phase and the sequence: no click
    this.spatialTest = {
      mode,
      startedMs: performance.now(),
      startedAt: ac.currentTime,
      sample: previous?.sample ?? 0,
      sequence: previous?.sequence ?? 0,
      posted: 0,
      timer: setInterval(() => this.spatialTestTick(), SPATIAL_TEST_TICK_MS),
    };
    this.spatialTestTick();
  }

  private spatialTestTick(): void {
    const test = this.spatialTest;
    const ac = this.audioContext;
    if (!test || !this.mixer || !ac) return;
    // Scheduled against the audio clock, not the timer: a throttled or late
    // timer posts the backlog at once instead of drifting, and a suspended
    // context (autoplay policy) does not pile frames up at all.
    const due = Math.floor((ac.currentTime - test.startedAt) * 50) + SPATIAL_TEST_LEAD;
    while (test.posted < due) {
      const pcm = testVoiceFrame(test.sample);
      test.sample += pcm.length;
      test.posted++;
      this.mixer.port.postMessage(
        { type: "frame", source: SPATIAL_TEST_KEY, sequence: test.sequence++, pcm },
        [pcm.buffer],
      );
    }
    this.pushSpatialGains(); // the orbit moved
  }

  stopSpatialTest(): void {
    const test = this.spatialTest;
    if (!test) return;
    clearInterval(test.timer);
    this.spatialTest = null;
    if (this.mixer) {
      // One frame faded to silence: cutting mid-syllable would click
      const pcm = testVoiceFrame(test.sample);
      for (let i = 0; i < pcm.length; i++) pcm[i] *= 1 - i / pcm.length;
      this.mixer.port.postMessage(
        { type: "frame", source: SPATIAL_TEST_KEY, sequence: test.sequence, pcm },
        [pcm.buffer],
      );
      this.mixer.port.postMessage({ type: "eot", source: SPATIAL_TEST_KEY });
    }
    // No gain push: the worklet keeps the last gains for the buffered tail,
    // and the next push (any placement change) drops the key.
  }

  async setVoiceMode(mode: string): Promise<void> {
    this.voiceMode = mode === "vad" || mode === "always_on" ? mode : "ptt";
  }

  setVadThreshold(thresholdDb: number): void {
    this.vadThresholdDb = Math.min(Math.max(thresholdDb, -96), 0);
  }

  getAudioLevel(): number {
    return this.levelDb;
  }

  applySettings(s: {
    muted: boolean;
    deafened: boolean;
    volume: number;
    input_gain: number;
    noise_suppression: boolean;
    voice_mode: string;
    vad_threshold_db: number;
    input_device: string | null;
    output_device: string | null;
    spatial_audio?: boolean;
    screen_audio_spatial?: boolean;
  }): void {
    this._muted = s.muted;
    this._deafened = s.deafened;
    this.mixer?.port.postMessage({ type: "deafen", value: this._deafened });
    this.setVolume(s.volume);
    this.setInputGain(s.input_gain);
    this.noiseSuppression = s.noise_suppression;
    void this.setVoiceMode(s.voice_mode);
    this.setVadThreshold(s.vad_threshold_db);
    this.inputDevice = s.input_device;
    this.outputDevice = s.output_device;
    // The persisted spatial preferences, like network.rs seeds SpatialState
    this.spatialEnabled = s.spatial_audio ?? true;
    this.screenAudioSpatial = s.screen_audio_spatial ?? true;
    this.pushSpatialGains();
    if (this.mixer) void this.applyOutputDevice();
  }

  // ── Devices ──────────────────────────────────────────────────────────

  private async listDevices(kind: MediaDeviceKind): Promise<AudioDeviceInfo[]> {
    if (!navigator.mediaDevices?.enumerateDevices) return [];
    const enumerate = async () =>
      (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === kind);
    let list = await enumerate();
    if (list.length > 0 && list.every((d) => !d.label)) {
      // Labels are only exposed after a media permission grant
      try {
        const s = await navigator.mediaDevices.getUserMedia({ audio: true });
        for (const t of s.getTracks()) t.stop();
        list = await enumerate();
      } catch {
        // keep the unlabeled list
      }
    }
    const hasDefault = list.some((d) => d.deviceId === "default");
    return list.map((d, i) => ({
      name: d.label || fallbackDeviceName(kind, i),
      is_default: hasDefault ? d.deviceId === "default" : i === 0,
    }));
  }

  getInputDevices(): Promise<AudioDeviceInfo[]> {
    return this.listDevices("audioinput");
  }

  getOutputDevices(): Promise<AudioDeviceInfo[]> {
    return this.listDevices("audiooutput");
  }

  async setInputDevice(name: string): Promise<void> {
    this.inputDevice = name;
    // Re-open the live voice capture on the new device (the settings panel
    // restarts its own mic test)
    if (this.transmitting && this.capture && this.audioContext) {
      this.capture.close();
      this.capture = null;
      try {
        const cap = await this.openCapture(this.audioContext, (f) => this.onCaptureFrame(f));
        if (!this.transmitting) {
          cap.close();
          return;
        }
        cap.onended = () => this.onCaptureEnded();
        this.capture = cap;
      } catch (e) {
        emit("audio-device-error", { error: describeError(e) });
      }
    }
  }

  async setOutputDevice(name: string): Promise<void> {
    this.outputDevice = name;
    await this.applyOutputDevice();
  }

  // ── Mic test ─────────────────────────────────────────────────────────

  async startMicTest(): Promise<void> {
    if (this.transmitting) throw new Error("Cannot test microphone while transmitting");
    if (this.micTestActive) return;
    this.micTestActive = true;
    try {
      const ac = await this.ensureGraph();
      const cap = await this.openCapture(ac, ({ levelDb }) => {
        const now = performance.now();
        if (now - this.lastMicLevelEmit >= MIC_TEST_EMIT_MS) {
          this.lastMicLevelEmit = now;
          emit("mic-test-level", { db: levelDb });
        }
      });
      if (!this.micTestActive) {
        cap.close();
        return;
      }
      this.micTest = cap;
    } catch (e) {
      this.micTestActive = false;
      emit("mic-test-error", { error: describeError(e) });
    }
  }

  stopMicTest(): void {
    this.micTestActive = false;
    this.micTest?.close();
    this.micTest = null;
  }

  // ── Screen-share audio (send side) ───────────────────────────────────

  /**
   * Send the desktop audio of a share we are hosting. `stream` is the
   * getDisplayMedia stream; its audio track (when the browser gave one) is
   * encoded like voice but sent as screen audio (0x15). Chromium offers a
   * track for tab and system audio, Firefox on Linux offers none.
   */
  startScreenAudio(stream: MediaStream): void {
    // The flag is set before the first await so two quick calls (share start
    // and an audio toggle) cannot build two captures on the same stream.
    if (this.screenCapture || this.screenAudioStarting) return;
    if (stream.getAudioTracks().length === 0) return;
    this.screenAudioStarting = true;
    void this.ensureGraph()
      .then((ac) => {
        // Sharing may have stopped while the graph was coming up
        if (!this.screenAudioStarting || stream.getAudioTracks().length === 0) return;
        this.screenEncodeTimestampUs = 0;
        this.screenEncoderFailed = false;
        this.screenCapture = Capture.fromStream(ac, stream, (f) => this.onScreenAudioFrame(f));
        this.screenCapture.onended = () => this.stopScreenAudio();
      })
      .catch((e) => console.warn("screen audio capture failed:", e))
      .finally(() => {
        this.screenAudioStarting = false;
      });
  }

  stopScreenAudio(): void {
    this.screenAudioStarting = false;
    this.screenCapture?.close();
    this.screenCapture = null;
    const enc = this.screenEncoder;
    this.screenEncoder = null;
    if (enc && enc.state !== "closed") {
      try {
        enc.close();
      } catch {
        // already closed
      }
    }
  }

  private onScreenAudioFrame({ pcm }: CaptureFrame): void {
    const ctx = this.ctx;
    if (!ctx || !this.screenCapture) return;
    const enc = this.ensureScreenEncoder();
    if (!enc) return;
    const data = new AudioData({
      format: "f32",
      sampleRate: SAMPLE_RATE,
      numberOfFrames: pcm.length,
      numberOfChannels: 1,
      timestamp: this.screenEncodeTimestampUs,
      data: pcm,
    });
    this.screenEncodeTimestampUs += FRAME_US;
    try {
      enc.encode(data);
    } catch (e) {
      console.warn("screen audio encode failed:", e);
    } finally {
      data.close();
    }
  }

  private ensureScreenEncoder(): AudioEncoder | null {
    if (this.screenEncoder && this.screenEncoder.state === "configured") return this.screenEncoder;
    if (this.screenEncoderFailed || typeof AudioEncoder === "undefined") return null;
    const enc = new AudioEncoder({
      output: (chunk) => this.onScreenAudioChunk(chunk),
      error: (e) => this.onScreenEncoderError(e.message),
    });
    try {
      // 64 kbps mono, the native sharer's SCREEN_AUDIO_BITRATE (screenshare/mod.rs)
      enc.configure({
        codec: "opus",
        sampleRate: SAMPLE_RATE,
        numberOfChannels: 1,
        bitrate: 64_000,
        opus: { application: "audio", frameDuration: FRAME_US } as OpusEncoderConfig,
      });
    } catch (e) {
      this.onScreenEncoderError(e instanceof Error ? e.message : String(e));
      return null;
    }
    this.screenEncoder = enc;
    return enc;
  }

  /**
   * A browser without an Opus encoder would otherwise rebuild one (and warn)
   * for every 20 ms frame of the whole share. Report once and send video only.
   */
  private onScreenEncoderError(message: string): void {
    this.screenEncoder = null;
    if (this.screenEncoderFailed) return;
    this.screenEncoderFailed = true;
    console.warn("screen audio encoder failed, sharing video only:", message);
    emit("screenshare-error", { reason: `Screen audio is not being sent: ${message}` });
  }

  private onScreenAudioChunk(chunk: EncodedAudioChunk): void {
    const ctx = this.ctx;
    if (!ctx || !this.screenCapture) return;
    const key = ctx.mediaKey;
    if (!key) return; // no key: drop the frame, never send plaintext
    // The sequence never restarts within a connection (AES-GCM nonce)
    const sequence = ctx.nextScreenAudioSequence();
    const opus = new Uint8Array(chunk.byteLength);
    chunk.copyTo(opus);
    try {
      ctx.sendDatagram(
        wasm().buildScreenAudioPacket(
          key,
          ctx.sessionId,
          sequence,
          Math.round(chunk.timestamp / 1000),
          opus,
        ),
      );
      this.screenAudioSent++;
    } catch (e) {
      console.warn(`screen audio encryption failed (seq ${sequence}):`, e);
    }
  }

  // ── Stats ────────────────────────────────────────────────────────────

  getVoiceStats(): [number, number] {
    return [this.framesPlayed, this.framesLost];
  }

  getScreenAudioStatus(): [number, number] {
    return [this.screenAudioSent, this.screenAudioRecv];
  }
}

export const audio: AudioApi = new AudioEngine();
