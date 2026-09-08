// Interfaces between the web backend modules. session.ts (transport +
// protocol + Signal orchestration) owns the connection; audio.ts and video.ts
// own the media pipelines and only see the session through `SessionContext`.

import type { MediaKey } from "./wasm";

/** Codec of a screen share, as the protocol names it (voipc-protocol types.rs). */
export type VideoCodec = "H264" | "H265" | "Vp8" | "Vp9";

/** What the media modules may use from the live session. */
export interface SessionContext {
  readonly sessionId: number;
  /** Current channel id (0 = General, where no media is allowed). */
  readonly channelId: number;
  /** Installed media key for the current channel, or null while waiting. */
  readonly mediaKey: MediaKey | null;
  /** Monotonic per-connection voice sequence (never restarts within a session). */
  nextVoiceSequence(): number;
  /**
   * Monotonic per-connection video frame id and screen-audio sequence. Like the
   * voice sequence they must never restart: they feed the AES-GCM nonce under
   * the channel key (screenshare/mod.rs SHARE_FRAME_ID / SHARE_AUDIO_SEQ).
   */
  nextVideoFrameId(): number;
  nextScreenAudioSequence(): number;
  /** Send one raw media packet as a QUIC datagram. No-op when not connected. */
  sendDatagram(bytes: Uint8Array): void;
  /** Send one encoded video frame on a stream of its own; false = dropped, uplink full. */
  sendVideoFrame(body: Uint8Array): boolean;
  /** Encode + send a ClientMessage (externally-tagged object or unit-variant string). */
  sendControl(msg: unknown): void;
  /**
   * Tell the server we stopped watching a share and clear the session's viewer
   * state. The video module calls this when it gives up on a stream (e.g. the
   * browser has no H.265 decoder), so the session does not keep thinking it is
   * still a viewer.
   */
  stopWatching(): void;
}

/** audio.ts — implemented by class AudioEngine. */
export interface AudioApi {
  /** Bind to a connected session (called by session.ts after Authenticated). */
  attach(ctx: SessionContext): void;
  /** Session ended: stop capture, drop all playback sources, emit nothing. */
  detach(): void;
  /** Channel changed (UserList with a new channel id): drop playback sources. */
  onChannelChanged(): void;
  /** Raw 0x05 packet from the server (decrypt with ctx.mediaKey inside). */
  onVoicePacket(bytes: Uint8Array): void;
  /** Raw 0x02 EndOfTransmission packet. */
  onEotPacket(bytes: Uint8Array): void;
  /** Raw 0x15 encrypted screen-share audio packet. */
  onScreenAudioPacket(bytes: Uint8Array): void;

  // invoke() commands (same semantics as client/src-tauri/src/commands.rs)
  startTransmit(): Promise<void>;
  stopTransmit(): Promise<void>;
  toggleMute(): Promise<boolean>;
  toggleDeafen(): Promise<boolean>;
  toggleNoiseSuppression(): Promise<boolean>;
  setInputGain(gain: number): void;
  setVolume(volume: number): void;
  setUserVolume(userId: number, volume: number): void;
  getUserVolume(userId: number): number;
  setVoiceMode(mode: string): Promise<void>;
  setVadThreshold(thresholdDb: number): void;
  getAudioLevel(): number;
  getInputDevices(): Promise<{ name: string; is_default: boolean }[]>;
  getOutputDevices(): Promise<{ name: string; is_default: boolean }[]>;
  setInputDevice(name: string): Promise<void>;
  setOutputDevice(name: string): Promise<void>;
  startMicTest(): Promise<void>;
  stopMicTest(): void;
  /** [frames_played, frames_lost] cumulative, for get_voice_stats. */
  getVoiceStats(): [number, number];
  /** [send_count, recv_count] cumulative screen-audio packets, for get_screen_audio_status. */
  getScreenAudioStatus(): [number, number];
  /** Send the desktop audio of a share we host (share.ts); no-op without an audio track. */
  startScreenAudio(stream: MediaStream): void;
  stopScreenAudio(): void;
  /** Restore persisted state at startup / after load_config. */
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
  }): void;
  readonly muted: boolean;
  readonly deafened: boolean;
}

/** video.ts — implemented by class VideoViewer. */
export interface VideoApi {
  attach(ctx: SessionContext): void;
  detach(): void;
  /** One reassembled record from a per-frame uni stream: a raw 0x13/0x14 packet. */
  onVideoPacket(bytes: Uint8Array): void;
  /** watch_screen_share was accepted (WatchingScreenShare); start decoding `codec`. */
  startWatching(sharerUserId: number, codec: VideoCodec): Promise<void>;
  /** Stopped watching (any reason): drop decoder, clear canvas. */
  stopWatching(): void;
  /** [frames_sent, bytes_sent, frames_recv, frames_dropped, bytes_recv, (w<<16)|h] */
  getStats(): [number, number, number, number, number, number];
  /** Canvas the viewer draws into (ScreenShareViewer binds it on web). */
  setCanvas(canvas: HTMLCanvasElement | null): void;
}

/** share.ts — sharing our own screen from the browser (implemented by ShareSender). */
export interface ShareApi {
  attach(ctx: SessionContext): void;
  /** Session ended: stop capture and encoding, send nothing. */
  detach(): void;
  /** Whether this browser can share at all (WebCodecs + getDisplayMedia). */
  readonly available: boolean;
  readonly sharing: boolean;
  /**
   * start_screen_share: ask the browser for a source (its own picker), pick a
   * codec this browser can actually encode, and announce the share. Encoding
   * itself waits for the first viewer (startEncoding).
   */
  start(resolution: number, fps: number): Promise<void>;
  /** stop_screen_share, the browser's own "Stop sharing", or a channel change. */
  stop(): void;
  /** start_screen_capture / stop_screen_capture: viewers arrived or all left. */
  startEncoding(resolution: number, fps: number): void;
  stopEncoding(): void;
  /** A viewer asked for a keyframe (KeyframeRequested). */
  requestKeyframe(): void;
  /** A viewer reported lost frames (VideoLossReported): step the quality down. */
  onLossReport(framesDropped: number): void;
  /** toggle_screen_audio: returns the new state. */
  toggleAudio(): boolean;
  /** [frames_sent, bytes_sent] for get_screen_share_stats. */
  getStats(): [number, number];
}
