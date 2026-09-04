// Interfaces between the web backend modules. session.ts (transport +
// protocol + Signal orchestration) owns the connection; audio.ts and video.ts
// own the media pipelines and only see the session through `SessionContext`.

import type { MediaKey } from "./wasm";

/** What the media modules may use from the live session. */
export interface SessionContext {
  readonly sessionId: number;
  readonly udpToken: bigint;
  /** Current channel id (0 = General, where no media is allowed). */
  readonly channelId: number;
  /** Installed media key for the current channel, or null while waiting. */
  readonly mediaKey: MediaKey | null;
  /** Monotonic per-connection voice sequence (never restarts within a session). */
  nextVoiceSequence(): number;
  /** Send one raw media packet as a QUIC datagram. No-op when not connected. */
  sendDatagram(bytes: Uint8Array): void;
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
  /** watch_screen_share was accepted (WatchingScreenShare); start decoding. */
  startWatching(sharerUserId: number): Promise<void>;
  /** Stopped watching (any reason): drop decoder, clear canvas. */
  stopWatching(): void;
  /** [frames_sent, bytes_sent, frames_recv, frames_dropped, bytes_recv, (w<<16)|h] */
  getStats(): [number, number, number, number, number, number];
  /** Canvas the viewer draws into (ScreenShareViewer binds it on web). */
  setCanvas(canvas: HTMLCanvasElement | null): void;
}
