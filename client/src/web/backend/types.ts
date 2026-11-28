// Interfaces between the web backend modules. session.ts (transport +
// protocol + Signal orchestration) owns the connection; audio.ts and video.ts
// own the media pipelines and only see the session through `SessionContext`.

import type { MediaKeys } from "./wasm";
import type { ProximityMode } from "../../lib/spatial";

/** Codec of a screen share, as the protocol names it (voipc-protocol types.rs). */
export type VideoCodec = "H264" | "H265" | "Vp8" | "Vp9";

/**
 * Whether a channel is a voice room whose keys come from the group key (plan part 5): on a
 * relay whose group key is on (`gkPosts`), any room that is not a text channel. None of the
 * old key paths runs there, out or in — no media key minted or handed over
 * (`DistributeMediaKey`), no sender key (`DistributeSenderKey`), nothing taken from either:
 * the relay refuses them, and a key taken from them is one nobody else in the room holds.
 */
export function gkVoiceRoom(gkOn: boolean, text: boolean): boolean {
  return gkOn && !text;
}

/**
 * Whether a roster of the room we stand in gets its members asked for pre-key bundles (`asks`:
 * live.ts `asksBundles`). Under the group key no key goes over a session there, and the history
 * ask opens its own (`historyAskSealed`): N bundle asks and N session set-ups per join would
 * only queue ahead of the keyholder's frames, which have deadlines.
 */
export function roomAsksBundles(asks: boolean, gkRoom: boolean): boolean {
  return asks && !gkRoom;
}

/**
 * Whether a history ask goes sealed, as a direct message the live path sends, opening a session
 * for it (plan 2k: the history hand-off, DM path). In a text channel, and in a voice room under
 * the group key: no sender key arrives there, which is what the old ask waited for, and no
 * bundle was asked at the join. The new-member wait refuses a direct message: then plain frames
 * ask whoever already has a session.
 */
export function historyAskSealed(text: boolean, gkRoom: boolean, directHeld: boolean): boolean {
  return (text || gkRoom) && !directHeld;
}

/**
 * Whether entering `channelId` asks its sharers for history at once, sealed (`askHistory`): a
 * voice room under the group key, where no sender key arrives to start the old ask. Never the
 * lobby (channel 0): the old ask never ran there, and the native app skips it too.
 */
export function entryAsksHistory(gkRoom: boolean, channelId: number): boolean {
  return gkRoom && channelId !== 0;
}

/**
 * Whether a voice seat the relay gave (`UserList` for a voice channel) needs this connection's
 * own ask first: "a voice seat needs an ask" (0.10.0). The lobby never does, nor a list for the
 * room the call already stands in. A move to another room does, on the connection carrying the
 * call too (dive 6 F7): no honest relay moves a seated user unasked (a kick goes to the lobby,
 * there is no moderator move), and the open microphone would follow it into a room whose
 * members the relay picks. Mirrors network.rs handle_server_message.
 */
export function seatNeedsAsk(channelId: number, holdsVoice: boolean, standsIn: number): boolean {
  return channelId !== 0 && (!holdsVoice || channelId !== standsIn);
}

/** What the media modules may use from the voice session. */
export interface SessionContext {
  readonly sessionId: number;
  /** Current channel id (0 = not in voice, where no media is allowed). */
  readonly channelId: number;
  /**
   * The channel's media keys: the generation we encrypt with and the one
   * before it. Always present — `hasChannel(channelId)` is what says whether
   * we can send yet. In a room under the group key (`gkVoiceRoom`) the ring is
   * in its group-key mode: ours and every sender's own key come from the room's
   * epoch key, and the packet exports look a received packet's key up by its
   * sender's session id and stream id.
   */
  readonly mediaKeys: MediaKeys;
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
  /**
   * Send one encoded video frame on a stream of its own; false = dropped,
   * uplink full. A keyframe (`key`) may use a few slots a delta may not.
   */
  sendVideoFrame(body: Uint8Array, key: boolean): boolean;
  /** Video frames still being written to the uplink (0 when not connected). */
  videoBacklog(): number;
  /**
   * How long the video waiting for the pacer takes to go out, in ms (0 while unpaced); on the
   * TCP fallback with what waits in the socket ahead of the oldest ping still out.
   */
  videoQueuedMs(): number;
  /** When our own uplink was last found queued (performance.now() ms), 0 never (lib/video-pacer.ts). */
  uplinkQueuedAt(): number;
  /** A share's video starts: sent unpaced, its uplink judged afresh. */
  uplinkReset(): void;
  /** The sharer's tick (a worker's clock): judge the uplink, time it with a ping where that is how. */
  uplinkTick(): void;
  /** Each time this share found its uplink queued (self-test): UplinkControl.finds. */
  uplinkFinds(): number[][];
  /** Encode + send a ClientMessage (externally-tagged object or unit-variant string). */
  sendControl(msg: unknown): void;
  /**
   * Tell the server we stopped watching a share and clear the session's viewer
   * state. The video module calls this when it gives up on a stream (e.g. the
   * browser cannot decode the share's codec), so the session does not keep
   * thinking it is still a viewer.
   */
  stopWatching(): void;
  /**
   * Emit a per-connection event as `{server, data}`, tagged with this
   * session's server. Device and test events stay bare and use events.ts.
   */
  emit(name: string, data?: unknown): void;
}

/** audio.ts — implemented by class AudioEngine. */
export interface AudioApi {
  /** Bind to the voice session (session.ts, once a server confirms a voice channel). */
  attach(ctx: SessionContext): void;
  /** Voice ended or moved to another server: stop capture, drop all playback sources, emit nothing. */
  detach(): void;
  /**
   * Channel changed (UserList with a new channel id): drop playback sources
   * and take on the new channel's proximity mode.
   */
  onChannelChanged(proximity?: ProximityMode): void;
  /** The current channel's proximity mode changed under us. */
  setProximityMode(proximity: ProximityMode): void;
  /** A leave of ours is out and not answered yet: the microphone stays shut for it. */
  readonly leavePending: boolean;
  /** Raw 0x05 packet from the server (decrypt with ctx.mediaKeys inside). */
  onVoicePacket(bytes: Uint8Array): void;
  /** Raw 0x02 EndOfTransmission packet. */
  onEotPacket(bytes: Uint8Array): void;
  /** Raw 0x15 encrypted screen-share audio packet. */
  onScreenAudioPacket(bytes: Uint8Array): void;
  /** Raw 0x06 encrypted position beacon from a member sharing their position. */
  onPositionPacket(bytes: Uint8Array): void;
  /** A user left the channel: forget where they stood. */
  onUserLeft(userId: number): void;

  // invoke() commands (same semantics as client/src-tauri/src/commands.rs)
  startTransmit(): Promise<void>;
  /** Never fails, attached or not. */
  stopTransmit(): Promise<void>;
  /**
   * The user leaves voice (or a seat the relay gave unasked is left): the microphone shuts now
   * and no start opens it until the relay's answer (`detach`, `onChannelChanged`) (dive 6 F10).
   */
  closeForLeave(): Promise<void>;
  /** Flip the global flag, attached or not; commands.ts tells every server. */
  toggleMute(): Promise<boolean>;
  toggleDeafen(): Promise<boolean>;
  toggleNoiseSuppression(): Promise<boolean>;
  setInputGain(gain: number): void;
  setVolume(volume: number): void;
  setUserVolume(userId: number, volume: number): void;
  getUserVolume(userId: number): number;
  /**
   * One incoming lane: an effect plus muffle, reverb and water, each 0-10.
   * Exactly the four controls our own microphone has.
   */
  setUserFx(userId: number, effect: string, muffle: number, reverb: number, water: number): void;
  getUserFx(userId: number): [string, number, number, number];
  /** Every source's level, keyed by user id, for the mixer's meters. */
  getSourceLevels(): Record<number, number>;
  /** Our own microphone's lane — the same four controls, and everyone hears it. */
  setMicFx(effect: string, muffle: number, reverb: number, water: number): void;
  setUserPosition(
    userId: number,
    pos: [number, number, number] | null,
    opts?: { range?: number; volume?: number; muffle?: number; direct?: boolean },
  ): void;
  setOwnPosition(pos: [number, number, number], fwd?: [number, number]): void;
  setPositionSync(enabled: boolean): void;
  clearPositions(): void;
  setSpatialSetting(key: string, value: boolean): void;
  /** Settings-panel spatial test (start_spatial_test / stop_spatial_test). */
  startSpatialTest(mode: ProximityMode): Promise<void>;
  stopSpatialTest(): void;
  setVoiceMode(mode: string): Promise<void>;
  setVadThreshold(thresholdDb: number): void;
  getAudioLevel(): number;
  getInputDevices(): Promise<{ name: string; is_default: boolean }[]>;
  getOutputDevices(): Promise<{ name: string; is_default: boolean }[]>;
  setInputDevice(name: string): Promise<void>;
  setOutputDevice(name: string): Promise<void>;
  /** `monitor` plays the microphone back through the sender effect. */
  startMicTest(monitor?: boolean): Promise<void>;
  stopMicTest(): void;
  /** The synthetic voice, hard left then hard right, until stopped. */
  startOutputTest(): Promise<void>;
  stopOutputTest(): void;
  /** Whether this browser can send audio to a device the user picks. */
  canPickOutput(): boolean;
  /** Ask for the microphone, and throw the refusal rather than swallow it. */
  requestMicrophone(): Promise<void>;
  /** [frames_played, frames_lost] cumulative, for get_voice_stats. */
  voiceDecoder(): "worklet" | "webcodecs";
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
    spatial_audio?: boolean;
    screen_audio_spatial?: boolean;
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
  /** Voice ended or moved to another server: stop capture and encoding. */
  detach(): void;
  /** Whether this browser can share at all (WebCodecs + getDisplayMedia). */
  readonly available: boolean;
  readonly sharing: boolean;
  /** What getDisplayMedia handed us, for the sharer's own preview — from
   *  start to stop, whether or not anybody watches. */
  readonly previewStream: MediaStream | null;
  /**
   * start_screen_share: ask the browser for a source (its own picker), pick a
   * codec this browser can actually encode, and announce the share. Encoding
   * itself waits for the first viewer (startEncoding).
   */
  start(resolution: number, fps: number): Promise<void>;
  /** stop_screen_share, the browser's own "Stop sharing", or a channel change. */
  stop(): void;
  /** ScreenShareStarted for our own user: the server accepted the share. */
  onStarted(): void;
  /** ScreenShareError: a refused share must release the capture we already hold. */
  onServerError(): void;
  /** start_screen_capture / stop_screen_capture: viewers arrived or all left. */
  startEncoding(resolution: number, fps: number): void;
  stopEncoding(): void;
  /** A viewer asked for a keyframe (KeyframeRequested). */
  requestKeyframe(): void;
  /** A viewer reported lost frames (VideoLossReported): step the quality down. */
  onLossReport(framesDropped: number): void;
  /**
   * Above 8 viewers the relay counts the reports instead (VideoLossSummary,
   * protocol 26): `reporters` of `viewers` lost frames lately. A majority steps
   * the quality down.
   */
  onLossSummary(reporters: number, viewers: number): void;
  /** toggle_screen_audio: returns the new state. */
  toggleAudio(): boolean;
  /** [frames_sent, bytes_sent] for get_screen_share_stats. */
  getStats(): [number, number];
}
