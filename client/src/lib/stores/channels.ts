import { derived, writable, type Readable } from "svelte/store";
import type { ChannelInfo, UserInfo } from "../types.js";
// Explicit extensions so Node's test runner can load this file as-is
import { scoped, serverAddress } from "./scoped.ts";
import { users } from "./users.ts";

export const channels = scoped<ChannelInfo[]>(() => []);
/**
 * The voice channel we stand in on each server. 0 is "not in voice": the server
 * parks every session in its lobby, channel 0, and the UI never shows it.
 */
export const currentChannelId = scoped<number>(() => 0);
export const previewChannelId = scoped<number | null>(() => null);
export const previewUsers = scoped<UserInfo[]>(() => []);

// ── Voice ──────────────────────────────────────────────────────────────────
//
// Voice is on one server at a time. The backend decides which, and it is the
// *latest confirmation* that wins, not "a channel other than 0": while voice
// moves from one server to another the old one still reports its channel for a
// round trip, until its own leave is confirmed. This store mirrors the backend
// from the events — a `user-list` for a voice channel names the voice server,
// and that server's `user-list` for channel 0, or losing it, ends voice. The
// front end never sends the leave on the other server itself; the backend does.

export interface VoiceSeat {
  server: string;
  channelId: number;
}

/** Where our voice is, or null when we are in no voice channel on any server. */
export const voice = writable<VoiceSeat | null>(null);

/** Just the server of `voice`: changes only when voice moves between servers. */
export const voiceServer: Readable<string | null> = derived(voice, ($v) => $v?.server ?? null);

/** The members of the channel we are talking in, on whichever server that is. */
export const voiceUsers: Readable<UserInfo[]> = users.at(voiceServer);

/** The channel we are talking in. */
export const voiceChannel: Readable<ChannelInfo | undefined> = derived(
  [channels.at(voiceServer), voice],
  ([$list, $voice]) => ($voice ? $list.find((c) => c.channel_id === $voice.channelId) : undefined),
);

/**
 * The server on screen is the one carrying voice. What only makes sense for the
 * call — who is speaking, a volume slider, watching a share — is shown only
 * then: the user ids on another server are another run's numbers.
 */
export const viewingVoice: Readable<boolean> = derived(
  [serverAddress, voiceServer],
  ([$viewed, $voice]) => $voice !== null && $viewed === $voice,
);
