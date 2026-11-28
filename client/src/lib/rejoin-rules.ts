// Which channels a reconnect is allowed to put you back into.
//
// A drop is remembered by *name*, never by id: the reconnect may land on a
// server that has been restarted in the meantime, and a channel id is only a
// slot in that run's list — `channels.json` reordered, or a user-created
// channel gone and its number handed to the next one. The names are what the
// people reading those channels would recognise.
//
// Which leaves one thing a name on its own does not carry, and it is the
// dangerous one. A text channel is a subscription: joining it costs nothing and
// leaves you standing where you were. A voice channel is a place you go, and
// arriving there announces you to everybody in it, hands you its media key and
// tears down whatever you were sharing. Resolving `#general` to whichever
// channel now holds that name could therefore turn "put my text channels back"
// into "walk into a room", silently, because the user was reconnecting rather
// than clicking anything. So the kind is part of the question, not a property
// of the answer.
//
// Pure, so rejoin-rules.test.ts can load it under Node's own test runner —
// App.svelte, which holds the connection, cannot.

import type { ChannelInfo } from "./types.ts";

/**
 * The channels to rejoin, from the names that were open before the drop.
 *
 * Names that no longer exist, or that now belong to a channel of the other
 * kind, are simply not in the answer: there is no channel to go back to, and
 * the user rejoining by hand is the right way to be wrong about that.
 */
export function resolveRejoin(
  names: string[],
  list: ChannelInfo[],
  kind: "text" | "voice",
): ChannelInfo[] {
  const wantText = kind === "text";
  const found: ChannelInfo[] = [];
  for (const name of names) {
    const channel = list.find((c) => c.name === name && c.text === wantText);
    // The same name twice is one channel to rejoin, not two: a reconnect must
    // not spend the server's join budget saying the same thing again.
    if (channel && !found.includes(channel)) found.push(channel);
  }
  return found;
}

/**
 * The voice room the user stood in as the link dropped, as the app knew it then.
 *
 * A name is not enough for a room (dive 6 F6). Rooms people make live in the relay's memory
 * only, so a restart ends every one of them and frees its name: anybody on that relay can
 * make "team-room" again before the reconnect comes round, with no password where the old
 * one had one, and a rejoin by name walked the user in with a live microphone.
 */
export interface RoomAtDrop {
  name: string;
  /** Its id in that run of the relay. */
  id: number;
  /** It had a password. */
  password: boolean;
  /** Not one of the relay's own: a person made it, or it hides who did (anonymous). */
  made: boolean;
  /** The relay's run then (`GroupKeys.run`, hex); "" from a relay that did not say (below 26). */
  run: string;
}

/** The room a drop leaves, read while the channel list is still the dropped connection's. */
export function roomAtDrop(room: ChannelInfo, run: string): RoomAtDrop {
  return {
    name: room.name,
    id: room.channel_id,
    password: room.has_password,
    // An anonymous room shows its maker to nobody else, so one with no maker shown may
    // still be a person's
    made: room.created_by !== null || room.anonymous,
    run,
  };
}

/**
 * Whether a reconnect may put the user back into `room`, the voice room of the old name in
 * the list the new connection pushed, by itself (dive 6 F6). Only the same room is:
 *
 * - the very room: the same run of the relay (`run`, the new connection's) and the same id.
 *   A relay hands out a channel id once per run, and keeps an empty room a person made for
 *   its empty-channel timeout (5 minutes, the reconnect's own budget), so a Wi-Fi roam finds
 *   it again;
 * - or one of the relay's own rooms both times: channels.json comes back under its names at
 *   every start, before anybody can connect and take one.
 *
 * And never a room without a password in place of one that had one, nor a password room
 * without the password this app knew: the relay checks that one, so whoever made the room
 * knew it too. Anything else the user joins by hand, seeing whose room it is.
 */
export function rejoinsVoice(was: RoomAtDrop, room: ChannelInfo, run: string, knowsPassword: boolean): boolean {
  if (room.text || room.name !== was.name) return false;
  if (was.password && !room.has_password) return false;
  if (room.has_password && !knowsPassword) return false;
  if (was.run !== "" && run === was.run && room.channel_id === was.id) return true;
  return !was.made && room.created_by === null && !room.anonymous;
}

/** The toast at a drop: "Connection lost" once, however the transport's words repeat it. */
export function connectionLostLine(reason: string): string {
  const rest = reason.replace(/^(connection lost:?\s*)+/i, "").trim();
  if (!rest) return "Connection lost";
  return rest.startsWith("(") ? `Connection lost ${rest}` : `Connection lost: ${rest}`;
}

/**
 * How long a reconnect waits before attempt `attempt` (1, 2, …): doubling to
 * at most 10 s, then spread over half to one and a half times that. Without
 * the spread, every client a relay restart dropped retried in the same second
 * and met its sign-in and connection limits as one burst (1.0 audit H5-17).
 *
 * The first also waits up to a millisecond for each person `online` when it dropped, at
 * most a minute: a relay of 100,000 that went down is back at about 1700 a second, not
 * all of them in that one second.
 */
export function reconnectDelay(attempt: number, random: () => number = Math.random, online = 0): number {
  const base = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
  const spread = attempt === 1 ? Math.min(60_000, Math.max(0, online)) : 0;
  return base * (0.5 + random()) + spread * random();
}
