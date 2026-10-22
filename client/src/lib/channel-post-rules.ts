// Who may write in a channel right now, and whether a channel needs the user's
// 18+ consent before it opens.
//
// The server is what enforces an announcement channel and slow mode: it sees
// who posts where, and when, and refuses the rest. These rules exist because
// the client shows your own message the moment you send it, before the server
// has answered — a refusal would arrive as a toast with the message already on
// screen as though it had gone out. So the composer asks first, and only the
// rare race (a demoted moderator, two devices) ever reaches the server's no.
//
// Pure, so channel-post-rules.test.ts can load it under Node's own test runner.

import type { ChannelInfo } from "./types.ts";

/** Who the client is on this server, as far as these rules care. */
export interface Me {
  userId: number | null;
  isAdmin: boolean;
  isModerator: boolean;
}

/**
 * The channel's managers: its creator, admins and moderators. The server lets
 * exactly these change a channel's settings, post in an announcement channel
 * and skip slow mode. The lobby has none.
 */
export function canManage(
  channel: Pick<ChannelInfo, "channel_id" | "created_by">,
  me: Me,
): boolean {
  if (channel.channel_id === 0) return false;
  return me.isAdmin || me.isModerator || (me.userId !== null && channel.created_by === me.userId);
}

export type PostBlock = { kind: "announce" } | { kind: "slow"; remainingSecs: number };

/**
 * Why the user may not post in `channel` right now, or null if they may.
 *
 * `lastSentAt` is when this client last sent there (ms), counted locally: the
 * server counts from when that post arrived, and gives half a second of grace
 * for the difference.
 */
export function postBlock(
  channel: Pick<ChannelInfo, "text" | "announce" | "slow_mode_secs">,
  manager: boolean,
  lastSentAt: number | undefined,
  now: number,
): PostBlock | null {
  if (manager) return null;
  if (channel.text && channel.announce) return { kind: "announce" };
  const secs = channel.slow_mode_secs ?? 0;
  if (secs > 0 && lastSentAt !== undefined) {
    const remainingSecs = Math.ceil((lastSentAt + secs * 1000 - now) / 1000);
    if (remainingSecs > 0) return { kind: "slow", remainingSecs };
  }
  return null;
}

/** A channel marked 18+ on a server the user has not confirmed their age for. */
export function needsNsfwConsent(channel: Pick<ChannelInfo, "nsfw"> | undefined, consented: boolean): boolean {
  return !!channel?.nsfw && !consented;
}

/** The slow-mode values the channel dialog offers, in seconds; 0 is off. */
export const SLOW_MODE_CHOICES = [0, 5, 10, 30, 60, 300, 900, 3600, 21600] as const;

/** "5 s", "1 min", "6 h" — a slow-mode interval, or a countdown, for people. */
export function slowModeLabel(secs: number): string {
  if (secs <= 0) return "Off";
  if (secs % 3600 === 0) return `${secs / 3600} h`;
  if (secs >= 60 && secs % 60 === 0) return `${secs / 60} min`;
  return `${secs} s`;
}
