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

import type { ChannelInfo, UserInfo } from "./types.ts";

/** Who the client is on this server, as far as these rules care. */
export interface Me {
  userId: number | null;
  isAdmin: boolean;
  /** Manages every channel (`voipc:channels`; the moderator role before 1.7). */
  isModerator: boolean;
}

/**
 * The channel's managers: its creator, admins and whoever manages channels. The server lets
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

/**
 * `canManage` for someone else: whether `sender`, as the roster lists them now,
 * is one of the channel's managers. What a pin is checked against — a pin is
 * an event any member could send, and only counts from a manager. Someone not
 * in the roster (null) manages nothing.
 */
export function canManageAs(
  channel: Pick<ChannelInfo, "channel_id" | "created_by">,
  sender: Pick<UserInfo, "user_id" | "is_admin" | "is_moderator"> | null | undefined,
): boolean {
  if (!sender) return false;
  return canManage(channel, { userId: sender.user_id, isAdmin: sender.is_admin, isModerator: !!sender.is_moderator });
}

export type PostBlock = { kind: "announce" } | { kind: "slow"; remainingSecs: number };

/**
 * Why the user may not post in `channel` right now, or null if they may.
 *
 * `lastSentAt` is when this client last sent there (ms), counted locally: the
 * server counts from when that post arrived, and gives half a second of grace
 * for the difference. `unhurried`: slow mode does not hold them back (a holder
 * of `voipc:hide`, whose hide is a post), though an announcement channel still does.
 */
export function postBlock(
  channel: Pick<ChannelInfo, "text" | "announce" | "slow_mode_secs">,
  manager: boolean,
  lastSentAt: number | undefined,
  now: number,
  unhurried = false,
): PostBlock | null {
  if (manager) return null;
  if (channel.text && channel.announce) return { kind: "announce" };
  if (unhurried) return null;
  const secs = channel.slow_mode_secs ?? 0;
  if (secs > 0 && lastSentAt !== undefined) {
    const remainingSecs = Math.ceil((lastSentAt + secs * 1000 - now) / 1000);
    if (remainingSecs > 0) return { kind: "slow", remainingSecs };
  }
  return null;
}

/** What a hide's sender holds, as the relay says or the roster shows. */
export interface Hider {
  hide: boolean;
  /** Holds `*`: alone acts on other holders. */
  admin: boolean;
}

/**
 * Whether a hide from `hider` counts on a message in `channel`. `writerIsMod`: the
 * message is first-hand from someone holding a privilege, whom only an admin acts
 * on, as with a kick; a member's copy naming them is hearsay and spares nobody.
 *
 * Nothing in an anonymous channel, where a hide would unmask its sender as staff.
 */
export function hideRight(channel: Pick<ChannelInfo, "anonymous">, hider: Hider, writerIsMod: boolean): boolean {
  if (channel.anonymous || !(hider.hide || hider.admin)) return false;
  return !writerIsMod || hider.admin;
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
