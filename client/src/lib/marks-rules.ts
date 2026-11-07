// What a followed channel's row shows, and how a person's read position moves.
//
// The position is in the relay's clock: post timestamps, and `last_post_ms`. A dot means the
// words are on this device or in a log this person can open. A ring means only that someone
// wrote here while they were away, and it may not be here.
// Pure, for marks-rules.test.ts.

import type { NotifyLevel } from "./notify-rules.ts";

/** Our own post moves the position by our own clock, and the relay stamped it by its own. */
export const OWN_CLOCK_SLACK_MS = 5000;

/**
 * A mark from the relay (`TextJoined`, `ChannelMarks`) against where this person read. A value
 * never seen is taken as read: the first sight of a channel is the baseline, so a new member
 * sees no marks. Zero is a relay that restarted and has seen no post since, so no ring, and
 * never a false one.
 */
export function afterMark(read: number | undefined, lastPost: number): { read: number | undefined; ring: boolean } {
  if (lastPost <= 0) return { read, ring: false };
  if (read === undefined) return { read: lastPost, ring: false };
  return { read, ring: lastPost > read + OWN_CLOCK_SLACK_MS };
}

export type RowMark = "count" | "dot" | "ring" | null;

/** What a row shows. A channel left, or set to nothing, stays plain. */
export function rowMark(s: { left: boolean; level: NotifyLevel; unread: number; unseen: boolean; ring: boolean }): RowMark {
  if (s.left || s.level === "nothing") return null;
  if (s.unread > 0) return "count";
  if (s.unseen) return "dot";
  return s.ring ? "ring" : null;
}
