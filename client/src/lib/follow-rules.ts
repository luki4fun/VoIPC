// Which text channels this app follows without being asked to, and the two kinds of channel
// that come from: an open one, where anyone online may read, and one where who is there
// goes by a list.
// Pure, for follow-rules.test.ts.

import { needsNsfwConsent } from "./channel-post-rules.ts";
import type { ChannelInfo } from "./types.ts";

export interface FollowState {
  /** Asked for on this connection already, or in it. */
  sent: ReadonlySet<number>;
  /** They left it, or were kicked out of it. */
  left: (channel: ChannelInfo) => boolean;
  /** They said they are 18 on this server. */
  consented: boolean;
}

/** The channels to ask for now, in id order. A password has no one to ask, and 18+ waits for
 *  the person's yes; neither is left out for good. */
export function toFollow(list: readonly ChannelInfo[], s: FollowState): number[] {
  return list
    .filter(
      (c) =>
        c.text &&
        c.auto_join &&
        !c.has_password &&
        !needsNsfwConsent(c, s.consented) &&
        !s.sent.has(c.channel_id) &&
        !s.left(c),
    )
    .map((c) => c.channel_id)
    .sort((a, b) => a - b);
}

export type QuietMode = "off" | "mobile" | "always";

/** Whether quiet mode holds now. "On mobile data" goes by the network this device says it is on. */
export function quietOn(mode: QuietMode, metered: boolean): boolean {
  return mode === "always" || (mode === "mobile" && metered);
}

/** Of these followed channels, the ones that go quiet: all but those picked to arrive here. */
export function quietSet(followed: readonly ChannelInfo[], whole: readonly string[], on: boolean): Set<number> {
  if (!on) return new Set();
  return new Set(followed.filter((c) => c.text && !marksChannel(whole, c)).map((c) => c.channel_id));
}

/** The relay's `tells_who_left`: a gate, or joined by hand. Who is there goes by a list here,
 *  which the sweep keeps. Elsewhere anyone online may read. `gated` is the relay's word from
 *  `TextJoined`; with none yet the careful answer is that a list is needed. */
export function goesByList(channel: Pick<ChannelInfo, "auto_join" | "has_password"> | undefined, gated: boolean | undefined): boolean {
  return gated !== false || !channel?.auto_join || !!channel.has_password;
}

/** How many names a line of new readers shows. The rest are a click away, and never only a
 *  number: a listener among "N others" would not be named. */
const READERS_SHOWN = 5;

/** The line for new readers, with the whole list when it does not fit in it. */
export function readersLine(names: readonly string[]): { line: string; all: string[] } {
  const shown = names.slice(0, READERS_SHOWN);
  const rest = names.length - shown.length;
  const list =
    rest > 0
      ? `${shown.join(", ")} and ${rest} other${rest === 1 ? "" : "s"}`
      : shown.length > 1
        ? `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`
        : shown[0];
  return { line: `${list} can now read what you write here`, all: rest > 0 ? [...names] : [] };
}

/** What identifies a channel on this device across a rename and a restart. */
export function stableName(channel: Pick<ChannelInfo, "log" | "name">): string {
  return channel.log || channel.name;
}

/** Whether a list of marks names this channel, by log or by name. */
export function marksChannel(list: readonly string[] | ReadonlySet<string>, channel: Pick<ChannelInfo, "log" | "name">): boolean {
  const has = (x: string) => ("has" in list ? list.has(x) : list.includes(x));
  return (!!channel.log && has(channel.log)) || has(channel.name);
}
