// What a message in a channel does to this person: the count on the channel's
// row, the sound, and the system notification. Each person's own choice per
// channel, kept on their device: the relay is told nothing, and it cannot know
// which messages are for whom anyway.
// Pure, for notify-rules.test.ts.

export type NotifyLevel = "all" | "mentions" | "nothing";

/** Above this many members, a channel nobody chose a level for asks only for what
 *  is for you: a sound for each of a thousand people's messages is no use to anybody. */
export const QUIET_ABOVE_MEMBERS = 50;

/** The level chosen, or the one for a channel of this size. */
export function levelOf(chosen: NotifyLevel | undefined, members: number): NotifyLevel {
  return chosen ?? (members > QUIET_ABOVE_MEMBERS ? "mentions" : "all");
}

export function nextLevel(level: NotifyLevel): NotifyLevel {
  return level === "all" ? "mentions" : level === "mentions" ? "nothing" : "all";
}

export function levelTitle(level: NotifyLevel): string {
  return level === "all"
    ? "Notifying you of every message here. Click for only what is for you."
    : level === "mentions"
      ? "Notifying you only of replies and mentions here. Click for nothing."
      : "No notifications from here. Click for every message.";
}

/**
 * What one message does.
 *
 * `forMe` still sounds on "mentions" where "all" would: the system notification
 * shows only while the window is unfocused, so a mention would otherwise arrive
 * in silence while another channel is on screen.
 */
export function arrival(
  level: NotifyLevel,
  m: { mine: boolean; onScreen: boolean; forMe: boolean },
): { count: boolean; sound: boolean; os: boolean } {
  if (level === "nothing") return { count: false, sound: false, os: false };
  const wanted = level === "all" || m.forMe;
  return {
    count: !m.onScreen && wanted,
    sound: !m.onScreen && wanted && !m.mine,
    os: m.forMe && !m.mine,
  };
}
