// What a message in a channel does to this person: the count on the channel's
// row, the sound, and the system notification. Each person's own choice per
// channel, kept on their device: the relay is told nothing, and it cannot know
// which messages are for whom anyway.
// Pure, for notify-rules.test.ts.

export type NotifyLevel = "all" | "mentions" | "nothing";

/** Whether a person can see this page now, so a system notification would tell them nothing.
 *  A WebView behind HOME goes on saying it has focus: only `hidden` tells. */
export function pageInView(page: { hidden: boolean; hasFocus(): boolean }): boolean {
  return !page.hidden && page.hasFocus();
}

/** Whether a pointer over a toast holds its clock: a mouse, which also says when it has left.
 *  A tap says nothing of the kind, and the toast would stay until the next tap elsewhere. */
export function holdsToast(pointerType: string): boolean {
  return pointerType === "mouse";
}

/** Above this many members, a channel nobody chose a level for asks only for what
 *  is for you: a sound for each of a thousand people's messages is no use to anybody. */
export const QUIET_ABOVE_MEMBERS = 50;

/** The level chosen, or the one for a channel of this size. One the server asks everyone to
 *  follow asks only for what is for you, whatever its size: nobody chose to hear all of it. */
export function levelOf(chosen: NotifyLevel | undefined, members: number, autoFollowed = false): NotifyLevel {
  return chosen ?? (autoFollowed || members > QUIET_ABOVE_MEMBERS ? "mentions" : "all");
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
