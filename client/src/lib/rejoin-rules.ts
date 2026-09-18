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
