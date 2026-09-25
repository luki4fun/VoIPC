import { writable } from "svelte/store";

export interface Poke {
  /** The server it came from; `from_user_id` is that server's id. */
  server: string;
  from_user_id: number;
  from_username: string;
  message: string;
  id: number;
}

let nextPokeId = 0;

export function createPoke(
  server: string,
  from_user_id: number,
  from_username: string,
  message: string,
): Poke {
  return { server, from_user_id, from_username, message, id: nextPokeId++ };
}

export const pendingPokes = writable<Poke[]>([]);

/** Popups kept on screen at once: each one stays until clicked. */
export const MAX_POKES = 5;

/**
 * File a poke. A sender who pokes again replaces their own popup instead of
 * adding one, and only the newest `max` stay: otherwise anybody on a server
 * (at the relay's 50 messages a second), or a hostile server at any rate, can
 * bury the window in popups that each want a click. `fresh` is whether this
 * is a new popup, i.e. whether to make a sound about it.
 */
export function addPoke(list: Poke[], poke: Poke, max = MAX_POKES): { list: Poke[]; fresh: boolean } {
  const others = list.filter(
    (p) => !(p.server === poke.server && p.from_user_id === poke.from_user_id),
  );
  return { list: [...others, poke].slice(-max), fresh: others.length === list.length };
}
