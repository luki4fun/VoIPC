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
