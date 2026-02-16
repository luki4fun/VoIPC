import { writable } from "svelte/store";

export interface Poke {
  from_user_id: number;
  from_username: string;
  message: string;
  id: number;
}

let nextPokeId = 0;

export function createPoke(from_user_id: number, from_username: string, message: string): Poke {
  return { from_user_id, from_username, message, id: nextPokeId++ };
}

export const pendingPokes = writable<Poke[]>([]);
