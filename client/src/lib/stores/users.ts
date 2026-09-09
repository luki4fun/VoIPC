import { writable } from "svelte/store";
import type { UserInfo } from "../types.js";

export const users = writable<UserInfo[]>([]);
export const speakingUsers = writable<Set<number>>(new Set());

/** One user's entry replaced. A list with nobody of that id comes back as it went in. */
export function patchUser(all: UserInfo[], id: number, patch: Partial<UserInfo>): UserInfo[] {
  return all.map((u) => (u.user_id === id ? { ...u, ...patch } : u));
}

/**
 * Who the member list shows.
 *
 * A channel may hide its members from non-admins: you then see yourself and
 * whoever has spoken recently, so their voice can still be turned down, but
 * not the roster. The clients still *receive* the roster — encryption keys are
 * exchanged per member — so this is a display rule, not a secret.
 */
export function visibleMembers(
  all: UserInfo[],
  selfId: number,
  recentSpeakers: Set<number>,
  hideMembers: boolean,
): UserInfo[] {
  if (!hideMembers) return all;
  return all.filter((u) => u.user_id === selfId || recentSpeakers.has(u.user_id));
}
