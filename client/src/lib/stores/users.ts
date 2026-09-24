import { writable } from "svelte/store";
import type { UserInfo } from "../types.js";
// Explicit extension so Node's test runner can load this file as-is
import { scoped } from "./scoped.ts";

/** Who stands in the voice channel we are in on each server (channel 0 there: the lobby). */
export const users = scoped<UserInfo[]>(() => []);
/** Who is talking in the call. The call's, not a server's: only one carries voice. */
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
