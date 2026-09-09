import { get, writable } from "svelte/store";
import { patchUser, users } from "./users.js";

export type ConnectionState = "disconnected" | "connecting" | "connected" | "reconnecting";

export const connectionState = writable<ConnectionState>("disconnected");
export const serverAddress = writable<string>("");
export const username = writable<string>("");
export const userId = writable<number>(0);
export const sessionId = writable<number>(0);
export const latency = writable<number>(0);
export const isMuted = writable<boolean>(false);
export const isDeafened = writable<boolean>(false);

/**
 * Our own mute or deafen, after we changed it ourselves.
 *
 * The server does not send `UserMuted` back to the session that caused it — the
 * broadcast deliberately skips the sender — so nothing else would ever update
 * our own row in the member list. It stayed stale until the next `UserList`,
 * which is why it looked like a channel switch fixed it. The toolbar button was
 * right the whole time only because it reads these stores instead.
 */
export function setSelfMuted(muted: boolean): void {
  isMuted.set(muted);
  users.update((all) => patchUser(all, get(userId), { is_muted: muted }));
}

export function setSelfDeafened(deafened: boolean): void {
  isDeafened.set(deafened);
  users.update((all) => patchUser(all, get(userId), { is_deafened: deafened }));
}
export const isTransmitting = writable<boolean>(false);
export const acceptSelfSigned = writable<boolean>(false);

/** This session is logged in with the server's admin token. */
export const isAdmin = writable<boolean>(false);

/** From an invite link: the channel to join once connected. */
export interface PendingInvite {
  channel: string;
  password: string | null;
}
export const pendingInvite = writable<PendingInvite | null>(null);

/** Channel passwords this session used (create / join / invite), keyed by
 *  channel name, so invite links can carry them. Memory only. */
export const channelPasswords = writable<Map<string, string>>(new Map());
