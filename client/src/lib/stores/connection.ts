import { writable } from "svelte/store";

export type ConnectionState = "disconnected" | "connecting" | "connected" | "reconnecting";

export const connectionState = writable<ConnectionState>("disconnected");
export const serverAddress = writable<string>("");
export const username = writable<string>("");
export const userId = writable<number>(0);
export const sessionId = writable<number>(0);
export const latency = writable<number>(0);
export const isMuted = writable<boolean>(false);
export const isDeafened = writable<boolean>(false);
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
