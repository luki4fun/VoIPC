import { get, writable } from "svelte/store";
import { patchUser, users } from "./users.js";
import { splitAddress } from "../invite.js";

export type ConnectionState = "disconnected" | "connecting" | "connected" | "reconnecting";

export const connectionState = writable<ConnectionState>("disconnected");
export const serverAddress = writable<string>("");

/**
 * The server we are on, as `"host:port"`, or `""` before a connection.
 *
 * Anything kept per server is filed under this: the text channels a user
 * walked out of, and the chat history itself — two servers' `#general` are not
 * the same room, and one server must never be handed the other's messages.
 */
export function serverKey(): string {
  const address = get(serverAddress);
  if (!address) return "";
  const { host, port } = splitAddress(address);
  return `${host}:${port}`;
}
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

/**
 * A game is holding push-to-talk down for us, because the player pressed their
 * in-game radio key. Off unless they allowed it in Settings, and shown in the
 * voice bar: a microphone somebody else opened has to look different from one
 * you opened yourself.
 */
export const transmitHeldByGame = writable<boolean>(false);
export const acceptSelfSigned = writable<boolean>(false);

/** This session is logged in with the server's admin token. */
export const isAdmin = writable<boolean>(false);

/** From an invite link: the channel to join once connected. */
export interface PendingInvite {
  channel: string;
  password: string | null;
}
export const pendingInvite = writable<PendingInvite | null>(null);

/** Channel passwords this session used (create / join / invite), so invite
 *  links can carry them and a reconnect can get back in. Memory only, and
 *  keyed per server like everything else that is named rather than numbered —
 *  two servers' `#staff` are two channels and one password is not the other.
 *  Use the three helpers below rather than the map. */
export const channelPasswords = writable<Map<string, string>>(new Map());

const passwordKey = (name: string) => `${serverKey()}/${name}`;

/** Remember the password this session used for a channel on this server. */
export function rememberChannelPassword(name: string, password: string): void {
  channelPasswords.update((m) => new Map(m).set(passwordKey(name), password));
}

/** Forget it — the channel no longer has one. */
export function forgetChannelPassword(name: string): void {
  channelPasswords.update((m) => {
    const next = new Map(m);
    next.delete(passwordKey(name));
    return next;
  });
}

/** The password this session knows for a channel here, if any. */
export function channelPassword(name: string): string | null {
  return get(channelPasswords).get(passwordKey(name)) ?? null;
}
