import { get, writable } from "svelte/store";
import { patchUser, users } from "./users.js";
import { scoped, serverAddress } from "./scoped.js";
import { openServers, serverKey } from "./servers.js";
import { voiceServer } from "./channels.js";

export type ConnectionState = "disconnected" | "connecting" | "connected" | "reconnecting";

/** Each server's connection. The bare store is the one on screen. */
export const connectionState = scoped<ConnectionState>(() => "disconnected");

// The server on screen, and the key anything named on a server is filed under
// — two servers' `#general` are not the same room, and one server must never be
// handed the other's messages. Both live with the server list now; re-exported
// because this is where everything else has always imported them from.
export { serverAddress, serverKey };

export const username = scoped<string>(() => "");
export const userId = scoped<number>(() => 0);
export const sessionId = writable<number>(0);
export const latency = scoped<number>(() => 0);
/** Mute and deafen are ours, not a server's: one flag, sent to every server. */
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
  patchSelf({ is_muted: muted });
}

export function setSelfDeafened(deafened: boolean): void {
  isDeafened.set(deafened);
  patchSelf({ is_deafened: deafened });
}

/** Our own row on every open server: the flag went to all of them. */
function patchSelf(patch: { is_muted?: boolean; is_deafened?: boolean }): void {
  for (const server of get(openServers)) {
    const self = get(userId.of(server));
    users.of(server).update((all) => patchUser(all, self, patch));
  }
}
export const isTransmitting = writable<boolean>(false);

/**
 * A game is holding push-to-talk down for us, because the player pressed their
 * in-game radio key. Off unless they allowed it in Settings, and shown in the
 * voice bar: a microphone somebody else opened has to look different from one
 * you opened yourself.
 */
export const transmitHeldByGame = writable<boolean>(false);
export const acceptSelfSigned = scoped<boolean>(() => false);

/** This session is logged in with the server's admin token. */
export const isAdmin = scoped<boolean>(() => false);

// Who we are on the server carrying voice: the mixer, the room and the voice
// keys are about the call, whichever server is on screen.
export const voiceUserId = userId.at(voiceServer);
export const voiceUsername = username.at(voiceServer);
export const voiceIsAdmin = isAdmin.at(voiceServer);

/** From an invite link: the channel to join once connected. */
export interface PendingInvite {
  channel: string;
  password: string | null;
  /** The server it is for; unset until known, and then the server on screen. */
  server?: string;
}
export const pendingInvite = writable<PendingInvite | null>(null);

/** Channel passwords this session used (create / join / invite), so invite
 *  links can carry them and a reconnect can get back in. Memory only, and
 *  keyed per server like everything else that is named rather than numbered —
 *  two servers' `#staff` are two channels and one password is not the other.
 *  Use the three helpers below rather than the map. */
export const channelPasswords = writable<Map<string, string>>(new Map());

const passwordKey = (server: string, name: string) => `${serverKey(server)}/${name}`;

/** Remember the password this session used for a channel on a server. */
export function rememberChannelPassword(server: string, name: string, password: string): void {
  channelPasswords.update((m) => new Map(m).set(passwordKey(server, name), password));
}

/** Forget it — the channel no longer has one. */
export function forgetChannelPassword(server: string, name: string): void {
  channelPasswords.update((m) => {
    const next = new Map(m);
    next.delete(passwordKey(server, name));
    return next;
  });
}

/** The password this session knows for a channel on a server, if any. */
export function channelPassword(server: string, name: string): string | null {
  return get(channelPasswords).get(passwordKey(server, name)) ?? null;
}
