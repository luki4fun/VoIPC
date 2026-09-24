// The servers: which are open, what they are called, and what the rail draws.
//
// Several can be open at once. Each is one connection in the backend, keyed by
// the id `serverId` builds — the string handed to `connect` as the address and
// passed as `server` to every command about that connection afterwards. The
// backend never re-normalizes it, so this is the one place an address becomes
// an id, and two spellings of one server cannot become two connections.
//
// Which one is on screen is `serverAddress` (scoped.ts); which one carries voice
// is `voice` (channels.ts). Neither is decided here.
//
// Pure — `svelte/store` and the address parser — so servers.test.ts can load it
// under Node. The derived list the rail reads, which needs every store in the
// app, is `serverEntries` in connect.ts.

import { writable } from "svelte/store";
import { splitAddress } from "../invite.ts";
import type { ConnectionState } from "./connection.js";
import type { DmConversation } from "./chat.js";
import type { SavedServer } from "./settings.js";

/** The open servers, in the order they were opened: connected, connecting or reconnecting. */
export const openServers = writable<string[]>([]);

/**
 * The id of a server: the host lower-cased, an IPv6 literal in brackets, then
 * the port. `Example.org` and `example.org` are one server, and `::1` must be
 * bracketed or the port cannot be told from the address.
 */
export function serverId(host: string, port: number): string {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h.includes(":") ? `[${h}]:${port}` : `${h}:${port}`;
}

/**
 * The prefix everything *named* on a server is kept under — chat history,
 * unread counts, channel passwords, the text channels a user walked out of —
 * as `"host:port"`, brackets stripped. That was the shape of those keys before
 * there was a server id, and keeping it keeps existing history addressable.
 * `""` for no server.
 */
export function serverKey(server: string): string {
  if (!server) return "";
  const { host, port } = splitAddress(server);
  return `${host}:${port}`;
}

/** What a server is called: its bookmark's name, or else its host. */
export function serverName(id: string, saved: SavedServer[]): string {
  const bookmark = saved.find((s) => serverId(s.host, s.port) === id);
  return bookmark ? bookmark.name || bookmark.host : splitAddress(id).host;
}

export interface ServerEntry {
  id: string;
  name: string;
  host: string;
  port: number;
  /** "disconnected" for a bookmark nobody opened. */
  state: ConnectionState;
  unread: number;
  /** Open right now, as opposed to only bookmarked. */
  open: boolean;
  /** The one whose channels and members are on screen. */
  active: boolean;
  /** The one carrying our voice. */
  inVoice: boolean;
}

/**
 * Everything the rail draws: the open servers in the order they were opened,
 * then every bookmark that is not open.
 *
 * `unread` is the channel unread map, keyed `"host:port/name"`; a server's
 * count is the sum of its own keys plus the unread of its conversation list.
 */
export function buildEntries(
  open: string[],
  states: Map<string, ConnectionState>,
  saved: SavedServer[],
  unread: Map<string, number>,
  viewed: string,
  voice: string | null,
  dms: Map<string, DmConversation[]> = new Map(),
): ServerEntry[] {
  const entries: ServerEntry[] = open.map((id) => {
    const { host, port } = splitAddress(id);
    const prefix = `${serverKey(id)}/`;
    let count = 0;
    for (const [key, n] of unread) if (key.startsWith(prefix)) count += n;
    for (const convo of dms.get(id) ?? []) count += convo.unread;
    return {
      id,
      name: serverName(id, saved),
      host,
      port,
      state: states.get(id) ?? "disconnected",
      unread: count,
      open: true,
      active: id === viewed,
      inVoice: id === voice,
    };
  });

  for (const bookmark of saved) {
    const id = serverId(bookmark.host, bookmark.port);
    if (entries.some((e) => e.id === id)) continue;
    entries.push({
      id,
      name: serverName(id, saved),
      host: bookmark.host,
      port: bookmark.port,
      state: "disconnected",
      unread: 0,
      open: false,
      active: false,
      inVoice: false,
    });
  }

  return entries;
}
