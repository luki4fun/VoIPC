// The server rail's list.
//
// **One connection exists at a time.** `AppState.connection` is an `Option` in
// Rust, `session.current` is a `Session | null` in the browser backend, and not
// one of the ~100 commands takes a connection id. This module does not change
// that and is not a step towards changing it on its own.
//
// What it does is make the *shape* right, so the rail is written against a list
// from the first commit rather than against "the connection" plus a special
// case. The day connections really are plural, this file grows a Map keyed by
// connection id and the rail does not change. What would still have to happen
// then, so nobody reads this as "multi-server is nearly done": `AppState
// .connection` and `session.current` become maps, every command and event gains
// a connection id, and `chat.ts` stops keying history by channel name alone —
// two servers with a `#general` collide today.

import { derived, type Readable } from "svelte/store";

import { connectionState, serverAddress, type ConnectionState } from "./connection.js";
import { unreadPerChannel } from "./chat.js";
import { savedServers } from "./settings.js";
import { splitAddress } from "../invite.js";

export interface ServerEntry {
  /** "host:port" today; a connection id the day there is more than one. */
  id: string;
  name: string;
  host: string;
  port: number;
  state: ConnectionState;
  unread: number;
  /** The one whose channels and members are on screen. */
  active: boolean;
}

/**
 * Everything the rail draws: the live connection first, then the bookmarks that
 * are not it.
 *
 * Nothing downstream may assume this has one entry, or reach past the entry it
 * was handed — that assumption is the thing this exists to prevent.
 */
export const serverEntries: Readable<ServerEntry[]> = derived(
  [connectionState, serverAddress, savedServers, unreadPerChannel],
  ([$state, $address, $saved, $unread]) => {
    const entries: ServerEntry[] = [];

    if ($address) {
      const { host, port } = splitAddress($address);
      // Unread is per channel and has no server dimension yet; with one
      // connection every count belongs to this entry.
      let total = 0;
      for (const n of $unread.values()) total += n;
      entries.push({
        id: `${host}:${port}`,
        name: $saved.find((s) => s.host === host && s.port === port)?.name ?? host,
        host,
        port,
        state: $state,
        unread: total,
        active: true,
      });
    }

    for (const saved of $saved) {
      const id = `${saved.host}:${saved.port}`;
      if (entries.some((e) => e.id === id)) continue;
      entries.push({
        id,
        name: saved.name || saved.host,
        host: saved.host,
        port: saved.port,
        state: "disconnected",
        unread: 0,
        active: false,
      });
    }

    return entries;
  },
);

export const activeServerId: Readable<string | null> = derived(
  serverEntries,
  ($entries) => $entries.find((e) => e.active)?.id ?? null,
);
