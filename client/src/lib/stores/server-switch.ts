// Clicking a server in the rail when you are already connected to another one.
//
// There is one connection, so this is a disconnect followed by a connect, and
// it drops whatever call you are in — which is why it asks first rather than
// doing it on a stray click.
//
// It goes through a store rather than calling ConnectDialog's own connect,
// which is component-local state plus a submit handler. The dialog mounts by
// itself the moment `connectionState` reaches "disconnected", sees this, and
// runs the same path as clicking one of its saved servers. One small store, no
// refactor of a dialog that works.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { connectionState } from "./connection.js";
import { savedServers } from "./settings.js";
import type { ServerEntry } from "./servers.js";

export interface PendingConnect {
  host: string;
  port: number;
  username: string;
  acceptSelfSigned: boolean;
}

/** Picked up by ConnectDialog once it is on screen. */
export const pendingConnect = writable<PendingConnect | null>(null);

/** The server a confirmation is being asked about, or null. */
export const switchPrompt = writable<ServerEntry | null>(null);

export function requestServerSwitch(entry: ServerEntry): void {
  if (get(connectionState) === "connected") {
    switchPrompt.set(entry);
    return;
  }
  void beginSwitch(entry);
}

export function cancelServerSwitch(): void {
  switchPrompt.set(null);
}

export async function confirmServerSwitch(): Promise<void> {
  const entry = get(switchPrompt);
  switchPrompt.set(null);
  if (entry) await beginSwitch(entry);
}

async function beginSwitch(entry: ServerEntry): Promise<void> {
  const saved = get(savedServers).find((s) => s.host === entry.host && s.port === entry.port);
  pendingConnect.set({
    host: entry.host,
    port: entry.port,
    // A bookmark carries the name it was saved with. Without one the dialog
    // keeps whatever is in its field, which is the last name used.
    username: saved?.username ?? "",
    acceptSelfSigned: saved?.accept_self_signed ?? false,
  });
  if (get(connectionState) !== "disconnected") {
    try {
      await invoke("disconnect");
    } catch {
      // Already gone; the state below is what matters
    }
    connectionState.set("disconnected");
  }
}
