// Connecting to a server: the sequence, in one place.
//
// It existed three times before — the connect dialog, auto-connect on startup,
// and the reconnect loop — each setting the same six stores, and the server rail
// would have made a fourth. The reconnect loop keeps its own copy on purpose:
// it retries with a backoff and reads specific error strings, which is a
// different job from "connect once and report what happened".

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import {
  acceptSelfSigned,
  connectionState,
  serverAddress,
  userId,
  username,
} from "./stores/connection.js";
import {
  lastAcceptSelfSigned,
  lastHost,
  lastPort,
  lastUsername,
  rememberConnection,
} from "./stores/settings.js";

export interface ConnectRequest {
  host: string;
  port: number;
  username: string;
  acceptSelfSigned: boolean;
  /** Save these details for next time. Leave out to keep the current setting. */
  remember?: boolean;
}

export type ConnectResult = { ok: true; userId: number } | { ok: false; error: string };

/**
 * Connect, and leave the connection stores describing what happened.
 *
 * Never throws: every caller has somewhere better to put the message than a
 * console — a field under the form, a toast, a line in the rail.
 */
export async function connectTo(request: ConnectRequest): Promise<ConnectResult> {
  const { host, port, username: name, acceptSelfSigned: selfSigned } = request;
  if (!host || !name) return { ok: false, error: "Please fill in all fields" };
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "Port must be between 1 and 65535" };
  }

  const address = `${host}:${port}`;
  connectionState.set("connecting");

  let id: number;
  try {
    id = await invoke<number>("connect", {
      address,
      username: name,
      acceptInvalidCerts: selfSigned,
    });
  } catch (e) {
    connectionState.set("disconnected");
    return { ok: false, error: String(e) };
  }

  userId.set(id);
  serverAddress.set(address);
  username.set(name);
  acceptSelfSigned.set(selfSigned);
  connectionState.set("connected");

  // Remembering is a separate concern from connecting, and a failure to write
  // the config must not report the connection as failed — it is already up.
  const remember = request.remember ?? get(rememberConnection);
  try {
    await invoke("save_connection_info", {
      host,
      port,
      username: name,
      acceptSelfSigned: selfSigned,
      remember,
    });
    rememberConnection.set(remember);
    if (remember) {
      lastHost.set(host);
      lastPort.set(port);
      lastUsername.set(name);
      lastAcceptSelfSigned.set(selfSigned);
    }
  } catch (e) {
    console.warn("Could not save connection details:", e);
  }

  return { ok: true, userId: id };
}
