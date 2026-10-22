// Connecting to servers, keeping them, and letting them go: the sequence, in
// one place.
//
// Several servers can be open at once, each its own connection in the backend
// under the id `serverId` builds. What is here: opening one (the connect
// dialog, a bookmark in the rail, the servers that were open at the last
// start), closing one (a Disconnect, the server showing us out), losing one and
// getting it back (the reconnect loop), and the list the rail draws.
//
// Nothing here decides where voice is. The backend does, and channels.ts
// mirrors it; closing the server that carries voice only lets go of the mirror.

import { hasNsfwConsent } from "./stores/channel-ui.js";
import { dropPrompts } from "./stores/account.js";
import { derived, get, writable, type Readable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import {
  acceptSelfSigned,
  channelPassword,
  connectionState,
  serverAddress,
  userId,
  username,
} from "./stores/connection.js";
import { voice, voiceServer } from "./stores/channels.js";
import {
  claimLegacyKeys,
  clearServerUnread,
  dmConversations,
  unreadPerChannel,
} from "./stores/chat.js";
import { pendingInvites } from "./stores/invites.js";
import { addNotification } from "./stores/notifications.js";
import { pendingPokes } from "./stores/pokes.js";
import { splitName, withTag } from "./username.js";
import { clearRosters } from "./stores/rosters.js";
import { dropServer, scoped } from "./stores/scoped.js";
import {
  buildEntries,
  openServers,
  serverId,
  serverName,
  type ServerEntry,
} from "./stores/servers.js";
import {
  lastAcceptSelfSigned,
  lastHost,
  lastPort,
  lastUsername,
  rememberConnection,
  savedServers,
  type SavedServer,
} from "./stores/settings.js";
import { resolveRejoin } from "./rejoin-rules.js";
import type { ChannelInfo } from "./types.js";

export { serverId };

// ── Events ─────────────────────────────────────────────────────────────────

/**
 * Listen for an event one connection sent. Every such event arrives as
 * `{ server, data }`; the handler gets both.
 *
 * An event for a server that is not open is dropped here. One can still be on
 * its way when the server is closed — the teardown races the reader — and
 * handling it would write that server's stores back into existence after they
 * were forgotten.
 */
export function listenServer<T>(
  name: string,
  handler: (server: string, data: T) => void,
): Promise<UnlistenFn> {
  return listen<{ server: string; data: T }>(name, (event) => {
    const { server, data } = event.payload;
    if (!get(openServers).includes(server)) return;
    handler(server, data);
  });
}

/** `"Name: "` for a server that is not on screen, so a toast from one in the
 *  background says where it is from; `""` for the one on screen. */
export function fromServer(server: string): string {
  return server === get(serverAddress) ? "" : `${serverName(server, get(savedServers))}: `;
}

// ── The list ───────────────────────────────────────────────────────────────

/** Everything the rail draws — see `buildEntries`. */
export const serverEntries: Readable<ServerEntry[]> = derived(
  [
    openServers,
    connectionState.all(),
    savedServers,
    unreadPerChannel,
    serverAddress,
    voiceServer,
    dmConversations.all(),
  ],
  ([$open, $states, $saved, $unread, $viewed, $voice, $dms]) =>
    buildEntries($open, $states, $saved, $unread, $viewed, $voice, $dms),
);

/** "+" in the rail asked for the connect dialog while servers are open. */
export const showConnectDialog = writable(false);

/** An account the connect dialog should open on, to sign in with the password
 *  (a reconnect found this device no longer remembered there). */
export const signInAgain = writable<{ host: string; port: number; name: string } | null>(null);

/** How each open server was reached: what a reconnect retries, and what the
 *  open list is saved as. Not a scoped store: losing a connection forgets
 *  the scoped state, and this is what brings it back. */
interface OpenDetails {
  host: string;
  port: number;
  /** The name in use there, which a reconnect asks for again: while the
   *  server still holds it, that is our own dropped session. */
  username: string;
  /** The name the user chose, which is what is remembered. Not the same as
   *  `username` when its tag was taken and a random one stood in. */
  asked: string;
  acceptSelfSigned: boolean;
  /** Signed in to an account there: a reconnect signs in again with the key
   *  this device was given, never with a password. */
  account?: boolean;
}
const details = new Map<string, OpenDetails>();

// ── Opening ────────────────────────────────────────────────────────────────

/** How a connect signs in to a relay account (account.rs `AccountArgs`). */
export interface AccountSignIn {
  /** "device": with the key this device got at an earlier sign-in. */
  mode: "login" | "register" | "device";
  password?: string;
  /** A sign-up invite code, where the relay wants one. */
  invite?: string | null;
}

export interface ConnectRequest {
  host: string;
  port: number;
  /** For an account, its name (no #tag). */
  username: string;
  acceptSelfSigned: boolean;
  /** Sign in to an account instead of coming as a guest. */
  account?: AccountSignIn;
  /** Save these details for next time. Leave out to keep the current setting. */
  remember?: boolean;
}

export interface ConnectOptions {
  /**
   * The user asked for this one (default). Such a connect is remembered — the
   * last-used details, and the list of open servers — and a failure is only
   * reported. An automatic one (startup) is neither remembered nor dropped on
   * failure: it goes to the reconnect loop, which keeps the server in the list.
   */
  manual?: boolean;
  /** Put it on screen once connected (default). */
  view?: boolean;
}

export type ConnectResult =
  | { ok: true; server: string; userId: number }
  | { ok: false; error: string };

/**
 * Open a server, and leave its stores describing what happened.
 *
 * Never throws: every caller has somewhere better to put the message than a
 * console — a field under the form, a toast, a line in the rail.
 */
export async function connectTo(
  request: ConnectRequest,
  { manual = true, view = true }: ConnectOptions = {},
): Promise<ConnectResult> {
  const { host, port, acceptSelfSigned: selfSigned, account } = request;
  // A name from before tags (a bookmark, the servers open at the last start)
  // takes the tag last used, or a new one, and keeps it. An account's name
  // has no tag: the account is what tells it apart.
  const { name, tag } = account ? { name: request.username.trim(), tag: "" } : splitName(request.username.trim());
  if (!host.trim() || !name.trim()) return { ok: false, error: "Please fill in all fields" };
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "Port must be between 1 and 65535" };
  }

  const server = serverId(host, port);
  if (get(openServers).includes(server)) {
    // One connection per server: this one is open, or on its way. Show it.
    if (view) serverAddress.set(server);
    return { ok: true, server, userId: get(userId.of(server)) };
  }

  const asked = account ? name : withTag(name, tag || splitName(get(lastUsername)).tag);
  let actual = asked;
  details.set(server, { host, port, username: actual, asked, acceptSelfSigned: selfSigned, account: !!account });
  // Open before the invoke, not after: the channel list arrives from the
  // reader task as soon as the server sends it, which can be before this call
  // returns, and `listenServer` drops events for servers that are not open.
  openServers.update((list) => [...list, server]);
  connectionState.of(server).set("connecting");

  let id: number;
  for (let tries = 0; ; tries++) {
    try {
      id = await invoke<number>("connect", {
        address: server,
        username: actual,
        acceptInvalidCerts: selfSigned,
        account: account
          ? { kind: account.mode, password: account.password ?? "", invite: account.invite ?? null }
          : null,
      });
      break;
    } catch (e) {
      const error = String(e);
      // Closed while it was trying: that already was the answer
      if (!get(openServers).includes(server)) return { ok: false, error };
      // Somebody there goes by this name and tag already. Another tag is
      // another name, and nobody's name is proof of who they are yet.
      if (!account && error.includes("username already taken") && tries < 3) {
        actual = withTag(name, "");
        details.set(server, { host, port, username: actual, asked, acceptSelfSigned: selfSigned, account: false });
        continue;
      }
      if (manual) {
        removeServer(server);
      } else {
        addNotification(`${serverName(server, get(savedServers))}: could not connect: ${error}`, "warning");
        void startReconnect(server, { voice: "", text: [] }, error);
      }
      return { ok: false, error };
    }
  }

  if (!get(openServers).includes(server)) {
    // Closed while the connect was on its way: do not adopt it
    invoke("disconnect", { server }).catch(() => {});
    return { ok: false, error: "Disconnected" };
  }

  userId.of(server).set(id);
  username.of(server).set(actual);
  acceptSelfSigned.of(server).set(selfSigned);
  connectionState.of(server).set("connected");
  claimLegacyKeys(server);
  if (actual !== asked) {
    addNotification(`${fromServer(server)}${asked} is taken there — you are ${actual}`, "info");
  }
  // Not asked to show it, but nothing else is on screen: better this one than
  // an empty window behind the connect dialog
  if (view || !get(serverAddress)) serverAddress.set(server);

  if (manual) {
    // Remembering is a separate concern from connecting, and a failure to
    // write the config must not report the connection as failed — it is up.
    const remember = request.remember ?? get(rememberConnection);
    try {
      await invoke("save_connection_info", {
        host,
        port,
        username: asked,
        acceptSelfSigned: selfSigned,
        remember,
      });
      rememberConnection.set(remember);
      if (remember) {
        lastHost.set(host);
        lastPort.set(port);
        lastUsername.set(asked);
        lastAcceptSelfSigned.set(selfSigned);
      }
    } catch (e) {
      console.warn("Could not save connection details:", e);
    }
    await saveOpenServers();
  } else if (!tag) {
    // The tag just made up for a name from before tags, kept: otherwise every
    // start would make up another
    await saveOpenServers();
  }

  return { ok: true, server, userId: id };
}

/**
 * Open every server that was open when the app last closed. Only the first is
 * put on screen — from the start, so its pane can say it is connecting, or
 * retrying — and a failure goes to the reconnect loop rather than away.
 */
export function reconnectAll(list: SavedServer[]): void {
  for (const s of list) {
    void connectTo(
      {
        host: s.host,
        port: s.port,
        username: s.username,
        acceptSelfSigned: s.accept_self_signed,
        account: s.account ? { mode: "device" } : undefined,
      },
      { manual: false, view: false },
    );
  }
  const first = list
    .map((s) => serverId(s.host, s.port))
    .find((id) => get(openServers).includes(id));
  if (first) serverAddress.set(first);
}

/**
 * Write down which servers are open, for the next start.
 *
 * After a connect or a Disconnect the user chose, never when a connection
 * drops: a server that went away is still one they meant to be on. With
 * "remember connection details" off nothing about where they connect is kept,
 * this list included.
 */
export async function saveOpenServers(): Promise<void> {
  const saved = get(savedServers);
  const servers: SavedServer[] = get(rememberConnection)
    ? get(openServers).flatMap((id) => {
        const d = details.get(id);
        if (!d) return [];
        return [
          {
            name: serverName(id, saved),
            host: d.host,
            port: d.port,
            username: d.asked,
            accept_self_signed: d.acceptSelfSigned,
            account: d.account ?? false,
          },
        ];
      })
    : [];
  try {
    await invoke("save_open_servers", { servers });
  } catch (e) {
    console.warn("Could not save the open servers:", e);
  }
}

// ── Closing ────────────────────────────────────────────────────────────────

/**
 * Forget what a connection held, keeping the server open: everything in a
 * scoped store, its unread counts, and the call if it was this server's.
 *
 * A channel id or a user id is a slot in one server's run — a reconnect may
 * land on a restarted server where the numbers have been handed out again — so
 * nothing of it is kept for the next connection to inherit.
 */
export function resetServer(server: string): void {
  clearRosters(server);
  dropServer(server);
  dropPrompts(server);
  clearServerUnread(server);
  if (get(voice)?.server === server) voice.set(null);
}

/** Take a server out of the list, and put the next one on screen if it was. */
function removeServer(server: string): void {
  const run = reconnectRuns.get(server);
  if (run) run.cancelled = true;
  reconnectRuns.delete(server);
  resetServer(server);
  details.delete(server);
  // What it sent can no longer be answered: its connection is gone
  pendingInvites.update((list) => list.filter((i) => i.server !== server));
  pendingPokes.update((list) => list.filter((p) => p.server !== server));

  const before = get(openServers);
  const index = before.indexOf(server);
  const after = before.filter((s) => s !== server);
  openServers.set(after);
  if (get(serverAddress) === server) {
    serverAddress.set(after[Math.min(index, after.length - 1)] ?? "");
  }
}

/**
 * Close one server. The others, and voice if it is on another one, stay.
 *
 * Forgotten *before* the backend is told, so nothing the connection says on
 * its way out — a `connection-lost` from the teardown — reaches a handler and
 * starts a reconnect or brings its stores back.
 *
 * `save: false` for a close the user did not choose (the server showed us
 * out), which leaves the open list as it was for the next start.
 */
export async function disconnectServer(
  server: string,
  { save = true }: { save?: boolean } = {},
): Promise<void> {
  removeServer(server);
  try {
    await invoke("disconnect", { server });
  } catch (e) {
    addNotification(`Failed to disconnect: ${e}`, "error");
  }
  if (save) await saveOpenServers();
}

// ── Losing one, and getting it back ────────────────────────────────────────

/** Where a reconnect loop is: shown by the overlay in that server's pane. */
export const reconnectInfo = scoped<{ attempt: number; error: string }>(() => ({
  attempt: 0,
  error: "",
}));

/** The loop running for each server; `cancelled` is how it is told to stop. */
const reconnectRuns = new Map<string, { cancelled: boolean; voiceTaken: boolean }>();

/**
 * Whoever is waiting for the channel list a fresh connection pushes, per
 * server.
 *
 * The list arrives as part of logging in, so it can land either side of
 * `invoke("connect")` resolving — which is why a caller registers the wait
 * *before* connecting rather than after.
 */
const channelListWaiters = new Map<string, Array<(list: ChannelInfo[]) => void>>();

/** App.svelte's `channel-list` handler reports every list here. */
export function channelListArrived(server: string, list: ChannelInfo[]): void {
  const waiting = channelListWaiters.get(server) ?? [];
  channelListWaiters.delete(server);
  for (const waiter of waiting) waiter(list);
}

function nextChannelList(server: string, timeoutMs = 5000): Promise<ChannelInfo[]> {
  return new Promise((resolve) => {
    const waiter = (list: ChannelInfo[]) => {
      clearTimeout(timer);
      resolve(list);
    };
    // No list, no rejoin: with nothing to resolve names against, the honest
    // answer is to leave the user where the server put them and let them
    // click. Guessing from a list we held before the drop is the bug.
    const timer = setTimeout(() => {
      const left = (channelListWaiters.get(server) ?? []).filter((w) => w !== waiter);
      if (left.length > 0) channelListWaiters.set(server, left);
      else channelListWaiters.delete(server);
      resolve([]);
    }, timeoutMs);
    channelListWaiters.set(server, [...(channelListWaiters.get(server) ?? []), waiter]);
  });
}

/**
 * Keep trying to get a lost server back, with a backoff, for five minutes.
 * The server stays in the list the whole time, and its pane says so.
 *
 * `previous` is where the user was, by name: the voice channel (only if the
 * call was on this server) and the text channels they had open.
 */
export async function startReconnect(
  server: string,
  previous: { voice: string; text: string[] },
  initialError = "",
): Promise<void> {
  const d = details.get(server);
  if (!d || reconnectRuns.has(server)) return;
  reconnectInfo.of(server).set({ attempt: 0, error: initialError });
  const run = { cancelled: false, voiceTaken: false };
  reconnectRuns.set(server, run);
  // Voice taken anywhere while this runs — even if left again since — means
  // the user has moved on from the call this server dropped: no rejoin then.
  // `voice === null` at the end cannot tell that from "never moved".
  const unwatch = voice.subscribe((v) => {
    if (v) run.voiceTaken = true;
  });
  try {
    await reconnectLoop(server, previous, d, run);
  } finally {
    unwatch();
  }
}

async function reconnectLoop(
  server: string,
  previous: { voice: string; text: string[] },
  d: OpenDetails,
  run: { cancelled: boolean; voiceTaken: boolean },
): Promise<void> {
  const info = reconnectInfo.of(server);
  connectionState.of(server).set("reconnecting");

  const startTime = Date.now();
  // Generous budget: a Wi-Fi roam, VPN flap, or laptop lid-close should
  // not end the session. The overlay has a Cancel button for giving up.
  const RECONNECT_TIMEOUT_MS = 300_000;

  for (let attempt = 1; !run.cancelled; attempt++) {
    info.update((i) => ({ ...i, attempt }));
    const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);

    // Wait before retrying
    await new Promise((resolve) => setTimeout(resolve, delay));
    if (run.cancelled) return;

    // Give up after the reconnect budget
    if (Date.now() - startTime > RECONNECT_TIMEOUT_MS) {
      addNotification(
        `${fromServer(server)}Reconnection timed out. Please reconnect manually.`,
        "error",
      );
      removeServer(server);
      return;
    }

    // Clean up stale connection state
    try {
      await invoke("disconnect", { server });
    } catch {
      // Ignore — may already be cleaned up
    }
    // Cancelled while that was on its way: a connect now could replace the
    // connection of a user who has just opened this server again by hand
    if (run.cancelled) return;

    try {
      // Registered before connecting: the server sends the channel list while
      // logging us in, so it can be here before `connect` has resolved.
      const listArrived = nextChannelList(server);
      const id = await invoke<number>("connect", {
        address: server,
        username: d.username,
        acceptInvalidCerts: d.acceptSelfSigned,
        // An account comes back with this device's key; there is no password to ask for here.
        account: d.account ? { kind: "device" } : null,
      });
      if (run.cancelled) {
        // Cancelled while this attempt was in flight — don't adopt its result,
        // unless the server has been opened again since, which is now its own
        if (!get(openServers).includes(server)) invoke("disconnect", { server }).catch(() => {});
        return;
      }
      reconnectRuns.delete(server);
      userId.of(server).set(id);
      username.of(server).set(d.username);
      acceptSelfSigned.of(server).set(d.acceptSelfSigned);
      connectionState.of(server).set("connected");
      info.set({ attempt: 0, error: "" });
      claimLegacyKeys(server);
      addNotification(`${fromServer(server)}Reconnected to server`, "info");

      // Where to go back to is decided against the list *this* connection
      // pushed, by name and by kind — see rejoin-rules.ts. Resolving a
      // remembered name against the ids we held before the drop is how a
      // reconnect ends up walking somebody into a voice channel.
      const list = await listArrived;
      if (!get(openServers).includes(server)) return;

      // The room they were standing in — unless voice has gone somewhere
      // else in the meantime. They took it there themselves, and pulling it
      // back here would end that call.
      const [room] = resolveRejoin(previous.voice ? [previous.voice] : [], list, "voice");
      // A room that turned 18+ meanwhile waits for the user's own yes.
      if (room && !run.voiceTaken && (!room.nsfw || hasNsfwConsent(server))) {
        try {
          // With the password, where this session knows one: a password room
          // is exactly the room a reconnect must not silently drop you out
          // of, and the text rejoin below has always carried it.
          await invoke("join_channel", {
            server,
            channelId: room.channel_id,
            password: room.has_password ? channelPassword(server, room.name) : null,
          });
        } catch {
          // Password changed, full, gone — stay out of voice
        }
      }
      // ...and the text channels that were open. An auto-join one comes back
      // on its own with the channel list; this is for the ones joined by
      // hand, which nothing else would bring back.
      for (const ch of resolveRejoin(previous.text, list, "text")) {
        // An `auto_join` one without a password is the effect's to re-join
        // (channel-ui.ts autoJoinTextChannels), which fires on the channel
        // list this connection just pushed. Asking for it here as well spends
        // two of the server's join tokens on one channel, and a connect that
        // runs out of them is a text channel that silently never opens. A
        // password one the effect skips, so it stays ours.
        if (ch.auto_join && !ch.has_password) continue;
        if (ch.nsfw && !hasNsfwConsent(server)) continue;
        // A password one comes back too, when this session knows the password
        const password = ch.has_password ? channelPassword(server, ch.name) : null;
        if (ch.has_password && password === null) continue;
        invoke("join_channel", { server, channelId: ch.channel_id, password }).catch(() => {
          // Gone with the server restart — the user can join it again
        });
      }
      return;
    } catch (e: any) {
      if (run.cancelled) return;
      const errMsg = typeof e === "string" ? e : e?.message ?? "Unknown error";
      if (errMsg.includes("username already taken")) {
        info.update((i) => ({ ...i, error: "Username still held by server, waiting..." }));
      } else if (errMsg.includes("version mismatch")) {
        addNotification(`${fromServer(server)}${errMsg}`, "error");
        removeServer(server);
        return;
      } else if (d.account && (errMsg.includes("not remembered") || errMsg.includes("key is damaged"))) {
        // Only the password signs this account in now, and a reconnect has
        // none to give: asked for, instead of retried for five minutes.
        addNotification(`${fromServer(server)}${errMsg}`, "error");
        removeServer(server);
        signInAgain.set({ host: d.host, port: d.port, name: d.username });
        showConnectDialog.set(true);
        return;
      } else {
        info.update((i) => ({ ...i, error: errMsg }));
      }
    }
  }
}

/** The overlay's Cancel: give up on that server, as a Disconnect would. */
export function cancelReconnect(server: string): void {
  void disconnectServer(server);
}
