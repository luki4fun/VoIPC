import { derived, writable, get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import {
  applyEvent,
  dropExpired,
  fromArchived,
  isLegacyDmKey,
  MAX_MESSAGES,
  mergeHistory,
  newestTimestamp,
  pruneConversations,
  receivedText,
  rowKey,
  sanitizeHistory,
  messageRefs,
  toArchived,
  type EventIn,
} from "../chat-rules.js";
import { archivedPeers, closeMarkKey, listRows } from "../dm-rules.js";
import { previewChannelId, previewUsers } from "./channels.js";
import { serverAddress, serverKey, userId } from "./connection.js";
import { scoped } from "./scoped.js";
import { openServers } from "./servers.js";
import { chatHistoryDisabled, maxConversations } from "./settings.js";
import type { ChatMessage } from "../types.js";

export interface DmConversation {
  user_id: number;
  username: string;
  unread: number;
  /** Their relay account (hex), for a conversation filed from the stored
   *  log: while they are away (a negative `user_id`), a reply goes there. */
  account?: string;
}

/**
 * Channel chat: chat key -> messages, where the key is `"host:port/name"`.
 *
 * Scoped to the server, because two servers' `#general` are two rooms. Without
 * that, a server that puts everybody in a text channel called `general` on
 * connect (`auto_join`) could ask a member for "the history of #general" and be
 * handed what its user wrote on somebody else's server.
 *
 * Use [`chatKey`] rather than a bare name to read or write it.
 */
export const channelMessages = writable<Map<string, ChatMessage[]>>(new Map());

/**
 * Chat key -> the newest timestamp the user deleted there.
 *
 * Deleting has to mean something in a design where everyone else holds a copy:
 * without this, clearing a channel and reconnecting would fill it straight back
 * up from the first member who offers. Nothing at or older than the watermark
 * is merged, until the user asks for a re-sync, which drops it.
 */
export const clearedBefore = writable<Map<string, number>>(new Map());

/**
 * The key a channel's messages are filed under, on one server.
 *
 * Without a server there is none to name; the bare channel name is used, which
 * is also the shape every key had before 0.9 — see [`adoptLegacyKeys`] for how
 * those are carried over.
 */
export function chatKey(server: string, channelName: string): string {
  const key = serverKey(server);
  return key ? `${key}/${channelName}` : channelName;
}

// DM messages: "min-max" key -> messages
export const dmMessages = writable<Map<string, ChatMessage[]>>(new Map());

// Which DM is currently open (null = showing channel chat), per server
export const activeDmUserId = scoped<number | null>(() => null);
export const activeDmUsername = scoped<string>(() => "");

/**
 * The text channel whose chat is on screen, or null for the voice channel's.
 *
 * The chat pane follows this rather than the channel you stand in, which is
 * what lets you read #general while sitting in a voice room — and what keeps
 * joining a voice room from yanking the pane away from what you were reading.
 */
export const activeTextChannelId = scoped<number | null>(() => null);

/** Text channels we are subscribed to, as the server confirmed them. */
export const joinedTextChannelIds = scoped<Set<number>>(() => new Set());

// List of DM conversations for the sidebar, keyed by that server's user ids
export const dmConversations = scoped<DmConversation[]>(() => []);

/** The direct conversations both sidebars list on the server on screen:
 *  newest first, closed ones left out (dm-rules.ts `listRows`). */
export const dmList = derived(
  [dmConversations, dmMessages, clearedBefore, activeDmUserId, activeDmUsername, serverAddress],
  ([$rows, $dms, $marks, $id, $name, $server]) =>
    listRows($rows, $dms, serverKey($server), $marks, $id === null ? null : $name),
);

/**
 * Unread message counts, chat key -> count.
 *
 * Keyed like the messages themselves, and for the same reason: two servers'
 * `#general` are two rooms. A server's `auto_join` puts everybody into a
 * channel of that name on connect, so with a bare name one server's unread
 * count sits on another's row, and the server rail — which sums this — badges
 * a server the user is not even on.
 *
 * Read it through [`channelUnread`] rather than by hand.
 */
export const unreadPerChannel = writable<Map<string, number>>(new Map());

/** One channel row's unread count, in whichever sidebar is drawing the row. */
export function channelUnread(
  unread: Map<string, number>,
  server: string,
  channelName: string,
): number {
  // The map is passed in rather than read here so that the row re-renders when
  // it changes: the caller's `$unreadPerChannel` is the subscription.
  return unread.get(chatKey(server, channelName)) ?? 0;
}

// Encrypted chat history state
export const chatUnlocked = writable<boolean>(false);

export interface ChatHistoryStatus {
  path_configured: boolean;
  current_path: string;
  file_exists: boolean;
  /** "newer" and "unreadable" are files this version must neither open nor replace. */
  file_state: "none" | "ours" | "newer" | "unreadable";
}

export const chatHistoryStatus = writable<ChatHistoryStatus | null>(null);

/**
 * The key a conversation with one person is filed under.
 *
 * By their name and by the server, like everything else that is kept: it used
 * to be the two user ids, and a user id is a counter handed out afresh on
 * every connection and reused as people come and go. Yesterday's conversation
 * with one person was therefore shown as today's with whoever holds that pair
 * of numbers now — on any server. Names are not proof of who somebody is
 * either, but they are what the user reads, and a server keeps them unique
 * while people are on it.
 */
export function dmKey(server: string, peerName: string): string {
  return chatKey(server, peerName);
}

/**
 * Who each user id we opened a conversation with is, per server. An echo of
 * our own message carries our name, not theirs, and comes back after the
 * screen may have moved to somebody else: this, not what is open by then,
 * says whose conversation it is. Ids are the connection's, so this goes
 * with it (`clearServerUnread`).
 */
const openedIds = new Map<string, Map<number, string>>();

function noteOpened(server: string, id: number, name: string): void {
  if (id <= 0 || !name) return;
  let ids = openedIds.get(server);
  if (!ids) openedIds.set(server, (ids = new Map()));
  ids.set(id, name);
}

/** What we call the person behind an id: what their conversation is filed
 *  under already, whom we opened it with, or the name we were given. */
function peerName(server: string, peerId: number, fallback: string): string {
  return (
    get(dmConversations.peek(server)).find((c) => c.user_id === peerId)?.username ||
    openedIds.get(server)?.get(peerId) ||
    fallback
  );
}

/** The shape of a scoped key. A channel name may itself contain a slash. */
const SCOPED_KEY = /^[^/]+:\d+\//;

/**
 * The server legacy history is filed under: the first one this run connected
 * to. Set once — with several servers open, "the server we are on" is no
 * longer one answer, and an archive must not be split between them.
 */
let legacyOwner: string | null = null;

/**
 * Take history stored under a bare channel name — everything written before
 * 0.9, when there was one bucket per name and no server in the key — as
 * belonging to the first server this run connected to.
 *
 * A single-server user keeps everything. Somebody who used two servers keeps it
 * on whichever they connect to first, which is the best an unlabelled archive
 * allows; the alternative is throwing it away.
 *
 * Idempotent, and runs at both moments a legacy key can appear: connecting
 * (the archive was already open) and unlocking (we were already connected).
 */
export function adoptLegacyKeys(): void {
  const owner = serverKey(legacyOwner ?? "");
  if (!owner) return;
  let moved = 0;
  channelMessages.update((map) => {
    for (const [key, msgs] of [...map]) {
      if (SCOPED_KEY.test(key)) continue;
      const scopedKey = `${owner}/${key}`;
      if (!map.has(scopedKey)) map.set(scopedKey, msgs);
      map.delete(key);
      moved++;
    }
    return moved > 0 ? new Map(map) : map;
  });
  if (moved > 0) scheduleSave();
}

/**
 * A server finished connecting — the first of the two moments a bare key can
 * be sitting there. Only once the connection is up, never at the attempt:
 * history must not be filed under a server we never reached.
 */
export function claimLegacyKeys(server: string): void {
  if (legacyOwner === null) legacyOwner = server;
  adoptLegacyKeys();
  seedArchivedDms(server);
}

/** The next id an archived conversation stands under: below the ones a
 *  stored-log row takes from its account (`fileStoredDm`), so never the same. */
let archivedId = -(2 ** 30);

/**
 * List the archive's conversations on `server` again. The list belongs to a
 * connection and starts empty, while the messages are kept: without this an
 * old conversation could only be read once its person wrote again. Each
 * stands under a made-up negative id until they are here (`attachDm`).
 *
 * Runs where a server's list is new (connecting, `claimLegacyKeys`) and where
 * the archive is (unlocking, `populateFromArchive`).
 */
export function seedArchivedDms(server: string): void {
  const key = serverKey(server);
  if (!key) return;
  const peers = archivedPeers(get(dmMessages), key);
  if (peers.length === 0) return;
  dmConversations.of(server).update((convos) => {
    const fresh = peers.filter((p) => !convos.some((c) => c.username === p.name));
    if (fresh.length === 0) return convos;
    return [
      ...convos,
      ...fresh.map((p) => ({ user_id: archivedId--, username: p.name, unread: 0, ...(p.account ? { account: p.account } : {}) })),
    ];
  });
}

/**
 * Their conversation stands under `id` now: the one by that name, and the open
 * one with it if it is that. Without the second, the conversation on screen
 * kept an id nobody had, counted its own messages as unread, and lost where
 * writing to them goes.
 */
export function attachDm(server: string, name: string, id: number): void {
  noteOpened(server, id, name);
  // Asked first: an update that changes nothing still wakes every list
  const row = get(dmConversations.peek(server)).find((x) => x.username === name);
  if (!row || row.user_id === id) return;
  const moved = row.user_id;
  dmConversations.of(server).update((convos) => {
    const c = convos.find((x) => x.username === name);
    if (c) c.user_id = id;
    return [...convos];
  });
  if (get(activeDmUserId.peek(server)) === moved) activeDmUserId.of(server).set(id);
}

// ---------------------------------------------------------------------------
// Debounced save to Tauri backend
// ---------------------------------------------------------------------------

let saveTimeout: ReturnType<typeof setTimeout> | null = null;
/** When the save now waiting was first asked for. */
let saveAskedAt = 0;
/**
 * Debounced, but not for ever: a channel with a message every two seconds
 * restarted the wait with each one and was never saved until it went quiet.
 */
const SAVE_MAX_WAIT_MS = 10_000;

function scheduleSave() {
  if (saveTimeout) {
    // Long enough waiting: let the one already set go off
    if (Date.now() - saveAskedAt >= SAVE_MAX_WAIT_MS) return;
    clearTimeout(saveTimeout);
  } else {
    saveAskedAt = Date.now();
  }
  saveTimeout = setTimeout(() => void saveNow(), 2000);
}

/**
 * Save now whatever is waiting for the debounce. The app calls it before it
 * quits, and the page before it unloads: the backend writes the archive on
 * exit, but only what it has been handed (H4-09).
 */
export async function flushChatSave(): Promise<void> {
  if (!saveTimeout) return;
  clearTimeout(saveTimeout);
  await saveNow();
}

async function saveNow() {
  saveTimeout = null;

  // Each conversation is capped, but their number is not: every channel of
  // every server ever connected to, and one per person ever messaged. Pruned
  // here because this is the moment the whole map is walked anyway — and to
  // whatever the user set, including not at all, because what this drops is
  // somebody's oldest conversations off their own disk.
  const limit = get(maxConversations);
  const chMap = pruneConversations(get(channelMessages), limit);
  if (chMap !== get(channelMessages)) channelMessages.set(chMap);
  const dmMap = pruneConversations(get(dmMessages), limit);
  if (dmMap !== get(dmMessages)) dmMessages.set(dmMap);

  // Nothing keeps it: history off, the archive still locked, or the browser.
  // The pruning above still bounds memory; the copy of every conversation
  // over IPC that the backend throws away does not happen (H5-06).
  if (get(chatHistoryDisabled) || !get(chatUnlocked)) return;

  // Convert Maps to plain objects for serde
  const channelObj: Record<string, ChatMessage[]> = {};
  chMap.forEach((msgs, name) => {
    channelObj[name] = msgs.map(toArchived);
  });
  const dmObj: Record<string, ChatMessage[]> = {};
  dmMap.forEach((msgs, key) => {
    dmObj[key] = msgs.map(toArchived);
  });

  const clearedObj: Record<string, number> = {};
  get(clearedBefore).forEach((at, key) => {
    clearedObj[key] = at;
  });

  try {
    await invoke("save_chat_messages", {
      channelMessages: channelObj,
      dmMessages: dmObj,
      cleared: clearedObj,
    });
  } catch (e) {
    console.error("Failed to save chat history:", e);
  }
}

// ---------------------------------------------------------------------------
// Populate stores from decrypted archive
// ---------------------------------------------------------------------------

export function populateFromArchive(archive: {
  channels: Record<string, Array<ChatMessage>>;
  dms: Record<string, Array<ChatMessage>>;
  cleared?: Record<string, number>;
}) {
  // Anything whose destruction timer ran out while the app was closed never
  // reaches the screen. The backend drops the same messages from the file it
  // hands over; this is the copy in memory.
  const now = Date.now();
  const chMap = new Map<string, ChatMessage[]>();
  for (const [key, msgs] of Object.entries(archive.channels)) {
    const live = dropExpired(msgs.map(fromArchived), now);
    if (live.length > 0) chMap.set(key, live);
  }
  channelMessages.set(chMap);

  const dmMap = new Map<string, ChatMessage[]>();
  let droppedLegacyDms = 0;
  for (const [key, msgs] of Object.entries(archive.dms)) {
    // Written before 0.9 under two user ids; there is nothing in the file to
    // say who they were. See `isLegacyDmKey`.
    if (isLegacyDmKey(key)) {
      droppedLegacyDms++;
      continue;
    }
    const live = dropExpired(msgs.map(fromArchived), now);
    if (live.length > 0) dmMap.set(key, live);
  }
  if (droppedLegacyDms > 0) {
    console.info(`dropped ${droppedLegacyDms} conversation(s) filed under user ids`);
  }
  dmMessages.set(dmMap);

  clearedBefore.set(new Map(Object.entries(archive.cleared ?? {})));

  // Unlocking while already connected is the other moment a bare key appears
  adoptLegacyKeys();
  for (const server of get(openServers)) seedArchivedDms(server);
}

// ---------------------------------------------------------------------------
// Destruction timers
// ---------------------------------------------------------------------------

/**
 * How often the app looks for messages whose timer has run out.
 *
 * Not a timer per message: a channel of five hundred messages would be five
 * hundred timeouts, and the deadline is an absolute moment anyway, so a sweep
 * that compares it against the clock says the same thing. Ten seconds is under
 * what anybody reads as "it is still there".
 */
const SWEEP_INTERVAL_MS = 10_000;

/**
 * Drop every message that has come due, from every conversation.
 *
 * Exported so a test can run one sweep without waiting for the interval.
 * Returns how many went, which is also what decides whether to save: a sweep
 * that finds nothing must not rewrite the whole archive every ten seconds.
 */
export function sweepExpired(now = Date.now()): number {
  let dropped = 0;
  const prune = (store: typeof channelMessages) => {
    store.update((map) => {
      let changed = false;
      const next = new Map(map);
      for (const [key, msgs] of map) {
        const live = dropExpired(msgs, now);
        if (live === msgs) continue;
        dropped += msgs.length - live.length;
        changed = true;
        if (live.length > 0) next.set(key, live);
        else next.delete(key);
      }
      return changed ? next : map;
    });
  };
  prune(channelMessages);
  prune(dmMessages);
  if (dropped > 0) scheduleSave();
  return dropped;
}

let sweepTimer: ReturnType<typeof setInterval> | null = null;

/** Start the sweep. Idempotent, so a reconnect does not stack timers. */
export function startExpirySweep(): void {
  if (sweepTimer !== null) return;
  sweepTimer = setInterval(() => sweepExpired(), SWEEP_INTERVAL_MS);
}

// ---------------------------------------------------------------------------
// Message operations
// ---------------------------------------------------------------------------

/**
 * The messages each server's connection received, by row (`rowKey`): what a
 * guest's edit or delete may change, and what can be "ours" by user id alone
 * (thread-rules.ts `isOwn`). The relay hands user ids out again after a
 * restart, so an archived message under an id says nothing about who has it
 * now. Forgotten with the connection (`clearServerUnread`).
 */
const thisConnection = new Map<string, WeakSet<ChatMessage>>();

function noteReceived(server: string, m: ChatMessage): void {
  let seen = thisConnection.get(server);
  if (!seen) thisConnection.set(server, (seen = new WeakSet()));
  seen.add(rowKey(m));
}

/** Whether `m` reached us on `server`'s current connection. */
export function receivedNow(server: string, m: ChatMessage): boolean {
  return !!thisConnection.get(server)?.has(rowKey(m));
}

/** A message as it is kept: its text cut where it arrives (D-7). */
function bounded(m: ChatMessage): ChatMessage {
  const content = receivedText(m.content);
  return content === m.content ? m : { ...m, content };
}

/** Already here: the same message by its sender's account and id, read from
 *  the stored log before it came live (a message queued while its writer was
 *  alone goes out live later). */
function held(existing: ChatMessage[] | undefined, m: ChatMessage): boolean {
  return !!m.id && !!m.account && !!existing?.some((h) => h.id === m.id && h.account === m.account);
}

/** Returns whether it was new. */
export function addChannelMessage(server: string, channelName: string, msg: ChatMessage): boolean {
  const key = chatKey(server, channelName);
  if (held(get(channelMessages).get(key), msg)) return false;
  msg = bounded(msg);
  noteReceived(server, msg);
  channelMessages.update((map) => {
    const existing = map.get(key) ?? [];
    const msgs = [...existing, msg];
    if (msgs.length > MAX_MESSAGES) {
      msgs.splice(0, msgs.length - MAX_MESSAGES);
    }
    map.set(key, msgs);
    return new Map(map);
  });
  scheduleSave();
  return true;
}

/**
 * A message from a channel's stored log (`ChannelInfo.log`), merged the way
 * a member's history is — a copy of one already here is the same message, by
 * its writer's account and id — but not hearsay: its writer signed it. What
 * the user cleared stays cleared. Returns whether it was new.
 */
export function fileStoredChannelMessage(server: string, channelName: string, msg: ChatMessage): boolean {
  if (msg.expires_at !== undefined && msg.expires_at <= Date.now()) return false;
  msg = bounded(msg);
  const key = chatKey(server, channelName);
  if (purged(key, msg)) return false;
  const watermark = get(clearedBefore).get(key) ?? 0;
  let added = false;
  channelMessages.update((map) => {
    const { messages, added: n } = mergeHistory(map.get(key) ?? [], [msg], "", watermark);
    if (n === 0) return map;
    added = true;
    map.set(key, messages.filter((x) => x.kind !== "history-marker").slice(-MAX_MESSAGES));
    return new Map(map);
  });
  if (added) scheduleSave();
  return added;
}

/**
 * Merge channel history shared by a member.
 *
 * Several members may share the same channel — they hold different parts of it
 * — so this is a merge rather than a hand-over: see chat-rules.ts for how the
 * same message is recognised in two people's copies, and why what the user
 * deleted is not brought back.
 */
export function mergeChannelHistory(
  server: string,
  channelName: string,
  incoming: unknown[],
  sharedBy: string,
  // The channel's own destruction timer, as it is advertised right now. What a
  // sharer claims is clamped by it, and a message with no claim at all takes
  // it — see `expiryFor`.
  policyTtlSecs?: number | null,
) {
  const key = chatKey(server, channelName);
  const valid = sanitizeHistory(incoming, policyTtlSecs).filter((m) => !purged(key, m));
  if (valid.length === 0) return;

  const watermark = get(clearedBefore).get(key) ?? 0;
  let added = 0;
  channelMessages.update((map) => {
    const result = mergeHistory(map.get(key) ?? [], valid, sharedBy, watermark);
    added = result.added;
    if (added === 0) return map;
    map.set(key, result.messages);
    return new Map(map);
  });
  if (added > 0) scheduleSave();
}

/**
 * An edit, delete, reaction or pin, done to a message of a channel's chat
 * (`applyEvent` in chat-rules.ts has the rules). `mayPin`: its sender is one
 * of the channel's managers, by the roster's roles. Returns whether it
 * changed anything.
 */
export function applyChannelEvent(server: string, channelName: string, ev: EventIn, mayPin: boolean): boolean {
  return applyTo(server, channelMessages, chatKey(server, channelName), ev, mayPin);
}

/** `applyChannelEvent` for a direct conversation, filed as `addDmMessage`
 *  files a message (`dmKeyOf`). There is nothing to pin in one. */
export function applyDmEvent(server: string, myId: number, fromId: number, fromName: string, toId: number, ev: EventIn): boolean {
  return applyTo(server, dmMessages, dmKeyOf(server, myId, fromId, fromName, toId), ev, false);
}

/** A stored log's event in a direct conversation, filed under the peer's name
 *  as `fileStoredDm` files its messages. */
export function applyStoredDmEvent(server: string, peerName: string, ev: EventIn): boolean {
  return applyTo(server, dmMessages, dmKey(server, peerName), ev, false);
}

function applyTo(server: string, store: typeof channelMessages, key: string, ev: EventIn, mayPin: boolean): boolean {
  let changed = false;
  // An edit's new text is a message's text: cut where it arrives too
  const content = receivedText(ev.content);
  const current = (m: ChatMessage) => receivedNow(server, m);
  store.update((map) => {
    const list = map.get(key);
    if (!list) return map;
    const next = applyEvent(list, content === ev.content ? ev : { ...ev, content }, { mayPin, current });
    if (next === list) return map;
    changed = true;
    return new Map(map).set(key, next);
  });
  if (changed) scheduleSave();
  return changed;
}

/** The key a direct message is filed under: the peer's name, which for our
 *  own echo is that server's open conversation, not the one on screen. */
function dmKeyOf(server: string, myId: number, fromId: number, fromName: string, toId: number): string {
  const isEcho = fromId === myId;
  const peerId = isEcho ? toId : fromId;
  const activeName = get(activeDmUsername.peek(server));
  // Our own echo carries our name, not theirs; theirs is what the
  // conversation is filed under.
  return dmKey(server, isEcho ? peerName(server, peerId, activeName || "Unknown") : fromName);
}

export function addDmMessage(
  server: string,
  myId: number,
  fromId: number,
  fromName: string,
  toId: number,
  msg: ChatMessage,
) {
  const isEcho = fromId === myId;
  const peerId = isEcho ? toId : fromId;
  // That server's open conversation, not the one on screen: an echo names its
  // peer by what is open where it was sent.
  const activeName = get(activeDmUsername.peek(server));
  const activeId = get(activeDmUserId.peek(server));
  // Read only if it is on screen: a conversation left open on a server the
  // user has since switched away from is not being looked at, and its unread
  // count is the only thing that puts a badge on that server's rail icon.
  const onScreen =
    server === get(serverAddress) && (activeId === peerId || (!isEcho && activeId !== null && activeName === fromName));
  const key = dmKeyOf(server, myId, fromId, fromName, toId);
  if (held(get(dmMessages).get(key), msg)) return;
  msg = bounded(msg);
  noteReceived(server, msg);

  dmMessages.update((map) => {
    const existing = map.get(key) ?? [];
    const msgs = [...existing, msg];
    if (msgs.length > MAX_MESSAGES) {
      msgs.splice(0, msgs.length - MAX_MESSAGES);
    }
    map.set(key, msgs);
    return new Map(map);
  });
  scheduleSave();

  // Update DM conversations list
  let moved: number | undefined;
  dmConversations.of(server).update((convos) => {
    // A conversation filed under the same name becomes theirs: one from the
    // stored log or the archive, before its peer was here (a made-up negative
    // id), or one from before they reconnected under a new id (H5-07). Names
    // carry their tag, so a name is one person on a server, and one row.
    // The name it is filed under (`dmKeyOf`); for our echo, whom we opened it with
    const name = isEcho ? peerName(server, peerId, activeName || "Unknown") : fromName;
    const existing = convos.find((c) => c.user_id === peerId) ?? convos.find((c) => c.username === name);
    if (existing && existing.user_id !== peerId) {
      moved = existing.user_id;
      existing.user_id = peerId;
    }
    if (existing) {
      // Only update peer name from incoming messages, not our own echo
      if (!isEcho) {
        existing.username = fromName;
      }
      if (!onScreen) {
        existing.unread++;
        noteUnread(dmKey(server, existing.username), msg.timestamp);
      }
      return [...convos];
    } else {
      if (!onScreen) noteUnread(dmKey(server, name), msg.timestamp);
      return [
        ...convos,
        {
          user_id: peerId,
          username: name,
          unread: onScreen ? 0 : 1,
        },
      ];
    }
  });
  // The open conversation goes with its row (`attachDm`)
  if (moved !== undefined && activeId === moved) activeDmUserId.of(server).set(peerId);
}

/**
 * A message from a direct conversation's stored log (an account's, kept on the
 * relay while one of us was away), filed under the peer's name and merged the
 * way a member's history is: a copy of one already here — live, or fetched
 * on another occasion — is the same message, by its sender's account and id.
 */
export function fileStoredDm(
  server: string,
  m: {
    peer_name: string;
    peer_account: string;
    from_me: boolean;
    message_id: string | null;
    content: string;
    timestamp: number;
    reply_to?: string | null;
    thread?: string | null;
    file?: unknown;
    fwd?: unknown;
  },
  own: { name: string; account: string },
  expires_at: number | undefined,
  peerUserId: number | undefined,
) {
  // A name the relay did not give: filed under the account instead of lost,
  // since the read cursor has already moved past it.
  const peerName = m.peer_name || `account ${m.peer_account.slice(0, 8)}`;
  const key = dmKey(server, peerName);
  const msg: ChatMessage = {
    user_id: m.from_me ? get(userId.peek(server)) : (peerUserId ?? 0),
    username: m.from_me ? own.name : peerName,
    content: receivedText(m.content),
    timestamp: m.timestamp,
    id: m.message_id ?? undefined,
    account: m.from_me ? own.account : m.peer_account,
    expires_at,
    ...messageRefs(m),
  };
  if (expires_at !== undefined && expires_at <= Date.now()) return;
  if (purged(key, msg)) return;
  // What the user cleared stays cleared, as in a channel (1.0 audit H2-06)
  const watermark = get(clearedBefore).get(key) ?? 0;
  let added = false;
  dmMessages.update((map) => {
    const existing = map.get(key) ?? [];
    const { messages, added: n } = mergeHistory(existing, [msg], "", watermark);
    if (n === 0) return map;
    added = true;
    // The marker a member's hand-off draws is not wanted here: the log is the
    // conversation itself, not somebody's copy of it.
    map.set(key, messages.filter((x) => x.kind !== "history-marker").slice(-MAX_MESSAGES));
    return new Map(map);
  });
  if (!added) return;
  scheduleSave();
  dmConversations.of(server).update((convos) => {
    const existing = convos.find((c) => c.username === peerName);
    if (existing) {
      existing.account = m.peer_account;
      if (!m.from_me) {
        existing.unread++;
        noteUnread(key, m.timestamp);
      }
      return [...convos];
    }
    // Not here now: a negative id stands in until they are (addDmMessage).
    const id = peerUserId ?? -parseInt(m.peer_account.slice(0, 7), 16) - 1;
    if (!m.from_me) noteUnread(key, m.timestamp);
    return [...convos, { user_id: id, username: peerName, unread: m.from_me ? 0 : 1, account: m.peer_account }];
  });
}

/** Show a text channel's chat, or (null) the chat of the channel we stand in. */
export function openTextChannel(server: string, channelId: number | null) {
  activeTextChannelId.of(server).set(channelId);
  // A preview outranks this in `displayChannelId`, so asking for a channel has
  // to drop one that is up: looking at any channel you are not in otherwise
  // wedges the pane there, and every later click on a channel you *are* in
  // sets this and changes nothing on screen.
  //
  // Not for null, which means "back to where I stand" rather than "show me
  // this": it is passed when a channel disappears under the user, and a preview
  // up at that moment is what they are reading. The one place that wants both —
  // clicking the voice channel you are in — drops the preview itself.
  if (channelId !== null) {
    previewChannelId.of(server).set(null);
    previewUsers.of(server).set([]);
  }
  closeDm(server);
}

export function openDm(server: string, userId: number, username: string) {
  attachDm(server, username, userId);
  activeDmUserId.of(server).set(userId);
  activeDmUsername.of(server).set(username);
  // Opened on purpose (a row, search, a user's menu): a closed one is listed again
  forgetMark(closeMarkKey(dmKey(server, username)));

  // Clear unread for this conversation
  dmConversations.of(server).update((convos) => {
    const c = convos.find((x) => x.user_id === userId);
    if (c?.unread) markRead(dmKey(server, c.username));
    if (c) c.unread = 0;
    return [...convos];
  });
}

export function closeDm(server: string) {
  activeDmUserId.of(server).set(null);
  activeDmUsername.of(server).set("");
}

/**
 * Take a conversation off the list, keeping every message: it comes back when
 * something newer is written there, or when it is opened again. The mark is
 * kept with the deletion watermarks, in the encrypted archive, so it goes
 * where the conversation goes. At least its newest message's time, so a
 * sender's clock ahead of ours does not bring it straight back.
 */
export function closeDmRow(server: string, name: string): void {
  const key = dmKey(server, name);
  const at = Math.max(Date.now(), newestTimestamp(get(dmMessages).get(key) ?? []));
  clearedBefore.update((marks) => new Map(marks).set(closeMarkKey(key), at));
  unreadSince.delete(key);
  dmConversations.of(server).update((convos) => {
    const c = convos.find((x) => x.username === name);
    if (!c?.unread) return convos;
    c.unread = 0;
    return [...convos];
  });
  if (get(activeDmUserId.peek(server)) !== null && get(activeDmUsername.peek(server)) === name) closeDm(server);
  scheduleSave();
}

function forgetMark(mark: string): void {
  if (!get(clearedBefore).has(mark)) return;
  clearedBefore.update((marks) => {
    const next = new Map(marks);
    next.delete(mark);
    return next;
  });
  scheduleSave();
}

// ── Where "New" begins ──────────────────────────────────────────────────────
//
// The count of a conversation is cleared the moment it comes on screen, which
// is also the moment the pane wants to know where the unread part began. So
// the time its count left zero is kept, handed to `newMessagesAt` when the
// count is cleared, and kept there until the reader moves on.

/** When each conversation's first unread message arrived, by chat key. */
const unreadSince = new Map<string, number>();
/** Per chat key, where the conversation's "New" divider goes (a timestamp). */
export const newMessagesAt = writable<Map<string, number>>(new Map());

function noteUnread(key: string, at: number) {
  if (!unreadSince.has(key)) unreadSince.set(key, at);
}

/** A conversation came on screen: what was unread there is now where "New" begins. */
export function markRead(key: string) {
  const at = unreadSince.get(key);
  if (at === undefined) return;
  unreadSince.delete(key);
  newMessagesAt.update((map) => new Map(map).set(key, at));
}

/** The reader moved on: the conversation's divider has done its job. */
export function forgetNewMessages(key: string) {
  if (!get(newMessagesAt).has(key)) return;
  newMessagesAt.update((map) => {
    const next = new Map(map);
    next.delete(key);
    return next;
  });
}

export function incrementChannelUnread(server: string, channelName: string, at = Date.now()) {
  const key = chatKey(server, channelName);
  noteUnread(key, at);
  unreadPerChannel.update((map) => {
    map.set(key, (map.get(key) ?? 0) + 1);
    return new Map(map);
  });
}

export function clearChannelUnread(server: string, channelName: string) {
  const key = chatKey(server, channelName);
  if (!get(unreadPerChannel).has(key)) return;
  markRead(key);
  unreadPerChannel.update((map) => {
    map.delete(key);
    return new Map(map);
  });
}

/**
 * Delete a channel's chat here, and remember that it was deleted.
 *
 * The watermark is what makes that stick: every other member still holds a
 * copy, and without it the next one to share would hand it all straight back.
 */
export function clearChannelChat(server: string, channelName: string) {
  const key = chatKey(server, channelName);
  channelMessages.update((map) => {
    const newest = newestTimestamp(map.get(key) ?? []);
    if (newest > 0) {
      clearedBefore.update((marks) => new Map(marks).set(key, newest));
    }
    map.delete(key);
    return new Map(map);
  });
  scheduleSave();
}

/** Where a writer's tombstone is remembered: beside the chat's own mark. */
function purgeMarkKey(key: string, account: string): string {
  return `${key}\u0001${account}`;
}

/** The mark for hand-off copies that name a writer (`purgeWritten`): they
 *  carry no account, only the name. */
function namedMark(key: string, writerName: string): string {
  return purgeMarkKey(key, `n:${writerName}`);
}

/** Whether `msg`'s writer deleted it (`purgeWritten`): by its account, or for
 *  a member's copy, which carries none, by the name it gives. */
function purged(key: string, msg: ChatMessage): boolean {
  const mark = msg.account
    ? purgeMarkKey(key, msg.account)
    : msg.kind === "shared"
      ? namedMark(key, msg.username)
      : undefined;
  return mark !== undefined && msg.timestamp <= (get(clearedBefore).get(mark) ?? 0);
}

/**
 * A tombstone from a stored log: everything `account` wrote in this chat up to
 * `before` goes, and stays gone when copies of it are offered again. So do the
 * copies members handed over that name the writer (`writerName`, the relay's
 * name for that account) as written by then (D-13, R3-01): what only claims
 * to be theirs, taken away at their own request.
 */
export function purgeWritten(
  server: string,
  kind: "channel" | "dm",
  name: string,
  account: string,
  before: number,
  writerName = "",
) {
  const key = kind === "channel" ? chatKey(server, name) : dmKey(server, name);
  const marks = [purgeMarkKey(key, account), ...(writerName ? [namedMark(key, writerName)] : [])];
  clearedBefore.update((all) => {
    if (marks.every((mark) => (all.get(mark) ?? 0) >= before)) return all;
    const next = new Map(all);
    for (const mark of marks) if ((next.get(mark) ?? 0) < before) next.set(mark, before);
    return next;
  });
  const store = kind === "channel" ? channelMessages : dmMessages;
  const theirs = (m: ChatMessage) =>
    m.timestamp <= before &&
    (m.account === account || (!!writerName && m.kind === "shared" && m.username === writerName));
  store.update((map) => {
    const msgs = map.get(key);
    if (!msgs) return map;
    const kept = msgs.filter((m) => !theirs(m));
    if (kept.length === msgs.length) return map;
    map.set(key, kept);
    return new Map(map);
  });
  scheduleSave();
}

/**
 * Take back a deletion: history offered for this channel counts again.
 *
 * Deliberate, and the only way past the watermark — deleting by accident is
 * recoverable, being re-handed what you meant to delete is not.
 */
export function forgetClearedBefore(server: string, channelName: string) {
  const key = chatKey(server, channelName);
  clearedBefore.update((marks) => {
    if (!marks.has(key)) return marks;
    const next = new Map(marks);
    next.delete(key);
    return next;
  });
  scheduleSave();
}

export function clearDmChat(server: string, peerId: number, peerUsername: string) {
  const key = dmKey(server, peerUsername);
  dmMessages.update((map) => {
    // Remembered, so the conversation's stored log does not hand it back
    const newest = newestTimestamp(map.get(key) ?? []);
    if (newest > 0) clearedBefore.update((marks) => new Map(marks).set(key, newest));
    forgetMark(closeMarkKey(key));
    map.delete(key);
    return new Map(map);
  });
  dmConversations.of(server).update((convos) =>
    convos.filter((c) => c.user_id !== peerId),
  );
  // If we're viewing this DM, close it
  if (get(activeDmUserId.peek(server)) === peerId) {
    closeDm(server);
  }
  scheduleSave();
}

/**
 * Clear every channel's and every direct conversation's history, on every
 * server. Resolves to null when it worked, or to why the saved copy on disk
 * could not be removed — the screen is cleared either way, and the caller
 * says which of the two happened instead of "cleared" for both.
 */
export async function clearAllHistory(): Promise<string | null> {
  // Same rule as one channel: what was deleted must not be handed back
  const marks = new Map(get(clearedBefore));
  for (const chats of [get(channelMessages), get(dmMessages)]) {
    chats.forEach((msgs, key) => {
      const newest = newestTimestamp(msgs);
      if (newest > 0) marks.set(key, newest);
    });
  }
  clearedBefore.set(marks);

  let failure: string | null = null;
  try {
    await invoke("clear_chat_history");
  } catch (e) {
    console.error("Failed to clear chat history:", e);
    failure = String(e);
  }
  channelMessages.set(new Map());
  dmMessages.set(new Map());
  for (const server of get(dmConversations.all()).keys()) dmConversations.of(server).set([]);
  // The watermarks the backend kept are rewritten from what we just cleared
  scheduleSave();
  return failure;
}

/**
 * What was unread on one server goes with its connection. Counts belong to a
 * session: nobody comes back to a badge for messages they were told about
 * before the drop. The other servers' counts are theirs and stay.
 */
export function clearServerUnread(server: string) {
  // What this connection received goes with it too (`receivedNow`), and whom
  // its ids were (`peerName`)
  thisConnection.delete(server);
  openedIds.delete(server);
  const prefix = `${serverKey(server)}/`;
  for (const key of [...unreadSince.keys()]) if (key.startsWith(prefix)) unreadSince.delete(key);
  unreadPerChannel.update((map) => {
    const next = new Map([...map].filter(([key]) => !key.startsWith(prefix)));
    return next.size === map.size ? map : next;
  });
}
