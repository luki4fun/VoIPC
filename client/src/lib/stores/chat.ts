import { writable, get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import {
  dropExpired,
  isLegacyDmKey,
  MAX_MESSAGES,
  mergeHistory,
  newestTimestamp,
  pruneConversations,
  sanitizeHistory,
} from "../chat-rules.js";
import { connectionState, serverKey } from "./connection.js";
import { maxConversations } from "./settings.js";
import type { ChatMessage } from "../types.js";

export interface DmConversation {
  user_id: number;
  username: string;
  unread: number;
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
 * The key a channel's messages are filed under.
 *
 * Before a connection there is no server to name; the bare channel name is
 * used, which is also the shape every key had before this release — see
 * [`populateFromArchive`] for how those are carried over.
 */
export function chatKey(channelName: string): string {
  const server = serverKey();
  return server ? `${server}/${channelName}` : channelName;
}

// DM messages: "min-max" key -> messages
export const dmMessages = writable<Map<string, ChatMessage[]>>(new Map());

// Which DM is currently open (null = showing channel chat)
export const activeDmUserId = writable<number | null>(null);
export const activeDmUsername = writable<string>("");

/**
 * The text channel whose chat is on screen, or null for the voice channel's.
 *
 * The chat pane follows this rather than the channel you stand in, which is
 * what lets you read #general while sitting in a voice room — and what keeps
 * joining a voice room from yanking the pane away from what you were reading.
 */
export const activeTextChannelId = writable<number | null>(null);

/** Text channels we are subscribed to, as the server confirmed them. */
export const joinedTextChannelIds = writable<Set<number>>(new Set());

// List of DM conversations for the sidebar
export const dmConversations = writable<DmConversation[]>([]);

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
export function channelUnread(unread: Map<string, number>, channelName: string): number {
  // The map is passed in rather than read here so that the row re-renders when
  // it changes: the caller's `$unreadPerChannel` is the subscription.
  return unread.get(chatKey(channelName)) ?? 0;
}

// Encrypted chat history state
export const chatUnlocked = writable<boolean>(false);

export interface ChatHistoryStatus {
  path_configured: boolean;
  current_path: string;
  file_exists: boolean;
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
export function dmKey(peerName: string): string {
  return chatKey(peerName);
}

/** What we call the person behind an id: what their conversation is filed
 *  under already, or the name we were given. */
function peerName(peerId: number, fallback: string): string {
  return get(dmConversations).find((c) => c.user_id === peerId)?.username || fallback;
}

/** The shape of a scoped key. A channel name may itself contain a slash. */
const SCOPED_KEY = /^[^/]+:\d+\//;

/**
 * Take history stored under a bare channel name — everything written before
 * 0.9, when there was one bucket per name and no server in the key — as
 * belonging to the server we are on now.
 *
 * A single-server user keeps everything. Somebody who used two servers keeps it
 * on whichever they connect to first, which is the best an unlabelled archive
 * allows; the alternative is throwing it away.
 *
 * Idempotent, and runs at both moments a legacy key can appear: connecting
 * (the archive was already open) and unlocking (we were already connected).
 */
export function adoptLegacyKeys(): void {
  const server = serverKey();
  if (!server) return;
  let moved = 0;
  channelMessages.update((map) => {
    for (const [key, msgs] of [...map]) {
      if (SCOPED_KEY.test(key)) continue;
      const scoped = `${server}/${key}`;
      if (!map.has(scoped)) map.set(scoped, msgs);
      map.delete(key);
      moved++;
    }
    return moved > 0 ? new Map(map) : map;
  });
  if (moved > 0) scheduleSave();
}

// Connecting is one of the two moments a bare key can be sitting there. On the
// connection rather than the address, which is set before the attempt and put
// back if it fails — history must not be filed under a server we never reached.
connectionState.subscribe((state) => {
  if (state === "connected") adoptLegacyKeys();
});

// ---------------------------------------------------------------------------
// Debounced save to Tauri backend
// ---------------------------------------------------------------------------

let saveTimeout: ReturnType<typeof setTimeout> | null = null;

function scheduleSave() {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(async () => {
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

    // Convert Maps to plain objects for serde
    const channelObj: Record<string, ChatMessage[]> = {};
    chMap.forEach((msgs, name) => {
      channelObj[name] = msgs;
    });
    const dmObj: Record<string, ChatMessage[]> = {};
    dmMap.forEach((msgs, key) => {
      dmObj[key] = msgs;
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
  }, 2000);
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
    const live = dropExpired(msgs, now);
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
    const live = dropExpired(msgs, now);
    if (live.length > 0) dmMap.set(key, live);
  }
  if (droppedLegacyDms > 0) {
    console.info(`dropped ${droppedLegacyDms} conversation(s) filed under user ids`);
  }
  dmMessages.set(dmMap);

  clearedBefore.set(new Map(Object.entries(archive.cleared ?? {})));

  // Unlocking while already connected is the other moment a bare key appears
  adoptLegacyKeys();
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

export function addChannelMessage(channelName: string, msg: ChatMessage) {
  const key = chatKey(channelName);
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
  channelName: string,
  incoming: unknown[],
  sharedBy: string,
  // The channel's own destruction timer, as it is advertised right now. What a
  // sharer claims is clamped by it, and a message with no claim at all takes
  // it — see `expiryFor`.
  policyTtlSecs?: number | null,
) {
  const valid = sanitizeHistory(incoming, policyTtlSecs);
  if (valid.length === 0) return;

  const key = chatKey(channelName);
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

export function addDmMessage(
  myId: number,
  fromId: number,
  fromName: string,
  toId: number,
  msg: ChatMessage,
) {
  const isEcho = fromId === myId;
  const peerId = isEcho ? toId : fromId;
  // Our own echo carries our name, not theirs; theirs is what the
  // conversation is filed under.
  const key = dmKey(isEcho ? peerName(peerId, get(activeDmUsername) || "Unknown") : fromName);

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
  dmConversations.update((convos) => {
    const existing = convos.find((c) => c.user_id === peerId);
    if (existing) {
      // Only update peer name from incoming messages, not our own echo
      if (!isEcho) {
        existing.username = fromName;
      }
      if (get(activeDmUserId) !== peerId) {
        existing.unread++;
      }
      return [...convos];
    } else {
      // New conversation: use sender name for incoming, active DM name for echo
      const peerName = isEcho ? get(activeDmUsername) || "Unknown" : fromName;
      return [
        ...convos,
        {
          user_id: peerId,
          username: peerName,
          unread: get(activeDmUserId) === peerId ? 0 : 1,
        },
      ];
    }
  });
}

/** Show a text channel's chat, or (null) the chat of the channel we stand in. */
export function openTextChannel(channelId: number | null) {
  activeTextChannelId.set(channelId);
  closeDm();
}

export function openDm(userId: number, username: string, _myId: number) {
  activeDmUserId.set(userId);
  activeDmUsername.set(username);

  // Clear unread for this conversation
  dmConversations.update((convos) => {
    const c = convos.find((x) => x.user_id === userId);
    if (c) c.unread = 0;
    return [...convos];
  });
}

export function closeDm() {
  activeDmUserId.set(null);
  activeDmUsername.set("");
}

/**
 * Forget the conversation list, on disconnect.
 *
 * The messages stay — they are filed by server and name and are the user's
 * history. The *list* is not: every row in it is a user id from the
 * connection that just ended, and the next connection hands those same
 * numbers to other people.
 */
export function clearDmState() {
  dmConversations.set([]);
  closeDm();
}

export function incrementChannelUnread(channelName: string) {
  const key = chatKey(channelName);
  unreadPerChannel.update((map) => {
    map.set(key, (map.get(key) ?? 0) + 1);
    return new Map(map);
  });
}

export function clearChannelUnread(channelName: string) {
  const key = chatKey(channelName);
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
export function clearChannelChat(channelName: string) {
  const key = chatKey(channelName);
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

/**
 * Take back a deletion: history offered for this channel counts again.
 *
 * Deliberate, and the only way past the watermark — deleting by accident is
 * recoverable, being re-handed what you meant to delete is not.
 */
export function forgetClearedBefore(channelName: string) {
  const key = chatKey(channelName);
  clearedBefore.update((marks) => {
    if (!marks.has(key)) return marks;
    const next = new Map(marks);
    next.delete(key);
    return next;
  });
  scheduleSave();
}

export function clearDmChat(peerId: number, peerUsername: string) {
  const key = dmKey(peerUsername);
  dmMessages.update((map) => {
    map.delete(key);
    return new Map(map);
  });
  dmConversations.update((convos) =>
    convos.filter((c) => c.user_id !== peerId),
  );
  // If we're viewing this DM, close it
  if (get(activeDmUserId) === peerId) {
    closeDm();
  }
  scheduleSave();
}

export async function clearAllHistory() {
  // Same rule as one channel: what was deleted must not be handed back
  const marks = new Map(get(clearedBefore));
  get(channelMessages).forEach((msgs, key) => {
    const newest = newestTimestamp(msgs);
    if (newest > 0) marks.set(key, newest);
  });
  clearedBefore.set(marks);

  try {
    await invoke("clear_chat_history");
  } catch (e) {
    console.error("Failed to clear chat history:", e);
  }
  channelMessages.set(new Map());
  dmMessages.set(new Map());
  dmConversations.set([]);
  // The watermarks the backend kept are rewritten from what we just cleared
  scheduleSave();
}

/** A connection's subscriptions die with it, and so does what was unread in it. */
export function clearTextChannels() {
  joinedTextChannelIds.set(new Set());
  activeTextChannelId.set(null);
  // Counts belong to a session: nobody comes back to a badge for messages they
  // were told about before the drop, and the next server's rows are not these.
  unreadPerChannel.set(new Map());
}
