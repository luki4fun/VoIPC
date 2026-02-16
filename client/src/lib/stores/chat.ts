import { writable, get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import type { ChatMessage } from "../types.js";

const MAX_MESSAGES = 500;

export interface DmConversation {
  user_id: number;
  username: string;
  unread: number;
}

// Channel chat messages: channel_name -> messages
export const channelMessages = writable<Map<string, ChatMessage[]>>(new Map());

// DM messages: "min-max" key -> messages
export const dmMessages = writable<Map<string, ChatMessage[]>>(new Map());

// Which DM is currently open (null = showing channel chat)
export const activeDmUserId = writable<number | null>(null);
export const activeDmUsername = writable<string>("");

// List of DM conversations for the sidebar
export const dmConversations = writable<DmConversation[]>([]);

// Per-channel unread message counts (keyed by channel name)
export const unreadPerChannel = writable<Map<string, number>>(new Map());

// Encrypted chat history state
export const chatUnlocked = writable<boolean>(false);
export const chatFileExists = writable<boolean | null>(null);

export interface ChatHistoryStatus {
  path_configured: boolean;
  current_path: string;
  file_exists: boolean;
}

export const chatHistoryStatus = writable<ChatHistoryStatus | null>(null);

function dmKey(a: number, b: number): string {
  return `${Math.min(a, b)}-${Math.max(a, b)}`;
}

// ---------------------------------------------------------------------------
// Debounced save to Tauri backend
// ---------------------------------------------------------------------------

let saveTimeout: ReturnType<typeof setTimeout> | null = null;

function scheduleSave() {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(async () => {
    saveTimeout = null;

    const chMap = get(channelMessages);
    const dmMap = get(dmMessages);

    // Convert Maps to plain objects for serde
    const channelObj: Record<string, ChatMessage[]> = {};
    chMap.forEach((msgs, name) => {
      channelObj[name] = msgs;
    });
    const dmObj: Record<string, ChatMessage[]> = {};
    dmMap.forEach((msgs, key) => {
      dmObj[key] = msgs;
    });

    try {
      await invoke("save_chat_messages", {
        channelMessages: channelObj,
        dmMessages: dmObj,
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
}) {
  const chMap = new Map<string, ChatMessage[]>();
  for (const [key, msgs] of Object.entries(archive.channels)) {
    chMap.set(key, msgs);
  }
  channelMessages.set(chMap);

  const dmMap = new Map<string, ChatMessage[]>();
  for (const [key, msgs] of Object.entries(archive.dms)) {
    dmMap.set(key, msgs);
  }
  dmMessages.set(dmMap);
}

// ---------------------------------------------------------------------------
// Message operations
// ---------------------------------------------------------------------------

export function addChannelMessage(channelName: string, msg: ChatMessage) {
  channelMessages.update((map) => {
    const existing = map.get(channelName) ?? [];
    const msgs = [...existing, msg];
    if (msgs.length > MAX_MESSAGES) {
      msgs.splice(0, msgs.length - MAX_MESSAGES);
    }
    map.set(channelName, msgs);
    return new Map(map);
  });
  scheduleSave();
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
  const key = dmKey(myId, peerId);

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

export function incrementChannelUnread(channelName: string) {
  unreadPerChannel.update((map) => {
    map.set(channelName, (map.get(channelName) ?? 0) + 1);
    return new Map(map);
  });
}

export function clearChannelUnread(channelName: string) {
  unreadPerChannel.update((map) => {
    map.delete(channelName);
    return new Map(map);
  });
}

export function clearChannelChat(channelName: string) {
  channelMessages.update((map) => {
    map.delete(channelName);
    return new Map(map);
  });
  scheduleSave();
}

export function clearDmChat(myId: number, peerId: number) {
  const key = dmKey(myId, peerId);
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
  try {
    await invoke("clear_chat_history");
  } catch (e) {
    console.error("Failed to clear chat history:", e);
  }
  channelMessages.set(new Map());
  dmMessages.set(new Map());
  dmConversations.set([]);
}
