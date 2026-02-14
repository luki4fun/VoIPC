<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { tick } from "svelte";
  import { channels, currentChannelId, previewChannelId } from "../stores/channels.js";
  import { userId } from "../stores/connection.js";
  import {
    channelMessages,
    dmMessages,
    activeDmUserId,
    activeDmUsername,
    closeDm,
    unreadPerChannel,
    clearChannelChat,
    clearDmChat,
  } from "../stores/chat.js";
  import type { ChatMessage } from "../types.js";

  let messageInput = $state("");
  let messagesContainer = $state<HTMLDivElement | null>(null);

  // DM key helper
  function dmKey(a: number, b: number): string {
    return `${Math.min(a, b)}-${Math.max(a, b)}`;
  }

  let isDmMode = $derived($activeDmUserId !== null);

  // Which channel's chat to display (preview takes priority over current)
  let isPreviewing = $derived(
    $previewChannelId !== null && $previewChannelId !== $currentChannelId
  );
  let effectiveChannelId = $derived(
    isPreviewing ? $previewChannelId! : $currentChannelId
  );

  let effectiveChannel = $derived(
    $channels.find((c) => c.channel_id === effectiveChannelId)
  );
  let channelName = $derived(effectiveChannel?.name ?? "");
  let isPasswordProtected = $derived(effectiveChannel?.has_password ?? false);

  let isLobby = $derived(effectiveChannelId === 0);

  // Can send messages only in own channel (not previewing, not lobby, not DM-locked)
  let canSendChannelMessage = $derived(!isPreviewing && !isLobby && !isDmMode);

  let totalUnreadChannels = $derived.by(() => {
    let total = 0;
    for (const count of $unreadPerChannel.values()) {
      total += count;
    }
    return total;
  });

  let displayMessages = $derived.by((): ChatMessage[] => {
    // Read both stores unconditionally so Svelte always tracks them as
    // dependencies — otherwise the branch that isn't taken loses its
    // subscription and accumulated messages won't appear when switching views.
    const chMap = $channelMessages;
    const dmMap = $dmMessages;

    if (isDmMode) {
      const key = dmKey($userId, $activeDmUserId!);
      return [...(dmMap.get(key) ?? [])];
    }
    return [...(chMap.get(channelName) ?? [])];
  });

  // Auto-scroll when messages change
  $effect(() => {
    // Access displayMessages to track changes
    displayMessages;
    tick().then(() => {
      if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      }
    });
  });

  function formatTime(timestamp: number): string {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function shouldShowHeader(index: number): boolean {
    if (index === 0) return true;
    const prev = displayMessages[index - 1];
    const curr = displayMessages[index];
    // Show header if different user or more than 5 minutes apart
    return (
      prev.user_id !== curr.user_id ||
      curr.timestamp - prev.timestamp > 5 * 60 * 1000
    );
  }

  async function sendMessage() {
    const content = messageInput.trim();
    if (!content) return;

    messageInput = "";

    try {
      if (isDmMode) {
        await invoke("send_direct_message", {
          targetUserId: $activeDmUserId,
          content,
        });
      } else {
        await invoke("send_channel_message", { content });
      }
    } catch (e) {
      console.error("Failed to send message:", e);
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  function backToChannel() {
    closeDm();
  }

  function clearCurrentChat() {
    if (isDmMode) {
      clearDmChat($userId, $activeDmUserId!);
    } else {
      clearChannelChat(channelName);
    }
  }
</script>

<div class="chat-panel">
  <div class="chat-header">
    {#if isDmMode}
      <button class="back-btn" onclick={backToChannel} title="Back to channel chat">&larr;</button>
      <span class="chat-title">DM with {$activeDmUsername}</span>
      {#if totalUnreadChannels > 0}
        <span class="unread-badge" title="Unread channel messages">{totalUnreadChannels}</span>
      {/if}
    {:else}
      <span class="chat-title"># {channelName}</span>
      {#if isPreviewing}
        <span class="preview-label">preview</span>
      {/if}
    {/if}
    {#if displayMessages.length > 0 && !isLobby}
      <button class="clear-chat-btn" onclick={clearCurrentChat} title="Clear chat history">&#128465;</button>
    {/if}
  </div>

  <div class="messages" bind:this={messagesContainer}>
    {#if !isDmMode && isLobby}
      <div class="empty-state">Chat is not available in the lobby. Join a channel to chat.</div>
    {:else if !isDmMode && isPreviewing && isPasswordProtected}
      <div class="empty-state">This channel is password protected. Join to view messages.</div>
    {:else if displayMessages.length === 0}
      <div class="empty-state">
        {#if isDmMode}
          No messages yet. Say hi!
        {:else}
          No messages yet.{#if isPreviewing} Messages will appear here in real-time.{:else} Start the conversation!{/if}
        {/if}
      </div>
    {:else}
      {#each displayMessages as msg, i (msg.timestamp + "-" + msg.user_id + "-" + i)}
        {#if shouldShowHeader(i)}
          <div class="msg-header">
            <span class="msg-username" class:self={msg.user_id === $userId}>{msg.username}</span>
            <span class="msg-time">{formatTime(msg.timestamp)}</span>
          </div>
        {/if}
        <div class="msg-content">{msg.content}</div>
      {/each}
    {/if}
  </div>

  {#if isDmMode}
    <form class="input-bar" onsubmit={(e) => { e.preventDefault(); sendMessage(); }}>
      <input
        class="chat-input"
        type="text"
        placeholder={`Message ${$activeDmUsername}...`}
        bind:value={messageInput}
        onkeydown={handleKeydown}
        maxlength="2000"
      />
      <button class="send-btn" type="submit" disabled={!messageInput.trim()}>Send</button>
    </form>
  {:else if canSendChannelMessage}
    <form class="input-bar" onsubmit={(e) => { e.preventDefault(); sendMessage(); }}>
      <input
        class="chat-input"
        type="text"
        placeholder={`Message #${channelName}...`}
        bind:value={messageInput}
        onkeydown={handleKeydown}
        maxlength="2000"
      />
      <button class="send-btn" type="submit" disabled={!messageInput.trim()}>Send</button>
    </form>
  {:else if isPreviewing && !isLobby && !isPasswordProtected}
    <div class="preview-footer">Double-click channel to join and chat</div>
  {/if}
</div>

<style>
  .chat-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
    flex: 1;
    min-width: 0;
  }

  .chat-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
  }

  .chat-title {
    font-weight: 600;
  }

  .back-btn {
    background: transparent;
    color: var(--text-secondary);
    font-size: 16px;
    padding: 0 4px;
    border: none;
    cursor: pointer;
    line-height: 1;
  }

  .back-btn:hover {
    color: var(--text-primary);
  }

  .clear-chat-btn {
    margin-left: auto;
    background: transparent;
    color: var(--text-secondary);
    font-size: 14px;
    padding: 0 4px;
    border: none;
    cursor: pointer;
    line-height: 1;
    opacity: 0.35;
    transition: opacity 0.15s;
  }

  .chat-header:hover .clear-chat-btn {
    opacity: 0.8;
  }

  .clear-chat-btn:hover {
    color: var(--danger);
  }

  .unread-badge {
    background: var(--accent);
    color: white;
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 10px;
    font-weight: 600;
  }

  .messages {
    flex: 1;
    overflow-y: auto;
    padding: 8px 16px;
  }

  .empty-state {
    color: var(--text-secondary);
    font-size: 13px;
    text-align: center;
    padding: 32px 16px;
    font-style: italic;
  }

  .msg-header {
    display: flex;
    align-items: baseline;
    gap: 8px;
    margin-top: 8px;
    margin-bottom: 2px;
  }

  .msg-username {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .msg-username.self {
    color: var(--accent);
  }

  .msg-time {
    font-size: 10px;
    color: var(--text-secondary);
  }

  .msg-content {
    font-size: 13px;
    color: var(--text-primary);
    padding-left: 0;
    line-height: 1.4;
    word-break: break-word;
  }

  .input-bar {
    display: flex;
    gap: 8px;
    padding: 8px 12px;
    border-top: 1px solid var(--border);
  }

  .chat-input {
    flex: 1;
    padding: 8px 12px;
    font-size: 13px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
  }

  .chat-input:focus {
    border-color: var(--accent);
  }

  .send-btn {
    background: var(--accent);
    color: white;
    padding: 8px 16px;
    font-size: 12px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .send-btn:hover:not(:disabled) {
    opacity: 0.9;
  }

  .send-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .preview-label {
    font-size: 9px;
    color: var(--accent);
    border: 1px solid var(--accent);
    padding: 1px 5px;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .preview-footer {
    padding: 10px 16px;
    font-size: 12px;
    color: var(--text-secondary);
    text-align: center;
    border-top: 1px solid var(--border);
    font-style: italic;
  }
</style>
