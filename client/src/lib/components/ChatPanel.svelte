<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    /**
     * Extra controls for the right-hand end of the header.
     *
     * The classic layout has a voice bar to put its room and mixer buttons in;
     * the modern one does not, so they live here. A snippet rather than a
     * `variant` string: one prop, and the shell keeps its own markup.
     */
    headerExtra?: Snippet;
  }
  let { headerExtra }: Props = $props();
  import { invoke } from "@tauri-apps/api/core";
  import { tick } from "svelte";
  import { channels } from "../stores/channels.js";
  import { uiPrefs } from "../stores/ui-prefs.js";
  import { userId } from "../stores/connection.js";
  import { addNotification } from "../stores/notifications.js";
  import {
    channelMessages,
    chatKey,
    dmKey,
    dmMessages,
    activeDmUserId,
    activeDmUsername,
    closeDm,
    forgetClearedBefore,
    joinedTextChannelIds,
    unreadPerChannel,
    clearChannelChat,
    clearDmChat,
  } from "../stores/chat.js";
  import {
    channelMessageTtl,
    dmMessageTtl,
    joinTextChannel,
    leftTextChannelNames,
    setDmMessageTtl,
  } from "../stores/channel-ui.js";
  import { displayChannelId, isPreviewing } from "../stores/roster.js";
  import { channelRosters } from "../stores/rosters.js";
  import type { ChatMessage } from "../types.js";
  import Icon from "./Icons.svelte";

  let messageInput = $state("");
  let messagesContainer = $state<HTMLDivElement | null>(null);
  let chatInputEl = $state<HTMLInputElement | null>(null);

  // ── Link handling: URLs become buttons that open a copy popup (never a
  // browser). Rendering stays plain text nodes — no HTML injection surface.
  const URL_RE = /(https?:\/\/[^\s]+)/g;

  function splitSegments(text: string): Array<{ text: string; url: boolean }> {
    return text
      .split(URL_RE)
      .filter((p) => p !== "")
      .map((p) => ({ text: p, url: /^https?:\/\//.test(p) }));
  }

  let linkPopupUrl = $state<string | null>(null);
  let linkInputEl = $state<HTMLInputElement | null>(null);

  $effect(() => {
    if (linkPopupUrl !== null && linkInputEl) {
      linkInputEl.focus();
      linkInputEl.select();
    }
  });

  async function copyLink() {
    if (linkPopupUrl === null) return;
    let copied = false;
    try {
      await navigator.clipboard.writeText(linkPopupUrl);
      copied = true;
    } catch {
      linkInputEl?.focus();
      linkInputEl?.select();
      copied = document.execCommand("copy");
    }
    if (copied) {
      addNotification("Link copied", "info", 2500);
      linkPopupUrl = null;
    }
    // Not copied: leave the popup open with the URL selected for manual Ctrl+C
  }

  // Emoji picker state
  let showEmojiPicker = $state(false);
  let emojiCategory = $state(0);

  const EMOJI_CATEGORIES = [
    { label: "Smileys", emojis: ["😀","😁","😂","🤣","😃","😄","😅","😆","😉","😊","😎","🤩","😏","😒","😞","😔","😟","😕","😣","😖","😫","😩","🥺","😢","😭","😤","😠","😡","🤬","😈","👿","💀","☠️","😱","😨","😰","😥","😓","🤗","🤔","🤭","🤫","🤥","😶","😐","😑","😬","🙄","😯","😧","😮","😲","🥱","😴","🤤","😷","🤒","🤕","🤢","🤮","🥴","😵","🤯","🥳","🥸","😇","🤠","🤡"] },
    { label: "Gestures", emojis: ["👋","🤚","🖐️","✋","🖖","👌","🤌","🤏","✌️","🤞","🤟","🤘","🤙","👈","👉","👆","👇","☝️","👍","👎","✊","👊","🤛","🤜","👏","🙌","👐","🤲","🤝","🙏","💪","🦾","🖕"] },
    { label: "Hearts", emojis: ["❤️","🧡","💛","💚","💙","💜","🖤","🤍","🤎","💔","❤️‍🔥","❤️‍🩹","💕","💞","💓","💗","💖","💘","💝","💟","♥️","😍","🥰","😘","😻"] },
    { label: "Objects", emojis: ["🔥","⭐","🌟","✨","💫","🎉","🎊","🎈","🎁","🏆","🥇","🎯","💡","💎","🔔","🎵","🎶","🎤","🎧","🎮","🕹️","📱","💻","⌨️","🖥️","📷","📸","🔒","🔑","🗝️","🛠️","⚙️","💣","🧨"] },
    { label: "Nature", emojis: ["🌈","☀️","🌤️","⛅","🌥️","☁️","🌧️","⛈️","🌩️","❄️","🌊","🌸","🌺","🌻","🌹","🌷","🌱","🌿","☘️","🍀","🍁","🍂","🌵","🌴","🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐸","🐵"] },
    { label: "Food", emojis: ["🍕","🍔","🍟","🌭","🍿","🧂","🥓","🍳","🥞","🧇","🧀","🍖","🍗","🥩","🌮","🌯","🍜","🍝","🍣","🍱","🍩","🍪","🎂","🍰","🧁","🍫","🍬","🍭","☕","🍵","🧃","🍺","🍻","🥂","🍷","🥃"] },
  ];

  function insertEmoji(emoji: string) {
    messageInput += emoji;
    showEmojiPicker = false;
    // Re-focus the input
    tick().then(() => chatInputEl?.focus());
  }

  function toggleEmojiPicker() {
    showEmojiPicker = !showEmojiPicker;
    if (showEmojiPicker) emojiCategory = 0;
  }

  function handleEmojiKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") showEmojiPicker = false;
  }

  let isDmMode = $derived($activeDmUserId !== null);

  // The channel whose chat is on screen: a preview, then the text channel the
  // user opened, then the channel they stand in. `displayChannelId` and
  // `isPreviewing` come from stores/roster.ts, which the member lists read as
  // well — this pane deriving its own copy would be a second answer to "which
  // channel is being shown", and the pane and the member list are meant to be
  // showing the same one.
  let effectiveChannel = $derived(
    $channels.find((c) => c.channel_id === $displayChannelId)
  );
  let channelName = $derived(effectiveChannel?.name ?? "");
  let isPasswordProtected = $derived(effectiveChannel?.has_password ?? false);

  let isLobby = $derived($displayChannelId === 0);

  // Can send messages only in a channel we are in: not a preview, not the
  // lobby, not a text channel we only have on screen, and not while a DM holds
  // the pane.
  let canSendChannelMessage = $derived(
    !$isPreviewing &&
      !isLobby &&
      !isDmMode &&
      (!effectiveChannel?.text || $joinedTextChannelIds.has($displayChannelId))
  );

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
      const key = dmKey($activeDmUsername);
      return [...(dmMap.get(key) ?? [])];
    }
    return [...(chMap.get(chatKey(channelName)) ?? [])];
  });

  // Who in this channel would answer a request for its recent chat. The
  // automatic ask happens once, when joining; this is what the user can do
  // afterwards — having cleared the channel by accident, or because somebody
  // who was away then is here now.
  let historySharers = $derived(
    ($channelRosters.get($displayChannelId) ?? []).filter(
      (u) => u.shares_history && u.user_id !== $userId,
    ),
  );
  let canResync = $derived(!$isPreviewing && !isLobby && !isDmMode && historySharers.length > 0);

  async function resyncHistory() {
    const names = historySharers.map((u) => u.username).join(", ");
    try {
      // Deliberate, so it also takes back a deletion: asking is how you undo
      // having cleared a channel, and nothing else reopens that door.
      forgetClearedBefore(channelName);
      await invoke("request_channel_history", {
        channelId: $displayChannelId,
        targetUserIds: historySharers.map((u) => u.user_id),
      });
      addNotification(`Asked ${names} for #${channelName}'s recent chat`, "info", 3000);
    } catch (e) {
      addNotification(`Could not ask for history: ${e}`, "error");
    }
  }

  // A draft belongs to the conversation it was typed in. This pane is mounted
  // once and never keyed, so nothing remounts it when that conversation changes
  // — or disappears under the user, which is the case this is here for: delete,
  // leave or be kicked from the channel being typed in and the pane falls back
  // to the voice room next door, with everybody in it. `sendMessage` reads the
  // target at send time, so the next Enter would post half a private thought
  // into a room it was never meant for.
  $effect(() => {
    void $displayChannelId;
    void $activeDmUserId;
    messageInput = "";
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
    // Show header if different user, after a history divider, or more than 5 minutes apart
    return (
      prev.kind === "history-marker" ||
      prev.user_id !== curr.user_id ||
      // Where a name came from is part of what the header says, so a second-hand
      // message never folds into a run of first-hand ones and inherits its badge.
      (prev.kind === "shared") !== (curr.kind === "shared") ||
      curr.timestamp - prev.timestamp > 5 * 60 * 1000
    );
  }

  // ── Destruction timer ────────────────────────────────────────────────────
  //
  // A channel's is the channel's: the server advertises it, everyone in the
  // room sees the same number, and only its creator or an admin may change it
  // (the gear dialog). A direct message has no such object, so it is this
  // user's own answer for that person, and it travels with each message they
  // write. Either way what is shown here is what our messages will carry.

  const TTL_CHOICES: Array<{ secs: number; label: string }> = [
    { secs: 0, label: "Off" },
    { secs: 5 * 60, label: "5 minutes" },
    { secs: 60 * 60, label: "1 hour" },
    { secs: 8 * 60 * 60, label: "8 hours" },
    { secs: 24 * 60 * 60, label: "24 hours" },
    { secs: 7 * 24 * 60 * 60, label: "7 days" },
  ];

  function ttlLabel(secs: number): string {
    return TTL_CHOICES.find((c) => c.secs === secs)?.label ?? `${Math.round(secs / 60)} minutes`;
  }

  let showTtlPicker = $state(false);
  // Re-read whenever the conversation changes, or the prefs do: `$uiPrefs` and
  // `$channels` are the two stores those answers live in.
  const activeTtl = $derived(
    isDmMode
      ? ($uiPrefs, dmMessageTtl($activeDmUsername))
      : ($channels, channelMessageTtl($displayChannelId)),
  );

  function chooseTtl(secs: number) {
    showTtlPicker = false;
    if (!isDmMode) return;
    setDmMessageTtl($activeDmUsername, secs);
  }

  async function sendMessage() {
    const content = messageInput.trim();
    if (!content) return;

    messageInput = "";

    try {
      // The destruction timer this conversation carries, stamped inside the
      // ciphertext so every copy of the message dies at the same moment: the
      // channel's own, or for a direct message the one this user set for that
      // person. Zero is no timer, which the backend reads as none.
      if (isDmMode) {
        await invoke("send_direct_message", {
          targetUserId: $activeDmUserId,
          content,
          ttlSecs: dmMessageTtl($activeDmUsername) || null,
        });
      } else {
        await invoke("send_channel_message", {
          content,
          channelId: $displayChannelId,
          ttlSecs: channelMessageTtl($displayChannelId) || null,
        });
      }
    } catch (e) {
      console.error("Failed to send message:", e);
      addNotification(`Failed to send message: ${e}`, "error");
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
      clearDmChat($activeDmUserId!, $activeDmUsername);
    } else {
      clearChannelChat(channelName);
    }
  }
</script>

<svelte:window onclick={() => { if (showEmojiPicker) showEmojiPicker = false; }} onkeydown={showEmojiPicker ? handleEmojiKeydown : undefined} />

<div class="chat-panel">
  <div class="chat-header" class:custom={headerExtra}>
    {#if isDmMode}
      <button class="back-btn" onclick={backToChannel} title="Back to channel chat"><Icon name="arrow-left" size={16} /></button>
      <span class="chat-title">DM with {$activeDmUsername}</span>
      {#if totalUnreadChannels > 0}
        <span class="unread-badge" title="Unread channel messages">{totalUnreadChannels}</span>
      {/if}
    {:else}
      <span class="chat-title"><Icon name="hash" size={14} /> {channelName}</span>
      {#if $isPreviewing}
        <span class="preview-label">preview</span>
      {/if}
    {/if}
    {#if canResync}
      <button
        class="resync-btn"
        class:first={displayMessages.length === 0 || isLobby}
        onclick={resyncHistory}
        title="Ask {historySharers.map((u) => u.username).join(', ')} for recent messages"
      ><Icon name="history" size={16} /></button>
    {/if}
    {#if activeTtl > 0}
      <span class="ttl-label" title="Every message written here is deleted for everyone once its timer runs out">
        <Icon name="clock" size={13} /> {ttlLabel(activeTtl)}
      </span>
    {/if}
    {#if isDmMode}
      <button
        class="clear-chat-btn"
        onclick={(e) => { e.stopPropagation(); showTtlPicker = !showTtlPicker; }}
        title="Delete messages you send here after a while"
      ><Icon name="clock" size={16} /></button>
      {#if showTtlPicker}
        <div class="ttl-picker">
          <p class="ttl-note">
            Messages you send {$activeDmUsername} are deleted on both sides once the timer runs
            out. What they send you carries theirs.
          </p>
          {#each TTL_CHOICES as choice (choice.secs)}
            <button
              class="ttl-choice"
              class:active={activeTtl === choice.secs}
              onclick={() => chooseTtl(choice.secs)}
            >{choice.label}</button>
          {/each}
        </div>
      {/if}
    {/if}
    {#if displayMessages.length > 0 && !isLobby}
      <button class="clear-chat-btn" onclick={clearCurrentChat} title="Clear chat history"><Icon name="trash" size={16} /></button>
    {/if}
    {#if headerExtra}
      <span class="header-extra">{@render headerExtra()}</span>
    {/if}
  </div>

  <div class="messages" bind:this={messagesContainer}>
    {#if !isDmMode && isLobby}
      <div class="empty-state">Chat is not available in the lobby. Join a channel to chat.</div>
    {:else if !isDmMode && $isPreviewing && isPasswordProtected && !effectiveChannel?.text}
      <div class="empty-state">This channel is password protected. Join to view messages.</div>
    {:else if displayMessages.length === 0}
      <div class="empty-state">
        {#if isDmMode}
          No messages yet. Say hi!
        {:else}
          No messages yet.{#if $isPreviewing}&nbsp;Messages will appear here in real-time.{:else}&nbsp;Start the conversation!{/if}
        {/if}
      </div>
    {:else}
      {#each displayMessages as msg, i (msg.timestamp + "-" + msg.user_id + "-" + i)}
        {#if msg.kind === "history-marker"}
          <div class="history-marker"><span>{msg.content}</span></div>
        {:else}
          {#if shouldShowHeader(i)}
            <div class="msg-header">
              <span class="msg-username" class:self={msg.user_id === $userId}>{msg.username}</span>
              <span class="msg-time">{formatTime(msg.timestamp)}</span>
              {#if msg.kind === "shared"}
                <span
                  class="shared-tag"
                  title="From a member's copy of this channel's past. Who wrote it and when is their word for it — nothing signs a message, so there is nothing to check it against."
                >shared</span>
              {/if}
            </div>
          {/if}
          <div class="msg-content" class:shared={msg.kind === "shared"}>
            {#if msg.kind === "undecryptable"}
              <span class="attachment-placeholder">{msg.content}</span>
            {:else if msg.kind && msg.kind !== "text" && msg.kind !== "shared"}
              <span class="attachment-placeholder">[attachment — not shared]</span>
            {:else}
              {#each splitSegments(msg.content) as seg}
                {#if seg.url}
                  <button class="msg-link" onclick={() => (linkPopupUrl = seg.text)} title="Copy link">{seg.text}</button>
                {:else}{seg.text}{/if}
              {/each}
            {/if}
          </div>
        {/if}
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
        bind:this={chatInputEl}
        onkeydown={handleKeydown}
        maxlength="2000"
      />
      <div class="emoji-wrapper">
        <button class="emoji-btn" type="button" onclick={(e) => { e.stopPropagation(); toggleEmojiPicker(); }} title="Emoji">
          <Icon name="smile" size={20} />
        </button>
        {#if showEmojiPicker}
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div class="emoji-picker" onkeydown={handleEmojiKeydown} onclick={(e) => e.stopPropagation()}>
            <div class="emoji-tabs">
              {#each EMOJI_CATEGORIES as cat, idx}
                <button
                  class="emoji-tab"
                  class:active={emojiCategory === idx}
                  type="button"
                  onclick={() => (emojiCategory = idx)}
                  title={cat.label}
                >{cat.emojis[0]}</button>
              {/each}
            </div>
            <div class="emoji-grid">
              {#each EMOJI_CATEGORIES[emojiCategory].emojis as emoji}
                <button class="emoji-item" type="button" onclick={() => insertEmoji(emoji)}>{emoji}</button>
              {/each}
            </div>
          </div>
        {/if}
      </div>
      <button class="send-btn" type="submit" disabled={!messageInput.trim()}>Send</button>
    </form>
  {:else if canSendChannelMessage}
    <form class="input-bar" onsubmit={(e) => { e.preventDefault(); sendMessage(); }}>
      <input
        class="chat-input"
        type="text"
        placeholder={`Message #${channelName}...`}
        bind:value={messageInput}
        bind:this={chatInputEl}
        onkeydown={handleKeydown}
        maxlength="2000"
      />
      <div class="emoji-wrapper">
        <button class="emoji-btn" type="button" onclick={(e) => { e.stopPropagation(); toggleEmojiPicker(); }} title="Emoji">
          <Icon name="smile" size={20} />
        </button>
        {#if showEmojiPicker}
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div class="emoji-picker" onkeydown={handleEmojiKeydown} onclick={(e) => e.stopPropagation()}>
            <div class="emoji-tabs">
              {#each EMOJI_CATEGORIES as cat, idx}
                <button
                  class="emoji-tab"
                  class:active={emojiCategory === idx}
                  type="button"
                  onclick={() => (emojiCategory = idx)}
                  title={cat.label}
                >{cat.emojis[0]}</button>
              {/each}
            </div>
            <div class="emoji-grid">
              {#each EMOJI_CATEGORIES[emojiCategory].emojis as emoji}
                <button class="emoji-item" type="button" onclick={() => insertEmoji(emoji)}>{emoji}</button>
              {/each}
            </div>
          </div>
        {/if}
      </div>
      <button class="send-btn" type="submit" disabled={!messageInput.trim()}>Send</button>
    </form>
  {:else if effectiveChannel?.text}
    <div class="preview-footer">
      <button class="join-text-btn" onclick={() => joinTextChannel(effectiveChannel!)}>
        {#if $leftTextChannelNames.has(channelName)}
          Rejoin #{channelName} — you left this channel
        {:else}
          Join #{channelName} to write here
        {/if}
      </button>
    </div>
  {:else if $isPreviewing && !isLobby && !isPasswordProtected}
    <div class="preview-footer">Double-click channel to join and chat</div>
  {/if}
</div>

{#if linkPopupUrl !== null}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="link-overlay" onclick={() => (linkPopupUrl = null)}>
    <div class="link-dialog" onclick={(e) => e.stopPropagation()}>
      <span class="link-title">Copy link</span>
      <input
        class="link-input"
        readonly
        bind:this={linkInputEl}
        value={linkPopupUrl}
        onfocus={(e) => e.currentTarget.select()}
      />
      <div class="link-actions">
        <button class="link-copy-btn" onclick={copyLink}>Copy</button>
        <button class="link-close-btn" onclick={() => (linkPopupUrl = null)}>Close</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .chat-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
    flex: 1;
    min-width: 0;
  }

  .history-marker {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 10px 0;
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .history-marker::before,
  .history-marker::after {
    content: "";
    flex: 1;
    border-top: 1px solid var(--border);
  }

  .attachment-placeholder {
    color: var(--text-secondary);
    font-style: italic;
  }

  /* Second-hand: a member's copy of what was said before we arrived. Drawn in
     the divider's own language — the divider is what introduces it — so it
     reads as a quieter kind of message rather than a broken one. */
  .shared-tag {
    font-size: 9px;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 1px 5px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .ttl-label {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-left: 8px;
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .ttl-picker {
    position: absolute;
    top: 100%;
    right: 8px;
    z-index: 20;
    display: flex;
    flex-direction: column;
    min-width: 200px;
    padding: 6px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-elevated, var(--bg-secondary));
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35);
  }

  .ttl-note {
    margin: 4px 6px 8px;
    font-size: 11px;
    line-height: 1.4;
    color: var(--text-muted);
  }

  .ttl-choice {
    padding: 6px 8px;
    border: none;
    border-radius: 4px;
    background: none;
    color: var(--text-primary);
    font-size: 12px;
    text-align: left;
    cursor: pointer;
  }

  .ttl-choice:hover {
    background: var(--bg-hover, var(--bg-tertiary));
  }

  .ttl-choice.active {
    color: var(--accent);
    font-weight: 600;
  }

  .chat-header {
    display: flex;
    align-items: center;
    /* the timer picker hangs off it */
    position: relative;
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
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .back-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .back-btn:hover {
    color: var(--text-primary);
  }

  /* The clear button sits at the right end unless the shell put controls
     there, in which case they take the margin and it stays beside the title. */
  .chat-header.custom .clear-chat-btn,
  .chat-header.custom .resync-btn.first {
    margin-left: 0;
  }

  /* Same quiet treatment as the clear button it sits beside */
  .resync-btn {
    display: flex;
    align-items: center;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    opacity: 0.35;
    transition: opacity 0.15s;
  }

  /* Takes the margin when it is the first of the two */
  .resync-btn.first {
    margin-left: auto;
  }

  .chat-header:hover .resync-btn {
    opacity: 0.8;
  }

  .resync-btn:hover {
    color: var(--accent);
  }

  .header-extra {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-left: auto;
  }

  .clear-chat-btn {
    display: flex;
    align-items: center;
    margin-left: auto;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
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
    margin-top: var(--msg-gap, 8px);
    margin-bottom: 2px;
  }

  .msg-username {
    font-size: var(--chat-font-size, 13px);
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
    font-size: var(--chat-font-size, 13px);
    color: var(--text-primary);
    padding-left: 0;
    line-height: 1.4;
    word-break: break-word;
  }

  .msg-content.shared {
    color: var(--text-secondary);
  }

  .msg-link {
    background: none;
    border: none;
    padding: 0;
    font-size: var(--chat-font-size, 13px);
    line-height: 1.4;
    color: var(--accent);
    text-decoration: underline;
    cursor: pointer;
    word-break: break-all;
  }

  .msg-link:hover {
    color: var(--accent-hover);
  }

  .link-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 150;
  }

  .link-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    width: 420px;
    max-width: 90vw;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .link-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .link-input {
    width: 100%;
    font-size: 13px;
    padding: 8px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-primary);
  }

  .link-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .link-copy-btn {
    background: var(--accent);
    color: white;
    padding: 6px 16px;
    font-size: 13px;
    border-radius: 4px;
  }

  .link-close-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 6px 16px;
    font-size: 13px;
    border-radius: 4px;
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

  .join-text-btn {
    padding: 4px 12px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 4px;
    font-size: 12px;
    font-style: normal;
  }

  .emoji-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .emoji-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 34px;
    height: 34px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .emoji-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .emoji-picker {
    position: absolute;
    bottom: calc(100% + 8px);
    right: 0;
    width: 320px;
    max-height: 340px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    display: flex;
    flex-direction: column;
    z-index: 150;
  }

  .emoji-tabs {
    display: flex;
    gap: 2px;
    padding: 6px 6px 4px;
    border-bottom: 1px solid var(--border);
  }

  .emoji-tab {
    flex: 1;
    padding: 4px 0;
    font-size: 16px;
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    opacity: 0.5;
    transition: opacity 0.1s;
    line-height: 1;
  }

  .emoji-tab:hover {
    opacity: 0.8;
    background: var(--bg-hover);
  }

  .emoji-tab.active {
    opacity: 1;
    background: var(--bg-tertiary);
  }

  .emoji-grid {
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: 2px;
    padding: 6px;
    overflow-y: auto;
    flex: 1;
  }

  .emoji-item {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    font-size: 20px;
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    line-height: 1;
    padding: 0;
  }

  .emoji-item:hover {
    background: var(--bg-hover);
    transform: scale(1.15);
  }
</style>
