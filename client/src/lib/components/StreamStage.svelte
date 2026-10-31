<script lang="ts">
  // The stream view: a share we watch, or the preview of our own, with the
  // chat docked beside it or under it.
  //
  // Shared by all three layouts — Modern shows it full-window
  // (ActivityOverlay), Classic in its centre column, Stage on the stage — and remembered
  // per layout in `ui_prefs.stream_chat`: whether the chat is open, where, and
  // how big. Under 600 px of its own width the chat always goes below, since
  // a phone has no room beside anything; the side width is kept for later.

  import { resizeHandle } from "../actions/resizable.js";
  import {
    defaultStreamChat,
    STREAM_CHAT_HEIGHT_MAX,
    STREAM_CHAT_HEIGHT_MIN,
    STREAM_CHAT_WIDTH_MAX,
    STREAM_CHAT_WIDTH_MIN,
  } from "../ui-prefs.js";
  import { activeStreamChat, uiLayout, updateActiveStreamChat } from "../stores/ui-prefs.js";
  import { streamStage } from "../stores/screenshare.js";
  import { displayChannelId, shownMessages } from "../stores/roster.js";
  import { activeDmUserId, activeDmUsername } from "../stores/chat.js";
  import { serverAddress } from "../stores/connection.js";
  import ChatPanel from "./ChatPanel.svelte";
  import ScreenShareViewer from "./ScreenShareViewer.svelte";
  import SharePreview from "./SharePreview.svelte";
  import Icon from "./Icons.svelte";

  interface Props {
    /** False where the layout has a chat of its own to open instead: Stage
     *  on a phone, whose chat sheet this would only shrink the share for. */
    dockChat?: boolean;
  }
  let { dockChat = true }: Props = $props();

  let root = $state<HTMLDivElement | undefined>(undefined);
  let width = $state(0);

  const prefs = $derived($activeStreamChat);
  const narrow = $derived(width > 0 && width < 600);
  const split = $derived(narrow ? "below" : prefs.split);
  const size = $derived(split === "side" ? prefs.width : prefs.height);
  const defaults = $derived(defaultStreamChat($uiLayout));

  // ── The unread dot ──
  //
  // While the chat is hidden, the toggle says when the conversation it would
  // show has moved on. "Seen" is the newest message while the chat was open,
  // or when the conversation itself changed — opening another channel is not
  // news from this one. Newer, not just different: a message expiring under
  // its timer is no news either.
  // A direct one by its person's name, which outlives their id (they came back)
  const conversation = $derived(
    `${$serverAddress}/${$activeDmUserId === null ? `#${$displayChannelId}` : `@${$activeDmUsername}`}`,
  );
  const newest = $derived($shownMessages.at(-1)?.timestamp ?? 0);
  let seen = $state(0);
  let seenIn = "";
  $effect(() => {
    if (prefs.open || conversation !== seenIn) {
      seen = newest;
      seenIn = conversation;
    }
  });
  const unread = $derived(!prefs.open && newest > seen);

  function toggleChat() {
    updateActiveStreamChat((c) => (c.open = !c.open));
  }

  function toggleSplit() {
    updateActiveStreamChat((c) => (c.split = c.split === "side" ? "below" : "side"));
  }
</script>

<div
  class="stream-stage"
  class:side={dockChat && prefs.open && split === "side"}
  class:below={dockChat && prefs.open && split === "below"}
  bind:this={root}
  bind:clientWidth={width}
  style="--stream-chat-size: {size}px;"
>
  <div class="stream">
    {#if $streamStage === "watch"}
      <ScreenShareViewer headerExtra={dockChat ? controls : undefined} />
    {:else}
      <SharePreview stage headerExtra={dockChat ? controls : undefined} />
    {/if}
  </div>

  {#if dockChat && prefs.open}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
      class="split-handle"
      role="separator"
      aria-label="Resize the chat"
      use:resizeHandle={{
        target: root ?? null,
        prop: "--stream-chat-size",
        axis: split === "side" ? "x" : "y",
        // The handle is on the chat's leading edge: dragging towards the
        // stream grows the chat.
        invert: true,
        min: split === "side" ? STREAM_CHAT_WIDTH_MIN : STREAM_CHAT_HEIGHT_MIN,
        max: split === "side" ? STREAM_CHAT_WIDTH_MAX : STREAM_CHAT_HEIGHT_MAX,
        defaultWidth: split === "side" ? defaults.width : defaults.height,
        current: () => size,
        onsettle: (px) =>
          updateActiveStreamChat((c) => {
            if (split === "side") c.width = px;
            else c.height = px;
          }),
      }}
    ></div>
    <div class="stream-chat"><ChatPanel /></div>
  {/if}
</div>

{#snippet controls()}
  <button
    class="stage-btn chat-toggle"
    class:on={prefs.open}
    aria-label={unread ? "Chat, new messages" : "Chat"}
    aria-pressed={prefs.open}
    onclick={toggleChat}
    title={prefs.open ? "Hide the chat" : unread ? "Show the chat — new messages" : "Show the chat"}
  >
    <Icon name="direct-message" size={16} />
    {#if unread}<span class="unread-dot"></span>{/if}
  </button>
  {#if prefs.open && !narrow}
    <button aria-label={split === "side" ? "Put the chat under the stream" : "Put the chat beside the stream"}
      class="stage-btn split-toggle"
      onclick={toggleSplit}
      title={split === "side" ? "Put the chat under the stream" : "Put the chat beside the stream"}
    >
      <Icon name={split === "side" ? "split-below" : "split-side"} size={16} />
    </button>
  {/if}
{/snippet}

<style>
  .stream-stage {
    display: flex;
    flex: 1;
    height: 100%;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
    background: var(--bg-primary);
  }

  .stream-stage.below {
    flex-direction: column;
  }

  .stream {
    flex: 1;
    display: flex;
    min-width: 0;
    min-height: 0;
  }

  .stream > :global(*) {
    flex: 1;
    min-width: 0;
    min-height: 0;
  }

  /* Capped as a share of the view as well, so a size remembered from a big
     window never leaves the stream nothing in a small one. */
  .stream-chat {
    display: flex;
    flex-shrink: 0;
    min-width: 0;
    min-height: 0;
  }

  .side .stream-chat {
    width: var(--stream-chat-size);
    max-width: 60%;
    border-left: 1px solid var(--border);
  }

  .below .stream-chat {
    height: var(--stream-chat-size);
    max-height: 70%;
    border-top: 1px solid var(--border);
  }

  .stream-chat > :global(.chat-panel) {
    flex: 1;
    min-width: 0;
    min-height: 0;
    width: auto;
  }

  .split-handle {
    flex-shrink: 0;
    background: transparent;
    /* The drag is ours; nothing here scrolls along it. */
    touch-action: none;
  }

  .side .split-handle {
    width: 4px;
    cursor: col-resize;
  }

  .below .split-handle {
    height: 4px;
    cursor: row-resize;
  }

  /* A finger needs more than four pixels to find. */
  @media (pointer: coarse) {
    .side .split-handle {
      width: 12px;
    }

    .below .split-handle {
      height: 12px;
    }
  }

  .split-handle:hover {
    background: var(--accent);
  }

  .stage-btn {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 3px 6px;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    flex-shrink: 0;
  }

  .stage-btn:hover,
  .stage-btn.on {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .stage-btn.on {
    background: var(--bg-hover);
  }

  .unread-dot {
    position: absolute;
    top: -3px;
    right: -3px;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--danger);
    border: 1.5px solid var(--bg-secondary);
  }

  /* A finger needs 44px (--hit) */
  @media (pointer: coarse) {
    .stage-btn {
      min-width: var(--hit);
      min-height: var(--hit);
    }
  }
</style>
