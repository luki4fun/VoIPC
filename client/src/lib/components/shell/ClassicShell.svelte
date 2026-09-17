<script lang="ts">
  // The layout VoIPC has always had: three columns on a desktop, five tabs on a
  // phone. Moved out of App.svelte word for word when a second layout arrived —
  // App keeps the event bus and the modal stack and picks a shell.
  //
  // Nothing about it changed in the move except where the settings gear sends
  // its click, and `.app-layout` / `.main-content` / `.titlebar` are still the
  // class names test-ui.mjs looks for.

  import ChannelList from "../ChannelList.svelte";
  import ChatPanel from "../ChatPanel.svelte";
  import UserList from "../UserList.svelte";
  import VoiceControls from "../VoiceControls.svelte";
  import ScreenShareViewer from "../ScreenShareViewer.svelte";
  import RoomView from "../RoomView.svelte";
  import MixerView from "../MixerView.svelte";
  import StatusBar from "../StatusBar.svelte";
  import MobilePTT from "../MobilePTT.svelte";
  import Icon from "../Icons.svelte";

  import { unreadPerChannel } from "../../stores/chat.js";
  import { isMobile, mobileTab } from "../../stores/platform.js";
  import { centreView, currentProximity } from "../../stores/room.js";
  import { poppedOut, watchingUserId } from "../../stores/screenshare.js";

  interface Props {
    onopensettings: () => void;
  }
  let { onopensettings }: Props = $props();

  // Chat pane below the screen-share viewer (desktop)
  let viewerChatOpen = $state(true);
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="app-layout" class:mobile={$isMobile} oncontextmenu={(e) => e.preventDefault()}>
  <div class="titlebar">
    <span class="title">VoIPC</span>
    <button class="settings-btn" onclick={onopensettings} title="Settings">
      <Icon name="settings" size={18} />
    </button>
  </div>

  {#if $isMobile}
    <!-- Mobile: single-column tabbed layout -->
    <div class="main-content mobile-main">
      {#if $watchingUserId !== null}
        <ScreenShareViewer />
      {:else if $mobileTab === 'channels'}
        <ChannelList />
      {:else if $mobileTab === 'chat'}
        <ChatPanel />
      {:else if $mobileTab === 'mixer'}
        <MixerView />
      {:else if $mobileTab === 'room'}
        <RoomView />
      {:else}
        <UserList />
      {/if}
    </div>

    <MobilePTT />
    <VoiceControls />
    <StatusBar />

    <!-- Bottom tab bar -->
    <nav class="mobile-tabs">
      <button
        class="tab-btn"
        class:active={$mobileTab === 'channels'}
        onclick={() => mobileTab.set('channels')}
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M3 12h4l3-9 4 18 3-9h4"/>
        </svg>
        <span>Channels</span>
      </button>
      <button
        class="tab-btn"
        class:active={$mobileTab === 'chat'}
        onclick={() => mobileTab.set('chat')}
      >
        <div class="tab-icon-wrap">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          </svg>
          {#if Array.from($unreadPerChannel.values()).reduce((a, b) => a + b, 0) > 0}
            <span class="tab-badge"></span>
          {/if}
        </div>
        <span>Chat</span>
      </button>
      {#if $currentProximity !== 'off'}
        <button
          class="tab-btn"
          class:active={$mobileTab === 'room'}
          onclick={() => mobileTab.set('room')}
        >
          <Icon name="room" size={20} />
          <span>Room</span>
        </button>
      {/if}
      <button
        class="tab-btn"
        class:active={$mobileTab === 'mixer'}
        onclick={() => mobileTab.set('mixer')}
      >
        <Icon name="music-note" size={20} />
        <span>Mixer</span>
      </button>
      <button
        class="tab-btn"
        class:active={$mobileTab === 'users'}
        onclick={() => mobileTab.set('users')}
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
          <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
        </svg>
        <span>Users</span>
      </button>
    </nav>
  {:else}
    <!-- Desktop: 3-column layout -->
    <div class="main-content">
      <ChannelList />
      {#if $watchingUserId !== null && !$poppedOut}
        <div class="viewer-with-chat">
          <ScreenShareViewer />
          <button
            class="chat-collapse"
            onclick={() => (viewerChatOpen = !viewerChatOpen)}
          >{viewerChatOpen ? "Hide chat ▾" : "Show chat ▴"}</button>
          {#if viewerChatOpen}
            <div class="viewer-chat-pane">
              <ChatPanel />
            </div>
          {/if}
        </div>
      {:else if $centreView === 'room' && $currentProximity !== 'off'}
        <RoomView />
      {:else if $centreView === 'mixer'}
        <MixerView />
      {:else}
        <ChatPanel />
      {/if}
      <UserList />
    </div>

    <VoiceControls />
    <StatusBar />
  {/if}
</div>

<style>
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .titlebar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 16px;
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border);
  }

  .title {
    font-size: 16px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 1px;
  }

  .settings-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: var(--icon-btn-size);
    height: var(--icon-btn-size);
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid transparent;
    border-radius: var(--icon-btn-radius);
    transition: color 0.15s, background-color 0.15s;
  }

  .settings-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .main-content {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  /* Screen-share viewer with the chat pane stacked below it */
  .viewer-with-chat {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }

  .viewer-with-chat > :global(.viewer) {
    flex: 1;
    min-height: 0;
  }

  .chat-collapse {
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border: none;
    border-top: 1px solid var(--border);
    padding: 3px 0;
    font-size: 11px;
    cursor: pointer;
  }

  .chat-collapse:hover {
    color: var(--text-primary);
  }

  .viewer-chat-pane {
    height: 280px;
    flex-shrink: 0;
    display: flex;
    min-height: 0;
  }

  .viewer-chat-pane > :global(*) {
    flex: 1;
    min-width: 0;
  }

  /* ── Mobile layout ── */
  .app-layout.mobile {
    height: 100vh;
    height: 100dvh; /* dynamic viewport height (respects on-screen keyboard) */
  }

  .app-layout.mobile .titlebar {
    padding-top: max(8px, env(safe-area-inset-top));
  }

  .mobile-main {
    flex-direction: column;
  }

  /* Mobile: each child fills the full width */
  .mobile-main > :global(*) {
    width: 100%;
    flex: 1;
    min-height: 0;
  }

  .mobile-tabs {
    display: flex;
    background: var(--bg-primary);
    border-top: 1px solid var(--border);
    padding: 4px 0;
    padding-bottom: max(4px, env(safe-area-inset-bottom));
    flex-shrink: 0;
  }

  .tab-btn {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    padding: 6px 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 0;
    font-size: 10px;
    transition: color 0.15s;
  }

  .tab-btn:active {
    transform: none;
  }

  .tab-btn.active {
    color: var(--accent);
  }

  .tab-btn span {
    font-size: 10px;
    line-height: 1;
  }

  .tab-icon-wrap {
    position: relative;
    display: inline-flex;
  }

  .tab-badge {
    position: absolute;
    top: -3px;
    right: -5px;
    width: 8px;
    height: 8px;
    background: var(--danger);
    border-radius: 50%;
    border: 1.5px solid var(--bg-primary);
  }

  /* Mobile: override scoped child component widths */
  .app-layout.mobile :global(.channel-list) {
    width: 100%;
    min-width: 0;
    border-right: none;
  }

  .app-layout.mobile :global(.user-list) {
    width: 100%;
    min-width: 0;
    border-left: none;
  }

  .app-layout.mobile :global(.chat-panel) {
    width: 100%;
  }

  .app-layout.mobile :global(.voice-controls) {
    flex-wrap: wrap;
    padding: 6px 12px;
  }

  .app-layout.mobile :global(.status-bar) {
    padding: 4px 12px;
  }
</style>
