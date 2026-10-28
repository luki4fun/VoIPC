<script lang="ts">
  // The layout VoIPC has always had: three columns on a desktop, five tabs on a
  // phone. Moved out of App.svelte word for word when a second layout arrived —
  // App keeps the event bus and the modal stack and picks a shell.
  //
  // Nothing about it changed in the move except where the settings gear sends
  // its click, and `.app-layout` / `.main-content` / `.titlebar` are still the
  // class names test-ui.mjs looks for. Since several servers can be open it
  // has the modern layout's server rail too: down the far left on a desktop,
  // beside the channel list in the phone's Channels tab.

  import ChannelList from "../ChannelList.svelte";
  import ChatPanel from "../ChatPanel.svelte";
  import UserList from "../UserList.svelte";
  import VoiceControls from "../VoiceControls.svelte";
  import ScreenShareViewer from "../ScreenShareViewer.svelte";
  import StreamStage from "../StreamStage.svelte";
  import RoomView from "../RoomView.svelte";
  import MixerView from "../MixerView.svelte";
  import StatusBar from "../StatusBar.svelte";
  import MobilePTT from "../MobilePTT.svelte";
  import ReconnectOverlay from "../ReconnectOverlay.svelte";
  import ServerRail from "../modern/ServerRail.svelte";
  import Icon from "../Icons.svelte";

  import { serverEntries, showConnectDialog } from "../../connect.js";
  import { voice } from "../../stores/channels.js";
  import { isMobile, mobileTab } from "../../stores/platform.js";
  import { centreView, currentProximity } from "../../stores/room.js";
  import { stopWatching, streamStage, watchingUserId } from "../../stores/screenshare.js";
  import { pushLayer } from "../../stores/back-stack.js";
  import { shellContextMenu } from "../../context-menu.js";

  interface Props {
    onopensettings: () => void;
  }
  let { onopensettings }: Props = $props();

  // Android's Back on the phone layout: out of a watched share first (the
  // viewer takes the whole column), then from any other tab back to the chat,
  // which is where the app opens. Only on the chat tab does Back leave.
  $effect(() => {
    if (!$isMobile) return;
    if ($watchingUserId !== null) return pushLayer(() => void stopWatching());
    if ($mobileTab !== "chat") return pushLayer(() => mobileTab.set("chat"));
  });

  // With the keyboard up a phone has room for the message list and little
  // else: the voice bar, the status bar and the tabs under it left about
  // 30 px of messages (D1-02). While a text field in the view has focus and
  // the window has shrunk for the keyboard, they step aside and the talk
  // button is one slim row — the owner's call (2026-10-27). Both, because the
  // keyboard can be put away with the field still focused.
  let fieldFocused = $state(false);
  let viewHeight = $state(0);
  /** The window's height without the keyboard, at the current width. */
  let fullHeight = $state(0);
  let measuredWidth = 0;
  const keyboardUp = $derived($isMobile && fieldFocused && viewHeight < fullHeight * 0.8);
  /** A phone on its side: the talk button is one row there too. */
  const short = $derived($isMobile && viewHeight > 0 && viewHeight <= 520);

  function measure() {
    const height = window.visualViewport?.height ?? window.innerHeight;
    if (window.innerWidth !== measuredWidth) {
      measuredWidth = window.innerWidth;
      fullHeight = 0;
    }
    fullHeight = Math.max(fullHeight, height);
    viewHeight = height;
    // The keyboard may scroll the page up rather than only shrink it, which
    // took the channel header under the status bar (D2-10): the page never
    // scrolls here, and the shell is as tall as what is visible
    const page = document.scrollingElement;
    if (page && page.scrollTop !== 0) page.scrollTop = 0;
  }

  $effect(() => {
    if (!$isMobile) return;
    measure();
    const vv = window.visualViewport;
    vv?.addEventListener("resize", measure);
    vv?.addEventListener("scroll", measure);
    window.addEventListener("resize", measure);
    return () => {
      vv?.removeEventListener("resize", measure);
      vv?.removeEventListener("scroll", measure);
      window.removeEventListener("resize", measure);
    };
  });

  const isTextField = (el: EventTarget | null) =>
    el instanceof HTMLElement &&
    (el instanceof HTMLTextAreaElement ||
      el.isContentEditable ||
      (el instanceof HTMLInputElement && !/^(checkbox|radio|range|button|submit|reset|file|color|image)$/.test(el.type)));
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="app-layout"
  class:mobile={$isMobile}
  class:typing={keyboardUp}
  style:height={$isMobile && viewHeight > 0 ? `${viewHeight}px` : undefined}
  oncontextmenu={shellContextMenu}
>
  <!-- The desktop's title row. A phone has no room to spare for a name the
       launcher already shows: its gear lives in the status bar instead. -->
  {#if !$isMobile}
    <div class="titlebar">
      <span class="title">VoIPC</span>
      <button aria-label="Settings" class="settings-btn" onclick={onopensettings} title="Settings">
        <Icon name="settings" size={18} />
      </button>
    </div>
  {/if}

  {#if $isMobile}
    <!-- Mobile: single-column tabbed layout -->
    <div
      class="main-content mobile-main"
      onfocusin={(e) => (fieldFocused = isTextField(e.target))}
      onfocusout={() => (fieldFocused = false)}
    >
      {#if $watchingUserId !== null}
        <ScreenShareViewer />
      {:else if $mobileTab === 'channels'}
        <div class="channels-tab">
          <ServerRail onadd={() => showConnectDialog.set(true)} />
          <div class="server-pane">
            <ChannelList />
            <ReconnectOverlay />
          </div>
        </div>
      {:else if $mobileTab === 'chat'}
        <ChatPanel />
      {:else if $mobileTab === 'mixer'}
        <MixerView />
      {:else if $mobileTab === 'room'}
        <RoomView />
      {:else}
        <UserList />
      {/if}
      <!-- The Channels tab has its own, beside the rail rather than over it -->
      {#if $watchingUserId !== null || $mobileTab !== 'channels'}
        <ReconnectOverlay />
      {/if}
    </div>

    {#if $voice !== null}
      <MobilePTT slim={keyboardUp || short} />
    {/if}
    <VoiceControls />
    <StatusBar compact onopensettings={onopensettings} />

    <!-- Bottom tab bar -->
    <nav class="mobile-tabs" aria-label="Views">
      <button
        class="tab-btn"
        class:active={$mobileTab === 'channels'}
        aria-current={$mobileTab === 'channels' ? 'page' : undefined}
        onclick={() => mobileTab.set('channels')}
      >
        <Icon name="hash" size={20} />
        <span>Channels</span>
      </button>
      <button
        class="tab-btn"
        class:active={$mobileTab === 'chat'}
        aria-current={$mobileTab === 'chat' ? 'page' : undefined}
        onclick={() => mobileTab.set('chat')}
      >
        <div class="tab-icon-wrap">
          <Icon name="direct-message" size={20} />
          <!-- This server's; the others' are on their icons in the rail -->
          {#if ($serverEntries.find((e) => e.active)?.unread ?? 0) > 0}
            <span class="tab-badge"><span class="sr-only">unread messages</span></span>
          {/if}
        </div>
        <span>Chat</span>
      </button>
      {#if $currentProximity !== 'off'}
        <button
          class="tab-btn"
          class:active={$mobileTab === 'room'}
          aria-current={$mobileTab === 'room' ? 'page' : undefined}
          onclick={() => mobileTab.set('room')}
        >
          <Icon name="room" size={20} />
          <span>Room</span>
        </button>
      {/if}
      <button
        class="tab-btn"
        class:active={$mobileTab === 'mixer'}
        aria-current={$mobileTab === 'mixer' ? 'page' : undefined}
        onclick={() => mobileTab.set('mixer')}
      >
        <Icon name="music-note" size={20} />
        <span>Mixer</span>
      </button>
      <button
        class="tab-btn"
        class:active={$mobileTab === 'users'}
        aria-current={$mobileTab === 'users' ? 'page' : undefined}
        onclick={() => mobileTab.set('users')}
      >
        <Icon name="members" size={20} />
        <span>Users</span>
      </button>
    </nav>
  {:else}
    <!-- Desktop: the rail, then the three columns of the server on screen -->
    <div class="main-content">
      <ServerRail onadd={() => showConnectDialog.set(true)} />
      <div class="server-pane">
      <ChannelList />
      {#if $streamStage !== null}
        <!-- The share and its chat: the same view as the modern layout's -->
        <StreamStage />
      {:else if $centreView === 'room' && $currentProximity !== 'off'}
        <RoomView />
      {:else if $centreView === 'mixer'}
        <MixerView />
      {:else}
        <ChatPanel />
      {/if}
      <UserList />
      <ReconnectOverlay />
      </div>
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
    font-size: var(--fs-lg);
    font-weight: 700;
    color: var(--text-primary);
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
    transition: color var(--dur-fast), background-color var(--dur-fast);
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

  /* Everything that belongs to the server on screen, and the box its
     reconnect overlay covers — the rail beside it stays usable. */
  .server-pane {
    position: relative;
    display: flex;
    flex: 1;
    min-width: 0;
    overflow: hidden;
  }

  /* ── Mobile layout ── */
  .app-layout.mobile {
    height: 100vh;
    height: 100dvh; /* dynamic viewport height (respects on-screen keyboard) */
  }

  /* No title bar on a phone: the first row is the content, out of the notch */
  .mobile-main {
    padding-top: env(safe-area-inset-top);
  }

  .mobile-main {
    position: relative;
    flex-direction: column;
  }

  .channels-tab {
    display: flex;
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
    font-size: var(--fs-micro);
    transition: color var(--dur-fast);
  }

  .tab-btn:active {
    transform: none;
  }

  .tab-btn.active {
    color: var(--text-primary);
  }

  .tab-btn span {
    font-size: var(--fs-micro);
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

  /* The keyboard is up: the messages and the talk button, nothing else */
  .app-layout.mobile.typing > :global(.voice-controls),
  .app-layout.mobile.typing > :global(.status-bar),
  .app-layout.mobile.typing > .mobile-tabs {
    display: none;
  }
</style>
