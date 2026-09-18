<script lang="ts">
  // The modern layout: rail, channel sidebar, chat, member list.
  //
  // Named for what it is rather than what it borrows from. The shape is the one
  // most people arriving here have spent years in, and the pieces under
  // components/modern/ exist only for it; everything with behaviour in it is
  // shared with the classic layout.
  //
  // Every behaviour-carrying piece under it is shared with the classic layout —
  // the channel dialogs, the member menu, the push-to-talk keys. What is here is
  // arrangement, plus the chrome Discord has and VoIPC did not: the rail, the
  // server header, the user panel.
  //
  // Panel widths are set on *this* element rather than on :root, which is what
  // makes a width dragged here independent of the one the classic layout uses.

  import { resizeHandle } from "../../actions/resizable.js";
  import { swipeable, type Pane } from "../../actions/swipe.js";
  import { defaultPanels } from "../../ui-prefs.js";
  import { activePanels, updateActivePanels } from "../../stores/ui-prefs.js";
  import { isMobile, showChatRequested } from "../../stores/platform.js";
  import { centreView, currentProximity } from "../../stores/room.js";
  import { watchingUserId } from "../../stores/screenshare.js";
  import { micLane } from "../../stores/mixer.js";
  import { pendingConnect } from "../../stores/server-switch.js";
  import { connectionState } from "../../stores/connection.js";
  import { invoke } from "@tauri-apps/api/core";

  import ChatPanel from "../ChatPanel.svelte";
  import MobilePTT from "../MobilePTT.svelte";
  import VoiceControls from "../VoiceControls.svelte";
  import Icon from "../Icons.svelte";

  import ServerRail from "./ServerRail.svelte";
  import ServerHeader from "./ServerHeader.svelte";
  import ChannelSidebar from "./ChannelSidebar.svelte";
  import VoicePanel from "./VoicePanel.svelte";
  import UserPanel from "./UserPanel.svelte";
  import MemberList from "./MemberList.svelte";
  import ActivityOverlay from "./ActivityOverlay.svelte";

  interface Props {
    onopensettings: () => void;
  }
  let { onopensettings }: Props = $props();

  let shell: HTMLDivElement | undefined = $state(undefined);

  // ── Narrow layout ──────────────────────────────────────────────────────
  //
  // Three panes on a track wider than the window, dragged with a thumb. Which
  // one is showing is decided by a container query on the shell rather than by
  // $isMobile, following the argument already written in MixerView: a container
  // query is the codebase's way of being responsive, and it means the phone
  // layout also appears in a narrow desktop window, which is how it gets
  // developed without a phone. `$isMobile` stays for what is about the device.
  let pane = $state<Pane>(1);
  /** Live offset while a finger is down; null when it is not. */
  let dragOffset = $state<number | null>(null);
  /** What the push-to-talk bar actually measures, so the message list reserves
   *  the space the bar takes rather than a number somebody guessed once. It is
   *  `position: fixed`, so nothing else makes room for it. */
  let pttHeight = $state(0);

  /** Where the track sits for each pane. Not evenly spaced: the drawers are
   *  82% of the width and the chat is all of it, so the member drawer has to
   *  travel past both of the panes before it (82 + 100) less the sliver of chat
   *  it leaves showing, the same sliver the channel drawer leaves on its side. */
  const PANE_OFFSET = ["0cqw", "-82cqw", "-164cqw"];

  // Set as custom properties rather than as a transform, so the container query
  // below decides whether the track moves at all — at desktop width the three
  // panes are simply side by side and none of this applies.
  const trackStyle = $derived(
    `--pane-offset: ${PANE_OFFSET[pane]}; --drag: ${dragOffset ?? 0}px;` +
      (dragOffset === null ? "" : " --drag-duration: 0s;"),
  );

  // An activity covers the whole window, so the drawers must not also be
  // draggable underneath it.
  const activityOpen = $derived($centreView !== "chat" || $watchingUserId !== null);

  /** Are the panes stacked? Read on demand rather than watched: a
   *  ResizeObserver would be a second opinion on what the container query
   *  already decides, and MixerView argues against exactly that. */
  const isNarrow = () => (shell?.clientWidth ?? 9999) <= 720;

  function toggleDrawer(which: Pane) {
    pane = pane === which ? 1 : which;
  }

  // Picking a channel asks for the chat, and here the channel list is a drawer
  // over it: without this the tap changes what is behind the drawer and looks
  // like it did nothing. The classic layout answers the same request with its
  // tab (stores/platform.ts showChatPane).
  $effect(() => {
    $showChatRequested;
    if (isNarrow()) pane = 1;
  });

  /** The full voice bar, on demand: mode, VAD meter, gain and output sliders. */
  let voiceOpen = $state(false);

  const panels = $derived($activePanels);
  const defaults = defaultPanels("modern");

  function addServer() {
    // Nothing to connect *to* yet — bring up the dialog by leaving the server.
    // With one connection that is what "add a server" can honestly mean.
    if ($connectionState === "connected") {
      pendingConnect.set(null);
      invoke("disconnect").catch(() => {});
      connectionState.set("disconnected");
    }
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="modern-shell"
  class:mobile={$isMobile}
  bind:this={shell}
  style="--sidebar-width: {panels.sidebar}px; --memberlist-width: {panels.members}px; --ptt-space: {pttHeight}px;"
  oncontextmenu={(e) => e.preventDefault()}
>
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="track"
    style={trackStyle}
    use:swipeable={{
      pane: () => pane,
      onmove: (px) => (dragOffset = px),
      onsettle: (next) => (pane = next),
      // Only where the panes are stacked, and never under an activity.
      enabled: () => !activityOpen && (shell?.clientWidth ?? 9999) <= 720,
    }}
  >
  <div class="pane pane-left">
  <ServerRail onadd={addServer} />

  {#if panels.sidebar_open}
    <div class="sidebar">
      <ServerHeader onopensettings={onopensettings} />
      <ChannelSidebar />
      <VoicePanel />
      <UserPanel {onopensettings} onopenvoice={() => (voiceOpen = !voiceOpen)} />
    </div>
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
      class="resize-handle"
      role="separator"
      aria-label="Resize the channel sidebar"
      use:resizeHandle={{
        target: shell ?? null,
        prop: "--sidebar-width",
        min: 160,
        max: 480,
        defaultWidth: defaults.sidebar,
        current: () => panels.sidebar,
        onsettle: (px) => updateActivePanels((p) => (p.sidebar = px)),
      }}
    ></div>
  {/if}

  </div>

  <div class="pane pane-main">
  <main class="content">
    <ChatPanel headerExtra={headerControls} />
  </main>
  {#if pane !== 1}
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="pane-scrim" onclick={() => (pane = 1)} title="Back to chat"></div>
  {/if}
  </div>

  {#if panels.members_open}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
      class="resize-handle"
      role="separator"
      aria-label="Resize the member list"
      use:resizeHandle={{
        target: shell ?? null,
        prop: "--memberlist-width",
        min: 140,
        max: 480,
        invert: true,
        defaultWidth: defaults.members,
        current: () => panels.members,
        onsettle: (px) => updateActivePanels((p) => (p.members = px)),
      }}
    ></div>
    <div class="pane pane-members"><MemberList /></div>
  {/if}
  </div>

  {#if $isMobile}
    <div class="mobile-ptt-bar" bind:clientHeight={pttHeight}><MobilePTT /></div>
  {/if}
</div>

{#if voiceOpen}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="voice-overlay" onclick={() => (voiceOpen = false)}>
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="voice-popover" onclick={(e) => e.stopPropagation()}>
      <div class="popover-title">Voice</div>
      <!-- The real voice bar, restyled. Mode select, VAD meter, mic gain,
           output volume and the screen-share controls all come with it, so
           none of them is written twice. -->
      <VoiceControls />
    </div>
  </div>
{/if}

<ActivityOverlay />

{#snippet headerControls()}
  <button
    class="header-btn drawer-btn"
    onclick={() => {
      if (isNarrow()) toggleDrawer(0);
      else updateActivePanels((p) => (p.sidebar_open = !p.sidebar_open));
    }}
    title="Channels"
  >
    <Icon name="hamburger" size={18} />
  </button>
  {#if $currentProximity !== "off"}
    <button
      class="header-btn"
      class:on={$centreView === "room"}
      onclick={() => centreView.set($centreView === "room" ? "chat" : "room")}
      title={$centreView === "room" ? "Close the virtual room" : "Show the virtual room"}
    >
      <Icon name="room" size={18} />
    </button>
  {/if}
  <button
    class="header-btn"
    class:on={$centreView === "mixer"}
    class:warn={$micLane.effect !== "none"}
    onclick={() => centreView.set($centreView === "mixer" ? "chat" : "mixer")}
    title={$micLane.effect !== "none"
      ? `Mixer — your voice is going out as a ${$micLane.effect}`
      : "Mixing desk"}
  >
    <Icon name="music-note" size={18} />
  </button>
  <button
    class="header-btn"
    class:on={panels.members_open && (!isNarrow() || pane === 2)}
    onclick={() => {
      if (isNarrow()) toggleDrawer(2);
      else updateActivePanels((p) => (p.members_open = !p.members_open));
    }}
    title={panels.members_open ? "Hide the member list" : "Show the member list"}
  >
    <Icon name="members" size={18} />
  </button>
{/snippet}

<style>
  .modern-shell {
    display: flex;
    height: 100vh;
    height: 100dvh;
    overflow: hidden;
    background: var(--bg-primary);
    container: shell / inline-size;
    /* Android draws this WebView behind the status and navigation bars, so
       without these the header sits under the clock and the user panel — the
       settings gear with it — sits under the back button. Zero everywhere the
       insets do not exist, which is every desktop and most browsers. */
    box-sizing: border-box;
    padding-top: env(safe-area-inset-top);
    padding-bottom: env(safe-area-inset-bottom);
    padding-left: env(safe-area-inset-left);
    padding-right: env(safe-area-inset-right);
  }

  .track {
    display: flex;
    flex: 1;
    min-width: 0;
  }

  /* Wide: the panes are not boxes at all, so the rail, sidebar, chat and member
     list are direct flex children of the track and lay out exactly as they did
     before there were panes. */
  .pane {
    display: contents;
  }

  .sidebar {
    display: flex;
    flex-direction: column;
    width: var(--sidebar-width, 240px);
    min-width: 160px;
    flex-shrink: 0;
    background: var(--bg-secondary);
    overflow: hidden;
  }

  .content {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    background: var(--bg-primary);
  }

  .content > :global(.chat-panel) {
    flex: 1;
    min-height: 0;
    width: auto;
  }

  /* The channel sidebar and member list carry their own widths; here they fill
     the space this shell gave them. */
  .sidebar > :global(.channel-list) {
    width: 100%;
    min-width: 0;
    border-right: none;
  }

  .resize-handle {
    width: 4px;
    flex-shrink: 0;
    cursor: col-resize;
    background: transparent;
    /* Horizontal drags are ours; nothing here scrolls sideways. */
    touch-action: none;
  }

  .resize-handle:hover {
    background: var(--accent);
  }

  /* Room for the push-to-talk button, which is `position: fixed` and so makes
     room for itself nowhere. It is rendered on `$isMobile` rather than on a
     width, so the space it needs is reserved on the same condition — the
     container query below is about the shape of the panes, and in landscape it
     does not match while the bar is still there. Both columns it covers get it:
     the message list, and the drawer, whose foot is your own name with the
     mute, deafen and settings buttons on it. On the sidebar rather than on the
     pane: outside the container query below a pane is `display: contents`, and
     padding on a box that generates none does nothing — which is how landscape
     came to keep its own version of this bug. */
  .modern-shell.mobile .pane-main .content,
  .modern-shell.mobile .pane-left .sidebar {
    padding-bottom: calc(var(--ptt-space, 64px) + 16px);
  }

  .mobile-ptt-bar {
    position: fixed;
    left: 8px;
    right: 8px;
    bottom: max(8px, env(safe-area-inset-bottom));
    /* Above the panes, below every overlay: Settings is 50, and a talk button
       drawn over a dialog is a dialog you cannot finish. */
    z-index: 40;
  }

  /* ── The voice popover ── */
  .voice-overlay {
    position: fixed;
    inset: 0;
    z-index: 120;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: flex-end;
    justify-content: flex-start;
    padding: 16px;
  }

  .voice-popover {
    width: min(520px, 92vw);
    padding: 12px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: var(--shadow-dialog);
  }

  .popover-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }

  .voice-popover > :global(.voice-controls) {
    flex-wrap: wrap;
    padding: 0;
    background: transparent;
    border-top: none;
  }

  /* ── Header controls, rendered into ChatPanel's header ── */
  .header-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 4px;
  }

  .header-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .header-btn.on {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .header-btn.warn {
    color: var(--danger);
  }

  /* The drawer button is only useful where the panes are stacked; at desktop
     width it collapses the sidebar instead, which is worth having but not
     worth a permanent button. */
  .drawer-btn {
    display: none;
  }

  .pane-scrim {
    display: none;
  }

  /* ── Narrow: the phone shape ────────────────────────────────────────────
     Three panes on a track, dragged with a thumb. A container query rather
     than a media query, for the reason MixerView already gives: it is the
     element's own width that decides, which also means this appears in a
     narrow desktop window and can be developed without a phone. */
  @container shell (max-width: 720px) {
    .track {
      flex: none;
      width: auto;
      transform: translate3d(calc(var(--pane-offset, 0cqw) + var(--drag, 0px)), 0, 0);
      transition: transform var(--drag-duration, 0.22s) cubic-bezier(0.2, 0.8, 0.2, 1);
      /* Horizontal pans are ours, vertical ones stay with the scroller and
         stay at full speed. The same lever ChannelList pulls, and the reason
         this is not a pile of preventDefault(). */
      touch-action: pan-y;
    }

    .pane {
      display: flex;
      flex-shrink: 0;
      overflow: hidden;
    }

    .pane-left {
      width: 82cqw;
    }

    .pane-main {
      width: 100cqw;
    }

    .pane-members {
      width: 82cqw;
    }

    .pane-left .sidebar {
      width: auto;
      flex: 1;
      min-width: 0;
    }

    .pane-members > :global(.user-list) {
      width: 100%;
    }

    /* Nothing to drag when the panes are full width. */
    .resize-handle {
      display: none;
    }



    .drawer-btn {
      display: flex;
    }

    .pane-main {
      position: relative;
    }

    /* The dimmed backdrop: the sliver of chat still showing is the way
       back, for anyone who would rather tap than swipe. */
    .pane-scrim {
      display: block;
      position: absolute;
      inset: 0;
      background: rgba(0, 0, 0, 0.4);
    }
  }
</style>
