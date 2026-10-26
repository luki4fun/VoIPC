<script lang="ts">
  // The Stage layout: the call in the middle (2026-10-26).
  //
  // Modern and Classic both put the chat in the centre and the call in a
  // sidebar. Voice and screen sharing are what VoIPC is for, so this one turns
  // that round: the people in your voice channel are the stage — a tile each,
  // the mint ring on whoever talks — and a share, when you watch one, takes the
  // stage with the people in a strip under it. The chat is a drawer beside it
  // (a sheet from below on a phone), shut until you want it. Out of a call the
  // stage lists the voice channels to go into.
  //
  // Arrangement only, like the other two shells: every behaviour comes from the
  // shared stores, dialogs and controls — ChatPanel, StreamStage, the room and
  // the mixer, VoiceControls for the dock, the member menu on every tile.
  // Panel prefs are this layout's own (`ui_prefs.panels.stage`); its second
  // panel is the chat drawer, so `members`/`members_open` hold the chat's width
  // and whether it is open.

  import { untrack } from "svelte";
  import { get } from "svelte/store";
  import { resizeHandle } from "../../actions/resizable.js";
  import { defaultPanels } from "../../ui-prefs.js";
  import { activePanels, updateActivePanels } from "../../stores/ui-prefs.js";
  import { isMobile, showChatRequested } from "../../stores/platform.js";
  import { centreView, currentProximity } from "../../stores/room.js";
  import { previewStage, stopWatching, streamStage } from "../../stores/screenshare.js";
  import { voice, voiceChannel, viewingVoice } from "../../stores/channels.js";
  import { latency } from "../../stores/connection.js";
  import { quality } from "../../stores/connection-quality.js";
  import { callMembers } from "../../stores/roster.js";
  import { pushLayer } from "../../stores/back-stack.js";
  import { serverEntries, showConnectDialog } from "../../connect.js";
  import { shellContextMenu } from "../../context-menu.js";

  import ChatPanel from "../ChatPanel.svelte";
  import MixerView from "../MixerView.svelte";
  import MobilePTT from "../MobilePTT.svelte";
  import ReconnectOverlay from "../ReconnectOverlay.svelte";
  import RoomView from "../RoomView.svelte";
  import StreamStage from "../StreamStage.svelte";
  import VoiceControls from "../VoiceControls.svelte";
  import Icon from "../Icons.svelte";
  import ServerRail from "../modern/ServerRail.svelte";
  import ServerHeader from "../modern/ServerHeader.svelte";
  import ChannelSidebar from "../modern/ChannelSidebar.svelte";
  import UserPanel from "../modern/UserPanel.svelte";
  import SpeakerTile from "./SpeakerTile.svelte";
  import ChannelCards from "./ChannelCards.svelte";

  interface Props {
    onopensettings: () => void;
  }
  let { onopensettings }: Props = $props();

  let shell: HTMLDivElement | undefined = $state(undefined);
  let shellRect = $state<DOMRectReadOnly | undefined>(undefined);
  /** The phone shape, observed (for the markup) and measured now (for a tap):
   *  the same split ModernShell makes, for the same background-window reason.
   *  A phone on its side is one too: 850 px wide but under 400 tall, and laid
   *  out wide it left a watched share about 8 px of height. */
  function phoneShape(width: number, height: number): boolean {
    return width <= 720 || ($isMobile && height <= 520);
  }
  const narrow = $derived(phoneShape(shellRect?.width ?? 9999, shellRect?.height ?? 9999));
  function isNarrow(): boolean {
    if (!shell) return narrow;
    const cs = getComputedStyle(shell);
    return phoneShape(
      shell.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight),
      shell.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom),
    );
  }

  const panels = $derived($activePanels);
  const defaults = defaultPanels("stage");

  /** What covers the stage on a phone: the channel drawer or the chat sheet. */
  let sheet = $state<"none" | "channels" | "chat">("none");

  const channelsOpen = $derived(narrow ? sheet === "channels" : panels.sidebar_open);
  const chatOpen = $derived(narrow ? sheet === "chat" : panels.members_open);

  function toggleChannels() {
    if (isNarrow()) sheet = sheet === "channels" ? "none" : "channels";
    else updateActivePanels((p) => (p.sidebar_open = !p.sidebar_open));
  }

  function toggleChat() {
    if (isNarrow()) sheet = sheet === "chat" ? "none" : "chat";
    else updateActivePanels((p) => (p.members_open = !p.members_open));
  }

  // Picking a channel asks for its chat: here that opens the drawer (on a
  // phone it also closes the channel list it was picked from)
  // Only a *new* request: the counter is read once at mount, and the panel
  // state is untracked, or closing the chat would ask for it again.
  let handledRequest = get(showChatRequested);
  $effect(() => {
    const n = $showChatRequested;
    if (n === handledRequest) return;
    handledRequest = n;
    untrack(() => {
      if (isNarrow()) sheet = "chat";
      else if (!panels.members_open) updateActivePanels((p) => (p.members_open = true));
    });
  });

  // A sheet over the stage is a layer: Back and Escape put the stage back
  $effect(() => {
    if (sheet === "none") return;
    return pushLayer(() => (sheet = "none"));
  });

  // Android's Back leaves what is on the stage the way the other layouts do:
  // a watched share stops (Stop's meaning), our own preview closes, and the
  // mixer or the room gives the stage back to the people. Escape does none of
  // this (the back stack is Back only): on a desktop it leaves fullscreen.
  // A sheet opened over it is pushed later, so Back reaches the sheet first.
  $effect(() => {
    const stage = $streamStage;
    if (stage === null) return;
    return pushLayer(() => (stage === "preview" ? previewStage.set(false) : void stopWatching()));
  });
  $effect(() => {
    if (!inCallHere || $centreView === "chat") return;
    return pushLayer(() => centreView.set("chat"));
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && sheet !== "none" && !e.defaultPrevented) {
      e.preventDefault();
      sheet = "none";
    }
  }

  const inCallHere = $derived($voice !== null && $viewingVoice);
  const callElsewhere = $derived($voice !== null && !$viewingVoice);
  const unread = $derived($serverEntries.find((e) => e.active)?.unread ?? 0);
  const showPtt = $derived($isMobile && $voice !== null);

  /** Columns for the grid: as square as the count allows. */
  const columns = $derived(Math.min(4, Math.max(1, Math.ceil(Math.sqrt($callMembers.length)))));
</script>

<svelte:window {onkeydown} />

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="stage-shell"
  class:mobile={$isMobile}
  class:narrow
  bind:this={shell}
  bind:contentRect={shellRect}
  style="--sidebar-width: {panels.sidebar}px; --memberlist-width: {panels.members}px;"
  oncontextmenu={shellContextMenu}
>
  {#if !narrow}
    <ServerRail onadd={() => showConnectDialog.set(true)} />
  {/if}

  {#if channelsOpen}
    <div class="channels" class:sheet={narrow} data-stage-channels>
      {#if narrow}
        <ServerRail onadd={() => showConnectDialog.set(true)} />
      {/if}
      <div class="sidebar">
        <ServerHeader {onopensettings} />
        <ChannelSidebar />
        <!-- Voice settings: the dock is the voice bar here, so it is Settings -->
        <UserPanel {onopensettings} onopenvoice={onopensettings} />
      </div>
    </div>
    {#if !narrow}
      <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
      <div
        class="resize-handle"
        role="separator"
        aria-label="Resize the channel list"
        use:resizeHandle={{
          target: shell ?? null,
          prop: "--sidebar-width",
          min: 180,
          max: 420,
          defaultWidth: defaults.sidebar,
          current: () => panels.sidebar,
          onsettle: (px) => updateActivePanels((p) => (p.sidebar = px)),
        }}
      ></div>
    {/if}
  {/if}

  <main class="stage" inert={narrow && sheet !== "none"}>
    <header class="stage-top">
      <button
        class="top-btn"
        onclick={toggleChannels}
        aria-label="Channels"
        aria-expanded={channelsOpen}
        title={channelsOpen ? "Hide the channel list" : "Show the channel list"}
      ><Icon name="hamburger" size={18} /></button>

      {#if inCallHere && $voiceChannel}
        <span class="where">
          <Icon name="volume" size={16} />
          <span class="where-name">{$voiceChannel.name}</span>
          <span class="where-count num">{$callMembers.length}</span>
        </span>
        <span class="quality num quality-{$quality}" title="Round trip to the server">{$latency}&nbsp;ms</span>
      {:else}
        <span class="where quiet">Not in a call</span>
      {/if}

      <span class="spacer"></span>

      {#if inCallHere && $currentProximity !== "off"}
        <button
          class="top-btn"
          class:on={$centreView === "room"}
          onclick={() => centreView.set($centreView === "room" ? "chat" : "room")}
          aria-label="Virtual room"
          aria-pressed={$centreView === "room"}
          title="Virtual room"
        ><Icon name="room" size={18} /></button>
      {/if}
      {#if inCallHere}
        <button
          class="top-btn"
          class:on={$centreView === "mixer"}
          onclick={() => centreView.set($centreView === "mixer" ? "chat" : "mixer")}
          aria-label="Mixing desk"
          aria-pressed={$centreView === "mixer"}
          title="Mixing desk"
        ><Icon name="music-note" size={18} /></button>
      {/if}
      <button
        class="top-btn"
        class:on={chatOpen}
        onclick={toggleChat}
        aria-label={unread > 0 ? `Chat, ${unread} unread` : "Chat"}
        aria-pressed={chatOpen}
        title={chatOpen ? "Hide the chat" : "Show the chat"}
        data-stage-chat-toggle
      >
        <Icon name="direct-message" size={18} />
        {#if unread > 0 && !chatOpen}<span class="dot" aria-hidden="true"></span>{/if}
      </button>
    </header>

    <section class="stage-centre">
      {#if callElsewhere}
        <div class="elsewhere">
          <p>Your call is on another server.</p>
          <p class="quiet">Pick it in the server rail to see who is talking there.</p>
        </div>
      {:else if inCallHere && $centreView === "room" && $currentProximity !== "off"}
        <!-- Asked for while watching too: they come first, and Back (or the
             same button) gives the stage back to the share underneath -->
        <RoomView />
      {:else if inCallHere && $centreView === "mixer"}
        <MixerView />
      {:else if $streamStage !== null}
        <div class="with-share">
          <div class="share"><StreamStage dockChat={!narrow} /></div>
          {#if $callMembers.length > 0}
            <div class="filmstrip" aria-label="In the call">
              {#each $callMembers as user (user.user_id)}
                <SpeakerTile {user} small />
              {/each}
            </div>
          {/if}
        </div>
      {:else if inCallHere}
        <div class="grid" style="--cols: {columns}" aria-label="In the call" data-stage-grid>
          {#each $callMembers as user (user.user_id)}
            <SpeakerTile {user} />
          {/each}
        </div>
      {:else}
        <ChannelCards />
      {/if}
    </section>

    {#if $voice !== null}
      <footer class="dock" class:ptt={showPtt}>
        {#if showPtt}<MobilePTT />{/if}
        <VoiceControls />
      </footer>
    {/if}

    <ReconnectOverlay />
  </main>

  {#if chatOpen}
    {#if !narrow}
      <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
      <div
        class="resize-handle"
        role="separator"
        aria-label="Resize the chat"
        use:resizeHandle={{
          target: shell ?? null,
          prop: "--memberlist-width",
          min: 280,
          max: 640,
          invert: true,
          defaultWidth: defaults.members,
          current: () => panels.members,
          onsettle: (px) => updateActivePanels((p) => (p.members = px)),
        }}
      ></div>
    {/if}
    <aside class="chat" class:sheet={narrow} aria-label="Chat" data-stage-chat>
      <ChatPanel />
    </aside>
  {/if}

  {#if narrow && sheet !== "none"}
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
    <div class="scrim" onclick={() => (sheet = "none")}></div>
  {/if}
</div>

<style>
  .stage-shell {
    position: relative;
    display: flex;
    height: 100vh;
    height: 100dvh;
    overflow: hidden;
    background: var(--bg-primary);
    container: stage / inline-size;
    box-sizing: border-box;
    padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom)
      env(safe-area-inset-left);
  }

  .channels {
    display: flex;
    flex-shrink: 0;
  }

  .sidebar {
    display: flex;
    flex-direction: column;
    width: var(--sidebar-width, 240px);
    min-width: 0;
    background: var(--bg-secondary);
    overflow: hidden;
  }

  .sidebar > :global(.channel-list) {
    width: 100%;
    min-width: 0;
    border-right: none;
  }

  .resize-handle {
    position: relative;
    width: 4px;
    flex-shrink: 0;
    cursor: col-resize;
    touch-action: none;
  }

  .resize-handle::before {
    content: "";
    position: absolute;
    inset: 0 -4px;
  }

  .resize-handle:hover,
  .resize-handle:focus-visible {
    background: var(--accent);
    outline: none;
  }

  .stage {
    position: relative;
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
  }

  .stage-top {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    min-height: 52px;
    padding: var(--sp-2) var(--sp-3);
    border-bottom: 1px solid var(--border);
  }

  .top-btn {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: var(--hit);
    height: var(--hit);
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border-radius: var(--r-sm);
  }

  .top-btn.on {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* A finger leaves :hover on whatever it last tapped, which then looked "on"
     after Back had closed what it opened: hover only where there is one */
  @media (hover: hover) {
    .top-btn:hover {
      background: var(--bg-hover);
      color: var(--text-primary);
    }
  }

  .dot {
    position: absolute;
    top: 7px;
    right: 7px;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--danger);
    border: 2px solid var(--bg-primary);
  }

  .where {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-2);
    min-width: 0;
    font-size: var(--fs-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .where-name {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .where-count {
    padding: 0 8px;
    border-radius: var(--r-pill);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: var(--fs-sm);
    font-weight: 600;
  }

  .where.quiet,
  .quiet {
    color: var(--text-muted);
    font-weight: 400;
  }

  .quality {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .quality-warn {
    color: var(--warning);
  }

  .quality-bad {
    color: var(--danger);
  }

  .spacer {
    flex: 1;
  }

  .stage-centre {
    position: relative;
    flex: 1;
    min-height: 0;
    display: flex;
    overflow: auto;
  }

  .stage-centre > :global(*) {
    flex: 1;
    min-width: 0;
  }

  /* As square as the count allows, never wider than four, centred in the room
     left over; tiles keep a sensible size rather than stretching to fill it */
  .grid {
    /* Auto margins centre it and, unlike align-self, never push an overflowing
       grid above the scroll origin (a landscape phone cut the first row off) */
    margin-block: auto;
    display: grid;
    grid-template-columns: repeat(var(--cols), minmax(160px, 240px));
    justify-content: center;
    align-content: center;
    gap: var(--sp-3);
    padding: var(--sp-6);
  }

  .with-share {
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .share {
    flex: 1;
    min-height: 0;
    display: flex;
  }

  .share > :global(*) {
    flex: 1;
    min-width: 0;
  }

  .filmstrip {
    display: flex;
    gap: var(--sp-2);
    padding: var(--sp-2) var(--sp-3);
    overflow-x: auto;
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }

  .elsewhere {
    align-self: center;
    text-align: center;
    color: var(--text-primary);
    font-size: var(--fs-md);
  }

  /* The call dock: the voice bar, floated and centred under the stage */
  .dock {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-2);
    padding: var(--sp-2) var(--sp-3) var(--sp-3);
  }

  .dock > :global(.voice-controls) {
    justify-content: center;
    max-width: 100%;
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    box-shadow: var(--shadow-menu);
  }

  .dock.ptt > :global(.mobile-ptt) {
    max-width: 480px;
  }

  .chat {
    display: flex;
    width: var(--memberlist-width, 360px);
    min-width: 0;
    flex-shrink: 0;
    border-left: 1px solid var(--border);
    background: var(--bg-primary);
  }

  .chat > :global(.chat-panel) {
    flex: 1;
    min-width: 0;
  }

  .scrim {
    position: absolute;
    inset: 0;
    z-index: 1;
    background: var(--scrim);
  }

  /* ── Phone shape ── the channel list is a drawer from the left, the chat
     a sheet from below, both over the stage. A class, not a container query:
     a phone on its side is this shape too, and width alone says it is not. */
  /* Absolute children sit on the shell's padding box, which runs under the
     system bars: the sheets paint to the edge and keep their content in
     the safe area, so nothing lands under the status or navigation bar */
  .stage-shell.narrow .channels.sheet {
    position: absolute;
    inset: 0 auto 0 0;
    z-index: 2;
    width: calc(min(88cqw, 420px) + env(safe-area-inset-left));
    box-sizing: border-box;
    padding: env(safe-area-inset-top) 0 env(safe-area-inset-bottom) env(safe-area-inset-left);
    background: var(--bg-tertiary);
    box-shadow: var(--shadow-dialog);
  }

  .stage-shell.narrow .channels.sheet .sidebar {
    flex: 1;
    width: auto;
  }

  .stage-shell.narrow .chat.sheet {
    position: absolute;
    inset: auto 0 0 0;
    z-index: 2;
    width: auto;
    height: 75%;
    box-sizing: border-box;
    padding: 0 env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
    border-left: none;
    border-top: 1px solid var(--border);
    border-radius: var(--r-lg) var(--r-lg) 0 0;
    box-shadow: var(--shadow-dialog);
    overflow: hidden;
  }

  .stage-shell.narrow .grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    margin-block: 0 auto;
    width: 100%;
    padding: var(--sp-3);
  }

  /* A phone on its side: under 400 px of height the share needs all of it.
     The strip of people goes (the share's own header still says who is
     there), and the dock lays the talk button beside the controls. */
  @media (max-height: 520px) and (pointer: coarse) {
    .with-share .filmstrip {
      display: none;
    }

    .stage-top {
      min-height: 0;
      padding-block: 0;
    }

    .dock.ptt > :global(.mobile-ptt) {
      min-height: var(--hit);
      padding-block: 0;
    }

    .dock.ptt {
      flex-direction: row;
      justify-content: center;
      padding: var(--sp-1) var(--sp-3);
    }

    .dock.ptt > :global(.mobile-ptt) {
      flex: 0 1 220px;
    }
  }
</style>
