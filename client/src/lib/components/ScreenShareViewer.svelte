<script lang="ts">
  import type { Snippet } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
  import { onDestroy } from "svelte";
  import {
    watchingUserId,
    currentFrame,
    activeScreenShares,
    screenAudioReceiving,
    poppedOut,
    setPopoutWindow,
    getPopoutWindow,
    receiverFps,
    receiverBitrate,
    receiverResolution,
    receiverFramesDropped,
    stopWatching,
  } from "../stores/screenshare.js";
  import { isMobile, isWeb } from "../stores/platform.js";
  import { addNotification } from "../stores/notifications.js";
  import { shortName } from "../username.js";
  import { users } from "../stores/users.js";
  import { currentProximity } from "../stores/room.js";
  import { screenAudioSpatial, spatialAudio } from "../stores/settings.js";
  import { pushLayer } from "../stores/back-stack.js";
  import { zoomable } from "../actions/zoom.js";
  import { FIT, type View } from "../zoom-rules.js";
  import Icon from "./Icons.svelte";

  interface Props {
    /** The stream view's own controls (the chat toggles), before Stop. */
    headerExtra?: Snippet;
  }
  let { headerExtra }: Props = $props();

  let bitrateLabel = $derived(
    $receiverBitrate >= 1000
      ? `${($receiverBitrate / 1000).toFixed(1)} Mbps`
      : `${$receiverBitrate} kbps`
  );

  // activeScreenShares only hears of shares that start while we are in the
  // channel; one already running when we joined is known from the user list
  let sharerName = $derived(
    shortName(
      $activeScreenShares.find((s) => s.user_id === $watchingUserId)?.username ??
        $users.find((u) => u.user_id === $watchingUserId)?.username ??
        "Unknown",
    ),
  );

  // requestAnimationFrame coalescing: only render the latest frame per vsync tick
  let displayFrame = $state<string | null>(null);
  let pendingFrame: string | null = null;
  let rafScheduled = false;
  let rafId = 0;

  $effect(() => {
    const frame = $currentFrame;
    if (!frame) {
      displayFrame = null;
      return;
    }

    pendingFrame = frame;
    if (!rafScheduled) {
      rafScheduled = true;
      rafId = requestAnimationFrame(() => {
        rafScheduled = false;
        if (pendingFrame) {
          displayFrame = pendingFrame;
        }
      });
    }
  });

  onDestroy(() => {
    cancelAnimationFrame(rafId);
    rafScheduled = false;
    pendingFrame = null;
  });

  // Web: the backend decodes straight into this canvas (registered through
  // the window bridge so this component never imports web-only code)
  let canvasEl = $state<HTMLCanvasElement | null>(null);
  $effect(() => {
    if (!isWeb) return;
    const bridge = (window as any).__voipc_web;
    bridge?.setVideoCanvas(canvasEl);
    return () => bridge?.setVideoCanvas(null);
  });

  /** Does this share's audio come from where the sharer stands, or centred? */
  async function toggleScreenAudioSpatial() {
    const value = !$screenAudioSpatial;
    screenAudioSpatial.set(value);
    try {
      await invoke("set_spatial_setting", { key: "screen_audio_spatial", value });
    } catch (e) {
      addNotification(`Failed to save setting: ${e}`, "error");
    }
  }

  let viewerEl = $state<HTMLDivElement | null>(null);

  // Fullscreen takes the whole viewer, its bar with it, so Stop and the way
  // out stay on screen. Where the page cannot go fullscreen — Android's
  // WebView refuses it, so does Safari on an iPhone — "immersive" does the
  // same job inside the window: the viewer covers everything else.
  const nativeFullscreen =
    typeof document !== "undefined" &&
    !!document.fullscreenEnabled &&
    typeof HTMLElement !== "undefined" &&
    "requestFullscreen" in HTMLElement.prototype &&
    !$isMobile;
  let fullscreen = $state(false);
  let immersive = $state(false);

  function syncFullscreen() {
    fullscreen = !!document.fullscreenElement && document.fullscreenElement === viewerEl;
  }

  function toggleFullscreen() {
    if (!nativeFullscreen) {
      immersive = !immersive;
      return;
    }
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    } else {
      // A refusal falls back to immersive rather than to nothing at all
      viewerEl?.requestFullscreen().catch(() => (immersive = true));
    }
  }

  // Back (and Escape, through the window handler below) leaves immersive
  $effect(() => {
    if (!immersive) return;
    return pushLayer(() => (immersive = false));
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && immersive && !e.defaultPrevented) {
      e.preventDefault();
      immersive = false;
    }
  }

  // Zoom and pan (actions/zoom.ts). Back to fit for every new share.
  let view = $state<View>(FIT);
  const zoomed = $derived(view.scale > 1.01);
  /** A double tap zooms; only a mouse's double click means fullscreen. */
  let lastPointer = "mouse";

  // One build at a time: a quick second click raced the first ("label already
  // exists") and failed with nothing on screen (R5-10)
  let poppingOut = false;

  async function popOut() {
    const existing = getPopoutWindow();
    if (existing) {
      try { await existing.setFocus(); } catch {}
      return;
    }
    if (poppingOut) return;
    poppingOut = true;

    // The backend makes the window: the page may not create windows itself
    let win: WebviewWindow | null;
    try {
      await invoke("open_share_popout", { sharerName });
      win = await WebviewWindow.getByLabel("screenshare-popout");
    } catch (e) {
      console.error("Failed to pop out the share:", e);
      addNotification(`Could not open the share in its own window: ${e}`, "error");
      return;
    } finally {
      poppingOut = false;
    }
    if (!win) return;

    // Clean up store state and stop watching when the popout window is destroyed.
    win.once('tauri://destroyed', () => {
      setPopoutWindow(null);
      poppedOut.set(false);
      // Notify backend to stop watching (covers X button close)
      invoke("stop_watching_screen_share").catch(() => {});
    });

    setPopoutWindow(win);
    poppedOut.set(true);
  }
</script>

<svelte:window {onkeydown} />
<svelte:document onfullscreenchange={syncFullscreen} />

<div class="viewer" class:immersive bind:this={viewerEl}>
  <div class="viewer-header">
    <span class="sharer-name">{sharerName}'s screen</span>
    <span class="audio-status" class:active={$screenAudioReceiving} role="status">
      <span class="audio-icon" aria-hidden="true"><Icon name="music-note" size={12} /></span>
      {#if $screenAudioReceiving}
        <span class="audio-label">Audio</span>
        <span class="audio-dot"></span>
      {:else}
        <span class="audio-label">No audio</span>
      {/if}
    </span>
    <!-- The stats change width every second; in a slot with no width of its
         own they can never rewrap the header and move Stop under a finger -->
    <span class="stats-slot">
    {#if $receiverResolution}
      <span class="stats-pill num">
        <span class="stat">{$receiverResolution}</span>
        <span class="stat-sep"></span>
        <span class="stat">{$receiverFps} fps</span>
        <span class="stat-sep"></span>
        <span class="stat">{bitrateLabel}</span>
        {#if $receiverFramesDropped > 0}
          <span class="stat-sep"></span>
          <span class="stat dropped">{$receiverFramesDropped} dropped</span>
        {/if}
      </span>
    {/if}
    </span>
    {#if $currentProximity !== "off" && $spatialAudio}
      <button
        class="popout-btn no-auto-margin"
        onclick={toggleScreenAudioSpatial}
        title={$screenAudioSpatial
          ? "This share's audio comes from where the sharer stands — click to centre it"
          : "This share's audio is centred — click to place it where the sharer stands"}
      >{$screenAudioSpatial ? "Placed audio" : "Centred audio"}</button>
    {/if}
    {#if zoomed}
      <button
        class="popout-btn no-auto-margin"
        onclick={() => (view = FIT)}
        title="Fit the screen to the window (0)"
        aria-label="Fit to window"
      ><Icon name="zoom-fit" size={16} /></button>
    {/if}
    <button
      class="popout-btn fullscreen-btn"
      onclick={toggleFullscreen}
      title={fullscreen || immersive ? "Leave fullscreen" : "Fullscreen (double-click the screen)"}
      aria-label={fullscreen || immersive ? "Leave fullscreen" : "Fullscreen"}
      aria-pressed={fullscreen || immersive}
    ><Icon name={fullscreen || immersive ? "minimize" : "maximize"} size={16} /></button>
    {#if !$isMobile && !isWeb}
      <button
        class="popout-btn no-auto-margin"
        onclick={popOut}
        title="Pop out to separate window"
        aria-label="Pop out to a separate window"
      ><Icon name="popout" size={16} /></button>
    {/if}
    {#if headerExtra}{@render headerExtra()}{/if}
    <button class="stop-btn" onclick={stopWatching}>Stop watching</button>
  </div>
  <!-- Focusable so + − 0 and the arrows can zoom and pan it (actions/zoom.ts);
       data-no-swipe keeps the phone's drawer swipe off it -->
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <div
    class="viewer-content"
    data-no-swipe
    tabindex="0"
    role="img"
    aria-label="{sharerName}'s screen. Plus and minus zoom, arrows move, 0 fits."
    use:zoomable={{ key: $watchingUserId, onchange: (v) => (view = v) }}
    onpointerdown={(e) => (lastPointer = e.pointerType)}
    ondblclick={() => {
      if (lastPointer === "mouse") toggleFullscreen();
    }}
  >
    <div
      class="zoom-stage"
      style="transform: translate({view.x}px, {view.y}px) scale({view.scale})"
    >
      {#if isWeb}
        <canvas class="frame" class:hidden={!displayFrame} bind:this={canvasEl} aria-hidden="true"></canvas>
      {:else if displayFrame}
        <img src={displayFrame} alt="" class="frame" />
      {/if}
    </div>
    {#if !displayFrame}
      <div class="waiting" role="status">Waiting for the stream…</div>
    {/if}
  </div>
</div>

<style>
  .viewer {
    display: flex;
    flex-direction: column;
    height: 100%;
    flex: 1;
    min-width: 0;
    background: #000;
  }

  /* Fullscreen without the browser's fullscreen (Android, iPhone): the viewer
     covers the window, out of the notch and the navigation bar */
  .viewer.immersive {
    position: fixed;
    inset: 0;
    z-index: var(--z-dialog);
    padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom)
      env(safe-area-inset-left);
  }

  .viewer:fullscreen {
    background: #000;
  }

  /* Wraps rather than clips: on a 360px phone the bar is two rows, and Stop
     watching is always on one of them */
  .viewer-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
    padding: 8px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    min-width: 0;
    container: viewer-head / inline-size;
  }


  .sharer-name {
    font-size: var(--fs-body);
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    flex-shrink: 1;
    min-width: 0;
  }

  .audio-status {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    padding: 2px 8px;
    border-radius: 10px;
    background: var(--bg-tertiary);
    flex-shrink: 0;
  }

  .audio-status.active {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 12%, transparent);
  }

  .audio-icon {
    display: inline-flex;
  }

  .audio-label {
    font-size: var(--fs-micro);
  }

  .audio-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--success);
    animation: pulse 1s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .stats-slot {
    display: flex;
    flex: 1 1 0;
    min-width: 0;
  }

  /* Narrow (a phone): the statistics take the last row, whole, rather than
     what width the buttons leave them (a clipped "12" read as nothing). Last,
     so a figure changing width still never moves a button. After the base
     rule and more specific than it: an @container block adds no weight, and
     the base rule's `flex` used to win from further down the file. */
  @container viewer-head (max-width: 560px) {
    .viewer-header .stats-slot {
      order: 1;
      flex: 1 1 100%;
    }
  }

  .stats-pill {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 2px 8px;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    background: var(--bg-tertiary);
    border-radius: 10px;
    flex-shrink: 1;
    min-width: 0;
    overflow: hidden;
  }

  .stat {
    white-space: nowrap;
  }

  .stat-sep {
    width: 1px;
    height: 10px;
    background: var(--border);
  }

  .stat.dropped {
    color: var(--warning);
  }

  .popout-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    margin-left: auto;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 4px 8px;
    font-size: var(--fs-md);
    line-height: 1;
    cursor: pointer;
    border-radius: 4px;
    flex-shrink: 0;
  }

  .popout-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .popout-btn.no-auto-margin {
    margin-left: 0;
  }

  .stop-btn {
    background: var(--danger);
    color: var(--on-danger);
    padding: 4px 12px;
    font-size: var(--fs-sm);
    font-weight: 600;
    flex-shrink: 0;
    white-space: nowrap;
  }

  .stop-btn:hover {
    opacity: 0.9;
  }

  .viewer-content {
    position: relative;
    flex: 1;
    min-height: 0;
    overflow: hidden;
    /* The pinch is ours, not the page zoom's (actions/zoom.ts) */
    touch-action: none;
  }

  .viewer-content:focus-visible {
    outline-offset: -2px;
  }

  /* The size of the box; the transform zooms and pans it from its corner */
  .zoom-stage {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    transform-origin: 0 0;
  }

  .frame {
    max-width: 100%;
    max-height: 100%;
    object-fit: contain;
  }

  .frame.hidden {
    display: none;
  }

  .waiting {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-secondary);
    font-size: var(--fs-md);
  }

  @media (pointer: coarse) {
    .popout-btn,
    .stop-btn {
      min-width: var(--hit);
      min-height: var(--hit);
    }
  }
</style>
