<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { onMount } from "svelte";
  import Icon from "./Icons.svelte";

  let { sharerName = "Unknown" }: { sharerName: string } = $props();

  let displayFrame = $state<string | null>(null);
  let pendingFrame: string | null = null;
  let rafScheduled = false;
  let audioReceiving = $state(false);

  // Local video stats (independent polling since popout is a separate window)
  let popoutFps = $state(0);
  let popoutBitrate = $state(0);
  let popoutResolution = $state("");
  let popoutDropped = $state(0);

  let popoutBitrateLabel = $derived(
    popoutBitrate >= 1000
      ? `${(popoutBitrate / 1000).toFixed(1)} Mbps`
      : `${popoutBitrate} kbps`
  );

  onMount(() => {
    const unlistenFns: Array<() => void> = [];

    // Register event listeners and collect unlisten functions
    listen<string>("screenshare-frame", (event) => {
      pendingFrame = event.payload;
      if (!rafScheduled) {
        rafScheduled = true;
        requestAnimationFrame(() => {
          rafScheduled = false;
          if (pendingFrame) {
            displayFrame = pendingFrame;
          }
        });
      }
    }).then((fn) => unlistenFns.push(fn));

    // The main window closes this too, when watching stops (App.svelte). Not on
    // `screenshare-stopped`: that is anybody in the channel ending theirs, and
    // closed this window while the one it shows was still live.
    listen("stopped-watching-screenshare", () => {
      getCurrentWindow().destroy().catch(() => {});
    }).then((fn) => unlistenFns.push(fn));

    let lastRecvCount = 0;
    let lastFramesRecv = 0;
    let lastBytesRecv = 0;
    // The counters run from when watching began, not from when this window
    // opened: the first answer is the baseline, or it read as "442 fps"
    let primed = false;
    const statsInterval = setInterval(() => {
      invoke<[number, number]>("get_screen_audio_status")
        .then(([, recvCount]) => {
          audioReceiving = recvCount !== lastRecvCount;
          lastRecvCount = recvCount;
        })
        .catch(() => {});

      invoke<[number, number, number, number, number, number]>("get_screen_share_stats")
        .then(([, , framesRecv, framesDropped, bytesRecv, resPacked]) => {
          const dt = 0.5;
          if (!primed) {
            primed = true;
            lastFramesRecv = framesRecv;
            lastBytesRecv = bytesRecv;
            return;
          }

          // A restarted share resets the counters: never a negative rate
          const recvDelta = Math.max(0, framesRecv - lastFramesRecv);
          popoutFps = Math.round(recvDelta / dt);
          lastFramesRecv = framesRecv;

          const bytesDelta = Math.max(0, bytesRecv - lastBytesRecv);
          popoutBitrate = Math.round((bytesDelta * 8) / (dt * 1000));
          lastBytesRecv = bytesRecv;

          if (resPacked > 0) {
            const w = (resPacked >> 16) & 0xFFFF;
            const h = resPacked & 0xFFFF;
            popoutResolution = `${w}x${h}`;
          }

          popoutDropped = framesDropped;
        })
        .catch(() => {});
    }, 500);

    return () => {
      clearInterval(statsInterval);
      unlistenFns.forEach((fn) => fn());
    };
  });

  function stopWatching() {
    invoke("stop_watching_screen_share").catch(() => {});
    getCurrentWindow().destroy().catch(() => {});
  }

  let contentEl = $state<HTMLDivElement | null>(null);

  function toggleFullscreen() {
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    } else {
      contentEl?.requestFullscreen().catch(() => {});
    }
  }
</script>

<div class="popout-viewer">
  <div class="popout-header">
    <span class="sharer-name">{sharerName}'s screen</span>
    <span class="audio-status" class:active={audioReceiving}>
      <span class="audio-icon" aria-hidden="true"><Icon name="music-note" size={12} /></span>
      {#if audioReceiving}
        <span class="audio-label">Audio</span>
        <span class="audio-dot"></span>
      {:else}
        <span class="audio-label">No audio</span>
      {/if}
    </span>
    {#if popoutResolution}
      <span class="stats-pill">
        <span class="stat">{popoutResolution}</span>
        <span class="stat-sep"></span>
        <span class="stat">{popoutFps} fps</span>
        <span class="stat-sep"></span>
        <span class="stat">{popoutBitrateLabel}</span>
        {#if popoutDropped > 0}
          <span class="stat-sep"></span>
          <span class="stat dropped">{popoutDropped} dropped</span>
        {/if}
      </span>
    {/if}
    <button
      class="fullscreen-btn"
      onclick={toggleFullscreen}
      title="Fullscreen (double-click video)"
      aria-label="Fullscreen"
    ><Icon name="maximize" size={16} /></button>
    <button class="stop-btn" onclick={stopWatching}>Stop watching</button>
  </div>
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="popout-content"
    bind:this={contentEl}
    ondblclick={toggleFullscreen}
    role="presentation"
  >
    {#if displayFrame}
      <img src={displayFrame} alt="Screen share" class="frame" />
    {:else}
      <div class="waiting">Waiting for video stream...</div>
    {/if}
  </div>
</div>

<style>
  .popout-viewer {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: #000;
  }

  .popout-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    user-select: none;
    overflow: hidden;
    min-width: 0;
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
    font-size: var(--fs-body);
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

  .fullscreen-btn {
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

  .fullscreen-btn:hover {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .popout-content:fullscreen {
    background: #000;
  }

  .stop-btn {
    background: var(--danger);
    color: var(--on-danger);
    padding: 4px 12px;
    font-size: var(--fs-micro);
    border: none;
    border-radius: 6px;
    cursor: pointer;
    flex-shrink: 0;
    white-space: nowrap;
  }

  .stop-btn:hover {
    opacity: 0.9;
  }

  .popout-content {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }

  .frame {
    max-width: 100%;
    max-height: 100%;
    object-fit: contain;
  }

  .waiting {
    color: var(--text-secondary);
    font-size: var(--fs-md);
    font-style: italic;
  }

  /* A finger needs 44px (--hit) */
  @media (pointer: coarse) {
    .stop-btn, .fullscreen-btn {
      min-width: var(--hit);
      min-height: var(--hit);
    }
  }
</style>
