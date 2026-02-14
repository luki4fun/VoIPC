<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { onMount } from "svelte";

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

    listen("stopped-watching-screenshare", () => {
      getCurrentWindow().destroy().catch(() => {});
    }).then((fn) => unlistenFns.push(fn));

    listen<{ user_id: number }>("screenshare-stopped", () => {
      getCurrentWindow().destroy().catch(() => {});
    }).then((fn) => unlistenFns.push(fn));

    let lastRecvCount = 0;
    let lastFramesRecv = 0;
    let lastBytesRecv = 0;
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

          const recvDelta = framesRecv - lastFramesRecv;
          popoutFps = Math.round(recvDelta / dt);
          lastFramesRecv = framesRecv;

          const bytesDelta = bytesRecv - lastBytesRecv;
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
</script>

<div class="popout-viewer">
  <div class="popout-header">
    <span class="sharer-name">{sharerName}'s screen</span>
    <span class="audio-status" class:active={audioReceiving}>
      <span class="audio-icon">&#9835;</span>
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
    <button class="stop-btn" onclick={stopWatching}>Stop Watching</button>
  </div>
  <div class="popout-content">
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
    font-size: 13px;
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
    font-size: 11px;
    color: var(--text-secondary);
    padding: 2px 8px;
    border-radius: 10px;
    background: var(--bg-tertiary);
    flex-shrink: 0;
  }

  .audio-status.active {
    color: #43b581;
    background: rgba(67, 181, 129, 0.1);
  }

  .audio-icon {
    font-size: 13px;
  }

  .audio-label {
    font-size: 11px;
  }

  .audio-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #43b581;
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
    font-size: 11px;
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
    color: #faa61a;
  }

  .stop-btn {
    margin-left: auto;
    background: var(--danger);
    color: white;
    padding: 4px 12px;
    font-size: 11px;
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
    font-size: 14px;
    font-style: italic;
  }
</style>
