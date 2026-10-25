<script lang="ts">
  // What we are sending, shown to the person sending it.
  //
  // The server relays a share to its viewers only, so the sender never sees
  // it come back. The native client therefore renders the frames it is about
  // to encode — the stream's own size and scaling, ten a second, as
  // `screenshare-preview` — and the browser plays the MediaStream it captures
  // from. Capture for this runs before anybody watches; encoding and sending
  // wait for a viewer (screenshare/mod.rs, FrameProcessor::process).
  //
  // Two shapes: the floating card, mounted once in App.svelte for both
  // layouts, and `stage`, which fills the stream view where a watched share
  // goes, chat and all (StreamStage.svelte).

  import type { Snippet } from "svelte";
  import { isWeb } from "../stores/platform.js";
  import {
    isSharingScreen,
    previewFrame,
    previewStage,
    streamStage,
    viewerCount,
  } from "../stores/screenshare.js";
  import { updateUiPrefs } from "../stores/ui-prefs.js";
  import Icon from "./Icons.svelte";

  interface Props {
    /** Fill the stream view instead of floating. */
    stage?: boolean;
    /** The stream view's own controls (the chat toggles). */
    headerExtra?: Snippet;
  }
  let { stage = false, headerExtra }: Props = $props();

  let videoEl = $state<HTMLVideoElement | null>(null);

  // The browser's capture, over the one bridge the web backend keeps
  // (web/backend/video.ts; components never import src/web). The getter is
  // not reactive, so it is read again whenever sharing starts or stops.
  $effect(() => {
    if (!isWeb || !videoEl) return;
    void $isSharingScreen;
    const bridge = (window as any).__voipc_web;
    videoEl.srcObject = bridge?.shareStream?.() ?? null;
  });

  const audience = $derived(
    $viewerCount === 0 ? "Nobody watching yet" : `${$viewerCount} watching`,
  );

  function enlarge() {
    previewStage.set(true);
  }

  /** Back to the card — which also brings the card back if it was hidden. */
  function shrink() {
    previewStage.set(false);
    updateUiPrefs((p) => (p.share_preview = true));
  }

  function hide() {
    previewStage.set(false);
    updateUiPrefs((p) => (p.share_preview = false));
  }
</script>

<div class="share-preview" class:stage>
  <div class="bar">
    <span class="live-dot"></span>
    <span class="title">{stage ? "Your screen — preview" : "Your screen"}</span>
    <span class="audience">{audience}</span>
    {#if headerExtra}{@render headerExtra()}{/if}
    {#if stage}
      <button aria-label="Back to the small preview" class="bar-btn" onclick={shrink} title="Back to the small preview">
        <Icon name="minimize" size={14} />
      </button>
    {:else if $streamStage !== "watch"}
      <!-- While somebody else's share fills the view, ours stays small -->
      <button aria-label="Enlarge the preview" class="bar-btn" onclick={enlarge} title="Enlarge the preview">
        <Icon name="maximize" size={14} />
      </button>
    {/if}
    <button aria-label="Hide the preview (the eye by Stop brings it back)" class="bar-btn" onclick={hide} title="Hide the preview (the eye by Stop brings it back)">
      <Icon name="close" size={14} />
    </button>
  </div>
  <div class="media">
    {#if isWeb}
      <video bind:this={videoEl} muted autoplay playsinline></video>
    {:else if $previewFrame}
      <img src={$previewFrame} alt="Your screen, as it is sent" />
    {:else}
      <div class="waiting">Starting the preview…</div>
    {/if}
  </div>
</div>

<style>
  .share-preview {
    position: fixed;
    right: 16px;
    /* Clear of the message box and the send button */
    bottom: 88px;
    width: min(280px, 60vw);
    display: flex;
    flex-direction: column;
    background: #000;
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: var(--shadow-dialog);
    overflow: hidden;
    /* Above the stream view (90), below every dialog (100 and up) */
    z-index: 95;
  }

  .share-preview.stage {
    position: static;
    width: auto;
    height: 100%;
    flex: 1;
    min-width: 0;
    min-height: 0;
    border: none;
    border-radius: 0;
    box-shadow: none;
  }

  .bar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 6px 4px 10px;
    background: var(--bg-secondary);
    font-size: 11px;
    color: var(--text-secondary);
    min-width: 0;
  }

  .stage .bar {
    gap: 12px;
    padding: 8px 16px;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
  }

  .live-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--danger);
    flex-shrink: 0;
  }

  .title {
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
  }

  .audience {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .bar-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border-radius: 4px;
    flex-shrink: 0;
  }

  .bar-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .media {
    display: flex;
    align-items: center;
    justify-content: center;
    aspect-ratio: 16 / 9;
    overflow: hidden;
  }

  .stage .media {
    flex: 1;
    min-height: 0;
    aspect-ratio: auto;
  }

  .media img,
  .media video {
    width: 100%;
    height: 100%;
    object-fit: contain;
  }

  .waiting {
    color: var(--text-secondary);
    font-size: 12px;
    font-style: italic;
  }
</style>
