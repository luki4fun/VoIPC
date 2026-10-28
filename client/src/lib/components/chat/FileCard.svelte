<script lang="ts">
  // The file a message carries. Nothing is fetched until it is asked for:
  // before that a picture shows as its 16×16 preview, drawn from the raw
  // pixels its message carries (no decoder runs on anything a peer sent).
  // Loaded, what it is comes from its own bytes (file-sniff.ts), never from
  // what its message claims: a picture is drawn, a video or a sound gets its
  // controls and never starts by itself, anything else is only saved.
  import { onDestroy, tick } from "svelte";
  import type { FileConv, FileRef } from "../../types.js";
  import { FILE_UNAVAILABLE, cancelFile, fetchFile, fileProgress, forgetProgress, newOp, saveFile } from "../../files.js";
  import { formatSize, previewPixels, PREVIEW_SIDE } from "../../file-rules.js";
  import { sniff, type Shown } from "../../file-sniff.js";
  import Icon from "../Icons.svelte";

  interface Props {
    file: FileRef;
    server: string;
    /** Where to fetch it from; null where no conversation can be named
     *  (then only this device's copy can open it). */
    conv: FileConv | null;
    /** A loaded picture was pressed: show it big. */
    onopen: (picture: { url: string; name: string; save: () => void }) => void;
    /** The card is going, and with it the picture at `url`. */
    ongone?: (url: string) => void;
  }
  let { file, server, conv, onopen, ongone }: Props = $props();

  let card = $state<HTMLElement | null>(null);
  let destroyed = false;

  /** What the card looks like before a load: the message's word for it. */
  const media = $derived(
    !!file.px || (file.w !== undefined && file.h !== undefined) || /^(image|video|audio)\//.test(file.mime ?? ""),
  );
  const aspect = $derived(file.w && file.h ? `${file.w} / ${file.h}` : "16 / 9");

  let op = $state<string | null>(null);
  let error = $state<string | null>(null);
  let bytes = $state.raw<Uint8Array | null>(null);
  let shown = $state.raw<Shown | null>(null);
  let url = $state<string | null>(null);

  const progress = $derived(op ? $fileProgress.get(op) : undefined);
  const seeking = $derived(progress?.stage === "seeking");
  const percent = $derived(progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0);

  /** Draw the preview's raw pixels: an ImageData, no decoder. */
  function paint(canvas: HTMLCanvasElement, px: string | undefined) {
    const draw = (p: string | undefined) => {
      const rgba = p ? previewPixels(p) : null;
      if (rgba) canvas.getContext("2d")?.putImageData(new ImageData(rgba, PREVIEW_SIDE, PREVIEW_SIDE), 0, 0);
    };
    draw(px);
    return { update: draw };
  }

  /** Its buttons change under the pointer: keep the focus in the card. */
  async function keepFocus() {
    const had = !!card?.contains(document.activeElement);
    await tick();
    if (had && !card?.contains(document.activeElement)) card?.focus();
  }

  async function fetchIt(): Promise<Uint8Array | null> {
    if (bytes) return bytes;
    if (op) return null;
    const mine = newOp();
    op = mine;
    error = null;
    void keepFocus();
    try {
      // No conversation to name: only this device's copy can open it (channel
      // 0 is never one, so the relay refuses anything further)
      const got = await fetchFile(server, conv ?? { channel: 0 }, file, mine);
      if (destroyed) return null;
      bytes = got;
      shown = sniff(got);
      if (shown) url = URL.createObjectURL(new Blob([got as Uint8Array<ArrayBuffer>], { type: shown.mime }));
      return got;
    } catch (e) {
      const why = String(e);
      if (why !== "cancelled") error = why === FILE_UNAVAILABLE ? "Nobody online has this file" : why;
      return null;
    } finally {
      forgetProgress(mine);
      if (op === mine) op = null;
      if (!destroyed) void keepFocus();
    }
  }

  async function save() {
    const got = await fetchIt();
    if (got) await saveFile(got, file.name, shown?.mime).catch((e) => (error = String(e)));
  }

  function cancel() {
    if (op) void cancelFile(op);
  }

  onDestroy(() => {
    destroyed = true;
    if (op) void cancelFile(op);
    if (url) {
      ongone?.(url);
      URL.revokeObjectURL(url);
    }
  });
</script>

<div class="file-card" class:media bind:this={card} tabindex="-1" aria-label={file.name}>
  {#if url && shown?.kind === "image"}
    <button
      class="file-media"
      type="button"
      style="aspect-ratio: {aspect}"
      onclick={() => onopen({ url: url!, name: file.name, save })}
      title="Show it big"
    >
      <img src={url} alt={file.name} />
    </button>
  {:else if url && shown?.kind === "video"}
    <!-- svelte-ignore a11y_media_has_caption -->
    <video class="file-media" src={url} controls preload="metadata" style="aspect-ratio: {aspect}"></video>
  {:else if url && shown?.kind === "audio"}
    <audio class="file-audio" src={url} controls preload="metadata"></audio>
  {:else if media && !bytes}
    <div class="file-media file-preview" style="aspect-ratio: {aspect}">
      {#if file.px}
        <canvas width={PREVIEW_SIDE} height={PREVIEW_SIDE} use:paint={file.px} aria-hidden="true"></canvas>
      {/if}
      <div class="file-over">
        {#if op}
          <span class="file-state" role="status">{seeking ? "Asking members…" : `Loading… ${percent}%`}</span>
          <div class="file-bar" aria-hidden="true"><div style="width: {seeking ? 0 : percent}%"></div></div>
          <button class="btn-ghost" type="button" onclick={cancel} aria-label="Stop loading {file.name}">Cancel</button>
        {:else}
          <button class="btn-secondary" type="button" onclick={fetchIt} aria-label="Load {file.name}">Load</button>
          <button class="btn-ghost" type="button" onclick={save} aria-label="Download {file.name}"><Icon name="download" size={14} /> Download</button>
        {/if}
      </div>
    </div>
  {/if}
  <div class="file-row">
    <Icon name="file" size={18} />
    <span class="file-name" title={file.name}>{file.name}</span>
    <span class="file-size num">{formatSize(file.size)}</span>
    {#if op && !media}
      <span class="file-state" role="status">{seeking ? "Asking members…" : `${percent}%`}</span>
      <button class="btn-ghost" type="button" onclick={cancel} aria-label="Stop loading {file.name}"><Icon name="close" size={14} /></button>
    {:else if !media || bytes}
      <button class="btn-ghost" type="button" onclick={save} aria-label="Download {file.name}"><Icon name="download" size={14} /> Download</button>
    {/if}
  </div>
  {#if bytes && !shown}
    <p class="file-note">This file is not shown here. Download it to open it with an app you trust.</p>
  {/if}
  {#if error}
    <p class="file-error" role="alert">{error}</p>
  {/if}
</div>

<style>
  .file-card {
    margin-top: 4px;
    width: min(420px, 100%);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    overflow: hidden;
  }
  .file-media {
    display: block;
    width: 100%;
    max-height: 320px;
    padding: 0;
    border: none;
    background: var(--bg-tertiary);
    position: relative;
    overflow: hidden;
  }
  button.file-media {
    cursor: zoom-in;
  }
  .file-media img {
    width: 100%;
    height: 100%;
    object-fit: contain;
    display: block;
  }
  video.file-media {
    object-fit: contain;
    background: #000;
  }
  /* Whatever shape it claims, the buttons stay in reach */
  .file-preview {
    min-height: 120px;
  }
  .file-preview canvas {
    width: 100%;
    height: 100%;
    display: block;
    /* Sixteen pixels, smeared: what it looks like, never what it says */
    filter: blur(12px);
    transform: scale(1.15);
  }
  .file-over {
    position: absolute;
    inset: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: center;
    align-content: center;
    gap: 8px;
    padding: 12px;
  }
  .file-audio {
    display: block;
    width: 100%;
    padding: 8px 8px 0;
    box-sizing: border-box;
  }
  .file-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    color: var(--text-secondary);
    min-width: 0;
  }
  .file-name {
    flex: 1;
    min-width: 0;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .file-size,
  .file-state {
    font-size: 0.8rem;
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .file-over .file-state {
    flex-basis: 100%;
    text-align: center;
    color: var(--text-primary);
  }
  .file-bar {
    flex-basis: 70%;
    height: 4px;
    border-radius: 2px;
    background: var(--border);
    overflow: hidden;
  }
  .file-bar div {
    height: 100%;
    background: var(--text-secondary);
    transition: width 0.2s;
  }
  .file-note,
  .file-error {
    margin: 0;
    padding: 0 10px 8px;
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .file-error {
    color: var(--danger);
  }
  @container (max-width: 390px) {
    .file-media {
      max-height: 240px;
    }
  }
</style>
