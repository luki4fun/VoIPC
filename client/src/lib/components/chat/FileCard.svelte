<script lang="ts">
  // The file a message carries. Nothing is fetched until it is asked for:
  // before that a picture shows as its 16×16 preview, drawn from the raw
  // pixels its message carries (no decoder runs on anything a peer sent).
  // Loaded, what it is comes from its own bytes (file-sniff.ts), never from
  // what its message claims: a picture is drawn, but only as the PNG the
  // sanitizer wrote for it (media.ts); a video or a sound gets its controls
  // and never starts by itself, where playing it here is allowed; anything
  // else is only saved.
  import { onDestroy, tick, untrack } from "svelte";
  import type { FileConv, FileRef } from "../../types.js";
  import { FILE_UNAVAILABLE, cancelFile, fetchFile, fileProgress, forgetProgress, newOp, saveFile } from "../../files.js";
  import { formatSize, PREVIEW_SIDE } from "../../file-rules.js";
  import { preview } from "../../actions/preview.js";
  import { sniff, type Shown } from "../../file-sniff.js";
  import { fileImage, knownPictures, pictureUrl, playableUrl, playsMedia } from "../../media.js";
  import { uiPrefs } from "../../stores/ui-prefs.js";
  import { settingsAsk } from "../../stores/channel-ui.js";
  import { reducedMotion } from "../../stores/emotes.js";
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
    /** Its buttons and player are Tab stops: in a message list, only on the
     *  row the keyboard is on (R2-06). */
    tabbable?: boolean;
    /** Shown without a press: a picture the person has just sent (their device
     *  has it, and they chose it), or one they asked to see (Settings → Files'
     *  Show). Never on its own for what a member sent: no decoder runs on that
     *  before it is asked for. */
    auto?: boolean;
  }
  let { file, server, conv, onopen, ongone, tabbable = true, auto = false }: Props = $props();
  const tabindex = $derived(tabbable ? undefined : -1);

  let card = $state<HTMLElement | null>(null);
  let destroyed = false;

  /** What the card looks like before a load: the message's word for it. */
  const media = $derived(
    !!file.px || (file.w !== undefined && file.h !== undefined) || /^(image|video|audio)\//.test(file.mime ?? ""),
  );
  const aspect = $derived(file.w && file.h ? `${file.w} / ${file.h}` : "16 / 9");
  /** A sound: its player is one row, not a picture's box (D2-14). */
  const sound = $derived(/^audio\//.test(file.mime ?? "") && !(file.w && file.h) && !file.px);

  let op = $state<string | null>(null);
  let error = $state<string | null>(null);
  let bytes = $state.raw<Uint8Array | null>(null);
  let shown = $state.raw<Shown | null>(null);
  let url = $state<string | null>(null);
  /** Why what was loaded is not shown here, when it is a picture or a video
   *  that is not. */
  let withheld = $state<string | null>(null);
  /** Why a moving picture is shown as its first frame alone (too long or too
   *  big to play here), when it is. */
  let stilled = $state<string | null>(null);
  /** A video or sound loaded while Settings → Files kept them from playing:
   *  it plays here as soon as they may. */
  let held = $state.raw<Shown | null>(null);
  /** A reason as a sentence: the media crate's start in lower case. */
  const sentence = (e: unknown) => {
    const t = String(e).replace(/^Error: /, "").trim();
    return t.charAt(0).toUpperCase() + t.slice(1) + (/[.!?]$/.test(t) ? "" : ".");
  };
  $effect(() => {
    if (held && bytes && playsMedia($uiPrefs)) {
      const is = held;
      untrack(() => {
        url = playableUrl(bytes!, is.mime);
        shown = is;
        held = null;
        withheld = null;
      });
    }
  });

  let autoTried = false;
  $effect(() => {
    if (auto && !autoTried && /^image\//.test(file.mime ?? "") && !bytes && !url && !op) {
      autoTried = true;
      void fetchIt();
    }
  });

  /** A moving picture is shown still where the person wants nothing to move. */
  const still = $derived($reducedMotion || $uiPrefs.animate_emotes === "never");
  // Asked for after it was drawn (reduced motion turned on, or "never"): the
  // picture is made again the way it is wanted now, from what is already here
  let drawnStill: boolean | null = null;
  $effect(() => {
    const want = still;
    untrack(() => {
      if (drawnStill === null || want === drawnStill || shown?.kind !== "image" || !url || op) return;
      drawnStill = want;
      const at = conv ?? { channel: 0 };
      const was = loadedFor;
      void fileImage(server, at, file, undefined, want)
        .then((pic) => {
          if (destroyed || was !== loadedFor || !url) return;
          ongone?.(url);
          URL.revokeObjectURL(url);
          url = pictureUrl(pic.png);
          stilled = pic.stilled;
        })
        .catch(() => {});
    });
  });

  const progress = $derived(op ? $fileProgress.get(op) : undefined);
  const seeking = $derived(progress?.stage === "seeking");
  const percent = $derived(progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0);

  /** Its buttons change under the pointer: keep the focus in the card. */
  async function keepFocus() {
    const had = !!card?.contains(document.activeElement);
    await tick();
    if (had && !card?.contains(document.activeElement)) card?.focus();
  }

  /** Which file what is loaded here is: a row's file can change under its
   *  card (a member's copy replaced by the message itself, `mergeHistory`),
   *  and what was loaded for the old one must not be shown, or saved, under
   *  the new one's name (R3-08). */
  let loadedFor = untrack(() => `${file.hash}:${file.key}`);
  $effect.pre(() => {
    const now = `${file.hash}:${file.key}`;
    if (now === loadedFor) return;
    loadedFor = now;
    untrack(() => {
      if (op) void cancelFile(op);
      op = null;
      error = null;
      if (url) {
        ongone?.(url);
        URL.revokeObjectURL(url);
      }
      url = null;
      bytes = null;
      shown = null;
      withheld = null;
      stilled = null;
      held = null;
    });
  });

  /** Fetch it; `draw`: and show it, where it is something to show. */
  async function fetchIt(draw = true): Promise<Uint8Array | null> {
    if (bytes) return bytes;
    if (op) return null;
    const mine = newOp();
    const wanted = loadedFor;
    op = mine;
    error = null;
    void keepFocus();
    try {
      // No conversation to name: only this device's copy can open it (channel
      // 0 is never one, so the relay refuses anything further)
      const at = conv ?? { channel: 0 };
      const known = draw && !url ? knownPictures.get(file.hash) : undefined;
      if (known) {
        const pic = await fileImage(server, at, file, mine, still);
        if (destroyed || wanted !== loadedFor) return null;
        url = pictureUrl(pic.png);
        stilled = pic.stilled;
        drawnStill = still;
        shown = known;
        return null;
      }
      const got = await fetchFile(server, at, file, mine);
      if (destroyed || wanted !== loadedFor) return null;
      if (draw) {
        const is = sniff(got);
        if (is?.kind === "image") {
          try {
            const pic = await fileImage(server, at, file, mine, still);
            if (destroyed || wanted !== loadedFor) return null;
            url = pictureUrl(pic.png);
            stilled = pic.stilled;
            drawnStill = still;
            shown = is;
            knownPictures.set(file.hash, is);
          } catch (e) {
            if (destroyed || wanted !== loadedFor) return null;
            withheld = sentence(e);
          }
        } else if (is && !playsMedia($uiPrefs)) {
          withheld = "Videos and sounds play here once Settings → Files allows it.";
          held = is;
        } else if (is) {
          url = playableUrl(got, is.mime);
          shown = is;
        }
      }
      bytes = got;
      return got;
    } catch (e) {
      const why = String(e);
      if (why !== "cancelled" && wanted === loadedFor) error = why === FILE_UNAVAILABLE ? "Nobody online has this file" : why;
      return null;
    } finally {
      forgetProgress(mine);
      if (op === mine) op = null;
      if (!destroyed) void keepFocus();
    }
  }

  /** Download: a card with no Load is not drawn by it (R3-12). */
  async function save() {
    // A known picture is drawn without its file: fetched now, to be saved
    const got = (await fetchIt(media)) ?? (url && !bytes ? await fetchIt(false) : null);
    if (got) await saveFile(got, file.name, (shown ?? sniff(got))?.mime).catch((e) => (error = String(e)));
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
      {tabindex}
      style="aspect-ratio: {aspect}"
      onclick={() => onopen({ url: url!, name: file.name, save })}
      title="Show it big"
    >
      <img src={url} alt={file.name} />
    </button>
  {:else if url && shown?.kind === "video"}
    <!-- svelte-ignore a11y_media_has_caption -->
    <video class="file-media" src={url} controls preload="metadata" {tabindex} style="aspect-ratio: {aspect}"></video>
  {:else if url && shown?.kind === "audio"}
    <audio class="file-audio" src={url} controls preload="metadata" {tabindex}></audio>
  {:else if media && !bytes}
    <div class="file-media file-preview" class:sound style={sound ? undefined : `aspect-ratio: ${aspect}`}>
      {#if file.px}
        <canvas width={PREVIEW_SIDE} height={PREVIEW_SIDE} use:preview={file.px} aria-hidden="true"></canvas>
      {/if}
      <div class="file-over">
        {#if op}
          <span class="file-state" role="status">{seeking ? "Asking members…" : `Loading… ${percent}%`}</span>
          <div class="file-bar" aria-hidden="true"><div style="width: {seeking ? 0 : percent}%"></div></div>
          <div class="file-over-row">
            <button class="btn btn-secondary" type="button" {tabindex} onclick={cancel} aria-label="Stop loading {file.name}">Cancel</button>
          </div>
        {:else}
          <!-- Where "Asking members…" was, so it is seen where the eyes are (D2-11) -->
          {#if error}<span class="file-state file-error-over" role="alert">{error}</span>{/if}
          <div class="file-over-row">
            <button class="btn btn-secondary" type="button" {tabindex} onclick={() => fetchIt()} aria-label="{error ? 'Try loading' : 'Load'} {file.name}{error ? ' again' : ''}"
              >{error ? "Try again" : "Load"}</button
            >
            <button class="btn btn-secondary" type="button" {tabindex} onclick={save} aria-label="Download {file.name}"><Icon name="download" size={14} /> Download</button>
          </div>
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
      <button class="icon-btn" type="button" {tabindex} onclick={cancel} aria-label="Stop loading {file.name}"><Icon name="close" size={14} /></button>
    {:else if !media || bytes || url}
      <button class="btn btn-ghost file-dl" type="button" {tabindex} onclick={save} aria-label="Download {file.name}"><Icon name="download" size={14} /> Download</button>
    {/if}
  </div>
  {#if url && shown?.kind === "image" && stilled}
    <!-- Whatever the person's motion setting: it would not move here either -->
    <p class="file-note">{sentence(`Shown still: ${stilled}`)}</p>
  {/if}
  {#if bytes && !shown}
    <p class="file-note">
      {withheld ?? "This file is not shown here."} Download it to open it with an app you trust.
      {#if held}
        <!-- Where the switch is, one press away (Settings → Files) -->
        <button class="btn btn-ghost file-dl" type="button" {tabindex} onclick={() => settingsAsk.set({ tab: "files", place: "" })}
          >Open Settings → Files</button
        >
      {/if}
    </p>
  {/if}
  {#if error && !(media && !bytes)}
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
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px;
  }
  /* A sound before it loads: one row the height of its player, so the list
     does not jump when it comes */
  /* On the card's own surface, so its solid buttons stand out from it */
  .file-preview.sound {
    min-height: 64px;
    background: transparent;
  }
  .file-preview.sound .file-over .btn {
    box-shadow: none;
  }
  .file-preview.sound .file-over {
    position: static;
    flex-direction: row;
    flex-wrap: wrap;
    min-height: 64px;
  }
  /* On the smeared picture nothing can count on what is under it: the words
     sit on the card's own surface, the buttons are solid (.btn-secondary) */
  .file-over .file-state {
    padding: 2px 8px;
    border-radius: var(--r-sm);
    background: var(--bg-secondary);
  }
  .file-over .file-state.file-error-over {
    color: var(--danger);
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
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .file-over .file-state {
    max-width: 100%;
    white-space: normal;
    text-align: center;
    color: var(--text-primary);
  }
  /* They float over a picture: lifted off it, so a dark preview cannot swallow them */
  .file-over .btn {
    background: var(--bg-secondary);
    box-shadow: var(--shadow-menu);
  }
  .file-over .btn:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .file-over-row {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 8px;
  }
  .file-dl {
    padding: 4px 8px;
    font-weight: 400;
  }
  .file-bar {
    width: 70%;
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
    font-size: var(--fs-sm);
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
