<script lang="ts">
  // A loaded picture, big, over everything: pinch, wheel or keys zoom it,
  // a drag pans it (actions/zoom.ts). Escape, Back or a click beside it close.
  import { dialog, backdrop } from "../../actions/dialog.js";
  import { portal } from "../../actions/portal.js";
  import { zoomable, ZOOM_STEP, type ZoomControls } from "../../actions/zoom.js";
  import { FIT, MAX_SCALE, type View } from "../../zoom-rules.js";
  import Icon from "../Icons.svelte";

  interface Props {
    /** An object URL of the picture, from its card. */
    url: string;
    name: string;
    onclose: () => void;
    onsave: () => void;
  }
  let { url, name, onclose, onsave }: Props = $props();

  let view = $state<View>(FIT);
  /** The gestures and keys, as buttons too: a mouse without a wheel, a
   *  finger that does not know to pinch, a reader who never sees the label. */
  let zoom = $state<ZoomControls | null>(null);
  let img = $state<HTMLImageElement>();
</script>

<!-- To the end of <body>: the chat's container query would hold a fixed box -->
<div class="lightbox-backdrop" use:portal onclick={backdrop(onclose)} role="presentation">
  <div class="lightbox" use:dialog={{ onclose }}>
    <div class="lightbox-bar">
      <h2 class="dialog-title" title={name}>{name}</h2>
      <div class="lightbox-zoom" role="group" aria-label="Zoom">
        <button class="icon-btn" type="button" title="Zoom out (−)" aria-label="Zoom out" aria-disabled={view.scale <= 1} onclick={() => view.scale > 1 && zoom?.zoom(1 / ZOOM_STEP)}
          ><Icon name="zoom-out" size={18} /></button
        >
        <!-- "Fit", not a percentage: the scale counts from the fitted picture,
             which is not its own size, and 100% would claim one-to-one -->
        <button class="btn btn-ghost lightbox-fit" type="button" title="Fit (0)" aria-label="Fit to the window" aria-disabled={view.scale <= 1} onclick={() => zoom?.fit()}
          >Fit</button
        >
        <button class="icon-btn" type="button" title="Zoom in (+)" aria-label="Zoom in" aria-disabled={view.scale >= MAX_SCALE} onclick={() => zoom?.zoom(ZOOM_STEP)}
          ><Icon name="zoom-in" size={18} /></button
        >
      </div>
      <button class="btn btn-ghost lightbox-dl" type="button" aria-label="Download {name}" title="Download" onclick={onsave}><Icon name="download" size={16} /> <span class="lightbox-dl-label">Download</span></button>
      <button class="icon-btn close" type="button" onclick={onclose} aria-label="Close" title="Close (Esc)"><Icon name="close" size={18} /></button>
    </div>
    <!-- Focusable so + − 0 and the arrows can zoom and pan it (actions/zoom.ts),
         as in the share viewer; data-no-swipe keeps the phone's drawer off it -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div
      class="lightbox-stage"
      data-no-swipe
      data-autofocus
      tabindex="0"
      role="img"
      aria-label="{name}. Plus and minus zoom, arrows move, 0 fits."
      use:zoomable={{
        key: url,
        onchange: (v) => (view = v),
        controls: (c) => (zoom = c),
        content: () => (img?.naturalWidth ? { w: img.naturalWidth, h: img.naturalHeight } : null),
      }}
    >
      <img bind:this={img} src={url} alt="" draggable="false" style="transform: translate({view.x}px, {view.y}px) scale({view.scale})" />
    </div>
  </div>
</div>

<style>
  .lightbox-backdrop {
    position: fixed;
    inset: 0;
    z-index: var(--z-modal);
    /* Near solid: a picture is looked at, not the chat behind it */
    background: color-mix(in srgb, var(--bg-tertiary) 92%, transparent);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
  }
  /* A WebView before Chrome 111 has no color-mix(). A plain fallback line
     before it does not help: with var() inside, the line parses, then fails
     when computed and leaves no backdrop at all */
  @supports not (background: color-mix(in srgb, red 50%, blue)) {
    .lightbox-backdrop {
      background: var(--scrim);
    }
  }
  .lightbox {
    display: flex;
    flex-direction: column;
    gap: 8px;
    width: min(100%, 1400px);
    height: 100%;
  }
  /* Solid: through the scrim, the chat's own header would show under the
     name and the buttons (D2-12) */
  .lightbox-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 4px 4px 12px;
    color: var(--text-primary);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
  }
  .lightbox-bar h2 {
    flex: 1;
    min-width: 0;
    margin: 0;
    font-size: var(--fs-md);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .lightbox-zoom {
    display: flex;
    align-items: center;
    gap: 2px;
  }
  /* aria-disabled, not disabled: a button that disables itself under the
     focus drops it to <body>, and Esc and the zoom keys went dead */
  .lightbox-zoom [aria-disabled="true"] {
    opacity: 0.4;
    cursor: default;
  }
  .lightbox-fit {
    min-width: 56px;
    padding: 4px 6px;
    font-weight: 400;
  }
  .lightbox-dl {
    padding: 4px 10px;
    font-weight: 400;
  }
  /* A phone: the name keeps what room there is, the button its icon */
  @media (max-width: 480px) {
    .lightbox-dl-label {
      display: none;
    }
  }
  .lightbox-stage {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    touch-action: none;
    border-radius: var(--r-md);
  }
  /* The box zoom-rules works in: the stage's own, the picture fitted inside */
  .lightbox-stage img {
    width: 100%;
    height: 100%;
    object-fit: contain;
    transform-origin: 0 0;
    user-select: none;
  }
</style>
