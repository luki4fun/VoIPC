<script lang="ts">
  // A loaded picture, big, over everything: pinch, wheel or keys zoom it,
  // a drag pans it (actions/zoom.ts). Escape, Back or a click beside it close.
  import { dialog, backdrop } from "../../actions/dialog.js";
  import { portal } from "../../actions/portal.js";
  import { zoomable } from "../../actions/zoom.js";
  import { FIT, type View } from "../../zoom-rules.js";
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
</script>

<!-- To the end of <body>: the chat's container query would hold a fixed box -->
<div class="lightbox-backdrop" use:portal onclick={backdrop(onclose)} role="presentation">
  <div class="lightbox" use:dialog={{ onclose }}>
    <div class="lightbox-bar">
      <h2 class="dialog-title" title={name}>{name}</h2>
      <button class="btn-ghost" type="button" onclick={onsave}><Icon name="download" size={16} /> Download</button>
      <button class="btn-ghost close" type="button" onclick={onclose} aria-label="Close"><Icon name="close" size={16} /></button>
    </div>
    <!-- Focusable so + − 0 and the arrows can zoom and pan it (actions/zoom.ts),
         as in the share viewer; data-no-swipe keeps the phone's drawer off it -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <div
      class="lightbox-stage"
      data-no-swipe
      tabindex="0"
      role="img"
      aria-label="{name}. Plus and minus zoom, arrows move, 0 fits."
      use:zoomable={{ key: url, onchange: (v) => (view = v) }}
    >
      <img src={url} alt="" draggable="false" style="transform: translate({view.x}px, {view.y}px) scale({view.scale})" />
    </div>
  </div>
</div>

<style>
  .lightbox-backdrop {
    position: fixed;
    inset: 0;
    z-index: 1000;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
  }
  .lightbox {
    display: flex;
    flex-direction: column;
    gap: 8px;
    width: min(100%, 1400px);
    height: 100%;
  }
  .lightbox-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-primary);
  }
  .lightbox-bar h2 {
    flex: 1;
    min-width: 0;
    margin: 0;
    font-size: 0.95rem;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
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
