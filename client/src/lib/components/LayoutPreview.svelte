<script lang="ts">
  // A wireframe of a layout, drawn in CSS. No screenshots to ship, nothing to
  // regenerate when the UI moves, and it themes itself with everything else.
  //
  // Shared by the first-run picker and Settings → Appearance, so the two cannot
  // drift into showing different things.

  import type { LayoutId } from "../ui-prefs.js";

  interface Props {
    layout: LayoutId;
    selected: boolean;
    onpick: () => void;
  }
  let { layout, selected, onpick }: Props = $props();

  const COPY: Record<LayoutId, { title: string; blurb: string }> = {
    modern: {
      title: "Modern",
      blurb:
        "The default. Server rail, channels with the people in them, chat in the middle, members on the right. Pick a channel to look in; join from the chat pane.",
    },
    classic: {
      title: "Classic",
      blurb:
        "VoIPC's original arrangement. Channels on the left, members on the right, voice and status bars along the bottom. Pick a channel to look in; join from the chat pane.",
    },
    stage: {
      title: "Stage",
      blurb:
        "Call first. The people in your voice channel fill the middle, with a ring around whoever talks, and a share takes the stage. Chat opens beside it when you want it.",
    },
  };
  const title = $derived(COPY[layout].title);
  const blurb = $derived(COPY[layout].blurb);
</script>

<!-- `data-layout` so test-ui.mjs can click a named layout rather than the
     second button in a row, which is what it did until the two were renamed. -->
<button
  class="layout-choice"
  class:selected
  data-layout={layout}
  onclick={onpick}
  role="radio"
  aria-checked={selected}
>
  <span class="wire" class:modern={layout !== "classic"} aria-hidden="true">
    {#if layout === "stage"}
      <span class="w-rail"></span>
      <span class="w-main">
        <span class="w-bar"></span>
        <span class="w-tiles">
          <span class="w-tile talking"></span>
          <span class="w-tile"></span>
          <span class="w-tile"></span>
          <span class="w-tile"></span>
        </span>
        <span class="w-dock"></span>
      </span>
    {:else if layout === "modern"}
      <span class="w-rail"></span>
      <span class="w-side">
        <span class="w-row"></span>
        <span class="w-row indent"></span>
        <span class="w-row indent"></span>
        <span class="w-row"></span>
        <span class="w-foot"></span>
      </span>
      <span class="w-main">
        <span class="w-bar"></span>
        <span class="w-body"></span>
        <span class="w-input"></span>
      </span>
      <span class="w-members"></span>
    {:else}
      <span class="w-top"></span>
      <span class="w-cols">
        <span class="w-side">
          <span class="w-row"></span>
          <span class="w-row"></span>
          <span class="w-row"></span>
        </span>
        <span class="w-main"><span class="w-body"></span></span>
        <span class="w-members"></span>
      </span>
      <span class="w-bottom"></span>
      <span class="w-bottom thin"></span>
    {/if}
  </span>
  <span class="choice-title">{title}</span>
  <span class="choice-blurb">{blurb}</span>
</button>

<style>
  .layout-choice {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex: 1;
    min-width: 150px;
    padding: 12px;
    background: var(--bg-tertiary);
    border: 2px solid transparent;
    border-radius: 10px;
    text-align: left;
    color: var(--text-secondary);
  }

  .layout-choice:hover {
    border-color: var(--border);
  }

  .layout-choice.selected {
    border-color: var(--text-primary);
    color: var(--text-primary);
  }

  .wire {
    display: flex;
    flex-direction: column;
    gap: 2px;
    height: 104px;
    padding: 4px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }

  .wire.modern {
    flex-direction: row;
  }

  .w-top,
  .w-bottom {
    height: 8px;
    background: var(--bg-secondary);
    border-radius: 2px;
    flex-shrink: 0;
  }

  .w-bottom.thin {
    height: 5px;
  }

  .w-cols {
    display: flex;
    gap: 2px;
    flex: 1;
    min-height: 0;
  }

  .w-rail {
    width: 10px;
    background: var(--bg-tertiary);
    border-radius: 2px;
    flex-shrink: 0;
  }

  .w-side {
    display: flex;
    flex-direction: column;
    gap: 3px;
    width: 34px;
    padding: 3px;
    background: var(--bg-secondary);
    border-radius: 2px;
    flex-shrink: 0;
  }

  .w-row {
    height: 5px;
    background: var(--bg-hover);
    border-radius: 2px;
  }

  .w-row.indent {
    margin-left: 6px;
    height: 4px;
    background: var(--text-muted);
    opacity: 0.5;
  }

  .w-foot {
    margin-top: auto;
    height: 10px;
    background: var(--bg-tertiary);
    border-radius: 2px;
  }

  .w-main {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex: 1;
    min-width: 0;
    padding: 3px;
  }

  .w-bar {
    height: 6px;
    background: var(--bg-secondary);
    border-radius: 2px;
  }

  .w-body {
    flex: 1;
    background: var(--bg-secondary);
    border-radius: 2px;
    opacity: 0.55;
  }

  .w-input {
    height: 7px;
    background: var(--bg-tertiary);
    border-radius: 2px;
  }

  .w-members {
    width: 22px;
    background: var(--bg-secondary);
    border-radius: 2px;
    flex-shrink: 0;
  }

  .choice-title {
    font-size: var(--fs-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .w-tiles {
    flex: 1;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 3px;
    min-height: 0;
  }

  .w-tile {
    background: var(--bg-secondary);
    border-radius: 3px;
  }

  /* Somebody talking: the one place the wireframe uses the live colour */
  .w-tile.talking {
    box-shadow: inset 0 0 0 2px var(--speaking);
  }

  .w-dock {
    align-self: center;
    width: 60%;
    height: 7px;
    background: var(--bg-tertiary);
    border-radius: 4px;
  }

  .choice-blurb {
    font-size: var(--fs-sm);
    line-height: 1.45;
  }
</style>
