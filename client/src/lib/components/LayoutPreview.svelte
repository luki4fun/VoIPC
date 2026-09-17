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

  const title = $derived(layout === "discord" ? "Discord style" : "Classic");
  const blurb = $derived(
    layout === "discord"
      ? "Server rail, channels with the people in them, chat in the middle, members on the right. One click joins a channel."
      : "Channels on the left, members on the right, voice and status bars along the bottom. Click to look, double click to join.",
  );
</script>

<button class="layout-choice" class:selected onclick={onpick} aria-pressed={selected}>
  <span class="wire" class:discord={layout === "discord"} aria-hidden="true">
    {#if layout === "discord"}
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
    min-width: 200px;
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
    border-color: var(--accent);
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

  .wire.discord {
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
    background: var(--accent);
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
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .choice-blurb {
    font-size: 11px;
    line-height: 1.45;
  }
</style>
