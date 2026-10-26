<script lang="ts">
  import type { Snippet } from "svelte";

  // ||hidden|| text: covered until pressed. While covered it is `inert`, so a
  // link inside cannot be reached or pressed through the cover, and hidden
  // from screen readers, which hear "spoiler" instead.
  let { children }: { children: Snippet } = $props();
  let open = $state(false);

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      open = true;
    }
  }
</script>

{#if open}<span class="spoiler open">{@render children()}</span>{:else}<span
    class="spoiler"
    role="button"
    tabindex="0"
    aria-label="Spoiler, press to show"
    aria-expanded="false"
    onclick={() => (open = true)}
    {onkeydown}><span class="cover" inert aria-hidden="true">{@render children()}</span></span
  >{/if}

<style>
  .spoiler {
    border-radius: var(--r-sm);
    padding: 0 2px;
    background: var(--bg-hover);
  }

  .spoiler:not(.open) {
    cursor: pointer;
  }

  .cover {
    color: transparent;
    user-select: none;
  }

  .spoiler.open {
    transition: background-color var(--dur-base);
  }
</style>
