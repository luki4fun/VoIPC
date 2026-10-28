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
    user-select: none;
  }

  /* Everything inside too: a link or a mention sets a colour (and a line or
     a chip) of its own, which would show through. `:not(.open)` outweighs
     `.mention.me` */
  .spoiler:not(.open) .cover,
  .spoiler:not(.open) .cover :global(*) {
    color: transparent;
    text-decoration-color: transparent;
    background: none;
  }

  .spoiler.open {
    transition: background-color var(--dur-base);
  }
</style>
