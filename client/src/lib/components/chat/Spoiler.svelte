<script lang="ts">
  import type { Snippet } from "svelte";

  // ||hidden|| text: covered until pressed, and covered again by a second
  // press. While covered it is `inert`, so a link inside cannot be reached or
  // pressed through the cover, and hidden from screen readers, which hear
  // "spoiler" instead. One element in both states, so the keyboard stays on
  // it and `aria-expanded` says which (R2-13). `tabbable`: a Tab stop
  // (Markdown's, R2-06).
  let { children, tabbable = true }: { children: Snippet; tabbable?: boolean } = $props();
  let open = $state(false);

  function onkeydown(e: KeyboardEvent) {
    if (e.target !== e.currentTarget) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      open = !open;
    }
  }

  function onclick(e: MouseEvent) {
    // A link inside an open spoiler is pressed, not the spoiler
    const inner = (e.target as Element).closest?.("button, a");
    if (open && inner && (e.currentTarget as Element).contains(inner)) return;
    open = !open;
  }
</script>

<span
  class="spoiler"
  class:open
  role="button"
  tabindex={tabbable ? 0 : -1}
  aria-label={open ? undefined : "Spoiler, press to show"}
  aria-expanded={open}
  {onclick}
  {onkeydown}><span class="cover" inert={!open} aria-hidden={open ? undefined : "true"}>{@render children()}</span></span
>

<style>
  .spoiler {
    border-radius: var(--r-sm);
    padding: 0 2px;
    background: var(--bg-hover);
  }

  .spoiler:not(.open) {
    cursor: pointer;
  }

  .spoiler:not(.open) .cover {
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
