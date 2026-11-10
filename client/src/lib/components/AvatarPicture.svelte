<script lang="ts">
  // A profile picture over the initials of the avatar it sits in (its parent needs
  // `position: relative`). Fetched only once on screen: a member list of thousands
  // should not fetch thousands of pictures for rows nobody scrolled to.

  import { toHex } from "../hex.js";
  import { serverAddress } from "../stores/scoped.js";
  import { askPicture, askProfile, pictureKey, pictures, profiles } from "../stores/profiles.js";

  let { account = null }: { account?: number[] | string | null } = $props();

  const key = $derived(typeof account === "string" ? account : account ? toHex(account) : null);
  const hash = $derived(key ? ($profiles.get(key)?.picture ?? null) : null);
  const url = $derived(hash ? ($pictures.get(pictureKey($serverAddress, hash)) ?? null) : null);
  let seen = $state(false);

  $effect(() => {
    if (key) askProfile($serverAddress, key);
  });
  $effect(() => {
    if (seen && hash) askPicture($serverAddress, hash);
  });

  function watch(el: HTMLElement) {
    if (typeof IntersectionObserver === "undefined") {
      seen = true;
      return;
    }
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        seen = true;
        io.disconnect();
      }
    });
    io.observe(el);
    return { destroy: () => io.disconnect() };
  }
</script>

{#if key}
  <span class="picture" use:watch>
    {#if url}<img src={url} alt="" />{/if}
  </span>
{/if}

<style>
  .picture {
    position: absolute;
    inset: 0;
    border-radius: inherit;
    pointer-events: none;
  }

  img {
    display: block;
    width: 100%;
    height: 100%;
    object-fit: cover;
    border-radius: inherit;
  }
</style>
