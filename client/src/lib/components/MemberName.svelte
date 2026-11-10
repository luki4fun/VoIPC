<script lang="ts">
  // A person's name wherever it is shown (1.9): what they chose to be called, and
  // always the `@name` it cannot be mistaken for. The chosen part is what gives way
  // when there is no room, and `<bdi>` keeps it from reordering what stands next to it.
  //
  // `account` must be the relay's word for this row (a roster row's own, a stored
  // log's), never what a message says about itself: a `shared` message could name
  // anybody's account and be shown under their chosen name.

  import { shortName } from "../username.js";
  import { toHex } from "../hex.js";
  import { serverAddress } from "../stores/scoped.js";
  import { askProfile, profiles } from "../stores/profiles.js";

  let { username, account = null }: { username: string; account?: number[] | string | null } = $props();

  const key = $derived(typeof account === "string" ? account : account ? toHex(account) : null);
  const shown = $derived(key ? ($profiles.get(key)?.name ?? null) : null);

  $effect(() => {
    if (key) askProfile($serverAddress, key);
  });
</script>

{#if shown}
  <span class="member-name"><bdi class="display">{shown}</bdi><span class="at">@{shortName(username)}</span></span>
{:else}
  {shortName(username)}
{/if}

<style>
  .member-name {
    display: inline-flex;
    align-items: baseline;
    gap: 4px;
    min-width: 0;
    max-width: 100%;
    vertical-align: bottom;
  }

  .display {
    flex: 0 1 auto;
    min-width: 2ch;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .at {
    flex: none;
    white-space: nowrap;
    font-size: 0.85em;
    font-weight: normal;
    opacity: 0.7;
  }
</style>
