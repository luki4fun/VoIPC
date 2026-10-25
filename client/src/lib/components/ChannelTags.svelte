<script lang="ts">
  // The marks a channel row carries for its options, the same in both
  // layouts: anonymous, hidden, routed, announcements, 18+. Each layout keeps
  // its own look for `.proximity-tag` (styled there with :global), and puts
  // its own marks — the proximity mode, "left" — before these.
  import Icon from "./Icons.svelte";
  import type { ChannelInfo } from "../types.js";

  let { channel }: { channel: ChannelInfo } = $props();
</script>

{#if channel.anonymous}
  <span class="proximity-tag" title="Anonymous: members see each other under random names">?</span>
{/if}
{#if channel.hidden}
  <span class="proximity-tag" title="Hidden: only admins see this channel in the list">H</span>
{/if}
{#if channel.routed}
  <span
    class="proximity-tag"
    title="Routed: the server is told which members you want to hear, and forwards only their voice"
    >R</span
  >
{/if}
{#if channel.text && channel.announce}
  <span class="proximity-tag announce-tag" title="Announcements: only moderators post here"
    ><Icon name="megaphone" size={10} /></span
  >
{/if}
{#if channel.nsfw}
  <span class="proximity-tag nsfw-tag" title="18+: you are asked to confirm your age before it opens">18+</span>
{/if}

<style>
  .nsfw-tag {
    color: var(--danger);
  }

  .announce-tag {
    display: inline-flex;
    align-items: center;
  }
</style>
