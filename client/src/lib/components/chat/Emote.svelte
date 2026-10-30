<script lang="ts">
  // One server emote or sticker, as the PNG this device made of its file
  // (stores/emotes.ts): shown only while the server lists a file of the hash
  // the message carries (emote-rules.ts), else the `:name:` it was typed as.
  import { serverAddress } from "../../stores/connection.js";
  import { emoteSets, emoteUrls, reducedMotion, wantStill } from "../../stores/emotes.js";
  import { uiPrefs } from "../../stores/ui-prefs.js";
  import { emoteOf, type Emote } from "../../emote-rules.js";

  interface Props {
    name: string;
    /** The token's 20 hex digits; absent for a reaction, found by name. */
    hash?: string;
    /** Shown as a sticker (big), or a jumbo emote. */
    size?: "inline" | "jumbo" | "sticker";
  }
  let { name, hash, size = "inline" }: Props = $props();

  const e = $derived<Emote | undefined>(
    hash ? emoteOf(hash, $emoteSets.emotes, name) : $emoteSets.emotes.find((x) => x.name === name && !x.sticker),
  );
  const urls = $derived(e ? $emoteUrls.get(e.hash) : undefined);
  const mode = $derived($reducedMotion ? "never" : $uiPrefs.animate_emotes);
  let hovered = $state(false);
  $effect(() => {
    if (e && mode !== "always") wantStill($serverAddress, e);
  });
  const src = $derived(
    !urls?.url ? undefined : mode === "always" || (mode === "hover" && hovered) ? urls.url : (urls.still ?? undefined),
  );
</script>

{#if src}
  <img
    class="emote {size}"
    {src}
    alt=":{name}:"
    title=":{e?.name ?? name}:"
    draggable="false"
    onpointerenter={() => (hovered = true)}
    onpointerleave={() => (hovered = false)}
  />
{:else}:{name}:{/if}

<style>
  .emote {
    display: inline-block;
    width: auto;
    height: 1.375em;
    vertical-align: -0.3em;
    object-fit: contain;
  }
  .emote.jumbo {
    height: 3em;
    vertical-align: middle;
  }
  .emote.sticker {
    display: block;
    height: auto;
    width: auto;
    max-width: min(160px, 100%);
    max-height: 160px;
    margin: 4px 0;
  }
</style>
