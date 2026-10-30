<script lang="ts">
  // One server emote or sticker, as the PNG this device made of its file
  // (stores/emotes.ts): shown only while the server lists a file of the hash
  // the message carries (emote-rules.ts), else the `:name:` it was typed as.
  // Its object URL is made only once it is on screen.
  import { serverAddress } from "../../stores/connection.js";
  import { emoteSets, emoteUrls, emoteWait, favEmotes, reducedMotion, toggleFav, urlKey, wantPicture } from "../../stores/emotes.js";
  import { uiPrefs } from "../../stores/ui-prefs.js";
  import { emoteOf, type Emote } from "../../emote-rules.js";
  import { portal } from "../../actions/portal.js";
  import { menu } from "../../actions/menu.js";
  import Icon from "../Icons.svelte";

  interface Props {
    name: string;
    /** The token's hex digits (or a whole hash); absent for a reaction,
     *  found by name. */
    hash?: string;
    /** Shown as a sticker (big), or a jumbo emote. */
    size?: "inline" | "jumbo" | "sticker";
    /** A token in a message's text: never a sticker's picture, which only a
     *  sticker sent as such shows (the admins' switch, the reader's choice). */
    inText?: boolean;
  }
  let { name, hash, size = "inline", inText = false }: Props = $props();

  const e = $derived<Emote | undefined>(
    hash
      ? emoteOf(hash, $emoteSets.emotes, name, inText ? false : undefined)
      : $emoteSets.emotes.find((x) => x.name === name && !x.sticker),
  );
  const urls = $derived(e ? $emoteUrls.get(urlKey(e.hash, e.sticker)) : undefined);
  const mode = $derived($reducedMotion ? "never" : $uiPrefs.animate_emotes);
  let hovered = $state(false);
  const moving = $derived(mode === "always" || (mode === "hover" && hovered));
  $effect(() => {
    if (!e) return;
    // Asked again once emotes that waited for Wi-Fi may come
    void $emoteWait;
    if (mode !== "always") wantPicture($serverAddress, e, true);
    if (moving) wantPicture($serverAddress, e, false);
  });
  const src = $derived(moving ? (urls?.url ?? urls?.still) : urls?.still);
  /** Its shape as the server lists it, so the room is kept before it is drawn. */
  const ratio = $derived(e?.w && e.h ? e.w / e.h : 1);

  // In a message, a press tells what it is: its name (a phone has no
  // tooltips to learn it from), its pack, why it is not shown, and a star
  const interactive = $derived(inText || size === "sticker");
  let info = $state<{ x: number; y: number } | null>(null);
  const faved = $derived(!!e && ($favEmotes[$serverAddress] ?? []).includes(e.name));
  function showInfo(ev: MouseEvent) {
    if (!interactive || !e) return;
    ev.stopPropagation();
    const below = ev.clientY + 140 < innerHeight;
    info = { x: Math.max(8, Math.min(ev.clientX - 20, innerWidth - 248)), y: below ? ev.clientY + 12 : ev.clientY - 140 };
  }
  $effect(() => {
    if (!info) return;
    const close = () => (info = null);
    addEventListener("click", close);
    return () => removeEventListener("click", close);
  });
</script>

{#if src}
  <!-- The name is its alt text: the press only tells more, for a phone that has no tooltips -->
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
  <img
    class="emote {size}"
    {src}
    alt=":{name}:"
    title=":{e?.name ?? name}:"
    draggable="false"
    class:pressable={interactive}
    onpointerenter={() => (hovered = true)}
    onpointerleave={() => (hovered = false)}
    onclick={showInfo}
  />
{:else if urls?.error}<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions --><span
    class="emote-failed"
    title="This emote could not be shown here: {urls.error}"
    onclick={showInfo}>:{name}:</span
  >{:else if e}<span
    class="emote emote-wait {size}"
    style="aspect-ratio: {ratio}{size === 'sticker' ? `; width: ${Math.round(160 * Math.min(1, ratio))}px` : ''}"
    role="img"
    aria-label=":{name}:"
    title=":{name}:"
  ></span>{:else}:{name}:{/if}{#if info && e}<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions --><div
    class="emote-info"
    style="left: {info.x}px; top: {info.y}px"
    use:portal
    use:menu={{ onclose: () => (info = null), label: `:${e.name}:` }}
    onclick={(ev) => ev.stopPropagation()}
  >
    <strong>:{e.name}:</strong>
    <span class="emote-info-meta">{e.sticker ? "A sticker" : "An emote"} of this server{e.pack ? ` · ${e.pack}` : ""}</span>
    {#if urls?.error}<span class="emote-info-error">Not shown here: {urls.error}</span>{/if}
    <button type="button" onclick={() => toggleFav($serverAddress, e.name)}
      ><Icon name="star" size={14} /> {faved ? "No longer a favourite" : "Make it a favourite"}</button
    >
  </div>{/if}

<style>
  .pressable {
    cursor: pointer;
  }
  .emote-info {
    position: fixed;
    z-index: var(--z-menu);
    display: flex;
    flex-direction: column;
    gap: 4px;
    width: 240px;
    padding: 8px 10px;
    font-size: var(--fs-sm);
    color: var(--text-primary);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-menu);
  }
  .emote-info-meta {
    color: var(--text-secondary);
  }
  .emote-info-error {
    color: var(--warning);
  }
  .emote-info button {
    display: flex;
    align-items: center;
    gap: 6px;
    min-height: var(--hit);
    padding: 0 6px;
    color: var(--text-primary);
    background: none;
    border: none;
    border-radius: var(--r-sm);
    cursor: pointer;
    text-align: left;
  }
  .emote-info button:hover,
  .emote-info button:focus-visible {
    background: var(--bg-hover);
  }
  .emote-wait {
    border-radius: 4px;
    background: var(--bg-hover);
  }
  .emote.sticker.emote-wait {
    max-height: none;
  }
  .emote-failed {
    opacity: 0.6;
    text-decoration: underline dotted;
  }
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
