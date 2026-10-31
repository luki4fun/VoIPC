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
  import { fit } from "../../actions/fit.js";
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
    /** In the message the keyboard is on (MessageList's roving focus): a Tab
     *  stop, as the message's links are. */
    tabbable?: boolean;
  }
  let { name, hash, size = "inline", inText = false, tabbable = false }: Props = $props();

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
  /** Held back on mobile data (stores/emotes.ts): in a message, its name until
   *  Wi-Fi, as the question promised, not an empty box that looks like it is
   *  loading. The picker keeps the boxes, with its own line about Wi-Fi. */
  const waiting = $derived.by(() => {
    if (!e) return false;
    const w = $emoteWait.get($serverAddress);
    return !!w && (w.missing === null || w.missing.has(urlKey(e.hash, e.sticker)));
  });
  /** Its shape as the server lists it, so the room is kept before it is drawn. */
  const ratio = $derived(e?.w && e.h ? e.w / e.h : 1);

  // In a message, a press tells what it is: its name (a phone has no
  // tooltips to learn it from), its pack, why it is not shown, and a star
  const interactive = $derived(inText || size === "sticker");
  let info = $state<{ x: number; y: number; up: number } | null>(null);
  const faved = $derived(!!e && ($favEmotes[$serverAddress] ?? []).includes(e.name));
  /** Under the emote, or above it where there is no room (actions/fit.ts
   *  measures the card, error line and all). From its box, not the pointer:
   *  Enter on it has no pointer position. */
  function showInfo(ev: MouseEvent) {
    if (!interactive || !e) return;
    ev.stopPropagation();
    if (info) {
      info = null;
      return;
    }
    const r = (ev.currentTarget as HTMLElement).getBoundingClientRect();
    info = { x: r.left, y: r.bottom + 6, up: r.top - 6 };
  }
  $effect(() => {
    if (!info) return;
    const close = () => (info = null);
    addEventListener("click", close);
    return () => removeEventListener("click", close);
  });
</script>

{#if src && interactive}
  <!-- In a message a press tells more: its name (a phone has no tooltips), its pack, a star -->
  <button
    class="emote-btn"
    type="button"
    tabindex={tabbable ? 0 : -1}
    aria-label=":{e?.name ?? name}:"
    aria-haspopup="menu"
    aria-expanded={!!info}
    title=":{e?.name ?? name}:"
    onpointerenter={() => (hovered = true)}
    onpointerleave={() => (hovered = false)}
    onclick={showInfo}><img class="emote {size}" {src} alt=":{name}:" draggable="false" /></button
  >
{:else if src}
  <img
    class="emote {size}"
    {src}
    alt=":{name}:"
    title=":{e?.name ?? name}:"
    draggable="false"
    onpointerenter={() => (hovered = true)}
    onpointerleave={() => (hovered = false)}
  />
{:else if urls?.error && interactive}<button
    class="emote-failed"
    type="button"
    tabindex={tabbable ? 0 : -1}
    aria-label=":{name}:, not shown here"
    aria-haspopup="menu"
    aria-expanded={!!info}
    title="This emote could not be shown here: {urls.error}"
    onclick={showInfo}>:{name}:</button
  >{:else if urls?.error}<span class="emote-failed" title="This emote could not be shown here: {urls.error}">:{name}:</span
  >{:else if waiting && interactive}<span class="emote-held" title="Waits for Wi-Fi">:{name}:</span>{:else if e}<span
    class="emote emote-wait {size}"
    style="aspect-ratio: {ratio}{size === 'sticker' ? `; width: ${Math.round(160 * Math.min(1, ratio))}px` : ''}"
    role="img"
    aria-label=":{name}:"
    title=":{name}:"
  ></span>{:else}:{name}:{/if}{#if info && e}<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions --><div
    class="emote-info"
    style="left: {info.x}px; top: {info.y}px"
    use:portal
    use:fit={info.up}
    use:menu={{ onclose: () => (info = null), label: `:${e.name}:` }}
    onclick={(ev) => ev.stopPropagation()}
  >
    <strong>:{e.name}:</strong>
    <span class="emote-info-meta">{e.sticker ? "A sticker" : "An emote"} of this server{e.pack ? ` · ${e.pack}` : ""}</span>
    {#if urls?.error}<span class="emote-info-error">Not shown here: {urls.error}</span>{/if}
    <button type="button" onclick={() => toggleFav($serverAddress, e.name)}
      ><Icon name="star" size={14} /> {faved ? "Remove from favourites" : "Add to favourites"}</button
    >
  </div>{/if}

<style>
  /* A press on it opens its card; it stays what it is, a picture in a line */
  .emote-btn {
    display: inline;
    padding: 0;
    margin: 0;
    font: inherit;
    line-height: inherit;
    color: inherit;
    background: none;
    border: none;
    border-radius: var(--r-sm);
    cursor: pointer;
    vertical-align: baseline;
  }
  .emote-btn:has(.emote.sticker) {
    display: block;
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
    border-radius: var(--r-sm);
    background: var(--bg-hover);
  }
  .emote.sticker.emote-wait {
    max-height: none;
  }
  /* Its name, as typed, marked as not drawn: muted ink (it still reads at
     4.5:1), never a faded copy of the text around it */
  .emote-failed {
    padding: 0;
    font: inherit;
    color: var(--text-muted);
    background: none;
    border: none;
    text-decoration: underline dotted;
    text-underline-offset: 2px;
    cursor: pointer;
  }
  span.emote-failed {
    cursor: default;
  }
  .emote-held {
    color: var(--text-secondary);
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
