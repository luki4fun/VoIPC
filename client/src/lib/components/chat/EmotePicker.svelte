<script module lang="ts">
  type Tab = "emotes" | "stickers" | number;
  /** The tab a picker opens on: the one used last, this session. */
  let lastTab: Tab = 0;
</script>

<script lang="ts">
  // One picker for the message box (Composer) and for reactions (MessageList):
  // the Unicode emoji by kind, this server's emotes, and its stickers where
  // they may be sent here. One search finds them all by name (an emote's, an
  // emoji's `:name:`); favourites and the recently used come first. The
  // keyboard drives it: the arrows walk the grid, Enter in the search takes
  // the first match, Escape closes the picker and nothing under it.
  import Icon from "../Icons.svelte";
  import Emote from "./Emote.svelte";
  import { EMOJI_CATEGORIES, EMOJI_NAMES, NAME_OF } from "../../emoji.js";
  import { drawsAsOne } from "../../emoji-support.js";
  import { byPack, byRecent, type Emote as Item } from "../../emote-rules.js";
  import { downloadEmotes, emoteSets, emoteWait, favEmotes, recentEmotes, toggleFav } from "../../stores/emotes.js";
  import { formatSize } from "../../file-rules.js";
  import { serverAddress } from "../../stores/connection.js";
  import { fold } from "../../search-rules.js";

  interface Props {
    /** An emoji, or a server emote's `:name:`; `keep`: picked with Shift, the
     *  picker stays open for another. */
    onpick: (text: string, keep: boolean) => void;
    /** A sticker, sent at once; absent where none may be sent here. */
    onsticker?: (e: Item) => void;
    /** Slow mode holds a sticker as it holds the draft. */
    held?: { title: string; label?: string } | null;
    /** Escape: the picker alone closes. Absent where its owner closes it on
     *  Escape (the reactions' menu). */
    onclose?: () => void;
    /** Into the search at once: opened by a mouse or the keyboard, never by a
     *  finger, whose keyboard would come up over it. */
    autofocus?: boolean;
  }
  let { onpick, onsticker, held = null, onclose, autofocus = false }: Props = $props();

  type Cell = { kind: "emoji"; emoji: string; name?: string } | { kind: "emote"; e: Item } | { kind: "sticker"; e: Item };
  interface Section {
    key: string;
    label: string;
    cells: Cell[];
  }

  const server = $derived($serverAddress);
  const recent = $derived($recentEmotes[server] ?? []);
  const favs = $derived($favEmotes[server] ?? []);
  const emotes = $derived($emoteSets.emotes.filter((e) => !e.sticker));
  const stickers = $derived(onsticker ? $emoteSets.emotes.filter((e) => e.sticker) : []);
  /** This server's emotes wait for Wi-Fi (stores/emotes.ts), and what they take. */
  const wait = $derived($emoteWait.get(server));

  let tab = $state<Tab>(lastTab);
  /** The tab shown: one that is not here now (no emotes, no stickers) is the first emoji's. */
  const current = $derived<Tab>((tab === "emotes" && !emotes.length) || (tab === "stickers" && !stickers.length) ? 0 : tab);
  function choose(t: Tab) {
    tab = lastTab = t;
    query = "";
  }

  let query = $state("");
  const q = $derived(fold(query.trim()));
  const matches = (e: Item) => fold(`${e.name} ${e.pack}`).includes(q);
  /** The name typed first, then names that start so, then a word of one
   *  (`fire` before `heart_on_fire`); the sort keeps each group's order. */
  const rank = (name: string) =>
    name === q ? 0 : name.startsWith(q) ? 1 : name.split("_").some((w) => w.startsWith(q)) ? 2 : 3;
  const emote = (e: Item): Cell => ({ kind: "emote", e });
  const sticker = (e: Item): Cell => ({ kind: "sticker", e });

  /** Favourites, then the recently used, then each pack. */
  function grouped(list: Item[], cell: (e: Item) => Cell, what: string): Section[] {
    const fav = favs.map((n) => list.find((e) => e.name === n)).filter((e): e is Item => !!e);
    const used = byRecent(
      list.filter((e) => recent.includes(e.name) && !favs.includes(e.name)),
      recent,
    );
    const out: Section[] = [
      ...(fav.length ? [{ key: "fav", label: "Favourites", cells: fav.map(cell) }] : []),
      ...(used.length ? [{ key: "recent", label: "Recently used", cells: used.map(cell) }] : []),
      ...byPack(list).map((p) => ({ key: p.key, label: p.label, cells: p.list.map(cell) })),
    ];
    // Among other sections, the ones of no pack need a heading too
    return out.map((s) => (s.label || out.length === 1 ? s : { ...s, label: what }));
  }

  const sections = $derived.by((): Section[] => {
    if (q) {
      if (current === "stickers") {
        const found = stickers.filter(matches);
        return found.length ? [{ key: "found", label: "", cells: found.map(sticker) }] : [];
      }
      const seen = new Set<string>();
      const emoji = Object.entries(EMOJI_NAMES)
        .filter(([name, e]) => name.includes(q) && drawsAsOne(e))
        .sort(([a], [b]) => rank(a) - rank(b))
        .filter(([, e]) => !seen.has(e) && !!seen.add(e))
        .map(([name, e]): Cell => ({ kind: "emoji", emoji: e, name }));
      const found = emotes.filter(matches).sort((a, b) => rank(a.name) - rank(b.name));
      return [
        ...(found.length ? [{ key: "found", label: "This server's", cells: found.map(emote) }] : []),
        ...(emoji.length ? [{ key: "emoji", label: "Emoji", cells: emoji }] : []),
      ];
    }
    if (current === "emotes") return grouped(emotes, emote, "Emotes");
    if (current === "stickers") return grouped(stickers, sticker, "Stickers");
    const cat = EMOJI_CATEGORIES[current];
    return [
      {
        key: cat.label,
        label: "",
        cells: cat.emojis.filter(drawsAsOne).map((emoji): Cell => ({ kind: "emoji", emoji, name: NAME_OF.get(emoji) })),
      },
    ];
  });
  const first = $derived(sections.find((s) => s.cells.length)?.cells[0]);
  const cellKey = (c: Cell) => (c.kind === "emoji" ? c.emoji : `${c.kind}:${c.e.name}`);

  function take(c: Cell, keep: boolean) {
    if (c.kind === "sticker") {
      if (held) return;
      onsticker?.(c.e);
      onclose?.();
      return;
    }
    onpick(c.kind === "emoji" ? c.emoji : `:${c.e.name}:`, keep);
  }

  /** Right click, or a long press on a touch screen: a favourite, or no longer.
   *  Said, since the emote moves away from under the pointer as it does. */
  let favSaid = $state("");
  let favTimer: ReturnType<typeof setTimeout> | undefined;
  function fav(ev: MouseEvent, e: Item) {
    ev.preventDefault();
    const was = favs.includes(e.name);
    toggleFav(server, e.name);
    favSaid = was ? `:${e.name}: is no longer a favourite` : `:${e.name}: is a favourite now`;
    clearTimeout(favTimer);
    favTimer = setTimeout(() => (favSaid = ""), 3000);
  }

  // A press never takes the focus from where it is: the message box keeps its
  // place, and a phone its keyboard (Composer's `keepField`)
  const keep = (e: PointerEvent) => e.preventDefault();

  let search = $state<HTMLInputElement | null>(null);
  let body = $state<HTMLElement | null>(null);
  $effect(() => {
    if (autofocus) search?.focus({ preventScroll: true });
  });

  function onSearchKey(e: KeyboardEvent) {
    if (e.key === "Enter") {
      // Never the message box's form: the first match
      e.preventDefault();
      e.stopPropagation();
      if (first) take(first, e.shiftKey);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      e.stopPropagation();
      cells()[0]?.focus();
    } else if (["ArrowUp", "ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
      // The caret's, not a menu's around it
      e.stopPropagation();
    }
  }

  const cells = () => [...(body?.querySelectorAll<HTMLElement>(".ep-cell:not([disabled])") ?? [])];

  /** The arrows by what is on screen: up and down to the nearest cell of the
   *  row above or below, whatever section it is in. */
  function onGridKey(e: KeyboardEvent) {
    const list = cells();
    const at = list.indexOf(document.activeElement as HTMLElement);
    if (at < 0) return;
    const box = (el: HTMLElement) => el.getBoundingClientRect();
    const here = box(list[at]);
    let next: HTMLElement | undefined;
    if (e.key === "ArrowRight") next = list[at + 1];
    else if (e.key === "ArrowLeft") next = list[at - 1];
    else if (e.key === "Home") next = list[0];
    else if (e.key === "End") next = list[list.length - 1];
    else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const down = e.key === "ArrowDown";
      const row = list.filter((c) => (down ? box(c).top > here.top + 1 : box(c).top < here.top - 1));
      const top = down ? Math.min(...row.map((c) => box(c).top)) : Math.max(...row.map((c) => box(c).top));
      next = row.filter((c) => box(c).top === top).sort((a, b) => Math.abs(box(a).left - here.left) - Math.abs(box(b).left - here.left))[0];
      if (!next && !down) {
        e.preventDefault();
        e.stopPropagation();
        search?.focus();
        return;
      }
    } else return;
    e.preventDefault();
    e.stopPropagation();
    next?.focus();
    next?.scrollIntoView({ block: "nearest" });
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === "Escape" && onclose) {
      e.preventDefault();
      e.stopPropagation();
      onclose();
    }
  }

  /** The tabs, in their order on screen: one Tab stop, the arrows walk them. */
  const tabs = $derived<Tab[]>([
    ...(emotes.length ? (["emotes"] as Tab[]) : []),
    ...(stickers.length ? (["stickers"] as Tab[]) : []),
    ...EMOJI_CATEGORIES.map((_, i) => i),
  ]);
  let tabRow = $state<HTMLElement | null>(null);
  function onTabKey(e: KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      e.stopPropagation();
      search?.focus();
      return;
    }
    const at = tabs.indexOf(current);
    const to =
      e.key === "ArrowRight" ? at + 1 : e.key === "ArrowLeft" ? at - 1 : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : null;
    if (to === null) return;
    e.preventDefault();
    e.stopPropagation();
    const next = (to + tabs.length) % tabs.length;
    choose(tabs[next]);
    tabRow?.querySelectorAll<HTMLElement>('[role="tab"]')[next]?.focus();
  }

  const uid = $props.id();
  /** A screen with no hover is held, not right-clicked (an emulator's touch
   *  screen says "fine pointer" but still has no hover). */
  const touchHint = typeof matchMedia === "function" && matchMedia("(hover: none)").matches;
  const searchLabel = $derived(current === "stickers" ? "Search stickers" : emotes.length ? "Search emoji and emotes" : "Search emoji");
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="ep" data-keys="own" onkeydown={onKey}>
  <!-- The selected tab is the row's one Tab stop (roving), so the row takes none -->
  <!-- svelte-ignore a11y_interactive_supports_focus -->
  <div class="ep-tabs" role="tablist" aria-label="Kinds of emoji" bind:this={tabRow} onkeydown={onTabKey}>
    {#if emotes.length}
      <button
        class="ep-tab"
        class:active={current === "emotes"}
        type="button"
        role="tab"
        id="{uid}-tab-emotes"
        aria-selected={current === "emotes"}
        aria-controls="{uid}-panel"
        tabindex={current === "emotes" ? 0 : -1}
        title="This server's emotes"
        aria-label="This server's emotes"
        onpointerdown={keep}
        onclick={() => choose("emotes")}><Emote name={emotes[0].name} hash={emotes[0].hash} /></button
      >
    {/if}
    {#if stickers.length}
      <button
        class="ep-tab"
        class:active={current === "stickers"}
        type="button"
        role="tab"
        id="{uid}-tab-stickers"
        aria-selected={current === "stickers"}
        aria-controls="{uid}-panel"
        tabindex={current === "stickers" ? 0 : -1}
        title="Stickers"
        aria-label="Stickers"
        onpointerdown={keep}
        onclick={() => choose("stickers")}><Icon name="sticker" size={18} /></button
      >
    {/if}
    {#each EMOJI_CATEGORIES as cat, idx (cat.label)}
      <button
        class="ep-tab"
        class:active={current === idx}
        type="button"
        role="tab"
        id="{uid}-tab-{idx}"
        aria-selected={current === idx}
        aria-controls="{uid}-panel"
        tabindex={current === idx ? 0 : -1}
        title={cat.label}
        aria-label={cat.label}
        onpointerdown={keep}
        onclick={() => choose(idx)}>{cat.emojis[0]}</button
      >
    {/each}
  </div>
  <input
    class="ep-search"
    type="search"
    placeholder={searchLabel}
    aria-label={searchLabel}
    bind:value={query}
    bind:this={search}
    onkeydown={onSearchKey}
  />
  <!-- Its first cell is the Tab stop into the grid, so the panel itself takes none -->
  <!-- svelte-ignore a11y_no_static_element_interactions, a11y_interactive_supports_focus -->
  <div
    class="ep-body"
    id="{uid}-panel"
    role="tabpanel"
    aria-labelledby="{uid}-tab-{current}"
    bind:this={body}
    onkeydown={onGridKey}
  >
    {#each sections as s, si (s.key)}
      {#if s.label}<div class="ep-head">{s.label}</div>{/if}
      <div class="ep-grid" class:stickers={s.cells[0]?.kind === "sticker"}>
        {#each s.cells as c, i (cellKey(c))}
          {@const tabindex = si === 0 && i === 0 ? 0 : -1}
          {#if c.kind === "emoji"}
            <button
              class="ep-cell"
              type="button"
              {tabindex}
              title={c.name ? `:${c.name}:` : undefined}
              aria-label={c.name ? `:${c.name}:` : c.emoji}
              onpointerdown={keep}
              onclick={(ev) => take(c, ev.shiftKey)}>{c.emoji}</button
            >
          {:else if c.kind === "emote"}
            <button
              class="ep-cell"
              type="button"
              {tabindex}
              title=":{c.e.name}:"
              aria-label=":{c.e.name}:"
              onpointerdown={keep}
              oncontextmenu={(ev) => fav(ev, c.e)}
              onclick={(ev) => take(c, ev.shiftKey)}><Emote name={c.e.name} hash={c.e.hash} /></button
            >
          {:else}
            <!-- A sticker is a message: slow mode holds it as it holds the draft -->
            <button
              class="ep-cell ep-sticker"
              type="button"
              {tabindex}
              disabled={!!held}
              title={held ? held.title : `:${c.e.name}:`}
              aria-label="Send the sticker :{c.e.name}:"
              onpointerdown={keep}
              oncontextmenu={(ev) => fav(ev, c.e)}
              onclick={(ev) => take(c, ev.shiftKey)}><Emote name={c.e.name} hash={c.e.hash} size="jumbo" /></button
            >
          {/if}
        {/each}
      </div>
    {:else}
      <p class="ep-none">Nothing is called “{query.trim()}”.</p>
    {/each}
  </div>
  {#if favSaid}
    <p class="ep-hint" role="status">{favSaid}</p>
  {:else if held && current === "stickers"}
    <!-- Said where the stickers are: a greyed one has no tooltip on a phone -->
    <p class="ep-hint" role="status">{held.title}{held.label ? `; the next in ${held.label}` : ""}.</p>
  {:else if wait?.bytes && (current === "emotes" || current === "stickers")}
    <p class="ep-hint">
      They wait for Wi-Fi.
      <button class="btn btn-ghost ep-dl" type="button" onpointerdown={keep} onclick={() => downloadEmotes(server)}>Download {formatSize(wait.bytes)} now</button>
    </p>
  {:else if current === "emotes" || current === "stickers"}
    <p class="ep-hint">{touchHint ? "Hold one to make it a favourite." : "Right-click one to make it a favourite."}</p>
  {/if}
</div>

<style>
  .ep {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }
  .ep-tabs {
    display: flex;
    gap: 2px;
    padding: 6px 6px 4px;
    border-bottom: 1px solid var(--border);
  }
  .ep-tab {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    min-width: 0;
    min-height: 32px;
    padding: 2px 0;
    font-size: var(--fs-lg);
    color: var(--text-secondary);
    background: transparent;
    border: none;
    border-radius: var(--r-sm);
    cursor: pointer;
    opacity: 0.75;
    line-height: 1;
    overflow: hidden;
  }
  /* Inside: the row's own edge would clip a ring drawn outside */
  .ep-tab:focus-visible {
    outline-offset: -2px;
  }
  .ep-tab:hover,
  .ep-tab:focus-visible {
    opacity: 0.85;
    background: var(--bg-hover);
  }
  .ep-tab.active {
    opacity: 1;
    background: var(--bg-tertiary);
  }
  .ep-tab :global(img.emote),
  .ep-tab :global(span.emote) {
    height: 20px;
    max-width: 100%;
    vertical-align: middle;
  }
  .ep-search {
    margin: 6px 6px 0;
    padding: 4px 8px;
    font-size: var(--fs-sm);
  }
  .ep-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 6px;
  }
  .ep-head {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    padding: 6px 2px 2px;
  }
  .ep-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(36px, 1fr));
    gap: 2px;
  }
  .ep-grid.stickers {
    grid-template-columns: repeat(auto-fill, minmax(72px, 1fr));
  }
  .ep-cell {
    display: flex;
    align-items: center;
    justify-content: center;
    min-width: 0;
    height: 36px;
    padding: 0;
    font-size: var(--fs-2xl);
    background: transparent;
    border: none;
    border-radius: var(--r-sm);
    cursor: pointer;
    line-height: 1;
    overflow: hidden;
  }
  .ep-cell:focus-visible {
    outline-offset: -2px;
  }
  .ep-cell.ep-sticker {
    height: 72px;
  }
  .ep-cell:hover,
  .ep-cell:focus-visible {
    background: var(--bg-hover);
  }
  .ep-cell:disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }
  /* A wide emote, or a sticker, stays in its cell */
  .ep-cell :global(img.emote),
  .ep-cell :global(span.emote) {
    height: 28px;
    max-width: 100%;
    margin: 0;
    vertical-align: middle;
  }
  .ep-cell.ep-sticker :global(img.emote),
  .ep-cell.ep-sticker :global(span.emote) {
    width: auto;
    height: 64px;
    max-height: 64px;
  }
  .ep-dl {
    padding: 4px 8px;
  }
  .ep-none,
  .ep-hint {
    margin: 0;
    padding: 4px 8px 6px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  @media (pointer: coarse) {
    /* A finger's size: the row scrolls sideways rather than shrink a tab */
    .ep-tabs {
      overflow-x: auto;
      scrollbar-width: none;
    }
    .ep-tabs::-webkit-scrollbar {
      display: none;
    }
    .ep-tab {
      flex: 1 0 var(--hit);
      min-height: var(--hit);
    }
    .ep-search {
      min-height: var(--hit);
    }
    .ep-grid {
      grid-template-columns: repeat(auto-fill, minmax(44px, 1fr));
    }
    .ep-cell {
      height: 44px;
    }
  }
</style>
