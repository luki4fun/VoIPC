<script lang="ts">
  import { onDestroy, tick, untrack } from "svelte";
  import type { ArchiveRow } from "../../types.js";
  import {
    ARCHIVE_LABEL,
    ARCHIVE_SEARCH_HINT,
    HIDDEN_LINE,
    LIST_CAP,
    archiveChips,
    isTakenBack,
    lookedAt,
    replyLine,
    threadOpener,
  } from "../../archive-rules.js";
  import { fullTime } from "../../chat-time.js";
  import { isEmoteReaction, tokenize } from "../../emote-rules.js";
  import { adminOp } from "../../stores/admin-ops.js";
  import { pushLayer } from "../../stores/back-stack.js";
  import { confirmAction } from "../../stores/confirm.js";
  import { emoteSets } from "../../stores/emotes.js";
  import {
    closeImported,
    importedBack,
    importedFurther,
    importedMineAsk,
    importedNewest,
    importedOlder,
    importedPins,
    importedSearch,
    importedSearchMore,
    importedShowAt,
    importedThread,
    importedView,
    openImported,
  } from "../../stores/imported.js";
  import { can } from "../../stores/powers.js";
  import Icon from "../Icons.svelte";
  import Emote from "./Emote.svelte";
  import Markdown from "./Markdown.svelte";

  // What came from Discord in this channel, beside the live chat and never in it: read
  // only, under its label. No composer, no reply, react, edit, forward, report or
  // moderator hide: nobody can answer in an old thread, and a row is nobody's signed word.
  interface Props {
    server: string;
    channelId: number;
    onlink: (url: string) => void;
    onclose: () => void;
  }
  let { server, channelId, onlink, onclose }: Props = $props();

  const view = $derived($importedView);
  const search = $derived(view?.search ?? null);
  const shown = $derived(search ? search.rows : (view?.rows ?? []));
  const admin = $derived($can("*"));
  /** The thread's opening row, once the list has reached it. Filed in the flow, not in the thread. */
  const opening = $derived(view && !search && view.thread && view.next === "" && view.asking === null ? view.threadRow : null);

  let query = $state("");
  let scroller = $state<HTMLDivElement | null>(null);
  let closeBtn = $state<HTMLButtonElement | null>(null);
  /** The row whose menu is open. */
  let menuOn = $state<string | null>(null);

  // Android's Back closes it, and the keyboard goes back where it was when it does
  $effect(() => pushLayer(() => onclose()));
  const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  // One list, for as long as the pane is up: ChatPanel shuts it when the conversation changes
  $effect(() =>
    untrack(() => {
      const s = server;
      openImported(s, channelId);
      tick().then(() => closeBtn?.focus());
      return () => closeImported(s);
    }),
  );
  onDestroy(() => {
    const active = document.activeElement;
    if (opener?.isConnected && (!active || active === document.body || !active.isConnected)) opener.focus();
  });

  /** Near the top of what is drawn: the list runs bottom up (`column-reverse`), so
   *  scrollTop is 0 at the newest and negative above it, and rows put on top need no
   *  scroll arithmetic. */
  function nearTop(el: HTMLElement): boolean {
    return el.scrollHeight - el.clientHeight + el.scrollTop < 300;
  }
  function onScroll() {
    if (scroller && !search && shown.length < LIST_CAP && nearTop(scroller)) importedOlder(server);
  }
  // A first page shorter than the pane has no scrolling to ask for the next
  $effect(() => {
    void shown.length;
    tick().then(onScroll);
  });
  // "Show here": the row asked for, in view once it has come
  $effect(() => {
    const id = view?.focus;
    if (!id || view?.asking !== null) return;
    tick().then(() => document.getElementById(`archive-${id}`)?.scrollIntoView({ block: "center" }));
  });

  function onkeydown(e: KeyboardEvent) {
    if (e.key !== "Escape" || e.defaultPrevented) return;
    e.preventDefault();
    if (menuOn) menuOn = null;
    else onclose();
  }
  /** A row pressed and gone took the focus with it: Escape then starts from the page. */
  function onWindowKeydown(e: KeyboardEvent) {
    if (document.activeElement === document.body) onkeydown(e);
  }

  function submit(e: SubmitEvent) {
    e.preventDefault();
    importedSearch(server, query);
  }
  function clearSearch() {
    query = "";
    importedSearch(server, "");
  }

  const message = (row: ArchiveRow) => ({ Message: { channel_id: channelId, id: row.id } });

  async function deleteMine(row: ArchiveRow) {
    const ok = await confirmAction({
      title: "Delete your post?",
      body: "It goes from this server for good, and a later import does not bring it back. Discord still has its own copy.",
      confirm: "Delete it",
      danger: true,
    });
    if (ok) importedMineAsk(server, "Delete", message(row));
  }

  async function deleteThis(row: ArchiveRow) {
    menuOn = null;
    const ok = await confirmAction({
      title: "Delete this imported post?",
      body: "It goes from this server for good, for everyone, and a later import does not bring it back. The moderation log says that you did, and not whose it was.",
      confirm: "Delete it",
      danger: true,
    });
    if (ok) void adminOp({ ArchiveDelete: { target: message(row) } }, null, server);
  }

  async function deleteAuthor(row: ArchiveRow) {
    menuOn = null;
    const ok = await confirmAction({
      title: `Delete everything imported from ${row.author}?`,
      body: "All of it goes from this server for good, in every channel, and a later import does not bring it back. Their account stays. The moderation log says that you did, and not whose it was.",
      confirm: "Delete it all",
      danger: true,
    });
    if (ok) void adminOp({ ArchiveDelete: { target: { Author: { id: row.author_id } } } }, null, server);
  }
</script>

{#snippet line(row: ArchiveRow, loaded: readonly ArchiveRow[], jump: boolean)}
  <div class="row" class:hidden-row={row.hidden} class:focus={view?.focus === row.id} id="archive-{row.id}" data-id={row.id}>
    <div class="row-head">
      {#if row.author}<strong class="who">{row.author}</strong>{/if}
      <time class="at" datetime={new Date(row.at_ms).toISOString()}>{fullTime(row.at_ms)}</time>
      {#if row.pinned}<span class="pin-mark" title="Pinned on Discord" aria-label="Pinned on Discord"><Icon name="pin" size={12} /></span>{/if}
      {#if admin && !isTakenBack(row)}
        <button class="icon-btn row-menu-btn" type="button" aria-label="More for this post" aria-expanded={menuOn === row.id} onclick={() => (menuOn = menuOn === row.id ? null : row.id)}>
          <Icon name="more-vertical" size={14} />
        </button>
      {/if}
    </div>
    {#if menuOn === row.id}
      <div class="row-menu" role="group" aria-label="Delete for everyone">
        <button class="btn btn-danger-outline delete-this" type="button" onclick={() => deleteThis(row)}>Delete this</button>
        {#if row.author_id}
          <button class="btn btn-danger-outline delete-author" type="button" onclick={() => deleteAuthor(row)}>Delete everything by this author</button>
        {/if}
      </div>
    {/if}
    {#if row.reply_to}
      <div class="reply-line">
        <span>{replyLine(row, loaded)}</span>
        <button class="link-btn show-reply" type="button" onclick={() => importedShowAt(server, { id: row.reply_to, thread: row.thread })}>Show here</button>
      </div>
    {/if}
    {#if row.body}
      <div class="body"><Markdown text={tokenize(row.body, $emoteSets.emotes)} {onlink} /></div>
    {/if}
    {#if row.reactions.length}
      <div class="chips" role="group" aria-label="Reactions on Discord">
        {#each archiveChips(row) as c (c.emoji)}
          <span class="chip"><span class="chip-emoji">{#if isEmoteReaction(c.emoji)}<Emote name={c.emoji.slice(1, -1)} />{:else}{c.emoji}{/if}</span><span class="num">{c.count}</span></span>
        {/each}
      </div>
    {/if}
    {#if row.thread_name}
      <button class="thread-open" type="button" onclick={() => importedThread(server, row)}>
        <Icon name="thread" size={14} /><span>{threadOpener(row)}</span>
      </button>
    {/if}
    {#if row.hidden}
      <p class="hidden-line">{HIDDEN_LINE}</p>
    {/if}
    {#if row.mine || jump}
      <div class="row-tools">
        {#if jump}
          <button class="link-btn show-here" type="button" onclick={() => importedShowAt(server, row)}>Show here</button>
        {/if}
        {#if row.hidden}
          <button class="link-btn show-mine" type="button" onclick={() => importedMineAsk(server, "Show", message(row))}>Show again</button>
        {:else if row.mine}
          <button class="link-btn hide-mine" type="button" onclick={() => importedMineAsk(server, "Hide", message(row))}>Hide</button>
        {/if}
        {#if row.mine}
          <button class="link-btn delete-mine" type="button" onclick={() => deleteMine(row)}>Delete</button>
        {/if}
      </div>
    {/if}
  </div>
{/snippet}

<svelte:window onkeydown={onWindowKeydown} />

<!-- Escape anywhere in it closes it -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<section class="archive-pane" aria-label="Discord archive" {onkeydown}>
  <header class="archive-header">
    {#if view?.back}
      <button class="icon-btn archive-back" type="button" aria-label="Back" title="Back" onclick={() => importedBack(server)}><Icon name="arrow-left" size={16} /></button>
    {:else}
      <Icon name="archive" size={16} />
    {/if}
    <span class="archive-title">{view?.threadRow?.thread_name || (view?.thread ? "Thread" : "Discord archive")}</span>
    <button class="icon-btn archive-pins" type="button" aria-pressed={view?.pinned ?? false} aria-label="Only what was pinned" title="Only what was pinned" onclick={() => importedPins(server)}><Icon name="pin" size={16} /></button>
    <button class="icon-btn archive-close" type="button" aria-label="Close the Discord archive" title="Close (Esc)" bind:this={closeBtn} onclick={onclose}><Icon name="close" size={16} /></button>
  </header>
  <p class="archive-label" role="note">{ARCHIVE_LABEL}</p>
  <form class="archive-search" role="search" onsubmit={submit}>
    <input class="archive-input" type="text" enterkeyhint="search" placeholder={ARCHIVE_SEARCH_HINT} aria-label={ARCHIVE_SEARCH_HINT} bind:value={query} />
    {#if search}
      <button class="icon-btn archive-search-clear" type="button" aria-label="Back to the list" title="Back to the list" onclick={clearSearch}><Icon name="close" size={14} /></button>
    {/if}
  </form>
  <!-- The words go from the box as soon as there are others in it, and the pane may be too narrow for them -->
  <p class="archive-sees">The server sees what you search.</p>
  {#if search}
    <p class="archive-status" role="status">
      {lookedAt(search.scanned)}{search.rows.length ? ` · ${search.rows.length.toLocaleString("en-US")} found` : ""}{search.asking !== null ? "…" : ""}
    </p>
  {/if}
  {#if view?.error}
    <p class="archive-error" role="alert">{view.error}</p>
  {/if}
  {#if search}
    <div class="archive-results">
      {#if search.rows.length === 0 && search.asking === null}
        <p class="archive-note">Nothing found.</p>
      {/if}
      {#each search.rows as row (row.id)}
        {@render line(row, search.rows, true)}
      {/each}
      {#if search.next !== "" && search.asking === null}
        <button class="btn btn-secondary archive-more" type="button" onclick={() => importedSearchMore(server)}>Look further</button>
      {/if}
    </div>
  {:else}
    <div class="archive-rows" bind:this={scroller} onscroll={onScroll}>
      {#each shown as row (row.id)}
        {@render line(row, shown, !!view?.pinned)}
      {/each}
      {#if opening}
        {@render line(opening, shown, false)}
      {/if}
      {#if view && view.asking === null && shown.length === 0 && !opening && !view.error}
        <p class="archive-note">{view.pinned ? "Nothing was pinned here." : "Nothing here."}</p>
      {/if}
      {#if view && view.next !== "" && shown.length >= LIST_CAP}
        <button class="btn btn-secondary archive-further" type="button" onclick={() => importedFurther(server)}>Go further back</button>
      {/if}
    </div>
    {#if view?.from}
      <button class="btn btn-secondary archive-newest" type="button" onclick={() => importedNewest(server)}>Back to the newest</button>
    {/if}
  {/if}
</section>

<style>
  .archive-pane {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    background: var(--bg-primary);
  }

  .archive-header {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 44px;
    padding: 0 8px 0 16px;
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
  }

  .archive-title {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-weight: 600;
    color: var(--text-primary);
  }

  .archive-header .icon-btn {
    width: var(--hit);
    height: var(--hit);
    background: transparent;
    flex-shrink: 0;
  }

  /* On is ink, never the live mint */
  .archive-pins[aria-pressed="true"] {
    background: var(--bg-hover);
    color: var(--text-primary);
    box-shadow: inset 0 0 0 1px var(--text-muted);
  }

  /* Never scrolls away: every row is under it */
  .archive-label {
    margin: 0;
    padding: 6px 16px;
    font-size: var(--fs-sm);
    font-weight: 600;
    color: var(--text-primary);
    background: var(--bg-tertiary);
    border-bottom: 1px solid var(--border);
  }

  .archive-search {
    position: relative;
    display: flex;
    align-items: center;
    padding: 8px 16px 4px;
  }

  .archive-input {
    flex: 1;
    min-width: 0;
    padding: 6px 28px 6px 8px;
    font: inherit;
    font-size: var(--fs-body);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
  }

  .archive-input:focus {
    outline: none;
    border-color: var(--focus-ring);
  }

  .archive-search-clear {
    position: absolute;
    right: 18px;
    background: transparent;
  }

  .archive-sees {
    margin: 0 16px 4px;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
  }

  .archive-status,
  .archive-note {
    margin: 4px 16px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .archive-error {
    margin: 4px 16px;
    font-size: var(--fs-sm);
    color: var(--danger);
  }

  .archive-rows,
  .archive-results {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 4px 16px 8px;
  }

  /* Newest at the bottom: rows put on top need no scroll arithmetic */
  .archive-rows {
    display: flex;
    flex-direction: column-reverse;
  }

  .archive-further,
  .archive-more {
    align-self: center;
    margin: 8px auto;
    display: block;
  }

  .archive-newest {
    margin: 4px 16px 8px;
  }

  .row {
    flex-shrink: 0;
    padding: 6px 0;
    content-visibility: auto;
    contain-intrinsic-size: auto 48px;
    /* Its pop-ups and focus ring stay inside the row's own box otherwise */
    overflow-clip-margin: 16px;
  }

  .row.focus {
    background: var(--bg-hover);
    box-shadow: 0 0 0 4px var(--bg-hover);
    border-radius: var(--r-sm);
  }

  .hidden-row {
    opacity: 0.65;
  }

  /* A date in full is long: it goes under the name rather than shorten it */
  .row-head {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    column-gap: 8px;
    min-width: 0;
  }

  .who {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: var(--fs-body);
    color: var(--text-primary);
  }

  .at {
    flex-shrink: 0;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
  }

  .pin-mark {
    display: inline-flex;
    color: var(--text-secondary);
    align-self: center;
  }

  .row-menu-btn {
    margin-left: auto;
    width: 24px;
    height: 24px;
    background: transparent;
    align-self: center;
    flex-shrink: 0;
  }

  .row-menu {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin: 4px 0;
  }

  .row-menu .btn {
    font-size: var(--fs-sm);
    min-height: 28px;
    padding: 2px 8px;
  }

  .reply-line {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .body {
    font-size: var(--chat-font-size, 13px);
    color: var(--text-primary);
    line-height: 1.4;
    word-break: break-word;
  }

  /* Read only: what Discord counted, not something to press */
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 4px;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0 6px;
    min-height: 22px;
    border: 1px solid var(--border);
    border-radius: var(--r-pill);
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .thread-open {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 28px;
    margin-top: 4px;
    padding: 2px 10px;
    max-width: 100%;
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: var(--fs-sm);
    cursor: pointer;
  }

  .thread-open span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .thread-open:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .hidden-line {
    margin: 4px 0 0;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .row-tools {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 2px;
  }

  .link-btn {
    padding: 0;
    min-height: 22px;
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
    text-decoration: underline;
    cursor: pointer;
  }

  /* A finger's size on a touch screen: Hide and Delete sat 22px tall side by side (W3-54) */
  @media (pointer: coarse) {
    .link-btn {
      min-height: var(--hit);
      padding: 0 var(--sp-2, 8px);
    }
  }

  .link-btn:hover {
    color: var(--text-primary);
  }
</style>
