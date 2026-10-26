<script lang="ts" generics="C">
  import { tick } from "svelte";
  import type { ChatMessage } from "../../types.js";
  import { pushLayer } from "../../stores/back-stack.js";
  import { excerpt, searchMessages, terms, type Hit } from "../../search-rules.js";
  import { plainText } from "../../markdown.js";
  import { fullTime } from "../../chat-time.js";
  import { shortName } from "../../username.js";
  import Icon from "../Icons.svelte";

  // Search what this device holds: the conversation on screen, or every one
  // in memory. Nothing is asked of the relay (search-rules.ts).
  interface Props {
    /** The conversation on screen, threads included. */
    here: ChatMessage[];
    /** Every conversation, each with what a result row calls it. */
    everywhere: { conv: C; messages: ChatMessage[] }[];
    /** What a conversation is called in a result row. */
    labelOf: (conv: C) => string;
    /** A result was picked; `conv` is null for one from the conversation on screen. */
    onpick: (hit: Hit<C | null>) => void;
    onclose: () => void;
  }
  let { here, everywhere, labelOf, onpick, onclose }: Props = $props();

  let query = $state("");
  let scope = $state<"here" | "everywhere">("here");
  let input = $state<HTMLInputElement | null>(null);

  $effect(() => pushLayer(() => onclose()));
  $effect(() => {
    tick().then(() => input?.focus());
  });

  const results = $derived<Hit<C | null>[]>(
    scope === "here"
      ? searchMessages([{ conv: null, messages: here }], query)
      : searchMessages(everywhere, query),
  );
  const want = $derived(terms(query));

  /** "Oct 27, 12:09": enough to tell results apart; the full date is its title */
  function shortTime(at: number): string {
    return new Date(at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      onclose();
    } else if (e.key === "Enter" && e.target === input && results[0]) {
      e.preventDefault();
      onpick(results[0]);
    }
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<section class="search-pane" aria-label="Search messages" {onkeydown}>
  <header class="search-header">
    <Icon name="search" size={16} />
    <input
      class="search-input"
      type="search"
      placeholder="Search messages"
      aria-label="Search messages"
      bind:value={query}
      bind:this={input}
    />
    <button class="icon-btn search-close" type="button" aria-label="Close search" title="Close search (Esc)" onclick={onclose}>
      <Icon name="close" size={16} />
    </button>
  </header>
  <div class="search-scope" role="group" aria-label="Where to search">
    <button type="button" class="scope" aria-pressed={scope === "here"} onclick={() => (scope = "here")}>This conversation</button>
    <button type="button" class="scope" aria-pressed={scope === "everywhere"} onclick={() => (scope = "everywhere")}>Everywhere</button>
  </div>
  <div class="search-results" aria-live="polite">
    {#if want.length === 0}
      <p class="search-note">Searches the messages on this device. Nothing is sent anywhere.</p>
    {:else if results.length === 0}
      <p class="search-note">No messages found.</p>
    {:else}
      {#each results as hit (hit.msg)}
        <button class="result" type="button" onclick={() => onpick(hit)}>
          <span class="result-meta">
            {#if hit.conv !== null}<span class="result-conv">{labelOf(hit.conv)}</span>{/if}
            <span class="result-name">{shortName(hit.msg.username)}</span>
            <time class="result-time" title={fullTime(hit.msg.timestamp)}>{shortTime(hit.msg.timestamp)}</time>
          </span>
          <span class="result-text"
            >{#each excerpt(plainText(hit.msg.content), want) as piece}{#if piece.hit}<mark>{piece.v}</mark>{:else}{piece.v}{/if}{/each}</span
          >
        </button>
      {/each}
    {/if}
  </div>
</section>

<style>
  .search-pane {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    background: var(--bg-primary);
  }

  .search-header {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 44px;
    padding: 0 8px 0 16px;
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
  }

  .search-input {
    flex: 1;
    min-width: 0;
    padding: 6px 8px;
    font: inherit;
    font-size: var(--fs-body);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
  }

  .search-input:focus {
    outline: none;
    border-color: var(--focus-ring);
  }

  .search-close {
    width: var(--hit);
    height: var(--hit);
    background: transparent;
  }

  .search-scope {
    display: flex;
    gap: 4px;
    padding: 8px 16px 4px;
  }

  /* On is ink, never the live mint */
  .scope {
    padding: 4px 10px;
    min-height: 28px;
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }

  .scope[aria-pressed="true"] {
    background: var(--bg-hover);
    color: var(--text-primary);
    box-shadow: inset 0 0 0 1px var(--text-muted);
  }

  .search-results {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 4px 8px 8px;
  }

  .search-note {
    margin: 16px 8px;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }

  .result {
    display: flex;
    flex-direction: column;
    gap: 2px;
    width: 100%;
    padding: 8px;
    border: none;
    border-radius: var(--r-sm);
    background: none;
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
  }

  .result:hover,
  .result:focus-visible {
    background: var(--bg-hover);
  }

  .result-meta {
    display: flex;
    gap: 8px;
    align-items: baseline;
    min-width: 0;
    white-space: nowrap;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .result-conv,
  .result-name {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    font-weight: 600;
    color: var(--text-primary);
  }

  .result-time {
    flex-shrink: 0;
  }

  .result-text {
    font-size: var(--chat-font-size, 13px);
    line-height: 1.4;
    word-break: break-word;
  }

  mark {
    background: color-mix(in srgb, var(--text-primary) 18%, transparent);
    color: inherit;
    border-radius: 2px;
  }
</style>
