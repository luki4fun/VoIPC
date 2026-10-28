<script lang="ts">
  import { parse, plainText, shownHref, type Block, type Inline } from "../../markdown.js";
  import { shortName } from "../../username.js";
  import CodeBlock from "./CodeBlock.svelte";
  import Spoiler from "./Spoiler.svelte";

  // A message's text, drawn from lib/markdown.ts's tree: elements of our own
  // and text nodes, never the sender's HTML.
  interface Props {
    text: string;
    /** Who an `@` may name here (see `ParseOptions.names`). */
    names?: readonly string[];
    /** Our own names: a mention of one of them stands out. */
    me?: readonly string[];
    /** A link was pressed: the owner shows its copy popup (never a browser). */
    onlink: (url: string) => void;
  }
  let { text, names = [], me = [], onlink }: Props = $props();

  const tree = $derived(parse(text, { names }));
  const isMe = (name: string) => me.some((m) => m.toLowerCase() === name.toLowerCase());

  // What a message that could not be drawn shows instead: its words
  function words(): string {
    try {
      return plainText(text);
    } catch {
      return text;
    }
  }
</script>

{#snippet inline(nodes: Inline[])}{#each nodes as n}{#if n.t === "text"}{n.v}{:else if n.t === "strong"}<strong>{@render inline(n.c)}</strong>{:else if n.t === "em"}<em>{@render inline(n.c)}</em>{:else if n.t === "del"}<del>{@render inline(n.c)}</del>{:else if n.t === "code"}<code class="md-code">{n.v}</code>{:else if n.t === "spoiler"}<Spoiler>{@render inline(n.c)}</Spoiler>{:else if n.t === "link"}<button class="msg-link" type="button" onclick={() => onlink(n.href)} title={shownHref(n.href)}>{@render inline(n.c)}</button>{:else if n.t === "br"}<br />{:else if n.t === "mention"}<span class="mention" class:me={isMe(n.name)}>@{shortName(n.name)}</span>{/if}{/each}{/snippet}

{#snippet blocks(list: Block[])}
  {#each list as b}
    {#if b.t === "p"}
      <p class="md-p">{@render inline(b.c)}</p>
    {:else if b.t === "h"}
      <p class="md-h md-h{b.level}">{@render inline(b.c)}</p>
    {:else if b.t === "pre"}
      <CodeBlock lang={b.lang} code={b.v} />
    {:else if b.t === "quote"}
      <blockquote class="md-quote">{@render blocks(b.c)}</blockquote>
    {:else if b.t === "list" && b.ordered}
      <ol class="md-list" start={b.start}>
        {#each b.items as item}<li>{@render blocks(item)}</li>{/each}
      </ol>
    {:else if b.t === "list"}
      <ul class="md-list">
        {#each b.items as item}<li>{@render blocks(item)}</li>{/each}
      </ul>
    {:else if b.t === "hr"}
      <hr class="md-hr" />
    {/if}
  {/each}
{/snippet}

<!-- A message that fails to draw is its plain text, and the rest of the
     conversation goes on drawing: one row must never take the list down -->
<svelte:boundary>
  {@render blocks(tree)}
  {#snippet failed()}<p class="md-p">{words()}</p>{/snippet}
</svelte:boundary>

<style>
  .md-p,
  .md-h {
    margin: 0;
  }

  .md-p + .md-p,
  .md-h + .md-p,
  .md-p + .md-h {
    margin-top: 4px;
  }

  .md-h {
    font-weight: 700;
  }

  .md-h1 {
    font-size: 1.3em;
  }

  .md-h2 {
    font-size: 1.15em;
  }

  .md-code {
    padding: 0 4px;
    border-radius: var(--r-sm);
    background: var(--bg-tertiary);
    font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
    font-size: 0.92em;
  }

  .md-quote {
    margin: 2px 0;
    padding-left: 8px;
    border-left: 3px solid var(--border);
    color: var(--text-secondary);
  }

  .md-list {
    margin: 2px 0;
    padding-left: 1.4em;
  }

  .md-hr {
    border: none;
    border-top: 1px solid var(--border);
    margin: 6px 0;
  }

  .mention {
    padding: 0 2px;
    border-radius: var(--r-sm);
    background: var(--bg-hover);
    font-weight: 600;
  }

  /* Ink, not mint: being named is not "live" */
  .mention.me {
    background: color-mix(in srgb, var(--text-primary) 16%, transparent);
  }

  .msg-link {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    color: var(--text-primary);
    text-decoration: underline;
    cursor: pointer;
    word-break: break-all;
    text-align: inherit;
  }

  /* Not the accent: in VoIPC night that is the mint that means live */
  .msg-link:hover {
    text-decoration-thickness: 2px;
  }
</style>
