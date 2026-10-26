<script lang="ts">
  import { tick, untrack } from "svelte";
  import type { ChatMessage } from "../../types.js";
  import { pushLayer } from "../../stores/back-stack.js";
  import { shortName } from "../../username.js";
  import Icon from "../Icons.svelte";
  import Composer from "./Composer.svelte";
  import MessageList from "./MessageList.svelte";

  // One thread: its first message and the answers that belong to it, with a
  // message box that writes into it. Inside the chat panel, so every layout
  // has it: beside the conversation where there is room, over it where not.
  interface Props {
    root: ChatMessage;
    answers: ChatMessage[];
    /** The whole conversation, where what an answer answers is looked up. */
    all: ChatMessage[];
    /** Absent where nothing can be written here (a preview, an announcement channel). */
    onsend?: (content: string, refs: { replyTo: string; thread: string }) => void;
    onlink: (url: string) => void;
    onclose: () => void;
    /** A quoted message that is not in this thread: the conversation shows it. */
    onjumpelsewhere: (m: ChatMessage) => void;
    /** Slow mode still counting (see Composer). */
    held?: { label: string; title: string } | null;
    /** Mentions: who an `@` may name, our own names, and who the box offers. */
    names?: readonly string[];
    me?: readonly string[];
    mentionables?: readonly string[];
    /** Opened to answer in it: the box gets the cursor. Not when opened to read,
     *  where on a phone it would bring the keyboard up over the thread. */
    focusComposer?: boolean;
  }
  let {
    root,
    answers,
    all,
    onsend,
    onlink,
    onclose,
    onjumpelsewhere,
    held = null,
    names = [],
    me = [],
    mentionables = [],
    focusComposer = false,
  }: Props = $props();

  const rows = $derived([root, ...answers]);
  let replyingTo = $state.raw<ChatMessage | null>(null);
  let composer = $state<{ focus: () => void } | null>(null);
  let scroller = $state<HTMLDivElement | null>(null);

  // Android's Back closes the thread (after an answer being written, which is
  // the composer's own layer on top of this one)
  $effect(() => pushLayer(() => onclose()));

  // A thread opened to answer starts with the box ready; a new answer is
  // followed when the reader was already at the end
  $effect(() => {
    void root;
    if (focusComposer) tick().then(() => composer?.focus());
  });
  let shown = 0;
  $effect.pre(() => {
    const count = rows.length;
    const el = untrack(() => scroller);
    const atEnd = !el || el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    if (count !== shown && atEnd) tick().then(() => scroller && (scroller.scrollTop = scroller.scrollHeight));
    shown = count;
  });

  function send(content: string) {
    const target = replyingTo ?? root;
    replyingTo = null;
    onsend?.(content, { replyTo: target.id!, thread: root.id! });
  }

  function reply(m: ChatMessage) {
    replyingTo = m === root ? null : m;
    composer?.focus();
  }
</script>

<!-- Escape anywhere in the thread closes it -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<section
  class="thread-pane"
  aria-label="Thread on {shortName(root.username)}'s message"
  onkeydown={(e) => { if (e.key === "Escape" && !e.defaultPrevented) { e.preventDefault(); onclose(); } }}
>
  <header class="thread-header">
    <Icon name="thread" size={16} />
    <span class="thread-title">Thread</span>
    <span class="thread-count">{answers.length} {answers.length === 1 ? "reply" : "replies"}</span>
    <button class="icon-btn thread-close" type="button" aria-label="Close thread" title="Close thread (Esc)" onclick={onclose}>
      <Icon name="close" size={16} />
    </button>
  </header>
  <div class="thread-messages" bind:this={scroller}>
    <MessageList messages={rows} {all} {onlink} under={root} onreply={onsend ? reply : undefined} {onjumpelsewhere} {names} {me} />
  </div>
  {#if onsend}
    <Composer
      bind:this={composer}
      placeholder="Reply in thread…"
      conversation={root.id ?? ""}
      {held}
      {mentionables}
      onsend={send}
      replying={replyingTo?.username ?? null}
      oncancelreply={() => (replyingTo = null)}
    />
  {/if}
</section>

<style>
  .thread-pane {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    background: var(--bg-primary);
  }

  .thread-header {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 44px;
    padding: 0 8px 0 16px;
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
  }

  .thread-title {
    font-weight: 600;
    color: var(--text-primary);
  }

  .thread-count {
    flex: 1;
    font-size: var(--fs-sm);
  }

  .thread-close {
    width: var(--hit);
    height: var(--hit);
    background: transparent;
  }

  .thread-messages {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 8px 16px;
  }
</style>
