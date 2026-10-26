<script lang="ts">
  import { tick } from "svelte";
  import { pushLayer } from "../../stores/back-stack.js";
  import { shortName } from "../../username.js";
  import Icon from "../Icons.svelte";

  interface Props {
    placeholder: string;
    /**
     * Which conversation the draft belongs to. This composer is not keyed by
     * its owner, so nothing remounts it when the conversation changes — or
     * disappears under the user, which is the case this is here for: delete,
     * leave or be kicked from the channel being typed in and the pane falls
     * back to the voice room next door, with everybody in it. The owner reads
     * the target at send time, so the next Enter would post half a private
     * thought into a room it was never meant for — or, after a click in the
     * rail, into another server's.
     */
    conversation: string;
    /** Sending is held (slow mode): the draft stays, the button says why. */
    held?: { label: string; title: string } | null;
    onsend: (content: string) => void;
    /** Who the message being written answers; the bar above says so. */
    replying?: string | null;
    oncancelreply?: () => void;
    /** Names `@` offers to complete (full names, with their tags). */
    mentionables?: readonly string[];
  }
  let {
    placeholder,
    conversation,
    held = null,
    onsend,
    replying = null,
    oncancelreply,
    mentionables = [],
  }: Props = $props();

  /** Put the cursor in the message box (after Reply was pressed, say). */
  export function focus() {
    inputEl?.focus();
  }

  // Android's Back cancels the answer before it closes anything else
  $effect(() => {
    if (!replying || !oncancelreply) return;
    const cancel = oncancelreply;
    return pushLayer(() => cancel());
  });

  let text = $state("");
  let inputEl = $state<HTMLTextAreaElement | null>(null);

  $effect(() => {
    void conversation;
    text = "";
  });

  // Grows with what is typed, up to the cap in the stylesheet, then scrolls
  $effect(() => {
    void text;
    const el = inputEl;
    if (!el) return;
    el.style.height = "auto";
    // border-box: the height includes the border, which scrollHeight leaves out
    el.style.height = `${el.scrollHeight + el.offsetHeight - el.clientHeight}px`;
  });

  function send() {
    const content = text.trim();
    if (!content) return;
    // Kept in the input rather than sent to be refused
    if (held) return;
    text = "";
    onsend(content);
  }

  // ── @ completion ──────────────────────────────────────────────────────────

  let caret = $state(0);
  /** Where the `@` was when Escape closed its list: not offered again for it. */
  let dismissedAt = $state(-1);
  let active = $state(0);
  const listId = `mentions-${Math.random().toString(36).slice(2)}`;

  /** The `@word` being typed just before the cursor. */
  const query = $derived.by(() => {
    if (mentionables.length === 0) return null;
    const before = text.slice(0, caret);
    const m = /(?:^|\s)@([^\s@]{0,32})$/.exec(before);
    return m ? { q: m[1].toLowerCase(), start: before.length - m[1].length - 1 } : null;
  });
  const suggestions = $derived.by(() => {
    if (!query || query.start === dismissedAt) return [];
    return mentionables
      .filter((n) => shortName(n).toLowerCase().startsWith(query.q) || n.toLowerCase().startsWith(query.q))
      .slice(0, 6);
  });
  $effect(() => {
    void suggestions;
    active = 0;
  });

  /** A name as typed: without its tag, unless somebody else here has the same one. */
  function label(n: string): string {
    const short = shortName(n);
    return mentionables.filter((m) => shortName(m) === short).length > 1 ? n : short;
  }

  function pick(n: string) {
    if (!query) return;
    const insert = `@${label(n)} `;
    const at = query.start + insert.length;
    text = text.slice(0, query.start) + insert + text.slice(caret);
    caret = at;
    tick().then(() => {
      inputEl?.focus();
      inputEl?.setSelectionRange(at, at);
    });
  }

  function trackCaret() {
    caret = inputEl?.selectionStart ?? text.length;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (suggestions.length > 0) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const step = e.key === "ArrowDown" ? 1 : -1;
        active = (active + step + suggestions.length) % suggestions.length;
        return;
      }
      if ((e.key === "Enter" || e.key === "Tab") && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        pick(suggestions[active]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        dismissedAt = query?.start ?? -1;
        return;
      }
    }
    if (e.key === "Escape" && replying && oncancelreply) {
      e.preventDefault();
      e.stopPropagation();
      oncancelreply();
      return;
    }
    // Shift+Enter is a new line; Enter while an IME is composing picks a candidate
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      send();
    }
  }

  // Emoji picker state
  let showEmojiPicker = $state(false);
  let emojiCategory = $state(0);

  const EMOJI_CATEGORIES = [
    { label: "Smileys", emojis: ["😀","😁","😂","🤣","😃","😄","😅","😆","😉","😊","😎","🤩","😏","😒","😞","😔","😟","😕","😣","😖","😫","😩","🥺","😢","😭","😤","😠","😡","🤬","😈","👿","💀","☠️","😱","😨","😰","😥","😓","🤗","🤔","🤭","🤫","🤥","😶","😐","😑","😬","🙄","😯","😧","😮","😲","🥱","😴","🤤","😷","🤒","🤕","🤢","🤮","🥴","😵","🤯","🥳","🥸","😇","🤠","🤡"] },
    { label: "Gestures", emojis: ["👋","🤚","🖐️","✋","🖖","👌","🤌","🤏","✌️","🤞","🤟","🤘","🤙","👈","👉","👆","👇","☝️","👍","👎","✊","👊","🤛","🤜","👏","🙌","👐","🤲","🤝","🙏","💪","🦾","🖕"] },
    { label: "Hearts", emojis: ["❤️","🧡","💛","💚","💙","💜","🖤","🤍","🤎","💔","❤️‍🔥","❤️‍🩹","💕","💞","💓","💗","💖","💘","💝","💟","♥️","😍","🥰","😘","😻"] },
    { label: "Objects", emojis: ["🔥","⭐","🌟","✨","💫","🎉","🎊","🎈","🎁","🏆","🥇","🎯","💡","💎","🔔","🎵","🎶","🎤","🎧","🎮","🕹️","📱","💻","⌨️","🖥️","📷","📸","🔒","🔑","🗝️","🛠️","⚙️","💣","🧨"] },
    { label: "Nature", emojis: ["🌈","☀️","🌤️","⛅","🌥️","☁️","🌧️","⛈️","🌩️","❄️","🌊","🌸","🌺","🌻","🌹","🌷","🌱","🌿","☘️","🍀","🍁","🍂","🌵","🌴","🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐸","🐵"] },
    { label: "Food", emojis: ["🍕","🍔","🍟","🌭","🍿","🧂","🥓","🍳","🥞","🧇","🧀","🍖","🍗","🥩","🌮","🌯","🍜","🍝","🍣","🍱","🍩","🍪","🎂","🍰","🧁","🍫","🍬","🍭","☕","🍵","🧃","🍺","🍻","🥂","🍷","🥃"] },
  ];

  function insertEmoji(emoji: string) {
    text += emoji;
    showEmojiPicker = false;
    // Re-focus the input
    tick().then(() => inputEl?.focus());
  }

  function toggleEmojiPicker() {
    showEmojiPicker = !showEmojiPicker;
    if (showEmojiPicker) emojiCategory = 0;
  }

  function handleEmojiKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") showEmojiPicker = false;
  }
</script>

<!-- Any click elsewhere closes the picker; Escape closes it too -->
<svelte:window
  onclick={() => { if (showEmojiPicker) showEmojiPicker = false; }}
  onkeydown={(e) => { if (showEmojiPicker) handleEmojiKeydown(e); }}
/>

{#if replying}
  <div class="reply-bar">
    <Icon name="reply" size={14} />
    <span class="reply-to">Replying to <strong>{shortName(replying)}</strong></span>
    <button class="icon-btn reply-cancel" type="button" aria-label="Cancel reply" title="Cancel reply (Esc)" onclick={() => oncancelreply?.()}>
      <Icon name="close" size={14} />
    </button>
  </div>
{/if}
<form class="input-bar" class:replying={!!replying} onsubmit={(e) => { e.preventDefault(); send(); }}>
  {#if suggestions.length > 0}
    <div class="mention-pop" id={listId} role="listbox" aria-label="People to mention">
      {#each suggestions as n, i (n)}
        <!-- Pressed, not clicked: the box keeps its focus, so its cursor stays where it was -->
        <div
          class="mention-option"
          class:active={i === active}
          id="{listId}-{i}"
          role="option"
          aria-selected={i === active}
          tabindex="-1"
          onpointerdown={(e) => { e.preventDefault(); pick(n); }}
        >
          <span class="mention-name">@{shortName(n)}</span>
          {#if label(n) !== shortName(n)}<span class="mention-tag">{n.slice(shortName(n).length)}</span>{/if}
        </div>
      {/each}
    </div>
  {/if}
  <textarea
    class="chat-input"
    rows="1"
    enterkeyhint="send"
    {placeholder}
    bind:value={text}
    bind:this={inputEl}
    onkeydown={handleKeydown}
    oninput={trackCaret}
    onkeyup={trackCaret}
    onclick={trackCaret}
    aria-autocomplete="list"
    aria-controls={suggestions.length > 0 ? listId : undefined}
    aria-activedescendant={suggestions.length > 0 ? `${listId}-${active}` : undefined}
    maxlength="2000"
  ></textarea>
  <div class="emoji-wrapper">
    <button class="emoji-btn" type="button" onclick={(e) => { e.stopPropagation(); toggleEmojiPicker(); }} title="Emoji">
      <Icon name="smile" size={20} />
    </button>
    {#if showEmojiPicker}
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="emoji-picker" onkeydown={handleEmojiKeydown} onclick={(e) => e.stopPropagation()}>
        <div class="emoji-tabs">
          {#each EMOJI_CATEGORIES as cat, idx}
            <button
              class="emoji-tab"
              class:active={emojiCategory === idx}
              type="button"
              onclick={() => (emojiCategory = idx)}
              title={cat.label}
            >{cat.emojis[0]}</button>
          {/each}
        </div>
        <div class="emoji-grid">
          {#each EMOJI_CATEGORIES[emojiCategory].emojis as emoji}
            <button class="emoji-item" type="button" onclick={() => insertEmoji(emoji)}>{emoji}</button>
          {/each}
        </div>
      </div>
    {/if}
  </div>
  {#if held}
    <button class="send-btn" type="submit" disabled title={held.title}>{held.label}</button>
  {:else}
    <button class="send-btn" type="submit" disabled={!text.trim()}>Send</button>
  {/if}
</form>

<style>
  .input-bar {
    position: relative;
    display: flex;
    /* The field grows upwards; the buttons stay on its last line */
    align-items: flex-end;
    gap: 8px;
    padding: 8px 12px;
    border-top: 1px solid var(--border);
  }

  .reply-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 8px 4px 12px;
    border-top: 1px solid var(--border);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }

  .reply-to {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .reply-to strong {
    color: var(--text-primary);
  }

  .reply-cancel {
    width: var(--hit);
    height: var(--hit);
    background: transparent;
  }

  .input-bar.replying {
    border-top: none;
  }

  .mention-pop {
    position: absolute;
    bottom: calc(100% + 4px);
    left: 12px;
    min-width: 220px;
    max-width: calc(100% - 24px);
    padding: 4px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-menu);
    z-index: var(--z-popover);
  }

  .mention-option {
    display: flex;
    align-items: center;
    gap: 4px;
    min-height: var(--hit);
    padding: 0 10px;
    border-radius: var(--r-sm);
    color: var(--text-primary);
    cursor: pointer;
  }

  .mention-option.active,
  .mention-option:hover {
    background: var(--bg-hover);
  }

  .mention-name {
    font-weight: 600;
  }

  .mention-tag {
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }

  .chat-input {
    flex: 1;
    /* A field's own width is ~20 characters: without this it would not
       shrink, and at tablet width it pushed Send out over the member list */
    min-width: 0;
    padding: 8px 12px;
    font: inherit;
    font-size: var(--fs-body);
    line-height: 1.4;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
    resize: none;
    /* About eight lines, then it scrolls */
    max-height: calc(8 * 1.4em + 18px);
    overflow-y: auto;
  }

  .chat-input:focus {
    border-color: var(--focus-ring);
  }

  .send-btn {
    flex-shrink: 0;
    background: var(--accent);
    color: var(--on-accent);
    padding: 8px 16px;
    font-size: var(--fs-sm);
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .send-btn:hover:not(:disabled) {
    opacity: 0.9;
  }

  /* Nothing to send: a quiet outline, not a half-faded primary that reads as
     broken */
  .send-btn:disabled {
    background: transparent;
    color: var(--text-muted);
    box-shadow: inset 0 0 0 1px var(--border);
    cursor: default;
  }

  .emoji-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .emoji-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 34px;
    height: 34px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .emoji-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .emoji-picker {
    position: absolute;
    bottom: calc(100% + 8px);
    right: 0;
    width: 320px;
    max-height: 340px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: var(--shadow-menu);
    display: flex;
    flex-direction: column;
    z-index: var(--z-popover);
  }

  .emoji-tabs {
    display: flex;
    gap: 2px;
    padding: 6px 6px 4px;
    border-bottom: 1px solid var(--border);
  }

  .emoji-tab {
    flex: 1;
    padding: 4px 0;
    font-size: var(--fs-lg);
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    opacity: 0.5;
    transition: opacity var(--dur-fast);
    line-height: 1;
  }

  .emoji-tab:hover {
    opacity: 0.8;
    background: var(--bg-hover);
  }

  .emoji-tab.active {
    opacity: 1;
    background: var(--bg-tertiary);
  }

  .emoji-grid {
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: 2px;
    padding: 6px;
    overflow-y: auto;
    flex: 1;
  }

  .emoji-item {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    font-size: var(--fs-2xl);
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    line-height: 1;
    padding: 0;
  }

  .emoji-item:hover {
    background: var(--bg-hover);
    transform: scale(1.15);
  }
</style>
