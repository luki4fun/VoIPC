<script lang="ts">
  import { tick } from "svelte";
  import { pushLayer } from "../../stores/back-stack.js";
  import { confirmAction } from "../../stores/confirm.js";
  import { shortName } from "../../username.js";
  import { cancelFile, fileProgress, forgetProgress, newOp } from "../../files.js";
  import { formatSize } from "../../file-rules.js";
  import { CannotClean, isPhoto } from "../../image-prep.js";
  import { isAnimated, sniff } from "../../file-sniff.js";
  import Icon from "../Icons.svelte";
  import { completeEmoji, completeEmote, type Emote as EmoteItem } from "../../emote-rules.js";
  import { emoteSets, favEmotes, recentEmotes } from "../../stores/emotes.js";
  import { serverAddress } from "../../stores/connection.js";
  import Emote from "./Emote.svelte";
  import EmotePicker from "./EmotePicker.svelte";
  import { drawsAsOne } from "../../emoji-support.js";

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
    /**
     * Send one file as its own message with `caption`, a photo as it is if
     * `original`, reporting under `op`. Absent where files cannot go (the
     * relay keeps none, or nobody to name): there is no attach button then.
     */
    onsendfile?: (file: File, original: boolean, caption: string, op: string) => Promise<void>;
    /** The largest file this server takes, said on a chip before Send is pressed. */
    maxBytes?: number | null;
    /** A sticker was picked: it goes as a message of its own. Absent where
     *  stickers cannot be sent here (the server's switch). */
    onsticker?: (e: EmoteItem) => void;
  }
  let {
    placeholder,
    conversation,
    held = null,
    onsend,
    replying = null,
    oncancelreply,
    mentionables = [],
    onsendfile,
    maxBytes = null,
    onsticker,
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
    staged = [];
    // A batch under way stops at its next file: what was staged here is
    // not for wherever the person went
    epoch++;
  });

  // Files that can no longer go (the relay keeps none now, or nobody to name)
  // are let go; one under way finishes. Written only when one goes: the
  // effect reads `staged`, and a new array every run would run it forever
  $effect(() => {
    if (!onsendfile && staged.some((f) => !f.op)) staged = staged.filter((f) => f.op);
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
    // Kept in the input rather than sent to be refused
    if (held) return;
    if (staged.some((f) => !f.op) && onsendfile && !sending) {
      text = "";
      // Pressed again: what failed is tried again
      staged = staged.map((f) => ({ ...f, error: null }));
      void sendFiles(content);
      return;
    }
    // Files on their way already take what is staged after them; words go
    // as words
    if (!content) return;
    text = "";
    onsend(content);
  }

  // ── Files ─────────────────────────────────────────────────────────────────

  /** A file picked, pasted or dropped, until its message is sent. */
  interface Staged {
    key: number;
    file: File;
    /** A still photo: the compressed / original choice is for it. */
    photo: boolean;
    /** A video, a sound or a moving picture: it goes as it is, metadata and
     *  all, and the chip says so (R3-10, D-16). */
    asIs: boolean;
    original: boolean;
    /** Its upload under way. */
    op: string | null;
    error: string | null;
  }
  let staged = $state<Staged[]>([]);
  let nextKey = 0;
  /** A batch is going out. */
  let sending = $state(false);
  /** Bumped when the conversation changes, which ends a batch. */
  let epoch = 0;
  let picker = $state<HTMLInputElement | null>(null);

  /** Stage files to go out, one message each (ChatPanel drops them here too). */
  export function addFiles(files: Iterable<File>) {
    if (!onsendfile) return;
    for (const file of files) {
      // Dropped and then pasted, or picked twice: one chip for one file
      if (staged.some((s) => s.file.name === file.name && s.file.size === file.size && s.file.lastModified === file.lastModified && !s.op)) continue;
      const entry: Staged = { key: nextKey++, file, photo: false, asIs: false, original: false, op: null, error: null };
      staged = [...staged, entry];
      // The first bytes say whether it is a photo, not the name or the type
      const key = entry.key;
      file
        .slice(0, 64)
        .arrayBuffer()
        .then((head) => {
          const bytes = new Uint8Array(head);
          const photo = isPhoto(bytes, file.type);
          const kind = sniff(bytes)?.kind;
          const asIs = kind === "video" || kind === "audio" || (kind === "image" && isAnimated(bytes));
          staged = staged.map((f) => (f.key === key ? { ...f, photo, asIs } : f));
        })
        .catch(() => {});
    }
    tick().then(() => inputEl?.focus());
  }

  function unstage(key: number) {
    staged = staged.filter((f) => f.key !== key);
  }

  function patch(key: number, change: Partial<Staged>) {
    staged = staged.map((f) => (f.key === key ? { ...f, ...change } : f));
  }

  /**
   * The staged files one by one, the caption with the first, each read as it
   * is now: one taken off or switched to Original meanwhile is seen. One that
   * fails stays, with why, to be sent again or taken off; if the first does,
   * its caption comes back into the box. Stops at a conversation change, and
   * when slow mode holds the next message.
   */
  async function sendFiles(caption: string) {
    const send = onsendfile;
    if (!send || sending) return;
    sending = true;
    const mine = epoch;
    let words = caption;
    try {
      for (;;) {
        const f = staged.find((s) => !s.op && !s.error);
        if (!f || epoch !== mine || held) break;
        let original = f.original;
        for (;;) {
          const op = newOp();
          patch(f.key, { op, error: null });
          try {
            await send(f.file, original, words, op);
            words = "";
            unstage(f.key);
            break;
          } catch (e) {
            if (e instanceof CannotClean && !original) {
              forgetProgress(op);
              const ok = await confirmAction({
                title: "Send the original?",
                body: `${f.file.name} cannot be made smaller here, so it would go exactly as it is, with any location and camera data in it.`,
                confirm: "Send original",
              });
              if (ok && epoch === mine) {
                original = true;
                continue;
              }
              patch(f.key, { op: null, error: "Not sent" });
            } else {
              // As a sentence: the backends' reasons start in lower case
              const why = String(e).replace(/^Error: /, "");
              patch(f.key, { op: null, error: why === "cancelled" ? STOPPED : why.charAt(0).toUpperCase() + why.slice(1) });
            }
            if (words && !text) text = words;
            words = "";
            break;
          } finally {
            forgetProgress(op);
          }
        }
      }
    } finally {
      sending = false;
    }
  }

  function cancelStaged(f: Staged) {
    if (f.op) void cancelFile(f.op);
    else unstage(f.key);
  }

  function onPaste(e: ClipboardEvent) {
    const files = e.clipboardData?.files;
    if (!onsendfile || !files || files.length === 0) return;
    e.preventDefault();
    addFiles(files);
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
  /** This device's recently used emotes here, newest first (stores/emotes.ts). */
  const recent = $derived($recentEmotes[$serverAddress] ?? []);
  /** The `:word` being typed just before the cursor: a server emote, or an
   *  emoji by name, to complete. */
  const emoteQuery = $derived.by(() => {
    const before = text.slice(0, caret);
    // Where `tokenize` reads a `:name:` (emote-rules.ts): after a space, an
    // emoji or a bracket too, never inside a word or an address
    const m = /(?:^|[^a-z0-9_:<\/]):([a-z0-9_]{2,30})$/.exec(before);
    return m ? { q: m[1], start: before.length - m[1].length - 1 } : null;
  });
  type Option = { kind: "emote"; e: EmoteItem } | { kind: "emoji"; name: string; emoji: string };
  /** The server's emotes first, favourites and the recently used ahead, then
   *  emoji by name. */
  const emoteOptions = $derived.by((): Option[] => {
    if (!emoteQuery || emoteQuery.start === dismissedAt || suggestions.length) return [];
    const own = completeEmote(emoteQuery.q, $emoteSets.emotes, 8, [...($favEmotes[$serverAddress] ?? []), ...recent]);
    return [
      ...own.map((e): Option => ({ kind: "emote", e })),
      ...completeEmoji(emoteQuery.q, 8 - own.length, drawsAsOne).map((o): Option => ({ kind: "emoji", ...o })),
    ];
  });
  const offered = $derived(suggestions.length || emoteOptions.length);
  $effect(() => {
    void suggestions;
    void emoteOptions;
    active = 0;
  });

  function pickEmote(o: Option) {
    if (!emoteQuery) return;
    const insert = o.kind === "emote" ? `:${o.e.name}: ` : `${o.emoji} `;
    const at = emoteQuery.start + insert.length;
    text = text.slice(0, emoteQuery.start) + insert + text.slice(caret);
    caret = at;
    tick().then(() => {
      inputEl?.focus();
      inputEl?.setSelectionRange(at, at);
    });
  }

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
    // The picker alone: never the thread or the pane around this box
    if (e.key === "Escape" && showEmojiPicker) {
      e.preventDefault();
      e.stopPropagation();
      showEmojiPicker = false;
      return;
    }
    if (offered > 0) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const step = e.key === "ArrowDown" ? 1 : -1;
        active = (active + step + offered) % offered;
        return;
      }
      if ((e.key === "Enter" || e.key === "Tab") && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        if (suggestions.length) pick(suggestions[active]);
        else pickEmote(emoteOptions[active]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        dismissedAt = (query ?? emoteQuery)?.start ?? -1;
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

  let showEmojiPicker = $state(false);
  /** Into the picker's search at once, unless a finger opened it (its
   *  keyboard would come up over the picker). */
  let pickerFocus = $state(false);

  /** `piece` into the draft where the cursor is: an emote's `:name:` with a
   *  space either side of it. `keep`: the picker stays open for another. */
  function insertAtCaret(piece: string, keep: boolean) {
    const from = inputEl?.selectionStart ?? text.length;
    const to = inputEl?.selectionEnd ?? from;
    const before = text.slice(0, from);
    const insert = piece.startsWith(":") ? `${/\S$/.test(before) ? " " : ""}${piece} ` : piece;
    text = before + insert + text.slice(to);
    const at = from + insert.length;
    caret = at;
    if (!keep) showEmojiPicker = false;
    tick().then(() => {
      if (!keep) inputEl?.focus();
      inputEl?.setSelectionRange(at, at);
    });
  }

  function closePicker() {
    showEmojiPicker = false;
    // Back to the message box for a mouse or the keyboard; a finger's sticker
    // is sent, and the phone's keyboard coming up for nothing hides the chat
    if (pickerFocus) tick().then(() => inputEl?.focus());
  }

  // A tap on the composer's own buttons never takes the focus from the text
  // field: on a phone the keyboard would drop, the shell around it reflow, and
  // the button move away before the finger lifts (D2: Send took two taps in
  // mobile Classic). The click still comes, and the keyboard stays up.
  const keepField = (e: PointerEvent) => e.preventDefault();
  const STOPPED = "Stopped";

  // Android Back closes the picker first, not the pane it sits in
  $effect(() => {
    if (showEmojiPicker) return pushLayer(() => (showEmojiPicker = false));
  });

  /** Into the search only for a mouse or the keyboard: a finger's tap would
   *  bring the phone's keyboard up over the picker. Told by the tap itself,
   *  since some touch screens (an emulator, some tablets) report a fine pointer. */
  function toggleEmojiPicker(e: MouseEvent) {
    showEmojiPicker = !showEmojiPicker;
    const finger = (e as PointerEvent).pointerType === "touch" || (e as PointerEvent).pointerType === "pen";
    pickerFocus = showEmojiPicker && !finger && !matchMedia("(pointer: coarse)").matches;
  }
</script>

<!-- Any click elsewhere closes the picker; Escape closes it too (its own, or the box's) -->
<svelte:window onclick={() => { if (showEmojiPicker) showEmojiPicker = false; }} />

{#if replying}
  <div class="reply-bar">
    <Icon name="reply" size={14} />
    <span class="reply-to">Replying to <strong>{shortName(replying)}</strong></span>
    <button class="icon-btn reply-cancel" type="button" onpointerdown={keepField} aria-label="Cancel reply" title="Cancel reply (Esc)" onclick={() => oncancelreply?.()}>
      <Icon name="close" size={14} />
    </button>
  </div>
{/if}
{#if staged.length > 0}
  <ul class="file-chips" aria-label="Files to send">
    {#each staged as f (f.key)}
      {@const p = f.op ? $fileProgress.get(f.op) : undefined}
      <li class="file-chip">
        <Icon name="file" size={16} />
        <span class="chip-name" title={f.file.name}>{f.file.name}</span>
        <span class="chip-size num">{formatSize(f.file.size)}</span>
        {#if f.photo && !f.op}
          <button
            class="btn btn-ghost chip-mode"
            type="button"
            onpointerdown={keepField}
            aria-pressed={f.original}
            aria-describedby="{listId}-mode-{f.key}"
            title={f.original
              ? "Sent exactly as it is: includes any location and camera data. Press to send it compressed."
              : "Sent compressed: smaller, without its location and camera data. Press to send it as it is."}
            onclick={() => patch(f.key, { original: !f.original })}
          >Original (1:1)</button>
          <!-- What the toggle means, in words a phone can see (it has no tooltips) -->
          <span class="chip-note" id="{listId}-mode-{f.key}">{f.original ? "as it is, with location and camera data" : "compressed, without location data"}</span>
        {/if}
        {#if maxBytes && f.file.size > maxBytes && !(f.photo && !f.original) && !f.op && !f.error}
          <!-- A file packed down before it goes may still fit: said, not refused -->
          <span class="chip-note chip-warn">Over this server's {Math.floor(maxBytes / 1_000_000)} MB: it goes only if it packs down that far</span>
        {/if}
        {#if f.asIs && !f.op}
          <span class="chip-note" title="Videos, sounds and moving pictures are sent exactly as they are, with any location and camera data in them">Sent as it is: may include location</span>
        {/if}
        {#if f.op}
          {@const pct = p && p.total > 0 ? Math.round((p.done / p.total) * 100) : 0}
          <span class="chip-bar" role="progressbar" aria-label="Sending {f.file.name}" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}
            ><span style="width: {pct}%"></span></span>
          <span class="chip-size num" aria-hidden="true">{pct}%</span>
        {/if}
        <button
          class="icon-btn"
          type="button"
          aria-label={f.op ? `Stop sending ${f.file.name}` : `Do not send ${f.file.name}`}
          onpointerdown={keepField}
          onclick={() => cancelStaged(f)}
        >
          <Icon name="close" size={14} />
        </button>
        {#if f.error}<span class="chip-error" class:stopped={f.error === STOPPED} role="alert">{f.error}</span>{/if}
      </li>
    {/each}
  </ul>
{/if}
<form class="input-bar" class:replying={!!replying} onsubmit={(e) => { e.preventDefault(); send(); }}>
  {#if onsendfile}
    <button class="emoji-btn" type="button" onpointerdown={keepField} onclick={() => picker?.click()} title="Attach files" aria-label="Attach files">
      <Icon name="paperclip" size={20} />
    </button>
    <input
      class="file-picker"
      type="file"
      multiple
      bind:this={picker}
      onchange={(e) => {
        const input = e.currentTarget;
        if (input.files) addFiles(input.files);
        input.value = "";
      }}
    />
  {/if}
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
  {#if emoteOptions.length > 0}
    <div class="mention-pop" id={listId} role="listbox" aria-label="Emotes">
      {#each emoteOptions as o, i (o.kind === "emote" ? `e:${o.e.name}` : o.name)}
        <div
          class="mention-option"
          class:active={i === active}
          id="{listId}-{i}"
          role="option"
          aria-selected={i === active}
          tabindex="-1"
          onpointerdown={(ev) => { ev.preventDefault(); pickEmote(o); }}
        >
          {#if o.kind === "emote"}<Emote name={o.e.name} hash={o.e.hash} />{:else}<span class="mention-emoji">{o.emoji}</span>{/if}
          <span class="mention-name">:{o.kind === "emote" ? o.e.name : o.name}:</span>
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
    onpaste={onPaste}
    aria-autocomplete="list"
    aria-controls={offered > 0 ? listId : undefined}
    aria-activedescendant={offered > 0 ? `${listId}-${active}` : undefined}
    maxlength="2000"
  ></textarea>
  <div class="emoji-wrapper">
    <button
      class="emoji-btn"
      type="button"
      onpointerdown={keepField}
      onclick={(e) => { e.stopPropagation(); toggleEmojiPicker(e); }}
      title="Emoji, emotes and stickers"
      aria-label="Emoji, emotes and stickers"
      aria-haspopup="dialog"
      aria-expanded={showEmojiPicker}
    >
      <Icon name="smile" size={20} />
    </button>
    {#if showEmojiPicker}
      <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
      <div class="emoji-picker" onclick={(e) => e.stopPropagation()}>
        <EmotePicker onpick={insertAtCaret} onsticker={onsticker ? (e) => onsticker(e) : undefined} {held} onclose={closePicker} autofocus={pickerFocus} />
      </div>
    {/if}
  </div>
  {#if held}
    <button class="send-btn" type="submit" onpointerdown={keepField} disabled title={held.title}>{held.label}</button>
  {:else}
    <button class="send-btn" type="submit" onpointerdown={keepField} disabled={!text.trim() && (sending || !staged.some((f) => !f.op))}>Send</button>
  {/if}
</form>

<style>
  .file-chips {
    list-style: none;
    margin: 0;
    padding: 8px 12px 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
    border-top: 1px solid var(--border);
  }
  .file-chip {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    padding: 4px 4px 4px 10px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    color: var(--text-secondary);
    min-width: 0;
  }
  .chip-name {
    flex: 1;
    min-width: 0;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chip-size {
    font-size: var(--fs-sm);
  }
  .chip-mode {
    font-size: var(--fs-sm);
    font-weight: 400;
    padding: 2px 8px;
  }
  /* On, as every toggle here is (DESIGN.md): raised and ringed, never just hovered */
  .chip-mode[aria-pressed="true"] {
    color: var(--text-primary);
    background: var(--bg-hover);
    box-shadow: inset 0 0 0 1px var(--text-muted);
  }
  .chip-bar {
    width: 80px;
    height: 4px;
    border-radius: 2px;
    background: var(--border);
    overflow: hidden;
  }
  .chip-bar span {
    display: block;
    height: 100%;
    background: var(--text-secondary);
    transition: width 0.2s;
  }
  .chip-note {
    font-size: var(--fs-sm);
  }
  .chip-warn {
    color: var(--warning);
  }
  /* Stopped by the person: not an error, so not in red */
  .chip-error.stopped {
    color: var(--text-secondary);
  }
  .chip-error {
    flex-basis: 100%;
    font-size: var(--fs-sm);
    color: var(--danger);
  }
  .file-picker {
    display: none;
  }
  .file-chips + .input-bar {
    border-top: none;
  }

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

  .mention-emoji {
    font-size: var(--fs-lg);
    line-height: 1;
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

  /* Not the picker's box: it hangs from the whole message row (as the @ list
     does), so it is inside the pane at any width without being measured.
     Measured and shifted, it went off a phone's edge when it opened while the
     panes were still sliding (B-01, D2-07). */
  .emoji-wrapper {
    display: flex;
    align-items: center;
  }

  .emoji-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: var(--hit);
    height: var(--hit);
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: var(--r-sm);
    cursor: pointer;
  }

  .emoji-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .emoji-picker {
    position: absolute;
    bottom: calc(100% + 8px);
    right: 12px;
    width: 320px;
    max-width: calc(100% - 24px);
    /* One size whatever the tab, so it never jumps under the pointer */
    height: min(380px, 60vh);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-menu);
    display: flex;
    flex-direction: column;
    z-index: var(--z-popover);
  }

</style>
