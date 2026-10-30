<script lang="ts">
  // The server's emotes and stickers, for its admins (protocol v14): what
  // there is, by pack, renamed, removed (several at once) or made the other
  // kind; whether members may send stickers; and adding more, from pictures,
  // a folder, a .zip or a .wastickers. Every picture shown is the PNG the
  // sanitizer wrote (emote-import.ts), never a picked file's own bytes. The
  // panel closes on a server switch (admin-ui.ts), so the server it opened on
  // is the one it changes.
  import { onDestroy } from "svelte";
  import { get } from "svelte/store";
  import { serverAddress } from "../stores/connection.js";
  import { emoteLimits, emoteSets } from "../stores/emotes.js";
  import { addNotification } from "../stores/notifications.js";
  import { confirmAction } from "../stores/confirm.js";
  import { nameFrom, uniqueName, type Emote as Item } from "../emote-rules.js";
  import {
    addEmote,
    emoteFile,
    fetchSource,
    isArchive,
    prepareEmote,
    readPack,
    removeEmote,
    renameEmote,
    setStickers,
    type Made,
    type Prepared,
  } from "../emote-import.js";
  import { isAndroidApp, isWeb } from "../stores/platform.js";
  import { pictureUrl } from "../media.js";
  import { fold } from "../search-rules.js";
  import { toHex } from "../hex.js";
  import Emote from "./chat/Emote.svelte";
  import Icon from "./Icons.svelte";

  const server = get(serverAddress);
  const NAME = /^[a-z0-9_]{2,30}$/;
  /** voipc-protocol `valid_emote_pack`: one line, no control, invisible or
   *  direction characters, 32 characters and 64 bytes at most. */
  const validPack = (p: string) =>
    p.trim() === p && [...p].length <= 32 && new TextEncoder().encode(p).length <= 64 && !/[\p{Cc}\u200B-\u200F\u061C\u202A-\u202E\u2060-\u2069\uFEFF]/u.test(p);
  const taken = (name: string) => $emoteSets.emotes.some((e) => e.name === name);
  const why = (e: unknown) => String(e).replace(/^Error: /, "");

  let filter = $state("");
  const shown = $derived($emoteSets.emotes.filter((e) => fold(`${e.name} ${e.pack}`).includes(fold(filter))));
  const stickerCount = $derived($emoteSets.emotes.filter((e) => e.sticker).length);
  /** What is shown, by kind and pack: emotes first, then stickers; no pack first. */
  const sections = $derived.by(() => {
    const by = new Map<string, { key: string; sticker: boolean; pack: string; list: Item[] }>();
    for (const e of shown) {
      const key = `${e.sticker ? 1 : 0}|${e.pack}`;
      if (!by.has(key)) by.set(key, { key, sticker: e.sticker, pack: e.pack, list: [] });
      by.get(key)!.list.push(e);
    }
    return [...by.values()].sort((a, b) => Number(a.sticker) - Number(b.sticker) || a.pack.localeCompare(b.pack));
  });

  // ── What there is ─────────────────────────────────────────────────────────

  let renaming = $state<string | null>(null);
  let newName = $state("");

  async function finishRename(e: Item, save: boolean) {
    // Once: the box's blur, as it goes, comes after Enter or Escape finished it
    if (renaming !== e.name) return;
    const to = newName.trim();
    renaming = null;
    if (!save || to === e.name) return;
    if (!NAME.test(to)) return addNotification("A name is 2 to 30 of a-z, 0-9 and _", "error");
    await renameEmote(server, e.name, to).catch((err) => addNotification(why(err), "error"));
  }

  /** Picked to remove together, by name; only what is shown counts. */
  let picked = $state.raw(new Set<string>());
  const pickedShown = $derived(shown.filter((e) => picked.has(e.name)).map((e) => e.name));

  function pick(name: string) {
    const next = new Set(picked);
    if (!next.delete(name)) next.add(name);
    picked = next;
  }

  async function removeAll(names: string[], what: string) {
    const ok = await confirmAction({
      title: `Remove ${what}?`,
      body:
        names.length === 1
          ? `It goes for everyone on this server. Messages that used it show :${names[0]}: instead.`
          : `All ${names.length} go for everyone on this server. Messages that used them show their names instead.`,
      confirm: "Remove",
      danger: true,
    });
    if (!ok) return;
    for (const n of names) await removeEmote(server, n).catch((err) => addNotification(why(err), "error"));
    picked = new Set([...picked].filter((n) => !names.includes(n)));
  }

  /** Being made the other kind: one at a time each. */
  let switching = $state.raw(new Set<string>());

  /** An emote made a sticker, or back: added again under a passing name as
   *  the other kind (the server has its file, so nothing goes up), the old one
   *  removed, and the new one called by the old name. */
  async function switchKind(e: Item) {
    const passing = uniqueName(`${e.name.slice(0, 25)}_swap`, taken);
    if (!passing || switching.has(e.name)) return;
    switching = new Set([...switching, e.name]);
    try {
      await addEmote(server, passing, !e.sticker, e.pack, await emoteFile(server, e.hash));
      await removeEmote(server, e.name);
      await renameEmote(server, passing, e.name);
    } catch (err) {
      addNotification(`:${e.name}: stays ${e.sticker ? "a sticker" : "an emote"}: ${why(err)}`, "error");
    } finally {
      switching = new Set([...switching].filter((n) => n !== e.name));
    }
  }

  // ── Adding ────────────────────────────────────────────────────────────────

  interface Row {
    key: number;
    source: string;
    name: string;
    status: "reading" | "ready" | "skipped" | "uploading" | "done" | "failed";
    note: string;
    prepared?: Prepared;
    url?: string;
    include: boolean;
    /** The picked file, kept to make it again as the other kind. */
    bytes?: Uint8Array;
  }
  let rows = $state<Row[]>([]);
  let asSticker = $state(false);
  let pack = $state("");
  let busy = $state(false);
  let over = $state(false);
  let nextKey = 0;
  /** Bumped by Clear: an import still running adds nothing after it. */
  let generation = 0;

  const NOTE: Record<Made, string> = {
    clean: "",
    original: "Goes up as the file is: it may carry the file's own metadata",
    trimmed: "Frames dropped to fit the server's size",
    still: "Only its first frame fits the server's size",
  };

  const set = (key: number, change: Partial<Row>) => (rows = rows.map((r) => (r.key === key ? { ...r, ...change } : r)));
  const takenFor = (name: string, key: number) => taken(name) || rows.some((r) => r.key !== key && r.include && r.name === name);
  const nameProblem = (r: Row) =>
    !NAME.test(r.name) ? "2 to 30 of a-z, 0-9 and _" : takenFor(r.name, r.key) ? "This name is taken" : "";
  /** Ready to go, or failed and so to try again (under another name). */
  const editable = (r: Row) => r.status === "ready" || r.status === "failed";
  const ready = $derived(rows.filter((r) => r.include && editable(r) && !nameProblem(r)));
  const allIn = $derived(rows.filter(editable).every((r) => r.include));

  /** `key`'s upload and preview, for the kind chosen now. */
  async function make(key: number, bytes: Uint8Array, gen: number) {
    const limits = get(emoteLimits.peek(server));
    if (!limits) return set(key, { status: "skipped", include: false, note: "This server keeps no emotes" });
    const sticker = asSticker;
    try {
      const p = await prepareEmote(bytes, sticker, sticker ? limits.max_sticker_bytes : limits.max_emote_bytes);
      const hash = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", p.upload as Uint8Array<ArrayBuffer>)));
      // Cleared, or switched to the other kind meanwhile: that run makes it again
      const row = rows.find((r) => r.key === key);
      if (gen !== generation || sticker !== asSticker || !row) return;
      if (row.url) URL.revokeObjectURL(row.url);
      const same = $emoteSets.emotes.find((e) => e.hash === hash);
      const base = nameFrom(row.source) ?? "emote";
      set(key, {
        prepared: p,
        url: pictureUrl(p.preview),
        status: "ready",
        note: same ? `Already here as :${same.name}:` : NOTE[p.how],
        name: row.name || (uniqueName(base, (n) => takenFor(n, key)) ?? base),
        // A row made again (the other kind) keeps its tick; a new one starts off if a copy is here
        include: row.name ? row.include : !same,
      });
    } catch (e) {
      if (gen === generation && sticker === asSticker) set(key, { status: "skipped", include: false, note: why(e) });
    }
  }

  async function prepare(source: string, bytes: Uint8Array, gen: number) {
    if (gen !== generation) return;
    const key = nextKey++;
    rows = [...rows, { key, source, name: "", status: "reading", note: "", include: true, bytes }];
    await make(key, bytes, gen);
  }

  /** Emotes or stickers: what is listed is made again for that kind. */
  async function setKind(sticker: boolean) {
    if (sticker === asSticker || busy) return;
    asSticker = sticker;
    const gen = generation;
    for (const r of rows.filter((r) => r.bytes && r.status !== "done" && r.status !== "uploading")) {
      if (gen !== generation || sticker !== asSticker) return;
      set(r.key, { status: "reading", note: "" });
      await make(r.key, r.bytes!, gen);
    }
  }

  function includeAll(on: boolean) {
    rows = rows.map((r) => (editable(r) ? { ...r, include: on } : r));
  }

  async function addFiles(files: Iterable<File>) {
    const gen = generation;
    for (const f of files) {
      const bytes = new Uint8Array(await f.arrayBuffer());
      if (!isArchive(bytes)) {
        await prepare(f.name, bytes, gen);
        continue;
      }
      try {
        const p = await readPack(bytes);
        if (gen !== generation) return;
        if (!pack) pack = [...(p.title ?? f.name.replace(/\.(zip|wastickers)$/i, ""))].slice(0, 32).join("").trim();
        for (const s of p.skipped) rows = [...rows, { key: nextKey++, source: s.name, name: "", status: "skipped", include: false, note: s.why }];
        for (const e of p.entries) await prepare(e.name, e.bytes, gen);
      } catch (e) {
        if (gen !== generation) return;
        rows = [...rows, { key: nextKey++, source: f.name, name: "", status: "skipped", include: false, note: why(e) }];
      }
    }
  }

  // One click, from elsewhere (desktop only: emote_sources.rs)
  let source = $state<"discord" | "7tv" | "bttv">("7tv");
  let sourceId = $state("");
  let token = $state("");
  let fetching = $state(false);
  async function fetchFrom() {
    fetching = true;
    const gen = generation;
    try {
      const got = await fetchSource(source, sourceId.trim(), source === "discord" ? token : "", asSticker);
      if (gen !== generation) return;
      if (!pack && got.title) pack = [...got.title].slice(0, 32).join("").trim();
      for (const s of got.skipped) rows = [...rows, { key: nextKey++, source: s.name, name: "", status: "skipped", include: false, note: s.why }];
      for (const e of got.entries) await prepare(e.name, e.bytes, gen);
    } catch (e) {
      addNotification(why(e), "error");
    } finally {
      // Kept nowhere: not even in this field
      token = "";
      fetching = false;
    }
  }

  function drop(e: DragEvent) {
    e.preventDefault();
    over = false;
    // Copied now: the browser empties the drop's list once this returns
    if (e.dataTransfer?.files.length) void addFiles([...e.dataTransfer.files]);
  }

  /** A picker's files, copied before it is cleared: the list is live. */
  function pickedFiles(e: Event) {
    const input = e.target as HTMLInputElement;
    const files = [...(input.files ?? [])];
    input.value = "";
    void addFiles(files);
  }

  async function upload() {
    if (!validPack(pack.trim())) return addNotification("A pack's name is one line of at most 32 characters", "error");
    busy = true;
    const todo = [...ready];
    let next = 0;
    const one = async () => {
      while (next < todo.length) {
        const r = todo[next++];
        set(r.key, { status: "uploading" });
        try {
          await addEmote(server, r.name, asSticker, pack.trim(), r.prepared!.upload);
          set(r.key, { status: "done", note: "", bytes: undefined });
        } catch (e) {
          set(r.key, { status: "failed", note: why(e) });
        }
      }
    };
    await Promise.all([one(), one(), one(), one()]);
    busy = false;
    const done = rows.filter((r) => r.status === "done").length;
    if (done) addNotification(`${done} added to this server`, "info");
  }

  function clear() {
    generation++;
    for (const r of rows) if (r.url) URL.revokeObjectURL(r.url);
    rows = [];
    pack = "";
  }
  onDestroy(clear);
</script>

<div class="em">
  <label class="em-switch">
    <input type="checkbox" checked={$emoteSets.stickers} onchange={(e) => setStickers(server, (e.target as HTMLInputElement).checked)} />
    <span>Members may send stickers</span>
  </label>
  <p class="em-hint">
    {$emoteSets.emotes.length - stickerCount} emotes, {stickerCount} stickers. They are stored on this server unencrypted, visible
    to everyone who joins; every member's app makes its own safe copy of each before showing it.
  </p>

  {#if $emoteSets.emotes.length}
    <div class="em-tools">
      <input class="em-input" type="search" placeholder="Search" aria-label="Search this server's emotes" bind:value={filter} />
      {#if pickedShown.length}
        <button class="btn btn-danger-outline" type="button" onclick={() => removeAll(pickedShown, pickedShown.length === 1 ? `:${pickedShown[0]}:` : `${pickedShown.length} emotes and stickers`)}>
          Remove {pickedShown.length}
        </button>
      {/if}
    </div>
    <div class="em-list">
      {#each sections as s (s.key)}
        <div class="em-section">
          <span>{s.sticker ? "Stickers" : "Emotes"}{s.pack ? ` · ${s.pack}` : ""}</span>
          <span class="em-count num">{s.list.length}</span>
          {#if s.pack}
            <button class="btn btn-ghost em-small" type="button" onclick={() => removeAll(s.list.map((e) => e.name), `the pack "${s.pack}"`)}>Remove pack</button>
          {/if}
        </div>
        <ul>
          {#each s.list as e (e.name)}
            <li class="em-row">
              <input type="checkbox" checked={picked.has(e.name)} onchange={() => pick(e.name)} aria-label="Pick :{e.name}:" />
              <span class="em-pic"><Emote name={e.name} hash={e.hash.slice(0, 20)} size="jumbo" /></span>
              {#if renaming === e.name}
                <!-- svelte-ignore a11y_autofocus -->
                <input
                  class="em-input em-name"
                  bind:value={newName}
                  autofocus
                  aria-label="New name for :{e.name}:"
                  onkeydown={(ev) => {
                    if (ev.key === "Enter") finishRename(e, true);
                    if (ev.key === "Escape") { ev.stopPropagation(); finishRename(e, false); }
                  }}
                  onblur={() => finishRename(e, true)}
                />
              {:else}
                <span class="em-name" title=":{e.name}:">:{e.name}:</span>
              {/if}
              <span class="em-meta">{switching.has(e.name) ? (e.sticker ? "Making it an emote…" : "Making it a sticker…") : ""}</span>
              <button
                class="icon-btn"
                type="button"
                title={e.sticker ? "Make it an emote" : "Make it a sticker"}
                aria-label="{e.sticker ? 'Make it an emote' : 'Make it a sticker'}: :{e.name}:"
                disabled={switching.has(e.name)}
                onclick={() => switchKind(e)}><Icon name="switch-source" size={14} /></button
              >
              <button class="icon-btn" type="button" title="Rename" aria-label="Rename :{e.name}:" onclick={() => { renaming = e.name; newName = e.name; }}><Icon name="pencil" size={14} /></button>
              <button class="icon-btn" type="button" title="Remove" aria-label="Remove :{e.name}:" onclick={() => removeAll([e.name], `:${e.name}:`)}><Icon name="trash" size={14} /></button>
            </li>
          {/each}
        </ul>
      {/each}
    </div>
  {/if}

  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="em-add" class:over ondragover={(e) => { e.preventDefault(); over = true; }} ondragleave={() => (over = false)} ondrop={drop}>
    <div class="em-heading">Add</div>
    <div class="em-kind" role="group" aria-label="Add as">
      <button type="button" class="em-chip" aria-pressed={!asSticker} disabled={busy} onclick={() => setKind(false)}>Emotes</button>
      <button type="button" class="em-chip" aria-pressed={asSticker} disabled={busy} onclick={() => setKind(true)}>Stickers</button>
    </div>
    <input class="em-input" placeholder="Pack (optional)" aria-label="Pack name" maxlength="32" bind:value={pack} />
    <div class="em-pick">
      <!-- No type filter: some systems' pickers then hide .zip and .wastickers.
           What is not a picture is set aside below, saying why. -->
      <label class="btn btn-secondary">
        Pictures or a .zip…
        <input type="file" multiple hidden onchange={pickedFiles} />
      </label>
      <label class="btn btn-secondary">
        A folder…
        <input type="file" hidden webkitdirectory onchange={pickedFiles} />
      </label>
    </div>
    <p class="em-hint">Or drop them here. A Discord, Slack or TeamSpeak folder, a WhatsApp .wastickers, a Telegram pack a bot saved as a .zip: names come from the files.</p>
    {#if !isWeb && !isAndroidApp}
      <div class="em-heading">Or fetch them</div>
      <div class="em-kind" role="group" aria-label="From">
        <button type="button" class="em-chip" aria-pressed={source === "7tv"} onclick={() => (source = "7tv")}>7TV</button>
        <button type="button" class="em-chip" aria-pressed={source === "bttv"} onclick={() => (source = "bttv")}>BetterTTV</button>
        <button type="button" class="em-chip" aria-pressed={source === "discord"} onclick={() => (source = "discord")}>Discord server</button>
      </div>
      <input
        class="em-input"
        aria-label="Where from"
        bind:value={sourceId}
        placeholder={source === "7tv" ? "An emote's or a set's address (7tv.app/emotes/… or 7tv.app/emote-sets/…)" : source === "bttv" ? "The Twitch user id (a number)" : "The Discord server's id (a number)"}
      />
      {#if source === "discord"}
        <input class="em-input" type="password" autocomplete="off" aria-label="Bot token" placeholder="A bot's token (the bot must be in that server)" bind:value={token} />
        <p class="em-hint">The token goes to discord.com only, for this one fetch, and is kept nowhere. {asSticker ? "Stickers" : "Emojis"} are fetched, as chosen above; animated (Lottie) stickers are passed over.</p>
      {/if}
      <div class="em-actions">
        <button class="btn btn-secondary" type="button" disabled={fetching || !sourceId.trim() || (source === "discord" && !token.trim())} onclick={fetchFrom}>
          {fetching ? "Fetching…" : "Fetch"}
        </button>
      </div>
    {/if}

    {#if rows.length}
      {#if rows.filter(editable).length > 1}
        <label class="em-all"><input type="checkbox" checked={allIn} onchange={() => includeAll(!allIn)} /> All</label>
      {/if}
      <ul class="em-list">
        {#each rows as r (r.key)}
          <li class="em-row" class:skip={!r.include}>
            {#if editable(r)}
              <input type="checkbox" bind:checked={r.include} aria-label="Add {r.source}" />
            {/if}
            <span class="em-pic">{#if r.url}<img src={r.url} alt="" />{:else}<Icon name="file" size={16} />{/if}</span>
            {#if editable(r)}
              <span class="em-namebox">
                <input class="em-input em-name" bind:value={r.name} aria-label="Name for {r.source}" aria-invalid={!!nameProblem(r)} aria-describedby={nameProblem(r) ? `em-p-${r.key}` : undefined} />
                {#if nameProblem(r)}<span class="em-problem" id="em-p-{r.key}">{nameProblem(r)}</span>{/if}
              </span>
            {:else}
              <span class="em-name" title={r.source}>{r.name ? `:${r.name}:` : r.source}</span>
            {/if}
            <span class="em-meta" role="status">
              {r.status === "reading" ? "Reading…" : r.status === "uploading" ? "Adding…" : r.status === "done" ? "Added" : ""}
              {r.note}
            </span>
          </li>
        {/each}
      </ul>
      <div class="em-actions">
        <button class="btn btn-ghost" type="button" disabled={busy} onclick={clear}>Clear</button>
        <button class="btn btn-primary" type="button" disabled={busy || ready.length === 0} onclick={upload}>
          {busy ? "Adding…" : `Add ${ready.length}`}
        </button>
      </div>
    {/if}
  </div>
</div>

<style>
  .em {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .em-switch,
  .em-all {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .em-hint {
    margin: 0;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .em-input {
    width: 100%;
    padding: 6px 8px;
    font: inherit;
    font-size: var(--fs-body);
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .em-input[aria-invalid="true"] {
    border-color: var(--danger, #e5484d);
  }
  .em-tools {
    display: flex;
    gap: 6px;
  }
  .em-tools .btn {
    flex-shrink: 0;
  }
  .em-list {
    list-style: none;
    margin: 0;
    padding: 0;
    max-height: 40vh;
    overflow-y: auto;
  }
  .em-list ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .em-section {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 0 2px;
    font-size: var(--fs-sm);
    font-weight: 600;
    color: var(--text-secondary);
  }
  .em-count {
    font-weight: 400;
  }
  .em-small {
    margin-left: auto;
    padding: 0 8px;
    min-height: 24px;
    font-size: var(--fs-sm);
  }
  .em-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 2px 0;
    border-bottom: 1px solid var(--border);
    min-width: 0;
  }
  .em-row.skip {
    opacity: 0.6;
  }
  .em-pic {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    flex-shrink: 0;
  }
  .em-pic img {
    max-width: 40px;
    max-height: 40px;
  }
  .em-name {
    flex: 0 1 160px;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .em-namebox {
    display: flex;
    flex-direction: column;
    flex: 0 1 180px;
    min-width: 0;
  }
  .em-namebox .em-name {
    flex: none;
  }
  .em-problem {
    font-size: var(--fs-sm);
    color: var(--danger, #e5484d);
  }
  .em-meta {
    flex: 1;
    min-width: 0;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .em-row .icon-btn {
    width: var(--icon-btn-size-sm);
    height: var(--icon-btn-size-sm);
    background: transparent;
  }
  .em-add {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 8px;
    border: 1px dashed var(--border);
    border-radius: var(--r-md);
  }
  .em-add.over {
    border-color: var(--focus-ring);
  }
  .em-heading {
    font-weight: 600;
  }
  .em-kind,
  .em-pick,
  .em-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .em-actions {
    justify-content: flex-end;
  }
  .em-chip {
    padding: 4px 10px;
    min-height: 28px;
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }
  .em-chip[aria-pressed="true"] {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
</style>
