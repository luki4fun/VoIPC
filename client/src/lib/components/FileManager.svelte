<script lang="ts">
  // Settings → Files: every file the chat here names, on every server, and
  // what of it this device keeps (file-index.ts). A row shows only what its
  // message says; opening it shows the card the chat shows, and nothing is
  // fetched until that card is asked to.
  import { invoke } from "@tauri-apps/api/core";
  import { onDestroy, tick } from "svelte";
  import { channelMessages, dmMessages } from "../stores/chat.js";
  import { serverKey } from "../stores/connection.js";
  import { openServers, serverId, serverName } from "../stores/servers.js";
  import { savedServers } from "../stores/settings.js";
  import { channels } from "../stores/channels.js";
  import { uiPrefs } from "../stores/ui-prefs.js";
  import { isWeb } from "../stores/platform.js";
  import { confirmAction } from "../stores/confirm.js";
  import { addNotification } from "../stores/notifications.js";
  import { settingsAsk, showMessage } from "../stores/channel-ui.js";
  import { get } from "svelte/store";
  import { fetchFile, fileConvAt, fileProgress, forgetProgress, newOp, saveFile } from "../files.js";
  import { sniff } from "../file-sniff.js";
  import { preview } from "../actions/preview.js";
  import {
    arrangeFiles,
    fileRows,
    type CachedBlob,
    type FileFilter,
    type FileGroup,
    type FileKind,
    type FileRow,
    type FileSection,
    type FileSort,
  } from "../file-index.js";
  import { formatSize, PREVIEW_SIDE } from "../file-rules.js";
  import { mobileOk } from "../stores/emotes.js";
  import { needsNsfwConsent } from "../channel-post-rules.js";
  import { rowKey, type ChatPlace } from "../chat-rules.js";
  import type { ChatMessage } from "../types.js";
  import { shortName } from "../username.js";
  import FileCard from "./chat/FileCard.svelte";
  import Lightbox from "./chat/Lightbox.svelte";
  import Icon from "./Icons.svelte";

  /** Closes Settings: a jump to a message shows the chat. */
  let { onclose }: { onclose: () => void } = $props();

  const MIB = 1024 * 1024;
  /** files.rs `CACHE_MB`. */
  const CAP_MIN_MB = 64;
  const CAP_MAX_MB = 1024 * 1024;
  /** Rows drawn at first, and added per "Show more". */
  const PAGE = 100;

  let cache = $state.raw<{ cap: number; entries: CachedBlob[] } | null>(null);
  let query = $state("");
  /** One conversation only, as the chat's Files button asked; its chip clears it. */
  let place = $state(get(settingsAsk)?.place ?? "");
  settingsAsk.set(null);
  let filter = $state<FileFilter>("all");
  let sort = $state<FileSort>("date");
  let group = $state<FileGroup>("none");
  let limit = $state(PAGE);
  /** Rows whose card is open, by their message's `rowKey`: a reaction or an
   *  edit keeps it open. Raw: looked up by identity. */
  let opened = $state.raw(new Set<ChatMessage>());
  /** Copies picked to remove together, by blob: only while "On this device"
   *  is shown, where every row has one. */
  let picked = $state.raw(new Set<string>());
  let picture = $state.raw<{ url: string; name: string; save: () => void } | null>(null);

  /** Why the list could not be read: said, with a way to try again, never
   *  shown as an empty cache. */
  let loadError = $state<string | null>(null);
  async function reload() {
    try {
      cache = await invoke<{ cap: number; entries: CachedBlob[] }>("file_cache_list");
      loadError = null;
    } catch (e) {
      console.warn("file cache:", e);
      loadError = String(e).replace(/^Error: /, "");
    }
  }
  void reload();

  /** What this device keeps of the servers' emotes and stickers (made again
   *  from their server when next shown, once cleared). */
  let emoteBytes = $state<number | null>(null);
  const emoteCache = () =>
    invoke<number>("emote_cache_size")
      .then((n) => (emoteBytes = n))
      .catch(() => (emoteBytes = null));
  void emoteCache();
  async function clearEmotes() {
    const was = emoteBytes ?? 0;
    try {
      await invoke("emote_cache_clear");
      addNotification(`Cleared ${formatSize(was)} of emotes and stickers from this ${isWeb ? "browser" : "device"}`);
    } catch (e) {
      addNotification(String(e), "error");
    }
    void emoteCache();
  }

  // A load or a send changes what is kept: look again once the bars are
  // still, and at least every few seconds while one keeps moving
  let settle: ReturnType<typeof setTimeout> | undefined;
  let since: number | null = null;
  $effect(() => {
    void $fileProgress;
    clearTimeout(settle);
    since ??= Date.now();
    settle = setTimeout(() => {
      since = null;
      void reload();
    }, Math.max(0, Math.min(1000, since + 5000 - Date.now())));
  });
  onDestroy(() => clearTimeout(settle));

  /** Not a channel the chat keeps behind its 18+ question, unanswered: the
   *  manager shows nothing of what the chat pane would not. A server not open
   *  now cannot say which of its channels are 18+. */
  const allChannels = channels.all();
  function behindGate(r: FileRow): boolean {
    if (r.place.kind !== "channel" || $uiPrefs.nsfw_ok.includes(r.place.server)) return false;
    for (const [id, list] of $allChannels) {
      if (serverKey(id) === r.place.server) return needsNsfwConsent(list.find((c) => c.name === r.place.name), false);
    }
    return false;
  }
  const rows = $derived(fileRows($channelMessages, $dmMessages, cache?.entries ?? []).filter((r) => !behindGate(r)));
  const sections = $derived(arrangeFiles(rows, { filter, sort, group, query, place }));
  const total = $derived(sections.reduce((n, s) => n + s.rows.length, 0));
  /** The sections as drawn: the first `limit` rows. */
  const drawn = $derived.by(() => {
    let left = limit;
    const out: FileSection[] = [];
    for (const s of sections) {
      if (left <= 0) break;
      out.push({ id: s.id, rows: s.rows.slice(0, left) });
      left -= s.rows.length;
    }
    return out;
  });
  const used = $derived(cache?.entries.reduce((n, e) => n + e.bytes, 0) ?? 0);
  const usedShare = $derived(cache?.cap ? Math.min(1, used / cache.cap) : 0);

  // A new view starts at its top, with nothing picked
  $effect(() => {
    void [filter, sort, group, query, place];
    limit = PAGE;
    picked = new Set();
  });
  /** The hashes of the copies shown now. */
  const shownCopies = $derived([...new Set(sections.flatMap((s) => s.rows).flatMap((r) => (r.local === null ? [] : [r.file.hash])))]);
  const allPicked = $derived(shownCopies.length > 0 && shownCopies.every((h) => picked.has(h)));

  function pick(hash: string) {
    const next = new Set(picked);
    if (!next.delete(hash)) next.add(hash);
    picked = next;
  }

  const FILTERS: [FileFilter, string][] = [
    ["all", "All"],
    ["image", "Pictures"],
    ["video", "Videos"],
    ["audio", "Sounds"],
    ["other", "Other"],
    ["local", `On this ${isWeb ? "tab" : "device"}`],
  ];

  const KIND_LABEL: Record<FileKind, string> = { image: "Pictures", video: "Videos", audio: "Sounds", other: "Other files" };

  /** An open server's id for a chat key's `host:port`, else a bookmark's. */
  function serverIdOf(key: string): string | undefined {
    return (
      $openServers.find((s) => serverKey(s) === key) ??
      $savedServers.map((b) => serverId(b.host, b.port)).find((id) => serverKey(id) === key)
    );
  }
  function serverLabel(key: string): string {
    const id = serverIdOf(key);
    return id ? serverName(id, $savedServers) : key;
  }
  function placeLabel(p: ChatPlace): string {
    return p.kind === "dm" ? `@${shortName(p.name)}` : p.name;
  }
  function sectionTitle(s: FileSection): string {
    const r = s.rows[0];
    if (group === "server") return serverLabel(r.place.server);
    if (group === "kind") return KIND_LABEL[r.kind];
    if (group === "conversation") return `${placeLabel(r.place)} · ${serverLabel(r.place.server)}`;
    return "";
  }
  function when(t: number): string {
    return new Date(t).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }
  function about(r: FileRow): string {
    const where =
      group === "conversation" ? [] : group === "server" ? [placeLabel(r.place)] : [placeLabel(r.place), serverLabel(r.place.server)];
    return [shortName(r.msg.username), ...where, when(r.msg.timestamp)].join(" · ");
  }

  function toggle(r: FileRow) {
    const next = new Set(opened);
    if (!next.delete(rowKey(r.msg))) next.add(rowKey(r.msg));
    opened = next;
  }

  /** Save the copy this device keeps; one it does not is saved from its card,
   *  which shows the transfer. */
  async function download(r: FileRow) {
    const id = serverIdOf(r.place.server);
    const op = newOp();
    try {
      const got = await fetchFile(id ?? r.place.server, { channel: 0 }, r.file, op);
      await saveFile(got, r.file.name, sniff(got)?.mime);
    } catch (e) {
      addNotification(`The file could not be saved: ${e}`, "error");
    } finally {
      forgetProgress(op);
    }
  }

  function go(r: FileRow) {
    if (showMessage(r.place, r.msg)) onclose();
  }

  let root = $state<HTMLElement | null>(null);

  /** Remove these blobs from here. The button pressed may go with them: the
   *  focus then goes to its row's first button, or to the list, never out of
   *  Settings. */
  async function remove(hashes: string[], from?: HTMLElement | null) {
    try {
      await invoke("file_cache_remove", { hashes });
    } catch (e) {
      addNotification(`The files could not be removed: ${e}`, "error");
    }
    await reload();
    picked = new Set([...picked].filter((h) => !hashes.includes(h)));
    await tick();
    if (root && !root.contains(document.activeElement)) {
      (from?.isConnected ? from.querySelector<HTMLElement>("button") : null)?.focus() ?? root.focus();
    }
  }

  async function removeAll() {
    const all = cache?.entries ?? [];
    const ok = await confirmAction({
      title: "Remove every file from this device?",
      body:
        `The ${all.length === 1 ? "file" : `${all.length} files`} this ${isWeb ? "tab" : "device"} keeps ` +
        `(${formatSize(used)}) are removed from it. The messages stay. A file loads again from its ` +
        "server while the server still has it, or from a member who does; nobody can load one " +
        "from you any more.",
      confirm: "Remove all",
      danger: true,
    });
    if (ok) await remove(all.map((e) => e.hash));
  }

  async function removePicked(from: HTMLElement | null) {
    const hashes = [...picked];
    if (hashes.length > 1) {
      const size = cache?.entries.filter((e) => picked.has(e.hash)).reduce((n, e) => n + e.bytes, 0) ?? 0;
      const ok = await confirmAction({
        title: `Remove ${hashes.length} files from this ${isWeb ? "tab" : "device"}?`,
        body:
          `The ${hashes.length} files picked (${formatSize(size)}) are removed from this ${isWeb ? "tab" : "device"}. ` +
          "The messages stay. A file loads again from its server while the server still has it, or " +
          "from a member who does; nobody can load one from you any more.",
        confirm: `Remove ${hashes.length}`,
        danger: true,
      });
      if (!ok) return;
    }
    await remove(hashes, from);
  }

  async function setCap(e: Event) {
    const input = e.target as HTMLInputElement;
    const was = Math.round((cache?.cap ?? 0) / MIB);
    const raw = Math.floor(Number(input.value));
    // An emptied field is no answer, and never the smallest cache there is
    if (!input.value.trim() || !Number.isFinite(raw) || raw <= 0) {
      input.value = String(was);
      return;
    }
    const mb = Math.max(CAP_MIN_MB, Math.min(CAP_MAX_MB, raw));
    input.value = String(mb);
    // Said, not silently changed: the field shows another number than typed
    if (mb !== raw) addNotification(`Files kept: ${CAP_MIN_MB} MB at least and 1 TB at most, so ${mb} MB`, "warning");
    if (mb === was) return;
    // Smaller than what is kept: the least recently used go now, so ask
    if (mb * MIB < used) {
      const ok = await confirmAction({
        title: `Keep at most ${mb} MB of files?`,
        body:
          `This device keeps ${formatSize(used)} of files now. The least recently used go from it ` +
          `until ${mb} MB is left. A file loads again from its server while the server still has ` +
          "it, or from a member who does.",
        confirm: `Keep ${mb} MB`,
        danger: true,
      });
      if (!ok) {
        input.value = String(was);
        return;
      }
    }
    try {
      await invoke("set_file_cache_mb", { mb });
    } catch (err) {
      addNotification(`Failed to save setting: ${err}`, "error");
    }
    await reload();
  }
</script>

<div class="fm" bind:this={root} tabindex="-1">
<div class="section">
  <h4>On this {isWeb ? "tab" : "device"}</h4>
  <div
    class="fm-bar"
    role="meter"
    aria-label="Space the files take"
    aria-valuemin="0"
    aria-valuemax={cache?.cap ?? 0}
    aria-valuenow={used}
    aria-valuetext="{formatSize(used)} of {formatSize(cache?.cap ?? 0)}"
  >
    <div style="width: {usedShare * 100}%"></div>
  </div>
  <div class="fm-usage">
    {#if loadError}
      <span class="fm-error" role="alert">Could not read what this {isWeb ? "tab" : "device"} keeps: {loadError}</span>
      <button class="btn btn-ghost" type="button" onclick={() => void reload()}>Try again</button>
    {:else if cache}
      <span class="num">{formatSize(used)} of {formatSize(cache.cap)}</span>
    {:else}
      <span role="status">Reading what this {isWeb ? "tab" : "device"} keeps…</span>
    {/if}
    {#if !isWeb && cache}
      <label class="fm-cap">
        <span>Keep at most</span>
        <input
          type="number"
          min={CAP_MIN_MB}
          max={CAP_MAX_MB}
          value={Math.round(cache.cap / MIB)}
          onchange={setCap}
        />
        <span>MB</span>
      </label>
    {/if}
  </div>
  <p class="fm-hint">
    {#if isWeb}
      Files you send or load are kept in this tab's memory until it closes, the least recently
      used going first.
    {:else}
      Files you send or load are kept here, encrypted, the least recently used going first. A
      file goes with its last message.
    {/if}
    While a copy is here, a member who asks for the file can get it from you.
  </p>
  {#if cache && cache.entries.length > 0}
    <button class="btn btn-danger-outline" type="button" onclick={removeAll}>Remove all from this {isWeb ? "tab" : "device"}…</button>
  {/if}
  {#if emoteBytes !== null}
    <div class="fm-usage">
      <span>Emotes and stickers: <span class="num">{emoteBytes ? formatSize(emoteBytes) : "none kept"}</span></span>
      <button class="btn btn-ghost" type="button" disabled={!emoteBytes} onclick={clearEmotes}>Clear</button>
    </div>
    <p class="fm-hint">
      The servers' emotes and stickers as this {isWeb ? "browser" : "device"} made them safe to show. Cleared, each is fetched
      and made again when it is next shown.
    </p>
  {/if}
  {#if $uiPrefs.emotes_mobile_ok.length}
    <!-- "Always on this server", said in the mobile-data question: here it is undone -->
    <p class="fm-hint">On mobile data, these servers' emotes and stickers download without asking:</p>
    <ul class="fm-mobile">
      {#each $uiPrefs.emotes_mobile_ok as server (server)}
        <li>
          <span>{serverName(server, $savedServers)}</span>
          <button class="btn btn-ghost fm-go" type="button" aria-label="Ask again before downloading {serverName(server, $savedServers)}'s emotes on mobile data" onclick={() => mobileOk(server, false)}
            >Ask again</button
          >
        </li>
      {/each}
    </ul>
  {/if}
</div>

<div class="section">
  <h4>Files in your chats</h4>
  <div class="fm-search">
    <Icon name="search" size={16} />
    <input class="fm-query" type="search" placeholder="Name, sender, words or place" aria-label="Search files" bind:value={query} />
  </div>
  <div class="fm-chips" role="group" aria-label="Show">
    {#if place}
      {@const at = rows.find((r) => `${r.place.kind} ${r.place.key}` === place)?.place}
      <button type="button" class="fm-chip" aria-pressed="true" onclick={() => (place = "")} title="Show every conversation's">
        {at ? placeLabel(at) : "This conversation"} <Icon name="close" size={12} />
      </button>
    {/if}
    {#each FILTERS as [id, label] (id)}
      <button type="button" class="fm-chip" aria-pressed={filter === id} onclick={() => (filter = id)}>{label}</button>
    {/each}
  </div>
  <div class="fm-controls">
    <label>
      <span>Sort by</span>
      <select bind:value={sort}>
        <option value="date">Date</option>
        <option value="used">Recently used</option>
        <option value="size">Size</option>
        <option value="name">Name</option>
        <option value="sender">Sender</option>
      </select>
    </label>
    <label>
      <span>Group by</span>
      <select bind:value={group}>
        <option value="none">Nothing</option>
        <option value="server">Server</option>
        <option value="conversation">Conversation</option>
        <option value="kind">Type</option>
      </select>
    </label>
    <span class="fm-count num" role="status">{total === rows.length ? `${total} ${total === 1 ? "file" : "files"}` : `${total} of ${rows.length}`}</span>
  </div>

  {#if filter === "local" && shownCopies.length > 0}
    <div class="fm-bulk">
      <label class="fm-pick-all">
        <input type="checkbox" checked={allPicked} onchange={() => (picked = allPicked ? new Set() : new Set(shownCopies))} />
        <span>All shown</span>
      </label>
      {#if picked.size > 0}
        <button class="btn btn-danger-outline" type="button" onclick={(e) => removePicked(e.currentTarget.closest<HTMLElement>(".section"))}>
          Remove {picked.size === 1 ? "1 copy" : `${picked.size} copies`}
        </button>
      {/if}
    </div>
  {/if}

  {#if total === 0}
    <p class="fm-hint">{rows.length === 0 ? "No message here carries a file." : "No file matches."}</p>
  {/if}

  {#each drawn as s (s.id)}
    {#if group !== "none"}
      <h5 class="fm-section">{sectionTitle(s)} <span class="num">{sections.find((x) => x.id === s.id)?.rows.length}</span></h5>
    {/if}
    <ul class="fm-list">
      {#each s.rows as r (rowKey(r.msg))}
        {@const open = opened.has(rowKey(r.msg))}
        <li class="fm-row">
          <div class="fm-line">
            {#if filter === "local" && r.local !== null}
              <input class="fm-pick" type="checkbox" checked={picked.has(r.file.hash)} onchange={() => pick(r.file.hash)} aria-label="Pick {r.file.name}" />
            {/if}
            <span class="fm-thumb" aria-hidden="true">
              {#if r.file.px}
                <canvas width={PREVIEW_SIDE} height={PREVIEW_SIDE} use:preview={r.file.px}></canvas>
              {:else}
                <Icon name="file" size={16} />
              {/if}
            </span>
            <button class="fm-main" type="button" aria-expanded={open} onclick={() => toggle(r)} title="{open ? 'Hide' : 'Show'} {r.file.name}">
              <span class="fm-name">{r.file.name}</span>
              <span class="fm-about">
                {about(r)}{#if r.local !== null}<span class="fm-local">{` · on this ${isWeb ? "tab" : "device"}`}</span>{/if}
              </span>
            </button>
            <span class="fm-size num">{formatSize(r.file.size)}</span>
            <span class="fm-actions">
              <button class="btn btn-ghost fm-go" type="button" onclick={() => go(r)} title="Go to message" aria-label="Go to the message with {r.file.name}">Go to</button>
              {#if r.local !== null}
                <button class="icon-btn" type="button" onclick={() => download(r)} title="Download" aria-label="Download {r.file.name}">
                  <Icon name="download" size={16} />
                </button>
                <button
                  class="icon-btn"
                  type="button"
                  onclick={(e) => remove([r.file.hash], e.currentTarget.closest("li"))}
                  title="Remove copy"
                  aria-label="Remove {r.file.name} from this {isWeb ? 'tab' : 'device'}"
                >
                  <Icon name="trash" size={16} />
                </button>
              {/if}
            </span>
          </div>
          {#if open}
            {@const id = serverIdOf(r.place.server)}
            <div class="fm-card">
              <FileCard
                file={r.file}
                server={id ?? r.place.server}
                conv={id && $openServers.includes(id) ? fileConvAt(id, r.place) : null}
                auto
                onopen={(p) => (picture = p)}
                ongone={(url) => {
                  if (picture?.url === url) picture = null;
                }}
              />
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/each}

  {#if total > limit}
    <button class="btn-ghost" type="button" onclick={() => (limit += PAGE)}>Show more ({total - limit} left)</button>
  {/if}
</div>

</div>

{#if picture}
  <Lightbox url={picture.url} name={picture.name} onsave={picture.save} onclose={() => (picture = null)} />
{/if}

<style>
  .fm:focus {
    outline: none;
  }
  .section {
    margin-bottom: 20px;
  }
  h4 {
    font-size: var(--fs-sm);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }
  .fm-bar {
    height: 6px;
    border-radius: 3px;
    background: var(--border);
    overflow: hidden;
  }
  .fm-bar div {
    height: 100%;
    background: var(--text-secondary);
  }
  .fm-usage {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin: 8px 0;
    font-size: var(--fs-body);
  }
  .fm-cap {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  /* Seven digits (1 TB in MB) and the field's own padding */
  .fm-cap input {
    width: 12ch;
    padding: 6px 8px;
  }
  .fm-hint {
    margin: 0 0 8px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-search {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
    color: var(--text-secondary);
  }
  /* The look of Settings' selects (SettingsPanel), one row with them */
  .fm-query {
    flex: 1;
    min-width: 0;
    padding: 8px 12px;
    font: inherit;
    font-size: var(--fs-md);
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
  }
  .fm-query:focus {
    outline: none;
    border-color: var(--focus-ring);
  }
  .fm-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-bottom: 8px;
  }
  /* SearchPane's scope buttons: on is ink, never the live mint */
  .fm-chip {
    padding: 4px 10px;
    min-height: 32px;
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }
  @media (pointer: coarse) {
    .fm-chip,
    .fm-query,
    .fm-controls select,
    .fm-cap input,
    .fm-main {
      min-height: var(--hit);
    }
  }
  .fm-error {
    color: var(--danger);
  }
  .fm-mobile {
    list-style: none;
    margin: 0 0 8px;
    padding: 0;
  }
  .fm-mobile li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: var(--fs-body);
  }
  .fm-chip[aria-pressed="true"] {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .fm-controls {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 16px;
    margin-bottom: 8px;
  }
  .fm-controls label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-controls select {
    width: auto;
  }
  .fm-count {
    margin-left: auto;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-bulk {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 16px;
    margin-bottom: 4px;
  }
  .fm-pick-all {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-section {
    margin: 12px 0 4px;
    font-size: var(--fs-body);
    font-weight: 600;
    color: var(--text-primary);
  }
  .fm-section .num {
    font-weight: 400;
    color: var(--text-secondary);
  }
  .fm-list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .fm-row {
    border-bottom: 1px solid var(--border);
    min-width: 0;
  }
  /* One line of a row: preview, name over where it is from, size, actions.
     On a narrow screen the actions go under it */
  .fm-line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 2px 8px;
    padding: 2px 0;
    min-width: 0;
  }
  .fm-thumb {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 24px;
    height: 24px;
    color: var(--text-secondary);
  }
  .fm-thumb canvas {
    width: 24px;
    height: 24px;
    border-radius: var(--r-sm);
  }
  .fm-main {
    flex: 1 1 180px;
    min-width: 0;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 1px;
    padding: 4px 6px;
    background: none;
    border: none;
    border-radius: var(--r-sm);
    color: inherit;
    text-align: left;
    cursor: pointer;
  }
  .fm-main:hover {
    background: var(--bg-hover);
  }
  .fm-name,
  .fm-about {
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .fm-name {
    font-size: var(--fs-body);
    color: var(--text-primary);
  }
  .fm-size,
  .fm-about {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-size {
    white-space: nowrap;
  }
  .fm-local {
    color: var(--text-primary);
  }
  .fm-actions {
    display: flex;
    align-items: center;
    gap: 2px;
    margin-left: auto;
  }
  .fm-actions .icon-btn {
    width: var(--icon-btn-size-sm);
    height: var(--icon-btn-size-sm);
    background: transparent;
  }
  .fm-actions .icon-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .fm-go {
    padding: 4px 8px;
    font-size: var(--fs-sm);
    font-weight: 400;
  }
  @media (pointer: coarse) {
    .fm-actions .icon-btn {
      width: var(--hit);
      height: var(--hit);
    }
  }
  .fm-card {
    padding: 4px 0 8px 32px;
  }
</style>
