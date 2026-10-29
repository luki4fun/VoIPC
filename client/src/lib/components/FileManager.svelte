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
  import { showMessage } from "../stores/channel-ui.js";
  import { fileConvAt, fileProgress } from "../files.js";
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
  import { formatSize } from "../file-rules.js";
  import { needsNsfwConsent } from "../channel-post-rules.js";
  import type { ChatPlace } from "../chat-rules.js";
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
  let filter = $state<FileFilter>("all");
  let sort = $state<FileSort>("date");
  let group = $state<FileGroup>("none");
  let limit = $state(PAGE);
  /** Rows whose card is open, by their message. Raw: looked up by identity. */
  let opened = $state.raw(new Set<ChatMessage>());
  let picture = $state.raw<{ url: string; name: string; save: () => void } | null>(null);

  async function reload() {
    try {
      cache = await invoke<{ cap: number; entries: CachedBlob[] }>("file_cache_list");
    } catch (e) {
      console.warn("file cache:", e);
      cache = { cap: 0, entries: [] };
    }
  }
  void reload();

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
  const sections = $derived(arrangeFiles(rows, { filter, sort, group }));
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

  // A new view starts at its top
  $effect(() => {
    void [filter, sort, group];
    limit = PAGE;
  });

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
    if (!next.delete(r.msg)) next.add(r.msg);
    opened = next;
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
    <span class="num">{formatSize(used)} of {formatSize(cache?.cap ?? 0)}</span>
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
</div>

<div class="section">
  <h4>Files in your chats</h4>
  <div class="fm-controls">
    <label>
      <span>Show</span>
      <select bind:value={filter}>
        <option value="all">All</option>
        <option value="image">Pictures</option>
        <option value="video">Videos</option>
        <option value="audio">Sounds</option>
        <option value="other">Other files</option>
        <option value="local">On this {isWeb ? "tab" : "device"}</option>
      </select>
    </label>
    <label>
      <span>Sort by</span>
      <select bind:value={sort}>
        <option value="date">Date</option>
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
  </div>

  {#if total === 0}
    <p class="fm-hint">{rows.length === 0 ? "No message here carries a file." : "No file matches."}</p>
  {/if}

  {#each drawn as s (s.id)}
    {#if group !== "none"}
      <h5 class="fm-section">{sectionTitle(s)} <span class="num">{sections.find((x) => x.id === s.id)?.rows.length}</span></h5>
    {/if}
    <ul class="fm-list">
      {#each s.rows as r (r.msg)}
        {@const open = opened.has(r.msg)}
        <li class="fm-row">
          <div class="fm-head">
            <Icon name="file" size={16} />
            <span class="fm-name" title={r.file.name}>{r.file.name}</span>
            <span class="fm-size num">{formatSize(r.file.size)}</span>
          </div>
          <div class="fm-about">
            {about(r)}{#if r.local !== null}<span class="fm-local"> · on this {isWeb ? "tab" : "device"}</span>{/if}
          </div>
          <div class="fm-actions">
            <button class="btn-ghost" type="button" aria-expanded={open} onclick={() => toggle(r)} aria-label="{open ? 'Hide' : 'Show'} {r.file.name}">{open ? "Hide" : "Show"}</button>
            <button class="btn-ghost" type="button" onclick={() => go(r)} aria-label="Go to the message with {r.file.name}">Go to message</button>
            {#if r.local !== null}
              <button
                class="btn-ghost"
                type="button"
                onclick={(e) => remove([r.file.hash], e.currentTarget.closest("li"))}
                aria-label="Remove {r.file.name} from this {isWeb ? 'tab' : 'device'}"
              >Remove copy</button>
            {/if}
          </div>
          {#if open}
            {@const id = serverIdOf(r.place.server)}
            <FileCard
              file={r.file}
              server={id ?? r.place.server}
              conv={id && $openServers.includes(id) ? fileConvAt(id, r.place) : null}
              onopen={(p) => (picture = p)}
              ongone={(url) => {
                if (picture?.url === url) picture = null;
              }}
            />
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
  .fm-cap input {
    width: 9ch;
  }
  .fm-hint {
    margin: 0 0 8px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-controls {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 16px;
    margin-bottom: 12px;
  }
  .fm-controls label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-section {
    margin: 12px 0 6px;
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
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    min-width: 0;
  }
  .fm-head {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-secondary);
    min-width: 0;
  }
  .fm-name {
    flex: 1;
    min-width: 0;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .fm-size,
  .fm-about {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .fm-about {
    margin: 2px 0 4px 24px;
    overflow-wrap: anywhere;
  }
  .fm-local {
    color: var(--text-primary);
  }
  .fm-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-left: 18px;
  }
</style>
