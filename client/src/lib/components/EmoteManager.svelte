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
  import { emoteLimits, emoteSets, emoteUrls, pendingImport, urlKey } from "../stores/emotes.js";
  import { savedServers } from "../stores/settings.js";
  import { serverId } from "../stores/servers.js";
  import { addNotification } from "../stores/notifications.js";
  import { confirmAction } from "../stores/confirm.js";
  import { nameFrom, uniqueName, type Emote as Item } from "../emote-rules.js";
  import {
    addEmote,
    fetchSource,
    isArchive,
    prepareEmote,
    readPack,
    moveEmotes,
    removeEmotes,
    seedEmote,
    emoteFile,
    renameEmote,
    setStickers,
    type Made,
    type Prepared,
  } from "../emote-import.js";
  import { isAndroidApp, isWeb } from "../stores/platform.js";
  import { pictureUrl } from "../media.js";
  import { fold } from "../search-rules.js";
  import { toHex } from "../hex.js";
  import { formatSize } from "../file-rules.js";
  import { saveFile } from "../files.js";
  import { storedZip } from "../zip.js";
  import Emote from "./chat/Emote.svelte";
  import Icon from "./Icons.svelte";

  const server = get(serverAddress);
  const NAME = /^[a-z0-9_]{2,30}$/;
  const HIDDEN = /[\p{Cc}\u200B-\u200F\u061C\u202A-\u202E\u2060-\u2069\uFEFF]/u;
  const byteLength = (s: string) => new TextEncoder().encode(s).length;
  /** voipc-protocol `valid_emote_pack`: one line, no control, invisible or
   *  direction characters, 32 characters and 64 bytes at most. Why not, or "". */
  const packProblem = (p: string) =>
    HIDDEN.test(p)
      ? "A pack's name cannot hold control, invisible or text-direction characters"
      : [...p].length > 32
        ? "A pack's name is 32 characters at most"
        : byteLength(p) > 64
          ? "A pack's name is 64 bytes at most: fewer letters from outside a-z"
          : p.trim() !== p
            ? "A pack's name cannot start or end with a space"
            : "";
  /** A 7TV set's or a zip's title made a name `packProblem` takes. */
  function packFrom(title: string): string {
    let out = "";
    let count = 0;
    for (const c of [...title].filter((c) => !HIDDEN.test(c)).join("").trim()) {
      if (count === 32 || byteLength(out + c) > 64) break;
      out += c;
      count++;
    }
    return out.trim();
  }
  const taken = (name: string) => $emoteSets.emotes.some((e) => e.name === name);
  const why = (e: unknown) => String(e).replace(/^Error: /, "");

  let filter = $state("");
  const shown = $derived($emoteSets.emotes.filter((e) => !removing.has(e.name) && fold(`${e.name} ${e.pack}`).includes(fold(filter))));
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

  function switchStickers(e: Event) {
    const box = e.target as HTMLInputElement;
    setStickers(server, box.checked).catch((err) => {
      addNotification(`Stickers stay ${$emoteSets.stickers ? "on" : "off"}: ${why(err)}`, "error");
      box.checked = $emoteSets.stickers;
    });
  }

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

  // ── Packs ─────────────────────────────────────────────────────────────────

  /** The section whose pack is being renamed, and the new name. */
  let renamingPack = $state<string | null>(null);
  let newPack = $state("");

  async function finishPackRename(from: string, names: string[], save: boolean) {
    // Once: the box's blur, as it goes, comes after Enter or Escape finished it
    if (renamingPack === null) return;
    renamingPack = null;
    const to = newPack.trim();
    if (!save || to === from) return;
    const problem = packProblem(to);
    if (problem) return addNotification(problem, "error");
    await moveEmotes(server, names, to, null).catch((err) => addNotification(why(err), "error"));
  }

  let moveTo = $state("");
  /** What is picked, into the pack `moveTo` (none, if it is empty). */
  async function movePicked() {
    const to = moveTo.trim();
    const problem = packProblem(to);
    if (problem) return addNotification(problem, "error");
    await moveEmotes(server, pickedShown, to, null)
      .then(() => {
        picked = new Set();
        moveTo = "";
      })
      .catch((err) => addNotification(why(err), "error"));
  }

  /** A file's kind by its first bytes, for its name in an export. */
  const extOf = (b: Uint8Array) => (b[0] === 0x89 ? "png" : b[0] === 0x47 ? "gif" : b[0] === 0x52 ? "webp" : "jpg");

  let exporting = $state<string | null>(null);
  /** A section's files as the server keeps them, as one .zip: a backup, or
   *  the way to another server (this importer reads it back, pack name and all). */
  async function exportPack(key: string, label: string, list: Item[]) {
    exporting = key;
    try {
      const files: { name: string; bytes: Uint8Array }[] = [];
      for (const e of list) {
        const bytes = await emoteFile(server, e.hash);
        files.push({ name: `${e.name}.${extOf(bytes)}`, bytes });
      }
      if (label) files.push({ name: "title.txt", bytes: new TextEncoder().encode(label) });
      await saveFile(storedZip(files), `${label || (list[0]?.sticker ? "stickers" : "emotes")}.zip`, "application/zip");
    } catch (err) {
      addNotification(`The pack could not be exported: ${why(err)}`, "error");
    } finally {
      exporting = null;
    }
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
    // Gone from here at once: the server's list follows a moment later
    removing = new Set([...removing, ...names]);
    picked = new Set([...picked].filter((n) => !names.includes(n)));
    await removeEmotes(server, names).catch((err) => {
      removing = new Set([...removing].filter((n) => !names.includes(n)));
      addNotification(why(err), "error");
    });
  }

  /** Removed or being made the other kind, until the server's next list. */
  let removing = $state.raw(new Set<string>());
  let switching = $state.raw(new Set<string>());
  $effect(() => {
    void $emoteSets;
    removing = new Set();
    switching = new Set();
  });

  /** An emote made a sticker, or back: the server has its file, so only the
   *  list changes. */
  async function switchKind(e: Item) {
    if (switching.has(e.name)) return;
    switching = new Set([...switching, e.name]);
    await moveEmotes(server, [e.name], null, !e.sticker).catch((err) => {
      switching = new Set([...switching].filter((n) => n !== e.name));
      addNotification(`:${e.name}: stays ${e.sticker ? "a sticker" : "an emote"}: ${why(err)}`, "error");
    });
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
  /** Set aside, saying why; its file is not kept. */
  const aside = (key: number, note: string) => set(key, { status: "skipped", include: false, note, bytes: undefined });
  const skippedRow = (source: string, note: string): Row => ({ key: nextKey++, source, name: "", status: "skipped", include: false, note });
  const takenFor = (name: string, key: number) => taken(name) || rows.some((r) => r.key !== key && r.include && r.name === name);
  const nameProblem = (r: Row) =>
    !NAME.test(r.name) ? "2 to 30 of a-z, 0-9 and _" : takenFor(r.name, r.key) ? "This name is taken" : "";
  /** Ready to go, or failed and so to try again (under another name). */
  const editable = (r: Row) => r.status === "ready" || r.status === "failed";
  const ready = $derived(rows.filter((r) => r.include && editable(r) && !nameProblem(r)));
  /** What the server's emotes take of what it allows. */
  const used = $derived($emoteSets.emotes.reduce((n, e) => n + e.len, 0));
  /** Of what is ready, in order, what still fits the server's total and its
   *  count; the rest is marked and not sent. */
  const fitting = $derived.by(() => {
    const limits = $emoteLimits;
    if (!limits) return new Set<number>();
    let [bytes, items] = [limits.max_total_bytes - used, limits.max_items - $emoteSets.emotes.length];
    const ok = new Set<number>();
    for (const r of ready) {
      const n = r.prepared!.upload.length;
      if (n > bytes || items < 1) continue;
      ok.add(r.key);
      bytes -= n;
      items--;
    }
    return ok;
  });
  const allIn = $derived(rows.filter(editable).every((r) => r.include));
  const reading = $derived(rows.filter((r) => r.status === "reading").length);
  /** "Reading 37 of 300 · 30 ready · 7 set aside". */
  const summary = $derived.by(() => {
    const count = (s: Row["status"]) => rows.filter((r) => r.status === s).length;
    const parts: [number, string][] = [
      [count("ready"), "ready"],
      [count("uploading"), "being added"],
      [count("done"), "added"],
      [count("failed"), "not added"],
      [count("skipped"), "set aside"],
    ];
    return [...(reading ? [`Reading ${rows.length - reading} of ${rows.length}`] : []), ...parts.filter(([n]) => n).map(([n, what]) => `${n} ${what}`)].join(" · ");
  });

  /** Whether the panel may close: asked first while what is listed is not
   *  all added or set aside, since closing drops it and stops adding. */
  export async function mayClose(): Promise<boolean> {
    const left = rows.filter((r) => r.status !== "done" && r.status !== "skipped").length;
    if (!left) return true;
    return confirmAction({
      title: "Close without adding?",
      body: busy
        ? `Adding is not finished: ${left} not added yet. Closing stops it; what the server has already stays.`
        : `${left} listed here ${left === 1 ? "is" : "are"} not added to the server. Closing drops the list.`,
      confirm: "Close",
      danger: true,
    });
  }

  /** `key`'s upload and preview, for the kind chosen now. */
  async function make(key: number, bytes: Uint8Array, gen: number) {
    const limits = get(emoteLimits.peek(server));
    if (!limits) return aside(key, "This server keeps no emotes");
    const sticker = asSticker;
    try {
      const p = await prepareEmote(bytes, sticker, sticker ? limits.max_sticker_bytes : limits.max_emote_bytes);
      const hash = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", p.upload as Uint8Array<ArrayBuffer>)));
      const row = rows.find((r) => r.key === key);
      if (gen !== generation || !row) return;
      // Switched to the other kind meanwhile: made again for that one
      if (sticker !== asSticker) return make(key, bytes, gen);
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
      if (gen !== generation) return;
      if (sticker !== asSticker) return make(key, bytes, gen);
      aside(key, why(e));
    }
  }

  /** A pack's pictures, listed in place of `key` (else at the end) as
   *  "Reading…" all at once, so Add waits for every one; then made in turn. */
  async function addPack(got: { skipped: { name: string; why: string }[]; entries: { name: string; bytes: Uint8Array }[] }, gen: number, key?: number) {
    if (gen !== generation) return;
    const keys = got.entries.map(() => nextKey++);
    const added: Row[] = [
      ...got.skipped.map((s) => skippedRow(s.name, s.why)),
      ...got.entries.map((e, i): Row => ({ key: keys[i], source: e.name, name: "", status: "reading", note: "", include: true, bytes: e.bytes })),
    ];
    rows = key === undefined ? [...rows, ...added] : rows.flatMap((r) => (r.key === key ? added : [r]));
    for (const [i, e] of got.entries.entries()) {
      if (gen !== generation) return;
      await make(keys[i], e.bytes, gen);
    }
  }

  /** Emotes or stickers: what is listed is made again for that kind. */
  async function setKind(sticker: boolean) {
    if (sticker === asSticker || busy) return;
    asSticker = sticker;
    const gen = generation;
    // What is still reading comes out as the kind chosen by then (`make`); the
    // rest is all "Reading…" at once, so none goes up as the kind it was before
    const again = new Set(rows.filter((r) => r.bytes && editable(r)).map((r) => r.key));
    rows = rows.map((r) => (again.has(r.key) ? { ...r, status: "reading", note: "" } : r));
    for (const key of again) {
      if (gen !== generation) return;
      const bytes = rows.find((r) => r.key === key)?.bytes;
      if (bytes) await make(key, bytes, gen);
    }
  }

  function includeAll(on: boolean) {
    rows = rows.map((r) => (editable(r) ? { ...r, include: on } : r));
  }

  /** voipc-media: the most a picture (`max_input`) and a pack (`MAX_PACK_BYTES`) may be. */
  const MAX_PICTURE = 16 << 20;
  const MAX_PACK = 200 << 20;

  async function addFiles(files: Iterable<File>) {
    const gen = generation;
    // Listed at once, as the rest of the import is: Add waits for them
    const list = [...files].map((f) => ({ f, key: nextKey++ }));
    rows = [...rows, ...list.map(({ f, key }): Row => ({ key, source: f.name, name: "", status: "reading", note: "", include: true }))];
    for (const { f, key } of list) {
      if (gen !== generation) return;
      let bytes: Uint8Array;
      try {
        // Its first bytes say whether it is a pack; what is too big is never read whole
        const zip = isArchive(new Uint8Array(await f.slice(0, 5).arrayBuffer()));
        if (f.size > (zip ? MAX_PACK : MAX_PICTURE)) {
          aside(key, zip ? "Too big for a pack: 200 MiB at most" : "Too big to be an emote or sticker: 16 MiB at most");
          continue;
        }
        bytes = new Uint8Array(await f.arrayBuffer());
      } catch (e) {
        aside(key, `Could not be read: ${why(e)}`);
        continue;
      }
      if (!isArchive(bytes)) {
        set(key, { bytes });
        await make(key, bytes, gen);
        continue;
      }
      try {
        const p = await readPack(bytes);
        if (gen !== generation) return;
        if (!pack) pack = packFrom(p.title ?? f.name.replace(/\.(zip|wastickers)$/i, ""));
        await addPack(p, gen, key);
      } catch (e) {
        aside(key, why(e));
      }
    }
  }

  // Another server this app is connected to: its emotes (or stickers) as
  // they are there, fetched like any member fetches them, into the importer
  const allSets = emoteSets.all();
  const otherServers = $derived(
    [...$allSets]
      .filter(([id, set]) => id !== server && set.emotes.some((e) => e.sticker === asSticker))
      .map(([id, set]) => ({
        id,
        name: $savedServers.find((b) => serverId(b.host, b.port) === id)?.name ?? id,
        count: set.emotes.filter((e) => e.sticker === asSticker).length,
      })),
  );
  let copyFrom = $state("");
  let copying = $state(false);
  async function copyServer() {
    const from = copyFrom;
    const gen = generation;
    copying = true;
    const got: { skipped: { name: string; why: string }[]; entries: { name: string; bytes: Uint8Array }[] } = { skipped: [], entries: [] };
    for (const e of get(emoteSets.peek(from)).emotes.filter((e) => e.sticker === asSticker)) {
      if (gen !== generation) break;
      try {
        got.entries.push({ name: e.name, bytes: await emoteFile(from, e.hash) });
      } catch (err) {
        got.skipped.push({ name: e.name, why: why(err) });
      }
    }
    copying = false;
    await addPack(got, gen);
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
      if (!pack && got.title) pack = packFrom(got.title);
      await addPack(got, gen);
    } catch (e) {
      addNotification(why(e), "error");
    } finally {
      // Kept nowhere: not even in this field
      token = "";
      fetching = false;
    }
  }

  // A chat picture an admin chose to make an emote or sticker of
  $effect(() => {
    const p = $pendingImport;
    if (!p || p.server !== server) return;
    pendingImport.set(null);
    void addFiles([new File([p.bytes as Uint8Array<ArrayBuffer>], p.name)]);
  });

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
    const problem = packProblem(pack.trim());
    if (problem) return addNotification(problem, "error");
    busy = true;
    const gen = generation;
    const todo = ready.filter((r) => fitting.has(r.key));
    let next = 0;
    const one = async () => {
      // Closed (or cleared): what is not on its way yet stays here
      while (next < todo.length && gen === generation) {
        const r = todo[next++];
        set(r.key, { status: "uploading" });
        try {
          await addEmote(server, r.name, asSticker, pack.trim(), r.prepared!.upload, r.prepared!.w, r.prepared!.h);
          // Shown here at once, from what was just made of it
          void seedEmote(r.prepared!, asSticker).catch(() => {});
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
    <input type="checkbox" checked={$emoteSets.stickers} onchange={switchStickers} />
    <span>Members may send stickers</span>
  </label>
  <p class="em-hint">
    {$emoteSets.emotes.length - stickerCount} emotes, {stickerCount} stickers. They are stored on this server unencrypted, visible
    to everyone who joins; every member's app makes its own safe copy of each before showing it.
  </p>
  {#if $emoteLimits}
    <div class="em-quota">
      <meter min="0" max={$emoteLimits.max_total_bytes} value={used} aria-label="Space the server's emotes take"></meter>
      <span>
        {formatSize(used)} of {formatSize($emoteLimits.max_total_bytes)} · {$emoteSets.emotes.length} of {$emoteLimits.max_items}
      </span>
    </div>
  {/if}

  {#if $emoteSets.emotes.length}
    <div class="em-tools">
      <input class="em-input" type="search" placeholder="Search" aria-label="Search this server's emotes" bind:value={filter} />
      {#if pickedShown.length}
        <input class="em-input em-move" placeholder="A pack (empty: none)" aria-label="Pack to move the picked ones to" bind:value={moveTo} />
        <button class="btn btn-secondary" type="button" onclick={movePicked}>Move {pickedShown.length} to it</button>
        <button class="btn btn-danger-outline" type="button" onclick={() => removeAll(pickedShown, pickedShown.length === 1 ? `:${pickedShown[0]}:` : `${pickedShown.length} emotes and stickers`)}>
          Remove {pickedShown.length}
        </button>
      {/if}
    </div>
    <div class="em-list">
      {#each sections as s (s.key)}
        <div class="em-section">
          {#if renamingPack === s.key}
            <!-- svelte-ignore a11y_autofocus -->
            <input
              class="em-input em-name"
              bind:value={newPack}
              autofocus
              aria-label="New name for the pack {s.pack}"
              onkeydown={(ev) => {
                if (ev.key === "Enter") finishPackRename(s.pack, s.list.map((e) => e.name), true);
                if (ev.key === "Escape") { ev.stopPropagation(); finishPackRename(s.pack, [], false); }
              }}
              onblur={() => finishPackRename(s.pack, s.list.map((e) => e.name), true)}
            />
          {:else}
            <span>{s.sticker ? "Stickers" : "Emotes"}{s.pack ? ` · ${s.pack}` : ""}</span>
          {/if}
          <span class="em-count num">{s.list.length}</span>
          {#if s.pack}
            <button class="btn btn-ghost em-small" type="button" onclick={() => { renamingPack = s.key; newPack = s.pack; }}>Rename</button>
          {/if}
          <button class="btn btn-ghost em-small" type="button" disabled={exporting !== null} onclick={() => exportPack(s.key, s.pack, s.list)}
            >{exporting === s.key ? "Exporting…" : "Export"}</button
          >
          {#if s.pack}
            <button class="btn btn-ghost em-small" type="button" onclick={() => removeAll(s.list.map((e) => e.name), `the pack "${s.pack}"`)}>Remove pack</button>
          {/if}
        </div>
        <ul>
          {#each s.list as e (e.name)}
            {@const failed = $emoteUrls.get(urlKey(e.hash, e.sticker))?.error}
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
              {#if failed}<span class="em-bad" title="This device could not make it: {failed}">Not shown</span>{/if}
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
      <!-- Android picks no folder and takes no drop -->
      {#if !isAndroidApp}
        <label class="btn btn-secondary">
          A folder…
          <input type="file" hidden webkitdirectory onchange={pickedFiles} />
        </label>
      {/if}
    </div>
    {#if isAndroidApp}
      <p class="em-hint">A folder of them (Discord, Slack, TeamSpeak) goes as a .zip of it; a WhatsApp .wastickers or a Telegram pack a bot saved as a .zip, as it is: names come from the files.</p>
    {:else}
      <p class="em-hint">Or drop them here. A Discord, Slack or TeamSpeak folder, a WhatsApp .wastickers, a Telegram pack a bot saved as a .zip: names come from the files.</p>
    {/if}
    {#if otherServers.length}
      <div class="em-heading">Or copy them from another server</div>
      <div class="em-actions">
        <select bind:value={copyFrom} aria-label="The server to copy from">
          <option value="">Choose a server…</option>
          {#each otherServers as o (o.id)}<option value={o.id}>{o.name} ({o.count} {asSticker ? "stickers" : "emotes"})</option>{/each}
        </select>
        <button class="btn btn-secondary" type="button" disabled={copying || !copyFrom} onclick={copyServer}>{copying ? "Copying…" : "Copy"}</button>
      </div>
    {/if}
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
        placeholder={source === "7tv" ? "A 7TV profile's, set's or emote's address (7tv.app/users/…, /emote-sets/…, /emotes/…)" : source === "bttv" ? "The Twitch user id (a number)" : "The Discord server's id (a number)"}
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
            <span class="em-meta">
              {r.status === "reading" ? "Reading…" : r.status === "uploading" ? "Adding…" : r.status === "done" ? "Added" : ""}
              {r.note}
              {#if ready.includes(r) && !fitting.has(r.key)}Will not fit: the server's emotes are full.{/if}
            </span>
          </li>
        {/each}
      </ul>
      <p class="em-hint" role="status">{summary}</p>
      <div class="em-actions">
        <button class="btn btn-ghost" type="button" disabled={busy} onclick={clear}>Clear</button>
        <button class="btn btn-primary" type="button" disabled={busy || reading > 0 || fitting.size === 0} onclick={upload}>
          {busy ? "Adding…" : `Add ${fitting.size}`}
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
    min-height: var(--hit);
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
  .em-bad {
    flex-shrink: 0;
    padding: 1px 5px;
    border: 1px solid var(--warning);
    border-radius: 3px;
    font-size: var(--fs-micro);
    color: var(--warning);
  }
  .em-move {
    flex: 0 1 180px;
  }
  .em-quota {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
  .em-quota meter {
    flex: 1;
    max-width: 200px;
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
    min-height: var(--hit);
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
