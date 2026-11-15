<script lang="ts">
  // The admin panel's Channels tab (1.9): channels that stay, their categories and
  // order, and the one newcomers land in. Channels from channels.json can be placed
  // here, and only the file renames or removes them. A channel's options and gate
  // are in its own settings, as for any channel.

  import { channelLayout, channels } from "../stores/channels.js";
  import { adminOp } from "../stores/admin-ui.js";
  import { serverAddress } from "../stores/connection.js";
  import { confirmAction } from "../stores/confirm.js";
  import { can } from "../stores/powers.js";
  import { olderRelay } from "../stores/relay.js";
  import { moves } from "../relay-rules.js";
  import { channelDeleteWords } from "../move-rules.js";
  import { movedBy, movedInCategory } from "../channel-groups.js";
  import Icon from "./Icons.svelte";
  import type { ChannelPlace } from "../types.js";

  let newName = $state("");
  let newText = $state(true);
  /** Apps follow it by themselves, as following costs nothing until someone writes. */
  let newFollowed = $state(true);
  let newCategory = $state<number | null>(null);
  let categoryName = $state("");
  /** The channel being renamed. */
  let editing = $state<{ id: number; name: string; description: string } | null>(null);

  const info = (id: number) => $channels.find((c) => c.channel_id === id);
  const rows = (category: number | null) => $channelLayout.channels.filter((p) => p.category === category);

  function sendLayout(places: ChannelPlace[], categories = $channelLayout.categories.map((c) => c.id)) {
    void adminOp({
      LayoutSet: { categories, channels: places.map((p): [number, number | null] => [p.channel_id, p.category]) },
    });
  }

  function create() {
    const name = newName.trim();
    if (!name) return;
    void adminOp({
      ChannelSave: { id: null, name, description: "", text: newText, auto_join: newText && newFollowed, category: newCategory, gate: null },
    });
    newName = "";
  }

  function toggleFollowed(id: number) {
    const c = info(id);
    if (!c) return;
    const category = $channelLayout.channels.find((p) => p.channel_id === id)?.category ?? null;
    void adminOp({
      ChannelSave: { id, name: c.name, description: c.description, text: c.text, auto_join: !c.auto_join, category, gate: null },
    });
  }

  function saveEdit() {
    const e = editing;
    const c = e && info(e.id);
    if (!e || !c) return;
    const category = $channelLayout.channels.find((p) => p.channel_id === e.id)?.category ?? null;
    void adminOp({
      ChannelSave: { id: e.id, name: e.name, description: e.description, text: c.text, auto_join: c.auto_join, category, gate: null },
    });
    editing = null;
  }

  async function remove(id: number) {
    const name = info(id)?.name ?? "this channel";
    // The server on screen now: ids are per server, and the view may move during the question
    const server = $serverAddress;
    const yes = await confirmAction({
      title: `Delete #${name}?`,
      body: channelDeleteWords(moves($olderRelay?.protocol ?? null), $can("*")),
      confirm: "Delete it",
      danger: true,
    });
    if (yes) void adminOp({ ChannelDelete: { id } }, null, server);
  }

  function addCategory() {
    const name = categoryName.trim();
    if (!name) return;
    void adminOp({ CategorySave: { id: null, name } });
    categoryName = "";
  }

  /** The category being renamed, here rather than in a prompt: a webview may have none. */
  let renaming = $state<{ id: number; name: string } | null>(null);

  function renameCategory() {
    const name = renaming?.name.trim();
    if (renaming && name) void adminOp({ CategorySave: { id: renaming.id, name } });
    renaming = null;
  }

  async function removeCategory(id: number, name: string) {
    const server = $serverAddress;
    const yes = await confirmAction({
      title: `Delete the category ${name}?`,
      body: "Its channels stay, outside any category.",
      confirm: "Delete it",
      danger: true,
    });
    if (yes) void adminOp({ CategoryDelete: { id } }, null, server);
  }
</script>

{#snippet channelRow(place: ChannelPlace)}
  {@const c = info(place.channel_id)}
  {#if c}
    {#if editing?.id === place.channel_id}
      <form class="edit" onsubmit={(e) => { e.preventDefault(); saveEdit(); }}>
        <input class="admin-input" aria-label="Name" bind:value={editing.name} maxlength="64" />
        <input class="admin-input" aria-label="Description" placeholder="Description" bind:value={editing.description} maxlength="256" />
        <button type="submit" class="btn btn-primary">Save</button>
        <button type="button" class="btn btn-ghost" onclick={() => (editing = null)}>Cancel</button>
      </form>
    {:else}
      <div class="row" data-channel={c.name}>
        <span class="channel-name" title={c.description}>
          <Icon name={c.text ? "hash" : "volume"} size={14} />
          {c.name}
          {#if place.welcome}<span class="pill">welcome</span>{/if}
          {#if !place.kept}<span class="pill" title="From channels.json: only that file renames or removes it">file</span>{/if}
          {#if !place.kept && c.text && c.auto_join}<span class="pill" title="Apps follow it by themselves. From channels.json: only that file changes this">auto-join</span>{/if}
        </span>
        <select
          class="admin-select"
          aria-label="Category of {c.name}"
          value={place.category}
          onchange={(e) => {
            const v = e.currentTarget.value;
            const to = v === "" ? null : Number(v);
            sendLayout($channelLayout.channels.map((p) => (p.channel_id === place.channel_id ? { ...p, category: to } : p)));
          }}
        >
          <option value={null}>No category</option>
          {#each $channelLayout.categories as cat (cat.id)}
            <option value={cat.id}>{cat.name}</option>
          {/each}
        </select>
        <button type="button" class="btn btn-ghost" aria-label="Move {c.name} up" onclick={() => sendLayout(movedInCategory($channelLayout.channels, place.channel_id, -1))}>↑</button>
        <button type="button" class="btn btn-ghost" aria-label="Move {c.name} down" onclick={() => sendLayout(movedInCategory($channelLayout.channels, place.channel_id, 1))}>↓</button>
        <!-- Unset too when a password came later: an older server keeps it the welcome (W3-19) -->
        {#if (c.text && !c.has_password) || place.welcome}
          <button
            type="button"
            class="btn btn-ghost"
            title="Opens the first time someone comes to this server"
            aria-label={place.welcome ? `${c.name} not the welcome` : `Make ${c.name} the welcome`}
            onclick={() => adminOp({ WelcomeSet: { channel_id: place.welcome ? null : place.channel_id } })}
          >{place.welcome ? "Not the welcome" : "Make welcome"}</button>
        {/if}
        {#if place.kept && c.text && !c.has_password}
          <button
            type="button"
            class="btn btn-ghost"
            title={c.auto_join ? "Apps follow it from the first connect. Turning this off makes nobody leave: their next connect just does not follow it." : "Apps follow it from the first connect, with nobody told. Whoever left it stays out."}
            aria-label={c.auto_join ? `${c.name} joins by itself` : `${c.name} is joined by hand`}
            onclick={() => toggleFollowed(place.channel_id)}
          >{c.auto_join ? "Joins by itself" : "Joined by hand"}</button>
        {/if}
        {#if place.kept}
          <button type="button" class="btn btn-ghost" aria-label="Edit {c.name}" onclick={() => (editing = { id: place.channel_id, name: c.name, description: c.description })}>Edit</button>
          <button type="button" class="btn btn-ghost danger" aria-label="Delete {c.name}" onclick={() => remove(place.channel_id)}>Delete</button>
        {/if}
      </div>
    {/if}
  {/if}
{/snippet}

<section class="section">
  <div class="section-title">New channel</div>
  <p class="admin-hint">It stays until someone deletes it, and can keep messages. For one that goes when it empties, use + in the channel list.</p>
  <form class="inline-form" onsubmit={(e) => { e.preventDefault(); create(); }}>
    <input class="admin-input" aria-label="Channel name" placeholder="Channel name" bind:value={newName} maxlength="64" />
    <select class="admin-select" aria-label="Text or voice" bind:value={newText}>
      <option value={true}>Text</option>
      <option value={false}>Voice</option>
    </select>
    {#if newText}
      <label class="check-row" title="Apps follow it from the first connect, with nobody told. Whoever leaves it stays out.">
        <input type="checkbox" aria-label="Joins by itself" bind:checked={newFollowed} /> Joins by itself
      </label>
    {/if}
    <select class="admin-select" aria-label="Category" bind:value={newCategory}>
      <option value={null}>No category</option>
      {#each $channelLayout.categories as cat (cat.id)}
        <option value={cat.id}>{cat.name}</option>
      {/each}
    </select>
    <button type="submit" class="btn btn-primary" disabled={!newName.trim()}>Create</button>
  </form>
</section>

<section class="section">
  <div class="section-title">Order</div>
  {#each rows(null) as place (place.channel_id)}
    {@render channelRow(place)}
  {/each}
  {#each $channelLayout.categories as cat, i (cat.id)}
    <div class="category" data-category={cat.name}>
      {#if renaming?.id === cat.id}
        <form class="inline-form" onsubmit={(e) => { e.preventDefault(); renameCategory(); }}>
          <input class="admin-input" aria-label="The name of {cat.name}" bind:value={renaming.name} maxlength="64" />
          <button type="submit" class="btn btn-secondary" disabled={!renaming.name.trim()}>Save</button>
        </form>
      {:else}
        <strong>{cat.name}</strong>
      {/if}
      <button type="button" class="btn btn-ghost" aria-label="Move {cat.name} up" onclick={() => sendLayout($channelLayout.channels, movedBy($channelLayout.categories, i, -1).map((c) => c.id))}>↑</button>
      <button type="button" class="btn btn-ghost" aria-label="Move {cat.name} down" onclick={() => sendLayout($channelLayout.channels, movedBy($channelLayout.categories, i, 1).map((c) => c.id))}>↓</button>
      <button type="button" class="btn btn-ghost" aria-label="Rename the category {cat.name}" onclick={() => (renaming = { id: cat.id, name: cat.name })}>Rename</button>
      <button type="button" class="btn btn-ghost danger" aria-label="Delete the category {cat.name}" onclick={() => removeCategory(cat.id, cat.name)}>Delete</button>
    </div>
    {#each rows(cat.id) as place (place.channel_id)}
      {@render channelRow(place)}
    {/each}
  {/each}
  <form class="inline-form new-category" onsubmit={(e) => { e.preventDefault(); addCategory(); }}>
    <input class="admin-input" aria-label="Category name" placeholder="New category" bind:value={categoryName} maxlength="64" />
    <button type="submit" class="btn btn-secondary" disabled={!categoryName.trim()}>Add</button>
  </form>
</section>

<style>
  .row,
  .category,
  .edit {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    padding: 4px 0;
  }
  .category {
    margin-top: 10px;
    border-top: 1px solid var(--border-color);
    padding-top: 10px;
  }
  .category strong,
  .channel-name {
    flex: 1 1 8rem;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .edit :global(.admin-input) {
    flex: 1 1 8rem;
  }
  .pill {
    font-size: 0.7rem;
    border: 1px solid var(--border-color);
    border-radius: 999px;
    padding: 0 6px;
  }
  .danger {
    color: var(--danger, #e5484d);
  }
  .new-category {
    margin-top: 12px;
  }
</style>
