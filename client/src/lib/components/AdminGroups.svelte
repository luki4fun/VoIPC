<script lang="ts">
  // The admin panel's Groups tab (1.7): the relay's groups (account roles),
  // the privileges (scopes) each hands out, its badge, and who is in it.
  // Its look (sections, fields, lists, check lists) is AdminDialogs.svelte's.

  import { onMount, untrack } from "svelte";
  import { adminError, adminGroups, adminMembers, adminOp } from "../stores/admin-ui.js";
  import { can } from "../stores/powers.js";
  import { confirmAction } from "../stores/confirm.js";
  import { PRIVILEGES, privilegeLabel } from "../scopes.js";
  import Icon from "./Icons.svelte";
  import type { GroupInfo } from "../types.js";

  const PAGE = 50;
  /** The group being edited, or a new one (`create`); null for the list. */
  let editing = $state<{ create: boolean; group: GroupInfo } | null>(null);

  onMount(() => void adminOp("Groups"));

  const blank = (): GroupInfo => ({ name: "", description: "", badge: "", scopes: [], builtin: false });

  function edit(g: GroupInfo) {
    editing = { create: false, group: { ...g, scopes: [...g.scopes] } };
    void adminOp({ GroupMembers: { name: g.name, offset: 0 } });
  }

  function toggle(scope: string, on: boolean) {
    if (!editing) return;
    const s = editing.group.scopes.filter((x) => x !== scope);
    editing.group.scopes = on ? [...s, scope].sort() : s;
  }

  /** A save or a delete is on its way: its answer is the list, back to it. */
  let saving = $state(false);

  function save() {
    if (!editing) return;
    saving = true;
    void adminOp({ GroupSave: { create: editing.create, group: editing.group } });
  }

  async function remove() {
    if (!editing) return;
    const name = editing.group.name;
    const ok = await confirmAction({
      title: `Delete the group ${name}?`,
      body: "Its members lose what it handed out, and its badge. A group a channel's gate names cannot be deleted: change that channel first.",
      confirm: "Delete group",
      danger: true,
    });
    if (ok) {
      saving = true;
      void adminOp({ GroupDelete: { name } });
    }
  }

  $effect(() => {
    void $adminGroups;
    untrack(() => {
      if (saving) {
        saving = false;
        editing = null;
      }
    });
  });
  // Refused: the form stays, with the reason above it
  $effect(() => {
    if ($adminError) untrack(() => (saving = false));
  });

  /** The privileges to tick: the known ones, then any other the group holds. */
  const choices = $derived(
    editing
      ? [
          ...PRIVILEGES,
          ...editing.group.scopes
            .filter((s) => !PRIVILEGES.some((p) => p.scope === s))
            .map((s) => ({ scope: s, label: s, hint: "Set from the server's shell" })),
        ]
      : [],
  );
  const mayEdit = $derived($can("roles:admin"));
  /** "Everything" covers the rest: they show ticked and cannot be unticked. */
  const everything = $derived(!!editing?.group.scopes.includes("*"));
  const summary = (g: GroupInfo) =>
    g.scopes.length ? g.scopes.map(privilegeLabel).join(", ") : "No privileges";
</script>

{#if editing}
  {@const g = editing.group}
  <button type="button" class="btn btn-ghost btn-back" onclick={() => (editing = null)}>
    <Icon name="arrow-left" size={16} /> All groups
  </button>
  <form class="group-form" onsubmit={(e) => { e.preventDefault(); save(); }}>
    <div class="section-title">
      {editing.create ? "New group" : g.name}
      {#if !editing.create && g.badge}<span class="pill">{g.badge}</span>{/if}
      {#if g.builtin}<span class="pill">built in</span>{/if}
    </div>
    {#if editing.create}
      <label class="field">
        Name
        <input class="admin-input" aria-label="Group name" bind:value={g.name} maxlength="32" autocomplete="off" />
        <span class="admin-hint">2 to 32 of a–z, 0–9, _ and -. It cannot be changed later.</span>
      </label>
    {/if}
    <div class="two-fields">
      <label class="field">
        Badge
        <input class="admin-input" aria-label="Badge" bind:value={g.badge} maxlength="32" disabled={!mayEdit} placeholder="None" />
        <span class="admin-hint">Next to members' names.</span>
      </label>
      <label class="field">
        Description
        <input class="admin-input" aria-label="Description" bind:value={g.description} maxlength="255" disabled={!mayEdit} placeholder="What the group is for" />
      </label>
    </div>
    <div class="section">
      <div class="section-title">Privileges</div>
      <p class="admin-hint">They apply once a member has set up two-factor codes. A group without any is still a group: for its badge, and for the channels that let it in.</p>
      <ul class="check-list">
        {#each choices as p (p.scope)}
          {@const covered = everything && p.scope !== "*"}
          <li>
            <label class="check-row" class:disabled={!mayEdit || covered}>
              <input
                type="checkbox"
                data-scope={p.scope}
                checked={covered || g.scopes.includes(p.scope)}
                disabled={!mayEdit || covered}
                onchange={(e) => toggle(p.scope, e.currentTarget.checked)}
              />
              <span class="check-text">
                <span>{p.label}</span>
                <span class="check-hint">{covered ? "Included in Everything" : p.hint}</span>
              </span>
            </label>
          </li>
        {/each}
      </ul>
    </div>
    {#if mayEdit}
      <div class="form-actions">
        {#if !editing.create && !g.builtin}
          <button type="button" class="btn btn-danger-outline push-left" onclick={remove}>Delete group</button>
        {/if}
        <button type="button" class="btn btn-secondary" onclick={() => (editing = null)}>Cancel</button>
        <button type="submit" class="btn btn-primary" disabled={saving || (editing.create && !g.name.trim())}>
          {editing.create ? "Create group" : "Save changes"}
        </button>
      </div>
    {/if}
  </form>
  {#if !editing.create && $adminMembers?.name === g.name}
    {@const m = $adminMembers}
    <section class="section">
      <div class="section-title">Members <span class="admin-hint">{m.total}</span></div>
      {#if m.users.length === 0}
        <p class="admin-hint">Nobody yet. Give the group to an account on the Users tab.</p>
      {:else}
        <ul class="list">
          {#each m.users as u (u.name)}
            <li class="list-item"><span class="row-name">{u.name}</span></li>
          {/each}
        </ul>
        {#if m.total > PAGE}
          <div class="form-actions">
            <span class="admin-hint push-left">{m.offset + 1}–{m.offset + m.users.length} of {m.total}</span>
            <button type="button" class="btn btn-secondary" disabled={m.offset === 0} onclick={() => adminOp({ GroupMembers: { name: g.name, offset: Math.max(0, m.offset - PAGE) } })}>Previous</button>
            <button type="button" class="btn btn-secondary" disabled={m.offset + PAGE >= m.total} onclick={() => adminOp({ GroupMembers: { name: g.name, offset: m.offset + PAGE } })}>Next</button>
          </div>
        {/if}
      {/if}
    </section>
  {/if}
{:else}
  <section class="section">
    <div class="section-head">
      <p class="admin-hint">Groups hand out privileges and badges, and channels can let in or give a voice to a group. Give them to accounts on the Users tab.</p>
      {#if mayEdit}
        <button type="button" class="btn btn-primary" onclick={() => (editing = { create: true, group: blank() })}>
          <Icon name="plus" size={16} /> New group
        </button>
      {/if}
    </div>
    {#if $adminGroups}
      <ul class="list">
        {#each $adminGroups as g (g.name)}
          <li>
            <button type="button" class="list-row" onclick={() => edit(g)}>
              <span class="row-text">
                <span class="row-name">
                  {g.name}
                  {#if g.badge}<span class="pill">{g.badge}</span>{/if}
                </span>
                <span class="row-meta">{summary(g)}{g.builtin ? " · built in" : ""}</span>
              </span>
              <span class="row-chevron"><Icon name="chevron-down" size={16} /></span>
            </button>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="admin-hint">Loading…</p>
    {/if}
  </section>
{/if}

<style>
  .group-form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3, 12px);
  }

  .two-fields {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 2fr);
    gap: var(--sp-3, 12px);
  }

  @media (max-width: 520px) {
    .two-fields {
      grid-template-columns: 1fr;
    }
  }

  .section-head .admin-hint {
    flex: 1;
  }
</style>
