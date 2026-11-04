<script lang="ts">
  // The admin panel's Groups tab (1.7): the relay's groups (account roles),
  // the privileges (scopes) each hands out, its badge, and who is in it.
  // Its look (sections, fields, lists, check lists) is AdminDialogs.svelte's.

  import { onMount, untrack } from "svelte";
  import { adminError, adminGroups, adminMembers, adminOp } from "../stores/admin-ui.js";
  import { can } from "../stores/powers.js";
  import { confirmAction } from "../stores/confirm.js";
  import { groupStyles } from "../stores/channels.js";
  import { olderRelay } from "../stores/relay.js";
  import { badgeStyle, colorOf, hexOf, pillStyle } from "../member-sections.js";
  import { community } from "../relay-rules.js";
  import { PRIVILEGES, privilegeLabel } from "../scopes.js";
  import Icon from "./Icons.svelte";
  import type { GroupInfo } from "../types.js";

  const PAGE = 50;
  /** The group being edited, or a new one (`create`); null for the list. */
  let editing = $state<{ create: boolean; group: GroupInfo } | null>(null);

  onMount(() => void adminOp("Groups"));

  const blank = (): GroupInfo => ({ name: "", description: "", badge: "", scopes: [], builtin: false });

  /** The form's colour and section, and what they were when opened: sent only if
   *  one changed. */
  let color = $state<number | null>(null);
  let section = $state(true);
  let colorBefore: number | null = null;
  let sectionBefore = true;
  /** Sent once the group is saved, not with it: a code may be asked for between,
   *  and what a code is asked for is the step sent last. */
  let colorToSend: { name: string; color: number | null; section: boolean } | null = null;

  function edit(g: GroupInfo) {
    editing = { create: false, group: { ...g, scopes: [...g.scopes] } };
    const style = $groupStyles.find((s) => s.badge === g.badge);
    colorBefore = color = style?.color ?? null;
    sectionBefore = section = style?.section ?? true;
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
    // As the relay will keep the name: `Crew` is stored as `crew`
    colorToSend =
      color !== colorBefore || section !== sectionBefore
        ? { name: editing.group.name.trim().toLowerCase(), color, section }
        : null;
    void adminOp({ GroupSave: { create: editing.create, group: editing.group } });
  }

  /** Out of the form. A save it was waiting on is no longer what the next answer is
   *  about: the list answers an arrow too, and that must not send this colour. */
  function leave() {
    saving = false;
    colorToSend = null;
    editing = null;
  }

  function startNew() {
    colorBefore = color = null;
    sectionBefore = section = true;
    editing = { create: true, group: blank() };
  }

  /** A group one place up or down; whoever holds less than it is refused there. */
  function move(g: GroupInfo, by: number) {
    const names = ($adminGroups ?? []).map((x) => x.name);
    const from = names.indexOf(g.name);
    const to = from + by;
    if (from < 0 || to < 0 || to >= names.length) return;
    [names[from], names[to]] = [names[to], names[from]];
    void adminOp({ GroupOrder: { names } });
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
        if (colorToSend) void adminOp({ GroupStyle: colorToSend });
        colorToSend = null;
      }
    });
  });
  // Refused: the form stays, with the reason above it
  $effect(() => {
    if ($adminError) {
      untrack(() => {
        saving = false;
        colorToSend = null;
      });
    }
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
  const keepsColor = $derived(community($olderRelay?.protocol ?? null));
  /** "Everything" covers the rest: they show ticked and cannot be unticked. */
  const everything = $derived(!!editing?.group.scopes.includes("*"));
  const summary = (g: GroupInfo) =>
    g.scopes.length ? g.scopes.map(privilegeLabel).join(", ") : "No privileges";
</script>

{#if editing}
  {@const g = editing.group}
  <button type="button" class="btn btn-ghost btn-back" onclick={leave}>
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
        <span class="admin-hint">Next to members' names. Anyone on this server can read it, guests too.</span>
      </label>
      <label class="field">
        Description
        <input class="admin-input" aria-label="Description" bind:value={g.description} maxlength="255" disabled={!mayEdit} placeholder="What the group is for" />
      </label>
    </div>
    {#if keepsColor && g.badge.trim()}
      <div class="colour-row">
        <label class="colour-label">
          Badge colour
          <input
            type="color"
            disabled={!mayEdit}
            value={hexOf(color ?? 0x8a8f98)}
            oninput={(e) => (color = colorOf(e.currentTarget.value))}
          />
        </label>
        {#if color !== null}
          <span class="pill" style={pillStyle(color)}>{g.badge}</span>
          {#if mayEdit}
            <button type="button" class="btn btn-ghost" onclick={() => (color = null)}>No colour</button>
          {/if}
        {:else}
          <span class="admin-hint">None: the theme's own</span>
        {/if}
      </div>
      <label class="check-row">
        <input type="checkbox" aria-label="Own section in the member list" disabled={!mayEdit} bind:checked={section} />
        <span class="check-text">
          <span>Own section in the member list</span>
          <span class="check-hint">Off, its people stay with everybody else, and only wear the badge.</span>
        </span>
      </label>
    {/if}
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
        <button type="button" class="btn btn-secondary" onclick={leave}>Cancel</button>
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
        <button type="button" class="btn btn-primary" onclick={startNew}>
          <Icon name="plus" size={16} /> New group
        </button>
      {/if}
    </div>
    {#if $adminGroups}
      <ul class="list">
        {#each $adminGroups as g, i (g.name)}
          <li class="group-row">
            <button type="button" class="list-row" onclick={() => edit(g)}>
              <span class="row-text">
                <span class="row-name">
                  {g.name}
                  {#if g.badge}<span class="pill" style={badgeStyle(g.badge, $groupStyles)}>{g.badge}</span>{/if}
                </span>
                <span class="row-meta">{summary(g)}{g.builtin ? " · built in" : ""}</span>
              </span>
              <span class="row-chevron"><Icon name="chevron-down" size={16} /></span>
            </button>
            {#if mayEdit && keepsColor}
              <button
                type="button"
                class="btn btn-ghost move"
                aria-label="Move {g.name} up"
                disabled={i === 0}
                onclick={() => move(g, -1)}>↑</button
              >
              <button
                type="button"
                class="btn btn-ghost move"
                aria-label="Move {g.name} down"
                disabled={i === $adminGroups.length - 1}
                onclick={() => move(g, 1)}>↓</button
              >
            {/if}
          </li>
        {/each}
      </ul>
    {:else}
      <p class="admin-hint">Loading…</p>
    {/if}
  </section>
{/if}

<style>
  .group-row {
    display: flex;
    align-items: center;
    gap: var(--sp-1, 4px);
  }

  .group-row .list-row {
    flex: 1;
    min-width: 0;
  }

  .move {
    padding: 4px 8px;
  }

  .colour-row {
    display: flex;
    align-items: center;
    gap: var(--sp-2, 8px);
  }

  .colour-label {
    display: flex;
    align-items: center;
    gap: var(--sp-2, 8px);
  }

  .colour-row input[type="color"] {
    width: 36px;
    height: 24px;
    padding: 0;
    border: 1px solid var(--border);
    background: none;
  }

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
