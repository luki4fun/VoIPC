<script lang="ts">
  // The admin panel's Moderation log tab (1.10): who did what to whom, newest first.
  // Read-only: the relay has no step that changes or deletes a row, so nothing here
  // offers one. Its look is AdminDialogs.svelte's.

  import { onMount } from "svelte";
  import { adminModLog, adminOp } from "../stores/admin-ui.js";
  import { modAction, modPlace } from "../modlog-rules.js";

  const when = (secs: number) => new Date(secs * 1000).toLocaleString();
  const rows = $derived($adminModLog?.rows ?? []);

  onMount(() => void adminOp({ ModLog: { before: 0 } }));

  function older() {
    const last = rows.at(-1);
    if (last) void adminOp({ ModLog: { before: last.id } });
  }
</script>

<section class="section modlog">
  <div class="section-title">Moderation log</div>
  <p class="admin-hint">
    Who did what to whom on this server. Nobody can change or delete a row here{#if $adminModLog}; each stays {$adminModLog.keep_days} days, names included, even after that account is deleted{/if}.
    A hidden message is only the moderator's app's word: the server cannot see inside messages.
  </p>
  {#if $adminModLog && rows.length === 0}
    <p class="admin-hint">Nothing has happened yet.</p>
  {/if}
  {#if rows.length > 0}
    <ul class="list">
      {#each rows as row (row.id)}
        {@const place = modPlace(row)}
        {@const [before, after] = modAction(row.action)}
        <li class="list-item modlog-row" data-action={row.action}>
          <div class="row-text">
            <span class="line">
              <strong>{row.actor}</strong> {before}{#if row.target}&nbsp;<strong>{row.target}</strong>{/if}{#if after}&nbsp;{after}{/if}
              {#if row.advisory}<span class="pill" title="The moderator's app said so; the server could not see it">their app's word</span>{/if}
            </span>
            <span class="line meta">
              {when(row.at)}{#if place}&nbsp;· {place}{/if}{#if row.detail}&nbsp;· {row.detail}{/if}{#if row.reason}&nbsp;· {row.reason}{/if}
            </span>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
  {#if $adminModLog?.more}
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" onclick={older}>Load older</button>
    </div>
  {/if}
</section>

<style>
  /* A reason is the point of a row: it wraps rather than ends in dots */
  .line {
    overflow-wrap: anywhere;
  }

  .meta {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }
</style>
