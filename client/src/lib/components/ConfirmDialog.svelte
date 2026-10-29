<script lang="ts">
  // The one confirmation (stores/confirm.ts). Mounted once, in App.svelte.
  // Cancel comes first, so it is what use:dialog focuses: Enter never
  // destroys anything by accident.

  import { backdrop, dialog } from "../actions/dialog.js";
  import { answerConfirm, pendingConfirm } from "../stores/confirm.js";
</script>

{#if $pendingConfirm}
  {@const q = $pendingConfirm}
  <div class="overlay" role="presentation" onclick={backdrop(() => answerConfirm(false))}>
    <div class="confirm" use:dialog={{ onclose: () => answerConfirm(false) }} aria-describedby="confirm-body">
      <h3 class="dialog-title">{q.title}</h3>
      <p id="confirm-body" class="body">{q.body}</p>
      {#if q.details?.length}
        <ul class="details">
          {#each q.details as line, i (i)}<li>{line}</li>{/each}
        </ul>
      {/if}
      <div class="actions">
        <button class="btn btn-secondary" onclick={() => answerConfirm(false)}>
          {q.cancel ?? "Cancel"}
        </button>
        <button class="btn {q.danger ? 'btn-danger' : 'btn-primary'}" onclick={() => answerConfirm(true)}>
          {q.confirm}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    z-index: var(--z-picker);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--sp-4);
    background: var(--scrim);
  }

  .confirm {
    width: min(440px, 100%);
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
    padding: var(--sp-6);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    box-shadow: var(--shadow-dialog);
    display: flex;
    flex-direction: column;
    gap: var(--sp-3);
  }

  .dialog-title {
    font-size: var(--fs-xl);
    color: var(--text-primary);
  }

  .body {
    font-size: var(--fs-md);
    line-height: 1.5;
    color: var(--text-primary);
  }

  .details {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: var(--sp-1);
    padding: var(--sp-3);
    background: var(--well);
    border-radius: var(--r-sm);
    font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    word-break: break-all;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    flex-wrap: wrap;
    gap: var(--sp-2);
    margin-top: var(--sp-2);
  }
</style>
