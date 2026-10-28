<script lang="ts">
  import { pendingPokes } from "../stores/pokes.js";
  import { serverAddress } from "../stores/connection.js";
  import { serverEntries } from "../connect.js";
  import { shortName } from "../username.js";

  function dismiss(id: number) {
    pendingPokes.update((p) => p.filter((poke) => poke.id !== id));
  }
</script>

<!-- Always there, like the toasts, so a poke is read out when it arrives -->
<div class="poke-container" aria-live="polite">
  {#each $pendingPokes as poke (poke.id)}
    <div class="poke" role="status">
      <div class="poke-content">
        <span class="poke-text">
          <strong title={poke.from_username}>{shortName(poke.from_username)}</strong> poked you{#if poke.server !== $serverAddress}&nbsp;on {$serverEntries.find((e) => e.id === poke.server)?.name ?? poke.server}{/if}
        </span>
        {#if poke.message}
          <span class="poke-message">"{poke.message}"</span>
        {/if}
      </div>
      <button class="dismiss-btn btn btn-primary" onclick={() => dismiss(poke.id)}>OK</button>
    </div>
  {/each}
</div>

<style>
  .poke-container {
    position: fixed;
    top: 48px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: var(--z-modal);
  }

  .poke {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: 6px;
    background: var(--bg-secondary);
    border: 1px solid var(--accent);
    color: var(--text-primary);
    font-size: var(--fs-body);
    box-shadow: var(--shadow-menu);
    animation: poke-in 0.25s ease-out;
    min-width: 250px;
    max-width: 400px;
  }

  @keyframes poke-in {
    from {
      transform: translateY(-20px);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }

  .poke-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .poke-text {
    font-size: var(--fs-body);
  }

  .poke-message {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    font-style: italic;
  }

  .dismiss-btn {
    padding: 4px 12px;
    font-size: var(--fs-sm);
    flex-shrink: 0;
  }
</style>
