<script lang="ts">
  import { pendingPokes } from "../stores/pokes.js";

  function dismiss(id: number) {
    pendingPokes.update((p) => p.filter((poke) => poke.id !== id));
  }
</script>

{#if $pendingPokes.length > 0}
  <div class="poke-container">
    {#each $pendingPokes as poke (poke.id)}
      <div class="poke">
        <div class="poke-content">
          <span class="poke-text">
            <strong>{poke.from_username}</strong> poked you
          </span>
          {#if poke.message}
            <span class="poke-message">"{poke.message}"</span>
          {/if}
        </div>
        <button class="dismiss-btn" onclick={() => dismiss(poke.id)}>OK</button>
      </div>
    {/each}
  </div>
{/if}

<style>
  .poke-container {
    position: fixed;
    top: 48px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 200;
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
    font-size: 13px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
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
    font-size: 13px;
  }

  .poke-message {
    font-size: 12px;
    color: var(--text-secondary);
    font-style: italic;
  }

  .dismiss-btn {
    background: var(--accent);
    color: white;
    border: none;
    padding: 4px 12px;
    font-size: 12px;
    border-radius: 4px;
    cursor: pointer;
    flex-shrink: 0;
  }

  .dismiss-btn:hover {
    opacity: 0.9;
  }
</style>
