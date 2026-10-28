<script lang="ts">
  // "This server is not up": over the pane of the server on screen while it
  // connects or reconnects. Inside the pane rather than over the window, so the
  // rail, the other servers and the call — which may be on one of them — stay
  // usable while this one retries.

  import { connectionState, serverAddress } from "../stores/connection.js";
  import { cancelReconnect, reconnectInfo } from "../connect.js";

  // What it covers is out of reach while it is up, for the keyboard and a
  // screen reader as for the mouse: Tab used to walk into the pane under it.
  // Only what this made inert is given back; the shell's own `inert` stays.
  function coverPane(node: HTMLElement) {
    const covered = [...(node.parentElement?.children ?? [])].filter(
      (el): el is HTMLElement =>
        el !== node && el instanceof HTMLElement && !el.inert && !el.hasAttribute("data-reconnect-status"),
    );
    for (const el of covered) el.inert = true;
    return {
      destroy() {
        for (const el of covered) el.inert = false;
      },
    };
  }
</script>

<!-- Always there, so a screen reader hears the pane go away and come back;
     without the attempt count, which would be read out at every retry -->
<span class="sr-only" role="status" data-reconnect-status
  >{#if $connectionState === "reconnecting"}Connection lost, reconnecting{:else if $connectionState === "connecting"}Connecting{/if}</span
>

{#if $connectionState === "reconnecting" || $connectionState === "connecting"}
  <div class="overlay" use:coverPane>
    <div class="dialog">
      <div class="spinner"></div>
      {#if $connectionState === "connecting"}
        <h2>Connecting</h2>
      {:else}
        <h2>Connection lost</h2>
        <p class="message">Reconnecting... attempt #{$reconnectInfo.attempt}</p>
      {/if}
      {#if $reconnectInfo.error}
        <p class="error-detail">{$reconnectInfo.error}</p>
      {/if}
      <button class="cancel-btn" onclick={() => cancelReconnect($serverAddress)}>Cancel</button>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: absolute;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-pane);
  }

  .dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 32px;
    width: min(320px, 90%);
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  h2 {
    font-size: var(--fs-xl);
    color: var(--text-primary);
    margin: 0;
  }

  .message {
    font-size: var(--fs-md);
    color: var(--text-secondary);
    margin: 0;
  }

  .error-detail {
    font-size: var(--fs-sm);
    color: var(--danger);
    margin: 0;
    text-align: center;
  }

  .cancel-btn {
    background: transparent;
    color: var(--danger);
    padding: 8px 24px;
    font-size: var(--fs-body);
    border: 1px solid var(--danger);
    cursor: pointer;
    border-radius: 4px;
  }

  .cancel-btn:hover {
    background: var(--danger);
    color: var(--on-danger);
  }
</style>
