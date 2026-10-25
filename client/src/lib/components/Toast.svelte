<script lang="ts">
  import { notifications, removeNotification } from "../stores/notifications.js";
  import Icon from "./Icons.svelte";
</script>

<!-- Always in the page, so a screen reader is watching it before the first
     toast arrives: polite for news, an alert for an error (H5-04) -->
<div class="toast-container" aria-live="polite">
  {#each $notifications as notification (notification.id)}
    <div class="toast toast-{notification.type}" role={notification.type === "error" ? "alert" : "status"}>
      <span class="toast-message">{notification.message}</span>
      <button
        class="toast-close"
        aria-label="Dismiss"
        onclick={() => removeNotification(notification.id)}
      ><Icon name="close" size={14} /></button>
    </div>
  {/each}
</div>

<style>
  .toast-container {
    position: fixed;
    bottom: 48px;
    right: 16px;
    display: flex;
    flex-direction: column-reverse;
    gap: 8px;
    z-index: 200;
    pointer-events: none;
  }

  .toast {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-radius: 6px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    font-size: 13px;
    min-width: 240px;
    max-width: min(380px, calc(100vw - 32px));
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    pointer-events: auto;
    animation: slide-in 0.2s ease-out;
  }

  @keyframes slide-in {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  .toast-info {
    border-left: 3px solid var(--accent);
  }

  .toast-warning {
    border-left: 3px solid #ff9800;
  }

  .toast-error {
    border-left: 3px solid var(--danger);
  }

  .toast-message {
    flex: 1;
    /* A fingerprint or a link has no spaces to break at; on a phone it ran
       off the screen */
    overflow-wrap: anywhere;
    min-width: 0;
  }

  .toast-close {
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 2px;
    border-radius: 3px;
    flex-shrink: 0;
  }

  .toast-close:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }
</style>
