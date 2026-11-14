<script lang="ts">
  import {
    notifications,
    pauseNotification,
    removeNotification,
    resumeNotification,
  } from "../stores/notifications.js";
  import { holdsToast } from "../notify-rules.js";
  import Icon from "./Icons.svelte";
</script>

<!-- Always in the page, so a screen reader is watching it before the first
     toast arrives: polite for news, an alert for an error (H5-04) -->
<div class="toast-container" aria-live="polite">
  {#each $notifications as notification (notification.id)}
    <div
      class="toast toast-{notification.type}"
      role={notification.type === "error" ? "alert" : "status"}
      onpointerenter={(e) => {
        if (holdsToast(e.pointerType)) pauseNotification(notification.id);
      }}
      onpointerleave={(e) => {
        if (holdsToast(e.pointerType)) resumeNotification(notification.id);
      }}
      onfocusin={() => pauseNotification(notification.id)}
      onfocusout={() => resumeNotification(notification.id)}
    >
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
    z-index: var(--z-toast);
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
    font-size: var(--fs-body);
    min-width: 240px;
    max-width: min(380px, calc(100vw - 32px));
    box-shadow: var(--shadow-menu);
    pointer-events: auto;
    animation: slide-in var(--dur-base) var(--ease-out);
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

  /* A short window, 800x600 the desktop's first: at the bottom the stack covered a dialog's
     buttons and its error, Next on the first-run microphone check and the Connect error
     among them (device pass). At the top it can cover a title for its seconds, no button */
  @media (max-height: 720px) {
    .toast-container {
      top: 12px;
      bottom: auto;
      right: auto;
      left: 50%;
      transform: translateX(-50%);
      flex-direction: column;
    }

    .toast {
      animation-name: drop-in;
    }
  }

  @keyframes drop-in {
    from {
      transform: translateY(-100%);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }

  /* What kind of news, as a dot before the words (the role says it to a
     screen reader) */
  .toast::before {
    content: "";
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--toast-kind);
  }

  .toast-info {
    --toast-kind: var(--text-secondary);
  }

  .toast-warning {
    --toast-kind: var(--warning);
  }

  .toast-error {
    --toast-kind: var(--danger);
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
