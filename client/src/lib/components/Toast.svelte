<script lang="ts">
  import {
    notifications,
    pauseNotification,
    removeNotification,
    resumeNotification,
  } from "../stores/notifications.js";
  import { holdsToast } from "../notify-rules.js";
  import Icon from "./Icons.svelte";

  let stackHeight = $state(0);
  // How much room the stack takes, for a phone's open dialog to move down by
  // (the rules at the end): only while a toast is up
  $effect(() => {
    const root = document.documentElement;
    root.toggleAttribute("data-toasts", stackHeight > 0);
    if (stackHeight > 0) root.style.setProperty("--toast-room", `${stackHeight}px`);
    else root.style.removeProperty("--toast-room");
  });
</script>

<!-- Always in the page, so a screen reader is watching it before the first
     toast arrives: polite for news, an alert for an error (H5-04) -->
<div class="toast-container" aria-live="polite" bind:clientHeight={stackHeight}>
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

  /* A phone's dialog has its buttons at the bottom too: a toast that stays (a new server's
     certificate) sat on Connect, and a tap there hit the toast (rc.2 device run). While one is
     open the stack goes to the top; with none, the top has the header's buttons, so not then */
  @media (max-width: 600px) {
    /* Across the screen between the gutters: centred from half way, a long
       one (a fingerprint) had half the width and stood three times as tall */
    :global(body:has([aria-modal="true"])) .toast-container {
      top: calc(12px + env(safe-area-inset-top, 0px));
      bottom: auto;
      right: 16px;
      left: 16px;
      transform: none;
      align-items: center;
      flex-direction: column;
    }

    :global(body:has([aria-modal="true"])) .toast {
      animation-name: drop-in;
    }

    /* ...and the dialog moves down under the stack: at the top a toast that
       stays covered the form's first fields instead (rc.3 device run). Its
       backdrop makes the room, and the dialog fits the rest */
    :global(html[data-toasts] body:has([aria-modal="true"]) :not(body):has(> [aria-modal="true"])) {
      padding-top: calc(var(--toast-room) + 20px + env(safe-area-inset-top, 0px));
    }

    :global(html[data-toasts] body:has([aria-modal="true"]) [aria-modal="true"]) {
      max-height: calc(100dvh - 52px - var(--toast-room) - env(safe-area-inset-top, 0px));
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
