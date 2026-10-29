<script lang="ts">
  // The status bar along the very bottom of the classic layout.
  //
  // Bar only. Packet loss is polled in stores/connection-quality.ts and the two
  // admin dialogs are AdminDialogs.svelte, both because the modern layout shows
  // the same things somewhere else and neither should be computed twice.

  import {
    connectionState,
    serverAddress,
    latency,
    viaTcp,
    TCP_HINT,
    isAdmin,
  } from "../stores/connection.js";
  import { viewingVoice } from "../stores/channels.js";
  import { lossPercent, quality } from "../stores/connection-quality.js";
  import { openAdminPanel, showAdminLogin } from "../stores/admin-ui.js";
  import { account, showPrompt } from "../stores/account.js";
  import { disconnectServer } from "../connect.js";
  import { playDisconnectedSound } from "../sounds.js";
  import Icon from "./Icons.svelte";

  // The server on screen only: the others, and the call if it is on one of
  // them, stay.
  async function disconnect() {
    await disconnectServer($serverAddress);
    playDisconnectedSound();
  }

  // The loss is the call's; next to another server's ping it would be a number
  // about somewhere else.
  const loss = $derived($viewingVoice ? $lossPercent : 0);

  interface Props {
    /** The phone: the bar is also where Settings lives (there is no title
     *  bar to carry the gear), and it says less so it fits on one line. */
    compact?: boolean;
    onopensettings?: () => void;
  }
  let { compact = false, onopensettings }: Props = $props();
</script>

<div class="status-bar" class:compact>
  <div class="status">
    <div
      class="dot"
      class:connected={$connectionState === "connected"}
      class:connecting={$connectionState === "connecting"}
    ></div>
    {#if $connectionState === "connected"}
      <span>Connected{#if !compact}&nbsp;to {$serverAddress}{/if}</span>
    {:else if $connectionState === "connecting"}
      <span>Connecting…</span>
    {:else}
      <span>Disconnected</span>
    {/if}
  </div>

  {#if $connectionState === "connected"}
    <span
      class="latency num quality-{$viewingVoice ? $quality : 'good'}"
      title={$viaTcp ? `${TCP_HINT} Voice packet loss (2s window)` : "Voice packet loss (2s window)"}
    >
      {#if !compact}Ping:&nbsp;{/if}{$latency}&nbsp;ms{#if $viaTcp}&nbsp;· TCP{/if}{#if loss > 0}&nbsp;· {loss}% loss{/if}
    </span>
    {#if $account}
      <button
        class="admin-btn"
        title="Your account on this server"
        onclick={() => showPrompt({ kind: "account", server: $serverAddress })}
      >
        <Icon name="lock" size={14} />
        {$account.name}
      </button>
    {/if}
    <button
      class="admin-btn"
      class:active={$isAdmin}
      title={$isAdmin ? "Server admin — active bans" : "Admin login (server token)"}
      onclick={() => ($isAdmin ? openAdminPanel() : showAdminLogin.set(true))}
    >
      <Icon name="shield" size={14} />
      {#if $isAdmin}Admin{/if}
    </button>
    <button class="disconnect-btn" onclick={disconnect} aria-label="Disconnect from {$serverAddress}">
      <Icon name="disconnect" size={14} />
      {#if !compact}Disconnect{/if}
    </button>
  {/if}
  {#if onopensettings}
    <button class="admin-btn settings-btn" onclick={onopensettings} title="Settings" aria-label="Settings">
      <Icon name="settings" size={16} />
    </button>
  {/if}
</div>


<style>
  .status-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 4px 16px;
    background: var(--bg-primary);
    border-top: 1px solid var(--border);
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .status {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .quality-warn {
    color: var(--warning);
  }

  .quality-bad {
    color: var(--danger);
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--danger);
  }

  .dot.connected {
    background: var(--success);
  }

  .dot.connecting {
    background: var(--warning);
    animation: pulse 1s infinite;
  }

  @keyframes pulse {
    50% {
      opacity: 0.5;
    }
  }

  .latency {
    margin-left: auto;
  }

  .disconnect-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    background: transparent;
    color: var(--danger);
    padding: 4px 10px;
    font-size: var(--fs-micro);
    border: 1px solid var(--danger);
  }

  .disconnect-btn:hover {
    background: var(--danger);
    color: var(--on-danger);
  }

  .admin-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px 8px;
    font-size: var(--fs-micro);
    border: 1px solid var(--border);
  }

  .admin-btn:hover,
  .admin-btn.active {
    color: var(--text-primary);
    border-color: var(--text-primary);
  }

  /* On a phone these are Classic's only way to Settings and to disconnect */
  @media (pointer: coarse) {
    .admin-btn,
    .disconnect-btn {
      min-width: var(--hit);
      min-height: var(--hit);
    }
  }
</style>
