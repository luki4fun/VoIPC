<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";
  import {
    connectionState,
    serverAddress,
    latency,
    isAdmin,
  } from "../stores/connection.js";
  import { playDisconnectedSound } from "../sounds.js";
  import { addNotification } from "../stores/notifications.js";
  import type { BanInfo } from "../types.js";
  import Icon from "./Icons.svelte";

  // ── Server admin: token login, then a small panel with the ban list ──
  let showAdminLogin = $state(false);
  let adminToken = $state("");
  let showAdminPanel = $state(false);
  let bans = $state<BanInfo[]>([]);

  onMount(() => {
    const unlisten = listen<{ bans: BanInfo[] }>("admin-bans", (e) => {
      bans = e.payload.bans;
    });
    return () => {
      unlisten.then((f) => f());
    };
  });

  // The server confirms the login through admin-status (isAdmin store)
  $effect(() => {
    if ($isAdmin) showAdminLogin = false;
    if (!$isAdmin) showAdminPanel = false;
  });

  async function submitAdminLogin() {
    const token = adminToken.trim();
    adminToken = "";
    if (!token) return;
    try {
      await invoke("admin_login", { token });
    } catch (e) {
      addNotification(`Admin login failed: ${e}`, "error");
    }
  }

  function openAdminPanel() {
    showAdminPanel = true;
    invoke("admin_list_bans").catch((e: unknown) => addNotification(`Could not load bans: ${e}`, "error"));
  }

  async function unban(ip: string) {
    try {
      await invoke("admin_unban", { ip });
    } catch (e) {
      addNotification(`Unban failed: ${e}`, "error");
    }
  }

  function expiry(ban: BanInfo): string {
    if (ban.expires_in_secs === null) return "until server restart";
    const s = ban.expires_in_secs;
    if (s >= 3600) return `${Math.ceil(s / 3600)} h left`;
    if (s >= 60) return `${Math.ceil(s / 60)} min left`;
    return `${s} s left`;
  }

  async function disconnect() {
    try {
      await invoke("disconnect");
      connectionState.set("disconnected");
      playDisconnectedSound();
    } catch (e) {
      console.error("Failed to disconnect:", e);
      addNotification(`Failed to disconnect: ${e}`, "error");
    }
  }

  // Voice loss % over a rolling 2s window (from jitter-buffer conceal counts)
  let lossPercent = $state(0);
  let lastPlayed = 0;
  let lastLost = 0;
  let lossInterval: ReturnType<typeof setInterval> | null = null;

  $effect(() => {
    if ($connectionState === "connected") {
      if (!lossInterval) {
        lastPlayed = 0;
        lastLost = 0;
        lossInterval = setInterval(() => {
          invoke<[number, number]>("get_voice_stats")
            .then(([played, lost]) => {
              const dPlayed = played - lastPlayed;
              const dLost = lost - lastLost;
              lastPlayed = played;
              lastLost = lost;
              const total = dPlayed + dLost;
              lossPercent = total > 0 ? Math.round((dLost / total) * 100) : 0;
            })
            .catch(() => {});
        }, 2000);
      }
    } else if (lossInterval) {
      clearInterval(lossInterval);
      lossInterval = null;
      lossPercent = 0;
    }
    return () => {
      if (lossInterval) {
        clearInterval(lossInterval);
        lossInterval = null;
      }
    };
  });

  let quality = $derived(
    lossPercent >= 5 ? "bad" : lossPercent >= 1 ? "warn" : "good",
  );
</script>

<div class="status-bar">
  <div class="status">
    <div
      class="dot"
      class:connected={$connectionState === "connected"}
      class:connecting={$connectionState === "connecting"}
    ></div>
    {#if $connectionState === "connected"}
      <span>Connected to {$serverAddress}</span>
    {:else if $connectionState === "connecting"}
      <span>Connecting...</span>
    {:else}
      <span>Disconnected</span>
    {/if}
  </div>

  {#if $connectionState === "connected"}
    <span class="latency quality-{quality}" title="Voice packet loss (2s window)">
      Ping: {$latency}ms{#if lossPercent > 0}&nbsp;· {lossPercent}% loss{/if}
    </span>
    <button
      class="admin-btn"
      class:active={$isAdmin}
      title={$isAdmin ? "Server admin — active bans" : "Admin login (server token)"}
      onclick={() => ($isAdmin ? openAdminPanel() : (showAdminLogin = true))}
    >
      <Icon name="shield" size={14} />
      {#if $isAdmin}Admin{/if}
    </button>
    <button class="disconnect-btn" onclick={disconnect}>
      <Icon name="disconnect" size={14} />
      Disconnect
    </button>
  {/if}
</div>

{#if showAdminLogin}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="admin-overlay" onclick={() => (showAdminLogin = false)}>
    <form class="admin-dialog" onclick={(e) => e.stopPropagation()} onsubmit={(e) => { e.preventDefault(); submitAdminLogin(); }}>
      <div class="admin-title">Admin login</div>
      <div class="admin-hint">The admin token is in the server's config (<code>admin_token</code>) or, if none is set, in the server log at startup.</div>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="admin-input" type="password" placeholder="Admin token" bind:value={adminToken} autofocus />
      <div class="admin-actions">
        <button type="button" class="admin-cancel" onclick={() => (showAdminLogin = false)}>Cancel</button>
        <button type="submit" class="admin-ok" disabled={!adminToken.trim()}>Log in</button>
      </div>
    </form>
  </div>
{/if}

{#if showAdminPanel}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="admin-overlay" onclick={() => (showAdminPanel = false)}>
    <div class="admin-dialog" onclick={(e) => e.stopPropagation()}>
      <div class="admin-title">Active bans</div>
      {#if bans.length === 0}
        <div class="admin-hint">No active bans. Right-click a user to kick or ban.</div>
      {:else}
        <ul class="ban-list">
          {#each bans as ban (ban.ip)}
            <li>
              <span class="ban-ip">{ban.ip}</span>
              <span class="ban-expiry">{expiry(ban)}</span>
              <button class="admin-cancel" onclick={() => unban(ban.ip)}>Unban</button>
            </li>
          {/each}
        </ul>
      {/if}
      <div class="admin-actions">
        <button type="button" class="admin-cancel" onclick={() => (showAdminPanel = false)}>Close</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .status-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 4px 16px;
    background: var(--bg-primary);
    border-top: 1px solid var(--border);
    font-size: 12px;
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
    font-size: 11px;
    border: 1px solid var(--danger);
  }

  .disconnect-btn:hover {
    background: var(--danger);
    color: white;
  }

  .admin-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    background: transparent;
    color: var(--text-secondary);
    padding: 4px 8px;
    font-size: 11px;
    border: 1px solid var(--border);
  }

  .admin-btn:hover,
  .admin-btn.active {
    color: var(--accent);
    border-color: var(--accent);
  }

  .admin-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 120;
  }

  .admin-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    width: min(380px, 92vw);
    display: flex;
    flex-direction: column;
    gap: 10px;
    font-size: 13px;
    color: var(--text-primary);
  }

  .admin-title {
    font-weight: 600;
    color: var(--accent);
  }

  .admin-hint {
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .admin-input {
    width: 100%;
    box-sizing: border-box;
  }

  .admin-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  .admin-cancel {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 4px 10px;
    font-size: 12px;
  }

  .admin-ok {
    padding: 4px 12px;
    font-size: 12px;
  }

  .ban-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 40vh;
    overflow-y: auto;
  }

  .ban-list li {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .ban-ip {
    font-family: monospace;
  }

  .ban-expiry {
    margin-left: auto;
    color: var(--text-secondary);
    font-size: 12px;
  }
</style>
