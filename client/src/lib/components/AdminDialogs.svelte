<script lang="ts">
  // Admin token login, and the list of active bans.
  //
  // Mounted once by App.svelte. Both layouts have a shield button somewhere —
  // the classic status bar, the modern layout's voice panel — and both open these.

  import {
    adminToken,
    bans,
    expiry,
    showAdminLogin,
    showAdminPanel,
    submitAdminLogin,
    unban,
  } from "../stores/admin-ui.js";
</script>

{#if $showAdminLogin}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="admin-overlay" onclick={() => showAdminLogin.set(false)}>
    <form class="admin-dialog" onclick={(e) => e.stopPropagation()} onsubmit={(e) => { e.preventDefault(); submitAdminLogin(); }}>
      <div class="admin-title">Admin login</div>
      <div class="admin-hint">The admin token is in the server's config (<code>admin_token</code>) or, if none is set, in the server log at startup.</div>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="admin-input" type="password" placeholder="Admin token" bind:value={$adminToken} autofocus />
      <div class="admin-actions">
        <button type="button" class="admin-cancel" onclick={() => showAdminLogin.set(false)}>Cancel</button>
        <button type="submit" class="admin-ok" disabled={!$adminToken.trim()}>Log in</button>
      </div>
    </form>
  </div>
{/if}

{#if $showAdminPanel}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="admin-overlay" onclick={() => showAdminPanel.set(false)}>
    <div class="admin-dialog" onclick={(e) => e.stopPropagation()}>
      <div class="admin-title">Active bans</div>
      {#if $bans.length === 0}
        <div class="admin-hint">No active bans. Right-click a user to kick or ban.</div>
      {:else}
        <ul class="ban-list">
          {#each $bans as ban (ban.ip)}
            <li>
              <span class="ban-ip">{ban.ip}</span>
              <span class="ban-expiry">{expiry(ban)}</span>
              <button class="admin-cancel" onclick={() => unban(ban.ip)}>Unban</button>
            </li>
          {/each}
        </ul>
      {/if}
      <div class="admin-actions">
        <button type="button" class="admin-cancel" onclick={() => showAdminPanel.set(false)}>Close</button>
      </div>
    </div>
  </div>
{/if}

<style>
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
