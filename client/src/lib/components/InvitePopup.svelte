<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { pendingInvites } from "../stores/invites.js";

  async function accept(channelId: number) {
    pendingInvites.update((inv) =>
      inv.filter((i) => i.channel_id !== channelId),
    );
    try {
      await invoke("accept_invite", { channelId });
    } catch (e) {
      console.error("Failed to accept invite:", e);
    }
  }

  async function decline(channelId: number) {
    pendingInvites.update((inv) =>
      inv.filter((i) => i.channel_id !== channelId),
    );
    try {
      await invoke("decline_invite", { channelId });
    } catch (e) {
      console.error("Failed to decline invite:", e);
    }
  }
</script>

{#if $pendingInvites.length > 0}
  <div class="invite-container">
    {#each $pendingInvites as invite (invite.channel_id)}
      <div class="invite">
        <span class="invite-text">
          <strong>{invite.invited_by}</strong> invited you to <strong>#{invite.channel_name}</strong>
        </span>
        <div class="invite-actions">
          <button class="accept-btn" onclick={() => accept(invite.channel_id)}>Accept</button>
          <button class="decline-btn" onclick={() => decline(invite.channel_id)}>Decline</button>
        </div>
      </div>
    {/each}
  </div>
{/if}

<style>
  .invite-container {
    position: fixed;
    top: 48px;
    right: 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 150;
  }

  .invite {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 14px;
    border-radius: 6px;
    background: var(--bg-secondary);
    border: 1px solid var(--accent);
    color: var(--text-primary);
    font-size: 13px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
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

  .invite-text {
    flex: 1;
  }

  .invite-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
  }

  .accept-btn {
    background: var(--accent);
    color: white;
    border: none;
    padding: 4px 10px;
    font-size: 12px;
    border-radius: 4px;
    cursor: pointer;
  }

  .accept-btn:hover {
    opacity: 0.9;
  }

  .decline-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 4px 10px;
    font-size: 12px;
    border-radius: 4px;
    cursor: pointer;
  }

  .decline-btn:hover {
    color: var(--text-primary);
  }
</style>
