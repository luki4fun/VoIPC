<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { addNotification } from "../stores/notifications.js";
  import { pendingInvites, type PendingInvite } from "../stores/invites.js";
  import { serverAddress } from "../stores/connection.js";
  import { serverEntries } from "../connect.js";
  import { askNsfwConsent } from "../stores/channel-ui.js";
  import { shortName } from "../username.js";

  function drop(invite: PendingInvite) {
    pendingInvites.update((inv) => inv.filter((i) => i !== invite));
  }

  // Back to the server that sent it, whichever one is on screen now
  async function accept(invite: PendingInvite) {
    drop(invite);
    const go = async () => {
      try {
        await invoke("accept_invite", { server: invite.server, channelId: invite.channel_id });
      } catch (e) {
        console.error("Failed to accept invite:", e);
        addNotification(`Could not join the channel you were invited to: ${e}`, "error");
      }
    };
    // Into an 18+ channel only once the user has said they may be there
    if (askNsfwConsent(invite.server, invite.channel_id, () => void go())) await go();
  }

  async function decline(invite: PendingInvite) {
    drop(invite);
    try {
      await invoke("decline_invite", { server: invite.server, channelId: invite.channel_id });
    } catch (e) {
      console.error("Failed to decline invite:", e);
      addNotification(`Could not decline the invite: ${e}`, "error");
    }
  }
</script>

{#if $pendingInvites.length > 0}
  <div class="invite-container">
    {#each $pendingInvites as invite (invite.server + "/" + invite.channel_id)}
      <div class="invite">
        <span class="invite-text">
          <strong title={invite.invited_by}>{shortName(invite.invited_by)}</strong> invited you to <strong>#{invite.channel_name}</strong
          >{#if invite.server !== $serverAddress}&nbsp;on {$serverEntries.find((e) => e.id === invite.server)?.name ?? invite.server}{/if}
        </span>
        <div class="invite-actions">
          <button class="accept-btn btn btn-primary" onclick={() => accept(invite)}>Accept</button>
          <button class="decline-btn" onclick={() => decline(invite)}>Decline</button>
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
    z-index: var(--z-popover);
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
    font-size: var(--fs-body);
    box-shadow: var(--shadow-menu);
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
    padding: 4px 10px;
    font-size: var(--fs-sm);
  }

  .decline-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    padding: 4px 10px;
    font-size: var(--fs-sm);
    border-radius: 4px;
    cursor: pointer;
  }

  .decline-btn:hover {
    color: var(--text-primary);
  }
</style>
