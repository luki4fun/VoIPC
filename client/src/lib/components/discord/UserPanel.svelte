<script lang="ts">
  // Discord's bottom-left panel: who you are, and the two buttons you reach for
  // most. Everything it does goes through stores/voice.ts, the same actions the
  // classic voice bar and the push-to-talk key use.

  import { avatarColor } from "../../avatar.js";
  import { isDeafened, isMuted, isTransmitting, userId, username } from "../../stores/connection.js";
  import { users } from "../../stores/users.js";
  import { toggleDeafen, toggleMute } from "../../stores/voice.js";
  import Icon from "../Icons.svelte";

  interface Props {
    onopensettings: () => void;
    onopenvoice: () => void;
  }
  let { onopensettings, onopenvoice }: Props = $props();

  // The name the channel knows us by: in an anonymous channel that is not the
  // one we connected with, and the member list carries the right one.
  const displayName = $derived(
    $users.find((u) => u.user_id === $userId)?.username ?? $username,
  );
</script>

<div class="user-panel">
  <button class="me" onclick={onopenvoice} title="Voice settings">
    <span class="avatar" class:speaking={$isTransmitting} style="background: {avatarColor(displayName)}"
      >{displayName.charAt(0).toUpperCase() || "?"}</span
    >
    <span class="who">
      <span class="name">{displayName}</span>
      <span class="sub">{$isMuted ? "Muted" : $isTransmitting ? "Talking" : "Connected"}</span>
    </span>
  </button>

  <div class="panel-actions">
    <button
      class="panel-btn"
      class:danger={$isMuted}
      onclick={toggleMute}
      title={$isMuted ? "Unmute (Ctrl+M)" : "Mute (Ctrl+M)"}
    >
      <Icon name={$isMuted ? "mic-off" : "mic-on"} size={18} />
    </button>
    <button
      class="panel-btn"
      class:danger={$isDeafened}
      onclick={toggleDeafen}
      title={$isDeafened ? "Undeafen (Ctrl+D)" : "Deafen (Ctrl+D)"}
    >
      <Icon name={$isDeafened ? "headphones-off" : "headphones-on"} size={18} />
    </button>
    <!-- `settings-btn` as well as the panel styling: "open settings" is then one
         selector in either layout, which is the same reason the channel rows and
         member rows kept their class names across the split. -->
    <button class="panel-btn settings-btn" onclick={onopensettings} title="Settings">
      <Icon name="settings" size={18} />
    </button>
  </div>
</div>

<style>
  .user-panel {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 6px 8px;
    background: var(--bg-tertiary);
    flex-shrink: 0;
  }

  .me {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 0;
    padding: 4px;
    background: transparent;
    border: none;
    border-radius: 4px;
    text-align: left;
  }

  .me:hover {
    background: var(--bg-hover);
  }

  .avatar {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    color: #fff;
    font-size: 13px;
    font-weight: 600;
    flex-shrink: 0;
  }

  .avatar.speaking {
    box-shadow: 0 0 0 2px var(--speaking);
  }

  .who {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .name {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .sub {
    font-size: 11px;
    color: var(--text-secondary);
  }

  .panel-actions {
    display: flex;
    gap: 2px;
    flex-shrink: 0;
  }

  .panel-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    padding: 0;
    background: transparent;
    color: var(--text-secondary);
    border: none;
    border-radius: 4px;
  }

  .panel-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .panel-btn.danger {
    color: var(--danger);
  }
</style>
