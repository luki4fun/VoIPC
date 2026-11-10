<script lang="ts">
  // The server name across the top of the sidebar, with its dropdown.

  import { serverAddress } from "../../stores/connection.js";
  import { copyInviteLink } from "../../stores/channel-ui.js";
  import { openAdminPanel, panelAllowed, showAdminLogin } from "../../stores/admin-ui.js";
  import { currentChannelId } from "../../stores/channels.js";
  import { disconnectServer, serverEntries } from "../../connect.js";
  import { playDisconnectedSound } from "../../sounds.js";
  import { account, showPrompt } from "../../stores/account.js";
  import { serverProfile } from "../../stores/profiles.js";
  import { cleanServerName } from "../../profile-rules.js";
  import Icon from "../Icons.svelte";
  import { menu } from "../../actions/menu.js";

  interface Props {
    /** The shell's own way into Settings. The gear in the user panel is the
     *  other one, and on a phone it is at the very bottom of a drawer — which
     *  is exactly where a system navigation bar sits. */
    onopensettings?: () => void;
  }
  let { onopensettings }: Props = $props();

  let open = $state(false);

  const entry = $derived($serverEntries.find((e) => e.active));
  const name = $derived(entry?.name ?? $serverAddress);
  /** What the server calls itself, always above its address: it is only a name. */
  const relayName = $derived(
    cleanServerName(
      $serverProfile?.name,
      $serverEntries.filter((e) => !e.active).flatMap((e) => [e.name, e.host]),
    ),
  );

  // This server only: the others, and the call if it is on one of them, stay
  async function disconnect() {
    open = false;
    await disconnectServer($serverAddress);
    playDisconnectedSound();
  }
</script>

<svelte:window onclick={() => (open = false)} />

<!-- `data-account` so test-ui.mjs can see a signed-in account; the menu that
     says so stays closed -->
<div class="server-header" data-account={$account ? "" : undefined}>
  <button
    class="header-btn"
    onclick={(e) => {
      e.stopPropagation();
      open = !open;
    }}
    title={$serverAddress}
    aria-haspopup="menu"
    aria-expanded={open}
  >
    {#if relayName}
      <span class="server-names">
        <span class="server-name">{relayName}</span>
        <span class="server-host">{entry ? `${entry.host}:${entry.port}` : $serverAddress}</span>
      </span>
    {:else}
      <span class="server-name">{name}</span>
    {/if}
    <Icon name="chevron-down" size={16} />
  </button>

  {#if open}
    <!-- The click only keeps the window's close-on-click from closing it;
         the keys are use:menu's -->
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_interactive_supports_focus -->
    <div
      class="menu"
      role="menu"
      onclick={(e) => e.stopPropagation()}
      use:menu={{ onclose: () => (open = false), label: name }}
    >
      {#if $serverProfile?.description}
        <p class="server-description">{$serverProfile.description}</p>
      {/if}
      {#if $currentChannelId !== 0}
        <button
          class="menu-item"
          onclick={() => {
            open = false;
            copyInviteLink();
          }}
        >
          <Icon name="user-plus" size={16} />
          <span>Invite people</span>
        </button>
      {/if}
      {#if $account}
        <button
          class="menu-item"
          onclick={() => {
            open = false;
            showPrompt({ kind: "account", server: $serverAddress });
          }}
        >
          <Icon name="lock" size={16} />
          <span>Your account</span>
        </button>
      {/if}
      <button
        class="menu-item"
        onclick={() => {
          open = false;
          $panelAllowed ? openAdminPanel() : showAdminLogin.set(true);
        }}
      >
        <Icon name="shield" size={16} />
        <span>{$panelAllowed ? "Server admin" : "Admin login"}</span>
      </button>
      <div class="menu-sep"></div>
      {#if onopensettings}
        <button
          class="menu-item"
          onclick={() => {
            open = false;
            onopensettings?.();
          }}
        >
          <Icon name="settings" size={16} />
          <span>Settings</span>
        </button>
      {/if}
      <div class="menu-sep"></div>
      <button class="menu-item danger" onclick={disconnect}>
        <Icon name="disconnect" size={16} />
        <span>Disconnect</span>
      </button>
    </div>
  {/if}
</div>

<style>
  .server-header {
    position: relative;
    flex-shrink: 0;
  }

  .header-btn {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
    padding: 12px 16px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: none;
    border-radius: 0;
    border-bottom: 1px solid var(--border);
    font-size: 15px;
    font-weight: 600;
  }

  /* Full width and flush with the sidebar's edges, which clip an outer ring
     to its bottom line: drawn inside instead */
  .header-btn:focus-visible {
    outline-offset: -2px;
  }

  .header-btn:hover {
    background: var(--bg-hover);
  }

  .server-names {
    display: flex;
    flex-direction: column;
    min-width: 0;
    line-height: 1.2;
    text-align: left;
  }

  .server-host {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: var(--fs-micro);
    font-weight: normal;
    color: var(--text-secondary);
  }

  .server-description {
    margin: 0;
    padding: 8px 12px;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    white-space: pre-line;
  }

  .server-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .menu {
    position: absolute;
    top: 100%;
    left: 8px;
    right: 8px;
    z-index: var(--z-dropdown);
    margin-top: 4px;
    padding: 6px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: var(--shadow-menu);
  }

  .menu-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 7px 8px;
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    font-size: var(--fs-body);
    border-radius: 4px;
  }

  .menu-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .menu-item.danger {
    color: var(--danger);
  }

  .menu-item.danger:hover {
    background: var(--danger);
    color: var(--on-danger);
  }

  .menu-sep {
    height: 1px;
    margin: 4px 0;
    background: var(--border);
  }
</style>
