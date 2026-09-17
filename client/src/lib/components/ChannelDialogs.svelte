<script lang="ts">
  // The three channel overlays: the password prompt on the way into a locked
  // channel, the invite link when the clipboard is blocked, and the channel
  // settings dialog.
  //
  // Mounted once by App.svelte, so both sidebars open the same dialogs. The
  // settings checkboxes carry `data-opt` because test-ui.mjs used to click them
  // by array index, and moving this markup is exactly the change that would
  // have silently set the wrong options.

  import {
    cancelChannelSettings,
    cancelPasswordPrompt,
    inviteLinkPopup,
    passwordEditChannelId,
    passwordEditHasPassword,
    passwordEditInput,
    passwordEditRemove,
    passwordPromptChannelId,
    passwordPromptInput,
    settingsAnonymous,
    settingsHidden,
    settingsHideMembers,
    settingsProximity,
    settingsRouted,
    settingsScreenShare,
    submitChannelSettings,
    submitPasswordJoin,
  } from "../stores/channel-ui.js";
</script>

{#if $passwordPromptChannelId !== null}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" onclick={cancelPasswordPrompt} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_to_interactive_role a11y_no_noninteractive_element_interactions -->
    <form
      class="password-dialog"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') cancelPasswordPrompt(); }}
      onsubmit={(e) => { e.preventDefault(); submitPasswordJoin(); }}
    >
      <div class="dialog-title">Enter Password</div>
      <input
        class="dialog-input"
        type="password"
        placeholder="Channel password"
        bind:value={$passwordPromptInput}
      />
      <div class="dialog-actions">
        <button class="create-btn" type="submit">Join</button>
        <button class="cancel-btn" type="button" onclick={cancelPasswordPrompt}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

{#if $inviteLinkPopup !== null}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" onclick={() => inviteLinkPopup.set(null)} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="password-dialog" onclick={(e) => e.stopPropagation()}>
      <div class="dialog-title">Invite link</div>
      <input class="dialog-input" readonly value={$inviteLinkPopup} onfocus={(e) => e.currentTarget.select()} />
      <div class="dialog-actions">
        <button class="cancel-btn" type="button" onclick={() => inviteLinkPopup.set(null)}>Close</button>
      </div>
    </div>
  </div>
{/if}

{#if $passwordEditChannelId !== null}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" onclick={cancelChannelSettings} role="presentation">
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_to_interactive_role a11y_no_noninteractive_element_interactions -->
    <form
      class="password-dialog"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => { if (e.key === 'Escape') cancelChannelSettings(); }}
      onsubmit={(e) => { e.preventDefault(); submitChannelSettings(); }}
    >
      <div class="dialog-title">Channel Settings</div>
      <input
        class="dialog-input"
        type="password"
        placeholder={$passwordEditHasPassword ? "New password (empty: keep current)" : "Set a password (optional)"}
        bind:value={$passwordEditInput}
        disabled={$passwordEditRemove}
      />
      {#if $passwordEditHasPassword}
        <label class="dialog-check">
          <input type="checkbox" bind:checked={$passwordEditRemove} />
          Remove the password
        </label>
      {/if}
      <label class="dialog-label">
        Proximity chat
        <select class="dialog-input" bind:value={$settingsProximity}>
          <option value="off">Off — everyone equally loud</option>
          <option value="2d">2D — on a floor plan</option>
          <option value="3d">3D — height counts too</option>
        </select>
      </label>
      <label class="dialog-check">
        <input type="checkbox" data-opt="hidden" bind:checked={$settingsHidden} />
        Hidden — not listed for anyone but admins
      </label>
      <label class="dialog-check">
        <input type="checkbox" data-opt="anonymous" bind:checked={$settingsAnonymous} />
        Anonymous — random names instead of real ones
      </label>
      <label class="dialog-check">
        <input type="checkbox" data-opt="hide-members" bind:checked={$settingsHideMembers} />
        Hide members — non-admins see only who is speaking
      </label>
      <label class="dialog-check">
        <input type="checkbox" data-opt="screen-share" bind:checked={$settingsScreenShare} />
        Allow screen sharing
      </label>
      <label class="dialog-check">
        <input type="checkbox" data-opt="routed" bind:checked={$settingsRouted} />
        Routed — the server forwards each voice only to whoever should hear it
      </label>
      <p class="dialog-note">
        For a channel a game drives, where everyone in it can be a whole map. It is the one
        setting that tells the server anything about who hears whom: members here tell it which
        of the others they want to hear, and a connected game server may narrow that further.
        The server still never receives positions, names it does not already have, or audio it
        can read. Off everywhere else, where fanning out to the whole channel costs nothing.
      </p>
      <div class="dialog-actions">
        <button class="create-btn" type="submit">Save</button>
        <button class="cancel-btn" type="button" onclick={cancelChannelSettings}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .password-dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    min-width: 280px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .dialog-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .dialog-input {
    padding: 8px 10px;
    font-size: 14px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
  }

  .dialog-input:focus {
    border-color: var(--accent);
  }

  .dialog-actions {
    display: flex;
    gap: 8px;
  }

  .create-label,
  .dialog-label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .dialog-check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-secondary);
  }

  /* What an option actually shares, spelled out where it is switched on.
     A setting that changes what the server learns has to say so. */
  .dialog-note {
    margin: -2px 0 0 22px;
    font-size: 11px;
    line-height: 1.4;
    color: var(--text-secondary);
    opacity: 0.85;
  }

  .create-btn {
    flex: 1;
    padding: 4px 8px;
    font-size: 12px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  .create-btn:hover {
    opacity: 0.9;
  }

  .cancel-btn {
    flex: 1;
    padding: 4px 8px;
    font-size: 12px;
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
  }

  .cancel-btn:hover {
    color: var(--text-primary);
  }
</style>
