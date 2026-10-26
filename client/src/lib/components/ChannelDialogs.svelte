<script lang="ts">
  // The channel overlays: the password prompt on the way into a locked
  // channel, the 18+ question on the way into a marked one, the invite link
  // when the clipboard is blocked, and the channel settings dialog.
  //
  // Mounted once by App.svelte, so both sidebars open the same dialogs. The
  // settings checkboxes carry `data-opt` because test-ui.mjs used to click them
  // by array index, and moving this markup is exactly the change that would
  // have silently set the wrong options.

  import { backdrop, dialog } from "../actions/dialog.js";
  import {
    cancelChannelSettings,
    cancelNsfwPrompt,
    cancelPasswordPrompt,
    confirmNsfwPrompt,
    inviteLinkPopup,
    nsfwPrompt,
    passwordEditChannelId,
    passwordEditHasPassword,
    passwordEditInput,
    passwordEditRemove,
    passwordPromptChannelId,
    passwordPromptInput,
    settingsAnnounce,
    settingsAnonymous,
    settingsHidden,
    settingsHideMembers,
    settingsMessageTtl,
    settingsIsText,
    settingsNsfw,
    settingsProximity,
    settingsRouted,
    settingsScreenShare,
    settingsSlowMode,
    submitChannelSettings,
    submitPasswordJoin,
  } from "../stores/channel-ui.js";
  import { SLOW_MODE_CHOICES, slowModeLabel } from "../channel-post-rules.js";

  // A value from channels.json the list does not offer is still shown as it
  // is, rather than as an empty select that would save as something else.
  let slowChoices = $derived(
    (SLOW_MODE_CHOICES as readonly number[]).includes($settingsSlowMode)
      ? [...SLOW_MODE_CHOICES]
      : [...SLOW_MODE_CHOICES, $settingsSlowMode].sort((a, b) => a - b),
  );
</script>

{#if $passwordPromptChannelId !== null}
  <div class="overlay" onclick={backdrop(cancelPasswordPrompt)} role="presentation">
    <form
      class="password-dialog"
      use:dialog={{ onclose: cancelPasswordPrompt }}
      onsubmit={(e) => { e.preventDefault(); submitPasswordJoin(); }}
    >
      <div class="dialog-title">Enter password</div>
      <input
        class="dialog-input"
        type="password"
        placeholder="Channel password"
        bind:value={$passwordPromptInput}
      />
      <div class="dialog-actions">
        <button class="create-btn btn btn-primary" type="submit">Join</button>
        <button class="cancel-btn" type="button" onclick={cancelPasswordPrompt}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

{#if $nsfwPrompt !== null}
  <div class="overlay" onclick={backdrop(cancelNsfwPrompt)} role="presentation">
    <form
      class="password-dialog"
      use:dialog={{ onclose: cancelNsfwPrompt }}
      onsubmit={(e) => { e.preventDefault(); confirmNsfwPrompt(); }}
    >
      <div class="dialog-title">18+ channel</div>
      <p class="dialog-note">
        {$nsfwPrompt.name} is marked 18+. Only go in if you are 18 or older. This server's 18+
        channels will not ask again.
      </p>
      <div class="dialog-actions">
        <button class="create-btn btn btn-primary" type="submit" data-opt="nsfw-confirm">I am 18 or older</button>
        <button class="cancel-btn" type="button" onclick={cancelNsfwPrompt}>Go back</button>
      </div>
    </form>
  </div>
{/if}

{#if $inviteLinkPopup !== null}
  <div class="overlay" onclick={backdrop(() => inviteLinkPopup.set(null))} role="presentation">
    <div
      class="password-dialog"
      use:dialog={{ onclose: () => inviteLinkPopup.set(null) }}
    >
      <div class="dialog-title">Invite link</div>
      <input class="dialog-input" readonly value={$inviteLinkPopup} onfocus={(e) => e.currentTarget.select()} />
      <div class="dialog-actions">
        <button class="cancel-btn" type="button" onclick={() => inviteLinkPopup.set(null)}>Close</button>
      </div>
    </div>
  </div>
{/if}

{#if $passwordEditChannelId !== null}
  <div class="overlay" onclick={backdrop(cancelChannelSettings)} role="presentation">
    <form
      class="password-dialog"
      use:dialog={{ onclose: cancelChannelSettings }}
      onsubmit={(e) => { e.preventDefault(); submitChannelSettings(); }}
    >
      <div class="dialog-title">Channel settings</div>
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
      <!-- A text channel carries no voice, so the options about voice are not
           shown for one: there is nothing there to place, forward or share. -->
      {#if !$settingsIsText}
        <label class="dialog-label">
          Proximity chat
          <select class="dialog-input" bind:value={$settingsProximity}>
            <option value="off">Off — everyone equally loud</option>
            <option value="2d">2D — on a floor plan</option>
            <option value="3d">3D — height counts too</option>
          </select>
        </label>
      {/if}
      <label class="dialog-check">
        <input type="checkbox" data-opt="hidden" bind:checked={$settingsHidden} />
        Hidden — not listed for anyone but admins
      </label>
      {#if !$settingsIsText}
        <label class="dialog-check">
          <input type="checkbox" data-opt="anonymous" bind:checked={$settingsAnonymous} />
          Anonymous — random names instead of real ones
        </label>
      {/if}
      <label class="dialog-check">
        <input type="checkbox" data-opt="hide-members" bind:checked={$settingsHideMembers} />
        Hide members — non-admins see only who is speaking
      </label>
      <label class="dialog-label">
        Message destruction timer
        <select class="dialog-input" data-opt="message-ttl" bind:value={$settingsMessageTtl}>
          <option value={0}>Off — messages stay until somebody deletes them</option>
          <option value={300}>5 minutes</option>
          <option value={3600}>1 hour</option>
          <option value={28800}>8 hours</option>
          <option value={86400}>24 hours</option>
          <option value={604800}>7 days</option>
        </select>
      </label>
      <p class="dialog-note">
        Every message written here is deleted for everyone once its timer runs out — including
        from the copies members hand to people who join later. The timer travels inside the
        encryption, so the server can neither read it nor change it; it applies to what is
        written from now on, not to what people already have.
      </p>
      <label class="dialog-label">
        Slow mode
        <select class="dialog-input" data-opt="slow-mode" bind:value={$settingsSlowMode}>
          {#each slowChoices as secs (secs)}
            <option value={secs}>
              {secs === 0 ? "Off — post as often as you like" : `One post every ${slowModeLabel(secs)}`}
            </option>
          {/each}
        </select>
      </label>
      {#if $settingsIsText}
        <label class="dialog-check">
          <input type="checkbox" data-opt="announce" bind:checked={$settingsAnnounce} />
          Announcements — only moderators post here
        </label>
      {/if}
      <label class="dialog-check">
        <input type="checkbox" data-opt="nsfw" bind:checked={$settingsNsfw} />
        18+ — members confirm their age before it opens
      </label>
      <p class="dialog-note">
        The server holds members to slow mode and announcements from who posts where and when; it
        still reads nothing. The channel's creator, admins and moderators are exempt. 18+ is a
        question each app asks, not an age check — a password is what keeps people out.
      </p>
      {#if !$settingsIsText}
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
      {/if}
      <div class="dialog-actions">
        <button class="create-btn btn btn-primary" type="submit">Save</button>
        <button class="cancel-btn" type="button" onclick={cancelChannelSettings}>Cancel</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-dialog);
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
    /* The window can be 640×480: the dialog scrolls, its buttons stay reachable */
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
  }

  .dialog-title {
    font-size: var(--fs-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .dialog-input {
    padding: 8px 10px;
    font-size: var(--fs-md);
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
  }

  .dialog-input:focus {
    border-color: var(--focus-ring);
  }

  .dialog-actions {
    display: flex;
    gap: 8px;
  }

  .dialog-label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .dialog-check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  /* What an option actually shares, spelled out where it is switched on.
     A setting that changes what the server learns has to say so. */
  .dialog-note {
    margin: -2px 0 0 22px;
    font-size: var(--fs-micro);
    line-height: 1.4;
    color: var(--text-secondary);
    opacity: 0.85;
  }

  .create-btn {
    flex: 1;
    padding: 4px 8px;
    font-size: var(--fs-sm);
  }

  .cancel-btn {
    flex: 1;
    padding: 4px 8px;
    font-size: var(--fs-sm);
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
