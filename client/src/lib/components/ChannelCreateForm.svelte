<script lang="ts">
  // The create-channel form. Inline rather than a modal, because it belongs in
  // the sidebar it was opened from — which is why it is its own component and
  // not part of ChannelDialogs: both sidebars render it in their own header.
  //
  // `.create-form` and `.create-form .create-btn` are driven by test-ui.mjs.

  import {
    cancelCreate,
    createChannel,
    newChannelAnonymous,
    newChannelName,
    newChannelPassword,
    newChannelProximity,
    newChannelText,
    showCreateForm,
  } from "../stores/channel-ui.js";
</script>


  {#if $showCreateForm}
    <form class="create-form" onsubmit={(e) => { e.preventDefault(); createChannel(); }}>
      <input
        class="create-input"
        type="text"
        placeholder="Channel name"
        bind:value={$newChannelName}
        maxlength="32"
      />
      <input
        class="create-input"
        type="password"
        placeholder="Password (optional)"
        bind:value={$newChannelPassword}
      />
      <!-- Radios rather than a select: `.create-form select` is how test-ui.mjs
           reaches the proximity dropdown, and a second select above it would
           silently become the one it sets. -->
      <div class="create-kind">
        <label>
          <input type="radio" data-kind="voice" value={false} bind:group={$newChannelText} />
          Voice
        </label>
        <label>
          <input type="radio" data-kind="text" value={true} bind:group={$newChannelText} />
          Text
        </label>
      </div>
      {#if !$newChannelText}
        <label class="create-label">
          Proximity chat
          <select class="create-input" bind:value={$newChannelProximity}>
            <option value="off">Off — everyone equally loud</option>
            <option value="2d">2D — on a floor plan</option>
            <option value="3d">3D — height counts too</option>
          </select>
        </label>
      {/if}
      {#if !$newChannelText}
        <!-- A pseudonym only hides somebody who is nowhere else, and a text
             channel is one you are in *besides* the voice channel you stand
             in — the same user id is in both rosters. The server refuses the
             combination; not offering it is how the user finds out early. -->
        <label class="dialog-check">
          <input type="checkbox" bind:checked={$newChannelAnonymous} />
          Anonymous (everyone gets a random name)
        </label>
      {/if}
      <div class="create-actions">
        <button class="create-btn" type="submit">Create</button>
        <button class="cancel-btn" type="button" onclick={cancelCreate}>Cancel</button>
      </div>
    </form>
  {/if}

<style>
  .create-form {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 8px;
    border-bottom: 1px solid var(--border);
  }

  .create-input {
    padding: 6px 8px;
    font-size: 13px;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    outline: none;
  }

  .create-input:focus {
    border-color: var(--accent);
  }

  .create-actions {
    display: flex;
    gap: 6px;
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

  .create-label,
  .dialog-label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .create-kind {
    display: flex;
    gap: 12px;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .create-kind label {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .dialog-check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-secondary);
  }
</style>
