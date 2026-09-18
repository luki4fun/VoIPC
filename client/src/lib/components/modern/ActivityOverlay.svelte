<script lang="ts">
  // The virtual room, the mixing desk and a screen share, full screen.
  //
  // VoIPC's centre column is a slot the classic layout swaps between chat, room
  // and mixer. This layout has no such column and nothing equivalent, so
  // in this layout they take the whole window and close with Escape — the shape
  // Discord uses for an Activity.
  //
  // Driven by `centreView` and `watchingUserId`, the same two stores the classic
  // layout reads. There is deliberately no third selector: the comment in
  // stores/room.ts explains why one selector beats three booleans, and that
  // reasoning did not stop applying because a second layout arrived.

  import { centreView, currentProximity } from "../../stores/room.js";
  import { poppedOut, watchingUserId } from "../../stores/screenshare.js";
  import RoomView from "../RoomView.svelte";
  import MixerView from "../MixerView.svelte";
  import ScreenShareViewer from "../ScreenShareViewer.svelte";
  import Icon from "../Icons.svelte";

  const watching = $derived($watchingUserId !== null && !$poppedOut);
  const showRoom = $derived($centreView === "room" && $currentProximity !== "off");
  const showMixer = $derived($centreView === "mixer");
  const open = $derived(watching || showRoom || showMixer);

  const title = $derived(
    watching ? "Screen share" : showRoom ? "Virtual room" : showMixer ? "Mixing desk" : "",
  );

  function close() {
    // Only the centre view is ours to reset. A share is stopped by its own
    // button, which knows to tell the server; closing this must not look like
    // that and silently keep decoding in the background.
    if (!watching) centreView.set("chat");
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && open) {
      e.preventDefault();
      close();
    }
  }
</script>

<svelte:window {onkeydown} />

{#if open}
  <div class="activity" role="dialog" aria-label={title}>
    <div class="activity-bar">
      <span class="activity-title">{title}</span>
      {#if !watching}
        <button class="activity-close" onclick={close} title="Close (Esc)">
          <Icon name="close" size={18} />
        </button>
      {/if}
    </div>
    <div class="activity-body">
      {#if watching}
        <ScreenShareViewer />
      {:else if showRoom}
        <RoomView />
      {:else if showMixer}
        <MixerView />
      {/if}
    </div>
  </div>
{/if}

<style>
  .activity {
    position: fixed;
    inset: 0;
    z-index: 90;
    display: flex;
    flex-direction: column;
    background: var(--bg-primary);
  }

  .activity-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .activity-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .activity-close {
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

  .activity-close:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .activity-body {
    flex: 1;
    display: flex;
    min-height: 0;
    overflow: hidden;
  }

  .activity-body > :global(*) {
    flex: 1;
    min-width: 0;
    min-height: 0;
  }
</style>
