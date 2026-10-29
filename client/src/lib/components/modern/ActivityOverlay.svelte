<script lang="ts">
  // The virtual room, the mixing desk and a screen share, full screen.
  //
  // VoIPC's centre column is a slot the classic layout swaps between chat, room
  // and mixer. This layout has no such column and nothing equivalent, so
  // in this layout they take the whole window and close with Escape — the shape
  // Discord uses for an Activity.
  //
  // Driven by `centreView` and `streamStage`, the same two stores the classic
  // layout reads. There is deliberately no third selector: the comment in
  // stores/room.ts explains why one selector beats three booleans, and that
  // reasoning did not stop applying because a second layout arrived.
  //
  // A share — watched, or the preview of our own — comes with its chat when
  // asked for (StreamStage), so this view no longer costs the conversation.

  import { dialog } from "../../actions/dialog.js";
  import { pushLayer } from "../../stores/back-stack.js";
  import { centreView, currentProximity } from "../../stores/room.js";
  import { previewStage, stopWatching, streamStage } from "../../stores/screenshare.js";
  import RoomView from "../RoomView.svelte";
  import MixerView from "../MixerView.svelte";
  import StreamStage from "../StreamStage.svelte";
  import Icon from "../Icons.svelte";

  interface Props {
    /** Height of the phone's talk button, which draws over this view: the
     *  body leaves that much room so the bottom of the view stays usable. */
    pttSpace?: number;
  }
  let { pttSpace = 0 }: Props = $props();

  const watching = $derived($streamStage === "watch");
  const showRoom = $derived($centreView === "room" && $currentProximity !== "off");
  const showMixer = $derived($centreView === "mixer");
  const open = $derived($streamStage !== null || showRoom || showMixer);

  const title = $derived(
    watching
      ? "Screen share"
      : $streamStage === "preview"
        ? "Your screen"
        : showRoom
          ? "Virtual room"
          : showMixer
            ? "Mixing desk"
            : "",
  );

  function close() {
    // Only the view is ours to reset. A watched share is stopped by its own
    // button, which knows to tell the server; closing this must not look like
    // that and silently keep decoding in the background. Our own preview
    // just goes back to its card.
    if ($streamStage === "preview") previewStage.set(false);
    else if (!watching) centreView.set("chat");
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === "Escape" && open) {
      e.preventDefault();
      close();
    }
  }

  // Android's Back leaves a watched share the way its Stop button does — that
  // is what Back means on a phone. Escape does not: on a desktop it is also
  // the key that leaves fullscreen, and must never stop the stream with it.
  // Pushed after the dialog's own layer, so it is the one Back reaches first.
  $effect(() => {
    if (!open || !watching) return;
    return pushLayer(() => void stopWatching());
  });
</script>

<svelte:window {onkeydown} />

{#if open}
  <div
    class="activity"
    aria-label={title}
    style="--ptt-space: {pttSpace}px"
    use:dialog={{ onclose: watching ? undefined : close }}
  >
    <div class="activity-bar">
      <span class="activity-title">{title}</span>
      {#if !watching}
        <button aria-label="Close (Esc)" class="activity-close" onclick={close} title="Close (Esc)">
          <Icon name="close" size={18} />
        </button>
      {/if}
    </div>
    <div class="activity-body">
      {#if $streamStage !== null}
        <StreamStage />
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
    z-index: var(--z-activity);
    display: flex;
    flex-direction: column;
    background: var(--bg-primary);
    /* Android draws the WebView under its status and navigation bars, the
       same as for the shell: without these the bar sits under the clock and
       a docked chat's message box under the back button. Zero elsewhere. */
    box-sizing: border-box;
    padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom)
      env(safe-area-inset-left);
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
    font-size: var(--fs-body);
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
    padding-bottom: var(--ptt-space, 0px);
  }

  .activity-body > :global(*) {
    flex: 1;
    min-width: 0;
    min-height: 0;
  }

  @media (pointer: coarse) {
    .activity-close {
      width: var(--hit);
      height: var(--hit);
    }
  }
</style>
