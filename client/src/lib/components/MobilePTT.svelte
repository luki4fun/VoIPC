<script lang="ts">
  import { isMuted, isDeafened, isTransmitting } from '../stores/connection';
  import { startTransmit, stopTransmit, voiceMode } from '../stores/voice';
  import Icon from './Icons.svelte';

  /** One row instead of two, for when the screen is short of room: the
   *  keyboard is up, or a sheet sits above it. A prop rather than a second
   *  button, so a press held across the change is the same press. */
  let { slim = false }: { slim?: boolean } = $props();

  let pressing = $state(false);
  /** A press that came with a pointer: its click is the end of a hold, not a toggle. */
  let fromPointer = false;

  const blocked = $derived($isMuted || $isDeafened);

  // Through the shared actions rather than invoking directly, which is also
  // what gives this button the guard it never had: outside a voice channel
  // holding it used to start a capture task that had nowhere to send. The
  // shells now mount it only in voice as well.
  function press() {
    if (blocked || pressing) return;
    pressing = true;
    void startTransmit();
  }

  function release() {
    if (!pressing) return;
    pressing = false;
    void stopTransmit();
  }

  // A press still held when the button goes away is let go (R5-08): the
  // screen-reader toggle has no pointer release, and an unmount that never
  // blurs the button (WebKitGTK, Android's WebView may not) left the
  // microphone open until the next press. Also a switch away from push to
  // talk mid-press, which removes the button and keeps this component.
  function letGoOnRemove(_node: HTMLElement) {
    return { destroy: release };
  }

  // Any pointer — finger, stylus, mouse — held, and captured so a thumb that
  // slides off the button still holds it. It was touch events only.
  function onpointerdown(e: PointerEvent) {
    e.preventDefault();
    fromPointer = true;
    (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
    press();
  }

  // A screen reader cannot hold: TalkBack's double tap arrives as a click with
  // no press before it. That click toggles talking instead.
  function onclick() {
    if (fromPointer) {
      fromPointer = false;
      return;
    }
    if (pressing) release();
    else press();
  }

  function onkeydown(e: KeyboardEvent) {
    if ((e.key === ' ' || e.key === 'Enter') && !e.repeat) {
      e.preventDefault();
      press();
    }
  }

  function onkeyup(e: KeyboardEvent) {
    if (e.key === ' ' || e.key === 'Enter') {
      e.preventDefault();
      release();
    }
  }
</script>

{#if $voiceMode === 'ptt'}
  <button
    class="mobile-ptt"
    class:slim
    class:pressing
    class:transmitting={$isTransmitting}
    class:disabled={blocked}
    aria-pressed={pressing}
    aria-disabled={blocked}
    aria-label={blocked ? 'Talk (unmute first)' : 'Talk'}
    {onpointerdown}
    onpointerup={release}
    onpointercancel={release}
    onlostpointercapture={release}
    {onclick}
    {onkeydown}
    {onkeyup}
    onblur={release}
    use:letGoOnRemove
  >
    <Icon name="mic-on" size={slim ? 20 : 32} />
    <span aria-hidden="true">{blocked ? 'Unmute to talk' : pressing ? 'Release to stop' : 'Hold to talk'}</span>
  </button>
{/if}

<style>
  .mobile-ptt {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
    width: 100%;
    padding: 12px;
    flex-shrink: 0;
    border: 2px solid var(--border);
    border-radius: 12px;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: var(--fs-body);
    touch-action: none;
    user-select: none;
    -webkit-user-select: none;
    transition: background-color var(--dur-fast), border-color var(--dur-fast), color var(--dur-fast);
  }

  .mobile-ptt.slim {
    flex-direction: row;
    gap: 8px;
    min-height: var(--hit);
    padding: 4px 12px;
  }

  .mobile-ptt.pressing,
  .mobile-ptt.transmitting {
    background: var(--speaking);
    border-color: var(--speaking);
    color: var(--on-success);
  }

  .mobile-ptt.disabled {
    opacity: 0.4;
    pointer-events: none;
  }
</style>
