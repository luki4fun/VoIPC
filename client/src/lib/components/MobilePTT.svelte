<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { isMuted, isDeafened, isTransmitting } from '../stores/connection';
  import { voiceMode } from '../stores/voice';

  let pressing = $state(false);

  function onTouchStart(e: TouchEvent) {
    e.preventDefault();
    if ($isMuted || $isDeafened) return;
    pressing = true;
    invoke('start_transmit').then(() => {
      isTransmitting.set(true);
    }).catch(() => {});
  }

  function onTouchEnd(e: TouchEvent) {
    e.preventDefault();
    pressing = false;
    invoke('stop_transmit').then(() => {
      isTransmitting.set(false);
    }).catch(() => {});
  }
</script>

{#if $voiceMode === 'ptt'}
  <button
    class="mobile-ptt"
    class:pressing
    class:transmitting={$isTransmitting}
    class:disabled={$isMuted || $isDeafened}
    ontouchstart={onTouchStart}
    ontouchend={onTouchEnd}
    ontouchcancel={onTouchEnd}
  >
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
      <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
      <line x1="12" y1="19" x2="12" y2="23"/>
      <line x1="8" y1="23" x2="16" y2="23"/>
    </svg>
    <span>{pressing ? 'Release to stop' : 'Hold to talk'}</span>
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
    font-size: 13px;
    touch-action: none;
    user-select: none;
    -webkit-user-select: none;
    transition: all 0.15s ease;
  }

  .mobile-ptt.pressing,
  .mobile-ptt.transmitting {
    background: var(--speaking);
    border-color: var(--speaking);
    color: white;
  }

  .mobile-ptt.disabled {
    opacity: 0.4;
    pointer-events: none;
  }
</style>
