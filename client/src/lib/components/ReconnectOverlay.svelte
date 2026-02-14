<script lang="ts">
  interface Props {
    attempt: number;
    oncancel: () => void;
  }

  let { attempt, oncancel }: Props = $props();
</script>

<div class="overlay">
  <div class="dialog">
    <div class="spinner"></div>
    <h2>Connection Lost</h2>
    <p class="message">Reconnecting... attempt #{attempt}</p>
    <button class="cancel-btn" onclick={oncancel}>Cancel</button>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 32px;
    width: 320px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  h2 {
    font-size: 18px;
    color: var(--text-primary);
    margin: 0;
  }

  .message {
    font-size: 14px;
    color: var(--text-secondary);
    margin: 0;
  }

  .cancel-btn {
    background: transparent;
    color: var(--danger);
    padding: 8px 24px;
    font-size: 13px;
    border: 1px solid var(--danger);
    cursor: pointer;
    border-radius: 4px;
  }

  .cancel-btn:hover {
    background: var(--danger);
    color: white;
  }
</style>
