<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { chatUnlocked, populateFromArchive } from "../stores/chat.js";

  let { fileExists }: { fileExists: boolean } = $props();

  let password = $state("");
  let confirmPassword = $state("");
  let error = $state("");
  let loading = $state(false);

  async function handleSubmit() {
    if (!password) {
      error = "Please enter a password";
      return;
    }

    if (!fileExists && password !== confirmPassword) {
      error = "Passwords do not match";
      return;
    }

    error = "";
    loading = true;

    try {
      if (fileExists) {
        const archive = await invoke<{
          channels: Record<string, Array<{ user_id: number; username: string; content: string; timestamp: number }>>;
          dms: Record<string, Array<{ user_id: number; username: string; content: string; timestamp: number }>>;
        }>("unlock_chat_history", { password });
        populateFromArchive(archive);
      } else {
        await invoke("create_chat_history", { password });
      }
      chatUnlocked.set(true);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
</script>

<div class="overlay">
  <div class="dialog">
    <h2>{fileExists ? "Unlock Chat History" : "Set Chat History Password"}</h2>
    <p class="hint">
      {fileExists
        ? "Enter your password to decrypt chat history."
        : "Choose a password to encrypt your chat history."}
    </p>

    <div class="field">
      <label for="password">Password</label>
      <input
        id="password"
        type="password"
        bind:value={password}
        placeholder="Enter password"
        disabled={loading}
        onkeydown={(e) => e.key === "Enter" && handleSubmit()}
      />
    </div>

    {#if !fileExists}
      <div class="field">
        <label for="confirm">Confirm Password</label>
        <input
          id="confirm"
          type="password"
          bind:value={confirmPassword}
          placeholder="Confirm password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleSubmit()}
        />
      </div>
    {/if}

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <button class="submit-btn" onclick={handleSubmit} disabled={loading}>
      {loading ? "Processing..." : fileExists ? "Unlock" : "Create"}
    </button>
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
    z-index: 200;
  }

  .dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 32px;
    width: 360px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  h2 {
    text-align: center;
    font-size: 20px;
    color: var(--accent);
  }

  .hint {
    text-align: center;
    font-size: 13px;
    color: var(--text-secondary);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  label {
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .error {
    color: var(--danger);
    font-size: 13px;
    text-align: center;
  }

  .submit-btn {
    background: var(--accent);
    color: white;
    padding: 10px;
    font-size: 14px;
    font-weight: 600;
    margin-top: 8px;
  }

  .submit-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .submit-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
