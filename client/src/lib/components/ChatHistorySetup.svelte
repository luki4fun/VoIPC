<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    chatUnlocked,
    chatHistoryStatus,
    populateFromArchive,
    type ChatHistoryStatus,
  } from "../stores/chat.js";

  type Mode =
    | "loading"
    | "first_run"
    | "unlock"
    | "create_new"
    | "delete_confirm"
    | "change_path"
    | "change_path_unlock"
    | "change_path_create";

  let mode = $state<Mode>("loading");
  let currentPath = $state("");
  let selectedDirectory = $state("");
  let newFullPath = $state("");
  let password = $state("");
  let confirmPassword = $state("");
  let deleteConfirmText = $state("");
  let error = $state("");
  let loading = $state(false);
  let previousMode = $state<Mode>("unlock");

  $effect(() => {
    loadStatus();
  });

  async function loadStatus() {
    mode = "loading";
    error = "";
    try {
      const status = await invoke<ChatHistoryStatus>("get_chat_history_status");
      chatHistoryStatus.set(status);
      currentPath = status.current_path;

      if (!status.path_configured && !status.file_exists) {
        mode = "first_run";
      } else if (status.file_exists) {
        mode = "unlock";
      } else {
        mode = "create_new";
      }
    } catch (e) {
      error = String(e);
      mode = "first_run";
    }
  }

  function resetFields() {
    password = "";
    confirmPassword = "";
    deleteConfirmText = "";
    error = "";
    loading = false;
  }

  function goToDeleteConfirm() {
    previousMode = mode;
    resetFields();
    mode = "delete_confirm";
  }

  function goToChangePath() {
    previousMode = mode;
    resetFields();
    selectedDirectory = "";
    newFullPath = "";
    mode = "change_path";
  }

  function goBack() {
    resetFields();
    mode = previousMode;
  }

  async function browseDirectory(): Promise<string | null> {
    try {
      const dir = await invoke<string | null>("browse_chat_history_directory");
      return dir;
    } catch (e) {
      error = String(e);
      return null;
    }
  }

  async function handleBrowseFirstRun() {
    const dir = await browseDirectory();
    if (dir) {
      selectedDirectory = dir;
      currentPath = dir + "/chat_history.bin";
    }
  }

  function useDefaultPath() {
    // Clear selection to signal "use default" — set_chat_history_path will be called
    // with the default data_dir
    selectedDirectory = "";
  }

  async function handleFirstRunCreate() {
    if (!password) {
      error = "Please enter a password";
      return;
    }
    if (password !== confirmPassword) {
      error = "Passwords do not match";
      return;
    }
    error = "";
    loading = true;
    try {
      // If a directory was chosen, set it; otherwise use default
      if (selectedDirectory) {
        const result = await invoke<{ full_path: string; file_exists: boolean }>(
          "set_chat_history_path",
          { directory: selectedDirectory },
        );
        if (result.file_exists) {
          // File already exists at chosen path — switch to unlock flow
          newFullPath = result.full_path;
          currentPath = result.full_path;
          resetFields();
          mode = "unlock";
          return;
        }
      } else {
        // Use default directory — extract dir from current default path
        const status = await invoke<ChatHistoryStatus>("get_chat_history_status");
        const defaultDir = status.current_path.replace(/[/\\][^/\\]*$/, "");
        await invoke<{ full_path: string; file_exists: boolean }>(
          "set_chat_history_path",
          { directory: defaultDir },
        );
      }
      await invoke("create_chat_history", { password });
      chatUnlocked.set(true);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function handleUnlock() {
    if (!password) {
      error = "Please enter a password";
      return;
    }
    error = "";
    loading = true;
    try {
      const archive = await invoke<{
        channels: Record<
          string,
          Array<{
            user_id: number;
            username: string;
            content: string;
            timestamp: number;
          }>
        >;
        dms: Record<
          string,
          Array<{
            user_id: number;
            username: string;
            content: string;
            timestamp: number;
          }>
        >;
      }>("unlock_chat_history", { password });
      populateFromArchive(archive);
      chatUnlocked.set(true);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function handleCreateNew() {
    if (!password) {
      error = "Please enter a password";
      return;
    }
    if (password !== confirmPassword) {
      error = "Passwords do not match";
      return;
    }
    error = "";
    loading = true;
    try {
      await invoke("create_chat_history", { password });
      chatUnlocked.set(true);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function handleDelete() {
    if (deleteConfirmText !== "DELETE") return;
    error = "";
    loading = true;
    try {
      await invoke<string>("delete_chat_history");
      resetFields();
      await loadStatus();
    } catch (e) {
      error = String(e);
      loading = false;
    }
  }

  async function handleBrowseChangePath() {
    const dir = await browseDirectory();
    if (!dir) return;
    error = "";
    loading = true;
    try {
      const result = await invoke<{ full_path: string; file_exists: boolean }>(
        "check_path_status",
        { directory: dir },
      );
      selectedDirectory = dir;
      newFullPath = result.full_path;
      if (result.file_exists) {
        resetFields();
        mode = "change_path_unlock";
      } else {
        resetFields();
        mode = "change_path_create";
      }
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function handleChangePathUnlock() {
    if (!password) {
      error = "Please enter a password";
      return;
    }
    error = "";
    loading = true;
    try {
      await invoke<{ full_path: string; file_exists: boolean }>(
        "set_chat_history_path",
        { directory: selectedDirectory },
      );
      const archive = await invoke<{
        channels: Record<
          string,
          Array<{
            user_id: number;
            username: string;
            content: string;
            timestamp: number;
          }>
        >;
        dms: Record<
          string,
          Array<{
            user_id: number;
            username: string;
            content: string;
            timestamp: number;
          }>
        >;
      }>("unlock_chat_history", { password });
      populateFromArchive(archive);
      chatUnlocked.set(true);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function handleChangePathCreate() {
    if (!password) {
      error = "Please enter a password";
      return;
    }
    if (password !== confirmPassword) {
      error = "Passwords do not match";
      return;
    }
    error = "";
    loading = true;
    try {
      await invoke<{ full_path: string; file_exists: boolean }>(
        "set_chat_history_path",
        { directory: selectedDirectory },
      );
      await invoke("create_chat_history", { password });
      chatUnlocked.set(true);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  function truncatePath(path: string, maxLen: number = 50): string {
    if (path.length <= maxLen) return path;
    return "..." + path.slice(-(maxLen - 3));
  }
</script>

<div class="overlay">
  <div class="dialog">
    {#if mode === "loading"}
      <h2>Chat History</h2>
      <p class="hint">Loading...</p>

    {:else if mode === "first_run"}
      <h2>Set Up Chat History</h2>
      <p class="hint">Choose where to store your encrypted chat history.</p>

      <div class="path-section">
        <label>Storage Location</label>
        <div class="path-row">
          <span class="path-display" title={currentPath}>
            {truncatePath(selectedDirectory || currentPath)}
          </span>
          <button class="secondary-btn" onclick={handleBrowseFirstRun} disabled={loading}>
            Browse
          </button>
        </div>
        {#if selectedDirectory}
          <button class="text-link" onclick={useDefaultPath}>Use default location</button>
        {/if}
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder="Enter password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleFirstRunCreate()}
        />
      </div>

      <div class="field">
        <label for="confirm">Confirm Password</label>
        <input
          id="confirm"
          type="password"
          bind:value={confirmPassword}
          placeholder="Confirm password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleFirstRunCreate()}
        />
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button class="submit-btn" onclick={handleFirstRunCreate} disabled={loading}>
        {loading ? "Processing..." : "Create"}
      </button>

    {:else if mode === "unlock"}
      <h2>Unlock Chat History</h2>
      <p class="hint">Enter your password to decrypt chat history.</p>
      <p class="path-info" title={currentPath}>{truncatePath(currentPath)}</p>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder="Enter password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleUnlock()}
        />
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button class="submit-btn" onclick={handleUnlock} disabled={loading}>
        {loading ? "Processing..." : "Unlock"}
      </button>

      <div class="secondary-actions">
        <button class="text-link danger-link" onclick={goToDeleteConfirm}>Delete History</button>
        <button class="text-link" onclick={goToChangePath}>Change Storage Location</button>
      </div>

    {:else if mode === "create_new"}
      <h2>Chat History Not Found</h2>
      <p class="hint">
        No chat history file found at the configured location. Create a new one?
      </p>
      <p class="path-info" title={currentPath}>{truncatePath(currentPath)}</p>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder="Enter password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleCreateNew()}
        />
      </div>

      <div class="field">
        <label for="confirm">Confirm Password</label>
        <input
          id="confirm"
          type="password"
          bind:value={confirmPassword}
          placeholder="Confirm password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleCreateNew()}
        />
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <button class="submit-btn" onclick={handleCreateNew} disabled={loading}>
        {loading ? "Processing..." : "Create"}
      </button>

      <div class="secondary-actions">
        <button class="text-link" onclick={goToChangePath}>Change Storage Location</button>
      </div>

    {:else if mode === "delete_confirm"}
      <h2>Delete Chat History</h2>
      <p class="warning-text">
        This will permanently delete your chat history. This cannot be undone.
      </p>
      <p class="path-info" title={currentPath}>{truncatePath(currentPath)}</p>

      <div class="field">
        <label for="delete-confirm">Type DELETE to confirm</label>
        <input
          id="delete-confirm"
          type="text"
          bind:value={deleteConfirmText}
          placeholder="DELETE"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleDelete()}
        />
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goBack} disabled={loading}>Cancel</button>
        <button
          class="danger-btn"
          onclick={handleDelete}
          disabled={loading || deleteConfirmText !== "DELETE"}
        >
          {loading ? "Deleting..." : "Delete"}
        </button>
      </div>

    {:else if mode === "change_path"}
      <h2>Change Storage Location</h2>
      <p class="hint">Select a new directory for your chat history.</p>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goBack} disabled={loading}>Cancel</button>
        <button class="submit-btn" onclick={handleBrowseChangePath} disabled={loading}>
          {loading ? "Checking..." : "Browse..."}
        </button>
      </div>

    {:else if mode === "change_path_unlock"}
      <h2>Existing History Found</h2>
      <p class="hint">Found existing chat history at the selected location. Enter password to unlock.</p>
      <p class="path-info" title={newFullPath}>{truncatePath(newFullPath)}</p>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder="Enter password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleChangePathUnlock()}
        />
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goToChangePath} disabled={loading}>Back</button>
        <button class="submit-btn" onclick={handleChangePathUnlock} disabled={loading}>
          {loading ? "Processing..." : "Unlock"}
        </button>
      </div>

    {:else if mode === "change_path_create"}
      <h2>Create New History</h2>
      <p class="hint">No existing history at the selected location. Create a new encrypted history.</p>
      <p class="path-info" title={newFullPath}>{truncatePath(newFullPath)}</p>

      <div class="field">
        <label for="password">Password</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder="Enter password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleChangePathCreate()}
        />
      </div>

      <div class="field">
        <label for="confirm">Confirm Password</label>
        <input
          id="confirm"
          type="password"
          bind:value={confirmPassword}
          placeholder="Confirm password"
          disabled={loading}
          onkeydown={(e) => e.key === "Enter" && handleChangePathCreate()}
        />
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goToChangePath} disabled={loading}>Back</button>
        <button class="submit-btn" onclick={handleChangePathCreate} disabled={loading}>
          {loading ? "Processing..." : "Create"}
        </button>
      </div>
    {/if}
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
    width: 400px;
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

  .path-info {
    text-align: center;
    font-size: 11px;
    color: var(--text-secondary);
    font-family: monospace;
    word-break: break-all;
    opacity: 0.8;
  }

  .warning-text {
    text-align: center;
    font-size: 13px;
    color: var(--danger);
    font-weight: 500;
  }

  .path-section {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .path-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .path-display {
    flex: 1;
    font-size: 11px;
    font-family: monospace;
    color: var(--text-secondary);
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 8px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
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
    margin-top: 4px;
  }

  .submit-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .submit-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .secondary-btn {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    padding: 6px 12px;
    font-size: 12px;
    white-space: nowrap;
  }

  .secondary-btn:hover:not(:disabled) {
    background: var(--border);
  }

  .cancel-btn {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    padding: 10px;
    font-size: 14px;
    flex: 1;
  }

  .cancel-btn:hover:not(:disabled) {
    background: var(--border);
  }

  .danger-btn {
    background: var(--danger);
    color: white;
    padding: 10px;
    font-size: 14px;
    font-weight: 600;
    flex: 1;
  }

  .danger-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .danger-btn:hover:not(:disabled) {
    filter: brightness(1.1);
  }

  .secondary-actions {
    display: flex;
    justify-content: center;
    gap: 16px;
    margin-top: 4px;
  }

  .text-link {
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
    padding: 2px 0;
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .text-link:hover {
    color: var(--text-primary);
  }

  .danger-link {
    color: var(--danger);
  }

  .danger-link:hover {
    color: var(--danger);
    filter: brightness(1.2);
  }

  .button-row {
    display: flex;
    gap: 12px;
    margin-top: 4px;
  }
</style>
