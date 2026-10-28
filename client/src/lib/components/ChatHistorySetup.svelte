<script lang="ts">
  import { dialog } from "../actions/dialog.js";
  import { invoke } from "@tauri-apps/api/core";
  import {
    chatUnlocked,
    chatHistoryStatus,
    populateFromArchive,
    type ChatHistoryStatus,
  } from "../stores/chat.js";
  import { chatHistoryDisabled } from "../stores/settings.js";

  // Skip the vault entirely: chat stays in-memory (persistence no-ops
  // without an unlock key) and this gate is not shown again.
  async function skipVault() {
    try {
      await invoke("set_chat_history_disabled", { disabled: true });
    } catch (e) {
      console.error("Failed to save skip choice:", e);
    }
    chatHistoryDisabled.set(true);
  }

  type Mode =
    | "loading"
    | "blocked"
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
  let fileState = $state<ChatHistoryStatus["file_state"]>("none");

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
      fileState = status.file_state;

      if (status.file_state === "newer" || status.file_state === "unreadable") {
        mode = "blocked";
      } else if (!status.path_configured && !status.file_exists) {
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

  // Keeps the file (renamed) and makes room for a new history in its place.
  async function moveAside() {
    error = "";
    loading = true;
    try {
      await invoke<string>("move_chat_history_aside");
      resetFields();
      await loadStatus();
    } catch (e) {
      error = String(e);
      loading = false;
    }
  }

  function truncatePath(path: string, maxLen: number = 50): string {
    if (path.length <= maxLen) return path;
    return "..." + path.slice(-(maxLen - 3));
  }
</script>

<div class="overlay">
  <!-- A gate with nothing to go back to: Back puts the app away until later -->
  <div class="dialog" use:dialog={{ back: "leave" }}>
    {#if mode === "loading"}
      <h2>Chat history</h2>
      <p class="hint">Loading...</p>

    {:else if mode === "blocked"}
      <h2>Chat History Can't Be Opened</h2>
      <p class="hint">
        {#if fileState === "newer"}
          This history was saved by a newer version of VoIPC. Update VoIPC to open it — this version
          leaves it as it is.
        {:else}
          The file at this location is damaged or is not a VoIPC chat history. It is left as it is.
        {/if}
      </p>
      <p class="path-info" title={currentPath}>{truncatePath(currentPath)}</p>

      {#if error}
        <div class="error" role="alert">{error}</div>
      {/if}

      <button class="submit-btn btn btn-primary" onclick={moveAside} disabled={loading}>
        {loading ? "Processing..." : "Keep it aside and start a new history"}
      </button>
      <div class="secondary-actions">
        <button class="text-link" onclick={goToChangePath}>Change storage location</button>
      </div>
      <button class="text-link skip-link" onclick={skipVault} disabled={loading}>
        Skip — don't save chat history (kept in memory only, lost on exit)
      </button>

    {:else if mode === "first_run"}
      <h2>Set up chat history</h2>
      <p class="hint">Choose where to store your encrypted chat history.</p>

      <div class="path-section" role="group" aria-labelledby="storage-label">
        <span class="label" id="storage-label">Storage location</span>
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
        <label for="confirm">Confirm password</label>
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
        <div class="error" role="alert">{error}</div>
      {/if}

      <button class="submit-btn btn btn-primary" onclick={handleFirstRunCreate} disabled={loading}>
        {loading ? "Processing..." : "Create"}
      </button>
      <button class="text-link skip-link" onclick={skipVault} disabled={loading}>
        Skip — don't save chat history (kept in memory only, lost on exit)
      </button>

    {:else if mode === "unlock"}
      <h2>Unlock chat history</h2>
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
        <div class="error" role="alert">{error}</div>
      {/if}

      <button class="submit-btn btn btn-primary" onclick={handleUnlock} disabled={loading}>
        {loading ? "Processing..." : "Unlock"}
      </button>

      <div class="secondary-actions">
        <button class="text-link danger-link" onclick={goToDeleteConfirm}>Delete history</button>
        <button class="text-link" onclick={goToChangePath}>Change storage location</button>
      </div>

    {:else if mode === "create_new"}
      <h2>Chat history not found</h2>
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
        <label for="confirm">Confirm password</label>
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
        <div class="error" role="alert">{error}</div>
      {/if}

      <button class="submit-btn btn btn-primary" onclick={handleCreateNew} disabled={loading}>
        {loading ? "Processing..." : "Create"}
      </button>

      <div class="secondary-actions">
        <button class="text-link" onclick={goToChangePath}>Change storage location</button>
      </div>

    {:else if mode === "delete_confirm"}
      <h2>Delete chat history</h2>
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
        <div class="error" role="alert">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goBack} disabled={loading}>Cancel</button>
        <button
          class="danger-btn btn btn-danger"
          onclick={handleDelete}
          disabled={loading || deleteConfirmText !== "DELETE"}
        >
          {loading ? "Deleting..." : "Delete"}
        </button>
      </div>

    {:else if mode === "change_path"}
      <h2>Change storage location</h2>
      <p class="hint">Select a new directory for your chat history.</p>

      {#if error}
        <div class="error" role="alert">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goBack} disabled={loading}>Cancel</button>
        <button class="submit-btn btn btn-primary" onclick={handleBrowseChangePath} disabled={loading}>
          {loading ? "Checking..." : "Browse..."}
        </button>
      </div>

    {:else if mode === "change_path_unlock"}
      <h2>Existing history found</h2>
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
        <div class="error" role="alert">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goToChangePath} disabled={loading}>Back</button>
        <button class="submit-btn btn btn-primary" onclick={handleChangePathUnlock} disabled={loading}>
          {loading ? "Processing..." : "Unlock"}
        </button>
      </div>

    {:else if mode === "change_path_create"}
      <h2>Create new history</h2>
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
        <label for="confirm">Confirm password</label>
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
        <div class="error" role="alert">{error}</div>
      {/if}

      <div class="button-row">
        <button class="cancel-btn" onclick={goToChangePath} disabled={loading}>Back</button>
        <button class="submit-btn btn btn-primary" onclick={handleChangePathCreate} disabled={loading}>
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
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-modal);
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
    /* The window can be 640×480: the dialog scrolls, its buttons stay reachable */
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
  }

  h2 {
    text-align: center;
    font-size: var(--fs-2xl);
    color: var(--text-primary);
  }

  .hint {
    text-align: center;
    font-size: var(--fs-body);
    color: var(--text-secondary);
  }

  .path-info {
    text-align: center;
    font-size: var(--fs-micro);
    color: var(--text-secondary);
    font-family: monospace;
    word-break: break-all;
    opacity: 0.8;
  }

  .warning-text {
    text-align: center;
    font-size: var(--fs-body);
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
    font-size: var(--fs-micro);
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

  label,
  .label {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .error {
    color: var(--danger);
    font-size: var(--fs-body);
    text-align: center;
  }

  .submit-btn {
    padding: 10px;
    font-size: var(--fs-md);
    margin-top: 4px;
  }

  .secondary-btn {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    padding: 6px 12px;
    font-size: var(--fs-sm);
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
    font-size: var(--fs-md);
    flex: 1;
  }

  .cancel-btn:hover:not(:disabled) {
    background: var(--border);
  }

  .danger-btn {
    padding: 10px;
    font-size: var(--fs-md);
    flex: 1;
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
    font-size: var(--fs-sm);
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
