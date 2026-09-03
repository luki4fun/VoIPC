<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    connectionState,
    serverAddress,
    username,
    userId,
    acceptSelfSigned,
  } from "../stores/connection.js";
  import {
    rememberConnection,
    lastHost,
    lastPort,
    lastUsername,
    lastAcceptSelfSigned,
    savedServers,
    type SavedServer,
  } from "../stores/settings.js";

  let host = $state($lastHost);
  let port = $state($lastPort);
  let name = $state($lastUsername);
  let error = $state("");
  let connecting = $state(false);
  let selfSigned = $state($lastAcceptSelfSigned);
  let remember = $state($rememberConnection);

  // Sync from stores when they're hydrated (async config load may arrive after first render)
  $effect(() => {
    host = $lastHost;
    port = $lastPort;
    name = $lastUsername;
    selfSigned = $lastAcceptSelfSigned;
    remember = $rememberConnection;
  });

  async function handleConnect() {
    if (!host || !name) {
      error = "Please fill in all fields";
      return;
    }

    if (port < 1 || port > 65535) {
      error = "Port must be between 1 and 65535";
      return;
    }

    const address = `${host}:${port}`;
    error = "";
    connecting = true;
    connectionState.set("connecting");

    try {
      const id = await invoke<number>("connect", {
        address,
        username: name,
        acceptInvalidCerts: selfSigned,
      });
      userId.set(id);
      serverAddress.set(address);
      username.set(name);
      acceptSelfSigned.set(selfSigned);
      connectionState.set("connected");

      // Save connection info if remember is checked
      await invoke("save_connection_info", {
        host,
        port,
        username: name,
        acceptSelfSigned: selfSigned,
        remember,
      });
      rememberConnection.set(remember);
      if (remember) {
        lastHost.set(host);
        lastPort.set(port);
        lastUsername.set(name);
        lastAcceptSelfSigned.set(selfSigned);
      }
    } catch (e) {
      error = String(e);
      connectionState.set("disconnected");
    } finally {
      connecting = false;
    }
  }

  async function connectToSaved(s: SavedServer) {
    host = s.host;
    port = s.port;
    name = s.username;
    selfSigned = s.accept_self_signed;
    await handleConnect();
  }

  async function saveCurrentServer() {
    if (!host || !name) {
      error = "Fill in host and username first";
      return;
    }
    try {
      const list = await invoke<SavedServer[]>("save_server", {
        name: host,
        host,
        port,
        username: name,
        acceptSelfSigned: selfSigned,
      });
      savedServers.set(list);
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  async function removeSaved(s: SavedServer, e: Event) {
    e.stopPropagation();
    try {
      const list = await invoke<SavedServer[]>("remove_server", {
        host: s.host,
        port: s.port,
      });
      savedServers.set(list);
    } catch (err) {
      error = String(err);
    }
  }
</script>

<div class="overlay">
  <div class="dialog">
    <h2>Connect to Server</h2>

    {#if $savedServers.length > 0}
      <div class="saved-servers">
        {#each $savedServers as s (s.host + ":" + s.port)}
          <div class="saved-server">
            <button class="saved-main" onclick={() => connectToSaved(s)} disabled={connecting}>
              <span class="saved-name">{s.name}</span>
              <span class="saved-detail">{s.host}:{s.port} &middot; {s.username}</span>
            </button>
            <button
              class="saved-remove"
              onclick={(e) => removeSaved(s, e)}
              disabled={connecting}
              title="Remove server"
            >&#x2715;</button>
          </div>
        {/each}
      </div>
    {/if}

    <div class="address-row">
      <div class="field host-field">
        <label for="host">Server IP / Hostname</label>
        <input
          id="host"
          type="text"
          bind:value={host}
          placeholder="localhost"
          disabled={connecting}
          onkeydown={(e) => e.key === "Enter" && handleConnect()}
        />
      </div>
      <div class="field port-field">
        <label for="port">Port</label>
        <input
          id="port"
          type="number"
          bind:value={port}
          placeholder="9987"
          min={1}
          max={65535}
          disabled={connecting}
          onkeydown={(e) => e.key === "Enter" && handleConnect()}
        />
      </div>
    </div>

    <div class="field">
      <label for="username">Username</label>
      <input
        id="username"
        type="text"
        bind:value={name}
        placeholder="Your name"
        disabled={connecting}
        maxlength={32}
        onkeydown={(e) => e.key === "Enter" && handleConnect()}
      />
    </div>

    <label class="checkbox-label">
      <input type="checkbox" bind:checked={selfSigned} disabled={connecting} />
      Accept self-signed certificates
    </label>

    {#if selfSigned}
      <div class="security-warning">
        Self-signed mode uses Trust-On-First-Use (TOFU) pinning. The server certificate is trusted on first connect and must match on subsequent connections. Only use this with servers you control.
      </div>
    {/if}

    <label class="checkbox-label">
      <input type="checkbox" bind:checked={remember} disabled={connecting} />
      Remember connection details
    </label>

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <div class="btn-row">
      <button
        class="save-server-btn"
        onclick={saveCurrentServer}
        disabled={connecting}
        title="Save this server to the list above"
      >&#9733; Save</button>
      <button class="connect-btn" onclick={handleConnect} disabled={connecting}>
        {connecting ? "Connecting..." : "Connect"}
      </button>
    </div>
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

  .address-row {
    display: flex;
    gap: 8px;
  }

  .host-field {
    flex: 1;
  }

  .port-field {
    width: 90px;
  }

  .port-field input {
    width: 100%;
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

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-secondary);
    cursor: pointer;
    text-transform: none;
    letter-spacing: normal;
  }

  .checkbox-label input[type="checkbox"] {
    accent-color: var(--accent);
  }

  .security-warning {
    background: rgba(243, 156, 18, 0.1);
    border: 1px solid var(--warning);
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 12px;
    color: var(--warning);
    line-height: 1.4;
  }

  .error {
    color: var(--danger);
    font-size: 13px;
    text-align: center;
  }

  .saved-servers {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 160px;
    overflow-y: auto;
  }

  .saved-server {
    display: flex;
    gap: 6px;
    align-items: stretch;
  }

  .saved-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
    padding: 8px 10px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    min-width: 0;
  }

  .saved-main:hover:not(:disabled) {
    border-color: var(--accent);
  }

  .saved-name {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .saved-detail {
    font-size: 11px;
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
  }

  .saved-remove {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0 10px;
    cursor: pointer;
    font-size: 12px;
  }

  .saved-remove:hover:not(:disabled) {
    color: var(--danger);
    border-color: var(--danger);
  }

  .btn-row {
    display: flex;
    gap: 8px;
    margin-top: 8px;
  }

  .save-server-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 13px;
    cursor: pointer;
    white-space: nowrap;
  }

  .save-server-btn:hover:not(:disabled) {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .connect-btn {
    flex: 1;
    background: var(--accent);
    color: white;
    padding: 10px;
    font-size: 14px;
    font-weight: 600;
  }

  .connect-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .connect-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
