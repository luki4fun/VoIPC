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
</script>

<div class="overlay">
  <div class="dialog">
    <h2>Connect to Server</h2>

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

    <button class="connect-btn" onclick={handleConnect} disabled={connecting}>
      {connecting ? "Connecting..." : "Connect"}
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

  .connect-btn {
    background: var(--accent);
    color: white;
    padding: 10px;
    font-size: 14px;
    font-weight: 600;
    margin-top: 8px;
  }

  .connect-btn:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .connect-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
