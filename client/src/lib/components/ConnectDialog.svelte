<script lang="ts">
  // Opens a server. Up on its own while no server is on screen, and from the
  // rail's "+" while some are — then with a close button, and connecting here
  // leaves every open server as it is. It stays up until a connect succeeds,
  // so the reason one failed stays on screen under the form.

  import { invoke } from "@tauri-apps/api/core";
  import {
    rememberConnection,
    lastHost,
    lastPort,
    lastUsername,
    lastAcceptSelfSigned,
    savedServers,
    type SavedServer,
  } from "../stores/settings.js";
  import { isWeb } from "../stores/platform.js";
  import { pendingInvite, serverAddress } from "../stores/connection.js";
  import { parseInviteLink } from "../invite.js";
  import { connectTo, serverId, showConnectDialog, signInAgain, type AccountSignIn } from "../connect.js";
  import { randomTag, splitName, withTag } from "../username.js";

  // Invite link pasted here: takes host/port from it and joins the channel
  // right after connecting (App.svelte watches pendingInvite)
  let inviteLink = $state("");

  function applyInviteLink() {
    const parsed = parseInviteLink(inviteLink);
    if (!parsed) {
      if (inviteLink.trim()) error = "Not a VoIPC invite link (expected https://host:port/#channel=…)";
      return;
    }
    host = parsed.host;
    port = parsed.port;
    touched = true;
    // Tagged with its own server now: App.svelte acts on an invite as soon as
    // its server is connected, and without a server it would take the one on
    // screen — which, from the rail's "+", is a different one.
    pendingInvite.set({ ...parsed.invite, server: serverId(parsed.host, parsed.port) });
    inviteLink = "";
    error = "";
  }

  let host = $state($lastHost);
  let port = $state($lastPort);
  let name = $state(splitName($lastUsername).name);
  /** The four digits after the name. Random unless the user picks them. */
  let tag = $state(splitName($lastUsername).tag || randomTag());
  let error = $state("");
  let connecting = $state(false);
  let selfSigned = $state($lastAcceptSelfSigned);
  let remember = $state($rememberConnection);

  // ── Accounts ──
  /** Come as a guest (name#tag), or sign in to an account on the server. */
  let mode = $state<"guest" | "account">("guest");
  let accountAction = $state<"signin" | "create">("signin");
  let password = $state("");
  let password2 = $state("");
  let signupInvite = $state("");
  /** This device is remembered for that account there: no password needed. */
  let remembered = $state(false);

  // A reconnect that needs the password again opens the dialog on that account.
  $effect(() => {
    const again = $signInAgain;
    if (!again) return;
    host = again.host;
    port = again.port;
    name = again.name;
    mode = "account";
    accountAction = "signin";
    signInAgain.set(null);
  });

  $effect(() => {
    const [h, p, n, m] = [host, port, name, mode];
    if (m !== "account" || !h || !n) {
      remembered = false;
      return;
    }
    const server = serverId(h, p);
    const want = n.trim().toLowerCase();
    invoke<{ server: string; name: string }[]>("account_devices")
      .then((list) => (remembered = list.some((d) => d.server === server && d.name === want)))
      .catch(() => (remembered = false));
  });

  /** What the connect signs in with, or a reason it cannot yet. */
  function accountRequest(): AccountSignIn | string {
    // One spelling of the password on every device: the keys come from its bytes.
    const pw = password.normalize("NFC");
    if (accountAction === "create") {
      if (pw.length < 10) return "Use a password of at least 10 characters.";
      if (pw !== password2.normalize("NFC")) return "The passwords do not match.";
      return { mode: "register", password: pw, invite: signupInvite.trim() || null };
    }
    if (!pw && remembered) return { mode: "device" };
    if (!pw) return "Enter your password.";
    return { mode: "login", password: pw };
  }

  /** Anything typed, pasted or picked here. From then on the fields are the
   *  user's: a connect finishing elsewhere (a bookmark clicked in the rail)
   *  rewrites the last-used details, and must not rewrite the form under them. */
  let touched = false;

  // Sync from stores when they're hydrated (async config load may arrive after first render)
  $effect(() => {
    const [h, p, u, ss, r] = [$lastHost, $lastPort, $lastUsername, $lastAcceptSelfSigned, $rememberConnection];
    if (touched) return;
    host = h;
    port = p;
    const parts = splitName(u);
    name = parts.name;
    tag = parts.tag || tag;
    selfSigned = ss;
    remember = r;
  });

  async function connectWith(h: string, p: number, u: string, selfSignedOk: boolean) {
    error = "";
    let account: AccountSignIn | undefined;
    if (mode === "account") {
      const req = accountRequest();
      if (typeof req === "string") {
        error = req;
        return;
      }
      account = req;
    }
    connecting = true;
    // An invite from this dialog is for the server it connects to — which is
    // not the one on screen when this is a second server being added.
    if ($pendingInvite) pendingInvite.set({ ...$pendingInvite, server: serverId(h, p) });
    const result = await connectTo({
      host: h,
      port: p,
      username: u,
      acceptSelfSigned: selfSignedOk,
      remember,
      account,
    });
    connecting = false;
    password = "";
    password2 = "";
    if (!result.ok) {
      error = result.error;
      // A server that takes no guests: the form turns to signing in.
      if (error.includes("needs an account")) mode = "account";
    } else showConnectDialog.set(false);
  }

  /** Name and tag as sent. A tag that is not four digits is replaced, here
   *  too, so the field shows the one that was used. */
  function fullName(): string {
    const full = withTag(name, tag);
    tag = splitName(full).tag;
    return full;
  }

  async function handleConnect() {
    await connectWith(host, port, mode === "account" ? name.trim() : fullName(), selfSigned);
  }

  async function connectToSaved(s: SavedServer) {
    host = s.host;
    port = s.port;
    const parts = splitName(s.username);
    name = parts.name;
    tag = parts.tag || tag;
    selfSigned = s.accept_self_signed;
    mode = s.account ? "account" : "guest";
    accountAction = "signin";
    touched = true;
    // An account bookmark connects at once only where this device is
    // remembered; otherwise the form waits for the password.
    if (s.account) {
      const server = serverId(s.host, s.port);
      const list = await invoke<{ server: string; name: string }[]>("account_devices").catch(() => []);
      if (!list.some((d) => d.server === server && d.name === parts.name.toLowerCase())) return;
      remembered = true;
    }
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
        username: mode === "account" ? name.trim() : fullName(),
        acceptSelfSigned: selfSigned,
        account: mode === "account",
      });
      savedServers.set(list);
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  // Offered when the TOFU pin rejected the server's certificate
  let pinRejected = $derived(error.includes("fingerprint changed"));

  // Offered when a server named a relay id this app knows from another
  // address, or a different one than before (account.rs `relay_ok`)
  let relayClash = $derived(
    error.includes("forget its account id")
      ? (error.match(/says it is (\S+), another server/)?.[1] ?? serverId(host, port))
      : null,
  );

  async function forgetRelayId(server: string) {
    try {
      await invoke("forget_relay_id", { server });
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  async function forgetPin() {
    try {
      await invoke("forget_server_pin", { host, port });
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
  <div class="dialog" oninput={() => (touched = true)}>
    <div class="title-row">
      <h2>Connect to Server</h2>
      {#if $serverAddress}
        <button
          class="connect-close"
          onclick={() => showConnectDialog.set(false)}
          title="Back to the open servers"
          disabled={connecting}>&#x2715;</button
        >
      {/if}
    </div>

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

    {#if $pendingInvite}
      <div class="invite-banner">
        <span>
          Invited to <strong>#{$pendingInvite.channel}</strong>{#if $pendingInvite.password} (password included){/if}
          — you join it right after connecting.
        </span>
        <button type="button" class="invite-dismiss" onclick={() => pendingInvite.set(null)} title="Discard invite">&#x2715;</button>
      </div>
    {:else}
      <div class="field">
        <label for="invite">Invite link (optional)</label>
        <input
          id="invite"
          type="text"
          bind:value={inviteLink}
          placeholder="https://server:9987/#channel=…"
          disabled={connecting}
          onchange={applyInviteLink}
          onpaste={() => setTimeout(applyInviteLink, 0)}
        />
      </div>
    {/if}

    <div class="mode-switch" role="tablist" aria-label="How to join">
      <button type="button" role="tab" class:active={mode === "guest"} aria-selected={mode === "guest"} onclick={() => (mode = "guest")} disabled={connecting}>Guest</button>
      <button type="button" role="tab" class:active={mode === "account"} aria-selected={mode === "account"} onclick={() => (mode = "account")} disabled={connecting}>Account</button>
    </div>

    {#if mode === "guest"}
      <div class="address-row">
        <div class="field host-field">
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
        <div class="field tag-field">
          <label for="tag" title="Tells you apart from anybody else of the same name. If it is taken on a server, you get a random one there.">Tag</label>
          <div class="tag-input">
            <span>#</span>
            <input
              id="tag"
              type="text"
              inputmode="numeric"
              bind:value={tag}
              placeholder="0000"
              disabled={connecting}
              maxlength={4}
              oninput={() => (tag = tag.replace(/\D/g, ""))}
              onkeydown={(e) => e.key === "Enter" && handleConnect()}
            />
          </div>
        </div>
      </div>
    {:else}
      <div class="mode-switch small">
        <button type="button" class:active={accountAction === "signin"} onclick={() => (accountAction = "signin")} disabled={connecting}>Sign in</button>
        <button type="button" class:active={accountAction === "create"} onclick={() => (accountAction = "create")} disabled={connecting}>Create account</button>
      </div>
      <div class="field">
        <label for="account-name">Account name</label>
        <input
          id="account-name"
          type="text"
          bind:value={name}
          placeholder="a-z, 0-9, _ and -"
          autocomplete="username"
          disabled={connecting}
          maxlength={32}
          onkeydown={(e) => e.key === "Enter" && handleConnect()}
        />
      </div>
      <div class="field">
        <label for="account-password">Password{#if accountAction === "signin" && remembered} (not needed on this device){/if}</label>
        <input
          id="account-password"
          type="password"
          bind:value={password}
          autocomplete={accountAction === "create" ? "new-password" : "current-password"}
          placeholder={accountAction === "signin" && remembered ? "This device is remembered" : "Password"}
          disabled={connecting}
          onkeydown={(e) => e.key === "Enter" && handleConnect()}
        />
      </div>
      {#if accountAction === "create"}
        <div class="field">
          <label for="account-password2">Password again</label>
          <input
            id="account-password2"
            type="password"
            bind:value={password2}
            autocomplete="new-password"
            disabled={connecting}
            onkeydown={(e) => e.key === "Enter" && handleConnect()}
          />
        </div>
        <div class="field">
          <label for="signup-invite">Invite code (if the server asks for one)</label>
          <input id="signup-invite" type="text" bind:value={signupInvite} disabled={connecting} />
        </div>
        <p class="account-note">
          Your password never leaves this device: the server gets a key made from it. Forget it, and only your
          recovery key opens your encrypted account data. Use a password you use on no other server: a server
          could pretend to be another one.
        </p>
      {/if}
    {/if}

    {#if !isWeb}
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={selfSigned} disabled={connecting} />
        Accept self-signed certificates
      </label>

      {#if selfSigned}
        <div class="security-warning">
          Self-signed mode uses Trust-On-First-Use (TOFU) pinning. The server certificate is trusted on first connect and must match on subsequent connections. Only use this with servers you control.
        </div>
      {/if}
    {:else}
      <div class="web-hint">
        The server's TLS certificate must be trusted by your browser; open https://{host}:{port} once and accept it.
      </div>
    {/if}

    <label class="checkbox-label">
      <input type="checkbox" bind:checked={remember} disabled={connecting} />
      Remember connection details
    </label>

    {#if error}
      <div class="error">{error}</div>
      {#if pinRejected && !isWeb}
        <button
          type="button"
          class="save-server-btn"
          onclick={forgetPin}
          disabled={connecting}
        >
          Forget pinned certificate for {host}:{port}
        </button>
      {/if}
      {#if relayClash && !isWeb}
        <button
          type="button"
          class="save-server-btn"
          onclick={() => forgetRelayId(relayClash)}
          disabled={connecting}
        >
          Forget the account id of {relayClash}
        </button>
      {/if}
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
  .mode-switch {
    display: flex;
    gap: 4px;
    background: var(--bg-primary);
    border-radius: 6px;
    padding: 3px;
  }

  .mode-switch button {
    flex: 1;
    padding: 6px;
    font-size: 13px;
    background: transparent;
    color: var(--text-secondary);
  }

  .mode-switch button.active {
    background: var(--accent);
    color: white;
  }

  .mode-switch.small button {
    padding: 4px;
    font-size: 12px;
  }

  .account-note {
    font-size: 12px;
    color: var(--text-secondary);
  }

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

  .title-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .title-row h2 {
    flex: 1;
  }

  .connect-close {
    background: transparent;
    color: var(--text-secondary);
    border: none;
    padding: 4px 8px;
    font-size: 14px;
  }

  .connect-close:hover {
    color: var(--text-primary);
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

  .port-field,
  .tag-field {
    width: 90px;
  }

  .port-field input {
    width: 100%;
  }

  .tag-input {
    display: flex;
    align-items: center;
    gap: 4px;
    color: var(--text-secondary);
  }

  .tag-input input {
    width: 100%;
    min-width: 0;
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

  .web-hint {
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .invite-banner {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 12px;
    line-height: 1.4;
    color: var(--text-primary);
    background: var(--bg-hover);
    border-radius: 6px;
    padding: 8px 10px;
  }

  .invite-dismiss {
    margin-left: auto;
    background: transparent;
    color: var(--text-secondary);
    padding: 0 4px;
    font-size: 12px;
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
