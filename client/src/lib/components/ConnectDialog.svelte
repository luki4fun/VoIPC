<script lang="ts">
  import { dialog } from "../actions/dialog.js";
  // Opens a server. Up on its own while no server is on screen, and from the
  // rail's "+" while some are — then with a close button, and connecting here
  // leaves every open server as it is. It stays up until a connect succeeds,
  // so the reason one failed stays on screen under the form.

  import { invoke } from "@tauri-apps/api/core";
  import { confirmAction } from "../stores/confirm.js";
  import Icon from "./Icons.svelte";
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
  import { DOWNLOAD_PAGE, RESET_DONE, connectTo, serverId, showConnectDialog, signInAgain, updateNeeded, type AccountSignIn } from "../connect.js";
  import { randomTag, splitName, withTag } from "../username.js";
  import { availableUpdate, checkForUpdate, checkUpdates, installUpdate, updateBusy, updatesSupported } from "../stores/updates.js";
  import { updateFits } from "../update-rules.js";
  import { voice } from "../stores/channels.js";

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
  let accountAction = $state<"signin" | "create" | "reset">("signin");
  let password = $state("");
  let password2 = $state("");
  /** "Forgot your password?": the recovery key, as it was shown. */
  let recoveryKey = $state("");
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
    if (accountAction === "create" || accountAction === "reset") {
      if (accountAction === "reset" && !recoveryKey.trim()) return "Enter your recovery key.";
      if ([...pw].length < 10) return "Use a password of at least 10 characters.";
      if (pw !== password2.normalize("NFC")) return "The passwords do not match.";
      if (accountAction === "reset") return { mode: "reset", recovery: recoveryKey.trim(), password: pw };
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
    updateNeeded.set(null);
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
    const request = { host: h, port: p, username: u, acceptSelfSigned: selfSignedOk, remember, account };
    let result = await connectTo(request);
    // A reset ends its connection: sign in with the new password at once
    if (!result.ok && account?.mode === "reset" && result.error.includes(RESET_DONE)) {
      accountAction = "signin";
      recoveryKey = "";
      result = await connectTo({ ...request, account: { mode: "login", password: account.password } });
    }
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
  // A refusal for another protocol, for the server in the form
  let update = $derived($updateNeeded?.server === serverId(host, port) ? $updateNeeded : null);
  // In the browser, the server this page came from: a reload brings its version
  const pageServer = isWeb ? serverId(location.hostname, Number(location.port) || 443) : "";
  // Refused for an older protocol: look for an update at once, not tomorrow
  let lookedForUpdate = $state(false);
  let updateError = $state("");
  $effect(() => {
    if (!update || isWeb || update.server_protocol <= update.our_protocol) return;
    lookedForUpdate = false;
    void checkForUpdate().then(() => (lookedForUpdate = true));
  });
  let fittingUpdate = $derived(update && updateFits($availableUpdate, update.server_protocol) ? $availableUpdate : null);
  async function updateNow() {
    updateError = await installUpdate();
  }

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

  /** The two fingerprints transport.rs names in its refusal, when it does. */
  let pinFingerprints = $derived(
    error.match(/remembered SHA-256 ([0-9A-F:]+); offered SHA-256 ([0-9A-F:]+)/),
  );

  async function forgetPin() {
    const ok = await confirmAction({
      title: "Trust the new certificate?",
      body:
        `VoIPC remembered a different certificate for ${host}:${port}. If the server's operator ` +
        "replaced it, trusting the new one is safe. If nobody did, someone may be sitting between " +
        "you and the server — ask the operator to compare the fingerprint before you go ahead.",
      details: pinFingerprints
        ? [`Remembered  ${pinFingerprints[1]}`, `Offered now ${pinFingerprints[2]}`]
        : undefined,
      confirm: "Forget the old certificate",
      danger: true,
    });
    if (!ok) return;
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
  <div
    class="dialog"
    oninput={() => (touched = true)}
    use:dialog={{ onclose: $serverAddress && !connecting ? () => showConnectDialog.set(false) : undefined }}
  >
    <div class="title-row">
      <h2>Connect to a server</h2>
      {#if $serverAddress}
        <button
          class="connect-close"
          onclick={() => showConnectDialog.set(false)}
          title="Back to the open servers"
          aria-label="Back to the open servers"
          disabled={connecting}><Icon name="close" size={16} /></button
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
              aria-label="Remove {s.name}"
            ><Icon name="close" size={14} /></button>
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
          inputmode="url"
          autocapitalize="off"
          autocomplete="off"
          spellcheck="false"
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
        <button type="button" class="invite-dismiss" onclick={() => pendingInvite.set(null)} title="Discard invite" aria-label="Discard invite"><Icon name="close" size={14} /></button>
      </div>
    {:else}
      <div class="field">
        <label for="invite">Invite link (optional)</label>
        <input
          id="invite"
          type="text"
          inputmode="url"
          autocapitalize="off"
          autocomplete="off"
          spellcheck="false"
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
            autocapitalize="off"
            autocomplete="off"
            spellcheck="false"
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
      {#if isWeb && host && serverId(host, port) !== pageServer}
        <p class="account-note">
          This page comes from {pageServer}, which sees what you do on {serverId(host, port)} in it. For an account
          there, open https://{serverId(host, port)}/ instead.
        </p>
      {/if}
      {#if accountAction === "reset"}
        <div class="field">
          <label for="account-recovery">Recovery key</label>
          <input
            id="account-recovery"
            type="text"
            bind:value={recoveryKey}
            placeholder="ABCD-EFGH-…"
            autocomplete="off"
            spellcheck="false"
            disabled={connecting}
          />
        </div>
      {/if}
      <div class="field">
        <label for="account-password">{accountAction === "reset" ? "New password" : "Password"}{#if accountAction === "signin" && remembered} (not needed on this device){/if}</label>
        <input
          id="account-password"
          type="password"
          bind:value={password}
          autocomplete={accountAction === "signin" ? "current-password" : "new-password"}
          placeholder={accountAction === "signin" && remembered ? "This device is remembered" : "Password"}
          disabled={connecting}
          onkeydown={(e) => e.key === "Enter" && handleConnect()}
        />
        {#if accountAction === "signin"}
          <button type="button" class="link-btn" onclick={() => (accountAction = "reset")} disabled={connecting}>Forgot your password?</button>
        {/if}
      </div>
      {#if accountAction === "reset"}
        <div class="field">
          <label for="account-password2">New password again</label>
          <input
            id="account-password2"
            type="password"
            bind:value={password2}
            autocomplete="new-password"
            disabled={connecting}
            onkeydown={(e) => e.key === "Enter" && handleConnect()}
          />
        </div>
        <p class="account-note">
          The recovery key you were shown when the account was made opens your encrypted account data, so nothing
          is lost. Your other devices are signed out and need the new password.
        </p>
      {/if}
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

    {#if update}
      <div class="error update-panel">
        <p>
          {update.server} runs VoIPC {update.server_version} (protocol {update.server_protocol}). This app is
          {update.our_version} (protocol {update.our_protocol}).
        </p>
        {#if update.server_protocol < update.our_protocol}
          <p>The server needs an update — tell its operator. There is nothing to do in this app.</p>
        {:else if isWeb && update.server === pageServer}
          <p>This page is out of date.</p>
          <button type="button" class="save-server-btn" onclick={() => location.reload()}>Reload the page</button>
        {:else if isWeb}
          <p>The server's own page brings the matching version.</p>
          <button type="button" class="save-server-btn" onclick={() => window.open(`https://${update.server}/`, "_blank", "noopener")}>
            Open {update.server}'s page
          </button>
        {:else if $updatesSupported && fittingUpdate}
          <p>VoIPC {fittingUpdate.version} speaks this server's protocol. Installing it restarts VoIPC.</p>
          <button
            type="button"
            class="save-server-btn"
            onclick={updateNow}
            disabled={$updateBusy !== null || $voice !== null}
          >
            {$updateBusy === "installing"
              ? "Updating…"
              : $voice !== null
                ? "Update after the call"
                : `Update VoIPC to ${fittingUpdate.version}`}
          </button>
          {#if updateError}<p>{updateError}</p>{/if}
        {:else}
          {#if $updatesSupported && $checkUpdates && update.server_protocol > update.our_protocol}
            <p>{$updateBusy === "checking" || !lookedForUpdate ? "Looking for an update…" : "There is no update for this server's version yet."}</p>
          {/if}
          <p>Update VoIPC to connect. Download it from:</p>
          <div class="update-link">
            <code>{DOWNLOAD_PAGE}</code>
            <button type="button" class="save-server-btn" onclick={() => navigator.clipboard?.writeText(DOWNLOAD_PAGE)}>Copy</button>
          </div>
        {/if}
      </div>
    {:else if error}
      <div class="error" role="alert">{error}</div>
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
      {#if relayClash}
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
      >Save server</button>
      <button class="connect-btn btn btn-primary" onclick={handleConnect} disabled={connecting}>
        {connecting ? "Connecting…" : "Connect"}
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
    font-size: var(--fs-body);
    background: transparent;
    color: var(--text-secondary);
  }

  .mode-switch button.active {
    background: var(--bg-hover);
    color: var(--text-primary);
    box-shadow: inset 0 0 0 1px var(--text-muted);
  }

  .mode-switch.small button {
    padding: 4px;
    font-size: var(--fs-sm);
  }

  .account-note {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .link-btn {
    align-self: flex-start;
    background: none;
    border: none;
    padding: 2px 0;
    font-size: var(--fs-sm);
    color: var(--text-primary);
    text-decoration: underline;
    cursor: pointer;
  }

  .link-btn:hover:not(:disabled) {
    text-decoration: underline;
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: var(--z-dialog);
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
    /* The window can be 640×480: the dialog scrolls, its buttons stay reachable */
    max-height: calc(100dvh - 32px);
    overflow-y: auto;
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
    font-size: var(--fs-md);
  }

  .connect-close:hover {
    color: var(--text-primary);
  }

  h2 {
    text-align: center;
    font-size: var(--fs-2xl);
    color: var(--text-primary);
  }

  .address-row {
    display: flex;
    gap: 8px;
  }

  .host-field {
    flex: 1;
    /* An input's own minimum is about twenty characters: kept, it squeezed
       the tag to three digits whenever the dialog had a scrollbar */
    min-width: 0;
  }

  /* Sized by what they hold, so a larger system font grows them too: five
     digits and the spin buttons; "#" and four digits */
  .port-field,
  .tag-field {
    flex-shrink: 0;
  }

  .port-field {
    width: calc(5ch + 52px);
  }

  .tag-field {
    width: calc(4ch + 48px);
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
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-body);
    color: var(--text-secondary);
    cursor: pointer;
    text-transform: none;
    letter-spacing: normal;
  }

  .checkbox-label input[type="checkbox"] {
    accent-color: var(--control-fill);
  }

  .security-warning {
    background: rgba(243, 156, 18, 0.1);
    border: 1px solid var(--warning);
    border-radius: 6px;
    padding: 10px 12px;
    font-size: var(--fs-sm);
    color: var(--warning);
    line-height: 1.4;
  }

  .web-hint {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .invite-banner {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: var(--fs-sm);
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
    font-size: var(--fs-sm);
  }

  .error {
    color: var(--danger);
    font-size: var(--fs-body);
    text-align: center;
  }

  .update-panel p {
    margin: 0 0 6px;
  }

  .update-link {
    display: flex;
    gap: 6px;
    align-items: center;
    flex-wrap: wrap;
  }

  .update-link code {
    overflow-wrap: anywhere;
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
    border-color: var(--text-muted);
  }

  .saved-name {
    font-size: var(--fs-body);
    font-weight: 600;
    color: var(--text-primary);
  }

  .saved-detail {
    font-size: var(--fs-micro);
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
    font-size: var(--fs-sm);
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
    font-size: var(--fs-body);
    cursor: pointer;
    white-space: nowrap;
  }

  .save-server-btn:hover:not(:disabled) {
    color: var(--text-primary);
    border-color: var(--text-secondary);
  }

  .connect-btn {
    flex: 1;
    padding: 10px;
    font-size: var(--fs-md);
  }
</style>
