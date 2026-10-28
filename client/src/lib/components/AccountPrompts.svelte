<script lang="ts">
  import { dialog } from "../actions/dialog.js";
  // The dialogs a relay account needs: the code a sign-in waits for, a new
  // account's recovery key (shown once), setting up the authenticator app
  // (when a role needs it, or when chosen), the recovery codes that come with
  // it, the one question about keeping copies on the server (the first-connect
  // setup), and the account panel. Listens for the account events both
  // backends emit itself, so App.svelte only mounts it.

  import { onDestroy, onMount } from "svelte";
  import { get } from "svelte/store";
  import { invoke } from "@tauri-apps/api/core";
  import type { UnlistenFn } from "@tauri-apps/api/event";
  import { listenServer, fromServer } from "../connect.js";
  import { account, accountHex, accountPrompt, closePrompt, relayAccounts, showPrompt } from "../stores/account.js";
  import { applyChannelEvent, applyStoredDmEvent, fileStoredDm, joinedTextChannelIds, purgeWritten } from "../stores/chat.js";
  import { channels, currentChannelId } from "../stores/channels.js";
  import { shareChannelHistory } from "../stores/settings.js";
  import { users } from "../stores/users.js";
  import { chatEvent, expiryFor } from "../chat-rules.js";
  import { dmMessageTtl, managesChannel } from "../stores/channel-ui.js";
  import { userId } from "../stores/connection.js";
  import { addNotification } from "../stores/notifications.js";
  import type { AccountInfo, RelayAccounts } from "../types.js";

  let code = $state("");
  let oldPassword = $state("");
  let newPassword = $state("");
  let newPassword2 = $state("");
  /** The account name, typed again to delete it. */
  let confirmName = $state("");
  let useRecovery = $state(false);
  let error = $state("");
  let busy = $state(false);
  let qr = $state("");
  let copied = $state(false);
  /** A new recovery key on its way: shown once the relay says it is in
   *  force (`RecoveryKeyChanged`), never before, and dropped on an error. */
  let pendingKey: { server: string; key: string } | null = null;
  /** The relay's `RecoveryKeyChanged` came before the key was handed back. */
  let keyChangedOn: string | null = null;

  function showNewKey(server: string, key: string) {
    pendingKey = null;
    keyChangedOn = null;
    reset();
    showPrompt({ kind: "recovery", server, key, renewed: true });
  }

  /** The servers whose question about copies waits for the dialogs that
   *  came first (recovery key, codes) to be out of the way. */
  const cloudNext: string[] = [];
  let cloudChoice = $state(false);
  let shareChoice = $state(true);

  function askCloud(server: string) {
    if (!get(relayAccounts.peek(server))?.cloud || !get(account.peek(server))) return;
    if (get(accountPrompt)) {
      if (!cloudNext.includes(server)) cloudNext.push(server);
      return;
    }
    reset();
    cloudChoice = get(account.peek(server))?.cloud ?? false;
    shareChoice = get(shareChannelHistory);
    showPrompt({ kind: "cloud", server, cloud: cloudChoice, share: shareChoice });
  }

  $effect(() => {
    const server = !$accountPrompt && cloudNext.shift();
    if (server) askCloud(server);
  });

  /** One consent, two ways: answering newcomers' requests for chat, and
   *  handing them our older keys in a channel's log. */
  function setShare(enabled: boolean) {
    shareChannelHistory.set(enabled);
    invoke("set_config_bool", { key: "share_channel_history", value: enabled }).catch((e) =>
      addNotification(`Failed to save setting: ${e}`, "error"),
    );
    invoke("set_history_sharing", { enabled }).catch(() => {});
  }

  /** The logs of the channels we are in now: kept from here on. */
  function enterLogs(server: string) {
    const here = new Set([get(currentChannelId.peek(server)), ...get(joinedTextChannelIds.peek(server))]);
    for (const ch of get(channels.peek(server))) {
      if (ch.log && here.has(ch.channel_id)) invoke("account_enter", { server, conv: ch.log }).catch(() => {});
    }
  }

  async function submitCloud(server: string, keep: boolean) {
    busy = true;
    error = "";
    try {
      await invoke("account_set_prefs", { server, prefs: { cloud: keep, asked: true } });
      account.of(server).update((a) => (a ? { ...a, cloud: keep } : a));
      if (shareChoice !== get(shareChannelHistory)) setShare(shareChoice);
      if (keep) enterLogs(server);
      closePrompt();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function reset() {
    code = "";
    oldPassword = "";
    newPassword = "";
    newPassword2 = "";
    confirmName = "";
    useRecovery = false;
    error = "";
    busy = false;
    qr = "";
    copied = false;
  }

  function askTotpSetup(server: string) {
    invoke("account_request", { server, request: "TotpSetup" }).catch((e) =>
      addNotification(`${fromServer(server)}could not start two-factor setup: ${e}`, "warning"),
    );
  }

  const unlisten: Promise<UnlistenFn>[] = [];
  onMount(() => {
    unlisten.push(
      listenServer<RelayAccounts>("relay-accounts", (server, data) => relayAccounts.of(server).set(data)),
      listenServer<{
        name: string;
        relay_id: string;
        info: AccountInfo;
        recovery: string | null;
        prefs: { cloud: boolean; asked: boolean };
      }>(
        "account-signed-in",
        (server, d) => {
          account.of(server).set({ name: d.name, relayId: d.relay_id, info: d.info, cloud: d.prefs.cloud });
          // The second factor a role needs is asked for by the backend once the
          // connection is listed (account.rs after_connect); its setup waits
          // behind the recovery key, which nothing replaces.
          if (d.recovery) {
            reset();
            showPrompt({ kind: "recovery", server, key: d.recovery });
          }
          // The first-connect setup's question, once per account, after the
          // recovery key (which waits for nothing).
          if (!d.prefs.asked) askCloud(server);
        },
      ),
      listenServer<boolean>("account-need-totp", (server, retry) => {
        reset();
        showPrompt({ kind: "totp", server, retry });
      }),
      listenServer<unknown>("account-reply", (server, reply) => onReply(server, reply)),
      // The stored log of a direct conversation: what was written while one of us was away.
      listenServer<{
        peer_name: string;
        peer_account: string;
        from_me: boolean;
        message_id: string | null;
        content: string;
        ttl_secs: number | null;
        timestamp: number;
        reply_to?: string | null;
        thread?: string | null;
        file?: unknown;
        fwd?: unknown;
      }>("stored-dm", (server, m) => {
        const me = get(account.peek(server));
        if (!me) return;
        const online = get(users.peek(server)).find((u) => u.username === m.peer_name);
        fileStoredDm(
          server,
          m,
          { name: me.name, account: accountHex(me.info.id) },
          expiryFor(m.timestamp, m.ttl_secs ?? undefined, dmMessageTtl(server, m.peer_name)),
          online?.user_id,
        );
      }),
      // A tombstone: its writer deleted what they wrote there up to `before`.
      listenServer<{ conv: string; name: string; account: string; from_me: boolean; before: number }>("stored-purge", (server, t) => {
        const me = get(account.peek(server));
        if (!me) return;
        const writer = t.from_me ? accountHex(me.info.id) : t.account;
        // Members' copies of what they wrote carry no account, only this name
        const writerName = t.from_me ? me.name : t.name;
        const ch = get(channels.peek(server)).find((c) => c.log === t.conv);
        if (ch) purgeWritten(server, "channel", ch.name, writer, t.before, writerName);
        else if (t.conv.startsWith("d:")) purgeWritten(server, "dm", t.name, writer, t.before, writerName);
      }),
      // An edit, delete, reaction or pin from a stored log, by its sender
      // (the other party of a direct one, or us). A pin counts only from a
      // manager the roster lists now: one whose sender is away is let go.
      listenServer<{
        conv: string;
        name: string;
        account: string;
        from_me: boolean;
        content: string;
        timestamp: number;
        event: unknown;
      }>("stored-event", (server, t) => {
        const me = get(account.peek(server));
        const event = chatEvent(t.event);
        if (!me || !event) return;
        const self = get(userId.peek(server));
        const writer = t.from_me ? accountHex(me.info.id) : t.account;
        // Theirs only where the name is theirs: the relay's name for an account
        const online = t.from_me
          ? undefined
          : get(users.peek(server)).find((u) => u.username === t.name && !!u.account && accountHex(u.account) === t.account);
        const by = { user_id: t.from_me ? self : (online?.user_id ?? 0), username: t.from_me ? me.name : t.name, account: writer };
        const ev = { event, by, at: t.timestamp, content: t.content };
        const ch = get(channels.peek(server)).find((c) => c.log === t.conv);
        if (ch) {
          const mayPin = event.kind === "pin" && (t.from_me || !!online) && managesChannel(server, ch.channel_id, by.user_id);
          applyChannelEvent(server, ch.name, ev, mayPin);
        } else if (t.conv.startsWith("d:")) {
          applyStoredDmEvent(server, t.name || `account ${t.account.slice(0, 8)}`, ev);
        }
      }),
      listenServer<{ reason: string }>("stored-not-kept", (server, d) =>
        addNotification(`${fromServer(server)}not kept on the server: ${d.reason}`, "warning"),
      ),
      // A vault item this device will not use as the server holds it (and so
      // never saves over this session).
      listenServer<{ item: string; problem: string }>("vault-problem", (server, d) => {
        const what =
          d.item === "item.pins" ? "the identities you pinned" : d.item === "item.logkey" ? "your key for kept messages" : "your account settings";
        const why =
          d.problem === "newer"
            ? "were saved by a newer VoIPC — update to use them"
            : d.problem === "older"
              ? "came back older than this device saw them: the server may be rolling them back"
              : d.problem === "missing"
                ? "are missing, though this device saw them before: the server may be withholding them"
                : "could not be read";
        const warn = d.item === "item.pins" ? ". People you meet now are not checked against them." : ".";
        addNotification(`${fromServer(server)}Security warning: ${what} ${why}${warn}`, "error", 0);
      }),
    );
  });
  onDestroy(() => unlisten.forEach((u) => u.then((f) => f())));

  function onReply(server: string, reply: unknown) {
    const [tag, body] =
      typeof reply === "string" ? [reply, {}] : (Object.entries(reply as Record<string, any>)[0] ?? ["", {}]);
    const prompt = get(accountPrompt);
    switch (tag) {
      case "TotpSetup": {
        // A role's codes come first; the question waits for them.
        if (prompt?.kind === "cloud" && !cloudNext.includes(prompt.server)) cloudNext.unshift(prompt.server);
        reset();
        const why = get(account.peek(server))?.info.needs_2fa ? "required" : "chosen";
        showPrompt({ kind: "totp-setup", server, secret: body.secret, uri: body.uri, sealed: body.sealed, why });
        invoke<string>("qr_svg", { text: body.uri }).then((svg) => (qr = svg), () => (qr = ""));
        break;
      }
      case "TotpEnabled":
        reset();
        showPrompt({ kind: "recovery-codes", server, codes: body.recovery_codes });
        break;
      case "Info": {
        const before = get(account.peek(server))?.info.needs_2fa;
        account.of(server).update((a) => (a ? { ...a, info: body as AccountInfo } : a));
        // A role arrived (the admin token's claim, a grant): it waits for codes.
        if ((body as AccountInfo).needs_2fa && !before && prompt?.kind !== "totp-setup") askTotpSetup(server);
        break;
      }
      case "LogPurged":
        addNotification(`${fromServer(server)}${body.entries} kept message${body.entries === 1 ? "" : "s"} deleted from the server`, "info");
        break;
      case "AccountDeleted": {
        if (prompt?.kind === "delete" && prompt.server === server) closePrompt(prompt);
        reset();
        const name = get(account.peek(server))?.name ?? "";
        // Nothing of it is any use here now: the remembered device, the
        // server's account id (a new account there is another one)
        invoke("forget_device", { server, name }).catch(() => {});
        invoke("forget_relay_id", { server }).catch(() => {});
        addNotification(`${fromServer(server)}account ${name} deleted`, "info");
        break;
      }
      case "PasswordChanged":
        if (prompt?.kind === "password" && prompt.server === server) closePrompt(prompt);
        reset();
        addNotification(`${fromServer(server)}password changed. Your other devices need the new one.`, "info");
        break;
      case "DeviceAdded":
        addNotification(`${fromServer(server)}this device is remembered — no password next time`, "info");
        break;
      case "RecoveryKeyChanged":
        // The old key stopped working: this one must be seen, whatever is on screen
        if (pendingKey?.server === server) showNewKey(server, pendingKey.key);
        else if (prompt?.kind === "recovery-new" && prompt.server === server) keyChangedOn = server;
        break;
      case "Error":
        if (body.request === "RecoveryKeyNew" && pendingKey?.server === server) pendingKey = null;
        if (body.request === "RecoveryKeyNew" && keyChangedOn === server) keyChangedOn = null;
        if (
          prompt &&
          prompt.server === server &&
          (prompt.kind === "totp-setup" ||
            (prompt.kind === "password" && body.request === "PasswordChange") ||
            (prompt.kind === "recovery-new" && body.request === "RecoveryKeyNew") ||
            (prompt.kind === "delete" && body.request === "DeleteAccount"))
        ) {
          error = body.reason;
          busy = false;
        } else {
          addNotification(`${fromServer(server)}${body.reason}`, "warning");
        }
        break;
    }
  }

  async function submitTotp() {
    const p = get(accountPrompt);
    if (!p || p.kind !== "totp" || !code.trim()) return;
    busy = true;
    try {
      await invoke("account_totp", { server: p.server, code: code.trim(), recovery: useRecovery });
      closePrompt(p);
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }

  function cancelTotp() {
    const p = get(accountPrompt);
    if (p) invoke("account_cancel", { server: p.server }).catch(() => {});
    closePrompt();
  }

  async function submitSetup() {
    const p = get(accountPrompt);
    if (!p || p.kind !== "totp-setup" || !/^\d{6}$/.test(code.trim())) {
      error = "Type the 6 digits the app shows.";
      return;
    }
    busy = true;
    error = "";
    try {
      await invoke("account_request", {
        server: p.server,
        request: { TotpEnable: { sealed: p.sealed, code: code.trim() } },
      });
    } catch (e) {
      error = String(e);
      busy = false;
    }
  }

  async function submitDelete() {
    const p = get(accountPrompt);
    if (!p || p.kind !== "delete") return;
    const server = p.server;
    if (p.what === "kept") {
      closePrompt(p);
      invoke("account_purge", { server, conv: null }).catch((e) => addNotification(`${fromServer(server)}${e}`, "error"));
      return;
    }
    const me = get(account.peek(server));
    const codes = me?.info.totp_enabled ?? false;
    error =
      confirmName.trim().toLowerCase() !== me?.name ? "Type the account's name to confirm."
      : !oldPassword ? "Enter your password."
      : codes && !code.trim() ? (useRecovery ? "Enter a recovery code." : "Enter the code from your authenticator app.")
      : "";
    if (error) return;
    busy = true;
    try {
      // The answer comes as account-reply (onReply)
      await invoke("account_delete", {
        server,
        password: oldPassword.normalize("NFC"),
        totp: codes && !useRecovery ? code.trim() : null,
        recovery: codes && useRecovery ? code.trim() : null,
      });
    } catch (e) {
      error = String(e);
      busy = false;
    }
  }

  async function submitPassword() {
    const p = get(accountPrompt);
    if (!p || p.kind !== "password") return;
    // One spelling of the password on every device: the keys come from its bytes.
    const [old, next] = [oldPassword.normalize("NFC"), newPassword.normalize("NFC")];
    const codes = get(account.peek(p.server))?.info.totp_enabled ?? false;
    error =
      !old ? "Enter your current password."
      : [...next].length < 10 ? "Use a new password of at least 10 characters."
      : next !== newPassword2.normalize("NFC") ? "The new passwords do not match."
      : codes && !code.trim() ? (useRecovery ? "Enter a recovery code." : "Enter the code from your authenticator app.")
      : "";
    if (error) return;
    busy = true;
    try {
      // The answer comes as account-reply (onReply)
      await invoke("account_password_change", {
        server: p.server,
        old,
        new: next,
        totp: codes && !useRecovery ? code.trim() : null,
        recovery: codes && useRecovery ? code.trim() : null,
      });
    } catch (e) {
      error = String(e);
      busy = false;
    }
  }

  async function submitRecoveryNew() {
    const p = get(accountPrompt);
    if (!p || p.kind !== "recovery-new") return;
    const codes = get(account.peek(p.server))?.info.totp_enabled ?? false;
    error =
      !oldPassword ? "Enter your password."
      : codes && !code.trim() ? (useRecovery ? "Enter a recovery code." : "Enter the code from your authenticator app.")
      : "";
    if (error) return;
    busy = true;
    keyChangedOn = null;
    try {
      // Held until the relay answers (onReply): a key it refused is no key
      const key = await invoke<string>("account_recovery_key_new", {
        server: p.server,
        password: oldPassword.normalize("NFC"),
        totp: codes && !useRecovery ? code.trim() : null,
        recovery: codes && useRecovery ? code.trim() : null,
      });
      if (keyChangedOn === p.server) showNewKey(p.server, key);
      else pendingKey = { server: p.server, key };
    } catch (e) {
      error = String(e);
      busy = false;
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
    } catch {
      copied = false;
    }
  }

  function closeRecovery() {
    closePrompt();
  }

  /**
   * What Escape does: the prompt's own Cancel, Later or Done. Nothing for
   * the ones that need an answer (a key or codes to write down, the
   * keep-messages question), or while a request is on its way.
   */
  function escapeFor(kind: string): (() => void) | undefined {
    if (busy) return undefined;
    if (kind === "totp") return cancelTotp;
    if (["totp-setup", "safety", "account", "delete", "password", "recovery-new"].includes(kind)) return () => closePrompt();
    return undefined;
  }
</script>

{#if $accountPrompt}
  {@const p = $accountPrompt}
  <div class="overlay">
    <div class="dialog account-dialog" data-kind={p.kind} use:dialog={{ onclose: escapeFor(p.kind) }}>
      {#if p.kind === "totp"}
        <h2>Two-factor code</h2>
        <p class="hint">
          {#if p.retry}That code was not right — try the next one.
          {:else}{fromServer(p.server)}enter the code from your authenticator app.{/if}
        </p>
        <div class="field">
          <label for="acct-code">{useRecovery ? "Recovery code" : "Code"}</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input
            id="acct-code"
            type="text"
            inputmode={useRecovery ? "text" : "numeric"}
            autocomplete="one-time-code"
            autofocus
            bind:value={code}
            placeholder={useRecovery ? "abcd-efgh-jkmn" : "123456"}
            disabled={busy}
            onkeydown={(e) => e.key === "Enter" && submitTotp()}
          />
        </div>
        <button type="button" class="link" onclick={() => (useRecovery = !useRecovery)}>
          {useRecovery ? "Use a code from the app" : "Lost your phone? Use a recovery code"}
        </button>
        {#if error}<div class="error" role="alert">{error}</div>{/if}
        <div class="buttons">
          <button type="button" class="secondary" onclick={cancelTotp} disabled={busy}>Cancel</button>
          <button type="button" class="submit-btn btn btn-primary" onclick={submitTotp} disabled={busy || !code.trim()}>Sign in</button>
        </div>
      {:else if p.kind === "recovery"}
        <h2>{fromServer(p.server)}Your {p.renewed ? "new " : ""}recovery key</h2>
        <p class="hint">
          {#if p.renewed}Your old recovery key no longer works. {/if}Write it down and keep it somewhere safe: if
          you forget your password, it sets a new one ("Forgot your password?" when you sign in) and opens your
          account's encrypted vault. VoIPC shows it only now, and the server cannot recover it for you.
        </p>
        <code class="secret">{p.key}</code>
        <button type="button" class="secondary" onclick={() => copy(p.key)}>{copied ? "Copied" : "Copy"}</button>
        <button type="button" class="submit-btn btn btn-primary" onclick={closeRecovery}>I have written it down</button>
      {:else if p.kind === "totp-setup"}
        <h2>{fromServer(p.server)}Set up two-factor codes</h2>
        <p class="hint">
          {#if p.why === "required"}Your role on this server needs a second factor before its rights apply.{/if}
          Scan this with an authenticator app (Aegis, 2FAS, Google Authenticator…), then type the code it shows.
        </p>
        {#if qr}
          <div class="qr">{@html qr}</div>
        {/if}
        <details>
          <summary>Can't scan? Type the key in</summary>
          <code class="secret">{p.secret}</code>
        </details>
        <div class="field">
          <label for="acct-setup-code">Code</label>
          <input
            id="acct-setup-code"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            bind:value={code}
            placeholder="123456"
            disabled={busy}
            onkeydown={(e) => e.key === "Enter" && submitSetup()}
          />
        </div>
        {#if error}<div class="error" role="alert">{error}</div>{/if}
        <div class="buttons">
          <button type="button" class="secondary" onclick={() => closePrompt()} disabled={busy}>Later</button>
          <button type="button" class="submit-btn btn btn-primary" onclick={submitSetup} disabled={busy}>Turn on</button>
        </div>
      {:else if p.kind === "safety"}
        <h2>{fromServer(p.server)}Verify {p.name}</h2>
        <p class="hint">
          Compare this number with {p.name} in person or on a call. If it matches theirs, nobody — not even this
          server — stands between your encrypted messages. It changes when either of you gets a new identity.
        </p>
        <code class="secret codes safety">{p.number}</code>
        <button type="button" class="submit-btn btn btn-primary" onclick={() => closePrompt()}>Done</button>
      {:else if p.kind === "cloud"}
        <h2>Keep your messages here too?</h2>
        <p class="hint">
          With a copy on {fromServer(p.server).replace(/: $/, "") || "this server"}, you can read your messages on
          your other devices, and what people write while you are away waits for you. This device keeps them only in
          its own chat history, if that is on; the browser keeps none between visits.
        </p>
        <p class="hint small">
          The copy is end-to-end encrypted: the server cannot read it. It does learn who wrote in which channel or
          conversation, when, how long each message is and when its copy may be deleted, and which channels you keep.
          Kept messages are signed by you, so the people they are for can prove you wrote them, and whoever gets into
          your account later can read them.
        </p>
        <label class="check">
          <input type="checkbox" bind:checked={shareChoice} disabled={busy} />
          <span>Let people who join a channel later read what I wrote there before</span>
        </label>
        {#if error}<div class="error" role="alert">{error}</div>{/if}
        <div class="buttons">
          <button type="button" class="secondary" onclick={() => submitCloud(p.server, false)} disabled={busy}>
            Only on this device
          </button>
          <button type="button" class="submit-btn btn btn-primary" onclick={() => submitCloud(p.server, true)} disabled={busy}>
            Keep a copy here
          </button>
        </div>
      {:else if p.kind === "account" && $account}
        <!-- `p` follows the store: a handler reads p.server before closePrompt(). -->
        <h2>{$account.name}</h2>
        <p class="hint">
          {$account.info.scopes.includes("*") ? "Admin" : $account.info.scopes.includes("voipc:moderate") ? "Moderator" : "Member"}
          · two-factor codes {$account.info.totp_enabled ? "on" : "off"}
        </p>
        <div class="rows">
          <div class="row">
            <span>Messages kept on this server: <strong>{$account.cloud ? "yes" : "no"}</strong></span>
            <button type="button" class="secondary" onclick={() => { const server = p.server; closePrompt(); askCloud(server); }}>Change</button>
          </div>
          <div class="row">
            <span>Password</span>
            <button type="button" class="secondary" onclick={() => { const server = p.server; closePrompt(); reset(); showPrompt({ kind: "password", server }); }}>Change</button>
          </div>
          <div class="row">
            <span>Recovery key</span>
            <button type="button" class="secondary" onclick={() => { const server = p.server; closePrompt(); reset(); showPrompt({ kind: "recovery-new", server }); }}>New</button>
          </div>
          {#if !$account.info.totp_enabled}
            <div class="row">
              <span>Two-factor codes protect the account on new devices.</span>
              <button type="button" class="secondary" onclick={() => { const server = p.server; closePrompt(); askTotpSetup(server); }}>Set up</button>
            </div>
          {/if}
          {#if $account.cloud}
            <div class="row">
              <span>Messages you kept here</span>
              <button type="button" class="secondary" onclick={() => { const server = p.server; closePrompt(); reset(); showPrompt({ kind: "delete", server, what: "kept" }); }}>Delete</button>
            </div>
          {/if}
          <div class="row">
            <span>If this device is remembered, it signs in without the password.</span>
            <button
              type="button"
              class="secondary"
              onclick={() =>
                invoke("forget_device", { server: p.server, name: $account?.name ?? "" }).then(
                  () => addNotification(`${fromServer(p.server)}this device is forgotten: the password is needed next time`, "info"),
                  (e) => addNotification(String(e), "warning"),
                )}
            >Forget</button>
          </div>
        </div>
        <div class="buttons">
          <button type="button" class="secondary danger" onclick={() => { const server = p.server; closePrompt(); reset(); showPrompt({ kind: "delete", server, what: "account" }); }}>Delete account…</button>
          <button type="button" class="submit-btn btn btn-primary" onclick={() => closePrompt()}>Done</button>
        </div>
      {:else if p.kind === "delete" && p.what === "kept"}
        <h2>{fromServer(p.server)}Delete your kept messages?</h2>
        <p class="hint">
          Every message you kept on this server goes from it, in every channel and conversation. Copies people's
          devices already fetched may stay there. New messages are still kept while copies are on.
        </p>
        <div class="buttons">
          <button type="button" class="secondary" onclick={() => closePrompt()}>Cancel</button>
          <button type="button" class="submit-btn btn btn-danger" onclick={submitDelete}>Delete them</button>
        </div>
      {:else if p.kind === "delete"}
        {@const codes = $account?.info.totp_enabled ?? false}
        <h2>{fromServer(p.server)}Delete your account?</h2>
        <p class="hint">
          This deletes {$account?.name ?? "the account"} on this server for good: its vault (your identity and the
          people you verified), the messages it kept, its remembered devices and its sessions. The name is free for
          someone else afterwards. What other people wrote to you, and copies of your messages their devices already
          have, stay theirs.
        </p>
        <div class="field">
          <label for="acct-delete-name">Type the account's name</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input id="acct-delete-name" type="text" autocomplete="off" autofocus bind:value={confirmName} disabled={busy} />
        </div>
        <div class="field">
          <label for="acct-delete-password">Password</label>
          <input id="acct-delete-password" type="password" autocomplete="current-password" bind:value={oldPassword} disabled={busy} />
        </div>
        {#if codes}
          <div class="field">
            <label for="acct-delete-code">{useRecovery ? "Recovery code" : "Code from your authenticator app"}</label>
            <input id="acct-delete-code" type="text" autocomplete="one-time-code" bind:value={code} disabled={busy} />
          </div>
          <button type="button" class="link" onclick={() => (useRecovery = !useRecovery)}>
            {useRecovery ? "Use a code from the app" : "Lost your phone? Use a recovery code"}
          </button>
        {/if}
        {#if error}<div class="error" role="alert">{error}</div>{/if}
        <div class="buttons">
          <button type="button" class="secondary" onclick={() => closePrompt()} disabled={busy}>Cancel</button>
          <button type="button" class="submit-btn btn btn-danger" onclick={submitDelete} disabled={busy}>Delete account</button>
        </div>
      {:else if p.kind === "password"}
        {@const codes = $account?.info.totp_enabled ?? false}
        <h2>{fromServer(p.server)}Change your password</h2>
        <p class="hint">
          Your other devices are signed out and need the new password. Your recovery key stays the same.
        </p>
        <div class="field">
          <label for="acct-old-password">Current password</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input id="acct-old-password" type="password" autocomplete="current-password" autofocus bind:value={oldPassword} disabled={busy} />
        </div>
        <div class="field">
          <label for="acct-new-password">New password</label>
          <input id="acct-new-password" type="password" autocomplete="new-password" bind:value={newPassword} disabled={busy} />
        </div>
        <div class="field">
          <label for="acct-new-password2">New password again</label>
          <input
            id="acct-new-password2"
            type="password"
            autocomplete="new-password"
            bind:value={newPassword2}
            disabled={busy}
            onkeydown={(e) => e.key === "Enter" && !codes && submitPassword()}
          />
        </div>
        {#if codes}
          <div class="field">
            <label for="acct-password-code">{useRecovery ? "Recovery code" : "Code from your authenticator app"}</label>
            <input
              id="acct-password-code"
              type="text"
              inputmode={useRecovery ? "text" : "numeric"}
              autocomplete="one-time-code"
              bind:value={code}
              placeholder={useRecovery ? "abcd-efgh-jkmn" : "123456"}
              disabled={busy}
              onkeydown={(e) => e.key === "Enter" && submitPassword()}
            />
          </div>
          <button type="button" class="link" onclick={() => (useRecovery = !useRecovery)}>
            {useRecovery ? "Use a code from the app" : "Lost your phone? Use a recovery code"}
          </button>
        {/if}
        {#if error}<div class="error" role="alert">{error}</div>{/if}
        <div class="buttons">
          <button type="button" class="secondary" onclick={() => closePrompt()} disabled={busy}>Cancel</button>
          <button type="button" class="submit-btn btn btn-primary" onclick={submitPassword} disabled={busy}>Change password</button>
        </div>
      {:else if p.kind === "recovery-new"}
        {@const codes = $account?.info.totp_enabled ?? false}
        <h2>{fromServer(p.server)}New recovery key</h2>
        <p class="hint">
          The recovery key you have now stops working, and only the new one resets your password. An account made
          before VoIPC 1.3 gets its reset key this way: until then, a device that remembers it could reset it too.
        </p>
        <div class="field">
          <label for="acct-recovery-password">Password</label>
          <!-- svelte-ignore a11y_autofocus -->
          <input
            id="acct-recovery-password"
            type="password"
            autocomplete="current-password"
            autofocus
            bind:value={oldPassword}
            disabled={busy}
            onkeydown={(e) => e.key === "Enter" && !codes && submitRecoveryNew()}
          />
        </div>
        {#if codes}
          <div class="field">
            <label for="acct-recovery-code">{useRecovery ? "Recovery code" : "Code from your authenticator app"}</label>
            <input
              id="acct-recovery-code"
              type="text"
              inputmode={useRecovery ? "text" : "numeric"}
              autocomplete="one-time-code"
              bind:value={code}
              placeholder={useRecovery ? "abcd-efgh-jkmn" : "123456"}
              disabled={busy}
              onkeydown={(e) => e.key === "Enter" && submitRecoveryNew()}
            />
          </div>
          <button type="button" class="link" onclick={() => (useRecovery = !useRecovery)}>
            {useRecovery ? "Use a code from the app" : "Lost your phone? Use a recovery code"}
          </button>
        {/if}
        {#if error}<div class="error" role="alert">{error}</div>{/if}
        <div class="buttons">
          <button type="button" class="secondary" onclick={() => closePrompt()} disabled={busy}>Cancel</button>
          <button type="button" class="submit-btn btn btn-primary" onclick={submitRecoveryNew} disabled={busy}>
            {busy ? "Making it…" : "Make a new key"}
          </button>
        </div>
      {:else if p.kind === "recovery-codes"}
        <h2>{fromServer(p.server)}Recovery codes</h2>
        <p class="hint">
          Each one signs you in once without your phone. Keep them with your recovery key; they are shown only now.
        </p>
        <code class="secret codes">{p.codes.join("\n")}</code>
        <button type="button" class="secondary" onclick={() => copy(p.codes.join("\n"))}>{copied ? "Copied" : "Copy"}</button>
        <button type="button" class="submit-btn btn btn-primary" onclick={() => closePrompt()}>Done</button>
      {/if}
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--scrim);
    display: flex;
    align-items: center;
    justify-content: center;
    /* Above the connect dialog (100) and the setup pop-ups (200/210): a
       sign-in waiting for a code must not sit behind them. */
    z-index: var(--z-account);
  }

  .dialog {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 28px;
    width: 380px;
    max-width: calc(100vw - 32px);
    display: flex;
    flex-direction: column;
    gap: 14px;
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

  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  label {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .secret {
    display: block;
    padding: 10px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-family: monospace;
    font-size: var(--fs-md);
    word-break: break-all;
    text-align: center;
    user-select: all;
  }

  .codes {
    white-space: pre;
  }

  .small {
    font-size: var(--fs-sm);
  }

  .check {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    text-transform: none;
    letter-spacing: normal;
    font-size: var(--fs-body);
    color: var(--text-primary);
  }

  .rows {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: var(--fs-body);
  }

  .row span {
    flex: 1;
  }

  .safety {
    white-space: normal;
    letter-spacing: 1px;
    line-height: 1.8;
  }

  .qr {
    align-self: center;
    background: white;
    padding: 8px;
    border-radius: 6px;
    line-height: 0;
  }

  .link {
    background: none;
    border: none;
    color: var(--text-primary);
    text-decoration: underline;
    font-size: var(--fs-sm);
    cursor: pointer;
    align-self: center;
  }

  .error {
    color: var(--danger);
    font-size: var(--fs-body);
    text-align: center;
  }

  .buttons {
    display: flex;
    gap: 8px;
  }

  .buttons > * {
    flex: 1;
  }

  .submit-btn {
    padding: 10px;
    font-size: var(--fs-md);
  }

  .secondary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* The other way out of a step (Cancel, Later, Copy). It set no colours of
     its own and so wore the browser's grey button on every dark palette. */
  .secondary {
    padding: 10px;
    font-size: var(--fs-md);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
  }

  .secondary:hover:not(:disabled) {
    background: var(--bg-hover);
  }

  .danger {
    color: var(--danger);
  }
</style>
