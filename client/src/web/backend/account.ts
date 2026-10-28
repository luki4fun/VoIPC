// Relay accounts for one browser session: the wasm `AccountSignIn` (the steps
// the desktop client runs too, voipc_crypto::account), the code the person
// types in mid-way, and then the wasm `AccountSession`
// (voipc_crypto::account_session), whose rules the desktop shares as well.
// This file only carries their messages and keeps what they hand over. The
// desktop's counterpart is client/src-tauri/src/account.rs; both emit the
// same events, so one front end serves both.

import { toHex } from "../../lib/hex";
import { getConfig } from "./config";
import { cursorStorageKey, findDevice, saveDevice } from "./devices";
import { wasm, type AccountActions, type AccountMethod, type AccountSession, type AccountSignIn, type SignInStep, type SignalClient } from "./wasm";

/** How the front end wants a connection to sign in. */
export type AccountArgs =
  | { kind: "login"; password: string }
  | { kind: "register"; password: string; invite?: string | null }
  | { kind: "device" }
  | { kind: "reset"; recovery: string; password: string };

/** What a reset ends with (account.rs RESET_DONE): the relay closes that
 *  connection, and the front end signs in with the new password. */
export const RESET_DONE = "Your password was reset. Sign in with the new one.";

/** The relay id (hex) each address named at its last account sign-in, as the
 *  desktop keeps `relay_ids` in its settings (1.0 audit H5-01): a server
 *  claiming another's id never gets a password stretched for that one. */
const RELAY_IDS = "voipc.relay_ids";

function relayIds(): Record<string, string> {
  try {
    const o = JSON.parse(localStorage.getItem(RELAY_IDS) ?? "{}");
    return o && typeof o === "object" ? o : {};
  } catch {
    return {};
  }
}

function setRelayId(server: string, id: string | null): boolean {
  const ids = relayIds();
  const had = server in ids;
  if (id === null) delete ids[server];
  else ids[server] = id;
  try {
    localStorage.setItem(RELAY_IDS, JSON.stringify(ids));
  } catch {
    // Asked again at the next sign-in
  }
  return had;
}

/** Forget the relay id remembered for `server` (it moved, or was set up again). */
export function forgetRelayId(server: string): boolean {
  return setRelayId(server, null);
}

/** PBKDF2-SHA256 of a password (NFC, as the front end hands it) with `salt`:
 *  voipc_crypto::account::stretch in WebCrypto, which is about eight times
 *  faster than in wasm on a phone (1.0 audit H5-18). */
async function stretch(password: string, salt: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: wasm().kdfRounds() }, key, 256);
  return new Uint8Array(bits);
}

/** What the driver needs from its session. */
export interface AccountHost {
  readonly server: string;
  sendRaw(payload: Uint8Array): void;
  sendControl(msg: unknown): void;
  emit(name: string, data?: unknown): void;
  /** The account's identity replaces the placeholder the session was made with. */
  replaceSignal(client: SignalClient): void;
  failAuth(e: Error): void;
}

/** What this browser keeps of an account's stored log (how far it read, who
 *  it named as readers), under a key with the relay id and the account
 *  (`cursorStorageKey`): one page's localStorage serves every server opened
 *  in it, not only the one that served it. */
function readCursors(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeCursors(key: string, json: string): void {
  try {
    localStorage.setItem(key, json);
  } catch {
    // Read again next time; the merge drops what is already there.
  }
}

type TotpAnswer = { code: string; recovery: boolean } | null;
type Body = Record<string, unknown>;

const TOTP_WAIT_MS = 115_000;

export class AccountDriver {
  private signIn: AccountSignIn | null;
  private totpWaiter: ((a: TotpAnswer) => void) | null = null;
  private asked = 0;
  /** What follows the sign-in (voipc_crypto::account_session, as on the desktop). */
  private session: AccountSession | null = null;

  private constructor(
    signIn: AccountSignIn,
    private readonly passwordBased: boolean,
    /** For the `stretch` step; none for a device-key sign-in. */
    private readonly password: string | null,
  ) {
    this.signIn = signIn;
  }

  /** Throws why it cannot start (a bad name, no remembered device). */
  static async create(server: string, username: string, args: AccountArgs): Promise<AccountDriver> {
    const api = wasm();
    const name = api.normalizeAccountName(username);
    let method: AccountMethod;
    if (args.kind === "device") {
      const d = await findDevice(server, name);
      if (!d) throw new Error("This browser is not remembered on this server. Sign in with your password.");
      // Plain arrays: serde-wasm-bindgen reads a Uint8Array as bytes, which a
      // Vec<u8> field refuses ("expected a sequence").
      method = { kind: "device", device_id: d.device_id, device_key: d.device_key, relay_id: d.relay_id, dek: d.dek };
    } else {
      method = args;
    }
    const signIn = api.newAccountSignIn(name, method);
    const ids = relayIds();
    signIn.expectRelay(
      ids[server],
      Object.entries(ids)
        .filter(([s]) => s !== server)
        .map(([s, id]) => [id, s]),
    );
    return new AccountDriver(signIn, args.kind !== "device", args.kind === "device" ? null : args.password);
  }

  /** The Authenticate payload. */
  first(): Uint8Array {
    if (!this.signIn) throw new Error("the sign-in is over");
    return this.signIn.first();
  }

  /** Every control payload, before it is decoded for anything else. */
  onPayload(host: AccountHost, payload: Uint8Array): void {
    const signIn = this.signIn;
    if (!signIn) return;
    try {
      this.steps(host, signIn, signIn.step(payload));
    } catch (e) {
      host.failAuth(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private steps(host: AccountHost, signIn: AccountSignIn, steps: SignInStep[]): void {
    for (const s of steps) {
      if (s.send) {
        host.sendRaw(s.send);
      } else if (s.keys) {
        const client = signIn.signalClient();
        host.replaceSignal(client);
        host.sendRaw(signIn.keys(client.bundle().prekey_bundle));
      } else if (s.needTotp) {
        void this.askTotp(host, signIn);
      } else if (s.stretch !== undefined) {
        void this.stretchThen(host, signIn, s.stretch);
      } else if (s.resetDone) {
        host.failAuth(new Error(RESET_DONE));
      }
    }
  }

  /** The password's stretching, off the page's thread, then the machine's next steps. */
  private async stretchThen(host: AccountHost, signIn: AccountSignIn, salt: string): Promise<void> {
    try {
      const master = await stretch(this.password ?? "", salt);
      // The sign-in may have ended meanwhile
      if (this.signIn === signIn) this.steps(host, signIn, signIn.stretched(master));
    } catch (e) {
      host.failAuth(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private async askTotp(host: AccountHost, signIn: AccountSignIn): Promise<void> {
    const answer = await new Promise<TotpAnswer>((resolve) => {
      const timer = setTimeout(() => resolve(null), TOTP_WAIT_MS);
      this.totpWaiter = (a) => {
        clearTimeout(timer);
        this.totpWaiter = null;
        resolve(a);
      };
      host.emit("account-need-totp", this.asked > 0);
      this.asked++;
    });
    if (!answer) {
      host.failAuth(new Error("No code was entered in time."));
      return;
    }
    host.sendRaw(answer.recovery ? signIn.recovery(answer.code) : signIn.totp(answer.code));
  }

  /** The code (or a recovery code) the person typed. */
  answerTotp(code: string, recovery: boolean): void {
    if (!this.totpWaiter) throw new Error("No sign-in is waiting for a code.");
    this.totpWaiter({ code, recovery });
  }

  cancel(): void {
    this.totpWaiter?.(null);
  }

  /** After Authenticated, with its `account` (AccountInfo). */
  onAuthenticated(host: AccountHost, info: Body): void {
    if (!this.signIn) return;
    const signIn = this.signIn;
    const done = signIn.finish();
    if (relayIds()[host.server] !== toHex(done.relay_id)) setRelayId(host.server, toHex(done.relay_id));
    const memory = readCursors(cursorStorageKey(done.relay_id, done.name));
    const { session, actions } = signIn.startSession(info, memory, getConfig().share_channel_history, this.passwordBased);
    signIn.free();
    this.signIn = null;
    this.session = session;
    this.run(host, actions);
  }

  /** Once the session is listed (commands find it): the sync's first asks,
   *  and the second-factor setup a role waits for, or remembering this browser. */
  afterConnect(host: AccountHost): void {
    if (this.session) this.run(host, this.session.afterConnect());
  }

  /** The session is over: the wasm objects go, and a prompt waiting for a code ends. */
  dispose(): void {
    this.totpWaiter?.(null);
    this.signIn?.free();
    this.signIn = null;
    this.session?.free();
    this.session = null;
  }

  /** What the session asked for: messages out, events to the front end, and
   *  what this browser keeps (the device key, the log's read cursors). */
  private run(host: AccountHost, a: AccountActions): void {
    for (const p of a.send) host.sendRaw(p);
    for (const e of a.emit) host.emit(e.name, e.payload);
    if (a.remember) {
      void saveDevice({ server: host.server, ...a.remember }).catch((err) => console.warn("could not remember this browser:", err));
    }
    if (a.memory) writeCursors(`voipc.cursors.${a.memory.key}`, a.memory.json);
  }

  /** A decoded AccountReply. */
  onReply(host: AccountHost, reply: unknown): void {
    if (this.session) this.run(host, this.session.onReply(reply));
  }

  /** The users of a UserList or UserJoined, for the pins. Never throws: the
   *  roster itself must still be shown. */
  noteRoster(host: AccountHost, users: unknown[]): void {
    try {
      if (this.session) this.run(host, this.session.noteRoster(users));
    } catch (e) {
      console.warn("could not read the roster's accounts:", e);
    }
  }

  /** An identity `userId` showed: in a pre-key bundle, or a session they opened. */
  checkIdentity(host: AccountHost, userId: number, key: ArrayLike<number>): void {
    if (this.session) this.run(host, this.session.checkIdentity(userId, Uint8Array.from(key)));
  }

  /** A direct message to `userId`, kept for them too when cloud copies are on. */
  outgoingDm(host: AccountHost, userId: number, envelope: Uint8Array, ttlSecs?: number | null): void {
    if (this.session) this.run(host, this.session.outgoingDm(userId, envelope, Date.now(), ttlSecs ?? null));
  }

  /** A direct message for an account that is away (hex id); throws why not. */
  keptDm(host: AccountHost, accountHex: string, envelope: Uint8Array, ttlSecs?: number | null): void {
    if (!this.session) throw new Error("Not signed in to an account on that server");
    this.run(host, this.session.keptDm(accountHex, envelope, Date.now(), ttlSecs ?? null));
  }

  /** A message written in a channel with log `log` ("" for none), kept for its members too. */
  outgoingChannel(host: AccountHost, log: string, envelope: Uint8Array, ttlSecs?: number | null): void {
    if (this.session) this.run(host, this.session.outgoingChannel(log, envelope, Date.now(), ttlSecs ?? null));
  }

  /** In a channel with log `conv`: keep it, and read what it kept. */
  enter(host: AccountHost, conv: string): void {
    if (this.session) this.run(host, this.session.enter(conv));
  }

  /** Delete what this account wrote to the stored logs, in `conv` or everywhere. */
  purge(host: AccountHost, conv: string | null): void {
    if (!this.session) throw new Error("Not signed in to an account on that server");
    this.run(host, this.session.purge(conv));
  }

  /** Delete this account; `AccountDeleted` answers as `account-reply`. */
  async deleteAccount(host: AccountHost, password: string, totp: string | null, recovery: string | null): Promise<void> {
    const session = this.session;
    if (!session) throw new Error("Not signed in to an account on that server");
    const master = await stretch(password, session.kdfSalt());
    if (this.session !== session) throw new Error("The connection ended.");
    this.run(host, session.deleteAccount(master, totp, recovery));
  }

  /** Out of channel log `conv`; with `tell`, the relay is asked to take us out. */
  leave(host: AccountHost, conv: string, tell: boolean): void {
    if (this.session) this.run(host, this.session.leave(conv, tell));
  }

  keptFor(userId: number): boolean {
    return this.session?.keptFor(userId) ?? false;
  }

  /** The safety number with `userId`; `live` is the key the session with them runs on. */
  safetyNumber(userId: number, ownKey: number[], live?: Uint8Array): string {
    if (!this.session) throw new Error("Sign in to an account to verify people");
    return this.session.safetyNumber(userId, Uint8Array.from(ownKey), live);
  }

  setShare(on: boolean): void {
    this.session?.setShare(on);
  }

  prefs(): { cloud: boolean; asked: boolean } | null {
    return this.session ? { cloud: this.session.cloud(), asked: this.session.asked() } : null;
  }

  /** A new password: the current one, and a code where the account has codes
   *  on. The answer comes as `account-reply` (`PasswordChanged`, or an Error
   *  for `PasswordChange`). */
  async passwordChange(host: AccountHost, old: string, next: string, totp: string | null, recovery: string | null): Promise<void> {
    const session = this.session;
    if (!session) throw new Error("Not signed in to an account on that server");
    if ([...next].length < 10) throw new Error("Use a password of at least 10 characters.");
    const salt = session.kdfSalt();
    const [o, n] = await Promise.all([stretch(old, salt), stretch(next, salt)]);
    if (this.session !== session) throw new Error("The connection ended.");
    this.run(host, session.passwordChange(o, n, totp, recovery));
  }

  /** A new recovery key (account.rs `account_recovery_key_new`): the
   *  password, and a code where the account has codes on. Resolves to the
   *  key's text, for the page to show once `RecoveryKeyChanged` answers as
   *  `account-reply` (an Error for `RecoveryKeyNew` means it is not in force). */
  async recoveryKeyNew(host: AccountHost, password: string, totp: string | null, recovery: string | null): Promise<string> {
    const session = this.session;
    if (!session) throw new Error("Not signed in to an account on that server");
    const master = await stretch(password, session.kdfSalt());
    if (this.session !== session) throw new Error("The connection ended.");
    const out = session.recoveryKeyNew(master, totp, recovery);
    this.run(host, out);
    return out.key;
  }

  setPrefs(host: AccountHost, cloud: boolean, asked: boolean): void {
    if (!this.session) throw new Error("Not signed in to an account on that server");
    this.run(host, this.session.setPrefs(cloud, asked));
  }
}
