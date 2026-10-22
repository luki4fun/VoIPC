// Relay accounts for one browser session: the wasm `AccountSignIn` (the steps
// the desktop client runs too, voipc_crypto::account), the code the person
// types in mid-way, and then the wasm `AccountSession`
// (voipc_crypto::account_session), whose rules the desktop shares as well.
// This file only carries their messages and keeps what they hand over. The
// desktop's counterpart is client/src-tauri/src/account.rs; both emit the
// same events, so one front end serves both.

import { getConfig } from "./config";
import { cursorStorageKey, findDevice, saveDevice } from "./devices";
import { wasm, type AccountActions, type AccountMethod, type AccountSession, type AccountSignIn, type SignalClient } from "./wasm";

/** How the front end wants a connection to sign in. */
export type AccountArgs =
  | { kind: "login"; password: string }
  | { kind: "register"; password: string; invite?: string | null }
  | { kind: "device" };

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
 *  it named as readers). localStorage is per origin, and the relay is the
 *  origin, so the key needs only the account. */
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

  private constructor(signIn: AccountSignIn, private readonly passwordBased: boolean) {
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
    return new AccountDriver(api.newAccountSignIn(name, method), args.kind !== "device");
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
    let steps;
    try {
      // The password's stretching runs in here, on this thread: a second or two.
      steps = signIn.step(payload);
    } catch (e) {
      host.failAuth(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    for (const s of steps) {
      if (s.send) {
        host.sendRaw(s.send);
      } else if (s.keys) {
        const client = wasm().signalClientFromIdentity(signIn.identity());
        host.replaceSignal(client);
        host.sendRaw(signIn.keys(client.bundle().prekey_bundle));
      } else if (s.needTotp) {
        void this.askTotp(host, signIn);
      }
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
  noteRoster(users: unknown[]): void {
    try {
      this.session?.noteRoster(users);
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

  setPrefs(host: AccountHost, cloud: boolean, asked: boolean): void {
    if (!this.session) throw new Error("Not signed in to an account on that server");
    this.run(host, this.session.setPrefs(cloud, asked));
  }
}
