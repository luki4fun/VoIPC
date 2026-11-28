// The live path's few rules of the page's own (session.ts): what a frame comes to is written
// once, in voipc_crypto::channel_state. Pure enough to run without wasm or a relay.

/** Whether someone listed in `channel` is asked for a bundle now (network.rs `asks_bundles`).
 *  Sessions open when there is something to say, and a list of General costs nothing: only
 *  a room we stand in has a key dance to do. */
export function asksBundles(channel: number, ownRoom: number): boolean {
  return channel === ownRoom && ownRoom !== 0;
}

/** The frames a list too long for one comes in, and at the last of them the list. A relay can
 *  say "more" for ever: past this many frames, about 19,000 channels, the rest is not kept. */
const CHANNEL_LIST_FRAMES_MOST = 64;

export class ChannelListParts<T> {
  private channels: T[] = [];
  private frames = 0;

  take(channels: readonly T[], more: boolean): T[] | null {
    if (this.frames < CHANNEL_LIST_FRAMES_MOST) {
      this.frames++;
      this.channels.push(...channels);
    }
    if (more) return null;
    const whole = this.channels;
    this.channels = [];
    this.frames = 0;
    return whole;
  }
}

/** What the key frames need from their session. */
export interface LivePumpHost {
  /** The next key frame, if one may go now. */
  nextFrame(inCall: boolean): Uint8Array | undefined;
  send(frame: Uint8Array): void;
  /** Control frames queued and not yet written. */
  queued(): number;
  inCall(): boolean;
  /** A frame just made may have used a session kept from before: its identity, past the pins. */
  checked(): void;
  over(): boolean;
}

/** How often the pump looks whether the queue has drained (network.rs `drained`). */
const DRAIN_POLL_MS = 5;
/** In a call the pause behind a frame is as long as the frame took, up to this. */
const CALL_PAUSE_MAX_MS = 10_000;

/**
 * network.rs `live_task`'s loop. One key frame in the queue at a time, whatever the job's size,
 * so a seat or a post queued behind it waits for one key frame at most, with no lanes. The page
 * thread is yielded between frames: wraps run on the thread that paints and feeds the mic.
 */
export class LivePump {
  private readonly host: LivePumpHost;
  private running = false;

  constructor(host: LivePumpHost) {
    this.host = host;
  }

  /** While it runs it asks for the next frame anyway, and it gives up only with no await
   *  left between that answer and being done, so no wake falls in between. */
  wake(): void {
    if (this.running) return;
    this.running = true;
    void this.run();
  }

  private drained(): Promise<void> {
    return new Promise((resolve) => {
      const look = () => {
        if (this.host.over() || this.host.queued() === 0) resolve();
        else setTimeout(look, DRAIN_POLL_MS);
      };
      look();
    });
  }

  private async run(): Promise<void> {
    try {
      for (;;) {
        await this.drained();
        if (this.host.over()) return;
        const started = Date.now();
        const inCall = this.host.inCall();
        const frame = this.host.nextFrame(inCall);
        if (!frame) break;
        this.host.send(frame);
        await this.drained();
        const pause = inCall ? Math.min(Date.now() - started, CALL_PAUSE_MAX_MS) : 0;
        await new Promise((resolve) => setTimeout(resolve, pause));
        if (this.host.over()) return;
      }
      this.host.checked();
    } catch (e) {
      console.warn("the live path's key frames stopped:", e);
    } finally {
      this.running = false;
    }
  }
}

/**
 * Whether this relay uses the group key (plan 3i): `none` until `Authenticated`, `wait` from
 * it until the next frame says, then `legacy` (no `GroupKeys`: a relay from before it, on the
 * old paths), `off` (the old paths, and kept history read under the group key) or `on`.
 */
export type GkPath = "none" | "wait" | "legacy" | "off" | "on";

/** The path after a frame `tag` (`on`: `GroupKeys.on`). The relay sends `GroupKeys` right
 *  after `Authenticated`, so any other frame first is a relay without it. */
export function gkPathAfter(path: GkPath, tag: string, on = false): GkPath {
  if (tag === "Authenticated") return "wait";
  if (path !== "wait") return path;
  if (tag === "GroupKeys") return on ? "on" : "off";
  return "legacy";
}

/** Whether the group key runs on this connection: on, or off for kept history only. */
export const gkRuns = (path: GkPath): boolean => path === "on" || path === "off";

/** Whether posts go under the group key: text channels and a voice room's chat alike. */
export const gkPosts = (path: GkPath): boolean => path === "on";

/** The next task, by a message to ourselves: a hidden tab clamps timers to a second or
 *  more, and never messages. */
export function yieldTask(): Promise<void> {
  return new Promise((resolve) => {
    const { port1, port2 } = new MessageChannel();
    port1.onmessage = () => {
      port1.close();
      resolve();
    };
    port2.postMessage(null);
  });
}

/** What a keyholder's uploads need from their session. */
export interface GkPumpHost {
  /** The next commit part or welcome page, if one waits. */
  nextFrame(inCall: boolean): Uint8Array | undefined;
  send(frame: Uint8Array): void;
  /** Resolves once the transport has written what was queued (network.rs `drained`). */
  writable(): Promise<void>;
  inCall(): boolean;
  over(): boolean;
}

/**
 * A keyholder's commit parts and welcome pages (plan 3g): one in the queue at a time, the
 * next once the transport has written the last, yielding to voice as `LivePump` does. Its
 * waits are on `ReadyClock`, never a page timer: a browser keyholder keeps its voice duty
 * with its page hidden, where a timer waits a second or more and a part would miss its due.
 */
export class GkPump {
  private readonly host: GkPumpHost;
  private running = false;

  constructor(host: GkPumpHost) {
    this.host = host;
  }

  /** Nothing is awaited between the last `nextFrame` and being done, so no wake is lost. */
  wake(): void {
    if (this.running) return;
    this.running = true;
    void this.run();
  }

  private async run(): Promise<void> {
    try {
      for (;;) {
        await this.host.writable();
        if (this.host.over()) return;
        const frame = this.host.nextFrame(this.host.inCall());
        if (!frame) return;
        this.host.send(frame);
      }
    } catch (e) {
      console.warn("a keyholder's uploads stopped:", e);
    } finally {
      this.running = false;
    }
  }
}

/**
 * Waits until each `ready()` says so, looked at on every tick of a clock a hidden tab does
 * not clamp (a worker's, worklets/tick-worker.js). `start` begins the ticks and returns
 * what stops them: they run only while something waits.
 */
export class ReadyClock {
  private readonly start: (tick: () => void) => () => void;
  private readonly waits = new Set<() => boolean>();
  private stop: (() => void) | undefined;

  constructor(start: (tick: () => void) => () => void) {
    this.start = start;
  }

  until(ready: () => boolean): Promise<void> {
    if (ready()) return Promise.resolve();
    return new Promise((resolve) => {
      this.waits.add(() => {
        if (!ready()) return false;
        resolve();
        return true;
      });
      this.stop ??= this.start(() => this.tick());
    });
  }

  private tick(): void {
    for (const look of [...this.waits]) if (look()) this.waits.delete(look);
    if (this.waits.size > 0) return;
    this.stop?.();
    this.stop = undefined;
  }
}

/**
 * Sessions with accounts between one connection and the next, by server and by the account
 * signed in there (network.rs `keep_sessions`). In this page's memory: a person's disconnect
 * wipes them, and a reload has none. `T` is a wasm object, so each is freed as it goes.
 */
export class KeptByAccount<T extends { free(): void }> {
  private readonly rows = new Map<string, Map<string, T>>();

  put(server: string, account: string, kept: T): void {
    let here = this.rows.get(server);
    if (!here) this.rows.set(server, (here = new Map()));
    here.get(account)?.free();
    here.set(account, kept);
  }

  take(server: string, account: string): T | undefined {
    const here = this.rows.get(server);
    const kept = here?.get(account);
    here?.delete(account);
    return kept;
  }

  forget(server: string): void {
    for (const kept of this.rows.get(server)?.values() ?? []) kept.free();
    this.rows.delete(server);
  }
}
