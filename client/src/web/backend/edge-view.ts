// Watching a share through a media edge (protocol 26, 1.15). For a big share the relay
// may send a viewer to an edge, a relay process of its own that forwards the share's
// sealed frames (ServerMessage::WatchAt). This holds the browser's one edge link: when
// it connects, what of it reaches the viewer, and when the viewer tells the relay the
// edge failed (ClientMessage::EdgeFailed), which moves it to another edge or back.
// session.ts gives it the link (transport.ts openEdgeView) and the media modules.
// Native mirror: client/src-tauri/src/edge_view.rs.
//
// Each WatchAt opens a generation. Whatever an older one's link still delivers, records
// already read, a late Ready or its end, is dropped here, so frames from an edge the
// viewer left never reach the assembler. The assembler's frame-id floor backs that up
// (voipc_protocol::video).

import { edgeFailedDue, EDGE_SILENT_MS, validEdgeView, type EdgeTarget } from "../../lib/share-rules.ts";
import type { EdgeViewHandlers, EdgeViewLink } from "./transport.ts";

/** At most one edge connect per this long on a connection; a later WatchAt waits its turn. */
export const EDGE_CONNECT_SPACING_MS = 5_000;
/** How long after an edge ended the link itself the viewer waits for the relay's word. */
export const EDGE_ENDED_GRACE_MS = 5_000;

/** `WatchAt.placement`: a u64, so a bigint as wasm decodes it; sent back as it came. */
export type Placement = bigint | number;

/** The `edge-view` event, for logs and lanes only: no viewer sees an edge. */
export interface EdgeViewEvent {
  sharer_user_id: number;
  host: string;
  state: "connecting" | "ready" | "failed" | "closed";
  reason?: string;
}

/** The clock and timers, so a test can run them. */
export interface Clock {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(timer: unknown): void;
}

export const realClock: Clock = {
  now: () => performance.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (timer) => clearTimeout(timer as ReturnType<typeof setTimeout>),
};

/** What the edge view needs from its session. */
export interface EdgeViewHost {
  /** Connect, show the ticket, and resolve once the edge said Ready (openEdgeView). */
  open(view: EdgeTarget, handlers: EdgeViewHandlers): Promise<EdgeViewLink>;
  /** Send `EdgeFailed` for the WatchAt in force. */
  edgeFailed(sharerUserId: number, placement: Placement): void;
  /**
   * One record of the watched share, into the same assembler as the relay's.
   * True when it completed a frame that decrypted: only that keeps the watchdog quiet.
   */
  video(bytes: Uint8Array): boolean;
  /** One screen-audio datagram of the watched share, into the same path as the relay's. */
  datagram(bytes: Uint8Array): void;
  /** This connection is the TCP fallback, which has no UDP to reach an edge with. */
  tunnel(): boolean;
  state(event: EdgeViewEvent): void;
}

type Phase =
  /** Nothing to watch here: no WatchAt, or the relay serves the share itself. */
  | "idle"
  /** A WatchAt came within the spacing of the last connect, and waits for it. */
  | "waiting"
  | "connecting"
  | "ready"
  /** The edge ended the link after its Ready; the relay has EDGE_ENDED_GRACE_MS to move us. */
  | "ended"
  /** The relay was told and has not answered: told again every EDGE_SILENT_MS. */
  | "failed";

/** The WatchAt in force. */
interface Current {
  sharer: number;
  placement: Placement;
  host: string;
}

export class EdgeView {
  private gen = 0;
  private phase: Phase = "idle";
  private current: Current | null = null;
  private link: EdgeViewLink | null = null;
  private timer: unknown = null;
  /** When the last connect started: the spacing counts from it, on this connection. */
  private lastConnectAt = -Infinity;
  /**
   * From when silence counts: the last complete decrypted frame, the Ready, the
   * last EdgeFailed, or the link's end while the relay has its grace.
   */
  private since = 0;
  private readonly host: EdgeViewHost;
  private readonly clock: Clock;

  constructor(host: EdgeViewHost, clock: Clock = realClock) {
    this.host = host;
    this.clock = clock;
  }

  /** The sharer the WatchAt in force is about, or 0. */
  get sharer(): number {
    return this.current?.sharer ?? 0;
  }

  /**
   * `WatchAt` with an edge, for the share being watched: leave any edge before,
   * and connect to this one (in its turn). An edge the app cannot connect to at
   * all, or a connection on the TCP fallback, fails at once.
   */
  watchAt(sharer: number, placement: Placement, view: unknown): void {
    this.leave("moved");
    const gen = this.gen;
    // For the event only, and the relay chose it: no longer than a host name
    const named = (view as { host?: unknown } | null)?.host;
    this.current = { sharer, placement, host: typeof named === "string" ? named.slice(0, 253) : "" };
    if (!validEdgeView(view)) return this.fail("the relay named no edge the app can reach");
    if (this.host.tunnel()) return this.fail("this connection is the TCP fallback");
    const wait = this.lastConnectAt + EDGE_CONNECT_SPACING_MS - this.clock.now();
    if (wait <= 0) return this.connect(gen, view);
    this.phase = "waiting";
    this.timer = this.clock.setTimeout(() => {
      this.timer = null;
      if (gen === this.gen) this.connect(gen, view);
    }, wait);
  }

  /**
   * The share comes over the relay's own connection again, or is not watched
   * any more (`WatchAt` without an edge, a stop, another share, leaving voice,
   * a disconnect): close the link, and nothing of it reaches the viewer after.
   */
  close(): void {
    this.leave("closed");
  }

  private leave(reason: string): void {
    this.gen++;
    this.clearTimer();
    const was = this.current;
    const link = this.link;
    this.link = null;
    this.current = null;
    const phase = this.phase;
    this.phase = "idle";
    link?.close();
    if (was && (phase === "connecting" || phase === "ready")) this.say(was, "closed", reason);
  }

  private connect(gen: number, view: EdgeTarget): void {
    const current = this.current!;
    this.phase = "connecting";
    this.lastConnectAt = this.clock.now();
    this.say(current, "connecting");
    const live = () => gen === this.gen;
    const handlers: EdgeViewHandlers = {
      onVideoPacket: (bytes) => {
        if (!live() || !this.ofShare(bytes, 0x13, 0x14)) return;
        // Stamped only by what the decode path made a whole frame of
        if (this.host.video(bytes) && this.phase === "ready") this.since = this.clock.now();
      },
      onDatagram: (bytes) => {
        if (live() && this.ofShare(bytes, 0x15, 0x15)) this.host.datagram(bytes);
      },
      onClosed: (reason) => {
        if (live() && this.phase === "ready") this.ended(reason);
      },
    };
    this.host.open(view, handlers).then(
      (link) => {
        if (!live()) return link.close();
        this.link = link;
        this.phase = "ready";
        this.since = this.clock.now();
        this.say(current, "ready");
        this.arm();
      },
      (e) => {
        if (live()) this.fail(e instanceof Error ? e.message : String(e));
      },
    );
  }

  /** Only the watched sharer's records (0x13/0x14) and screen audio (0x15). */
  private ofShare(bytes: Uint8Array, lo: number, hi: number): boolean {
    if (bytes.length < 5 || bytes[0] < lo || bytes[0] > hi) return false;
    // Bytes 1..5: the sender's session id, which the relay makes the user id
    const sender = ((bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4]) >>> 0;
    return sender === this.current?.sharer;
  }

  /** The edge ended the link itself: the relay usually moves us first, else we ask it to. */
  private ended(reason: string): void {
    this.link = null;
    this.phase = "ended";
    this.since = this.clock.now();
    this.say(this.current!, "closed", reason);
    this.arm();
  }

  /** Tell the relay now, and again every EDGE_SILENT_MS while it does not answer. */
  private fail(reason: string): void {
    this.link?.close();
    this.link = null;
    this.phase = "failed";
    this.tell(reason);
  }

  private tell(reason: string): void {
    const current = this.current!;
    this.since = this.clock.now();
    this.host.edgeFailed(current.sharer, current.placement);
    this.say(current, "failed", reason);
    this.arm();
  }

  /** The one timer, for what the phase waits on next. */
  private arm(): void {
    this.clearTimer();
    if (this.phase !== "ready" && this.phase !== "failed" && this.phase !== "ended") return;
    const bound = this.phase === "ended" ? EDGE_ENDED_GRACE_MS : EDGE_SILENT_MS;
    const gen = this.gen;
    const wait = Math.max(0, this.since + bound - this.clock.now());
    this.timer = this.clock.setTimeout(() => {
      this.timer = null;
      if (gen === this.gen) this.check();
    }, wait);
  }

  private check(): void {
    const now = this.clock.now();
    if (this.phase === "ended") {
      if (now - this.since >= EDGE_ENDED_GRACE_MS) return this.fail("the edge ended the link and the relay said nothing");
    } else if (edgeFailedDue(now, this.since, this.phase === "ready" || this.phase === "failed")) {
      return this.tell(this.phase === "ready" ? "no whole frame from the edge for 10 s" : "the relay has not answered");
    }
    // A frame came meanwhile: the deadline moved with it
    this.arm();
  }

  private clearTimer(): void {
    if (this.timer !== null) this.clock.clearTimeout(this.timer);
    this.timer = null;
  }

  private say(current: Current, state: EdgeViewEvent["state"], reason?: string): void {
    this.host.state({ sharer_user_id: current.sharer, host: current.host, state, ...(reason ? { reason } : {}) });
  }
}
