// Which update the connect dialog may offer for a server that refused us
// (1.0, B6), and how an update is offered at all (1.3.1, design input 5).
// Pure, for the tests; the stores live in stores/updates.ts.

/** A newer VoIPC the feed offers (updater.rs `UpdateInfo`). */
export interface UpdateInfo {
  version: string;
  notes: string | null;
  /** The protocol it speaks, when the feed says. */
  protocol: number | null;
  /** The oldest relay protocol it still talks to (since 1.6); the feed of an
   *  older release says none, and that one talks only to its own. */
  oldest_protocol?: number | null;
  /** The protocol this app speaks (since 1.3.1). */
  our_protocol?: number;
}

/** A server this app is connected to, and its protocol: null for our own. */
export interface Connected {
  name: string;
  protocol: number | null;
}

/** The relay protocols an update connects to, or null where the feed does
 *  not say: its own, and the older ones it talks down to (1.6). */
function reach(update: UpdateInfo): [number, number] | null {
  return update.protocol === null ? null : [update.oldest_protocol ?? update.protocol, update.protocol];
}

const within = (r: [number, number], p: number) => r[0] <= p && p <= r[1];

/** Whether installing `update` gets us onto a server that speaks
 *  `serverProtocol`. A feed that does not name the protocol is taken at its
 *  word that the newest version is the one to have. */
export function updateFits(update: UpdateInfo | null, serverProtocol: number): boolean {
  if (update === null) return false;
  const r = reach(update);
  return r === null || within(r, serverProtocol);
}

/** The servers `connected` that `update` would no longer reach. */
function lockedOut(update: UpdateInfo, connected: readonly Connected[]): Connected[] {
  const r = reach(update);
  const ours = update.our_protocol;
  if (r === null || ours === undefined) return [];
  return connected.filter((c) => !within(r, c.protocol ?? ours));
}

/**
 * How an update is offered (R4-01, design input 5):
 * - `plain`: every server this app reaches now, or this app's own protocol
 *   while it reaches none, is one the update reaches too (or the feed does
 *   not say): the toast, and one press installs it;
 * - `protocol`: some server would refuse it until that server is updated
 *   too. No toast; Settings says so, and installing takes a second press.
 */
export type UpdateOffer = "none" | "plain" | "protocol";

export function updateOffer(update: UpdateInfo | null, connected: readonly Connected[] = []): UpdateOffer {
  if (update === null) return "none";
  const servers = connected.length ? connected : [{ name: "", protocol: null }];
  return lockedOut(update, servers).length ? "protocol" : "plain";
}

/** The toast for a new update, or null for none (a protocol change waits for
 *  the person in Settings, Updates). */
export function updateToast(update: UpdateInfo | null, connected: readonly Connected[] = []): string | null {
  return updateOffer(update, connected) === "plain" && update ? `VoIPC ${update.version} is available: Settings, Updates.` : null;
}

/** "a", "a and b", "a, b and c". */
function listed(names: readonly string[]): string {
  return names.length < 2 ? (names[0] ?? "") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** What Settings says about an update some server would refuse: the ones of
 *  `connected` (the servers this app is connected to now) it locks out. */
export function protocolWarning(update: UpdateInfo, connected: readonly Connected[]): string {
  const [oldest, newest] = reach(update) ?? [update.protocol, update.protocol];
  const head =
    oldest === newest
      ? `VoIPC ${update.version} speaks protocol ${newest}.`
      : `VoIPC ${update.version} speaks protocols ${oldest} to ${newest}.`;
  const ours = update.our_protocol;
  const locked = lockedOut(update, connected);
  if (locked.length === 0) {
    const range = oldest === newest ? `${newest}` : `${oldest} to ${newest}`;
    return `${head} This VoIPC speaks ${ours}: after updating, you can connect only to servers that run ${range}.`;
  }
  const one = locked.length === 1;
  const protocols = [...new Set(locked.map((c) => c.protocol ?? ours))];
  const runs = protocols.length === 1 ? `protocol ${protocols[0]}` : "older protocols";
  return (
    `${head} ${listed(locked.map((c) => c.name))} ${one ? "runs" : "run"} ${runs}: after updating, you cannot connect to ` +
    `${one ? "it" : "them"} until ${one ? "it is" : "they are"} updated too.`
  );
}
