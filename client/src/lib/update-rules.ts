// Which update the connect dialog may offer for a server that refused us
// (1.0, B6), and how an update is offered at all (1.3.1, design input 5).
// Pure, for the tests; the stores live in stores/updates.ts.

/** A newer VoIPC the feed offers (updater.rs `UpdateInfo`). */
export interface UpdateInfo {
  version: string;
  notes: string | null;
  /** The protocol it speaks, when the feed says. */
  protocol: number | null;
  /** The protocol this app speaks (since 1.3.1). */
  our_protocol?: number;
}

/** Whether installing `update` gets us onto a server that speaks
 *  `serverProtocol`. Versions connect only on the same protocol, so a newer
 *  one past the server's is no use either. A feed that does not name the
 *  protocol is taken at its word that the newest version is the one to have. */
export function updateFits(update: UpdateInfo | null, serverProtocol: number): boolean {
  return update !== null && (update.protocol === null || update.protocol === serverProtocol);
}

/**
 * How an update is offered (R4-01, design input 5):
 * - `plain`: it speaks this app's protocol, or the feed does not say: the
 *   toast, and one press installs it;
 * - `protocol`: it speaks another one, so every server this app reaches now
 *   refuses it until that server is updated too. No toast; Settings says so,
 *   and installing takes a second press.
 */
export type UpdateOffer = "none" | "plain" | "protocol";

export function updateOffer(update: UpdateInfo | null): UpdateOffer {
  if (update === null) return "none";
  const ours = update.our_protocol;
  return update.protocol !== null && ours !== undefined && update.protocol !== ours ? "protocol" : "plain";
}

/** The toast for a new update, or null for none (a protocol change waits for
 *  the person in Settings, Updates). */
export function updateToast(update: UpdateInfo | null): string | null {
  return updateOffer(update) === "plain" && update ? `VoIPC ${update.version} is available: Settings, Updates.` : null;
}

/** "a", "a and b", "a, b and c". */
function listed(names: readonly string[]): string {
  return names.length < 2 ? (names[0] ?? "") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** What Settings says about an update on another protocol. `connected`: the
 *  servers this app is connected to now, which all speak its own protocol. */
export function protocolWarning(update: UpdateInfo, connected: readonly string[]): string {
  const head = `VoIPC ${update.version} speaks protocol ${update.protocol}.`;
  const ours = update.our_protocol;
  if (connected.length === 0) {
    return `${head} This VoIPC speaks ${ours}: after updating, you can connect only to servers that run ${update.protocol} too.`;
  }
  const one = connected.length === 1;
  return (
    `${head} ${listed(connected)} ${one ? "runs" : "run"} protocol ${ours}: after updating, you cannot connect to ` +
    `${one ? "it" : "them"} until ${one ? "it is" : "they are"} updated too.`
  );
}
