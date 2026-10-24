// Which update the connect dialog may offer for a server that refused us
// (1.0, B6). Pure, for the tests; the stores live in stores/updates.ts.

/** A newer VoIPC the feed offers (updater.rs `UpdateInfo`). */
export interface UpdateInfo {
  version: string;
  notes: string | null;
  /** The protocol it speaks, when the feed says. */
  protocol: number | null;
}

/** Whether installing `update` gets us onto a server that speaks
 *  `serverProtocol`. Versions connect only on the same protocol, so a newer
 *  one past the server's is no use either. A feed that does not name the
 *  protocol is taken at its word that the newest version is the one to have. */
export function updateFits(update: UpdateInfo | null, serverProtocol: number): boolean {
  return update !== null && (update.protocol === null || update.protocol === serverProtocol);
}
