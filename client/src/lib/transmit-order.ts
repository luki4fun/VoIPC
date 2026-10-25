/**
 * Opens and closes the microphone in the order it was asked for.
 *
 * Opening takes a while — the device, a browser's permission prompt — and the
 * microphone only counts as open once it is. A push-to-talk key released in
 * that time used to find nothing to close, the open landed afterwards, and the
 * mic stayed on with no key held. Here a close asked for during an open is
 * carried out the moment the open finishes.
 *
 * `open` and `close` are the backend calls; `close` is expected to do nothing
 * when nothing is open.
 */
export function transmitOrder(open: () => Promise<void>, close: () => Promise<void>) {
  let wanted = false;
  let opening: Promise<void> | null = null;

  async function start(): Promise<void> {
    wanted = true;
    if (opening) return opening;
    opening = (async () => {
      try {
        await open();
      } finally {
        opening = null;
      }
      // Released while it was opening
      if (!wanted) await stop();
    })();
    return opening;
  }

  async function stop(): Promise<void> {
    wanted = false;
    // The open in flight sees `wanted` and closes behind itself
    if (opening) return;
    await close();
  }

  return { start, stop };
}
