// Voice packet loss over a rolling two-second window.
//
// From the jitter buffer's conceal counts, which is the only number that says
// "the call sounds bad" rather than "the network is fine". Lived in StatusBar
// until the modern layout needed the same figure in its voice panel; polling
// it twice would have been two intervals asking the same backend the same
// question and computing two different answers from interleaved samples.

import { derived, writable, type Readable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { voiceServer } from "./channels.js";
import { connectionState } from "./connection.js";

const POLL_MS = 2000;

export const lossPercent = writable(0);

/** Buckets the bars colour themselves by. */
export const quality: Readable<"good" | "warn" | "bad"> = derived(lossPercent, ($loss) =>
  $loss >= 5 ? "bad" : $loss >= 1 ? "warn" : "good",
);

let interval: ReturnType<typeof setInterval> | null = null;
let lastPlayed = 0;
let lastLost = 0;

/** The server carrying voice, while it is connected; null otherwise. The loss
 *  is the call's, wherever the user is looking. */
const voiceConnection: Readable<string | null> = derived(
  [voiceServer, connectionState.at(voiceServer)],
  ([$server, $state]) => ($state === "connected" ? $server : null),
);

voiceConnection.subscribe(($server) => {
  if (interval) {
    clearInterval(interval);
    interval = null;
    lossPercent.set(0);
  }
  if ($server === null) return;
  // Counters are per connection; a reconnect or a move to another server
  // starts from other totals, and carrying the old ones over would report one
  // enormous loss spike. The first tick only takes the baseline.
  let primed = false;
  interval = setInterval(() => {
    invoke<[number, number]>("get_voice_stats")
      .then(([played, lost]) => {
        const dPlayed = played - lastPlayed;
        const dLost = lost - lastLost;
        lastPlayed = played;
        lastLost = lost;
        if (!primed) {
          primed = true;
          return;
        }
        const total = dPlayed + dLost;
        lossPercent.set(total > 0 ? Math.round((dLost / total) * 100) : 0);
      })
      .catch(() => {});
  }, POLL_MS);
});
