// Voice packet loss over a rolling two-second window.
//
// From the jitter buffer's conceal counts, which is the only number that says
// "the call sounds bad" rather than "the network is fine". Lived in StatusBar
// until the Discord layout needed the same figure in its voice panel; polling
// it twice would have been two intervals asking the same backend the same
// question and computing two different answers from interleaved samples.

import { derived, writable, type Readable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

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

connectionState.subscribe(($state) => {
  if ($state === "connected") {
    if (interval) return;
    // Counters are per connection; a reconnect restarts them, and carrying the
    // old totals over would report one enormous loss spike on the first tick.
    lastPlayed = 0;
    lastLost = 0;
    interval = setInterval(() => {
      invoke<[number, number]>("get_voice_stats")
        .then(([played, lost]) => {
          const dPlayed = played - lastPlayed;
          const dLost = lost - lastLost;
          lastPlayed = played;
          lastLost = lost;
          const total = dPlayed + dLost;
          lossPercent.set(total > 0 ? Math.round((dLost / total) * 100) : 0);
        })
        .catch(() => {});
    }, POLL_MS);
  } else if (interval) {
    clearInterval(interval);
    interval = null;
    lossPercent.set(0);
  }
});
