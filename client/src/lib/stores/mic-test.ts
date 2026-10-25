// The microphone test: one in the backend, so one writer here (H5-10).
//
// Audio setup, Settings and the mixer each ran their own copy of it. Starting
// and stopping the test in one view stopped the backend's while another still
// showed "testing" over a frozen meter. Every view now reads these stores and
// calls these functions; whoever stops it, it is stopped for all of them.

import { get, writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { addNotification } from "./notifications.js";

/** The test is running. */
export const micTesting = writable(false);
/** Its level in dBFS; -100 while it is off. */
export const micTestLevel = writable(-100);
/** Why the last test ended early, for a view that says it in place. */
export const micTestError = writable<string | null>(null);

let unlisten: Array<() => void> = [];
let starting: Promise<void> | null = null;
/** Bumped by every stop, so a start still on its way knows it was cancelled. */
let generation = 0;
/** What the running test was asked for, so a device change can reopen it. */
let monitorOn = false;

/** Start the test, playing the microphone back when `monitor` is set. */
export function startMicTest(monitor: boolean): Promise<void> {
  if (get(micTesting)) return Promise.resolve();
  if (starting) return starting;
  const gen = ++generation;
  monitorOn = monitor;
  micTestError.set(null);
  starting = (async () => {
    try {
      unlisten.push(await listen<{ db: number }>("mic-test-level", (e) => micTestLevel.set(e.payload.db)));
      unlisten.push(
        await listen<{ error: string }>("mic-test-error", (e) => {
          fail(e.payload.error);
          void stopMicTest();
        }),
      );
      await invoke("start_mic_test", { monitor });
      // Stopped while it was starting (a view closing): the stop missed it
      if (gen !== generation) return void (await invoke("stop_mic_test").catch(() => {}));
      micTesting.set(true);
    } catch (e) {
      fail(String(e));
      await stopMicTest();
    } finally {
      starting = null;
    }
  })();
  return starting;
}

export async function stopMicTest(): Promise<void> {
  generation++;
  micTesting.set(false);
  micTestLevel.set(-100);
  unlisten.forEach((off) => off());
  unlisten = [];
  await invoke("stop_mic_test").catch(() => {});
}

/** Reopen a running test, on the device just chosen. */
export async function restartMicTest(): Promise<void> {
  if (!get(micTesting)) return;
  await stopMicTest();
  await startMicTest(monitorOn);
}

function fail(error: string): void {
  micTestError.set(error);
  addNotification(`Microphone test failed: ${error}`, "error");
}
