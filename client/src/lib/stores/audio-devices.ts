// The audio devices and the pick of one: what the audio setup and Settings
// both show, with one copy of the loading and the saving (H5-10).

import { writable } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";
import type { AudioDeviceInfo } from "../types.js";
import { inputDevice, outputDevice } from "./settings.js";
import { restartMicTest } from "./mic-test.js";

export const inputDevices = writable<AudioDeviceInfo[]>([]);
export const outputDevices = writable<AudioDeviceInfo[]>([]);

/** Read both lists from the backend. Throws what it could not read. */
export async function loadDevices(): Promise<void> {
  inputDevices.set(await invoke<AudioDeviceInfo[]>("get_input_devices"));
  outputDevices.set(await invoke<AudioDeviceInfo[]>("get_output_devices"));
}

/** What a picker shows when nothing is saved: the system's own default. */
export const defaultDeviceName = (list: AudioDeviceInfo[]): string =>
  list.find((d) => d.is_default)?.name ?? list[0]?.name ?? "";

/** Choose the microphone; a running test moves to it. Throws a refusal. */
export async function pickInput(name: string): Promise<void> {
  inputDevice.set(name);
  await invoke("set_input_device", { deviceName: name });
  await restartMicTest();
}

/** Choose the speakers. Throws a refusal. */
export async function pickOutput(name: string): Promise<void> {
  outputDevice.set(name);
  await invoke("set_output_device", { deviceName: name });
}
