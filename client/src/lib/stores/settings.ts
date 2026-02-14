import { writable } from "svelte/store";

export const inputDevice = writable<string>("");
export const outputDevice = writable<string>("");
export const volume = writable<number>(1.0);
export const pttKey = writable<string>("Space");
