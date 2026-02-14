import { writable } from "svelte/store";

export type ConnectionState = "disconnected" | "connecting" | "connected" | "reconnecting";

export const connectionState = writable<ConnectionState>("disconnected");
export const serverAddress = writable<string>("");
export const username = writable<string>("");
export const userId = writable<number>(0);
export const sessionId = writable<number>(0);
export const latency = writable<number>(0);
export const isMuted = writable<boolean>(false);
export const isDeafened = writable<boolean>(false);
export const isTransmitting = writable<boolean>(false);
export const acceptSelfSigned = writable<boolean>(false);
