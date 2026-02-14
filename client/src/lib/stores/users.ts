import { writable } from "svelte/store";
import type { UserInfo } from "../types.js";

export const users = writable<UserInfo[]>([]);
export const speakingUsers = writable<Set<number>>(new Set());
