import { writable } from "svelte/store";
import type { ChannelInfo, UserInfo } from "../types.js";

export const channels = writable<ChannelInfo[]>([]);
export const currentChannelId = writable<number>(0);
export const previewChannelId = writable<number | null>(null);
export const previewUsers = writable<UserInfo[]>([]);
