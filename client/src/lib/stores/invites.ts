import { writable } from "svelte/store";

export interface PendingInvite {
  channel_id: number;
  channel_name: string;
  invited_by: string;
}

export const pendingInvites = writable<PendingInvite[]>([]);
