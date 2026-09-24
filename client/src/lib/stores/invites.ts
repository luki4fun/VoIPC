import { writable } from "svelte/store";

export interface PendingInvite {
  /** The server that sent it: accepting and declining go back there. */
  server: string;
  channel_id: number;
  channel_name: string;
  invited_by: string;
}

export const pendingInvites = writable<PendingInvite[]>([]);
