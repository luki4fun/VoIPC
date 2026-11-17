// What a relay carries now, for its admin's Load view (protocol 25): asked while the tab is
// open (`admin_load`), answered as `admin-load`.

import { scoped } from "./scoped.js";

export interface ShareLoad {
  channel_id: number;
  sharer: string;
  viewers: number;
  cap: number;
  kbps: number;
}

export interface LoadReport {
  online: number;
  max_users: number;
  in_rooms: number;
  lobby: number;
  live_lobby: number;
  shares: ShareLoad[];
  video_kbps: number;
  video_budget_kbps: number;
  rss_mib: number;
  cpu_secs: number;
  udp_dropped: number;
  last_minute: string[];
  warnings: string[];
}

export const adminLoad = scoped<LoadReport | null>(() => null);
