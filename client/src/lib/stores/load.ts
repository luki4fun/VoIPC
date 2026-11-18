// What a relay carries now, for its admin's Load view (protocol 25; its media edges since
// 26, and its group keys): asked while the tab is open (`admin_load`), answered as `admin-load`.

import { scoped } from "./scoped.js";

export interface ShareLoad {
  channel_id: number;
  sharer: string;
  /** Everyone watching, those on edges included. */
  viewers: number;
  /** `[media] share_viewers`: the most the relay serves itself. */
  cap: number;
  kbps: number;
  /** Of `viewers`, how many an edge serves; 0 from a relay at 25. */
  on_edges: number;
}

/** One media edge of the relay's `[pool]`, linked or not (protocol 26). */
export interface EdgeLoad {
  name: string;
  /** Where viewers reach it, `host:port`. */
  address: string;
  online: boolean;
  pool_version: number;
  /** What the relay assigned to it, against the edge's own limits. */
  viewers: number;
  max_viewers: number;
  shares: number;
  max_shares: number;
  kbps: number;
  budget_kbps: number;
  /** What the edge last reported, `report_age_secs` ago. */
  egress_kbps: number;
  frames_dropped: number;
  cpu_secs: number;
  rss_mib: number;
  report_age_secs: number;
}

/** One group with its key (Track C): at 1000 seats or with a warning, 50 at most. */
export interface GroupLoad {
  channel_id: number;
  /** `gk::group_kind`: 0 text, 1 voice. */
  kind: number;
  seats: number;
  keyholders: number;
  keyholders_online: number;
  /** How long ago its head moved. */
  last_commit_secs: number;
  joins_waiting: number;
  exits_waiting: number;
  missed_deadlines: number;
  mem_bytes: number;
  db_bytes: number;
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
  /** Empty without a pool, and from a relay at 25: then the tab shows no Edges table. */
  edges: EdgeLoad[];
  /** Empty with the group key off: then the tab shows no Groups table. */
  groups: GroupLoad[];
}

export const adminLoad = scoped<LoadReport | null>(() => null);
