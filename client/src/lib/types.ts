import type { ProximityMode } from "./spatial";

export type { ProximityMode };

export interface UserInfo {
  user_id: number;
  username: string;
  channel_id: number;
  is_muted: boolean;
  is_deafened: boolean;
  is_screen_sharing: boolean;
  /** Logged in with the server's admin token. */
  is_admin: boolean;
}

/** An active IP ban (admin view). */
export interface BanInfo {
  ip: string;
  /** Seconds until expiry; null = until the server restarts. */
  expires_in_secs: number | null;
}

export interface ChannelInfo {
  channel_id: number;
  name: string;
  description: string;
  max_users: number;
  user_count: number;
  has_password: boolean;
  created_by: number | null;
  /** Positional audio mode of this channel. */
  proximity: ProximityMode;
}

export interface ConnectionInfo {
  user_id: number;
  session_id: number;
}

export interface AudioDeviceInfo {
  name: string;
  is_default: boolean;
}

export interface ChatMessage {
  user_id: number;
  username: string;
  content: string;
  timestamp: number;
  /**
   * Absent/"text" = a normal message. "history-marker" = the divider inserted
   * where a member's shared history ends. Anything else (a future attachment
   * type) renders as a placeholder and is never re-shared.
   */
  kind?: string;
}
