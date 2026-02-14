export interface UserInfo {
  user_id: number;
  username: string;
  channel_id: number;
  is_muted: boolean;
  is_deafened: boolean;
  is_screen_sharing: boolean;
}

export interface ChannelInfo {
  channel_id: number;
  name: string;
  description: string;
  max_users: number;
  user_count: number;
  has_password: boolean;
  created_by: number | null;
}

export interface ConnectionInfo {
  user_id: number;
  session_id: number;
  udp_port: number;
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
}
