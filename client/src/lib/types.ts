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
  /**
   * This user answers a newcomer's request for recent channel chat.
   *
   * The one thing about chat the server is told, and only so a member list can
   * show who asking would reach — it has always seen the requests go past.
   */
  shares_history: boolean;
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
  /** Kept out of the sidebar for non-admins; joining by id still works. */
  hidden: boolean;
  /** Members see each other under random pseudonyms (admins see real names). */
  anonymous: boolean;
  /** Whether screen sharing is allowed here. */
  screen_share: boolean;
  /** Non-admins see only whoever is speaking, not the member list. */
  hide_members: boolean;
  /**
   * The server forwards each voice only to whoever should hear it, instead of
   * to every member. Off everywhere by default, and the only state in which
   * the server is told anything about who hears whom — so a channel says it,
   * and the people in it are told when they arrive.
   */
  routed: boolean;
  /**
   * A text channel: joining it is a subscription, so several can be open at
   * once and none of them costs you the voice channel you stand in.
   */
  text: boolean;
  /** Clients join this text channel on connect unless the user left it. */
  auto_join: boolean;
  /**
   * Seconds a message written here is meant to live; 0 is no timer.
   *
   * The server neither stores chat nor deletes it — this is what the channel
   * tells its members. Each client stamps it on what it sends and applies it to
   * what it keeps, taking the shorter of it and what a message itself claims,
   * so a relay that raises the number cannot make a copy outlive its sender's
   * intent.
   */
  message_ttl_secs: number;
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
   * Minted by the sender inside the end-to-end envelope, so every copy of a
   * message carries the same one — which is what lets history offered by
   * several members be merged without duplicates. Absent for anything stored
   * before this release, and for the dividers we make ourselves.
   */
  id?: string;
  /**
   * Absent/"text" = a normal message we received first-hand.
   *
   * "shared" = a message another member handed us as history. There is nothing
   * to check it against — identities are per-connection and never stored, so
   * nothing signs an archived message — which makes its author and its text
   * that member's word, not the author's. It is shown as second-hand and
   * relayed onward as second-hand: once hearsay, always hearsay, so a
   * fabrication can never launder itself back into first-hand.
   *
   * "history-marker" = the divider inserted where a member's shared history
   * ends. "undecryptable" = ciphertext we could not open, kept on screen but
   * never handed to anyone as history: a placeholder is not what was written,
   * and re-sharing it spreads one member's missing key to everyone who joins
   * after them. Anything else (a future attachment type) renders as a
   * placeholder and is never re-shared.
   */
  kind?: string;
  /**
   * When this message is to be deleted, as a Unix millisecond timestamp.
   * Absent for a message with no destruction timer.
   *
   * An absolute moment rather than the timer it came from, worked out once when
   * the message arrives: every copy of a message computes the same instant from
   * the same timestamp, so a conversation shared with three people disappears
   * from all four archives together. A timer a channel sets later does not
   * reach back into what is already here, and a member re-sharing a message can
   * only ever bring its deadline forward — see `expiryFor` in chat-rules.ts.
   */
  expires_at?: number;
}
