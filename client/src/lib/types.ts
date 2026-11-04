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
  /** Manages every channel (servers with accounts: `voipc:channels`, the
   *  moderator role before 1.7); their pins count anywhere. */
  is_moderator?: boolean;
  /**
   * This user answers a newcomer's request for recent channel chat.
   *
   * The one thing about chat the server is told, and only so a member list can
   * show who asking would reach — it has always seen the requests go past.
   */
  shares_history: boolean;
  /** The relay account they signed in with (16 bytes); absent for a guest,
   *  and never shown behind a pseudonym. */
  account?: number[] | null;
  /** Their groups' badges (1.7), at most three; empty where `account` is. */
  badges?: string[];
}

/** An active ban (admin view). An address ban shows the name it was given
 *  under, never the address. */
export interface BanInfo {
  /** What `admin_unban` lifts. */
  id: number;
  /** An account ban; else an address ban. */
  account: boolean;
  /** The account's name, or the name the user went by when banned. */
  label: string;
  reason: string;
  /** An account's name, "admin token" or "server shell". */
  by: string;
  /** Unix seconds. */
  created_at: number;
  /** Seconds until expiry; null = permanent. */
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
  /** Only the channel's managers — its creator, admins, moderators — may post
   *  here; the server refuses everybody else's messages. Text channels only. */
  announce?: boolean;
  /** A member may post once per this many seconds (0 = off); the channel's
   *  managers are exempt. The server enforces it. */
  slow_mode_secs?: number;
  /** Marked 18+: the client asks for consent before joining or showing it. */
  nsfw?: boolean;
  /** Its stored-message log (`c:<uid>`), on relays that keep one for
   *  accounts; empty or absent where there is none (protocol v11). */
  log?: string;
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
   * The sender's relay account (hex), when they had one. With `id` it names a
   * message across connects, where `user_id` is new every time: what lets a
   * message from the stored log meet its live copy as one message.
   */
  account?: string;
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
   * ends. "notice" = a line of our own in a conversation, shown the same way
   * ("Not delivered — bob left the server"); never sent to anybody. "undecryptable" = ciphertext we could not open, kept on screen but
   * never handed to anyone as history: a placeholder is not what was written,
   * and re-sharing it spreads one member's missing key to everyone who joins
   * after them. "deleted" = a message its writer deleted: a tombstone, never
   * drawn and never re-shared, kept so that a copy of the message offered
   * again (a hand-off, the stored log) finds it and stays out. Anything else
   * (a future attachment type) renders as a placeholder and is never re-shared.
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
  /**
   * The message this one answers, by the `id` its sender minted, and the
   * thread it belongs to (the id of the thread's first message). Both travel
   * inside the end-to-end envelope; only the id, never a quote, so an answer
   * never keeps the text it answers alive past that text's own timer. The
   * message itself is looked up in the same conversation when shown.
   */
  reply_to?: string;
  thread?: string;
  /** The file this message carries (its text is then the caption). */
  file?: FileRef;
  /** Forwarded from another conversation: who wrote it there, and when. */
  fwd?: Forwarded;
  // ── What later events did to it (chat-rules.ts `applyEvent`): this
  //    reader's own record, never handed to anyone with the message ──
  /** When its writer last changed it (ms). Shown as "(edited)". */
  edited_at?: number;
  /** The reactions on it, by emoji, each with who reacted (latest wins). */
  reactions?: Reaction[];
  /** Pinned in its channel by a manager (`on`), or unpinned; latest wins. */
  pin?: { on: boolean; at: number; by: string };
  /** It arrived from a member allowed to call on everybody (mention-rules.ts). */
  power?: boolean;
  /** What a later version kept in this message's archive entry that this one
   *  does not know (JSON): written back on the next save, never read, never
   *  handed to anyone (chat-rules.ts `fromArchived`). */
  extra_kept?: string;
}

/** Where a forwarded message came from (envelope.rs `Forwarded`): the
 *  forwarder's word, shown as a label. */
export interface Forwarded {
  name: string;
  /** When it was written there (ms). */
  at: number;
}

/**
 * Something done to an earlier message of the same conversation, named by id
 * (envelope.rs `ChatEvent`). An edit's new text is the event's `content`.
 */
export type ChatEvent =
  | { kind: "edit"; target: string }
  | { kind: "delete"; target: string }
  | { kind: "react"; target: string; emoji: string; on: boolean }
  | { kind: "pin"; target: string; on: boolean };

/** One emoji on a message, and everyone who put it there or took it off. */
export interface Reaction {
  emoji: string;
  by: Reactor[];
}

export interface Reactor {
  /** Who, as `authorKey` names a writer. */
  key: string;
  /** Their name then, for the chip's list. */
  name: string;
  on: boolean;
  /** When (ms): an older event for the same person and emoji changes nothing. */
  at: number;
}

/**
 * A file's blob as the backends move it: what `send_file` returns and
 * `fetch_file` takes, all of it end to end (the relay sees only `hash`).
 */
export interface FileBlob {
  /** The blob id: SHA-256 of the blob, 64 hex digits. */
  hash: string;
  /** The file's key, 64 hex digits. */
  key: string;
  /** The file's own length, before any deflate. */
  size: number;
  /** The blob holds the file deflated. */
  z: boolean;
}

/**
 * The file a message carries (envelope.rs `FileRef`), checked where it
 * enters (`fileRef` in chat-rules.ts). Only a card believes the rest: what a
 * loaded file is shown as comes from its bytes (`file-sniff.ts`), never `mime`.
 */
export interface FileRef extends FileBlob {
  /** As the sender named it: shown as text, cleaned again to save. */
  name: string;
  mime?: string;
  /** A picture's or video's size in pixels. */
  w?: number;
  h?: number;
  /** Seconds of audio or video. */
  dur?: number;
  /** 16×16 RGB pixels, base64 (1024 characters): drawn as they are. */
  px?: string;
}

/** A conversation as the backends name it for files (files.rs `Conv`). */
export type FileConv = { channel: number } | { direct: number } | { account: string };

/** A relay with accounts, as `Authenticated.accounts` describes it (protocol v11). */
export interface RelayAccounts {
  /** Guests are refused. */
  required: boolean;
  registration: "Open" | "Invite" | "Closed";
  /** Members may keep an encrypted copy of their messages there. */
  cloud: boolean;
  relay_id: number[];
}

/** The account a connection signed in with. */
export interface AccountInfo {
  id: number[];
  name: string;
  /** What it may do now: "*", "voipc:kick", … (scopes.ts) */
  scopes: string[];
  /** It holds a role whose rights wait for a second factor. */
  needs_2fa: boolean;
  totp_enabled: boolean;
}

// ── Server administration (protocol 16) ─────────────────────────────────

export interface AdminUser {
  id: number[];
  name: string;
  totp: boolean;
  /** Unix seconds. */
  created_at: number;
}

/** A group: an account role, and the privileges (scopes) it hands out. */
export interface GroupInfo {
  name: string;
  description: string;
  /** Shown next to members' names; "" for none. */
  badge: string;
  scopes: string[];
  /** `admin` and `user` (every account): never deleted. */
  builtin: boolean;
}

export interface AuditRow {
  event: string;
  actor: string | null;
  detail: string;
  at: number;
}

export interface InviteLinkInfo {
  id: string;
  max_uses: number;
  uses: number;
  expires_at: number | null;
  group: string | null;
}

export interface InviteInfo {
  id: string;
  name: string | null;
  created_by: string | null;
  expires_at: number;
  used_by: string | null;
}

/** Who may see and join a channel, and who may speak there (group names).
 *  Empty means everyone. */
export interface ChannelGate {
  groups: string[];
  speakers: string[];
}

/** `AdminOp` as serde writes it. */
export type AdminOp =
  | { Users: { search: string; offset: number } }
  | { User: { id: number[] } }
  | { Grant: { id: number[]; group: string } }
  | { Revoke: { id: number[]; group: string } }
  | { Reset2fa: { id: number[] } }
  | "Groups"
  | { GroupSave: { create: boolean; group: GroupInfo } }
  | { GroupDelete: { name: string } }
  | { GroupMembers: { name: string; offset: number } }
  | "Invites"
  | { InviteNew: { name: string | null; days: number } }
  | { InviteRevoke: { id: string } }
  | { GateGet: { channel_id: number } }
  | { GateSet: { channel_id: number; gate: ChannelGate } }
  | {
      ChannelSave: {
        id: number | null;
        name: string;
        description: string;
        text: boolean;
        auto_join: boolean;
        category: number | null;
        gate: ChannelGate | null;
      };
    }
  | { ChannelDelete: { id: number } }
  | { CategorySave: { id: number | null; name: string } }
  | { CategoryDelete: { id: number } }
  | { LayoutSet: { categories: number[]; channels: [number, number | null][] } }
  | { WelcomeSet: { channel_id: number | null } }
  | { GroupStyle: { name: string; color: number | null } }
  | { GroupOrder: { names: string[] } }
  | { ProfileReset: { id: number[]; name: boolean; picture: boolean } }
  | { ServerProfileSet: { name: string; description: string } }
  | { ServerIconSet: { image: number[] | null } }
  | "InviteLinks"
  | { InviteLinkNew: { max_uses: number; days: number; group: string | null } }
  | { InviteLinkRevoke: { id: string } };

/** `AdminReply` as serde writes it. */
export type AdminReply =
  | { Users: { search: string; offset: number; total: number; users: AdminUser[] } }
  | { User: { user: AdminUser; groups: string[]; audit: AuditRow[] } }
  | { Groups: { groups: GroupInfo[] } }
  | { Members: { name: string; offset: number; total: number; users: AdminUser[] } }
  | { Invites: { invites: InviteInfo[] } }
  | { InviteCode: { code: string } }
  | { InviteLinks: { links: InviteLinkInfo[] } }
  | { InviteLinkCode: { code: string } }
  | { Gate: { channel_id: number; gate: ChannelGate; groups: string[] } }
  | { ChannelDone: { channel_id: number | null } }
  | "StepUp";

/** A category of channels (protocol 18). */
export interface ChannelCategory {
  id: number;
  name: string;
}

/** Where a channel sits (`ServerMessage::ChannelLayout`). */
export interface ChannelPlace {
  channel_id: number;
  category: number | null;
  /** Made in the app, so it can be renamed and deleted there. */
  kept: boolean;
  /** Opened the first time someone comes to this server. */
  welcome: boolean;
}
