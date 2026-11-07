//! A note on `#[serde(default)]` in the wire types: it only helps JSON
//! callers (the browser builds messages as JS objects and may leave a field
//! out). On the wire, postcard is positional, so it never lets an older and a
//! newer layout read each other: every layout change is a protocol bump, which
//! `tests/golden.rs` enforces.

use serde::{Deserialize, Serialize};

/// Unique user identifier assigned by the server upon connection.
pub type UserId = u32;

/// Channel identifier. Channel 0 is always the root/lobby.
pub type ChannelId = u32;

/// Opaque session token issued after authentication,
/// used to correlate UDP packets to a TCP session.
pub type SessionId = u32;

/// Sequence number for voice packets, monotonically increasing per sender.
pub type SequenceNumber = u32;

/// Information about a connected user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: UserId,
    pub username: String,
    pub channel_id: ChannelId,
    pub is_muted: bool,
    #[serde(default)]
    pub is_deafened: bool,
    #[serde(default)]
    pub is_screen_sharing: bool,
    /// Logged in with the server's admin token.
    #[serde(default)]
    pub is_admin: bool,
    /// This user answers a newcomer's request for recent channel chat
    /// (protocol v9). The one thing about chat the server is told, and only so
    /// that a member list can say who a history request would reach — the
    /// server already sees every request and every reply go past.
    #[serde(default)]
    pub shares_history: bool,
    /// The relay account this user signed in with (protocol v11), or `None`
    /// for a guest. Peers show a verified mark for it, and key what they
    /// remember about a person (an identity, a message id) by it instead of by
    /// the user id, which is new on every connect.
    #[serde(default)]
    pub account: Option<[u8; 16]>,
    /// Manages every channel (protocol v16: holds `voipc:channels`, as the
    /// moderator role did before): their pins count anywhere.
    #[serde(default)]
    pub is_moderator: bool,
    /// The badges of the groups this account counts in (protocol v16), at
    /// most `MAX_BADGES`. Empty wherever `account` is withheld.
    #[serde(default)]
    pub badges: Vec<String>,
}

/// An account holding a privilege (`ServerMessage::ChatMods`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMod {
    pub account: [u8; 16],
    /// Holds `voipc:hide`.
    pub hide: bool,
    /// Holds `*`: alone acts on other holders.
    pub admin: bool,
}

/// Badges a member shows at most (`UserInfo::badges`).
pub const MAX_BADGES: usize = 3;

// ── Accounts (protocol v11) ──────────────────────────────────────────────

/// Who may make an account on a relay that has them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Registration {
    /// Anyone, behind a proof of work the client solves.
    Open,
    /// With a code from an admin, which may be bound to one name.
    Invite,
    /// Only with a code an admin made for that name.
    Closed,
}

/// What a relay with accounts tells every client in `Authenticated`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAccounts {
    /// Guests are refused; everybody signs in.
    pub required: bool,
    pub registration: Registration,
    /// Members may keep an encrypted copy of their messages here.
    pub cloud: bool,
    /// The relay's own id: the client derives its keys from it, so they
    /// survive the relay moving to another address.
    pub relay_id: [u8; 16],
}

/// What a relay with a file cache tells every client in `Authenticated`
/// (protocol v13). `None` there means the relay keeps no files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLimits {
    /// Largest blob it takes, in bytes: the sealed file, not the file.
    pub max_bytes: u64,
    /// How the apps keep a moving picture posted here (protocol v14): fitted
    /// into this many pixels a side, and at most this many MiB of its frames,
    /// past which every other frame goes. An app holds both to
    /// `ANIMATION_SIDE` and `ANIMATION_MB`, whatever a relay says.
    pub animation_side: u32,
    pub animation_mb: u32,
}

/// What `FileLimits.animation_side` may be, and its default.
pub const ANIMATION_SIDE: std::ops::RangeInclusive<u32> = 256..=2560;
pub const ANIMATION_SIDE_DEFAULT: u32 = 1024;
/// What `FileLimits.animation_mb` may be, and its default.
pub const ANIMATION_MB: std::ops::RangeInclusive<u32> = 16..=512;
pub const ANIMATION_MB_DEFAULT: u32 = 128;

impl FileLimits {
    /// `animation_side` and `animation_mb` as an app keeps them: a relay's
    /// numbers held to their ranges.
    pub fn animation(&self) -> (u32, u32) {
        (
            self.animation_side
                .clamp(*ANIMATION_SIDE.start(), *ANIMATION_SIDE.end()),
            self.animation_mb
                .clamp(*ANIMATION_MB.start(), *ANIMATION_MB.end()),
        )
    }
}

/// An emote or sticker of the server (protocol v14). Admins add them; every
/// member gets the list and fetches each file by its hash. They are the
/// server's own, like its channel names: the relay holds the files as they
/// came, readable, and never decodes them. Members' clients show only what
/// their own sanitizer writes from one (crates/voipc-media).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Emote {
    /// `:name:` in a message: `^[a-z0-9_]{2,30}$`, one per server.
    pub name: String,
    /// SHA-256 of the file.
    pub hash: [u8; 32],
    /// A sticker, sent as a message of its own; else an emote, inline.
    pub sticker: bool,
    /// What the picker groups it under; empty for none. A label an admin
    /// chose, at most `EMOTE_PACK_MAX` characters.
    pub pack: String,
    /// The file's size in bytes (protocol v15): what the relay keeps of it.
    pub len: u32,
    /// Its shape as the adding admin's app made it, fitted into the emote or
    /// sticker box; 0 where unknown. Only for the room a reader keeps for it
    /// before it is drawn: a reader holds it to the box too.
    pub w: u16,
    pub h: u16,
}

/// The box an emote is fitted into, and a sticker (voipc-media's profiles).
pub const EMOTE_BOX: u16 = 128;
pub const STICKER_BOX: u16 = 320;

/// The longest emote name: `:name:` fits a reaction (`MAX_EMOJI_BYTES`, 32).
pub const EMOTE_NAME_MAX: usize = 30;
/// The longest pack label: this many characters, and twice as many bytes.
pub const EMOTE_PACK_MAX: usize = 32;
/// The most emotes and stickers a server has: the list goes in one message,
/// at most about 140 bytes each, under `MAX_MSG_SIZE` (golden.rs checks it).
pub const MAX_EMOTES: usize = 400;

/// What an emote may be called, on the relay and in every client.
pub fn valid_emote_name(s: &str) -> bool {
    (2..=EMOTE_NAME_MAX).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// A pack label a person may see: one line, no control, invisible or
/// direction characters, at most `EMOTE_PACK_MAX` characters.
pub fn valid_emote_pack(s: &str) -> bool {
    s.chars().count() <= EMOTE_PACK_MAX
        && s.len() <= 2 * EMOTE_PACK_MAX
        && s.trim() == s
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{200B}'..='\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
        })
}

/// A secret that must never reach a log: `Debug` prints only that it is one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(…)")
    }
}

/// What a relay with emotes tells every client in `Authenticated` (protocol
/// v14). `None` there means it has none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmoteAccess {
    /// `Authorization: Bearer <token>` for `GET /e/v1/<hash>`: this
    /// connection's, and good while it lasts.
    pub token: Secret,
    /// The largest emote and sticker file an admin may add, in bytes.
    pub max_emote_bytes: u32,
    pub max_sticker_bytes: u32,
    /// All of them together, in bytes, and how many there may be (v15):
    /// what an admin's app shows as used of what.
    pub max_total_bytes: u64,
    pub max_items: u32,
}

/// The conversation a file was posted in (protocol v13), named as the client
/// sending the message sees it. The relay checks every upload and fetch
/// against it, and asks that conversation's members when a blob has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileConv {
    /// A text channel.
    Channel(ChannelId),
    /// A direct conversation with this user, who is online.
    Direct(UserId),
    /// A kept direct conversation with this account, which may be away.
    Account([u8; 16]),
}

/// How a client means to sign in, in `Authenticate.account`. The account name
/// is `Authenticate.username`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountStart {
    /// With the password (the secret derived from it).
    Login,
    /// A new account; `invite` is the code from an invite link.
    Register { invite: Option<String> },
    /// With the key this device was given at an earlier sign-in.
    DeviceKey { device_id: Vec<u8> },
    /// A forgotten password, set anew with the recovery key (1.0): the
    /// account proves itself with its identity key, which only the vault's
    /// recovery slot opens. It ends in `AuthStep::ResetDone`, not a sign-in.
    Reset,
    /// Which providers this relay signs in with (protocol v17). Answered with
    /// `AuthStep::Providers`; the connection ends there, no account involved.
    Providers,
    /// Sign in with a provider (protocol v17). Answered with
    /// `AuthStep::OpenBrowser`; the connection ends there, so that an app the
    /// system suspends while the browser is open loses nothing. No name yet:
    /// the provider's answer decides the account.
    Provider { kind: ProviderKind },
    /// Back from the browser with `AuthStep::OpenBrowser`'s ticket.
    ProviderResume { ticket: Vec<u8> },
    /// Whether the browser is through (`AuthStep::ProviderReady`, or
    /// `ProviderPending`), without spending the ticket; the connection ends there.
    ProviderStatus { ticket: Vec<u8> },
    /// `ProviderResume` from someone holding an invite code or link (protocol v18): a
    /// person nobody knows may then make an account, where sign-up alone would not let them.
    ProviderResumeInvited { ticket: Vec<u8>, invite: String },
}

/// Who can vouch for an account at sign-in. Never for its vault: the relay sees
/// all a provider says, so nothing of that may open anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderKind {
    Discord,
    Google,
    Facebook,
}

/// How a member chose to be shown (`ServerMessage::Profiles`; protocol v18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub account: [u8; 16],
    /// Shown beside the `@name`, never instead of it.
    pub name: Option<String>,
    /// `ClientMessage::ProfilePictureGet` fetches it.
    pub picture: Option<[u8; 32]>,
}

/// A reusable invite link (protocol v18). Its code was shown once and is not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteLinkInfo {
    /// Names it for `AdminOp::InviteLinkRevoke`; not the code.
    pub id: String,
    pub max_uses: u32,
    pub uses: u32,
    /// Unix seconds; `None`: it does not run out by time.
    pub expires_at: Option<i64>,
    /// The group a new account starts in.
    pub group: Option<String>,
}

/// Characters of a server's name (`ServerMessage::ServerProfile`).
pub const MAX_SERVER_NAME_CHARS: usize = 32;
/// Characters of a server's description.
pub const MAX_SERVER_DESCRIPTION_CHARS: usize = 256;

/// Characters of a display name.
pub const MAX_DISPLAY_NAME_CHARS: usize = 32;
/// Bytes of a profile picture, as it is stored.
pub const MAX_PROFILE_PICTURE: usize = 32 * 1024;
/// Accounts asked about in one `ClientMessage::ProfilesGet`.
pub const MAX_PROFILES_ASKED: usize = 64;

/// How a badged group shows (`ServerMessage::GroupStyles`; protocol v18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStyle {
    pub badge: String,
    /// `0xRRGGBB`. A number, so no client ever has a relay's string in its CSS.
    pub color: Option<u32>,
    /// Its people stand under it in the member list. Off, the badge is only a badge.
    pub section: bool,
}

/// A category of channels (protocol v18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCategory {
    pub id: u32,
    pub name: String,
}

/// Where a channel sits (`ServerMessage::ChannelLayout`; protocol v18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPlace {
    pub channel_id: ChannelId,
    pub category: Option<u32>,
    /// Made in the app, so it can be renamed and deleted there.
    pub kept: bool,
    /// Opened the first time someone comes to this server.
    pub welcome: bool,
}

/// A provider linked to an account, as the account panel lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedProvider {
    pub kind: ProviderKind,
    /// What the provider calls the person.
    pub name: String,
}

/// The sign-up proof of work: an ALTCHA challenge (JSON) and the relay's
/// signed timestamp, both handed back with the solution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    pub altcha: String,
    pub ts: String,
}

/// One item of the account's vault as the relay keeps it: ciphertext the
/// client made, under a key the relay never sees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBlob {
    pub k: String,
    pub v: Vec<u8>,
    /// Compare-and-set version; 0 = new.
    pub version: i64,
}

/// The signed-in account, in `Authenticated` and after it changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub id: [u8; 16],
    pub name: String,
    /// What the account may do right now (`*`, `voipc:kick`, …).
    pub scopes: Vec<String>,
    /// It holds a role whose rights wait for a second factor: the client
    /// asks the user to set one up.
    pub needs_2fa: bool,
    pub totp_enabled: bool,
}

/// The privilege to share history with newcomers, once its holder turns the switch on.
pub const SHARE_HISTORY: &str = "voipc:share_history";
/// The protocol that brought it: a relay before this has no such privilege to give.
pub const SHARE_HISTORY_SINCE: u32 = 21;
/// The protocol that brought the live path for text channels: an app asks for it at once
/// on a relay at this or later, and runs the old key paths on anything older.
pub const LIVE_PATH_SINCE: u32 = 21;
/// The protocol that brought chains and buckets for a channel's kept messages: older relays
/// keep theirs on a writer's epochs, as direct conversations do everywhere.
pub const KEPT_CHAINS_SINCE: u32 = 21;
/// The protocol that brought paged pins: `item.pins` says which pages there are, and the
/// pages `pins.0` up to `PIN_PAGES` lie outside the sign-in frame. Older relays keep one item.
pub const VAULT_PAGES_SINCE: u32 = 21;
pub const PIN_PAGES: u16 = 56;

/// Whether this connection's switch counts here. No accounts, or a relay too old to
/// have the privilege: yes. Otherwise an account holding it. `scopes`: None for a guest.
pub fn may_share_history(proto: u32, has_accounts: bool, scopes: Option<&[String]>) -> bool {
    proto < SHARE_HISTORY_SINCE
        || !has_accounts
        || scopes.is_some_and(|held| {
            held.iter()
                .any(|s| s == "*" || s == "voipc:*" || s == SHARE_HISTORY)
        })
}

// ── Server administration (protocol v16) ────────────────────────────────

/// An account as the admin pages list it: no address, no e-mail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: [u8; 16],
    pub name: String,
    pub totp: bool,
    /// Unix seconds.
    pub created_at: i64,
}

/// A group (an account role) and the privileges (scopes) it hands out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// 2 to 32 of a-z, 0-9, `_` and `-`; never renamed.
    pub name: String,
    pub description: String,
    /// Shown next to members' names; empty for none.
    pub badge: String,
    /// `*`, `voipc:kick`, `users:admin`, …
    pub scopes: Vec<String>,
    /// `admin` and `user` (every account) are built in: never deleted.
    pub builtin: bool,
}

/// One line of an account's history, for the admin pages. Never the address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRow {
    /// `role_grant`, `totp_reset`, `register`, …
    pub event: String,
    /// The name of the account that did it; `None` for the account itself
    /// or the server's shell.
    pub actor: Option<String>,
    pub detail: String,
    pub at: i64,
}

/// One line of the moderation log. Names are as they were then, and as anyone
/// but an admin saw them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModRow {
    pub id: i64,
    /// Unix seconds.
    pub at: i64,
    /// `kick`, `ban`, `unban`, `channel_kick`, `remove_posts`, `hide`, ...
    pub action: String,
    pub actor: String,
    pub target: String,
    /// None: server-wide, or a channel this reader cannot see.
    pub channel: Option<String>,
    pub reason: String,
    pub detail: String,
    /// The actor's app said so; the relay could not see it.
    pub advisory: bool,
}

/// Whose posts this server says it removed (`ServerMessage::PostsHidden`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostsMark {
    /// None: a guest, or someone known here only by a pseudonym.
    pub account: Option<[u8; 16]>,
    pub name: String,
    /// Message timestamps in Unix ms, not seconds.
    pub since_ms: u64,
    pub before_ms: u64,
    pub by: String,
}

/// People one `ServerMessage::ReportTakers` names at most.
pub const MAX_REPORT_TAKERS: usize = 5;

/// Someone who takes a report of a message (protocol v19). Never someone standing
/// under a pseudonym: this ties a user id to a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportTaker {
    /// Here now: a report goes to this id. None: away, a sealed copy waits for `account`.
    pub user_id: Option<UserId>,
    /// None: the admin token, with no account.
    pub account: Option<[u8; 16]>,
    pub name: String,
}

/// Who may not speak for now (protocol v19). No name and no channel: an id says
/// nothing a roster did not, under a pseudonym too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restriction {
    pub user_id: UserId,
    /// No voice, no screen share.
    pub voice: bool,
    /// No posts (reactions, pins, edits, deletes included), pokes, invites, new
    /// channels, display name or picture.
    pub text: bool,
    /// No direct messages. The new-member wait sets this; a moderator's
    /// restriction does not.
    pub direct: bool,
    /// Seconds until this row next changes, by the relay's clock. None: until
    /// someone lifts it.
    pub expires_in_secs: Option<u32>,
    /// An account's name or "admin token". Empty: only the new-member wait applies.
    pub by: String,
    /// Told to the member and to holders of `voipc:restrict`; empty for everyone else.
    pub reason: String,
}

// ── The move from Discord (protocol v20) ────────────────────────────────

/// A frame of an import is built under this, and checked: `encode_client_msg` refuses one
/// past the limit, which would lose that frame, and `try_decode_frame` ends the connection.
pub const IMPORT_FRAME_BYTES: usize = 48 * 1024;
/// The most a message's text may be: Discord's 4,000 characters at four bytes each.
pub const IMPORT_BODY_BYTES: usize = 16 * 1024;
/// Categories, threads, members or bans one frame may carry.
pub const IMPORT_FRAME_ROWS: usize = 200;
/// Channels one frame may carry: each makes the relay write and tell people.
pub const IMPORT_CHANNEL_ROWS: usize = 32;
/// Messages one frame may carry: one page of Discord's.
pub const IMPORT_MESSAGE_ROWS: usize = 100;

/// What a run of the importer takes. A channel's own choices stay on the importer's
/// machine: nothing about one left out reaches the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportOptions {
    pub channels: bool,
    pub roles: bool,
    pub permissions: bool,
    pub members: bool,
    pub bans: bool,
    pub emotes: bool,
    pub messages: bool,
    pub threads: bool,
    pub pins: bool,
    pub reactions: bool,
    pub anonymise: bool,
    /// The operator ticked what copying members' messages means.
    pub acknowledged: bool,
}

/// What the dry-run needs of this relay (`AdminReply::ImportFacts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFacts {
    /// SQLite: the relay copies the database itself before a run.
    pub backup_here: bool,
    pub db_bytes: Option<u64>,
    pub max_users: u32,
    pub online: u32,
    pub registration: Registration,
    pub discord_sign_in: bool,
    pub public_url: String,
    pub takes_guests: bool,
    pub accounts: u32,
    pub channel_list_bytes: u32,
    pub channel_list_limit: u32,
    pub categories: u32,
    pub max_categories: u32,
    pub emotes: u32,
    /// A run some other live session is on.
    pub running: Option<i64>,
    /// A run no one finished: its id and guild, in decimal.
    pub unfinished: Option<(i64, String)>,
    /// `cloud = true`: this relay may keep messages at all.
    pub cloud: bool,
    /// Of the newest run not undone: what a delta starts from.
    pub last_options: Option<ImportOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCategory {
    pub dc_id: u64,
    pub name: String,
}

/// Who a channel takes, as the importer worked it out. No way to say "empty means
/// open": `Roles` of nothing the relay knows reads as `Closed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportGate {
    Open,
    Closed,
    /// By Discord's role ids: the relay finds its own groups, so a client cannot name one.
    Roles(Vec<u64>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportChannel {
    pub dc_id: u64,
    pub name: String,
    pub description: String,
    pub text: bool,
    pub category: Option<u64>,
    pub max_users: u32,
    pub slow_mode_secs: u32,
    pub nsfw: bool,
    pub announce: bool,
    pub screen_share: bool,
    pub see: ImportGate,
    pub speak: ImportGate,
}

/// What a thread's opening row says once someone took it back: there is a thread here, and
/// the others' replies are in it. Never the title.
pub const THREAD_TAKEN_BACK: &str = "Thread";

/// A thread: its name and count on a root row of its parent, in the archive. Private
/// threads never come.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportThread {
    pub id: u64,
    pub parent: u64,
    /// Who named it, which is whose wish reaches its name. None: anonymised on the importer,
    /// or Discord does not say.
    pub owner: Option<u64>,
    pub name: String,
    pub replies: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReaction {
    pub emoji: String,
    pub count: u32,
}

/// The name of a file a message had, for a later backfill. Never its address: a signed
/// URL runs out. Never served to readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportAttachment {
    pub id: u64,
    pub name: String,
    pub bytes: u64,
    pub mime: String,
}

/// One message read from Discord. No time: the relay takes it from the id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportMessage {
    pub id: u64,
    /// None: anonymised on the importer, or a webhook's.
    pub author: Option<u64>,
    pub author_name: String,
    /// At most `IMPORT_BODY_BYTES`.
    pub body: String,
    pub reply_to: Option<u64>,
    pub pinned: bool,
    pub reactions: Vec<ImportReaction>,
    pub attachments: Vec<ImportAttachment>,
}

/// What someone said about their rows (`AdminOp::ArchiveWishes`). `channel` 0: every channel.
/// `low..=high`: Discord ids. Without `erase`, hidden from all but its author.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveWish {
    pub author: u64,
    pub channel: u64,
    pub low: u64,
    pub high: u64,
    pub erase: bool,
}

/// What `ImportUndo` of a run would take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportUndoCounts {
    pub channels: u32,
    /// Written live in those channels since, which go with them.
    pub live_posts: u64,
    pub groups: u32,
    pub placeholders: u32,
    pub claimed_kept: u32,
    /// The stored count, so "about".
    pub archive_rows: u64,
    pub emotes: u32,
    /// Runs of this guild after it that are not undone: those go first.
    pub later_runs: u32,
}

/// A role on Discord. The relay derives the group's name and badge, and alone maps
/// `permissions` to privileges (`discord::scopes_of`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportRole {
    pub dc_id: u64,
    /// Discord's, up to 100 characters.
    pub name: String,
    /// `colors.primary_color`, else the deprecated `color`; 0 none.
    pub color: u32,
    /// Higher is higher.
    pub position: u32,
    pub hoist: bool,
    pub permissions: u64,
}

/// A member of the Discord server. Bots and members still in screening are never sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportMember {
    pub dc_id: u64,
    /// Discord's; the relay cleans it.
    pub username: String,
    /// The guild nickname, else `global_name`; "" none.
    pub shown_as: String,
    /// Unix seconds; 0: Discord gave null.
    pub joined_at: i64,
    /// At most 250.
    pub roles: Vec<u64>,
}

/// Someone banned on Discord: only the id. Their name and the reason stay on the
/// importer's screen, not on the relay for good.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportBan {
    pub dc_id: u64,
}

/// Which accounts `AdminOp::MoveAccounts` lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveFilter {
    All,
    Waiting,
    Claimed,
    Banned,
}

/// What the move knows of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveState {
    NotImported,
    /// Made by an import, and nobody has opened it.
    Waiting,
    Claimed,
    /// Holds a banned Discord id, so its owner cannot sign up with it.
    Banned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveAccount {
    pub user: AdminUser,
    pub state: MoveState,
    /// In decimal; "" unless the reader holds `*`.
    pub dc_id: String,
    /// Waiting with a limit, Unix seconds; else 0.
    pub expires_at: i64,
}

/// Someone who could do `scopes` on Discord, and waits for the owner's OK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerRow {
    pub account: [u8; 16],
    pub name: String,
    /// Someone has opened the account: the only ones the owner can answer.
    pub claimed: bool,
    pub group: String,
    pub badge: String,
    pub scopes: Vec<String>,
}

/// One run of the importer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveRun {
    pub id: i64,
    /// In decimal.
    pub guild_id: String,
    pub by: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub undone_at: Option<i64>,
    pub accounts: u32,
    pub groups: u32,
    /// Undone, and not all of it has gone yet: an undo left halfway, or its archive rows
    /// with the worker. A new run waits.
    pub clearing: bool,
}

/// One message imported from Discord, as a reader gets it. The relay can read it and
/// nobody signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveRow {
    /// The Discord message's id, in decimal: a JS number cannot hold it.
    pub id: String,
    /// "" for a root with no message of its own.
    pub author: String,
    /// In decimal, to `*` only; "" otherwise, and for an anonymised row or a webhook's.
    pub author_id: String,
    pub at_ms: u64,
    pub body: String,
    /// The thread it was written in, in decimal; "" in the channel's own flow. Pins and
    /// search reach into threads, and "show it where it stands" needs to know which.
    pub thread: String,
    /// What it answers, in decimal; "" for nothing.
    pub reply_to: String,
    pub reactions: Vec<ArchiveReaction>,
    pub pinned: bool,
    /// This row opens a thread when not "".
    pub thread_name: String,
    pub replies: u32,
    /// Written by a Discord account this account has linked.
    pub mine: bool,
    /// Hidden by its author: only they get such a row.
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReaction {
    pub emoji: String,
    pub count: u32,
}

/// What `AccountRequest::ArchiveMine` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveAction {
    Count,
    Hide,
    Show,
    Delete,
}

/// How much of someone's own rows `AccountRequest::ArchiveMine` covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveScope {
    Message { channel_id: ChannelId, id: String },
    Channel { channel_id: ChannelId },
    Everything,
}

/// What `AdminOp::ArchiveDelete` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveTarget {
    /// A decimal Discord id. Their account stays.
    Author { id: String },
    /// The way to reach an anonymised row, which has no author to match.
    Message { channel_id: ChannelId, id: String },
}

/// A sign-up code that is still open or was used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    /// What `InviteRevoke` names (not the code, which is shown once).
    pub id: String,
    /// Only this name may use it.
    pub name: Option<String>,
    pub created_by: Option<String>,
    pub expires_at: i64,
    pub used_by: Option<String>,
}

/// Who may see and join a channel, and who may speak in it: group names.
/// Empty means everyone (every account and guest); `*` passes every gate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelGate {
    pub groups: Vec<String>,
    pub speakers: Vec<String>,
}

/// An active ban, as shown to admins. An address ban shows the name it was
/// given under, never the address (the relay keeps a keyed hash of it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanInfo {
    /// What `AdminUnban` lifts.
    pub id: u64,
    /// An account ban; else an address ban (an IPv4 address, or an IPv6 /64).
    pub account: bool,
    /// The account's name, or the name the user went by when banned.
    pub label: String,
    pub reason: String,
    /// Who banned: an account's name, "admin token" or "server shell".
    pub by: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Seconds until the ban expires; None = permanent.
    pub expires_in_secs: Option<u64>,
}

/// Video codec of a screen share, chosen by the sharer and fixed for the life
/// of the share. H.264 is the default because every viewer decodes it (browsers
/// included); H.265 is smaller but browsers expose no HEVC decoder on Linux and
/// Firefox none at all. VP8/VP9 exist because a Firefox sharer cannot encode
/// H.264 (Bugzilla 1918769) — no client encodes them natively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum VideoCodec {
    #[default]
    H264 = 0,
    H265 = 1,
    Vp8 = 2,
    Vp9 = 3,
}

impl VideoCodec {
    /// For passing the codec through an `AtomicU8`; unknown values read as H264.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::H265,
            2 => Self::Vp8,
            3 => Self::Vp9,
            _ => Self::H264,
        }
    }
}

/// Information about a screen capture source (display or window).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSourceInfo {
    pub id: String,
    pub name: String,
    /// "display" or "window"
    pub source_type: String,
}

// ── E2E Encryption types ──────────────────────────────────────────────

/// A pre-key bundle for X3DH key agreement, sent during authentication
/// and returned when requesting another user's keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundleData {
    pub registration_id: u32,
    pub device_id: u32,
    /// 32-byte Curve25519 identity public key.
    pub identity_key: Vec<u8>,
    pub signed_prekey_id: u32,
    /// 32-byte Curve25519 public key.
    pub signed_prekey: Vec<u8>,
    /// 64-byte XEdDSA signature by the identity key over the signed pre-key.
    pub signed_prekey_signature: Vec<u8>,
    /// Batch of one-time pre-keys.
    pub prekeys: Vec<OneTimePreKey>,
    /// The signed Kyber1024 last-resort pre-key (protocol v12): every session
    /// start is post-quantum (PQXDH).
    pub kyber_prekey_id: u32,
    /// 1569 bytes: a type byte, then the Kyber1024 public key.
    pub kyber_prekey: Vec<u8>,
    /// 64-byte XEdDSA signature by the identity key over `kyber_prekey`.
    pub kyber_prekey_signature: Vec<u8>,
}

/// A single one-time pre-key's public portion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    /// 32-byte Curve25519 public key.
    pub public_key: Vec<u8>,
}

/// Positional ("proximity") audio mode of a channel. Rendering happens on
/// each client; the server only stores the mode and relays the encrypted
/// position beacons of members who sync their position.
///
/// Coordinates are metres: x/y is the ground plane, z is up. `TwoD` ignores
/// z for distance; `ThreeD` uses all three axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProximityMode {
    #[default]
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "2d")]
    TwoD,
    #[serde(rename = "3d")]
    ThreeD,
}

/// Information about a channel/room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub channel_id: ChannelId,
    pub name: String,
    pub description: String,
    /// Maximum users allowed (0 = unlimited).
    pub max_users: u32,
    /// Current number of users in this channel.
    pub user_count: u32,
    /// Whether a password is required to join.
    pub has_password: bool,
    /// User who created this channel (None for the permanent General channel).
    pub created_by: Option<UserId>,
    /// Positional audio mode (protocol v6).
    #[serde(default)]
    pub proximity: ProximityMode,
    /// Not listed in the sidebar for non-admins (protocol v7). Joining by id
    /// still works, so invite links and the game SDK's join-by-name keep
    /// working — this hides the room, it does not lock it.
    #[serde(default)]
    pub hidden: bool,
    /// Members are shown to each other under a random pseudonym. The server
    /// substitutes it in every message; admins see the real names.
    #[serde(default)]
    pub anonymous: bool,
    /// Whether screen sharing is allowed here. Default true, so a channel
    /// from an older config keeps working.
    #[serde(default = "default_true")]
    pub screen_share: bool,
    /// Non-admins do not see the member list, only whoever is speaking.
    #[serde(default)]
    pub hide_members: bool,
    /// A text channel (protocol v9): joining it is a subscription, not a move.
    /// Several can be joined at once, and joining one leaves the voice channel
    /// the user stands in alone. No voice, no screen share, no proximity.
    #[serde(default)]
    pub text: bool,
    /// Clients join this text channel on connect unless the user left it
    /// before (which the client remembers). A hint only — the server never
    /// joins anybody by itself.
    #[serde(default)]
    pub auto_join: bool,
    /// Seconds a message written here is meant to live; 0 (the default) is no
    /// timer at all (protocol v9).
    ///
    /// The server neither stores chat nor enforces this — it cannot, the
    /// messages are end-to-end encrypted and it keeps none of them. This is the
    /// channel saying what it expects, which each client stamps on what it
    /// sends and applies to what it keeps. A client takes the shorter of this
    /// and what a message itself claims, so a relay that raises the number
    /// cannot make anybody's copy outlive what its sender intended.
    #[serde(default)]
    pub message_ttl_secs: u32,
    /// The relay forwards voice only to the people who should hear it, instead
    /// of to everyone in the channel (protocol v8).
    ///
    /// Off everywhere by default, and it is the **only** state in which the
    /// relay is told anything about who hears whom. It exists for channels a
    /// game drives, where "everyone in the channel" can be hundreds of players
    /// spread over a map; everywhere else fanning out to the whole channel
    /// costs nothing and tells the server nothing. A client entering one is
    /// told, in as many words, what it now shares.
    #[serde(default)]
    pub routed: bool,
    /// An announcement channel (protocol v11): only its managers — the
    /// creator, admins and moderators — may post, and the relay refuses
    /// everybody else's messages. Text channels only.
    #[serde(default)]
    pub announce: bool,
    /// Slow mode (protocol v11): a member may post once per this many seconds;
    /// 0 is off. Enforced by the relay, which sees who posts where and when
    /// but nothing of what; the channel's managers are exempt.
    #[serde(default)]
    pub slow_mode_secs: u32,
    /// Marked 18+ (protocol v11). The relay only carries the flag: each client
    /// asks its user for consent before joining or showing the channel.
    #[serde(default)]
    pub nsfw: bool,
    /// The stored-message log this channel keeps for accounts that ask for
    /// one (protocol v11): `c:<uid>`. Empty where there is none — a relay
    /// without accounts or without storage, a temporary channel, and one that
    /// is anonymous or hides its members (a log's members see each other).
    #[serde(default)]
    pub log: String,
}

/// The options a `SetChannelOptions` asks for; `None` leaves one as it is.
/// One struct from the settings dialog to the relay's checks (protocol v11),
/// so a new option is a field here and one in `ChannelInfo`, not one per layer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOptions {
    #[serde(default)]
    pub hidden: Option<bool>,
    #[serde(default)]
    pub anonymous: Option<bool>,
    #[serde(default)]
    pub screen_share: Option<bool>,
    #[serde(default)]
    pub hide_members: Option<bool>,
    /// Have the relay forward voice only to whoever should hear it
    /// (protocol v8). See `ChannelInfo::routed`.
    #[serde(default)]
    pub routed: Option<bool>,
    /// Seconds a message written here is meant to live; 0 turns the timer
    /// off (protocol v9). See `ChannelInfo::message_ttl_secs`.
    #[serde(default)]
    pub message_ttl_secs: Option<u32>,
    /// Only the channel's managers may post (protocol v11; text channels
    /// only). See `ChannelInfo::announce`.
    #[serde(default)]
    pub announce: Option<bool>,
    /// One post per this many seconds per member, 0 = off (protocol v11).
    /// See `ChannelInfo::slow_mode_secs`.
    #[serde(default)]
    pub slow_mode_secs: Option<u32>,
    /// Mark the channel 18+ (protocol v11). See `ChannelInfo::nsfw`.
    #[serde(default)]
    pub nsfw: Option<bool>,
}

/// An empty channel with every option off, but screen sharing on (as an
/// older peer's message reads too): what a literal fills in with
/// `..Default::default()`, so a new field is one edit, not one per site.
impl Default for ChannelInfo {
    fn default() -> Self {
        ChannelInfo {
            channel_id: 0,
            name: String::new(),
            description: String::new(),
            max_users: 0,
            user_count: 0,
            has_password: false,
            created_by: None,
            proximity: ProximityMode::default(),
            hidden: false,
            anonymous: false,
            screen_share: true,
            hide_members: false,
            text: false,
            auto_join: false,
            message_ttl_secs: 0,
            routed: false,
            announce: false,
            slow_mode_secs: 0,
            nsfw: false,
            log: String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_info_roundtrip() {
        let info = UserInfo {
            user_id: 42,
            username: "alice".into(),
            channel_id: 1,
            is_muted: true,
            is_deafened: true,
            is_screen_sharing: false,
            is_admin: true,
            shares_history: true,
            account: None,
            is_moderator: false,
            badges: vec![],
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: UserInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.user_id, 42);
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.channel_id, 1);
        assert!(decoded.is_muted);
        assert!(decoded.is_deafened);
        assert!(!decoded.is_screen_sharing);
    }

    #[test]
    fn channel_info_roundtrip() {
        let info = ChannelInfo {
            channel_id: 5,
            name: "Test".into(),
            description: "desc".into(),
            max_users: 10,
            user_count: 3,
            has_password: true,
            created_by: Some(1),
            proximity: ProximityMode::TwoD,
            hidden: true,
            anonymous: true,
            screen_share: false,
            hide_members: true,
            routed: true,
            text: true,
            auto_join: true,
            message_ttl_secs: 3600,
            announce: true,
            slow_mode_secs: 30,
            nsfw: true,
            log: "c:abc".into(),
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: ChannelInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.channel_id, 5);
        assert_eq!(decoded.name, "Test");
        assert_eq!(decoded.max_users, 10);
        assert!(decoded.has_password);
        assert_eq!(decoded.created_by, Some(1));
        assert_eq!(decoded.proximity, ProximityMode::TwoD);
        assert!(decoded.hidden && decoded.anonymous && decoded.hide_members);
        assert!(!decoded.screen_share);
        assert!(decoded.announce && decoded.nsfw);
        assert_eq!(decoded.slow_mode_secs, 30);
    }

    #[test]
    fn channel_options_default_to_an_ordinary_room() {
        // A channels.json entry that names none of them, and an older config
        // reaching a newer server, must both give a plain public channel that
        // still allows screen sharing.
        let info: ChannelInfo = serde_json::from_str(
            r#"{"channel_id":1,"name":"X","description":"","max_users":0,
                "user_count":0,"has_password":false,"created_by":null}"#,
        )
        .unwrap();
        assert!(!info.hidden && !info.anonymous && !info.hide_members);
        assert!(
            info.screen_share,
            "sharing must stay on unless switched off"
        );
        assert_eq!(info.proximity, ProximityMode::Off);
        assert!(!info.announce && !info.nsfw && info.slow_mode_secs == 0);
    }

    #[test]
    fn proximity_mode_json_names() {
        assert_eq!(
            serde_json::to_string(&ProximityMode::Off).unwrap(),
            "\"off\""
        );
        assert_eq!(
            serde_json::to_string(&ProximityMode::TwoD).unwrap(),
            "\"2d\""
        );
        assert_eq!(
            serde_json::to_string(&ProximityMode::ThreeD).unwrap(),
            "\"3d\""
        );
        let m: ProximityMode = serde_json::from_str("\"3d\"").unwrap();
        assert_eq!(m, ProximityMode::ThreeD);
        assert!(serde_json::from_str::<ProximityMode>("\"4d\"").is_err());
    }

    #[test]
    fn user_info_default_screen_sharing() {
        // Serialize a UserInfo without is_screen_sharing, verify default is false
        let info = UserInfo {
            user_id: 1,
            username: "bob".into(),
            channel_id: 0,
            is_muted: false,
            is_deafened: false,
            is_screen_sharing: false,
            is_admin: false,
            shares_history: false,
            account: None,
            is_moderator: false,
            badges: vec![],
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let decoded: UserInfo = postcard::from_bytes(&bytes).unwrap();
        assert!(!decoded.is_screen_sharing);
    }

    #[test]
    fn may_share_history_table() {
        let held = |s: &str| vec![s.to_string()];
        let none: Vec<String> = Vec::new();
        for (proto, accounts, scopes, want) in [
            // Too old to have the privilege: the switch alone
            (20, true, None, true),
            (20, true, Some(none.clone()), true),
            (20, false, None, true),
            // No accounts: the switch alone
            (21, false, None, true),
            (21, false, Some(none.clone()), true),
            // Accounts: a guest never, an account by what it holds
            (21, true, None, false),
            (21, true, Some(none.clone()), false),
            (21, true, Some(held("voipc:kick")), false),
            (21, true, Some(held(SHARE_HISTORY)), true),
            (21, true, Some(held("*")), true),
            (21, true, Some(held("voipc:*")), true),
            (21, true, Some(held("voipc:share_historyx")), false),
            (21, true, Some(held("voipcx:*")), false),
            (22, true, None, false),
        ] {
            assert_eq!(
                may_share_history(proto, accounts, scopes.as_deref()),
                want,
                "{proto} {accounts} {scopes:?}"
            );
        }
    }
}
