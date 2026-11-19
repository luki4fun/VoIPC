use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use bytes::Bytes;
use dashmap::DashMap;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, RwLock};
use tracing::warn;
use zeroize::Zeroizing;

use voipc_crypto::group_key::GroupKind;
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::*;

use crate::channels::{ChannelEntry, MAX_SLOW_MODE_SECS};
use crate::config::ServerConfig;
use crate::control::ControlTx;
use crate::gk::group::cause as gk_cause;
use crate::settings::ServerSettings;

/// Simple token-bucket rate limiter.
pub struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Whether the bucket has refilled completely.
    pub fn is_full(&mut self) -> bool {
        self.has_token();
        self.tokens >= self.max_tokens
    }

    /// Whether one token is there, without taking it.
    pub fn has_token(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
        self.tokens >= 1.0
    }

    /// Try to consume one token. Returns true if allowed, false if rate-limited.
    pub fn try_consume(&mut self) -> bool {
        let allowed = self.has_token();
        if allowed {
            self.tokens -= 1.0;
        }
        allowed
    }

    /// `try_consume`, for a budget counted in something other than messages.
    pub fn try_consume_n(&mut self, n: f64) -> bool {
        self.has_token();
        let allowed = self.tokens >= n;
        if allowed {
            self.tokens -= n;
        }
        allowed
    }
}

/// Per-user session state held by the server.
pub struct UserSession {
    pub user_id: UserId,
    pub username: String,
    pub channel_id: ChannelId,
    pub is_muted: bool,
    pub is_deafened: bool,
    /// Sender for pushing control messages to this user's writer task.
    pub control_tx: ControlTx,
    /// Media packets (voice, video, screen audio) queued for this user's
    /// QUIC session. A full queue drops the packet, like UDP would.
    pub media_tx: mpsc::Sender<Bytes>,
    /// The client's IP (bans).
    pub peer_ip: IpAddr,
    /// Logged in with the admin token, or (with accounts) holds `*`.
    pub is_admin: bool,
    /// Holds any privilege at all (1.7: any scope). Only `*` kicks or bans
    /// such a member. (`UserInfo::is_moderator` is `voipc:channels`.)
    pub is_moderator: bool,
    /// The privileges the account's scopes grant (`can`).
    pub powers: crate::accounts::Powers,
    /// Which read of the account's scopes is the latest one started (`refresh`),
    /// and which is the latest one written.
    pub scope_read: u64,
    pub scope_written: u64,
    /// The relay account this connection signed in with; `None` for a guest.
    pub account: Option<AccountSession>,
    /// Put out by a moderator or the server, not gone by itself: their disconnect is an
    /// exit, and whoever keyed them starts a new chain (`session::eject`).
    pub ejected: bool,
    /// Writers who asked this follower to open a session (`OpenSessions`) and have had no
    /// hello: a `SessionHello` goes only to one of these, once.
    pub session_asked: HashSet<UserId>,
    /// This user answers requests for recent channel chat. Told to the server
    /// only so a member list can show who asking would reach; the server has
    /// always seen the requests themselves go past.
    pub shares_history: bool,
    /// Failed AdminLogin attempts; the third closes the connection.
    pub admin_login_failures: u8,
    /// Woken by an admin kick/ban: the connection loop exits and cleans up.
    pub close: std::sync::Arc<tokio::sync::Notify>,
    /// Rate limiter for channel history requests (each one makes a peer
    /// encrypt and send up to ~48 KiB). The burst covers a connect that
    /// auto-joins every text channel on the server and asks each channel's
    /// sharers — so it is sized from the channel budget, not a fixed number.
    pub history_request_rate: RateLimiter,
    /// Rate limiter for UDP voice packets (55 pkt/s — 50fps + margin).
    pub voice_rate: RateLimiter,
    /// Rate limiter for position beacons (12 pkt/s — senders coalesce to 10 Hz).
    /// Separate from voice so positions cannot eat the voice budget.
    pub position_rate: RateLimiter,
    /// Rate limiter for UDP video packets (120 pkt/s — 60fps × 2 fragments avg).
    pub video_rate: RateLimiter,
    /// Global rate limiter for all TCP messages (50 msg/s burst).
    pub global_rate: RateLimiter,
    /// Rate limiter for channel password attempts (3 burst, 1/s refill).
    pub password_attempt_rate: RateLimiter,
    /// Rate limiter for chat messages (channel + DM).
    pub chat_rate: RateLimiter,
    /// Account requests (the database work behind kept messages and the
    /// vault): 10 a second, 30 at once.
    pub account_rate: RateLimiter,
    /// Reads of the stored log: a browser reads its conversations back after
    /// every reload, and that must not refuse the writes (or uploads) sharing
    /// `account_rate` meanwhile. Bounded queries, so a larger budget.
    pub log_read_rate: RateLimiter,
    /// Display names and pictures asked for. A member list asks for all it shows,
    /// and pictures are the larger part: its own budget, not `account_rate`.
    pub profile_rate: RateLimiter,
    /// Asking who takes a report: each ask reads the groups of a relay with
    /// accounts, and nobody reports twice a minute for long.
    pub report_rate: RateLimiter,
    /// Searching what came from Discord: each request reads rows for up to a fifth of a
    /// second, so it has its own small budget.
    pub archive_search_rate: RateLimiter,
    /// Rate limiter for keyframe requests relayed *to* this user as a sharer
    /// (each one forces an IDR); per share, so many viewers losing the same
    /// frames cannot storm the sharer.
    pub keyframe_relay_rate: RateLimiter,
    /// Rate limiter for this user's frame-loss reports as a viewer.
    pub loss_report_rate: RateLimiter,
    /// Rate limiter for the flags a client sets about itself — muted,
    /// deafened, history sharing, its audio filter, its channel's options.
    /// None of them is expensive to store; every one of them makes the server
    /// announce something about this user to other people.
    pub state_change_rate: RateLimiter,
    /// Rate limiter for the audio filter a client sets in a routed channel.
    ///
    /// Its own, and not the "something about me changed" budget it used to
    /// share: this one announces nothing and stores one bounded set, but it is
    /// driven by a game and changes whenever who the player can hear changes —
    /// `docs/SDK.md` puts that at up to 20 times a second. At 2/s the surplus
    /// was dropped without a word, which leaves the relay culling by a filter
    /// the game has moved on from: somebody standing next to you that you
    /// cannot hear, and nothing on either screen to say why.
    pub audio_filter_rate: RateLimiter,
    /// Rate limiter for joining and leaving channels, of either kind.
    ///
    /// Every one of them is a broadcast over every session on the server —
    /// twice, for a voice channel, which is a leave and a join. A text
    /// subscription does not bound itself by being a move, and a voice join
    /// only looks as though it does: asking for the room you are already in
    /// changes nothing, but flapping between two rooms is two broadcasts a
    /// time for as long as you keep asking.
    pub join_rate: RateLimiter,
    /// Rate limiter for *answering* a history request: the budget of the
    /// member being asked. `history_request_rate` bounds one asker;
    /// this is what stops every member of a channel asking the same person at
    /// the same time, each request costing them an encrypt and up to ~48 KiB.
    pub history_serve_rate: RateLimiter,
    /// Rate limiters for sender-key and media-key distributions relayed on
    /// this user's behalf, **one per person they distribute to**.
    ///
    /// Each relayed key takes a slot in the target's 256-deep control queue,
    /// and a full queue drops whatever arrives next — so without a budget,
    /// whoever distributes fastest decides whose messages get through. But the
    /// cost lands on the *target*, and the shape of honest traffic is exactly
    /// the opposite of the attack: a client hands a key to every member of
    /// every channel it shares with them, which is a wide burst at many people
    /// and never a burst at one. A single budget could only be set wide enough
    /// for the first or tight enough for the second. Per target it is both.
    ///
    /// An entry appears only once the pair has passed the membership check, so
    /// the map is bounded by the people this user actually shares a channel
    /// with. Limiters that have refilled are pruned as it grows (`may_relay_key_to`):
    /// they say nothing a new one would not, and a departed user's refills too.
    pub key_relay_rate: HashMap<UserId, RateLimiter>,
    /// The size at which `key_relay_rate` is next pruned: doubled each time, so a map of
    /// live limiters is not walked again at every new target.
    pub(crate) key_relay_prune_at: usize,
    /// The burst each of those limiters starts with: a sender key per channel
    /// this server can hold, plus the media key and room for a re-key or two.
    pub(crate) key_relay_burst: f64,
    /// Rate limiter for channel creation.
    pub create_channel_rate: RateLimiter,
    /// `KeyCheck`s: one before each post that needs one, and it can list everybody.
    pub key_check_rate: RateLimiter,
    /// Asking who is in a channel: each answer builds and sorts the list, and can be
    /// megabytes. One per channel in a burst, which a sweep takes, and more for long lists.
    pub roster_rate: RateLimiter,
    /// Bytes of text channel posts: a post goes to everyone online, whatever it weighs.
    pub post_bytes_rate: RateLimiter,
    /// `RenewSessionKeys`: stored, told to nobody, and one a key job at most from an honest
    /// app, whose old keys go a minute later, so an honest one must not hit this.
    pub renew_keys_rate: RateLimiter,
    /// Rate limiter for pre-key uploads.
    pub prekey_rate: RateLimiter,
    /// Rate limiter for pre-key bundle requests (each consumes a target's one-time key).
    pub prekey_bundle_rate: RateLimiter,
    /// Whether this user is currently screen sharing.
    pub is_screen_sharing: bool,
    /// The channels where this member may only listen and read: their gate
    /// names who speaks, and they are not one (`gates`). Set on every join
    /// and when a gate or their groups change, so voice checks no gate.
    pub listen_only: HashSet<ChannelId>,
    /// What keeps them from speaking anywhere on this server now (`restrict`).
    pub silence: crate::restrict::Silence,
    /// The user_id of the screenshare this user is currently watching (if any).
    pub watching_screenshare: Option<UserId>,
    /// This connection is the TCP tunnel (`tunnel.rs`): it reaches no edge, since what keeps
    /// it off UDP to the relay keeps it off UDP to an edge too, so it watches from here.
    pub tunnel: bool,
    /// `ClientMessage::EdgeFailed`: one in 2 s. The app sends one per 10 s of silence.
    pub edge_failed_rate: RateLimiter,
    /// The edges that failed this viewer lately, with when: none of them is picked for it
    /// again for `pool::AVOID_FOR`. At most `pool::MAX_AVOID`.
    pub edge_avoid: Vec<(String, Instant)>,
    /// The group key's asks (plan 1b), each refused `RATE` past its budget, which the app
    /// paces: `EpochFetch` 10/s after a burst of 50 (one token a frame, however many past
    /// epochs it names), `EpochBlobWanted` 20/s, `EpochNames` 1/s (a connect into a few
    /// gated channels asks each once).
    pub gk_fetch_rate: RateLimiter,
    pub gk_blob_rate: RateLimiter,
    pub gk_names_rate: RateLimiter,
    /// `EpochPost`s: `chat_rate`'s 5 a second, but 32 at once, since an app sends everything
    /// of the last `HOLD_MS` at once after `OLD_EPOCH` or `RATE`, and every post it held
    /// while it waited for its key (writer.rs `flush`); a post refused here is lost to it.
    pub gk_post_rate: RateLimiter,
    /// `KeyholdVolunteer{on}`: 1 a minute after a burst of 4 (plan 1b). A browser offers
    /// each time its page is shown or hidden or a call begins or ends (`BROWSER_BUSY`);
    /// past the budget its newest offer is held, not refused.
    pub gk_volunteer_rate: RateLimiter,
    /// The newest `KeyholdVolunteer{on}` past its budget: it goes at the first keepalive
    /// tick with a token (`gk_volunteer_late`), unless an `off` came after it. Refused, the
    /// app would think itself offered for good (a refusal names no group it could place).
    pub gk_volunteer_held: Option<voipc_protocol::messages::ClientMessage>,
    /// The last `KeyholdVolunteer` let through was `on`: an `off` changes nothing otherwise.
    pub gk_volunteered: bool,
    /// When an `EpochFloorAhead` went last, per group (plan 1b: 1 a minute a group).
    pub gk_ahead: HashMap<String, Instant>,
    /// This connection's last `EpochPost` still waiting on its group's task (a blob does):
    /// the next one waits behind it, so its posts keep their order while its other frames
    /// are read on (plan 2a: never a blocked session).
    pub gk_post_tail: Option<tokio::sync::oneshot::Receiver<()>>,
    /// An old key path was refused on this connection already (plan 2k): told once.
    pub gk_legacy_told: bool,

    // ── E2E Encryption fields ─────────────────────────────────────────
    /// Client's long-term identity public key (Curve25519). Opaque to server.
    pub identity_key: Option<Vec<u8>>,
    /// The pre-key bundle the client brought. Its `prekeys` is the pool of
    /// one-time keys: each bundle request takes one, `UploadPreKeys` refills it.
    pub bundle: Option<PreKeyBundleData>,
}

/// A connection's account: who, its l4f session (ended with the connection),
/// and what it may do now.
pub struct AccountSession {
    pub user: l4f_accounts::model::User,
    pub token: String,
    pub info: l4f_accounts::model::SessionInfo,
    pub scopes: Vec<String>,
    /// What the account was last told: a role of its waits for codes. A role
    /// given from the shell changes this and no scope (`accounts::revalidate`).
    pub needs_2fa: bool,
    /// A device-key enrolment challenge waiting for its signature, and the
    /// nonce it was issued against (kept here, never sent).
    pub device_challenge: Option<(String, [u8; 16])>,
    /// When the new-member wait starts for an account the move from Discord knows, 0 if
    /// it was served there (`placeholder::wait_start`). None: from `created_at`, as for
    /// anyone else, and always while no wait is set.
    pub wait_from: Option<i64>,
    /// Its groups and badges, read with the scopes.
    pub standing: crate::accounts::Standing,
    /// When a code last passed an admin step-up (`AdminReply::StepUp`).
    pub step_up_at: Option<std::time::Instant>,
    /// A provider's sign-in, and this connection's device then opened the vault
    /// (or made it): as good as a recent password for remembering this device or
    /// turning codes on, and for nothing else. A provider alone never sets this,
    /// nor does a remembered device, so one stolen device stays what it was.
    pub vault_proven: bool,
    /// This connection's TLS exporter (`voipc_crypto::bind`): what its proofs are bound to.
    pub binding: Option<[u8; voipc_crypto::bind::BIND_LEN]>,
    /// A login-key challenge waiting for `KeyStepUp`, and its nonce (kept here, never sent).
    pub key_challenge: Option<(String, [u8; 16])>,
    /// When `KeyStepUp` last held: the password again, for the next request that wants it
    /// (`accounts::prove_recent` takes it, as it took a secret in the request).
    pub key_stepped: Option<std::time::Instant>,
    /// Signed in with the password's secret on this connection, or proved it again since
    /// (`accounts::confirm_again`), and not moved to the login key yet
    /// (`accounts::login_key_set`).
    pub by_secret: bool,
}

impl UserSession {
    /// The relay account this session signed in with, if any.
    pub fn account_id(&self) -> Option<[u8; 16]> {
        self.account.as_ref().map(|a| a.user.id.0)
    }

    /// The badges this member shows, where `account` (as `account_shown`
    /// gave it) shows too.
    pub fn badges_with(&self, account: Option<[u8; 16]>) -> Vec<String> {
        match (&self.account, account) {
            (Some(a), Some(_)) => a.standing.badges.clone(),
            _ => Vec::new(),
        }
    }

    /// Admin (`*`, or the admin token without accounts) or the privilege.
    pub fn can(&self, p: crate::accounts::Powers) -> bool {
        self.is_admin || self.powers.has(p)
    }

    /// The account's roles as `scopes` say: its powers, and the scopes kept
    /// to compare against later (`accounts::revalidate`). The one place they
    /// are set, at sign-in and after a change alike.
    pub fn set_scopes(&mut self, user: l4f_accounts::model::User, scopes: Vec<String>) {
        self.is_admin = crate::accounts::is_star(&scopes);
        self.is_moderator = crate::accounts::holds_power(&scopes);
        self.powers = crate::accounts::Powers::of(&scopes);
        if let Some(a) = self.account.as_mut() {
            a.user = user;
            a.scopes = scopes;
        }
    }

    /// A session with every budget at full, as a client that has just
    /// authenticated gets it.
    ///
    /// One place, because the numbers are an argument with each other — the
    /// control-message rate bounds all of them, and the per-message ones are
    /// sized against what an honest client does on a busy connect — and two
    /// copies of that argument drift.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: UserId,
        username: String,
        control_tx: ControlTx,
        media_tx: mpsc::Sender<Bytes>,
        peer_ip: IpAddr,
        max_users: u32,
        channel_budget: u32,
    ) -> Self {
        Self {
            user_id,
            username,
            channel_id: 0,
            is_muted: false,
            is_deafened: false,
            control_tx,
            media_tx,
            peer_ip,
            is_admin: false,
            is_moderator: false,
            powers: Default::default(),
            scope_read: 0,
            scope_written: 0,
            account: None,
            ejected: false,
            session_asked: HashSet::new(),
            shares_history: false,
            admin_login_failures: 0,
            close: Default::default(),
            // Asking the members who share for a channel's recent chat. A
            // connect that lands in a voice channel and every auto-joined text
            // channel asks a few people in each, so the burst is the whole
            // connect and the refill is a person pressing the history button.
            // `HISTORY_SOURCES` members per channel, every channel this server
            // can hold: a client is not limited in how many text channels it
            // subscribes to, so neither is the budget that pays for them.
            history_request_rate: RateLimiter::new(
                voipc_crypto::HISTORY_SOURCES as f64 * (channel_budget as f64 + 1.0),
                2.0,
            ),
            voice_rate: RateLimiter::new(55.0, 55.0),
            // Position beacons: senders coalesce to 10 Hz, so 12/s with a
            // matching burst is plenty and keeps them off the voice budget.
            position_rate: RateLimiter::new(12.0, 12.0),
            // 1200 pkt/s ≈ 12 Mbps at 1280B packets: covers 1080p60 video
            // (~7.5 Mbps) + screen audio with headroom; burst 400 absorbs a
            // full keyframe (up to 255 fragments).
            video_rate: RateLimiter::new(400.0, 1200.0),
            // The one budget both ends know about: clients pace themselves
            // just under it (codec.rs CONTROL_MSGS_PER_SEC).
            global_rate: RateLimiter::new(
                voipc_protocol::codec::CONTROL_MSGS_PER_SEC as f64,
                voipc_protocol::codec::CONTROL_MSGS_PER_SEC as f64,
            ),
            password_attempt_rate: RateLimiter::new(3.0, 1.0),
            chat_rate: RateLimiter::new(5.0, 5.0),
            account_rate: RateLimiter::new(30.0, 10.0),
            log_read_rate: RateLimiter::new(60.0, 20.0),
            profile_rate: RateLimiter::new(40.0, 10.0),
            report_rate: RateLimiter::new(4.0, 1.0 / 30.0),
            archive_search_rate: RateLimiter::new(10.0, 1.0),
            keyframe_relay_rate: RateLimiter::new(2.0, 1.0),
            loss_report_rate: RateLimiter::new(2.0, 1.0),
            // Everything a client says about itself — muted, deafened, sharing
            // history, its audio filter, its channel's options — is cheap to
            // store and expensive to announce. 8 in a burst covers a client
            // settling in on connect; 2/s is faster than anyone clicks.
            state_change_rate: RateLimiter::new(8.0, 2.0),
            // The SDK's documented ceiling is 20 updates a second and a real
            // mod sends 4–10, so this keeps up with the fastest of them while
            // still being a bound. Cheap to serve: a truncate, a sort and one
            // map write, no fan-out.
            audio_filter_rate: RateLimiter::new(20.0, 20.0),
            // Joins and leaves. The burst is every channel on the server plus
            // the voice room and a little slack, because a connect that
            // auto-joins them all does exactly that and a client refused here
            // is a text channel that silently never opens; 2/s afterwards is a
            // person changing their mind, not a client making us broadcast to
            // everybody twice a second.
            join_rate: RateLimiter::new(channel_budget as f64 + 4.0, 2.0),
            // Answering history requests, as the one being asked. 6 in a burst
            // covers a full channel arriving at once; the slow refill is the
            // point — a second wave of askers costs the same person another
            // ~48 KiB of encrypting each.
            history_serve_rate: RateLimiter::new(6.0, 0.5),
            key_relay_rate: HashMap::new(),
            key_relay_prune_at: KEY_RELAY_PRUNE_AT,
            key_relay_burst: channel_budget as f64 + 8.0,
            create_channel_rate: RateLimiter::new(1.0, 0.2),
            key_check_rate: RateLimiter::new(channel_budget as f64 + 8.0, 5.0),
            roster_rate: RateLimiter::new(channel_budget as f64 + 8.0, 5.0),
            post_bytes_rate: RateLimiter::new(64.0 * 1024.0, 4.0 * 1024.0),
            renew_keys_rate: RateLimiter::new(8.0, 1.0),
            prekey_rate: RateLimiter::new(1.0, 0.2),
            // One bundle per person on the server, in a burst, because that is
            // what arriving costs: a pairwise session with everybody, for DMs
            // and for the keys. Draining somebody's one-time pre-keys is not
            // what this guards — running out is answered with a bundle that
            // has none, which X3DH accepts. Past 10,000, though, what it guards is the
            // relay's egress: 1.7 KB a bundle, 32 guests an address.
            // shortcut: past 10,000 a newcomer reaches the rest at 10 a second; the group
            // key (scale plan Track C) ends the pairwise arrival this pays for.
            prekey_bundle_rate: RateLimiter::new(max_users.clamp(16, 10_000) as f64, 10.0),
            is_screen_sharing: false,
            listen_only: HashSet::new(),
            silence: Default::default(),
            watching_screenshare: None,
            tunnel: false,
            edge_failed_rate: RateLimiter::new(1.0, 0.5),
            edge_avoid: Vec::new(),
            gk_fetch_rate: RateLimiter::new(50.0, 10.0),
            gk_blob_rate: RateLimiter::new(20.0, 20.0),
            gk_names_rate: RateLimiter::new(4.0, 1.0),
            gk_post_rate: RateLimiter::new(32.0, 5.0),
            gk_volunteer_rate: RateLimiter::new(4.0, 1.0 / 60.0),
            gk_volunteer_held: None,
            gk_volunteered: false,
            gk_ahead: HashMap::new(),
            gk_post_tail: None,
            gk_legacy_told: false,
            identity_key: None,
            bundle: None,
        }
    }

    /// This member as a row of `channel_id`'s list.
    pub(crate) fn row_in(
        &self,
        channel_id: ChannelId,
        username: String,
        account: Option<[u8; 16]>,
    ) -> UserInfo {
        UserInfo {
            user_id: self.user_id,
            username,
            // The channel being listed, not the one the member stands
            // in: for a text channel those differ, and handing out the
            // voice room would tie an anonymous channel's pseudonym to
            // a roster where the same person appears under their name.
            channel_id,
            is_muted: self.is_muted,
            is_deafened: self.is_deafened,
            is_screen_sharing: self.is_screen_sharing,
            is_admin: self.is_admin,
            shares_history: self.shares_history,
            account,
            is_moderator: self.powers.has(crate::accounts::Powers::CHANNELS),
            badges: self.badges_with(account),
        }
    }

    /// Spend one of this session's key-relay tokens for `target`.
    ///
    /// Call it only once the pair has passed the membership check: that is
    /// what keeps the map to people this user really shares a channel with.
    pub fn may_relay_key_to(&mut self, target: UserId) -> bool {
        if self.key_relay_rate.len() >= self.key_relay_prune_at
            && !self.key_relay_rate.contains_key(&target)
        {
            self.key_relay_rate.retain(|_, limiter| !limiter.is_full());
            self.key_relay_prune_at = KEY_RELAY_PRUNE_AT.max(2 * self.key_relay_rate.len());
        }
        let burst = self.key_relay_burst;
        self.key_relay_rate
            .entry(target)
            .or_insert_with(|| RateLimiter::new(burst, KEY_RELAY_REFILL))
            .try_consume()
    }
}

/// How many key distributions one member may aim at one other member a second.
///
/// The *burst* is per session and sized from the channel budget
/// (`UserSession::key_relay_burst`): a sender key per channel the two might
/// share, the media key, and room for a re-key or two on top. This is what
/// follows it, and nothing honest sustains a rate to one person at all — a key
/// is handed over once per channel and then only when somebody leaves.
const KEY_RELAY_REFILL: f64 = 2.0;
/// Below this many targets `key_relay_rate` is never pruned.
const KEY_RELAY_PRUNE_AT: usize = 1024;

/// Writers a follower may have asked of it at once (`session_asked`). Past that the set is
/// emptied, departed writers' entries with the rest.
/// shortcut: a writer still waiting then has its hello refused and asks again; prune by who is
/// online instead if a relay ever sees this.
pub const MAX_ASKED: usize = 4096;

/// Tracks an active screen share session within a channel.
pub struct ScreenShareSession {
    pub sharer_user_id: UserId,
    pub sharer_session_id: SessionId,
    /// Set of user_ids currently watching this share.
    pub viewers: HashSet<UserId>,
    /// Codec the sharer encodes with; handed to every viewer on watch.
    pub codec: VideoCodec,
    /// What it may send each viewer at its resolution (kbit/s), for `[media]`'s budget.
    pub ceiling_kbps: u32,
    /// The viewers a media edge serves (`[pool]`), and where. The rest of `viewers` are
    /// served by this relay. `viewers` names both, so the count, keyframe requests and loss
    /// reports are the same wherever a viewer watches from.
    pub on_edge: HashMap<UserId, crate::pool::Placement>,
    /// How many of `on_edge` each edge serves, by its name: this relay sends each of these
    /// edges one copy of the share.
    edges: HashMap<String, u32>,
}

impl ScreenShareSession {
    fn new(
        sharer_user_id: UserId,
        sharer_session_id: SessionId,
        codec: VideoCodec,
        ceiling_kbps: u32,
    ) -> Self {
        Self {
            sharer_user_id,
            sharer_session_id,
            viewers: HashSet::new(),
            codec,
            ceiling_kbps,
            on_edge: HashMap::new(),
            edges: HashMap::new(),
        }
    }

    /// The viewers this relay sends the share to itself.
    pub fn local_viewers(&self) -> usize {
        self.viewers.len().saturating_sub(self.on_edge.len())
    }

    /// The edges this relay sends the share to, one copy each.
    pub fn edges_fed(&self) -> usize {
        self.edges.len()
    }

    /// What the share costs this relay to send (kbit/s), counted at its resolution: one copy
    /// for each of its own viewers, and one for each edge that serves any.
    pub fn egress_kbps(&self) -> u64 {
        self.ceiling_kbps as u64 * (self.local_viewers() + self.edges_fed()) as u64
    }

    fn put_on_edge(&mut self, viewer: UserId, placement: crate::pool::Placement) {
        *self.edges.entry(placement.edge.clone()).or_insert(0) += 1;
        if let Some(before) = self.on_edge.insert(viewer, placement) {
            self.forget_edge(&before.edge);
        }
    }

    fn take_off_edge(&mut self, viewer: UserId) -> Option<crate::pool::Placement> {
        let placement = self.on_edge.remove(&viewer)?;
        self.forget_edge(&placement.edge);
        Some(placement)
    }

    fn forget_edge(&mut self, edge: &str) {
        if let Some(n) = self.edges.get_mut(edge) {
            *n -= 1;
            if *n == 0 {
                self.edges.remove(edge);
            }
        }
    }

    /// Takes `viewer` out of the share. One an edge served has its ticket's slot revoked
    /// there (`CoreMsg::Revoke`), so the edge ends it, and the edge's counts here go down.
    /// Whether it watched. The caller refans.
    pub(crate) fn drop_viewer(&mut self, viewer: UserId, pool: Option<&crate::pool::Pool>) -> bool {
        if let Some(placement) = self.take_off_edge(viewer) {
            if let Some(pool) = pool {
                pool.unplace(&placement, self.sharer_session_id, self.ceiling_kbps, true);
            }
        }
        self.viewers.remove(&viewer)
    }
}

/// The end of a share, for the edges that carry it: each is told `CoreMsg::ShareEnded`,
/// which ends its viewers there, and its counts and feed of the share go. Every path that
/// removes a share from its channel comes here.
fn end_share(state: &ServerState, share: &ScreenShareSession) {
    if let Some(pool) = &state.pool {
        pool.end_share(
            state,
            share.sharer_session_id,
            share.ceiling_kbps,
            share.on_edge.values(),
        );
    }
}

/// Whether `user` shares in any channel: what `UserSession::is_screen_sharing` says. A share
/// can be left in a room its sharer was moved out of until that move's own cleanup ends it
/// (a kick's comes after the log is written), and the flag stays up until it does, so that
/// no second share of the same sharer starts meanwhile: past `channels`, a share is known by
/// its sharer alone (its fan, the pool's placements and feeds, an edge's tickets), and two
/// would feed each other's edges and end each other there.
fn shares_anywhere(channels: &HashMap<ChannelId, Channel>, user: UserId) -> bool {
    channels
        .values()
        .any(|c| c.screen_shares.contains_key(&user))
}

/// What a share costs this relay to send, all of them together (kbit/s): what `[media]
/// video_egress_mbit` is weighed against.
pub(crate) fn video_egress_kbps(channels: &HashMap<ChannelId, Channel>) -> u64 {
    channels
        .values()
        .flat_map(|c| c.screen_shares.values())
        .map(ScreenShareSession::egress_kbps)
        .sum()
}

/// What `watch_screen_share` says.
#[derive(Debug)]
pub struct Watched {
    pub sharer_sid: SessionId,
    /// How many watch the share now.
    pub new_count: u32,
    pub codec: VideoCodec,
    /// Where the viewer fetches the share, when an edge serves it: `ServerMessage::WatchAt`'s
    /// placement and edge, to go right after `WatchingScreenShare`.
    pub edge: Option<(u64, EdgeView)>,
}

/// Where a viewer is seated (`ServerState::seat`).
enum Spot {
    Edge(crate::pool::Placement, EdgeView),
    Here,
}

/// The edges a viewer is to avoid now, of those that failed it (`UserSession::edge_avoid`),
/// once those past `pool::AVOID_FOR` are forgotten.
fn avoided(list: &mut Vec<(String, Instant)>, now: Instant) -> Vec<String> {
    list.retain(|(_, at)| now.saturating_duration_since(*at) < crate::pool::AVOID_FOR);
    list.iter().map(|(edge, _)| edge.clone()).collect()
}

/// Where one share's packets go (`ServerState::share_fans`), kept beside `channels` so the
/// video path takes no `channels` lock per packet. With a read lock for each packet, every
/// join, leave and watch waited behind the fan-out, and as the lock is write-preferring, a
/// write that waited held up every share's packets in turn.
///
/// Each half is swapped whole and read by cloning the `Arc`, so a packet goes to the list as
/// it was when the packet came in.
pub struct Fan {
    /// The channel the share is in. A packet goes out only while its sharer is still there:
    /// a kick moves the sharer to General under the lock, and the share is ended after.
    pub channel_id: ChannelId,
    /// The media queues of the viewers on this relay, as the share's `viewers` names them.
    /// Rebuilt under the `channels` write lock on every change of who watches, which keeps
    /// two rebuilds in order (`ServerState::refan`).
    pub local: Arc<[mpsc::Sender<Bytes>]>,
    /// The feeds of the edges that carry this share. Empty while no edge does; the pool
    /// swaps it without the `channels` lock.
    pub feeds: Arc<[mpsc::Sender<Bytes>]>,
    /// When the share last sent a video fragment, in `ServerState::uptime_ms`; 0 while it has
    /// sent none. Viewers who say they get nothing from an edge are not moved while the share
    /// itself is silent. Screen audio does not count: viewers judge an edge by its video.
    pub last_packet_ms: Arc<AtomicU64>,
    /// What the sharer is told of its viewers. Here and not under `channels`, so a loss
    /// report, of which a big share's viewers send up to a thousand a second, takes no
    /// `channels` lock.
    pub news: Mutex<ShareNews>,
}

impl Fan {
    fn new(channel_id: ChannelId, sharer_tx: ControlTx) -> Self {
        Self {
            channel_id,
            local: Arc::from(Vec::new()),
            feeds: Arc::from(Vec::new()),
            last_packet_ms: Arc::default(),
            news: Mutex::new(ShareNews::new(sharer_tx)),
        }
    }
}

/// Above this many viewers a sharer hears its viewers' loss as one `VideoLossSummary` a
/// second, not as each viewer's `VideoLossReported`: a thousand viewers who each report
/// every 2 s were 500 messages a second to one app.
pub const LOSS_SUMMARY_ABOVE: u32 = 8;
/// A viewer's loss report counts in the summary for this long, as it does in the apps'
/// own tally of `VideoLossReported` (viewers report every 2 s).
pub const LOSS_REPORT_TTL_MS: u64 = 2_000;

/// What a sharer hears about its viewers, each kind at most once a second
/// (`ServerState::share_tick`), apart from the count going to 0 or from 0, which goes at once:
/// the app captures only while somebody watches.
///
/// Sent under this lock, so two counts reach the app in the order they were made. Each
/// change of who watches comes here under the `channels` write lock (`ServerState::refan`),
/// the tick and the loss reports with no `channels` lock.
pub struct ShareNews {
    /// The sharer's control queue, taken when the share started: nothing here looks
    /// `sessions` up while the fan's shard is held.
    tx: ControlTx,
    /// How many watch, as the share's `viewers` counts them.
    viewers: u32,
    /// The count the sharer was told last.
    told: u32,
    /// The viewers who reported loss in the last `LOSS_REPORT_TTL_MS`, with when
    /// (`ServerState::uptime_ms`). Filled only while more than `LOSS_SUMMARY_ABOVE` watch.
    lossy: HashMap<UserId, u64>,
    /// A loss report came in since the last summary: a summary goes out only after news.
    fresh: bool,
}

impl ShareNews {
    fn new(tx: ControlTx) -> Self {
        Self {
            tx,
            viewers: 0,
            told: 0,
            lossy: HashMap::new(),
            fresh: false,
        }
    }

    /// Who watches changed: to 0 or from 0 the sharer is told at once, the rest waits for
    /// the tick, which sends the last count of the second, if it is not what was told.
    fn viewers_now(&mut self, viewers: u32) {
        self.viewers = viewers;
        if (viewers == 0) != (self.told == 0) {
            self.tell_count();
        }
    }

    fn tell_count(&mut self) {
        self.told = self.viewers;
        let _ = crate::session::send_msg(
            &self.tx,
            &ServerMessage::ViewerCountChanged {
                viewer_count: self.viewers,
            },
        );
    }

    /// A viewer lost frames: relayed as it is to a sharer with few viewers, kept for the
    /// summary above `LOSS_SUMMARY_ABOVE`. A report of no loss counts for nothing there,
    /// as the apps count it.
    fn loss(&mut self, viewer: UserId, frames_dropped: u32, frames_received: u32, now_ms: u64) {
        if self.viewers <= LOSS_SUMMARY_ABOVE {
            let _ = crate::session::send_msg(
                &self.tx,
                &ServerMessage::VideoLossReported {
                    viewer_user_id: viewer,
                    frames_dropped,
                    frames_received,
                },
            );
        } else if frames_dropped > 0 {
            self.lossy.insert(viewer, now_ms);
            self.fresh = true;
        }
    }

    /// Once a second: the count, if the sharer was told another, and a summary of the loss
    /// reported since the last one.
    fn tick(&mut self, now_ms: u64) {
        if self.viewers != self.told {
            self.tell_count();
        }
        self.lossy
            .retain(|_, at| now_ms.saturating_sub(*at) < LOSS_REPORT_TTL_MS);
        if std::mem::take(&mut self.fresh) && !self.lossy.is_empty() {
            // Somebody who reported and left within the 2 s still counts, but never past
            // how many watch: the app weighs the one against the other.
            let reporters = (self.lossy.len() as u32).min(self.viewers);
            let _ = crate::session::send_msg(
                &self.tx,
                &ServerMessage::VideoLossSummary {
                    reporters,
                    viewers: self.viewers,
                },
            );
        }
    }
}

/// What a share may send each viewer, by its resolution (kbit/s): the encoders' top rates.
pub fn share_ceiling_kbps(resolution: u16) -> u32 {
    match resolution {
        1080.. => 7500,
        720.. => 4000,
        _ => 2000,
    }
}

/// A watch refused for room, not because of anything the viewer did.
pub const SHARE_FULL: &str =
    "This share is full: it has as many viewers as this server carries. Try again later.";
pub const VIDEO_FULL: &str = "This server is sending all the video it can. Try again later.";

/// A follower's place in a text channel's count (`Follow`).
#[derive(Clone, Copy)]
pub struct Seat {
    /// A writer whose `keyed` has not reached this owes them a key, and sends them no post.
    pub at: u64,
    /// Their first stamp since coming in. A writer who keyed them holds on to that through
    /// quiet and back, so an exit goes by this one.
    pub first: u64,
}

/// A quiet follower nobody ever keyed: no writer's `keyed` reaches this.
const NEVER_WHOLE: u64 = u64::MAX;

/// Who follows a text channel on the live path (protocol v21), and how far each writer has
/// named them. In memory only. Everyone here is in `Channel::members` too, which gates,
/// post rules and files go by.
#[derive(Default)]
pub struct Follow {
    /// Taking posts.
    pub joined: HashMap<UserId, Seat>,
    /// Holding a seat and a mark, with no post and no key: their first stamp.
    pub quiet: HashMap<UserId, u64>,
    /// Writer -> the last stamp they have been told of. A post goes up to here.
    pub keyed: HashMap<UserId, u64>,
    /// The last stamp given.
    pub last_join: u64,
    /// When the last post passed, for marks. Set without a write lock, 0 since a restart.
    pub last_post_ms: AtomicU64,
}

impl Follow {
    /// Takes `user` whole or quiet. Nothing changes for someone already that, so a repeated
    /// join owes nobody anything.
    pub fn set(&mut self, user: UserId, quiet: bool) {
        let first = self
            .joined
            .get(&user)
            .map(|s| s.first)
            .or_else(|| self.quiet.get(&user).copied());
        if quiet {
            self.joined.remove(&user);
            self.quiet.insert(user, first.unwrap_or(NEVER_WHOLE));
        } else if !self.joined.contains_key(&user) {
            self.quiet.remove(&user);
            self.last_join += 1;
            let at = self.last_join;
            let first = first.unwrap_or(at).min(at);
            self.joined.insert(user, Seat { at, first });
        }
    }

    pub fn holds(&self, user: UserId) -> bool {
        self.joined.contains_key(&user) || self.quiet.contains_key(&user)
    }

    /// Out, as a follower and as a writer: the stamp their exit goes by.
    fn remove(&mut self, user: UserId) -> Option<u64> {
        self.keyed.remove(&user);
        self.joined
            .remove(&user)
            .map(|s| s.first)
            .or_else(|| self.quiet.remove(&user))
    }

    /// Whom `writer` owes a key, in id order, and the stamp that takes them to.
    pub fn owed(&self, writer: UserId, restart: bool) -> (Vec<UserId>, u64) {
        let upto = self.last_join;
        let from = if restart {
            0
        } else {
            self.keyed.get(&writer).copied().unwrap_or(0)
        };
        if from >= upto {
            return (Vec::new(), upto);
        }
        let mut ids: Vec<UserId> = self
            .joined
            .iter()
            .filter(|(u, s)| **u != writer && s.at > from)
            .map(|(u, _)| *u)
            .collect();
        ids.sort_unstable();
        (ids, upto)
    }

    /// Who reads a post by `writer`.
    pub fn readers_of(&self, writer: UserId) -> Vec<UserId> {
        let Some(&upto) = self.keyed.get(&writer) else {
            return Vec::new();
        };
        self.joined
            .iter()
            .filter(|(u, s)| **u != writer && s.at <= upto)
            .map(|(u, _)| *u)
            .collect()
    }

    /// The writers an exit by a follower with this first stamp reaches.
    fn who_keyed(&self, first: u64) -> impl Iterator<Item = UserId> + '_ {
        self.keyed
            .iter()
            .filter(move |(_, upto)| **upto >= first)
            .map(|(w, _)| *w)
    }
}

/// A channel/room on the server.
pub struct Channel {
    pub info: ChannelInfo,
    /// Set of user_ids currently in this channel.
    pub members: HashSet<UserId>,
    /// Channel password (None = no password required). Zeroized on drop.
    pub password: Option<Zeroizing<String>>,
    /// Handle to the auto-delete timer task (cancelled when a user joins).
    pub delete_timer: Option<tokio::task::JoinHandle<()>>,
    /// Users who have been invited (bypass password on join).
    pub invited_users: HashSet<UserId>,
    /// An invite sent by someone other than the creator, who hears its answer
    /// (`add_invite`): invited -> who asked.
    pub summons: HashMap<UserId, UserId>,
    /// Active screen shares: sharer_user_id -> ScreenShareSession.
    pub screen_shares: HashMap<UserId, ScreenShareSession>,
    /// Whether this channel was loaded from channels.json and cannot be auto-deleted.
    pub persistent: bool,
    /// The name each member is known by here while the channel is anonymous.
    /// Assigned on join, dropped on leave; admins are told the real names.
    pub pseudonyms: HashMap<UserId, String>,
    /// The stored-message log this channel would keep (`ChannelEntry::log_conv`):
    /// persistent channels on a relay with accounts and storage, else empty.
    pub log_conv: String,
    /// Who may see, join and speak here (`gates`).
    pub gate: ChannelGate,
    /// What the gate of a persistent channel is kept under in the database
    /// (`ChannelEntry::log_conv`); empty for the temporary ones people make.
    pub gate_key: String,
    /// Made in the app (`crate::layout`): a row of `voipc_channels`, not of the file.
    pub kept: bool,
    /// Who follows it on the live path, if it is a text channel.
    pub follow: Follow,
}

impl Channel {
    /// Whether a list of groups keeps people out.
    pub fn gated(&self) -> bool {
        !self.gate.groups.is_empty()
    }

    /// Where a device asks who is here, so a person's going is pushed to it: a gate, or one
    /// joined by hand. Elsewhere anyone online may read anyway.
    pub fn tells_who_left(&self) -> bool {
        self.info.text && (self.gated() || !self.info.auto_join || self.password.is_some())
    }

    /// A `TextJoined` row, for a follower who listens only or not.
    pub fn seat_row(&self, listen_only: bool) -> (ChannelId, bool, bool, u64) {
        (
            self.info.channel_id,
            listen_only,
            self.gated(),
            self.follow.last_post_ms.load(Ordering::Relaxed),
        )
    }

    /// A persistent channel, as an entry says. `logs`: this relay keeps messages.
    pub fn from_entry(
        entry: &ChannelEntry,
        channel_id: ChannelId,
        logs: bool,
        proximity_enabled: bool,
    ) -> Channel {
        // A server with proximity chat switched off serves every channel
        // as `off`, so clients never see a mode they may not use.
        let proximity = if proximity_enabled {
            entry.proximity
        } else {
            if entry.proximity != ProximityMode::Off {
                warn!(
                    channel = %entry.name,
                    "proximity chat is disabled on this server; channel served as off"
                );
            }
            ProximityMode::Off
        };
        let mut channel = Channel {
            info: ChannelInfo {
                channel_id,
                name: entry.name.clone(),
                description: entry.description.clone(),
                max_users: entry.max_users,
                has_password: entry.password_hash.is_some(),
                // A text channel has no voice, so no mode to serve.
                proximity: if entry.text {
                    ProximityMode::Off
                } else {
                    proximity
                },
                routed: entry.routed,
                hidden: entry.hidden,
                anonymous: entry.anonymous,
                screen_share: entry.screen_share && !entry.text,
                hide_members: entry.hide_members,
                text: entry.text,
                auto_join: entry.auto_join,
                message_ttl_secs: entry.message_ttl_secs,
                announce: entry.announce && entry.text,
                slow_mode_secs: entry.slow_mode_secs.min(MAX_SLOW_MODE_SECS),
                nsfw: entry.nsfw,
                ..Default::default()
            },
            members: HashSet::new(),
            password: entry.password_hash.clone().map(Zeroizing::new),
            delete_timer: None,
            invited_users: HashSet::new(),
            summons: HashMap::new(),
            screen_shares: HashMap::new(),
            persistent: true,
            pseudonyms: HashMap::new(),
            log_conv: if logs {
                entry.log_conv()
            } else {
                String::new()
            },
            gate: ChannelGate::default(),
            gate_key: entry.log_conv(),
            kept: false,
            follow: Follow::default(),
        };
        channel.refresh_log();
        channel
    }

    /// The entry a channel made in the app is kept as, its options as they are now.
    pub fn to_entry(&self) -> ChannelEntry {
        let i = &self.info;
        ChannelEntry {
            name: i.name.clone(),
            description: i.description.clone(),
            password_hash: self.password.as_ref().map(|p| p.to_string()),
            max_users: i.max_users,
            proximity: i.proximity,
            hidden: i.hidden,
            anonymous: i.anonymous,
            screen_share: i.screen_share,
            hide_members: i.hide_members,
            routed: i.routed,
            text: i.text,
            auto_join: i.auto_join,
            message_ttl_secs: i.message_ttl_secs,
            announce: i.announce,
            slow_mode_secs: i.slow_mode_secs,
            nsfw: i.nsfw,
            uid: self.gate_key.strip_prefix("c:").map(String::from),
            ..ChannelEntry::default()
        }
    }

    /// An invite of `user_id` is over, used or not. Whether there was one.
    fn end_invite(&mut self, user_id: UserId) -> bool {
        self.summons.remove(&user_id);
        self.invited_users.remove(&user_id)
    }

    /// Who hears the answer to an invite of `user_id`.
    pub fn inviter_of(&self, user_id: UserId) -> Option<UserId> {
        self.summons.get(&user_id).copied().or(self.info.created_by)
    }

    /// Offers the log in `info.log` unless an option rules it out: in an
    /// anonymous channel, or one hiding its members, a log would show who is
    /// there (its members wrap keys to each other by account).
    pub fn refresh_log(&mut self) {
        self.info.log = if self.info.anonymous || self.info.hide_members {
            String::new()
        } else {
            self.log_conv.clone()
        };
    }
}

/// Whether everyone with an app holds who stands in this room, as a list they asked for or
/// the joins since: so a bare id tells them who it is.
pub(crate) fn list_is_public(channel: &Channel) -> bool {
    !channel.info.text
        && !channel.info.anonymous
        && !channel.info.hide_members
        && channel.password.is_none()
        && !channel.gated()
}

/// What an anonymous room does is not told under the real name: a mute or a share there
/// and here at once ties the two (G1).
pub(crate) fn masked_flags(row: &mut UserInfo) {
    row.is_muted = false;
    row.is_deafened = false;
    row.is_screen_sharing = false;
}

/// What a page of people may fill: a frame, less what goes around it.
pub(crate) const PAGE_BYTES: usize = 60 * 1024;
/// What a bare id costs a page at most.
const ID_BYTES: usize = 5;

/// What a row costs a page at most: its ids and flags, and its strings.
pub(crate) fn row_bytes(row: &UserInfo) -> usize {
    48 + row.username.len() + row.badges.iter().map(|b| b.len() + 5).sum::<usize>()
}

/// As many of `rows` as a page holds, and the rest.
pub fn cut_rows(mut rows: Vec<UserInfo>) -> (Vec<UserInfo>, Vec<UserInfo>) {
    let mut bytes = 0;
    let fit = rows
        .iter()
        .position(|r| {
            bytes += row_bytes(r);
            bytes > PAGE_BYTES
        })
        .unwrap_or(rows.len());
    let rest = rows.split_off(fit.max(1).min(rows.len()));
    (rows, rest)
}

/// The one admission decision. Returns whether an invite is what let them in —
/// the caller consumes it, which is the only difference between checking a
/// join and performing one.
///
/// Written once deliberately: this was three copies (`validate_join`,
/// `join_channel`, `join_text_channel`), which meant the channel password was
/// compared in three places and each of them had to keep agreeing about
/// hashed-vs-plaintext, about who bypasses it and about what "full" means.
fn check_admission(
    channel: &Channel,
    user_id: UserId,
    password: Option<&str>,
    passes_gate: bool,
    room_cap: u32,
) -> anyhow::Result<bool> {
    // Worded as for a channel that is not there: to someone outside its
    // groups, it is not (`gates`). No invite opens it either.
    if !passes_gate {
        anyhow::bail!("channel {} does not exist", channel.info.channel_id);
    }
    let is_invited = channel.invited_users.contains(&user_id);

    if !is_invited {
        if let Some(ref channel_pw) = channel.password {
            // A channel from channels.json keeps a hash, which the attempt
            // was checked against before the lock: what arrives here is that
            // hash, or nothing that matches (`channel_password_attempt`).
            // Channels people make keep the password as typed.
            let matches: bool = match password {
                Some(pw) => pw.as_bytes().ct_eq(channel_pw.as_bytes()).into(),
                None => false,
            };
            if !matches {
                anyhow::bail!("incorrect channel password");
            }
        }
    }

    // A voice room with no cap of its own takes `[media] voice_room`: each joiner there trades
    // keys with every member, and each voice packet is sent to each. A routed room sends each
    // only to who is near, and keeps no cap it was not given.
    let cap = match channel.info.max_users {
        0 if !channel.info.text && !channel.info.routed && channel.info.channel_id != 0 => room_cap,
        own => own,
    };
    if cap > 0 && channel.members.len() >= cap as usize {
        anyhow::bail!("channel is full");
    }

    Ok(is_invited)
}

/// The pseudonym `subject` goes by in whichever anonymous channel they stand in.
/// `ServerState::channel_seen_by` for a viewer already in hand: inside `sessions.iter()`, no
/// second `sessions.get` into the map the loop holds (DashMap's re-entry hazard).
pub(crate) fn channel_seen_as(info: &ChannelInfo, user_id: UserId, admin: bool) -> ChannelInfo {
    let mut info = info.clone();
    if info.anonymous && !admin && info.created_by.is_some() && info.created_by != Some(user_id) {
        info.created_by = None;
    }
    info
}

/// A row under a pseudonym, for someone who is not an admin: no role, privilege or history
/// switch of the person behind it. The shield, the moderator's mark and the history icon on
/// it named staff, and so narrowed who it could be, for every honest app (G1).
pub(crate) fn masked(row: &mut UserInfo) {
    row.is_admin = false;
    row.is_moderator = false;
    row.shares_history = false;
    row.badges.clear();
}

fn alias_anywhere(channels: &HashMap<ChannelId, Channel>, subject: UserId) -> Option<String> {
    channels.values().find_map(|ch| {
        (ch.info.anonymous && ch.members.contains(&subject))
            .then(|| ch.pseudonyms.get(&subject).cloned())
            .flatten()
    })
}

/// What a `set_channel_options` call actually moved. Both answers exist to
/// stop the caller paying for a change that did not happen: a client is free
/// to re-send the options a channel already has, and every one of those
/// announces itself to every session on the server, while an `anonymous` that
/// did not flip would additionally rebuild one roster per member.
#[derive(Debug, Default)]
pub struct OptionsChanged {
    /// Any option now holds a different value than it did.
    pub any: bool,
    /// `anonymous` in particular flipped, so the names the members go by here
    /// have all changed and their clients are holding the old ones.
    pub anonymity: bool,
}

/// How long `last` (a member's previous post) still holds them back in a
/// channel with `secs` of slow mode, in whole seconds rounded up; `None` when
/// they may post now.
///
/// Half a second of grace: the client counts the wait from when it sent, we
/// count it from when the previous post arrived, and the two posts need not
/// cross the network equally fast. Without it a client that waits exactly as
/// long as it was told is refused now and then.
pub fn slow_mode_wait(last: Option<Instant>, now: Instant, secs: u32) -> Option<u64> {
    if secs == 0 {
        return None;
    }
    let elapsed = now.saturating_duration_since(last?) + std::time::Duration::from_millis(500);
    let need = std::time::Duration::from_secs(secs.into());
    (elapsed < need).then(|| (need - elapsed).as_secs_f64().ceil().max(1.0) as u64)
}

/// The account behind a member, for one viewer: only where that viewer is
/// shown the real name, or to an admin. An account id is as good as the name
/// (any account can look its name up), so it may go no further than the name:
/// not behind a pseudonym, and not to the outsiders of a channel.
pub fn account_shown(
    account: Option<[u8; 16]>,
    sees_real_name: bool,
    viewer_is_admin: bool,
) -> Option<[u8; 16]> {
    if sees_real_name || viewer_is_admin {
        account
    } else {
        None
    }
}

/// The name one recipient may see: the pseudonym unless they are an admin.
pub fn pick_name(real: &str, alias: &Option<String>, viewer_is_admin: bool) -> String {
    match alias {
        Some(alias) if !viewer_is_admin => alias.clone(),
        _ => real.to_string(),
    }
}

/// A pseudonym for an anonymous channel, unique among the ones in use. Long enough
/// not to come round again: a removal goes by this name, and hides the copies of
/// whoever else once held it.
fn mint_pseudonym(taken: &HashMap<UserId, String>) -> String {
    for _ in 0..64 {
        let name = format!("Guest-{:08}", rand::random::<u32>() % 100_000_000);
        if !taken.values().any(|n| n == &name) {
            return name;
        }
    }
    // 64 collisions in a row means the channel is impossibly full; fall back
    // to something unique rather than looping.
    format!("Guest-{}", rand::random::<u32>())
}

/// Whether `name` has the shape `mint_pseudonym` gives. An account may be called
/// `guest-1234`, but stored in lower case: this capital is never an account's.
pub fn is_pseudonym(name: &str) -> bool {
    name.strip_prefix("Guest-")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The shared server state, designed for concurrent access.
/// Wrong admin or game tokens an address may present: 10, then one per 90 s.
/// One budget for both doors, per address (IPv4) or /64 (IPv6): a session
/// count reset by reconnecting, or none at all on the HTTP door, let a weak
/// token be guessed at line rate (1.0 audit H1-09).
pub const TOKEN_GUESSES: f64 = 10.0;
pub const TOKEN_GUESS_REFILL: f64 = 1.0 / 90.0;
/// The shortest admin or game token a server starts with.
pub const MIN_TOKEN_LEN: usize = 16;

pub struct ServerState {
    /// Wrong-token budgets (`TOKEN_GUESSES`), by `ConnLimits` key.
    pub token_failures: DashMap<IpAddr, RateLimiter>,
    /// The connection slots (`ConnLimits`): authentication moves a session
    /// into the main pool, its cleanup back.
    pub limits: Arc<crate::ConnLimits>,
    /// All active sessions, keyed by session_id — which is the user's
    /// user_id too (session.rs `authenticate`), so a user's session is
    /// `sessions.get(&user_id)`.
    pub sessions: DashMap<SessionId, UserSession>,
    /// Atomic username reservation: lowercase username -> session_id.
    pub username_to_session: DashMap<String, SessionId>,
    /// All channels, keyed by channel_id.
    pub channels: RwLock<HashMap<ChannelId, Channel>>,
    /// Where persistent channels sit (`crate::layout`).
    pub layout: RwLock<crate::layout::Layout>,
    /// Maximum concurrent users.
    pub max_users: u32,
    /// How many channels can exist here at once: the lobby, every channel from
    /// `channels.json`, and the user-created ones `max_channels` allows.
    ///
    /// Not a limit anybody is refused by — it is what the per-session budgets
    /// are sized from. A client may subscribe to every text channel on the
    /// server, so the budgets that pay for joining them, for handing each one a
    /// sender key and for asking each one's members for its history all have to
    /// be able to cover doing it once, on a server of any size.
    pub channel_budget: AtomicU32,
    /// Runtime settings.
    pub settings: ServerSettings,
    /// Admin token (from config, or generated at startup).
    pub admin_token: String,
    /// Argon2 runs for channel passwords at once (`channel_password_attempt`):
    /// each takes 19 MiB, so a flood of wrong ones waits instead.
    pub channel_kdf: tokio::sync::Semaphore,
    /// Bans in force (`crate::bans`), as kept in the database or `bans.json`.
    pub bans: DashMap<crate::bans::Key, crate::bans::Ban>,
    /// Restrictions in force (`crate::restrict`), as kept in the database, or
    /// here alone on a relay without accounts.
    pub restrictions: DashMap<crate::bans::Key, crate::restrict::Held>,
    /// When a guest at each address (`limit_key`) was first and last seen, while the
    /// wait for new members is on.
    pub guest_clocks: DashMap<IpAddr, crate::restrict::GuestClock>,
    /// Writers to tell on the next tick that someone they keyed is out of these channels
    /// (`session::send_exits`).
    pub prune_asks: crate::gates::PruneAsks,
    pub exits_due: DashMap<UserId, HashSet<ChannelId>>,
    /// Every account holding a privilege (`accounts::read_chat_mods`), as clients
    /// were last told. Stays empty on a relay without accounts.
    pub chat_mods: RwLock<Vec<voipc_protocol::types::ChatMod>>,
    /// Held by one `accounts::refresh_chat_mods` at a time, across its reads, so that two at
    /// once cannot end with the older one's answer; `chat_mods` only for the swap (W2-2).
    pub chat_mods_reading: tokio::sync::Mutex<()>,
    /// How often that list was read, for the tests.
    #[cfg(test)]
    pub chat_mods_reads: std::sync::atomic::AtomicUsize,
    /// Address bans' hash key on a relay without accounts (made at start).
    pub ban_salt: [u8; 32],
    /// `bans.json`, on a relay without accounts; None keeps bans in memory.
    pub bans_file: Option<std::path::PathBuf>,
    /// One writer of `bans.json` at a time.
    pub bans_writer: std::sync::Mutex<()>,
    /// Next user_id counter (session_id is always equal to user_id).
    next_user_id: AtomicU32,
    /// Next channel_id counter (0 is reserved for General).
    next_channel_id: AtomicU32,
    /// Who may hear whom, in channels whose `routed` flag is on. Empty on
    /// every other server, and that is the default.
    pub routing: crate::routing::Routing,
    /// Opt-in accounts; `None` when `[accounts] mode = "off"`.
    pub accounts: Option<Arc<crate::accounts::Relay>>,
    /// The importer's run in progress (`accounts::import`).
    pub import: tokio::sync::Mutex<Option<crate::accounts::import::ActiveRun>>,
    /// The live session of each signed-in account: a new sign-in replaces it.
    pub account_sessions: DashMap<[u8; 16], SessionId>,
    /// When each member last wrote in each slow-mode channel (`post_rules`).
    /// Here rather than on the channel, so leaving and coming back does not
    /// reset the clock; an account's goes across its connections.
    pub post_marks: DashMap<(ChannelId, Poster, PostStamp), Instant>,
    /// Who online may call on everybody (`accounts::holds_mention_power`), kept as it
    /// changes so a connect is not a walk of every session to find out.
    pub mention_holders: dashmap::DashSet<UserId>,
    /// The lobby's pages, watchers and size for live news (`lobby`, protocol v25).
    pub lobby: crate::lobby::Lobby,
    /// What screen shares may cost (`[media]`).
    pub media: crate::config::MediaConfig,
    /// The UDP port, whose socket's drops the Load view reads (`web::udp_drops`).
    pub udp_port: u16,
    /// Accounts on SQLite, which a very big relay outgrows (the Load view says so).
    pub sqlite_accounts: bool,
    /// `tcp_fallback`: whether `GET /voipc` is served (`tunnel::serve`).
    pub tcp_fallback: bool,
    /// The encrypted file cache; `None` with `[files] enabled = false`, and
    /// until main.rs has opened its directory (`files::FileStore::open`).
    pub files: Option<Arc<crate::files::FileStore>>,
    /// The server's emotes; `None` with `[emotes] enabled = false`, and until
    /// main.rs has opened their directory (`emotes::EmoteStore::open`).
    pub emotes: Option<Arc<crate::emotes::EmoteStore>>,
    /// Where each screen share's packets go, by sharer (`Fan`). The video path reads this
    /// and never `channels`.
    pub share_fans: DashMap<UserId, Fan>,
    /// When this state was made: the clock of `uptime_ms`.
    pub started: Instant,
    /// The media edges of `[pool]`; `None` without any.
    pub pool: Option<Arc<crate::pool::Pool>>,
    /// The group epoch key (`group_key`), and this start's run.
    pub gk: Arc<crate::gk::Groups>,
}

/// Which of a member's posts slow mode counts: the live message, or its copy
/// in the channel's stored log. Each has its own clock, so a post and its
/// copy do not hold each other back.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PostStamp {
    Live,
    Kept,
    /// Would a live post pass now? Starts no clock (`KeyCheck`).
    Check,
    /// Would a kept copy pass now? Starts no clock: what it comes to is up to the log.
    KeptCheck,
    /// May they hand out a key here? A check without slow mode: keys go out behind a post
    /// that has just started its clock (`OpenSessions`).
    Keys,
}

/// Who slow mode holds back: an account across every connection it makes (a
/// reconnect does not reset the clock), a guest per connection.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Poster {
    Account([u8; 16]),
    Session(SessionId),
}

/// `TextJoined`, in as many frames as it takes, and at least one: the answer is also how an
/// app knows it was heard.
/// A client's list of channels in order, each once.
fn each_once(ids: &[ChannelId]) -> Vec<ChannelId> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn send_text_joined(
    tx: &ControlTx,
    joined: Vec<(ChannelId, bool, bool, u64)>,
    mut refused: Vec<ChannelId>,
) {
    // In one order: what no gate was asked about comes first otherwise, and that says which
    // of them are channels someone cannot see
    refused.sort_unstable();
    // A row is at most 17 bytes, an id 5, and a frame holds 64 KiB
    let mut rows = joined.chunks(3000);
    let mut out = refused.chunks(10_000);
    loop {
        let _ = crate::session::send_msg(
            tx,
            &ServerMessage::TextJoined {
                joined: rows.next().unwrap_or_default().to_vec(),
                refused: out.next().unwrap_or_default().to_vec(),
            },
        );
        if rows.len() == 0 && out.len() == 0 {
            return;
        }
    }
}

impl ServerState {
    /// Take one token from one of a session's limiters: false when it is empty,
    /// or the session is gone.
    pub fn spend(
        &self,
        session_id: SessionId,
        limiter: impl FnOnce(&mut UserSession) -> &mut RateLimiter,
    ) -> bool {
        self.sessions
            .get_mut(&session_id)
            .is_some_and(|mut s| limiter(&mut s).try_consume())
    }

    /// Whether `ip` may present a token at all: it has wrong guesses left.
    pub fn token_guess_allowed(&self, ip: IpAddr) -> bool {
        self.token_failures
            .get_mut(&crate::limit_key(ip))
            .is_none_or(|mut b| b.has_token())
    }

    /// One wrong token from `ip`.
    pub fn token_guess_failed(&self, ip: IpAddr) {
        // Bounded like the connect-rate table: addresses whose budget is
        // whole again say nothing a new entry would not
        if self.token_failures.len() > 4096 {
            self.token_failures.retain(|_, b| !b.is_full());
        }
        self.token_failures
            .entry(crate::limit_key(ip))
            .or_insert_with(|| RateLimiter::new(TOKEN_GUESSES, TOKEN_GUESS_REFILL))
            .try_consume();
    }

    /// Create a new server state from the given configuration.
    pub fn new(
        config: &ServerConfig,
        settings: ServerSettings,
        persistent_channels: Vec<ChannelEntry>,
        admin_token: String,
    ) -> Self {
        let mut channels = HashMap::new();
        channels.insert(
            0,
            Channel {
                info: ChannelInfo {
                    channel_id: 0,
                    name: "General".into(),
                    description: "Lobby — no voice".into(),
                    ..Default::default()
                },
                members: HashSet::new(),
                password: None,
                delete_timer: None,
                invited_users: HashSet::new(),
                summons: HashMap::new(),
                screen_shares: HashMap::new(),
                persistent: false,
                pseudonyms: HashMap::new(),
                log_conv: String::new(),
                gate: ChannelGate::default(),
                gate_key: String::new(),
                kept: false,
                follow: Follow::default(),
            },
        );

        // A channel's stored-message log exists where accounts and storage
        // are on; `Channel::refresh_log` decides whether it is offered.
        let logs =
            config.accounts.mode != crate::config::AccountsMode::Off && config.accounts.cloud;

        // Insert persistent channels from channels.json with IDs starting at 1
        let mut next_id: u32 = 1;
        for entry in &persistent_channels {
            let channel_id = next_id;
            next_id += 1;

            channels.insert(
                channel_id,
                Channel::from_entry(entry, channel_id, logs, settings.proximity_enabled),
            );
            if let Some(ch) = channels.get_mut(&channel_id) {
                ch.refresh_log();
            }
        }

        Self {
            sessions: DashMap::new(),
            username_to_session: DashMap::new(),
            channels: RwLock::new(channels),
            layout: RwLock::default(),
            limits: Arc::new(crate::ConnLimits::from_config(config)),
            token_failures: DashMap::new(),
            max_users: config.max_users,
            channel_budget: AtomicU32::new(
                settings
                    .max_channels
                    .saturating_add(persistent_channels.len() as u32)
                    .saturating_add(1),
            ),
            settings,
            admin_token,
            channel_kdf: tokio::sync::Semaphore::new(2),
            bans: DashMap::new(),
            restrictions: DashMap::new(),
            guest_clocks: DashMap::new(),
            prune_asks: Default::default(),
            exits_due: DashMap::new(),
            chat_mods: RwLock::new(Vec::new()),
            chat_mods_reading: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            chat_mods_reads: Default::default(),
            ban_salt: rand::random(),
            bans_file: None,
            bans_writer: std::sync::Mutex::new(()),
            next_user_id: AtomicU32::new(1),
            next_channel_id: AtomicU32::new(next_id),
            routing: crate::routing::Routing::default(),
            accounts: None,
            import: tokio::sync::Mutex::new(None),
            account_sessions: DashMap::new(),
            post_marks: DashMap::new(),
            mention_holders: dashmap::DashSet::new(),
            lobby: crate::lobby::Lobby::new(config.live_lobby),
            media: config.media.clone(),
            udp_port: config.udp_port,
            sqlite_accounts: config.accounts.mode != crate::config::AccountsMode::Off
                && config.accounts.database.starts_with("sqlite"),
            tcp_fallback: config.tcp_fallback,
            files: None,
            emotes: None,
            share_fans: DashMap::new(),
            started: Instant::now(),
            pool: crate::pool::Pool::new(&config.pool).map(Arc::new),
            gk: Arc::new(crate::gk::Groups::new(config.group_key)),
        }
    }

    /// Milliseconds since this state was made, on a clock no change of the wall clock moves.
    pub fn uptime_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// A state for tests, with the default settings.
    #[cfg(test)]
    pub fn for_tests() -> ServerState {
        ServerState::new(
            &crate::config::ServerConfig::default(),
            crate::settings::ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        )
    }

    /// Whether this session may write in `channel_id` now, live or into the
    /// channel's stored log: a member there, the announcement rule, and slow
    /// mode, whose clock starts when the post passes. Neither rule needs to
    /// read a post: who writes where, and when, is all they are about, and
    /// the relay has always seen that much. The channel's managers are held
    /// to neither.
    pub async fn post_rules(
        &self,
        session_id: SessionId,
        user_id: UserId,
        channel_id: ChannelId,
        stamp: PostStamp,
    ) -> Result<(), String> {
        if channel_id == 0 {
            return Err("Chat is not available in the lobby".into());
        }
        // The sender names the channel (they may be in several text channels
        // at once), so membership is what decides whether they may write there.
        if !self.is_member(channel_id, user_id).await {
            return Err("you are not in that channel".into());
        }
        let rules = {
            let channels = self.channels.read().await;
            channels.get(&channel_id).map(|c| {
                (
                    c.info.announce,
                    c.info.slow_mode_secs,
                    c.info.created_by,
                    c.info.name.clone(),
                )
            })
        };
        let Some((announce, slow_mode_secs, created_by, name)) = rules else {
            return Err("you are not in that channel".into());
        };
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|s| s.listen_only.contains(&channel_id))
        {
            return Err(format!("you can only read in #{name}"));
        }
        // Before the managers' pass below, which would let them through, and
        // before slow mode's clock, which a refused post must not start
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|s| s.silence.text())
        {
            return Err(crate::restrict::TEXT_HELD.into());
        }
        if !(announce || slow_mode_secs > 0) || self.may_manage(session_id, created_by) {
            return Ok(());
        }
        if announce {
            return Err(format!("only moderators can post in #{name}"));
        }
        if stamp == PostStamp::Keys {
            return Ok(());
        }
        // A hide is a post the relay cannot tell from any other, and slow mode
        // must not hold back taking something down
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|s| crate::accounts::holds_hide(&s))
        {
            return Ok(());
        }
        let poster = match self.sessions.get(&session_id).and_then(|s| s.account_id()) {
            Some(a) => Poster::Account(a),
            None => Poster::Session(session_id),
        };
        let clock = match stamp {
            PostStamp::Check => PostStamp::Live,
            PostStamp::KeptCheck => PostStamp::Kept,
            other => other,
        };
        let key = (channel_id, poster, clock);
        let now = Instant::now();
        if let Some(wait) =
            slow_mode_wait(self.post_marks.get(&key).map(|t| *t), now, slow_mode_secs)
        {
            return Err(format!("slow mode in #{name}: wait {wait} s"));
        }
        if matches!(stamp, PostStamp::Check | PostStamp::KeptCheck) {
            return Ok(());
        }
        // Nothing older than the longest slow mode can still hold anybody back.
        let longest = std::time::Duration::from_secs(MAX_SLOW_MODE_SECS.into());
        self.post_marks
            .retain(|_, t| now.saturating_duration_since(*t) < longest);
        self.post_marks.insert(key, now);
        Ok(())
    }

    /// Forget every routing decision for one channel. Called when its `routed`
    /// flag goes off, so the switch hands everybody back at once rather than
    /// leaving a stale table deciding who is audible.
    ///
    /// `members` are the people standing in it right now: their own "these are
    /// the ones I want to hear" requests belong to the channel as much as the
    /// game server's table does, and a filter left behind would be enforced
    /// again the moment somebody switched routing back on.
    pub fn clear_routing(&self, channel_id: ChannelId, members: impl IntoIterator<Item = UserId>) {
        let sessions = members
            .into_iter()
            .filter(|uid| self.sessions.contains_key(uid));
        self.routing.clear_channel(channel_id, sessions);
    }

    /// Allocate a new unique user ID.
    ///
    /// The session ID is always identical to the user ID (one counter): the
    /// client keys per-user volume and speaking indicators by the session_id
    /// carried in voice packets, while the UI only knows user_ids.
    pub fn next_user_id(&self) -> UserId {
        self.next_user_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate a new unique channel ID.
    pub fn next_channel_id(&self) -> ChannelId {
        self.next_channel_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Get the total number of connected users.
    pub fn user_count(&self) -> usize {
        self.sessions.len()
    }

    // ── Moderation ─────────────────────────────────────────────────────

    /// The session holds the privilege (or is an admin).
    pub fn can(&self, session_id: SessionId, p: crate::accounts::Powers) -> bool {
        self.sessions.get(&session_id).is_some_and(|s| s.can(p))
    }

    /// Whoever may change a channel's settings: its creator (`created_by`), or
    /// someone with `voipc:channels`. They are also the ones an announcement
    /// channel lets post and slow mode does not hold back.
    pub fn may_manage(&self, session_id: SessionId, created_by: Option<UserId>) -> bool {
        self.sessions.get(&session_id).is_some_and(|s| {
            s.can(crate::accounts::Powers::CHANNELS) || created_by == Some(s.user_id)
        })
    }

    /// Whether the session is logged in as admin.
    pub fn is_admin(&self, session_id: SessionId) -> bool {
        self.sessions
            .get(&session_id)
            .map(|s| s.is_admin)
            .unwrap_or(false)
    }

    /// Broadcast a raw serialized message to all connected sessions.
    pub async fn broadcast_raw_to_all(&self, data: &[u8]) {
        let data = bytes::Bytes::copy_from_slice(data);
        for entry in self.sessions.iter() {
            let _ = entry.value().control_tx.try_send(data.clone());
        }
    }

    /// A channel as `viewer` is told of it. An anonymous room names its creator only to them
    /// and to admins: the crown on the first pseudonym, and the creator's join right after
    /// `ChannelCreated`, tied it to a name for every honest app (G1).
    pub fn channel_seen_by(&self, info: &ChannelInfo, viewer: SessionId) -> ChannelInfo {
        let (user_id, admin) = self
            .sessions
            .get(&viewer)
            .map_or((0, false), |s| (s.user_id, s.is_admin));
        channel_seen_as(info, user_id, admin)
    }

    /// The channels `session_id` may see: every one whose gate they pass.
    pub async fn channel_list_for(&self, session_id: SessionId) -> Vec<ChannelInfo> {
        let channels = self.channels.read().await;
        let mut list: Vec<ChannelInfo> = channels
            .values()
            .filter(|ch| self.passes(session_id, &ch.gate.groups))
            .map(|ch| self.channel_seen_by(&ch.info, session_id))
            .collect();
        list.sort_by_key(|ch| ch.channel_id);
        list
    }

    /// Whether the member passes these groups (`gates::passes`); someone
    /// who has gone passes only an open gate.
    pub fn passes(&self, user_id: UserId, groups: &[String]) -> bool {
        groups.is_empty()
            || self
                .sessions
                .get(&user_id)
                .is_some_and(|s| crate::gates::passes(&s, groups))
    }

    /// False for a channel whose gate this session is outside, and for none at all:
    /// one answer for both, or the answer says which channels exist.
    pub async fn may_reach(&self, session_id: SessionId, channel_id: ChannelId) -> bool {
        self.channels
            .read()
            .await
            .get(&channel_id)
            .is_some_and(|c| self.passes(session_id, &c.gate.groups))
    }

    /// Get a snapshot of all channel info (for sending to clients).
    pub async fn channel_list(&self) -> Vec<ChannelInfo> {
        let channels = self.channels.read().await;
        let mut list: Vec<ChannelInfo> = channels.values().map(|ch| ch.info.clone()).collect();
        list.sort_by_key(|ch| ch.channel_id);
        list
    }

    /// Get users in a specific channel, as `viewer` may see them: in an
    /// anonymous channel a non-admin viewer gets the members' pseudonyms.
    pub async fn users_in_channel_for(
        &self,
        channel_id: ChannelId,
        viewer_session: SessionId,
    ) -> Vec<UserInfo> {
        let channels = self.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return Vec::new();
        };
        let anonymous = channel.info.anonymous && !self.is_admin(viewer_session);
        let viewer = self.sessions.get(&viewer_session).map(|s| s.user_id);

        channel
            .members
            .iter()
            .filter_map(|&uid| {
                let session = self.sessions.get(&uid)?;
                let username = match anonymous.then(|| channel.pseudonyms.get(&uid)).flatten() {
                    Some(alias) => alias.clone(),
                    None => session.username.clone(),
                };
                // Never under a pseudonym: it would name the account.
                let account = account_shown(session.account_id(), !anonymous, false);
                let mut row = session.row_in(channel_id, username, account);
                // Their own row as it is: their app reads its own switches off it
                if anonymous && Some(uid) != viewer {
                    masked(&mut row);
                }
                Some(row)
            })
            .collect()
    }

    /// Whether a channel shows its members under pseudonyms.
    pub async fn is_anonymous_channel(&self, channel_id: ChannelId) -> bool {
        let channels = self.channels.read().await;
        channels
            .get(&channel_id)
            .is_some_and(|ch| ch.info.anonymous)
    }

    /// Check if a join would succeed (password, capacity) without modifying state.
    /// Invited users bypass the password check.
    /// For a channel from channels.json, which keeps a hash: the hash itself
    /// when `attempt` is its password, else an empty string, which matches
    /// nothing. Run before the channel lock is taken, since Argon2 takes tens
    /// of milliseconds; `check_admission` then compares what it is given.
    /// Other channels get the attempt as typed.
    pub async fn channel_password_attempt(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        attempt: Option<&str>,
    ) -> Option<Zeroizing<String>> {
        let attempt = Zeroizing::new(attempt?.to_string());
        let stored = match self.channels.read().await.get(&channel_id) {
            // Outside its gate it is not there: nothing to hash, and nothing that could match
            Some(c) if c.persistent && !self.passes(user_id, &c.gate.groups) => {
                return Some(Zeroizing::new(String::new()));
            }
            Some(c) if c.persistent => c.password.clone(),
            _ => None,
        };
        let Some(stored) = stored else {
            return Some(attempt);
        };
        let Ok(_turn) = self.channel_kdf.acquire().await else {
            return Some(Zeroizing::new(String::new()));
        };
        let hash = stored.clone();
        let ok =
            tokio::task::spawn_blocking(move || crate::channels::verify_password(&attempt, &hash))
                .await
                .unwrap_or(false);
        Some(if ok {
            stored
        } else {
            Zeroizing::new(String::new())
        })
    }

    pub async fn validate_join(
        &self,
        channel_id: ChannelId,
        password: Option<&str>,
        user_id: UserId,
    ) -> anyhow::Result<()> {
        let channels = self.channels.read().await;
        let channel = channels
            .get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel {} does not exist", channel_id))?;

        // The invite is left where it is: this decides nothing, so it must
        // not spend anything either.
        check_admission(
            channel,
            user_id,
            password,
            self.passes(user_id, &channel.gate.groups),
            self.media.voice_room,
        )?;

        Ok(())
    }

    /// Add a user to a channel with optional password.
    /// Invited users bypass the password check automatically.
    /// Returns the list of other members' session_ids for notification.
    pub async fn join_channel(
        &self,
        user_id: UserId,
        session_id: SessionId,
        channel_id: ChannelId,
        password: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut channels = self.channels.write().await;

        // Read under the lock, which is the only place `channel_id` changes.
        // A session that has gone is refused: its cleanup has run, or runs
        // next, against the channel it names, so a join now would leave an id
        // behind that nothing removes (S-002).
        let previous = self
            .sessions
            .get(&session_id)
            .map(|s| s.channel_id)
            .ok_or_else(|| anyhow::anyhow!("session {} has gone", session_id))?;

        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel {} does not exist", channel_id))?;

        // An invite is spent by the join it paid for, not by a join that was
        // refused for some other reason — so it is consumed only here, once
        // the admission has been granted in full.
        let passes = self.passes(user_id, &channel.gate.groups);
        if check_admission(channel, user_id, password, passes, self.media.voice_room)? {
            channel.end_invite(user_id);
        }
        let speakers = channel.gate.speakers.clone();

        // Cancel any pending delete timer
        if let Some(timer) = channel.delete_timer.take() {
            timer.abort();
        }

        channel.members.insert(user_id);
        channel.info.user_count = channel.members.len() as u32;

        // In an anonymous channel this is the only name the other members
        // ever learn; it lasts as long as this visit.
        if channel.info.anonymous {
            let name = mint_pseudonym(&channel.pseudonyms);
            channel.pseudonyms.insert(user_id, name);
        }

        // Update the session's channel_id, and whether they may speak in it:
        // under this lock, so no voice gets past before it is known
        let mut account = None;
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            session.channel_id = channel_id;
            let listen = !crate::gates::passes(&session, &speakers);
            crate::gates::mark(&mut session.listen_only, channel_id, listen);
            account = session.account_id();
        }
        self.gk_room_join(channel, user_id, account);
        // A voice room is one at a time. The caller leaves the old one first
        // (and tells its members); this is for a move that landed in between,
        // a kick's to General, which would otherwise leave them in both.
        if previous != channel_id {
            if let Some(old) = channels.get_mut(&previous).filter(|c| !c.info.text) {
                if old.members.remove(&user_id) {
                    old.info.user_count = old.members.len() as u32;
                    old.pseudonyms.remove(&user_id);
                    self.gk_room_leave(old, user_id, gk_cause::LEAVE);
                }
            }
        }
        // Whatever they asked to hear belonged to the channel they were in.
        // Carrying it over would cull the new one by a list that means nothing
        // there — and we would be holding a stale answer about somebody who
        // has left, which is exactly what this server should not be keeping.
        self.routing.clear_session(session_id);

        Ok(())
    }

    /// Whether a channel exists and is a text channel.
    pub async fn is_text_channel(&self, channel_id: ChannelId) -> bool {
        let channels = self.channels.read().await;
        channels.get(&channel_id).is_some_and(|ch| ch.info.text)
    }

    /// Whether a user is in a channel — the one question that means the same
    /// thing for a voice room and a text channel's subscribers.
    pub async fn is_member(&self, channel_id: ChannelId, user_id: UserId) -> bool {
        let channels = self.channels.read().await;
        channels
            .get(&channel_id)
            .is_some_and(|ch| ch.members.contains(&user_id))
    }

    /// Subscribe a user to a text channel.
    ///
    /// Unlike `join_channel` this adds rather than moves: `session.channel_id`
    /// keeps naming the voice channel the user stands in, and the routing
    /// filter — which is about voice — is left alone. Joining twice is a
    /// no-op, so a client re-sending an auto-join costs nothing.
    ///
    /// There is no per-user limit on how many of these one session holds.
    /// There was one until 0.9.0 — sixteen — to stop a connection creating
    /// channels and subscribing to every one so that none of them ever emptied
    /// and expired. That is now answered where the problem is: a channel starts
    /// its delete timer when it is created, so an unjoined one goes away on its
    /// own. A cap here only ever cost the user, who cannot know how many
    /// conversations a server means them to follow.
    ///
    /// Returns `true` if this was a new membership.
    pub async fn join_text_channel(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
        password: Option<&str>,
    ) -> anyhow::Result<bool> {
        let mut channels = self.channels.write().await;

        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel {} does not exist", channel_id))?;

        if !channel.info.text {
            anyhow::bail!("channel {} is not a text channel", channel_id);
        }

        if channel.members.contains(&user_id) {
            return Ok(false);
        }

        let passes = self.passes(user_id, &channel.gate.groups);
        if check_admission(channel, user_id, password, passes, self.media.voice_room)? {
            channel.end_invite(user_id);
        }
        if let Some(mut session) = self.sessions.get_mut(&user_id) {
            let listen = !crate::gates::passes(&session, &channel.gate.speakers);
            crate::gates::mark(&mut session.listen_only, channel_id, listen);
        }

        if let Some(timer) = channel.delete_timer.take() {
            timer.abort();
        }

        channel.members.insert(user_id);
        channel.info.user_count = channel.members.len() as u32;
        // No pseudonym to mint: a text channel cannot be anonymous, because
        // its members are in other channels at the same time where the same
        // user id carries their real name (see `create_channel`).

        Ok(true)
    }

    /// Follows these text channels, whole or quiet, in one write of the channel map, and
    /// answers under it, so nothing about them overtakes the answer. It tells nobody else.
    /// Each passes the admission a join does, with no password; an id it fails, a voice room
    /// or nothing at all is `refused`, in the same words. Past a gate only `*` opens, it is
    /// refused too: a person walks into that by a click, never their app.
    pub async fn follow_text_channels(
        &self,
        user_id: UserId,
        whole: &[ChannelId],
        quiet: &[ChannelId],
        tx: &ControlTx,
    ) {
        // Every room's voice queues behind the write lock, and one frame names some 60,000
        // ids. Only text channels there are get that far, each once, so it holds for no more
        // than the server has. No count cuts the rest off, which would tell a guest how many
        // channels there are, hidden ones too: they go back as refused, about as long as asked.
        let quiet = each_once(quiet);
        let mut whole = each_once(whole);
        whole.retain(|id| quiet.binary_search(id).is_err());
        let mut refused = Vec::new();
        let (whole, quiet) = {
            let channels = self.channels.read().await;
            let mut real = |ids: Vec<ChannelId>| -> Vec<ChannelId> {
                let (real, rest) = ids
                    .into_iter()
                    .partition(|id| channels.get(id).is_some_and(|c| c.info.text));
                refused.extend::<Vec<ChannelId>>(rest);
                real
            };
            (real(whole), real(quiet))
        };
        if whole.is_empty() && quiet.is_empty() {
            send_text_joined(tx, Vec::new(), refused);
            return;
        }
        let mut channels = self.channels.write().await;
        let Some(mut session) = self.sessions.get_mut(&user_id) else {
            return;
        };
        let mut joined = Vec::new();
        let asked = whole
            .iter()
            .map(|id| (*id, false))
            .chain(quiet.iter().map(|id| (*id, true)));
        for (channel_id, go_quiet) in asked {
            let Some(channel) = channels.get_mut(&channel_id).filter(|c| c.info.text) else {
                refused.push(channel_id);
                continue;
            };
            if !channel.members.contains(&user_id) {
                let passes = crate::gates::passes_without_star(&session, &channel.gate.groups);
                match check_admission(channel, user_id, None, passes, self.media.voice_room) {
                    Ok(invited) => {
                        if invited {
                            channel.end_invite(user_id);
                        }
                    }
                    Err(_) => {
                        refused.push(channel_id);
                        continue;
                    }
                }
                if let Some(timer) = channel.delete_timer.take() {
                    timer.abort();
                }
                channel.members.insert(user_id);
                channel.info.user_count = channel.members.len() as u32;
            }
            channel.follow.set(user_id, go_quiet);
            let listen = !crate::gates::passes(&session, &channel.gate.speakers);
            crate::gates::mark(&mut session.listen_only, channel_id, listen);
            joined.push(channel.seat_row(listen));
            self.gk_follow(channel, user_id, session.account_id());
        }
        drop(session);
        send_text_joined(tx, joined, refused);
    }

    /// A text channel's group id (spec §11.1): `c:` its offered log, else `r:`.
    pub(crate) fn gk_id(&self, channel: &Channel) -> String {
        let log = Some(channel.info.log.as_str()).filter(|l| !l.is_empty());
        self.gk.id_for(channel.info.channel_id, log)
    }

    /// A follower of a text channel, whole or quiet, follows its group (plan 2a). The
    /// channel's gate goes first where the group key does not hold it yet (a channel loaded
    /// or made with one): the group, whichever path started it, holds it before any due.
    fn gk_follow(&self, channel: &Channel, user_id: UserId, account: Option<[u8; 16]>) {
        if !self.gk.on {
            return;
        }
        let (channel_id, id) = (channel.info.channel_id, self.gk_id(channel));
        if self.gk.gated(channel_id) != channel.gated() {
            self.gk.on_gate(channel_id, channel.gated());
        }
        self.gk
            .on_follow(channel_id, &id, GroupKind::Text, user_id, account);
    }

    /// A member of a voice room follows its group from its join on (plan part 5), the
    /// channel's gate told first as `gk_follow` tells it. The lobby carries no voice.
    fn gk_room_join(&self, channel: &Channel, user_id: UserId, account: Option<[u8; 16]>) {
        let channel_id = channel.info.channel_id;
        if !self.gk.on || channel.info.text || channel_id == 0 {
            return;
        }
        if self.gk.gated(channel_id) != channel.gated() {
            self.gk.on_gate(channel_id, channel.gated());
        }
        self.gk
            .on_room_join(channel_id, user_id, account, channel.info.anonymous);
    }

    /// Out of a voice room, already taken out of its members: its seat exits, with `cause`,
    /// and the room's group goes once nobody is left in it.
    fn gk_room_leave(&self, channel: &Channel, user_id: UserId, cause: u8) {
        if !self.gk.on || channel.info.text {
            return;
        }
        let empty = channel.members.is_empty();
        self.gk
            .on_room_leave(channel.info.channel_id, user_id, cause, empty);
    }

    /// Takes followed channels whole or quiet. Going quiet is no exit: nobody rotates, and
    /// the first stamp stays. Going whole is a new stamp, so writers name them at their next
    /// post, and is answered. An id this session does not follow changes nothing.
    pub async fn set_quiet(&self, user_id: UserId, ids: &[ChannelId], quiet: bool, tx: &ControlTx) {
        // As `follow_text_channels`: only what they follow reaches the write lock, each once
        let (ids, mut refused): (Vec<ChannelId>, Vec<ChannelId>) = {
            let channels = self.channels.read().await;
            each_once(ids)
                .into_iter()
                .partition(|id| channels.get(id).is_some_and(|c| c.follow.holds(user_id)))
        };
        if ids.is_empty() {
            if !quiet {
                send_text_joined(tx, Vec::new(), refused);
            }
            return;
        }
        let mut channels = self.channels.write().await;
        let mut joined = Vec::new();
        for channel_id in ids {
            match channels
                .get_mut(&channel_id)
                .filter(|c| c.follow.holds(user_id))
            {
                Some(channel) => {
                    channel.follow.set(user_id, quiet);
                    let listen = self
                        .sessions
                        .get(&user_id)
                        .is_some_and(|s| s.listen_only.contains(&channel_id));
                    joined.push(channel.seat_row(listen));
                }
                None => refused.push(channel_id),
            }
        }
        if !quiet {
            send_text_joined(tx, joined, refused);
        }
    }

    /// Who `writer` owes a key in `channel_id`, as `KeysOwed` frames carry them: `(ids,
    /// rows)`. From here on their posts reach everyone named. `None`: not a text channel.
    pub async fn keys_owed(
        &self,
        channel_id: ChannelId,
        writer: UserId,
        restart: bool,
    ) -> Option<Vec<(Vec<UserId>, Vec<UserInfo>)>> {
        // Walked under the read lock, which voice shares; the map is written after, and a
        // join in between has a later stamp, so it is owed next time.
        let (frames, upto, known) = {
            let channels = self.channels.read().await;
            let channel = channels.get(&channel_id).filter(|c| c.info.text)?;
            let (ids, upto) = channel.follow.owed(writer, restart);
            let known = channel
                .follow
                .keyed
                .get(&writer)
                .is_some_and(|k| *k >= upto);
            let mut frames = Vec::new();
            let mut left = ids.as_slice();
            while !left.is_empty() {
                let (bare, rows, used) = self.member_frame(&channels, channel_id, left);
                frames.push((bare, rows));
                left = &left[used..];
            }
            (frames, upto, known)
        };
        if !known {
            if let Some(channel) = self.channels.write().await.get_mut(&channel_id) {
                if channel.members.contains(&writer) {
                    let keyed = channel.follow.keyed.entry(writer).or_insert(0);
                    *keyed = upto.max(*keyed);
                }
            }
        }
        Some(frames)
    }

    /// As much of `ids` as a frame holds: a bare id for someone a public list names, a row
    /// for anyone else. How many of `ids` that used up.
    fn member_frame(
        &self,
        channels: &HashMap<ChannelId, Channel>,
        channel_id: ChannelId,
        ids: &[UserId],
    ) -> (Vec<UserId>, Vec<UserInfo>, usize) {
        let (mut bare, mut rows, mut bytes) = (Vec::new(), Vec::new(), 0);
        for (used, uid) in ids.iter().enumerate() {
            let Some(session) = self.sessions.get(uid) else {
                continue;
            };
            // Since 25 no app holds the lobby whole: someone standing there goes as a row
            let public = session.channel_id != 0
                && channels
                    .get(&session.channel_id)
                    .is_some_and(list_is_public);
            // Standing in an anonymous room: what it does there is not told under the name
            // here, or a mute or a share there and here at once ties the two (G1)
            let masked_room = channels
                .get(&session.channel_id)
                .is_some_and(|c| c.info.anonymous);
            let row = (!public).then(|| {
                // A text channel never has a pseudonym: this name is the one it has always
                // told its members.
                let account = account_shown(session.account_id(), true, false);
                let mut row = session.row_in(channel_id, session.username.clone(), account);
                if masked_room {
                    masked_flags(&mut row);
                }
                row
            });
            bytes += row.as_ref().map_or(ID_BYTES, row_bytes);
            if bytes > PAGE_BYTES && used > 0 {
                return (bare, rows, used);
            }
            match row {
                Some(row) => rows.push(row),
                None => bare.push(*uid),
            }
        }
        (bare, rows, ids.len())
    }

    /// One page of who is in a channel, from past `after`, for `viewer`, whose asking has been
    /// allowed: `(ids, rows, next, total)`.
    pub async fn channel_page(
        &self,
        channel_id: ChannelId,
        viewer: SessionId,
        after: UserId,
    ) -> (Vec<UserId>, Vec<UserInfo>, UserId, u32) {
        let text = {
            let channels = self.channels.read().await;
            match channels.get(&channel_id).filter(|c| c.info.text) {
                Some(channel) => {
                    let mut all: Vec<UserId> = channel
                        .members
                        .iter()
                        .copied()
                        .filter(|uid| self.sessions.contains_key(uid))
                        .collect();
                    all.sort_unstable();
                    let total = all.len() as u32;
                    let from = all.partition_point(|uid| *uid <= after);
                    let left = &all[from..];
                    let (ids, rows, used) = self.member_frame(&channels, channel_id, left);
                    let next = if used < left.len() { left[used - 1] } else { 0 };
                    Some((ids, rows, next, total))
                }
                None => None,
            }
        };
        if let Some(page) = text {
            return page;
        }
        let mut users = self.users_in_channel_for(channel_id, viewer).await;
        let total = users.len() as u32;
        users.retain(|u| u.user_id > after);
        users.sort_unstable_by_key(|u| u.user_id);
        let (rows, rest) = cut_rows(users);
        let next = if rest.is_empty() {
            0
        } else {
            rows.last().map_or(0, |u| u.user_id)
        };
        (Vec::new(), rows, next, total)
    }

    /// Puts an exit from `channel_id` on the next tick for the writers who keyed that
    /// follower (`session::send_exits`). The channel lock is what keeps it in step.
    fn exit_due(&self, channel_id: ChannelId, follow: &Follow, first: u64) {
        for writer in follow.who_keyed(first) {
            self.exits_due.entry(writer).or_default().insert(channel_id);
        }
    }

    /// Unsubscribe a user from a text channel. Returns the remaining member
    /// count, or `None` if they were not in it (or it is not a text channel).
    pub async fn leave_text_channel(
        &self,
        user_id: UserId,
        channel_id: ChannelId,
    ) -> Option<usize> {
        let mut channels = self.channels.write().await;
        let channel = channels.get_mut(&channel_id)?;
        if !channel.info.text || !channel.members.remove(&user_id) {
            return None;
        }
        channel.info.user_count = channel.members.len() as u32;
        channel.pseudonyms.remove(&user_id);
        if let Some(first) = channel.follow.remove(user_id) {
            self.exit_due(channel_id, &channel.follow, first);
        }
        self.gk.on_unfollow(channel_id, user_id);
        Some(channel.members.len())
    }

    /// Drop every text subscription a user holds (on disconnect).
    /// Returns each channel left and how many members it has left.
    pub async fn leave_all_text_channels(&self, user_id: UserId) -> Vec<(ChannelId, usize)> {
        // Going offline tells no one: a chain's age covers it. Being put out does.
        let ejected = self.sessions.get(&user_id).is_some_and(|s| s.ejected);
        let mut channels = self.channels.write().await;
        let mut left = Vec::new();
        for channel in channels.values_mut() {
            if !channel.info.text || !channel.members.remove(&user_id) {
                continue;
            }
            channel.info.user_count = channel.members.len() as u32;
            channel.pseudonyms.remove(&user_id);
            if let Some(first) = channel.follow.remove(user_id) {
                if ejected {
                    self.exit_due(channel.info.channel_id, &channel.follow, first);
                }
            }
            // Put out, their seat exits at once; going offline is the group's to judge
            // (`on_session_end`: an account's text seat stays)
            if ejected {
                self.gk
                    .on_kick(channel.info.channel_id, user_id, gk_cause::KICK);
            }
            left.push((channel.info.channel_id, channel.members.len()));
        }
        left
    }

    /// Remove a user from their current channel.
    /// Returns (channel_id, remaining_session_ids, remaining_member_count).
    pub async fn leave_current_channel(
        &self,
        user_id: UserId,
        session_id: SessionId,
    ) -> Option<(ChannelId, usize)> {
        let mut channels = self.channels.write().await;
        // Under the lock: a kick moves the session to General under it, and a
        // `channel_id` read before would leave the wrong room (S-002).
        let channel_id = self.sessions.get(&session_id)?.channel_id;
        let channel = channels.get_mut(&channel_id)?;

        // If the user isn't actually in this channel's member set, nothing to leave
        if !channel.members.remove(&user_id) {
            return None;
        }
        channel.info.user_count = channel.members.len() as u32;
        self.gk_room_leave(channel, user_id, gk_cause::LEAVE);
        // Coming back means a new pseudonym, which is the point
        channel.pseudonyms.remove(&user_id);
        // Whatever they asked to hear belonged to this channel. `join_channel`
        // clears it on the way in; this is the way out that does not go through
        // one — stepping back into the lobby — and a stale answer about people
        // somebody has left is exactly what this server should not be keeping.
        self.routing.clear_session(session_id);
        Some((channel_id, channel.members.len()))
    }

    /// Remove a user session entirely (on disconnect).
    pub async fn remove_session(&self, session_id: SessionId) -> Option<UserSession> {
        let (_, session) = self.sessions.remove(&session_id)?;

        self.routing.clear_session(session_id);
        // Out of every group it followed, its volunteering and its commit lane with it
        self.gk.on_session_end(session_id);
        // Only if it is still ours: an account signing in again elsewhere
        // took the name over, and this cleanup runs after that.
        self.username_to_session
            .remove_if(&session.username.to_lowercase(), |_, sid| {
                *sid == session_id
            });
        if let Some(a) = &session.account {
            self.account_sessions
                .remove_if(&a.user.id.0, |_, sid| *sid == session_id);
        }
        self.mention_holders.remove(&session.user_id);
        self.lobby.watchers.remove(&session.user_id);
        // A guest's slow-mode clock goes with its connection; an account's stays.
        self.post_marks
            .retain(|(_, p, _), _| *p != Poster::Session(session_id));

        // Remove from channel
        let mut channels = self.channels.write().await;
        if let Some(channel) = channels.get_mut(&session.channel_id) {
            if channel.members.remove(&session.user_id) {
                self.gk_room_leave(channel, session.user_id, gk_cause::DISCONNECT);
            }
            channel.info.user_count = channel.members.len() as u32;
        }
        // Unanswered invites would otherwise pin the user_id in every
        // channel's invite set forever (ids are never reused) and fill the cap.
        for channel in channels.values_mut() {
            channel.end_invite(session.user_id);
        }
        // The fans hold media queues themselves, so this one comes out of any it is still in
        // (the share cleanup takes it out of `viewers` first, on every path that has one).
        // Out of the share too, or an edge would keep its seat and its ticket. A share of its
        // own sends nothing more: its packets came on this connection.
        self.share_fans.remove(&session.user_id);
        for (&channel_id, channel) in channels.iter_mut() {
            for share in channel.screen_shares.values_mut() {
                if share.drop_viewer(session.user_id, self.pool.as_deref()) {
                    self.refan(channel_id, share);
                }
            }
        }
        // Not swept from everybody else's `key_relay_rate` and `session_asked` here: a walk
        // of every session under this lock stalled every voice packet at each disconnect.
        // Those prune themselves (`may_relay_key_to`, `MAX_ASKED`).
        Some(session)
    }

    /// Create a new user-created channel.
    pub async fn create_channel(
        &self,
        name: String,
        password: Option<String>,
        proximity: ProximityMode,
        anonymous: bool,
        text: bool,
        created_by: UserId,
    ) -> anyhow::Result<ChannelInfo> {
        // A text channel has no voice, so no mode and no screen share.
        let proximity = if text { ProximityMode::Off } else { proximity };
        // Pseudonyms only hide a member who is nowhere else: user ids are the
        // same everywhere, and a text channel is one you are in *besides* the
        // voice channel you stand in, so anyone could match the two rosters up.
        if text && anonymous {
            anyhow::bail!("a text channel cannot be anonymous");
        }
        if proximity != ProximityMode::Off && !self.settings.proximity_enabled {
            anyhow::bail!("proximity chat is disabled on this server");
        }

        let mut channels = self.channels.write().await;

        // Count only user-created channels (exclude General and persistent channels)
        let user_channels = channels
            .values()
            .filter(|ch| !ch.persistent && ch.info.channel_id != 0)
            .count();
        if user_channels >= self.settings.max_channels as usize {
            anyhow::bail!("maximum number of channels reached");
        }

        // Check for duplicate names, ignoring case as channels.json does: a
        // made-up "Announcements" beside the real "announcements" is a look-alike.
        // By the one rule a channel made in the panel goes by, where a text channel
        // may share the lobby's name (W3-32)
        let lower = name.to_lowercase();
        if crate::layout::name_taken(&channels, &lower, text, None) {
            anyhow::bail!("a channel with that name already exists");
        }

        let channel_id = self.next_channel_id();
        // Guard the insert, not the counter. An id that is already in the map
        // means the counter wrapped and came back round to something live —
        // and the first id it comes back to is 0, which is General. Inserting
        // over it would delete the lobby and every membership in it, so refuse
        // the creation instead; the counter is the thing that is broken, and
        // the map is where that becomes visible.
        if channels.contains_key(&channel_id) {
            anyhow::bail!("channel id {} is already in use", channel_id);
        }
        let has_password = password.is_some();

        let info = ChannelInfo {
            channel_id,
            name,
            has_password,
            created_by: Some(created_by),
            proximity,
            // A user-created channel is an ordinary room; the rest are set
            // afterwards through SetChannelOptions.
            anonymous,
            screen_share: !text,
            text,
            // Only a channel from channels.json can ask every client to join
            // it; a user-created one is joined by the people who want it.
            auto_join: false,
            // Off until somebody sets it, like every other option here.
            message_ttl_secs: 0,
            // A temporary channel keeps nothing: it is gone when it empties.
            log: String::new(),
            ..Default::default()
        };

        channels.insert(
            channel_id,
            Channel {
                info: info.clone(),
                members: HashSet::new(),
                password: password.map(Zeroizing::new),
                delete_timer: None,
                invited_users: HashSet::new(),
                summons: HashMap::new(),
                screen_shares: HashMap::new(),
                persistent: false,
                pseudonyms: HashMap::new(),
                log_conv: String::new(),
                gate: ChannelGate::default(),
                gate_key: String::new(),
                kept: false,
                follow: Follow::default(),
            },
        );

        Ok(info)
    }

    /// Delete an empty, non-General, non-persistent channel.
    pub async fn delete_channel(&self, channel_id: ChannelId) -> anyhow::Result<()> {
        if channel_id == 0 {
            anyhow::bail!("cannot delete the General channel");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if channel.persistent {
            anyhow::bail!("cannot delete a persistent channel");
        }

        if !channel.members.is_empty() {
            anyhow::bail!("channel is not empty");
        }

        // Plain drop, no abort: the caller IS the timer task whose handle is
        // stored here — aborting it would cancel the ChannelDeleted broadcast
        // that follows at its next yield point.
        self.remove_channel(&mut channels, channel_id);
        // And with it whatever a game server had told us about who could hear
        // whom in it: the ids will be handed to different people. (The channel
        // is empty — that is checked above — so there are no members' own
        // requests left to forget.)
        self.routing.clear_channel(channel_id, []);

        Ok(())
    }

    /// Takes `channel_id` out of `channels`, with every share still in it: of a sharer moved
    /// out before that move's cleanup ran, or of one who came in while it was being emptied.
    /// Each ends as a stop ends it, but for the room's own messages, since everyone who
    /// could see the channel is told it is gone: its edges let it go (`end_share`), its fan
    /// goes, its sharer may share again, and a viewer still watching it is told it stopped.
    /// Every path that removes a channel comes here, under the `channels` write lock.
    pub(crate) fn remove_channel(
        &self,
        channels: &mut HashMap<ChannelId, Channel>,
        channel_id: ChannelId,
    ) {
        let Some(gone) = channels.remove(&channel_id) else {
            return;
        };
        for share in gone.screen_shares.values() {
            let sharer = share.sharer_user_id;
            self.share_fans
                .remove_if(&sharer, |_, fan| fan.channel_id == channel_id);
            end_share(self, share);
            if let Some(mut session) = self.sessions.get_mut(&share.sharer_session_id) {
                if !shares_anywhere(channels, sharer) {
                    session.is_screen_sharing = false;
                }
            }
            for viewer in &share.viewers {
                if let Some(mut session) = self.sessions.get_mut(viewer) {
                    if session.watching_screenshare == Some(sharer) {
                        session.watching_screenshare = None;
                        let _ = crate::session::send_msg(
                            &session.control_tx,
                            &ServerMessage::StoppedWatchingScreenShare {
                                reason: "sharer_left".into(),
                            },
                        );
                    }
                }
            }
        }
        // A text channel's group goes with it, retired as a moved one is and followed by
        // nobody: a delete takes its followers out in bulk (layout's, with no word to the
        // group), a purged conversation's rows must not be written back, and an `r:` id
        // comes back with the channel id. Its name for the group and its gate go with it: an
        // id made again starts open. So does a voice room's
        if self.gk.on {
            let id = match gone.info.text {
                true => self.gk_id(&gone),
                false => self.gk.room_id(channel_id),
            };
            self.gk.on_channel_gone(channel_id, &id);
        }
    }

    /// Change a channel's password (creator or admin). Returns the updated
    /// info, or `None` when the password is the one the channel already had —
    /// see `OptionsChanged` for why a change that did not happen must not be
    /// announced to every session on the server.
    pub async fn set_channel_password(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        password: Option<String>,
        overrides: bool,
    ) -> anyhow::Result<Option<ChannelInfo>> {
        if channel_id == 0 {
            anyhow::bail!("cannot modify the General channel");
        }

        // A channel from channels.json is checked against a hash
        // (`check_admission`), so that is what it keeps here too: stored as
        // typed, the right password never matched and nobody got in
        // (1.0 audit H1-05). Hashed before the lock: Argon2 takes a while.
        let persistent = self
            .channels
            .read()
            .await
            .get(&channel_id)
            .is_some_and(|c| c.persistent);
        let password = match password {
            Some(p) if persistent => {
                let _turn = self.channel_kdf.acquire().await?;
                Some(
                    tokio::task::spawn_blocking(move || crate::channels::hash_password(&p))
                        .await??,
                )
            }
            p => p,
        };

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if !overrides && channel.info.created_by != Some(user_id) {
            anyhow::bail!("only the channel creator can change the password");
        }
        if channel.persistent != persistent {
            anyhow::bail!("the channel changed meanwhile, try again");
        }
        if channel.password.as_ref().map(|p| p.as_str()) == password.as_deref() {
            return Ok(None);
        }
        channel.info.has_password = password.is_some();
        channel.password = password.map(Zeroizing::new);

        Ok(Some(channel.info.clone()))
    }

    /// Change a channel's proximity mode (creator or admin — persistent
    /// channels have no creator, so those are admin-only, exactly as their
    /// password is). Returns the updated info, or `None` when it is the mode
    /// the channel was already in.
    pub async fn set_channel_proximity(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        proximity: ProximityMode,
        overrides: bool,
    ) -> anyhow::Result<Option<ChannelInfo>> {
        if channel_id == 0 {
            anyhow::bail!("cannot modify the General channel");
        }
        if proximity != ProximityMode::Off && !self.settings.proximity_enabled {
            anyhow::bail!("proximity chat is disabled on this server");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if !overrides && channel.info.created_by != Some(user_id) {
            anyhow::bail!("only the channel creator can change the proximity mode");
        }
        if channel.info.text {
            anyhow::bail!("a text channel carries no voice to place");
        }

        if channel.info.proximity == proximity {
            return Ok(None);
        }
        channel.info.proximity = proximity;

        Ok(Some(channel.info.clone()))
    }

    /// Change the other channel options (creator or admin — persistent
    /// channels have no creator, so those are admin-only, exactly as their
    /// password is). `None` leaves an option alone. Returns the updated info
    /// and what actually moved.
    pub async fn set_channel_options(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        request: ChannelOptions,
        overrides: bool,
    ) -> anyhow::Result<(ChannelInfo, OptionsChanged)> {
        let ChannelOptions {
            hidden,
            anonymous,
            screen_share,
            hide_members,
            routed,
            message_ttl_secs,
            announce,
            slow_mode_secs,
            nsfw,
        } = request;
        if channel_id == 0 {
            anyhow::bail!("cannot modify the General channel");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if !overrides && channel.info.created_by != Some(user_id) {
            anyhow::bail!("only the channel creator can change the channel options");
        }
        let group_was = self.gk_id(channel);

        // A text channel carries no voice, so the options about voice do not
        // apply there — and turning screen share "on" in one would advertise
        // something the share path refuses anyway.
        let voice = !channel.info.text;

        // Everything that can be refused is refused before anything changes:
        // a request that fails halfway would leave the channel with part of
        // it applied and nobody told, because the error is all that is sent.
        if anonymous == Some(true) && !voice {
            // Same reason as at creation: a text channel's members are in other
            // channels at the same time, where the same ids carry real names.
            anyhow::bail!("a text channel cannot be anonymous");
        }
        if announce == Some(true) && voice {
            anyhow::bail!("only a text channel can be an announcement channel");
        }
        if slow_mode_secs.is_some_and(|v| v > MAX_SLOW_MODE_SECS) {
            anyhow::bail!("slow mode can be at most 6 hours");
        }

        let mut changed = OptionsChanged::default();

        if let Some(v) = hidden {
            changed.any |= channel.info.hidden != v;
            channel.info.hidden = v;
        }
        if let Some(v) = screen_share.filter(|_| voice) {
            changed.any |= channel.info.screen_share != v;
            channel.info.screen_share = v;
        }
        if let Some(v) = hide_members {
            changed.any |= channel.info.hide_members != v;
            channel.info.hide_members = v;
        }
        if let Some(v) = routed.filter(|_| voice) {
            changed.any |= channel.info.routed != v;
            channel.info.routed = v;
            // Unconditional, even when the flag was already off: this is the
            // switch people reach for when a table has gone wrong, and it has
            // to mean "forget all of it" every time it is used.
            if !v {
                // Switching it off hands everybody back at once: whatever any
                // client asked for, and whatever a game server had us
                // enforcing, is forgotten rather than left half-applied.
                let members: Vec<UserId> = channel.members.iter().copied().collect();
                self.clear_routing(channel_id, members);
            }
        }
        if let Some(v) = message_ttl_secs {
            // Bounded like the timer inside a message is, and for the same
            // reason: this number decides when somebody's chat is deleted, and
            // a channel advertising a year is advertising "never" in a way that
            // reads like a setting.
            let v = v.min(voipc_crypto::MAX_MESSAGE_TTL_SECS);
            changed.any |= channel.info.message_ttl_secs != v;
            channel.info.message_ttl_secs = v;
        }
        if let Some(v) = announce {
            changed.any |= channel.info.announce != v;
            channel.info.announce = v;
        }
        if let Some(v) = slow_mode_secs {
            changed.any |= channel.info.slow_mode_secs != v;
            channel.info.slow_mode_secs = v;
        }
        if let Some(v) = nsfw {
            changed.any |= channel.info.nsfw != v;
            channel.info.nsfw = v;
        }
        if let Some(v) = anonymous {
            if v != channel.info.anonymous {
                changed.any = true;
                changed.anonymity = true;
                channel.info.anonymous = v;
                // Everyone here needs the names the channel now goes by: fresh
                // pseudonyms when switching on, the real names when switching off.
                channel.pseudonyms.clear();
                if v {
                    let members: Vec<UserId> = channel.members.iter().copied().collect();
                    for uid in members {
                        let name = mint_pseudonym(&channel.pseudonyms);
                        channel.pseudonyms.insert(uid, name);
                    }
                }
                // A voice room's seats are named anew (open choice 11)
                if !channel.info.text {
                    self.gk.on_room_anonymous(channel_id, v);
                }
            }
        }
        // ponytail: a log switched off this way keeps its stored members and
        // entries until they expire; clients just stop writing to it.
        channel.refresh_log();
        self.gk_moved(channel, &group_was);

        Ok((channel.info.clone(), changed))
    }

    /// A text channel's offered log came or went (`hide_members`, spec §5.12): its group id
    /// moved from `was`, and every follower follows the group under the new one. A voice
    /// room's id is `r:` either way.
    fn gk_moved(&self, channel: &Channel, was: &str) {
        let now = self.gk_id(channel);
        if !self.gk.on || !channel.info.text || now == was {
            return;
        }
        self.gk.on_group_moved(channel.info.channel_id, was, &now);
        for uid in channel
            .follow
            .joined
            .keys()
            .chain(channel.follow.quiet.keys())
        {
            let account = self.sessions.get(uid).and_then(|s| s.account_id());
            self.gk_follow(channel, *uid, account);
        }
    }

    /// The real name of `subject`, and the pseudonym they currently go by if
    /// they are in an anonymous channel.
    ///
    /// Broadcast loops resolve this once and then pick per recipient with
    /// [`pick_name`] — the alternative, calling [`Self::display_name`] inside
    /// the loop, would take the channels lock while holding a session shard.
    pub async fn names_of(&self, subject: UserId) -> (String, Option<String>) {
        let real = self.real_name_of(subject);
        let alias = alias_anywhere(&*self.channels.read().await, subject);
        (real, alias)
    }

    /// The same, for one named channel.
    ///
    /// A user can be in several channels at once now — a voice room and any
    /// number of text channels — so "the pseudonym they go by" is only a
    /// question with an answer once you say where. Anywhere a channel is
    /// known, this is the one to ask: `names_of` would hand an anonymous text
    /// channel's pseudonym to the ordinary voice room next door.
    pub async fn names_of_in(
        &self,
        channel_id: ChannelId,
        subject: UserId,
    ) -> (String, Option<String>) {
        let real = self.real_name_of(subject);
        let channels = self.channels.read().await;
        let alias = channels.get(&channel_id).and_then(|ch| {
            ch.info
                .anonymous
                .then(|| ch.pseudonyms.get(&subject).cloned())
                .flatten()
        });
        (real, alias)
    }

    fn real_name_of(&self, subject: UserId) -> String {
        self.sessions
            .get(&subject)
            .map(|s| s.username.clone())
            .unwrap_or_default()
    }

    /// The name `subject` goes by as far as `viewer` is concerned.
    ///
    /// In an anonymous channel every member — including the subject, so they
    /// know what the others see — is shown a pseudonym. Admins are shown the
    /// real name, which is what makes moderating such a channel possible.
    pub async fn display_name(&self, subject: UserId, viewer_session: SessionId) -> String {
        let (real, alias) = self.names_of(subject).await;
        pick_name(&real, &alias, self.is_admin(viewer_session))
    }

    /// Why `kick_user` would refuse, with nothing done: a moderator's kick is
    /// written down first, and only one that goes through.
    pub async fn may_kick(
        &self,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
        requester_moderates: bool,
        target_spared: bool,
    ) -> anyhow::Result<()> {
        Self::check_kick(
            &*self.channels.read().await,
            channel_id,
            requester_id,
            target_id,
            requester_moderates,
            target_spared,
        )
    }

    fn check_kick(
        channels: &HashMap<ChannelId, Channel>,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
        requester_moderates: bool,
        target_spared: bool,
    ) -> anyhow::Result<()> {
        if channel_id == 0 {
            anyhow::bail!("cannot kick users from the General channel");
        }

        if requester_id == target_id {
            anyhow::bail!("you cannot kick yourself");
        }

        let channel = channels
            .get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        let creator = channel.info.created_by == Some(requester_id);
        if !requester_moderates && !creator {
            anyhow::bail!("only the channel creator can kick users");
        }
        if target_spared && !creator {
            anyhow::bail!("only an admin can kick an admin or someone with privileges");
        }

        if !channel.members.contains(&target_id) {
            anyhow::bail!("user is not in this channel");
        }
        Ok(())
    }

    /// Remove a user from a channel (creator or admin kicks them).
    /// Returns the kicked user's session_id, the channel's remaining member
    /// count, and whether they were moved to General (a voice room's kick).
    pub async fn kick_user(
        &self,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
        requester_moderates: bool,
        target_spared: bool,
    ) -> anyhow::Result<(SessionId, usize, bool)> {
        let mut channels = self.channels.write().await;
        Self::check_kick(
            &channels,
            channel_id,
            requester_id,
            target_id,
            requester_moderates,
            target_spared,
        )?;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        channel.members.remove(&target_id);
        channel.info.user_count = channel.members.len() as u32;
        channel.pseudonyms.remove(&target_id);
        if let Some(first) = channel.follow.remove(target_id) {
            self.exit_due(channel_id, &channel.follow, first);
        }
        // Requester 0 is the relay putting out who lost the gate (`session::evict`)
        let cause = if requester_id == 0 {
            gk_cause::GATE
        } else {
            gk_cause::KICK
        };
        if channel.info.text {
            self.gk.on_kick(channel_id, target_id, cause);
        } else {
            // A voice kick to the lobby: out of the room, into no group
            self.gk_room_leave(channel, target_id, cause);
        }

        let target_session_id = self
            .sessions
            .contains_key(&target_id)
            .then_some(target_id)
            .ok_or_else(|| anyhow::anyhow!("user session not found"))?;

        let remaining = channel.members.len();
        // Into General under the same lock, and only while the session still
        // names this room. Done later by the handler, the target's own join
        // could land in between and leave them in two voice rooms (S-002).
        // Out of a text channel they lose the subscription and nothing else.
        let moved = !channel.info.text
            && self
                .sessions
                .get_mut(&target_session_id)
                .is_some_and(|mut s| {
                    let here = s.channel_id == channel_id;
                    if here {
                        s.channel_id = 0;
                    }
                    here
                });
        if moved {
            if let Some(general) = channels.get_mut(&0) {
                general.members.insert(target_id);
                general.info.user_count = general.members.len() as u32;
            }
            self.routing.clear_session(target_session_id);
        }
        Ok((target_session_id, remaining, moved))
    }

    /// Store a delete timer handle for a channel (replaces any existing one).
    pub async fn set_channel_delete_timer(
        &self,
        channel_id: ChannelId,
        handle: tokio::task::JoinHandle<()>,
    ) {
        let mut channels = self.channels.write().await;
        match channels.get_mut(&channel_id) {
            Some(channel) => {
                if let Some(old) = channel.delete_timer.take() {
                    old.abort();
                }
                channel.delete_timer = Some(handle);
            }
            // The channel went away while we were spawning the timer for it.
            // Dropping a JoinHandle does not stop the task, so without this
            // the timer sleeps out the whole empty-channel timeout before
            // waking to delete something that is already gone.
            None => handle.abort(),
        }
    }

    /// Why `add_invite` would refuse, with nothing done. `Ok(true)`: this one takes
    /// a row in the moderation log, written before it goes out.
    pub async fn may_invite(
        &self,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
        manages: bool,
    ) -> anyhow::Result<bool> {
        self.check_invite(
            &*self.channels.read().await,
            channel_id,
            requester_id,
            target_id,
            manages,
        )
    }

    /// `manages`: the requester holds `voipc:channels`, which lets someone who is
    /// not the creator invite too. Only into a room they stand in, whose password
    /// they could change anyway, and by their own name: an invite says who sent it,
    /// and from behind a pseudonym it would say who that is.
    fn check_invite(
        &self,
        channels: &HashMap<ChannelId, Channel>,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
        manages: bool,
    ) -> anyhow::Result<bool> {
        if channel_id == 0 {
            anyhow::bail!("cannot invite to the General channel");
        }

        let channel = channels
            .get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        let summon = channel.info.created_by != Some(requester_id);
        if summon {
            if !manages {
                anyhow::bail!("only the channel creator can invite users");
            }
            if !channel.members.contains(&requester_id) {
                anyhow::bail!("you can only invite people to a channel you are in");
            }
            if alias_anywhere(channels, requester_id).is_some() {
                anyhow::bail!("you cannot invite people while you go by a pseudonym");
            }
            // Nobody will ever come to spend it, and ids are not reused, so it would
            // hold a place on the list until the relay restarts
            if !self.sessions.contains_key(&target_id) {
                anyhow::bail!("they cannot join this channel");
            }
        }

        if channel.members.contains(&target_id) {
            anyhow::bail!("user is already in this channel");
        }

        if channel.invited_users.len() >= 50 {
            anyhow::bail!("invite list is full (max 50)");
        }
        // The invite would name the channel to someone it is hidden from
        if !self.passes(target_id, &channel.gate.groups) {
            anyhow::bail!("they cannot join this channel");
        }

        // A re-send only raises the same popup again: one row for one invite
        Ok(summon && channel.summons.get(&target_id) != Some(&requester_id))
    }

    /// Add a user to a channel's invite list, by its creator or, `manages`, by
    /// someone `check_invite` lets. Whoever asked last hears the answer.
    /// Returns (channel_name, inviter_username) for the notification.
    pub async fn add_invite(
        &self,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
        manages: bool,
    ) -> anyhow::Result<(String, String)> {
        let mut channels = self.channels.write().await;
        self.check_invite(&channels, channel_id, requester_id, target_id, manages)?;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if channel.info.created_by == Some(requester_id) {
            channel.summons.remove(&target_id);
        } else {
            channel.summons.insert(target_id, requester_id);
        }

        let channel_name = channel.info.name.clone();
        channel.invited_users.insert(target_id);

        // Look up inviter's username
        let inviter_name = self
            .sessions
            .get(&requester_id)
            .map(|s| s.username.clone())
            .unwrap_or_else(|| "Unknown".into());

        Ok((channel_name, inviter_name))
    }

    /// Remove a user from a channel's invite list. Returns whether there was
    /// one — declining an invitation nobody sent must not reach anybody: the
    /// message names a channel of the sender's choosing and the reply goes to
    /// that channel's creator, or whoever asked.
    pub async fn remove_invite(&self, channel_id: ChannelId, user_id: UserId) -> bool {
        let mut channels = self.channels.write().await;
        channels
            .get_mut(&channel_id)
            .is_some_and(|channel| channel.end_invite(user_id))
    }

    /// Check if a user is a member of a channel or the channel is public (no password).
    pub async fn is_channel_public_or_member(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
    ) -> bool {
        let channels = self.channels.read().await;
        match channels.get(&channel_id) {
            Some(channel) => {
                // A gated channel is not there for whoever is outside its groups
                if !self.passes(user_id, &channel.gate.groups) {
                    return false;
                }
                // A channel that hides its members shows them to nobody who is
                // not in it, password or not
                if channel.info.hide_members && !channel.members.contains(&user_id) {
                    return false;
                }
                channel.password.is_none() || channel.members.contains(&user_id)
            }
            None => false,
        }
    }

    // ── Screen share methods ───────────────────────────────────────────

    /// Start a screen share. Returns session_ids of other channel members for notification.
    pub async fn start_screen_share(
        &self,
        user_id: UserId,
        session_id: SessionId,
        channel_id: ChannelId,
        codec: VideoCodec,
        resolution: u16,
    ) -> anyhow::Result<Vec<SessionId>> {
        if channel_id == 0 {
            anyhow::bail!("cannot screen share in the General channel");
        }

        // Every refusal happens before the session is marked as sharing: a
        // bail after that flag is set leaves the user unable to ever share
        // again (it is only cleared on stop).
        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;
        if !channel.info.screen_share {
            anyhow::bail!("screen sharing is off in this channel");
        }

        // Mark user as sharing
        let sharer_tx = if let Some(mut session) = self.sessions.get_mut(&session_id) {
            if session.listen_only.contains(&channel_id) {
                anyhow::bail!("you can only listen in this channel");
            }
            if session.silence.voice() {
                anyhow::bail!("you cannot share your screen on this server for now");
            }
            if session.is_screen_sharing {
                anyhow::bail!("already screen sharing");
            }
            session.is_screen_sharing = true;
            session.control_tx.clone()
        } else {
            anyhow::bail!("session not found");
        };

        channel.screen_shares.insert(
            user_id,
            ScreenShareSession::new(user_id, session_id, codec, share_ceiling_kbps(resolution)),
        );
        // The only place a fan is made: `refan` updates a fan of this channel only
        self.share_fans
            .insert(user_id, Fan::new(channel_id, sharer_tx));

        // Return other members' session_ids for broadcasting
        let others: Vec<SessionId> = channel
            .members
            .iter()
            .filter(|&&uid| uid != user_id)
            .filter_map(|&uid| self.sessions.contains_key(&uid).then_some(uid))
            .collect();

        Ok(others)
    }

    /// Stop a screen share. Returns (viewer_session_ids, channel_member_session_ids).
    pub async fn stop_screen_share(
        &self,
        user_id: UserId,
        session_id: SessionId,
        channel_id: ChannelId,
    ) -> anyhow::Result<(Vec<(UserId, SessionId)>, Vec<SessionId>)> {
        let mut channels = self.channels.write().await;
        let removed = channels
            .get_mut(&channel_id)
            .and_then(|c| c.screen_shares.remove(&user_id));
        // Unmark user as sharing, unless a share of theirs is left in another room
        // (`shares_anywhere`): a stop asked of this one does not end that
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            if removed.is_some() || !shares_anywhere(&channels, user_id) {
                session.is_screen_sharing = false;
            }
        }
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        let share = removed.ok_or_else(|| anyhow::anyhow!("not screen sharing"))?;
        self.share_fans
            .remove_if(&user_id, |_, fan| fan.channel_id == channel_id);
        end_share(self, &share);

        // Clear watching state for all viewers
        let viewer_sessions: Vec<(UserId, SessionId)> = share
            .viewers
            .iter()
            .filter_map(|&vid| {
                self.sessions.get_mut(&vid)?.watching_screenshare = None;
                Some((vid, vid))
            })
            .collect();

        // All channel members for broadcast
        let member_sessions: Vec<SessionId> = channel
            .members
            .iter()
            .filter(|&&uid| uid != user_id)
            .filter_map(|&uid| self.sessions.contains_key(&uid).then_some(uid))
            .collect();

        Ok((viewer_sessions, member_sessions))
    }

    /// Start watching a screen share. Enforces one-at-a-time: a viewer of another share is
    /// taken out of that one. With `[pool]`, a viewer past the share's first `local_first`
    /// may be placed on an media edge (`Watched::edge`). Watching the same share again is
    /// never refused; on an edge it gets a fresh ticket, and the one before is revoked.
    pub async fn watch_screen_share(
        &self,
        viewer_user_id: UserId,
        viewer_session_id: SessionId,
        sharer_user_id: UserId,
        channel_id: ChannelId,
    ) -> anyhow::Result<Watched> {
        // Check if viewer is already watching someone else — auto-unwatch
        let (prev_unwatch, tunnel, avoid) = {
            let mut session = self
                .sessions
                .get_mut(&viewer_session_id)
                .ok_or_else(|| anyhow::anyhow!("session not found"))?;
            let avoid = avoided(&mut session.edge_avoid, Instant::now());
            (session.watching_screenshare, session.tunnel, avoid)
        };
        let pool = self.pool.as_deref();

        // Every refusal comes before anything changes: a click on somebody
        // whose share just ended must not cost the stream being watched, nor
        // leave a watch recorded for a share that does not exist (it is what
        // lets a session ask that user for keyframes and report losses).
        let mut channels = self.channels.write().await;
        let channel = channels
            .get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;
        let Some(share) = channel.screen_shares.get(&sharer_user_id) else {
            anyhow::bail!("user is not screen sharing");
        };
        let rewatch = share.viewers.contains(&viewer_user_id);
        // Room for one more, unless they watch it already (`[media]`, `[pool]`)
        let spot = if rewatch {
            None
        } else {
            Some(
                self.seat(&channels, share, tunnel, &avoid)
                    .map_err(|why| anyhow::anyhow!(why))?,
            )
        };
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        // Its sharer is told the new count by the fan (`ShareNews`)
        if let Some(prev_sharer_id) = prev_unwatch.filter(|&id| id != sharer_user_id) {
            if let Some(prev_share) = channel.screen_shares.get_mut(&prev_sharer_id) {
                prev_share.drop_viewer(viewer_user_id, pool);
                self.refan(channel_id, prev_share);
            }
        }

        if let Some(mut session) = self.sessions.get_mut(&viewer_session_id) {
            session.watching_screenshare = Some(sharer_user_id);
        }

        let share = channel
            .screen_shares
            .get_mut(&sharer_user_id)
            .ok_or_else(|| anyhow::anyhow!("user is not screen sharing"))?;

        let mut edge = None;
        match spot {
            Some(Spot::Edge(placement, view)) => {
                edge = Some((placement.id, view));
                share.put_on_edge(viewer_user_id, placement);
            }
            Some(Spot::Here) => {}
            // Again on its edge: a fresh slot there, and the one before revoked, so a viewer
            // holds one live ticket however often it clicks
            None => {
                let held = share.on_edge.get(&viewer_user_id);
                if let Some((placement, view)) =
                    held.and_then(|p| pool.and_then(|pool| pool.reslot(p, share.sharer_session_id)))
                {
                    edge = Some((placement.id, view));
                    share.put_on_edge(viewer_user_id, placement);
                }
            }
        }
        share.viewers.insert(viewer_user_id);
        let new_count = share.viewers.len() as u32;
        // Again on a watch of the same share too: it is the list, so nobody is in it twice
        self.refan(channel_id, share);

        Ok(Watched {
            sharer_sid: share.sharer_session_id,
            new_count,
            codec: share.codec,
            edge,
        })
    }

    /// Where a viewer who does not watch `share` yet is to watch it from: a media edge
    /// (`Pool::place`), or this relay, or nowhere, with why. Past the share's first
    /// `[pool] local_first` an edge is tried first, unless the viewer comes through the TCP
    /// tunnel; this relay takes one under its own `[media]` caps, which count only the viewers
    /// it serves itself. Within the first `local_first`, a viewer this relay has no room for
    /// goes to an edge that carries the share already, which costs this relay nothing more,
    /// rather than be refused. Called under the `channels` write lock, which the counts are
    /// made in.
    fn seat(
        &self,
        channels: &HashMap<ChannelId, Channel>,
        share: &ScreenShareSession,
        tunnel: bool,
        avoid: &[String],
    ) -> Result<Spot, &'static str> {
        let local = share.local_viewers();
        let sent = video_egress_kbps(channels);
        let room_here =
            sent + share.ceiling_kbps as u64 <= self.media.video_egress_mbit as u64 * 1000;
        if let Some(pool) = &self.pool {
            // Without `room_here`, only an edge that carries the share is eligible
            if !tunnel && (local >= pool.local_first as usize || !room_here) {
                if let Some((placement, view)) = pool.place(
                    share.sharer_session_id,
                    share.ceiling_kbps,
                    avoid,
                    room_here,
                ) {
                    return Ok(Spot::Edge(placement, view));
                }
            }
        }
        if local as u32 >= self.media.share_viewers {
            return Err(SHARE_FULL);
        }
        if !room_here {
            return Err(VIDEO_FULL);
        }
        Ok(Spot::Here)
    }

    /// Seats again a viewer of `sharer`'s share in `channel_id` whose edge failed it or went
    /// away, taken out of the share's `viewers` and `on_edge` already (`seat`), and tells it
    /// where the share comes from now: `WatchAt` with another edge, or with none for this
    /// relay. With no room anywhere it watches nothing and is told why. Whether it still
    /// watches. The caller refans.
    fn reseat(
        &self,
        channels: &mut HashMap<ChannelId, Channel>,
        channel_id: ChannelId,
        sharer: UserId,
        viewer: UserId,
        avoid: &[String],
    ) -> bool {
        let tunnel = self.sessions.get(&viewer).is_some_and(|s| s.tunnel);
        let Some(share) = channels
            .get(&channel_id)
            .and_then(|c| c.screen_shares.get(&sharer))
        else {
            return false;
        };
        let spot = self.seat(channels, share, tunnel, avoid);
        let Some(share) = channels
            .get_mut(&channel_id)
            .and_then(|c| c.screen_shares.get_mut(&sharer))
        else {
            return false;
        };
        let told = match spot {
            Ok(Spot::Edge(placement, view)) => {
                let msg = ServerMessage::WatchAt {
                    sharer_user_id: sharer,
                    placement: placement.id,
                    edge: Some(view),
                };
                share.viewers.insert(viewer);
                share.put_on_edge(viewer, placement);
                vec![msg]
            }
            Ok(Spot::Here) => {
                share.viewers.insert(viewer);
                // It joins the fan mid-stream: a keyframe, within the share's budget
                crate::session::relay_keyframe_request(self, share.sharer_session_id);
                vec![ServerMessage::WatchAt {
                    sharer_user_id: sharer,
                    placement: self.pool.as_ref().map_or(0, |p| p.next_placement()),
                    edge: None,
                }]
            }
            Err(why) => {
                if let Some(mut session) = self.sessions.get_mut(&viewer) {
                    if session.watching_screenshare == Some(sharer) {
                        session.watching_screenshare = None;
                    }
                }
                vec![
                    ServerMessage::StoppedWatchingScreenShare {
                        reason: "edge_lost".into(),
                    },
                    ServerMessage::WatchRefused {
                        sharer_user_id: sharer,
                        reason: why.into(),
                    },
                ]
            }
        };
        let watches = matches!(told[0], ServerMessage::WatchAt { .. });
        if let Some(session) = self.sessions.get(&viewer) {
            for msg in &told {
                let _ = crate::session::send_msg(&session.control_tx, msg);
            }
        }
        watches
    }

    /// A viewer says the edge of its `WatchAt` numbered `placement` failed it
    /// (`ClientMessage::EdgeFailed`, from a viewer of `sharer`'s share, within its rate). It
    /// is moved off that edge, which is revoked its ticket and not picked for it again for
    /// `pool::AVOID_FOR`: to another edge, or to this relay, or, with no room, out of the
    /// share. Not while the share itself has sent nothing for `pool::SHARE_SILENT_MS`: then
    /// no edge is to blame, and a stalled sharer would empty every edge onto this relay.
    /// A placement that is not the viewer's current one is ignored, so a late word about an
    /// edge it left never moves it off the one it is on.
    pub async fn edge_failed(
        &self,
        viewer: UserId,
        sharer: UserId,
        placement: u64,
        channel_id: ChannelId,
    ) {
        let Some(pool) = self.pool.as_deref() else {
            return;
        };
        let mut channels = self.channels.write().await;
        let Some(share) = channels
            .get_mut(&channel_id)
            .and_then(|c| c.screen_shares.get_mut(&sharer))
        else {
            self.limits.count("edge failed", "no such share");
            return;
        };
        match share.on_edge.get(&viewer) {
            Some(p) if p.id == placement => {}
            Some(_) => return self.limits.count("edge failed", "stale placement"),
            None => return self.limits.count("edge failed", "not on an edge"),
        }
        if self.share_silent(sharer) {
            return self.limits.count("edge failed", "share silent");
        }
        let Some(failed) = share.take_off_edge(viewer) else {
            return;
        };
        share.viewers.remove(&viewer);
        pool.unplace(&failed, share.sharer_session_id, share.ceiling_kbps, true);
        let avoid = match self.sessions.get_mut(&viewer) {
            Some(mut session) => {
                let now = Instant::now();
                let list = &mut session.edge_avoid;
                list.retain(|(edge, _)| *edge != failed.edge);
                list.push((failed.edge.clone(), now));
                if list.len() > crate::pool::MAX_AVOID {
                    list.remove(0);
                }
                avoided(list, now)
            }
            None => vec![failed.edge.clone()],
        };
        let watches = self.reseat(&mut channels, channel_id, sharer, viewer, &avoid);
        self.limits
            .count("edge failed", if watches { "moved" } else { "no room" });
        if let Some(share) = channels
            .get(&channel_id)
            .and_then(|c| c.screen_shares.get(&sharer))
        {
            self.refan(channel_id, share);
        }
    }

    /// Whether `sharer`'s share has sent no video for `pool::SHARE_SILENT_MS`, or none yet.
    fn share_silent(&self, sharer: UserId) -> bool {
        let last = self
            .share_fans
            .get(&sharer)
            .map_or(0, |fan| fan.last_packet_ms.load(Ordering::Relaxed));
        crate::pool::share_silent(last, self.uptime_ms())
    }

    /// The edge link `name`/`link` ended: closed, timed out, or its queue full. Its viewers
    /// are seated again, with a new placement each, as after `edge_failed` but avoiding
    /// nothing (`move_off_edge`). Nobody is moved back once it returns.
    pub async fn edge_lost(&self, name: &str, link: u64, why: &str) {
        let Some(pool) = self.pool.as_deref() else {
            return;
        };
        let mut channels = self.channels.write().await;
        if !pool.unlink(self, name, link) {
            // Replaced by a newer link of the same edge, which moved its viewers then
            return;
        }
        let (moved, refused) = self.move_off_edge(&mut channels, name, link);
        tracing::info!("edge {name} offline ({why}); {moved} viewers moved, {refused} refused");
    }

    /// Seats again every viewer placed on the edge link `name`/`link`, which is gone from the
    /// pool already: `(moved, refused)`.
    pub(crate) fn move_off_edge(
        &self,
        channels: &mut HashMap<ChannelId, Channel>,
        name: &str,
        link: u64,
    ) -> (usize, usize) {
        let mut stranded = Vec::new();
        for (&channel_id, channel) in channels.iter_mut() {
            for (&sharer, share) in channel.screen_shares.iter_mut() {
                let gone: Vec<UserId> = share
                    .on_edge
                    .iter()
                    .filter(|(_, p)| p.edge == name && p.link == link)
                    .map(|(&viewer, _)| viewer)
                    .collect();
                for &viewer in &gone {
                    share.take_off_edge(viewer);
                    share.viewers.remove(&viewer);
                }
                if !gone.is_empty() {
                    stranded.push((channel_id, sharer, gone));
                }
            }
        }
        let (mut moved, mut refused) = (0, 0);
        for (channel_id, sharer, viewers) in stranded {
            for viewer in viewers {
                if self.reseat(channels, channel_id, sharer, viewer, &[]) {
                    moved += 1;
                } else {
                    refused += 1;
                }
            }
            if let Some(share) = channels
                .get(&channel_id)
                .and_then(|c| c.screen_shares.get(&sharer))
            {
                self.refan(channel_id, share);
            }
        }
        (moved, refused)
    }

    /// Stop watching a screen share.
    /// Returns (sharer_user_id, sharer_session_id, old_count, new_count).
    pub async fn stop_watching_screen_share(
        &self,
        viewer_user_id: UserId,
        viewer_session_id: SessionId,
        channel_id: ChannelId,
    ) -> anyhow::Result<(UserId, SessionId, u32, u32)> {
        let sharer_user_id = {
            let session = self
                .sessions
                .get(&viewer_session_id)
                .ok_or_else(|| anyhow::anyhow!("session not found"))?;
            session
                .watching_screenshare
                .ok_or_else(|| anyhow::anyhow!("not watching any screen share"))?
        };

        // Clear watching state
        if let Some(mut session) = self.sessions.get_mut(&viewer_session_id) {
            session.watching_screenshare = None;
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        let share = channel
            .screen_shares
            .get_mut(&sharer_user_id)
            .ok_or_else(|| anyhow::anyhow!("screen share not found"))?;

        let old_count = share.viewers.len() as u32;
        share.drop_viewer(viewer_user_id, self.pool.as_deref());
        let new_count = share.viewers.len() as u32;
        self.refan(channel_id, share);

        Ok((
            sharer_user_id,
            share.sharer_session_id,
            old_count,
            new_count,
        ))
    }

    /// Points a share's fan at its viewers' media queues again, after who watches changed,
    /// and gives the sharer the new count (`ShareNews::viewers_now`).
    ///
    /// Called under the `channels` write lock, which orders the rebuilds and the counts, and
    /// with no `sessions` guard held, since it reads `sessions`. A viewer whose session is
    /// gone gets nothing, as when the video path looked each one up. A fan of another
    /// channel is left alone: only `start_screen_share` makes one, so a share left behind in
    /// a channel its sharer has moved out of never takes over the fan of the share in force.
    /// Viewers on an edge are not in it: their edge's feed is (`Fan::feeds`), and the count
    /// is of everyone.
    fn refan(&self, channel_id: ChannelId, share: &ScreenShareSession) {
        let local: Arc<[mpsc::Sender<Bytes>]> = share
            .viewers
            .iter()
            .filter(|vid| !share.on_edge.contains_key(vid))
            .filter_map(|vid| Some(self.sessions.get(vid)?.media_tx.clone()))
            .collect();
        if let Some(mut fan) = self.share_fans.get_mut(&share.sharer_user_id) {
            if fan.channel_id == channel_id {
                fan.local = local;
                fan.news
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .viewers_now(share.viewers.len() as u32);
            }
        }
    }

    /// A viewer of `sharer`'s share lost frames (`ClientMessage::VideoLossReport`, already
    /// checked to come from a viewer of it, within its rate). Takes no `channels` lock.
    pub fn loss_reported(
        &self,
        sharer: UserId,
        viewer: UserId,
        frames_dropped: u32,
        frames_received: u32,
    ) {
        let now_ms = self.uptime_ms();
        if let Some(fan) = self.share_fans.get(&sharer) {
            fan.news
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .loss(viewer, frames_dropped, frames_received, now_ms);
        }
    }

    /// Each second (main.rs): tells every sharer whose viewer count moved since it was last
    /// told, and those with more than `LOSS_SUMMARY_ABOVE` viewers how many lose frames.
    /// Also ends the edges' feeds that no viewer was placed for in 10 s (`Pool::tick`).
    pub fn share_tick(&self) {
        let now_ms = self.uptime_ms();
        for fan in self.share_fans.iter() {
            fan.news
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .tick(now_ms);
        }
        if let Some(pool) = &self.pool {
            pool.tick(self, Instant::now());
        }
    }

    /// Clean up screen share state when a user disconnects or leaves a channel.
    /// Returns a list of actions to take: (viewer notifications, sharer notifications).
    /// The sharer of a share the user watched is told the new count from here (`refan`).
    pub async fn cleanup_screen_shares_for_user(
        &self,
        user_id: UserId,
        session_id: SessionId,
        channel_id: ChannelId,
    ) -> ScreenShareCleanup {
        let mut cleanup = ScreenShareCleanup::default();

        let mut channels = self.channels.write().await;
        let Some(channel) = channels.get_mut(&channel_id) else {
            return cleanup;
        };

        // If the user was screen sharing, remove their share and notify viewers
        if let Some(share) = channel.screen_shares.remove(&user_id) {
            self.share_fans
                .remove_if(&user_id, |_, fan| fan.channel_id == channel_id);
            end_share(self, &share);
            for &viewer_id in &share.viewers {
                if let Some(mut vs) = self.sessions.get_mut(&viewer_id) {
                    vs.watching_screenshare = None;
                    cleanup.viewers_to_notify_stopped.push(viewer_id);
                }
            }
            cleanup.stopped_sharer_user_id = Some(user_id);
        }

        // Unmark sharing on session, unless a share of theirs is left in another room
        // (`shares_anywhere`), which its own cleanup ends
        let removed = cleanup.stopped_sharer_user_id.is_some();
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            if session.is_screen_sharing && (removed || !shares_anywhere(&channels, user_id)) {
                session.is_screen_sharing = false;
            }
        }
        let Some(channel) = channels.get_mut(&channel_id) else {
            return cleanup;
        };

        // If the user was watching someone, remove them as a viewer
        let watching = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.watching_screenshare);

        if let Some(sharer_id) = watching {
            if let Some(share) = channel.screen_shares.get_mut(&sharer_id) {
                share.drop_viewer(user_id, self.pool.as_deref());
                self.refan(channel_id, share);
            }
            if let Some(mut session) = self.sessions.get_mut(&session_id) {
                session.watching_screenshare = None;
            }
        }

        // Collect all remaining channel members for broadcast
        cleanup.channel_member_sessions = channel
            .members
            .iter()
            .filter(|&&uid| uid != user_id)
            .filter_map(|&uid| self.sessions.contains_key(&uid).then_some(uid))
            .collect();

        cleanup
    }
}

/// Result of cleaning up screen share state when a user leaves.
#[derive(Default)]
pub struct ScreenShareCleanup {
    /// Viewers to notify that the share they were watching stopped.
    pub viewers_to_notify_stopped: Vec<SessionId>,
    /// The user_id of the share that stopped (if any).
    pub stopped_sharer_user_id: Option<UserId>,
    /// All remaining channel member session_ids (for broadcast).
    pub channel_member_sessions: Vec<SessionId>,
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::config::ServerConfig;
    use crate::settings::ServerSettings;

    pub(crate) fn make_state() -> ServerState {
        make_state_with(ServerSettings::default())
    }

    pub(crate) fn make_state_with(settings: ServerSettings) -> ServerState {
        ServerState::new(
            &ServerConfig::default(),
            settings,
            Vec::new(),
            "test-admin-token".into(),
        )
    }

    /// Registers a user with dummy control/media queues.
    pub(crate) fn add_user(state: &ServerState, username: &str) -> (UserId, SessionId) {
        let (user_id, session_id, _media) = add_user_with_media(state, username);
        (user_id, session_id)
    }

    /// Registers a user and hands back the media queue so a test can watch
    /// what the relay fans out to them.
    pub(crate) fn add_user_with_media(
        state: &ServerState,
        username: &str,
    ) -> (UserId, SessionId, mpsc::Receiver<Bytes>) {
        let user_id = state.next_user_id();
        let session_id = user_id;
        let tx = ControlTx::placeholder();
        let (media_tx, media_rx) = mpsc::channel(16);
        let session = UserSession::new(
            user_id,
            username.into(),
            tx,
            media_tx,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            state.max_users,
            state
                .channel_budget
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        state.sessions.insert(session_id, session);
        state
            .username_to_session
            .insert(username.to_lowercase(), session_id);
        (user_id, session_id, media_rx)
    }

    /// Puts `users` into `channel_id`, creating the channel if needed
    /// (bypasses join validation: no passwords, no notifications).
    pub(crate) async fn put_in_channel(
        state: &ServerState,
        channel_id: ChannelId,
        users: &[(UserId, SessionId)],
    ) {
        let mut channels = state.channels.write().await;
        let channel = channels.entry(channel_id).or_insert_with(|| Channel {
            info: ChannelInfo {
                channel_id,
                name: format!("test-{channel_id}"),
                ..Default::default()
            },
            members: HashSet::new(),
            password: None,
            delete_timer: None,
            invited_users: HashSet::new(),
            summons: HashMap::new(),
            screen_shares: HashMap::new(),
            persistent: false,
            pseudonyms: HashMap::new(),
            log_conv: String::new(),
            gate: ChannelGate::default(),
            gate_key: String::new(),
            kept: false,
            follow: Follow::default(),
        });
        for &(user_id, session_id) in users {
            channel.members.insert(user_id);
            if let Some(mut session) = state.sessions.get_mut(&session_id) {
                session.channel_id = channel_id;
            }
        }
        channel.info.user_count = channel.members.len() as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    #[allow(unused_imports)]
    use crate::config::ServerConfig;
    #[allow(unused_imports)]
    use crate::settings::ServerSettings;

    // ── RateLimiter ────────────────────────────────────────────────────

    #[test]
    fn rate_limiter_fresh_allows() {
        let mut rl = RateLimiter::new(5.0, 5.0);
        for _ in 0..5 {
            assert!(rl.try_consume());
        }
    }

    #[test]
    fn rate_limiter_exhausted_denies() {
        let mut rl = RateLimiter::new(3.0, 1.0);
        for _ in 0..3 {
            assert!(rl.try_consume());
        }
        assert!(!rl.try_consume());
    }

    #[test]
    fn rate_limiter_refill() {
        let mut rl = RateLimiter::new(2.0, 100.0);
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(!rl.try_consume());
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(rl.try_consume());
    }

    #[test]
    fn rate_limiter_cap() {
        let mut rl = RateLimiter::new(3.0, 100.0);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(!rl.try_consume());
    }

    // ── ServerState basics ─────────────────────────────────────────────

    #[test]
    fn new_has_general_channel() {
        let state = make_state();
        let channels = state.channels.blocking_read();
        let general = channels.get(&0).expect("General channel should exist");
        assert_eq!(general.info.name, "General");
        assert_eq!(general.info.channel_id, 0);
        assert!(general.info.created_by.is_none());
    }

    #[test]
    fn new_empty_sessions() {
        let state = make_state();
        assert_eq!(state.user_count(), 0);
        assert!(state.sessions.is_empty());
    }

    #[test]
    fn id_generation_increments() {
        let state = make_state();
        assert_eq!(state.next_user_id(), 1);
        assert_eq!(state.next_user_id(), 2);
        assert_eq!(state.next_user_id(), 3);
        assert_eq!(state.next_channel_id(), 1);
        assert_eq!(state.next_channel_id(), 2);
    }

    #[test]
    fn username_taken() {
        let state = make_state();
        assert!(!state.username_to_session.contains_key("alice"));
        add_user(&state, "alice");
        assert!(state.username_to_session.contains_key("alice"));
        assert!(!state.username_to_session.contains_key("bob"));
    }

    // ── Channel operations ─────────────────────────────────────────────

    /// W3-32: a temporary channel went by a copy of the name rule that had drifted from
    /// `layout::name_taken`, and refused a text `general` that one from the panel may have.
    #[tokio::test]
    async fn a_temporary_channel_goes_by_the_one_name_rule() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let lobby = state.channels.read().await[&0].info.name.to_lowercase();
        let made = |name: String, text: bool| {
            state.create_channel(name, None, ProximityMode::Off, false, text, uid)
        };
        assert!(
            made(lobby.clone(), true).await.is_ok(),
            "text beside the lobby"
        );
        assert!(
            made(lobby.to_uppercase(), false).await.is_err(),
            "the control: voice"
        );
        assert!(made("Open".into(), false).await.is_ok());
        assert!(
            made("open".into(), true).await.is_err(),
            "any other name, whatever the kind"
        );
    }

    #[tokio::test]
    async fn validate_join_open_channel() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel("Open".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        assert!(state.validate_join(ch.channel_id, None, uid).await.is_ok());
    }

    #[tokio::test]
    async fn validate_join_wrong_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Priv".into(),
                Some("secret".into()),
                ProximityMode::Off,
                false,
                false,
                uid,
            )
            .await
            .unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state
            .validate_join(ch.channel_id, Some("wrong"), uid2)
            .await;
        assert!(err.unwrap_err().to_string().contains("incorrect"));
    }

    #[tokio::test]
    async fn validate_join_correct_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Priv".into(),
                Some("secret".into()),
                ProximityMode::Off,
                false,
                false,
                uid,
            )
            .await
            .unwrap();
        let (uid2, _) = add_user(&state, "bob");
        assert!(state
            .validate_join(ch.channel_id, Some("secret"), uid2)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn validate_join_full_channel() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Small".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        {
            let mut channels = state.channels.write().await;
            channels.get_mut(&ch.channel_id).unwrap().info.max_users = 1;
        }
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state.validate_join(ch.channel_id, None, uid2).await;
        assert!(err.unwrap_err().to_string().contains("full"));
    }

    #[tokio::test]
    async fn validate_join_invited_bypasses_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Inv".into(),
                Some("secret".into()),
                ProximityMode::Off,
                false,
                false,
                uid,
            )
            .await
            .unwrap();
        let (uid2, _) = add_user(&state, "bob");
        {
            let mut channels = state.channels.write().await;
            channels
                .get_mut(&ch.channel_id)
                .unwrap()
                .invited_users
                .insert(uid2);
        }
        assert!(state.validate_join(ch.channel_id, None, uid2).await.is_ok());
    }

    #[tokio::test]
    async fn join_channel_adds_member() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Test".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        let channels = state.channels.read().await;
        let channel = channels.get(&ch.channel_id).unwrap();
        assert!(channel.members.contains(&uid));
        assert_eq!(channel.info.user_count, 1);
    }

    #[tokio::test]
    async fn join_channel_clears_invite() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Test".into(),
                Some("pw".into()),
                ProximityMode::Off,
                false,
                false,
                uid,
            )
            .await
            .unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        {
            let mut channels = state.channels.write().await;
            channels
                .get_mut(&ch.channel_id)
                .unwrap()
                .invited_users
                .insert(uid2);
        }
        state
            .join_channel(uid2, sid2, ch.channel_id, None)
            .await
            .unwrap();
        let channels = state.channels.read().await;
        assert!(!channels
            .get(&ch.channel_id)
            .unwrap()
            .invited_users
            .contains(&uid2));
    }

    #[tokio::test]
    async fn leave_channel_removes_member() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Test".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        let (left_ch, count) = state.leave_current_channel(uid, sid).await.unwrap();
        assert_eq!(left_ch, ch.channel_id);
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn create_channel_succeeds() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "MyRoom".into(),
                Some("pw".into()),
                ProximityMode::Off,
                false,
                false,
                uid,
            )
            .await
            .unwrap();
        assert_eq!(ch.name, "MyRoom");
        assert!(ch.has_password);
        assert_eq!(ch.created_by, Some(uid));
        assert_eq!(ch.user_count, 0);
    }

    #[tokio::test]
    async fn create_channel_stores_proximity_mode() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Room".into(),
                None,
                ProximityMode::ThreeD,
                false,
                false,
                uid,
            )
            .await
            .unwrap();
        assert_eq!(ch.proximity, ProximityMode::ThreeD);
    }

    #[tokio::test]
    async fn proximity_kill_switch_refuses_create_and_set() {
        let settings = ServerSettings {
            proximity_enabled: false,
            ..ServerSettings::default()
        };
        let state = make_state_with(settings);
        let (uid, _) = add_user(&state, "alice");

        let err = state
            .create_channel("Room".into(), None, ProximityMode::TwoD, false, false, uid)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disabled"));

        // An off channel is still fine, but it cannot be switched on later
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        let err = state
            .set_channel_proximity(ch.channel_id, uid, ProximityMode::TwoD, true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn persistent_channels_are_served_off_when_disabled() {
        let entry = ChannelEntry {
            name: "Ingame".into(),
            description: String::new(),
            password: None,
            password_hash: None,
            max_users: 0,
            proximity: ProximityMode::TwoD,
            ..Default::default()
        };
        let on = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            vec![entry.clone()],
            "t".into(),
        );
        assert_eq!(
            on.channels.read().await[&1].info.proximity,
            ProximityMode::TwoD
        );

        let off = ServerState::new(
            &ServerConfig::default(),
            ServerSettings {
                proximity_enabled: false,
                ..ServerSettings::default()
            },
            vec![entry],
            "t".into(),
        );
        assert_eq!(
            off.channels.read().await[&1].info.proximity,
            ProximityMode::Off
        );
    }

    #[tokio::test]
    async fn set_channel_proximity_permissions() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let (other, _) = add_user(&state, "bob");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();

        // Creator may change it
        let updated = state
            .set_channel_proximity(ch.channel_id, uid, ProximityMode::TwoD, false)
            .await
            .unwrap();
        assert_eq!(updated.unwrap().proximity, ProximityMode::TwoD);
        // Asking for the mode it is already in changes nothing, and telling
        // every session on the server about it is the cost that matters.
        assert!(state
            .set_channel_proximity(ch.channel_id, uid, ProximityMode::TwoD, false)
            .await
            .unwrap()
            .is_none());

        // A stranger may not
        assert!(state
            .set_channel_proximity(ch.channel_id, other, ProximityMode::Off, false)
            .await
            .is_err());
        // An admin may
        assert!(state
            .set_channel_proximity(ch.channel_id, other, ProximityMode::ThreeD, true)
            .await
            .is_ok());
        // The General channel never
        assert!(state
            .set_channel_proximity(0, uid, ProximityMode::TwoD, true)
            .await
            .is_err());
    }

    // ── Channel options: hidden / anonymous / screen share / hide members ──

    /// Marks a session as logged in with the admin token.
    fn make_admin(state: &ServerState, session_id: SessionId) {
        state.sessions.get_mut(&session_id).unwrap().is_admin = true;
    }

    #[tokio::test]
    async fn an_anonymous_channel_hands_out_pseudonyms() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (bob, bob_sid) = add_user(&state, "bob");
        let ch = state
            .create_channel(
                "Ingame".into(),
                None,
                ProximityMode::Off,
                true,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .join_channel(bob, bob_sid, ch.channel_id, None)
            .await
            .unwrap();

        let seen = state.users_in_channel_for(ch.channel_id, bob_sid).await;
        assert_eq!(seen.len(), 2);
        for user in &seen {
            assert!(user.username.starts_with("Guest-"), "{}", user.username);
        }
        // Unique, so two members are never the same person
        assert_ne!(seen[0].username, seen[1].username);
        // Stable while they stay: the list must not reshuffle on every send
        let again = state.users_in_channel_for(ch.channel_id, bob_sid).await;
        assert_eq!(seen[0].username, again[0].username);
        // Even about themselves, so they know what the others see
        let own = state.display_name(bob, bob_sid).await;
        assert!(own.starts_with("Guest-"), "{own}");
    }

    /// G1: on an honest app nothing an anonymous room tells ties a pseudonym to a person: no
    /// role on its rows, its maker named only to them and to admins, and nothing of what they
    /// do there on a text roster that shows their name.
    #[tokio::test]
    async fn an_anonymous_room_tells_no_role_its_maker_or_what_they_do_there() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (bob, bob_sid) = add_user(&state, "bob");
        let (_adm, adm_sid) = add_user(&state, "admin");
        // Staff behind a pseudonym
        make_admin(&state, alice_sid);
        make_admin(&state, adm_sid);
        let room = state
            .create_channel(
                "Ingame".into(),
                None,
                ProximityMode::Off,
                true,
                false,
                alice,
            )
            .await
            .unwrap();
        for (u, s) in [(alice, alice_sid), (bob, bob_sid)] {
            state
                .join_channel(u, s, room.channel_id, None)
                .await
                .unwrap();
        }
        let seen = state.users_in_channel_for(room.channel_id, bob_sid).await;
        let a = seen.iter().find(|u| u.user_id == alice).unwrap();
        assert!(!a.is_admin && !a.is_moderator && !a.shares_history, "{a:?}");
        // An admin reads it as it is
        let seen = state.users_in_channel_for(room.channel_id, adm_sid).await;
        assert!(seen.iter().find(|u| u.user_id == alice).unwrap().is_admin);
        for (sid, want) in [
            (bob_sid, None),
            (alice_sid, Some(alice)),
            (adm_sid, Some(alice)),
        ] {
            let list = state.channel_list_for(sid).await;
            let c = list
                .iter()
                .find(|c| c.channel_id == room.channel_id)
                .unwrap();
            assert_eq!(c.created_by, want, "seen by {sid}");
        }

        // A text roster with her name says nothing of what she does in the room
        let text = state
            .create_channel("lounge".into(), None, ProximityMode::Off, false, true, bob)
            .await
            .unwrap();
        state
            .join_text_channel(alice, text.channel_id, None)
            .await
            .unwrap();
        let busy = |state: &ServerState| {
            let mut s = state.sessions.get_mut(&alice_sid).unwrap();
            s.is_screen_sharing = true;
            s.is_muted = true;
        };
        busy(&state);
        let (_, rows, _, _) = state.channel_page(text.channel_id, bob_sid, 0).await;
        let row = rows.iter().find(|r| r.user_id == alice).expect("a row");
        assert!(!row.is_screen_sharing && !row.is_muted, "{row:?}");
        // The control: in a room that is only locked, it is told as ever
        let locked = state
            .create_channel(
                "Locked".into(),
                Some("pw".into()),
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, locked.channel_id, Some("pw"))
            .await
            .unwrap();
        busy(&state);
        let (_, rows, _, _) = state.channel_page(text.channel_id, bob_sid, 0).await;
        let row = rows.iter().find(|r| r.user_id == alice).expect("a row");
        assert!(row.is_screen_sharing && row.is_muted, "{row:?}");
    }

    #[test]
    fn a_pseudonym_is_too_long_to_come_round_again_and_has_a_shape_of_its_own() {
        let name = mint_pseudonym(&HashMap::new());
        assert!(is_pseudonym(&name), "{name}");
        assert_eq!(name.len(), "Guest-".len() + 8, "{name}");
        assert!(is_pseudonym("Guest-1234"), "a ban from before");
        for other in [
            "guest-1234",
            "GUEST-1234",
            "Guest-",
            "Guest-12a4",
            "gus#1234",
        ] {
            assert!(!is_pseudonym(other), "{other}");
        }
    }

    #[tokio::test]
    async fn an_admin_sees_the_real_names() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (mod_id, mod_sid) = add_user(&state, "moderator");
        make_admin(&state, mod_sid);
        let ch = state
            .create_channel(
                "Ingame".into(),
                None,
                ProximityMode::Off,
                true,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .join_channel(mod_id, mod_sid, ch.channel_id, None)
            .await
            .unwrap();

        let seen = state.users_in_channel_for(ch.channel_id, mod_sid).await;
        let names: Vec<&str> = seen.iter().map(|u| u.username.as_str()).collect();
        assert!(names.contains(&"alice"), "{names:?}");
        assert_eq!(state.display_name(alice, mod_sid).await, "alice");
    }

    #[tokio::test]
    async fn a_pseudonym_lasts_only_for_the_visit() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Ingame".into(),
                None,
                ProximityMode::Off,
                true,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        let first = state.display_name(alice, alice_sid).await;

        state.leave_current_channel(alice, alice_sid).await;
        {
            let channels = state.channels.read().await;
            assert!(
                channels[&ch.channel_id].pseudonyms.is_empty(),
                "left behind"
            );
        }
        // Outside an anonymous channel the real name is used again
        assert_eq!(state.display_name(alice, alice_sid).await, "alice");

        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        let second = state.display_name(alice, alice_sid).await;
        assert!(second.starts_with("Guest-"));
        let _ = first; // a repeat is possible, just unlikely; identity is not the claim
    }

    #[tokio::test]
    async fn what_a_client_asked_to_hear_belongs_to_the_channel_it_asked_in() {
        // The one thing a routed channel tells this server is who each member
        // wants to hear. It has to go when they do — and when the channel stops
        // being routed, or switching it back on would enforce an answer from
        // another day against people who are not the same people any more.
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Ingame".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        let now = tokio::time::Instant::now();

        // Stepping back into the lobby
        state.routing.set_filter(alice_sid, Some(vec![7]));
        state.leave_current_channel(alice, alice_sid).await;
        assert!(
            state
                .routing
                .may_hear(ch.channel_id, alice, alice_sid, 9, now),
            "a filter outlived the channel it was asked in"
        );

        // …and switching the flag off, with the member still standing there
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        state.routing.set_filter(alice_sid, Some(vec![7]));
        state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    routed: Some(false),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(
            state
                .routing
                .may_hear(ch.channel_id, alice, alice_sid, 9, now),
            "a filter outlived the routing it belonged to"
        );
    }

    #[tokio::test]
    async fn an_ordinary_channel_uses_real_names() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        assert_eq!(state.display_name(alice, alice_sid).await, "alice");
        assert_eq!(
            state.users_in_channel_for(ch.channel_id, alice_sid).await[0].username,
            "alice"
        );
    }

    #[tokio::test]
    async fn switching_anonymity_on_and_off_swaps_the_names() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();

        let (on, changed) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    anonymous: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(on.anonymous);
        assert!(changed.anonymity, "the flip is what makes the names stale");
        assert!(state
            .display_name(alice, alice_sid)
            .await
            .starts_with("Guest-"));

        // Setting it to what it already holds moves nothing, so nobody has to
        // be told and no roster has to be rebuilt.
        let (_, again) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    anonymous: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(!again.any && !again.anonymity);

        let (off, changed) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    anonymous: Some(false),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(!off.anonymous);
        assert!(changed.anonymity);
        assert_eq!(state.display_name(alice, alice_sid).await, "alice");
    }

    #[tokio::test]
    async fn set_channel_options_permissions() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let (bob, _) = add_user(&state, "bob");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();

        // The creator may, a stranger may not, an admin may
        let (updated, _) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    hidden: Some(true),
                    screen_share: Some(false),
                    hide_members: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(updated.hidden && updated.hide_members && !updated.screen_share);
        assert!(state
            .set_channel_options(
                ch.channel_id,
                bob,
                ChannelOptions {
                    hidden: Some(false),
                    ..Default::default()
                },
                false
            )
            .await
            .is_err());
        assert!(state
            .set_channel_options(
                ch.channel_id,
                bob,
                ChannelOptions {
                    hidden: Some(false),
                    ..Default::default()
                },
                true
            )
            .await
            .is_ok());
        // Never the General channel
        assert!(state
            .set_channel_options(
                0,
                alice,
                ChannelOptions {
                    hidden: Some(true),
                    ..Default::default()
                },
                true
            )
            .await
            .is_err());

        // None leaves an option alone
        let (before, changed) = state
            .set_channel_options(ch.channel_id, alice, ChannelOptions::default(), false)
            .await
            .unwrap();
        assert!(!before.hidden, "hidden was set to false above");
        assert!(before.hide_members, "hide_members must be untouched");
        assert!(!changed.any, "a call that sets nothing changes nothing");
    }

    /// The server neither stores chat nor deletes it — this is the number a
    /// channel tells its members, so all it owes them is a bound and the usual
    /// "say nothing when nothing changed".
    #[tokio::test]
    async fn a_channels_message_timer_is_bounded_and_announced_once() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, true, alice)
            .await
            .unwrap();
        assert_eq!(ch.message_ttl_secs, 0, "a new channel has no timer");

        let (updated, changed) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    message_ttl_secs: Some(3600),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert_eq!(updated.message_ttl_secs, 3600);
        assert!(changed.any);

        // Setting the same value again announces nothing: this goes to every
        // session on the server.
        let (_, changed) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    message_ttl_secs: Some(3600),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(!changed.any);

        // A year is "never" dressed up as a setting.
        let (updated, _) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    message_ttl_secs: Some(u32::MAX),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert_eq!(updated.message_ttl_secs, 30 * 24 * 60 * 60);

        // And it can be switched off again.
        let (updated, changed) = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    message_ttl_secs: Some(0),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert_eq!(updated.message_ttl_secs, 0);
        assert!(changed.any);
    }

    /// A request that is refused leaves the channel exactly as it was: the
    /// error is all its sender is told, so half of it applied would be a
    /// change nobody knows about.
    #[tokio::test]
    async fn a_refused_options_request_changes_nothing() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let voice = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        let text = state
            .create_channel("news".into(), None, ProximityMode::Off, false, true, alice)
            .await
            .unwrap();
        let hidden_of = |id: ChannelId| {
            let state = &state;
            async move { state.channels.read().await[&id].info.hidden }
        };

        // A voice room has no posts of its own to reserve for its managers
        let err = state
            .set_channel_options(
                voice.channel_id,
                alice,
                ChannelOptions {
                    hidden: Some(true),
                    announce: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("text channel"), "{err}");
        assert!(
            !hidden_of(voice.channel_id).await,
            "hidden was applied before the refusal"
        );

        // The text channel's old refusal used to come after the rest had moved
        assert!(state
            .set_channel_options(
                text.channel_id,
                alice,
                ChannelOptions {
                    hidden: Some(true),
                    anonymous: Some(true),
                    ..Default::default()
                },
                false
            )
            .await
            .is_err());
        assert!(
            !hidden_of(text.channel_id).await,
            "hidden was applied before the refusal"
        );

        assert!(state
            .set_channel_options(
                text.channel_id,
                alice,
                ChannelOptions {
                    hidden: Some(true),
                    slow_mode_secs: Some(MAX_SLOW_MODE_SECS + 1),
                    ..Default::default()
                },
                false
            )
            .await
            .is_err());
        assert!(
            !hidden_of(text.channel_id).await,
            "hidden was applied before the refusal"
        );

        // What does apply, applies — and says so once
        let (updated, changed) = state
            .set_channel_options(
                text.channel_id,
                alice,
                ChannelOptions {
                    announce: Some(true),
                    slow_mode_secs: Some(30),
                    nsfw: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(updated.announce && updated.nsfw && updated.slow_mode_secs == 30);
        assert!(changed.any);
        let (_, changed) = state
            .set_channel_options(
                text.channel_id,
                alice,
                ChannelOptions {
                    announce: Some(true),
                    slow_mode_secs: Some(30),
                    nsfw: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(!changed.any);
        let (updated, _) = state
            .set_channel_options(
                voice.channel_id,
                alice,
                ChannelOptions {
                    nsfw: Some(true),
                    slow_mode_secs: Some(5),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(
            updated.nsfw && updated.slow_mode_secs == 5,
            "a voice room's chat can be paced and marked 18+"
        );
    }

    #[test]
    fn slow_mode_wait_counts_from_the_last_post_with_a_little_grace() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + std::time::Duration::from_millis(ms);
        assert_eq!(
            slow_mode_wait(None, at(0), 30),
            None,
            "a first post is never held back"
        );
        assert_eq!(slow_mode_wait(Some(t0), at(5_000), 0), None, "0 is off");
        assert_eq!(slow_mode_wait(Some(t0), at(0), 30), Some(30));
        assert_eq!(slow_mode_wait(Some(t0), at(10_000), 30), Some(20));
        // Half a second short is network jitter, not impatience
        assert_eq!(slow_mode_wait(Some(t0), at(29_500), 30), None);
        assert_eq!(slow_mode_wait(Some(t0), at(29_400), 30), Some(1));
        assert_eq!(slow_mode_wait(Some(t0), at(31_000), 30), None);
    }

    #[tokio::test]
    async fn screen_sharing_can_be_switched_off_per_channel() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Ingame".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    screen_share: Some(false),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();

        let err = state
            .start_screen_share(alice, alice_sid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("off in this channel"), "{err}");
        // The refusal must not leave the session marked as sharing: that flag
        // is only cleared on stop, so they could never share again
        assert!(!state.sessions.get(&alice_sid).unwrap().is_screen_sharing);

        // Switched back on, sharing works
        state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    screen_share: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert!(state
            .start_screen_share(alice, alice_sid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn switching_sharing_off_leaves_a_running_share_to_be_stopped() {
        // The option flip does not itself end the share; session.rs stops the
        // sharers it finds here, so the list must still be readable.
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .start_screen_share(alice, alice_sid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .unwrap();

        state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    screen_share: Some(false),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        let sharers: Vec<UserId> = {
            let channels = state.channels.read().await;
            channels[&ch.channel_id]
                .screen_shares
                .values()
                .map(|s| s.sharer_user_id)
                .collect()
        };
        assert_eq!(
            sharers,
            vec![alice],
            "the running share must still be findable"
        );
    }

    #[tokio::test]
    async fn a_hide_members_channel_shows_nobody_to_outsiders() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (bob, _) = add_user(&state, "bob");
        let ch = state
            .create_channel(
                "Ingame".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    hide_members: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();

        // The preview a non-member asks for is refused, password or not
        assert!(!state.is_channel_public_or_member(ch.channel_id, bob).await);
        // A member still sees the channel, since the keys are per member
        assert!(
            state
                .is_channel_public_or_member(ch.channel_id, alice)
                .await
        );
    }

    #[tokio::test]
    async fn persistent_channels_carry_their_options() {
        let state = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            vec![ChannelEntry {
                name: "Ingame".into(),
                proximity: ProximityMode::ThreeD,
                hidden: true,
                anonymous: true,
                screen_share: false,
                hide_members: true,
                ..Default::default()
            }],
            "t".into(),
        );
        let info = &state.channels.read().await[&1].info;
        assert!(info.hidden && info.anonymous && info.hide_members);
        assert!(!info.screen_share);
        assert_eq!(info.proximity, ProximityMode::ThreeD);
    }

    /// H1-05: a password an admin sets at runtime on a channel from
    /// channels.json lets in whoever types it.
    #[tokio::test]
    async fn a_runtime_password_on_a_persistent_channel_admits() {
        let state = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            vec![ChannelEntry {
                name: "Lounge".into(),
                ..Default::default()
            }],
            "t".into(),
        );
        assert!(state
            .set_channel_password(1, 9, Some("pw".into()), true)
            .await
            .unwrap()
            .is_some());
        assert!(state.channels.read().await[&1]
            .password
            .as_ref()
            .unwrap()
            .starts_with("$argon2id$"));
        let right = state.channel_password_attempt(1, 5, Some("pw")).await;
        let wrong = state.channel_password_attempt(1, 5, Some("nope")).await;
        let channels = state.channels.read().await;
        assert!(check_admission(
            &channels[&1],
            5,
            right.as_deref().map(|p| p.as_str()),
            true,
            0
        )
        .is_ok());
        assert!(check_admission(
            &channels[&1],
            5,
            wrong.as_deref().map(|p| p.as_str()),
            true,
            0
        )
        .is_err());
        assert!(
            check_admission(&channels[&1], 5, Some("pw"), true, 0).is_err(),
            "only an attempt checked against the hash gets in"
        );
    }

    /// Outside its gate a channel is not there, so working out a hash for it would tell it from
    /// one that is not there by how long the answer takes. Both turns taken: whatever waits for
    /// a turn cannot finish.
    #[tokio::test]
    async fn outside_a_gate_no_password_is_hashed() {
        let state = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            vec![ChannelEntry {
                name: "Lounge".into(),
                ..Default::default()
            }],
            "t".into(),
        );
        assert!(state
            .set_channel_password(1, 9, Some("pw".into()), true)
            .await
            .unwrap()
            .is_some());
        let _turns = state.channel_kdf.acquire_many(2).await.unwrap();
        let wait = std::time::Duration::from_millis(200);
        assert!(
            tokio::time::timeout(wait, state.channel_password_attempt(1, 5, Some("pw")))
                .await
                .is_err(),
            "the control: with no gate it waits for its turn"
        );
        state
            .channels
            .write()
            .await
            .get_mut(&1)
            .unwrap()
            .gate
            .groups = vec!["crew".into()];
        let attempt = tokio::time::timeout(wait, state.channel_password_attempt(1, 5, Some("pw")))
            .await
            .expect("nothing to wait for");
        let channels = state.channels.read().await;
        assert!(
            check_admission(
                &channels[&1],
                5,
                attempt.as_deref().map(|p| p.as_str()),
                true,
                0
            )
            .is_err(),
            "what comes back matches nothing, should a grant land in between"
        );
    }

    #[tokio::test]
    async fn persistent_channel_proximity_is_admin_only() {
        let state = ServerState::new(
            &ServerConfig::default(),
            ServerSettings::default(),
            vec![ChannelEntry {
                name: "Ingame".into(),
                description: String::new(),
                password: None,
                password_hash: None,
                max_users: 0,
                proximity: ProximityMode::Off,
                ..Default::default()
            }],
            "t".into(),
        );
        let (uid, _) = add_user(&state, "alice");
        // created_by is None on persistent channels, so only an admin passes
        assert!(state
            .set_channel_proximity(1, uid, ProximityMode::TwoD, false)
            .await
            .is_err());
        assert!(state
            .set_channel_proximity(1, uid, ProximityMode::TwoD, true)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn create_channel_duplicate_name_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        state
            .create_channel("Dup".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        let err = state
            .create_channel("Dup".into(), None, ProximityMode::Off, false, false, uid)
            .await;
        assert!(err.unwrap_err().to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn delete_channel_general_fails() {
        let state = make_state();
        let err = state.delete_channel(0).await;
        assert!(err.unwrap_err().to_string().contains("General"));
    }

    #[tokio::test]
    async fn delete_channel_empty_succeeds() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "ToDelete".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                uid,
            )
            .await
            .unwrap();
        assert!(state.delete_channel(ch.channel_id).await.is_ok());
        let channels = state.channels.read().await;
        assert!(!channels.contains_key(&ch.channel_id));
    }

    // ── Text channels ──────────────────────────────────────────────────

    #[tokio::test]
    async fn text_channel_join_is_a_subscription_not_a_move() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let voice = state
            .create_channel(
                "Voice".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        let text = state
            .create_channel(
                "Lounge".into(),
                None,
                ProximityMode::Off,
                false,
                true,
                alice,
            )
            .await
            .unwrap();
        assert!(text.text);
        // A text channel has no voice, so nothing to share or place there
        assert!(!text.screen_share);

        state
            .join_channel(alice, alice_sid, voice.channel_id, None)
            .await
            .unwrap();
        assert!(state
            .join_text_channel(alice, text.channel_id, None)
            .await
            .unwrap());

        // Still standing in the voice channel, and in both channels' members
        assert_eq!(
            state.sessions.get(&alice_sid).unwrap().channel_id,
            voice.channel_id
        );
        assert!(state.is_member(voice.channel_id, alice).await);
        assert!(state.is_member(text.channel_id, alice).await);

        // Joining again is a no-op rather than an error
        assert!(!state
            .join_text_channel(alice, text.channel_id, None)
            .await
            .unwrap());

        // Moving to another voice channel keeps the subscription
        state.leave_current_channel(alice, alice_sid).await;
        state.join_channel(alice, alice_sid, 0, None).await.unwrap();
        assert!(state.is_member(text.channel_id, alice).await);

        assert_eq!(
            state.leave_text_channel(alice, text.channel_id).await,
            Some(0)
        );
        assert!(!state.is_member(text.channel_id, alice).await);
        // Leaving twice says so rather than reporting an empty channel again
        assert_eq!(state.leave_text_channel(alice, text.channel_id).await, None);
    }

    /// There is no per-user ceiling on text subscriptions, and there must not
    /// be one: a server decides how many conversations it runs, and a client
    /// that is refused the seventeenth gets a channel that silently never
    /// opens. What the cap used to protect — one session creating channels and
    /// subscribing to all of them so none ever emptied and expired — is
    /// answered where the problem is, by a channel starting its delete timer
    /// when it is created (`handle_create_channel`).
    #[tokio::test]
    async fn one_user_can_hold_every_text_channel_on_the_server() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");

        let mut channels = Vec::new();
        for i in 0..state.settings.max_channels {
            channels.push(
                state
                    .create_channel(
                        format!("text-{i}"),
                        None,
                        ProximityMode::Off,
                        false,
                        true,
                        alice,
                    )
                    .await
                    .unwrap(),
            );
        }

        for ch in &channels {
            assert!(
                state
                    .join_text_channel(alice, ch.channel_id, None)
                    .await
                    .unwrap(),
                "a text channel this server has was refused to the user"
            );
        }
        for ch in &channels {
            assert!(state.is_member(ch.channel_id, alice).await);
        }

        // And every budget sized from the channel count can pay for having
        // done it — the joins above are the ones an auto-joining connect makes.
        let mut session = state.sessions.get_mut(&alice).unwrap();
        for _ in 0..channels.len() {
            assert!(session.join_rate.try_consume(), "the join budget ran out");
            assert!(
                session.may_relay_key_to(2),
                "the key-relay budget for one peer ran out"
            );
        }
        for _ in 0..channels.len() * voipc_crypto::HISTORY_SOURCES {
            assert!(
                session.history_request_rate.try_consume(),
                "the history budget ran out"
            );
        }
    }

    /// Refilled limiters (a departed user's among them) are pruned as the map grows, live
    /// ones never, and a map of live ones is not walked again at the next target.
    #[test]
    fn the_key_relay_map_prunes_refilled_limiters_only() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let mut s = state.sessions.get_mut(&alice).unwrap();
        s.key_relay_burst = 1.0;
        for target in 0..KEY_RELAY_PRUNE_AT as UserId {
            assert!(s.may_relay_key_to(target + 10));
        }
        // All spent: the next target finds nothing to prune, and the next prune waits
        assert!(s.may_relay_key_to(1));
        assert_eq!(s.key_relay_rate.len(), KEY_RELAY_PRUNE_AT + 1);
        assert_eq!(s.key_relay_prune_at, 2 * KEY_RELAY_PRUNE_AT);
        assert!(!s.may_relay_key_to(10), "a spent limiter is still there");
        // A second refills one token at KEY_RELAY_REFILL 2/s
        std::thread::sleep(std::time::Duration::from_millis(600));
        s.key_relay_prune_at = KEY_RELAY_PRUNE_AT;
        assert!(s.may_relay_key_to(2));
        assert_eq!(s.key_relay_rate.len(), 1, "every refilled one went");
        assert_eq!(s.key_relay_prune_at, KEY_RELAY_PRUNE_AT);
    }

    #[tokio::test]
    async fn leave_text_channel_refuses_a_voice_channel() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let voice = state
            .create_channel(
                "Voice".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, voice.channel_id, None)
            .await
            .unwrap();
        assert_eq!(
            state.leave_text_channel(alice, voice.channel_id).await,
            None
        );
        assert!(state.is_member(voice.channel_id, alice).await);
    }

    #[tokio::test]
    async fn disconnect_drops_every_text_subscription() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (bob, _) = add_user(&state, "bob");
        let one = state
            .create_channel("One".into(), None, ProximityMode::Off, false, true, alice)
            .await
            .unwrap();
        let two = state
            .create_channel("Two".into(), None, ProximityMode::Off, false, true, alice)
            .await
            .unwrap();
        state
            .join_text_channel(alice, one.channel_id, None)
            .await
            .unwrap();
        state
            .join_text_channel(alice, two.channel_id, None)
            .await
            .unwrap();
        state
            .join_text_channel(bob, one.channel_id, None)
            .await
            .unwrap();

        let mut left = state.leave_all_text_channels(alice).await;
        left.sort_unstable();
        // One still has bob in it, two is now empty
        assert_eq!(left, vec![(one.channel_id, 1), (two.channel_id, 0)]);
        state.remove_session(alice_sid).await;
        assert!(!state.is_member(one.channel_id, alice).await);
        assert!(state.is_member(one.channel_id, bob).await);
    }

    #[tokio::test]
    async fn text_channel_password_is_checked() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let ch = state
            .create_channel(
                "Secret".into(),
                Some("pw".into()),
                ProximityMode::Off,
                false,
                true,
                alice,
            )
            .await
            .unwrap();
        assert!(state
            .join_text_channel(alice, ch.channel_id, None)
            .await
            .is_err());
        assert!(state
            .join_text_channel(alice, ch.channel_id, Some("wrong"))
            .await
            .is_err());
        assert!(state
            .join_text_channel(alice, ch.channel_id, Some("pw"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn pseudonym_belongs_to_the_channel_it_was_minted_in() {
        // A user in an anonymous voice channel and an ordinary one must not
        // carry the pseudonym into the ordinary one.
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (bob, bob_sid) = add_user(&state, "bob");
        let plain = state
            .create_channel(
                "Voice".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        let anon = state
            .create_channel("Anon".into(), None, ProximityMode::Off, true, false, alice)
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, plain.channel_id, None)
            .await
            .unwrap();
        state
            .join_channel(bob, bob_sid, anon.channel_id, None)
            .await
            .unwrap();

        let (real, alias) = state.names_of_in(plain.channel_id, alice).await;
        assert_eq!(real, "alice");
        assert!(
            alias.is_none(),
            "an ordinary channel must not borrow a pseudonym"
        );

        let (_, alias) = state.names_of_in(anon.channel_id, bob).await;
        assert!(alias.is_some_and(|a| a.starts_with("Guest-")));
    }

    #[tokio::test]
    async fn a_text_channel_cannot_be_anonymous() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let err = state
            .create_channel(
                "Secrets".into(),
                None,
                ProximityMode::Off,
                true,
                true,
                alice,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("anonymous"), "{err}");

        // ...nor become one later
        let ch = state
            .create_channel(
                "Lounge".into(),
                None,
                ProximityMode::Off,
                false,
                true,
                alice,
            )
            .await
            .unwrap();
        let err = state
            .set_channel_options(
                ch.channel_id,
                alice,
                ChannelOptions {
                    anonymous: Some(true),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("anonymous"), "{err}");
    }

    /// A text channel's roster names that channel, not the voice room each
    /// member happens to be standing in.
    #[tokio::test]
    async fn text_roster_carries_the_text_channel_id() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let voice = state
            .create_channel(
                "Voice".into(),
                None,
                ProximityMode::Off,
                false,
                false,
                alice,
            )
            .await
            .unwrap();
        let text = state
            .create_channel(
                "Lounge".into(),
                None,
                ProximityMode::Off,
                false,
                true,
                alice,
            )
            .await
            .unwrap();
        state
            .join_channel(alice, alice_sid, voice.channel_id, None)
            .await
            .unwrap();
        state
            .join_text_channel(alice, text.channel_id, None)
            .await
            .unwrap();

        let roster = state.users_in_channel_for(text.channel_id, alice_sid).await;
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].channel_id, text.channel_id);
        // ...and the voice room still lists itself
        let roster = state
            .users_in_channel_for(voice.channel_id, alice_sid)
            .await;
        assert_eq!(roster[0].channel_id, voice.channel_id);
    }

    // ── Permission-gated operations ────────────────────────────────────

    #[tokio::test]
    async fn set_password_by_creator() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        let updated = state
            .set_channel_password(ch.channel_id, uid, Some("pw".into()), false)
            .await
            .unwrap();
        assert!(updated.unwrap().has_password);
        // ...and setting the same password again announces nothing
        assert!(state
            .set_channel_password(ch.channel_id, uid, Some("pw".into()), false)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn set_password_non_creator_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state
            .set_channel_password(ch.channel_id, uid2, Some("hack".into()), false)
            .await;
        assert!(err.unwrap_err().to_string().contains("creator"));
    }

    #[tokio::test]
    async fn set_password_general_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let err = state
            .set_channel_password(0, uid, Some("pw".into()), false)
            .await;
        assert!(err.unwrap_err().to_string().contains("General"));
    }

    #[tokio::test]
    async fn kick_user_by_creator() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state
            .join_channel(uid2, sid2, ch.channel_id, None)
            .await
            .unwrap();
        let (kicked_sid, remaining, moved) = state
            .kick_user(ch.channel_id, uid, uid2, false, false)
            .await
            .unwrap();
        assert_eq!(kicked_sid, sid2);
        assert_eq!(remaining, 1);
        assert!(moved);
    }

    /// The voice rooms (not text subscriptions) whose member set holds `uid`.
    async fn voice_rooms_of(state: &ServerState, uid: UserId) -> Vec<ChannelId> {
        let channels = state.channels.read().await;
        let mut rooms: Vec<ChannelId> = channels
            .values()
            .filter(|c| !c.info.text && c.members.contains(&uid))
            .map(|c| c.info.channel_id)
            .collect();
        rooms.sort();
        rooms
    }

    // S-002: a kick racing the target's own join. The join's leave read the
    // room before the kick took the lock, so it found nothing to leave; the
    // target must still end in exactly one voice room, the one it asked for.
    #[tokio::test]
    async fn a_kick_racing_the_targets_own_join_leaves_one_voice_room() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (bob, bob_sid) = add_user(&state, "bob");
        let x = state
            .create_channel("X".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        let y = state
            .create_channel("Y".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        for (uid, sid) in [(alice, alice_sid), (bob, bob_sid)] {
            state
                .join_channel(uid, sid, x.channel_id, None)
                .await
                .unwrap();
        }

        let (_, _, moved) = state
            .kick_user(x.channel_id, alice, bob, false, false)
            .await
            .unwrap();
        assert!(moved);
        // Moved under the kick's own lock, not by a later step of the handler
        assert_eq!(voice_rooms_of(&state, bob).await, vec![0]);
        assert_eq!(state.sessions.get(&bob_sid).unwrap().channel_id, 0);

        // Bob's join, whose leave ran against X and found nothing
        state
            .join_channel(bob, bob_sid, y.channel_id, None)
            .await
            .unwrap();
        assert_eq!(voice_rooms_of(&state, bob).await, vec![y.channel_id]);
        assert_eq!(
            state.sessions.get(&bob_sid).unwrap().channel_id,
            y.channel_id
        );

        // And the other way round: once bob has left X, a kick from X is
        // refused and moves nobody
        let err = state
            .kick_user(x.channel_id, alice, bob, false, false)
            .await;
        assert!(err.is_err());
        assert_eq!(voice_rooms_of(&state, bob).await, vec![y.channel_id]);
    }

    // S-002: a join that lands after the session's cleanup would leave an id
    // that nothing ever removes.
    #[tokio::test]
    async fn a_join_after_the_session_has_gone_is_refused() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let x = state
            .create_channel("X".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        state.remove_session(alice_sid).await.unwrap();
        assert!(state
            .join_channel(alice, alice_sid, x.channel_id, None)
            .await
            .is_err());
        assert!(voice_rooms_of(&state, alice).await.is_empty());
    }

    #[tokio::test]
    async fn kick_self_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        let err = state.kick_user(ch.channel_id, uid, uid, false, false).await;
        assert!(err.unwrap_err().to_string().contains("yourself"));
    }

    #[tokio::test]
    async fn kick_non_creator_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state
            .join_channel(uid2, sid2, ch.channel_id, None)
            .await
            .unwrap();
        let err = state
            .kick_user(ch.channel_id, uid2, uid, false, false)
            .await;
        assert!(err.unwrap_err().to_string().contains("creator"));
    }

    #[tokio::test]
    async fn add_invite_succeeds() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let (ch_name, inviter) = state
            .add_invite(ch.channel_id, uid, uid2, false)
            .await
            .unwrap();
        assert_eq!(ch_name, "Room");
        assert_eq!(inviter, "alice");
        let channels = state.channels.read().await;
        assert!(channels
            .get(&ch.channel_id)
            .unwrap()
            .invited_users
            .contains(&uid2));
    }

    #[tokio::test]
    async fn add_invite_limit() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        for i in 0..50 {
            let (target, _) = add_user(&state, &format!("user{i}"));
            state
                .add_invite(ch.channel_id, uid, target, false)
                .await
                .unwrap();
        }
        let (target, _) = add_user(&state, "overflow");
        let err = state.add_invite(ch.channel_id, uid, target, false).await;
        assert!(err.unwrap_err().to_string().contains("full"));
    }

    #[tokio::test]
    async fn a_summon_goes_with_its_invite() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let (mod_id, mod_sid) = add_user(&state, "mod");
        let (bob, bob_sid) = add_user(&state, "bob");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap()
            .channel_id;
        state.join_channel(mod_id, mod_sid, ch, None).await.unwrap();
        let summoned = || async { state.channels.read().await[&ch].summons.get(&bob).copied() };
        let summon = || state.add_invite(ch, mod_id, bob, true);

        summon().await.unwrap();
        assert_eq!(summoned().await, Some(mod_id));
        assert!(state.remove_invite(ch, bob).await);
        assert_eq!(summoned().await, None, "declined");

        // A creator's invite after it takes the answer back
        summon().await.unwrap();
        state.add_invite(ch, alice, bob, false).await.unwrap();
        assert_eq!(summoned().await, None, "the creator asked last");

        summon().await.unwrap();
        state.join_channel(bob, bob_sid, ch, None).await.unwrap();
        assert_eq!(summoned().await, None, "joined");
        state.leave_current_channel(bob, bob_sid).await;

        summon().await.unwrap();
        state.remove_session(bob_sid).await;
        assert_eq!(summoned().await, None, "gone");
        assert!(state.channels.read().await[&ch].invited_users.is_empty());
    }

    #[tokio::test]
    async fn a_summon_needs_someone_there_to_answer_it() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let (mod_id, mod_sid) = add_user(&state, "mod");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap()
            .channel_id;
        state.join_channel(mod_id, mod_sid, ch, None).await.unwrap();
        let err = state.add_invite(ch, mod_id, 4242, true).await.unwrap_err();
        assert!(err.to_string().contains("cannot join"), "{err}");
        assert!(state.channels.read().await[&ch].invited_users.is_empty());

        // A creator asks about nobody as before: this must not say who is online
        assert!(state.add_invite(ch, alice, 4242, false).await.is_ok());
    }

    // ── Screen share ───────────────────────────────────────────────────

    #[tokio::test]
    async fn start_screen_share() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        let others = state
            .start_screen_share(uid, sid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .unwrap();
        assert!(others.is_empty());
        assert!(state.sessions.get(&sid).unwrap().is_screen_sharing);
        let channels = state.channels.read().await;
        assert!(channels
            .get(&ch.channel_id)
            .unwrap()
            .screen_shares
            .contains_key(&uid));
    }

    /// `[media]`: a share holds `share_viewers`, and the relay sends what `video_egress_mbit`
    /// allows, counted at each share's resolution; watching again is never refused.
    #[tokio::test]
    async fn a_full_share_or_a_full_relay_refuses_the_next_viewer() {
        let state = ServerState::new(
            &ServerConfig {
                media: crate::config::MediaConfig {
                    share_viewers: 2,
                    video_egress_mbit: 10,
                    voice_room: 0,
                },
                ..ServerConfig::default()
            },
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        let people: Vec<_> = ["alice", "bob", "cat", "dan"]
            .iter()
            .map(|n| add_user(&state, n))
            .collect();
        let (alice, asid) = people[0];
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        for &(uid, sid) in &people {
            state
                .join_channel(uid, sid, ch.channel_id, None)
                .await
                .unwrap();
        }
        state
            .start_screen_share(alice, asid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .unwrap();
        let watch = |(uid, sid): (UserId, SessionId)| {
            let state = &state;
            async move {
                state
                    .watch_screen_share(uid, sid, alice, ch.channel_id)
                    .await
            }
        };
        watch(people[1]).await.unwrap();
        watch(people[1]).await.unwrap();
        // 7.5 Mbit/s sent, 7.5 more is past 10
        let err = watch(people[2]).await.unwrap_err();
        assert_eq!(err.to_string(), VIDEO_FULL);

        let roomy = ServerState::new(
            &ServerConfig {
                media: crate::config::MediaConfig {
                    share_viewers: 1,
                    video_egress_mbit: 1000,
                    voice_room: 0,
                },
                ..ServerConfig::default()
            },
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        let (a, a_sid) = add_user(&roomy, "alice");
        let (b, b_sid) = add_user(&roomy, "bob");
        let (c, c_sid) = add_user(&roomy, "cat");
        let ch = roomy
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, a)
            .await
            .unwrap();
        for (uid, sid) in [(a, a_sid), (b, b_sid), (c, c_sid)] {
            roomy
                .join_channel(uid, sid, ch.channel_id, None)
                .await
                .unwrap();
        }
        roomy
            .start_screen_share(a, a_sid, ch.channel_id, VideoCodec::H264, 480)
            .await
            .unwrap();
        roomy
            .watch_screen_share(b, b_sid, a, ch.channel_id)
            .await
            .unwrap();
        let err = roomy
            .watch_screen_share(c, c_sid, a, ch.channel_id)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), SHARE_FULL);
    }

    /// A voice room that names no limit takes `[media] voice_room`; a text channel, a routed
    /// room and one with its own limit do not.
    #[tokio::test]
    async fn a_voice_room_without_a_limit_takes_the_relays() {
        let state = ServerState::new(
            &ServerConfig {
                media: crate::config::MediaConfig {
                    voice_room: 2,
                    ..Default::default()
                },
                ..ServerConfig::default()
            },
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        let people: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|n| add_user(&state, n))
            .collect();
        let (a, _) = people[0];
        let room = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, a)
            .await
            .unwrap();
        let text = state
            .create_channel("Text".into(), None, ProximityMode::Off, false, true, a)
            .await
            .unwrap();
        for &(uid, sid) in &people[..2] {
            state
                .join_channel(uid, sid, room.channel_id, None)
                .await
                .unwrap();
        }
        let (c, c_sid) = people[2];
        let err = state
            .join_channel(c, c_sid, room.channel_id, None)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "channel is full");
        for &(uid, _) in &people {
            assert!(state
                .join_text_channel(uid, text.channel_id, None)
                .await
                .unwrap());
        }
        state
            .channels
            .write()
            .await
            .get_mut(&room.channel_id)
            .unwrap()
            .info
            .routed = true;
        state
            .join_channel(c, c_sid, room.channel_id, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn start_screen_share_general_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let err = state
            .start_screen_share(uid, sid, 0, VideoCodec::H264, 1080)
            .await;
        assert!(err.unwrap_err().to_string().contains("General"));
    }

    #[tokio::test]
    async fn stop_screen_share_clears_state() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .start_screen_share(uid, sid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .unwrap();
        state
            .stop_screen_share(uid, sid, ch.channel_id)
            .await
            .unwrap();
        assert!(!state.sessions.get(&sid).unwrap().is_screen_sharing);
        let channels = state.channels.read().await;
        assert!(!channels
            .get(&ch.channel_id)
            .unwrap()
            .screen_shares
            .contains_key(&uid));
    }

    #[tokio::test]
    async fn watch_screen_share_adds_viewer() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .start_screen_share(uid, sid, ch.channel_id, VideoCodec::H265, 1080)
            .await
            .unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state
            .join_channel(uid2, sid2, ch.channel_id, None)
            .await
            .unwrap();
        let watched = state
            .watch_screen_share(uid2, sid2, uid, ch.channel_id)
            .await
            .unwrap();
        assert_eq!(watched.sharer_sid, sid);
        assert_eq!(watched.new_count, 1);
        assert!(watched.edge.is_none(), "no pool, no edge");
        // The viewer is told what the sharer encodes with
        assert_eq!(watched.codec, VideoCodec::H265);
    }

    #[tokio::test]
    async fn watching_a_non_sharer_keeps_the_current_watch() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap();
        let (bob, bob_sid) = add_user(&state, "bob");
        let (carol, carol_sid) = add_user(&state, "carol");
        for (uid, sid) in [(alice, alice_sid), (bob, bob_sid), (carol, carol_sid)] {
            state
                .join_channel(uid, sid, ch.channel_id, None)
                .await
                .unwrap();
        }
        state
            .start_screen_share(alice, alice_sid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .unwrap();
        state
            .watch_screen_share(bob, bob_sid, alice, ch.channel_id)
            .await
            .unwrap();

        // Carol is not sharing: refused, and Bob is still watching Alice
        let err = state
            .watch_screen_share(bob, bob_sid, carol, ch.channel_id)
            .await;
        assert!(err.unwrap_err().to_string().contains("not screen sharing"));
        assert_eq!(
            state.sessions.get(&bob_sid).unwrap().watching_screenshare,
            Some(alice)
        );
        let channels = state.channels.read().await;
        let share = &channels.get(&ch.channel_id).unwrap().screen_shares[&alice];
        assert!(share.viewers.contains(&bob));
    }

    #[tokio::test]
    async fn cleanup_screen_shares_for_user() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, uid)
            .await
            .unwrap();
        state
            .join_channel(uid, sid, ch.channel_id, None)
            .await
            .unwrap();
        state
            .start_screen_share(uid, sid, ch.channel_id, VideoCodec::H264, 1080)
            .await
            .unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state
            .join_channel(uid2, sid2, ch.channel_id, None)
            .await
            .unwrap();
        state
            .watch_screen_share(uid2, sid2, uid, ch.channel_id)
            .await
            .unwrap();
        let cleanup = state
            .cleanup_screen_shares_for_user(uid, sid, ch.channel_id)
            .await;
        assert_eq!(cleanup.stopped_sharer_user_id, Some(uid));
        assert!(cleanup.viewers_to_notify_stopped.contains(&sid2));
    }

    /// Whose media queues `sharer`'s fan holds, of `people`; `None` without a fan. Each
    /// queue is in it once, and nothing else is.
    fn fanned(
        state: &ServerState,
        sharer: UserId,
        people: &[(UserId, mpsc::Sender<Bytes>)],
    ) -> Option<Vec<UserId>> {
        let fan = state.share_fans.get(&sharer)?;
        let mut who: Vec<UserId> = people
            .iter()
            .filter(|(_, tx)| fan.local.iter().any(|t| t.same_channel(tx)))
            .map(|&(uid, _)| uid)
            .collect();
        who.sort();
        assert_eq!(fan.local.len(), who.len(), "a queue twice, or a stranger's");
        assert!(fan.feeds.is_empty());
        Some(who)
    }

    #[tokio::test]
    async fn the_fan_follows_who_watches() {
        let state = make_state();
        let names = ["alice", "bob", "carol", "dan", "erin"];
        let people: Vec<(UserId, SessionId)> = names.iter().map(|n| add_user(&state, n)).collect();
        let queues: Vec<(UserId, mpsc::Sender<Bytes>)> = people
            .iter()
            .map(|&(uid, sid)| (uid, state.sessions.get(&sid).unwrap().media_tx.clone()))
            .collect();
        let [alice, bob, carol, dan, erin] = [0, 1, 2, 3, 4].map(|i| people[i].0);
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, false, alice)
            .await
            .unwrap()
            .channel_id;
        for &(uid, sid) in &people {
            state.join_channel(uid, sid, ch, None).await.unwrap();
        }
        let fan = |sharer| fanned(&state, sharer, &queues);

        // Start
        assert_eq!(fan(alice), None);
        state
            .start_screen_share(alice, alice, ch, VideoCodec::H264, 1080)
            .await
            .unwrap();
        assert_eq!(fan(alice), Some(vec![]));
        assert_eq!(state.share_fans.get(&alice).unwrap().channel_id, ch);

        // Watch, and the same watch again
        state.watch_screen_share(bob, bob, alice, ch).await.unwrap();
        assert_eq!(fan(alice), Some(vec![bob]));
        state.watch_screen_share(bob, bob, alice, ch).await.unwrap();
        assert_eq!(fan(alice), Some(vec![bob]));

        // A watch of another share takes Bob out of Alice's
        state
            .start_screen_share(carol, carol, ch, VideoCodec::H264, 1080)
            .await
            .unwrap();
        state.watch_screen_share(bob, bob, carol, ch).await.unwrap();
        assert_eq!(fan(alice), Some(vec![]));
        assert_eq!(fan(carol), Some(vec![bob]));

        // Stop watching
        state.watch_screen_share(dan, dan, carol, ch).await.unwrap();
        assert_eq!(fan(carol), Some(vec![bob, dan]));
        state
            .stop_watching_screen_share(bob, bob, ch)
            .await
            .unwrap();
        assert_eq!(fan(carol), Some(vec![dan]));

        // The cleanup of a viewer leaving
        state.watch_screen_share(bob, bob, alice, ch).await.unwrap();
        assert_eq!(fan(alice), Some(vec![bob]));
        state.cleanup_screen_shares_for_user(bob, bob, ch).await;
        assert_eq!(fan(alice), Some(vec![]));

        // A viewer's session gone, though nothing took it out of `viewers`
        state.remove_session(dan).await.unwrap();
        assert_eq!(fan(carol), Some(vec![]));

        // The sharer stops, and the cleanup of a sharer leaving
        state
            .watch_screen_share(erin, erin, carol, ch)
            .await
            .unwrap();
        assert_eq!(fan(carol), Some(vec![erin]));
        state.stop_screen_share(carol, carol, ch).await.unwrap();
        assert_eq!(fan(carol), None);
        state.cleanup_screen_shares_for_user(alice, alice, ch).await;
        assert_eq!(fan(alice), None);

        // A sharer's session gone
        state
            .start_screen_share(erin, erin, ch, VideoCodec::H264, 1080)
            .await
            .unwrap();
        assert_eq!(fan(erin), Some(vec![]));
        state.remove_session(erin).await.unwrap();
        assert_eq!(fan(erin), None);
    }

    /// A share left behind in a channel its sharer moved out of takes nothing from the share
    /// they started since: not when somebody watches it, nor when it is ended.
    #[tokio::test]
    async fn a_share_left_behind_does_not_touch_the_fan_in_force() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let (bob, _) = add_user(&state, "bob");
        let (carol, _) = add_user(&state, "carol");
        let queues: Vec<_> = [bob, carol]
            .map(|uid| (uid, state.sessions.get(&uid).unwrap().media_tx.clone()))
            .into();
        let mut rooms = Vec::new();
        for name in ["One", "Two"] {
            rooms.push(
                state
                    .create_channel(name.into(), None, ProximityMode::Off, false, false, alice)
                    .await
                    .unwrap()
                    .channel_id,
            );
        }
        let [one, two] = [rooms[0], rooms[1]];
        state.join_channel(alice, alice, one, None).await.unwrap();
        state.join_channel(carol, carol, one, None).await.unwrap();
        state
            .start_screen_share(alice, alice, one, VideoCodec::H264, 1080)
            .await
            .unwrap();
        // Moved without the share in `one` ended. No second share starts then
        // (`a_sharer_with_a_share_left_behind_starts_no_second_one`); should one, as here
        // with the flag put down by hand, the fan of the share in force is its own
        state.join_channel(alice, alice, two, None).await.unwrap();
        state.sessions.get_mut(&alice).unwrap().is_screen_sharing = false;
        state.join_channel(bob, bob, two, None).await.unwrap();
        state
            .start_screen_share(alice, alice, two, VideoCodec::H264, 1080)
            .await
            .unwrap();
        state
            .watch_screen_share(bob, bob, alice, two)
            .await
            .unwrap();

        state
            .watch_screen_share(carol, carol, alice, one)
            .await
            .unwrap();
        assert_eq!(fanned(&state, alice, &queues), Some(vec![bob]));
        state.stop_screen_share(alice, alice, one).await.unwrap();
        assert_eq!(fanned(&state, alice, &queues), Some(vec![bob]));
        assert_eq!(state.share_fans.get(&alice).unwrap().channel_id, two);
    }

    /// A share left in a room its sharer was moved out of, until that move's cleanup ends it:
    /// a stop asked of the new room does not end it, and no second share of the same sharer
    /// starts beside it. Past `channels` a share is known by its sharer alone, so two would
    /// feed each other's edges and end each other there.
    #[tokio::test]
    async fn a_sharer_with_a_share_left_behind_starts_no_second_one() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let mut rooms = Vec::new();
        for name in ["One", "Two"] {
            rooms.push(
                state
                    .create_channel(name.into(), None, ProximityMode::Off, false, false, alice)
                    .await
                    .unwrap()
                    .channel_id,
            );
        }
        let [one, two] = [rooms[0], rooms[1]];
        state.join_channel(alice, alice, one, None).await.unwrap();
        state
            .start_screen_share(alice, alice, one, VideoCodec::H264, 1080)
            .await
            .unwrap();
        state.join_channel(alice, alice, two, None).await.unwrap();
        assert!(state.stop_screen_share(alice, alice, two).await.is_err());
        assert!(state.sessions.get(&alice).unwrap().is_screen_sharing);
        assert!(state
            .start_screen_share(alice, alice, two, VideoCodec::H264, 1080)
            .await
            .is_err());
        // A cleanup of another room it is in leaves it up too
        state
            .cleanup_screen_shares_for_user(alice, alice, two)
            .await;
        assert!(state.sessions.get(&alice).unwrap().is_screen_sharing);
        // The cleanup of the room it was left in ends it: then a share may start
        state
            .cleanup_screen_shares_for_user(alice, alice, one)
            .await;
        assert!(!state.sessions.get(&alice).unwrap().is_screen_sharing);
        state
            .start_screen_share(alice, alice, two, VideoCodec::H264, 1080)
            .await
            .unwrap();
        // And a stop asked of a room with none, with none left anywhere, puts it down
        state
            .channels
            .write()
            .await
            .get_mut(&two)
            .unwrap()
            .screen_shares
            .clear();
        assert!(state.stop_screen_share(alice, alice, two).await.is_err());
        assert!(!state.sessions.get(&alice).unwrap().is_screen_sharing);
    }

    /// What a sharer heard, in a form tests compare.
    #[derive(Debug, PartialEq)]
    enum Heard {
        Count(u32),
        Summary { reporters: u32, viewers: u32 },
    }

    /// What a control queue holds, waiting for no more.
    async fn heard(rx: &mut crate::control::ControlRx) -> Vec<Heard> {
        let mut out = Vec::new();
        while let Ok(Some(frame)) =
            tokio::time::timeout(std::time::Duration::from_millis(20), rx.recv()).await
        {
            let mut buf = bytes::BytesMut::from(&frame[..]);
            let payload = voipc_protocol::codec::try_decode_frame(&mut buf)
                .unwrap()
                .unwrap();
            out.push(
                match voipc_protocol::codec::decode_server_msg(&payload).unwrap() {
                    ServerMessage::ViewerCountChanged { viewer_count } => {
                        Heard::Count(viewer_count)
                    }
                    ServerMessage::VideoLossSummary { reporters, viewers } => {
                        Heard::Summary { reporters, viewers }
                    }
                    other => panic!("not news of the viewers: {other:?}"),
                },
            );
        }
        out
    }

    fn summary(reporters: u32, viewers: u32) -> Heard {
        Heard::Summary { reporters, viewers }
    }

    /// A report counts for 2 s, as in the apps' own tally; a summary goes only after a new
    /// report, and a report of no loss is none.
    #[tokio::test]
    async fn a_loss_report_counts_in_the_summary_for_2_s() {
        let (tx, mut rx) = crate::control::control_queue(Arc::default());
        let mut news = ShareNews::new(tx);
        news.viewers_now(9);
        assert_eq!(heard(&mut rx).await, [Heard::Count(9)]);

        news.loss(11, 3, 50, 0);
        assert_eq!(heard(&mut rx).await, [], "kept for the tick");
        news.tick(500);
        assert_eq!(heard(&mut rx).await, [summary(1, 9)]);
        news.loss(12, 1, 50, 1_500);
        news.tick(1_600);
        assert_eq!(heard(&mut rx).await, [summary(2, 9)], "11 still counts");
        news.tick(2_600);
        assert_eq!(heard(&mut rx).await, [], "nothing new");
        news.loss(13, 2, 50, 3_000);
        news.loss(14, 0, 60, 3_000);
        news.tick(3_100);
        assert_eq!(
            heard(&mut rx).await,
            [summary(2, 9)],
            "11 is past its 2 s, and 14 lost nothing"
        );
    }

    /// A count that moves and comes back within the second is no news for the sharer.
    #[tokio::test]
    async fn a_count_back_where_it_was_by_the_tick_is_not_sent() {
        let (tx, mut rx) = crate::control::control_queue(Arc::default());
        let mut news = ShareNews::new(tx);
        news.viewers_now(1);
        news.viewers_now(2);
        news.tick(0);
        assert_eq!(heard(&mut rx).await, [Heard::Count(1), Heard::Count(2)]);
        news.viewers_now(3);
        news.viewers_now(2);
        news.tick(1_000);
        assert_eq!(heard(&mut rx).await, []);
    }
}
