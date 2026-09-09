use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use bytes::Bytes;
use dashmap::DashMap;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, RwLock};
use tracing::warn;
use zeroize::Zeroizing;

use voipc_protocol::types::*;

use crate::channels::ChannelEntry;
use crate::config::ServerConfig;
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

    /// Try to consume one token. Returns true if allowed, false if rate-limited.
    pub fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-user session state held by the server.
#[allow(dead_code)]
pub struct UserSession {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub username: String,
    pub channel_id: ChannelId,
    pub is_muted: bool,
    pub is_deafened: bool,
    /// Sender for pushing control messages to this user's writer task.
    pub tcp_tx: mpsc::Sender<Vec<u8>>,
    /// Media packets (voice, video, screen audio) queued for this user's
    /// QUIC session. A full queue drops the packet, like UDP would.
    pub media_tx: mpsc::Sender<Bytes>,
    /// The client's IP (bans).
    pub peer_ip: IpAddr,
    /// Logged in with the admin token.
    pub is_admin: bool,
    /// Failed AdminLogin attempts; the third closes the connection.
    pub admin_login_failures: u8,
    /// Woken by an admin kick/ban: the connection loop exits and cleans up.
    pub close: std::sync::Arc<tokio::sync::Notify>,
    /// Rate limiter for channel history requests (each one makes a peer
    /// encrypt and send up to ~48 KiB).
    pub history_request_rate: RateLimiter,
    /// Rate limiter for UDP voice packets (55 pkt/s — 50fps + margin).
    pub udp_voice_rate: RateLimiter,
    /// Rate limiter for position beacons (12 pkt/s — senders coalesce to 10 Hz).
    /// Separate from voice so positions cannot eat the voice budget.
    pub position_rate: RateLimiter,
    /// Rate limiter for UDP video packets (120 pkt/s — 60fps × 2 fragments avg).
    pub udp_video_rate: RateLimiter,
    /// Global rate limiter for all TCP messages (50 msg/s burst).
    pub global_rate: RateLimiter,
    /// Rate limiter for channel password attempts (3 burst, 1/s refill).
    pub password_attempt_rate: RateLimiter,
    /// Rate limiter for chat messages (channel + DM).
    pub chat_rate: RateLimiter,
    /// Rate limiter for keyframe requests relayed *to* this user as a sharer
    /// (each one forces an IDR); per share, so many viewers losing the same
    /// frames cannot storm the sharer.
    pub keyframe_relay_rate: RateLimiter,
    /// Rate limiter for this user's frame-loss reports as a viewer.
    pub loss_report_rate: RateLimiter,
    /// Rate limiter for channel creation.
    pub create_channel_rate: RateLimiter,
    /// Rate limiter for pre-key uploads.
    pub prekey_rate: RateLimiter,
    /// Rate limiter for pre-key bundle requests (each consumes a target's one-time key).
    pub prekey_bundle_rate: RateLimiter,
    /// Whether this user is currently screen sharing.
    pub is_screen_sharing: bool,
    /// The user_id of the screenshare this user is currently watching (if any).
    pub watching_screenshare: Option<UserId>,

    // ── E2E Encryption fields ─────────────────────────────────────────
    /// Client's long-term identity public key (Curve25519). Opaque to server.
    pub identity_key: Option<Vec<u8>>,
    /// Available one-time pre-keys (consumed when another user requests a bundle).
    pub prekeys: Vec<OneTimePreKey>,
    /// Current signed pre-key data.
    pub signed_prekey_id: Option<u32>,
    pub signed_prekey: Option<Vec<u8>>,
    pub signed_prekey_signature: Option<Vec<u8>>,
    /// Signal Protocol registration ID.
    pub registration_id: u32,
    /// Device ID (always 1 for now — single device per user).
    pub device_id: u32,
}

/// Tracks an active screen share session within a channel.
#[allow(dead_code)]
pub struct ScreenShareSession {
    pub sharer_user_id: UserId,
    pub sharer_session_id: SessionId,
    /// Set of user_ids currently watching this share.
    pub viewers: HashSet<UserId>,
    /// Resolution being shared.
    pub resolution: u16,
    /// Codec the sharer encodes with; handed to every viewer on watch.
    pub codec: VideoCodec,
}

/// A channel/room on the server.
#[allow(dead_code)]
pub struct Channel {
    pub info: ChannelInfo,
    /// Set of user_ids currently in this channel.
    pub members: HashSet<UserId>,
    /// Channel password (None = no password required). Zeroized on drop.
    pub password: Option<Zeroizing<String>>,
    /// Handle to the auto-delete timer task (cancelled when a user joins).
    pub delete_timer: Option<tokio::task::JoinHandle<()>>,
    /// Who created this channel (None for the permanent General channel).
    pub created_by: Option<UserId>,
    /// Users who have been invited (bypass password on join).
    pub invited_users: HashSet<UserId>,
    /// Active screen shares: sharer_user_id -> ScreenShareSession.
    pub screen_shares: HashMap<UserId, ScreenShareSession>,
    /// Whether this channel was loaded from channels.json and cannot be auto-deleted.
    pub persistent: bool,
    /// The name each member is known by here while the channel is anonymous.
    /// Assigned on join, dropped on leave; admins are told the real names.
    pub pseudonyms: HashMap<UserId, String>,
}

/// The name one recipient may see: the pseudonym unless they are an admin.
pub fn pick_name(real: &str, alias: &Option<String>, viewer_is_admin: bool) -> String {
    match alias {
        Some(alias) if !viewer_is_admin => alias.clone(),
        _ => real.to_string(),
    }
}

/// A pseudonym for an anonymous channel, unique among the ones in use.
fn mint_pseudonym(taken: &HashMap<UserId, String>) -> String {
    for _ in 0..64 {
        let name = format!("Guest-{:04}", rand::random::<u16>() % 10_000);
        if !taken.values().any(|n| n == &name) {
            return name;
        }
    }
    // 64 collisions in a row means the channel is impossibly full; fall back
    // to something unique rather than looping.
    format!("Guest-{}", rand::random::<u32>())
}

/// The shared server state, designed for concurrent access.
pub struct ServerState {
    /// All active sessions, keyed by session_id.
    pub sessions: DashMap<SessionId, UserSession>,
    /// Reverse lookup: user_id -> session_id.
    pub user_to_session: DashMap<UserId, SessionId>,
    /// Atomic username reservation: lowercase username -> session_id.
    pub username_to_session: DashMap<String, SessionId>,
    /// All channels, keyed by channel_id.
    pub channels: RwLock<HashMap<ChannelId, Channel>>,
    /// Maximum concurrent users.
    pub max_users: u32,
    /// Runtime settings.
    pub settings: ServerSettings,
    /// Admin token (from config, or generated at startup).
    pub admin_token: String,
    /// Banned IPs with their expiry (None = until restart). Memory only.
    pub bans: DashMap<IpAddr, Option<Instant>>,
    /// Next user_id counter (session_id is always equal to user_id).
    next_user_id: AtomicU32,
    /// Next channel_id counter (0 is reserved for General).
    next_channel_id: AtomicU32,
}

impl ServerState {
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
                    max_users: 0,
                    user_count: 0,
                    has_password: false,
                    created_by: None,
                    proximity: ProximityMode::Off,
                    hidden: false,
                    anonymous: false,
                    screen_share: true,
                    hide_members: false,
                },
                members: HashSet::new(),
                password: None,
                delete_timer: None,
                created_by: None,
                invited_users: HashSet::new(),
                screen_shares: HashMap::new(),
                persistent: false,
                pseudonyms: HashMap::new(),
            },
        );

        // Insert persistent channels from channels.json with IDs starting at 1
        let mut next_id: u32 = 1;
        for entry in &persistent_channels {
            let channel_id = next_id;
            next_id += 1;

            let has_password = entry.password_hash.is_some();
            let password = entry.password_hash.clone().map(Zeroizing::new);

            // A server with proximity chat switched off serves every channel
            // as `off`, so clients never see a mode they may not use.
            let proximity = if settings.proximity_enabled {
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

            channels.insert(
                channel_id,
                Channel {
                    info: ChannelInfo {
                        channel_id,
                        name: entry.name.clone(),
                        description: entry.description.clone(),
                        max_users: entry.max_users,
                        user_count: 0,
                        has_password,
                        created_by: None,
                        proximity,
                        hidden: entry.hidden,
                        anonymous: entry.anonymous,
                        screen_share: entry.screen_share,
                        hide_members: entry.hide_members,
                    },
                    members: HashSet::new(),
                    password,
                    delete_timer: None,
                    created_by: None,
                    invited_users: HashSet::new(),
                    screen_shares: HashMap::new(),
                    persistent: true,
                    pseudonyms: HashMap::new(),
                },
            );
        }

        Self {
            sessions: DashMap::new(),
            user_to_session: DashMap::new(),
            username_to_session: DashMap::new(),
            channels: RwLock::new(channels),
            max_users: config.max_users,
            settings,
            admin_token,
            bans: DashMap::new(),
            next_user_id: AtomicU32::new(1),
            next_channel_id: AtomicU32::new(next_id),
        }
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

    /// Whether the session is logged in as admin.
    pub fn is_admin(&self, session_id: SessionId) -> bool {
        self.sessions
            .get(&session_id)
            .map(|s| s.is_admin)
            .unwrap_or(false)
    }

    /// Whether `ip` is banned. An expired entry is dropped on the way.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        match self.bans.get(&ip).map(|e| *e) {
            None => false,
            Some(None) => true,
            Some(Some(until)) if Instant::now() < until => true,
            Some(Some(_)) => {
                self.bans.remove(&ip);
                false
            }
        }
    }

    /// Ban `ip` for `duration` (None = until the server restarts).
    pub fn ban(&self, ip: IpAddr, duration: Option<std::time::Duration>) {
        self.bans.insert(ip, duration.map(|d| Instant::now() + d));
    }

    /// Lift a ban. Returns whether one existed.
    pub fn unban(&self, ip: IpAddr) -> bool {
        self.bans.remove(&ip).is_some()
    }

    /// Active bans, sorted by IP; expired ones are purged.
    pub fn list_bans(&self) -> Vec<BanInfo> {
        let now = Instant::now();
        self.bans.retain(|_, until| until.map_or(true, |u| u > now));
        let mut bans: Vec<BanInfo> = self
            .bans
            .iter()
            .map(|e| BanInfo {
                ip: e.key().to_string(),
                expires_in_secs: e
                    .value()
                    .map(|u| u.saturating_duration_since(now).as_secs()),
            })
            .collect();
        bans.sort_by(|a, b| a.ip.cmp(&b.ip));
        bans
    }

    /// Broadcast a raw serialized message to all connected sessions.
    pub async fn broadcast_raw_to_all(&self, data: &[u8]) {
        for entry in self.sessions.iter() {
            let _ = entry.value().tcp_tx.try_send(data.to_vec());
        }
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

        channel
            .members
            .iter()
            .filter_map(|&uid| {
                let sid = self.user_to_session.get(&uid)?;
                let session = self.sessions.get(&*sid)?;
                let username = match anonymous.then(|| channel.pseudonyms.get(&uid)).flatten() {
                    Some(alias) => alias.clone(),
                    None => session.username.clone(),
                };
                Some(UserInfo {
                    user_id: session.user_id,
                    username,
                    channel_id: session.channel_id,
                    is_muted: session.is_muted,
                    is_deafened: session.is_deafened,
                    is_screen_sharing: session.is_screen_sharing,
                    is_admin: session.is_admin,
                })
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

        let is_invited = channel.invited_users.contains(&user_id);

        if !is_invited {
            if let Some(ref channel_pw) = channel.password {
                let matches = match password {
                    Some(pw) if channel.persistent => {
                        // Persistent channels store a SHA-256 hash — hash the attempt first
                        let attempt_hash = crate::channels::hash_password(pw);
                        attempt_hash.as_bytes().ct_eq(channel_pw.as_bytes()).into()
                    }
                    Some(pw) => {
                        // User-created channels store plaintext passwords
                        pw.as_bytes().ct_eq(channel_pw.as_bytes()).into()
                    }
                    None => false,
                };
                if !matches {
                    anyhow::bail!("incorrect channel password");
                }
            }
        }

        if channel.info.max_users > 0 && channel.members.len() >= channel.info.max_users as usize {
            anyhow::bail!("channel is full");
        }

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
    ) -> anyhow::Result<Vec<SessionId>> {
        let mut channels = self.channels.write().await;

        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel {} does not exist", channel_id))?;

        // Check if the user was invited (bypass password if so)
        let was_invited = channel.invited_users.remove(&user_id);

        if !was_invited {
            if let Some(ref channel_pw) = channel.password {
                let matches = match password {
                    Some(pw) if channel.persistent => {
                        let attempt_hash = crate::channels::hash_password(pw);
                        attempt_hash.as_bytes().ct_eq(channel_pw.as_bytes()).into()
                    }
                    Some(pw) => pw.as_bytes().ct_eq(channel_pw.as_bytes()).into(),
                    None => false,
                };
                if !matches {
                    anyhow::bail!("incorrect channel password");
                }
            }
        }

        if channel.info.max_users > 0 && channel.members.len() >= channel.info.max_users as usize {
            anyhow::bail!("channel is full");
        }

        // Cancel any pending delete timer
        if let Some(timer) = channel.delete_timer.take() {
            timer.abort();
        }

        // Get other members before adding (for notification)
        let others: Vec<SessionId> = channel
            .members
            .iter()
            .filter_map(|&uid| self.user_to_session.get(&uid).map(|s| *s))
            .collect();

        channel.members.insert(user_id);
        channel.info.user_count = channel.members.len() as u32;

        // In an anonymous channel this is the only name the other members
        // ever learn; it lasts as long as this visit.
        if channel.info.anonymous {
            let name = mint_pseudonym(&channel.pseudonyms);
            channel.pseudonyms.insert(user_id, name);
        }

        // Update the session's channel_id
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            session.channel_id = channel_id;
        }

        Ok(others)
    }

    /// Remove a user from their current channel.
    /// Returns (channel_id, remaining_session_ids, remaining_member_count).
    pub async fn leave_current_channel(
        &self,
        user_id: UserId,
        session_id: SessionId,
    ) -> Option<(ChannelId, Vec<SessionId>, usize)> {
        let channel_id = {
            let session = self.sessions.get(&session_id)?;
            session.channel_id
        };

        let mut channels = self.channels.write().await;
        let channel = channels.get_mut(&channel_id)?;

        // If the user isn't actually in this channel's member set, nothing to leave
        if !channel.members.remove(&user_id) {
            return None;
        }
        channel.info.user_count = channel.members.len() as u32;
        // Coming back means a new pseudonym, which is the point
        channel.pseudonyms.remove(&user_id);

        let remaining: Vec<SessionId> = channel
            .members
            .iter()
            .filter_map(|&uid| self.user_to_session.get(&uid).map(|s| *s))
            .collect();

        let count = channel.members.len();
        Some((channel_id, remaining, count))
    }

    /// Remove a user session entirely (on disconnect).
    pub async fn remove_session(&self, session_id: SessionId) -> Option<UserSession> {
        let (_, session) = self.sessions.remove(&session_id)?;

        self.user_to_session.remove(&session.user_id);
        self.username_to_session.remove(&session.username.to_lowercase());

        // Remove from channel
        let mut channels = self.channels.write().await;
        if let Some(channel) = channels.get_mut(&session.channel_id) {
            channel.members.remove(&session.user_id);
            channel.info.user_count = channel.members.len() as u32;
        }
        // Unanswered invites would otherwise pin the user_id in every
        // channel's invite set forever (ids are never reused) and fill the cap.
        for channel in channels.values_mut() {
            channel.invited_users.remove(&session.user_id);
        }

        Some(session)
    }

    /// Create a new user-created channel.
    pub async fn create_channel(
        &self,
        name: String,
        password: Option<String>,
        proximity: ProximityMode,
        anonymous: bool,
        created_by: UserId,
    ) -> anyhow::Result<ChannelInfo> {
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

        // Check for duplicate names
        if channels.values().any(|ch| ch.info.name == name) {
            anyhow::bail!("a channel with that name already exists");
        }

        let channel_id = self.next_channel_id();
        let has_password = password.is_some();

        let info = ChannelInfo {
            channel_id,
            name,
            description: String::new(),
            max_users: 0,
            user_count: 0,
            has_password,
            created_by: Some(created_by),
            proximity,
            // A user-created channel is an ordinary room; the rest are set
            // afterwards through SetChannelOptions.
            hidden: false,
            anonymous,
            screen_share: true,
            hide_members: false,
        };

        channels.insert(
            channel_id,
            Channel {
                info: info.clone(),
                members: HashSet::new(),
                password: password.map(Zeroizing::new),
                delete_timer: None,
                created_by: Some(created_by),
                invited_users: HashSet::new(),
                screen_shares: HashMap::new(),
                persistent: false,
                pseudonyms: HashMap::new(),
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
        let _ = channels.remove(&channel_id);

        Ok(())
    }

    /// Change a channel's password (creator or admin). Returns the updated ChannelInfo.
    pub async fn set_channel_password(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        password: Option<String>,
        is_admin: bool,
    ) -> anyhow::Result<ChannelInfo> {
        if channel_id == 0 {
            anyhow::bail!("cannot modify the General channel");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if !is_admin && channel.created_by != Some(user_id) {
            anyhow::bail!("only the channel creator can change the password");
        }

        channel.info.has_password = password.is_some();
        channel.password = password.map(Zeroizing::new);

        Ok(channel.info.clone())
    }

    /// Change a channel's proximity mode (creator or admin — persistent
    /// channels have no creator, so those are admin-only, exactly as their
    /// password is). Returns the updated ChannelInfo.
    pub async fn set_channel_proximity(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        proximity: ProximityMode,
        is_admin: bool,
    ) -> anyhow::Result<ChannelInfo> {
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

        if !is_admin && channel.created_by != Some(user_id) {
            anyhow::bail!("only the channel creator can change the proximity mode");
        }

        channel.info.proximity = proximity;

        Ok(channel.info.clone())
    }

    /// Change the other channel options (creator or admin — persistent
    /// channels have no creator, so those are admin-only, exactly as their
    /// password is). `None` leaves an option alone. Returns the updated info.
    pub async fn set_channel_options(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        hidden: Option<bool>,
        anonymous: Option<bool>,
        screen_share: Option<bool>,
        hide_members: Option<bool>,
        is_admin: bool,
    ) -> anyhow::Result<ChannelInfo> {
        if channel_id == 0 {
            anyhow::bail!("cannot modify the General channel");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if !is_admin && channel.created_by != Some(user_id) {
            anyhow::bail!("only the channel creator can change the channel options");
        }

        if let Some(v) = hidden {
            channel.info.hidden = v;
        }
        if let Some(v) = screen_share {
            channel.info.screen_share = v;
        }
        if let Some(v) = hide_members {
            channel.info.hide_members = v;
        }
        if let Some(v) = anonymous {
            if v != channel.info.anonymous {
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
            }
        }

        Ok(channel.info.clone())
    }

    /// The real name of `subject`, and the pseudonym they currently go by if
    /// they are in an anonymous channel.
    ///
    /// Broadcast loops resolve this once and then pick per recipient with
    /// [`pick_name`] — the alternative, calling [`Self::display_name`] inside
    /// the loop, would take the channels lock while holding a session shard.
    pub async fn names_of(&self, subject: UserId) -> (String, Option<String>) {
        let real = self
            .user_to_session
            .get(&subject)
            .and_then(|sid| self.sessions.get(&*sid).map(|s| s.username.clone()))
            .unwrap_or_default();
        let channels = self.channels.read().await;
        let alias = channels.values().find_map(|ch| {
            (ch.info.anonymous && ch.members.contains(&subject))
                .then(|| ch.pseudonyms.get(&subject).cloned())
                .flatten()
        });
        (real, alias)
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

    /// Remove a user from a channel (creator or admin kicks them).
    /// Returns the kicked user's session_id and the channel's remaining member count.
    pub async fn kick_user(
        &self,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
        requester_is_admin: bool,
    ) -> anyhow::Result<(SessionId, usize)> {
        if channel_id == 0 {
            anyhow::bail!("cannot kick users from the General channel");
        }

        if requester_id == target_id {
            anyhow::bail!("you cannot kick yourself");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if !requester_is_admin && channel.created_by != Some(requester_id) {
            anyhow::bail!("only the channel creator can kick users");
        }

        if !channel.members.remove(&target_id) {
            anyhow::bail!("user is not in this channel");
        }
        channel.info.user_count = channel.members.len() as u32;
        channel.pseudonyms.remove(&target_id);

        let target_session_id = self
            .user_to_session
            .get(&target_id)
            .map(|s| *s)
            .ok_or_else(|| anyhow::anyhow!("user session not found"))?;

        let remaining = channel.members.len();
        Ok((target_session_id, remaining))
    }

    /// Store a delete timer handle for a channel (replaces any existing one).
    pub async fn set_channel_delete_timer(
        &self,
        channel_id: ChannelId,
        handle: tokio::task::JoinHandle<()>,
    ) {
        let mut channels = self.channels.write().await;
        if let Some(channel) = channels.get_mut(&channel_id) {
            if let Some(old) = channel.delete_timer.take() {
                old.abort();
            }
            channel.delete_timer = Some(handle);
        }
    }

    /// Add a user to a channel's invite list (creator only).
    /// Returns (channel_name, inviter_username) for the notification.
    pub async fn add_invite(
        &self,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
    ) -> anyhow::Result<(String, String)> {
        if channel_id == 0 {
            anyhow::bail!("cannot invite to the General channel");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if channel.created_by != Some(requester_id) {
            anyhow::bail!("only the channel creator can invite users");
        }

        if channel.members.contains(&target_id) {
            anyhow::bail!("user is already in this channel");
        }

        if channel.invited_users.len() >= 50 {
            anyhow::bail!("invite list is full (max 50)");
        }

        let channel_name = channel.info.name.clone();
        channel.invited_users.insert(target_id);

        // Look up inviter's username
        let inviter_name = self
            .user_to_session
            .get(&requester_id)
            .and_then(|sid| self.sessions.get(&*sid).map(|s| s.username.clone()))
            .unwrap_or_else(|| "Unknown".into());

        Ok((channel_name, inviter_name))
    }

    /// Remove a user from a channel's invite list.
    pub async fn remove_invite(&self, channel_id: ChannelId, user_id: UserId) {
        let mut channels = self.channels.write().await;
        if let Some(channel) = channels.get_mut(&channel_id) {
            channel.invited_users.remove(&user_id);
        }
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
        resolution: u16,
        codec: VideoCodec,
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
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            if session.is_screen_sharing {
                anyhow::bail!("already screen sharing");
            }
            session.is_screen_sharing = true;
        } else {
            anyhow::bail!("session not found");
        }

        channel.screen_shares.insert(
            user_id,
            ScreenShareSession {
                sharer_user_id: user_id,
                sharer_session_id: session_id,
                viewers: HashSet::new(),
                resolution,
                codec,
            },
        );

        // Return other members' session_ids for broadcasting
        let others: Vec<SessionId> = channel
            .members
            .iter()
            .filter(|&&uid| uid != user_id)
            .filter_map(|&uid| self.user_to_session.get(&uid).map(|s| *s))
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
        // Unmark user as sharing
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            session.is_screen_sharing = false;
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        let share = channel
            .screen_shares
            .remove(&user_id)
            .ok_or_else(|| anyhow::anyhow!("not screen sharing"))?;

        // Clear watching state for all viewers
        let viewer_sessions: Vec<(UserId, SessionId)> = share
            .viewers
            .iter()
            .filter_map(|&vid| {
                let sid = *self.user_to_session.get(&vid)?;
                if let Some(mut vs) = self.sessions.get_mut(&sid) {
                    vs.watching_screenshare = None;
                }
                Some((vid, sid))
            })
            .collect();

        // All channel members for broadcast
        let member_sessions: Vec<SessionId> = channel
            .members
            .iter()
            .filter(|&&uid| uid != user_id)
            .filter_map(|&uid| self.user_to_session.get(&uid).map(|s| *s))
            .collect();

        Ok((viewer_sessions, member_sessions))
    }

    /// Start watching a screen share. Enforces one-at-a-time.
    /// Returns (sharer_session_id, old_viewer_count, new_viewer_count,
    /// Option<previous_sharer_session_for_unwatch>, share_codec).
    pub async fn watch_screen_share(
        &self,
        viewer_user_id: UserId,
        viewer_session_id: SessionId,
        sharer_user_id: UserId,
        channel_id: ChannelId,
    ) -> anyhow::Result<(SessionId, u32, u32, Option<(UserId, SessionId, u32)>, VideoCodec)> {
        // Check if viewer is already watching someone else — auto-unwatch
        let prev_unwatch = {
            let session = self
                .sessions
                .get(&viewer_session_id)
                .ok_or_else(|| anyhow::anyhow!("session not found"))?;
            session.watching_screenshare
        };

        let mut prev_info = None;
        if let Some(prev_sharer_id) = prev_unwatch {
            if prev_sharer_id != sharer_user_id {
                // Unwatch previous
                let mut channels = self.channels.write().await;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    if let Some(prev_share) = channel.screen_shares.get_mut(&prev_sharer_id) {
                        prev_share.viewers.remove(&viewer_user_id);
                        let new_count = prev_share.viewers.len() as u32;
                        prev_info =
                            Some((prev_sharer_id, prev_share.sharer_session_id, new_count));
                    }
                }
                drop(channels);
            }
        }

        // Set watching state
        if let Some(mut session) = self.sessions.get_mut(&viewer_session_id) {
            session.watching_screenshare = Some(sharer_user_id);
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        let share = channel
            .screen_shares
            .get_mut(&sharer_user_id)
            .ok_or_else(|| anyhow::anyhow!("user is not screen sharing"))?;

        let old_count = share.viewers.len() as u32;
        share.viewers.insert(viewer_user_id);
        let new_count = share.viewers.len() as u32;

        Ok((
            share.sharer_session_id,
            old_count,
            new_count,
            prev_info,
            share.codec,
        ))
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
        share.viewers.remove(&viewer_user_id);
        let new_count = share.viewers.len() as u32;

        Ok((sharer_user_id, share.sharer_session_id, old_count, new_count))
    }

    /// Get the media queues of all viewers of a given sharer.
    /// Called from media routing to forward video packets only to viewers.
    pub async fn get_screen_share_viewer_txs(
        &self,
        sharer_user_id: UserId,
        channel_id: ChannelId,
    ) -> Vec<mpsc::Sender<Bytes>> {
        let channels = self.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return Vec::new();
        };
        let Some(share) = channel.screen_shares.get(&sharer_user_id) else {
            return Vec::new();
        };

        share
            .viewers
            .iter()
            .filter_map(|&vid| {
                let sid = *self.user_to_session.get(&vid)?;
                let session = self.sessions.get(&sid)?;
                Some(session.media_tx.clone())
            })
            .collect()
    }

    /// Clean up screen share state when a user disconnects or leaves a channel.
    /// Returns a list of actions to take: (viewer notifications, sharer notifications).
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
            for &viewer_id in &share.viewers {
                if let Some(viewer_sid) = self.user_to_session.get(&viewer_id).map(|s| *s) {
                    if let Some(mut vs) = self.sessions.get_mut(&viewer_sid) {
                        vs.watching_screenshare = None;
                    }
                    cleanup.viewers_to_notify_stopped.push(viewer_sid);
                }
            }
            cleanup.notify_channel_share_stopped = true;
            cleanup.stopped_sharer_user_id = Some(user_id);
        }

        // Unmark sharing on session
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            session.is_screen_sharing = false;
        }

        // If the user was watching someone, remove them as a viewer
        let watching = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.watching_screenshare);

        if let Some(sharer_id) = watching {
            if let Some(share) = channel.screen_shares.get_mut(&sharer_id) {
                share.viewers.remove(&user_id);
                let new_count = share.viewers.len() as u32;
                cleanup.sharer_viewer_count_changed =
                    Some((share.sharer_session_id, new_count));
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
            .filter_map(|&uid| self.user_to_session.get(&uid).map(|s| *s))
            .collect();

        cleanup
    }
}

/// Result of cleaning up screen share state when a user leaves.
#[derive(Default)]
pub struct ScreenShareCleanup {
    /// Viewers to notify that the share they were watching stopped.
    pub viewers_to_notify_stopped: Vec<SessionId>,
    /// Whether to broadcast ScreenShareStopped to channel members.
    pub notify_channel_share_stopped: bool,
    /// The user_id of the share that stopped (if any).
    pub stopped_sharer_user_id: Option<UserId>,
    /// If the leaving user was a viewer, notify the sharer of new viewer count.
    pub sharer_viewer_count_changed: Option<(SessionId, u32)>,
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
        let (tx, _rx) = mpsc::channel(1);
        let (media_tx, media_rx) = mpsc::channel(16);
        let session = UserSession {
            user_id,
            session_id,
            username: username.into(),
            channel_id: 0,
            is_muted: false,
            is_deafened: false,
            tcp_tx: tx,
            media_tx,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            is_admin: false,
            admin_login_failures: 0,
            close: Default::default(),
            history_request_rate: RateLimiter::new(3.0, 0.5),
            udp_voice_rate: RateLimiter::new(55.0, 55.0),
            position_rate: RateLimiter::new(12.0, 12.0),
            udp_video_rate: RateLimiter::new(400.0, 1200.0),
            global_rate: RateLimiter::new(50.0, 50.0),
            password_attempt_rate: RateLimiter::new(3.0, 1.0),
            chat_rate: RateLimiter::new(5.0, 5.0),
            keyframe_relay_rate: RateLimiter::new(2.0, 1.0),
            loss_report_rate: RateLimiter::new(2.0, 1.0),
            create_channel_rate: RateLimiter::new(1.0, 0.2),
            prekey_rate: RateLimiter::new(1.0, 0.2),
            prekey_bundle_rate: RateLimiter::new(60.0, 1.0),
            is_screen_sharing: false,
            watching_screenshare: None,
            identity_key: None,
            prekeys: Vec::new(),
            signed_prekey_id: None,
            signed_prekey: None,
            signed_prekey_signature: None,
            registration_id: 0,
            device_id: 1,
        };
        state.sessions.insert(session_id, session);
        state.user_to_session.insert(user_id, session_id);
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
                description: String::new(),
                max_users: 0,
                user_count: 0,
                has_password: false,
                created_by: None,
                proximity: ProximityMode::Off,
                hidden: false,
                anonymous: false,
                screen_share: true,
                hide_members: false,
            },
            members: HashSet::new(),
            password: None,
            delete_timer: None,
            created_by: None,
            invited_users: HashSet::new(),
            screen_shares: HashMap::new(),
            persistent: false,
            pseudonyms: HashMap::new(),
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
        assert!(general.created_by.is_none());
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

    #[tokio::test]
    async fn validate_join_open_channel() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Open".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        assert!(state.validate_join(ch.channel_id, None, uid).await.is_ok());
    }

    #[tokio::test]
    async fn validate_join_wrong_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Priv".into(), Some("secret".into()), ProximityMode::Off, false, uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state.validate_join(ch.channel_id, Some("wrong"), uid2).await;
        assert!(err.unwrap_err().to_string().contains("incorrect"));
    }

    #[tokio::test]
    async fn validate_join_correct_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Priv".into(), Some("secret".into()), ProximityMode::Off, false, uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        assert!(state.validate_join(ch.channel_id, Some("secret"), uid2).await.is_ok());
    }

    #[tokio::test]
    async fn validate_join_full_channel() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Small".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        {
            let mut channels = state.channels.write().await;
            channels.get_mut(&ch.channel_id).unwrap().info.max_users = 1;
        }
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state.validate_join(ch.channel_id, None, uid2).await;
        assert!(err.unwrap_err().to_string().contains("full"));
    }

    #[tokio::test]
    async fn validate_join_invited_bypasses_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Inv".into(), Some("secret".into()), ProximityMode::Off, false, uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        {
            let mut channels = state.channels.write().await;
            channels.get_mut(&ch.channel_id).unwrap().invited_users.insert(uid2);
        }
        assert!(state.validate_join(ch.channel_id, None, uid2).await.is_ok());
    }

    #[tokio::test]
    async fn join_channel_adds_member() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Test".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        let others = state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        assert!(others.is_empty());
        let channels = state.channels.read().await;
        let channel = channels.get(&ch.channel_id).unwrap();
        assert!(channel.members.contains(&uid));
        assert_eq!(channel.info.user_count, 1);
    }

    #[tokio::test]
    async fn join_channel_clears_invite() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Test".into(), Some("pw".into()), ProximityMode::Off, false, uid).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        {
            let mut channels = state.channels.write().await;
            channels.get_mut(&ch.channel_id).unwrap().invited_users.insert(uid2);
        }
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        let channels = state.channels.read().await;
        assert!(!channels.get(&ch.channel_id).unwrap().invited_users.contains(&uid2));
    }

    #[tokio::test]
    async fn leave_channel_removes_member() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Test".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let (left_ch, remaining, count) = state.leave_current_channel(uid, sid).await.unwrap();
        assert_eq!(left_ch, ch.channel_id);
        assert!(remaining.is_empty());
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn create_channel_succeeds() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("MyRoom".into(), Some("pw".into()), ProximityMode::Off, false, uid).await.unwrap();
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
            .create_channel("Room".into(), None, ProximityMode::ThreeD, false, uid)
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
            .create_channel("Room".into(), None, ProximityMode::TwoD, false, uid)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disabled"));

        // An off channel is still fine, but it cannot be switched on later
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, uid)
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
        assert_eq!(on.channels.read().await[&1].info.proximity, ProximityMode::TwoD);

        let off = ServerState::new(
            &ServerConfig::default(),
            ServerSettings { proximity_enabled: false, ..ServerSettings::default() },
            vec![entry],
            "t".into(),
        );
        assert_eq!(off.channels.read().await[&1].info.proximity, ProximityMode::Off);
    }

    #[tokio::test]
    async fn set_channel_proximity_permissions() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let (other, _) = add_user(&state, "bob");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, uid)
            .await
            .unwrap();

        // Creator may change it
        let updated = state
            .set_channel_proximity(ch.channel_id, uid, ProximityMode::TwoD, false)
            .await
            .unwrap();
        assert_eq!(updated.proximity, ProximityMode::TwoD);

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
            .create_channel("Ingame".into(), None, ProximityMode::Off, true, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
        state.join_channel(bob, bob_sid, ch.channel_id, None).await.unwrap();

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

    #[tokio::test]
    async fn an_admin_sees_the_real_names() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (mod_id, mod_sid) = add_user(&state, "moderator");
        make_admin(&state, mod_sid);
        let ch = state
            .create_channel("Ingame".into(), None, ProximityMode::Off, true, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
        state.join_channel(mod_id, mod_sid, ch.channel_id, None).await.unwrap();

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
            .create_channel("Ingame".into(), None, ProximityMode::Off, true, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
        let first = state.display_name(alice, alice_sid).await;

        state.leave_current_channel(alice, alice_sid).await;
        {
            let channels = state.channels.read().await;
            assert!(channels[&ch.channel_id].pseudonyms.is_empty(), "left behind");
        }
        // Outside an anonymous channel the real name is used again
        assert_eq!(state.display_name(alice, alice_sid).await, "alice");

        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
        let second = state.display_name(alice, alice_sid).await;
        assert!(second.starts_with("Guest-"));
        let _ = first; // a repeat is possible, just unlikely; identity is not the claim
    }

    #[tokio::test]
    async fn an_ordinary_channel_uses_real_names() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
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
            .create_channel("Room".into(), None, ProximityMode::Off, false, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();

        let on = state
            .set_channel_options(ch.channel_id, alice, None, Some(true), None, None, false)
            .await
            .unwrap();
        assert!(on.anonymous);
        assert!(state.display_name(alice, alice_sid).await.starts_with("Guest-"));

        let off = state
            .set_channel_options(ch.channel_id, alice, None, Some(false), None, None, false)
            .await
            .unwrap();
        assert!(!off.anonymous);
        assert_eq!(state.display_name(alice, alice_sid).await, "alice");
    }

    #[tokio::test]
    async fn set_channel_options_permissions() {
        let state = make_state();
        let (alice, _) = add_user(&state, "alice");
        let (bob, _) = add_user(&state, "bob");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, alice)
            .await
            .unwrap();

        // The creator may, a stranger may not, an admin may
        let updated = state
            .set_channel_options(ch.channel_id, alice, Some(true), None, Some(false), Some(true), false)
            .await
            .unwrap();
        assert!(updated.hidden && updated.hide_members && !updated.screen_share);
        assert!(state
            .set_channel_options(ch.channel_id, bob, Some(false), None, None, None, false)
            .await
            .is_err());
        assert!(state
            .set_channel_options(ch.channel_id, bob, Some(false), None, None, None, true)
            .await
            .is_ok());
        // Never the General channel
        assert!(state
            .set_channel_options(0, alice, Some(true), None, None, None, true)
            .await
            .is_err());

        // None leaves an option alone
        let before = state
            .set_channel_options(ch.channel_id, alice, None, None, None, None, false)
            .await
            .unwrap();
        assert!(!before.hidden, "hidden was set to false above");
        assert!(before.hide_members, "hide_members must be untouched");
    }

    #[tokio::test]
    async fn screen_sharing_can_be_switched_off_per_channel() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Ingame".into(), None, ProximityMode::Off, false, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
        state
            .set_channel_options(ch.channel_id, alice, None, None, Some(false), None, false)
            .await
            .unwrap();

        let err = state
            .start_screen_share(alice, alice_sid, ch.channel_id, 720, VideoCodec::H264)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("off in this channel"), "{err}");
        // The refusal must not leave the session marked as sharing: that flag
        // is only cleared on stop, so they could never share again
        assert!(!state.sessions.get(&alice_sid).unwrap().is_screen_sharing);

        // Switched back on, sharing works
        state
            .set_channel_options(ch.channel_id, alice, None, None, Some(true), None, false)
            .await
            .unwrap();
        assert!(state
            .start_screen_share(alice, alice_sid, ch.channel_id, 720, VideoCodec::H264)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn switching_sharing_off_leaves_a_running_share_to_be_stopped() {
        // The option flip does not itself end the share; tcp.rs stops the
        // sharers it finds here, so the list must still be readable.
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let ch = state
            .create_channel("Room".into(), None, ProximityMode::Off, false, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
        state
            .start_screen_share(alice, alice_sid, ch.channel_id, 720, VideoCodec::H264)
            .await
            .unwrap();

        state
            .set_channel_options(ch.channel_id, alice, None, None, Some(false), None, false)
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
        assert_eq!(sharers, vec![alice], "the running share must still be findable");
    }

    #[tokio::test]
    async fn a_hide_members_channel_shows_nobody_to_outsiders() {
        let state = make_state();
        let (alice, alice_sid) = add_user(&state, "alice");
        let (bob, _) = add_user(&state, "bob");
        let ch = state
            .create_channel("Ingame".into(), None, ProximityMode::Off, false, alice)
            .await
            .unwrap();
        state.join_channel(alice, alice_sid, ch.channel_id, None).await.unwrap();
        state
            .set_channel_options(ch.channel_id, alice, None, None, None, Some(true), false)
            .await
            .unwrap();

        // The preview a non-member asks for is refused, password or not
        assert!(!state.is_channel_public_or_member(ch.channel_id, bob).await);
        // A member still sees the channel, since the keys are per member
        assert!(state.is_channel_public_or_member(ch.channel_id, alice).await);
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
        state.create_channel("Dup".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        let err = state.create_channel("Dup".into(), None, ProximityMode::Off, false, uid).await;
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
        let ch = state.create_channel("ToDelete".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        assert!(state.delete_channel(ch.channel_id).await.is_ok());
        let channels = state.channels.read().await;
        assert!(!channels.contains_key(&ch.channel_id));
    }

    // ── Permission-gated operations ────────────────────────────────────

    #[tokio::test]
    async fn set_password_by_creator() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        let updated = state.set_channel_password(ch.channel_id, uid, Some("pw".into()), false).await.unwrap();
        assert!(updated.has_password);
    }

    #[tokio::test]
    async fn set_password_non_creator_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state.set_channel_password(ch.channel_id, uid2, Some("hack".into()), false).await;
        assert!(err.unwrap_err().to_string().contains("creator"));
    }

    #[tokio::test]
    async fn set_password_general_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let err = state.set_channel_password(0, uid, Some("pw".into()), false).await;
        assert!(err.unwrap_err().to_string().contains("General"));
    }

    #[tokio::test]
    async fn kick_user_by_creator() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        let (kicked_sid, remaining) = state.kick_user(ch.channel_id, uid, uid2, false).await.unwrap();
        assert_eq!(kicked_sid, sid2);
        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn kick_self_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let err = state.kick_user(ch.channel_id, uid, uid, false).await;
        assert!(err.unwrap_err().to_string().contains("yourself"));
    }

    #[tokio::test]
    async fn kick_non_creator_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        let err = state.kick_user(ch.channel_id, uid2, uid, false).await;
        assert!(err.unwrap_err().to_string().contains("creator"));
    }

    #[tokio::test]
    async fn add_invite_succeeds() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let (ch_name, inviter) = state.add_invite(ch.channel_id, uid, uid2).await.unwrap();
        assert_eq!(ch_name, "Room");
        assert_eq!(inviter, "alice");
        let channels = state.channels.read().await;
        assert!(channels.get(&ch.channel_id).unwrap().invited_users.contains(&uid2));
    }

    #[tokio::test]
    async fn add_invite_limit() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        for i in 0..50 {
            let (target, _) = add_user(&state, &format!("user{i}"));
            state.add_invite(ch.channel_id, uid, target).await.unwrap();
        }
        let (target, _) = add_user(&state, "overflow");
        let err = state.add_invite(ch.channel_id, uid, target).await;
        assert!(err.unwrap_err().to_string().contains("full"));
    }

    // ── Screen share ───────────────────────────────────────────────────

    #[tokio::test]
    async fn start_screen_share() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let others = state.start_screen_share(uid, sid, ch.channel_id, 720, VideoCodec::H264).await.unwrap();
        assert!(others.is_empty());
        assert!(state.sessions.get(&sid).unwrap().is_screen_sharing);
        let channels = state.channels.read().await;
        assert!(channels.get(&ch.channel_id).unwrap().screen_shares.contains_key(&uid));
    }

    #[tokio::test]
    async fn start_screen_share_general_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let err = state.start_screen_share(uid, sid, 0, 720, VideoCodec::H264).await;
        assert!(err.unwrap_err().to_string().contains("General"));
    }

    #[tokio::test]
    async fn stop_screen_share_clears_state() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        state.start_screen_share(uid, sid, ch.channel_id, 720, VideoCodec::H264).await.unwrap();
        state.stop_screen_share(uid, sid, ch.channel_id).await.unwrap();
        assert!(!state.sessions.get(&sid).unwrap().is_screen_sharing);
        let channels = state.channels.read().await;
        assert!(!channels.get(&ch.channel_id).unwrap().screen_shares.contains_key(&uid));
    }

    #[tokio::test]
    async fn watch_screen_share_adds_viewer() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        state.start_screen_share(uid, sid, ch.channel_id, 720, VideoCodec::H265).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        let (sharer_sid, old, new, prev, codec) =
            state.watch_screen_share(uid2, sid2, uid, ch.channel_id).await.unwrap();
        assert_eq!(sharer_sid, sid);
        assert_eq!(old, 0);
        assert_eq!(new, 1);
        assert!(prev.is_none());
        // The viewer is told what the sharer encodes with
        assert_eq!(codec, VideoCodec::H265);
    }

    #[tokio::test]
    async fn cleanup_screen_shares_for_user() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, ProximityMode::Off, false, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        state.start_screen_share(uid, sid, ch.channel_id, 720, VideoCodec::H264).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        state.watch_screen_share(uid2, sid2, uid, ch.channel_id).await.unwrap();
        let cleanup = state.cleanup_screen_shares_for_user(uid, sid, ch.channel_id).await;
        assert!(cleanup.notify_channel_share_stopped);
        assert_eq!(cleanup.stopped_sharer_user_id, Some(uid));
        assert!(cleanup.viewers_to_notify_stopped.contains(&sid2));
    }
}
