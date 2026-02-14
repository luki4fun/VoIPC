use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use voipc_protocol::types::*;

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
    /// Sender for pushing TCP control messages to this user's writer task.
    pub tcp_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// The user's UDP source address (learned from their first UDP packet).
    pub udp_addr: Option<SocketAddr>,
    /// Random token for authenticating UDP voice packets.
    pub udp_token: u64,
    /// Rate limiter for chat messages (channel + DM).
    pub chat_rate: RateLimiter,
    /// Rate limiter for channel creation.
    pub create_channel_rate: RateLimiter,
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
    /// AES-256-GCM media encryption key for voice/video in this channel.
    /// None for General (channel 0) where voice is disabled. Zeroized on drop.
    pub media_key_bytes: Option<Zeroizing<[u8; 32]>>,
    /// Incrementing key ID for this channel's media key.
    pub media_key_id: u16,
}

/// The shared server state, designed for concurrent access.
pub struct ServerState {
    /// All active sessions, keyed by session_id.
    pub sessions: DashMap<SessionId, UserSession>,
    /// Reverse lookup: user_id -> session_id.
    pub user_to_session: DashMap<UserId, SessionId>,
    /// Reverse lookup: UDP address -> session_id (for routing incoming voice).
    pub addr_to_session: DashMap<SocketAddr, SessionId>,
    /// All channels, keyed by channel_id.
    pub channels: RwLock<HashMap<ChannelId, Channel>>,
    /// Maximum concurrent users.
    pub max_users: u32,
    /// UDP port (sent to clients during authentication).
    pub udp_port: u16,
    /// Runtime settings.
    pub settings: ServerSettings,
    /// Next user_id counter.
    next_user_id: AtomicU32,
    /// Next session_id counter.
    next_session_id: AtomicU32,
    /// Next channel_id counter (0 is reserved for General).
    next_channel_id: AtomicU32,
}

impl ServerState {
    /// Create a new server state from the given configuration.
    pub fn new(config: &ServerConfig, settings: ServerSettings) -> Self {
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
                },
                members: HashSet::new(),
                password: None,
                delete_timer: None,
                created_by: None,
                invited_users: HashSet::new(),
                screen_shares: HashMap::new(),
                media_key_bytes: None,
                media_key_id: 0,
            },
        );

        Self {
            sessions: DashMap::new(),
            user_to_session: DashMap::new(),
            addr_to_session: DashMap::new(),
            channels: RwLock::new(channels),
            max_users: config.max_users,
            udp_port: config.udp_port,
            settings,
            next_user_id: AtomicU32::new(1),
            next_session_id: AtomicU32::new(1),
            next_channel_id: AtomicU32::new(1),
        }
    }

    /// Allocate a new unique user ID.
    pub fn next_user_id(&self) -> UserId {
        self.next_user_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate a new unique session ID.
    pub fn next_session_id(&self) -> SessionId {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate a new unique channel ID.
    pub fn next_channel_id(&self) -> ChannelId {
        self.next_channel_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Get the total number of connected users.
    pub fn user_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if a username is already taken.
    pub fn is_username_taken(&self, username: &str) -> bool {
        self.sessions
            .iter()
            .any(|entry| entry.value().username == username)
    }

    /// Get a snapshot of all channel info (for sending to clients).
    pub async fn channel_list(&self) -> Vec<ChannelInfo> {
        let channels = self.channels.read().await;
        let mut list: Vec<ChannelInfo> = channels.values().map(|ch| ch.info.clone()).collect();
        list.sort_by_key(|ch| ch.channel_id);
        list
    }

    /// Get users in a specific channel.
    pub async fn users_in_channel(&self, channel_id: ChannelId) -> Vec<UserInfo> {
        let channels = self.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return Vec::new();
        };

        channel
            .members
            .iter()
            .filter_map(|&uid| {
                let sid = self.user_to_session.get(&uid)?;
                let session = self.sessions.get(&*sid)?;
                Some(UserInfo {
                    user_id: session.user_id,
                    username: session.username.clone(),
                    channel_id: session.channel_id,
                    is_muted: session.is_muted,
                    is_deafened: session.is_deafened,
                    is_screen_sharing: session.is_screen_sharing,
                })
            })
            .collect()
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
                match password {
                    Some(pw) if pw == channel_pw.as_str() => {}
                    _ => anyhow::bail!("incorrect channel password"),
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
            // Check password
            if let Some(ref channel_pw) = channel.password {
                match password {
                    Some(pw) if pw == channel_pw.as_str() => {}
                    _ => anyhow::bail!("incorrect channel password"),
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

        if let Some(addr) = &session.udp_addr {
            self.addr_to_session.remove(addr);
        }

        // Remove from channel
        let mut channels = self.channels.write().await;
        if let Some(channel) = channels.get_mut(&session.channel_id) {
            channel.members.remove(&session.user_id);
            channel.info.user_count = channel.members.len() as u32;
        }

        Some(session)
    }

    /// Create a new user-created channel.
    pub async fn create_channel(
        &self,
        name: String,
        password: Option<String>,
        created_by: UserId,
    ) -> anyhow::Result<ChannelInfo> {
        let mut channels = self.channels.write().await;

        // Enforce max channel limit (subtract 1 for the permanent General channel)
        let user_channels = channels.len().saturating_sub(1);
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
        };

        // Generate a random AES-256 media key for this channel
        let mut key_bytes = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut key_bytes);

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
                media_key_bytes: Some(Zeroizing::new(key_bytes)),
                media_key_id: 0,
            },
        );

        Ok(info)
    }

    /// Delete an empty, non-General channel.
    pub async fn delete_channel(&self, channel_id: ChannelId) -> anyhow::Result<()> {
        if channel_id == 0 {
            anyhow::bail!("cannot delete the General channel");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if !channel.members.is_empty() {
            anyhow::bail!("channel is not empty");
        }

        if let Some(ch) = channels.remove(&channel_id) {
            if let Some(timer) = ch.delete_timer {
                timer.abort();
            }
        }

        Ok(())
    }

    /// Change a channel's password (creator only). Returns the updated ChannelInfo.
    pub async fn set_channel_password(
        &self,
        channel_id: ChannelId,
        user_id: UserId,
        password: Option<String>,
    ) -> anyhow::Result<ChannelInfo> {
        if channel_id == 0 {
            anyhow::bail!("cannot modify the General channel");
        }

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel does not exist"))?;

        if channel.created_by != Some(user_id) {
            anyhow::bail!("only the channel creator can change the password");
        }

        channel.info.has_password = password.is_some();
        channel.password = password.map(Zeroizing::new);

        Ok(channel.info.clone())
    }

    /// Remove a user from a channel (creator kicks them).
    /// Returns the kicked user's session_id and the channel's remaining member count.
    pub async fn kick_user(
        &self,
        channel_id: ChannelId,
        requester_id: UserId,
        target_id: UserId,
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

        if channel.created_by != Some(requester_id) {
            anyhow::bail!("only the channel creator can kick users");
        }

        if !channel.members.remove(&target_id) {
            anyhow::bail!("user is not in this channel");
        }
        channel.info.user_count = channel.members.len() as u32;

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
                channel.password.is_none() || channel.members.contains(&user_id)
            }
            None => false,
        }
    }

    /// Get the current media key for a channel (if any).
    /// Returns (key_id, key_bytes) for non-General channels.
    pub async fn get_channel_media_key(&self, channel_id: ChannelId) -> Option<(u16, [u8; 32])> {
        let channels = self.channels.read().await;
        let channel = channels.get(&channel_id)?;
        let key_bytes = channel.media_key_bytes.as_ref()?;
        Some((channel.media_key_id, **key_bytes))
    }

    // ── Screen share methods ───────────────────────────────────────────

    /// Start a screen share. Returns session_ids of other channel members for notification.
    pub async fn start_screen_share(
        &self,
        user_id: UserId,
        session_id: SessionId,
        channel_id: ChannelId,
        resolution: u16,
    ) -> anyhow::Result<Vec<SessionId>> {
        if channel_id == 0 {
            anyhow::bail!("cannot screen share in the General channel");
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

        let mut channels = self.channels.write().await;
        let channel = channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("channel not found"))?;

        channel.screen_shares.insert(
            user_id,
            ScreenShareSession {
                sharer_user_id: user_id,
                sharer_session_id: session_id,
                viewers: HashSet::new(),
                resolution,
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
    /// Returns (sharer_session_id, old_viewer_count, new_viewer_count, Option<previous_sharer_session_for_unwatch>).
    pub async fn watch_screen_share(
        &self,
        viewer_user_id: UserId,
        viewer_session_id: SessionId,
        sharer_user_id: UserId,
        channel_id: ChannelId,
    ) -> anyhow::Result<(SessionId, u32, u32, Option<(UserId, SessionId, u32)>)> {
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

        Ok((share.sharer_session_id, old_count, new_count, prev_info))
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

    /// Get the UDP addresses of all viewers of a given sharer.
    /// Called from UDP routing to forward video packets only to viewers.
    pub async fn get_screen_share_viewer_addrs(
        &self,
        sharer_user_id: UserId,
        channel_id: ChannelId,
    ) -> Vec<SocketAddr> {
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
                session.udp_addr
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
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::settings::ServerSettings;

    fn make_state() -> ServerState {
        ServerState::new(&ServerConfig::default(), ServerSettings::default())
    }

    fn add_user(state: &ServerState, username: &str) -> (UserId, SessionId) {
        let user_id = state.next_user_id();
        let session_id = state.next_session_id();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let session = UserSession {
            user_id,
            session_id,
            username: username.into(),
            channel_id: 0,
            is_muted: false,
            is_deafened: false,
            tcp_tx: tx,
            udp_addr: None,
            udp_token: user_id as u64 * 1000,
            chat_rate: RateLimiter::new(5.0, 5.0),
            create_channel_rate: RateLimiter::new(1.0, 0.2),
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
        (user_id, session_id)
    }

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
        assert_eq!(state.next_session_id(), 1);
        assert_eq!(state.next_session_id(), 2);
        assert_eq!(state.next_channel_id(), 1);
        assert_eq!(state.next_channel_id(), 2);
    }

    #[test]
    fn username_taken() {
        let state = make_state();
        assert!(!state.is_username_taken("alice"));
        add_user(&state, "alice");
        assert!(state.is_username_taken("alice"));
        assert!(!state.is_username_taken("bob"));
    }

    // ── Channel operations ─────────────────────────────────────────────

    #[tokio::test]
    async fn validate_join_open_channel() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Open".into(), None, uid).await.unwrap();
        assert!(state.validate_join(ch.channel_id, None, uid).await.is_ok());
    }

    #[tokio::test]
    async fn validate_join_wrong_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Priv".into(), Some("secret".into()), uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state.validate_join(ch.channel_id, Some("wrong"), uid2).await;
        assert!(err.unwrap_err().to_string().contains("incorrect"));
    }

    #[tokio::test]
    async fn validate_join_correct_password() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Priv".into(), Some("secret".into()), uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        assert!(state.validate_join(ch.channel_id, Some("secret"), uid2).await.is_ok());
    }

    #[tokio::test]
    async fn validate_join_full_channel() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Small".into(), None, uid).await.unwrap();
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
        let ch = state.create_channel("Inv".into(), Some("secret".into()), uid).await.unwrap();
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
        let ch = state.create_channel("Test".into(), None, uid).await.unwrap();
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
        let ch = state.create_channel("Test".into(), Some("pw".into()), uid).await.unwrap();
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
        let ch = state.create_channel("Test".into(), None, uid).await.unwrap();
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
        let ch = state.create_channel("MyRoom".into(), Some("pw".into()), uid).await.unwrap();
        assert_eq!(ch.name, "MyRoom");
        assert!(ch.has_password);
        assert_eq!(ch.created_by, Some(uid));
        assert_eq!(ch.user_count, 0);
    }

    #[tokio::test]
    async fn create_channel_duplicate_name_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        state.create_channel("Dup".into(), None, uid).await.unwrap();
        let err = state.create_channel("Dup".into(), None, uid).await;
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
        let ch = state.create_channel("ToDelete".into(), None, uid).await.unwrap();
        assert!(state.delete_channel(ch.channel_id).await.is_ok());
        let channels = state.channels.read().await;
        assert!(!channels.contains_key(&ch.channel_id));
    }

    // ── Permission-gated operations ────────────────────────────────────

    #[tokio::test]
    async fn set_password_by_creator() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        let updated = state.set_channel_password(ch.channel_id, uid, Some("pw".into())).await.unwrap();
        assert!(updated.has_password);
    }

    #[tokio::test]
    async fn set_password_non_creator_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        let (uid2, _) = add_user(&state, "bob");
        let err = state.set_channel_password(ch.channel_id, uid2, Some("hack".into())).await;
        assert!(err.unwrap_err().to_string().contains("creator"));
    }

    #[tokio::test]
    async fn set_password_general_fails() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let err = state.set_channel_password(0, uid, Some("pw".into())).await;
        assert!(err.unwrap_err().to_string().contains("General"));
    }

    #[tokio::test]
    async fn kick_user_by_creator() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        let (kicked_sid, remaining) = state.kick_user(ch.channel_id, uid, uid2).await.unwrap();
        assert_eq!(kicked_sid, sid2);
        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    async fn kick_self_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let err = state.kick_user(ch.channel_id, uid, uid).await;
        assert!(err.unwrap_err().to_string().contains("yourself"));
    }

    #[tokio::test]
    async fn kick_non_creator_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        let err = state.kick_user(ch.channel_id, uid2, uid).await;
        assert!(err.unwrap_err().to_string().contains("creator"));
    }

    #[tokio::test]
    async fn add_invite_succeeds() {
        let state = make_state();
        let (uid, _) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
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
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
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
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        let others = state.start_screen_share(uid, sid, ch.channel_id, 720).await.unwrap();
        assert!(others.is_empty());
        assert!(state.sessions.get(&sid).unwrap().is_screen_sharing);
        let channels = state.channels.read().await;
        assert!(channels.get(&ch.channel_id).unwrap().screen_shares.contains_key(&uid));
    }

    #[tokio::test]
    async fn start_screen_share_general_fails() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let err = state.start_screen_share(uid, sid, 0, 720).await;
        assert!(err.unwrap_err().to_string().contains("General"));
    }

    #[tokio::test]
    async fn stop_screen_share_clears_state() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        state.start_screen_share(uid, sid, ch.channel_id, 720).await.unwrap();
        state.stop_screen_share(uid, sid, ch.channel_id).await.unwrap();
        assert!(!state.sessions.get(&sid).unwrap().is_screen_sharing);
        let channels = state.channels.read().await;
        assert!(!channels.get(&ch.channel_id).unwrap().screen_shares.contains_key(&uid));
    }

    #[tokio::test]
    async fn watch_screen_share_adds_viewer() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        state.start_screen_share(uid, sid, ch.channel_id, 720).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        let (sharer_sid, old, new, prev) =
            state.watch_screen_share(uid2, sid2, uid, ch.channel_id).await.unwrap();
        assert_eq!(sharer_sid, sid);
        assert_eq!(old, 0);
        assert_eq!(new, 1);
        assert!(prev.is_none());
    }

    #[tokio::test]
    async fn cleanup_screen_shares_for_user() {
        let state = make_state();
        let (uid, sid) = add_user(&state, "alice");
        let ch = state.create_channel("Room".into(), None, uid).await.unwrap();
        state.join_channel(uid, sid, ch.channel_id, None).await.unwrap();
        state.start_screen_share(uid, sid, ch.channel_id, 720).await.unwrap();
        let (uid2, sid2) = add_user(&state, "bob");
        state.join_channel(uid2, sid2, ch.channel_id, None).await.unwrap();
        state.watch_screen_share(uid2, sid2, uid, ch.channel_id).await.unwrap();
        let cleanup = state.cleanup_screen_shares_for_user(uid, sid, ch.channel_id).await;
        assert!(cleanup.notify_channel_share_stopped);
        assert_eq!(cleanup.stopped_sharer_user_id, Some(uid));
        assert!(cleanup.viewers_to_notify_stopped.contains(&sid2));
    }
}
