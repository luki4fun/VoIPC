//! Implementation of `ServerBridge` for `ServerState`.
//!
//! This bridges the TS3 compatibility layer to the VoIPC server state,
//! allowing TS3 clients to be registered as users, join channels, etc.

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::sync::broadcast;
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{ChannelInfo, UserInfo};
use voipc_ts3compat::server_bridge::{
    BridgeEvent, ServerBridge, Ts3UserRegistration, UserSnapshot,
};

use crate::state::{RateLimiter, ServerState, UserSession};

#[async_trait]
impl ServerBridge for ServerState {
    async fn channel_list(&self) -> Vec<ChannelInfo> {
        self.channel_list().await
    }

    async fn connected_users(&self) -> Vec<UserSnapshot> {
        self.sessions
            .iter()
            .map(|entry| {
                let s = entry.value();
                UserSnapshot {
                    user_id: s.user_id,
                    username: s.username.clone(),
                    channel_id: s.channel_id,
                    is_muted: s.is_muted,
                    is_deafened: s.is_deafened,
                }
            })
            .collect()
    }

    fn next_user_id(&self) -> u32 {
        self.next_user_id()
    }

    fn next_session_id(&self) -> u32 {
        self.next_session_id()
    }

    async fn register_ts3_user(
        &self,
        info: Ts3UserRegistration,
    ) -> anyhow::Result<(u32, u32)> {
        let user_id = self.next_user_id();
        let session_id = self.next_session_id();

        // Create a dummy mpsc channel — TS3 clients get messages via UDP, not TCP.
        // The receiver is dropped immediately, so any sends will fail (which is fine).
        let (dummy_tx, _dummy_rx) = tokio::sync::mpsc::channel(1);

        let user_session = UserSession {
            user_id,
            session_id,
            username: info.username,
            channel_id: 0,
            is_muted: false,
            is_deafened: false,
            tcp_tx: dummy_tx,
            udp_addr: Some(info.addr),
            udp_token: 0, // TS3 clients don't use VoIPC UDP tokens
            chat_rate: RateLimiter::new(5.0, 5.0),
            create_channel_rate: RateLimiter::new(1.0, 0.2),
            prekey_rate: RateLimiter::new(1.0, 0.2),
            is_screen_sharing: false,
            watching_screenshare: None,
            identity_key: None,
            prekeys: Vec::new(),
            signed_prekey_id: None,
            signed_prekey: None,
            signed_prekey_signature: None,
            registration_id: 0,
            device_id: 1,
            is_ts3_client: true,
        };

        self.sessions.insert(session_id, user_session);
        self.user_to_session.insert(user_id, session_id);
        self.addr_to_session.insert(info.addr, session_id);

        Ok((user_id, session_id))
    }

    async fn join_channel(
        &self,
        user_id: u32,
        session_id: u32,
        channel_id: u32,
    ) -> anyhow::Result<Vec<u32>> {
        self.join_channel(user_id, session_id, channel_id, None)
            .await
    }

    async fn leave_current_channel(
        &self,
        user_id: u32,
        session_id: u32,
    ) -> Option<(u32, Vec<u32>, usize)> {
        self.leave_current_channel(user_id, session_id).await
    }

    async fn update_user_muted(&self, session_id: u32, muted: bool) {
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            session.is_muted = muted;
        }
    }

    async fn update_user_deafened(&self, session_id: u32, deafened: bool) {
        if let Some(mut session) = self.sessions.get_mut(&session_id) {
            session.is_deafened = deafened;
        }
    }

    async fn remove_user(&self, _user_id: u32, session_id: u32) {
        self.remove_session(session_id).await;
    }

    // ── Cross-protocol notifications ─────────────────────────────────────

    async fn broadcast_user_joined(&self, user_id: u32, session_id: u32, channel_id: u32) {
        let (username, is_muted, is_deafened) = self
            .sessions
            .get(&session_id)
            .map(|s| (s.username.clone(), s.is_muted, s.is_deafened))
            .unwrap_or_default();

        let msg = ServerMessage::UserJoined {
            user: UserInfo {
                user_id,
                username,
                channel_id,
                is_muted,
                is_deafened,
                is_screen_sharing: false,
            },
        };
        self.broadcast_to_all_tcp(&msg, Some(user_id)).await;
    }

    async fn broadcast_user_left(&self, user_id: u32, channel_id: u32) {
        let msg = ServerMessage::UserLeft {
            user_id,
            channel_id,
        };
        self.broadcast_to_all_tcp(&msg, Some(user_id)).await;
    }

    async fn broadcast_user_muted(&self, user_id: u32, channel_id: u32, muted: bool) {
        let msg = ServerMessage::UserMuted { user_id, muted };
        self.broadcast_to_channel_tcp(channel_id, &msg, Some(user_id))
            .await;
    }

    async fn broadcast_user_deafened(&self, user_id: u32, channel_id: u32, deafened: bool) {
        let msg = ServerMessage::UserDeafened { user_id, deafened };
        self.broadcast_to_channel_tcp(channel_id, &msg, Some(user_id))
            .await;
    }

    fn subscribe_events(&self) -> broadcast::Receiver<BridgeEvent> {
        self.subscribe_events()
    }

    fn emit_event(&self, event: BridgeEvent) {
        self.emit_event(event);
    }

    // ── Voice bridging ────────────────────────────────────────────────────

    async fn channel_voipc_voice_targets(
        &self,
        channel_id: u32,
        exclude_user_id: u32,
    ) -> Vec<SocketAddr> {
        let channels = self.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            return Vec::new();
        };
        channel
            .members
            .iter()
            .filter(|&&uid| uid != exclude_user_id)
            .filter_map(|&uid| {
                let sid = *self.user_to_session.get(&uid)?;
                let session = self.sessions.get(&sid)?;
                if session.is_ts3_client {
                    return None;
                }
                session.udp_addr
            })
            .collect()
    }

    async fn ts3_joined_channel(&self, channel_id: u32) {
        if channel_id == 0 {
            return; // Voice disabled in General
        }
        let mut channels = self.channels.write().await;
        if let Some(channel) = channels.get_mut(&channel_id) {
            let was_zero = channel.ts3_client_count == 0;
            channel.ts3_client_count += 1;
            if was_zero {
                drop(channels);
                let msg = ServerMessage::ChannelSecurityDowngraded { channel_id };
                self.broadcast_to_channel_tcp(channel_id, &msg, None).await;
            }
        }
    }

    async fn ts3_left_channel(&self, channel_id: u32) {
        if channel_id == 0 {
            return;
        }
        let mut channels = self.channels.write().await;
        if let Some(channel) = channels.get_mut(&channel_id) {
            channel.ts3_client_count = channel.ts3_client_count.saturating_sub(1);
            if channel.ts3_client_count == 0 {
                drop(channels);
                let msg = ServerMessage::ChannelSecurityRestored { channel_id };
                self.broadcast_to_channel_tcp(channel_id, &msg, None).await;
            }
        }
    }
}
