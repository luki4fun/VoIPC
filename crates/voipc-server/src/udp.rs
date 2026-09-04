use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, error, trace, warn};

use voipc_protocol::voice::{VoicePacketType, VOICE_HEADER_SIZE};

use crate::state::ServerState;

/// Maximum buffer size for incoming UDP packets.
/// Video fragments can be up to ~1400 bytes, voice up to 512.
const MAX_UDP_PACKET_SIZE: usize = 1500;

/// Run the UDP voice+video packet receive/forward loop.
pub async fn run_udp_loop(socket: Arc<UdpSocket>, state: Arc<ServerState>) {
    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    loop {
        let (len, src_addr) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                error!("UDP recv error: {}", e);
                continue;
            }
        };

        let data = &mut buf[..len];

        if data.is_empty() {
            continue;
        }

        let packet_type_byte = data[0];

        // Only encrypted media is relayed. Plaintext voice/video types exist
        // in the wire format but no keyed client ever sends them — accepting
        // them here would let anyone on-path inject audio into a channel.
        match packet_type_byte {
            // Voice control + encrypted voice (EOT 0x02, Ping 0x03, encrypted 0x05).
            // Pong (0x04) is server→client only; a relayed one would spoof RTT
            // and keepalive state on every receiver.
            0x02 | 0x03 | 0x05 => {
                handle_voice_packet(data, src_addr, &socket, &state).await;
            }
            // Encrypted video fragments (0x13, 0x14) + encrypted screen audio (0x15)
            0x13..=0x15 => {
                handle_video_packet(data, src_addr, &socket, &state).await;
            }
            _ => {
                debug!(src = %src_addr, "dropping UDP packet type: 0x{:02x}", packet_type_byte);
            }
        }
    }
}

/// Zero the sender's udp_token (bytes 5..13 of every media header) before a
/// packet is forwarded. The token authenticates NAT rebinds in
/// `resolve_session`; relaying it verbatim handed it to every peer, and a
/// peer behind the same public IP could then hijack the sender's binding.
fn scrub_token(data: &mut [u8]) {
    data[5..13].fill(0);
}

/// Handle a voice packet (existing SFU logic — forward to all channel members except sender).
///
/// Only the header is parsed — the payload is relayed verbatim, so no
/// per-packet payload allocation on the hot path.
async fn handle_voice_packet(
    data: &mut [u8],
    src_addr: std::net::SocketAddr,
    socket: &UdpSocket,
    state: &ServerState,
) {
    if data.len() < VOICE_HEADER_SIZE {
        debug!(src = %src_addr, "voice packet too short");
        return;
    }
    let packet_type = data[0];
    let packet_session_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let udp_token = u64::from_be_bytes([
        data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
    ]);

    // Look up session by UDP address, or learn the address
    let session_id = match resolve_session(src_addr, packet_session_id, udp_token, state) {
        Some(sid) => sid,
        None => return,
    };

    // UDP voice rate limiting
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.udp_voice_rate.try_consume())
        .unwrap_or(false);
    if !allowed {
        trace!(session_id, "UDP voice rate limit exceeded, dropping packet");
        return;
    }

    // Handle ping — echo back as a Pong, keeping the sequence (the client
    // uses it as a timestamp for RTT measurement)
    if packet_type == VoicePacketType::Ping as u8 {
        let mut pong = [0u8; VOICE_HEADER_SIZE];
        pong.copy_from_slice(&data[..VOICE_HEADER_SIZE]);
        pong[0] = VoicePacketType::Pong as u8;
        if let Err(e) = socket.send_to(&pong, src_addr).await {
            warn!(session_id, %src_addr, "pong send failed: {}", e);
        }
        return;
    }

    // Forward voice packet to all other members in the same channel
    let channel_id = match state.sessions.get(&session_id) {
        Some(session) => session.channel_id,
        None => {
            warn!(session_id, "voice forward: session not found in state");
            return;
        }
    };

    // Voice is disabled in the General channel (channel 0)
    if channel_id == 0 {
        debug!(session_id, "voice forward: dropping (General channel)");
        return;
    }

    scrub_token(data);

    // Collect recipient addresses, then release the channels lock BEFORE
    // sending — the lock is write-preferring, so holding it across awaited
    // sends would let any join/leave stall voice for the whole server.
    let member_addrs: Vec<std::net::SocketAddr> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            warn!(session_id, channel_id, "voice forward: channel not found");
            return;
        };
        channel
            .members
            .iter()
            .filter_map(|member_uid| {
                let member_sid = state.user_to_session.get(member_uid)?;
                if *member_sid == session_id {
                    return None;
                }
                state.sessions.get(&*member_sid)?.udp_addr
            })
            .collect()
    };

    for member_addr in member_addrs {
        if let Err(e) = socket.send_to(data, member_addr).await {
            warn!(%member_addr, "failed to forward voice packet: {}", e);
        }
    }
}

/// Handle a video packet — forward ONLY to viewers of this sharer (not all channel members).
async fn handle_video_packet(
    data: &mut [u8],
    src_addr: std::net::SocketAddr,
    socket: &UdpSocket,
    state: &ServerState,
) {
    // Video packets have the same session_id/udp_token layout as voice packets
    // at bytes 1-4 (session_id) and 5-12 (udp_token), so we can reuse the header parsing
    if data.len() < VOICE_HEADER_SIZE {
        debug!(src = %src_addr, "video packet too short");
        return;
    }

    let session_id_bytes = [data[1], data[2], data[3], data[4]];
    let session_id = u32::from_be_bytes(session_id_bytes);
    let udp_token = u64::from_be_bytes([
        data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
    ]);

    let resolved_session_id = match resolve_session(src_addr, session_id, udp_token, state) {
        Some(sid) => sid,
        None => return,
    };

    // UDP video rate limiting
    let allowed = state
        .sessions
        .get_mut(&resolved_session_id)
        .map(|mut s| s.udp_video_rate.try_consume())
        .unwrap_or(false);
    if !allowed {
        trace!(session_id, "UDP video rate limit exceeded, dropping packet");
        return;
    }

    // Get the sharer's user_id and channel_id
    let (sharer_user_id, channel_id) = match state.sessions.get(&resolved_session_id) {
        Some(session) => (session.user_id, session.channel_id),
        None => return,
    };

    if channel_id == 0 {
        return;
    }

    scrub_token(data);

    // Get viewer addresses for this sharer (only viewers, not all channel members)
    let viewer_addrs = state
        .get_screen_share_viewer_addrs(sharer_user_id, channel_id)
        .await;

    // Forward the raw packet to each viewer
    for viewer_addr in viewer_addrs {
        if let Err(e) = socket.send_to(data, viewer_addr).await {
            trace!("failed to forward video packet: {}", e);
        }
    }
}

/// Resolve a session from the source address (using address learning).
///
/// Security: always validates the UDP token (even on cache hit) and verifies the
/// source IP matches the TCP-authenticated peer IP.  A token- and IP-validated
/// packet from a new source port rebinds the session's UDP address (NAT
/// mappings expire and reopen on new ports).
fn resolve_session(
    src_addr: std::net::SocketAddr,
    packet_session_id: u32,
    packet_udp_token: u64,
    state: &ServerState,
) -> Option<u32> {
    // Fast path: cached address — still verify token every time
    if let Some(cached_sid) = state.addr_to_session.get(&src_addr) {
        let sid = *cached_sid;
        let valid = state
            .sessions
            .get(&sid)
            .map(|s| s.udp_token == packet_udp_token)
            .unwrap_or(false);
        if valid {
            return Some(sid);
        }
        // Token mismatch on cached entry — evict stale mapping
        drop(cached_sid);
        state.addr_to_session.remove(&src_addr);
        return None;
    }

    // Address learning: validate and bind in a single write-guard to prevent TOCTOU races.
    // Using get_mut() ensures the token check, IP check, first-packet-wins check, and
    // udp_addr assignment all happen atomically under the same DashMap shard lock.
    let mut session = state.sessions.get_mut(&packet_session_id)?;
    if session.udp_token != packet_udp_token {
        // debug, not warn: reachable by anyone on the internet before any
        // rate limit, and this task also relays everyone's voice
        debug!(
            session_id = packet_session_id,
            src = %src_addr,
            "rejected UDP: invalid token"
        );
        return None;
    }
    if session.tcp_peer_ip != src_addr.ip() {
        warn!(
            session_id = packet_session_id,
            src = %src_addr,
            expected_ip = %session.tcp_peer_ip,
            "rejected UDP: source IP doesn't match TCP peer"
        );
        return None;
    }
    // Validated rebind: NAT mappings expire during silent periods and come
    // back on a new source port. Token + TCP-peer-IP were just validated —
    // the same trust as the initial bind — so rebind instead of rejecting
    // (rejecting would kill voice until a full reconnect).
    let old_addr = session.udp_addr.filter(|&bound| bound != src_addr);
    let needs_insert = session.udp_addr != Some(src_addr);
    if needs_insert && old_addr.is_none() {
        // Guard cache size to prevent memory exhaustion from spoofed addresses
        // (a rebind frees its old slot, so only genuinely new binds count)
        let cache_cap = (state.max_users as usize).saturating_mul(2).max(64);
        if state.addr_to_session.len() >= cache_cap {
            warn!("addr_to_session cache full ({cache_cap}), rejecting new learning");
            return None;
        }
    }
    session.udp_addr = Some(src_addr);
    drop(session);

    if let Some(old) = old_addr {
        state.addr_to_session.remove(&old);
        tracing::info!(
            session_id = packet_session_id,
            old = %old,
            new = %src_addr,
            "UDP address rebound"
        );
    }
    if needs_insert {
        state.addr_to_session.insert(src_addr, packet_session_id);
    }

    debug!(
        session_id = packet_session_id,
        src = %src_addr,
        "learned UDP address"
    );
    Some(packet_session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_token_zeroes_only_the_token_bytes() {
        let mut pkt: Vec<u8> = (1u8..=20).collect();
        scrub_token(&mut pkt);
        assert_eq!(&pkt[..5], &[1, 2, 3, 4, 5]);
        assert_eq!(&pkt[5..13], &[0u8; 8]);
        assert_eq!(&pkt[13..], &[14, 15, 16, 17, 18, 19, 20]);
    }
}
