use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, error, trace, warn};

use voipc_protocol::voice::{VoicePacket, VoicePacketType, VOICE_HEADER_SIZE};

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

        let data = &buf[..len];

        if data.is_empty() {
            continue;
        }

        let packet_type_byte = data[0];

        match packet_type_byte {
            // Voice packets: 0x01-0x05 (includes encrypted voice 0x05)
            0x01..=0x05 => {
                handle_voice_packet(data, src_addr, &socket, &state).await;
            }
            // Video / screen-share audio packets: 0x10-0x15 (includes encrypted 0x13-0x15)
            0x10..=0x15 => {
                handle_video_packet(data, src_addr, &socket, &state).await;
            }
            _ => {
                warn!(src = %src_addr, "unknown UDP packet type: 0x{:02x}", packet_type_byte);
            }
        }
    }
}

/// Handle a voice packet (existing SFU logic — forward to all channel members except sender).
async fn handle_voice_packet(
    data: &[u8],
    src_addr: std::net::SocketAddr,
    socket: &UdpSocket,
    state: &ServerState,
) {
    let packet = match VoicePacket::from_bytes(data) {
        Ok(p) => p,
        Err(e) => {
            warn!(src = %src_addr, "invalid voice packet: {}", e);
            return;
        }
    };

    // Look up session by UDP address, or learn the address
    let session_id = match resolve_session(src_addr, packet.session_id, packet.udp_token, state) {
        Some(sid) => sid,
        None => return,
    };

    // Handle ping
    if packet.packet_type == VoicePacketType::Ping {
        let pong = VoicePacket {
            packet_type: VoicePacketType::Pong,
            session_id: packet.session_id,
            udp_token: packet.udp_token,
            sequence: packet.sequence,
            opus_data: Vec::new(),
            key_id: 0,
        };
        if let Err(e) = socket.send_to(&pong.to_bytes(), src_addr).await {
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

    let channels = state.channels.read().await;
    let Some(channel) = channels.get(&channel_id) else {
        warn!(session_id, channel_id, "voice forward: channel not found");
        return;
    };

    for &member_uid in &channel.members {
        let Some(member_sid) = state.user_to_session.get(&member_uid) else {
            continue;
        };
        if *member_sid == session_id {
            continue;
        }

        let Some(member_session) = state.sessions.get(&*member_sid) else {
            continue;
        };

        if let Some(member_addr) = member_session.udp_addr {
            if let Err(e) = socket.send_to(data, member_addr).await {
                warn!(
                    target_user = member_uid,
                    %member_addr,
                    "failed to forward voice packet: {}",
                    e
                );
            }
        }
    }
}

/// Handle a video packet — forward ONLY to viewers of this sharer (not all channel members).
async fn handle_video_packet(
    data: &[u8],
    src_addr: std::net::SocketAddr,
    socket: &UdpSocket,
    state: &ServerState,
) {
    // Video packets have the same session_id/udp_token layout as voice packets
    // at bytes 1-4 (session_id) and 5-12 (udp_token), so we can reuse the header parsing
    if data.len() < VOICE_HEADER_SIZE {
        warn!(src = %src_addr, "video packet too short");
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

    // Get the sharer's user_id and channel_id
    let (sharer_user_id, channel_id) = match state.sessions.get(&resolved_session_id) {
        Some(session) => (session.user_id, session.channel_id),
        None => return,
    };

    if channel_id == 0 {
        return;
    }

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
fn resolve_session(
    src_addr: std::net::SocketAddr,
    packet_session_id: u32,
    packet_udp_token: u64,
    state: &ServerState,
) -> Option<u32> {
    if let Some(sid) = state.addr_to_session.get(&src_addr) {
        return Some(*sid);
    }

    // Address learning: verify session_id exists AND udp_token matches
    let token_valid = state
        .sessions
        .get(&packet_session_id)
        .map(|s| s.udp_token == packet_udp_token)
        .unwrap_or(false);

    if token_valid {
        state.addr_to_session.insert(src_addr, packet_session_id);

        if let Some(mut session) = state.sessions.get_mut(&packet_session_id) {
            session.udp_addr = Some(src_addr);
        }

        debug!(
            session_id = packet_session_id,
            src = %src_addr,
            "learned UDP address"
        );

        Some(packet_session_id)
    } else {
        warn!(
            session_id = packet_session_id,
            src = %src_addr,
            "rejected UDP packet: invalid session or token"
        );
        None
    }
}
