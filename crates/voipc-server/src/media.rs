//! Media relay (SFU). Voice, screen-share video and screen audio packets
//! arrive on a session's QUIC connection (datagrams or per-frame streams)
//! and are fanned out to the right peers through their `media_tx` queues.
//! Only the packet header is parsed — payloads are end-to-end encrypted and
//! relayed verbatim, with no per-packet payload allocation on the hot path.

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use voipc_protocol::types::SessionId;
use voipc_protocol::voice::{VoicePacketType, VOICE_HEADER_SIZE};

use crate::state::ServerState;

/// Largest media packet accepted (video fragments are at most 1280 bytes).
pub const MAX_PACKET_SIZE: usize = 1500;

/// Relay one media packet received from `session_id`'s connection.
pub async fn handle_packet(session_id: SessionId, data: Bytes, state: &ServerState) {
    // At least a media header, at most one packet.
    if !(VOICE_HEADER_SIZE..=MAX_PACKET_SIZE).contains(&data.len()) {
        return;
    }

    // Only the session's own id may appear in the header: receivers key
    // jitter buffers, speaking state and AES-GCM nonces by it, so a foreign
    // id would let one client inject into another's stream.
    let claimed = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    if claimed != session_id {
        debug!(session_id, claimed, "dropping media packet with foreign session id");
        return;
    }

    // Only encrypted media is relayed. Plaintext voice/video types exist
    // in the wire format but no keyed client ever sends them — accepting
    // them here would let anyone inject audio into a channel.
    match data[0] {
        // Voice control + encrypted voice (EOT 0x02, Ping 0x03, encrypted 0x05).
        // Pong (0x04) is server→client only; a relayed one would spoof RTT
        // on every receiver.
        0x02 | 0x03 | 0x05 => handle_voice_packet(session_id, data, state).await,
        // Encrypted video fragments (0x13, 0x14) + encrypted screen audio (0x15)
        0x13..=0x15 => handle_video_packet(session_id, data, state).await,
        other => debug!(session_id, "dropping media packet type: 0x{other:02x}"),
    }
}

/// Voice: forward to all channel members except the sender; answer pings.
async fn handle_voice_packet(session_id: SessionId, data: Bytes, state: &ServerState) {
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.udp_voice_rate.try_consume())
        .unwrap_or(false);
    if !allowed {
        trace!(session_id, "voice rate limit exceeded, dropping packet");
        return;
    }

    // Ping — echo back as a Pong, keeping the sequence (the client uses it
    // as a timestamp for RTT measurement)
    if data[0] == VoicePacketType::Ping as u8 {
        let mut pong = data[..VOICE_HEADER_SIZE].to_vec();
        pong[0] = VoicePacketType::Pong as u8;
        if let Some(tx) = state.sessions.get(&session_id).map(|s| s.media_tx.clone()) {
            let _ = tx.try_send(Bytes::from(pong));
        }
        return;
    }

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

    // Collect recipients under the channels read lock, send after releasing
    // it — the lock is write-preferring, so a join/leave must never wait
    // behind voice fan-out.
    let member_txs: Vec<mpsc::Sender<Bytes>> = {
        let channels = state.channels.read().await;
        let Some(channel) = channels.get(&channel_id) else {
            warn!(session_id, channel_id, "voice forward: channel not found");
            return;
        };
        channel
            .members
            .iter()
            .filter_map(|member_uid| {
                let member_sid = *state.user_to_session.get(member_uid)?;
                if member_sid == session_id {
                    return None;
                }
                Some(state.sessions.get(&member_sid)?.media_tx.clone())
            })
            .collect()
    };

    for tx in member_txs {
        // A full queue drops the packet, as UDP would.
        let _ = tx.try_send(data.clone());
    }
}

/// Video / screen audio: forward ONLY to viewers of this sharer.
async fn handle_video_packet(session_id: SessionId, data: Bytes, state: &ServerState) {
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .map(|mut s| s.udp_video_rate.try_consume())
        .unwrap_or(false);
    if !allowed {
        trace!(session_id, "video rate limit exceeded, dropping packet");
        return;
    }

    let (sharer_user_id, channel_id) = match state.sessions.get(&session_id) {
        Some(session) => (session.user_id, session.channel_id),
        None => return,
    };

    if channel_id == 0 {
        return;
    }

    for tx in state
        .get_screen_share_viewer_txs(sharer_user_id, channel_id)
        .await
    {
        let _ = tx.try_send(data.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_support::*;
    use voipc_protocol::types::VideoCodec;
    use voipc_protocol::video::VideoPacket;
    use voipc_protocol::voice::VoicePacket;

    fn encrypted_voice(session_id: u32) -> Bytes {
        Bytes::from(VoicePacket::encrypted_voice(session_id, 1, 1, vec![9; 40]).to_bytes())
    }

    #[tokio::test]
    async fn ping_is_answered_with_pong_to_sender_only() {
        let state = make_state();
        let (_, alice_sid, mut alice_media) = add_user_with_media(&state, "alice");
        let (_, _bob_sid, mut bob_media) = add_user_with_media(&state, "bob");

        handle_packet(alice_sid, Bytes::from(VoicePacket::ping(alice_sid, 77).to_bytes()), &state).await;

        let pong = VoicePacket::from_bytes(&alice_media.try_recv().unwrap()).unwrap();
        assert_eq!(pong.packet_type, VoicePacketType::Pong);
        assert_eq!(pong.sequence, 77);
        assert!(bob_media.try_recv().is_err());
    }

    #[tokio::test]
    async fn voice_reaches_channel_members_but_not_sender_or_outsiders() {
        let state = make_state();
        let (alice_uid, alice_sid, mut alice_media) = add_user_with_media(&state, "alice");
        let (bob_uid, bob_sid, mut bob_media) = add_user_with_media(&state, "bob");
        let (_, _carol_sid, mut carol_media) = add_user_with_media(&state, "carol");
        put_in_channel(&state, 5, &[(alice_uid, alice_sid), (bob_uid, bob_sid)]).await;

        let packet = encrypted_voice(alice_sid);
        handle_packet(alice_sid, packet.clone(), &state).await;

        assert_eq!(bob_media.try_recv().unwrap(), packet);
        assert!(alice_media.try_recv().is_err());
        assert!(carol_media.try_recv().is_err());
    }

    #[tokio::test]
    async fn voice_is_dropped_in_general() {
        let state = make_state();
        let (_, alice_sid, _) = add_user_with_media(&state, "alice");
        let (_, _bob_sid, mut bob_media) = add_user_with_media(&state, "bob");
        // Both sit in channel 0 by default
        handle_packet(alice_sid, encrypted_voice(alice_sid), &state).await;
        assert!(bob_media.try_recv().is_err());
    }

    #[tokio::test]
    async fn foreign_session_id_and_plaintext_are_dropped() {
        let state = make_state();
        let (alice_uid, alice_sid, _) = add_user_with_media(&state, "alice");
        let (bob_uid, bob_sid, mut bob_media) = add_user_with_media(&state, "bob");
        put_in_channel(&state, 5, &[(alice_uid, alice_sid), (bob_uid, bob_sid)]).await;

        // Alice claims bob's session id in the header
        handle_packet(alice_sid, encrypted_voice(bob_sid), &state).await;
        // Plaintext voice (0x01) is never relayed
        handle_packet(
            alice_sid,
            Bytes::from(VoicePacket::voice(alice_sid, 1, vec![1; 40]).to_bytes()),
            &state,
        )
        .await;
        // Too short / too long
        handle_packet(alice_sid, Bytes::from_static(&[0x05, 0, 0, 0, 1]), &state).await;
        handle_packet(alice_sid, Bytes::from(vec![0x05; MAX_PACKET_SIZE + 1]), &state).await;

        assert!(bob_media.try_recv().is_err());
    }

    #[tokio::test]
    async fn video_goes_to_viewers_only() {
        let state = make_state();
        let (alice_uid, alice_sid, _) = add_user_with_media(&state, "alice");
        let (bob_uid, bob_sid, mut bob_media) = add_user_with_media(&state, "bob");
        let (carol_uid, carol_sid, mut carol_media) = add_user_with_media(&state, "carol");
        put_in_channel(
            &state,
            5,
            &[(alice_uid, alice_sid), (bob_uid, bob_sid), (carol_uid, carol_sid)],
        )
        .await;
        state
            .start_screen_share(alice_uid, alice_sid, 5, 720, VideoCodec::H264)
            .await
            .unwrap();
        state
            .watch_screen_share(bob_uid, bob_sid, alice_uid, 5)
            .await
            .unwrap();

        let packet = Bytes::from(
            VideoPacket::encrypted_fragment(true, alice_sid, 1, 0, 1, 0, 1, vec![7; 100])
                .to_bytes(),
        );
        handle_packet(alice_sid, packet.clone(), &state).await;

        assert_eq!(bob_media.try_recv().unwrap(), packet);
        assert!(carol_media.try_recv().is_err());
    }
}
