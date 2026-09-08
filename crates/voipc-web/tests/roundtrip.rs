//! Host-target round trips through the plain Rust core (the wasm-bindgen
//! layer is a thin wrapper over it). They also prove that the libsignal
//! futures resolve on the first poll and that the Kyber stub is never reached.

use voipc_crypto::{build_aad, media_encrypt, MediaKey};
use voipc_protocol::video::{
    fragment_frame, stream_records, ScreenShareAudioPacket, VideoPacket,
    MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE, MAX_VIDEO_PACKET_SIZE,
};
use voipc_web::media::{self, VideoAssemblerCore};
use voipc_web::signal::SignalCore;

const ALICE: u32 = 1;
const BOB: u32 = 2;

#[test]
fn signal_pairwise_and_group_round_trip() {
    let mut alice = SignalCore::new().unwrap();
    let mut bob = SignalCore::new().unwrap();

    let bob_bundle = bob.bundle().unwrap();
    assert_eq!(bob_bundle.prekey_bundle.prekeys.len(), 100);
    assert_eq!(bob_bundle.identity_key, bob_bundle.prekey_bundle.identity_key);
    assert_eq!(bob_bundle.prekey_bundle.device_id, 1);
    assert_eq!(bob_bundle.prekey_bundle.signed_prekey_id, 1);

    alice
        .establish_session(BOB, &bob_bundle.prekey_bundle)
        .unwrap();

    let (ct, ty) = alice.encrypt(BOB, b"hello bob").unwrap();
    assert_eq!(ty, 1, "first message is a PreKeySignalMessage");
    assert_eq!(bob.decrypt(ALICE, &ct, ty).unwrap(), b"hello bob");

    // Bob now has a session too and answers with a normal SignalMessage.
    let (ct, ty) = bob.encrypt(ALICE, b"hi alice").unwrap();
    assert_eq!(ty, 2);
    assert_eq!(alice.decrypt(BOB, &ct, ty).unwrap(), b"hi alice");

    // The one-time pre-key Alice used is no longer advertised.
    assert_eq!(bob.bundle().unwrap().prekey_bundle.prekeys.len(), 99);

    // Sender keys for channel 5.
    let dist = alice.create_sender_key_distribution(ALICE, 5).unwrap();
    bob.process_sender_key_distribution(ALICE, 5, &dist).unwrap();
    let ct = alice.group_encrypt(ALICE, 5, b"channel text").unwrap();
    assert_eq!(bob.group_decrypt(ALICE, 5, &ct).unwrap(), b"channel text");
}

#[test]
fn voice_packet_round_trip() {
    let key = MediaKey::generate(7, 3).unwrap();
    let opus = [0x11u8, 0x22, 0x33, 0x44, 0x55];
    let packet = media::build_voice_packet(&key, 42, 10, &opus).unwrap();
    assert_eq!(packet[0], 0x05);

    let info = media::parse_voice_packet(Some(&key), &packet).unwrap();
    assert_eq!(info.packet_type, 0x05);
    assert_eq!(info.session_id, 42);
    assert_eq!(info.sequence, 10);
    assert_eq!(info.opus.as_deref(), Some(&opus[..]));

    // Encrypted voice needs the key, and another key fails authentication.
    assert!(media::parse_voice_packet(None, &packet).is_err());
    let other = MediaKey::generate(7, 4).unwrap();
    assert!(media::parse_voice_packet(Some(&other), &packet).is_err());

    // EOT and ping are header only and need no key.
    let eot = media::parse_voice_packet(None, &media::build_eot_packet(42, 11)).unwrap();
    assert_eq!((eot.packet_type, eot.session_id, eot.sequence), (0x02, 42, 11));
    assert!(eot.opus.is_none());
    let ping = media::parse_voice_packet(None, &media::build_ping_packet(42, 12)).unwrap();
    assert_eq!((ping.packet_type, ping.sequence), (0x03, 12));
}

#[test]
fn position_packet_round_trip() {
    let key = MediaKey::generate(7, 3).unwrap();
    let packet = media::build_position_packet(&key, 42, 5, 1.5, -2.25, 0.75).unwrap();
    assert_eq!(packet[0], 0x06);
    assert_eq!(packet.len(), voipc_protocol::voice::POSITION_PACKET_SIZE);

    let info = media::parse_position_packet(&key, &packet).unwrap();
    assert_eq!(info.session_id, 42);
    assert_eq!((info.x, info.y, info.z), (1.5, -2.25, 0.75));

    // Wrong key fails authentication, and a voice packet is not a position
    let other = MediaKey::generate(7, 4).unwrap();
    assert!(media::parse_position_packet(&other, &packet).is_err());
    let voice = media::build_voice_packet(&key, 42, 10, &[1, 2, 3]).unwrap();
    assert!(media::parse_position_packet(&key, &voice).is_err());
    assert!(media::parse_voice_packet(Some(&key), &packet).is_err());
}

#[test]
fn screen_audio_round_trip() {
    let key = MediaKey::generate(7, 0).unwrap();
    let opus = [9u8; 40];
    let aad = build_aad(7, 0x15);
    let encrypted = media_encrypt(&key, 8, 100, 0, &aad, &opus).unwrap();
    let packet =
        ScreenShareAudioPacket::new_encrypted(8, 100, 2500, key.key_id, encrypted).to_bytes();

    let info = media::parse_screen_audio_packet(&key, &packet).unwrap();
    assert_eq!((info.session_id, info.sequence, info.timestamp), (8, 100, 2500));
    assert_eq!(info.opus, opus);

    // Plaintext screen audio is refused.
    let plain = ScreenShareAudioPacket::new(8, 101, 2520, opus.to_vec()).to_bytes();
    assert!(media::parse_screen_audio_packet(&key, &plain).is_err());
}

#[test]
fn video_fragments_reassemble() {
    let key = MediaKey::generate(7, 0).unwrap();
    let frame: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let (session_id, frame_id, timestamp) = (9, 0, 1234);

    // Encrypted exactly like the native sharer (client/src-tauri/src/screenshare/mod.rs).
    let packets: Vec<Vec<u8>> = fragment_frame(
        &frame,
        true,
        session_id,
        frame_id,
        timestamp,
        MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE,
    )
    .into_iter()
    .map(|pkt| {
        let aad = build_aad(key.channel_id, 0x14);
        let encrypted = media_encrypt(
            &key,
            session_id,
            frame_id,
            pkt.fragment_index as u32,
            &aad,
            &pkt.payload,
        )
        .unwrap();
        VideoPacket::encrypted_fragment(
            true,
            session_id,
            frame_id,
            pkt.fragment_index,
            pkt.fragment_count,
            timestamp,
            key.key_id,
            encrypted,
        )
        .to_bytes()
    })
    .collect();
    assert_eq!(packets.len(), 5);
    assert!(packets.iter().all(|p| p.len() <= MAX_VIDEO_PACKET_SIZE));

    let mut assembler = VideoAssemblerCore::new();
    let (last, rest) = packets.split_last().unwrap();
    for packet in rest {
        let r = assembler.push(&key, packet).unwrap();
        assert!(r.frame.is_none());
        assert!(r.is_keyframe);
        assert!(!r.frame_dropped);
    }
    let r = assembler.push(&key, last).unwrap();
    assert_eq!(r.frame.as_deref(), Some(&frame[..]));
    assert!(r.is_keyframe);
    assert_eq!(r.timestamp, timestamp);
    assert!(!r.frame_dropped);

    // A wrong key fails authentication instead of feeding garbage to the decoder.
    let other = MediaKey::generate(7, 1).unwrap();
    assert!(assembler.push(&other, &packets[0]).is_err());
}

/// A browser sharer's frame stream must come apart exactly like the native
/// sharer's: `stream_records` splits it, the assembler puts the frame back.
#[test]
fn video_frame_stream_round_trip() {
    let key = MediaKey::generate(7, 2).unwrap();
    let frame: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let (session_id, frame_id, timestamp) = (9, 4, 777);

    let stream =
        media::build_video_frame_stream(&key, session_id, frame_id, timestamp, true, &frame)
            .unwrap();
    let records = stream_records(&stream);
    assert_eq!(records.len(), 5);
    assert!(records.iter().all(|r| r.len() <= MAX_VIDEO_PACKET_SIZE));
    // Keyframe fragments, and the native fragmenter agrees on the count
    assert!(records.iter().all(|r| r[0] == 0x14));

    let mut assembler = VideoAssemblerCore::new();
    let (last, rest) = records.split_last().unwrap();
    for record in rest {
        assert!(assembler.push(&key, record).unwrap().frame.is_none());
    }
    let r = assembler.push(&key, last).unwrap();
    assert_eq!(r.frame.as_deref(), Some(&frame[..]));
    assert!(r.is_keyframe);
    assert_eq!(r.timestamp, timestamp);

    // A delta frame is tagged 0x13 and reassembles on the same assembler
    let delta = vec![0xABu8; 900];
    let stream =
        media::build_video_frame_stream(&key, session_id, frame_id + 1, timestamp + 33, false, &delta)
            .unwrap();
    let records = stream_records(&stream);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0][0], 0x13);
    let r = assembler.push(&key, records[0]).unwrap();
    assert_eq!(r.frame.as_deref(), Some(&delta[..]));
    assert!(!r.is_keyframe);

    // Too big for the 255-fragment wire format: refused, never truncated
    let huge = vec![0u8; MAX_ENCRYPTED_VIDEO_PAYLOAD_SIZE * 256];
    assert!(
        media::build_video_frame_stream(&key, session_id, 2, 0, true, &huge).is_err(),
        "an oversized frame must be refused, not silently cut short"
    );
}

/// The browser sharer's screen audio must parse with the receive path both
/// clients use.
#[test]
fn screen_audio_packet_round_trip() {
    let key = MediaKey::generate(7, 5).unwrap();
    let opus = [3u8; 60];
    let packet = media::build_screen_audio_packet(&key, 8, 101, 2540, &opus).unwrap();
    assert_eq!(packet[0], 0x15);

    let info = media::parse_screen_audio_packet(&key, &packet).unwrap();
    assert_eq!((info.session_id, info.sequence, info.timestamp), (8, 101, 2540));
    assert_eq!(info.opus, opus);

    // Another key fails authentication instead of playing noise
    let other = MediaKey::generate(7, 6).unwrap();
    assert!(media::parse_screen_audio_packet(&other, &packet).is_err());
}

/// The browser's voice packets must decrypt with the native receive path, and
/// the native sender's packets must parse in the browser. Both sides go through
/// the same crates, so this pins the byte layout rather than the crypto: the
/// native steps below are copied from client/src-tauri/src/network.rs
/// (`udp_receiver_task`, `spawn_capture_encode_task`).
#[test]
fn voice_interoperates_with_the_native_client() {
    let channel_id = 7;
    let key = MediaKey::generate(channel_id, 0).unwrap();
    let opus: Vec<u8> = (0..80u8).collect();
    let (session_id, sequence) = (3, 99);

    // Browser sends → native client receives.
    let packet = media::build_voice_packet(&key, session_id, sequence, &opus).unwrap();
    let header = voipc_protocol::voice::ENCRYPTED_VOICE_HEADER_SIZE;
    assert_eq!(header, 11);
    assert_eq!(packet[0], 0x05);
    assert_eq!(
        u32::from_be_bytes(packet[1..5].try_into().unwrap()),
        session_id
    );
    assert_eq!(
        u32::from_be_bytes(packet[5..9].try_into().unwrap()),
        sequence
    );
    assert_eq!(
        u16::from_be_bytes(packet[9..11].try_into().unwrap()),
        key.key_id
    );
    let decrypted = voipc_crypto::media_decrypt(
        &key,
        session_id,
        sequence,
        0,
        &build_aad(channel_id, 0x05),
        &packet[header..],
    )
    .unwrap();
    assert_eq!(decrypted, opus);

    // Native client sends → browser receives.
    let encrypted = media_encrypt(
        &key,
        session_id,
        sequence,
        0,
        &build_aad(channel_id, 0x05),
        &opus,
    )
    .unwrap();
    let native =
        voipc_protocol::voice::VoicePacket::encrypted_voice(session_id, sequence, key.key_id, encrypted)
            .to_bytes();
    let info = media::parse_voice_packet(Some(&key), &native).unwrap();
    assert_eq!(info.opus.as_deref(), Some(&opus[..]));
    assert_eq!(info.sequence, sequence);
}
