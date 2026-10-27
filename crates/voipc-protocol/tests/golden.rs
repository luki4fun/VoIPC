//! The wire format, pinned. Client and relay must speak the same
//! `PROTOCOL_VERSION` (1.0's rule), so any change to what goes over the wire
//! has to bump it. This test is what makes that a rule instead of a hope:
//!
//! - the traced format of every message and every type inside one is kept per
//!   protocol version in `golden/v<N>.json`. A change with the same version
//!   number fails here; record a new version with
//!   `VOIPC_WRITE_GOLDEN=1 cargo test -p voipc-protocol --test golden`
//!   after bumping `PROTOCOL_VERSION`;
//! - a few things are frozen for ever, because older or newer versions must
//!   read them to be told to update: the start of `Authenticate`, `AuthError`
//!   and `Refused`. Their bytes are written out below;
//! - the media packets are laid out by hand, not by serde, so their bytes are
//!   written out too.

use serde_reflection::{Tracer, TracerConfig};
use voipc_protocol::codec::{encode_client_msg, encode_server_msg, MAX_MSG_SIZE, PROTOCOL_VERSION};
use voipc_protocol::messages::*;
use voipc_protocol::types::*;
use voipc_protocol::video::{ScreenShareAudioPacket, VideoPacket};
use voipc_protocol::voice::VoicePacket;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Every wire type, enums traced through all their variants.
fn traced_format() -> String {
    let mut tracer = Tracer::new(TracerConfig::default());
    macro_rules! trace {
        ($($t:ty),* $(,)?) => { $( tracer.trace_simple_type::<$t>().expect(stringify!($t)); )* };
    }
    trace!(
        ClientMessage,
        ServerMessage,
        AuthContinue,
        AccountRequest,
        AuthStep,
        AccountReply,
        Registration,
        AccountStart,
        VideoCodec,
        ProximityMode,
        FileConv,
    );
    let registry = tracer
        .registry()
        .expect("every variant of every enum is traced; add the one named here to trace!");
    serde_json::to_string_pretty(&registry).unwrap() + "\n"
}

#[test]
fn the_wire_format_matches_its_protocol_version() {
    let path = format!(
        "{}/tests/golden/v{PROTOCOL_VERSION}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let now = traced_format();
    if std::env::var_os("VOIPC_WRITE_GOLDEN").is_some() {
        std::fs::create_dir_all(format!("{}/tests/golden", env!("CARGO_MANIFEST_DIR"))).unwrap();
        std::fs::write(&path, &now).unwrap();
        return;
    }
    let recorded = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("no recorded format for protocol {PROTOCOL_VERSION}: record it with VOIPC_WRITE_GOLDEN=1")
    });
    assert!(
        recorded == now,
        "the wire format changed but PROTOCOL_VERSION is still {PROTOCOL_VERSION}: bump it in codec.rs, \
         say what changed there, and record the new format with VOIPC_WRITE_GOLDEN=1 \
         (an older golden/v<N>.json is history: never edit it)"
    );
}

/// Read by every version before and after this one to say "update".
#[test]
fn what_tells_another_version_to_update_never_changes() {
    // Authenticate is variant 0 and starts with the username and the protocol
    // version, which the relay reads from a client of any version
    // (`legacy_protocol_version`).
    let auth = ClientMessage::Authenticate {
        username: "ab".into(),
        protocol_version: 300,
        app_version: String::new(),
        identity_key: None,
        prekey_bundle: None,
        account: None,
    };
    assert!(
        hex(&encode_client_msg(&auth).unwrap()[4..]).starts_with("00026162ac02"),
        "Authenticate's start moved"
    );

    // AuthError is variant 1: what every client before 0.12 (protocol 12) shows.
    let err = ServerMessage::AuthError { reason: "x".into() };
    assert_eq!(
        hex(&encode_server_msg(&err).unwrap()),
        "00000003010178",
        "AuthError moved"
    );

    // Refused: its variant index and fields, for every later version.
    let refused = ServerMessage::Refused {
        code: REFUSED_VERSION,
        server_protocol: 12,
        server_version: "1.0.0".into(),
        text: "t".into(),
    };
    assert_eq!(
        hex(&encode_server_msg(&refused).unwrap()),
        "0000000b30010c05312e302e300174",
        "Refused moved"
    );
    assert_eq!((REFUSED_VERSION, FIRST_STRUCTURED_REFUSAL), (1, 12));

    // The frame: a big-endian length, then the message, at most 64 KiB.
    assert_eq!(MAX_MSG_SIZE, 65_536);
}

/// The media headers, which the relay parses and peers of the same protocol
/// must agree on byte for byte.
#[test]
fn media_packets_keep_their_layout() {
    let voice = VoicePacket::encrypted_voice(0x0102_0304, 5, 6, 0x0708_090a, vec![0xee]).to_bytes();
    assert_eq!(hex(&voice), "05010203040000000500060708090aee");
    let position = VoicePacket::position(1, 2, 3, 4, vec![0xee]).to_bytes();
    assert_eq!(hex(&position), "060000000100000002000300000004ee");
    assert_eq!(
        hex(&VoicePacket::end_of_transmission(1, 2).to_bytes()),
        "020000000100000002"
    );
    assert_eq!(
        hex(&VoicePacket::ping(1, 2).to_bytes()),
        "030000000100000002"
    );
    let video = VideoPacket::encrypted_fragment(true, 1, 2, 3, 4, 5, 6, 7, vec![0xee]).to_bytes();
    assert_eq!(hex(&video), "140000000100000002030400000005000600000007ee");
    let audio = ScreenShareAudioPacket::new_encrypted(1, 2, 3, 4, 5, vec![0xee]).to_bytes();
    assert_eq!(hex(&audio), "15000000010000000200000003000400000005ee");
}

/// Kept-message conversation ids are stored by the relay and the clients.
#[test]
fn conversation_ids_keep_their_form() {
    let (a, b) = ([0x11; 16], [0x22; 16]);
    let conv = voipc_protocol::conv::dm_conv(&b, &a);
    assert_eq!(conv, format!("d:{}:{}", "11".repeat(16), "22".repeat(16)));
}
