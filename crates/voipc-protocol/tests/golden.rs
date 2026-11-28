//! The wire format, pinned. A relay admits only its own `PROTOCOL_VERSION`
//! (1.0's rule), so any change to what goes over the wire has to bump it, and
//! `compat.rs` keeps the older shapes the apps still speak (1.6). This test is
//! what makes that a rule instead of a hope:
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
//!   written out too;
//! - the media edge pool (1.15) has a version of its own, `pool::POOL_VERSION`, kept
//!   the same way in `golden/pool-v<N>.json`, with the same switch to record it. Its
//!   `Hello` and `Refused` start the same in every pool version.

use serde_reflection::{Tracer, TracerConfig};
use voipc_protocol::codec::{encode_client_msg, encode_server_msg, MAX_MSG_SIZE, PROTOCOL_VERSION};
use voipc_protocol::error::ProtocolError;
use voipc_protocol::gk::{GkMember, VersionMake};
use voipc_protocol::messages::*;
use voipc_protocol::pool::{self, CoreMsg, EdgeMsg, EdgeViewMsg, TicketBody, ViewerMsg};
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
        AdminOp,
        AdminReply,
        Registration,
        AccountStart,
        ProviderKind,
        VideoCodec,
        ProximityMode,
        FileConv,
        Emote,
        EmoteAccess,
        MoveFilter,
        MoveState,
        ImportGate,
        ArchiveAction,
        ArchiveScope,
        ArchiveTarget,
        GkMember,
        VersionMake,
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

/// The pool's wire, traced as the client protocol's is.
fn traced_pool_format() -> String {
    let mut tracer = Tracer::new(TracerConfig::default());
    tracer.trace_simple_type::<EdgeMsg>().unwrap();
    tracer.trace_simple_type::<CoreMsg>().unwrap();
    tracer.trace_simple_type::<ViewerMsg>().unwrap();
    tracer.trace_simple_type::<EdgeViewMsg>().unwrap();
    tracer.trace_simple_type::<TicketBody>().unwrap();
    serde_json::to_string_pretty(&tracer.registry().unwrap()).unwrap() + "\n"
}

#[test]
fn pool_format_matches_pool_version() {
    let dir = format!("{}/tests/golden", env!("CARGO_MANIFEST_DIR"));
    let path = format!("{dir}/pool-v{}.json", pool::POOL_VERSION);
    let now = traced_pool_format();
    if std::env::var_os("VOIPC_WRITE_GOLDEN").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &now).unwrap();
        return;
    }
    let recorded = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "no recorded format for pool version {}: record it with VOIPC_WRITE_GOLDEN=1",
            pool::POOL_VERSION
        )
    });
    assert!(
        recorded == now,
        "the pool's wire changed but POOL_VERSION is still {}: bump it in pool.rs and record \
         the new format with VOIPC_WRITE_GOLDEN=1 (an older golden/pool-v<N>.json is history: \
         never edit it). A core admits only its own pool version, so upgrade the core first",
        pool::POOL_VERSION
    );
}

/// Read by every pool version before and after this one to say "wrong version", and a
/// viewer's hello, which the browser builds through wasm and transport.test.ts pins too.
#[test]
fn what_says_wrong_pool_version_never_changes() {
    // Hello is variant 0 and starts with the pool version, which the core reads from an
    // edge of any version (`pool::hello_version`)
    let hello = EdgeMsg::Hello {
        pool_version: 300,
        name: "e1".into(),
        proof: [0; 32],
        public_host: "h".into(),
        public_port: 1,
        cert_hashes: vec![],
        max_viewers: 1,
        egress_mbit: 1,
        max_shares: 1,
        version: String::new(),
    };
    let bytes = pool::encode_edge_msg(&hello).unwrap();
    assert!(
        hex(&bytes[4..]).starts_with("00ac02"),
        "Hello's start moved"
    );
    assert_eq!(pool::hello_version(&bytes[4..]), Some(300));

    // Refused is variant 1 and starts with the pool version (`pool::refused_version`)
    let refused = CoreMsg::Refused {
        pool_version: 1,
        reason: "t".into(),
    };
    let bytes = pool::encode_core_msg(&refused).unwrap();
    assert_eq!(hex(&bytes), "0000000401010174", "Refused moved");
    assert_eq!(pool::refused_version(&bytes[4..]), Some(1));

    let viewer = ViewerMsg::Hello {
        ticket: vec![1, 2, 3],
    };
    assert_eq!(
        hex(&pool::encode_viewer_msg(&viewer).unwrap()),
        "000000050003010203",
        "a viewer's hello moved: transport.test.ts pins the same bytes"
    );
    assert_eq!(
        (pool::POOL_PATH, pool::VIEW_PATH),
        ("/voipc-edge", "/voipc-view")
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

/// The emote list is one message: the most a server may have, each with the
/// longest name and pack label there may be, fits.
#[test]
fn the_largest_emote_list_fits_one_message() {
    let label = "é".repeat(EMOTE_PACK_MAX);
    assert!(valid_emote_pack(&label));
    assert!(
        !valid_emote_pack(&"😀".repeat(EMOTE_PACK_MAX)),
        "four bytes a character is over the bytes"
    );
    let emotes = (0..MAX_EMOTES)
        .map(|i| Emote {
            name: format!("{i:0>width$}", width = EMOTE_NAME_MAX),
            hash: [0xff; 32],
            sticker: true,
            pack: label.clone(),
            len: u32::MAX,
            w: u16::MAX,
            h: u16::MAX,
        })
        .collect();
    let len = encode_server_msg(&ServerMessage::EmoteList {
        stickers: true,
        emotes,
    })
    .unwrap()
    .len();
    assert!(len <= MAX_MSG_SIZE as usize, "{len} bytes");
}

#[test]
fn emote_names_and_pack_labels() {
    assert!(valid_emote_name("pog_2") && valid_emote_name(&"x".repeat(EMOTE_NAME_MAX)));
    for bad in ["a", "Pog", "a-b", "a b", "ä_b", ""] {
        assert!(!valid_emote_name(bad), "{bad}");
    }
    assert!(!valid_emote_name(&"x".repeat(EMOTE_NAME_MAX + 1)));
    assert!(valid_emote_pack("") && valid_emote_pack("Cats & dogs"));
    for bad in [
        " lead",
        "trail ",
        "two\nlines",
        "rtl\u{202E}gnp",
        "zero\u{200B}width",
    ] {
        assert!(!valid_emote_pack(bad), "{bad:?}");
    }
    assert_eq!(format!("{:?}", Secret("hunter2".into())), "Secret(…)");
}

/// A frame of an import seals before it passes `IMPORT_FRAME_BYTES`, which only works if the
/// longest row there can be leaves room, and a reader's page holds the longest row. The
/// limits are the relay's (`archive_put`), which clips the rest away.
#[test]
fn the_longest_imported_row_fits_a_frame_and_a_page() {
    let wide = |chars: usize| "\u{1F600}".repeat(chars);
    let row = ImportMessage {
        id: u64::MAX,
        author: Some(u64::MAX),
        author_name: wide(64),
        body: "x".repeat(IMPORT_BODY_BYTES),
        reply_to: Some(u64::MAX),
        pinned: true,
        reactions: vec![
            ImportReaction {
                emoji: wide(64),
                count: u32::MAX,
            };
            20
        ],
        attachments: vec![
            ImportAttachment {
                id: u64::MAX,
                name: wide(128),
                bytes: u64::MAX,
                mime: wide(64),
            };
            20
        ],
    };
    let frame = |rows: Vec<ImportMessage>| {
        let encoded = encode_client_msg(&ClientMessage::Account(AccountRequest::Admin {
            op: AdminOp::ImportMessages {
                run: i64::MAX,
                channel: u64::MAX,
                thread: Some(u64::MAX),
                high: u64::MAX,
                rows,
            },
            code: None,
        }));
        match encoded {
            Ok(frame) => frame.len(),
            Err(ProtocolError::MessageTooLarge(len)) => len,
            Err(e) => panic!("{e}"),
        }
    };
    assert!(frame(vec![row.clone()]) < IMPORT_FRAME_BYTES);
    assert!(IMPORT_FRAME_BYTES < MAX_MSG_SIZE as usize);
    // ... and the check can fail: rows do not all fit one frame
    assert!(frame(vec![row; IMPORT_MESSAGE_ROWS]) > IMPORT_FRAME_BYTES);

    let reader = ArchiveRow {
        id: u64::MAX.to_string(),
        author: wide(64),
        author_id: u64::MAX.to_string(),
        at_ms: u64::MAX,
        body: "x".repeat(IMPORT_BODY_BYTES),
        thread: u64::MAX.to_string(),
        reply_to: u64::MAX.to_string(),
        reactions: vec![
            ArchiveReaction {
                emoji: wide(64),
                count: u32::MAX,
            };
            20
        ],
        pinned: true,
        thread_name: wide(100),
        replies: u32::MAX,
        mine: true,
        hidden: true,
    };
    let page = encode_server_msg(&ServerMessage::Account(AccountReply::ArchivePage {
        channel_id: u32::MAX,
        thread: u64::MAX.to_string(),
        before: u64::MAX.to_string(),
        pinned: true,
        rows: vec![reader],
        next: u64::MAX.to_string(),
    }))
    .unwrap();
    assert!(page.len() < 44 * 1024);
}

/// What the desktop emits as `posts-hidden`, which the browser's backend makes the
/// same (`posts-marks.ts`) and the store reads (`onPostsHidden`).
#[test]
fn a_posts_mark_in_json_is_what_the_front_end_reads() {
    let mark = |account| PostsMark {
        account,
        name: "dan".into(),
        since_ms: 1_000,
        before_ms: 2_000,
        by: "bobby".into(),
    };
    assert_eq!(
        serde_json::to_value(mark(None)).unwrap(),
        serde_json::json!({ "account": null, "name": "dan", "since_ms": 1000, "before_ms": 2000, "by": "bobby" })
    );
    assert_eq!(
        serde_json::to_value(mark(Some([7; 16]))).unwrap()["account"],
        serde_json::json!([7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7])
    );
}

/// What the desktop emits as `report-takers`, which `cleanTakers` reads as it does the
/// browser's decoder, where None is undefined.
#[test]
fn a_report_taker_in_json_is_what_the_front_end_reads() {
    let taker = |user_id, account| ReportTaker {
        user_id,
        account,
        name: "bobby".into(),
    };
    assert_eq!(
        serde_json::to_value(taker(None, None)).unwrap(),
        serde_json::json!({ "user_id": null, "account": null, "name": "bobby" })
    );
    assert_eq!(
        serde_json::to_value(taker(Some(5), Some([7; 16]))).unwrap(),
        serde_json::json!({
            "user_id": 5,
            "account": [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
            "name": "bobby",
        })
    );
}
