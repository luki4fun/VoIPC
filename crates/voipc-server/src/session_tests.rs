use super::*;
use std::net::Ipv4Addr;

use voipc_protocol::codec::{decode_server_msg, encode_client_msg};

use crate::config::ServerConfig;
use crate::settings::ServerSettings;

#[test]
fn names_refuse_invisible_and_reordering_characters() {
    let bad = |name: &str| name.chars().any(bad_name_char);
    assert!(bad("admin\u{200B}"), "zero-width space");
    assert!(bad("Luki\u{202E}0240#"), "RTL override");
    assert!(
        bad("\u{3164}"),
        "Hangul filler, a name that prints as nothing"
    );
    assert!(bad("tab\there"), "control characters, as before");
    for fine in [
        "Luki#0420",
        "Zoë",
        "Ærøskøbing",
        "名前",
        "Ελένη",
        "a b-c_d.e",
    ] {
        assert!(!bad(fine), "{fine} must pass");
    }
}

/// Drives `handle_connection` over an in-memory duplex without QUIC —
/// exactly how the session bridge feeds it.
#[tokio::test]
async fn authenticates_over_duplex() {
    let config = ServerConfig::default();
    let state = Arc::new(ServerState::new(
        &config,
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    ));
    let (mut client, server) = tokio::io::duplex(65536);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, sid_rx) = oneshot::channel();
    let mut handler = tokio::spawn(handle_connection(
        server,
        "test".into(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        media_tx,
        sid_tx,
        state.clone(),
    ));

    let auth = ClientMessage::Authenticate {
        username: "web".into(),
        protocol_version: PROTOCOL_VERSION,
        app_version: APP_VERSION.to_string(),
        identity_key: None,
        prekey_bundle: None,
        account: None,
    };
    client
        .write_all(&encode_client_msg(&auth).unwrap())
        .await
        .unwrap();

    let mut buf = BytesMut::new();
    let mut replies = Vec::new();
    let read_replies = async {
        while replies.len() < 3 {
            let n = client.read_buf(&mut buf).await.unwrap();
            assert!(n > 0, "server closed the connection");
            while let Some(payload) = try_decode_frame(&mut buf).unwrap() {
                replies.push(decode_server_msg(&payload).unwrap());
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), read_replies)
        .await
        .expect("replies within 5 s");

    let ServerMessage::Authenticated { session_id, .. } = replies[0] else {
        panic!("expected Authenticated, got {:?}", replies[0]);
    };
    assert!(matches!(replies[1], ServerMessage::ChannelList { .. }));
    assert!(matches!(
        replies[2],
        ServerMessage::UserList { channel_id: 0, .. }
    ));
    assert_eq!(state.sessions.len(), 1);
    // The bridge learns the session id as soon as the session exists
    assert_eq!(sid_rx.await.unwrap(), session_id);

    // Dropping our end is what the bridge does on teardown: the handler
    // must see EOF and clean the session up.
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), &mut handler)
        .await
        .expect("handler exits after EOF")
        .unwrap();
    assert!(state.sessions.is_empty());
}

// ── Moderation ─────────────────────────────────────────────────────

struct Client {
    stream: tokio::io::DuplexStream,
    handler: tokio::task::JoinHandle<()>,
    buf: BytesMut,
}

impl Client {
    async fn send(&mut self, msg: &ClientMessage) {
        self.stream
            .write_all(&encode_client_msg(msg).unwrap())
            .await
            .unwrap();
    }

    /// Next server message, or None once the server closed the stream.
    async fn next(&mut self) -> Option<ServerMessage> {
        loop {
            if let Some(payload) = try_decode_frame(&mut self.buf).unwrap() {
                return Some(decode_server_msg(&payload).unwrap());
            }
            let n =
                tokio::time::timeout(Duration::from_secs(5), self.stream.read_buf(&mut self.buf))
                    .await
                    .expect("a server message within 5 s")
                    .unwrap();
            if n == 0 {
                return None;
            }
        }
    }

    /// Skips messages (broadcasts about other users) until `pred` matches.
    async fn expect(&mut self, what: &str, pred: impl Fn(&ServerMessage) -> bool) -> ServerMessage {
        loop {
            match self.next().await {
                Some(msg) if pred(&msg) => return msg,
                Some(_) => continue,
                None => panic!("connection closed while waiting for {what}"),
            }
        }
    }

    async fn assert_closed(mut self) {
        assert!(
            self.next().await.is_none(),
            "server should close the stream"
        );
        tokio::time::timeout(Duration::from_secs(5), &mut self.handler)
            .await
            .expect("handler exits")
            .unwrap();
    }
}

fn admin_state() -> Arc<ServerState> {
    Arc::new(ServerState::new(
        &ServerConfig::default(),
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    ))
}

/// Authenticates `username` from `ip` over a duplex.
async fn connect(state: &Arc<ServerState>, username: &str, ip: IpAddr) -> Client {
    let mut client = open(state, username, ip).await;
    client
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await;
    client
}

/// Why the server turned `username` away.
async fn refusal(state: &Arc<ServerState>, username: &str) -> String {
    let mut client = open(state, username, IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    match client.next().await {
        Some(ServerMessage::AuthError { reason }) => reason,
        other => panic!("{username} was not refused: {other:?}"),
    }
}

/// Sends the `Authenticate` for `username` from `ip`, and no more.
async fn open(state: &Arc<ServerState>, username: &str, ip: IpAddr) -> Client {
    let (stream, server) = tokio::io::duplex(65536);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, _sid_rx) = oneshot::channel();
    let handler = tokio::spawn(handle_connection(
        server,
        username.into(),
        ip,
        media_tx,
        sid_tx,
        state.clone(),
    ));
    let mut client = Client {
        stream,
        handler,
        buf: BytesMut::new(),
    };
    client
        .send(&ClientMessage::Authenticate {
            username: username.into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: None,
            account: None,
        })
        .await;
    client
}

/// A channel is created and then joined, and the join can be refused —
/// the creator is out of join budget, or their password is wrong for the
/// channel they have just made. Before 0.9.0 the timer that removes an
/// empty channel was started only by a *leave*, so a channel nobody ever
/// joined stayed in the map for the life of the server. Enough of them, at
/// one channel per five seconds, and nobody on the server can create one
/// again.
#[tokio::test]
async fn a_channel_whose_creator_never_joined_it_goes_away_on_its_own() {
    let state = Arc::new(ServerState::new(
        &ServerConfig::default(),
        ServerSettings {
            empty_channel_timeout_secs: 0,
            ..ServerSettings::default()
        },
        Vec::new(),
        "test-admin-token".into(),
    ));
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await;

    // Spend the joins, so the auto-join that follows the creation cannot.
    {
        let mut session = state.sessions.get_mut(&1).unwrap();
        while session.join_rate.try_consume() {}
    }

    alice
        .send(&ClientMessage::CreateChannel {
            name: "Orphan".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: true,
        })
        .await;
    alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await;

    // The timer is spawned with a zero timeout, so it only needs the
    // scheduler to come round to it.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if state.channel_list().await.len() == 1 {
            break;
        }
    }
    let names: Vec<String> = state
        .channel_list()
        .await
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(
        names,
        vec!["General".to_string()],
        "the orphan stayed behind"
    );
}

/// The key material a client uploads is opaque to us and we hold it until
/// they disconnect. Unbounded, one client parks a hundred 60 KiB blobs in
/// our memory — and a bundle built from them is a message too long to
/// frame, so whoever asked for it is told nothing at all and can never open
/// a session with that person.
#[tokio::test]
async fn an_oversized_prekey_bundle_is_refused_at_the_door() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (stream, server) = tokio::io::duplex(65536);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, _sid_rx) = oneshot::channel();
    let handler = tokio::spawn(handle_connection(
        server,
        "mallory".into(),
        lo,
        media_tx,
        sid_tx,
        state.clone(),
    ));
    let mut client = Client {
        stream,
        handler,
        buf: BytesMut::new(),
    };
    client
        .send(&ClientMessage::Authenticate {
            username: "mallory".into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: Some(PreKeyBundleData {
                identity_key: vec![0u8; 60_000],
                ..test_bundle(0)
            }),
            account: None,
        })
        .await;
    client
        .expect("AuthError", |m| {
            matches!(m, ServerMessage::AuthError { .. })
        })
        .await;
    assert_eq!(state.user_count(), 0, "the session was registered anyway");
}

/// ...and the same bound on the ones uploaded later, which arrive by
/// another door and used to be counted but not measured.
#[tokio::test]
async fn an_oversized_uploaded_prekey_is_not_stored() {
    let state = admin_state();
    let (mut alice, _) = connect_with_bundle(&state, "alice", test_bundle(0)).await;
    alice
        .send(&ClientMessage::UploadPreKeys {
            prekeys: vec![
                OneTimePreKey {
                    id: 1,
                    public_key: vec![0u8; 33],
                },
                OneTimePreKey {
                    id: 2,
                    public_key: vec![0u8; 60_000],
                },
            ],
        })
        .await;
    // Answered by nothing, so measure it against a round trip that is.
    alice.send(&ClientMessage::Ping { timestamp: 7 }).await;
    alice
        .expect("Pong", |m| matches!(m, ServerMessage::Pong { .. }))
        .await;

    let session = state.sessions.get(&1).unwrap();
    let prekeys = &session.bundle.as_ref().unwrap().prekeys;
    assert_eq!(prekeys.len(), 1, "the oversized key was stored");
    assert_eq!(prekeys[0].id, 1);
}

/// H1-08: a connection task that ends without its own cleanup (a panic)
/// still takes its session out, through the guard.
#[tokio::test]
async fn a_connection_task_that_dies_still_cleans_up() {
    let state = admin_state();
    let _alice = connect(&state, "alice", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    assert_eq!(state.user_count(), 1);
    drop(CleanupGuard {
        state: Some(state.clone()),
        user_id: 1,
        session_id: 1,
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.user_count() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the session was cleaned up");
}

/// A bundle with `n` one-time keys and a Kyber key of the real size.
fn test_bundle(n: u32) -> PreKeyBundleData {
    PreKeyBundleData {
        registration_id: 1,
        device_id: 1,
        identity_key: vec![5u8; 33],
        signed_prekey_id: 1,
        signed_prekey: vec![0u8; 33],
        signed_prekey_signature: vec![0u8; 64],
        prekeys: (1..=n)
            .map(|id| OneTimePreKey {
                id,
                public_key: vec![id as u8; 33],
            })
            .collect(),
        kyber_prekey_id: 1,
        kyber_prekey: vec![7u8; MAX_KEM_KEY_BYTES],
        kyber_prekey_signature: vec![9u8; 64],
    }
}

/// Authenticates `username` with `bundle`; the client and its user id.
async fn connect_with_bundle(
    state: &Arc<ServerState>,
    username: &str,
    bundle: PreKeyBundleData,
) -> (Client, UserId) {
    let (stream, server) = tokio::io::duplex(65536);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, _sid_rx) = oneshot::channel();
    let handler = tokio::spawn(handle_connection(
        server,
        username.into(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        media_tx,
        sid_tx,
        state.clone(),
    ));
    let mut client = Client {
        stream,
        handler,
        buf: BytesMut::new(),
    };
    client
        .send(&ClientMessage::Authenticate {
            username: username.into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: Some(bundle.identity_key.clone()),
            prekey_bundle: Some(bundle),
            account: None,
        })
        .await;
    let ServerMessage::Authenticated { user_id, .. } = client
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await
    else {
        unreachable!()
    };
    (client, user_id)
}

/// The Kyber key goes to whoever asks, with one one-time key; the owner is
/// asked for more once, when the pool reaches the low mark.
#[tokio::test]
async fn a_bundle_carries_the_kyber_key_and_a_low_pool_asks_for_more() {
    let state = admin_state();
    let (mut alice, alice_id) =
        connect_with_bundle(&state, "alice", test_bundle(PREKEYS_LOW as u32 + 1)).await;
    let (mut bob, _) = connect_with_bundle(&state, "bob", test_bundle(0)).await;

    bob.send(&ClientMessage::RequestPreKeyBundle {
        target_user_id: alice_id,
    })
    .await;
    let ServerMessage::PreKeyBundle { bundle, .. } = bob
        .expect("PreKeyBundle", |m| {
            matches!(m, ServerMessage::PreKeyBundle { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert_eq!(bundle.prekeys.len(), 1);
    assert_eq!(
        (
            bundle.kyber_prekey_id,
            bundle.kyber_prekey.len(),
            bundle.kyber_prekey_signature.len()
        ),
        (1, MAX_KEM_KEY_BYTES, 64)
    );
    alice.expect("PreKeysLow", |m| matches!(m, ServerMessage::PreKeysLow { remaining } if *remaining == PREKEYS_LOW as u32)).await;

    // Below the mark: no second ask
    bob.send(&ClientMessage::RequestPreKeyBundle {
        target_user_id: alice_id,
    })
    .await;
    bob.expect("PreKeyBundle", |m| {
        matches!(m, ServerMessage::PreKeyBundle { .. })
    })
    .await;
    alice.send(&ClientMessage::Ping { timestamp: 1 }).await;
    let next = alice
        .expect("Pong or PreKeysLow", |m| {
            matches!(
                m,
                ServerMessage::Pong { .. } | ServerMessage::PreKeysLow { .. }
            )
        })
        .await;
    assert!(
        matches!(next, ServerMessage::Pong { .. }),
        "asked again: {next:?}"
    );
}

/// A Kyber key larger than Kyber1024 is refused at the door like any key.
#[test]
fn an_oversized_kyber_key_is_refused() {
    let b = PreKeyBundleData {
        kyber_prekey: vec![0u8; MAX_KEM_KEY_BYTES + 1],
        ..test_bundle(0)
    };
    assert!(!bundle_is_sane(&b));
    assert!(bundle_is_sane(&test_bundle(3)));
}

/// H1-09: wrong admin tokens are counted per address, not per session, so
/// reconnecting does not buy more guesses; once spent, even the right
/// token is refused for a while.
#[tokio::test]
async fn wrong_admin_tokens_are_counted_per_address() {
    let state = admin_state();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    for round in 0..4 {
        let mut c = connect(&state, &format!("g{round}"), ip).await;
        for _ in 0..3 {
            c.send(&ClientMessage::AdminLogin {
                token: "wrong-wrong-wrong".into(),
            })
            .await;
            c.expect("AdminError", |m| {
                matches!(m, ServerMessage::AdminError { .. })
            })
            .await;
        }
    }
    let mut c = connect(&state, "last", ip).await;
    c.send(&ClientMessage::AdminLogin {
        token: "test-admin-token".into(),
    })
    .await;
    let ServerMessage::AdminError { reason } = c
        .expect("AdminError", |m| {
            matches!(m, ServerMessage::AdminError { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("too many wrong"), "{reason}");
    // Somebody else's address has its own budget
    let mut other = connect(&state, "other", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10))).await;
    other
        .send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
    other
        .expect("AdminStatus", |m| {
            matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
        })
        .await;
}

/// Give a connected session these scopes, as a sign-in would.
fn grant(state: &ServerState, sid: SessionId, scopes: &[&str]) {
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let mut s = state.sessions.get_mut(&sid).unwrap();
    s.is_admin = crate::accounts::is_star(&scopes);
    s.is_moderator = !scopes.is_empty();
    s.powers = crate::accounts::Powers::of(&scopes);
}

/// Each privilege does its own thing and no other (1.7).
#[tokio::test]
async fn each_privilege_grants_its_own_step_only() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut kicker = connect(&state, "kicker", lo).await; // user 1
    let mut lister = connect(&state, "lister", lo).await; // user 2
    let mut target = connect(&state, "target", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))).await; // 3
    let _emotes = connect(&state, "emoter", lo).await; // user 4
    grant(&state, 1, &["voipc:kick"]);
    grant(&state, 2, &["voipc:bans"]);
    grant(&state, 4, &["voipc:emotes"]);
    let admin_reply = |m: &ServerMessage| {
        matches!(
            m,
            ServerMessage::AdminError { .. } | ServerMessage::AdminBans { .. }
        )
    };

    // Kicking is not banning, and not the ban list
    kicker
        .send(&ClientMessage::AdminBan {
            user_id: 3,
            reason: String::new(),
            duration_secs: 60,
            account: false,
        })
        .await;
    assert!(matches!(
        kicker.expect("refused", admin_reply).await,
        ServerMessage::AdminError { .. }
    ));
    kicker.send(&ClientMessage::AdminListBans).await;
    assert!(matches!(
        kicker.expect("refused", admin_reply).await,
        ServerMessage::AdminError { .. }
    ));
    kicker.send(&ClientMessage::AdminUnban { id: 1 }).await;
    assert!(matches!(
        kicker.expect("refused", admin_reply).await,
        ServerMessage::AdminError { .. }
    ));
    // ... and spares whoever holds any privilege, even another one
    kicker
        .send(&ClientMessage::AdminKick {
            user_id: 4,
            reason: String::new(),
        })
        .await;
    let ServerMessage::AdminError { reason } = kicker.expect("refused", admin_reply).await else {
        panic!("refused")
    };
    assert!(reason.contains("only an admin"), "{reason}");
    assert!(state.sessions.contains_key(&4));

    // The ban list is not a kick
    lister
        .send(&ClientMessage::AdminKick {
            user_id: 3,
            reason: String::new(),
        })
        .await;
    assert!(matches!(
        lister.expect("refused", admin_reply).await,
        ServerMessage::AdminError { .. }
    ));
    lister.send(&ClientMessage::AdminListBans).await;
    assert!(matches!(
        lister.expect("the list", admin_reply).await,
        ServerMessage::AdminBans { .. }
    ));

    // A kick holder kicks a member
    kicker
        .send(&ClientMessage::AdminKick {
            user_id: 3,
            reason: "out".into(),
        })
        .await;
    target
        .expect("Disconnected", |m| {
            matches!(m, ServerMessage::Disconnected { .. })
        })
        .await;
}

/// `voipc:channels` changes any channel's options, but showing real names
/// behind a pseudonym is an admin's or the creator's alone.
#[tokio::test]
async fn a_channel_editor_cannot_switch_anonymity_off() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut owner = connect(&state, "owner", lo).await; // user 1
    let mut editor = connect(&state, "editor", lo).await; // user 2
    grant(&state, 2, &["voipc:channels"]);
    owner
        .send(&ClientMessage::CreateChannel {
            name: "masks".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: true,
            text: false,
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = owner
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };
    let id = channel.channel_id;
    let set = |options: ChannelOptions| ClientMessage::SetChannelOptions {
        channel_id: id,
        options,
    };
    editor
        .send(&set(ChannelOptions {
            anonymous: Some(false),
            ..Default::default()
        }))
        .await;
    let ServerMessage::ChannelError { reason } = editor
        .expect("refused", |m| {
            matches!(m, ServerMessage::ChannelError { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("anonymity off"), "{reason}");
    assert!(state.channels.read().await[&id].info.anonymous);
    // Another option of someone else's channel is fine
    editor
        .send(&set(ChannelOptions {
            hide_members: Some(true),
            ..Default::default()
        }))
        .await;
    editor
        .expect(
            "ChannelUpdated",
            |m| matches!(m, ServerMessage::ChannelUpdated { channel } if channel.hide_members),
        )
        .await;
    // The creator may
    owner
        .send(&set(ChannelOptions {
            anonymous: Some(false),
            ..Default::default()
        }))
        .await;
    owner
        .expect(
            "ChannelUpdated",
            |m| matches!(m, ServerMessage::ChannelUpdated { channel } if !channel.anonymous),
        )
        .await;
}

#[tokio::test]
async fn admin_login_ban_and_unban() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let far = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", far).await; // user 2

    // Not an admin: refused
    bob.send(&ClientMessage::AdminKick {
        user_id: 1,
        reason: String::new(),
    })
    .await;
    bob.expect("AdminError", |m| {
        matches!(m, ServerMessage::AdminError { .. })
    })
    .await;

    // Wrong token, then the right one; everyone learns about the login
    alice
        .send(&ClientMessage::AdminLogin {
            token: "nope".into(),
        })
        .await;
    alice
        .expect("AdminError", |m| {
            matches!(m, ServerMessage::AdminError { .. })
        })
        .await;
    alice
        .send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
    let is_login = |m: &ServerMessage| {
        matches!(
            m,
            ServerMessage::AdminStatus {
                user_id: 1,
                is_admin: true
            }
        )
    };
    alice.expect("AdminStatus", is_login).await;
    bob.expect("AdminStatus broadcast", is_login).await;
    assert!(state.is_admin(1));

    // Ban bob: he gets the reason, his stream closes, his IP is blocked,
    // alice gets the updated ban list
    alice
        .send(&ClientMessage::AdminBan {
            user_id: 2,
            reason: "spam".into(),
            duration_secs: 60,
            account: true,
        })
        .await;
    let gone = bob
        .expect("Disconnected", |m| {
            matches!(m, ServerMessage::Disconnected { .. })
        })
        .await;
    assert!(matches!(gone, ServerMessage::Disconnected { reason } if reason.contains("spam")));
    bob.assert_closed().await;
    assert!(crate::bans::refused_at_accept(&state, far));
    assert!(!crate::bans::refused_at_accept(&state, lo));
    assert_eq!(state.sessions.len(), 1);
    let bans = alice
        .expect("AdminBans", |m| {
            matches!(m, ServerMessage::AdminBans { .. })
        })
        .await;
    let ServerMessage::AdminBans { bans } = bans else {
        unreachable!()
    };
    assert_eq!(bans.len(), 1, "a guest has no account to ban");
    assert!(
        !bans[0].account
            && bans[0].label == "bob"
            && bans[0].reason == "spam"
            && bans[0].by == "admin token",
        "{bans:?}"
    );
    assert!(
        format!("{bans:?}").find("10.0.0.5").is_none(),
        "the list names no address"
    );

    // Unban
    alice
        .send(&ClientMessage::AdminUnban { id: bans[0].id })
        .await;
    let bans = alice
        .expect("AdminBans", |m| {
            matches!(m, ServerMessage::AdminBans { .. })
        })
        .await;
    assert!(matches!(&bans, ServerMessage::AdminBans { bans } if bans.is_empty()));
    assert!(!crate::bans::refused_at_accept(&state, far));
}

#[tokio::test]
async fn three_failed_admin_logins_disconnect() {
    let state = admin_state();
    let mut dave = connect(&state, "dave", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    for _ in 0..3 {
        dave.send(&ClientMessage::AdminLogin {
            token: "wrong".into(),
        })
        .await;
        dave.expect("AdminError", |m| {
            matches!(m, ServerMessage::AdminError { .. })
        })
        .await;
    }
    dave.expect("Disconnected", |m| {
        matches!(m, ServerMessage::Disconnected { .. })
    })
    .await;
    dave.assert_closed().await;
    assert!(state.sessions.is_empty());
}

/// A viewer must be told which codec the share it just joined uses: it is
/// the only thing that reaches a late joiner before the first frame, and
/// building the wrong decoder means a black window.
#[tokio::test]
async fn watchers_learn_the_share_codec() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2

    // Sharing needs a real channel; General never carries media.
    alice
        .send(&ClientMessage::CreateChannel {
            name: "room".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: false,
        })
        .await;
    let created = alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = created else {
        unreachable!()
    };
    let channel_id = channel.channel_id;
    bob.send(&ClientMessage::JoinChannel {
        channel_id,
        password: None,
    })
    .await;
    bob.expect(
        "UserList",
        |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
    )
    .await;

    // Alice shares in a codec that is not the default
    alice
        .send(&ClientMessage::StartScreenShare {
            source: "portal".into(),
            resolution: 720,
            codec: VideoCodec::Vp9,
        })
        .await;
    bob.expect("ScreenShareStarted", |m| {
        matches!(m, ServerMessage::ScreenShareStarted { user_id: 1, .. })
    })
    .await;

    bob.send(&ClientMessage::WatchScreenShare { sharer_user_id: 1 })
        .await;
    let watching = bob
        .expect("WatchingScreenShare", |m| {
            matches!(m, ServerMessage::WatchingScreenShare { .. })
        })
        .await;
    assert!(
        matches!(
            watching,
            ServerMessage::WatchingScreenShare {
                sharer_user_id: 1,
                codec: VideoCodec::Vp9
            }
        ),
        "the viewer was told the wrong codec: {watching:?}"
    );
}

/// A text channel is a subscription: joining one does not move anybody out
/// of the voice channel they stand in, both parties keep receiving its
/// chat, and the channel a message names is what decides who gets it.
#[tokio::test]
async fn text_channel_chat_reaches_members_without_moving_them() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2

    // A voice room for alice to stand in, and a text channel for both
    alice
        .send(&ClientMessage::CreateChannel {
            name: "room".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: false,
        })
        .await;
    let ServerMessage::ChannelCreated { channel: voice } = alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };
    alice
            .expect("UserList for the voice room", |m| {
                matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == voice.channel_id)
            })
            .await;

    bob.send(&ClientMessage::CreateChannel {
        name: "lounge".into(),
        password: None,
        proximity: ProximityMode::Off,
        anonymous: false,
        text: true,
    })
    .await;
    let ServerMessage::ChannelCreated { channel: text } = bob
        .expect(
            "ChannelCreated",
            |m| matches!(m, ServerMessage::ChannelCreated { channel } if channel.text),
        )
        .await
    else {
        unreachable!()
    };
    bob.expect(
        "UserList for the text channel",
        |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == text.channel_id),
    )
    .await;
    // Creating a text channel did not move bob out of the lobby
    assert_eq!(state.sessions.get(&2).unwrap().channel_id, 0);

    alice
        .send(&ClientMessage::JoinChannel {
            channel_id: text.channel_id,
            password: None,
        })
        .await;
    alice
        .expect(
            "UserList for the text channel",
            |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == text.channel_id),
        )
        .await;
    // ...and joining it did not take alice out of the voice room
    assert_eq!(state.sessions.get(&1).unwrap().channel_id, voice.channel_id);
    assert!(state.is_member(text.channel_id, 1).await);

    // A message naming the text channel reaches its other member
    alice
        .send(&ClientMessage::SendEncryptedChannelMessage {
            channel_id: text.channel_id,
            ciphertext: vec![1, 2, 3],
        })
        .await;
    let got = bob
        .expect("EncryptedChannelChatMessage", |m| {
            matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
        })
        .await;
    assert!(matches!(
        got,
        ServerMessage::EncryptedChannelChatMessage { channel_id, user_id: 1, .. }
            if channel_id == text.channel_id
    ));

    // A message naming a channel the sender is not in is refused
    bob.send(&ClientMessage::SendEncryptedChannelMessage {
        channel_id: voice.channel_id,
        ciphertext: vec![4],
    })
    .await;
    let refused = bob
        .expect("ChannelError", |m| {
            matches!(m, ServerMessage::ChannelError { .. })
        })
        .await;
    assert!(matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("not in")));

    // Leaving is its own message, and everybody hears about it
    alice
        .send(&ClientMessage::LeaveChannel {
            channel_id: text.channel_id,
        })
        .await;
    alice
            .expect("UserLeft for ourselves", |m| {
                matches!(m, ServerMessage::UserLeft { user_id: 1, channel_id: c } if *c == text.channel_id)
            })
            .await;
    assert!(!state.is_member(text.channel_id, 1).await);
    // Still standing where they were
    assert_eq!(state.sessions.get(&1).unwrap().channel_id, voice.channel_id);

    // Leaving a voice channel is still JoinChannel(0), never this
    alice
        .send(&ClientMessage::LeaveChannel {
            channel_id: voice.channel_id,
        })
        .await;
    let refused = alice
        .expect("ChannelError", |m| {
            matches!(m, ServerMessage::ChannelError { .. })
        })
        .await;
    assert!(
        matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("text channel"))
    );
    assert_eq!(state.sessions.get(&1).unwrap().channel_id, voice.channel_id);
}

/// An announcement channel takes posts only from its managers, and slow
/// mode holds everybody else to one post per interval — both decided by
/// the relay from who posts where and when, without reading a word.
#[tokio::test]
async fn announce_and_slow_mode_hold_back_members_but_not_managers() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2

    // bob's text channel, so bob is its creator and manages it
    bob.send(&ClientMessage::CreateChannel {
        name: "news".into(),
        password: None,
        proximity: ProximityMode::Off,
        anonymous: false,
        text: true,
    })
    .await;
    let ServerMessage::ChannelCreated { channel } = bob
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };
    let news = channel.channel_id;
    alice
        .send(&ClientMessage::JoinChannel {
            channel_id: news,
            password: None,
        })
        .await;
    alice
        .expect(
            "UserList for news",
            |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == news),
        )
        .await;

    let set =
        |announce: Option<bool>, slow_mode_secs: Option<u32>| ClientMessage::SetChannelOptions {
            channel_id: news,
            options: ChannelOptions {
                announce,
                slow_mode_secs,
                ..Default::default()
            },
        };
    let post = |byte: u8| ClientMessage::SendEncryptedChannelMessage {
        channel_id: news,
        ciphertext: vec![byte],
    };
    let is_post = |byte: u8| move |m: &ServerMessage| matches!(m, ServerMessage::EncryptedChannelChatMessage { ciphertext, .. } if ciphertext == &vec![byte]);
    let is_refusal = |what: &'static str| move |m: &ServerMessage| matches!(m, ServerMessage::ChannelError { reason } if reason.contains(what));

    // Announcements: alice is refused, the creator gets through
    bob.send(&set(Some(true), None)).await;
    bob.expect(
        "ChannelUpdated",
        |m| matches!(m, ServerMessage::ChannelUpdated { channel } if channel.announce),
    )
    .await;
    alice.send(&post(1)).await;
    alice
        .expect("announce refusal", is_refusal("only moderators"))
        .await;
    bob.send(&post(2)).await;
    alice.expect("bob's announcement", is_post(2)).await;

    // Slow mode: one post from alice, the next one too soon is refused
    bob.send(&set(Some(false), Some(60))).await;
    bob.expect("ChannelUpdated", |m| {
            matches!(m, ServerMessage::ChannelUpdated { channel } if !channel.announce && channel.slow_mode_secs == 60)
        })
        .await;
    alice.send(&post(3)).await;
    alice.send(&post(4)).await;
    alice
        .expect("slow mode refusal", is_refusal("slow mode"))
        .await;
    // The first post bob gets from alice is 3, so 1 never left the relay
    let got = bob
        .expect("a post", |m| {
            matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
        })
        .await;
    assert!(
        is_post(3)(&got),
        "a refused announcement was relayed: {got:?}"
    );

    // The creator is not held back, nor is a moderator
    bob.send(&post(5)).await;
    bob.send(&post(6)).await;
    alice.expect("bob's first post", is_post(5)).await;
    alice.expect("bob's second post", is_post(6)).await;
    state.sessions.get_mut(&1).unwrap().powers = crate::accounts::Powers::CHANNELS;
    alice.send(&post(7)).await;
    // ...and the next one is 7, so 4 did not either
    let got = bob
        .expect("a post", |m| {
            matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
        })
        .await;
    assert!(
        is_post(7)(&got),
        "a post refused by slow mode was relayed: {got:?}"
    );
}

/// Who answers a request for recent chat is the one thing about chat the
/// server is told, and everybody is told it — including the person whose
/// flag it is, whose own member list has to agree with everyone else's.
#[tokio::test]
async fn history_sharing_is_announced_to_everyone() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2

    alice
        .send(&ClientMessage::SetHistorySharing { enabled: true })
        .await;
    alice
        .expect("our own UserHistorySharing", |m| {
            matches!(
                m,
                ServerMessage::UserHistorySharing {
                    user_id: 1,
                    enabled: true
                }
            )
        })
        .await;
    bob.expect("UserHistorySharing", |m| {
        matches!(
            m,
            ServerMessage::UserHistorySharing {
                user_id: 1,
                enabled: true
            }
        )
    })
    .await;
    assert!(state.sessions.get(&1).unwrap().shares_history);

    // ...and it rides in the roster, which is what a member list draws
    let roster = state.users_in_channel_for(0, 2).await;
    assert!(roster.iter().any(|u| u.user_id == 1 && u.shares_history));
    assert!(roster.iter().any(|u| u.user_id == 2 && !u.shares_history));

    alice
        .send(&ClientMessage::SetHistorySharing { enabled: false })
        .await;
    bob.expect("UserHistorySharing, off again", |m| {
        matches!(
            m,
            ServerMessage::UserHistorySharing {
                user_id: 1,
                enabled: false
            }
        )
    })
    .await;
    assert!(!state.sessions.get(&1).unwrap().shares_history);
}

/// Creates a text channel owned by `owner` and subscribes `other` to it.
/// Both ends are left drained of the join traffic.
async fn text_channel_with_two(owner: &mut Client, other: &mut Client, name: &str) -> ChannelId {
    owner
        .send(&ClientMessage::CreateChannel {
            name: name.into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: true,
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = owner
        .expect(
            "ChannelCreated",
            |m| matches!(m, ServerMessage::ChannelCreated { channel } if channel.text),
        )
        .await
    else {
        unreachable!()
    };
    let channel_id = channel.channel_id;
    owner
        .expect(
            "UserList",
            |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
        )
        .await;
    other
        .send(&ClientMessage::JoinChannel {
            channel_id,
            password: None,
        })
        .await;
    other
        .expect(
            "UserList",
            |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
        )
        .await;
    channel_id
}

/// The whole point of the size chain: a blob the relay could not re-wrap
/// into a readable frame is refused at the sender, not delivered to
/// everybody else as a length prefix their decoders reject and their
/// clients hang up over.
#[tokio::test]
async fn an_oversized_message_is_refused_instead_of_dropping_the_channel() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2
    let channel_id = text_channel_with_two(&mut alice, &mut bob, "lounge").await;

    alice
        .send(&ClientMessage::SendEncryptedChannelMessage {
            channel_id,
            ciphertext: vec![0u8; MAX_RELAY_CIPHERTEXT + 1],
        })
        .await;
    let refused = alice
        .expect("ChannelError", |m| {
            matches!(m, ServerMessage::ChannelError { .. })
        })
        .await;
    assert!(
        matches!(refused, ServerMessage::ChannelError { reason } if reason.contains("too large"))
    );

    // Bob is the one this protects: his connection is still there and
    // still carrying the channel's chat.
    alice
        .send(&ClientMessage::SendEncryptedChannelMessage {
            channel_id,
            ciphertext: vec![1, 2, 3],
        })
        .await;
    let got = bob
        .expect("EncryptedChannelChatMessage", |m| {
            matches!(m, ServerMessage::EncryptedChannelChatMessage { .. })
        })
        .await;
    assert!(matches!(
        got,
        ServerMessage::EncryptedChannelChatMessage { channel_id: c, user_id: 1, .. }
            if c == channel_id
    ));
}

/// A name is unique together with its tag, not on its own: two people can
/// both be alice as long as their tags differ. The tag rides on top of the
/// 32 bytes a name may have, and only a real tag does.
#[tokio::test]
async fn a_tag_lets_two_people_share_a_name() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _first = connect(&state, "alice#0001", lo).await;
    let _second = connect(&state, "alice#0002", lo).await;
    let _longest = connect(&state, &format!("{}#1234", "x".repeat(32)), lo).await;

    assert!(refusal(&state, "ALICE#0001").await.contains("taken"));
    assert!(refusal(&state, &"x".repeat(33)).await.contains("1-32"));
    // Five digits are no tag, so all of it is the name
    assert!(refusal(&state, &format!("{}#12345", "x".repeat(32)))
        .await
        .contains("1-32"));
    assert!(refusal(&state, "#0001").await.contains("1-32"));
}

/// A direct message to somebody who has left used to vanish: the server
/// dropped it, and the sender's client had already shown it as sent. The
/// sender is told now, and only then.
#[tokio::test]
async fn a_direct_message_to_somebody_who_left_is_answered() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let bob = connect(&state, "bob", lo).await; // user 2
    let dm = ClientMessage::SendEncryptedDirectMessage {
        target_user_id: 2,
        ciphertext: vec![1, 2, 3],
        message_type: 2,
    };
    let answer = |m: &ServerMessage| {
        matches!(
            m,
            ServerMessage::EncryptedDirectChatMessage { .. }
                | ServerMessage::DirectMessageUndelivered { .. }
        )
    };

    // Delivered: the echo comes back, with no "undelivered" ahead of it
    alice.send(&dm).await;
    let got = alice.expect("the echo", answer).await;
    assert!(matches!(
        got,
        ServerMessage::EncryptedDirectChatMessage { to_user_id: 2, .. }
    ));

    drop(bob);
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.sessions.contains_key(&2) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("bob's session is cleaned up");

    alice.send(&dm).await;
    let got = alice.expect("the answer", answer).await;
    assert!(matches!(
        got,
        ServerMessage::DirectMessageUndelivered { target_user_id: 2 }
    ));
}

/// An `AcceptInvite` for a channel that never invited you joined nothing,
/// and used to tell the channel's creator you had accepted all the same.
#[tokio::test]
async fn an_acceptance_without_an_invite_reaches_nobody() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await;
    let mut bob = connect(&state, "bob", lo).await; // user 2
    alice
        .send(&ClientMessage::CreateChannel {
            name: "Room".into(),
            password: Some("pw".into()),
            proximity: ProximityMode::Off,
            anonymous: false,
            text: false,
        })
        .await;
    let created = alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = created else {
        unreachable!()
    };
    let room = channel.channel_id;
    let pong = |m: &ServerMessage| {
        matches!(
            m,
            ServerMessage::Pong { .. } | ServerMessage::InviteAccepted { .. }
        )
    };

    // Uninvited: bob's handler is done with it once his Pong is back, and
    // anything it sent alice is then queued ahead of hers
    bob.send(&ClientMessage::AcceptInvite { channel_id: room })
        .await;
    bob.send(&ClientMessage::Ping { timestamp: 1 }).await;
    bob.expect("Pong", |m| matches!(m, ServerMessage::Pong { .. }))
        .await;
    alice.send(&ClientMessage::Ping { timestamp: 2 }).await;
    let got = alice.expect("Pong", pong).await;
    assert!(
        matches!(got, ServerMessage::Pong { .. }),
        "fake acceptance: {got:?}"
    );

    // Invited: the acceptance does go through
    alice
        .send(&ClientMessage::SendInvite {
            channel_id: room,
            target_user_id: 2,
        })
        .await;
    bob.expect("InviteReceived", |m| {
        matches!(m, ServerMessage::InviteReceived { .. })
    })
    .await;
    bob.send(&ClientMessage::AcceptInvite { channel_id: room })
        .await;
    let got = alice.expect("InviteAccepted", pong).await;
    assert!(matches!(
        got,
        ServerMessage::InviteAccepted { user_id: 2, .. }
    ));
}

/// `hide_members` and a password both mean "nobody outside learns who is
/// in here", and the roster query has always honoured that. The join and
/// leave broadcasts go to *every* session, because they double as the
/// user-count update — and they used to carry the user id even where the
/// name was blanked. With one `#general` everybody is in, every id has a
/// name, so the ids alone rebuild the withheld roster.
#[tokio::test]
async fn a_join_to_a_hidden_member_channel_names_nobody_to_outsiders() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2

    alice
        .send(&ClientMessage::CreateChannel {
            name: "back room".into(),
            password: Some("pw".into()),
            proximity: ProximityMode::Off,
            anonymous: false,
            text: false,
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };

    // Bob is not in it: he learns that the count went up and no more.
    let joined = bob
            .expect("UserJoined", |m| {
                matches!(m, ServerMessage::UserJoined { user } if user.channel_id == channel.channel_id)
            })
            .await;
    let ServerMessage::UserJoined { user } = joined else {
        unreachable!()
    };
    assert_eq!(user.user_id, 0, "an outsider was told who joined");
    assert_eq!(user.username, "");

    // And the same on the way out.
    alice
        .send(&ClientMessage::JoinChannel {
            channel_id: 0,
            password: None,
        })
        .await;
    let left = bob
            .expect("UserLeft", |m| {
                matches!(m, ServerMessage::UserLeft { channel_id, .. } if *channel_id == channel.channel_id)
            })
            .await;
    assert!(matches!(left, ServerMessage::UserLeft { user_id: 0, .. }));

    // A member is told, because that is the roster they are allowed.
    bob.send(&ClientMessage::JoinChannel {
        channel_id: channel.channel_id,
        password: Some("pw".into()),
    })
    .await;
    bob.expect("UserList", |m| {
            matches!(m, ServerMessage::UserList { channel_id, .. } if *channel_id == channel.channel_id)
        })
        .await;
    alice
        .send(&ClientMessage::JoinChannel {
            channel_id: channel.channel_id,
            password: Some("pw".into()),
        })
        .await;
    let joined = bob
            .expect("UserJoined", |m| {
                matches!(m, ServerMessage::UserJoined { user } if user.channel_id == channel.channel_id)
            })
            .await;
    let ServerMessage::UserJoined { user } = joined else {
        unreachable!()
    };
    assert_eq!((user.user_id, user.username.as_str()), (1, "alice"));
}

/// The id rule above must not widen the *name* rule it sits next to: an
/// ordinary channel's joins carry an id to everybody, and have never
/// carried a name to anybody outside it. That is what stops a move between
/// an anonymous channel and an ordinary one from handing an outsider both
/// names for one person.
#[tokio::test]
async fn an_ordinary_channel_still_names_its_members_to_nobody_outside() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2

    alice
        .send(&ClientMessage::CreateChannel {
            name: "lounge".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: false,
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };
    let joined = bob
            .expect("UserJoined", |m| {
                matches!(m, ServerMessage::UserJoined { user } if user.channel_id == channel.channel_id)
            })
            .await;
    let ServerMessage::UserJoined { user } = joined else {
        unreachable!()
    };
    assert_eq!(user.user_id, 1, "the count has to be attributable");
    assert_eq!(user.username, "", "an outsider was told the name");
}

/// A game drives the audio filter in a routed channel — `docs/SDK.md`
/// documents up to 20 updates a second — while the budget it drew on
/// allows two. The surplus was dropped without a word, so the relay went
/// on culling by a filter the game had moved on from.
#[tokio::test]
async fn a_game_can_update_its_audio_filter_as_fast_as_the_sdk_allows() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1, session 1
    alice
        .send(&ClientMessage::CreateChannel {
            name: "ingame".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: false,
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };
    alice
        .send(&ClientMessage::SetChannelOptions {
            channel_id: channel.channel_id,
            options: ChannelOptions {
                routed: Some(true),
                ..Default::default()
            },
        })
        .await;
    alice
        .expect(
            "ChannelUpdated",
            |m| matches!(m, ServerMessage::ChannelUpdated { channel: c } if c.routed),
        )
        .await;

    // One update per player the game moved past, at the documented rate.
    // The last one is the one that has to be in force.
    for speaker in 1..=20u32 {
        alice
            .send(&ClientMessage::SetAudioFilter {
                allow: Some(vec![speaker]),
            })
            .await;
    }
    // Driven by a message that must come back, so the filters ahead of it
    // have all been handled rather than merely sent.
    alice.send(&ClientMessage::Ping { timestamp: 1 }).await;
    alice
        .expect("Pong", |m| {
            matches!(m, ServerMessage::Pong { timestamp: 1 })
        })
        .await;

    let now = tokio::time::Instant::now();
    assert!(
        state.routing.may_hear(channel.channel_id, 1, 1, 20, now),
        "the last filter the game sent was dropped"
    );
    assert!(
        !state.routing.may_hear(channel.channel_id, 1, 1, 19, now),
        "an earlier filter is still in force"
    );
}

/// The budget for relaying keys belongs to the pair, not the sender: an
/// honest client hands a key to every member of every channel it shares
/// with them, which is a wide burst at many people and never a burst at
/// one. A single per-session budget could only be set wide enough for the
/// first or tight enough for the second — and set wide, a flood at one
/// member fills the queue their real keys have to arrive through.
#[tokio::test]
async fn keys_to_many_members_pass_while_a_flood_at_one_is_capped() {
    // A small server on purpose: the per-target burst is sized from how
    // many channels can exist here, and on a 50-channel one it is wider
    // than the per-frame control budget — which would then be the thing
    // this test measured.
    let state = Arc::new(ServerState::new(
        &ServerConfig::default(),
        ServerSettings {
            max_channels: 4,
            ..ServerSettings::default()
        },
        Vec::new(),
        "test-admin-token".into(),
    ));
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2
    let mut carol = connect(&state, "carol", lo).await; // user 3
    let channel_id = text_channel_with_two(&mut alice, &mut bob, "lounge").await;
    carol
        .send(&ClientMessage::JoinChannel {
            channel_id,
            password: None,
        })
        .await;
    carol
        .expect(
            "UserList",
            |m| matches!(m, ServerMessage::UserList { channel_id: c, .. } if *c == channel_id),
        )
        .await;

    // Past one target's budget, aimed at Bob — and deliberately still
    // inside the per-frame control budget, so it is this limiter being
    // measured and not that one.
    let burst = state
        .sessions
        .get(&1)
        .map(|s| s.key_relay_burst as usize)
        .expect("alice has a session");
    let flood = burst + 5;
    for i in 0..flood {
        alice
            .send(&ClientMessage::DistributeSenderKey {
                channel_id,
                target_user_id: 2,
                distribution_message: vec![i as u8],
                message_type: 1,
            })
            .await;
    }
    // Carol's key is sent last and must still arrive: her budget is her
    // own, and the flood at Bob has not touched it.
    alice
        .send(&ClientMessage::DistributeSenderKey {
            channel_id,
            target_user_id: 3,
            distribution_message: vec![0xAA],
            message_type: 1,
        })
        .await;
    let got = carol
        .expect("SenderKeyReceived", |m| {
            matches!(m, ServerMessage::SenderKeyReceived { .. })
        })
        .await;
    assert!(matches!(
        got,
        ServerMessage::SenderKeyReceived { from_user_id: 1, distribution_message, .. }
            if distribution_message == vec![0xAA]
    ));

    // Bob got his burst and no more. Counted against a message that must
    // arrive after them rather than against a timeout.
    alice
        .send(&ClientMessage::SendEncryptedChannelMessage {
            channel_id,
            ciphertext: vec![7],
        })
        .await;
    let mut relayed = 0usize;
    loop {
        match bob.next().await {
            Some(ServerMessage::SenderKeyReceived { .. }) => relayed += 1,
            Some(ServerMessage::EncryptedChannelChatMessage { .. }) => break,
            Some(_) => continue,
            None => panic!("connection closed"),
        }
    }
    assert!(
        relayed < flood && relayed <= burst + 2,
        "{relayed} of {flood} keys relayed at one member"
    );
    assert!(relayed > 0, "an honest key to a member must still pass");
}

/// `shares_history` is a flag the server has always stored and announced
/// and never read: a request could be aimed at anybody, and the client on
/// the other end was the only thing deciding whether to answer.
#[tokio::test]
async fn a_history_request_stops_at_a_member_who_does_not_share() {
    let state = admin_state();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut alice = connect(&state, "alice", lo).await; // user 1
    let mut bob = connect(&state, "bob", lo).await; // user 2
    let channel_id = text_channel_with_two(&mut alice, &mut bob, "lounge").await;

    // Bob shares nothing, so the question must not reach him at all.
    alice
        .send(&ClientMessage::RequestChannelHistory {
            channel_id,
            target_user_id: 2,
        })
        .await;
    // Driven by a message that must arrive rather than by a timeout: if
    // the request was forwarded it is already in Bob's queue ahead of it.
    alice
        .send(&ClientMessage::SendEncryptedChannelMessage {
            channel_id,
            ciphertext: vec![7],
        })
        .await;
    loop {
        match bob.next().await {
            Some(ServerMessage::ChannelHistoryRequested { .. }) => {
                panic!("the request reached a member who does not share history")
            }
            Some(ServerMessage::EncryptedChannelChatMessage { .. }) => break,
            Some(_) => continue,
            None => panic!("connection closed"),
        }
    }

    // ...and it is the flag doing the work: switch it on and the same
    // request goes through.
    bob.send(&ClientMessage::SetHistorySharing { enabled: true })
        .await;
    bob.expect("our own UserHistorySharing", |m| {
        matches!(
            m,
            ServerMessage::UserHistorySharing {
                user_id: 2,
                enabled: true
            }
        )
    })
    .await;
    alice
        .send(&ClientMessage::RequestChannelHistory {
            channel_id,
            target_user_id: 2,
        })
        .await;
    let asked = bob
        .expect("ChannelHistoryRequested", |m| {
            matches!(m, ServerMessage::ChannelHistoryRequested { .. })
        })
        .await;
    assert!(matches!(
        asked,
        ServerMessage::ChannelHistoryRequested { channel_id: c, from_user_id: 1 }
            if c == channel_id
    ));
}

#[tokio::test]
async fn bans_expire() {
    let state = admin_state();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    crate::bans::add(
        &state,
        crate::bans::Target::Addr(ip),
        "x",
        "r",
        "admin token",
        Some(Duration::from_secs(1)),
    )
    .await
    .unwrap();
    assert!(crate::bans::refused_at_accept(&state, ip));
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(!crate::bans::refused_at_accept(&state, ip));
    assert!(crate::bans::list(&state).is_empty());
    crate::bans::add(
        &state,
        crate::bans::Target::Addr(ip),
        "x",
        "r",
        "admin token",
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        crate::bans::list(&state)[0].expires_in_secs,
        None,
        "permanent"
    );
}

/// A relay without accounts keeps its bans in bans.json, with the plain
/// addresses, and reads them again after a restart. An IPv6 ban covers
/// the /64.
#[tokio::test]
async fn bans_outlive_a_restart_without_accounts() {
    let path = std::env::temp_dir().join(format!(
        "voipc-bans-{}.json",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    let mut first = ServerState::new(
        &ServerConfig::default(),
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    );
    first.bans_file = Some(path.clone());
    let v6: IpAddr = "2001:db8:1:2::77".parse().unwrap();
    crate::bans::add(
        &first,
        crate::bans::Target::Addr(v6),
        "eve#0001",
        "spam",
        "admin token",
        None,
    )
    .await
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut second = ServerState::new(
        &ServerConfig::default(),
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    );
    second.bans_file = Some(path.clone());
    crate::bans::load(&second).await.unwrap();
    assert!(
        crate::bans::refused_at_accept(&second, "2001:db8:1:2:ffff::1".parse().unwrap()),
        "the same /64"
    );
    assert!(
        !crate::bans::refused_at_accept(&second, "2001:db8:1:3::77".parse().unwrap()),
        "another /64"
    );
    let id = crate::bans::list(&second)[0].id;
    assert!(crate::bans::remove(&second, id).await.unwrap());
    crate::bans::load(&first).await.unwrap();
    assert!(
        !crate::bans::refused_at_accept(&first, v6),
        "lifted in the file, so for the other reader too"
    );
    let _ = std::fs::remove_file(&path);
}

// ── Accounts ───────────────────────────────────────────────────────

use crate::config::{AccountsMode, RegistrationMode};
use voipc_protocol::messages::{AccountReply, AccountRequest, AuthContinue};

const SECRET: [u8; 32] = [7; 32];
const IDENTITY: [u8; 33] = [5; 33];

/// A SQLite file in the temp dir, removed with its WAL when dropped. A file
/// rather than `:memory:`, as a relay runs: the boot lock's connection
/// leaves the pool for good, and an in-memory database dies with the last
/// connection to it.
struct TempDb(std::path::PathBuf);

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

/// A relay with accounts on a fresh SQLite database.
async fn relay_state(
    mode: AccountsMode,
    registration: RegistrationMode,
) -> (Arc<ServerState>, TempDb) {
    relay_state_then(mode, registration, |_| {}).await
}

/// `relay_state`, with `then` done to the state before it is shared.
async fn relay_state_then(
    mode: AccountsMode,
    registration: RegistrationMode,
    then: impl FnOnce(&mut ServerState),
) -> (Arc<ServerState>, TempDb) {
    let mut config = ServerConfig::default();
    config.accounts.mode = mode;
    config.accounts.registration = registration;
    let db = TempDb(std::env::temp_dir().join(format!(
        "voipc-relay-{}.db",
        hex::encode(rand::random::<[u8; 8]>())
    )));
    let store = l4f_accounts::store::Store::connect(&format!("sqlite://{}", db.0.display()))
        .await
        .unwrap();
    let relay = crate::accounts::Relay::open_with(&config.accounts, store, &[9u8; 32])
        .await
        .unwrap();
    let mut state = ServerState::new(
        &config,
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    );
    state.accounts = Some(Arc::new(relay));
    then(&mut state);
    (Arc::new(state), db)
}

fn bundle() -> PreKeyBundleData {
    PreKeyBundleData {
        registration_id: 1,
        device_id: 1,
        identity_key: IDENTITY.to_vec(),
        signed_prekey_id: 1,
        signed_prekey: vec![0u8; 33],
        signed_prekey_signature: vec![0u8; 64],
        prekeys: Vec::new(),
        kyber_prekey_id: 1,
        kyber_prekey: vec![0u8; 1569],
        kyber_prekey_signature: vec![0u8; 64],
    }
}

fn keys(identity: &[u8], reset_identity: bool) -> ClientMessage {
    ClientMessage::AuthContinue(AuthContinue::Keys {
        identity_key: identity.to_vec(),
        prekey_bundle: bundle(),
        reset_identity,
    })
}

async fn open_account(state: &Arc<ServerState>, name: &str, start: AccountStart) -> Client {
    let (stream, server) = tokio::io::duplex(65536);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, _sid_rx) = oneshot::channel();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let handler = tokio::spawn(handle_connection(
        server,
        name.into(),
        lo,
        media_tx,
        sid_tx,
        state.clone(),
    ));
    let mut client = Client {
        stream,
        handler,
        buf: BytesMut::new(),
    };
    client
        .send(&ClientMessage::Authenticate {
            username: name.into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: None,
            account: Some(start),
        })
        .await;
    client
}

/// What `pow.js` does, from the relay's challenge JSON.
fn solve(altcha: &str) -> String {
    use sha2::Digest;
    let c: serde_json::Value = serde_json::from_str(altcha).unwrap();
    let (salt, challenge) = (
        c["salt"].as_str().unwrap(),
        c["challenge"].as_str().unwrap(),
    );
    for n in 0..=c["maxnumber"].as_u64().unwrap() {
        if hex::encode(sha2::Sha256::digest(format!("{salt}{n}").as_bytes())) == challenge {
            return serde_json::json!({
                "algorithm": c["algorithm"], "challenge": challenge,
                "number": n, "salt": salt, "signature": c["signature"]
            })
            .to_string();
        }
    }
    panic!("unsolvable challenge");
}

fn reply(m: &ServerMessage) -> Option<&AccountReply> {
    match m {
        ServerMessage::Account(r) => Some(r),
        _ => None,
    }
}

/// What every 1.3 sign-up carries: the reset key (S-006).
fn reset_slot() -> VaultBlob {
    VaultBlob {
        k: "slot.reset".into(),
        v: vec![7; 32],
        version: 0,
    }
}

/// Signs up `name` on an open relay; returns the signed-in connection.
async fn register(state: &Arc<ServerState>, name: &str) -> (Client, AccountInfo) {
    let mut c = open_account(state, name, AccountStart::Register { invite: None }).await;
    let Some(ServerMessage::AuthStep(AuthStep::Salt { pow: Some(pow), .. })) = c.next().await
    else {
        panic!("an open relay hands out a proof of work");
    };
    let vault = vec![
        VaultBlob {
            k: "slot.hkdf".into(),
            v: vec![1, 2, 3],
            version: 0,
        },
        reset_slot(),
    ];
    let altcha = solve(&pow.altcha);
    c.send(&ClientMessage::AuthContinue(AuthContinue::Register {
        auth_secret: SECRET.to_vec(),
        altcha,
        ts: pow.ts,
        vault,
    }))
    .await;
    c.send(&keys(&IDENTITY, false)).await;
    let ServerMessage::Authenticated {
        account: Some(info),
        accounts: Some(relay),
        ..
    } = c
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await
    else {
        panic!("an account sign-in says which account and which relay");
    };
    assert_eq!(relay.relay_id, state.accounts.as_ref().unwrap().relay_id);
    (c, info)
}

/// Signs `name` in with the password secret; answers a code with `code`.
async fn login(state: &Arc<ServerState>, name: &str, identity: &[u8], reset: bool) -> Client {
    let mut c = open_account(state, name, AccountStart::Login).await;
    assert!(matches!(
        c.next().await,
        Some(ServerMessage::AuthStep(AuthStep::Salt { pow: None, .. }))
    ));
    c.send(&ClientMessage::AuthContinue(AuthContinue::Secret {
        auth_secret: SECRET.to_vec(),
    }))
    .await;
    c.send(&keys(identity, reset)).await;
    c
}

#[tokio::test]
async fn an_account_signs_up_and_signs_in_with_its_vault_and_identity() {
    let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (alice, info) = register(&state, "alice").await;
    assert_eq!(info.name, "alice");
    assert!(info.scopes.is_empty() && !info.needs_2fa && !info.totp_enabled);
    let session = state.sessions.iter().next().unwrap();
    assert_eq!(session.username, "alice", "an account's name is bare");
    assert!(session.account.is_some());
    drop(session);
    drop(alice);

    // Signing in again: the vault comes back, the identity must match.
    let mut c = login(&state, "Alice", &IDENTITY, false).await;
    let ServerMessage::AuthStep(AuthStep::Vault { blobs }) = c
        .expect("Vault", |m| matches!(m, ServerMessage::AuthStep(_)))
        .await
    else {
        unreachable!()
    };
    assert_eq!(
        (blobs[0].k.as_str(), blobs[0].v.as_slice()),
        ("slot.hkdf", &[1, 2, 3][..])
    );
    c.expect("Authenticated", |m| {
        matches!(
            m,
            ServerMessage::Authenticated {
                account: Some(_),
                ..
            }
        )
    })
    .await;

    let mut other = login(&state, "alice", &[6; 33], false).await;
    let ServerMessage::AuthError { reason } = other
        .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("identity"), "{reason}");
    let mut reset = login(&state, "alice", &[6; 33], true).await;
    reset
        .expect("Authenticated", |m| {
            matches!(
                m,
                ServerMessage::Authenticated {
                    account: Some(_),
                    ..
                }
            )
        })
        .await;
    assert_eq!(
        state
            .accounts
            .as_ref()
            .unwrap()
            .identity(l4f_accounts::model::AccountId(info.id))
            .await
            .unwrap(),
        Some(vec![6; 33])
    );

    let mut wrong = open_account(&state, "alice", AccountStart::Login).await;
    wrong.next().await;
    wrong
        .send(&ClientMessage::AuthContinue(AuthContinue::Secret {
            auth_secret: vec![8; 32],
        }))
        .await;
    assert!(
        matches!(wrong.next().await, Some(ServerMessage::AuthError { reason }) if reason.contains("Wrong"))
    );
}

#[tokio::test]
async fn a_second_sign_in_takes_over_and_the_first_is_told_not_to_return() {
    let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut first, _) = register(&state, "bob").await;
    let mut second = login(&state, "bob", &IDENTITY, false).await;
    second
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await;
    let ServerMessage::Disconnected { reason } = first
        .expect("Disconnected", |m| {
            matches!(m, ServerMessage::Disconnected { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("another device"), "{reason}");
    // News about the new session may still be on its way to the old one.
    while first.next().await.is_some() {}
    first.assert_closed().await;
    // The old session's cleanup must not take the name or the account from the new one.
    assert_eq!(state.sessions.len(), 1);
    let sid = *state.username_to_session.get("bob").unwrap();
    assert!(state.sessions.contains_key(&sid));
    assert_eq!(
        state.account_sessions.iter().next().map(|e| *e.value()),
        Some(sid)
    );
}

#[tokio::test]
async fn guests_need_a_tag_and_cannot_take_an_accounts_name() {
    let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (_carol, _) = register(&state, "carol").await;
    assert!(refusal(&state, "dave").await.contains("#tag"));
    assert!(refusal(&state, "Carol#1234")
        .await
        .contains("belongs to an account"));
    // S-014: a look-alike in another script is no account's name, and
    // would pass for one; a name in another script that looks like no
    // account is anybody's to take
    assert!(refusal(&state, "\u{441}arol#1234")
        .await
        .contains("looks like"));
    assert!(refusal(&state, "c\u{430}rol#1234")
        .await
        .contains("looks like"));
    connect(&state, "J\u{fc}rgen#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    connect(
        &state,
        "\u{43c}\u{430}\u{448}\u{430}#1234",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )
    .await;
    let mut guest = connect(&state, "dave#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    guest
        .send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
    let ServerMessage::AdminError { reason } = guest
        .expect("AdminError", |m| {
            matches!(m, ServerMessage::AdminError { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(
        reason.contains("account"),
        "a guest cannot claim admin with the token: {reason}"
    );

    let (required, _db_required) =
        relay_state(AccountsMode::Required, RegistrationMode::Invite).await;
    let mut g = open(&required, "erin#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    assert!(matches!(
        g.next().await,
        Some(ServerMessage::AuthStep(AuthStep::AccountRequired {
            registration: Registration::Invite
        }))
    ));
    g.assert_closed().await;
}

#[tokio::test]
async fn invites_are_the_way_in_when_sign_up_is_not_open() {
    use sha2::Digest;
    let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
    let mut c = open_account(&state, "frank", AccountStart::Register { invite: None }).await;
    assert!(
        matches!(c.next().await, Some(ServerMessage::AuthError { reason }) if reason.contains("invite"))
    );

    let raw = [3u8; 16];
    let hash: [u8; 32] = sha2::Sha256::digest(raw).into();
    let relay = state.accounts.as_ref().unwrap();
    relay
        .store()
        .insert_invite(&hash, None, Some("frank"), l4f_accounts::util::now() + 3600)
        .await
        .unwrap();
    let code = l4f_accounts::util::b64u(&raw);
    let mut c = open_account(
        &state,
        "frank",
        AccountStart::Register { invite: Some(code) },
    )
    .await;
    assert!(
        matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::Salt { pow: None, .. }))
        ),
        "no proof of work with an invite"
    );
    c.send(&ClientMessage::AuthContinue(AuthContinue::Register {
        auth_secret: SECRET.to_vec(),
        altcha: String::new(),
        ts: String::new(),
        vault: vec![reset_slot()],
    }))
    .await;
    c.send(&keys(&IDENTITY, false)).await;
    c.expect("Authenticated", |m| {
        matches!(
            m,
            ServerMessage::Authenticated {
                account: Some(_),
                ..
            }
        )
    })
    .await;
}

async fn totp_on(c: &mut Client) -> Vec<u8> {
    c.send(&ClientMessage::Account(AccountRequest::TotpSetup))
        .await;
    let ServerMessage::Account(AccountReply::TotpSetup { secret, sealed, .. }) =
        c.expect("TotpSetup", |m| reply(m).is_some()).await
    else {
        panic!("TotpSetup")
    };
    let secret = l4f_accounts::totp::base32_decode(&secret).unwrap();
    let code = format!(
        "{:06}",
        l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30)
    );
    c.send(&ClientMessage::Account(AccountRequest::TotpEnable {
        sealed,
        code,
    }))
    .await;
    let msg = c.expect("TotpEnabled", |m| reply(m).is_some()).await;
    assert!(
        matches!(msg, ServerMessage::Account(AccountReply::TotpEnabled { ref recovery_codes }) if recovery_codes.len() == 10),
        "{msg:?}"
    );
    secret
}

#[tokio::test]
async fn the_admin_token_makes_the_first_admin_whose_rights_wait_for_codes() {
    let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut gina, _) = register(&state, "gina").await;
    gina.send(&ClientMessage::AdminLogin {
        token: "test-admin-token".into(),
    })
    .await;
    let ServerMessage::Account(AccountReply::Info(info)) =
        gina.expect("Info", |m| reply(m).is_some()).await
    else {
        panic!("the new admin is told what changed")
    };
    assert!(
        info.needs_2fa && info.scopes.is_empty(),
        "admin rights wait for a second factor: {info:?}"
    );
    assert!(!state.can(
        *state.username_to_session.get("gina").unwrap(),
        crate::accounts::Powers::KICK
    ));

    let secret = totp_on(&mut gina).await;
    let ServerMessage::Account(AccountReply::Info(info)) = gina
        .expect("Info", |m| {
            matches!(m, ServerMessage::Account(AccountReply::Info(_)))
        })
        .await
    else {
        unreachable!()
    };
    assert_eq!(info.scopes, ["*"]);
    gina.expect("AdminStatus", |m| {
        matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
    })
    .await;

    // The token is spent once an admin exists.
    let (mut hank, _) = register(&state, "hank").await;
    hank.send(&ClientMessage::AdminLogin {
        token: "test-admin-token".into(),
    })
    .await;
    let ServerMessage::AdminError { reason } = hank
        .expect("AdminError", |m| {
            matches!(m, ServerMessage::AdminError { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("already"), "{reason}");

    // A new device: password, then a code; a wrong code asks again.
    let mut c = open_account(&state, "gina", AccountStart::Login).await;
    c.next().await;
    c.send(&ClientMessage::AuthContinue(AuthContinue::Secret {
        auth_secret: SECRET.to_vec(),
    }))
    .await;
    assert!(matches!(
        c.next().await,
        Some(ServerMessage::AuthStep(AuthStep::NeedTotp))
    ));
    c.send(&ClientMessage::AuthContinue(AuthContinue::Totp {
        code: "000000".into(),
    }))
    .await;
    assert!(
        matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::NeedTotp))
        ),
        "a wrong code asks again"
    );
    let code = format!(
        "{:06}",
        l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
    );
    c.send(&ClientMessage::AuthContinue(AuthContinue::Totp { code }))
        .await;
    c.expect("Vault", |m| {
        matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
    })
    .await;
    c.send(&keys(&IDENTITY, false)).await;
    let ServerMessage::Authenticated {
        account: Some(info),
        ..
    } = c
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert_eq!(info.scopes, ["*"]);
    let sid = *state.username_to_session.get("gina").unwrap();
    assert!(state.is_admin(sid) && state.can(sid, crate::accounts::Powers::KICK));
    // The app shows its admin controls only on AdminStatus: a later
    // sign-in needs it as much as the first.
    let uid = state.sessions.get(&sid).unwrap().user_id;
    c.expect(
        "AdminStatus",
        |m| matches!(m, ServerMessage::AdminStatus { user_id, is_admin: true } if *user_id == uid),
    )
    .await;
}

#[tokio::test]
async fn a_remembered_device_signs_in_alone_and_its_signature_does_not_replay() {
    use ring::signature::KeyPair;
    let (state, _db_state) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let relay_id = state.accounts.as_ref().unwrap().relay_id;
    let (mut ivy, _) = register(&state, "ivy").await;
    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let device_id = vec![0x42u8; 16];
    let origin = format!("voipc://{}", hex::encode(relay_id));
    let sign = |challenge: &str| {
        let msg = l4f_accounts::verify::devkey::message(
            &origin,
            &device_id,
            &l4f_accounts::challenge::challenge_bytes(challenge),
        );
        key.sign(&msg).as_ref().to_vec()
    };
    ivy.send(&ClientMessage::Account(AccountRequest::DeviceChallenge))
        .await;
    let ServerMessage::Account(AccountReply::DeviceChallenge { challenge }) =
        ivy.expect("challenge", |m| reply(m).is_some()).await
    else {
        panic!("a fresh sign-in may remember its device")
    };
    let signature = sign(&challenge);
    ivy.send(&ClientMessage::Account(AccountRequest::DeviceAdd {
        device_id: device_id.clone(),
        public_key: key.public_key().as_ref().to_vec(),
        signature,
    }))
    .await;
    assert!(matches!(
        ivy.expect("added", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::DeviceAdded)
    ));

    let mut d = open_account(
        &state,
        "ivy",
        AccountStart::DeviceKey {
            device_id: device_id.clone(),
        },
    )
    .await;
    let Some(ServerMessage::AuthStep(AuthStep::DeviceChallenge {
        challenge,
        relay_id: rid,
    })) = d.next().await
    else {
        panic!("a device challenge")
    };
    assert_eq!(rid, relay_id);
    let first_sig = sign(&challenge);
    d.send(&ClientMessage::AuthContinue(AuthContinue::DeviceSig {
        signature: first_sig.clone(),
    }))
    .await;
    d.expect("Vault", |m| {
        matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
    })
    .await;
    d.send(&keys(&IDENTITY, false)).await;
    d.expect("Authenticated", |m| {
        matches!(
            m,
            ServerMessage::Authenticated {
                account: Some(_),
                ..
            }
        )
    })
    .await;

    // The same signature on another connection: another challenge, another nonce.
    let mut replay = open_account(
        &state,
        "ivy",
        AccountStart::DeviceKey {
            device_id: device_id.clone(),
        },
    )
    .await;
    replay.next().await;
    replay
        .send(&ClientMessage::AuthContinue(AuthContinue::DeviceSig {
            signature: first_sig,
        }))
        .await;
    assert!(
        matches!(replay.next().await, Some(ServerMessage::AuthError { .. })),
        "a replayed signature is refused"
    );

    // H1-14: a remembered device alone cannot replace the identity every
    // contact pinned; that takes the password
    let mut reset = open_account(
        &state,
        "ivy",
        AccountStart::DeviceKey {
            device_id: device_id.clone(),
        },
    )
    .await;
    let Some(ServerMessage::AuthStep(AuthStep::DeviceChallenge { challenge, .. })) =
        reset.next().await
    else {
        panic!("a device challenge")
    };
    reset
        .send(&ClientMessage::AuthContinue(AuthContinue::DeviceSig {
            signature: sign(&challenge),
        }))
        .await;
    reset
        .expect("Vault", |m| {
            matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
        })
        .await;
    reset.send(&keys(&[7u8; 33], true)).await;
    let Some(ServerMessage::AuthError { reason }) = reset.next().await else {
        panic!("the reset went through")
    };
    assert!(reason.contains("password"), "{reason}");
}

/// A 0.12 app (protocol 11) reads only `AuthError`, and stops
/// reconnecting on its words.
#[tokio::test]
async fn a_pre_1_0_client_is_told_to_update() {
    #[derive(serde::Serialize)]
    enum Old {
        Authenticate {
            username: String,
            protocol_version: u32,
            app_version: String,
            identity_key: Option<Vec<u8>>,
            prekey_bundle: Option<PreKeyBundleData>,
        },
    }
    let state = admin_state();
    let (mut stream, server) = tokio::io::duplex(65536);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, _sid_rx) = oneshot::channel();
    let handler = tokio::spawn(handle_connection(
        server,
        "old".into(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        media_tx,
        sid_tx,
        state.clone(),
    ));
    let payload = postcard::to_allocvec(&Old::Authenticate {
        username: "old".into(),
        protocol_version: FIRST_STRUCTURED_REFUSAL - 1,
        app_version: "0.12.0".into(),
        identity_key: None,
        prekey_bundle: None,
    })
    .unwrap();
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&payload).await.unwrap();
    let mut c = Client {
        stream,
        handler,
        buf: BytesMut::new(),
    };
    let Some(ServerMessage::AuthError { reason }) = c.next().await else {
        panic!("an old client hears why")
    };
    // The words a 0.12 client stops reconnecting on (connect.ts)
    assert!(
        reason.contains("version mismatch") && reason.contains("please update your app"),
        "{reason}"
    );
}

/// Protocol match only: another app version on the same protocol is in.
#[tokio::test]
async fn another_app_version_on_the_same_protocol_is_admitted() {
    let state = admin_state();
    let first = ClientMessage::Authenticate {
        username: "newer-patch".into(),
        protocol_version: PROTOCOL_VERSION,
        app_version: "1.0.7".into(),
        identity_key: None,
        prekey_bundle: None,
        account: None,
    };
    let mut c = open_raw(&state, &first).await;
    c.expect("Authenticated", |m| {
        matches!(m, ServerMessage::Authenticated { .. })
    })
    .await;
}

/// A 1.x app one protocol behind (12, the first that reads `Refused`)
/// hears that it is the one to update.
#[tokio::test]
async fn a_client_one_protocol_behind_is_told_to_update() {
    let state = admin_state();
    let first = ClientMessage::Authenticate {
        username: "older".into(),
        protocol_version: PROTOCOL_VERSION - 1,
        app_version: "1.2.0".into(),
        identity_key: None,
        prekey_bundle: None,
        account: None,
    };
    let mut c = open_raw(&state, &first).await;
    let Some(ServerMessage::Refused {
        code,
        server_protocol,
        text,
        ..
    }) = c.next().await
    else {
        panic!("not refused")
    };
    assert_eq!((code, server_protocol), (REFUSED_VERSION, PROTOCOL_VERSION));
    assert!(
        text.contains("version mismatch") && text.contains("please update your app"),
        "{text}"
    );
}

/// A newer client hears, in a form it can read, that the server is the
/// one behind.
#[tokio::test]
async fn a_newer_client_is_told_the_server_needs_an_update() {
    let state = admin_state();
    let first = ClientMessage::Authenticate {
        username: "future".into(),
        protocol_version: PROTOCOL_VERSION + 1,
        app_version: "1.1.0".into(),
        identity_key: None,
        prekey_bundle: None,
        account: None,
    };
    let mut c = open_raw(&state, &first).await;
    let Some(ServerMessage::Refused {
        code,
        server_protocol,
        server_version,
        text,
    }) = c.next().await
    else {
        panic!("not refused")
    };
    assert_eq!(
        (code, server_protocol, server_version.as_str()),
        (REFUSED_VERSION, PROTOCOL_VERSION, APP_VERSION)
    );
    assert!(
        text.contains("version mismatch") && text.contains("the server needs an update"),
        "{text}"
    );
}

/// A guest whose stream holds next to nothing, so that as soon as it stops reading
/// the relay's writer stalls and everything queues up.
async fn slow_reader(state: &Arc<ServerState>, name: &str) -> Client {
    let (stream, server) = tokio::io::duplex(256);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, _sid_rx) = oneshot::channel();
    let handler = tokio::spawn(handle_connection(
        server,
        name.into(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        media_tx,
        sid_tx,
        state.clone(),
    ));
    let mut c = Client {
        stream,
        handler,
        buf: BytesMut::new(),
    };
    c.send(&ClientMessage::Authenticate {
        username: name.into(),
        protocol_version: PROTOCOL_VERSION,
        app_version: APP_VERSION.to_string(),
        identity_key: None,
        prekey_bundle: None,
        account: None,
    })
    .await;
    // The whole first burst, up to the list of the channel everybody starts in
    c.expect("General's list", |m| {
        matches!(m, ServerMessage::UserList { channel_id: 0, .. })
    })
    .await;
    c
}

/// Everybody joining at once, seen by someone whose writer is behind. At 256
/// messages this lost members without a word, measured at 1000 people on a small
/// server, and whoever misses a member never hands them their keys.
#[tokio::test]
async fn a_reader_behind_loses_nobody_in_a_burst_of_joins() {
    let state = admin_state();
    let mut c = slow_reader(&state, "behind").await;
    const JOINS: u32 = 5000;
    for i in 0..JOINS {
        broadcast_user_joined(
            &state,
            UserInfo {
                user_id: 1_000_000 + i,
                username: format!("joiner{i}"),
                channel_id: 0,
                is_muted: false,
                is_deafened: false,
                is_screen_sharing: false,
                is_admin: false,
                shares_history: false,
                account: None,
                is_moderator: false,
                badges: Vec::new(),
            },
        )
        .await;
    }
    let mut next = 0;
    while next < JOINS {
        match c.next().await {
            Some(ServerMessage::UserJoined { user }) => {
                assert_eq!(user.user_id, 1_000_000 + next, "in order, none missing");
                next += 1;
            }
            Some(_) => {}
            None => panic!("the connection ended after {next} of {JOINS}"),
        }
    }
}

/// Past what a connection may have waiting, it ends. It is not left behind with a
/// state that is quietly wrong, and it does not hold the relay's memory.
#[tokio::test]
async fn a_client_that_stopped_reading_is_ended_not_left_behind() {
    let state = admin_state();
    let c = slow_reader(&state, "stopped").await;
    assert_eq!(state.sessions.len(), 1);
    let frame = vec![0u8; 60_000];
    for _ in 0..crate::control::MAX_QUEUED_BYTES / frame.len() + 1 {
        state.broadcast_raw_to_all(&frame).await;
    }
    tokio::time::timeout(Duration::from_secs(10), c.handler)
        .await
        .expect("the connection ends though nothing reads it")
        .unwrap();
    assert_eq!(state.sessions.len(), 0, "and is cleaned up");
}

/// Runs the client's sign-in machine (voipc-crypto) against this relay.
async fn drive(
    c: &mut Client,
    m: &mut voipc_crypto::account::SignIn,
) -> Result<AccountInfo, String> {
    use voipc_crypto::account::Step;
    loop {
        let msg = c.next().await.ok_or("closed")?;
        if let ServerMessage::Authenticated {
            account: Some(info),
            ..
        } = &msg
        {
            return Ok(info.clone());
        }
        for step in m.on_message(&msg)? {
            match step {
                Step::Send(out) => c.send(&out).await,
                Step::Keys => {
                    let ik = m.identity().unwrap().public_key().serialize().to_vec();
                    let b = PreKeyBundleData {
                        identity_key: ik,
                        ..bundle()
                    };
                    c.send(&m.keys(b)).await;
                }
                Step::NeedTotp => return Err("asked for a code".into()),
                Step::Ignore => {}
                _ => return Err("not a sign-in step".into()),
            }
        }
    }
}

/// Runs a reset with the recovery key through the client's machine;
/// `code` answers a second factor.
async fn reset_with(
    state: &Arc<ServerState>,
    name: &str,
    recovery: &str,
    password: &str,
    code: Option<&str>,
) -> Result<(), String> {
    use voipc_crypto::account::{recovery_parse, Method, SignIn, Step};
    let recovery = zeroize::Zeroizing::new(recovery_parse(recovery).ok_or("not a recovery key")?);
    let method = Method::Reset {
        recovery,
        password: zeroize::Zeroizing::new(password.into()),
    };
    let (mut m, first) = SignIn::start(name, method, PROTOCOL_VERSION, APP_VERSION);
    let mut c = open_raw(state, &first).await;
    loop {
        let msg = c.next().await.ok_or("closed")?;
        for step in m.on_message(&msg)? {
            match step {
                Step::Send(out) => c.send(&out).await,
                Step::NeedTotp => c.send(&m.totp(code.ok_or("asked for a code")?)).await,
                Step::ResetDone => return Ok(()),
                _ => {}
            }
        }
    }
}

async fn password_sign_in(
    state: &Arc<ServerState>,
    name: &str,
    password: &str,
) -> Result<voipc_crypto::account::SignedIn, String> {
    use voipc_crypto::account::{Method, SignIn};
    let (mut m, first) = SignIn::start(
        name,
        Method::Password {
            password: zeroize::Zeroizing::new(password.into()),
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    drive(&mut open_raw(state, &first).await, &mut m).await?;
    m.finish()
}

/// 1.0 (A4): a forgotten password, set anew with the recovery key. The
/// relay hands out only what the key opens, checks the identity's
/// signature, and signs every device out.
#[tokio::test]
async fn the_recovery_key_sets_a_new_password_and_signs_every_device_out() {
    use voipc_crypto::account::{DeviceEnrol, DeviceKey, Method, SignIn};
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, _, signed) = register_with(&state, "kim").await;
    let recovery = signed.recovery.clone().unwrap();
    let identity = signed.identity.public_key().serialize().to_vec();
    let (enrol, ask) = DeviceEnrol::start(signed.relay_id);
    c.send(&ask).await;
    let ServerMessage::Account(r) = c.expect("challenge", |m| reply(m).is_some()).await else {
        unreachable!()
    };
    c.send(&enrol.on_reply(&r).unwrap()).await;
    assert!(matches!(
        c.expect("added", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::DeviceAdded)
    ));

    // Another key opens nothing; the client stops there.
    let other = voipc_crypto::account::recovery_text(&[7u8; 32]);
    let e = reset_with(&state, "kim", &other, "a brand new password", None)
        .await
        .unwrap_err();
    assert!(e.contains("recovery key"), "{e}");
    // The relay hands out no password slot, and refuses another identity's signature.
    let mut raw = open_account(&state, "kim", AccountStart::Reset).await;
    let Some(ServerMessage::AuthStep(AuthStep::ResetChallenge {
        blobs,
        second_factor: false,
        ..
    })) = raw.next().await
    else {
        panic!("a challenge")
    };
    assert!(
        blobs
            .iter()
            .all(|b| b.k == "slot.recovery" || b.k == "item.identity")
            && blobs.len() == 2,
        "{blobs:?}"
    );
    let forged = voipc_crypto::account::reset_proof(
        &voipc_crypto::generate_identity_key_pair(),
        &signed.relay_id,
        "kim",
        b"x",
    );
    raw.send(&ClientMessage::AuthContinue(AuthContinue::Reset {
        signature: forged,
        key_signature: vec![0; 64],
        auth_secret: SECRET.to_vec(),
        pass_slot: vec![1; 101],
        totp: None,
        recovery_code: None,
    }))
    .await;
    let ServerMessage::AuthError { reason } = raw
        .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("not this account's"), "{reason}");

    reset_with(&state, "kim", &recovery, "a brand new password", None)
        .await
        .unwrap();
    c.expect("signed out", |m| {
        matches!(m, ServerMessage::Disconnected { .. })
    })
    .await;
    assert!(password_sign_in(&state, "kim", "correct horse battery")
        .await
        .err()
        .unwrap()
        .contains("Wrong"));
    let key = DeviceKey::from_parts(enrol.key.device_id, enrol.key.pkcs8().to_vec()).unwrap();
    let (mut m, first) = SignIn::start(
        "kim",
        Method::Device {
            key,
            relay_id: signed.relay_id,
            dek: signed.vault.dek(),
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    assert!(
        drive(&mut open_raw(&state, &first).await, &mut m)
            .await
            .is_err(),
        "the remembered device is forgotten"
    );
    // The new password opens the same vault: the same identity, so nobody's pins break.
    let again = password_sign_in(&state, "kim", "a brand new password")
        .await
        .unwrap();
    assert_eq!(again.identity.public_key().serialize().to_vec(), identity);
}

/// S-006: the vault's DEK, which a remembered device keeps, opens the
/// identity, so it can make the old reset proof. An account with a reset
/// key refuses that proof: only the recovery key resets its password.
#[tokio::test]
async fn a_device_that_holds_the_vault_key_cannot_reset_the_password() {
    use voipc_crypto::account::{reset_proof, Vault};
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (_c, _, signed) = register_with(&state, "ida").await;
    let mut raw = open_account(&state, "ida", AccountStart::Reset).await;
    let Some(ServerMessage::AuthStep(AuthStep::ResetChallenge {
        relay_id,
        challenge,
        blobs,
        ..
    })) = raw.next().await
    else {
        panic!("a challenge")
    };
    let opened = Vault::from_dek(relay_id, "ida", signed.vault.dek())
        .open_item(&blobs, "item.identity")
        .unwrap()
        .payload;
    assert_eq!(opened, signed.identity.serialize().to_vec());
    raw.send(&ClientMessage::AuthContinue(AuthContinue::Reset {
        signature: reset_proof(&signed.identity, &relay_id, "ida", &challenge),
        key_signature: vec![0; 64],
        auth_secret: SECRET.to_vec(),
        pass_slot: vec![1; 101],
        totp: None,
        recovery_code: None,
    }))
    .await;
    let ServerMessage::AuthError { reason } = raw
        .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("not this account's"), "{reason}");
    let recovery = signed.recovery.clone().unwrap();
    reset_with(&state, "ida", &recovery, "a brand new password", None)
        .await
        .unwrap();
}

/// S-006: a new recovery key, with the password, replaces the old one:
/// the old stops working, the new resets. It is how an account made
/// before 1.3 gets its reset key.
#[tokio::test]
async fn a_new_recovery_key_replaces_the_old_one() {
    use voipc_crypto::account::{derive_from_master, recovery_text, reset_key, stretch, Vault};
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, _, signed) = register_with(&state, "joe").await;
    let old = signed.recovery.clone().unwrap();
    let fresh = [9u8; 32];
    let ask = |password: &str| {
        let master = stretch(password, &signed.relay_id, "joe");
        let vault = Vault::from_dek(signed.relay_id, "joe", signed.vault.dek());
        ClientMessage::Account(AccountRequest::RecoveryKeyNew {
            secret: derive_from_master(&master).auth_secret.to_vec(),
            recovery_slot: vault.recovery_slot(&fresh).v,
            reset_key: reset_key(&fresh, &signed.relay_id, "joe").to_vec(),
            totp: None,
            recovery_code: None,
        })
    };
    c.send(&ask("not the password")).await;
    assert!(matches!(
        c.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    c.send(&ask("correct horse battery")).await;
    assert!(matches!(
        c.expect("changed", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::RecoveryKeyChanged)
    ));
    assert!(
        reset_with(&state, "joe", &old, "a brand new password", None)
            .await
            .is_err()
    );
    reset_with(
        &state,
        "joe",
        &recovery_text(&fresh),
        "a brand new password",
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_reset_of_an_account_with_codes_needs_a_code() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, _, signed) = register_with(&state, "lou").await;
    let secret = totp_on(&mut c).await;
    let recovery = signed.recovery.clone().unwrap();
    assert_eq!(
        reset_with(&state, "lou", &recovery, "a brand new password", None)
            .await
            .unwrap_err(),
        "asked for a code"
    );
    assert!(reset_with(
        &state,
        "lou",
        &recovery,
        "a brand new password",
        Some("000000")
    )
    .await
    .is_err());
    let code = format!(
        "{:06}",
        l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
    );
    reset_with(
        &state,
        "lou",
        &recovery,
        "a brand new password",
        Some(&code),
    )
    .await
    .unwrap();
    assert_eq!(
        password_sign_in(&state, "lou", "a brand new password")
            .await
            .err()
            .as_deref(),
        Some("asked for a code"),
        "codes stay on"
    );
    assert!(password_sign_in(&state, "lou", "correct horse battery")
        .await
        .err()
        .unwrap()
        .contains("Wrong"));
}

#[tokio::test]
async fn a_password_change_keeps_this_connection_and_forgets_the_device_keys() {
    use voipc_crypto::account::stretch;
    use voipc_crypto::account::{DeviceEnrol, DeviceKey, Method, SignIn};
    use voipc_crypto::account_session::AccountSession;
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, info, signed) = register_with(&state, "max").await;
    let (enrol, ask) = DeviceEnrol::start(signed.relay_id);
    c.send(&ask).await;
    let ServerMessage::Account(r) = c.expect("challenge", |m| reply(m).is_some()).await else {
        unreachable!()
    };
    c.send(&enrol.on_reply(&r).unwrap()).await;
    assert!(matches!(
        c.expect("added", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::DeviceAdded)
    ));
    let (relay_id, dek) = (signed.relay_id, signed.vault.dek());
    let (mut session, _) = AccountSession::start(signed, &info, Default::default(), false, true);
    let old = stretch("correct horse battery", &relay_id, "max");
    let new = stretch("another good password", &relay_id, "max");
    for m in session.password_change(&new, &new, None, None).send {
        c.send(&m).await;
    }
    let msg = c.expect("refused", |m| reply(m).is_some()).await;
    assert!(
        matches!(msg, ServerMessage::Account(AccountReply::Error { ref request, .. }) if request == "PasswordChange"),
        "the old password must be right: {msg:?}"
    );
    for m in session.password_change(&old, &new, None, None).send {
        c.send(&m).await;
    }
    let ServerMessage::Account(changed) = c.expect("changed", |m| reply(m).is_some()).await else {
        unreachable!()
    };
    assert!(
        matches!(changed, AccountReply::PasswordChanged),
        "{changed:?}"
    );
    // Every device key went with the old password, this one's too: the
    // session asks to remember this device again.
    let again = session.on_reply(&changed);
    assert!(again
        .send
        .iter()
        .any(|m| matches!(m, ClientMessage::Account(AccountRequest::DeviceChallenge))));
    // This connection's token was swapped with l4f's, so it stays.
    crate::accounts::revalidate(&state).await;
    c.send(&ClientMessage::Account(AccountRequest::VaultPut {
        k: "item.still".into(),
        v: b"here".to_vec(),
        expect: 0,
    }))
    .await;
    assert!(matches!(
        c.expect("stored", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::VaultStored { .. })
    ));
    let key = DeviceKey::from_parts(enrol.key.device_id, enrol.key.pkcs8().to_vec()).unwrap();
    let (mut m, first) = SignIn::start(
        "max",
        Method::Device { key, relay_id, dek },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    assert!(
        drive(&mut open_raw(&state, &first).await, &mut m)
            .await
            .is_err(),
        "the old device key is forgotten"
    );
    assert!(password_sign_in(&state, "max", "correct horse battery")
        .await
        .err()
        .unwrap()
        .contains("Wrong"));
    let again = password_sign_in(&state, "max", "another good password")
        .await
        .expect("the new password opens the vault");
    assert_eq!(again.vault.dek(), dek, "the same vault: the DEK stays");
}

/// A password change that l4f refuses after the slot was written puts the
/// old slot back, so the vault still opens with the password that signs in.
#[tokio::test]
async fn a_failed_password_change_puts_the_old_slot_back() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (_c, info, _) = register_with(&state, "ned").await;
    let relay = state.accounts.clone().unwrap();
    let id = l4f_accounts::model::AccountId(info.id);
    let slot = |v: &[VaultBlob]| v.iter().find(|b| b.k == "slot.pass").unwrap().v.clone();
    let before = relay.vault(id).await.unwrap();
    let failed = crate::accounts::replace_pass_slot(&relay, id, &before, &[1u8; 101], || async {
        Err(l4f_accounts::service::Error::Invalid("refused"))
    })
    .await;
    assert_eq!(failed.unwrap_err(), "refused");
    assert_eq!(slot(&relay.vault(id).await.unwrap()), slot(&before));
    password_sign_in(&state, "ned", "correct horse battery")
        .await
        .expect("the old password still opens the vault");
}

async fn open_raw(state: &Arc<ServerState>, first: &ClientMessage) -> Client {
    let (stream, server) = tokio::io::duplex(65536);
    let (media_tx, _media_rx) = mpsc::channel(8);
    let (sid_tx, _sid_rx) = oneshot::channel();
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let handler = tokio::spawn(handle_connection(
        server,
        "raw".into(),
        lo,
        media_tx,
        sid_tx,
        state.clone(),
    ));
    let mut c = Client {
        stream,
        handler,
        buf: BytesMut::new(),
    };
    c.send(first).await;
    c
}

async fn epoch_put(c: &mut Client, conv: &str, epoch: u32, to: &[[u8; 16]]) -> ServerMessage {
    let wraps = to
        .iter()
        .map(|r| voipc_protocol::messages::WrapIn {
            recipient: *r,
            wrapped: vec![0xAB; 92],
        })
        .collect();
    c.send(&ClientMessage::Account(AccountRequest::EpochPut {
        conv: conv.into(),
        epoch,
        wraps,
    }))
    .await;
    c.expect("an EpochPut answer", |m| {
        matches!(
            m,
            ServerMessage::Account(AccountReply::EpochStored { .. } | AccountReply::Error { .. })
        )
    })
    .await
}

/// H1-03: new epochs per writer and conversation are capped per hour; an
/// epoch already there can still take more wraps.
#[tokio::test]
async fn new_epochs_are_capped_per_hour() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let relay = state.accounts.clone().unwrap();
    let (mut eve, e) = register(&state, "eve").await;
    let (_bob, b) = register(&state, "bob").await;
    let conv = voipc_protocol::conv::dm_conv(&e.id, &b.id);
    let now = l4f_accounts::util::now();
    for epoch in 0..60 {
        crate::accounts::raw(&relay, &format!(
                "INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ('{conv}', x'{}', {epoch}, x'{}', x'00', {now})",
                hex::encode(e.id), hex::encode(b.id)
            )).await.unwrap();
    }
    let refused = epoch_put(&mut eve, &conv, 1000, &[e.id, b.id]).await;
    assert!(
        matches!(refused, ServerMessage::Account(AccountReply::Error { ref reason, .. }) if reason.contains("Too many new keys")),
        "{refused:?}"
    );
    let known = epoch_put(&mut eve, &conv, 5, &[e.id, b.id]).await;
    assert!(
        matches!(
            known,
            ServerMessage::Account(AccountReply::EpochStored { .. })
        ),
        "{known:?}"
    );
}

/// H1-04: one member minting epochs no longer pushes another writer's key
/// out of what a reader fetches.
#[tokio::test]
async fn one_writer_cannot_crowd_another_out_of_the_wraps() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let relay = state.accounts.clone().unwrap();
    let (mut alice, a) = register(&state, "alice").await;
    let (mut bob, b) = register(&state, "bob").await;
    let (_eve, e) = register(&state, "eve").await;
    let conv = "c:00112233445566778899aabbccddeeff";
    for id in [a.id, b.id, e.id] {
        crate::accounts::raw(
            &relay,
            &format!(
                "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{conv}', x'{}', 0)",
                hex::encode(id)
            ),
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        epoch_put(&mut alice, conv, 1, &[a.id, b.id, e.id]).await,
        ServerMessage::Account(AccountReply::EpochStored { .. })
    ));
    let later = l4f_accounts::util::now() + 10;
    for epoch in 0..400 {
        crate::accounts::raw(&relay, &format!(
                "INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ('{conv}', x'{}', {epoch}, x'{}', x'00', {later})",
                hex::encode(e.id), hex::encode(b.id)
            )).await.unwrap();
    }
    bob.send(&ClientMessage::Account(AccountRequest::WrapsFetch {
        conv: conv.into(),
    }))
    .await;
    let ServerMessage::Account(AccountReply::Wraps { wraps, .. }) = bob
        .expect("Wraps", |m| {
            matches!(m, ServerMessage::Account(AccountReply::Wraps { .. }))
        })
        .await
    else {
        unreachable!()
    };
    assert!(
        wraps.iter().any(|w| w.owner == a.id),
        "alice's key was pushed out"
    );
    assert!(wraps.len() <= 400);
}

/// H1-02: a sign-in waiting for its client holds no permit, so sign-ins
/// that stall (or are made to) cannot lock everybody else out.
#[tokio::test]
async fn stalled_sign_ins_hold_no_permit() {
    use voipc_crypto::account::{Method, SignIn};
    use zeroize::Zeroizing;
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let pw = || Zeroizing::new("correct horse battery".to_string());
    let (mut m, first) = SignIn::start(
        "kim",
        Method::Register {
            password: pw(),
            invite: None,
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    drive(&mut open_raw(&state, &first).await, &mut m)
        .await
        .unwrap();

    // More stalled sign-ins from this address than it has permits
    let mut stalled = Vec::new();
    for _ in 0..4 + 2 {
        let mut c = open_account(&state, "kim", AccountStart::Login).await;
        assert!(matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::Salt { .. }))
        ));
        stalled.push(c);
    }
    let (mut m, first) = SignIn::start(
        "kim",
        Method::Password { password: pw() },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    drive(&mut open_raw(&state, &first).await, &mut m)
        .await
        .expect("signs in beside the stalled ones");
}

#[tokio::test]
async fn the_clients_sign_in_machine_signs_up_remembers_the_device_and_signs_in_both_ways() {
    use voipc_crypto::account::{DeviceEnrol, Method, SignIn};
    use zeroize::Zeroizing;
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let pw = || Zeroizing::new("correct horse battery".to_string());

    let (mut m, first) = SignIn::start(
        "jules",
        Method::Register {
            password: pw(),
            invite: None,
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    let mut c = open_raw(&state, &first).await;
    drive(&mut c, &mut m).await.unwrap();
    let signed = m.finish().unwrap();
    assert!(
        signed.recovery.is_some(),
        "a new account gets its recovery key"
    );
    let identity = signed.identity.public_key().serialize().to_vec();

    // Remember this device.
    let (enrol, ask) = DeviceEnrol::start(signed.relay_id);
    c.send(&ask).await;
    let ServerMessage::Account(r) = c.expect("challenge", |m| reply(m).is_some()).await else {
        unreachable!()
    };
    c.send(&enrol.on_reply(&r).expect("a challenge to sign"))
        .await;
    assert!(matches!(
        c.expect("added", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::DeviceAdded)
    ));
    let dek = signed.vault.dek();

    // A new device: the password opens the same vault and the same identity.
    let (mut m, first) = SignIn::start(
        "jules",
        Method::Password { password: pw() },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    let mut c2 = open_raw(&state, &first).await;
    drive(&mut c2, &mut m).await.unwrap();
    assert_eq!(
        m.finish()
            .unwrap()
            .identity
            .public_key()
            .serialize()
            .to_vec(),
        identity
    );

    // The remembered device: no password.
    let key = voipc_crypto::account::DeviceKey::from_parts(
        enrol.key.device_id,
        enrol.key.pkcs8().to_vec(),
    )
    .unwrap();
    let (mut m, first) = SignIn::start(
        "jules",
        Method::Device {
            key,
            relay_id: signed.relay_id,
            dek,
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    let mut c3 = open_raw(&state, &first).await;
    drive(&mut c3, &mut m).await.unwrap();
    assert_eq!(
        m.finish()
            .unwrap()
            .identity
            .public_key()
            .serialize()
            .to_vec(),
        identity
    );

    // A wrong password does not open the vault the relay would never hand out anyway.
    let (mut m, first) = SignIn::start(
        "jules",
        Method::Password {
            password: Zeroizing::new("wrong wrong wrong".into()),
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    let mut c4 = open_raw(&state, &first).await;
    assert!(drive(&mut c4, &mut m).await.unwrap_err().contains("Wrong"));
}

#[tokio::test]
async fn vault_items_are_written_compare_and_set() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, _) = register(&state, "kim").await;
    let put = |k: &str, v: &[u8], expect: i64| {
        ClientMessage::Account(AccountRequest::VaultPut {
            k: k.into(),
            v: v.to_vec(),
            expect,
        })
    };
    c.send(&put("item.pins", b"one", 0)).await;
    let ServerMessage::Account(AccountReply::VaultStored { version, .. }) =
        c.expect("stored", |m| reply(m).is_some()).await
    else {
        panic!("a new item is stored")
    };
    assert_eq!(version, 1);
    // A second writer that did not see version 1 gets it back to merge with.
    c.send(&put("item.pins", b"two", 0)).await;
    let ServerMessage::Account(AccountReply::VaultConflict { blob: Some(b), .. }) =
        c.expect("conflict", |m| reply(m).is_some()).await
    else {
        panic!("a stale write is refused with what is there")
    };
    assert_eq!((b.v.as_slice(), b.version), (&b"one"[..], 1));
    c.send(&put("item.pins", b"two", 1)).await;
    assert!(matches!(
        c.expect("stored", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::VaultStored { version: 2, .. })
    ));
    c.send(&put("Bad Name!", b"x", 0)).await;
    assert!(matches!(
        c.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    // One item, and the whole vault, stay under the frame a sign-in sends them in.
    c.send(&put("item.big", &vec![0u8; 49 * 1024], 0)).await;
    assert!(matches!(
        c.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    c.send(&put("item.a", &vec![0u8; 40 * 1024], 0)).await;
    assert!(matches!(
        c.expect("stored", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::VaultStored { .. })
    ));
    c.send(&put("item.b", &vec![0u8; 20 * 1024], 0)).await;
    assert!(matches!(
        c.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    // And it still fits the frame at sign-in.
    drop(c);
    let mut again = login(&state, "kim", &IDENTITY, false).await;
    let ServerMessage::AuthStep(AuthStep::Vault { blobs }) = again
        .expect("Vault", |m| matches!(m, ServerMessage::AuthStep(_)))
        .await
    else {
        unreachable!()
    };
    assert!(blobs.iter().any(|b| b.k == "item.a"));
    // A guest has no vault.
    let mut g = connect(&state, "lee#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    g.send(&put("item.pins", b"x", 0)).await;
    assert!(matches!(
        g.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
}

/// Registers `name` with a real identity (so its log key can be endorsed).
async fn register_with(
    state: &Arc<ServerState>,
    name: &str,
) -> (Client, AccountInfo, voipc_crypto::account::SignedIn) {
    use voipc_crypto::account::{Method, SignIn};
    use zeroize::Zeroizing;
    let (mut m, first) = SignIn::start(
        name,
        Method::Register {
            password: Zeroizing::new("correct horse battery".into()),
            invite: None,
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    let mut c = open_raw(state, &first).await;
    let info = drive(&mut c, &mut m).await.unwrap();
    (c, info, m.finish().unwrap())
}

#[tokio::test]
async fn a_dm_kept_for_somebody_offline_reaches_them_sealed_end_to_end() {
    use voipc_crypto::log::{
        dm_conv, endorsed, epoch_key, open_entry, seal_entry, unwrap, wrap, LogKey,
    };
    use voipc_protocol::messages::WrapIn;
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut alice, a, alice_id) = register_with(&state, "alice").await;
    let (mut bob, b, bob_id) = register_with(&state, "bob").await;
    let (alice_lk, bob_lk) = (LogKey::generate(), LogKey::generate());
    let ask = |r: AccountRequest| ClientMessage::Account(r);
    for (c, lk, id) in [
        (&mut alice, &alice_lk, &alice_id),
        (&mut bob, &bob_lk, &bob_id),
    ] {
        c.send(&ask(AccountRequest::LogKeyPublish {
            logkey: lk.public(),
            sig: lk.endorse(&id.identity),
        }))
        .await;
        assert!(matches!(
            c.expect("stored", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::LogKeyStored)
        ));
    }
    // Alice looks bob's log key up and checks it is his identity's.
    alice
        .send(&ask(AccountRequest::LogKeys {
            accounts: vec![b.id],
        }))
        .await;
    let ServerMessage::Account(AccountReply::LogKeysFound { keys }) =
        alice.expect("keys", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    assert_eq!(keys.len(), 1);
    assert!(
        endorsed(&keys[0].identity, &keys[0].logkey, &keys[0].sig),
        "bob's log key is endorsed by bob's identity"
    );
    let conv = dm_conv(&a.id, &b.id);
    let k = epoch_key();
    let wraps = vec![
        WrapIn {
            recipient: a.id,
            wrapped: wrap(&alice_lk.public(), &k, &conv, &a.id, 1, &a.id).unwrap(),
        },
        WrapIn {
            recipient: b.id,
            wrapped: wrap(&keys[0].logkey, &k, &conv, &a.id, 1, &b.id).unwrap(),
        },
    ];
    alice
        .send(&ask(AccountRequest::EpochPut {
            conv: conv.clone(),
            epoch: 1,
            wraps,
        }))
        .await;
    assert!(matches!(
        alice.expect("epoch", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::EpochStored { epoch: 1, .. })
    ));
    let env = voipc_crypto::envelope::envelope("m1", "while you were away", None);
    let ct = seal_entry(&k, &conv, &a.id, 1, &alice_lk, &env, 1_700_000_000_000);
    alice
        .send(&ask(AccountRequest::LogAppend {
            conv: conv.clone(),
            epoch: 1,
            ct,
            ttl_secs: None,
        }))
        .await;
    let ServerMessage::Account(AccountReply::LogAppended { seq, .. }) =
        alice.expect("appended", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    // A message whose timer is zero is never handed out.
    let gone = seal_entry(
        &k,
        &conv,
        &a.id,
        1,
        &alice_lk,
        &voipc_crypto::envelope::envelope("m0", "gone", Some(1)),
        1,
    );
    alice
        .send(&ask(AccountRequest::LogAppend {
            conv: conv.clone(),
            epoch: 1,
            ct: gone,
            ttl_secs: Some(0),
        }))
        .await;
    alice.expect("appended", |m| reply(m).is_some()).await;

    // Bob, later: the index names the conversation, the wrap and the entry open.
    bob.send(&ask(AccountRequest::LogIndex)).await;
    // (Past the news of alice's key for him, pushed when she filed it.)
    let ServerMessage::Account(AccountReply::LogConvs { convs }) = bob
        .expect("index", |m| {
            matches!(m, ServerMessage::Account(AccountReply::LogConvs { .. }))
        })
        .await
    else {
        panic!()
    };
    assert!(
        convs.iter().any(|(c, last)| *c == conv && *last >= seq),
        "{convs:?}"
    );
    bob.send(&ask(AccountRequest::WrapsFetch { conv: conv.clone() }))
        .await;
    let ServerMessage::Account(AccountReply::Wraps { wraps, .. }) =
        bob.expect("wraps", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    assert_eq!(wraps.len(), 1, "only the wrap for bob");
    let key = unwrap(
        &bob_lk,
        &wraps[0].wrapped,
        &conv,
        &wraps[0].owner,
        wraps[0].epoch,
        &b.id,
    )
    .unwrap();
    bob.send(&ask(AccountRequest::LogFetch {
        conv: conv.clone(),
        after: 0,
    }))
    .await;
    let ServerMessage::Account(AccountReply::LogPage { entries, more, .. }) =
        bob.expect("page", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    assert!(!more);
    assert_eq!(entries.len(), 1, "the zero-timer entry is not handed out");
    let (envelope, _) = open_entry(
        &key,
        &conv,
        &entries[0].sender,
        entries[0].epoch,
        &alice_lk.public(),
        &entries[0].ct,
    )
    .unwrap();
    assert_eq!(
        voipc_crypto::envelope::open_envelope(&envelope).text,
        "while you were away"
    );

    // Nobody else reads it, and wraps go to members only.
    let (mut carol, c, _) = register_with(&state, "carol").await;
    carol
        .send(&ask(AccountRequest::LogFetch {
            conv: conv.clone(),
            after: 0,
        }))
        .await;
    assert!(matches!(
        carol.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    let outsider = vec![WrapIn {
        recipient: c.id,
        wrapped: vec![0; 93],
    }];
    alice
        .send(&ask(AccountRequest::EpochPut {
            conv: conv.clone(),
            epoch: 2,
            wraps: outsider,
        }))
        .await;
    assert!(matches!(
        alice.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    let mut guest = connect(&state, "dan#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    guest
        .send(&ask(AccountRequest::LogFetch { conv, after: 0 }))
        .await;
    assert!(matches!(
        guest.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
}

#[tokio::test]
async fn a_relay_that_keeps_no_messages_refuses_them() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    // `cloud = false`, after the fact: the flag the operator sets.
    let mut relay = std::sync::Arc::try_unwrap(state)
        .ok()
        .expect("one owner")
        .accounts
        .take()
        .unwrap();
    std::sync::Arc::get_mut(&mut relay).unwrap().cloud = false;
    let mut s = ServerState::new(
        &ServerConfig::default(),
        ServerSettings::default(),
        Vec::new(),
        "t".into(),
    );
    s.accounts = Some(relay);
    let state = Arc::new(s);
    let (mut a, info) = register(&state, "erin").await;
    let conv = voipc_protocol::conv::dm_conv(&info.id, &[0xff; 16]);
    a.send(&ClientMessage::Account(AccountRequest::LogAppend {
        conv,
        epoch: 1,
        ct: vec![1; 40],
        ttl_secs: None,
    }))
    .await;
    let ServerMessage::Account(AccountReply::Error { reason, .. }) =
        a.expect("refused", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    assert!(reason.contains("keeps no messages"), "{reason}");
}

/// Feeds every account reply to `sync` and sends what it answers, until
/// the relay has been quiet for a moment. Returns the events.
async fn pump(
    c: &mut Client,
    sync: &mut voipc_crypto::sync::AccountSync,
    first: Vec<ClientMessage>,
) -> Vec<voipc_crypto::sync::Event> {
    for m in first {
        c.send(&m).await;
    }
    let mut events = Vec::new();
    loop {
        let next = async {
            loop {
                if let Some(payload) = try_decode_frame(&mut c.buf).unwrap() {
                    return Some(decode_server_msg(&payload).unwrap());
                }
                if c.stream.read_buf(&mut c.buf).await.unwrap() == 0 {
                    return None;
                }
            }
        };
        let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), next).await else {
            return events;
        };
        if let ServerMessage::Account(r) = msg {
            if let Some((out, ev)) = sync.on_reply(&r) {
                for m in out {
                    c.send(&m).await;
                }
                events.extend(ev);
            }
        }
    }
}

async fn sign_in_password(
    state: &Arc<ServerState>,
    name: &str,
) -> (Client, AccountInfo, voipc_crypto::account::SignedIn) {
    use voipc_crypto::account::{Method, SignIn};
    let (mut m, first) = SignIn::start(
        name,
        Method::Password {
            password: zeroize::Zeroizing::new("correct horse battery".into()),
        },
        PROTOCOL_VERSION,
        APP_VERSION,
    );
    let mut c = open_raw(state, &first).await;
    let info = drive(&mut c, &mut m).await.unwrap();
    (c, info, m.finish().unwrap())
}

#[tokio::test]
async fn a_dm_written_while_they_were_away_is_read_on_every_device_once() {
    use voipc_crypto::sync::{AccountSync, Event, Prefs};
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut alice, a, alice_signed) = register_with(&state, "alice").await;
    let (mut bob, b, bob_signed) = register_with(&state, "bob").await;
    let (mut sa, first) = AccountSync::start(&alice_signed, a.id, Default::default(), true);
    pump(&mut alice, &mut sa, first).await;
    let (mut sb, first) = AccountSync::start(&bob_signed, b.id, Default::default(), true);
    pump(&mut bob, &mut sb, first).await;
    drop(bob);

    // Off by default: nothing is kept until alice says so.
    let env = voipc_crypto::envelope::envelope("m1", "hi bob, while you were away", None);
    assert!(
        sa.send_dm(b.id, env.clone(), 1_700_000_000_000, None)
            .is_empty(),
        "opt-in"
    );
    let save = sa.set_prefs(Prefs {
        cloud: true,
        asked: true,
    });
    pump(&mut alice, &mut sa, save).await;
    let out = sa.send_dm(b.id, env, 1_700_000_000_000, None);
    let events = pump(&mut alice, &mut sa, out).await;
    assert!(
        events.iter().any(|e| matches!(e, Event::Kept { .. })),
        "{events:?}"
    );

    // Bob comes back: it is there, from alice, opened and proven.
    let (mut bob2, _, bob_signed2) = sign_in_password(&state, "bob").await;
    let (mut sb2, first) = AccountSync::start(&bob_signed2, b.id, Default::default(), true);
    let events = pump(&mut bob2, &mut sb2, first).await;
    let got: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                envelope,
                from_me,
                peer,
                peer_name,
                ..
            } => Some((
                voipc_crypto::envelope::open_envelope(envelope).text,
                *from_me,
                *peer,
                peer_name.clone(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        got,
        vec![(
            "hi bob, while you were away".to_string(),
            false,
            a.id,
            "alice".to_string()
        )]
    );
    // Read once: with this device's cursors it is not handed over again.
    let memory = sb2.memory();
    drop(bob2);
    let (mut bob3, _, bob_signed3) = sign_in_password(&state, "bob").await;
    let (mut sb3, first) = AccountSync::start(&bob_signed3, b.id, memory, true);
    let again = pump(&mut bob3, &mut sb3, first).await;
    assert!(
        !again.iter().any(|e| matches!(e, Event::Message { .. })),
        "{again:?}"
    );
    // And alice's other device sees her own message as hers.
    drop(alice);
    let (mut alice2, _, alice_signed2) = sign_in_password(&state, "alice").await;
    let (mut sa2, first) = AccountSync::start(&alice_signed2, a.id, Default::default(), true);
    let mine = pump(&mut alice2, &mut sa2, first).await;
    assert!(
        mine.iter()
            .any(|e| matches!(e, Event::Message { from_me: true, peer, .. } if *peer == b.id)),
        "{mine:?}"
    );
    assert!(
        sa2.prefs().cloud,
        "the choice followed her to the other device"
    );
}

/// Somebody online reads a kept message at once. It is what repairs a live
/// copy that missed them: they had just reloaded, or sit on no list the
/// writer sees.
#[tokio::test]
async fn a_message_kept_for_somebody_online_reaches_them_at_once() {
    use voipc_crypto::sync::{AccountSync, Event, Prefs};
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut alice, a, alice_signed) = register_with(&state, "alice").await;
    let (mut bob, b, bob_signed) = register_with(&state, "bob").await;
    let (mut sa, first) = AccountSync::start(&alice_signed, a.id, Default::default(), true);
    pump(&mut alice, &mut sa, first).await;
    let (mut sb, first) = AccountSync::start(&bob_signed, b.id, Default::default(), true);
    pump(&mut bob, &mut sb, first).await;
    let save = sa.set_prefs(Prefs {
        cloud: true,
        asked: true,
    });
    pump(&mut alice, &mut sa, save).await;

    for text in ["one", "two"] {
        let env = voipc_crypto::envelope::envelope(text, text, None);
        let out = sa.send_dm(b.id, env, 1_700_000_000_000, None);
        pump(&mut alice, &mut sa, out).await;
        let events = pump(&mut bob, &mut sb, Vec::new()).await;
        let got: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                Event::Message { envelope, .. } => {
                    Some(voipc_crypto::envelope::open_envelope(envelope).text)
                }
                _ => None,
            })
            .collect();
        assert_eq!(got, vec![text.to_string()], "{events:?}");
    }
}

/// Appends an entry whose bytes the relay cannot read anyway.
async fn append_raw(c: &mut Client, conv: &str, size: usize) -> AccountReply {
    c.send(&ClientMessage::Account(AccountRequest::LogAppend {
        conv: conv.to_string(),
        epoch: 1,
        ct: vec![7; size],
        ttl_secs: None,
    }))
    .await;
    let ServerMessage::Account(r) = c.expect("answer", |m| reply(m).is_some()).await else {
        panic!()
    };
    r
}

async fn fetch_raw(c: &mut Client, conv: &str, after: i64) -> (Vec<i64>, bool) {
    c.send(&ClientMessage::Account(AccountRequest::LogFetch {
        conv: conv.to_string(),
        after,
    }))
    .await;
    let ServerMessage::Account(AccountReply::LogPage { entries, more, .. }) = c
        .expect("page", |m| {
            matches!(m, ServerMessage::Account(AccountReply::LogPage { .. }))
        })
        .await
    else {
        panic!()
    };
    (entries.iter().map(|e| e.seq).collect(), more)
}

/// A browser reads back what it holds after every reload, not a year's log.
#[tokio::test]
async fn a_negative_fetch_starts_at_the_newest_entries_and_pages_on() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut alice, a, _) = register_with(&state, "alice").await;
    let conv = voipc_protocol::conv::dm_conv(&a.id, &[0xee; 16]);
    let mut seqs = Vec::new();
    for _ in 0..5 {
        // Big enough that a page holds two
        let AccountReply::LogAppended { seq, .. } = append_raw(&mut alice, &conv, 16 * 1024).await
        else {
            panic!("appended")
        };
        seqs.push(seq);
    }
    let (first, more) = fetch_raw(&mut alice, &conv, -4).await;
    assert_eq!(first, seqs[1..3], "the oldest of the newest four, in order");
    assert!(more);
    let (rest, more) = fetch_raw(&mut alice, &conv, *first.last().unwrap()).await;
    assert_eq!(rest, seqs[3..5]);
    assert!(!more);
    // Fewer than asked for, or the most anybody could ask for: from the start
    for after in [-100, i64::MIN, 0] {
        assert_eq!(
            fetch_raw(&mut alice, &conv, after).await.0,
            seqs[..2],
            "{after}"
        );
    }
}

/// A kept copy carries the writer's account, and the live message goes out
/// under the alias: together they would tie the two for its reader.
#[tokio::test]
async fn nothing_is_kept_for_a_direct_message_written_under_a_pseudonym() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut alice, a, _) = register_with(&state, "alice").await;
    let conv = voipc_protocol::conv::dm_conv(&a.id, &[0xee; 16]);
    assert!(matches!(
        append_raw(&mut alice, &conv, 8).await,
        AccountReply::LogAppended { .. }
    ));
    alice
        .send(&ClientMessage::CreateChannel {
            name: "masks".into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: true,
            text: false,
        })
        .await;
    let ServerMessage::ChannelCreated { channel } = alice
        .expect("ChannelCreated", |m| {
            matches!(m, ServerMessage::ChannelCreated { .. })
        })
        .await
    else {
        unreachable!()
    };
    alice
        .send(&ClientMessage::JoinChannel {
            channel_id: channel.channel_id,
            password: None,
        })
        .await;
    alice
        .expect("in the channel", |m| {
            matches!(m, ServerMessage::UserList { channel_id, .. } if *channel_id == channel.channel_id)
        })
        .await;
    assert!(matches!(
        append_raw(&mut alice, &conv, 8).await,
        AccountReply::Error { request, reason } if request == "LogAppend" && reason.contains("pseudonym")
    ));
}

/// Reading a long log back must not refuse a message being written, nor the
/// other way round.
#[tokio::test]
async fn reading_the_log_has_its_own_budget() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut alice, a, _) = register_with(&state, "alice").await;
    let conv = voipc_protocol::conv::dm_conv(&a.id, &[0xee; 16]);
    let limiter = || crate::state::RateLimiter::new(0.0, 0.0);
    for mut s in state.sessions.iter_mut() {
        s.account_rate = limiter();
    }
    assert!(
        matches!(append_raw(&mut alice, &conv, 8).await, AccountReply::Error { request, reason } if request == "LogAppend" && reason.contains("slow down"))
    );
    assert!(
        fetch_raw(&mut alice, &conv, 0).await.0.is_empty(),
        "still read"
    );
    for mut s in state.sessions.iter_mut() {
        s.account_rate = crate::state::RateLimiter::new(30.0, 10.0);
        s.log_read_rate = limiter();
    }
    assert!(matches!(
        append_raw(&mut alice, &conv, 8).await,
        AccountReply::LogAppended { .. }
    ));
    alice
        .send(&ClientMessage::Account(AccountRequest::LogFetch {
            conv: conv.clone(),
            after: 0,
        }))
        .await;
    assert!(matches!(
        alice.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { request, reason }) if request == "LogFetch" && reason.contains("slow down")
    ));
}

// ── channel logs ──

/// A relay with accounts and one persistent text channel (id 1), which
/// keeps a log; returns the log's conversation id too.
async fn relay_with_log() -> (Arc<ServerState>, TempDb, String) {
    let mut config = ServerConfig::default();
    config.accounts.mode = AccountsMode::Optional;
    config.accounts.registration = RegistrationMode::Open;
    let db = TempDb(std::env::temp_dir().join(format!(
        "voipc-relay-{}.db",
        hex::encode(rand::random::<[u8; 8]>())
    )));
    let store = l4f_accounts::store::Store::connect(&format!("sqlite://{}", db.0.display()))
        .await
        .unwrap();
    let relay = crate::accounts::Relay::open_with(&config.accounts, store, &[9u8; 32])
        .await
        .unwrap();
    let lounge = crate::channels::ChannelEntry {
        name: "lounge".into(),
        text: true,
        ..Default::default()
    };
    let mut state = ServerState::new(
        &config,
        ServerSettings::default(),
        vec![lounge],
        "test-admin-token".into(),
    );
    state.accounts = Some(Arc::new(relay));
    let log = state.channels.get_mut()[&1].info.log.clone();
    assert!(
        log.starts_with("c:"),
        "a persistent channel on a relay with accounts keeps a log: {log:?}"
    );
    (Arc::new(state), db, log)
}

/// Puts the session `account` has into channel 1.
async fn into_lounge(state: &Arc<ServerState>, account: &[u8; 16]) {
    let sid = *state.account_sessions.get(account).unwrap();
    let uid = state.sessions.get(&sid).unwrap().user_id;
    crate::state::test_support::put_in_channel(state, 1, &[(uid, sid)]).await;
}

/// Signs `name` up with cloud copies on, in channel 1, keeping its log.
async fn member(
    state: &Arc<ServerState>,
    log: &str,
    name: &str,
    share: bool,
) -> (Client, AccountInfo, voipc_crypto::sync::AccountSync) {
    use voipc_crypto::sync::{AccountSync, Prefs};
    let (mut c, info, signed) = register_with(state, name).await;
    let (mut s, first) = AccountSync::start(&signed, info.id, Default::default(), share);
    pump(&mut c, &mut s, first).await;
    let save = s.set_prefs(Prefs {
        cloud: true,
        asked: true,
    });
    pump(&mut c, &mut s, save).await;
    into_lounge(state, &info.id).await;
    let out = s.enter(log);
    pump(&mut c, &mut s, out).await;
    (c, info, s)
}

/// (writer, text) of each stored channel message among `events`.
fn channel_texts(events: &[voipc_crypto::sync::Event]) -> Vec<(String, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            voipc_crypto::sync::Event::ChannelMessage {
                sender_name,
                envelope,
                ..
            } => Some((
                sender_name.clone(),
                voipc_crypto::envelope::open_envelope(envelope).text,
            )),
            _ => None,
        })
        .collect()
}

/// The names in each `Readers` event, and whether it came with history.
fn readers(events: &[voipc_crypto::sync::Event]) -> Vec<(Vec<String>, bool)> {
    events
        .iter()
        .filter_map(|e| match e {
            voipc_crypto::sync::Event::Readers {
                accounts, history, ..
            } => Some((accounts.iter().map(|(_, n)| n.clone()).collect(), *history)),
            _ => None,
        })
        .collect()
}

fn say(id: &str, text: &str) -> Vec<u8> {
    voipc_crypto::envelope::envelope(id, text, None)
}

#[tokio::test]
async fn a_channel_log_is_read_by_members_who_were_away() {
    use voipc_crypto::sync::{AccountSync, Event};
    let (state, _db, log) = relay_with_log().await;
    let (mut alice, _, mut sa) = member(&state, &log, "alice", true).await;
    let (bob, b, _) = member(&state, &log, "bob", true).await;
    drop(bob);

    // Nobody else is here: alice writes for whoever reads it later, and is
    // told who that is.
    let out = sa.send_channel(&log, say("m1", "for later"), 1_700_000_000_000, None);
    let events = pump(&mut alice, &mut sa, out).await;
    assert!(
        events.iter().any(|e| matches!(e, Event::Kept { .. })),
        "{events:?}"
    );
    assert_eq!(readers(&events), vec![(vec!["bob".to_string()], false)]);

    // Bob, on another device and not in the channel: it is there for him.
    let (mut bob2, _, signed) = sign_in_password(&state, "bob").await;
    let (mut sb2, first) = AccountSync::start(&signed, b.id, Default::default(), true);
    let events = pump(&mut bob2, &mut sb2, first).await;
    assert_eq!(
        channel_texts(&events),
        vec![("alice".to_string(), "for later".to_string())]
    );
    // Read once.
    let memory = sb2.memory();
    drop(bob2);
    let (mut bob3, _, signed) = sign_in_password(&state, "bob").await;
    let (mut sb3, first) = AccountSync::start(&signed, b.id, memory, true);
    assert!(channel_texts(&pump(&mut bob3, &mut sb3, first).await).is_empty());

    // Somebody who never kept the channel reads nothing of it, and cannot
    // start keeping it from outside.
    let (mut carol, _, _) = register_with(&state, "carol").await;
    let ask = |r: AccountRequest| ClientMessage::Account(r);
    carol
        .send(&ask(AccountRequest::LogFetch {
            conv: log.clone(),
            after: 0,
        }))
        .await;
    assert!(matches!(
        carol.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    carol
        .send(&ask(AccountRequest::LogJoin { conv: log.clone() }))
        .await;
    let ServerMessage::Account(AccountReply::Error { reason, .. }) =
        carol.expect("refused", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    assert!(reason.contains("Join the channel"), "{reason}");
}

/// The shell is another process: what it ends in the database reaches a
/// connection that is already open at the next check.
#[tokio::test]
async fn a_session_ended_from_the_shell_ends_the_connection_too() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, info) = register(&state, "sam").await;
    crate::accounts::revalidate(&state).await;
    assert!(
        state.account_sessions.contains_key(&info.id),
        "nothing changed, nothing ends"
    );
    // What `voipc-server admin reset-2fa` does to the account's sessions.
    let relay = state.accounts.clone().unwrap();
    relay
        .store()
        .delete_sessions_of(l4f_accounts::model::AccountId(info.id), None)
        .await
        .unwrap();
    crate::accounts::revalidate(&state).await;
    let msg = c
        .expect("Disconnected", |m| {
            matches!(m, ServerMessage::Disconnected { .. })
        })
        .await;
    assert!(matches!(msg, ServerMessage::Disconnected { reason } if reason.contains("signed out")));
}

/// A role given from the shell to an account without codes changes none of
/// its rights yet, so no scope changes; the account is still asked to set
/// codes up at the next check, not at its next sign-in.
#[tokio::test]
async fn a_role_given_from_the_shell_asks_for_codes_at_the_next_check() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, info) = register(&state, "rita").await;
    let relay = state.accounts.clone().unwrap();
    let ctx = relay.ctx(IpAddr::V4(Ipv4Addr::LOCALHOST), "test");
    relay
        .accounts
        .grant_role_as_host(&ctx, l4f_accounts::model::AccountId(info.id), "moderator")
        .await
        .unwrap();
    crate::accounts::revalidate(&state).await;
    let ServerMessage::Account(AccountReply::Info(now)) = c
        .expect("Info", |m| {
            matches!(m, ServerMessage::Account(AccountReply::Info(_)))
        })
        .await
    else {
        unreachable!()
    };
    assert!(now.needs_2fa && now.scopes.is_empty(), "{now:?}");
    // Told once: the next check finds nothing new.
    crate::accounts::revalidate(&state).await;
    c.send(&ClientMessage::Account(AccountRequest::LogKeys {
        accounts: Vec::new(),
    }))
    .await;
    let msg = c.expect("a reply", |m| reply(m).is_some()).await;
    assert!(
        matches!(
            msg,
            ServerMessage::Account(AccountReply::LogKeysFound { .. })
        ),
        "{msg:?}"
    );
}

/// Codes are the account's first second factor: l4f ends its other
/// sessions and gives this one a new token, which the connection keeps.
#[tokio::test]
async fn turning_codes_on_keeps_the_connection_signed_in() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut c, _) = register(&state, "tess").await;
    totp_on(&mut c).await;
    crate::accounts::revalidate(&state).await;
    c.send(&ClientMessage::Account(AccountRequest::LogKeys {
        accounts: Vec::new(),
    }))
    .await;
    let msg = c
        .expect("a reply", |m| {
            matches!(
                m,
                ServerMessage::Account(AccountReply::LogKeysFound { .. })
                    | ServerMessage::Disconnected { .. }
            )
        })
        .await;
    assert!(matches!(msg, ServerMessage::Account(_)), "{msg:?}");
}

/// An account id is as good as the name (any account can look the name
/// up), so it goes where the name goes and no further.
#[tokio::test]
async fn an_account_goes_only_where_the_name_goes() {
    let (state, _db, _log) = relay_with_log().await;
    let (mut out, _) = register(&state, "outsider").await;
    let (mut inside, i) = register(&state, "insider").await;
    let (_joiner, j) = register(&state, "joiner").await;
    let sid = |a: &[u8; 16]| *state.account_sessions.get(a).unwrap();
    let uid = |s: u32| state.sessions.get(&s).unwrap().user_id;
    let (si, sj) = (sid(&i.id), sid(&j.id));
    crate::state::test_support::put_in_channel(&state, 1, &[(uid(si), si)]).await;
    let joined_one =
        |m: &ServerMessage| matches!(m, ServerMessage::UserJoined { user } if user.channel_id == 1);
    for hide in [false, true] {
        state
            .channels
            .write()
            .await
            .get_mut(&1)
            .unwrap()
            .info
            .hide_members = hide;
        broadcast_user_joined(&state, user_info_for(&state, uid(sj), sj, 1)).await;
        let ServerMessage::UserJoined { user } = out.expect("UserJoined", joined_one).await else {
            unreachable!()
        };
        assert_eq!(
            (user.account, user.username.as_str()),
            (None, ""),
            "an outsider gets the count, no account (hide_members={hide})"
        );
        let ServerMessage::UserJoined { user } = inside.expect("UserJoined", joined_one).await
        else {
            unreachable!()
        };
        assert_eq!(
            user.account,
            Some(j.id),
            "a member sees who joined (hide_members={hide})"
        );
    }
}

#[tokio::test]
async fn one_address_holds_only_a_few_of_the_sign_in_slots() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let relay = state.accounts.clone().unwrap();
    let a: IpAddr = "203.0.113.5".parse().unwrap();
    let held: Vec<_> = (0..4)
        .map(|_| relay.pending_slot(a).expect("a share"))
        .collect();
    assert!(
        relay.pending_slot(a).is_none(),
        "that address's share is used up"
    );
    assert!(
        relay.pending_slot("203.0.113.6".parse().unwrap()).is_some(),
        "another address still gets in"
    );
    let v6: Vec<_> = (0..4)
        .map(|i| {
            relay
                .pending_slot(format!("2001:db8::{i}").parse().unwrap())
                .expect("a share")
        })
        .collect();
    assert!(
        relay
            .pending_slot("2001:db8::99".parse().unwrap())
            .is_none(),
        "one /64 is one address"
    );
    drop((held, v6));
    assert!(relay.pending_slot(a).is_some(), "given back when they end");
}

#[tokio::test]
async fn an_open_sign_up_needs_its_puzzle_solved() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let mut c = open_account(&state, "gus", AccountStart::Register { invite: None }).await;
    let Some(ServerMessage::AuthStep(AuthStep::Salt { pow: Some(pow), .. })) = c.next().await
    else {
        panic!("an open relay hands out a proof of work");
    };
    let register = AuthContinue::Register {
        auth_secret: SECRET.to_vec(),
        altcha: String::new(),
        ts: pow.ts,
        vault: vec![reset_slot()],
    };
    c.send(&ClientMessage::AuthContinue(register)).await;
    assert!(
        matches!(c.next().await, Some(ServerMessage::AuthError { reason }) if reason.contains("puzzle"))
    );
}

/// 1.0 (A5): bans with accounts. The account goes wherever it signs in
/// from; the address keeps out guests and accounts without a role, but
/// not someone holding one there (H1-07). The list names no address and
/// lives in the database.
#[tokio::test]
async fn account_bans_follow_the_account_and_roles_pass_address_bans() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (mut gina, _) = register(&state, "gina").await;
    gina.send(&ClientMessage::AdminLogin {
        token: "test-admin-token".into(),
    })
    .await;
    gina.expect("Info", |m| reply(m).is_some()).await;
    let secret = totp_on(&mut gina).await;
    gina.expect("AdminStatus", |m| {
        matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
    })
    .await;
    let (mut hank, hi) = register(&state, "hank").await;
    let hank_uid = state
        .sessions
        .get(&*state.account_sessions.get(&hi.id).unwrap())
        .unwrap()
        .user_id;
    let bans_reply = |m: &ServerMessage| {
        matches!(
            m,
            ServerMessage::AdminBans { .. } | ServerMessage::AdminError { .. }
        )
    };

    gina.send(&ClientMessage::AdminBan {
        user_id: hank_uid,
        reason: "spam".into(),
        duration_secs: 0,
        account: true,
    })
    .await;
    hank.expect(
        "Disconnected",
        |m| matches!(m, ServerMessage::Disconnected { reason } if reason.contains("spam")),
    )
    .await;
    let ServerMessage::AdminBans { bans } = gina.expect("the list", bans_reply).await else {
        panic!("refused")
    };
    assert_eq!(bans.len(), 2, "{bans:?}");
    assert!(
        bans[0].account
            && bans[0].label == "hank"
            && bans[0].by == "gina"
            && bans[0].expires_in_secs.is_none(),
        "accounts first: {bans:?}"
    );
    assert!(!bans[1].account && bans[1].label == "hank", "{bans:?}");
    let gina_sid = *state
        .account_sessions
        .get(
            &state
                .sessions
                .iter()
                .find(|e| e.value().username == "gina")
                .unwrap()
                .account
                .as_ref()
                .unwrap()
                .user
                .id
                .0,
        )
        .unwrap();
    assert!(
        state.sessions.contains_key(&gina_sid),
        "the admin on the same address stays"
    );
    assert!(
        refusal(&state, "lee#1234").await.contains("You are banned"),
        "a guest from the address is kept out"
    );

    // The admin signs in again from the banned address: password, code, in.
    let mut c = open_account(&state, "gina", AccountStart::Login).await;
    c.next().await;
    c.send(&ClientMessage::AuthContinue(AuthContinue::Secret {
        auth_secret: SECRET.to_vec(),
    }))
    .await;
    assert!(matches!(
        c.next().await,
        Some(ServerMessage::AuthStep(AuthStep::NeedTotp))
    ));
    let code = format!(
        "{:06}",
        l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
    );
    c.send(&ClientMessage::AuthContinue(AuthContinue::Totp { code }))
        .await;
    c.expect("Vault", |m| {
        matches!(m, ServerMessage::AuthStep(AuthStep::Vault { .. }))
    })
    .await;
    c.send(&keys(&IDENTITY, false)).await;
    c.expect("Authenticated", |m| {
        matches!(
            m,
            ServerMessage::Authenticated {
                account: Some(_),
                ..
            }
        )
    })
    .await;

    // The address lifted, the account still goes, from anywhere.
    c.send(&ClientMessage::AdminUnban { id: bans[1].id }).await;
    let ServerMessage::AdminBans { bans: left } = c.expect("the list", bans_reply).await else {
        panic!("refused")
    };
    assert_eq!(left.len(), 1);
    let mut again = login(&state, "hank", &IDENTITY, false).await;
    let ServerMessage::AuthError { reason } = again
        .expect("refusal", |m| matches!(m, ServerMessage::AuthError { .. }))
        .await
    else {
        unreachable!()
    };
    assert!(
        reason.contains("This account is banned") && reason.contains("spam"),
        "{reason}"
    );
    drop(connect(&state, "lee#1234", lo).await); // guests are back

    // Kept in the database: a restarted relay reads it back.
    let mut restarted = ServerState::new(
        &ServerConfig::default(),
        ServerSettings::default(),
        Vec::new(),
        "t".into(),
    );
    restarted.accounts = state.accounts.clone();
    crate::bans::load(&restarted).await.unwrap();
    assert!(crate::bans::refusal(
        &restarted,
        "198.51.100.1".parse().unwrap(),
        Some((hi.id, false))
    )
    .is_some());

    // An account that is not here, by name.
    let (ivy, _) = register(&state, "ivy").await;
    drop(ivy);
    c.send(&ClientMessage::AdminBanAccount {
        name: "Ivy".into(),
        reason: "later".into(),
        duration_secs: 3600,
    })
    .await;
    let ServerMessage::AdminBans { bans } = c.expect("the list", bans_reply).await else {
        panic!("refused")
    };
    assert!(
        bans.iter()
            .any(|b| b.account && b.label == "ivy" && b.expires_in_secs.is_some_and(|s| s <= 3600)),
        "{bans:?}"
    );
    c.send(&ClientMessage::AdminBanAccount {
        name: "nobody".into(),
        reason: String::new(),
        duration_secs: 0,
    })
    .await;
    assert!(matches!(
        c.expect("refused", bans_reply).await,
        ServerMessage::AdminError { .. }
    ));
}

/// Moderators moderate people: not admins, not each other, and never with
/// the addresses the ban list is made of.
#[tokio::test]
async fn a_moderator_cannot_touch_admins_or_see_addresses() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut m, mi) = register(&state, "molly").await;
    let (_boss, bi) = register(&state, "boss").await;
    let sid = |a: &[u8; 16]| *state.account_sessions.get(a).unwrap();
    {
        let mut molly = state.sessions.get_mut(&sid(&mi.id)).unwrap();
        molly.is_moderator = true;
        molly.powers = crate::accounts::Powers::of(&[
            "voipc:ban".into(),
            "voipc:channels".into(),
            "voipc:kick".into(),
        ]);
    }
    state.sessions.get_mut(&sid(&bi.id)).unwrap().is_admin = true;
    let boss_uid = state.sessions.get(&sid(&bi.id)).unwrap().user_id;
    let admin_reply = |m: &ServerMessage| {
        matches!(
            m,
            ServerMessage::AdminError { .. } | ServerMessage::AdminBans { .. }
        )
    };
    m.send(&ClientMessage::AdminKick {
        user_id: boss_uid,
        reason: String::new(),
    })
    .await;
    let ServerMessage::AdminError { reason } = m.expect("refused", admin_reply).await else {
        panic!("refused")
    };
    assert!(reason.contains("only an admin"), "{reason}");
    assert!(state.sessions.contains_key(&sid(&bi.id)), "the admin stays");
    m.send(&ClientMessage::AdminListBans).await;
    assert!(
        matches!(
            m.expect("refused", admin_reply).await,
            ServerMessage::AdminError { .. }
        ),
        "no addresses for a moderator"
    );
    // A guest from elsewhere: banned, and the moderator is told no address.
    let mut pat = connect(&state, "pat#1234", "203.0.113.9".parse().unwrap()).await;
    let pat_uid = state
        .sessions
        .iter()
        .find(|e| e.value().username == "pat#1234")
        .map(|e| e.value().user_id)
        .unwrap();
    // Out of a channel, too: the admin stays, the guest goes.
    let uid = |a: &[u8; 16]| state.sessions.get(&sid(a)).unwrap().user_id;
    let pat_sid = pat_uid;
    crate::state::test_support::put_in_channel(
        &state,
        1,
        &[
            (uid(&mi.id), sid(&mi.id)),
            (boss_uid, sid(&bi.id)),
            (pat_uid, pat_sid),
        ],
    )
    .await;
    m.send(&ClientMessage::KickUser {
        channel_id: 1,
        user_id: boss_uid,
    })
    .await;
    let ServerMessage::ChannelError { reason } = m
        .expect("refused", |m| {
            matches!(m, ServerMessage::ChannelError { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("only an admin"), "{reason}");
    assert!(
        state.channels.read().await[&1].members.contains(&boss_uid),
        "the admin stays in the channel"
    );
    m.send(&ClientMessage::KickUser {
        channel_id: 1,
        user_id: pat_uid,
    })
    .await;
    let ServerMessage::Kicked { reason, .. } = pat
        .expect("Kicked", |m| matches!(m, ServerMessage::Kicked { .. }))
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("by a moderator"), "{reason}");
    m.send(&ClientMessage::AdminBan {
        user_id: pat_uid,
        reason: String::new(),
        duration_secs: 60,
        account: true,
    })
    .await;
    m.send(&ClientMessage::AdminListBans).await;
    assert!(
        matches!(
            m.expect("refused", admin_reply).await,
            ServerMessage::AdminError { .. }
        ),
        "the ban came back without the list"
    );
    assert!(crate::bans::refusal(&state, "203.0.113.9".parse().unwrap(), None).is_some());
    drop(pat);
}

/// At boot, a channel that was locked in channels.json while the relay was
/// down keeps none of the members its log had.
#[tokio::test]
async fn a_channel_locked_while_the_relay_was_down_starts_its_log_members_over() {
    let (state, _db, log) = relay_with_log().await;
    let (_alice, _, _) = member(&state, &log, "alice", true).await;
    let relay = state.accounts.clone().unwrap();
    let members = || async {
        crate::accounts::raw(&relay, "SELECT COUNT(*) FROM voipc_members")
            .await
            .unwrap()
    };
    crate::accounts::locked_logs_at_boot(&state).await.unwrap();
    assert_eq!(members().await, 1, "an open channel keeps its members");
    state.channels.write().await.get_mut(&1).unwrap().password = Some(zeroize::Zeroizing::new(
        crate::channels::hash_password("s3cret").unwrap(),
    ));
    crate::accounts::locked_logs_at_boot(&state).await.unwrap();
    assert_eq!(
        members().await,
        0,
        "nobody showed they know the new password"
    );
    let (_bob, _, _) = member(&state, &log, "bob", true).await;
    crate::accounts::locked_logs_at_boot(&state).await.unwrap();
    assert_eq!(
        members().await,
        1,
        "the same password again changes nothing"
    );
}

/// The stored copy of a channel post keeps to the channel's rules, as the
/// post does: a log member could otherwise announce, flood a slow channel,
/// or write from outside it.
#[tokio::test]
async fn a_channels_stored_copy_keeps_to_its_announce_and_slow_mode_rules() {
    use crate::state::{PostStamp, Poster};
    use voipc_crypto::sync::Event;
    let (state, _db, log) = relay_with_log().await;
    let (mut alice, a, mut sa) = member(&state, &log, "alice", true).await;
    let (_bob, _, _) = member(&state, &log, "bob", true).await;
    let not_kept = |events: &[Event]| {
        events.iter().find_map(|e| match e {
            Event::NotKept { reason } => Some(reason.clone()),
            _ => None,
        })
    };
    // Alice manages nothing here: in an announcement channel her copy is
    // refused like her post would be.
    state
        .channels
        .write()
        .await
        .get_mut(&1)
        .unwrap()
        .info
        .announce = true;
    let out = sa.send_channel(&log, say("a1", "not an announcement"), 1, None);
    let reason = not_kept(&pump(&mut alice, &mut sa, out).await).expect("refused");
    assert!(reason.contains("only moderators"), "{reason}");

    // Slow mode: one stored copy per interval, on a clock of its own.
    {
        let mut channels = state.channels.write().await;
        let c = channels.get_mut(&1).unwrap();
        c.info.announce = false;
        c.info.slow_mode_secs = 60;
    }
    let out = sa.send_channel(&log, say("s1", "first"), 2, None);
    let events = pump(&mut alice, &mut sa, out).await;
    assert!(
        events.iter().any(|e| matches!(e, Event::Kept { .. })),
        "{events:?}"
    );
    let out = sa.send_channel(&log, say("s2", "too soon"), 3, None);
    let reason = not_kept(&pump(&mut alice, &mut sa, out).await).expect("held back");
    assert!(reason.contains("slow mode"), "{reason}");
    let sid = *state.account_sessions.get(&a.id).unwrap();
    let uid = state.sessions.get(&sid).unwrap().user_id;
    assert!(
        state.post_rules(sid, uid, 1, PostStamp::Live).await.is_ok(),
        "the post itself is not held back by its copy"
    );
    assert!(state
        .post_rules(sid, uid, 1, PostStamp::Live)
        .await
        .is_err());
    assert!(
        state
            .post_marks
            .contains_key(&(1, Poster::Account(a.id), PostStamp::Live)),
        "an account's clock, which a reconnect does not reset"
    );

    // From outside the channel: refused too.
    state
        .channels
        .write()
        .await
        .get_mut(&1)
        .unwrap()
        .info
        .slow_mode_secs = 0;
    state.leave_text_channel(uid, 1).await;
    let out = sa.send_channel(&log, say("o1", "from outside"), 4, None);
    let reason = not_kept(&pump(&mut alice, &mut sa, out).await).expect("refused");
    assert!(reason.contains("not in that channel"), "{reason}");
}

#[tokio::test]
async fn joiners_read_older_messages_only_from_writers_who_share() {
    let (state, _db, log) = relay_with_log().await;
    let (mut alice, _, mut sa) = member(&state, &log, "alice", true).await;
    let (mut bob, _, mut sb) = member(&state, &log, "bob", false).await;
    let out = sa.send_channel(&log, say("a1", "from alice, before"), 1, None);
    pump(&mut alice, &mut sa, out).await;
    let out = sb.send_channel(&log, say("b1", "from bob, before"), 2, None);
    pump(&mut bob, &mut sb, out).await;

    // Carol joins: both writers are here and answer her.
    let (mut carol, _, mut sc) = member(&state, &log, "carol", true).await;
    let from_alice = pump(&mut alice, &mut sa, Vec::new()).await;
    assert_eq!(
        readers(&from_alice),
        vec![(vec!["carol".to_string()], true)],
        "alice shares what she wrote before"
    );
    let from_bob = pump(&mut bob, &mut sb, Vec::new()).await;
    assert_eq!(
        readers(&from_bob),
        vec![(vec!["carol".to_string()], false)],
        "bob only lets her read what comes next"
    );
    let got = channel_texts(&pump(&mut carol, &mut sc, Vec::new()).await);
    assert_eq!(
        got,
        vec![("alice".to_string(), "from alice, before".to_string())],
        "bob's earlier message stays closed to her"
    );

    // What bob writes now, she reads.
    let out = sb.send_channel(&log, say("b2", "from bob, after"), 3, None);
    pump(&mut bob, &mut sb, out).await;
    let out = sc.enter(&log);
    let got = channel_texts(&pump(&mut carol, &mut sc, out).await);
    assert_eq!(
        got,
        vec![("bob".to_string(), "from bob, after".to_string())]
    );
}

#[tokio::test]
async fn who_leaves_reads_nothing_after_and_every_new_reader_is_named() {
    let (state, _db, log) = relay_with_log().await;
    let (mut alice, _, mut sa) = member(&state, &log, "alice", true).await;
    let (mut bob, b, _) = member(&state, &log, "bob", true).await;
    let out = sa.send_channel(&log, say("m1", "both of us"), 1, None);
    pump(&mut alice, &mut sa, out).await;

    // Bob leaves: alice's next message needs a key he does not have.
    bob.send(&ClientMessage::Account(AccountRequest::LogLeave {
        conv: log.clone(),
    }))
    .await;
    // (Past the news of alice's key for him, which came first.)
    bob.expect("left", |m| {
        matches!(m, ServerMessage::Account(AccountReply::LogLeft { .. }))
    })
    .await;
    let out = sa.send_channel(&log, say("m2", "just me"), 2, None);
    let events = pump(&mut alice, &mut sa, out).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, voipc_crypto::sync::Event::Kept { .. })),
        "kept after a new key: {events:?}"
    );
    let relay = state.accounts.clone().unwrap();
    let bobs = crate::accounts::raw(
            &relay,
            &format!("SELECT COUNT(*) FROM voipc_wraps w WHERE w.recipient = x'{}' AND w.epoch = (SELECT epoch FROM voipc_log ORDER BY seq DESC LIMIT 1)", hex::encode(b.id)),
        )
        .await
        .unwrap();
    assert_eq!(
        bobs, 0,
        "the key of what came after he left is not wrapped to him"
    );
    bob.send(&ClientMessage::Account(AccountRequest::LogFetch {
        conv: log.clone(),
        after: 0,
    }))
    .await;
    bob.expect("refused", |m| matches!(m, ServerMessage::Account(AccountReply::Error { request, .. }) if request == "LogFetch")).await;

    // A relay that makes up a member (eve, never in the channel) cannot
    // slip her in unseen: alice's client names her before her key is used.
    let (_eve, e, eve_signed) = register_with(&state, "eve").await;
    let (mut se, first) =
        voipc_crypto::sync::AccountSync::start(&eve_signed, e.id, Default::default(), true);
    let mut eve = _eve;
    pump(&mut eve, &mut se, first).await; // publishes her log key
    crate::accounts::log::join(&relay, l4f_accounts::model::AccountId(e.id), &log, true)
        .await
        .unwrap();
    let out = sa.send_channel(&log, say("m3", "who reads this?"), 3, None);
    let events = pump(&mut alice, &mut sa, out).await;
    assert!(
        readers(&events)
            .iter()
            .any(|(names, _)| names.contains(&"eve".to_string())),
        "{events:?}"
    );
}

#[tokio::test]
async fn a_new_password_keeps_only_who_is_there_and_a_kick_removes_one() {
    let (state, _db, log) = relay_with_log().await;
    let (mut alice, _, _) = member(&state, &log, "alice", true).await;
    let (mut bob, b, _) = member(&state, &log, "bob", true).await;
    // Bob steps out; the channel gets a password.
    let uid = state
        .sessions
        .get(&*state.account_sessions.get(&b.id).unwrap())
        .unwrap()
        .user_id;
    state
        .channels
        .write()
        .await
        .get_mut(&1)
        .unwrap()
        .members
        .remove(&uid);
    crate::accounts::locked_log(&state, 1).await;
    let fetch = ClientMessage::Account(AccountRequest::LogFetch {
        conv: log.clone(),
        after: 0,
    });
    bob.send(&fetch).await;
    assert!(matches!(
        bob.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
    alice.send(&fetch).await;
    assert!(matches!(
        alice.expect("page", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::LogPage { .. })
    ));
    // Alice is kicked from it.
    let sid = *state
        .account_sessions
        .get(
            &state
                .sessions
                .iter()
                .find(|s| s.username == "alice")
                .unwrap()
                .account
                .as_ref()
                .unwrap()
                .user
                .id
                .0,
        )
        .unwrap();
    crate::accounts::out_of_log(&state, 1, sid).await;
    alice.send(&fetch).await;
    assert!(matches!(
        alice.expect("refused", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::Error { .. })
    ));
}

/// 1.0 (D10): leaving a text channel takes its account out of the log
/// there, the relay doing it; a rejoin keeps it again.
#[tokio::test]
async fn leaving_a_text_channel_ends_its_readership() {
    let (state, _db, log) = relay_with_log().await;
    let (_alice, _, _) = member(&state, &log, "alice", true).await;
    let (mut bob, b, mut sb) = member(&state, &log, "bob", true).await;
    let fetch = ClientMessage::Account(AccountRequest::LogFetch {
        conv: log.clone(),
        after: 0,
    });
    bob.send(&ClientMessage::LeaveChannel { channel_id: 1 })
        .await;
    bob.expect("left", |m| {
        matches!(m, ServerMessage::UserLeft { channel_id: 1, .. })
    })
    .await;
    bob.send(&fetch).await;
    assert!(
        matches!(
            bob.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ),
        "no reader any more"
    );
    // His client forgets what this run knew of it, so a rejoin asks again.
    assert!(
        sb.leave(&log, false).is_empty(),
        "the relay did it: nothing to send"
    );
    into_lounge(&state, &b.id).await;
    let out = sb.enter(&log);
    assert!(
        out.iter()
            .any(|m| matches!(m, ClientMessage::Account(AccountRequest::LogJoin { .. }))),
        "{out:?}"
    );
    pump(&mut bob, &mut sb, out).await;
    bob.send(&fetch).await;
    assert!(matches!(
        bob.expect("page", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::LogPage { .. })
    ));
}

/// 1.0 (A6): a writer deletes what they kept in a conversation; a
/// tombstone tells the readers' devices to drop their copies too.
#[tokio::test]
async fn a_purge_deletes_what_i_wrote_and_a_tombstone_tells_the_readers() {
    let (state, _db, log) = relay_with_log().await;
    let (mut alice, a, mut sa) = member(&state, &log, "alice", true).await;
    let (mut bob, _, mut sb) = member(&state, &log, "bob", true).await;
    for (id, text) in [("m1", "one"), ("m2", "two")] {
        let out = sa.send_channel(&log, say(id, text), 1, None);
        pump(&mut alice, &mut sa, out).await;
    }
    let out = sb.send_channel(&log, say("b1", "bob's"), 2, None);
    pump(&mut bob, &mut sb, out).await;
    let relay = state.accounts.clone().unwrap();
    let mine = format!(
        "SELECT COUNT(*) FROM voipc_log WHERE sender = x'{}'",
        hex::encode(a.id)
    );
    assert_eq!(crate::accounts::raw(&relay, &mine).await.unwrap(), 2);

    alice
        .send(&ClientMessage::Account(AccountRequest::LogPurge {
            conv: Some(log.clone()),
        }))
        .await;
    let ServerMessage::Account(r) = alice
        .expect("purged", |m| {
            matches!(reply(m), Some(AccountReply::LogPurged { .. }))
        })
        .await
    else {
        unreachable!()
    };
    assert!(
        matches!(&r, AccountReply::LogPurged { entries: 2, .. }),
        "{r:?}"
    );
    assert_eq!(
        crate::accounts::raw(&relay, &mine).await.unwrap(),
        0,
        "hers are gone"
    );
    assert_eq!(
        crate::accounts::raw(&relay, "SELECT COUNT(*) FROM voipc_log")
            .await
            .unwrap(),
        1,
        "bob's stays: it is his"
    );
    assert!(sa.on_reply(&r).is_none(), "the front end hears of it too");
    // The tombstone, on a new key (the old one went with the purge).
    let out = sa.send_channel(
        &log,
        voipc_crypto::envelope::purge_envelope("t1", 9_000_000_000_000),
        9,
        None,
    );
    let events = pump(&mut alice, &mut sa, out).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, voipc_crypto::sync::Event::Kept { .. })
                || matches!(e, voipc_crypto::sync::Event::Readers { .. })),
        "{events:?}"
    );
    // Bob's device fetches it: a purge for alice, never past when the relay filed it.
    let out = sb.enter(&log);
    let events = pump(&mut bob, &mut sb, out).await;
    let wire: Vec<_> = events
        .iter()
        .filter_map(|e| e.to_wire())
        .filter(|(n, _)| *n == "stored-purge")
        .collect();
    assert_eq!(wire.len(), 1, "{events:?}");
    assert_eq!(wire[0].1["account"], hex::encode(a.id));
    assert!(
        wire[0].1["before"].as_u64().unwrap() < 9_000_000_000_000,
        "clamped to the relay's time"
    );
}

/// 1.0 (A6): an account deletes itself with its password; its rows go
/// with it and its name is free again. The last admin cannot.
#[tokio::test]
async fn an_account_deletes_itself_and_its_name_is_free() {
    let (state, _db, log) = relay_with_log().await;
    let (mut dora, d, mut sd) = member(&state, &log, "dora", true).await;
    let out = sd.send_channel(&log, say("d1", "bye"), 1, None);
    pump(&mut dora, &mut sd, out).await;
    let relay = state.accounts.clone().unwrap();
    let secret = |pw: &str| {
        voipc_crypto::account::derive(pw, &relay.relay_id, "dora")
            .auth_secret
            .to_vec()
    };
    let delete = |secret: Vec<u8>| {
        ClientMessage::Account(AccountRequest::DeleteAccount {
            secret,
            totp: None,
            recovery_code: None,
        })
    };
    dora.send(&delete(secret("not her password"))).await;
    let msg = dora.expect("refused", |m| reply(m).is_some()).await;
    assert!(
        matches!(&msg, ServerMessage::Account(AccountReply::Error { request, .. }) if request == "DeleteAccount"),
        "{msg:?}"
    );
    dora.send(&delete(secret("correct horse battery"))).await;
    assert!(matches!(
        dora.expect("deleted", |m| reply(m).is_some()).await,
        ServerMessage::Account(AccountReply::AccountDeleted)
    ));
    dora.expect("closed", |m| {
        matches!(m, ServerMessage::Disconnected { .. })
    })
    .await;
    let id = hex::encode(d.id);
    for table in [
        "voipc_identity WHERE account",
        "voipc_logkeys WHERE account",
        "voipc_members WHERE account",
        "voipc_log WHERE sender",
        "voipc_wraps WHERE owner",
    ] {
        assert_eq!(
            crate::accounts::raw(&relay, &format!("SELECT COUNT(*) FROM {table} = x'{id}'"))
                .await
                .unwrap(),
            0,
            "{table}"
        );
    }
    let (_again, d2, _) = register_with(&state, "dora").await;
    assert_ne!(d2.id, d.id, "the name is free: a new account under it");

    // The only admin stays.
    let (mut gina, _) = register(&state, "gina").await;
    gina.send(&ClientMessage::AdminLogin {
        token: "test-admin-token".into(),
    })
    .await;
    gina.expect("Info", |m| reply(m).is_some()).await;
    let secret = totp_on(&mut gina).await;
    gina.expect("AdminStatus", |m| {
        matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
    })
    .await;
    let code = format!(
        "{:06}",
        l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
    );
    gina.send(&ClientMessage::Account(AccountRequest::DeleteAccount {
        secret: SECRET.to_vec(),
        totp: Some(code),
        recovery_code: None,
    }))
    .await;
    let ServerMessage::Account(AccountReply::Error { reason, .. }) =
        gina.expect("refused", |m| reply(m).is_some()).await
    else {
        panic!("deleted the last admin")
    };
    assert!(reason.contains("last admin"), "{reason}");
}

#[tokio::test]
async fn the_sweep_drops_keys_nothing_uses_any_more() {
    let (state, _db, log) = relay_with_log().await;
    let (mut alice, a, mut sa) = member(&state, &log, "alice", true).await;
    let out = sa.send_channel(&log, say("m1", "kept"), 1, None);
    pump(&mut alice, &mut sa, out).await;
    let relay = state.accounts.clone().unwrap();
    let me = hex::encode(a.id);
    // A key minted long ago that no entry uses, beside one that is used.
    crate::accounts::raw(&relay, &format!("INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ('{log}', x'{me}', 99, x'{me}', x'00', 0)")).await.unwrap();
    crate::accounts::raw(&relay, "UPDATE voipc_wraps SET created_at = 0")
        .await
        .unwrap();
    crate::accounts::log::sweep(&relay).await.unwrap();
    let count = |sql: String| {
        let relay = relay.clone();
        async move { crate::accounts::raw(&relay, &sql).await.unwrap() }
    };
    assert_eq!(
        count("SELECT COUNT(*) FROM voipc_wraps WHERE epoch = 99".into()).await,
        0,
        "the unused key went"
    );
    assert!(
        count("SELECT COUNT(*) FROM voipc_wraps".into()).await > 0,
        "the used one stayed"
    );
    assert_eq!(count("SELECT COUNT(*) FROM voipc_log".into()).await, 1);
}

/// An accounts database as 0.12.0 left it (tests/fixtures/0.12.0, written
/// once by 0.12.0's own code, see its README): this version opens it with
/// its key file and migrates it, bob signs in with his password, and he
/// still reads the DM alice kept for him then.
#[tokio::test]
async fn a_0_12_accounts_database_opens_signs_in_and_keeps_its_messages() {
    use voipc_crypto::log::{open_entry, unwrap, LogKey};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/0.12.0");
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("accounts.json")).unwrap()).unwrap();
    let tmp = std::env::temp_dir().join(format!(
        "voipc-upgrade-{}",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    for f in ["voipc.db", "accounts.key"] {
        std::fs::copy(dir.join(f), tmp.join(f)).unwrap();
    }
    let mut config = ServerConfig::default();
    config.accounts.mode = AccountsMode::Optional;
    config.accounts.registration = RegistrationMode::Open;
    config.accounts.database = format!("sqlite://{}", tmp.join("voipc.db").display());
    config.accounts.key_file = tmp.join("accounts.key").display().to_string();
    let relay = crate::accounts::Relay::open(&config.accounts)
        .await
        .unwrap();
    assert_eq!(hex::encode(relay.relay_id), meta["relay_id"]);
    let mut state = ServerState::new(
        &config,
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    );
    state.accounts = Some(Arc::new(relay));
    let state = Arc::new(state);

    let (mut bob, b, _) = sign_in_password(&state, "bob").await;
    assert_eq!(hex::encode(b.id), meta["bob"]);
    let conv = meta["conv"].as_str().unwrap().to_string();
    bob.send(&ClientMessage::Account(AccountRequest::WrapsFetch {
        conv: conv.clone(),
    }))
    .await;
    let ServerMessage::Account(AccountReply::Wraps { wraps, .. }) =
        bob.expect("wraps", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    let bob_lk =
        LogKey::from_bytes(&hex::decode(meta["bob_logkey"].as_str().unwrap()).unwrap()).unwrap();
    let key = unwrap(
        &bob_lk,
        &wraps[0].wrapped,
        &conv,
        &wraps[0].owner,
        wraps[0].epoch,
        &b.id,
    )
    .unwrap();
    bob.send(&ClientMessage::Account(AccountRequest::LogFetch {
        conv: conv.clone(),
        after: 0,
    }))
    .await;
    let ServerMessage::Account(AccountReply::LogPage { entries, .. }) =
        bob.expect("page", |m| reply(m).is_some()).await
    else {
        panic!()
    };
    let alice_lk = hex::decode(meta["alice_logkey_public"].as_str().unwrap()).unwrap();
    let (envelope, _) = open_entry(
        &key,
        &conv,
        &entries[0].sender,
        entries[0].epoch,
        &alice_lk,
        &entries[0].ct,
    )
    .unwrap();
    assert_eq!(
        voipc_crypto::envelope::open_envelope(&envelope).text,
        meta["text"]
    );
    drop(bob);
    drop(state);
    let _ = std::fs::remove_dir_all(&tmp);
}

// ── Files (protocol v13) ─────────────────────────────────────────────

use crate::files::test_support::{blob, path_of, state_with_files};

const HERE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// One whole-blob `PUT` through the HTTP handler both carriers share.
async fn put_blob(state: &Arc<ServerState>, hash: &[u8; 32], ticket: &str, bytes: &[u8]) -> u16 {
    let target = format!("{}?offset=0", path_of(hash));
    let auth = format!("Bearer {ticket}");
    let body = Bytes::copy_from_slice(bytes);
    crate::files::http(state, HERE, "PUT", &target, Some(&auth), None, body)
        .await
        .status
}

async fn get_blob(state: &Arc<ServerState>, hash: &[u8; 32], ticket: &str) -> (u16, Bytes) {
    let auth = format!("Bearer {ticket}");
    let reply = crate::files::http(
        state,
        HERE,
        "GET",
        &path_of(hash),
        Some(&auth),
        None,
        Bytes::new(),
    )
    .await;
    (reply.status, reply.body)
}

async fn upload_ready(client: &mut Client) -> String {
    match client
        .expect("FileUploadReady", |m| {
            matches!(m, ServerMessage::FileUploadReady { .. })
        })
        .await
    {
        ServerMessage::FileUploadReady { ticket, .. } => ticket,
        _ => unreachable!(),
    }
}

async fn ready(client: &mut Client) -> (String, u64) {
    match client
        .expect("FileReady", |m| {
            matches!(m, ServerMessage::FileReady { .. })
        })
        .await
    {
        ServerMessage::FileReady { ticket, size, .. } => (ticket, size),
        _ => unreachable!(),
    }
}

async fn refused(client: &mut Client) -> String {
    match client
        .expect("FileRefused", |m| {
            matches!(m, ServerMessage::FileRefused { .. })
        })
        .await
    {
        ServerMessage::FileRefused { reason, .. } => reason,
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn a_relay_with_files_says_so_and_one_without_refuses_them() {
    let (state, _dir) = state_with_files(|c| c.max_size_mb = 3);
    let mut alice = open(&state, "alice", HERE).await;
    let ServerMessage::Authenticated { files, .. } = alice
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert_eq!(files.map(|f| f.max_bytes), Some(3 * 1024 * 1024));

    let state = admin_state();
    let mut bob = open(&state, "bob", HERE).await;
    let ServerMessage::Authenticated { files, .. } = bob
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(files.is_none());
    let (_, hash) = blob(10, 1);
    bob.send(&ClientMessage::FileFetch {
        conv: FileConv::Channel(1),
        hash,
    })
    .await;
    assert!(refused(&mut bob).await.contains("keeps no files"));
}

#[tokio::test]
async fn a_file_posted_in_a_channel_reaches_its_members_only() {
    let (state, _dir) = state_with_files(|_| {});
    let mut alice = connect(&state, "alice", HERE).await;
    let mut bob = connect(&state, "bob", HERE).await;
    let mut carol = connect(&state, "carol", HERE).await;
    let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
    let conv = FileConv::Channel(channel);
    let (bytes, hash) = blob(3000, 2);

    // Carol is not in it: she may neither post nor fetch there
    carol
        .send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
    refused(&mut carol).await;
    alice
        .send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
    let ticket = upload_ready(&mut alice).await;
    assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);
    alice
        .expect("FileStored", |m| {
            matches!(m, ServerMessage::FileStored { .. })
        })
        .await;

    bob.send(&ClientMessage::FileFetch { conv, hash }).await;
    let (ticket, size) = ready(&mut bob).await;
    assert_eq!(size, 3000);
    assert_eq!(
        get_blob(&state, &hash, &ticket).await,
        (206, Bytes::from(bytes))
    );
    carol.send(&ClientMessage::FileFetch { conv, hash }).await;
    refused(&mut carol).await;
    assert_eq!(get_blob(&state, &hash, "not-a-ticket").await.0, 401);
}

/// Protocol 14: a member who is not an admin cannot add one; an admin adds
/// one and uploads its file, every member gets the new list, and fetches
/// the file with the bearer its `Authenticated` carried.
#[tokio::test]
async fn an_admin_adds_an_emote_and_every_member_gets_it() {
    use sha2::{Digest, Sha256};
    use voipc_protocol::conv::hex;
    let dir = std::env::temp_dir().join(format!(
        "voipc-emotes-tcp-{}",
        hex(&rand::random::<[u8; 8]>())
    ));
    let mut s = ServerState::new(
        &ServerConfig::default(),
        ServerSettings::default(),
        Vec::new(),
        "test-admin-token".into(),
    );
    let cfg = crate::config::EmotesConfig {
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    s.emotes = Some(Arc::new(crate::emotes::EmoteStore::open(&cfg).unwrap()));
    let state = Arc::new(s);
    let mut admin = connect(&state, "admin", HERE).await;
    let mut bob = open(&state, "bob", HERE).await;
    let ServerMessage::Authenticated {
        emotes: Some(access),
        ..
    } = bob
        .expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { .. })
        })
        .await
    else {
        panic!("no emote access in Authenticated")
    };
    bob.expect(
        "the list on join",
        |m| matches!(m, ServerMessage::EmoteList { emotes, .. } if emotes.is_empty()),
    )
    .await;
    let png = b"\x89PNG\r\n\x1a\nthe relay never decodes this".to_vec();
    let emote = Emote {
        name: "pog".into(),
        hash: Sha256::digest(&png).into(),
        sticker: false,
        pack: String::new(),
        len: png.len() as u32,
        w: 64,
        h: 32,
    };
    let path = format!("/e/v1/{}", hex(&emote.hash));

    bob.send(&ClientMessage::EmoteAdd {
        emote: emote.clone(),
    })
    .await;
    bob.expect("EmoteError", |m| {
        matches!(m, ServerMessage::EmoteError { .. })
    })
    .await;

    admin
        .send(&ClientMessage::AdminLogin {
            token: "test-admin-token".into(),
        })
        .await;
    admin
        .expect("AdminStatus", |m| {
            matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
        })
        .await;
    admin
        .send(&ClientMessage::EmoteAdd {
            emote: emote.clone(),
        })
        .await;
    let ServerMessage::EmoteTicket { ticket, .. } = admin
        .expect("EmoteTicket", |m| {
            matches!(m, ServerMessage::EmoteTicket { .. })
        })
        .await
    else {
        unreachable!()
    };
    let auth = format!("Bearer {ticket}");
    let put = crate::files::http(
        &state,
        HERE,
        "PUT",
        &path,
        Some(&auth),
        None,
        Bytes::from(png.clone()),
    )
    .await;
    assert_eq!(put.status, 201);
    let want = vec![emote.clone()];
    bob.expect(
        "the new list",
        |m| matches!(m, ServerMessage::EmoteList { emotes, .. } if *emotes == want),
    )
    .await;
    let auth = format!("Bearer {}", access.token.0);
    let got = crate::files::http(&state, HERE, "GET", &path, Some(&auth), None, Bytes::new()).await;
    assert_eq!((got.status, &got.body[..]), (200, &png[..]));

    // A rename: the same file under a new name, no upload
    let renamed = Emote {
        name: "poggers".into(),
        ..emote.clone()
    };
    admin
        .send(&ClientMessage::EmoteRename {
            from: "pog".into(),
            to: "poggers".into(),
        })
        .await;
    let want = vec![renamed.clone()];
    bob.expect(
        "the renamed list",
        |m| matches!(m, ServerMessage::EmoteList { emotes, .. } if *emotes == want),
    )
    .await;

    // v15: many at once, one list each
    admin
        .send(&ClientMessage::EmoteMove {
            names: vec!["poggers".into()],
            pack: Some("Cats".into()),
            sticker: Some(true),
        })
        .await;
    let want = vec![Emote {
        pack: "Cats".into(),
        sticker: true,
        ..renamed
    }];
    bob.expect(
        "the moved list",
        |m| matches!(m, ServerMessage::EmoteList { emotes, .. } if *emotes == want),
    )
    .await;
    admin
        .send(&ClientMessage::EmoteRemove {
            names: vec!["poggers".into(), "nope".into()],
        })
        .await;
    admin
        .expect(
            "the unknown name, said",
            |m| matches!(m, ServerMessage::EmoteError { reason, .. } if reason.contains(":nope:")),
        )
        .await;
    bob.expect(
        "the emptied list",
        |m| matches!(m, ServerMessage::EmoteList { emotes, .. } if emotes.is_empty()),
    )
    .await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_file_in_a_direct_conversation_is_for_its_two_parties() {
    let (state, _dir) = state_with_files(|_| {});
    let mut alice = connect(&state, "alice", HERE).await;
    let mut bob = connect(&state, "bob", HERE).await;
    let mut carol = connect(&state, "carol", HERE).await;
    let id = |name: &str| *state.username_to_session.get(name).unwrap();
    let (alice_id, bob_id) = (id("alice"), id("bob"));
    let (bytes, hash) = blob(3000, 3);

    alice
        .send(&ClientMessage::FileUpload {
            conv: FileConv::Direct(bob_id),
            size: 3000,
            hash,
        })
        .await;
    let ticket = upload_ready(&mut alice).await;
    assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);

    // Bob names the same conversation from his end
    bob.send(&ClientMessage::FileFetch {
        conv: FileConv::Direct(alice_id),
        hash,
    })
    .await;
    ready(&mut bob).await;
    // Carol's conversation with Alice is another one: the file is sought
    // there, and Alice's app answers only for a message there that names it
    carol
        .send(&ClientMessage::FileFetch {
            conv: FileConv::Direct(alice_id),
            hash,
        })
        .await;
    carol
        .expect("FileSeeking", |m| {
            matches!(m, ServerMessage::FileSeeking { .. })
        })
        .await;
    let carol_id = id("carol");
    alice
            .expect("FileWanted in carol's conversation", |m| {
                matches!(m, ServerMessage::FileWanted { conv: FileConv::Direct(who), .. } if *who == carol_id)
            })
            .await;
    // Nobody has a conversation with themselves
    alice
        .send(&ClientMessage::FileFetch {
            conv: FileConv::Direct(alice_id),
            hash,
        })
        .await;
    refused(&mut alice).await;
}

/// The blob has gone: the channel's other members are asked, without a
/// word about who asked; the one who has it uploads it again, and the
/// asker is served.
#[tokio::test]
async fn a_member_who_has_the_file_brings_it_back() {
    let (state, _dir) = state_with_files(|_| {});
    let mut alice = connect(&state, "alice", HERE).await;
    let mut bob = connect(&state, "bob", HERE).await;
    let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
    let conv = FileConv::Channel(channel);
    let (bytes, hash) = blob(3000, 4);
    alice
        .send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
    let ticket = upload_ready(&mut alice).await;
    put_blob(&state, &hash, &ticket, &bytes).await;
    alice
        .expect("FileStored", |m| {
            matches!(m, ServerMessage::FileStored { .. })
        })
        .await;
    // Long enough later for the blob to have gone
    let store = state.files.clone().unwrap();
    crate::files::deliver(
        &state,
        store.sweep(Instant::now() + Duration::from_secs(25 * 3600)),
    )
    .await;

    bob.send(&ClientMessage::FileFetch { conv, hash }).await;
    bob.expect("FileSeeking", |m| {
        matches!(m, ServerMessage::FileSeeking { .. })
    })
    .await;
    let wanted = alice
        .expect("FileWanted", |m| {
            matches!(m, ServerMessage::FileWanted { .. })
        })
        .await;
    assert!(matches!(
        wanted,
        ServerMessage::FileWanted { conv: FileConv::Channel(c), hash: h } if c == channel && h == hash
    ));
    alice
        .send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
    let ticket = upload_ready(&mut alice).await;
    assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);
    let (ticket, _) = ready(&mut bob).await;
    assert_eq!(get_blob(&state, &hash, &ticket).await.1, Bytes::from(bytes));
}

/// An uploader who leaves hands the upload to the next member with it.
#[tokio::test]
async fn an_upload_left_behind_passes_to_the_next_member() {
    let (state, _dir) = state_with_files(|_| {});
    let mut alice = connect(&state, "alice", HERE).await;
    let mut bob = connect(&state, "bob", HERE).await;
    let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
    let conv = FileConv::Channel(channel);
    let (bytes, hash) = blob(3000, 5);
    alice
        .send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
    upload_ready(&mut alice).await;
    bob.send(&ClientMessage::FileUpload {
        conv,
        size: 3000,
        hash,
    })
    .await;
    // A session's messages are handled in order: past the Pong, Bob is
    // queued behind Alice. Then Alice goes.
    bob.send(&ClientMessage::Ping { timestamp: 7 }).await;
    bob.expect("Pong", |m| {
        matches!(m, ServerMessage::Pong { timestamp: 7 })
    })
    .await;
    drop(alice);
    let ticket = upload_ready(&mut bob).await;
    assert_eq!(put_blob(&state, &hash, &ticket, &bytes).await, 201);
    bob.expect("FileStored", |m| {
        matches!(m, ServerMessage::FileStored { .. })
    })
    .await;
}

#[tokio::test]
async fn a_cancel_spends_the_ticket() {
    let (state, _dir) = state_with_files(|_| {});
    let mut alice = connect(&state, "alice", HERE).await;
    let mut bob = connect(&state, "bob", HERE).await;
    let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
    let conv = FileConv::Channel(channel);
    let (bytes, hash) = blob(3000, 6);
    alice
        .send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
    let ticket = upload_ready(&mut alice).await;
    alice.send(&ClientMessage::FileCancel { hash }).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while put_blob(&state, &hash, &ticket, &bytes).await != 401 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the ticket is spent");
}

/// A kept conversation is between two accounts that exist: a made-up
/// one is refused, and so is a guest naming one.
#[tokio::test]
async fn a_file_for_an_away_account_needs_a_real_account() {
    let dir = crate::files::test_support::TempDir::new();
    let files = crate::files::test_support::config_in(&dir);
    let (state, _db) = relay_state_then(AccountsMode::Optional, RegistrationMode::Open, |s| {
        s.files = Some(Arc::new(crate::files::FileStore::open(&files).unwrap()));
    })
    .await;
    let (mut alice, _) = register(&state, "alice").await;
    let (away, bob) = register(&state, "bob").await;
    drop(away);
    let (_, hash) = blob(3000, 8);
    alice
        .send(&ClientMessage::FileUpload {
            conv: FileConv::Account([0x42; 16]),
            size: 3000,
            hash,
        })
        .await;
    refused(&mut alice).await;
    alice
        .send(&ClientMessage::FileUpload {
            conv: FileConv::Account(bob.id),
            size: 3000,
            hash,
        })
        .await;
    upload_ready(&mut alice).await;

    let mut guest = connect(&state, "dave#1234", HERE).await;
    guest
        .send(&ClientMessage::FileFetch {
            conv: FileConv::Account(bob.id),
            hash,
        })
        .await;
    refused(&mut guest).await;
}

/// Asking for a blob that has gone reaches the channel's other members,
/// and nobody outside it.
#[tokio::test]
async fn only_members_are_asked_for_a_file() {
    let (state, _dir) = state_with_files(|_| {});
    let mut alice = connect(&state, "alice", HERE).await;
    let mut bob = connect(&state, "bob", HERE).await;
    let mut carol = connect(&state, "carol", HERE).await;
    let channel = text_channel_with_two(&mut alice, &mut bob, "files").await;
    let conv = FileConv::Channel(channel);
    let (bytes, hash) = blob(3000, 9);
    alice
        .send(&ClientMessage::FileUpload {
            conv,
            size: 3000,
            hash,
        })
        .await;
    let ticket = upload_ready(&mut alice).await;
    put_blob(&state, &hash, &ticket, &bytes).await;
    let store = state.files.clone().unwrap();
    crate::files::deliver(
        &state,
        store.sweep(Instant::now() + Duration::from_secs(25 * 3600)),
    )
    .await;
    bob.send(&ClientMessage::FileFetch { conv, hash }).await;
    bob.expect("FileSeeking", |m| {
        matches!(m, ServerMessage::FileSeeking { .. })
    })
    .await;
    alice
        .expect("FileWanted", |m| {
            matches!(m, ServerMessage::FileWanted { .. })
        })
        .await;
    // Carol's connection is in order: past her Pong, any FileWanted for
    // her would have arrived
    carol.send(&ClientMessage::Ping { timestamp: 9 }).await;
    loop {
        match carol.next().await {
            Some(ServerMessage::Pong { timestamp: 9 }) => break,
            Some(ServerMessage::FileWanted { .. }) => panic!("a non-member was asked"),
            Some(_) => {}
            None => panic!("carol's connection closed"),
        }
    }
}

// ── Groups, gates and the admin pages (1.7) ──────────────────────────────

use l4f_accounts::model::AccountId;
use voipc_protocol::messages::{AdminOp, AdminReply};

/// A group of the relay's, made from the shell.
async fn group(state: &ServerState, name: &str, badge: Option<&str>, scopes: &[&str]) {
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    state
        .accounts
        .as_ref()
        .unwrap()
        .store()
        .create_role_with_scopes(name, "", badge, &scopes)
        .await
        .unwrap();
}

/// Gives (or takes) `group` from the shell, and has the relay see it now.
async fn give(state: &Arc<ServerState>, account: [u8; 16], group: &str, on: bool) {
    let relay = state.accounts.clone().unwrap();
    let ctx = relay.ctx(IpAddr::V4(Ipv4Addr::LOCALHOST), "test");
    let id = AccountId(account);
    if on {
        relay
            .accounts
            .grant_role_as_host(&ctx, id, group)
            .await
            .unwrap();
    } else {
        relay
            .accounts
            .revoke_role_as_host(&ctx, id, group)
            .await
            .unwrap();
    }
    let sid = *state.account_sessions.get(&account).unwrap();
    crate::accounts::refresh(state, &relay, sid, id)
        .await
        .unwrap();
}

/// An admin with codes on, and its authenticator's secret.
async fn admin_account(state: &Arc<ServerState>, name: &str) -> (Client, AccountInfo, Vec<u8>) {
    let (mut c, info) = register(state, name).await;
    let relay = state.accounts.clone().unwrap();
    let ctx = relay.ctx(IpAddr::V4(Ipv4Addr::LOCALHOST), "test");
    relay
        .accounts
        .grant_role_as_host(&ctx, AccountId(info.id), "admin")
        .await
        .unwrap();
    let secret = totp_on(&mut c).await;
    c.expect("AdminStatus", |m| {
        matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
    })
    .await;
    (c, info, secret)
}

fn admin_op(op: AdminOp, code: Option<String>) -> ClientMessage {
    ClientMessage::Account(AccountRequest::Admin { op, code })
}

fn admin_answer(m: &ServerMessage) -> bool {
    match m {
        ServerMessage::Account(AccountReply::Admin(_)) => true,
        ServerMessage::Account(AccountReply::Error { request, .. }) => request == "Admin",
        _ => false,
    }
}

async fn create(c: &mut Client, name: &str, text: bool) -> ChannelId {
    c.send(&ClientMessage::CreateChannel {
        name: name.into(),
        password: None,
        proximity: ProximityMode::Off,
        anonymous: false,
        text,
    })
    .await;
    let ServerMessage::ChannelCreated { channel } = c
        .expect(
            "ChannelCreated",
            |m| matches!(m, ServerMessage::ChannelCreated { channel } if channel.name == name),
        )
        .await
    else {
        unreachable!()
    };
    channel.channel_id
}

#[tokio::test]
async fn a_gate_hides_its_channel_and_lets_only_its_speakers_speak() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    group(&state, "crew", None, &[]).await;
    group(&state, "leads", Some("lead"), &[]).await;
    let (mut ann, _, _) = admin_account(&state, "ann").await;
    let (mut bob, bi) = register(&state, "bob").await;
    let (mut cat, _) = register(&state, "cat").await;
    let mut dan = connect(&state, "dan#1234", "203.0.113.4".parse().unwrap()).await;
    give(&state, bi.id, "crew", true).await;
    let deck = create(&mut ann, "deck", false).await;

    ann.send(&admin_op(
        AdminOp::GateSet {
            channel_id: deck,
            gate: ChannelGate {
                groups: vec!["crew".into()],
                speakers: vec!["leads".into()],
            },
        },
        None,
    ))
    .await;
    let r = ann.expect("Gate", admin_answer).await;
    assert!(
        matches!(&r, ServerMessage::Account(AccountReply::Admin(AdminReply::Gate { gate, groups, .. }))
            if gate.groups == ["crew"] && groups.iter().any(|g| g == "leads")),
        "{r:?}"
    );
    // Outside the crew it goes, for an account and a guest alike
    let gone = |m: &ServerMessage| matches!(m, ServerMessage::ChannelDeleted { channel_id } if *channel_id == deck);
    cat.expect("ChannelDeleted", gone).await;
    dan.expect("ChannelDeleted", gone).await;
    cat.send(&ClientMessage::JoinChannel {
        channel_id: deck,
        password: None,
    })
    .await;
    let ServerMessage::ChannelError { reason } = cat
        .expect("refused", |m| {
            matches!(m, ServerMessage::ChannelError { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(reason.contains("does not exist"), "{reason}");
    cat.send(&ClientMessage::RequestChannelUsers { channel_id: deck })
        .await;
    cat.expect("an empty preview", |m| {
        matches!(m, ServerMessage::ChannelUsers { channel_id, users } if *channel_id == deck && users.is_empty())
    })
    .await;
    cat.send(&ClientMessage::RequestChannelList).await;
    let ServerMessage::ChannelList { channels } = cat
        .expect("ChannelList", |m| {
            matches!(m, ServerMessage::ChannelList { .. })
        })
        .await
    else {
        unreachable!()
    };
    assert!(channels.iter().all(|c| c.channel_id != deck));

    // In the crew: in, but only to listen
    bob.send(&ClientMessage::JoinChannel {
        channel_id: deck,
        password: None,
    })
    .await;
    bob.expect(
        "ListenOnly",
        |m| matches!(m, ServerMessage::ListenOnly { channel_id, on: true } if *channel_id == deck),
    )
    .await;
    ann.expect(
        "UserJoined",
        |m| matches!(m, ServerMessage::UserJoined { user } if user.channel_id == deck),
    )
    .await;
    // An outsider is not even told the count moved
    cat.send(&ClientMessage::Ping { timestamp: 99 }).await;
    loop {
        match cat.next().await.unwrap() {
            ServerMessage::Pong { timestamp: 99 } => break,
            ServerMessage::UserJoined { user } => assert_ne!(user.channel_id, deck),
            _ => {}
        }
    }
    let bob_sid = *state.account_sessions.get(&bi.id).unwrap();
    let bob_uid = state.sessions.get(&bob_sid).unwrap().user_id;
    let err = state
        .post_rules(bob_sid, bob_uid, deck, crate::state::PostStamp::Kept)
        .await
        .unwrap_err();
    assert!(err.contains("only read"), "{err}");

    // A lead speaks, and the room sees the badge
    give(&state, bi.id, "leads", true).await;
    bob.expect(
        "ListenOnly off",
        |m| matches!(m, ServerMessage::ListenOnly { channel_id, on: false } if *channel_id == deck),
    )
    .await;
    assert!(state
        .post_rules(bob_sid, bob_uid, deck, crate::state::PostStamp::Live)
        .await
        .is_ok());
    ann.expect(
        "UserUpdated",
        |m| matches!(m, ServerMessage::UserUpdated { user } if user.badges == ["lead"]),
    )
    .await;

    // Out of the crew, out of the channel, and still signed in
    give(&state, bi.id, "crew", false).await;
    bob.expect("ChannelDeleted", gone).await;
    assert!(!state.channels.read().await[&deck]
        .members
        .contains(&bob_uid));
    assert!(
        state.sessions.contains_key(&bob_sid),
        "a group without privileges signs nobody out"
    );
}

#[tokio::test]
async fn admin_steps_that_hand_out_power_ask_for_a_fresh_code() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    let (mut ann, _, secret) = admin_account(&state, "ann").await;
    let (mut bob, bi) = register(&state, "bob").await;
    let (mut cat, _) = register(&state, "cat").await;
    let save = |name: &str, badge: &str, scopes: &[&str]| AdminOp::GroupSave {
        create: true,
        group: GroupInfo {
            name: name.into(),
            description: String::new(),
            badge: badge.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            builtin: false,
        },
    };
    let error = |m: &ServerMessage| matches!(m, ServerMessage::Account(AccountReply::Error { .. }));

    ann.send(&admin_op(save("vip", "VIP", &["voipc:kick"]), None))
        .await;
    assert!(matches!(
        ann.expect("StepUp", admin_answer).await,
        ServerMessage::Account(AccountReply::Admin(AdminReply::StepUp))
    ));
    ann.send(&admin_op(
        save("vip", "VIP", &["voipc:kick"]),
        Some("000000".into()),
    ))
    .await;
    assert!(error(&ann.expect("a wrong code", admin_answer).await));
    let code = format!(
        "{:06}",
        l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
    );
    ann.send(&admin_op(save("vip", "VIP", &["voipc:kick"]), Some(code)))
        .await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::Groups { groups })) =
        ann.expect("Groups", admin_answer).await
    else {
        panic!("the group is made")
    };
    assert!(groups
        .iter()
        .any(|g| g.name == "vip" && g.scopes == ["voipc:kick"] && g.badge == "VIP"));
    // The code holds for ten minutes
    ann.send(&admin_op(save("fans", "fan", &[]), None)).await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::Groups { groups })) =
        ann.expect("Groups", admin_answer).await
    else {
        panic!("no second code")
    };
    assert!(groups.iter().any(|g| g.name == "fans"));

    ann.send(&admin_op(
        AdminOp::Users {
            search: "bo".into(),
            offset: 0,
        },
        None,
    ))
    .await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::Users { users, total, .. })) =
        ann.expect("Users", admin_answer).await
    else {
        panic!("Users")
    };
    assert_eq!((total, users[0].name.as_str()), (1, "bob"));

    // A group without privileges counts at once, badge and all
    ann.send(&admin_op(
        AdminOp::Grant {
            id: bi.id,
            group: "fans".into(),
        },
        None,
    ))
    .await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::User { groups, .. })) =
        ann.expect("User", admin_answer).await
    else {
        panic!("User")
    };
    assert!(groups.contains(&"fans".to_string()));
    let bob_sid = *state.account_sessions.get(&bi.id).unwrap();
    let badges = |state: &ServerState| {
        state
            .sessions
            .get(&bob_sid)
            .unwrap()
            .account
            .as_ref()
            .unwrap()
            .standing
            .badges
            .clone()
    };
    assert_eq!(badges(&state), ["fan"]);
    // One with privileges waits for codes, and does not show yet
    ann.send(&admin_op(
        AdminOp::Grant {
            id: bi.id,
            group: "vip".into(),
        },
        None,
    ))
    .await;
    ann.expect("User", admin_answer).await;
    bob.expect(
        "Info",
        |m| matches!(m, ServerMessage::Account(AccountReply::Info(i)) if i.needs_2fa),
    )
    .await;
    assert_eq!(badges(&state), ["fan"]);
    ann.send(&admin_op(AdminOp::User { id: bi.id }, None)).await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::User { audit, .. })) =
        ann.expect("User", admin_answer).await
    else {
        panic!("User")
    };
    assert!(
        audit
            .iter()
            .any(|e| e.event == "role_grant" && e.actor.as_deref() == Some("ann")),
        "{audit:?}"
    );
    ann.send(&admin_op(
        AdminOp::GroupMembers {
            name: "fans".into(),
            offset: 0,
        },
        None,
    ))
    .await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::Members { users, total, .. })) =
        ann.expect("Members", admin_answer).await
    else {
        panic!("Members")
    };
    assert_eq!((total, users[0].name.as_str()), (1, "bob"));

    // A group a gate names stays
    let club = create(&mut ann, "club", false).await;
    ann.send(&admin_op(
        AdminOp::GateSet {
            channel_id: club,
            gate: ChannelGate {
                groups: vec!["fans".into()],
                speakers: vec![],
            },
        },
        None,
    ))
    .await;
    ann.expect("Gate", admin_answer).await;
    ann.send(&admin_op(
        AdminOp::GroupDelete {
            name: "fans".into(),
        },
        None,
    ))
    .await;
    let ServerMessage::Account(AccountReply::Error { reason, .. }) =
        ann.expect("refused", admin_answer).await
    else {
        panic!("refused")
    };
    assert!(reason.contains("Change that channel first"), "{reason}");

    // Taking away privileges signs the account out
    ann.send(&admin_op(
        AdminOp::Revoke {
            id: bi.id,
            group: "vip".into(),
        },
        None,
    ))
    .await;
    bob.expect("Disconnected", |m| {
        matches!(m, ServerMessage::Disconnected { .. })
    })
    .await;
    ann.expect("User", admin_answer).await;

    // Nobody else reads the user list
    cat.send(&admin_op(
        AdminOp::Users {
            search: String::new(),
            offset: 0,
        },
        None,
    ))
    .await;
    assert!(error(&cat.expect("refused", admin_answer).await));

    // Invites: made, listed, revoked
    ann.send(&admin_op(
        AdminOp::InviteNew {
            name: None,
            days: 7,
        },
        None,
    ))
    .await;
    let r = ann.expect("InviteCode", admin_answer).await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::InviteCode { code })) = r else {
        panic!("InviteCode: {r:?}")
    };
    assert!(!code.is_empty());
    ann.send(&admin_op(AdminOp::Invites, None)).await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::Invites { invites })) =
        ann.expect("Invites", admin_answer).await
    else {
        panic!("Invites")
    };
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].created_by.as_deref(), Some("ann"));
    let id = invites[0].id.clone();
    ann.send(&admin_op(AdminOp::InviteRevoke { id: id.clone() }, None))
        .await;
    let ServerMessage::Account(AccountReply::Admin(AdminReply::Invites { invites })) =
        ann.expect("Invites", admin_answer).await
    else {
        panic!("Invites")
    };
    assert!(invites.iter().all(|i| i.id != id));
}

#[tokio::test]
async fn a_channel_editor_reaches_only_channels_it_may_see() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    group(&state, "staff", None, &[]).await;
    let (mut ann, _, _) = admin_account(&state, "ann").await;
    let (mut eve, ei) = register(&state, "eve").await;
    let eve_sid = *state.account_sessions.get(&ei.id).unwrap();
    grant(&state, eve_sid, &["voipc:channels"]);
    let room = create(&mut ann, "staffroom", false).await;
    let gate = |groups: &[&str]| ChannelGate {
        groups: groups.iter().map(|g| g.to_string()).collect(),
        speakers: vec![],
    };
    ann.send(&admin_op(
        AdminOp::GateSet {
            channel_id: room,
            gate: gate(&["staff"]),
        },
        None,
    ))
    .await;
    ann.expect("Gate", admin_answer).await;
    for op in [
        AdminOp::GateGet { channel_id: room },
        AdminOp::GateSet {
            channel_id: room,
            gate: gate(&[]),
        },
    ] {
        eve.send(&admin_op(op, None)).await;
        let ServerMessage::Account(AccountReply::Error { reason, .. }) =
            eve.expect("refused", admin_answer).await
        else {
            panic!("refused")
        };
        assert!(reason.contains("does not exist"), "{reason}");
    }
    assert_eq!(state.channels.read().await[&room].gate.groups, ["staff"]);
    // Nor shuts itself out of one it may
    let open = create(&mut eve, "lobby2", false).await;
    eve.send(&admin_op(
        AdminOp::GateSet {
            channel_id: open,
            gate: gate(&["staff"]),
        },
        None,
    ))
    .await;
    let ServerMessage::Account(AccountReply::Error { reason, .. }) =
        eve.expect("refused", admin_answer).await
    else {
        panic!("refused")
    };
    assert!(reason.contains("shut you out"), "{reason}");
}

#[tokio::test]
async fn a_persistent_channels_gate_outlives_a_restart() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    group(&state, "crew", None, &[]).await;
    let (mut ann, _, _) = admin_account(&state, "ann").await;
    crate::state::test_support::put_in_channel(&state, 7, &[]).await;
    state.channels.write().await.get_mut(&7).unwrap().gate_key = "c:feedfeed".into();
    let set = |groups: Vec<String>| {
        admin_op(
            AdminOp::GateSet {
                channel_id: 7,
                gate: ChannelGate {
                    groups,
                    speakers: vec![],
                },
            },
            None,
        )
    };
    ann.send(&set(vec!["crew".into()])).await;
    ann.expect("Gate", admin_answer).await;
    let relay = state.accounts.clone().unwrap();
    assert_eq!(
        relay.gates().await.unwrap(),
        [(
            "c:feedfeed".to_string(),
            ChannelGate {
                groups: vec!["crew".into()],
                speakers: vec![]
            }
        )]
    );
    state.channels.write().await.get_mut(&7).unwrap().gate = ChannelGate::default();
    crate::gates::load(&state).await.unwrap();
    assert_eq!(state.channels.read().await[&7].gate.groups, ["crew"]);
    // An open gate keeps no row
    ann.send(&set(vec![])).await;
    ann.expect("Gate", admin_answer).await;
    assert!(relay.gates().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_gated_channels_log_keeps_only_who_passes() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    group(&state, "crew", None, &[]).await;
    let (_bob, bi) = register(&state, "bob").await;
    let (_cat, ci) = register(&state, "cat").await;
    give(&state, bi.id, "crew", true).await;
    let relay = state.accounts.clone().unwrap();
    for a in [bi.id, ci.id] {
        crate::accounts::raw(
            &relay,
            &format!(
                "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('c:aa', X'{}', 1)",
                hex::encode(a)
            ),
        )
        .await
        .unwrap();
    }
    relay.prune_log("c:aa", &["crew".into()]).await.unwrap();
    let count = |sql: String| {
        let relay = relay.clone();
        async move { crate::accounts::raw(&relay, &sql).await.unwrap() }
    };
    assert_eq!(
        count("SELECT COUNT(*) FROM voipc_members WHERE conv = 'c:aa'".into()).await,
        1
    );
    assert_eq!(
        count(format!(
            "SELECT COUNT(*) FROM voipc_members WHERE account = X'{}'",
            hex::encode(bi.id)
        ))
        .await,
        1,
        "the one in the crew stays"
    );
}

#[tokio::test]
async fn a_group_given_from_the_shell_reaches_the_connection_at_the_next_check() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    group(&state, "crew", Some("crew"), &[]).await;
    let (_bob, bi) = register(&state, "bob").await;
    let relay = state.accounts.clone().unwrap();
    let ctx = relay.ctx(IpAddr::V4(Ipv4Addr::LOCALHOST), "test");
    relay
        .accounts
        .grant_role_as_host(&ctx, AccountId(bi.id), "crew")
        .await
        .unwrap();
    let sid = *state.account_sessions.get(&bi.id).unwrap();
    let groups = |state: &ServerState| {
        state
            .sessions
            .get(&sid)
            .unwrap()
            .account
            .as_ref()
            .unwrap()
            .standing
            .groups
            .clone()
    };
    assert!(!groups(&state).contains(&"crew".to_string()));
    // No scope moved: only the standing tells the check something changed
    crate::accounts::revalidate(&state).await;
    assert!(groups(&state).contains(&"crew".to_string()));
}

// ── Sign-in with a provider ──────────────────────────────────────────────

mod providers {
    use super::*;
    use crate::accounts::provider::{self, NOT_YET};
    use l4f_accounts::oauth::{Kind, Provider};
    use l4f_accounts::service::OAuth;
    use std::sync::Mutex;
    use voipc_crypto::account::{provider_ask, Method, SignIn, Step};
    use voipc_protocol::types::{AccountStart, ProviderKind};

    use hyper::StatusCode;

    const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const IDENTITY_OTHER: [u8; 33] = [6; 33];

    /// A provider on a local port: any code is good, and it says the person is
    /// whoever `subject` holds. Answers each request and closes.
    async fn fake_provider() -> (String, Arc<Mutex<String>>) {
        let subject = Arc::new(Mutex::new("1001".to_string()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let who = subject.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let who = who.clone();
                tokio::spawn(async move {
                    let mut got = Vec::new();
                    let mut chunk = [0u8; 2048];
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk).await {
                            Ok(n) if n > 0 => got.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    }
                    let body = if got.starts_with(b"POST") {
                        r#"{"access_token":"at","token_type":"Bearer"}"#.to_string()
                    } else {
                        format!(
                            r#"{{"id":"{}","username":"dee_d","global_name":"Dee D"}}"#,
                            who.lock().unwrap()
                        )
                    };
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(answer.as_bytes()).await;
                });
            }
        });
        (base, subject)
    }

    /// A relay with accounts and a Discord application at `fake_provider`.
    async fn relay(
        registration: RegistrationMode,
    ) -> (Arc<ServerState>, TempDb, Arc<Mutex<String>>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (base, subject) = fake_provider().await;
        let mut config = ServerConfig::default();
        config.accounts.mode = AccountsMode::Optional;
        config.accounts.registration = registration;
        config.accounts.public_url = "https://voice.example".into();
        let db = TempDb(std::env::temp_dir().join(format!(
            "voipc-relay-{}.db",
            hex::encode(rand::random::<[u8; 8]>())
        )));
        let store = l4f_accounts::store::Store::connect(&format!("sqlite://{}", db.0.display()))
            .await
            .unwrap();
        let mut discord = Provider::new(Kind::Discord, "client".into(), "secret".into());
        discord.authorize_url = format!("{base}/authorize");
        discord.token_url = format!("{base}/token");
        discord.profile_url = format!("{base}/profile");
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let relay = crate::accounts::Relay::open_with(&config.accounts, store, &[9u8; 32])
            .await
            .unwrap()
            .with_providers(OAuth::new(http, vec![discord]));
        let mut state = ServerState::new(
            &config,
            ServerSettings::default(),
            Vec::new(),
            "test-admin-token".into(),
        );
        state.accounts = Some(Arc::new(relay));
        (Arc::new(state), db, subject)
    }

    fn relay_of(state: &ServerState) -> &crate::accounts::Relay {
        state.accounts.as_deref().unwrap()
    }

    /// `AccountStart::Provider`: the page, the code, the ticket.
    async fn open_page(state: &Arc<ServerState>) -> (String, String, Vec<u8>) {
        let first = provider_ask(
            AccountStart::Provider {
                kind: ProviderKind::Discord,
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(state, &first).await;
        let Some(ServerMessage::AuthStep(AuthStep::OpenBrowser { url, code, ticket })) =
            c.next().await
        else {
            panic!("no page to open")
        };
        (url, code, ticket)
    }

    /// `AccountStart::ProviderStatus`.
    async fn status(state: &Arc<ServerState>, ticket: &[u8]) -> bool {
        let first = provider_ask(
            AccountStart::ProviderStatus {
                ticket: ticket.to_vec(),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(state, &first).await;
        match c.next().await {
            Some(ServerMessage::AuthStep(AuthStep::ProviderReady)) => true,
            Some(ServerMessage::AuthStep(AuthStep::ProviderPending)) => false,
            other => panic!("{other:?}"),
        }
    }

    fn state_in(url: &str) -> &str {
        url.split(['?', '&'])
            .find_map(|p| p.strip_prefix("state="))
            .unwrap()
    }

    /// The browser: back from the provider, and `pick` tapped.
    async fn browser(state: &Arc<ServerState>, url: &str, pick: &str) -> StatusCode {
        let s = state_in(url);
        let back = provider::callback(state, "/account/oauth/discord/cb", &format!("state={s}&code=abc"));
        assert_eq!(back.status(), StatusCode::OK);
        provider::confirm(state, format!("state={s}&pick={pick}").as_bytes(), LO)
            .await
            .status()
    }

    /// What the person chooses at `Step::ProviderChoice`.
    enum Choice {
        Claim,
        Recovery([u8; 32]),
    }

    /// Runs the client's machine through a provider's sign-in.
    async fn sign_in(
        state: &Arc<ServerState>,
        ticket: Vec<u8>,
        choice: Choice,
    ) -> Result<(Client, voipc_crypto::account::SignedIn), String> {
        sign_in_with(state, ticket, None, choice, &["deedee"]).await
    }

    /// With an invite, and the names to try in turn when asked for one.
    async fn sign_in_with(
        state: &Arc<ServerState>,
        ticket: Vec<u8>,
        invite: Option<&str>,
        choice: Choice,
        names: &[&str],
    ) -> Result<(Client, voipc_crypto::account::SignedIn), String> {
        let mut names = names.iter();
        let (mut m, first) = SignIn::start(
            "",
            Method::Provider {
                ticket,
                invite: invite.map(String::from),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(state, &first).await;
        loop {
            let msg = c.next().await.ok_or("closed")?;
            if matches!(msg, ServerMessage::Authenticated { account: Some(_), .. }) {
                return Ok((c, m.finish()?));
            }
            let mut steps = m.on_message(&msg)?;
            while !steps.is_empty() {
                match steps.remove(0) {
                    Step::Send(out) => c.send(&out).await,
                    Step::Keys => {
                        let ik = m.identity().unwrap().public_key().serialize().to_vec();
                        let b = PreKeyBundleData {
                            identity_key: ik,
                            ..bundle()
                        };
                        c.send(&m.keys(b)).await;
                    }
                    Step::ProviderSignup { .. } => {
                        let name = names.next().ok_or("asked for one name too many")?;
                        let out = m.provider_signup(name)?;
                        c.send(&out).await;
                    }
                    Step::ProviderChoice { .. } => {
                        steps = match &choice {
                            Choice::Claim => m.provider_claim()?,
                            Choice::Recovery(key) => m.provider_recovery(key)?,
                        };
                    }
                    Step::ProviderPending => return Err(NOT_YET.into()),
                    Step::Ignore => {}
                    _ => return Err("not a step here".into()),
                }
            }
        }
    }

    /// A first sign-in on an open relay: the provider's person takes a name and
    /// claims. Returns the connection, what it signed in with, and the recovery key.
    async fn claimed(state: &Arc<ServerState>) -> (Client, voipc_crypto::account::SignedIn, [u8; 32]) {
        let (url, code, ticket) = open_page(state).await;
        assert_eq!(browser(state, &url, &code).await, StatusCode::OK);
        let (c, signed) = sign_in(state, ticket, Choice::Claim).await.unwrap();
        let key = voipc_crypto::account::recovery_parse(signed.recovery.as_ref().unwrap()).unwrap();
        (c, signed, key)
    }

    fn stored_keys(blobs: &[VaultBlob]) -> Vec<&str> {
        blobs.iter().map(|b| b.k.as_str()).collect()
    }

    #[tokio::test]
    async fn a_relay_without_providers_lists_none_and_offers_no_page() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let first = provider_ask(AccountStart::Providers, PROTOCOL_VERSION, APP_VERSION);
        let mut c = open_raw(&state, &first).await;
        assert!(
            matches!(
                c.next().await,
                Some(ServerMessage::AuthStep(AuthStep::Providers { ref kinds })) if kinds.is_empty()
            ),
        );
        let first = provider_ask(
            AccountStart::Provider {
                kind: ProviderKind::Discord,
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(&state, &first).await;
        assert!(matches!(c.next().await, Some(ServerMessage::AuthError { .. })));
    }

    /// Nothing is asked of the provider before the tap, and a wrong tap ends it:
    /// that is what a person sent somebody else's link does.
    #[tokio::test]
    async fn the_flow_waits_for_the_right_code_and_a_wrong_one_ends_it() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (url, code, ticket) = open_page(&state).await;

        let not_yet = sign_in(&state, ticket.clone(), Choice::Claim).await;
        assert_eq!(not_yet.err().as_deref(), Some(NOT_YET));
        assert!(!status(&state, &ticket).await, "asking does not end the flow");

        let s = state_in(&url).to_string();
        let page = provider::callback(&state, "/account/oauth/discord/cb", &format!("state={s}&code=abc"));
        assert_eq!(page.status(), StatusCode::OK);
        let csp = page.headers().get(hyper::header::CONTENT_SECURITY_POLICY).unwrap();
        assert!(csp.to_str().unwrap().contains("form-action 'self'"));
        let not_yet = sign_in(&state, ticket.clone(), Choice::Claim).await;
        assert_eq!(
            not_yet.err().as_deref(),
            Some(NOT_YET),
            "back from the provider, not tapped"
        );

        let wrong = if code == "100" { "101" } else { "100" };
        let tapped = provider::confirm(&state, format!("state={s}&pick={wrong}").as_bytes(), LO).await;
        assert_eq!(tapped.status(), StatusCode::FORBIDDEN);
        // A second tap, now with the right code, changes nothing
        let again = provider::confirm(&state, format!("state={s}&pick={code}").as_bytes(), LO).await;
        assert_eq!(again.status(), StatusCode::GONE);
        assert!(status(&state, &ticket).await, "through, if not well");
        let ended = sign_in(&state, ticket, Choice::Claim).await;
        assert!(ended.err().unwrap().contains("not the one"));
    }

    #[tokio::test]
    async fn a_callback_for_no_flow_or_another_provider_ends_there() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let gone = provider::callback(&state, "/account/oauth/discord/cb", "state=nothing&code=abc");
        assert_eq!(gone.status(), StatusCode::GONE);
        let (url, _, _) = open_page(&state).await;
        let other = provider::callback(
            &state,
            "/account/oauth/google/cb",
            &format!("state={}&code=abc", state_in(&url)),
        );
        assert_eq!(other.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn the_first_sign_in_claims_with_a_recovery_key_and_no_password_slot() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (_c, signed, _) = claimed(&state).await;
        assert_eq!(signed.name, "deedee");
        let relay = relay_of(&state);
        let user = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        assert!(!user.has_password);
        let stored = relay.vault(user.id).await.unwrap();
        let keys = stored_keys(&stored);
        assert!(!keys.contains(&"slot.pass"), "{keys:?}");
        assert!(keys.contains(&"slot.recovery") && keys.contains(&"slot.reset"), "{keys:?}");
        assert_eq!(
            relay.identity(user.id).await.unwrap().unwrap(),
            signed.identity.public_key().serialize().to_vec()
        );
    }

    /// The recovery key opens the same vault on a new device, the same identity
    /// comes out, and the live connection is taken over only then.
    #[tokio::test]
    async fn a_new_device_comes_in_with_the_recovery_key() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (old, signed, key) = claimed(&state).await;
        let (url, code, ticket) = open_page(&state).await;
        browser(&state, &url, &code).await;
        let (_c, again) = sign_in(&state, ticket, Choice::Recovery(key)).await.unwrap();
        assert_eq!(
            again.identity.public_key().serialize(),
            signed.identity.public_key().serialize()
        );
        assert!(again.recovery.is_none(), "shown once, at the claim");
        let mut old = old;
        loop {
            match old.next().await {
                Some(ServerMessage::Disconnected { reason }) => {
                    assert!(reason.contains("another device"), "{reason}");
                    break;
                }
                Some(_) => {}
                None => panic!("closed without saying why"),
            }
        }
    }

    /// Steps to `ProviderSigned` for an account that exists, by hand.
    async fn at_the_choice(state: &Arc<ServerState>) -> (Client, Vec<u8>, Vec<VaultBlob>, bool) {
        let (url, code, ticket) = open_page(state).await;
        browser(state, &url, &code).await;
        let first = ClientMessage::Authenticate {
            username: String::new(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: None,
            prekey_bundle: None,
            account: Some(AccountStart::ProviderResume { ticket }),
        };
        let mut c = open_raw(state, &first).await;
        let Some(ServerMessage::AuthStep(AuthStep::ProviderSigned {
            challenge,
            blobs,
            claim,
            ..
        })) = c.next().await
        else {
            panic!("no ProviderSigned")
        };
        (c, challenge, blobs, claim)
    }

    /// The hole this all exists for: `Keys` only compares a public key, which a
    /// relay's members can all see. Without the vault, nobody gets to it, and the
    /// real person's connection is not touched.
    #[tokio::test]
    async fn a_hijacked_provider_account_gets_no_admission_and_takes_nothing_over() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (mut real, signed, _) = claimed(&state).await;
        let public = signed.identity.public_key().serialize().to_vec();

        let (mut c, _, _, claim) = at_the_choice(&state).await;
        assert!(!claim);
        c.send(&keys(&public, false)).await;
        assert!(
            matches!(c.next().await, Some(ServerMessage::AuthError { .. })),
            "the public key alone is no way in"
        );

        let (mut c, _, _, _) = at_the_choice(&state).await;
        c.send(&ClientMessage::AuthContinue(AuthContinue::ProviderProof {
            signature: vec![0; 64],
        }))
        .await;
        let Some(ServerMessage::AuthError { reason }) = c.next().await else {
            panic!("a made-up signature is no way in")
        };
        assert!(reason.contains("does not open"), "{reason}");

        // And someone else's real signature, over the right challenge
        let (mut c, challenge, _, _) = at_the_choice(&state).await;
        let stranger = voipc_crypto::generate_identity_key_pair();
        let relay_id = relay_of(&state).relay_id;
        c.send(&ClientMessage::AuthContinue(AuthContinue::ProviderProof {
            signature: voipc_crypto::account::provider_proof(&stranger, &relay_id, "deedee", &challenge),
        }))
        .await;
        assert!(matches!(c.next().await, Some(ServerMessage::AuthError { .. })));

        real.send(&ClientMessage::Ping { timestamp: 7 }).await;
        real.expect("the real connection lives on", |m| {
            matches!(m, ServerMessage::Pong { timestamp: 7 })
        })
        .await;
    }

    #[tokio::test]
    async fn the_password_slot_never_goes_out_to_a_provider_sign_in() {
        let (state, _db, subject) = relay(RegistrationMode::Open).await;
        let (_c, _, _) = register_with(&state, "wendy").await;
        let relay = relay_of(&state);
        let wendy = relay.store().user_by_username("wendy").await.unwrap().unwrap();
        assert!(
            relay.vault(wendy.id).await.unwrap().iter().any(|b| b.k == "slot.pass"),
            "the control: this vault has one"
        );
        *subject.lock().unwrap() = "2002".into();
        link_directly(&state, wendy.id, "2002").await;

        let (url, code, ticket) = open_page(&state).await;
        browser(&state, &url, &code).await;
        let first = provider_ask(
            AccountStart::ProviderResume { ticket },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(&state, &first).await;
        let Some(ServerMessage::AuthStep(AuthStep::ProviderSigned {
            name,
            has_password,
            claim,
            blobs,
            ..
        })) = c.next().await
        else {
            panic!("no ProviderSigned")
        };
        assert_eq!(name, "wendy");
        assert!(has_password && !claim);
        assert!(!stored_keys(&blobs).contains(&"slot.pass"), "{:?}", stored_keys(&blobs));
    }

    /// An identity on record for `user`'s account: what a provider's `credential`
    /// row looks like when made by hand, with fields l4f's `Credential` keeps public.
    async fn link_directly(state: &Arc<ServerState>, user: AccountId, subject: &str) {
        let c = l4f_accounts::model::Credential {
            kind: Kind::Discord.credential_kind(),
            ext_id: subject.as_bytes().to_vec(),
            user_id: user,
            public_key: None,
            alg: 0,
            sign_count: 0,
            flags: 0,
            name: "dee_d".into(),
            created_at: l4f_accounts::util::now(),
            last_used_at: None,
            public: false,
        };
        assert!(relay_of(state).store().insert_credential(&c).await.unwrap());
    }

    /// A code makes the session fresh, and fresh is what a password's reset asks.
    /// Here it must not matter: the code says nothing about the vault.
    #[tokio::test]
    async fn a_provider_and_a_code_cannot_replace_an_identity() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (mut c, signed, key) = claimed(&state).await;
        let secret = totp_on(&mut c).await;
        drop(c);

        let (url, code, ticket) = open_page(&state).await;
        browser(&state, &url, &code).await;
        let first = provider_ask(
            AccountStart::ProviderResume { ticket },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(&state, &first).await;
        assert!(matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::NeedTotp))
        ));
        let code = format!(
            "{:06}",
            l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
        );
        c.send(&ClientMessage::AuthContinue(AuthContinue::Totp { code })).await;
        let msg = c.next().await.unwrap();
        let (mut m, _) = SignIn::start(
            "",
            Method::Provider { ticket: vec![], invite: None },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        m.on_message(&msg).unwrap();
        // The vault opened and proved, as the real person's device would
        let Step::Send(proof) = m.provider_recovery(&key).unwrap().remove(0) else {
            panic!("no proof")
        };
        c.send(&proof).await;
        c.send(&keys(&IDENTITY_OTHER, true)).await;
        let Some(ServerMessage::AuthError { reason }) = c.next().await else {
            panic!("an identity replaced through a provider")
        };
        assert!(reason.contains("not your account's"), "{reason}");
        let on_record = relay_of(&state)
            .identity(relay_of(&state).store().user_by_username("deedee").await.unwrap().unwrap().id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(on_record, signed.identity.public_key().serialize().to_vec());
    }

    /// A claim is for an account nobody opened, and a relay's answer is not
    /// what makes that so: the database's identity row is.
    #[tokio::test]
    async fn a_claim_is_refused_once_an_identity_exists() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (_real, signed, _) = claimed(&state).await;
        let (mut c, _, _, _) = at_the_choice(&state).await;
        c.send(&ClientMessage::AuthContinue(AuthContinue::Claim {
            identity_key: IDENTITY_OTHER.to_vec(),
            vault: vec![reset_slot()],
        }))
        .await;
        assert!(matches!(c.next().await, Some(ServerMessage::AuthError { .. })));
        let relay = relay_of(&state);
        let user = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        assert_eq!(
            relay.identity(user.id).await.unwrap().unwrap(),
            signed.identity.public_key().serialize().to_vec()
        );
        assert!(
            relay.vault(user.id).await.unwrap().iter().any(|b| b.k == "slot.recovery"),
            "the vault is still there"
        );
    }

    /// Two devices at the same unopened account: the database decides, not what
    /// the relay told each of them a moment ago.
    #[tokio::test]
    async fn the_second_of_two_claims_changes_nothing() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (_c, signed, _) = claimed(&state).await;
        let relay = relay_of(&state);
        let user = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        let before = relay.vault(user.id).await.unwrap();
        let err = provider::claim(relay, user.id, &IDENTITY_OTHER, &[reset_slot()])
            .await
            .unwrap_err();
        assert!(err.contains("opened just now"), "{err}");
        assert_eq!(
            relay.identity(user.id).await.unwrap().unwrap(),
            signed.identity.public_key().serialize().to_vec()
        );
        assert_eq!(relay.vault(user.id).await.unwrap().len(), before.len());
    }

    /// A claim that died halfway left blobs nobody can open, and no identity.
    #[tokio::test]
    async fn a_claim_goes_through_what_a_dead_one_left() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_c, _) = register(&state, "gwen").await;
        let relay = relay_of(&state);
        let user = relay.store().user_by_username("gwen").await.unwrap().unwrap();
        db_forget_identity(relay, user.id).await;
        provider::claim(relay, user.id, &IDENTITY_OTHER, &[reset_slot()])
            .await
            .unwrap();
        let keys: Vec<String> = relay.vault(user.id).await.unwrap().into_iter().map(|b| b.k).collect();
        assert_eq!(keys, ["slot.reset"], "only what this claim wrote");
    }

    async fn db_forget_identity(relay: &crate::accounts::Relay, user: AccountId) {
        let l4f_accounts::store::Store::Lite(b) = relay.store() else {
            panic!("these tests run on SQLite")
        };
        sqlx::query("DELETE FROM voipc_identity WHERE account = $1")
            .bind(&user.0[..])
            .execute(&b.0)
            .await
            .unwrap();
    }

    /// The way back for someone who lost everything, from the shell only, and not
    /// for an account with a password, which it would lock out.
    #[tokio::test]
    async fn reclaim_reopens_an_account_without_a_password_only() {
        let (state, _db, subject) = relay(RegistrationMode::Open).await;
        let (c, signed, _) = claimed(&state).await;
        drop(c);
        let relay = relay_of(&state);
        let ctx = relay.ctx(LO, "test");
        let user = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        relay.reclaim(&ctx, &user).await.unwrap();
        assert!(relay.identity(user.id).await.unwrap().is_none());
        assert!(relay.vault(user.id).await.unwrap().is_empty());

        // The same provider opens it anew, under the same name, with a new identity
        let (url, code, ticket) = open_page(&state).await;
        browser(&state, &url, &code).await;
        let (_c, again) = sign_in(&state, ticket, Choice::Claim).await.unwrap();
        assert_eq!(again.name, "deedee");
        assert_ne!(
            again.identity.public_key().serialize(),
            signed.identity.public_key().serialize()
        );

        *subject.lock().unwrap() = "5005".into();
        let (_w, _, _) = register_with(&state, "wendy").await;
        let wendy = relay.store().user_by_username("wendy").await.unwrap().unwrap();
        let err = relay.reclaim(&ctx, &wendy).await.unwrap_err();
        assert!(err.contains("has a password"), "{err}");
        assert!(relay.identity(wendy.id).await.unwrap().is_some());
    }

    /// How an account without a password gets one: the recovery key, as anyone
    /// who forgot theirs. It then signs in with it, from any device.
    #[tokio::test]
    async fn the_recovery_key_adds_a_password_to_an_account_without_one() {
        use voipc_crypto::account::recovery_text;
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (c, signed, key) = claimed(&state).await;
        drop(c);
        tokio::time::sleep(Duration::from_millis(100)).await;
        reset_with(&state, "deedee", &recovery_text(&key), "a brand new password", None)
            .await
            .unwrap();
        let relay = relay_of(&state);
        let user = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        assert!(user.has_password);

        let (mut m, first) = SignIn::start(
            "deedee",
            Method::Password {
                password: zeroize::Zeroizing::new("a brand new password".into()),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(&state, &first).await;
        drive(&mut c, &mut m).await.unwrap();
        assert_eq!(
            m.finish().unwrap().identity.public_key().serialize(),
            signed.identity.public_key().serialize()
        );
    }

    /// A claim needs what every account's reset depends on.
    #[tokio::test]
    async fn a_claim_without_a_reset_key_is_refused() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (url, code, ticket) = open_page(&state).await;
        browser(&state, &url, &code).await;
        let first = provider_ask(
            AccountStart::ProviderResume { ticket },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let (mut m, _) = SignIn::start("", Method::Provider { ticket: vec![], invite: None }, PROTOCOL_VERSION, APP_VERSION);
        let mut c = open_raw(&state, &first).await;
        let msg = c.next().await.unwrap();
        for s in m.on_message(&msg).unwrap() {
            assert!(matches!(s, Step::ProviderSignup { .. }));
        }
        c.send(&m.provider_signup("deedee").unwrap()).await;
        assert!(matches!(
            c.next().await,
            Some(ServerMessage::AuthStep(AuthStep::ProviderSigned { claim: true, .. }))
        ));
        c.send(&ClientMessage::AuthContinue(AuthContinue::Claim {
            identity_key: IDENTITY_OTHER.to_vec(),
            vault: vec![],
        }))
        .await;
        assert!(matches!(c.next().await, Some(ServerMessage::AuthError { .. })));
        let relay = relay_of(&state);
        let user = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        assert!(relay.identity(user.id).await.unwrap().is_none(), "still unclaimed");
    }

    /// A link's maker, on any relay: someone with an account, made from the shell.
    async fn link_maker(state: &Arc<ServerState>) -> AccountId {
        let relay = state.accounts.clone().unwrap();
        let ctx = relay.ctx(LO, "test");
        let name = format!("maker{:04}", rand::random::<u16>());
        let code = relay
            .accounts
            .invite_create_as_host(&ctx, Some(&name), 1)
            .await
            .unwrap();
        let form = l4f_accounts::service::InviteForm {
            code: &code,
            username: &name,
            password: "a long enough password here",
            email: None,
            display_name: None,
        };
        relay.accounts.register_invite(&ctx, form).await.unwrap().info.user_id
    }

    async fn in_group(state: &ServerState, name: &str, group: &str) -> bool {
        let relay = state.accounts.as_ref().unwrap();
        let user = relay.store().user_by_username(name).await.unwrap().unwrap();
        relay
            .store()
            .user_roles(user.id)
            .await
            .unwrap()
            .iter()
            .any(|r| r.name == group)
    }

    /// Where sign-up is by invite: a link lets a stranger in through a provider, as
    /// it does with a password, with its limits and its starting group.
    #[tokio::test]
    async fn a_link_lets_a_stranger_in_through_a_provider() {
        let (state, _db, subject) = relay(RegistrationMode::Invite).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        let relay = state.accounts.clone().unwrap();
        let maker = link_maker(&state).await;
        let (code, _) = relay.link_new(1, 7, Some("crew"), maker).await.unwrap().unwrap();

        // A name that is taken asks again, and costs no use
        let (url, shown, ticket) = open_page(&state).await;
        browser(&state, &url, &shown).await;
        let taken = relay.store().user_by_id(maker).await.unwrap().unwrap().username;
        sign_in_with(&state, ticket, Some(&code), Choice::Claim, &[&taken, "deedee"])
            .await
            .expect("signed up under the second name");
        assert!(in_group(&state, "deedee", "crew").await, "its starting group");
        assert_eq!(relay.links().await.unwrap()[0].uses, 1);
        let dee = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        let audit = relay.store().audit_of(dee.id, 50).await.unwrap();
        let used = audit.iter().find(|e| e.event == "invite_link_used").unwrap();
        assert_eq!(used.actor_id, Some(maker), "by whose link");

        // Used up: nobody else gets in on it
        *subject.lock().unwrap() = "someone-else".into();
        let (url, shown, ticket) = open_page(&state).await;
        browser(&state, &url, &shown).await;
        let err = sign_in_with(&state, ticket, Some(&code), Choice::Claim, &["other"])
            .await
            .err()
            .unwrap();
        assert!(err.contains("not valid"), "{err}");
    }

    /// An admin's single-use code works through a provider too, and is spent.
    #[tokio::test]
    async fn an_invite_code_lets_a_stranger_in_through_a_provider() {
        let (state, _db, subject) = relay(RegistrationMode::Invite).await;
        let relay = state.accounts.clone().unwrap();
        let ctx = relay.ctx(LO, "test");
        let code = relay.accounts.invite_create_as_host(&ctx, None, 1).await.unwrap();
        let (url, shown, ticket) = open_page(&state).await;
        browser(&state, &url, &shown).await;
        sign_in_with(&state, ticket, Some(&code), Choice::Claim, &["deedee"])
            .await
            .expect("signed up");
        *subject.lock().unwrap() = "someone-else".into();
        let (url, shown, ticket) = open_page(&state).await;
        browser(&state, &url, &shown).await;
        let err = sign_in_with(&state, ticket, Some(&code), Choice::Claim, &["other"])
            .await
            .err();
        assert!(err.is_some(), "spent");
    }

    /// Where anyone may sign up, a link adds its group; one that ran out only does not.
    #[tokio::test]
    async fn on_an_open_relay_a_dead_link_turns_nobody_away() {
        let (state, _db, subject) = relay(RegistrationMode::Open).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        let relay = state.accounts.clone().unwrap();
        let maker = link_maker(&state).await;
        let (code, _) = relay.link_new(1, 7, Some("crew"), maker).await.unwrap().unwrap();
        let (url, shown, ticket) = open_page(&state).await;
        browser(&state, &url, &shown).await;
        sign_in_with(&state, ticket, Some(&code), Choice::Claim, &["deedee"])
            .await
            .expect("signed up");
        assert!(in_group(&state, "deedee", "crew").await);

        *subject.lock().unwrap() = "someone-else".into();
        let (url, shown, ticket) = open_page(&state).await;
        browser(&state, &url, &shown).await;
        sign_in_with(&state, ticket, Some(&code), Choice::Claim, &["other"])
            .await
            .expect("anyone may sign up here");
        assert!(!in_group(&state, "other", "crew").await, "the link had run out");
    }

    /// Sign-up closed means closed: a link is no way round it.
    #[tokio::test]
    async fn a_closed_relay_takes_no_link_from_a_provider_either() {
        let (state, _db, _) = relay(RegistrationMode::Closed).await;
        let relay = state.accounts.clone().unwrap();
        let maker = link_maker(&state).await;
        let (code, _) = relay.link_new(5, 7, None, maker).await.unwrap().unwrap();
        let (url, shown, ticket) = open_page(&state).await;
        browser(&state, &url, &shown).await;
        let err = sign_in_with(&state, ticket, Some(&code), Choice::Claim, &["deedee"])
            .await
            .err()
            .unwrap();
        assert!(err.contains("not valid"), "{err}");
        assert!(!relay.is_account_name("deedee").await.unwrap());
    }

    /// On a relay that takes invites only, a provider nobody knows makes no account.
    #[tokio::test]
    async fn a_closed_relay_makes_no_account_for_a_stranger() {
        let (state, _db, _) = relay(RegistrationMode::Invite).await;
        let (url, code, ticket) = open_page(&state).await;
        browser(&state, &url, &code).await;
        let err = sign_in(&state, ticket, Choice::Claim).await.err().unwrap();
        assert!(err.contains("No account here uses that sign-in"), "{err}");
    }

    /// A proven connection may remember its device; a remembered device's own
    /// connection may not reset anything or get that for free.
    #[tokio::test]
    async fn only_a_proven_connection_counts_as_recent_for_remembering_a_device() {
        use voipc_crypto::account::DeviceEnrol;
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (mut c, signed, _) = claimed(&state).await;
        let (enrol, ask) = DeviceEnrol::start(signed.relay_id);
        c.send(&ask).await;
        let ServerMessage::Account(r) = c.expect("challenge", |m| reply(m).is_some()).await else {
            unreachable!()
        };
        assert!(matches!(r, AccountReply::DeviceChallenge { .. }), "{r:?}");
        c.send(&enrol.on_reply(&r).unwrap()).await;
        assert!(matches!(
            c.expect("added", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::DeviceAdded)
        ));
        drop(c);

        // Signed in by that device key: as a stolen device would be
        let (mut m, first) = SignIn::start(
            "deedee",
            Method::Device {
                key: enrol.key,
                relay_id: signed.relay_id,
                dek: signed.vault.dek(),
            },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(&state, &first).await;
        drive(&mut c, &mut m).await.unwrap();
        c.send(&ClientMessage::Account(AccountRequest::DeviceChallenge)).await;
        let ServerMessage::Account(AccountReply::Error { request, .. }) =
            c.expect("refused", |m| reply(m).is_some()).await
        else {
            panic!("a remembered device enrolled another")
        };
        assert_eq!(request, "DeviceChallenge");
        c.send(&ClientMessage::Account(AccountRequest::DeleteAccount {
            secret: vec![],
            totp: None,
            recovery_code: None,
        }))
        .await;
        let ServerMessage::Account(AccountReply::Error { reason, .. }) =
            c.expect("refused", |m| reply(m).is_some()).await
        else {
            panic!("a stolen device deleted the account")
        };
        assert!(reason.contains("provider"), "{reason}");
    }

    // ── Pairing ──

    /// The old device hears the ask and answers with a nonce.
    async fn pair_asked(old: &mut Client) -> (u64, Vec<u8>, Vec<u8>) {
        let ServerMessage::Account(AccountReply::PairAsked { pair, commitment }) = old
            .expect("asked", |m| matches!(reply(m), Some(AccountReply::PairAsked { .. })))
            .await
        else {
            unreachable!()
        };
        let nonce = vec![3u8; voipc_crypto::pair::NONCE_LEN];
        old.send(&ClientMessage::Account(AccountRequest::PairNonce {
            pair,
            nonce: nonce.clone(),
        }))
        .await;
        (pair, commitment, nonce)
    }

    /// The new device answers the nonce: the reveal goes out, its code comes back.
    async fn pair_reveal(m: &mut SignIn, c: &mut Client) -> String {
        let msg = c.next().await.unwrap();
        let mut steps = m.on_message(&msg).unwrap();
        let Step::Send(reveal) = steps.remove(0) else {
            panic!("no reveal")
        };
        c.send(&reveal).await;
        let Step::PairCode { code } = steps.remove(0) else {
            panic!("no code")
        };
        code
    }

    /// The old device checks the reveal and works out its own code.
    async fn pair_revealed(old: &mut Client, commitment: &[u8], nonce: &[u8]) -> (Vec<u8>, String) {
        let ServerMessage::Account(AccountReply::PairRevealed {
            ephemeral, blind, ..
        }) = old
            .expect("revealed", |m| {
                matches!(reply(m), Some(AccountReply::PairRevealed { .. }))
            })
            .await
        else {
            unreachable!()
        };
        assert!(voipc_crypto::pair::reveal_ok(commitment, &ephemeral, &blind));
        let code = voipc_crypto::pair::code(commitment, nonce, &ephemeral);
        (ephemeral, code)
    }

    /// Runs what the machine returned, until the relay says the device is in.
    async fn run_to_authenticated(m: &mut SignIn, c: &mut Client, steps: Vec<Step>) {
        for s in steps {
            match s {
                Step::Send(out) => c.send(&out).await,
                Step::Keys => {
                    let ik = m.identity().unwrap().public_key().serialize().to_vec();
                    let b = PreKeyBundleData {
                        identity_key: ik,
                        ..bundle()
                    };
                    c.send(&m.keys(b)).await;
                }
                _ => panic!("unexpected step"),
            }
        }
        c.expect("Authenticated", |m| {
            matches!(m, ServerMessage::Authenticated { account: Some(_), .. })
        })
        .await;
    }

    /// The new device up to `ProviderChoice`.
    async fn new_device(state: &Arc<ServerState>) -> (SignIn, Client) {
        let (url, code, ticket) = open_page(state).await;
        browser(state, &url, &code).await;
        let (mut m, first) = SignIn::start(
            "",
            Method::Provider { ticket, invite: None },
            PROTOCOL_VERSION,
            APP_VERSION,
        );
        let mut c = open_raw(state, &first).await;
        let msg = c.next().await.unwrap();
        let steps = m.on_message(&msg).unwrap();
        assert!(matches!(steps[0], Step::ProviderChoice { claim: false, .. }));
        (m, c)
    }

    #[tokio::test]
    async fn the_other_device_hands_the_vault_key_over_when_the_codes_match() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (mut old, signed, _) = claimed(&state).await;
        let (mut m, mut c) = new_device(&state).await;
        c.send(&m.pair_start().unwrap()).await;
        let (pair, commitment, nonce) = pair_asked(&mut old).await;
        let code = pair_reveal(&mut m, &mut c).await;
        let (ephemeral, old_code) = pair_revealed(&mut old, &commitment, &nonce).await;
        assert_eq!(code, old_code, "both show the same");

        let wrapped = voipc_crypto::pair::wrap_dek(
            &ephemeral,
            &signed.vault.dek(),
            &signed.relay_id,
            &signed.name,
            &commitment,
        )
        .unwrap();
        old.send(&ClientMessage::Account(AccountRequest::PairApprove { pair, wrapped }))
            .await;
        let msg = c.next().await.unwrap();
        let steps = m.on_message(&msg).unwrap();
        run_to_authenticated(&mut m, &mut c, steps).await;
        assert_eq!(
            m.finish().unwrap().identity.public_key().serialize(),
            signed.identity.public_key().serialize()
        );
    }

    #[tokio::test]
    async fn the_other_device_saying_no_leaves_the_choice_open() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (mut old, _, key) = claimed(&state).await;
        let (mut m, mut c) = new_device(&state).await;
        c.send(&m.pair_start().unwrap()).await;
        let (pair, commitment, nonce) = pair_asked(&mut old).await;
        pair_reveal(&mut m, &mut c).await;
        pair_revealed(&mut old, &commitment, &nonce).await;
        old.send(&ClientMessage::Account(AccountRequest::PairDecline { pair })).await;
        let msg = c.next().await.unwrap();
        let steps = m.on_message(&msg).unwrap();
        assert!(matches!(steps[0], Step::PairRefused { .. }));
        // Still waiting for an answer: the recovery key works
        let steps = m.provider_recovery(&key).unwrap();
        run_to_authenticated(&mut m, &mut c, steps).await;
    }

    /// A stranger with the provider account must not be able to wear the person
    /// down with questions on their other device.
    #[tokio::test]
    async fn asking_the_other_device_is_rate_limited() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (_old, _, _) = claimed(&state).await;
        let (mut m, mut c) = new_device(&state).await;
        let relay = relay_of(&state);
        let user = relay.store().user_by_username("deedee").await.unwrap().unwrap();
        for _ in 0..3 {
            assert!(relay.spend_pair_ask(user.id));
        }
        c.send(&m.pair_start().unwrap()).await;
        let msg = c.next().await.unwrap();
        let steps = m.on_message(&msg).unwrap();
        let Step::PairRefused { reason } = &steps[0] else {
            panic!("asked past the limit")
        };
        assert!(reason.contains("Too many"), "{reason}");
    }

    #[tokio::test]
    async fn nobody_answers_a_pairing_for_another_account() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (mut old, _, _) = claimed(&state).await;
        let (mut m, mut c) = new_device(&state).await;
        let (mut mallory, _) = register(&state, "mallory").await;
        c.send(&m.pair_start().unwrap()).await;
        let ServerMessage::Account(AccountReply::PairAsked { pair, .. }) = old
            .expect("asked", |m| matches!(reply(m), Some(AccountReply::PairAsked { .. })))
            .await
        else {
            unreachable!()
        };
        for msg in [
            AccountRequest::PairDecline { pair },
            AccountRequest::PairApprove {
                pair,
                wrapped: vec![1; 93],
            },
            AccountRequest::PairNonce {
                pair,
                nonce: vec![1; voipc_crypto::pair::NONCE_LEN],
            },
        ] {
            mallory.send(&ClientMessage::Account(msg)).await;
        }
        // The next thing the new device hears is the real device's nonce
        tokio::time::sleep(Duration::from_millis(100)).await;
        let nonce = vec![3u8; voipc_crypto::pair::NONCE_LEN];
        old.send(&ClientMessage::Account(AccountRequest::PairNonce {
            pair,
            nonce: nonce.clone(),
        }))
        .await;
        let Some(ServerMessage::AuthStep(AuthStep::PairNonce { nonce: got })) = c.next().await
        else {
            panic!("somebody else answered")
        };
        assert_eq!(got, nonce);
    }

    // ── A signed-in account's providers ──

    #[tokio::test]
    async fn a_password_account_links_with_its_password_and_unlinks_again() {
        let (state, _db, subject) = relay(RegistrationMode::Open).await;
        *subject.lock().unwrap() = "3003".into();
        let (mut c, _, signed) = register_with(&state, "wendy").await;
        let secret = voipc_crypto::account::derive("correct horse battery", &signed.relay_id, "wendy")
            .auth_secret
            .to_vec();
        c.send(&ClientMessage::Account(AccountRequest::ProviderList)).await;
        let ServerMessage::Account(AccountReply::Providers {
            offered,
            linked,
            has_password,
        }) = c.expect("list", |m| reply(m).is_some()).await
        else {
            panic!("no list")
        };
        assert_eq!(offered, [ProviderKind::Discord]);
        assert!(linked.is_empty() && has_password);

        // Without the password: no
        c.send(&ClientMessage::Account(AccountRequest::ProviderStart {
            kind: ProviderKind::Discord,
            link: true,
            secret: None,
            totp: None,
            recovery_code: None,
        }))
        .await;
        assert!(matches!(
            c.expect("refused", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::Error { .. })
        ));

        c.send(&ClientMessage::Account(AccountRequest::ProviderStart {
            kind: ProviderKind::Discord,
            link: true,
            secret: Some(secret.clone()),
            totp: None,
            recovery_code: None,
        }))
        .await;
        let ServerMessage::Account(AccountReply::ProviderBrowser { url, code }) =
            c.expect("page", |m| reply(m).is_some()).await
        else {
            panic!("no page")
        };
        assert_eq!(browser(&state, &url, &code).await, StatusCode::OK);
        assert!(matches!(
            c.expect("done", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::ProviderDone { link: true, .. })
        ));
        c.send(&ClientMessage::Account(AccountRequest::ProviderList)).await;
        let ServerMessage::Account(AccountReply::Providers { linked, .. }) =
            c.expect("list", |m| reply(m).is_some()).await
        else {
            panic!("no list")
        };
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].kind, ProviderKind::Discord);

        c.send(&ClientMessage::Account(AccountRequest::ProviderUnlink {
            kind: ProviderKind::Discord,
            secret: Some(secret),
            totp: None,
            recovery_code: None,
        }))
        .await;
        assert!(matches!(
            c.expect("unlinked", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::ProviderUnlinked { .. })
        ));
    }

    /// Nothing but this provider signs this account in: it stays.
    #[tokio::test]
    async fn the_last_way_in_cannot_be_unlinked() {
        let (state, _db, _) = relay(RegistrationMode::Open).await;
        let (mut c, _, _) = claimed(&state).await;
        // Prove it with the provider first: a password-less account's recent sign-in
        c.send(&ClientMessage::Account(AccountRequest::ProviderStart {
            kind: ProviderKind::Discord,
            link: false,
            secret: None,
            totp: None,
            recovery_code: None,
        }))
        .await;
        let ServerMessage::Account(AccountReply::ProviderBrowser { url, code }) =
            c.expect("page", |m| reply(m).is_some()).await
        else {
            panic!("no page")
        };
        browser(&state, &url, &code).await;
        assert!(matches!(
            c.expect("done", |m| reply(m).is_some()).await,
            ServerMessage::Account(AccountReply::ProviderDone { link: false, .. })
        ));
        c.send(&ClientMessage::Account(AccountRequest::ProviderUnlink {
            kind: ProviderKind::Discord,
            secret: None,
            totp: None,
            recovery_code: None,
        }))
        .await;
        let ServerMessage::Account(AccountReply::Error { reason, .. }) =
            c.expect("refused", |m| reply(m).is_some()).await
        else {
            panic!("the last way in went")
        };
        assert!(reason.contains("leave no"), "{reason}");
    }

    /// A move signs up far more than an ordinary hour does, and raising the
    /// setting has to raise both of l4f's limits it passes through.
    #[test]
    fn signups_per_hour_raises_the_attempts_limit_too() {
        let mut cfg = ServerConfig::default().accounts;
        cfg.signups_per_hour = 2000;
        let limits = crate::accounts::l4f_config(&cfg, [0; 16]).signup;
        assert_eq!(limits.max_accounts_per_hour, 2000);
        assert_eq!(limits.max_attempts_per_hour, 2000);
        cfg.signups_per_hour = 5;
        let limits = crate::accounts::l4f_config(&cfg, [0; 16]).signup;
        assert_eq!(limits.max_attempts_per_hour, 60, "never below l4f's own");
    }

    #[test]
    fn public_url_is_checked() {
        let with = |url: &str| {
            let mut c = ServerConfig::default();
            c.accounts.mode = AccountsMode::Optional;
            c.accounts.public_url = url.into();
            c.validate().is_ok()
        };
        assert!(with("https://voice.example.org:9987"));
        assert!(with(""));
        assert!(!with("http://voice.example.org"));
        assert!(!with("https://voice.example.org/"));
        assert!(!with("https://voice.example.org/x"));
        assert!(!with("https://"));
    }
}

// ── Channels made in the app, and where channels sit ─────────────────────

mod layouts {
    use super::*;
    use crate::channels::ChannelEntry;
    use voipc_protocol::messages::{AdminOp, AdminReply};
    use voipc_protocol::types::{ChannelCategory, ChannelGate, ChannelPlace};

    /// A manager of channels: an account holding `voipc:channels`.
    async fn manager(state: &Arc<ServerState>, name: &str) -> Client {
        let (c, _) = register(state, name).await;
        let sid = state
            .account_sessions
            .iter()
            .max_by_key(|e| *e.value())
            .map(|e| *e.value())
            .unwrap();
        grant(state, sid, &["voipc:channels"]);
        c
    }

    /// What the layout says to this account's connection right now.
    async fn layout_of(
        state: &Arc<ServerState>,
        name: &str,
    ) -> (Vec<ChannelCategory>, Vec<ChannelPlace>) {
        let sid = state
            .sessions
            .iter()
            .find(|s| s.value().username == name)
            .map(|s| *s.key())
            .unwrap();
        let ServerMessage::ChannelLayout {
            categories,
            channels,
        } = crate::layout::for_session(state, sid).await
        else {
            unreachable!()
        };
        (categories, channels)
    }

    async fn relay_op(c: &mut Client, op: AdminOp, code: Option<String>) -> AccountReply {
        c.send(&ClientMessage::Account(AccountRequest::Admin { op, code }))
            .await;
        let ServerMessage::Account(r) = c
            .expect("the answer", |m| {
                matches!(
                    m,
                    ServerMessage::Account(AccountReply::Admin(_))
                        | ServerMessage::Account(AccountReply::Error { .. })
                )
            })
            .await
        else {
            unreachable!()
        };
        r
    }

    fn save(id: Option<u32>, name: &str, text: bool, category: Option<u32>) -> AdminOp {
        AdminOp::ChannelSave {
            id,
            name: name.into(),
            description: String::new(),
            text,
            auto_join: false,
            category,
            gate: None,
        }
    }

    async fn made(c: &mut Client, op: AdminOp) -> u32 {
        match relay_op(c, op, None).await {
            AccountReply::Admin(AdminReply::ChannelDone {
                channel_id: Some(id),
            }) => id,
            other => panic!("{other:?}"),
        }
    }

    async fn ok(c: &mut Client, op: AdminOp) {
        let r = relay_op(c, op, None).await;
        assert!(
            matches!(r, AccountReply::Admin(AdminReply::ChannelDone { .. })),
            "{r:?}"
        );
    }

    async fn refused(c: &mut Client, op: AdminOp) -> String {
        match relay_op(c, op, None).await {
            AccountReply::Error { reason, .. } => reason,
            other => panic!("not refused: {other:?}"),
        }
    }

    /// The next layout this client hears.
    async fn layout(c: &mut Client) -> (Vec<ChannelCategory>, Vec<ChannelPlace>) {
        let ServerMessage::ChannelLayout {
            categories,
            channels,
        } = c
            .expect("the layout", |m| {
                matches!(m, ServerMessage::ChannelLayout { .. })
            })
            .await
        else {
            unreachable!()
        };
        (categories, channels)
    }

    /// What a start does, on the same database, with `file` as channels.json.
    async fn restart(db: &TempDb, file: Vec<ChannelEntry>) -> Arc<ServerState> {
        let mut config = ServerConfig::default();
        config.accounts.mode = AccountsMode::Optional;
        config.accounts.registration = RegistrationMode::Open;
        let store = l4f_accounts::store::Store::connect(&format!("sqlite://{}", db.0.display()))
            .await
            .unwrap();
        let relay = crate::accounts::Relay::open_with(&config.accounts, store, &[9u8; 32])
            .await
            .unwrap();
        let kept = relay.layout_rows().await.unwrap();
        let mut entries = file;
        let apps = crate::layout::merge_kept(&kept, &mut entries);
        let mut state = ServerState::new(
            &config,
            ServerSettings::default(),
            entries,
            "test-admin-token".into(),
        );
        state.accounts = Some(Arc::new(relay));
        crate::layout::load(&state, kept, &apps).await;
        crate::accounts::locked_logs_at_boot(&state).await.unwrap();
        crate::gates::load(&state).await.unwrap();
        Arc::new(state)
    }

    async fn named(state: &ServerState, name: &str) -> Option<(u32, String, ChannelGate, bool)> {
        let channels = state.channels.read().await;
        channels.values().find(|c| c.info.name == name).map(|c| {
            (
                c.info.channel_id,
                c.gate_key.clone(),
                c.gate.clone(),
                c.kept,
            )
        })
    }

    #[tokio::test]
    async fn a_channel_made_in_the_app_survives_a_restart_with_its_place_and_its_log() {
        let (state, db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        ok(
            &mut m,
            AdminOp::CategorySave {
                id: None,
                name: "Games".into(),
            },
        )
        .await;
        let id = made(&mut m, save(None, "news", true, Some(1))).await;
        let (_, conv, _, kept) = named(&state, "news").await.unwrap();
        assert!(kept);
        assert!(
            conv.starts_with("c:") && conv.len() == 34,
            "its own uid, not its name's hash: {conv}"
        );

        let (categories, places) = layout_of(&state, "mona").await;
        assert_eq!(categories[0].name, "Games");
        let place = places.iter().find(|p| p.channel_id == id).unwrap();
        assert_eq!((place.category, place.kept), (Some(1), true));

        let again = restart(&db, Vec::new()).await;
        let (_, conv2, _, kept2) = named(&again, "news").await.expect("back after a restart");
        assert_eq!(conv2, conv, "the same log");
        assert!(kept2);
        let l = again.layout.read().await;
        assert_eq!(l.categories[0].name, "Games");
        assert_eq!(l.places.get(&conv).unwrap().category, Some(1));
    }

    /// A rename keeps the channel's log and gate: they go by its uid.
    #[tokio::test]
    async fn a_rename_keeps_the_log_and_reaches_the_row() {
        let (state, db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        let id = made(&mut m, save(None, "news", true, None)).await;
        let (_, conv, _, _) = named(&state, "news").await.unwrap();
        ok(&mut m, save(Some(id), "headlines", true, None)).await;
        assert!(named(&state, "news").await.is_none());
        let (_, renamed, _, _) = named(&state, "headlines").await.unwrap();
        assert_eq!(renamed, conv);
        let again = restart(&db, Vec::new()).await;
        assert_eq!(named(&again, "headlines").await.unwrap().1, conv);
    }

    /// `SetChannelOptions` was written with the file's channels in mind, which
    /// forget at a restart: a channel made in the app must not.
    #[tokio::test]
    async fn an_option_changed_in_the_ordinary_way_survives_a_restart() {
        let (state, db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        let id = made(&mut m, save(None, "news", true, None)).await;
        crate::session::channel_updated(&state, {
            let mut channels = state.channels.write().await;
            let c = channels.get_mut(&id).unwrap();
            c.info.slow_mode_secs = 30;
            c.info.clone()
        })
        .await;
        let again = restart(&db, Vec::new()).await;
        let (id2, ..) = named(&again, "news").await.unwrap();
        assert_eq!(again.channels.read().await[&id2].info.slow_mode_secs, 30);
    }

    #[tokio::test]
    async fn only_who_manages_channels_may_change_them() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut plain, _) = register(&state, "pete").await;
        for op in [
            save(None, "news", true, None),
            AdminOp::CategorySave {
                id: None,
                name: "x".into(),
            },
            AdminOp::LayoutSet {
                categories: vec![],
                channels: vec![],
            },
            AdminOp::WelcomeSet { channel_id: None },
        ] {
            let why = refused(&mut plain, op).await;
            assert!(why.contains("may not"), "{why}");
        }
    }

    /// Telling people first and gating after would say the channel exists, and a
    /// category named after what is gated says it just the same.
    #[tokio::test]
    async fn a_gated_channel_and_its_category_stay_hidden() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        let (mut outsider, _) = register(&state, "pete").await;
        ok(
            &mut m,
            AdminOp::CategorySave {
                id: None,
                name: "Staff".into(),
            },
        )
        .await;
        // The manager has to pass the gate it sets
        grant(
            &state,
            state
                .account_sessions
                .iter()
                .min_by_key(|e| *e.value())
                .map(|e| *e.value())
                .unwrap(),
            &["*"],
        );
        let id = made(
            &mut m,
            AdminOp::ChannelSave {
                id: None,
                name: "secret".into(),
                description: String::new(),
                text: true,
                auto_join: false,
                category: Some(1),
                gate: Some(ChannelGate {
                    groups: vec!["moderator".into()],
                    speakers: vec![],
                }),
            },
        )
        .await;
        let (categories, places) = layout(&mut outsider).await;
        let (categories2, places2) = layout(&mut outsider).await;
        for (cats, seen) in [(&categories, &places), (&categories2, &places2)] {
            assert!(cats.is_empty(), "a category says what is hidden: {cats:?}");
            assert!(!seen.iter().any(|p| p.channel_id == id));
        }
        // And nothing else has told it
        outsider.send(&ClientMessage::Ping { timestamp: 5 }).await;
        loop {
            match outsider.next().await.unwrap() {
                ServerMessage::ChannelCreated { channel } => {
                    assert_ne!(channel.name, "secret", "told an outsider")
                }
                ServerMessage::Pong { timestamp: 5 } => break,
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn the_files_channels_are_placed_but_not_renamed_or_removed() {
        let (state, _db) = relay_state_then(AccountsMode::Optional, RegistrationMode::Open, |s| {
            let entry = ChannelEntry {
                name: "lobby".into(),
                text: true,
                ..ChannelEntry::default()
            };
            let mut c = crate::state::Channel::from_entry(&entry, 7, true, true);
            c.kept = false;
            s.channels.get_mut().insert(7, c);
        })
        .await;
        let mut m = manager(&state, "mona").await;
        let why = refused(&mut m, save(Some(7), "renamed", true, None)).await;
        assert!(why.contains("channels.json"), "{why}");
        ok(
            &mut m,
            AdminOp::CategorySave {
                id: None,
                name: "Cat".into(),
            },
        )
        .await;
        ok(
            &mut m,
            AdminOp::LayoutSet {
                categories: vec![1],
                channels: vec![(7, Some(1))],
            },
        )
        .await;
        let conv = state.channels.read().await[&7].gate_key.clone();
        assert_eq!(state.layout.read().await.places[&conv].category, Some(1));
    }

    /// Everything kept in it goes, and it takes a fresh code.
    #[tokio::test]
    async fn deleting_takes_a_code_and_everything_kept_goes_with_it() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut m, _) = register(&state, "mona").await;
        // Before the grant: turning codes on reads the account's roles again
        let secret = totp_on(&mut m).await;
        m.send(&ClientMessage::Ping { timestamp: 1 }).await;
        m.expect("that done", |r| {
            matches!(r, ServerMessage::Pong { timestamp: 1 })
        })
        .await;
        let sid = state
            .account_sessions
            .iter()
            .next()
            .map(|e| *e.value())
            .unwrap();
        grant(&state, sid, &["voipc:channels"]);
        let id = made(&mut m, save(None, "news", true, None)).await;
        let (_, conv, _, _) = named(&state, "news").await.unwrap();
        let relay = state.accounts.as_deref().unwrap();
        crate::accounts::raw(
            relay,
            &format!("INSERT INTO voipc_gates (conv, may_join, may_speak) VALUES ('{conv}', 'crew', '') RETURNING 1"),
        )
        .await
        .unwrap();

        let asked = relay_op(&mut m, AdminOp::ChannelDelete { id }, None).await;
        assert!(
            matches!(asked, AccountReply::Admin(AdminReply::StepUp)),
            "{asked:?}"
        );
        assert!(
            named(&state, "news").await.is_some(),
            "nothing happened yet"
        );

        let code = format!(
            "{:06}",
            l4f_accounts::totp::code_at(&secret, l4f_accounts::util::now() / 30 + 1)
        );
        let r = relay_op(&mut m, AdminOp::ChannelDelete { id }, Some(code)).await;
        assert!(
            matches!(r, AccountReply::Admin(AdminReply::ChannelDone { .. })),
            "{r:?}"
        );
        assert!(named(&state, "news").await.is_none());
        for table in ["voipc_channels", "voipc_gates"] {
            let n = crate::accounts::raw(
                relay,
                &format!("SELECT COUNT(*) FROM {table} WHERE conv = '{conv}'"),
            )
            .await
            .unwrap();
            assert_eq!(n, 0, "{table}");
        }
    }

    /// A file edited since must not stop the relay, and its row is not thrown away:
    /// take the clash out of the file and the channel is back.
    #[tokio::test]
    async fn a_kept_channel_that_clashes_with_the_file_waits_and_stops_nothing() {
        let (state, db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        made(&mut m, save(None, "news", true, None)).await;
        let (_, conv, ..) = named(&state, "news").await.unwrap();
        let file = vec![ChannelEntry {
            name: "NEWS".into(),
            text: true,
            ..ChannelEntry::default()
        }];
        let clashed = restart(&db, file).await;
        let (_, theirs, _, kept) = named(&clashed, "NEWS").await.unwrap();
        assert!(!kept && theirs != conv, "the file's own");
        assert!(named(&clashed, "news").await.is_none());
        let back = restart(&db, Vec::new()).await;
        assert!(named(&back, "news").await.is_some());
    }

    /// A row that does not read is the same: left out, and the start goes on.
    #[tokio::test]
    async fn a_row_that_does_not_read_stops_nothing() {
        let (state, db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let relay = state.accounts.as_deref().unwrap();
        crate::accounts::raw(
            relay,
            "INSERT INTO voipc_channels (conv, entry, position) VALUES ('c:x', 'not json', 1) RETURNING 1",
        )
        .await
        .unwrap();
        let again = restart(&db, Vec::new()).await;
        assert_eq!(again.channels.read().await.len(), 1, "General alone");
    }

    /// The fingerprint at a start compares what only a start writes: a password set
    /// in the app would look changed, and every stored member would be dropped.
    #[tokio::test]
    async fn a_restart_keeps_the_members_of_a_kept_channel_with_a_password() {
        let (state, db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        let id = made(&mut m, save(None, "news", true, None)).await;
        let (_, conv, ..) = named(&state, "news").await.unwrap();
        crate::session::channel_updated(&state, {
            let mut channels = state.channels.write().await;
            let c = channels.get_mut(&id).unwrap();
            // A hash a start accepts: an invalid one leaves the channel out, and then
            // nothing here would be testing the rule
            let hash = format!("sha256:{}", "ab".repeat(32));
            c.password = Some(zeroize::Zeroizing::new(hash));
            c.info.has_password = true;
            c.info.clone()
        })
        .await;
        let relay = state.accounts.as_deref().unwrap();
        let account = state
            .account_sessions
            .iter()
            .next()
            .map(|e| hex::encode(e.key()))
            .unwrap();
        crate::accounts::raw(
            relay,
            &format!(
                "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{conv}', X'{account}', 1) RETURNING 1"
            ),
        )
        .await
        .unwrap();
        let again = restart(&db, Vec::new()).await;
        assert!(named(&again, "news").await.is_some_and(|c| c.3), "it came back, as the app's");
        let n = crate::accounts::raw(
            again.accounts.as_deref().unwrap(),
            &format!("SELECT COUNT(*) FROM voipc_members WHERE conv = '{conv}'"),
        )
        .await
        .unwrap();
        assert_eq!(n, 1);
    }

    /// One who cannot see a gated channel cannot move it, and reordering what they
    /// can see leaves it where it was.
    #[tokio::test]
    async fn a_reorder_leaves_what_the_editor_cannot_see_in_place() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        let a = made(&mut m, save(None, "aa", true, None)).await;
        let hidden = made(&mut m, save(None, "hidden", true, None)).await;
        let b = made(&mut m, save(None, "bb", true, None)).await;
        let (_, hidden_conv, ..) = named(&state, "hidden").await.unwrap();
        let before = state.layout.read().await.places[&hidden_conv].position;
        state
            .channels
            .write()
            .await
            .get_mut(&hidden)
            .unwrap()
            .gate
            .groups = vec!["crew".into()];
        ok(
            &mut m,
            AdminOp::LayoutSet {
                categories: vec![],
                channels: vec![(b, None), (a, None), (hidden, None)],
            },
        )
        .await;
        let l = state.layout.read().await;
        assert_eq!(l.places[&hidden_conv].position, before, "not touched");
        let channels = state.channels.read().await;
        let pos = |id: u32| l.places[&channels[&id].gate_key].position;
        assert!(pos(b) < pos(a), "swapped");
    }

    #[tokio::test]
    async fn the_welcome_channel_is_a_kept_text_channel_anyone_can_open() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        let voice = made(&mut m, save(None, "talk", false, None)).await;
        let text = made(&mut m, save(None, "rules", true, None)).await;
        let why = refused(
            &mut m,
            AdminOp::WelcomeSet {
                channel_id: Some(voice),
            },
        )
        .await;
        assert!(why.contains("text channel"), "{why}");
        ok(
            &mut m,
            AdminOp::WelcomeSet {
                channel_id: Some(text),
            },
        )
        .await;
        let (_, places) = layout_of(&state, "mona").await;
        assert_eq!(places.iter().find(|p| p.welcome).unwrap().channel_id, text);
    }

    #[tokio::test]
    async fn a_list_that_would_not_fit_is_refused_when_it_is_asked_for() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let mut m = manager(&state, "mona").await;
        // Past the 60 KiB one list holds: full descriptions, directly
        {
            let mut channels = state.channels.write().await;
            for i in 0..250u32 {
                let entry = ChannelEntry {
                    name: format!("filler-{i}"),
                    description: "d".repeat(256),
                    ..ChannelEntry::default()
                };
                channels.insert(
                    1000 + i,
                    crate::state::Channel::from_entry(&entry, 1000 + i, true, true),
                );
            }
        }
        let why = refused(&mut m, save(None, "one-more", true, None)).await;
        assert!(why.contains("One channel list"), "{why}");
    }

    /// With too many at a start, the newest made in the app wait; the rest serve.
    #[tokio::test]
    async fn a_start_past_what_one_list_holds_leaves_out_the_newest_made_here() {
        let (state, db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let relay = state.accounts.as_deref().unwrap();
        for i in 0..250i64 {
            let entry = ChannelEntry {
                name: format!("kept-{i}"),
                description: "d".repeat(256),
                uid: Some(format!("u{i}")),
                ..ChannelEntry::default()
            };
            relay
                .layout_put(&entry.log_conv(), Some(&entry), i, None)
                .await
                .unwrap();
        }
        let again = restart(&db, Vec::new()).await;
        let list = again.channel_list().await;
        assert!(list.len() < 251, "some wait: {}", list.len());
        assert!(list.iter().any(|c| c.name == "kept-0"), "the oldest stay");
        assert!(
            !list.iter().any(|c| c.name == "kept-249"),
            "the newest wait"
        );
        let framed = encode_server_msg(&ServerMessage::ChannelList { channels: list }).unwrap();
        assert!(framed.len() <= 60 * 1024);
    }
}

/// Group colours and order (1.9).
mod group_styles {
    use super::*;
    use voipc_protocol::types::GroupStyle;

    fn styled(badge: &str, color: Option<u32>) -> GroupStyle {
        GroupStyle {
            badge: badge.into(),
            color,
            section: true,
        }
    }

    async fn answer(c: &mut Client, op: AdminOp) -> AccountReply {
        c.send(&admin_op(op, None)).await;
        let ServerMessage::Account(r) = c.expect("the answer", admin_answer).await else {
            unreachable!()
        };
        r
    }

    async fn styles(c: &mut Client) -> Vec<GroupStyle> {
        let ServerMessage::GroupStyles { groups } = c
            .expect("the styles", |m| {
                matches!(m, ServerMessage::GroupStyles { .. })
            })
            .await
        else {
            unreachable!()
        };
        groups
    }

    /// An account holding `roles:admin` and nothing more, with codes on.
    async fn group_keeper(state: &Arc<ServerState>, name: &str) -> (Client, AccountInfo) {
        group(state, "keepers", None, &["roles:admin"]).await;
        let (mut c, info) = register(state, name).await;
        totp_on(&mut c).await;
        give(state, info.id, "keepers", true).await;
        (c, info)
    }

    #[tokio::test]
    async fn colour_and_order_reach_everybody_and_outlast_a_connection() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        group(&state, "lead", Some("Lead"), &[]).await;
        group(&state, "quiet", None, &[]).await;
        let (mut ann, _, _) = admin_account(&state, "ann").await;
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut guest = connect(&state, "guest#1234", lo).await;
        assert_eq!(
            styles(&mut guest).await,
            [styled("mod", None), styled("Crew", None), styled("Lead", None)],
            "those with privileges first, then by name, and a group with no badge is not told"
        );

        answer(
            &mut ann,
            AdminOp::GroupStyle {
                name: "lead".into(),
                color: Some(0xff8800),
                section: true,
            },
        )
        .await;
        assert_eq!(
            styles(&mut guest).await,
            [styled("mod", None), styled("Crew", None), styled("Lead", Some(0xff8800))]
        );

        let names = ["lead", "admin", "crew", "moderator", "quiet", "user"]
            .map(String::from)
            .to_vec();
        let reply = answer(
            &mut ann,
            AdminOp::GroupOrder {
                names: names.clone(),
            },
        )
        .await;
        let AccountReply::Admin(AdminReply::Groups { groups }) = reply else {
            panic!("{reply:?}");
        };
        assert_eq!(
            groups.iter().map(|g| g.name.clone()).collect::<Vec<_>>(),
            names,
            "the panel lists them as the server shows them"
        );
        assert_eq!(
            styles(&mut guest).await,
            [
                styled("Lead", Some(0xff8800)),
                styled("Crew", None),
                styled("mod", None)
            ]
        );

        // A colour later keeps the place, and a place the colour
        answer(
            &mut ann,
            AdminOp::GroupStyle {
                name: "crew".into(),
                color: Some(1),
                section: true,
            },
        )
        .await;
        assert_eq!(
            styles(&mut guest).await,
            [
                styled("Lead", Some(0xff8800)),
                styled("Crew", Some(1)),
                styled("mod", None)
            ]
        );

        let mut late = connect(&state, "late#1234", lo).await;
        assert_eq!(
            styles(&mut late).await,
            [
                styled("Lead", Some(0xff8800)),
                styled("Crew", Some(1)),
                styled("mod", None)
            ],
            "told at connect"
        );
    }

    #[tokio::test]
    async fn the_top_badges_are_the_ones_a_row_keeps() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        for (name, badge) in [("a1", "A"), ("b2", "B"), ("c3", "C"), ("d4", "D")] {
            group(&state, name, Some(badge), &[]).await;
        }
        let (mut ann, _, _) = admin_account(&state, "ann").await;
        let (_bob, bi) = register(&state, "bob").await;
        for g in ["a1", "b2", "c3", "d4"] {
            give(&state, bi.id, g, true).await;
        }
        let relay = state.accounts.clone().unwrap();
        let bob = relay
            .store()
            .user_by_id(AccountId(bi.id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            relay.standing(&bob, &[]).await.unwrap().badges,
            ["A", "B", "C"]
        );

        let names = ["d4", "c3", "admin", "b2", "a1", "moderator", "user"]
            .map(String::from)
            .to_vec();
        answer(&mut ann, AdminOp::GroupOrder { names }).await;
        let standing = relay.standing(&bob, &[]).await.unwrap();
        assert_eq!(standing.badges, ["D", "C", "B"]);
        assert_eq!(
            standing.groups.len(),
            5,
            "the order cuts badges, never groups"
        );
    }

    #[tokio::test]
    async fn nobody_styles_or_climbs_over_a_group_they_could_not_make() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        group(&state, "mods", Some("Mod"), &["voipc:kick"]).await;
        group(&state, "team", Some("Team"), &[]).await;
        let (mut kim, _) = group_keeper(&state, "kim").await;
        let (mut bob, _) = register(&state, "bob").await;

        // Holding nothing: not even a colour
        let r = answer(
            &mut bob,
            AdminOp::GroupStyle {
                name: "crew".into(),
                color: Some(1),
                section: true,
            },
        )
        .await;
        assert!(matches!(r, AccountReply::Error { .. }), "{r:?}");
        let r = answer(&mut bob, AdminOp::GroupOrder { names: vec![] }).await;
        assert!(matches!(r, AccountReply::Error { .. }), "{r:?}");

        // Holding `roles:admin`: not a group with more in it than they hold
        let r = answer(
            &mut kim,
            AdminOp::GroupStyle {
                name: "mods".into(),
                color: Some(1),
                section: true,
            },
        )
        .await;
        assert!(matches!(r, AccountReply::Error { .. }), "{r:?}");
        let r = answer(
            &mut kim,
            AdminOp::GroupStyle {
                name: "crew".into(),
                color: Some(0x100_0000),
                section: true,
            },
        )
        .await;
        assert!(
            matches!(r, AccountReply::Error { .. }),
            "not a colour: {r:?}"
        );
        let r = answer(
            &mut kim,
            AdminOp::GroupStyle {
                name: "crew".into(),
                color: Some(1),
                section: true,
            },
        )
        .await;
        assert!(
            matches!(r, AccountReply::Admin(AdminReply::Groups { .. })),
            "{r:?}"
        );

        // `admin`, `moderator` and `mods` are out of kim's reach: each stays where it
        // is, and nothing crosses one. Between them she moves what she likes.
        let relay = state.accounts.clone().unwrap();
        let now: Vec<String> = relay
            .groups_in_order()
            .await
            .unwrap()
            .into_iter()
            .map(|(r, _)| r.name)
            .collect();
        let at = |name: &str| now.iter().position(|n| n == name).unwrap();
        assert!(at("mods") < at("crew") && at("mods") < at("team"), "{now:?}");
        assert!(at("keepers") < at("moderator"), "{now:?}");
        let swapped = |a: &str, b: &str| {
            let mut names = now.clone();
            names.swap(at(a), at(b));
            names
        };
        let order = |names: Vec<String>| AdminOp::GroupOrder { names };

        let r = answer(&mut kim, order(swapped("admin", "keepers"))).await;
        assert!(matches!(r, AccountReply::Error { .. }), "moves the admins: {r:?}");
        let r = answer(&mut kim, order(swapped("team", "keepers"))).await;
        assert!(matches!(r, AccountReply::Error { .. }), "team past mods: {r:?}");
        let mut short = now.clone();
        short.pop();
        let r = answer(&mut kim, order(short.clone())).await;
        assert!(matches!(r, AccountReply::Error { .. }), "one short: {r:?}");
        short.push(short[0].clone());
        let r = answer(&mut kim, order(short)).await;
        assert!(matches!(r, AccountReply::Error { .. }), "one twice: {r:?}");

        let wanted = swapped("crew", "team");
        let r = answer(&mut kim, order(wanted.clone())).await;
        assert!(matches!(r, AccountReply::Admin(AdminReply::Groups { .. })), "{r:?}");
        let shown: Vec<String> = relay
            .groups_in_order()
            .await
            .unwrap()
            .into_iter()
            .map(|(r, _)| r.name)
            .collect();
        assert_eq!(shown, wanted);
    }

    #[tokio::test]
    async fn a_name_is_no_way_to_climb_and_one_badge_on_two_groups_is_one_badge() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "00-mine", Some("Mine"), &[]).await;
        group(&state, "staff-a", Some("Staff"), &[]).await;
        group(&state, "staff-b", Some("Staff"), &[]).await;
        let relay = state.accounts.clone().unwrap();
        let names: Vec<String> = relay
            .groups_in_order()
            .await
            .unwrap()
            .into_iter()
            .map(|(r, _)| r.name)
            .collect();
        let at = |name: &str| names.iter().position(|n| n == name).unwrap();
        assert!(at("admin") < at("00-mine") && at("moderator") < at("00-mine"), "{names:?}");

        // A row draws its badges keyed by their text, so a repeat would stop every
        // client showing this member
        let (_bob, bi) = register(&state, "bob").await;
        give(&state, bi.id, "staff-a", true).await;
        give(&state, bi.id, "staff-b", true).await;
        let bob = relay.store().user_by_id(AccountId(bi.id)).await.unwrap().unwrap();
        let standing = relay.standing(&bob, &[]).await.unwrap();
        assert_eq!(standing.badges, ["Staff"]);
        assert_eq!(standing.my_badges, ["Staff"]);
        let styles = relay.group_styles().await.unwrap();
        assert_eq!(styles.iter().filter(|s| s.badge == "Staff").count(), 1);
    }

    #[tokio::test]
    async fn a_groups_section_can_be_turned_off_and_keeps_its_colour_and_place() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        let (mut ann, _, _) = admin_account(&state, "ann").await;
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut guest = connect(&state, "guest#1234", lo).await;
        let crew_of = |list: Vec<GroupStyle>| list.into_iter().find(|s| s.badge == "Crew").unwrap();
        assert!(crew_of(styles(&mut guest).await).section, "on until someone turns it off");

        let r = answer(
            &mut ann,
            AdminOp::GroupStyle {
                name: "crew".into(),
                color: Some(7),
                section: false,
            },
        )
        .await;
        assert!(matches!(r, AccountReply::Admin(AdminReply::Groups { .. })), "{r:?}");
        let crew = crew_of(styles(&mut guest).await);
        assert_eq!((crew.color, crew.section), (Some(7), false));

        // Moving it changes neither, and someone arriving later hears the same
        let relay = state.accounts.clone().unwrap();
        let mut names: Vec<String> = relay
            .groups_in_order()
            .await
            .unwrap()
            .into_iter()
            .map(|(r, _)| r.name)
            .collect();
        names.reverse();
        answer(&mut ann, AdminOp::GroupOrder { names }).await;
        let mut late = connect(&state, "late#1234", lo).await;
        let crew = crew_of(styles(&mut late).await);
        assert_eq!((crew.color, crew.section), (Some(7), false));
    }

    #[tokio::test]
    async fn a_deleted_group_takes_its_style_along() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        let (mut ann, _, _) = admin_account(&state, "ann").await;
        let relay = state.accounts.clone().unwrap();
        answer(
            &mut ann,
            AdminOp::GroupStyle {
                name: "crew".into(),
                color: Some(7),
                section: true,
            },
        )
        .await;
        let crew = relay.store().role_by_name("crew").await.unwrap().unwrap();
        relay.store().delete_role(crew.id).await.unwrap();
        group(&state, "crew", Some("Crew"), &[]).await;
        assert_eq!(
            relay.group_styles().await.unwrap(),
            [styled("mod", None), styled("Crew", None)]
        );
    }
}

/// Display names and pictures (1.9).
mod profiles {
    use super::*;
    use sha2::Digest;
    use voipc_protocol::types::{ProfileInfo, MAX_PROFILE_PICTURE};

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nnot really";

    async fn answer(c: &mut Client, request: AccountRequest) -> AccountReply {
        c.send(&ClientMessage::Account(request)).await;
        let ServerMessage::Account(r) = c
            .expect("the answer", |m| {
                matches!(
                    m,
                    ServerMessage::Account(AccountReply::ProfileDone)
                        | ServerMessage::Account(AccountReply::Error { .. })
                )
            })
            .await
        else {
            unreachable!()
        };
        r
    }

    async fn name_is(c: &mut Client, name: &str) -> AccountReply {
        answer(
            c,
            AccountRequest::ProfileSet {
                name: Some(name.into()),
            },
        )
        .await
    }

    async fn profiles(c: &mut Client) -> Vec<ProfileInfo> {
        let ServerMessage::Profiles { profiles } = c
            .expect("profiles", |m| matches!(m, ServerMessage::Profiles { .. }))
            .await
        else {
            unreachable!()
        };
        profiles
    }

    async fn asked(c: &mut Client, accounts: &[[u8; 16]]) -> Vec<ProfileInfo> {
        c.send(&ClientMessage::ProfilesGet {
            accounts: accounts.to_vec(),
        })
        .await;
        profiles(c).await
    }

    async fn picture(c: &mut Client, hash: [u8; 32]) -> Vec<u8> {
        c.send(&ClientMessage::ProfilePictureGet { hash }).await;
        let ServerMessage::ProfilePicture { image, .. } = c
            .expect("the picture", |m| {
                matches!(m, ServerMessage::ProfilePicture { .. })
            })
            .await
        else {
            unreachable!()
        };
        image
    }

    #[tokio::test]
    async fn anyone_may_read_online_or_not_and_no_account_reads_as_no_profile() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut ann, ai) = register(&state, "ann").await;
        assert!(matches!(
            name_is(&mut ann, "Ann Example").await,
            AccountReply::ProfileDone
        ));
        drop(ann);
        while state.account_sessions.contains_key(&ai.id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let mut guest = connect(&state, "guest#1234", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let got = asked(&mut guest, &[ai.id, [7; 16]]).await;
        assert_eq!(got[0].name.as_deref(), Some("Ann Example"), "ann has left");
        assert_eq!(got[1].account, [7; 16]);
        assert_eq!(got[1].name, None);
    }

    #[tokio::test]
    async fn too_many_at_once_are_not_read() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut ann, ai) = register(&state, "ann").await;
        ann.send(&ClientMessage::ProfilesGet {
            accounts: vec![[1; 16]; 65],
        })
        .await;
        assert_eq!(asked(&mut ann, &[ai.id]).await.len(), 1);
    }

    #[tokio::test]
    async fn a_name_cannot_pass_for_someone_elses() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_bob, _) = register(&state, "bobby").await;
        let (mut ann, ai) = register(&state, "ann").await;
        // This is about the names, not how many are tried
        let sid = *state.account_sessions.get(&ai.id).unwrap();
        state.sessions.get_mut(&sid).unwrap().state_change_rate =
            crate::state::RateLimiter::new(100.0, 100.0);
        for bad in [
            "@bobby",
            "bobby",
            "BOBBY",
            "bobby\u{2800}",
            "bobby\u{E0061}",
            "bobby#1234 \u{2800}",
            "bobby\u{1BCA0}",
            "b\u{34F}obby",
            "bobby\u{FE0F}",
            "\u{FF20}bobby",
            "\u{FE6B}bobby",
            "bobby\u{FF03}1234",
            "Bobby @bobby",
            "Support @alice",
            "\u{2800}",
            "b\u{043E}bby", // a Cyrillic o
            "bobby#1234",
            "Admin\u{202E}nimdA",
            "a\u{200B}b",
            &"x".repeat(33),
        ] {
            let r = name_is(&mut ann, bad).await;
            assert!(matches!(r, AccountReply::Error { .. }), "{bad:?}: {r:?}");
        }
        for fine in [
            "\u{2764}\u{FE0F} Ann",
            "\u{1F469}\u{200D}\u{1F4BB} Ann",
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}",
            "ann",
            "ANN",
            "Jürgen",
            "Ann Example",
            "Bob the builder",
            "日本語の名前",
        ] {
            let r = name_is(&mut ann, fine).await;
            assert!(matches!(r, AccountReply::ProfileDone), "{fine:?}: {r:?}");
        }
        name_is(&mut ann, "  ").await;
        assert_eq!(
            asked(&mut ann, &[ai.id]).await[0].name,
            None,
            "blank clears"
        );
    }

    #[tokio::test]
    async fn saying_the_same_again_tells_nobody_and_changing_it_over_and_over_is_stopped() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut ann, ai) = register(&state, "ann").await;
        name_is(&mut ann, "Same").await;
        let relay = state.accounts.clone().unwrap();
        let sid = *state.account_sessions.get(&ai.id).unwrap();
        // Its budget at nothing: a repeat needs none of it
        state
            .sessions
            .get_mut(&sid)
            .unwrap()
            .state_change_rate = crate::state::RateLimiter::new(1.0, 0.0);
        assert!(matches!(name_is(&mut ann, "Same").await, AccountReply::ProfileDone));
        assert!(matches!(name_is(&mut ann, "Other").await, AccountReply::ProfileDone));
        assert!(matches!(name_is(&mut ann, "Third").await, AccountReply::Error { .. }));
        assert_eq!(
            relay.profiles(&[ai.id]).await.unwrap()[0].name.as_deref(),
            Some("Other")
        );
    }

    #[test]
    fn a_servers_name_may_not_read_as_an_address_in_any_of_its_words() {
        use crate::accounts::profile::server_name_ok as ok;
        for bad in [
            "ivy.l4f.cc",
            "10.0.0.1:9987",
            "10.0.0.1",
            "chat.example.org (official)",
            "voipc.example.com :443",
            "[::1]:9987",
            "the real ivy.l4f.cc",
        ] {
            assert!(ok(bad).is_err(), "{bad}");
        }
        for fine in ["Night Owls", "v1.2 Night Owls", "St. Pauli", "Dr. Who & co"] {
            assert!(ok(fine).is_ok(), "{fine}");
        }
    }

    #[test]
    fn the_address_test_agrees_with_the_clients_on_one_list() {
        // The same list is in client/src/lib/profile-rules.test.ts
        let text = include_str!("../../../client/src/lib/address-shapes.json");
        let shapes: serde_json::Value = serde_json::from_str(text).unwrap();
        for (want, list) in [(false, "fine"), (true, "address")] {
            for name in shapes[list].as_array().unwrap() {
                let name = name.as_str().unwrap();
                assert_eq!(
                    crate::accounts::profile::server_name_ok(name).is_err(),
                    want,
                    "{name}"
                );
            }
        }
    }

    /// Sets a name, and what the account itself heard before the answer.
    async fn told_itself(c: &mut Client, name: &str) -> Option<String> {
        c.send(&ClientMessage::Account(AccountRequest::ProfileSet {
            name: Some(name.into()),
        }))
        .await;
        let mut told = None;
        loop {
            match c.next().await.expect("connected") {
                ServerMessage::Profiles { profiles } => told = profiles[0].name.clone(),
                ServerMessage::Account(AccountReply::ProfileDone) => return told,
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn a_change_goes_to_the_people_who_see_the_row_and_to_nobody_else() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut ann, ai) = register(&state, "ann").await;
        let (mut bob, _) = register(&state, "bob").await;
        // Signing in is told before the join: who hears a change is who is there
        while state.channels.read().await[&0].members.len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(matches!(
            name_is(&mut ann, "Annie").await,
            AccountReply::ProfileDone
        ));
        assert_eq!(profiles(&mut bob).await[0].name.as_deref(), Some("Annie"));

        // Both are in General, which from here on hides its people
        state
            .channels
            .write()
            .await
            .get_mut(&0)
            .unwrap()
            .info
            .hide_members = true;
        assert_eq!(
            told_itself(&mut ann, "Annie 2").await.as_deref(),
            Some("Annie 2"),
            "its own other tabs and panels hear it all the same"
        );
        bob.send(&ClientMessage::ProfilesGet {
            accounts: vec![ai.id],
        })
        .await;
        assert_eq!(
            profiles(&mut bob).await[0].name.as_deref(),
            Some("Annie 2"),
            "what it asked for, and not a change pushed before that"
        );
        // Under an alias, the same
        {
            let mut channels = state.channels.write().await;
            let general = channels.get_mut(&0).unwrap();
            general.info.hide_members = false;
            general.info.anonymous = true;
        }
        assert!(matches!(
            name_is(&mut ann, "Annie 3").await,
            AccountReply::ProfileDone
        ));
        bob.send(&ClientMessage::ProfilesGet {
            accounts: vec![[9; 16]],
        })
        .await;
        assert_eq!(
            profiles(&mut bob).await[0].account,
            [9; 16],
            "no push came first"
        );
    }

    #[tokio::test]
    async fn a_picture_is_a_small_png_or_webp_and_is_fetched_by_its_hash() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut ann, ai) = register(&state, "ann").await;
        let set = |image: Option<Vec<u8>>| AccountRequest::ProfilePictureSet { image };

        for bad in [
            b"GIF89a.....".to_vec(),
            b"<svg onload=x>".to_vec(),
            Vec::new(),
            [PNG, &vec![0; MAX_PROFILE_PICTURE]].concat(),
        ] {
            let r = answer(&mut ann, set(Some(bad))).await;
            assert!(matches!(r, AccountReply::Error { .. }), "{r:?}");
        }
        let webp = b"RIFF\0\0\0\0WEBPrest".to_vec();
        assert!(matches!(
            answer(&mut ann, set(Some(webp))).await,
            AccountReply::ProfileDone
        ));
        assert!(matches!(
            answer(&mut ann, set(Some(PNG.to_vec()))).await,
            AccountReply::ProfileDone
        ));
        let hash = asked(&mut ann, &[ai.id]).await[0].picture.unwrap();
        assert_eq!(hash, <[u8; 32]>::from(sha2::Sha256::digest(PNG)));
        assert_eq!(picture(&mut ann, hash).await, PNG);
        assert!(
            picture(&mut ann, [3; 32]).await.is_empty(),
            "no such picture"
        );

        assert!(matches!(
            answer(&mut ann, set(None)).await,
            AccountReply::ProfileDone
        ));
        assert_eq!(asked(&mut ann, &[ai.id]).await[0].picture, None);
        assert!(picture(&mut ann, hash).await.is_empty(), "gone, not hidden");
    }

    async fn op(c: &mut Client, id: [u8; 16]) -> ServerMessage {
        c.send(&admin_op(
            AdminOp::ProfileReset {
                id,
                name: true,
                picture: true,
            },
            None,
        ))
        .await;
        c.expect("the answer", |m| {
            matches!(
                m,
                ServerMessage::Account(AccountReply::ProfileDone)
                    | ServerMessage::Account(AccountReply::Error { .. })
            )
        })
        .await
    }

    fn code(secret: &[u8], ahead: i64) -> String {
        format!(
            "{:06}",
            l4f_accounts::totp::code_at(secret, l4f_accounts::util::now() / 30 + ahead)
        )
    }

    async fn server_op(c: &mut Client, op: AdminOp, code: Option<String>) -> ServerMessage {
        c.send(&admin_op(op, code)).await;
        c.expect("the answer", |m| {
            matches!(
                m,
                ServerMessage::Account(AccountReply::ProfileDone)
                    | ServerMessage::Account(AccountReply::Admin(AdminReply::StepUp))
                    | ServerMessage::Account(AccountReply::Error { .. })
            )
        })
        .await
    }

    async fn told(c: &mut Client) -> (String, String, Option<[u8; 32]>) {
        let ServerMessage::ServerProfile {
            name,
            description,
            icon,
        } = c
            .expect("the server profile", |m| {
                matches!(m, ServerMessage::ServerProfile { .. })
            })
            .await
        else {
            unreachable!()
        };
        (name, description, icon)
    }

    #[tokio::test]
    async fn an_admin_names_the_server_with_a_fresh_code_and_everybody_hears() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut ann, _, secret) = admin_account(&state, "ann").await;
        let (mut bob, _) = register(&state, "bob").await;
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut guest = connect(&state, "guest#1234", lo).await;
        let set = || AdminOp::ServerProfileSet {
            name: "Night Owls".into(),
            description: "Second home.\nBe kind.".into(),
        };

        let r = server_op(&mut bob, set(), None).await;
        assert!(
            matches!(r, ServerMessage::Account(AccountReply::Error { .. })),
            "{r:?}"
        );
        let r = server_op(&mut ann, set(), None).await;
        assert!(
            matches!(
                r,
                ServerMessage::Account(AccountReply::Admin(AdminReply::StepUp))
            ),
            "{r:?}"
        );
        for bad in [
            "ivy.l4f.cc",
            "10.0.0.1:9987",
            "evil\u{202E}",
            &"x".repeat(33),
        ] {
            let op = AdminOp::ServerProfileSet {
                name: bad.into(),
                description: String::new(),
            };
            let r = server_op(&mut ann, op, Some(code(&secret, 1))).await;
            assert!(
                matches!(r, ServerMessage::Account(AccountReply::Error { .. })),
                "{bad:?}: {r:?}"
            );
        }
        let r = server_op(&mut ann, set(), Some(code(&secret, 1))).await;
        assert!(
            matches!(r, ServerMessage::Account(AccountReply::ProfileDone)),
            "{r:?}"
        );
        assert_eq!(told(&mut guest).await.0, "Night Owls");

        // Within the code's ten minutes: no second one
        let icon = PNG.to_vec();
        let r = server_op(&mut ann, AdminOp::ServerIconSet { image: Some(icon) }, None).await;
        assert!(
            matches!(r, ServerMessage::Account(AccountReply::ProfileDone)),
            "{r:?}"
        );
        let (_, _, hash) = told(&mut guest).await;
        let hash = hash.expect("an icon");
        assert_eq!(
            picture(&mut guest, hash).await,
            PNG,
            "fetched as a picture is"
        );

        let mut late = connect(&state, "late#1234", lo).await;
        let (name, description, icon) = told(&mut late).await;
        assert_eq!(name, "Night Owls");
        assert_eq!(description, "Second home.\nBe kind.");
        assert_eq!(icon, Some(hash));

        let r = server_op(&mut ann, AdminOp::ServerIconSet { image: None }, None).await;
        assert!(
            matches!(r, ServerMessage::Account(AccountReply::ProfileDone)),
            "{r:?}"
        );
        assert_eq!(told(&mut guest).await.2, None);
        assert!(picture(&mut guest, hash).await.is_empty(), "gone");
    }

    #[tokio::test]
    async fn a_relay_without_accounts_names_itself_in_its_settings_held_to_the_same_rules() {
        let mut state = ServerState::new(
            &ServerConfig::default(),
            ServerSettings {
                server_name: Some("Night Owls".into()),
                server_description: Some("Be kind.".into()),
                ..Default::default()
            },
            Vec::new(),
            "test-admin-token".into(),
        );
        let ServerMessage::ServerProfile {
            name,
            description,
            icon,
        } = crate::accounts::profile::server_profile(&state).await
        else {
            unreachable!()
        };
        assert_eq!(
            (name.as_str(), description.as_str(), icon),
            ("Night Owls", "Be kind.", None)
        );

        state.settings.server_name = Some("ivy.l4f.cc".into());
        let ServerMessage::ServerProfile { name, .. } =
            crate::accounts::profile::server_profile(&state).await
        else {
            unreachable!()
        };
        assert_eq!(name, "", "a bad one reads as none");
    }

    #[tokio::test]
    async fn a_reset_needs_the_privilege_spares_who_holds_more_and_is_written_down() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "wardens", None, &["voipc:profiles"]).await;
        let (mut kim, ki) = register(&state, "kim").await;
        totp_on(&mut kim).await;
        let (mut bob, bi) = register(&state, "bob").await;
        name_is(&mut bob, "Rude Name").await;
        let (mut ann, ai, _) = admin_account(&state, "ann").await;
        name_is(&mut ann, "The Owner").await;

        let refused =
            |m: &ServerMessage| matches!(m, ServerMessage::Account(AccountReply::Error { .. }));

        assert!(refused(&op(&mut kim, bi.id).await), "holds nothing yet");
        give(&state, ki.id, "wardens", true).await;
        assert!(!refused(&op(&mut kim, bi.id).await));
        assert_eq!(asked(&mut kim, &[bi.id]).await[0].name, None);
        assert!(refused(&op(&mut kim, ai.id).await), "the owner holds more");
        assert_eq!(
            asked(&mut kim, &[ai.id]).await[0].name.as_deref(),
            Some("The Owner")
        );

        // Clearing nothing is refused, and writes nothing
        let nothing = AdminOp::ProfileReset {
            id: bi.id,
            name: false,
            picture: false,
        };
        kim.send(&admin_op(nothing, None)).await;
        assert!(refused(&kim.expect("the answer", admin_answer).await));

        let relay = state.accounts.clone().unwrap();
        let audit = relay.store().audit_of(AccountId(bi.id), 50).await.unwrap();
        assert!(
            audit
                .iter()
                .any(|e| e.event == "profile_reset" && e.ip.is_empty()),
            "written down, without the mod's address"
        );
    }
}

/// What the review of 1.9's layouts found.
mod layout_limits {
    use super::*;
    use voipc_protocol::types::{ChannelCategory, ChannelGate, ChannelPlace};

    fn sid_of(state: &ServerState, account: [u8; 16]) -> SessionId {
        *state.account_sessions.get(&account).unwrap()
    }

    async fn layout_of(
        state: &ServerState,
        sid: SessionId,
    ) -> (Vec<ChannelCategory>, Vec<ChannelPlace>) {
        let ServerMessage::ChannelLayout {
            categories,
            channels,
        } = crate::layout::for_session(state, sid).await
        else {
            unreachable!()
        };
        (categories, channels)
    }

    /// A kept channel gated to `board`, in a category of its own, and that category.
    async fn hidden_channel(state: &Arc<ServerState>, sid: SessionId) -> (ChannelId, u32) {
        grant(state, sid, &["*"]);
        let id = crate::layout::channel_save(
            state, sid, None, "board-room", "", true, false, None, None,
        )
        .await
        .unwrap();
        let category = crate::layout::category_save(state, sid, None, "Board talks")
            .await
            .unwrap();
        crate::layout::layout_set(state, sid, &[], &[(id, Some(category))])
            .await
            .unwrap();
        group(state, "board", None, &[]).await;
        state.channels.write().await.get_mut(&id).unwrap().gate = ChannelGate {
            groups: vec!["board".into()],
            speakers: vec![],
        };
        grant(state, sid, &["voipc:channels"]);
        (id, category)
    }

    #[tokio::test]
    async fn one_layout_message_cannot_repeat_itself_into_the_list() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        grant(&state, sid, &["voipc:channels"]);
        let a = crate::layout::category_save(&state, sid, None, "A").await.unwrap();
        let b = crate::layout::category_save(&state, sid, None, "B").await.unwrap();
        let id = crate::layout::channel_save(&state, sid, None, "news", "", true, false, None, None)
            .await
            .unwrap();
        crate::layout::layout_set(&state, sid, &[b, b, a, b], &[(id, Some(b)), (id, Some(a))])
            .await
            .unwrap();
        let (categories, channels) = layout_of(&state, sid).await;
        assert_eq!(categories.iter().map(|c| c.id).collect::<Vec<_>>(), [b, a]);
        let news: Vec<_> = channels.iter().filter(|p| p.channel_id == id).collect();
        assert_eq!(news.len(), 1);
        assert_eq!(news[0].category, Some(b), "the first naming counts");
    }

    #[tokio::test]
    async fn categories_stop_where_one_message_still_holds_them() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        grant(&state, sid, &["voipc:channels"]);
        let name = |i: usize| format!("{i:0>64}");
        for i in 0..200 {
            crate::layout::category_save(&state, sid, None, &name(i)).await.unwrap();
        }
        let e = crate::layout::category_save(&state, sid, None, "one more")
            .await
            .unwrap_err();
        assert!(e.contains("200"), "{e}");
        let msg = crate::layout::for_session(&state, sid).await;
        assert!(encode_server_msg(&msg).is_ok(), "or nobody could see them to delete one");
    }

    #[tokio::test]
    async fn a_category_of_hidden_channels_does_not_exist_for_a_manager_outside_the_gate() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        let (_, hidden) = hidden_channel(&state, sid).await;
        let open = crate::layout::category_save(&state, sid, None, "Open").await.unwrap();
        let empty = crate::layout::category_save(&state, sid, None, "Empty").await.unwrap();

        let (categories, _) = layout_of(&state, sid).await;
        let ids: Vec<u32> = categories.iter().map(|c| c.id).collect();
        assert!(!ids.contains(&hidden), "its name says what the gate hides: {ids:?}");
        assert!(ids.contains(&open) && ids.contains(&empty), "the really empty ones show: {ids:?}");

        let no_such = "There is no such category.";
        assert_eq!(
            crate::layout::category_save(&state, sid, Some(hidden), "Mine").await.unwrap_err(),
            no_such
        );
        assert_eq!(
            crate::layout::category_delete(&state, sid, hidden).await.unwrap_err(),
            no_such
        );
        // Its slot stays its own, whatever they do to the others
        let before = state.layout.read().await.categories.iter().position(|c| c.id == hidden);
        crate::layout::layout_set(&state, sid, &[empty, open], &[]).await.unwrap();
        let after = state.layout.read().await.categories.clone();
        assert_eq!(after.iter().position(|c| c.id == hidden), before);
        let others: Vec<u32> = after.iter().map(|c| c.id).filter(|id| *id != hidden).collect();
        assert_eq!(others, [empty, open]);
    }

    #[tokio::test]
    async fn deleting_a_category_does_not_move_a_channel_the_editor_cannot_see() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        let (hidden_id, category) = hidden_channel(&state, sid).await;
        // Someone who sees everything put a channel the editor sees in there too
        grant(&state, sid, &["*"]);
        let seen = crate::layout::channel_save(&state, sid, None, "open-one", "", true, false, None, None)
            .await
            .unwrap();
        crate::layout::layout_set(&state, sid, &[], &[(seen, Some(category))]).await.unwrap();
        grant(&state, sid, &["voipc:channels"]);
        assert!(crate::layout::category_delete(&state, sid, category).await.is_err());
        let conv = state.channels.read().await[&hidden_id].gate_key.clone();
        assert_eq!(
            state.layout.read().await.places[&conv].category,
            Some(category),
            "still in it"
        );
    }

    #[tokio::test]
    async fn a_hidden_categorys_name_cannot_be_read_by_moving_something_into_it() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        let (_, hidden) = hidden_channel(&state, sid).await;
        let mine = crate::layout::channel_save(&state, sid, None, "mine", "", true, false, None, None)
            .await
            .unwrap();
        let no_such = "There is no such category.";
        assert_eq!(
            crate::layout::layout_set(&state, sid, &[], &[(mine, Some(hidden))])
                .await
                .unwrap_err(),
            no_such
        );
        assert_eq!(
            crate::layout::channel_save(&state, sid, Some(mine), "mine", "", true, false, Some(hidden), None)
                .await
                .unwrap_err(),
            no_such
        );
        assert_eq!(
            crate::layout::layout_set(&state, sid, &[], &[(mine, Some(9999))])
                .await
                .unwrap_err(),
            no_such,
            "the same as for one that does not exist"
        );
        assert_eq!(
            crate::layout::category_delete(&state, sid, 9999).await.unwrap_err(),
            no_such
        );
    }

    #[tokio::test]
    async fn a_category_whose_channel_went_from_the_file_can_still_be_deleted() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        grant(&state, sid, &["voipc:channels"]);
        let id = crate::layout::category_save(&state, sid, None, "Info").await.unwrap();
        // A row left behind: a file channel renamed, removed, or a kept one left out
        state.layout.write().await.places.insert(
            "c:gone".into(),
            crate::layout::Place {
                position: 1,
                category: Some(id),
            },
        );
        let (categories, _) = layout_of(&state, sid).await;
        assert!(
            categories.iter().any(|c| c.id == id),
            "or nobody could ever see it, to delete it"
        );
        crate::layout::category_delete(&state, sid, id).await.unwrap();
    }

    #[tokio::test]
    async fn a_channel_being_deleted_cannot_be_written_back_or_entered() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        grant(&state, sid, &["voipc:channels"]);
        let id = crate::layout::channel_save(&state, sid, None, "going", "", true, false, None, None)
            .await
            .unwrap();
        let conv = state.channels.read().await[&id].gate_key.clone();
        crate::layout::channel_delete(&state, sid, id).await.unwrap();
        assert!(!state.channels.read().await.contains_key(&id));
        let rows = state.accounts.as_ref().unwrap().layout_rows().await.unwrap();
        assert!(!rows.rows.iter().any(|r| r.conv == conv));
    }

    #[tokio::test]
    async fn a_channels_id_says_nothing_about_a_gate_or_whether_it_exists() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        let (id, _) = hidden_channel(&state, sid).await;
        state.channels.write().await.get_mut(&id).unwrap().info.anonymous = true;
        let answers = async |c: &mut Client, m: ClientMessage| {
            c.send(&m).await;
            let ServerMessage::ChannelError { reason } = c
                .expect("refused", |m| matches!(m, ServerMessage::ChannelError { .. }))
                .await
            else {
                unreachable!()
            };
            reason
        };
        for channel_id in [id, 99_999] {
            let reason = answers(
                &mut kim,
                ClientMessage::SetChannelOptions {
                    channel_id,
                    options: ChannelOptions {
                        anonymous: Some(false),
                        ..Default::default()
                    },
                },
            )
            .await;
            assert_eq!(reason, "channel does not exist", "{channel_id}");
        }
    }

    #[tokio::test]
    async fn a_gate_holds_for_a_channels_password_and_options_too() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        let (id, _) = hidden_channel(&state, sid).await;
        kim.send(&ClientMessage::SetChannelPassword {
            channel_id: id,
            password: Some("mine".into()),
        })
        .await;
        let ServerMessage::ChannelError { reason } = kim
            .expect("refused", |m| matches!(m, ServerMessage::ChannelError { .. }))
            .await
        else {
            unreachable!()
        };
        assert_eq!(reason, "channel does not exist", "the same as for no channel at all");
        assert!(!state.channels.read().await[&id].info.has_password);
    }

    #[tokio::test]
    async fn a_refused_edit_changes_nothing() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        grant(&state, sid, &["voipc:channels"]);
        let id = crate::layout::channel_save(&state, sid, None, "old", "", true, false, None, None)
            .await
            .unwrap();
        let bad = ChannelGate {
            groups: vec!["no-such-group".into()],
            speakers: vec![],
        };
        crate::layout::channel_save(&state, sid, Some(id), "new", "", true, false, None, Some(bad))
            .await
            .unwrap_err();
        assert_eq!(state.channels.read().await[&id].info.name, "old");
    }

    #[tokio::test]
    async fn a_channel_made_here_counts_towards_the_join_burst_of_who_comes_next() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (_kim, ki) = register(&state, "kim").await;
        let sid = sid_of(&state, ki.id);
        grant(&state, sid, &["voipc:channels"]);
        let budget = || state.channel_budget.load(std::sync::atomic::Ordering::Relaxed);
        let before = budget();
        let id = crate::layout::channel_save(&state, sid, None, "news", "", true, false, None, None)
            .await
            .unwrap();
        assert_eq!(budget(), before + 1);
        crate::layout::channel_delete(&state, sid, id).await.unwrap();
        assert_eq!(budget(), before);
    }

    #[tokio::test]
    async fn who_comes_to_manage_channels_is_told_the_empty_categories() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "editors", None, &["voipc:channels"]).await;
        let (_ann, ai) = register(&state, "ann").await;
        let (mut kim, ki) = register(&state, "kim").await;
        totp_on(&mut kim).await;
        grant(&state, sid_of(&state, ai.id), &["voipc:channels"]);
        crate::layout::category_save(&state, sid_of(&state, ai.id), None, "Empty")
            .await
            .unwrap();
        give(&state, ki.id, "editors", true).await;
        loop {
            let ServerMessage::ChannelLayout { categories, .. } = kim
                .expect("the layout", |m| matches!(m, ServerMessage::ChannelLayout { .. }))
                .await
            else {
                unreachable!()
            };
            if categories.iter().any(|c| c.name == "Empty") {
                break;
            }
        }
    }
}

/// The slower of two reads of an account's scopes must not undo the newer one: a
/// grant at the moment codes go on came out with no privilege at all, until the next
/// pass of `revalidate`.
#[tokio::test]
async fn a_slower_read_of_an_accounts_scopes_does_not_undo_a_newer_one() {
    let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
    group(&state, "keepers", None, &["roles:admin"]).await;
    let (mut kim, ki) = register(&state, "kim").await;
    totp_on(&mut kim).await;
    let relay = state.accounts.clone().unwrap();
    let sid = *state.account_sessions.get(&ki.id).unwrap();
    let scopes_now = || {
        state
            .sessions
            .get(&sid)
            .and_then(|s| s.account.as_ref().map(|a| a.scopes.clone()))
            .unwrap()
    };
    let kim_user = relay.store().user_by_id(AccountId(ki.id)).await.unwrap().unwrap();

    // Started first, and it read before the grant
    let slow = crate::accounts::scope_read(&state, sid);
    let stale = relay.accounts.effective_scopes(&kim_user).await.unwrap();
    assert!(!stale.contains(&"roles:admin".to_string()));

    give(&state, ki.id, "keepers", true).await;
    assert!(scopes_now().contains(&"roles:admin".to_string()), "the grant");

    // Finishes last
    crate::accounts::apply_scopes(&state, &relay, sid, kim_user.clone(), stale.clone(), slow)
        .await
        .unwrap();
    assert!(
        scopes_now().contains(&"roles:admin".to_string()),
        "the older answer is dropped"
    );

    // A read that wrote nothing cancels nothing: `revalidate` starts one for every
    // session on its round, and most find nothing to do
    let quiet = crate::accounts::scope_read(&state, sid);
    let _ = crate::accounts::scope_read(&state, sid);
    crate::accounts::apply_scopes(&state, &relay, sid, kim_user.clone(), scopes_now(), quiet)
        .await
        .unwrap();
    assert!(scopes_now().contains(&"roles:admin".to_string()));

    // The latest read does count, whatever it says
    let last = crate::accounts::scope_read(&state, sid);
    crate::accounts::apply_scopes(&state, &relay, sid, kim_user, stale, last)
        .await
        .unwrap();
    assert!(!scopes_now().contains(&"roles:admin".to_string()));
}

/// `@everyone`, `@here`, `@&badge`: who the relay says may use them (1.9).
mod mention_power {
    use super::*;

    async fn holders(c: &mut Client) -> (Vec<UserId>, bool) {
        let ServerMessage::MentionPower { user_ids, on } = c
            .expect("the holders", |m| {
                matches!(m, ServerMessage::MentionPower { .. })
            })
            .await
        else {
            unreachable!()
        };
        (user_ids, on)
    }

    async fn badges(c: &mut Client) -> Vec<String> {
        let ServerMessage::MyBadges { badges } = c
            .expect("our badges", |m| {
                matches!(m, ServerMessage::MyBadges { .. })
            })
            .await
        else {
            unreachable!()
        };
        badges
    }

    fn uid_of(state: &ServerState, account: [u8; 16]) -> UserId {
        let sid = *state.account_sessions.get(&account).unwrap();
        state.sessions.get(&sid).unwrap().user_id
    }

    #[tokio::test]
    async fn holders_are_told_on_change_and_to_whoever_arrives() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "callers", None, &["voipc:mention_all"]).await;
        let (mut kim, ki) = register(&state, "kim").await;
        totp_on(&mut kim).await;
        let (mut bob, _) = register(&state, "bob").await;
        give(&state, ki.id, "callers", true).await;
        let kim_id = uid_of(&state, ki.id);
        assert_eq!(holders(&mut bob).await, (vec![kim_id], true));

        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut late = connect(&state, "late#1234", lo).await;
        assert_eq!(
            holders(&mut late).await,
            (vec![kim_id], true),
            "a guest hears too"
        );

        // Bob may have heard it twice, as a change and on connecting: it adds nothing
        give(&state, ki.id, "callers", false).await;
        while holders(&mut bob).await.1 {}
    }

    #[test]
    fn calling_on_everybody_is_no_role_for_an_address_ban_either() {
        let only = ["voipc:mention_all".to_string()];
        assert!(!crate::accounts::holds_power(&only));
        assert!(!crate::accounts::holds_power(&[]));
        assert!(crate::accounts::holds_power(&["voipc:kick".to_string()]));
        assert!(crate::accounts::holds_power(&[
            "voipc:mention_all".to_string(),
            "voipc:profiles".to_string()
        ]));
    }

    #[tokio::test]
    async fn calling_on_everybody_spares_nobody_from_a_kick() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        group(&state, "callers", None, &["voipc:mention_all"]).await;
        group(&state, "kickers", None, &["voipc:kick"]).await;
        let (mut kim, ki) = register(&state, "kim").await;
        totp_on(&mut kim).await;
        let sid = *state.account_sessions.get(&ki.id).unwrap();
        give(&state, ki.id, "callers", true).await;
        assert!(!state.sessions.get(&sid).unwrap().is_moderator);
        give(&state, ki.id, "kickers", true).await;
        assert!(state.sessions.get(&sid).unwrap().is_moderator);
    }

    #[tokio::test]
    async fn every_own_badge_reaches_the_account_though_a_row_shows_three() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        for (name, badge) in [("a1", "A"), ("b2", "B"), ("c3", "C"), ("d4", "D")] {
            group(&state, name, Some(badge), &[]).await;
        }
        let (mut bob, bi) = register(&state, "bob").await;
        for g in ["a1", "b2", "c3", "d4"] {
            give(&state, bi.id, g, true).await;
        }
        // One at a time, and one of them may also have been told on connecting
        while badges(&mut bob).await != ["A", "B", "C", "D"] {}
        let sid = *state.account_sessions.get(&bi.id).unwrap();
        let shown = state
            .sessions
            .get(&sid)
            .unwrap()
            .account
            .as_ref()
            .unwrap()
            .standing
            .badges
            .clone();
        assert_eq!(shown, ["A", "B", "C"]);
    }

    #[test]
    fn the_names_it_means_cannot_be_taken() {
        let cfg = crate::accounts::l4f_config(&crate::config::AccountsConfig::default(), [0; 16]);
        for name in ["everyone", "here"] {
            assert!(cfg.reserved_usernames.iter().any(|r| r == name), "{name}");
        }
    }
}

/// Reusable invite links (1.9).
mod invite_links {
    use super::*;

    async fn answer(c: &mut Client, op: AdminOp) -> AccountReply {
        c.send(&admin_op(op, None)).await;
        let ServerMessage::Account(r) = c.expect("the answer", admin_answer).await else {
            unreachable!()
        };
        r
    }

    async fn new_link(ann: &mut Client, max_uses: u32, days: u32, group: Option<&str>) -> String {
        let op = AdminOp::InviteLinkNew {
            max_uses,
            days,
            group: group.map(String::from),
        };
        match answer(ann, op).await {
            AccountReply::Admin(AdminReply::InviteLinkCode { code }) => code,
            other => panic!("{other:?}"),
        }
    }

    /// Signs up with a link, as `register` does; what the relay said if not.
    async fn sign_up(state: &Arc<ServerState>, name: &str, code: &str) -> Result<(Client, AccountInfo), String> {
        let mut c = open_account(
            state,
            name,
            AccountStart::Register {
                invite: Some(code.into()),
            },
        )
        .await;
        let pow = match c.next().await {
            Some(ServerMessage::AuthStep(AuthStep::Salt { pow: Some(pow), .. })) => pow,
            Some(ServerMessage::AuthError { reason }) => return Err(reason),
            other => panic!("{other:?}"),
        };
        let vault = vec![
            VaultBlob {
                k: "slot.hkdf".into(),
                v: vec![1, 2, 3],
                version: 0,
            },
            reset_slot(),
        ];
        let altcha = solve(&pow.altcha);
        c.send(&ClientMessage::AuthContinue(AuthContinue::Register {
            auth_secret: SECRET.to_vec(),
            altcha,
            ts: pow.ts,
            vault,
        }))
        .await;
        c.send(&keys(&IDENTITY, false)).await;
        loop {
            match c.next().await {
                Some(ServerMessage::Authenticated {
                    account: Some(info),
                    ..
                }) => return Ok((c, info)),
                Some(ServerMessage::AuthError { reason }) => return Err(reason),
                Some(_) => {}
                None => return Err("closed".into()),
            }
        }
    }

    #[tokio::test]
    async fn many_people_sign_up_with_one_link_where_sign_up_is_by_invite() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        let (mut ann, _, _) = admin_on_invite_relay(&state, "ann").await;
        let code = new_link(&mut ann, 2, 7, Some("crew")).await;
        assert_eq!(code.len(), 43);
        let codes = state.accounts.as_ref().unwrap().store().invites(l4f_accounts::util::now()).await.unwrap().len();

        let (_bob, bi) = sign_up(&state, "bob", &code).await.unwrap();
        let (_cat, _) = sign_up(&state, "cat", &code).await.unwrap();
        let e = sign_up(&state, "dan", &code).await.err().unwrap();
        assert!(e.contains("not valid"), "used up: {e}");

        let relay = state.accounts.clone().unwrap();
        let bob = relay.store().user_by_id(AccountId(bi.id)).await.unwrap().unwrap();
        assert!(
            relay.store().user_roles(bob.id).await.unwrap().iter().any(|r| r.name == "crew"),
            "in its starting group"
        );
        assert_eq!(
            relay.store().invites(l4f_accounts::util::now()).await.unwrap().len(),
            codes,
            "no row left behind per sign-up"
        );
        let reply = answer(&mut ann, AdminOp::InviteLinks).await;
        let AccountReply::Admin(AdminReply::InviteLinks { links }) = reply else {
            panic!("{reply:?}");
        };
        assert_eq!((links[0].uses, links[0].max_uses), (2, 2));
        assert_eq!(links[0].group.as_deref(), Some("crew"));
        assert_ne!(links[0].id, code, "the list never holds the code");
    }

    #[tokio::test]
    async fn a_refused_sign_up_gives_its_use_back() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        let (mut ann, _, _) = admin_on_invite_relay(&state, "ann").await;
        let code = new_link(&mut ann, 1, 7, None).await;
        let e = sign_up(&state, "ann", &code).await.err().unwrap();
        assert!(!e.contains("not valid"), "the name was taken: {e}");
        sign_up(&state, "bob", &code).await.expect("its one use is still there");
    }

    #[tokio::test]
    async fn a_taken_name_costs_neither_a_use_nor_the_limits_all_sign_up_shares() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        let (mut ann, _, _) = admin_on_invite_relay(&state, "ann").await;
        let code = new_link(&mut ann, 5, 7, None).await;
        let relay = state.accounts.clone().unwrap();
        let hour = Duration::from_secs(3600);
        assert!(relay.accounts.limiter.peek("acct-reg:try:global", hour, 1));
        for name in ["ann", "general"] {
            assert!(sign_up(&state, name, &code).await.is_err(), "{name}");
        }
        assert!(
            relay.accounts.limiter.peek("acct-reg:try:global", hour, 1),
            "someone with the link could otherwise shut sign-up for everybody"
        );
        assert_eq!(relay.links().await.unwrap()[0].uses, 0);
    }

    #[tokio::test]
    async fn who_made_a_link_and_who_came_through_it_is_written_down() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        let (mut ann, ai, _) = admin_on_invite_relay(&state, "ann").await;
        let relay = state.accounts.clone().unwrap();
        let code = new_link(&mut ann, 5, 7, None).await;
        let (_bob, bi) = sign_up(&state, "bob", &code).await.unwrap();
        let id = relay.links().await.unwrap()[0].id.clone();
        answer(&mut ann, AdminOp::InviteLinkRevoke { id: id.clone() }).await;

        let of = |a: [u8; 16]| {
            let relay = relay.clone();
            async move { relay.store().audit_of(AccountId(a), 50).await.unwrap() }
        };
        let ann_did = of(ai.id).await;
        for event in ["invite_link_new", "invite_link_revoke"] {
            let row = ann_did.iter().find(|e| e.event == event).unwrap_or_else(|| panic!("{event}"));
            assert_eq!(row.actor_id, Some(AccountId(ai.id)), "{event}");
            assert!(row.detail.contains(&id), "{event}: {}", row.detail);
        }
        let bob_came = of(bi.id).await;
        let row = bob_came.iter().find(|e| e.event == "invite_link_used").unwrap();
        assert_eq!(row.actor_id, Some(AccountId(ai.id)), "by whose link");
        assert_eq!(row.detail, id);
    }

    #[tokio::test]
    async fn a_link_does_not_stand_in_for_the_proof_of_work() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        let (mut ann, _, _) = admin_on_invite_relay(&state, "ann").await;
        let code = new_link(&mut ann, 5, 7, None).await;
        let mut c = open_account(
            &state,
            "bob",
            AccountStart::Register {
                invite: Some(code),
            },
        )
        .await;
        let Some(ServerMessage::AuthStep(AuthStep::Salt { pow: Some(pow), .. })) = c.next().await else {
            panic!("a link is asked for the work too");
        };
        c.send(&ClientMessage::AuthContinue(AuthContinue::Register {
            auth_secret: SECRET.to_vec(),
            altcha: String::new(),
            ts: pow.ts,
            vault: vec![
                VaultBlob {
                    k: "slot.hkdf".into(),
                    v: vec![1, 2, 3],
                    version: 0,
                },
                reset_slot(),
            ],
        }))
        .await;
        assert!(matches!(c.next().await, Some(ServerMessage::AuthError { .. }) | None));
    }

    #[tokio::test]
    async fn a_revoked_or_expired_link_or_a_made_up_one_lets_nobody_in() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        let (mut ann, _, _) = admin_on_invite_relay(&state, "ann").await;
        let relay = state.accounts.clone().unwrap();

        assert!(sign_up(&state, "bob", &"A".repeat(43)).await.is_err(), "made up");

        let gone = new_link(&mut ann, 5, 7, None).await;
        let id = relay.links().await.unwrap()[0].id.clone();
        let reply = answer(&mut ann, AdminOp::InviteLinkRevoke { id }).await;
        assert!(matches!(reply, AccountReply::Admin(AdminReply::InviteLinks { .. })), "{reply:?}");
        assert!(sign_up(&state, "bob", &gone).await.is_err(), "revoked");

        let late = new_link(&mut ann, 5, 7, None).await;
        relay.links_all_expired().await.unwrap();
        assert!(sign_up(&state, "bob", &late).await.is_err(), "expired");
    }

    #[tokio::test]
    async fn a_starting_group_holds_nothing_when_made_and_when_used() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Invite).await;
        group(&state, "crew", Some("Crew"), &[]).await;
        group(&state, "mods", None, &["voipc:kick"]).await;
        let (mut ann, _, _) = admin_on_invite_relay(&state, "ann").await;
        let relay = state.accounts.clone().unwrap();

        let op = AdminOp::InviteLinkNew {
            max_uses: 5,
            days: 7,
            group: Some("mods".into()),
        };
        assert!(matches!(answer(&mut ann, op).await, AccountReply::Error { .. }));
        for bad in [
            AdminOp::InviteLinkNew { max_uses: 0, days: 7, group: None },
            AdminOp::InviteLinkNew { max_uses: 5, days: 366, group: None },
        ] {
            assert!(matches!(answer(&mut ann, bad).await, AccountReply::Error { .. }));
        }

        let code = new_link(&mut ann, 5, 0, Some("crew")).await;
        let crew = relay.store().role_by_name("crew").await.unwrap().unwrap();
        relay
            .store()
            .set_role_scopes(crew.id, &["voipc:kick".to_string()])
            .await
            .unwrap();
        let (_bob, bi) = sign_up(&state, "bob", &code).await.unwrap();
        assert!(
            !relay.store().user_roles(AccountId(bi.id)).await.unwrap().iter().any(|r| r.name == "crew"),
            "the group was given power since: the link no longer hands it out"
        );
    }

    #[tokio::test]
    async fn only_who_manages_accounts_makes_links_and_a_closed_relay_has_none() {
        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Open).await;
        let (mut bob, _) = register(&state, "bob").await;
        let op = AdminOp::InviteLinkNew { max_uses: 5, days: 7, group: None };
        assert!(matches!(answer(&mut bob, op.clone()).await, AccountReply::Error { .. }));
        assert!(matches!(answer(&mut bob, AdminOp::InviteLinks).await, AccountReply::Error { .. }));

        let (state, _db) = relay_state(AccountsMode::Optional, RegistrationMode::Closed).await;
        let (mut ann, _, _) = admin_on_invite_relay(&state, "ann").await;
        assert!(matches!(answer(&mut ann, op).await, AccountReply::Error { .. }));
    }

    /// `admin_account` on a relay where nobody signs up without a code.
    async fn admin_on_invite_relay(
        state: &Arc<ServerState>,
        name: &str,
    ) -> (Client, AccountInfo, Vec<u8>) {
        let relay = state.accounts.clone().unwrap();
        let ctx = relay.ctx(IpAddr::V4(Ipv4Addr::LOCALHOST), "test");
        let code = relay.accounts.invite_create_as_host(&ctx, Some(name), 1).await.unwrap();
        let mut c = open_account(state, name, AccountStart::Register { invite: Some(code) }).await;
        let Some(ServerMessage::AuthStep(AuthStep::Salt { .. })) = c.next().await else {
            panic!("a code opens the door");
        };
        c.send(&ClientMessage::AuthContinue(AuthContinue::Register {
            auth_secret: SECRET.to_vec(),
            altcha: String::new(),
            ts: String::new(),
            vault: vec![
                VaultBlob {
                    k: "slot.hkdf".into(),
                    v: vec![1, 2, 3],
                    version: 0,
                },
                reset_slot(),
            ],
        }))
        .await;
        c.send(&keys(&IDENTITY, false)).await;
        let ServerMessage::Authenticated {
            account: Some(info),
            ..
        } = c
            .expect("Authenticated", |m| matches!(m, ServerMessage::Authenticated { .. }))
            .await
        else {
            panic!("signed in");
        };
        relay
            .accounts
            .grant_role_as_host(&ctx, AccountId(info.id), "admin")
            .await
            .unwrap();
        let secret = totp_on(&mut c).await;
        c.expect("AdminStatus", |m| {
            matches!(m, ServerMessage::AdminStatus { is_admin: true, .. })
        })
        .await;
        (c, info, secret)
    }
}
