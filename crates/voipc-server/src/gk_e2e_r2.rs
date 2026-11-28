//! End-to-end group-key scenarios added by slice R2 (wave 3): the relay's real `gk` code
//! reached through the real session path (`handle_connection` over a duplex, as the session
//! bridge feeds it: session.rs's arms, caps and post helper, state.rs's follow hooks), and
//! members running the clients' real `voipc_crypto::group_state` code on what that session
//! sent them. The keyholder is a guest building honest commits with `group_key::build`
//! (Genesis and Join only), as `gk_e2e_tests.rs` has one, until C3c's holder is wired.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use voipc_crypto::group_key::build::{
    build_genesis, build_join, Built, Holding, Lists, RowBases, Start,
};
use voipc_crypto::group_key::commit::{Joiner, Pair};
use voipc_crypto::group_key::{
    Endorsement, Group, GroupKind, Keyholder as Entry, Keyring, Me, MemberId, Origin, SeatPair,
    SeatRef, SeedRolls, SignedHeader,
};
use voipc_crypto::group_state::{
    group_id, GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, MemoryPins, OpenedPost,
    Platform, VaultFloor,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::codec::{
    decode_server_msg, encode_client_msg, try_decode_frame, APP_VERSION, PROTOCOL_VERSION,
};
use voipc_protocol::gk::{
    self, commit_frame_overhead, cut_commit, CommitPiece, DuePiece, Part, Parts, Seq,
    PIECE_MAX_BYTES,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, ChannelOptions, UserId};
use zeroize::Zeroizing;

use crate::channels::ChannelEntry;
use crate::config::ServerConfig;
use crate::settings::ServerSettings;
use crate::state::ServerState;

/// The one channel: persistent, text.
pub(crate) const LOUNGE: ChannelId = 1;

/// How long a wait may take before a test calls it hung.
const HANG: Duration = Duration::from_secs(60);

/// A relay with the group key on, no accounts, and `LOUNGE`, whose group lives in memory.
pub(crate) fn gk_state() -> Arc<ServerState> {
    Arc::new(ServerState::new(
        &ServerConfig {
            group_key: true,
            ..ServerConfig::default()
        },
        ServerSettings::default(),
        vec![lounge()],
        "test-admin-token".into(),
    ))
}

fn lounge() -> ChannelEntry {
    ChannelEntry {
        name: "lounge".into(),
        text: true,
        ..Default::default()
    }
}

/// `LOUNGE`'s group, as the app derives it from what the relay told it (`run`).
pub(crate) async fn lounge_group(state: &ServerState, run: &[u8; 16]) -> String {
    let log = state.channels.read().await[&LOUNGE].info.log.clone();
    group_id(GroupKind::Text, &log, run, LOUNGE)
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// A guest connection's seat pair (origin 0x02), endorsed by its identity `ik`.
pub(crate) fn conn_pair(ik: &IdentityKeyPair, sid: UserId) -> (SeatPair, Pair) {
    let pair = SeatPair::generate();
    let endorsement = Endorsement::sign(
        ik,
        Origin::Connection,
        MemberId::Conn(sid),
        0,
        wall_ms() / 1000,
        &pair.public(),
    )
    .unwrap();
    let wire = Pair {
        keys: pair.public(),
        endorsement,
    };
    (pair, wire)
}

// ── A connection ─────────────────────────────────────────────────────────

/// One guest's connection, served by `handle_connection` as the session bridge serves it.
pub(crate) struct Conn {
    pub sid: UserId,
    /// `GroupKeys`, the frame right after `Authenticated`.
    pub on: bool,
    pub run: [u8; 16],
    stream: DuplexStream,
    _handler: tokio::task::JoinHandle<()>,
    buf: BytesMut,
}

impl Conn {
    /// Signs `name` in as a guest with identity `ik`, past `Authenticated` and `GroupKeys`.
    pub async fn open(state: &Arc<ServerState>, name: &str, ik: &IdentityKeyPair) -> Conn {
        let (stream, server) = tokio::io::duplex(1 << 20);
        let (media_tx, _media_rx) = mpsc::channel(8);
        let (sid_tx, _sid_rx) = oneshot::channel();
        let handler = tokio::spawn(crate::session::handle_connection(
            server,
            name.into(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            media_tx,
            sid_tx,
            state.clone(),
            Some([0x5a; 32]),
        ));
        let mut c = Conn {
            sid: 0,
            on: false,
            run: [0; 16],
            stream,
            _handler: handler,
            buf: BytesMut::new(),
        };
        c.send(&ClientMessage::Authenticate {
            username: name.into(),
            protocol_version: PROTOCOL_VERSION,
            app_version: APP_VERSION.to_string(),
            identity_key: Some([&[0x05u8][..], &raw(ik)].concat()),
            prekey_bundle: None,
            account: None,
        })
        .await;
        let ServerMessage::Authenticated { user_id, .. } = c.next().await else {
            panic!("{name} was not let in");
        };
        let ServerMessage::GroupKeys { on, run, .. } = c.next().await else {
            panic!("GroupKeys right after Authenticated");
        };
        (c.sid, c.on, c.run) = (user_id, on, run);
        c
    }

    pub async fn send(&mut self, msg: &ClientMessage) {
        self.stream
            .write_all(&encode_client_msg(msg).unwrap())
            .await
            .unwrap();
    }

    /// The next frame.
    pub async fn next(&mut self) -> ServerMessage {
        loop {
            if let Some(p) = try_decode_frame(&mut self.buf).unwrap() {
                return decode_server_msg(&p).unwrap();
            }
            let n = tokio::time::timeout(HANG, self.stream.read_buf(&mut self.buf))
                .await
                .expect("a frame before the hang guard")
                .unwrap();
            assert!(n > 0, "the relay closed the connection");
        }
    }

    /// Frames until one `pred` takes, that one.
    pub async fn expect(&mut self, pred: impl Fn(&ServerMessage) -> bool) -> ServerMessage {
        loop {
            let f = self.next().await;
            if pred(&f) {
                return f;
            }
        }
    }

    /// Every frame there is by now.
    pub async fn drain(&mut self) -> Vec<ServerMessage> {
        let mut got = vec![];
        loop {
            while let Some(p) = try_decode_frame(&mut self.buf).unwrap() {
                got.push(decode_server_msg(&p).unwrap());
            }
            let read = self.stream.read_buf(&mut self.buf);
            match tokio::time::timeout(Duration::from_millis(1), read).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => return got,
            }
        }
    }

    /// Follows `LOUNGE` whole, as the app's auto-join does.
    pub async fn follow(&mut self) {
        self.send(&ClientMessage::JoinTextChannels {
            channels: vec![LOUNGE],
            quiet: vec![],
        })
        .await;
        self.expect(|m| matches!(m, ServerMessage::TextJoined { joined, .. } if joined.iter().any(|r| r.0 == LOUNGE)))
            .await;
    }

    /// Everything the relay sent before it answered a ping.
    pub async fn settled(&mut self) -> Vec<ServerMessage> {
        let stamp: u64 = rand::random();
        self.send(&ClientMessage::Ping { timestamp: stamp }).await;
        let mut before = vec![];
        loop {
            match self.next().await {
                ServerMessage::Pong { timestamp } if timestamp == stamp => return before,
                f => before.push(f),
            }
        }
    }
}

// ── A keyholder ──────────────────────────────────────────────────────────

/// What a keyholder holds once its commit was taken.
struct Held {
    head: SignedHeader,
    kh: SignedHeader,
    ring: Keyring,
    krk: Zeroizing<[u8; 32]>,
    rolls: SeedRolls,
}

/// A guest keyholder app: follows `LOUNGE`, volunteers with its connection pair, takes each
/// Genesis or Join due whole, asks the lists it needs, and holds a commit once the relay
/// pushes its header. Other dues it lets pass.
pub(crate) struct Keyholder {
    pub conn: Conn,
    ik: IdentityKeyPair,
    m: MemberId,
    pair: SeatPair,
    wire: Pair,
    group: String,
    held: Option<Held>,
    cache: RowBases,
    out: Option<(u64, Built)>,
    dues: Parts<u64, DuePiece>,
    waiting: Option<(u64, DuePiece)>,
    lists: Lists,
    /// Due kinds asked, in order.
    pub asked: Vec<u8>,
}

impl Keyholder {
    pub async fn new(state: &Arc<ServerState>) -> Keyholder {
        let ik = voipc_crypto::generate_identity_key_pair();
        let mut conn = Conn::open(state, "keys", &ik).await;
        let group = lounge_group(state, &conn.run).await;
        conn.follow().await;
        let m = MemberId::Conn(conn.sid);
        let (pair, wire) = conn_pair(&ik, conn.sid);
        conn.send(&ClientMessage::KeyholdVolunteer {
            on: true,
            platform: gk::platform::DESKTOP,
            pair: Some((&wire).into()),
        })
        .await;
        Keyholder {
            conn,
            ik,
            m,
            pair,
            wire,
            group,
            held: None,
            cache: RowBases::new(),
            out: None,
            dues: Parts::new(Seq::Due),
            waiting: None,
            lists: Lists::new(),
            asked: vec![],
        }
    }

    /// The head it holds: generation and epoch.
    pub fn head(&self) -> Option<([u8; 16], u32)> {
        let h = self.held.as_ref()?.head.header();
        Some((h.gen, h.epoch))
    }

    /// Takes what the relay sent; sends what it answers.
    pub async fn step(&mut self, now: u64) {
        let mut send = vec![];
        for f in self.conn.drain().await {
            send.extend(self.frame(&f, now));
        }
        for m in send {
            self.conn.send(&m).await;
        }
    }

    fn entry(&self) -> Entry {
        self.wire
            .entry(GroupKind::Text, self.m, raw(&self.ik))
            .unwrap()
    }

    fn frame(&mut self, f: &ServerMessage, now: u64) -> Vec<ClientMessage> {
        match f {
            ServerMessage::EpochDue {
                due,
                part,
                last,
                piece,
                ..
            } => {
                let bytes = crate::gk::push::len(f);
                let Part::Whole(d, ps) = self
                    .dues
                    .take(*due, *part, *last, (**piece).clone(), bytes)
                    .part
                else {
                    return vec![];
                };
                let mut p = ps[0].clone();
                for q in &ps[1..] {
                    p.joins.extend(q.joins.clone());
                    p.held.extend(q.held.clone());
                }
                self.asked.push(p.kind);
                match (p.kind, &self.held) {
                    (gk::due::GENESIS, _) => self.build(d, &p, now),
                    (gk::due::JOIN, Some(held)) => {
                        let versions = held.ring.buckets.iter().map(|k| (k.b, k.v)).collect();
                        let gen = held.head.header().gen;
                        self.waiting = Some((d, p));
                        vec![ClientMessage::EpochListsWanted {
                            group: self.group.clone(),
                            gen,
                            versions,
                        }]
                    }
                    _ => vec![],
                }
            }
            ServerMessage::EpochLists { lists, more, .. } => {
                for l in lists.iter().cloned() {
                    let (v, seats) = voipc_crypto::group_key::wire::list(l);
                    self.lists.insert(v, seats);
                }
                match (more, self.waiting.take()) {
                    (false, Some((due, piece))) => self.build(due, &piece, now),
                    (_, w) => {
                        self.waiting = w;
                        vec![]
                    }
                }
            }
            ServerMessage::EpochIn { piece, .. } => {
                let pushed = |sh: &SignedHeader| {
                    piece
                        .chain
                        .iter()
                        .chain(piece.head.iter().map(|l| &l.header))
                        .filter_map(|h| {
                            SignedHeader::decode(&h.body, &h.sig, GroupKind::Text, &self.group).ok()
                        })
                        .any(|x| x.d() == sh.d())
                };
                if self.out.as_ref().is_some_and(|(_, b)| pushed(&b.header)) {
                    let (_, b) = self.out.take().unwrap();
                    self.took(b);
                }
                vec![]
            }
            ServerMessage::EpochStale { .. } => {
                self.out = None;
                vec![]
            }
            _ => vec![],
        }
    }

    fn took(&mut self, b: Built) {
        let h = b.header.header();
        let kh = if h.kind.sets_keyholders() {
            b.header.clone()
        } else {
            self.held.as_ref().expect("a head").kh.clone()
        };
        let rolls = match &self.held {
            Some(x) => x.rolls.after(x.head.header(), h),
            None => SeedRolls::at_start(h),
        };
        self.held = Some(Held {
            head: b.header,
            kh,
            ring: b.ring,
            krk: b.krk,
            rolls,
        });
        self.lists.clear();
    }

    fn build(&mut self, due: u64, piece: &DuePiece, now: u64) -> Vec<ClientMessage> {
        let joiners: Vec<Joiner> = piece
            .joins
            .iter()
            .map(|j| Joiner::try_from(j).unwrap())
            .collect();
        let refs: Vec<&Joiner> = joiners.iter().collect();
        let me = Me {
            m: self.m,
            keys: &self.pair,
        };
        let built = match &self.held {
            None => {
                let st = Start {
                    kind: GroupKind::Text,
                    id: &self.group,
                    me,
                    ik: &self.ik,
                    entry: self.entry(),
                    joiners: &refs,
                    gated: piece.gated,
                    stored: false,
                    now: now / 1000,
                };
                build_genesis(&st, &mut self.cache)
            }
            Some(held) => {
                let grp = Group::new(GroupKind::Text, &self.group, held.head.header().gen).unwrap();
                let seed = held.head.header().seed;
                let behind: std::collections::HashMap<SeatRef, u32> = piece
                    .held
                    .iter()
                    .map(|(s, n)| (SeatRef::from(*s), *n))
                    .collect();
                let held_of = |s: &SeatRef| behind.get(s).copied().or(Some(seed));
                let hold = Holding {
                    g: &grp,
                    head: &held.head,
                    kh: &held.kh,
                    ring: &held.ring,
                    krk: &held.krk,
                    me,
                    ik: &self.ik,
                    lists: &self.lists,
                    held: &held_of,
                    rolls: held.rolls,
                    stored: false,
                };
                build_join(&hold, &refs, vec![], now / 1000, &mut self.cache, None)
            }
        };
        let b = built.unwrap_or_else(|e| panic!("due {} did not build: {e:?}", piece.kind));
        let commit = CommitPiece::try_from(b.commit.clone()).unwrap();
        let parts =
            cut_commit(commit, PIECE_MAX_BYTES - commit_frame_overhead(&self.group)).unwrap();
        let n = parts.len();
        let msgs = parts
            .into_iter()
            .enumerate()
            .map(|(i, p)| ClientMessage::EpochCommit {
                group: self.group.clone(),
                due,
                part: i as u16,
                last: i + 1 == n,
                piece: p,
            })
            .collect();
        self.out = Some((due, b));
        msgs
    }
}

// ── A member (C3b) ────────────────────────────────────────────────────────

/// One guest app's `GroupKeying` on its own connection.
pub(crate) struct Member {
    pub conn: Conn,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    group: String,
    pub posts: Vec<OpenedPost>,
    pub events: Vec<GkEvent>,
    /// The refusals it was sent: `EpochRefused` and `ChannelError`.
    pub told: Vec<ServerMessage>,
}

impl Member {
    /// Signs in, starts at `GroupKeys`, follows `LOUNGE` and tracks its group.
    pub async fn new(state: &Arc<ServerState>, name: &str) -> Member {
        let ik = voipc_crypto::generate_identity_key_pair();
        let mut conn = Conn::open(state, name, &ik).await;
        let mut keying = GroupKeying::default();
        let _ = keying.start(GkStart {
            on: conn.on,
            run: conn.run,
            relay_clock: state.gk.now() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: conn.sid,
            identity: ik,
            account: None,
            seat_keys: None,
            local: None,
            visible: true,
        });
        let group = lounge_group(state, &conn.run).await;
        conn.follow().await;
        let mut m = Member {
            st: SignalStores::new(&ik, conn.sid),
            conn,
            keying,
            pins: MemoryPins::default(),
            group: group.clone(),
            posts: vec![],
            events: vec![],
            told: vec![],
        };
        let out = m.keying.track(
            GkTrack {
                channel_id: LOUNGE,
                group,
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: false,
            },
            VaultFloor::None,
        );
        m.took(out).await;
        m
    }

    async fn took(&mut self, out: GkOut) {
        self.posts.extend(out.posts);
        self.events.extend(out.events);
        for msg in out.send {
            self.conn.send(&msg).await;
        }
    }

    /// Takes what the relay sent (and its 1 s tick when `tick`); sends what it answers.
    pub async fn step(&mut self, now: u64, tick: bool) {
        for f in self.conn.drain().await {
            if matches!(
                f,
                ServerMessage::EpochRefused { .. } | ServerMessage::ChannelError { .. }
            ) {
                self.told.push(f.clone());
            }
            let c = GkCtx {
                pins: &mut self.pins,
                now,
            };
            let out = self.keying.frame(&mut self.st, &f, c);
            self.took(out).await;
        }
        if tick {
            let c = GkCtx {
                pins: &mut self.pins,
                now,
            };
            let out = self.keying.tick(&mut self.st, c);
            self.took(out).await;
        }
    }

    pub async fn post(&mut self, id: u8, text: &[u8], now: u64) {
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, LOUNGE, [id; 16], text, c);
        self.took(out).await;
    }

    /// The head epoch it holds `CK` of.
    pub fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(&self.group).map(|e| e.epoch)
    }

    pub fn texts(&self) -> Vec<Vec<u8>> {
        self.posts.iter().map(|p| p.envelope.clone()).collect()
    }
}

// ── The world ─────────────────────────────────────────────────────────────

/// A relay with a keyholder and members, each on its own session.
pub(crate) struct World {
    pub state: Arc<ServerState>,
    pub holder: Keyholder,
    pub members: Vec<Member>,
    last_tick: u64,
}

impl World {
    pub async fn new(state: Arc<ServerState>) -> World {
        World {
            holder: Keyholder::new(&state).await,
            state,
            members: vec![],
            last_tick: 0,
        }
    }

    pub async fn member(&mut self, name: &str) -> usize {
        let m = Member::new(&self.state, name).await;
        self.members.push(m);
        self.members.len() - 1
    }

    /// One round: every connection's frames taken, what each answers sent.
    pub async fn step(&mut self) {
        let now = self.state.gk.now();
        self.holder.step(now).await;
        let tick = now >= self.last_tick + 1_000;
        for m in &mut self.members {
            m.step(now, tick).await;
        }
        if tick {
            self.last_tick = now;
        }
    }

    /// Rounds until `done`, at most `ms`; whether it was.
    pub async fn until(&mut self, ms: u64, done: impl Fn(&World) -> bool) -> bool {
        let end = self.state.gk.now() + ms;
        while self.state.gk.now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.step().await;
            if done(self) {
                return true;
            }
        }
        done(self)
    }
}

// ── Scenarios ─────────────────────────────────────────────────────────────

/// Two guests over real sessions: each follows, fetches and is seated (the keyholder's
/// Genesis, then one Join), A's post goes through session.rs's post helper with its blob,
/// and B opens it under the epoch key; A gets no echo.
#[tokio::test]
async fn e2e_r2_guests_over_real_sessions_fetch_post_and_read_under_the_epoch_key() {
    let mut w = World::new(gk_state()).await;
    let a = w.member("ann").await;
    let b = w.member("bob").await;
    assert!(
        w.until(20_000, |w| w.members.iter().all(|m| m.epoch().is_some()))
            .await,
        "both seated; events: {:?}",
        w.members.iter().map(|m| &m.events).collect::<Vec<_>>()
    );
    assert_eq!(w.holder.asked, vec![gk::due::GENESIS, gk::due::JOIN]);
    assert_eq!(w.members[a].epoch(), w.members[b].epoch(), "one epoch");
    let now = w.state.gk.now();
    w.members[a].post(1, b"hello", now).await;
    assert!(
        w.until(5_000, |w| !w.members[b].posts.is_empty()).await,
        "B opens A's post; events: {:?}",
        w.members[b].events
    );
    assert_eq!(w.members[b].texts(), vec![b"hello".to_vec()]);
    assert_eq!(w.members[b].posts[0].user_id, w.members[a].conn.sid);
    assert!(w.members[a].posts.is_empty(), "no echo to the writer");
}

/// A writer's budget emptied (the relay's own rule) twice in one epoch: each refused post
/// carries no blob, so it is told as a channel error and the writer's chain stays. Its first
/// post (blob 1 of the epoch) stays delivered, and later posts on that chain still go:
/// refused `POST`, the app would drop the delivered one and start a chain, a blob more each
/// time, until the third was refused `THIRD_BLOB` and nothing went.
#[tokio::test]
async fn e2e_r2_a_post_the_relays_rules_refuse_keeps_the_writers_chain_and_later_posts_go() {
    let mut w = World::new(gk_state()).await;
    let a = w.member("ann").await;
    let b = w.member("bob").await;
    assert!(
        w.until(20_000, |w| w.members.iter().all(|m| m.epoch().is_some()))
            .await,
        "both seated"
    );
    let sid = w.members[a].conn.sid;
    let budget = |w: &World, on: bool| {
        w.state.sessions.get_mut(&sid).unwrap().gk_post_rate = match on {
            true => crate::state::RateLimiter::new(32.0, 5.0),
            false => crate::state::RateLimiter::new(0.0, 0.0),
        };
    };
    let mut read = 0;
    for (i, text) in [&b"one"[..], b"two", b"three", b"four", b"five"]
        .into_iter()
        .enumerate()
    {
        let refused = i % 2 == 1;
        budget(&w, !refused);
        let told = w.members[a].told.len();
        let now = w.state.gk.now();
        w.members[a].post(i as u8, text, now).await;
        if refused {
            assert!(
                w.until(5_000, |w| w.members[a].told.len() > told).await,
                "post {i} refused"
            );
        } else {
            read += 1;
            assert!(
                w.until(5_000, |w| w.members[b].posts.len() == read).await,
                "post {i} read; A was told {:?}",
                w.members[a].told
            );
        }
    }
    assert_eq!(
        w.members[b].texts(),
        vec![b"one".to_vec(), b"three".to_vec(), b"five".to_vec()]
    );
    assert!(
        w.members[a]
            .told
            .iter()
            .all(|f| matches!(f, ServerMessage::ChannelError { .. })),
        "told as the old path tells it: {:?}",
        w.members[a].told
    );
    assert!(
        !w.members[a]
            .events
            .iter()
            .any(|e| matches!(e, GkEvent::PostDropped { .. })),
        "no post that went is dropped"
    );
}

/// Posts a writer makes before it holds the key wait, then go at once when it does: more
/// than the old path's burst of 5, the first with its blob through the group's task and the
/// rest behind it. Every one reaches the reader, in order.
#[tokio::test]
async fn e2e_r2_posts_held_until_the_writer_has_its_key_all_go_at_once_in_order() {
    let mut w = World::new(gk_state()).await;
    let b = w.member("bob").await;
    assert!(
        w.until(20_000, |w| w.members[b].epoch().is_some()).await,
        "the reader seated"
    );
    let a = w.member("ann").await;
    let texts: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'p', b'0' + i]).collect();
    let now = w.state.gk.now();
    for (i, t) in texts.iter().enumerate() {
        w.members[a].post(i as u8, t, now).await;
    }
    assert!(w.members[a].epoch().is_none(), "held: no key yet");
    assert!(
        w.until(20_000, |w| w.members[b].posts.len() == texts.len())
            .await,
        "all read; A was told {:?}",
        w.members[a].told
    );
    assert_eq!(w.members[b].texts(), texts);
    assert!(w.members[a].told.is_empty());
}

/// A text channel whose offered log goes (`hide_members` on) moves to its `r:` group and its
/// follower follows there; back, the stored `c:` group starts again.
#[tokio::test]
async fn hiding_members_moves_a_text_channels_group_and_its_followers_with_it() {
    let id = rand::random::<u32>();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/gk-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("gk-r2-{id:08x}.db"));
    let mut config = ServerConfig {
        group_key: true,
        ..ServerConfig::default()
    };
    config.accounts.mode = crate::config::AccountsMode::Optional;
    let url = format!("sqlite://{}?mode=rwc", file.display());
    let store = l4f_accounts::store::Store::connect(&url).await.unwrap();
    let relay = crate::accounts::Relay::open_with(&config.accounts, store.clone(), &[9u8; 32])
        .await
        .unwrap();
    let mut state = ServerState::new(
        &config,
        ServerSettings::default(),
        vec![lounge()],
        "test-admin-token".into(),
    );
    state.accounts = Some(Arc::new(relay));
    let inc = crate::accounts::gk::gk_start(&store, true)
        .await
        .unwrap()
        .unwrap();
    state.gk.attach(store, inc);
    let state = Arc::new(state);
    let log = state.channels.read().await[&LOUNGE].info.log.clone();
    assert!(log.starts_with("c:"), "a stored log: {log:?}");

    let (uid, _) = crate::state::test_support::add_user(&state, "ann");
    let tx = crate::control::ControlTx::placeholder();
    state.follow_text_channels(uid, &[LOUNGE], &[], &tx).await;
    let stored = lounge_group(&state, &state.gk.run).await;
    assert_eq!(stored, log);
    assert!(state.gk.get(&stored).is_some(), "following started it");

    let hide = |on| ChannelOptions {
        hide_members: Some(on),
        ..ChannelOptions::default()
    };
    state
        .set_channel_options(LOUNGE, uid, hide(true), true)
        .await
        .unwrap();
    let memory = lounge_group(&state, &state.gk.run).await;
    assert!(memory.starts_with("r:"));
    assert!(state.gk.get(&stored).is_none(), "the stored group stopped");
    assert!(
        state.gk.get(&memory).is_some(),
        "its follower follows the new one"
    );

    state
        .set_channel_options(LOUNGE, uid, hide(false), true)
        .await
        .unwrap();
    assert!(
        state.gk.get(&memory).is_none(),
        "a memory group left is gone"
    );
    assert!(state.gk.get(&stored).is_some(), "back to the stored one");
    drop(state);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", file.display()));
    }
}
