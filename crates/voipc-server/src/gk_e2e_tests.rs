//! End to end, Track C slices R1 and C3b together: the relay's group key as R1 built it
//! (`Groups`, its actors and stores, every `ClientMessage` through `Groups::handle` as
//! session.rs will hand it over), members as C3b built them (`group_state::GroupKeying`, fed
//! exactly the frames the relay queued on their control queues, their `ClientMessage`s handed
//! back), and keyholders that build honest commits with `group_key::build` from the dues the
//! relay sends (C3c, the app's keyholder loop, is not built yet).
//!
//! `EpochPost` is R2's (session.rs's post helper): `Relay::post` stands in for it, with
//! `Groups::post_check` and a fan-out of `EpochPostIn` to the group's other followers, or
//! `EpochRefused{POST}` to the writer.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use voipc_crypto::group_key::build::{
    build_genesis, build_join, build_opening, Built, Holding, Lists, OpeningAsk, RowBases, Start,
};
use voipc_crypto::group_key::commit::{DueKind, Exit, Joiner, Pair};
use voipc_crypto::group_key::{
    wire, Endorsement, Group, GroupKind, Keyholder, Keyring, Kind, Me, MemberId, Origin, SeatKeys,
    SeatPair, SeatPublic, SeatRef, SeedRolls, SignedHeader,
};
use voipc_crypto::group_state::{
    GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, LocalGk, MemoryPins, OpenedPost,
    Platform, VaultFloor, Warn,
};
use voipc_crypto::{IdentityKeyPair, SignalStores};
use voipc_protocol::gk::{
    self, commit_frame_overhead, cut_commit, refused_what, refused_why, CommitPiece, DuePiece,
    GkMember, Part, Parts, Seq, PIECE_MAX_BYTES,
};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelId, UserId};
use zeroize::Zeroizing;

use crate::control::{ControlRx, ControlTx};
use crate::gk::group::cause;
use crate::gk::Groups;

const CHANNEL: ChannelId = 7;

/// `GK_E2E_TRACE=1`: the crates' logs and every frame each session takes, on stderr.
fn tracing_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        let on = std::env::var_os("GK_E2E_TRACE").is_some();
        if on {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("debug,sqlx=warn,hyper=warn")
                .with_test_writer()
                .try_init();
        }
        on
    })
}

/// A frame, shortly.
fn show(f: &ServerMessage) -> String {
    match f {
        ServerMessage::EpochIn {
            part, last, piece, ..
        } => {
            let kind = |h: &gk::HeaderIn| {
                SignedHeader::decode(&h.body, &h.sig, GroupKind::Text, "")
                    .map(|x| {
                        format!(
                            "{:?}e{}j{}",
                            x.header().kind,
                            x.header().epoch,
                            x.header().join
                        )
                    })
                    .unwrap_or_else(|_| "?".into())
            };
            format!(
                "EpochIn[{part}{}] chain={:?} walk={} head={:?} kh={} opening={} own_join={} leaf={:?} seal={} seat={:?} pushed={}",
                if *last { " last" } else { "" },
                piece.chain.len(),
                piece.walk.len(),
                piece.head.as_ref().map(|l| l.header.body.len()),
                piece.kh.is_some(),
                piece.opening.is_some(),
                piece.own_join.is_some(),
                piece.leaf.as_ref().map(|l| (l.b, l.v)),
                piece.seal.is_some(),
                piece.seat.as_ref().map(|s| (s.b, s.base_v, s.welcome.is_some(), s.row.is_some(), s.ratchets.len())),
                piece.pushed,
            ) + &format!(" {}", piece.head.as_ref().map(|l| kind(&l.header)).unwrap_or_default())
        }
        ServerMessage::EpochPostIn { epoch, user_id, .. } => {
            format!("EpochPostIn e{epoch} from {user_id}")
        }
        ServerMessage::EpochRefused { what, why, .. } => format!(
            "EpochRefused {} {}",
            refused_what::name(*what),
            refused_why::name(*why)
        ),
        ServerMessage::EpochWait { why, .. } => format!("EpochWait {}", gk::wait::name(*why)),
        ServerMessage::EpochDue { due, piece, .. } => {
            format!("EpochDue {due} {}", gk::due::name(piece.kind))
        }
        ServerMessage::EpochStale { reason, .. } => {
            format!("EpochStale {}", gk::stale::name(*reason))
        }
        other => format!("{other:?}").chars().take(80).collect(),
    }
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

// ── The relay ─────────────────────────────────────────────────────────────

/// A relay's `Groups` over sessions on control queues, with R2's post path stood in.
struct Relay {
    groups: Groups,
    state: Arc<crate::state::ServerState>,
    rxs: HashMap<UserId, ControlRx>,
    txs: HashMap<UserId, ControlTx>,
    tx: ControlTx,
    accounts: HashMap<UserId, [u8; 16]>,
    /// Each group's followers, for the post fan-out.
    followers: HashMap<String, Vec<UserId>>,
    /// Every `EpochPostIn` the fan-out sent.
    fanned: Vec<ServerMessage>,
    /// Every `EpochRefused{POST}` the post path sent: (writer, why).
    post_refusals: Vec<(UserId, u8)>,
}

impl Relay {
    fn new() -> Relay {
        Relay {
            groups: Groups::new(true),
            state: Arc::new(crate::state::test_support::make_state()),
            rxs: HashMap::new(),
            txs: HashMap::new(),
            tx: ControlTx::placeholder(),
            accounts: HashMap::new(),
            followers: HashMap::new(),
            fanned: vec![],
            post_refusals: vec![],
        }
    }

    /// A session with identity `ik`, signed in to `account` where given.
    fn session(&mut self, ik: &IdentityKeyPair, account: Option<[u8; 16]>) -> UserId {
        let (sid, _) = crate::state::test_support::add_user(
            &self.state,
            &format!("u{}", rand::random::<u32>()),
        );
        {
            let mut s = self.state.sessions.get_mut(&sid).unwrap();
            s.identity_key = Some([&[0x05u8][..], &raw(ik)].concat());
            if let Some(a) = account {
                s.account = Some(account_session(a));
            }
        }
        if let Some(a) = account {
            self.accounts.insert(sid, a);
        }
        let (tx, rx) = crate::control::control_queue(Arc::default());
        self.groups.on_connect(sid, tx.clone());
        self.rxs.insert(sid, rx);
        self.txs.insert(sid, tx);
        sid
    }

    fn follow(&mut self, sid: UserId, group: &str) {
        let account = self.accounts.get(&sid).copied();
        self.groups
            .on_follow(CHANNEL, group, GroupKind::Text, sid, account);
        self.followers
            .entry(group.to_string())
            .or_default()
            .push(sid);
    }

    fn unfollow(&mut self, sid: UserId, group: &str) {
        self.groups.on_unfollow(CHANNEL, sid);
        if let Some(f) = self.followers.get_mut(group) {
            f.retain(|s| *s != sid);
        }
    }

    fn kick(&mut self, sid: UserId, group: &str) {
        self.groups.on_kick(CHANNEL, sid, cause::KICK);
        if let Some(f) = self.followers.get_mut(group) {
            f.retain(|s| *s != sid);
        }
    }

    /// Frames `sid`'s control queue holds now.
    async fn drain(&mut self, sid: UserId) -> Vec<ServerMessage> {
        let mut got = vec![];
        let Some(rx) = self.rxs.get_mut(&sid) else {
            return got;
        };
        while let Ok(Some(b)) = tokio::time::timeout(Duration::ZERO, rx.recv()).await {
            got.push(voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap());
        }
        got
    }

    fn queue(&self, sid: UserId, msg: &ServerMessage) {
        if let Some(tx) = self.txs.get(&sid) {
            let _ = crate::session::send_msg(tx, msg);
        }
    }

    async fn send(&mut self, sid: UserId, msg: ClientMessage) {
        match msg {
            ClientMessage::EpochPost {
                channel_id,
                group,
                gen,
                epoch,
                blob,
                ciphertext,
            } => {
                self.post(sid, channel_id, group, gen, epoch, blob, ciphertext)
                    .await
            }
            m => self.groups.handle(&self.state, sid, m, &self.tx).await,
        }
    }

    /// R2's post helper, as plan 1f.1/1f.2 have it: the group key's checks, then the post
    /// to every other follower of the group, or `EpochRefused{POST}` to its writer.
    #[allow(clippy::too_many_arguments)]
    async fn post(
        &mut self,
        sid: UserId,
        channel_id: ChannelId,
        group: String,
        gen: [u8; 16],
        epoch: u32,
        blob: Option<Vec<u8>>,
        ciphertext: Vec<u8>,
    ) {
        match self
            .groups
            .post_check(sid, &group, gen, epoch, blob.clone())
            .await
        {
            Ok(()) => {
                let account = self.accounts.get(&sid).copied();
                let msg = ServerMessage::EpochPostIn {
                    channel_id,
                    group: group.clone(),
                    gen,
                    epoch,
                    user_id: sid,
                    username: format!("u{sid}"),
                    account,
                    is_admin: false,
                    is_moderator: false,
                    writer: account.map_or(GkMember::Conn(sid), GkMember::Account),
                    blob,
                    ciphertext,
                    timestamp: self.groups.now(),
                };
                for f in self.followers.get(&group).cloned().unwrap_or_default() {
                    if f != sid {
                        self.queue(f, &msg);
                    }
                }
                self.fanned.push(msg);
            }
            Err(why) => {
                self.post_refusals.push((sid, why));
                self.queue(
                    sid,
                    &ServerMessage::EpochRefused {
                        group,
                        what: refused_what::POST,
                        why,
                        detail: String::new(),
                    },
                );
            }
        }
    }
}

/// A signed-in connection's account, as session.rs sets it at sign-in.
fn account_session(a: [u8; 16]) -> crate::state::AccountSession {
    use l4f_accounts::model::{AccountId, SessionInfo, User, UserStatus};
    crate::state::AccountSession {
        user: User {
            id: AccountId(a),
            username: format!("a{}", a[0]),
            display_name: format!("a{}", a[0]),
            email: None,
            email_pending: None,
            has_password: false,
            totp_enabled: false,
            has_passkey: false,
            status: UserStatus::Active,
            sync_enabled: false,
            created_at: 0,
        },
        token: String::new(),
        info: SessionInfo {
            token_hash: [0; 32],
            user_id: AccountId(a),
            created_at: 0,
            seen_at: 0,
            expires_at: i64::MAX,
            auth_at: 0,
            mfa_ok: false,
            method: "password".into(),
            ip: String::new(),
            ua: String::new(),
        },
        scopes: vec![],
        needs_2fa: false,
        device_challenge: None,
        wait_from: None,
        standing: Default::default(),
        step_up_at: None,
        vault_proven: false,
        binding: None,
        key_challenge: None,
        key_stepped: None,
        by_secret: false,
    }
}

// ── Keyholders ────────────────────────────────────────────────────────────

/// What a keyholder holds once its commit was taken.
struct Held {
    head: SignedHeader,
    kh: SignedHeader,
    ring: Keyring,
    krk: Zeroizing<[u8; 32]>,
    rolls: SeedRolls,
}

/// A keyholder app as C3c will be: volunteers, takes each due whole, asks the lists of the
/// versions it holds, builds with `group_key::build`, sends the commit in parts, and holds
/// the result once the relay shows the header taken.
struct Holder {
    sid: UserId,
    ik: IdentityKeyPair,
    m: MemberId,
    pair: SeatPair,
    wire: Pair,
    group: String,
    stored: bool,
    held: Option<Held>,
    cache: RowBases,
    /// The commit sent, until taken.
    out: Option<(u64, Built)>,
    dues: Parts<u64, DuePiece>,
    /// An opening or Join due waiting for its lists.
    waiting: Option<(u64, DuePiece)>,
    lists: Lists,
    /// Due kinds asked, in order.
    asked: Vec<u8>,
    stales: Vec<u8>,
}

impl Holder {
    /// A guest: its connection pair (0x02, counter 0) is its keyholder pair and its seat.
    fn guest(sid: UserId, ik: IdentityKeyPair, group: &str, stored: bool) -> Holder {
        Holder::new(
            sid,
            ik,
            MemberId::Conn(sid),
            Origin::Connection,
            0,
            group,
            stored,
        )
    }

    /// An account's desktop: a 0x03 pair under the account's counter `n`.
    fn desktop(
        sid: UserId,
        ik: IdentityKeyPair,
        a: [u8; 16],
        n: u32,
        group: &str,
        stored: bool,
    ) -> Holder {
        Holder::new(
            sid,
            ik,
            MemberId::Account(a),
            Origin::Desktop,
            n,
            group,
            stored,
        )
    }

    fn new(
        sid: UserId,
        ik: IdentityKeyPair,
        m: MemberId,
        origin: Origin,
        n: u32,
        group: &str,
        stored: bool,
    ) -> Holder {
        let pair = SeatPair::generate();
        let em = match origin {
            Origin::Connection => MemberId::Conn(sid),
            _ => m,
        };
        let endorsement =
            Endorsement::sign(&ik, origin, em, n, wall_ms() / 1000, &pair.public()).unwrap();
        let wire = Pair {
            keys: pair.public(),
            endorsement,
        };
        Holder {
            sid,
            ik,
            m,
            pair,
            wire,
            group: group.to_string(),
            stored,
            held: None,
            cache: RowBases::new(),
            out: None,
            dues: Parts::new(Seq::Due),
            waiting: None,
            lists: Lists::new(),
            asked: vec![],
            stales: vec![],
        }
    }

    fn volunteer(&self) -> ClientMessage {
        ClientMessage::KeyholdVolunteer {
            on: true,
            platform: gk::platform::DESKTOP,
            pair: Some((&self.wire).into()),
        }
    }

    fn entry(&self) -> Keyholder {
        self.wire
            .entry(GroupKind::Text, self.m, raw(&self.ik))
            .unwrap()
    }

    /// One frame from the relay; what it sends back.
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
                    p.exits.extend(q.exits.clone());
                    p.pairs.extend(q.pairs.clone());
                    p.held.extend(q.held.clone());
                    p.seed_seats.extend(q.seed_seats.clone());
                    p.promote = p.promote.or(q.promote.clone());
                    p.remove = p.remove.or(q.remove);
                }
                self.due(d, p, now)
            }
            ServerMessage::EpochLists { lists, more, .. } => {
                for l in lists.iter().cloned() {
                    let (v, seats) = wire::list(l);
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
                let mut seen: Vec<[u8; 32]> = vec![];
                for h in piece
                    .chain
                    .iter()
                    .chain(piece.head.iter().map(|l| &l.header))
                {
                    if let Ok(sh) =
                        SignedHeader::decode(&h.body, &h.sig, GroupKind::Text, &self.group)
                    {
                        seen.push(sh.d());
                    }
                }
                if let Some((_, b)) = &self.out {
                    if seen.contains(&b.header.d()) {
                        let (_, b) = self.out.take().unwrap();
                        self.took(b);
                    }
                }
                vec![]
            }
            ServerMessage::EpochStale { reason, .. } => {
                self.stales.push(*reason);
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

    fn due(&mut self, due: u64, piece: DuePiece, now: u64) -> Vec<ClientMessage> {
        self.asked.push(piece.kind);
        if piece.kind == gk::due::GENESIS {
            return self.build(due, &piece, now);
        }
        let Some(held) = &self.held else {
            return vec![];
        };
        // The lists of every version it holds: a Join may add to one, an opening re-keys
        let versions: Vec<(u64, u64)> = held.ring.buckets.iter().map(|k| (k.b, k.v)).collect();
        self.waiting = Some((due, piece));
        vec![ClientMessage::EpochListsWanted {
            group: self.group.clone(),
            gen: held.head.header().gen,
            versions,
        }]
    }

    fn build(&mut self, due: u64, piece: &DuePiece, now: u64) -> Vec<ClientMessage> {
        let built = match piece.kind {
            gk::due::GENESIS => {
                let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
                let st = Start {
                    kind: GroupKind::Text,
                    id: &self.group,
                    me: Me {
                        m: self.m,
                        keys: &self.pair,
                    },
                    ik: &self.ik,
                    entry: self.entry(),
                    joiners: &[&joiner],
                    gated: piece.gated,
                    stored: self.stored,
                    now: now / 1000,
                };
                build_genesis(&st, &mut self.cache)
            }
            kind => {
                let held = self.held.as_ref().expect("a head");
                let grp = Group::new(GroupKind::Text, &self.group, held.head.header().gen).unwrap();
                let seed = held.head.header().seed;
                let behind: HashMap<SeatRef, u32> = piece
                    .held
                    .iter()
                    .map(|(s, n)| (SeatRef::from(*s), *n))
                    .collect();
                let held_of = |s: &SeatRef| behind.get(s).copied().or(Some(seed));
                let me = Me {
                    m: self.m,
                    keys: &self.pair,
                };
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
                    stored: self.stored,
                };
                if kind == gk::due::JOIN {
                    let joiners: Vec<Joiner> = piece
                        .joins
                        .iter()
                        .map(|j| Joiner::try_from(j).unwrap())
                        .collect();
                    let refs: Vec<&Joiner> = joiners.iter().collect();
                    build_join(&hold, &refs, vec![], now / 1000, &mut self.cache, None)
                } else {
                    let exits: Vec<Exit> = piece.exits.iter().cloned().map(Exit::from).collect();
                    let own = self.wire.clone();
                    let pairs = piece.pairs.clone();
                    let pair_of = |e: &Keyholder| -> Option<SeatPublic> {
                        if own.kx() == e.kx {
                            return Some(own.keys.clone());
                        }
                        pairs.iter().find_map(|p| {
                            wire::pair(p, e.m.into())
                                .ok()
                                .filter(|x| x.kx() == e.kx)
                                .map(|x| x.keys)
                        })
                    };
                    let seed_seats = HashMap::new();
                    let ask = OpeningAsk {
                        kind: DueKind::from_code(kind).unwrap().header_kind(),
                        exits: &exits,
                        exits_upto: piece.exits_upto,
                        refresh: kind == gk::due::REFRESH,
                        gated: piece.gated,
                        candidate: None,
                        remove: None,
                        replace: None,
                        finish: piece.finish,
                        seed_seats: &seed_seats,
                        pairs: &pair_of,
                        now: now / 1000,
                    };
                    build_opening(&hold, &ask, &mut self.cache, None)
                }
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

// ── Members (C3b) ─────────────────────────────────────────────────────────

/// One connection's `GroupKeying`, as the app runs it.
struct Member {
    sid: UserId,
    keying: GroupKeying,
    st: SignalStores,
    pins: MemoryPins,
    group: String,
    posts: Vec<OpenedPost>,
    events: Vec<GkEvent>,
    sent: Vec<ClientMessage>,
    /// Frames in flight: kept back while set, taken in order once released.
    hold: bool,
    backlog: Vec<ServerMessage>,
}

impl Member {
    fn new(
        relay: &Relay,
        sid: UserId,
        ik: IdentityKeyPair,
        account: Option<[u8; 16]>,
        seat_keys: Option<SeatKeys>,
        local: Option<LocalGk>,
        group: &str,
    ) -> Member {
        let mut keying = GroupKeying::default();
        let _ = keying.start(GkStart {
            on: true,
            run: relay.groups.run,
            relay_clock: relay.groups.now() / 1000,
            platform: Platform::Desktop,
            help_hold_keys: false,
            user_id: sid,
            identity: ik,
            account,
            seat_keys,
            local,
            visible: true,
        });
        Member {
            sid,
            keying,
            st: SignalStores::new(&ik, sid),
            pins: MemoryPins::default(),
            group: group.to_string(),
            posts: vec![],
            events: vec![],
            sent: vec![],
            hold: false,
            backlog: vec![],
        }
    }

    fn track(&mut self) -> Vec<ClientMessage> {
        let out = self.keying.track(
            GkTrack {
                channel_id: CHANNEL,
                group: self.group.clone(),
                kind: GroupKind::Text,
                anonymous: false,
                hide_members: false,
                viewer_admin: false,
                keeps_history: self.group.starts_with("c:"),
            },
            VaultFloor::None,
        );
        self.took(out)
    }

    fn took(&mut self, out: GkOut) -> Vec<ClientMessage> {
        self.posts.extend(out.posts);
        self.events.extend(out.events);
        self.sent.extend(out.send.iter().cloned());
        out.send
    }

    fn frame(&mut self, f: &ServerMessage, now: u64) -> Vec<ClientMessage> {
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.frame(&mut self.st, f, c);
        self.took(out)
    }

    fn tick(&mut self, now: u64) -> Vec<ClientMessage> {
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.tick(&mut self.st, c);
        self.took(out)
    }

    fn post(&mut self, id: u8, text: &[u8], now: u64) -> Vec<ClientMessage> {
        let c = GkCtx {
            pins: &mut self.pins,
            now,
        };
        let out = self.keying.post(&mut self.st, CHANNEL, [id; 16], text, c);
        self.took(out)
    }

    /// The head epoch it holds `CK` of.
    fn epoch(&self) -> Option<u32> {
        self.keying.current_epoch(&self.group).map(|e| e.epoch)
    }

    fn texts(&self) -> Vec<Vec<u8>> {
        self.posts.iter().map(|p| p.envelope.clone()).collect()
    }

    fn sent_posts(&self) -> Vec<(u32, Vec<u8>)> {
        self.sent
            .iter()
            .filter_map(|m| match m {
                ClientMessage::EpochPost {
                    epoch, ciphertext, ..
                } => Some((*epoch, ciphertext.clone())),
                _ => None,
            })
            .collect()
    }
}

// ── The world ─────────────────────────────────────────────────────────────

struct World {
    relay: Relay,
    holders: Vec<Holder>,
    members: Vec<Member>,
    last_tick: u64,
}

impl World {
    fn new(relay: Relay) -> World {
        World {
            relay,
            holders: vec![],
            members: vec![],
            last_tick: 0,
        }
    }

    fn now(&self) -> u64 {
        self.relay.groups.now()
    }

    /// A guest keyholder following `group`, volunteering. Its index.
    async fn guest_holder(&mut self, group: &str, stored: bool) -> usize {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        self.relay.follow(sid, group);
        let h = Holder::guest(sid, ik, group, stored);
        self.relay.send(sid, h.volunteer()).await;
        self.holders.push(h);
        self.holders.len() - 1
    }

    /// A guest member following `group`, tracking it. Its index.
    async fn guest(&mut self, group: &str) -> usize {
        let ik = voipc_crypto::generate_identity_key_pair();
        let sid = self.relay.session(&ik, None);
        let m = Member::new(&self.relay, sid, ik, None, None, None, group);
        self.join(m).await
    }

    /// `m` follows its group and tracks it.
    async fn join(&mut self, mut m: Member) -> usize {
        self.relay.follow(m.sid, &m.group.clone());
        for msg in m.track() {
            self.relay.send(m.sid, msg).await;
        }
        self.members.push(m);
        self.members.len() - 1
    }

    async fn post(&mut self, i: usize, id: u8, text: &[u8]) {
        let now = self.now();
        let sid = self.members[i].sid;
        for msg in self.members[i].post(id, text, now) {
            self.relay.send(sid, msg).await;
        }
    }

    /// One round: every queue drained into its holder or member, what they send handed back.
    async fn step(&mut self) {
        let now = self.now();
        for i in 0..self.holders.len() {
            let sid = self.holders[i].sid;
            let frames = self.relay.drain(sid).await;
            let mut send = vec![];
            for f in &frames {
                if tracing_on() {
                    eprintln!("[{now}] holder {sid} <- {}", show(f));
                }
                send.extend(self.holders[i].frame(f, now));
            }
            for m in send {
                self.relay.send(sid, m).await;
            }
        }
        let tick = now >= self.last_tick + 1_000;
        for i in 0..self.members.len() {
            let sid = self.members[i].sid;
            let frames = self.relay.drain(sid).await;
            let m = &mut self.members[i];
            let mut send = vec![];
            if m.hold {
                m.backlog.extend(frames);
            } else {
                let all: Vec<ServerMessage> = m.backlog.drain(..).chain(frames).collect();
                for f in &all {
                    if tracing_on() {
                        eprintln!("[{now}] member {sid} <- {}", show(f));
                    }
                    send.extend(m.frame(f, now));
                }
                if tick {
                    send.extend(m.tick(now));
                }
            }
            for msg in send {
                if tracing_on() {
                    eprintln!(
                        "[{now}] member {sid} -> {}",
                        format!("{msg:?}").chars().take(100).collect::<String>()
                    );
                }
                self.relay.send(sid, msg).await;
            }
        }
        if tick {
            self.last_tick = now;
        }
    }

    /// Runs `ms` of relay time.
    async fn run(&mut self, ms: u64) {
        let end = self.now() + ms;
        while self.now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.step().await;
        }
    }

    /// Runs until `done`, at most `ms`; whether it was.
    async fn until(&mut self, ms: u64, done: impl Fn(&World) -> bool) -> bool {
        let end = self.now() + ms;
        while self.now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.step().await;
            if done(self) {
                return true;
            }
        }
        done(self)
    }

    /// Runs until every member in `who` holds `CK` of an epoch.
    async fn seated(&mut self, who: &[usize], ms: u64) -> bool {
        let who = who.to_vec();
        self.until(ms, move |w| {
            who.iter().all(|i| w.members[*i].epoch().is_some())
        })
        .await
    }
}

/// A memory group's world: keyholder 0 and guest members `n`, all holding the head epoch.
async fn memory_world(n: usize) -> (World, String) {
    let mut w = World::new(Relay::new());
    let id = w.relay.groups.id_for(CHANNEL, None);
    assert!(id.starts_with("r:"));
    w.guest_holder(&id, false).await;
    for _ in 0..n {
        w.guest(&id).await;
    }
    let all: Vec<usize> = (0..n).collect();
    assert!(
        w.seated(&all, 10_000).await,
        "every guest holds the epoch key; events: {:?}",
        w.members.iter().map(|m| &m.events).collect::<Vec<_>>()
    );
    (w, id)
}

// ── Scenarios ─────────────────────────────────────────────────────────────

/// (1) A memory group: the volunteer's Genesis, the two guests seated by one Join, and A's
/// post opens for B (a fresh chain's blob attached).
#[tokio::test]
async fn e2e_a_memory_groups_guests_are_seated_by_a_join_and_a_post_opens_for_the_other() {
    let (mut w, _) = memory_world(2).await;
    let asked = w.holders[0].asked.clone();
    assert_eq!(asked, vec![gk::due::GENESIS, gk::due::JOIN]);
    assert!(w.holders[0].stales.is_empty());
    let e = w.members[0].epoch().unwrap();
    assert_eq!(w.members[1].epoch(), Some(e), "one epoch for both");
    w.post(0, 1, b"hello").await;
    w.run(300).await;
    let sent = w.members[0].sent_posts();
    assert_eq!(sent.len(), 1, "the post went at once");
    assert!(w.relay.post_refusals.is_empty());
    assert_eq!(w.members[1].texts(), vec![b"hello".to_vec()]);
    assert_eq!(w.members[1].posts[0].user_id, w.members[0].sid);
    assert!(w.members[0].texts().is_empty(), "no echo to the writer");
}

/// (2) A third guest joins by a later Join batch: it opens a post made after its join (the
/// chain's blob asked with `EpochBlobWanted`, served by the relay), and none made before
/// it followed reaches it.
#[tokio::test]
async fn e2e_a_guest_seated_by_a_later_join_reads_posts_after_its_join_and_none_before() {
    let (mut w, id) = memory_world(2).await;
    w.post(0, 1, b"before").await;
    w.run(300).await;
    assert_eq!(w.members[1].texts(), vec![b"before".to_vec()]);
    let c = w.guest(&id).await;
    assert!(w.seated(&[c], 10_000).await, "{:?}", w.members[c].events);
    assert_eq!(w.holders[0].asked.last(), Some(&gk::due::JOIN));
    w.post(0, 2, b"after").await;
    w.run(500).await;
    assert!(w.relay.post_refusals.is_empty());
    assert_eq!(
        w.members[c].texts(),
        vec![b"after".to_vec()],
        "the joiner opens the post after its join, and has none before"
    );
    assert!(
        w.members[c]
            .sent
            .iter()
            .any(|m| matches!(m, ClientMessage::EpochBlobWanted { .. })),
        "the chain's blob went with the post before: asked of the relay"
    );
    assert_eq!(
        w.members[1].texts(),
        vec![b"before".to_vec(), b"after".to_vec()]
    );
}

/// (3) A guest is kicked: its exit enters a batch, the keyholder's opening drops its seat.
/// The writer is pushed the opening and posts under it; a member that only reads opens that
/// post (fetching the head); the leaver, handed the same post, cannot open it.
#[tokio::test]
async fn e2e_a_leaver_cannot_open_a_post_under_the_opening_its_exit_asked_and_the_others_can() {
    let (mut w, id) = memory_world(3).await;
    let (a, b, c) = (0, 1, 2);
    let e = w.members[a].epoch().unwrap();
    // A writes, so it is pushed the opening
    w.post(a, 1, b"first").await;
    w.run(300).await;
    assert_eq!(w.members[b].texts(), vec![b"first".to_vec()]);
    let leaver = w.members[c].sid;
    w.relay.kick(leaver, &id);
    let opened = w
        .until(15_000, |w| w.members[a].epoch().is_some_and(|x| x > e))
        .await;
    assert!(
        opened,
        "the writer takes the opening; holder asked {:?}, stales {:?}, writer events {:?}",
        w.holders[0].asked, w.holders[0].stales, w.members[a].events
    );
    assert_eq!(w.holders[0].asked.last(), Some(&gk::due::EXITS));
    w.post(a, 2, b"second").await;
    w.run(2_000).await;
    assert!(
        w.relay.post_refusals.is_empty(),
        "{:?}",
        w.relay.post_refusals
    );
    assert_eq!(
        w.members[b].texts(),
        vec![b"first".to_vec(), b"second".to_vec()],
        "a member that only reads opens the post under the new epoch; events {:?}",
        w.members[b].events
    );
    // The leaver is handed the post anyway (as if it got it another way)
    let second = w.relay.fanned.last().cloned().unwrap();
    let now = w.now();
    let sends = w.members[c].frame(&second, now);
    for msg in sends {
        w.relay.send(leaver, msg).await;
    }
    w.run(2_000).await;
    assert_eq!(
        w.members[c].texts(),
        vec![b"first".to_vec()],
        "the leaver cannot open the post under the opening"
    );
    assert_eq!(w.members[c].epoch(), Some(e), "it holds the old epoch only");
}

/// (6) The writer posts under an epoch the relay no longer takes (its pushes still in
/// flight): `EpochRefused{POST, OLD_EPOCH}`. It fetches and posts again under the head
/// everything it sent in the last `HOLD_MS`; the reader opens each again with the same
/// envelope, so the app drops the repeat by its envelope id.
#[tokio::test]
async fn e2e_an_old_epoch_refusal_makes_the_writer_post_again_under_the_head_and_the_reader_gets_the_same_envelope(
) {
    let (mut w, id) = memory_world(4).await;
    let (a, b, c, d) = (0, 1, 2, 3);
    let e = w.members[a].epoch().unwrap();
    w.post(a, 1, b"p1").await;
    w.run(300).await;
    assert_eq!(w.members[b].texts(), vec![b"p1".to_vec()]);
    // A's frames are in flight from here; two openings go by
    w.members[a].hold = true;
    let sid_c = w.members[c].sid;
    w.relay.unfollow(sid_c, &id);
    let _ = w.members[c].keying.untrack(CHANNEL);
    assert!(
        w.until(15_000, |w| w.holders[0].held.as_ref().is_some_and(|h| h
            .head
            .header()
            .epoch
            == e + 1))
            .await,
        "the first opening"
    );
    let sid_d = w.members[d].sid;
    w.relay.unfollow(sid_d, &id);
    let _ = w.members[d].keying.untrack(CHANNEL);
    assert!(
        w.until(15_000, |w| w.holders[0].held.as_ref().is_some_and(|h| h
            .head
            .header()
            .epoch
            == e + 2))
            .await,
        "the second opening"
    );
    // A posts under e: refused, the refusal queued behind the pushes
    w.post(a, 2, b"p2").await;
    assert_eq!(
        w.relay.post_refusals,
        vec![(w.members[a].sid, refused_why::OLD_EPOCH)]
    );
    w.members[a].hold = false;
    let again = w
        .until(15_000, |w| {
            w.members[a]
                .sent_posts()
                .iter()
                .filter(|(ep, _)| *ep == e + 2)
                .count()
                >= 2
        })
        .await;
    assert!(
        again,
        "the writer posts both again under the head; sent {:?}, events {:?}",
        w.members[a]
            .sent_posts()
            .iter()
            .map(|p| p.0)
            .collect::<Vec<_>>(),
        w.members[a].events
    );
    w.run(1_000).await;
    assert_eq!(
        w.relay.post_refusals.len(),
        1,
        "nothing refused once it posts under the head"
    );
    let got = w.members[b].texts();
    assert_eq!(
        got,
        vec![b"p1".to_vec(), b"p1".to_vec(), b"p2".to_vec()],
        "the reader opens p2 once and p1 again with the same envelope; events {:?}",
        w.members[b].events
    );
    let mut shown = got.clone();
    shown.dedup();
    shown.sort();
    shown.dedup();
    assert_eq!(shown, vec![b"p1".to_vec(), b"p2".to_vec()]);
}

// ── With a database ───────────────────────────────────────────────────────

async fn scratch_db() -> (l4f_accounts::store::Store, std::path::PathBuf) {
    let id = rand::random::<u32>();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/gk-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("gk-e2e-{id:08x}.db"));
    let url = match std::env::var("VOIPC_TEST_POSTGRES") {
        // A throwaway database on that server, as accounts/gk.rs's tests make one
        // (`postgres://user@host:port/postgres`)
        Ok(server) => {
            let name = format!("voipc_gkt_{id:08x}");
            let admin = l4f_accounts::store::Store::connect(&server).await.unwrap();
            let l4f_accounts::store::Store::Pg(b) = &admin else {
                panic!("VOIPC_TEST_POSTGRES names a postgres server");
            };
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                .execute(&b.0)
                .await
                .unwrap();
            let (base, _) = server.rsplit_once('/').unwrap();
            format!("{base}/{name}")
        }
        Err(_) => format!("sqlite://{}?mode=rwc", file.display()),
    };
    let store = l4f_accounts::store::Store::connect(&url).await.unwrap();
    let cfg = crate::config::AccountsConfig {
        mode: crate::config::AccountsMode::Optional,
        ..Default::default()
    };
    crate::accounts::Relay::open_with(&cfg, store.clone(), &[9u8; 32])
        .await
        .unwrap();
    (store, file)
}

fn drop_db(file: &std::path::Path) {
    for suffix in ["", "-wal", "-shm", ".lock"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", file.display()));
    }
}

/// An account with its identity and published seat keys (counter 1).
struct Account {
    a: [u8; 16],
    ik: IdentityKeyPair,
    keys: SeatKeys,
}

impl Account {
    async fn new(db: &l4f_accounts::store::Store, name: &str) -> Account {
        let id = l4f_accounts::model::AccountId::new();
        db.create_user(
            &l4f_accounts::model::NewUser {
                id,
                username: name.into(),
                display_name: name.into(),
                email_pending: None,
                password_hash: None,
                created_at: l4f_accounts::util::now(),
            },
            None,
        )
        .await
        .unwrap();
        let ik = voipc_crypto::generate_identity_key_pair();
        let keys = SeatKeys::generate(1, wall_ms() / 1000);
        let public = keys.pair.public();
        let e = Endorsement::sign(
            &ik,
            Origin::VaultSeat,
            MemberId::Account(id.0),
            keys.n,
            keys.made,
            &public,
        )
        .unwrap();
        crate::accounts::gk::put_seat_keys(
            db,
            &id.0,
            &crate::accounts::gk::SeatKeys {
                n: keys.n,
                kem: public.kem_bytes().into(),
                dh: public.dh_bytes().into(),
                made: e.made,
                sig: e.sig.to_vec(),
                published: wall_ms(),
            },
        )
        .await
        .unwrap();
        Account { a: id.0, ik, keys }
    }

    fn keys(&self) -> SeatKeys {
        SeatKeys::from_bytes(&self.keys.to_bytes()).unwrap()
    }
}

impl World {
    /// A session of `acc` on this relay, as a C3b member of `group` with `local` kept.
    async fn account(&mut self, acc: &Account, group: &str, local: Option<LocalGk>) -> usize {
        let sid = self.relay.session(&acc.ik, Some(acc.a));
        let m = Member::new(
            &self.relay,
            sid,
            acc.ik,
            Some(acc.a),
            Some(acc.keys()),
            local,
            group,
        );
        self.join(m).await
    }
}

/// (4) A stored group across a relay restart (2i): the new relay loads the head from the
/// database; account members come back on new connections with only their local floor, are
/// answered from the loaded snapshot, and post and read again under the same head.
#[tokio::test]
async fn e2e_a_stored_group_across_a_restart_lets_a_member_with_only_its_floor_post_again() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let ann = Account::new(&db, "ann").await;
    let bob = Account::new(&db, "bob").await;
    let mut w = World::new(Relay::new());
    w.relay.groups.attach(db.clone(), inc);
    let id = w.relay.groups.id_for(CHANNEL, Some("lounge"));
    assert_eq!(id, "c:lounge");
    w.guest_holder(&id, true).await;
    let a = w.account(&ann, &id, None).await;
    let b = w.account(&bob, &id, None).await;
    assert!(
        w.seated(&[a, b], 15_000).await,
        "seated: holder asked {:?}, stales {:?}, events {:?} {:?}",
        w.holders[0].asked,
        w.holders[0].stales,
        w.members[a].events,
        w.members[b].events
    );
    let head = w.holders[0].held.as_ref().unwrap().head.d();
    let e = w.members[a].epoch().unwrap();
    w.post(a, 1, b"before the restart").await;
    w.run(1_000).await;
    assert_eq!(w.members[b].texts(), vec![b"before the restart".to_vec()]);
    // The connections end with the relay: each app keeps its local floor
    let mut locals = vec![];
    for m in w.members.iter_mut() {
        let _ = m.keying.end();
        locals.push(m.keying.local().cloned().expect("a local floor"));
    }
    for f in locals[0].floors.values() {
        assert_eq!(f.floor.d, head, "the floor is the head");
    }
    w.relay.groups.on_purge("lounge");
    drop(w);

    // The relay starts again over the same database
    let inc2 = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inc2, inc, "the same incarnation");
    let mut w = World::new(Relay::new());
    w.relay.groups.attach(db.clone(), inc2);
    assert_eq!(w.relay.groups.id_for(CHANNEL, Some("lounge")), id);
    let a = w.account(&ann, &id, Some(locals[0].clone())).await;
    let b = w.account(&bob, &id, Some(locals[1].clone())).await;
    let back = w.seated(&[a, b], 15_000).await;
    assert!(
        back,
        "with only its floor, each member holds the head's key again; events {:?} {:?}; \
         fetches sent {}",
        w.members[a].events,
        w.members[b].events,
        w.members[a]
            .sent
            .iter()
            .filter(|m| matches!(m, ClientMessage::EpochFetch { .. }))
            .count()
    );
    assert_eq!(w.members[a].epoch(), Some(e), "the same head epoch");
    w.post(a, 2, b"after the restart").await;
    w.run(1_000).await;
    assert!(
        w.relay.post_refusals.is_empty(),
        "{:?}",
        w.relay.post_refusals
    );
    assert_eq!(w.members[b].texts(), vec![b"after the restart".to_vec()]);
    drop_db(&file);
}

/// (5) A gated group: an account desktop keyholder, account members. The writer's post goes
/// once its fold of the gated names passes; the gate goes off, an exit's opening carries
/// `gated` false, and the writer, pushed that opening, is told the group is open
/// (`GatedOpened`). Whether it also holds that epoch's key is scenario (3)'s.
#[tokio::test]
async fn e2e_a_gated_group_turned_open_tells_its_writer_gated_opened_at_the_next_opening() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let kim = Account::new(&db, "kim").await;
    let ann = Account::new(&db, "ann").await;
    let bob = Account::new(&db, "bob").await;
    let cat = Account::new(&db, "cat").await;
    let mut w = World::new(Relay::new());
    w.relay.groups.attach(db.clone(), inc);
    let id = w.relay.groups.id_for(CHANNEL, None);
    // The keyholder: kim's desktop, following first so the channel's gate can turn on
    let ksid = w.relay.session(&kim.ik, Some(kim.a));
    w.relay.follow(ksid, &id);
    w.relay.groups.on_gate(CHANNEL, true);
    let k = Holder::desktop(ksid, kim.ik, kim.a, 1, &id, false);
    w.relay.send(ksid, k.volunteer()).await;
    w.holders.push(k);
    let a = w.account(&ann, &id, None).await;
    let b = w.account(&bob, &id, None).await;
    let c = w.account(&cat, &id, None).await;
    assert!(
        w.seated(&[a, b, c], 15_000).await,
        "seated: holder asked {:?}, stales {:?}, events {:?}",
        w.holders[0].asked,
        w.holders[0].stales,
        w.members[a].events
    );
    assert!(
        w.holders[0].held.as_ref().unwrap().head.header().gated,
        "the head is gated"
    );
    let e = w.members[a].epoch().unwrap();
    // A writes in the gated group: its fold of the names passes first
    w.post(a, 1, b"gated").await;
    let read = w.until(15_000, |w| !w.members[b].posts.is_empty()).await;
    assert!(
        read,
        "the gated post goes once the names fold; writer sent {:?}, events {:?}",
        w.members[a]
            .sent
            .iter()
            .filter(|m| matches!(m, ClientMessage::EpochNames { .. }))
            .collect::<Vec<_>>(),
        w.members[a].events
    );
    assert_eq!(w.members[b].texts(), vec![b"gated".to_vec()]);
    // The gate goes off; an exit's opening clears it
    w.relay.groups.on_gate(CHANNEL, false);
    let sid_c = w.members[c].sid;
    w.relay.unfollow(sid_c, &id);
    let gated_opened = GkEvent::Warning {
        channel_id: CHANNEL,
        kind: Warn::GatedOpened,
        n: 0,
    };
    let told = w
        .until(20_000, |w| {
            w.members[a].events.contains(&gated_opened)
                && w.holders[0]
                    .held
                    .as_ref()
                    .is_some_and(|h| h.head.header().epoch > e)
        })
        .await;
    assert_eq!(
        w.holders[0].asked.last(),
        Some(&gk::due::EXITS),
        "the exit's opening was asked"
    );
    let head = w.holders[0].held.as_ref().unwrap().head.header().clone();
    assert!(
        head.epoch > e && !head.gated,
        "the opening after the gate went off carries gated false"
    );
    assert!(
        told,
        "the writer, pushed that opening, is told the group is open: {:?}",
        w.members[a].events
    );
    drop_db(&file);
}

/// (7) A stored group gated after it opened: the gate's opening goes only to writers, so a
/// member that only read holds a names floor from the open period. A gated Join, an exit's
/// opening and another Join follow. After a relay restart the member comes back with only
/// its floor, takes the head (the last Join) with its epoch's opening (not the gate-on
/// one), and folds the names from the gate-on opening's list and the first Join's, which
/// the relay kept and loaded from its database; its post goes and the other reads it.
#[tokio::test]
async fn e2e_a_member_whose_names_floor_predates_the_gate_folds_from_the_gate_on_opening_after_a_restart(
) {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let kim = Account::new(&db, "kim").await;
    let ann = Account::new(&db, "ann").await;
    let bob = Account::new(&db, "bob").await;
    let cat = Account::new(&db, "cat").await;
    let dan = Account::new(&db, "dan").await;
    let mut w = World::new(Relay::new());
    w.relay.groups.attach(db.clone(), inc);
    let id = w.relay.groups.id_for(CHANNEL, Some("c:den"));
    assert_eq!(id, "c:den");
    let ksid = w.relay.session(&kim.ik, Some(kim.a));
    w.relay.follow(ksid, &id);
    let k = Holder::desktop(ksid, kim.ik, kim.a, 1, &id, true);
    w.relay.send(ksid, k.volunteer()).await;
    w.holders.push(k);
    let a = w.account(&ann, &id, None).await;
    let b = w.account(&bob, &id, None).await;
    assert!(
        w.seated(&[a, b], 15_000).await,
        "seated: holder asked {:?}, stales {:?}",
        w.holders[0].asked,
        w.holders[0].stales
    );
    // The gate goes on: its opening, then a gated Join; bob writes nothing meanwhile
    w.relay.groups.on_gate(CHANNEL, true);
    let gated = w
        .until(15_000, |w| {
            w.holders[0]
                .held
                .as_ref()
                .is_some_and(|h| h.head.header().gated)
        })
        .await;
    assert!(gated, "the gate's opening: asked {:?}", w.holders[0].asked);
    let c = w.account(&cat, &id, None).await;
    assert!(w.seated(&[c], 15_000).await, "cat seated by a gated Join");
    let gate_epoch = w.holders[0].held.as_ref().unwrap().head.header().epoch;
    // cat leaves: an exit's opening, a new epoch of the gated period; then dan joins
    let sid_c = w.members[c].sid;
    w.relay.unfollow(sid_c, &id);
    let _ = w.members[c].keying.untrack(CHANNEL);
    let opened = w
        .until(15_000, |w| {
            w.holders[0]
                .held
                .as_ref()
                .is_some_and(|h| h.head.header().epoch > gate_epoch)
        })
        .await;
    assert!(opened, "the exit's opening: asked {:?}", w.holders[0].asked);
    let d = w.account(&dan, &id, None).await;
    assert!(w.seated(&[d], 15_000).await, "dan seated by a gated Join");
    // The keyholder holds its Join once it sees the header pushed back
    let joined = w
        .until(5_000, |w| {
            w.holders[0].held.as_ref().is_some_and(|h| {
                h.head.header().kind == Kind::Join && h.head.header().epoch > gate_epoch
            })
        })
        .await;
    assert!(joined, "dan's Join in the exit's epoch");
    let head = w.holders[0].held.as_ref().unwrap().head.clone();
    assert!(head.header().gated && head.header().kind == Kind::Join);
    assert!(head.header().epoch > gate_epoch);
    // The relay restarts; the apps come back with what each kept
    let mut locals = vec![];
    for m in w.members.iter_mut() {
        let _ = m.keying.end();
        locals.push(m.keying.local().cloned().expect("a local floor"));
    }
    w.relay.groups.on_purge(&id);
    drop(w);
    let mut w = World::new(Relay::new());
    w.relay.groups.attach(db.clone(), inc);
    let a = w.account(&ann, &id, Some(locals[a].clone())).await;
    let b = w.account(&bob, &id, Some(locals[b].clone())).await;
    assert!(
        w.seated(&[a, b], 15_000).await,
        "back at the head: {:?} {:?}",
        w.members[a].events,
        w.members[b].events
    );
    w.post(b, 1, b"after the gate").await;
    let read = w.until(15_000, |w| !w.members[a].posts.is_empty()).await;
    assert!(
        read,
        "bob's fold reaches the head from the gate-on opening; sent {:?}, events {:?}",
        w.members[b]
            .sent
            .iter()
            .filter(|m| matches!(m, ClientMessage::EpochNames { .. }))
            .collect::<Vec<_>>(),
        w.members[b].events
    );
    assert_eq!(w.members[a].texts(), vec![b"after the gate".to_vec()]);
    drop_db(&file);
}
