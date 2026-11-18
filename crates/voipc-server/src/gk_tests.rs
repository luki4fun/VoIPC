//! The relay's group key (plan 2a–2f, 2h, 2i), through `GroupState`, the stores and
//! `Groups`. Keyholders here build honest commits with `voipc_crypto::group_key::build`
//! from the dues the relay sends them, as a keyholder app would.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use voipc_crypto::group_key::build::{
    build_genesis, build_join, build_opening, kx_tag, Built, Holding, ListSeat, Lists, OpeningAsk,
    RowBases, Start,
};
use voipc_crypto::group_key::commit::{DueKind, Exit, HolderRef, Joiner, Pair, ReplaceAsk};
use voipc_crypto::group_key::{
    path_ok, seat_record, Endorsement, Group, GroupKind, Keyholder, Keyring, Kind, Me, MemberId,
    Origin, SeatPair, SeatPublic, SeatRef,
};
use voipc_crypto::IdentityKeyPair;
use voipc_protocol::gk::{
    self, commit_frame_overhead, cut_commit, refused_why, stale, wait, CommitPiece, DuePiece,
    InPiece, Part, Parts, Seq, PIECE_MAX_BYTES,
};
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::UserId;
use zeroize::Zeroizing;

use crate::gk::due::{exit_cap, Exits, EXIT_BATCH_MAX};
use crate::gk::group::{cause, Fetch, Fetched, GroupState, OpenCaps, Out};
use crate::gk::holders::{Holders, Volunteer};
use crate::gk::push;
use crate::gk::snapshot::HeadView;
use crate::gk::store::Store;

const ID: &str = "r:00112233445566778899aabbccddeeff:7";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// A connection: its identity and its seat pair (0x02), which is also its keyholder pair;
/// or a device of an account with the account's seat keys (0x01).
struct Person {
    sid: UserId,
    ik: IdentityKeyPair,
    pair: SeatPair,
    endorsement: Endorsement,
    account: Option<[u8; 16]>,
}

impl Person {
    fn guest(sid: UserId) -> Person {
        let ik = voipc_crypto::generate_identity_key_pair();
        let pair = SeatPair::generate();
        let endorsement = Endorsement::sign(
            &ik,
            Origin::Connection,
            MemberId::Conn(sid),
            1,
            now_ms() / 1000,
            &pair.public(),
        )
        .unwrap();
        Person {
            sid,
            ik,
            pair,
            endorsement,
            account: None,
        }
    }

    fn account(sid: UserId, a: [u8; 16]) -> Person {
        let ik = voipc_crypto::generate_identity_key_pair();
        let pair = SeatPair::generate();
        let endorsement = Endorsement::sign(
            &ik,
            Origin::VaultSeat,
            MemberId::Account(a),
            1,
            now_ms() / 1000,
            &pair.public(),
        )
        .unwrap();
        Person {
            sid,
            ik,
            pair,
            endorsement,
            account: Some(a),
        }
    }

    fn m(&self) -> MemberId {
        self.account
            .map_or(MemberId::Conn(self.sid), MemberId::Account)
    }

    fn wire(&self) -> Pair {
        Pair {
            keys: self.pair.public(),
            endorsement: self.endorsement.clone(),
        }
    }

    fn seat(&self) -> SeatRef {
        self.pair.public().seat(self.m())
    }

    fn joiner(&self) -> Joiner {
        Joiner {
            seat: self.seat(),
            ik: raw(&self.ik),
            keys: self.pair.public(),
            endorsement: self.endorsement.clone(),
            returning: false,
        }
    }

    fn fetch(&self) -> Fetch {
        Fetch {
            have: None,
            pair: Some(self.wire()),
            ik: Some(raw(&self.ik)),
        }
    }

    fn volunteer(&self, platform: u8) -> Volunteer {
        Volunteer {
            sid: self.sid,
            platform,
            m: self.m(),
            ik: raw(&self.ik),
            pair: self.wire(),
            seat: Some(self.joiner()),
        }
    }

    fn entry(&self) -> Keyholder {
        self.wire()
            .entry(GroupKind::Text, self.m(), raw(&self.ik))
            .unwrap()
    }

    fn me(&self) -> Me<'_> {
        Me {
            m: self.m(),
            keys: &self.pair,
        }
    }
}

/// What a keyholder holds once its commit was taken.
struct Holds {
    ring: Keyring,
    krk: Zeroizing<[u8; 32]>,
    cache: RowBases,
}

impl Holds {
    fn took(&mut self, b: Built) {
        self.ring = b.ring;
        self.krk = b.krk;
    }
}

fn new_group(stored: bool) -> GroupState {
    GroupState::new(
        ID.into(),
        GroupKind::Text,
        stored,
        Arc::new(OpenCaps::default()),
    )
}

/// The dues `out` sends `sid`, each reassembled as a keyholder takes them.
fn dues(out: &[Out], sid: UserId) -> Vec<(u64, DuePiece)> {
    let mut parts: Parts<u64, DuePiece> = Parts::new(Seq::Due);
    let mut whole = vec![];
    for Out(to, frames) in out {
        if *to != sid {
            continue;
        }
        for f in frames {
            if let ServerMessage::EpochDue {
                due,
                part,
                last,
                piece,
                ..
            } = f
            {
                let bytes = push::len(f);
                if let Part::Whole(d, ps) = parts
                    .take(*due, *part, *last, (**piece).clone(), bytes)
                    .part
                {
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
                    whole.push((d, p));
                }
            }
        }
    }
    whole
}

/// Every `EpochIn` piece `out` sends `sid`, merged per sequence.
fn ins(out: &[Out], sid: UserId) -> Vec<InPiece> {
    let mut whole = vec![];
    for Out(to, frames) in out {
        if *to != sid {
            continue;
        }
        let mut cur = InPiece::default();
        for f in frames {
            if let ServerMessage::EpochIn { last, piece, .. } = f {
                let p = (**piece).clone();
                cur.chain.extend(p.chain);
                cur.walk.extend(p.walk);
                cur.self_rows.extend(p.self_rows);
                cur.kh = cur.kh.or(p.kh);
                cur.seed_welcome = cur.seed_welcome.or(p.seed_welcome);
                cur.head = cur.head.or(p.head);
                cur.opening = cur.opening.or(p.opening);
                cur.own_join = cur.own_join.or(p.own_join);
                cur.leaf = cur.leaf.or(p.leaf);
                cur.path = cur.path.or(p.path);
                cur.seal = cur.seal.or(p.seal);
                cur.seat = cur.seat.or(p.seat);
                cur.pushed = p.pushed;
                if *last {
                    whole.push(std::mem::take(&mut cur));
                }
            }
        }
    }
    whole
}

fn waits(out: &[Out], sid: UserId) -> Vec<u8> {
    out.iter()
        .filter(|o| o.0 == sid)
        .flat_map(|o| &o.1)
        .filter_map(|f| match f {
            ServerMessage::EpochWait { why, .. } => Some(*why),
            _ => None,
        })
        .collect()
}

fn stales(out: &[Out], sid: UserId) -> Vec<u8> {
    out.iter()
        .filter(|o| o.0 == sid)
        .flat_map(|o| &o.1)
        .filter_map(|f| match f {
            ServerMessage::EpochStale { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect()
}

/// A keyholder's commit, cut into parts and sent; the `Taken` at its last part.
fn send(
    g: &mut GroupState,
    sid: UserId,
    due: u64,
    b: &Built,
    now: u64,
    out: &mut Vec<Out>,
) -> Option<crate::gk::group::Taken> {
    let piece = CommitPiece::try_from(b.commit.clone()).unwrap();
    let parts = cut_commit(piece, PIECE_MAX_BYTES - commit_frame_overhead(ID)).unwrap();
    let n = parts.len();
    let mut taken = None;
    for (i, p) in parts.into_iter().enumerate() {
        let bytes = push::len(&p);
        taken = g.commit_part(sid, due, i as u16, i + 1 == n, p, bytes, now, out);
    }
    taken
}

async fn land(
    g: &mut GroupState,
    store: &Store,
    t: crate::gk::group::Taken,
    now: u64,
    out: &mut Vec<Out>,
) -> Vec<(UserId, bool)> {
    store.commit(g, &t, now).await.unwrap();
    let answer = g.apply(t, now, out);
    store.prune(g);
    answer
}

fn group_of(g: &GroupState) -> Group {
    Group::new(GroupKind::Text, ID, g.gen().unwrap()).unwrap()
}

fn lists(g: &GroupState) -> Lists {
    g.leaves
        .iter()
        .map(|l| {
            let seats = l
                .seats
                .iter()
                .map(|s| ListSeat {
                    seat: *s,
                    dh: g.seats[s].dh.to_vec(),
                })
                .collect();
            (l.version(), seats)
        })
        .collect()
}

/// The keyholder `k` builds the Genesis due `piece` asked of it.
fn genesis(k: &Person, id: &str, piece: &DuePiece, stored: bool, now: u64) -> Built {
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let st = Start {
        kind: GroupKind::Text,
        id,
        me: k.me(),
        ik: &k.ik,
        entry: k.entry(),
        joiners: &[&joiner],
        gated: piece.gated,
        stored,
        now: now / 1000,
    };
    build_genesis(&st, &mut RowBases::new()).unwrap()
}

fn holding<R>(
    g: &GroupState,
    k: &Person,
    h: &mut Holds,
    f: impl FnOnce(&Holding, &mut RowBases) -> R,
) -> R {
    let grp = group_of(g);
    let head = g.head.as_ref().unwrap();
    let lists = lists(g);
    let held = |s: &SeatRef| g.seats.get(s).map(|x| x.seed);
    let hold = Holding {
        g: &grp,
        head: &head.sh,
        kh: &head.kh,
        ring: &h.ring,
        krk: &h.krk,
        me: k.me(),
        ik: &k.ik,
        lists: &lists,
        held: &held,
        rolls: g.rolls,
        stored: g.stored,
    };
    f(&hold, &mut h.cache)
}

fn join(g: &GroupState, k: &Person, h: &mut Holds, piece: &DuePiece, now: u64) -> Built {
    let joiners: Vec<Joiner> = piece
        .joins
        .iter()
        .map(|j| Joiner::try_from(j).unwrap())
        .collect();
    let refs: Vec<&Joiner> = joiners.iter().collect();
    holding(g, k, h, |hold, cache| {
        build_join(hold, &refs, vec![], now / 1000, cache, None)
    })
    .unwrap()
}

fn opening(g: &GroupState, k: &Person, h: &mut Holds, piece: &DuePiece, now: u64) -> Built {
    let exits: Vec<Exit> = piece.exits.iter().cloned().map(Exit::from).collect();
    let mut pairs: HashMap<[u8; 32], SeatPublic> = g
        .holders
        .pairs
        .iter()
        .map(|(kx, p)| (*kx, p.keys.clone()))
        .collect();
    // A candidate's pair comes with the due (`DuePiece.pairs`)
    let candidate = piece
        .promote
        .as_ref()
        .map(|c| voipc_crypto::group_key::commit::Candidate::try_from(c).unwrap());
    if let Some(c) = &candidate {
        pairs.insert(c.pair.kx(), c.pair.keys.clone());
    }
    let seed_seats = HashMap::new();
    holding(g, k, h, |hold, cache| {
        let pair_of = |e: &Keyholder| pairs.get(&e.kx).cloned();
        let ask = OpeningAsk {
            kind: DueKind::from_code(piece.kind).unwrap().header_kind(),
            exits: &exits,
            exits_upto: piece.exits_upto,
            refresh: piece.kind == gk::due::REFRESH,
            gated: piece.gated,
            candidate: candidate.as_ref(),
            remove: piece.remove.map(Into::into),
            replace: None,
            finish: piece.finish,
            seed_seats: &seed_seats,
            pairs: &pair_of,
            now: now / 1000,
        };
        build_opening(hold, &ask, cache, None)
    })
    .unwrap()
}

/// A memory group with guest keyholder 1 and guest members 2 and 3, all seated: a Genesis,
/// then one Join.
async fn seated_group(store: &Store) -> (GroupState, Person, Holds, Vec<Person>, u64) {
    seated_group_back(store, 0).await
}

/// `seated_group` with its Genesis dated `back` ms ago (a seed old enough to roll).
async fn seated_group_back(
    store: &Store,
    back: u64,
) -> (GroupState, Person, Holds, Vec<Person>, u64) {
    let mut g = new_group(false);
    let k = Person::guest(1);
    let people: Vec<Person> = (2..4).map(Person::guest).collect();
    let mut now = now_ms();
    let mut out = vec![];
    g.follow(1, None);
    g.volunteer(1, Some(k.volunteer(gk::platform::DESKTOP)), now, &mut out);
    for p in &people {
        g.follow(p.sid, None);
        assert_eq!(g.fetch(p.sid, p.fetch(), now, &mut out), Fetched::Not);
    }
    let (due, piece) = dues(&out, 1).pop().expect("a Genesis due");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let b = genesis(&k, ID, &piece, false, now - back);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    let answered = land(&mut g, store, t, now, &mut out).await;
    assert_eq!(answered, vec![(1, false)], "the volunteer's own seat");
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    assert_eq!((piece.kind, piece.joins.len()), (gk::due::JOIN, 2));
    let b = join(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    let answered = land(&mut g, store, t, now, &mut out).await;
    assert_eq!(
        answered,
        vec![(2, true), (3, true)],
        "each joiner, with its own Join"
    );
    h.took(b);
    (g, k, h, people, now)
}

#[tokio::test]
async fn a_first_fetch_asks_the_best_volunteer_for_a_genesis_and_a_join_seats_the_fetchers() {
    let store = Store::memory();
    let (g, k, _, people, _) = seated_group(&store).await;
    assert_eq!(g.seats.len(), 3);
    assert_eq!(g.holders.set.len(), 1);
    assert_eq!(g.holders.set[0].kx, k.wire().kx());
    for p in &people {
        assert!(g.seats.contains_key(&p.seat()));
    }
    assert_eq!(g.head.as_ref().unwrap().sh.header().kind, Kind::Join);
}

#[tokio::test]
async fn a_fetch_with_no_volunteer_waits_for_a_keyholder_and_one_without_seat_keys_is_told_so() {
    let mut g = new_group(false);
    let p = Person::guest(2);
    let mut out = vec![];
    let now = now_ms();
    g.follow(2, None);
    g.fetch(2, Fetch::default(), now, &mut out);
    g.fetch(2, p.fetch(), now, &mut out);
    g.fetch(9, p.fetch(), now, &mut out);
    assert_eq!(waits(&out, 2), vec![wait::NO_SEAT_KEYS, wait::NO_KEYHOLDER]);
    assert!(dues(&out, 2).is_empty());
    assert!(out.iter().any(|o| o.0 == 9
        && matches!(
            o.1[0],
            ServerMessage::EpochRefused {
                why: refused_why::NOT_MEMBER,
                ..
            }
        )));
}

#[tokio::test]
async fn a_seated_fetch_is_answered_from_the_snapshot_with_its_leaf_path_seal_and_keying() {
    let store = Store::memory();
    let (mut g, _, _, people, now) = seated_group(&store).await;
    let p = &people[0];
    let mut out = vec![];
    assert_eq!(
        g.fetch(p.sid, p.fetch(), now, &mut out),
        Fetched::Seated(p.seat())
    );
    let snap = g.snapshot().unwrap();
    let mut piece = snap.head_piece(None, None, false);
    snap.seat_piece(&p.seat(), &mut piece);
    let at = snap.base_of(&p.seat()).unwrap();
    let gen = g.gen().unwrap();
    let base = store.base(ID, &gen, &p.seat(), at).await;
    piece.seat = snap.keying(&p.seat(), base);
    let h = snap.head.header();
    let leaf = voipc_crypto::group_key::Leaf::try_from(piece.leaf.unwrap()).unwrap();
    let path = voipc_crypto::group_key::Path::from(piece.path.unwrap());
    assert!(path_ok(&h.bucket_root, h.buckets, &leaf, &path));
    assert_eq!(piece.seal.map(|s| s.len()), Some(gk::SEAL_BYTES));
    let seat = piece.seat.unwrap();
    assert_eq!(seat.welcome.map(|w| w.len()), Some(gk::SEAT_WELCOME_BYTES));
    assert!(
        piece.opening.is_some(),
        "the head is a Join: its epoch's opening comes too"
    );
    assert_eq!(piece.walk.len(), 1, "back to the Genesis");
    // A memory group's welcome goes once its answers went out
    store.welcomed(&p.seat());
    assert!(store.base(ID, &gen, &p.seat(), at).await.is_none());
}

#[tokio::test]
async fn exits_close_into_a_fresh_due_whose_commit_drops_their_seats() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    assert_eq!(g.exits.waiting(), 1);
    now += 3 * 20 + 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("an exits due");
    assert_eq!(
        (piece.kind, piece.exits.len(), piece.exits_upto),
        (gk::due::EXITS, 1, 1)
    );
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert!(!g.seats.contains_key(&people[0].seat()));
    assert_eq!(g.exits.waiting(), 0);
    assert_eq!(g.head.as_ref().unwrap().sh.header().exits_upto, 1);
}

#[tokio::test]
async fn a_genesis_header_deals_no_exit_and_the_batch_its_due_carried_is_done() {
    let store = Store::memory();
    let (mut g, _, _, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    // The keyholder goes, then a member: no keyholder is online for the exit
    g.leave(1, cause::DISCONNECT, now, &mut out);
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    now += 3_000;
    g.tick(now, &mut out);
    assert_eq!(g.exits.closed.len(), 1, "closed, waiting for an opening");
    assert_eq!(
        g.exits.waiting(),
        2,
        "the keyholder's own seat and the member's"
    );
    // A new volunteer: a memory group starts a new generation at once
    let v = Person::guest(5);
    g.follow(5, None);
    let mut out = vec![];
    g.volunteer(5, Some(v.volunteer(gk::platform::DESKTOP)), now, &mut out);
    let (due, piece) = dues(&out, 5).pop().expect("a Genesis due");
    assert_eq!(piece.kind, gk::due::GENESIS);
    assert_eq!(
        (piece.exits.len(), piece.exits_upto),
        (2, 2),
        "it carries the closed batch"
    );
    let b = genesis(&v, ID, &piece, false, now);
    assert_eq!(b.header.header().exits_upto, 0, "a Genesis names no exit");
    let mut out = vec![];
    let t = send(&mut g, 5, due, &b, now, &mut out).expect("taken");
    assert_eq!(t.applied.exits_done, vec![1, 2]);
    land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(g.exits.waiting(), 0, "the batch is done, not asked again");
    assert_eq!(
        g.seats.len(),
        1,
        "a new generation seats only the volunteer"
    );
    assert!(
        g.members[&people[1].sid].seat.is_none(),
        "the others fetch again"
    );
}

#[tokio::test]
async fn a_due_lists_every_seat_on_a_seed_older_than_the_heads_and_finishes_only_with_none() {
    let store = Store::memory();
    let (mut g, _, _, people, now) = seated_group(&store).await;
    // As if a roll ran: the head on seed 2, one seat still on 1
    let behind = people[0].seat();
    for (s, x) in g.seats.iter_mut() {
        x.seed = if *s == behind { 0 } else { 1 };
    }
    g.next_refresh = Some(now);
    let mut out = vec![];
    g.tick(now + 2_000, &mut out);
    let (_, piece) = dues(&out, 1).pop().expect("a refresh due");
    assert_eq!(piece.kind, gk::due::REFRESH);
    assert_eq!(piece.held, vec![(behind.into(), 0)]);
    assert!(!piece.finish);
}

#[tokio::test]
async fn a_part_for_another_due_is_not_due_and_a_commit_on_a_moved_head_is_head_moved() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().unwrap();
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    assert!(send(&mut g, 1, due + 7, &b, now, &mut out).is_none());
    assert_eq!(stales(&out, 1)[0], stale::NOT_DUE);
    assert_eq!(g.dues.len(), 1, "the due stays out");
    // Another session's commit for it is no more due
    let mut out = vec![];
    assert!(send(&mut g, 2, due, &b, now, &mut out).is_none());
    assert_eq!(stales(&out, 2)[0], stale::NOT_DUE);
    // The head moves under the commit (as when another keyholder's due landed)
    let mut moved = g.head.clone().unwrap();
    moved.sh = g.recent[0].clone();
    let real = g.head.replace(moved);
    let mut out = vec![];
    assert!(send(&mut g, 1, due, &b, now, &mut out).is_none());
    assert_eq!(stales(&out, 1), vec![stale::HEAD_MOVED]);
    assert_eq!(g.missed_total, 0, "no miss");
    g.head = real;
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken on the head");
    land(&mut g, &store, t, now, &mut out).await;
}

#[tokio::test]
async fn a_commit_failing_a_rule_is_a_check_miss_and_a_deadline_passed_is_a_timed_out_miss() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().unwrap();
    let mut b = opening(&g, &k, &mut h, &piece, now);
    b.commit.seals.pop();
    let mut out = vec![];
    assert!(send(&mut g, 1, due, &b, now, &mut out).is_none());
    assert_eq!(stales(&out, 1), vec![stale::CHECK]);
    assert_eq!(g.missed_total, 1);
    assert_eq!(g.holders.stats[&k.wire().kx()].missed.len(), 1);
    // The only keyholder missed: asked again after the retry wait, and that one times out
    now += 30_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (_, again) = dues(&out, 1).pop().expect("asked again");
    assert_eq!(again.exits_upto, piece.exits_upto);
    now += 4_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    assert_eq!(stales(&out, 1), vec![stale::TIMED_OUT]);
    assert_eq!(g.missed_total, 2);
}

#[tokio::test]
async fn a_decline_passes_the_due_over_without_a_miss() {
    let store = Store::memory();
    let (mut g, _, _, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, _) = dues(&out, 1).pop().unwrap();
    let mut out = vec![];
    g.decline(1, due, gk::decline::CANDIDATE, now, &mut out);
    assert_eq!(g.missed_total, 0);
    assert!(
        g.holders.stats.values().all(|s| s.count() == 0),
        "a CANDIDATE decline is not counted"
    );
    assert!(g.dues.is_empty(), "nobody else to ask");
}

#[tokio::test]
async fn a_blob_makes_a_writer_that_hears_of_pending_exits_and_a_third_is_refused() {
    let store = Store::memory();
    let (mut g, _, _, people, now) = seated_group(&store).await;
    let h = g.head.as_ref().unwrap().sh.header().clone();
    let mut out = vec![];
    let (w, other) = (&people[0], &people[1]);
    assert_eq!(
        g.post_blob(w.sid, h.gen, h.epoch + 1, vec![1], now, &mut out),
        Err(refused_why::OLD_EPOCH)
    );
    assert_eq!(
        g.post_blob(w.sid, h.gen, h.epoch, vec![0; 1025], now, &mut out),
        Err(refused_why::TOO_LARGE)
    );
    g.post_blob(w.sid, h.gen, h.epoch, vec![1], now, &mut out)
        .unwrap();
    g.post_blob(w.sid, h.gen, h.epoch, vec![2], now, &mut out)
        .unwrap();
    assert_eq!(
        g.post_blob(w.sid, h.gen, h.epoch, vec![3], now, &mut out),
        Err(refused_why::THIRD_BLOB)
    );
    let mut out = vec![];
    g.leave(other.sid, cause::LEAVE, now, &mut out);
    let exits: Vec<u64> = out
        .iter()
        .filter(|o| o.0 == w.sid)
        .flat_map(|o| &o.1)
        .filter_map(|f| match f {
            ServerMessage::EpochExit { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(exits, vec![1], "the writer hears of the exit at once");
}

#[tokio::test]
async fn an_opening_pushes_its_header_to_keyholders_and_to_writers_with_their_leaf() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let hd = g.head.as_ref().unwrap().sh.header().clone();
    let mut out = vec![];
    let w = &people[0];
    g.post_blob(w.sid, hd.gen, hd.epoch, vec![1], now, &mut out)
        .unwrap();
    g.leave(people[1].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().unwrap();
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).unwrap();
    land(&mut g, &store, t, now, &mut out).await;
    let to_kh = ins(&out, 1);
    assert_eq!(to_kh.len(), 1);
    assert!(to_kh[0].pushed && to_kh[0].chain.len() == 1);
    let to_w = ins(&out, w.sid);
    assert_eq!(to_w.len(), 1);
    assert!(to_w[0].head.is_some() && to_w[0].leaf.is_some() && to_w[0].seal.is_some());
    // Within HOLD_MS after the opening the epoch before is still good for posts
    let v = g.head_view().unwrap();
    assert!(v.post_ok(&hd.gen, hd.epoch, now + 59_000));
    assert!(!v.post_ok(&hd.gen, hd.epoch, now + 60_000));
    assert!(v.post_ok(&hd.gen, hd.epoch + 1, now + 600_000));
}

#[test]
fn a_head_view_takes_the_head_epoch_and_the_one_before_for_hold_ms() {
    let v = HeadView {
        gen: [1; 16],
        epoch: 5,
        opened_ms: 1_000,
    };
    assert!(v.post_ok(&[1; 16], 5, 1_000_000));
    assert!(v.post_ok(&[1; 16], 4, 60_999));
    assert!(!v.post_ok(&[1; 16], 4, 61_000));
    assert!(!v.post_ok(&[2; 16], 5, 1_000));
    assert!(!v.post_ok(&[1; 16], 6, 1_000));
}

#[test]
fn an_open_exit_batch_closes_at_its_count_cap_and_its_due_fits_one_epoch_due() {
    let seat = |i: u32| SeatRef {
        m: MemberId::Account([0xff; 16]),
        tag_sk: [0xff; 8],
        tag_sx: i.to_be_bytes().repeat(2).try_into().unwrap(),
    };
    let mut x = Exits::new(u64::MAX / 4);
    for i in 0..EXIT_BATCH_MAX as u32 {
        x.add(seat(i), u64::MAX, cause::LEAVE, 10);
    }
    assert_eq!(
        x.closes_at(GroupKind::Text, 100_000, false),
        Some(10),
        "at once at the cap"
    );
    assert_eq!(exit_cap(true), 768);
    x.close(false);
    x.add(seat(0), 1, cause::LEAVE, 11);
    x.close(false);
    assert_eq!(x.closed.len(), 2, "a batch past the cap is not merged");
    // The worst case of one batch: one EpochDue the receiver takes whole
    let piece = DuePiece {
        kind: gk::due::EXITS,
        exits: x.closed[0]
            .exits
            .iter()
            .map(|l| gk::ExitIn {
                seq: l.exit.seq,
                seat: l.exit.seat.into(),
                b: l.exit.b,
            })
            .collect(),
        exits_upto: x.closed[0].upto(),
        ..DuePiece::default()
    };
    let frames = push::epoch_due(ID, u64::MAX, piece);
    let mut parts: Parts<u64, DuePiece> = Parts::new(Seq::Due);
    let mut whole = None;
    for f in &frames {
        let bytes = push::len(f);
        assert!(bytes <= voipc_protocol::codec::MAX_MSG_SIZE as usize);
        let ServerMessage::EpochDue {
            due,
            part,
            last,
            piece,
            ..
        } = f
        else {
            panic!()
        };
        if let Part::Whole(_, ps) = parts
            .take(*due, *part, *last, (**piece).clone(), bytes)
            .part
        {
            whole = Some(ps.iter().map(|p| p.exits.len()).sum::<usize>());
        }
    }
    assert_eq!(
        whole,
        Some(EXIT_BATCH_MAX),
        "the receiver's 12 MB cap takes it"
    );
}

#[test]
fn an_epoch_in_puts_each_item_in_the_first_part_with_room_and_spreads_lists_in_order() {
    let header = gk::HeaderIn {
        body: vec![7; 20_000],
        sig: vec![0; 64],
    };
    let small = gk::HeaderIn {
        body: vec![8; 500],
        sig: vec![0; 64],
    };
    let piece = InPiece {
        walk: (0..5)
            .map(|_| gk::WalkLinkIn {
                header: header.clone(),
                parent: None,
            })
            .collect(),
        head: Some(gk::WalkLinkIn {
            header: header.clone(),
            parent: Some(small),
        }),
        seal: Some(vec![1; 60]),
        ..InPiece::default()
    };
    let frames = push::epoch_in(ID, piece.clone());
    let mut got = InPiece::default();
    let mut heads = 0;
    for (i, f) in frames.iter().enumerate() {
        assert!(push::len(f) <= voipc_protocol::codec::MAX_MSG_SIZE as usize);
        let ServerMessage::EpochIn {
            part,
            last,
            piece: p,
            ..
        } = f
        else {
            panic!()
        };
        assert_eq!((*part as usize, *last), (i, i + 1 == frames.len()));
        heads += usize::from(p.head.is_some());
        got.walk.extend(p.walk.clone());
        got.seal = got.seal.or(p.seal.clone());
    }
    assert_eq!(heads, 1, "an Option once a sequence");
    assert_eq!(got.walk, piece.walk, "the walk in order");
    assert_eq!(got.seal, piece.seal);
}

#[test]
fn volunteers_rank_account_desktops_first_and_phones_never_hold_text_keys() {
    let g = Person::guest(1);
    let mut v = g.volunteer(gk::platform::DESKTOP);
    assert_eq!(v.rank(GroupKind::Text), Some(2));
    v.platform = gk::platform::BROWSER;
    assert_eq!(v.rank(GroupKind::Text), Some(3));
    v.platform = gk::platform::PHONE;
    assert_eq!(v.rank(GroupKind::Text), None);
    v.m = MemberId::Account([1; 16]);
    v.platform = gk::platform::DESKTOP;
    assert_eq!(v.rank(GroupKind::Text), Some(0));
}

#[test]
fn three_misses_in_an_hour_propose_a_removal_and_never_of_the_last_entry() {
    let (a, b) = (Person::guest(1), Person::guest(2));
    let mut h = Holders::default();
    h.set_to(vec![a.entry()], |_| None);
    let vols: HashMap<UserId, Volunteer> = [(1, a.volunteer(gk::platform::DESKTOP))].into();
    for t in 0..3 {
        h.missed(&a.wire().kx(), t);
    }
    assert_eq!(
        h.removal_where(&vols, 10, false, 10, |_| true),
        None,
        "the last entry stays"
    );
    h.set_to(vec![a.entry(), b.entry()], |_| None);
    let vols: HashMap<UserId, Volunteer> = [
        (1, a.volunteer(gk::platform::DESKTOP)),
        (2, b.volunteer(gk::platform::DESKTOP)),
    ]
    .into();
    h.seen(&vols, 0);
    for t in 0..3 {
        h.missed(&a.wire().kx(), t);
    }
    assert_eq!(
        h.removal_where(&vols, 10, false, 10, |_| true)
            .map(|r| r.kx),
        Some(a.wire().kx())
    );
    // An hour later they no longer count
    assert_eq!(h.removal_where(&vols, 10, false, 3_600_010, |_| true), None);
}

// ── Groups, actors and the database ───────────────────────────────────────

use crate::gk::Groups;

async fn scratch_db() -> (l4f_accounts::store::Store, std::path::PathBuf) {
    let id = rand::random::<u32>();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/gk-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(format!("gk-{id:08x}.db"));
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
    crate::gk_e2e_tests::drop_db(file);
}

/// A stored group `id` over a scratch database: guest keyholder 1's Genesis, stored and
/// taken.
async fn stored_genesis(
    id: &str,
) -> (
    l4f_accounts::store::Store,
    std::path::PathBuf,
    Store,
    GroupState,
    Person,
    u64,
) {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let store = Store::Db(Arc::new(crate::gk::store::DbStore {
        db: db.clone(),
        incarnation: inc,
    }));
    let mut g = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    let k = Person::guest(1);
    let mut out = vec![];
    let now = now_ms();
    g.follow(1, None);
    g.volunteer(1, Some(k.volunteer(gk::platform::DESKTOP)), now, &mut out);
    g.follow(2, None);
    let p = Person::guest(2);
    g.fetch(2, p.fetch(), now, &mut out);
    let (due, piece) = dues(&out, 1).pop().unwrap();
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let st = Start {
        kind: GroupKind::Text,
        id,
        me: k.me(),
        ik: &k.ik,
        entry: k.entry(),
        joiners: &[&joiner],
        gated: false,
        stored: true,
        now: now / 1000,
    };
    let b = build_genesis(&st, &mut RowBases::new()).unwrap();
    let piece = CommitPiece::try_from(b.commit.clone()).unwrap();
    let mut t = None;
    let parts = cut_commit(piece, PIECE_MAX_BYTES - commit_frame_overhead(id)).unwrap();
    let n = parts.len();
    for (i, x) in parts.into_iter().enumerate() {
        let bytes = push::len(&x);
        t = g.commit_part(1, due, i as u16, i + 1 == n, x, bytes, now, &mut out);
    }
    let t = t.expect("taken");
    store.commit(&g, &t, now).await.unwrap();
    g.apply(t, now, &mut out);
    (db, file, store, g, k, now)
}

#[tokio::test]
async fn a_stored_group_keeps_its_head_across_a_restart_and_its_connection_seats_exit() {
    let id = "c:lounge-1";
    let (db, file, store, g, k, now) = stored_genesis(id).await;
    let head = g.head.as_ref().unwrap().sh.d();

    let mut again = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut again).await.unwrap();
    assert_eq!(again.head.as_ref().unwrap().sh.d(), head);
    assert_eq!(again.leaves, g.leaves);
    assert_eq!(again.tree.root(), g.tree.root());
    assert_eq!(again.seats.len(), 1);
    assert_eq!(again.seals, g.seals);
    assert_eq!(again.holders.set, g.holders.set);
    assert!(!again.new_gen);
    let seat = k.seat();
    let at = again.snapshot().unwrap().base_of(&seat).unwrap();
    let base = store
        .base(id, &again.gen().unwrap(), &seat, at)
        .await
        .unwrap();
    assert!(base.2, "its seat welcome, from the database");
    let mut out = vec![];
    again.exit(seat, cause::RESTART, now, &mut out);
    assert_eq!(again.exits.waiting(), 1, "a connection seat exits at start");

    // An old incarnation: reset, and a new generation at the next fetch (2i)
    let other = Store::Db(Arc::new(crate::gk::store::DbStore {
        db: db.clone(),
        incarnation: [0xee; 16],
    }));
    let mut reset = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    other.load(&mut reset).await.unwrap();
    assert!(reset.new_gen && reset.head.is_none());
    assert!(other.keyring(id, &g.gen().unwrap(), 1, 0).await.is_empty());
    drop_db(&file);
}

async fn gk_rows(db: &l4f_accounts::store::Store) -> i64 {
    let mut n = 0;
    for t in [
        "voipc_gk_groups",
        "voipc_gk_headers",
        "voipc_gk_seats",
        "voipc_gk_lists",
        "voipc_gk_vids",
        "voipc_gk_names",
        "voipc_gk_welcomes",
        "voipc_gk_rows",
        "voipc_gk_seals",
        "voipc_gk_keyring",
        "voipc_gk_krk",
        "voipc_gk_pending",
        "voipc_gk_exits",
        "voipc_gk_holders",
    ] {
        let q = format!("SELECT COUNT(*) FROM {t}");
        n += match db {
            l4f_accounts::store::Store::Lite(b) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q))
                    .fetch_one(&b.0)
                    .await
                    .unwrap()
            }
            l4f_accounts::store::Store::Pg(b) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q))
                    .fetch_one(&b.0)
                    .await
                    .unwrap()
            }
        };
    }
    n
}

/// Frames a session's control queue holds now.
async fn drain(rx: &mut crate::control::ControlRx) -> Vec<ServerMessage> {
    let mut got = vec![];
    while let Ok(Some(b)) = tokio::time::timeout(std::time::Duration::ZERO, rx.recv()).await {
        got.push(voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap());
    }
    got
}

/// A relay's `Groups` with sessions on control queues, for the tests through its API.
struct Net {
    groups: Groups,
    state: Arc<crate::state::ServerState>,
    rxs: HashMap<UserId, crate::control::ControlRx>,
    tx: crate::control::ControlTx,
}

impl Net {
    fn new() -> Net {
        Net {
            groups: Groups::new(true),
            state: Arc::new(crate::state::test_support::make_state()),
            rxs: HashMap::new(),
            tx: crate::control::ControlTx::placeholder(),
        }
    }

    /// A guest session following channel `channel`'s group `id`.
    fn guest(&mut self, channel: u32, id: &str) -> Person {
        let (sid, _) = crate::state::test_support::add_user(&self.state, "guest");
        let p = Person::guest(sid);
        self.state.sessions.get_mut(&sid).unwrap().identity_key =
            Some([&[0x05u8][..], &raw(&p.ik)].concat());
        let (tx, rx) = crate::control::control_queue(Arc::default());
        self.groups.on_connect(sid, tx);
        self.rxs.insert(sid, rx);
        self.groups
            .on_follow(channel, id, GroupKind::Text, sid, None);
        p
    }

    async fn send(&self, sid: UserId, msg: voipc_protocol::messages::ClientMessage) {
        self.groups.handle(&self.state, sid, msg, &self.tx).await;
    }

    /// What `sid` was sent once the actor had `ms` to work.
    async fn frames(&mut self, sid: UserId, ms: u64) -> Vec<Out> {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        vec![Out(sid, drain(self.rxs.get_mut(&sid).unwrap()).await)]
    }

    async fn volunteer(&self, k: &Person) {
        self.send(
            k.sid,
            voipc_protocol::messages::ClientMessage::KeyholdVolunteer {
                on: true,
                platform: gk::platform::DESKTOP,
                pair: Some((&k.wire()).into()),
            },
        )
        .await;
    }

    async fn fetch(&self, p: &Person, id: &str) {
        self.send(
            p.sid,
            voipc_protocol::messages::ClientMessage::EpochFetch {
                group: id.into(),
                have: None,
                at: vec![],
                seat: Some((&p.wire()).into()),
            },
        )
        .await;
    }

    async fn commit(&self, sid: UserId, id: &str, due: u64, b: &Built) {
        let commit = CommitPiece::try_from(b.commit.clone()).unwrap();
        let parts = cut_commit(commit, PIECE_MAX_BYTES - commit_frame_overhead(id)).unwrap();
        let n = parts.len();
        for (i, p) in parts.into_iter().enumerate() {
            self.send(
                sid,
                voipc_protocol::messages::ClientMessage::EpochCommit {
                    group: id.into(),
                    due,
                    part: i as u16,
                    last: i + 1 == n,
                    piece: p,
                },
            )
            .await;
        }
    }
}

/// Channel `channel`'s Load row once `done` holds, or after 5 s: the actor publishes it
/// after its store writes, which take their time on Postgres.
async fn stats_until(
    net: &Net,
    channel: u32,
    done: impl Fn(&voipc_protocol::types::GroupLoad) -> bool,
) -> voipc_protocol::types::GroupLoad {
    let mut row = None;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        row = net
            .groups
            .stats()
            .into_iter()
            .find(|s| s.channel_id == channel);
        if row.as_ref().is_some_and(&done) {
            break;
        }
    }
    row.expect("a Load row")
}

/// The keyholder's Join on `head`, as it holds the group after its own Genesis.
fn join_on(
    k: &Person,
    id: &str,
    head: &voipc_crypto::group_key::SignedHeader,
    h: &mut Holds,
    piece: &DuePiece,
    stored: bool,
    now: u64,
) -> Built {
    join_on_kh(k, id, head, head, h, piece, stored, now)
}

/// `join_on` with the keyholder set of `kh`, a head before `head`.
#[allow(clippy::too_many_arguments)]
fn join_on_kh(
    k: &Person,
    id: &str,
    head: &voipc_crypto::group_key::SignedHeader,
    kh: &voipc_crypto::group_key::SignedHeader,
    h: &mut Holds,
    piece: &DuePiece,
    stored: bool,
    now: u64,
) -> Built {
    let grp = Group::new(GroupKind::Text, id, head.header().gen).unwrap();
    let joiners: Vec<Joiner> = piece
        .joins
        .iter()
        .map(|j| Joiner::try_from(j).unwrap())
        .collect();
    let refs: Vec<&Joiner> = joiners.iter().collect();
    let lists = Lists::new();
    let held = |_: &SeatRef| Some(1);
    let hold = Holding {
        g: &grp,
        head,
        kh,
        ring: &h.ring,
        krk: &h.krk,
        me: k.me(),
        ik: &k.ik,
        lists: &lists,
        held: &held,
        rolls: voipc_crypto::group_key::SeedRolls::at_start(head.header()),
        stored,
    };
    build_join(&hold, &refs, vec![], now / 1000, &mut h.cache, None).unwrap()
}

#[tokio::test]
async fn a_run_over_memory_groups_with_guests_leaves_every_gk_table_empty() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, None);
    assert!(
        id.starts_with("r:"),
        "no stored conversation: a memory group"
    );
    let k = net.guest(7, &id);
    let people: Vec<Person> = (0..2).map(|_| net.guest(7, &id)).collect();
    net.volunteer(&k).await;
    for p in &people {
        net.fetch(p, &id).await;
    }
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid)
        .pop()
        .expect("a Genesis due through the actor");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let b = genesis(&k, &id, &piece, false, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    let head = b.header.clone();
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    let out = net.frames(k.sid, 2_500).await;
    assert!(!ins(&out, k.sid).is_empty(), "the volunteer is answered");
    let (due, piece) = dues(&out, k.sid).pop().expect("then a Join due");
    assert_eq!(piece.joins.len(), 2);
    let b = join_on(&k, &id, &head, &mut h, &piece, false, net.groups.now());
    let join = b.header.clone();
    net.commit(k.sid, &id, due, &b).await;
    let out = net.frames(people[0].sid, 100).await;
    let got = ins(&out, people[0].sid);
    let answer = got
        .iter()
        .find(|p| p.own_join.is_some())
        .expect("its own Join");
    assert!(answer.seat.as_ref().is_some_and(|s| s.welcome.is_some()));
    assert!(answer.leaf.is_some() && answer.path.is_some() && answer.seal.is_some());
    // A plain post under the head, a blob that makes a writer, an old epoch refused
    let (gen, epoch) = (join.header().gen, join.header().epoch);
    let w = people[0].sid;
    assert_eq!(
        net.groups.post_check(w, &id, gen, epoch, None).await,
        Ok(())
    );
    assert_eq!(
        net.groups
            .post_check(w, &id, gen, epoch, Some(vec![1]))
            .await,
        Ok(())
    );
    assert_eq!(
        net.groups.post_check(w, &id, gen, epoch + 1, None).await,
        Err(refused_why::OLD_EPOCH)
    );
    // A seated fetch is answered outside the actor
    net.fetch(&people[1], &id).await;
    let out = net.frames(people[1].sid, 0).await;
    assert!(
        ins(&out, people[1].sid).iter().any(|p| p.leaf.is_some()),
        "from the snapshot"
    );
    assert_eq!(
        gk_rows(&db).await,
        0,
        "nothing of a memory group reaches the database"
    );
    let row = net
        .groups
        .stats()
        .into_iter()
        .find(|s| s.channel_id == 7)
        .unwrap();
    assert_eq!(
        (row.seats, row.keyholders, row.keyholders_online),
        (3, 1, 1)
    );
    // A kick and an unfollow are exits; the gate makes every connection seat exit
    net.groups.on_kick(7, people[1].sid, cause::KICK);
    net.groups.on_unfollow(7, people[0].sid);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let row = net
        .groups
        .stats()
        .into_iter()
        .find(|s| s.channel_id == 7)
        .unwrap();
    assert_eq!(row.exits_waiting, 2);
    net.groups.on_gate(7, true);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let row = net
        .groups
        .stats()
        .into_iter()
        .find(|s| s.channel_id == 7)
        .unwrap();
    assert_eq!(
        row.exits_waiting, 3,
        "the keyholder's own connection seat too"
    );
    // The channel moves to another id: the old group stops
    let moved = format!("r:{}:8", "ab".repeat(16));
    net.groups.on_group_moved(7, &id, &moved);
    assert!(net.groups.get(&id).is_none());
    for p in people.iter().chain([&k]) {
        net.groups.on_session_end(p.sid);
    }
    drop_db(&file);
}

#[tokio::test]
async fn the_account_hooks_seat_an_account_eagerly_and_exit_its_seat_at_a_rotation() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("lounge"));
    assert_eq!(id, "c:lounge");
    // An account with published seat keys
    let a = l4f_accounts::model::AccountId::new();
    db.create_user(
        &l4f_accounts::model::NewUser {
            id: a,
            username: "ann".into(),
            display_name: "ann".into(),
            email_pending: None,
            password_hash: None,
            created_at: l4f_accounts::util::now(),
        },
        None,
    )
    .await
    .unwrap();
    let ann = voipc_crypto::generate_identity_key_pair();
    let publish = |n: u32| {
        let pair = SeatPair::generate();
        let e = Endorsement::sign(
            &ann,
            Origin::VaultSeat,
            MemberId::Account(a.0),
            n,
            now_ms() / 1000,
            &pair.public(),
        )
        .unwrap();
        (pair, e)
    };
    let (seat1, e1) = publish(1);
    crate::accounts::gk::put_seat_keys(
        &db,
        &a.0,
        &crate::accounts::gk::SeatKeys {
            n: 1,
            kem: seat1.public().kem_bytes().into(),
            dh: seat1.public().dh_bytes().into(),
            made: e1.made,
            sig: e1.sig.to_vec(),
            published: now_ms(),
        },
    )
    .await
    .unwrap();
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    // A session of the account, following: it hears how a rotation's re-seat goes
    let (asid, _) = crate::state::test_support::add_user(&net.state, "ann");
    let (tx, rx) = crate::control::control_queue(Arc::default());
    net.groups.on_connect(asid, tx);
    net.rxs.insert(asid, rx);
    net.groups
        .on_follow(7, &id, GroupKind::Text, asid, Some(a.0));
    net.groups.on_log_join("lounge", a.0, raw(&ann)).await;
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid)
        .pop()
        .expect("a Genesis for the eager seat");
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let st = Start {
        kind: GroupKind::Text,
        id: &id,
        me: k.me(),
        ik: &k.ik,
        entry: k.entry(),
        joiners: &[&joiner],
        gated: false,
        stored: true,
        now: net.groups.now() / 1000,
    };
    let b = build_genesis(&st, &mut RowBases::new()).unwrap();
    net.commit(k.sid, &id, due, &b).await;
    let head = b.header.clone();
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    let out = net.frames(k.sid, 2_500).await;
    let (due, piece) = dues(&out, k.sid)
        .pop()
        .expect("a Join of the account's seat");
    assert_eq!(piece.joins[0].seat.m, gk::GkMember::Account(a.0));
    let b = join_on(&k, &id, &head, &mut h, &piece, true, net.groups.now());
    let gen = b.header.header().gen;
    net.commit(k.sid, &id, due, &b).await;
    let old = seat1.public().seat(MemberId::Account(a.0));
    // Stored once the actor took it (a Postgres commit takes its time)
    let mut makers = vec![];
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        makers = net.groups.row_makers(&id, &gen, &old).await;
        if !makers.is_empty() {
            break;
        }
    }
    assert_eq!(
        makers.len(),
        1,
        "a stored Join rows each new account seat (open choice 24)"
    );
    assert_eq!(makers[0].from.kx, k.wire().kx());
    // A rotation: the old seat exits, the new one waits to be seated
    let (seat2, e2) = publish(2);
    let pair = Pair {
        keys: seat2.public(),
        endorsement: e2,
    };
    net.groups.on_seat_keys(a.0, pair, raw(&ann)).await;
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let reseated = |frames: Vec<ServerMessage>| {
        frames
            .into_iter()
            .filter_map(|f| match f {
                ServerMessage::EpochReseated { n, left } => Some((n, left)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let got = drain(net.rxs.get_mut(&asid).unwrap()).await;
    assert_eq!(reseated(got), vec![(2, 1)], "one group to re-seat");
    let new = seat2.public().seat(MemberId::Account(a.0));
    net.groups.reseat_done_for_test(&id, &new);
    let got = drain(net.rxs.get_mut(&asid).unwrap()).await;
    assert_eq!(reseated(got), vec![(2, 0)], "done: the old keys may go");
    let row = stats_until(&net, 7, |r| (r.exits_waiting, r.joins_waiting) == (1, 1)).await;
    assert_eq!((row.exits_waiting, row.joins_waiting), (1, 1));
    let out = net.frames(k.sid, 200).await;
    let (_, piece) = dues(&out, k.sid).pop().expect("the exits go first");
    assert_eq!(
        (piece.kind, piece.exits[0].seat),
        (gk::due::EXITS, old.into())
    );
    // The account is gone: its waiting seat with it
    net.groups.on_log_leave("lounge", a.0, cause::LEAVE);
    net.groups.on_account_gone(a.0, cause::DELETED).await;
    let row = stats_until(&net, 7, |r| r.joins_waiting == 0).await;
    assert_eq!(row.joins_waiting, 0);
    net.groups.on_purge("lounge");
    assert!(net.groups.get(&id).is_none());
    drop_db(&file);
}

#[test]
fn every_exit_cause_has_its_own_code() {
    let all = [
        cause::LEAVE,
        cause::KICK,
        cause::BAN,
        cause::GATE,
        cause::RESET,
        cause::DELETED,
        cause::ROTATION,
        cause::EXPIRY,
        cause::DISCONNECT,
        cause::RESTART,
        cause::REJOIN,
    ];
    let set: std::collections::HashSet<u8> = all.into_iter().collect();
    assert_eq!(set.len(), all.len());
}

#[tokio::test]
async fn a_full_inbox_refuses_fetches_rate_and_still_takes_commit_parts() {
    let mut net = Net::new();
    let id = net.groups.id_for(9, None);
    let k = net.guest(9, &id);
    let p = net.guest(9, &id);
    net.volunteer(&k).await;
    net.fetch(&p, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, _) = dues(&out, k.sid).pop().expect("a Genesis due");
    net.frames(p.sid, 0).await;
    net.groups.get(&id).unwrap().inbox_full_for_test();
    net.fetch(&p, &id).await;
    net.send(
        k.sid,
        voipc_protocol::messages::ClientMessage::EpochCommit {
            group: id.clone(),
            due,
            part: 0,
            last: true,
            piece: CommitPiece::default(),
        },
    )
    .await;
    let got = net.frames(p.sid, 50).await.remove(0).1;
    assert!(matches!(
        got[..],
        [ServerMessage::EpochRefused {
            why: refused_why::RATE,
            ..
        }]
    ));
    let got = net.frames(k.sid, 0).await.remove(0).1;
    assert!(
        got.iter()
            .any(|f| matches!(f, ServerMessage::EpochStale { due: d, .. } if *d == due)),
        "the commit lane reached the actor"
    );
}

#[test]
fn a_sequence_to_a_session_is_queued_whole_while_others_queue_theirs() {
    let groups = Arc::new(Groups::new(true));
    let (tx, mut rx) = crate::control::control_queue(Arc::default());
    groups.on_connect(5, tx);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let id = rt.block_on(async {
        let id = groups.id_for(3, None);
        groups.on_follow(3, &id, GroupKind::Text, 5, None);
        id
    });
    let seq = |n: u16, tag: u8| -> Vec<ServerMessage> {
        (0..n)
            .map(|i| ServerMessage::EpochIn {
                group: ID.into(),
                part: i,
                last: i + 1 == n,
                piece: Box::new(InPiece {
                    seal: Some(vec![tag]),
                    ..InPiece::default()
                }),
            })
            .collect()
    };
    std::thread::scope(|s| {
        for tag in 0..8u8 {
            let groups = groups.clone();
            let id = id.clone();
            s.spawn(move || {
                for _ in 0..20 {
                    groups.deliver_for_test(&id, vec![Out(5, seq(6, tag))]);
                }
            });
        }
    });
    let got = rt.block_on(drain(&mut rx));
    assert_eq!(got.len(), 8 * 20 * 6);
    for run in got.chunks(6) {
        let tags: Vec<u8> = run
            .iter()
            .map(|f| match f {
                ServerMessage::EpochIn { piece, .. } => piece.seal.as_ref().unwrap()[0],
                _ => panic!(),
            })
            .collect();
        assert!(
            tags.iter().all(|t| *t == tags[0]),
            "parts of one sequence never interleave"
        );
    }
}

#[tokio::test]
async fn a_floor_ahead_signed_by_a_keyholder_starts_a_new_generation_once_an_hour() {
    let store = Store::memory();
    let (mut g, k, mut h, people, now) = seated_group(&store).await;
    // A header past the head that this relay never took
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    let mut out = vec![];
    g.tick(now + 2_100, &mut out);
    let (_, piece) = dues(&out, 1).pop().unwrap();
    let b = opening(&g, &k, &mut h, &piece, now + 2_100);
    let ahead = voipc_crate_header(&b);
    let mut out = vec![];
    g.floor_ahead(people[1].sid, &ahead, now + 3_000, &mut out);
    assert!(g.new_gen);
    g.new_gen = false;
    g.floor_ahead(people[1].sid, &ahead, now + 4_000, &mut out);
    assert!(!g.new_gen, "at most one new generation an hour");
}

fn voipc_crate_header(b: &Built) -> gk::HeaderIn {
    gk::HeaderIn {
        body: b.commit.body.clone(),
        sig: b.commit.sig.clone(),
    }
}

#[tokio::test]
async fn an_open_commit_is_charged_to_its_connection_and_the_relay_until_its_sender_leaves() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().unwrap();
    let b = opening(&g, &k, &mut h, &piece, now);
    let whole = CommitPiece::try_from(b.commit.clone()).unwrap();
    let max = push::len(&whole.header) + 64;
    let parts = cut_commit(whole, max).unwrap();
    assert!(parts.len() > 1);
    let first = parts.into_iter().next().unwrap();
    let bytes = push::len(&first);
    assert!(g
        .commit_part(1, due, 0, false, first, bytes, now, &mut out)
        .is_none());
    let caps = g.caps.clone();
    assert!(caps.by_conn.get(&1).is_some_and(|c| *c >= bytes));
    assert!(caps.relay.load(std::sync::atomic::Ordering::Relaxed) >= bytes);
    g.leave(1, cause::DISCONNECT, now, &mut out);
    assert!(caps.by_conn.get(&1).is_none());
    assert_eq!(caps.relay.load(std::sync::atomic::Ordering::Relaxed), 0);
}

// ── Review fixes (R1) ─────────────────────────────────────────────────────

/// Guest keyholder 1 starts a group (`stored` or not), sessions `sids` of account
/// `[7; 16]` fetch its one seat, and the keyholder builds the Join asked: out, not sent.
async fn account_join(
    store: &Store,
    stored: bool,
    sids: &[UserId],
) -> (GroupState, Person, u64, u64, Built) {
    let mut g = new_group(stored);
    let k = Person::guest(1);
    let a = Person::account(sids[0], [7; 16]);
    let mut now = now_ms();
    let mut out = vec![];
    g.follow(1, None);
    g.volunteer(1, Some(k.volunteer(gk::platform::DESKTOP)), now, &mut out);
    for sid in sids {
        g.follow(*sid, Some([7; 16]));
        g.fetch(*sid, a.fetch(), now, &mut out);
    }
    let (due, piece) = dues(&out, 1).pop().expect("a Genesis due");
    let b = genesis(&k, ID, &piece, stored, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, store, t, now, &mut out).await;
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    assert_eq!(piece.joins.len(), 1, "one seat for the account's sessions");
    let b = join(&g, &k, &mut h, &piece, now);
    (g, a, now, due, b)
}

#[tokio::test]
async fn a_replace_asked_by_anyone_but_the_entrys_keyholder_is_ignored_and_exits_still_go() {
    let store = Store::memory();
    let (mut g, k, _, people, mut now) = seated_group(&store).await;
    let ask = ReplaceAsk {
        old: kx_tag(&k.wire().kx()),
        pair: people[0].wire(),
    };
    let mut out = vec![];
    g.replace(people[0].sid, ask, now, &mut out);
    assert!(
        g.replaces.is_empty(),
        "only the keyholder of the entry asks its Replace"
    );
    g.leave(people[1].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (_, piece) = dues(&out, k.sid).pop().expect("the exits are asked");
    assert_eq!(piece.kind, gk::due::EXITS);
}

#[test]
fn a_gated_batch_closes_in_batches_of_768_however_many_exits_one_event_entered() {
    let seat = |i: u32| SeatRef {
        m: MemberId::Account([0xee; 16]),
        tag_sk: [0xee; 8],
        tag_sx: i.to_be_bytes().repeat(2).try_into().unwrap(),
    };
    let mut x = Exits::new(1);
    for i in 0..800 {
        x.add(seat(i), 1, cause::GATE, 10);
    }
    x.close(true);
    let sizes: Vec<usize> = x.closed.iter().map(|b| b.exits.len()).collect();
    assert_eq!(sizes, vec![768, 32]);
}

#[tokio::test]
async fn a_reload_drops_kept_exits_of_seats_no_longer_seated() {
    let id = "c:lounge-2";
    let (db, file, store, g, k, _) = stored_genesis(id).await;
    let gen = g.gen().unwrap();
    // A seat a Regenesis left behind, then the keyholder's own
    let gone = Person::guest(9).seat();
    let exit = |seq: u64, seat: &SeatRef| crate::accounts::gk::Exit {
        seq,
        gen,
        seat: seat_record(seat),
        cause: cause::LEAVE,
        at: 0,
    };
    crate::accounts::gk::add_exits(&db, id, &[exit(1, &gone), exit(2, &k.seat())])
        .await
        .unwrap();
    let mut again = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut again).await.unwrap();
    assert_eq!(again.exits.waiting(), 1);
    let x = again.exits.closed[0].exits[0].exit;
    assert_eq!(
        (x.seq, x.seat, x.b),
        (2, k.seat(), again.seats[&k.seat()].b)
    );
    drop_db(&file);
}

#[tokio::test]
async fn an_account_seat_survives_a_disconnect_and_exits_when_its_last_session_leaves() {
    let store = Store::memory();
    let (mut g, a, now, due, b) = account_join(&store, true, &[2]).await;
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let mut out = vec![];
    g.leave(2, cause::DISCONNECT, now, &mut out);
    assert_eq!(g.exits.waiting(), 0, "going offline is no exit");
    assert!(g.seats.contains_key(&a.seat()));
    // Another device of the account takes the seat, then leaves the channel
    g.follow(3, Some([7; 16]));
    assert_eq!(
        g.fetch(3, a.fetch(), now, &mut out),
        Fetched::Seated(a.seat())
    );
    g.leave(3, cause::LEAVE, now, &mut out);
    assert!(g.exits.has(&a.seat()));
}

#[tokio::test]
async fn an_account_that_exits_while_its_join_is_out_exits_once_the_join_lands() {
    let store = Store::memory();
    let (mut g, a, now, due, b) = account_join(&store, true, &[2]).await;
    let mut out = vec![];
    g.account_exit(&[7; 16], cause::BAN, now, &mut out);
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert!(g.seats.contains_key(&a.seat()), "the Join seated it");
    let open = g.exits.open.as_ref().expect("an exit");
    assert_eq!(
        (open.exits[0].exit.seat, open.exits[0].cause),
        (a.seat(), cause::BAN)
    );
}

#[tokio::test]
async fn every_session_of_a_memory_seat_a_join_seated_gets_its_welcome() {
    let store = Arc::new(Store::memory());
    let (mut g, a, now, due, b) = account_join(&store, false, &[2, 3]).await;
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    let answered = land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(answered, vec![(2, true), (3, true)]);
    let groups = Groups::new(true);
    let mut rxs = vec![];
    for sid in [2, 3] {
        let (tx, rx) = crate::control::control_queue(Arc::default());
        groups.on_connect(sid, tx);
        rxs.push((sid, rx));
    }
    groups
        .answer_for_test(&mut g, store.clone(), answered)
        .await;
    for (sid, rx) in &mut rxs {
        let got = vec![Out(*sid, drain(rx).await)];
        let keying = ins(&got, *sid).pop().and_then(|p| p.seat);
        assert!(
            keying.is_some_and(|s| s.welcome.is_some()),
            "session {sid} has its welcome"
        );
    }
    // Both went out: the welcome goes (2b)
    let at = g.snapshot().unwrap().base_of(&a.seat()).unwrap();
    assert!(store
        .base(ID, &g.gen().unwrap(), &a.seat(), at)
        .await
        .is_none());
}

#[tokio::test]
async fn a_time_only_an_ask_acts_on_wakes_the_actor_no_more_once_past() {
    let store = Store::memory();
    let (mut g, _, _, _, mut now) = seated_group(&store).await;
    // A Join out: its batch's close time stays past until it lands
    let p = Person::guest(4);
    g.follow(4, None);
    let mut out = vec![];
    g.fetch(4, p.fetch(), now, &mut out);
    now += 2_000;
    g.tick(now, &mut out);
    assert_eq!(g.dues.len(), 1);
    assert!(g.wake(now).is_some_and(|t| t > now), "{:?}", g.wake(now));
    // No keyholder online, a refresh past
    g.leave(1, cause::DISCONNECT, now, &mut out);
    g.next_refresh = Some(now - 1);
    g.tick(now, &mut out);
    assert!(g.wake(now).is_none_or(|t| t > now), "{:?}", g.wake(now));
}

#[tokio::test]
async fn a_batch_a_slow_due_carries_is_asked_of_no_other_keyholder() {
    let store = Store::memory();
    let (mut g, k, _, people, mut now) = seated_group(&store).await;
    // Two keyholders online; the second resigns while a batch closes
    let p = &people[0];
    g.vols.insert(p.sid, p.volunteer(gk::platform::DESKTOP));
    g.holders
        .set_to(vec![k.entry(), p.entry()], |_| Some(p.wire()));
    g.holders.seen(&g.vols, now);
    let mut out = vec![];
    g.leave(people[1].sid, cause::LEAVE, now, &mut out);
    g.resigns.push(HolderRef::of(&p.entry()));
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (_, piece) = dues(&out, k.sid).pop().expect("the Remove");
    assert_eq!((piece.kind, piece.exits.len()), (gk::due::REMOVE, 1));
    let mut out = vec![];
    g.tick(now + 1, &mut out);
    assert!(
        dues(&out, p.sid).is_empty(),
        "the batch the Remove carries is not asked again"
    );
}

/// C3c F6: a slow due asked with an exit batch that another keyholder's Fresh then dealt
/// with is rebased without those exits; the relay checks it against its due trimmed the
/// same way, so it is taken, not refused `CHECK`.
#[tokio::test]
async fn a_slow_due_rebased_after_a_fresh_dealt_its_exits_is_taken() {
    let store = Store::memory();
    let (mut g, k, mut hk, people, mut now) = seated_group(&store).await;
    // A second keyholder: seated, then promoted
    let v = Person::guest(5);
    let mut out = vec![];
    g.follow(5, None);
    g.volunteer(5, Some(v.volunteer(gk::platform::DESKTOP)), now, &mut out);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("the volunteer's Join");
    let b = join(&g, &k, &mut hk, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    hk.took(b);
    let (due, piece) = dues(&out, k.sid).pop().expect("a Promote due");
    assert_eq!(piece.kind, gk::due::PROMOTE);
    let b = opening(&g, &k, &mut hk, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    hk.took(b);
    let mut hv = Holds {
        ring: Keyring {
            base: hk.ring.base.clone(),
            buckets: hk.ring.buckets.clone(),
        },
        krk: hk.krk.clone(),
        cache: RowBases::new(),
    };
    // One member leaves and the new keyholder resigns: the Remove, carrying that exit
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    g.resign(v.sid, None, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (slow, remove) = dues(&out, k.sid).pop().expect("the Remove");
    assert_eq!((remove.kind, remove.exits.len()), (gk::due::REMOVE, 1));
    let first = opening(&g, &k, &mut hk, &remove, now);
    // The next member leaves: both exits go to the other keyholder, whose Fresh lands first
    let mut out = vec![];
    g.leave(people[1].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (fresh, piece) = dues(&out, v.sid)
        .pop()
        .expect("the batch, to the other keyholder");
    assert_eq!((piece.kind, piece.exits.len()), (gk::due::EXITS, 2));
    let b = opening(&g, &v, &mut hv, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, v.sid, fresh, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    hk.took(b);
    let mut out = vec![];
    assert!(send(&mut g, k.sid, slow, &first, now, &mut out).is_none());
    assert_eq!(stales(&out, k.sid), vec![stale::HEAD_MOVED]);
    // Rebased as its keyholder does (holder.rs `on_stale`): the exits past the new head's
    let upto = g.head.as_ref().unwrap().sh.header().exits_upto;
    let mut rebased = remove.clone();
    rebased.exits.retain(|x| x.seq > upto);
    assert!(rebased.exits.is_empty());
    let b = opening(&g, &k, &mut hk, &rebased, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, slow, &b, now, &mut out);
    assert_eq!(stales(&out, k.sid), Vec::<u8>::new(), "not refused CHECK");
    land(&mut g, &store, t.expect("taken"), now, &mut out).await;
    assert_eq!(g.holders.set.len(), 1, "the resigned entry is gone");
}

#[tokio::test]
async fn an_exit_is_asked_in_the_bucket_its_seat_sits_in_at_the_ask() {
    let store = Store::memory();
    let (mut g, k, _, people, mut now) = seated_group(&store).await;
    let seat = people[0].seat();
    let mut out = vec![];
    g.leave(people[0].sid, cause::LEAVE, now, &mut out);
    // As if an opening merged its bucket meanwhile
    g.seats.get_mut(&seat).unwrap().b = 4242;
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (_, piece) = dues(&out, k.sid).pop().expect("the exits");
    assert_eq!(piece.exits[0].b, 4242);
}

/// The frames `sid`'s queue holds without the test yielding (no actor ran meanwhile).
fn queued(rx: &mut crate::control::ControlRx) -> Vec<ServerMessage> {
    use std::future::Future;
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut got = vec![];
    while let std::task::Poll::Ready(Some(b)) = std::pin::pin!(rx.recv()).poll(&mut cx) {
        got.push(voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap());
    }
    got
}

#[tokio::test]
async fn commit_parts_queue_only_from_a_session_with_a_due_out_and_12_mb_a_connection() {
    let mut net = Net::new();
    let id = net.groups.id_for(7, None);
    let k = net.guest(7, &id);
    let p = net.guest(7, &id);
    net.volunteer(&k).await;
    net.fetch(&p, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, _) = dues(&out, k.sid).pop().expect("a Genesis due");
    net.frames(p.sid, 0).await;
    let part = |n: u16| voipc_protocol::messages::ClientMessage::EpochCommit {
        group: id.clone(),
        due,
        part: n,
        last: false,
        piece: CommitPiece {
            keyring: vec![0; 50_000],
            ..CommitPiece::default()
        },
    };
    // No due out: refused at once, nothing queued
    net.send(p.sid, part(0)).await;
    assert_eq!(net.groups.lane_for_test(p.sid), 0);
    let got = queued(net.rxs.get_mut(&p.sid).unwrap());
    assert!(matches!(
        got[..],
        [ServerMessage::EpochStale {
            reason: stale::NOT_DUE,
            ..
        }]
    ));
    // The keyholder asked: its parts queue up to its connection's cap
    for n in 0..300 {
        net.send(k.sid, part(n)).await;
    }
    let queued_bytes = net.groups.lane_for_test(k.sid);
    assert!(queued_bytes > 0 && queued_bytes <= gk::COMMIT_MAX_BYTES);
    let got = queued(net.rxs.get_mut(&k.sid).unwrap());
    assert!(got.iter().any(|f| matches!(
        f,
        ServerMessage::EpochStale {
            reason: stale::TOO_LARGE,
            ..
        }
    )));
    // The actor takes them: the lane is free again
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(net.groups.lane_for_test(k.sid), 0);
}

// ── Cross-check of R1 and C3b (2026-11-18) ────────────────────────────────

/// The floor a member holds at `g`'s head.
fn floor_at(g: &GroupState) -> gk::FloorRef {
    let head = g.head.as_ref().unwrap();
    let h = head.sh.header();
    gk::FloorRef {
        gen: h.gen,
        epoch: h.epoch,
        join: h.join,
        d: head.sh.d(),
        kh: head.kh.d(),
    }
}

/// `p` follows, fetches naming `have`, and a Join seats it; the answers owed.
#[allow(clippy::too_many_arguments)]
async fn join_one(
    g: &mut GroupState,
    store: &Store,
    k: &Person,
    h: &mut Holds,
    p: &Person,
    have: Option<gk::FloorRef>,
    now: &mut u64,
) -> Vec<(UserId, bool)> {
    let mut out = vec![];
    g.follow(p.sid, p.account);
    let f = Fetch { have, ..p.fetch() };
    assert_eq!(g.fetch(p.sid, f, *now, &mut out), Fetched::Not);
    *now += 2_000;
    let mut out = vec![];
    g.tick(*now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("a Join due");
    assert_eq!(piece.kind, gk::due::JOIN);
    let b = join(g, k, h, &piece, *now);
    let mut out = vec![];
    let t = send(g, k.sid, due, &b, *now, &mut out).expect("taken");
    let answered = land(g, store, t, *now, &mut out).await;
    h.took(b);
    answered
}

/// Sessions on control queues of a `Groups`, for answers in rounds.
fn queues(groups: &Groups, sids: &[UserId]) -> HashMap<UserId, crate::control::ControlRx> {
    let mut rxs = HashMap::new();
    for sid in sids {
        let (tx, rx) = crate::control::control_queue(Arc::default());
        groups.on_connect(*sid, tx);
        rxs.insert(*sid, rx);
    }
    rxs
}

async fn answer_to(rxs: &mut HashMap<UserId, crate::control::ControlRx>, sid: UserId) -> InPiece {
    let got = vec![Out(sid, drain(rxs.get_mut(&sid).unwrap()).await)];
    ins(&got, sid).pop().expect("an answer")
}

/// Finding: a keyholder change pushed head-only moved a member's floor with no `BK` of the
/// version it ratcheted every bucket to, and every later fetch named that header, so the
/// keying never came. The push carries it; and a floor at a keyholder header walks nothing
/// (it named itself as its `kh`, which the walk never met).
#[tokio::test]
async fn a_keyholder_change_is_pushed_to_members_with_their_keying_and_a_floor_at_it_walks_nothing()
{
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    // A second volunteer: seated first, then promoted
    let v = Person::guest(5);
    let mut out = vec![];
    g.follow(5, None);
    g.volunteer(5, Some(v.volunteer(gk::platform::DESKTOP)), now, &mut out);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("the volunteer's Join");
    assert_eq!(piece.kind, gk::due::JOIN);
    let b = join(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    h.took(b);
    // Seated, it is promoted at once
    let (due, piece) = dues(&out, k.sid).pop().expect("a Promote due");
    assert_eq!(piece.kind, gk::due::PROMOTE);
    let b = opening(&g, &k, &mut h, &piece, now);
    assert_eq!(b.header.header().kind, Kind::KeyholdersAdd);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let p = ins(&out, people[0].sid).pop().expect("the push");
    assert!(p.pushed && p.leaf.is_some() && p.seal.is_some());
    let keying = p
        .seat
        .expect("its keying: the version moved at this header");
    assert!(keying.welcome.is_none() && keying.row.is_none());
    assert_eq!(
        keying.ratchets.len(),
        1,
        "one step from the version it held"
    );
    let leaf = p.leaf.unwrap();
    assert_eq!(
        (keying.ratchets[0].to, keying.ratchets[0].from),
        (leaf.v, keying.base_v)
    );
    // A floor at the keyholder header: nothing to walk
    let snap = g.snapshot().unwrap();
    let have = floor_at(&g);
    assert_eq!(have.kh, have.d);
    assert!(snap.walk(Some(&have)).is_empty());
    assert_eq!(snap.head_piece(Some(&have), None, false).walk.len(), 0);
}

/// Finding: a fetch naming the header that made its version was told nothing moved; the
/// floor is no proof that `BK` is held (a pushed header, another device's vault floor).
#[tokio::test]
async fn a_version_made_at_the_floor_still_counts_as_moved() {
    let store = Store::memory();
    let (g, _, _, people, _) = seated_group(&store).await;
    let snap = g.snapshot().unwrap();
    let have = floor_at(&g);
    assert!(
        snap.moved_since(&people[0].seat(), Some(&have)),
        "made at the Join the floor is at"
    );
}

/// Finding: a new connection (a restart, a second device) with a floor at the head holds
/// no `BK`: its first answer carries the keying though the version predates the floor; a
/// second answer on that connection does not.
#[tokio::test]
async fn a_connections_first_answer_carries_its_keying_though_its_version_predates_its_floor() {
    let store = Arc::new(Store::memory());
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    // A later Join in a bucket of its own: the head moves past the members' version
    let late = Person::guest(4);
    join_one(&mut g, &store, &k, &mut h, &late, None, &mut now).await;
    let groups = Groups::new(true);
    let sid = people[0].sid;
    let mut rxs = queues(&groups, &[sid]);
    let hd = groups.handle_for_test(&g, store.clone());
    let have = floor_at(&g);
    assert!(!g
        .snapshot()
        .unwrap()
        .moved_since(&people[0].seat(), Some(&have)));
    groups
        .answers_for_test(&hd, vec![(sid, Some(have), false)])
        .await;
    let p = answer_to(&mut rxs, sid).await;
    assert!(
        p.seat.is_some_and(|s| s.welcome.is_some()),
        "its welcome, on the connection's first answer"
    );
    groups
        .answers_for_test(&hd, vec![(sid, Some(have), false)])
        .await;
    assert!(answer_to(&mut rxs, sid).await.seat.is_none(), "once");
}

/// Finding: `kh` was marked sent by an answer that carried none (a joiner's, from no
/// floor), so a later fetch naming a floor never got it, and the member asked again and
/// again. It goes whenever the floor names a `kh` this connection was not sent.
#[tokio::test]
async fn a_kh_header_goes_to_a_floor_naming_one_this_connection_was_not_sent() {
    let store = Arc::new(Store::memory());
    let (g, _, _, people, _) = seated_group(&store).await;
    let groups = Groups::new(true);
    let sid = people[1].sid;
    let mut rxs = queues(&groups, &[sid]);
    let hd = groups.handle_for_test(&g, store.clone());
    groups.answers_for_test(&hd, vec![(sid, None, true)]).await;
    assert!(
        answer_to(&mut rxs, sid).await.kh.is_none(),
        "no floor, no kh"
    );
    let have = floor_at(&g);
    groups
        .answers_for_test(&hd, vec![(sid, Some(have), false)])
        .await;
    let kh = answer_to(&mut rxs, sid).await.kh.expect("the floor's kh");
    assert_eq!(kh.body, g.head.as_ref().unwrap().kh.body());
    groups
        .answers_for_test(&hd, vec![(sid, Some(have), false)])
        .await;
    assert!(answer_to(&mut rxs, sid).await.kh.is_none(), "sent already");
}

/// Finding: the answers a commit owes (a joiner, a fetch it held) were built from no floor:
/// their walk ran back to the generation's start, past a same-generation floor, and the
/// member refused it. Each is built from the floor its queued fetch named.
#[tokio::test]
async fn a_fetch_queued_with_a_floor_is_answered_from_that_floor_once_seated() {
    let store = Arc::new(Store::memory());
    let (mut g, k, mut h, _, mut now) = seated_group(&store).await;
    let have = floor_at(&g);
    let p = Person::guest(4);
    let answered = join_one(&mut g, &store, &k, &mut h, &p, Some(have), &mut now).await;
    assert_eq!(answered, vec![(4, true)]);
    let groups = Groups::new(true);
    let mut rxs = queues(&groups, &[4]);
    groups
        .answer_for_test(&mut g, store.clone(), answered)
        .await;
    let a = answer_to(&mut rxs, 4).await;
    assert!(a.walk.is_empty(), "from its floor's kh: nothing to walk");
    assert!(a.kh.is_some(), "the kh its floor names");
    assert!(a.own_join.is_some() && a.seat.is_some());
}

/// Finding: an answer built from the snapshot could be queued after the push of a newer
/// head the actor queued meanwhile; the member took the push, then met the old head below
/// its floor and reported the relay behind. An answer from a snapshot since replaced does
/// not go.
#[tokio::test]
async fn an_answer_from_a_snapshot_a_newer_head_replaced_is_not_queued() {
    let store = Arc::new(Store::memory());
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let groups = Groups::new(true);
    let hd = groups.handle_for_test(&g, store.clone());
    join_one(
        &mut g,
        &store,
        &k,
        &mut h,
        &Person::guest(4),
        None,
        &mut now,
    )
    .await;
    assert_eq!(
        groups.answers_go_for_test(&hd, &g, people[0].sid),
        (false, true)
    );
}

/// An account's desktop keyholder: its 0x03 pair, and its seat on the account's seat keys.
fn desktop(sid: UserId, a: [u8; 16]) -> (Person, Volunteer) {
    let ik = voipc_crypto::generate_identity_key_pair();
    let pair = SeatPair::generate();
    let endorsement = Endorsement::sign(
        &ik,
        Origin::Desktop,
        MemberId::Account(a),
        1,
        now_ms() / 1000,
        &pair.public(),
    )
    .unwrap();
    let k = Person {
        sid,
        ik,
        pair,
        endorsement,
        account: Some(a),
    };
    let seat = Person::account(sid, a);
    let seat = Person {
        ik: k.ik,
        endorsement: Endorsement::sign(
            &k.ik,
            Origin::VaultSeat,
            MemberId::Account(a),
            1,
            now_ms() / 1000,
            &seat.pair.public(),
        )
        .unwrap(),
        ..seat
    };
    let v = Volunteer {
        seat: Some(seat.joiner()),
        ..k.volunteer(gk::platform::DESKTOP)
    };
    (k, v)
}

/// Finding: the opening that turned the gate on kept no names list (only Joins and new
/// starts did), and a fold from the start needs it first.
#[tokio::test]
async fn the_opening_that_turns_the_gate_on_keeps_its_names_list() {
    let store = Store::memory();
    let mut g = new_group(false);
    let (k, v) = desktop(1, [1; 16]);
    let ann = Person::account(2, [2; 16]);
    let mut now = now_ms();
    let mut out = vec![];
    g.follow(1, Some([1; 16]));
    g.volunteer(1, Some(v), now, &mut out);
    g.follow(2, Some([2; 16]));
    g.fetch(2, ann.fetch(), now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Genesis due");
    let b = genesis(&k, ID, &piece, false, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    let b = join(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    h.took(b);
    assert!(!g.head.as_ref().unwrap().sh.header().gated);
    let gen = g.gen().unwrap();
    // The gate goes on: `DUE_GATE`, an opening with `gated` on an open head
    let mut out = vec![];
    g.set_gate(true, now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("the gate's due");
    assert_eq!((piece.kind, piece.gated), (gk::due::GATE, true));
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let o = g.head.as_ref().unwrap().sh.clone();
    assert!(o.header().gated && o.header().kind.opens_epoch());
    let all = gk::NamesRef {
        gen,
        epoch: 0,
        join: 0,
    };
    let to = gk::NamesRef {
        gen,
        epoch: o.header().epoch,
        join: 0,
    };
    let lists = g.names.answer(&all, &to, false).lists;
    assert_eq!(
        lists.iter().map(|l| (l.epoch, l.join)).collect::<Vec<_>>(),
        vec![(o.header().epoch, 0)],
        "the gate-on opening's list, the fold's first step"
    );
}

/// Finding: names lists were in memory only (a restart or an idle stop lost them) and no
/// "gone" step was ever answered. A stored group loads them back with the step before the
/// oldest; the step answers a floor from before it.
#[tokio::test]
async fn a_stored_group_loads_its_names_lists_and_answers_gone_before_its_step() {
    let id = "c:lounge-3";
    let (db, file, store, g, _, _) = stored_genesis(id).await;
    let gen = g.gen().unwrap();
    let list =
        |epoch: u32, j: u32, kind: u8, hash: [u8; 32], list: Vec<u8>| crate::accounts::gk::Names {
            gen,
            epoch,
            j,
            kind,
            time: now_ms() / 1000,
            names_hash: hash,
            list,
        };
    let empty = postcard::to_allocvec(&Vec::<voipc_crypto::group_key::AddedSeat>::new()).unwrap();
    crate::accounts::gk::put_names(
        &db,
        id,
        &[
            list(0, 5, crate::gk::store::NAMES_STEP, [3; 32], vec![4; 32]),
            list(1, 0, crate::gk::store::NAMES_LIST, [5; 32], empty.clone()),
        ],
    )
    .await
    .unwrap();
    let mut again = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut again).await.unwrap();
    let from = gk::NamesRef {
        gen,
        epoch: 0,
        join: 0,
    };
    let to = gk::NamesRef {
        gen,
        epoch: 1,
        join: 0,
    };
    let a = again.names.answer(&from, &to, false);
    assert_eq!(a.lists.len(), 1, "the list, from the database");
    let gone = a.gone.expect("a floor before the step: gone");
    assert_eq!((gone.before, gone.epoch, gone.join), ([3; 32], 0, 5));
    let after = gk::NamesRef {
        gen,
        epoch: 0,
        join: 5,
    };
    assert!(again.names.answer(&after, &to, false).gone.is_none());
    drop_db(&file);
}

/// Finding: lists swept at 90 days left no step, so a floor before them could never fold.
/// The step of the newest list swept that moved the hash is kept: the fold from it reaches
/// the hash that list's header carried.
#[test]
fn a_names_sweep_keeps_the_step_before_the_oldest_list_kept() {
    use crate::gk::names::{Kept, Names};
    use voipc_crypto::group_key::{names_start, NamesList, NamesStep, NAMES_KEPT};
    let gen = [1; 16];
    let now = 1_000_000_000;
    let old = now - NAMES_KEPT - 10;
    let start = NamesList {
        time: old,
        epoch: 3,
        join: 0,
        added: vec![],
    };
    let h0 = names_start(&start);
    let join = NamesList {
        time: old,
        epoch: 3,
        join: 1,
        added: vec![],
    };
    let kept = NamesList {
        time: now,
        epoch: 4,
        join: 0,
        added: vec![],
    };
    let mut n = Names::default();
    n.restore(
        vec![
            Kept {
                gen,
                list: (&start).into(),
                hash: h0,
            },
            Kept {
                gen,
                list: (&join).into(),
                hash: h0,
            },
            Kept {
                gen,
                list: (&kept).into(),
                hash: h0,
            },
        ],
        vec![],
        None,
    );
    n.sweep(&gen, now);
    let step = n.take_swept().expect("a step");
    assert_eq!(NamesStep::from(step).hash(), h0);
    assert_eq!((step.epoch, step.join, step.before), (3, 0, [0; 32]));
    let from = gk::NamesRef {
        gen,
        epoch: 2,
        join: 0,
    };
    let to = gk::NamesRef {
        gen,
        epoch: 4,
        join: 0,
    };
    let a = n.answer(&from, &to, false);
    assert_eq!(a.gone, Some(step));
    assert_eq!(a.lists.len(), 1);
}

/// Finding: the relay never told an account's sessions how a rotation's re-seat went, so
/// a device kept its old seat keys 7 days and a second rotation waited that long.
#[tokio::test]
async fn a_rotation_is_told_to_the_accounts_sessions_as_its_groups_seat_the_new_seat() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let groups = Groups::new(true);
    groups.attach(db.clone(), inc);
    let a = [8; 16];
    let mut rxs = queues(&groups, &[9]);
    groups.on_follow(7, "c:lounge-4", GroupKind::Text, 9, Some(a));
    let ann = voipc_crypto::generate_identity_key_pair();
    let pair = SeatPair::generate();
    let e = Endorsement::sign(
        &ann,
        Origin::VaultSeat,
        MemberId::Account(a),
        2,
        now_ms() / 1000,
        &pair.public(),
    )
    .unwrap();
    let wire = Pair {
        keys: pair.public(),
        endorsement: e,
    };
    let reseated = |frames: &[ServerMessage]| {
        frames
            .iter()
            .filter_map(|f| match f {
                ServerMessage::EpochReseated { n, left } => Some((*n, *left)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    // No seat anywhere: done at once
    groups.on_seat_keys(a, wire.clone(), raw(&ann)).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let got = drain(rxs.get_mut(&9).unwrap()).await;
    assert_eq!(reseated(&got), vec![(2, 0)]);
    drop_db(&file);
}

/// Runs `sql` (no binds) on the scratch database.
async fn exec(db: &l4f_accounts::store::Store, sql: String) {
    match db {
        l4f_accounts::store::Store::Lite(b) => {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&b.0)
                .await
                .unwrap();
        }
        l4f_accounts::store::Store::Pg(b) => {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&b.0)
                .await
                .unwrap();
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A blob literal both backends read.
fn blob(db: &l4f_accounts::store::Store, b: &[u8]) -> String {
    match db {
        l4f_accounts::store::Store::Lite(_) => format!("x'{}'", hex(b)),
        l4f_accounts::store::Store::Pg(_) => format!("'\\x{}'::bytea", hex(b)),
    }
}

/// Finding: at a stored group's Genesis or Regenesis only the volunteer was seated; the
/// accounts that keep the conversation's log, offline ones too, were never queued again
/// (they send `LogJoin` once). They are queued eagerly once a new start lands.
#[tokio::test]
async fn a_stored_groups_new_start_queues_every_member_with_seat_keys_eagerly() {
    new_start_eagerly(5000).await;
}

/// Finding: `kept_seats = 0` is no limit (ACCOUNTS.md, the logs it caps), yet the group
/// key took it as a cap of none and seated nobody eagerly. The bound itself:
/// `an_idle_group_keeps_its_eager_joins_and_queues_at_most_kept_seats`.
#[tokio::test]
async fn kept_seats_0_is_no_limit_and_a_new_start_queues_every_member_eagerly() {
    new_start_eagerly(0).await;
}

async fn new_start_eagerly(kept_seats: u32) {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    net.groups.set_kept_seats(kept_seats);
    let id = net.groups.id_for(7, Some("c:den"));
    assert_eq!(id, "c:den", "a stored group's id is its conversation's");
    // An offline account that keeps the log, with its identity and seat keys
    let a = l4f_accounts::model::AccountId::new();
    db.create_user(
        &l4f_accounts::model::NewUser {
            id: a,
            username: "ann".into(),
            display_name: "ann".into(),
            email_pending: None,
            password_hash: None,
            created_at: l4f_accounts::util::now(),
        },
        None,
    )
    .await
    .unwrap();
    let ann = voipc_crypto::generate_identity_key_pair();
    let seat = SeatPair::generate();
    let e = Endorsement::sign(
        &ann,
        Origin::VaultSeat,
        MemberId::Account(a.0),
        1,
        now_ms() / 1000,
        &seat.public(),
    )
    .unwrap();
    crate::accounts::gk::put_seat_keys(
        &db,
        &a.0,
        &crate::accounts::gk::SeatKeys {
            n: 1,
            kem: seat.public().kem_bytes().into(),
            dh: seat.public().dh_bytes().into(),
            made: e.made,
            sig: e.sig.to_vec(),
            published: now_ms(),
        },
    )
    .await
    .unwrap();
    let ik = [&[0x05u8][..], &raw(&ann)].concat();
    exec(
        &db,
        format!(
            "INSERT INTO voipc_identity (account, identity_key, updated_at) VALUES ({}, {}, 0)",
            blob(&db, &a.0),
            blob(&db, &ik)
        ),
    )
    .await;
    exec(
        &db,
        format!(
            "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{id}', {}, 0)",
            blob(&db, &a.0)
        ),
    )
    .await;
    // A guest's fetch starts the group: the volunteer's Genesis
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    let p = net.guest(7, &id);
    net.fetch(&p, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("a Genesis");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let st = Start {
        kind: GroupKind::Text,
        id: &id,
        me: k.me(),
        ik: &k.ik,
        entry: k.entry(),
        joiners: &[&joiner],
        gated: false,
        stored: true,
        now: net.groups.now() / 1000,
    };
    let b = build_genesis(&st, &mut RowBases::new()).unwrap();
    net.commit(k.sid, &id, due, &b).await;
    let (due, piece) = due_within(&mut net, k.sid, 10_000).await.expect("a Join");
    assert_eq!(piece.kind, gk::due::JOIN);
    let ann_seat: gk::GkSeat = seat.public().seat(MemberId::Account(a.0)).into();
    let mut joins: Vec<gk::GkSeat> = piece.joins.iter().map(|j| j.seat).collect();
    // The members are read beside the actor: when that takes longer than the fetcher's
    // batch (a slow database), the account goes in the Join after it
    if !joins.contains(&ann_seat) {
        let mut h = Holds {
            ring: b.ring,
            krk: b.krk,
            cache: RowBases::new(),
        };
        let j = join_on(&k, &id, &b.header, &mut h, &piece, true, net.groups.now());
        net.commit(k.sid, &id, due, &j).await;
        let (_, next) = due_within(&mut net, k.sid, 10_000)
            .await
            .expect("the next Join");
        joins.extend(next.joins.iter().map(|j| j.seat));
    }
    assert!(
        joins.contains(&ann_seat),
        "the account is queued eagerly (kept_seats {kept_seats})"
    );
    assert_eq!(joins.len(), 2);
    net.groups.on_purge(&id);
    drop_db(&file);
}

// ── R1b: keyholder upkeep, seed pages, kept reads, sweeps, Load ───────────

/// An entry made up for the keyholder rules alone: `x` fills its keys.
fn entry(m: MemberId, origin: u8, n: u32, x: u8) -> Keyholder {
    Keyholder {
        m,
        u: None,
        origin,
        n,
        ik: [x; 32],
        kx: [x; 32],
        tag_kk: [x; 8],
    }
}

const DAY_MS: u64 = 86_400_000;

#[test]
fn a_full_set_removes_the_entry_away_longest_before_a_promotion() {
    let mut h = Holders::default();
    let set: Vec<Keyholder> = (1..=8u8)
        .map(|i| entry(MemberId::Account([i; 16]), gk::origin::DESKTOP, 1, i))
        .collect();
    h.set_to(set, |_| None);
    let (_, v) = desktop(9, [9; 16]);
    let vols: HashMap<UserId, Volunteer> = [(9, v)].into();
    h.seen(&vols, 1_000);
    h.stats.get_mut(&[5; 32]).unwrap().away_since = Some(500);
    assert!(
        h.promotion(GroupKind::Text, &vols, false, 10).is_none(),
        "no ninth entry"
    );
    assert_eq!(
        h.swap_out(GroupKind::Text, &vols, false, 10).map(|r| r.kx),
        Some([5; 32])
    );
    assert!(
        h.swap_out(GroupKind::Text, &HashMap::new(), false, 10)
            .is_none(),
        "with nobody to promote, nobody goes"
    );
}

#[test]
fn a_connection_pairs_entry_goes_once_offline_by_its_origin_and_a_desktop_after_seven_days() {
    let mut h = Holders::default();
    let browser = entry(MemberId::Account([1; 16]), gk::origin::CONNECTION, 1, 1);
    let desk = entry(MemberId::Account([2; 16]), gk::origin::DESKTOP, 1, 2);
    let other = entry(MemberId::Account([3; 16]), gk::origin::DESKTOP, 1, 3);
    let vols = HashMap::new();
    h.set_to(vec![desk, other], |_| None);
    h.seen(&vols, 0);
    assert_eq!(h.removal_where(&vols, 10, false, 1_000, |_| true), None);
    assert_eq!(
        h.removal_where(&vols, 10, false, 7 * DAY_MS, |_| true)
            .map(|r| r.kx),
        Some([2; 32]),
        "a desktop away seven days"
    );
    h.set_to(vec![desk, browser, other], |_| None);
    h.seen(&vols, 0);
    assert_eq!(
        h.removal_where(&vols, 10, false, 1_000, |_| true)
            .map(|r| r.kx),
        Some([1; 32]),
        "an account browser's 0x02 entry at once"
    );
}

#[test]
fn an_entry_below_its_accounts_newest_counter_goes_after_seven_days() {
    let mut h = Holders::default();
    h.set_to(
        vec![
            entry(MemberId::Account([1; 16]), gk::origin::DESKTOP, 1, 1),
            entry(MemberId::Account([2; 16]), gk::origin::DESKTOP, 2, 2),
        ],
        |_| None,
    );
    h.newest.insert([1; 16], (2, 1_000));
    h.newest.insert([2; 16], (2, 1_000));
    let vols = HashMap::new();
    assert_eq!(
        h.removal_where(&vols, 10, false, 6 * DAY_MS, |_| true),
        None
    );
    assert_eq!(
        h.removal_where(&vols, 10, false, 7 * DAY_MS + 1_000, |_| true)
            .map(|r| r.kx),
        Some([1; 32])
    );
}

#[test]
fn a_higher_ranked_volunteer_is_promoted_over_two_online_guests_one_at_a_time() {
    let (a, b) = (Person::guest(1), Person::guest(2));
    let mut h = Holders::default();
    h.set_to(vec![a.entry(), b.entry()], |_| None);
    let mut vols: HashMap<UserId, Volunteer> = [
        (1, a.volunteer(gk::platform::DESKTOP)),
        (2, b.volunteer(gk::platform::DESKTOP)),
    ]
    .into();
    assert!(h.promotion(GroupKind::Text, &vols, false, 10).is_none());
    let (k, d) = desktop(3, [3; 16]);
    vols.insert(3, d);
    assert_eq!(
        h.promotion(GroupKind::Text, &vols, false, 10)
            .map(|v| v.sid),
        Some(3),
        "the hand-over"
    );
    h.set_to(vec![a.entry(), b.entry(), k.entry()], |_| None);
    let (_, d2) = desktop(4, [4; 16]);
    vols.insert(4, d2);
    assert!(
        h.promotion(GroupKind::Text, &vols, false, 10).is_none(),
        "one of that rank holds keys: no second"
    );
}

#[test]
fn a_device_removed_from_its_account_takes_its_entries() {
    let mut h = Holders::default();
    h.set_to(
        vec![
            entry(MemberId::Account([1; 16]), gk::origin::DESKTOP, 1, 1),
            entry(MemberId::Account([2; 16]), gk::origin::DESKTOP, 1, 2),
        ],
        |_| None,
    );
    h.device.insert([1; 32], b"laptop".to_vec());
    let vols = HashMap::new();
    h.device_removed(&[1; 16], b"phone");
    assert_eq!(h.removal_where(&vols, 10, false, 0, |_| true), None);
    h.device_removed(&[1; 16], b"laptop");
    assert_eq!(
        h.removal_where(&vols, 10, false, 0, |_| true).map(|r| r.kx),
        Some([1; 32])
    );
}

#[test]
fn an_idle_group_keeps_its_eager_joins_and_queues_at_most_kept_seats() {
    let mut g = new_group(true);
    let mut out = vec![];
    let now = now_ms();
    g.kept_seats = 1;
    let (a, b) = (Person::account(2, [2; 16]), Person::account(3, [3; 16]));
    g.eager(a.joiner(), [2; 16], now, &mut out);
    g.eager(b.joiner(), [3; 16], now, &mut out);
    assert_eq!(g.joins.queue.len(), 1, "kept_seats");
    assert!(!g.idle(), "the actor stays while an eager seat waits");
}

#[tokio::test]
async fn members_with_no_keyholder_online_warn_once_in_ten_minutes() {
    let store = Store::memory();
    let (mut g, _, _, _, now) = seated_group(&store).await;
    let mut out = vec![];
    g.leave(1, cause::DISCONNECT, now, &mut out);
    g.tick(now + 61_000, &mut out);
    assert_eq!(
        g.warnings(now + 61_000),
        vec!["no keyholder online for 1 min".to_string()]
    );
    g.tick(now + 300_000, &mut out);
    assert_eq!(
        g.warnings(now + 300_000),
        vec!["no keyholder online for 1 min".to_string()],
        "throttled"
    );
    assert!(g.warnings(now + 61_000 + 600_000).is_empty());
    assert!(g.mem_bytes() > 0);
}

#[tokio::test]
async fn a_seed_page_takes_only_its_own_seats_under_its_seed_and_pushes_each_welcome() {
    let store = Store::memory();
    let (mut g, k, _, people, now) = seated_group(&store).await;
    let gen = g.gen().unwrap();
    let by = HolderRef {
        m: k.m(),
        kx: k.wire().kx(),
    };
    let (mine, other) = (people[0].seat(), people[1].seat());
    g.page = Some(crate::gk::group::Page {
        id: 77,
        sid: 1,
        by,
        seed: 2,
        seats: [mine].into(),
        deadline: now + 60_000,
    });
    let w = |seat: SeatRef| gk::SeedWelcomeOut {
        seat: seat.into(),
        bytes: vec![7; gk::SEED_WELCOME_BYTES],
    };
    let mut out = vec![];
    assert!(g
        .take_welcomes(1, 78, gen, 2, vec![w(mine)], &mut out)
        .is_none());
    assert!(g
        .take_welcomes(1, 77, gen, 1, vec![w(mine)], &mut out)
        .is_none());
    assert_eq!(stales(&out, 1), vec![stale::NOT_DUE, stale::CHECK]);
    let (from, took) = g
        .take_welcomes(1, 77, gen, 2, vec![w(mine), w(other)], &mut out)
        .unwrap();
    assert_eq!(from, by);
    assert_eq!(took.len(), 1, "a seat of another page is not taken");
    store.seeds(ID, &gen, 2, &by, &took, now).await.unwrap();
    let mut out = vec![];
    g.seeded(by, 2, &took, now, &mut out);
    assert_eq!(g.seats[&mine].seed, 2);
    assert!(g.page.is_none(), "every seat of the page has one");
    let pushed = ins(&out, people[0].sid);
    assert_eq!(pushed[0].seed_welcome.as_ref().map(|w| w.s), Some(2));
    assert!(
        store.seed_welcome(ID, &gen, &mine, 2).await.is_some(),
        "kept for the seat's next connection"
    );
}

/// An account in `db` with its identity key and seat keys (counter 1), keeping `conv`'s log
/// where given: its seat as `Person::account`.
async fn db_account(db: &l4f_accounts::store::Store, sid: UserId, conv: Option<&str>) -> Person {
    let a = l4f_accounts::model::AccountId::new();
    db.create_user(
        &l4f_accounts::model::NewUser {
            id: a,
            username: format!("u{}", rand::random::<u32>()),
            display_name: "x".into(),
            email_pending: None,
            password_hash: None,
            created_at: l4f_accounts::util::now(),
        },
        None,
    )
    .await
    .unwrap();
    let p = Person::account(sid, a.0);
    crate::accounts::gk::put_seat_keys(
        db,
        &a.0,
        &crate::accounts::gk::SeatKeys {
            n: 1,
            kem: p.pair.public().kem_bytes().into(),
            dh: p.pair.public().dh_bytes().into(),
            made: p.endorsement.made,
            sig: p.endorsement.sig.to_vec(),
            published: now_ms(),
        },
    )
    .await
    .unwrap();
    let ik = [&[0x05u8][..], &raw(&p.ik)].concat();
    exec(
        db,
        format!(
            "INSERT INTO voipc_identity (account, identity_key, updated_at) VALUES ({}, {}, 0)",
            blob(db, &a.0),
            blob(db, &ik)
        ),
    )
    .await;
    if let Some(conv) = conv {
        exec(
            db,
            format!(
                "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{conv}', {}, 0)",
                blob(db, &a.0)
            ),
        )
        .await;
    }
    p
}

#[tokio::test]
async fn an_accounts_rows_page_through_every_group_once() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let net = Net::new();
    net.groups.attach(db.clone(), inc);
    let p = db_account(&db, 1, None).await;
    let a = p.account.unwrap();
    for (grp, seed) in [("c:a", 1), ("c:a", 2), ("c:b", 1)] {
        exec(
            &db,
            format!(
                "INSERT INTO voipc_gk_self (grp, account, gen, seed, tag_sk, tag_sx, kind, sealed)
                 VALUES ('{grp}', {}, {}, {seed}, {}, {}, 0, {})",
                blob(&db, &a),
                blob(&db, &[1; 16]),
                blob(&db, &[2; 8]),
                blob(&db, &[3; 8]),
                blob(&db, &[4; gk::SELF_ROW_BYTES]),
            ),
        )
        .await;
    }
    let (first, next) = net.groups.rows_of(a, None, 2).await;
    assert_eq!(first.len(), 2);
    let (rest, end) = net.groups.rows_of(a, next.as_deref(), 2).await;
    assert_eq!(end, None);
    let mut all: Vec<(String, u32)> = first
        .iter()
        .chain(&rest)
        .map(|r| (r.group.clone(), r.seed))
        .collect();
    all.sort();
    assert_eq!(
        all,
        vec![("c:a".into(), 1), ("c:a".into(), 2), ("c:b".into(), 1)]
    );
    drop_db(&file);
}

#[tokio::test]
async fn keyholder_pairs_ranks_and_devices_outlive_a_restart() {
    let id = "c:den-k";
    let (db, file, store, mut g, k, now) = stored_genesis(id).await;
    g.holders.device.insert(k.wire().kx(), b"laptop".to_vec());
    store.put_holders(&g, now).await;
    let mut again = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut again).await.unwrap();
    let kx = k.wire().kx();
    let pair = again.holders.pairs.get(&kx).expect("the pair");
    assert_eq!(pair.keys.seat(k.m()), k.seat());
    assert_eq!(pair.endorsement.sig, k.endorsement.sig);
    assert_eq!(
        again.holders.rank.get(&kx),
        Some(&2),
        "a guest desktop's rank"
    );
    assert_eq!(
        again.holders.device.get(&kx).map(Vec::as_slice),
        Some(&b"laptop"[..])
    );
    assert!(
        again.holders.stats[&kx].away_since.is_some(),
        "offline since it was last seen"
    );
    let rows = crate::accounts::gk::holders(&db, id).await.unwrap();
    assert_eq!(rows.len(), 1, "accounts::gk still reads the row");
    drop_db(&file);
}

/// A stored group's two epochs: guest keyholder 1's Genesis, then its refresh opening.
async fn stored_two_epochs(
    id: &str,
) -> (
    l4f_accounts::store::Store,
    std::path::PathBuf,
    Store,
    GroupState,
    u64,
) {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let store = Store::Db(Arc::new(crate::gk::store::DbStore {
        db: db.clone(),
        incarnation: inc,
    }));
    let mut g = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    let k = Person::guest(1);
    let mut now = now_ms();
    let mut out = vec![];
    g.follow(1, None);
    g.volunteer(1, Some(k.volunteer(gk::platform::DESKTOP)), now, &mut out);
    g.fetch(1, k.fetch(), now, &mut out);
    let (due, piece) = dues(&out, 1).pop().unwrap();
    let b = genesis(&k, id, &piece, true, now);
    let mut out = vec![];
    let t = send_to(&mut g, id, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    now += 61_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a refresh");
    assert_eq!(piece.kind, gk::due::REFRESH);
    let grp = Group::new(GroupKind::Text, id, g.gen().unwrap()).unwrap();
    let held = |s: &SeatRef| g.seats.get(s).map(|x| x.seed);
    let lists = lists(&g);
    let head = g.head.as_ref().unwrap();
    let hold = Holding {
        g: &grp,
        head: &head.sh,
        kh: &head.kh,
        ring: &h.ring,
        krk: &h.krk,
        me: k.me(),
        ik: &k.ik,
        lists: &lists,
        held: &held,
        rolls: g.rolls,
        stored: true,
    };
    let pairs: HashMap<[u8; 32], SeatPublic> = [(k.wire().kx(), k.pair.public())].into();
    let pair_of = |e: &Keyholder| pairs.get(&e.kx).cloned();
    let seed_seats = HashMap::new();
    let ask = OpeningAsk {
        kind: Kind::Fresh,
        exits: &[],
        exits_upto: 0,
        refresh: true,
        gated: false,
        candidate: None,
        remove: None,
        replace: None,
        finish: piece.finish,
        seed_seats: &seed_seats,
        pairs: &pair_of,
        now: now / 1000,
    };
    let b = build_opening(&hold, &ask, &mut h.cache, None).unwrap();
    let mut out = vec![];
    let t = send_to(&mut g, id, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(g.head.as_ref().unwrap().sh.header().epoch, 2);
    (db, file, store, g, now)
}

/// `send` for a group id other than `ID`.
fn send_to(
    g: &mut GroupState,
    id: &str,
    sid: UserId,
    due: u64,
    b: &Built,
    now: u64,
    out: &mut Vec<Out>,
) -> Option<crate::gk::group::Taken> {
    let piece = CommitPiece::try_from(b.commit.clone()).unwrap();
    let parts = cut_commit(piece, PIECE_MAX_BYTES - commit_frame_overhead(id)).unwrap();
    let n = parts.len();
    let mut taken = None;
    for (i, p) in parts.into_iter().enumerate() {
        let bytes = push::len(&p);
        taken = g.commit_part(sid, due, i as u16, i + 1 == n, p, bytes, now, out);
    }
    taken
}

async fn count(db: &l4f_accounts::store::Store, q: &str) -> i64 {
    let q = q.to_string();
    match db {
        l4f_accounts::store::Store::Lite(b) => sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q))
            .fetch_one(&b.0)
            .await
            .unwrap(),
        l4f_accounts::store::Store::Pg(b) => sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(q))
            .fetch_one(&b.0)
            .await
            .unwrap(),
    }
}

#[tokio::test]
async fn a_sweep_takes_an_old_epochs_seals_unless_a_kept_chain_references_it() {
    let id = "c:den-s";
    let (db, file, _store, g, now) = stored_two_epochs(id).await;
    let gen = g.gen().unwrap();
    let seals =
        |e: u32| format!("SELECT COUNT(*) FROM voipc_gk_seals WHERE grp = '{id}' AND epoch = {e}");
    // A kept chain starting in epoch 1
    let owner = db_account(&db, 9, None).await.account.unwrap();
    exec(
        &db,
        format!(
            "INSERT INTO voipc_writers (id, conv, owner) VALUES (1, '{id}', {})",
            blob(&db, &owner)
        ),
    )
    .await;
    exec(
        &db,
        format!(
            "INSERT INTO voipc_chains (id, writer, chain, top, self_wrap, created_at) VALUES (1, 1, 1, 0, {}, 0)",
            blob(&db, &[1])
        ),
    )
    .await;
    exec(
        &db,
        format!(
            "INSERT INTO voipc_gk_chains (chain_id, grp, gen, epoch, idx, sealed) VALUES (1, '{id}', {}, 1, 0, {})",
            blob(&db, &gen),
            blob(&db, &[1])
        ),
    )
    .await;
    let later = now + 3_600_000;
    crate::gk::store::sweep_material(&db, id, now)
        .await
        .unwrap();
    assert_eq!(
        count(&db, &seals(1)).await,
        1,
        "the next opening is too young"
    );
    crate::gk::store::sweep_material(&db, id, later)
        .await
        .unwrap();
    assert_eq!(count(&db, &seals(1)).await, 1, "a kept chain references it");
    let piece = crate::gk::store::past(
        &db,
        id,
        MemberId::Conn(1),
        gk::EpochRef { gen, epoch: 1 },
        None,
    )
    .await
    .unwrap()
    .expect("a past answer for the referenced epoch");
    assert_eq!(piece.past, Some(gk::EpochRef { gen, epoch: 1 }));
    assert!(piece.seat.is_some() && piece.seal.is_some() && piece.path.is_some());
    exec(&db, "DELETE FROM voipc_gk_chains".into()).await;
    crate::gk::store::sweep_material(&db, id, later)
        .await
        .unwrap();
    assert_eq!(count(&db, &seals(1)).await, 0, "unreferenced, it goes");
    assert_eq!(count(&db, &seals(2)).await, 1, "the head epoch's stay");
    assert!(
        crate::gk::store::past(
            &db,
            id,
            MemberId::Conn(1),
            gk::EpochRef { gen, epoch: 1 },
            None
        )
        .await
        .unwrap()
        .is_none(),
        "not to be had once swept"
    );
    drop_db(&file);
}

#[tokio::test]
async fn a_seat_unused_ninety_days_exits_unless_a_session_holds_it() {
    let id = "c:den-x";
    let (db, file, store, mut g, _k, now) = stored_genesis(id).await;
    let gen = g.gen().unwrap();
    exec(
        &db,
        format!("UPDATE voipc_gk_seats SET last_use = 5 WHERE grp = '{id}'"),
    )
    .await;
    let seats = crate::gk::store::expired(&db, id, 10).await.unwrap();
    assert_eq!(seats.len(), 1);
    assert!(crate::gk::store::expired(&db, id, 5)
        .await
        .unwrap()
        .is_empty());
    let mut out = vec![];
    g.expire(&seats, now, &mut out);
    assert_eq!(g.exits.waiting(), 0, "its session holds it");
    g.leave(1, cause::LEAVE, now, &mut out);
    let left = g.exits.waiting();
    g.expire(&seats, now, &mut out);
    assert_eq!(g.exits.waiting(), left, "once out, no second exit");
    let _ = (store, gen);
    drop_db(&file);
}

#[tokio::test]
async fn a_used_seat_has_its_last_use_written_by_the_daily_sweep_and_load_shows_db_bytes() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("c:den-u"));
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    net.fetch(&k, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("a Genesis");
    let b = genesis(&k, &id, &piece, true, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    stats_until(&net, 7, |s| s.seats == 1).await;
    exec(
        &db,
        format!("UPDATE voipc_gk_seats SET last_use = 0 WHERE grp = '{id}'"),
    )
    .await;
    // Its next fetch is answered from the snapshot: the seat is used
    net.fetch(&k, &id).await;
    let _ = net.frames(k.sid, 50).await;
    net.groups.sweep_for_test(true).await;
    let used = count(
        &db,
        &format!("SELECT MAX(last_use) FROM voipc_gk_seats WHERE grp = '{id}'"),
    )
    .await;
    assert!(used > 0, "written");
    let row = stats_until(&net, 7, |s| s.db_bytes > 0).await;
    assert!(row.db_bytes > 0 && row.mem_bytes > 0);
    net.groups.on_purge(&id);
    drop_db(&file);
}

#[tokio::test]
async fn an_accounts_first_seat_keys_seat_it_eagerly_in_its_conversations_stored_groups() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("c:den-e"));
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    net.fetch(&k, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("a Genesis");
    let b = genesis(&k, &id, &piece, true, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    stats_until(&net, 7, |s| s.seats == 1).await;
    // An offline account joins the conversation's log, then publishes its first seat keys
    let ann = db_account(&db, 50, Some(&id)).await;
    let a = ann.account.unwrap();
    net.groups.on_seat_keys(a, ann.wire(), raw(&ann.ik)).await;
    let (_, piece) = due_within(&mut net, k.sid, 10_000).await.expect("a Join");
    assert_eq!(piece.kind, gk::due::JOIN);
    let seat: gk::GkSeat = ann.seat().into();
    assert!(piece.joins.iter().any(|j| j.seat == seat));
    // The page `eager_all` reads of them names the same account
    let page = crate::gk::store::eager_page(&db, &id, None, 10)
        .await
        .unwrap();
    assert_eq!(page.iter().map(|(x, _)| *x).collect::<Vec<_>>(), vec![a]);
    net.groups.on_purge(&id);
    drop_db(&file);
}

/// With the switch off the database is attached for kept reads alone (R2): no account
/// hook starts a group or writes a gk table.
#[tokio::test]
async fn with_the_switch_off_the_account_hooks_start_no_group_and_write_no_gk_table() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let groups = Groups::new(false);
    groups.attach(db.clone(), inc);
    let ann = db_account(&db, 50, Some("c:den-off")).await;
    let a = ann.account.unwrap();
    groups.on_log_join("c:den-off", a, raw(&ann.ik)).await;
    groups.on_log_leave("c:den-off", a, cause::LEAVE);
    groups.on_seat_keys(a, ann.wire(), raw(&ann.ik)).await;
    groups.on_device_removed(a, &[1; 16]).await;
    groups.on_account_gone(a, cause::LEAVE).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(groups.stats().is_empty(), "no group started");
    assert_eq!(gk_rows(&db).await, 0);
    drop_db(&file);
}

/// Finding: a group another channel named first (a deleted one whose conversation came
/// back in a new, gated channel) kept that channel's open gate: the new channel's gate
/// reached the group key before any follow there named the group, and its follow told the
/// group nothing, so a guest was asked an ungated Genesis. The follow tells it its gate.
#[tokio::test]
async fn a_group_another_channel_named_takes_the_gate_of_the_channel_following_it_now() {
    let mut net = Net::new();
    let id = "c:dc-5";
    let k = net.guest(5, id);
    net.volunteer(&k).await;
    net.groups.on_gate(6, true);
    let p = net.guest(6, id);
    net.fetch(&p, id).await;
    let out = net.frames(k.sid, 50).await;
    assert!(
        dues(&out, k.sid).is_empty(),
        "no guest starts a gated group's keys"
    );
    let out = net.frames(p.sid, 0).await;
    assert_eq!(waits(&out, p.sid), vec![wait::NO_KEYHOLDER]);
    net.groups.on_purge(id);
}

/// Finding: a deleted channel still named its group, whose rows outlive it, so an account
/// hook that started the group again took the channel that was gone (and its open gate).
/// The channel names it no more and keeps no gate.
#[tokio::test]
async fn a_deleted_channel_names_its_group_no_more() {
    let mut net = Net::new();
    let id = "c:dc-5";
    let _ = net.guest(5, id);
    net.groups.on_gate(5, true);
    net.groups.on_channel_gone(5, id);
    assert!(!net.groups.gated(5), "its gate went with it");
    assert!(net.groups.stats().is_empty(), "its group stopped");
    net.groups.on_log_leave(id, [1; 16], cause::LEAVE);
    let rows = net.groups.stats();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].channel_id, 0, "it names no channel that is gone");
    net.groups.on_purge(id);
}

#[tokio::test]
async fn going_quiet_is_no_exit() {
    let mut net = Net::new();
    let id = net.groups.id_for(7, None);
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    net.fetch(&k, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("a Genesis");
    let b = genesis(&k, &id, &piece, false, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    stats_until(&net, 7, |s| s.seats == 1).await;
    // Going quiet is a follow again (state.rs `gk_follow`), no exit (§5.4)
    net.groups.on_follow(7, &id, GroupKind::Text, k.sid, None);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let row = stats_until(&net, 7, |_| true).await;
    assert_eq!((row.seats, row.exits_waiting), (1, 0));
    net.groups.on_purge(&id);
}

#[tokio::test]
async fn a_member_reporting_another_generation_ahead_warns_the_admin_of_its_channel() {
    let mut net = Net::new();
    let id = net.groups.id_for(7, None);
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    net.fetch(&k, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("a Genesis");
    let b = genesis(&k, &id, &piece, false, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    stats_until(&net, 7, |s| s.seats == 1).await;
    // A header of a generation this relay never had
    let other = genesis(&k, &id, &piece, false, net.groups.now());
    net.send(
        k.sid,
        voipc_protocol::messages::ClientMessage::EpochFloorAhead {
            group: id.clone(),
            header: voipc_crate_header(&other),
        },
    )
    .await;
    let mut warned = vec![];
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        warned = net.groups.warnings();
        if !warned.is_empty() {
            break;
        }
    }
    assert_eq!(
        warned,
        vec![(
            7,
            "#7: a member reports it ahead of this database".to_string()
        )]
    );
    net.groups.on_purge(&id);
}

/// The first due `sid` is sent within `ms`, its store writes taking what they take (Postgres).
async fn due_within(net: &mut Net, sid: UserId, ms: u64) -> Option<(u64, DuePiece)> {
    let mut out = vec![];
    for _ in 0..ms / 100 {
        out.extend(net.frames(sid, 100).await);
        if let Some(d) = dues(&out, sid).pop() {
            return Some(d);
        }
    }
    None
}

// ── R1b fixer (review of 2026-11-18) ──────────────────────────────────────

/// Review 1: an entry only its own session could remove (the one online entry, its counter
/// stale or its device removed) held every due behind its Remove: nobody could sign it
/// (rule 2), so nothing was asked, joins waited for ever. It waits; the Join goes.
#[tokio::test]
async fn a_removal_only_its_own_entry_could_sign_waits_and_the_join_behind_it_is_asked() {
    let store = Store::memory();
    let (mut g, k, _, _, mut now) = seated_group(&store).await;
    let mut set = g.holders.set.clone();
    set.push(entry(MemberId::Account([9; 16]), gk::origin::DESKTOP, 1, 9));
    g.holders.set_to(set, |_| None);
    let own = HolderRef {
        m: k.m(),
        kx: k.wire().kx(),
    };
    g.holders.forced.push(own);
    let p = Person::guest(5);
    let mut out = vec![];
    g.follow(5, None);
    assert_eq!(g.fetch(5, p.fetch(), now, &mut out), Fetched::Not);
    now += 3_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let asked: Vec<u8> = dues(&out, 1).iter().map(|(_, d)| d.kind).collect();
    assert_eq!(asked, vec![gk::due::JOIN], "the Join behind the Remove");
    assert_eq!(
        g.holders
            .removal_where(&g.vols, g.seats.len(), false, now, |_| true),
        Some(own),
        "still proposed, for when another entry is online"
    );
}

/// Review 3: `last_online` was written only when the set or who of it is online changed,
/// so a restart counted a desktop online for eight days as away eight days and removed it.
/// The 10-minute sweep writes it for the online entries.
#[tokio::test]
async fn an_online_keyholders_last_online_is_written_by_the_sweep_so_a_restart_counts_no_time_away()
{
    let id = "c:den-o";
    let (_db, file, store, mut g, k, now) = stored_genesis(id).await;
    store.put_holders(&g, now).await;
    let later = now + 8 * DAY_MS;
    store.sweep_live(&mut g, later, false).await;
    let mut again = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut again).await.unwrap();
    assert_eq!(
        again.holders.stats[&k.wire().kx()].away_since,
        Some(later),
        "away only from when the sweep last saw it online"
    );
    drop_db(&file);
}

/// Review 4: the 10-minute sweep read the head's generation once, then deleted every other
/// generation's material: a new generation that took the head meanwhile lost its seals,
/// lists, keyring and headers. Each statement reads the head's generation itself.
#[tokio::test]
async fn a_sweep_begun_before_a_new_generation_took_the_head_keeps_all_of_that_generation() {
    let id = "c:den-g";
    let (db, file, store, mut g, k, now) = stored_genesis(id).await;
    let row = crate::accounts::gk::group(&db, id).await.unwrap().unwrap();
    let old = g.gen().unwrap();
    g.new_gen = true;
    let p = Person::guest(3);
    let mut out = vec![];
    g.follow(3, None);
    g.fetch(3, p.fetch(), now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Genesis due");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let later = now + 5_000;
    let b = genesis(&k, id, &piece, true, later);
    let mut out = vec![];
    let t = send_to(&mut g, id, 1, due, &b, later, &mut out).expect("taken");
    land(&mut g, &store, t, later, &mut out).await;
    let new = g.gen().unwrap();
    assert_ne!(old, new);
    crate::gk::store::sweep_material_from(&db, id, &row, later + 3_600_000)
        .await
        .unwrap();
    let of = |table: &str, gen: &[u8; 16]| {
        format!(
            "SELECT COUNT(*) FROM {table} WHERE grp = '{id}' AND gen = {}",
            blob(&db, gen)
        )
    };
    for table in [
        "voipc_gk_seals",
        "voipc_gk_lists",
        "voipc_gk_headers",
        "voipc_gk_keyring",
        "voipc_gk_seats",
    ] {
        assert!(
            count(&db, &of(table, &new)).await > 0,
            "{table} of the head"
        );
    }
    assert_eq!(
        count(&db, &of("voipc_gk_seals", &old)).await,
        0,
        "the old go"
    );
    let mut again = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut again).await.unwrap();
    assert_eq!(again.gen(), Some(new));
    drop_db(&file);
}

/// Review 6: a memory group keeps a seed welcome only until it went out (2b). A seat keyed
/// by a row has no `s_m` on a new connection without its seed's welcome (no self-rows in
/// memory): lost, so it joins again, rather than answered with a row it cannot open.
#[tokio::test]
async fn a_memory_seat_keyed_by_a_row_is_lost_to_a_new_connection_unless_its_seeds_welcome_is_kept()
{
    let store = Arc::new(Store::memory());
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    g.leave(people[1].sid, cause::LEAVE, now, &mut out);
    now += 3 * 20 + 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("an exits due");
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let seat = people[0].seat();
    let gen = g.gen().unwrap();
    let at = g.snapshot().unwrap().base_of(&seat).expect("a base");
    let (s, by, welcome, _) = store.base(ID, &gen, &seat, at).await.expect("kept");
    assert!(!welcome, "re-keyed by a row");
    let groups = Groups::new(true);
    let hd = groups.handle_for_test(&g, store.clone());
    assert!(hd.lost_for_test(&seat).await, "no s_m to open the row");
    let w = vec![(seat, vec![7; gk::SEED_WELCOME_BYTES])];
    store.seeds(ID, &gen, s, &by, &w, now).await.unwrap();
    assert!(!hd.lost_for_test(&seat).await, "its seed's welcome kept");
    store.seed_sent(&seat, s);
    assert_eq!(hd.seed_kept_for_test(), 0, "gone once it went out");
}

/// Review 7: a declined page was ignored (only dues were looked at), so it waited out its
/// 60 s deadline and counted as a miss. It is let go and asked again at once.
#[tokio::test]
async fn a_declined_seed_page_is_asked_again_at_once_and_is_no_miss() {
    let store = Store::memory();
    let (mut g, k, _, people, now) = seated_group(&store).await;
    let by = HolderRef {
        m: k.m(),
        kx: k.wire().kx(),
    };
    g.page = Some(crate::gk::group::Page {
        id: 77,
        sid: 1,
        by,
        seed: 2,
        seats: [people[0].seat()].into(),
        deadline: now + 60_000,
    });
    g.next_page = now + 10_000;
    let mut out = vec![];
    g.decline(1, 77, gk::decline::NOT_READY, now, &mut out);
    assert!(g.page.is_none(), "let go");
    assert_eq!(g.next_page, now, "asked again at once");
    assert!(g.holders.stats[&by.kx].missed.is_empty(), "no miss");
    assert_eq!(g.holders.stats[&by.kx].declined.len(), 1, "a decline");
}

/// Review 7: a page's welcomes went through the inbox, so a full one dropped them and their
/// keyholder took the miss. They take the commit lane; a session asked nothing is refused.
#[tokio::test]
async fn a_full_inbox_still_takes_a_pages_welcomes_on_the_commit_lane() {
    let mut net = Net::new();
    let id = net.groups.id_for(9, None);
    let k = net.guest(9, &id);
    let p = net.guest(9, &id);
    net.volunteer(&k).await;
    net.fetch(&p, &id).await;
    let out = net.frames(k.sid, 50).await;
    let (due, _) = dues(&out, k.sid).pop().expect("a Genesis due");
    net.frames(p.sid, 0).await;
    net.groups.get(&id).unwrap().inbox_full_for_test();
    let welcomes = |sid: UserId| {
        (
            sid,
            voipc_protocol::messages::ClientMessage::EpochWelcomes {
                group: id.clone(),
                due,
                gen: [0; 16],
                seed: 2,
                welcomes: vec![],
            },
        )
    };
    let (sid, msg) = welcomes(p.sid);
    net.send(sid, msg).await;
    let got = net.frames(p.sid, 0).await.remove(0).1;
    assert!(
        matches!(
            got[..],
            [ServerMessage::EpochStale {
                reason: stale::NOT_DUE,
                ..
            }]
        ),
        "asked nothing: {got:?}"
    );
    let (sid, msg) = welcomes(k.sid);
    net.send(sid, msg).await;
    let got = net.frames(k.sid, 50).await.remove(0).1;
    assert!(
        got.iter()
            .any(|f| matches!(f, ServerMessage::EpochStale { due: d, reason: stale::NOT_DUE, .. } if *d == due)),
        "the lane reached the actor (no page of that id): {got:?}"
    );
    assert_eq!(net.groups.lane_for_test(k.sid), 0, "and was freed");
}

/// Review 8: a page asked seats on their way out, and a seat whose keys no seed welcome
/// could reach (rotated in a memory group) stayed behind for ever, so the roll never
/// ended. A seat waiting to exit is asked no page; one with no keys exits.
#[tokio::test]
async fn a_page_asks_no_seat_on_its_way_out_and_a_seat_no_seed_welcome_can_reach_exits() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group_back(&store, 25 * 3_600_000).await;
    g.rolls.removal = true;
    now += 61_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a refresh");
    assert_eq!(piece.kind, gk::due::REFRESH);
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert!(g.roll_runs(), "the refresh started a roll");
    let (out_seat, gone) = (people[0].seat(), people[1].seat());
    let mut out = vec![];
    g.exit(out_seat, cause::KICK, now, &mut out);
    let want = g.page_wanted(now).expect("a page");
    assert!(!want.contains(&out_seat), "not one on its way out");
    assert!(want.contains(&gone) && want.contains(&k.seat()));
    let mut out = vec![];
    g.ask_page(vec![], vec![(gone, cause::ROTATION)], now, &mut out);
    assert!(g.exits.has(&gone), "it exits, so the roll can end");
}

/// Review 8: a rotation exited the old seat in stored groups only, so in a memory group it
/// sat on, behind every roll. Its seats but the new one exit, its sessions seated anew.
#[tokio::test]
async fn a_rotation_exits_the_accounts_other_seats_in_a_memory_group() {
    let store = Store::memory();
    let (mut g, k, mut h, _, mut now) = seated_group(&store).await;
    let a = Person::account(5, [5; 16]);
    join_one(&mut g, &store, &k, &mut h, &a, None, &mut now).await;
    let mut out = vec![];
    g.rotated(&[5; 16], &a.seat(), now, &mut out);
    assert!(!g.exits.has(&a.seat()), "the seat it keeps");
    let new = Person::account(6, [5; 16]).seat();
    g.rotated(&[5; 16], &new, now, &mut out);
    assert!(g.exits.has(&a.seat()), "the old seat exits");
    assert_eq!(g.members[&5].seat, None, "seated anew at its next fetch");
}

// ── J4: a ban, identity reset or deletion removes the keyholder entries ───

/// A memory group held by kim's desktop (session 1, account `[1; 16]`), ann (session 2) a
/// member, and account `a`'s desktop (session 5) seated with its Promote asked of kim: out,
/// not sent. Kim's volunteer comes back with it, for when kim goes and comes back.
async fn promote_out(
    store: &Store,
    a: [u8; 16],
) -> (
    GroupState,
    (Person, Volunteer),
    Holds,
    Person,
    u64,
    (u64, DuePiece),
) {
    let mut g = new_group(false);
    let (k, kv) = desktop(1, [1; 16]);
    let ann = Person::account(2, [2; 16]);
    let mut now = now_ms();
    let mut out = vec![];
    g.follow(1, Some([1; 16]));
    g.volunteer(1, Some(kv.clone()), now, &mut out);
    g.follow(2, Some([2; 16]));
    g.fetch(2, ann.fetch(), now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Genesis due");
    let b = genesis(&k, ID, &piece, false, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, store, t, now, &mut out).await;
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    // `a`'s desktop volunteers: seated, then promoted
    let (d, dv) = desktop(5, a);
    let mut out = vec![];
    g.follow(5, Some(a));
    g.volunteer(5, Some(dv), now, &mut out);
    for _ in 0..4 {
        now += 2_100;
        g.tick(now, &mut out);
        let (due, piece) = dues(&out, 1).pop().expect("a Join, then the Promote");
        if piece.kind == gk::due::PROMOTE {
            return (g, (k, kv), h, d, now, (due, piece));
        }
        let b = match piece.kind {
            gk::due::JOIN => join(&g, &k, &mut h, &piece, now),
            _ => opening(&g, &k, &mut h, &piece, now),
        };
        out = vec![];
        let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
        land(&mut g, store, t, now, &mut out).await;
        h.took(b);
    }
    panic!("no Promote asked");
}

/// `promote_out` with the Promote landed: both desktops hold keys.
async fn two_desktops(
    store: &Store,
    a: [u8; 16],
) -> (GroupState, (Person, Volunteer), Holds, Person, u64) {
    let (mut g, k, mut h, d, now, (due, piece)) = promote_out(store, a).await;
    let b = opening(&g, &k.0, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, store, t, now, &mut out).await;
    h.took(b);
    assert_eq!(g.holders.set.len(), 2, "both desktops hold keys");
    (g, k, h, d, now)
}

/// The keyholder entries the head names, by member.
fn entries(g: &GroupState) -> Vec<MemberId> {
    let head = g.head.as_ref().unwrap();
    head.kh.header().keyholders.iter().map(|e| e.m).collect()
}

/// K2 review 3: the keyholder set is in the signed head, so a ban, an identity reset or an
/// account deletion took the account's seats but left its entries, and every new keyring's
/// `KRK` welcome went to them. Each is removed by the next commit, asked of another online
/// keyholder (not of the entry itself, though its session is still up).
#[tokio::test]
async fn a_banned_reset_or_deleted_accounts_keyholder_entry_goes_by_the_next_commit() {
    for why in [cause::BAN, cause::RESET, cause::DELETED] {
        let store = Store::memory();
        let a = [5; 16];
        let (mut g, (k, _), mut h, d, mut now) = two_desktops(&store, a).await;
        let mut out = vec![];
        g.account_exit(&a, why, now, &mut out);
        now += 2_100;
        let mut out = vec![];
        g.tick(now, &mut out);
        assert!(dues(&out, d.sid).is_empty(), "cause {why}");
        let (due, piece) = dues(&out, k.sid).pop().expect("a due");
        assert_eq!(
            (piece.kind, piece.remove.map(|r| r.kx)),
            (gk::due::REMOVE, Some(d.wire().kx())),
            "cause {why}"
        );
        let b = opening(&g, &k, &mut h, &piece, now);
        let mut out = vec![];
        let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
        land(&mut g, &store, t, now, &mut out).await;
        assert_eq!(entries(&g), vec![k.m()], "cause {why}");
        assert!(!g.seats.keys().any(|s| s.m == MemberId::Account(a)));
    }
}

/// With no other keyholder online only the removed entry could sign its Remove (R1b): it
/// waits and the other dues go (the exit of its seat, to the one online). Once another
/// keyholder is back, the Remove is asked of it.
#[tokio::test]
async fn a_banned_keyholders_removal_waits_for_another_keyholder_and_other_dues_go_meanwhile() {
    let store = Store::memory();
    let a = [5; 16];
    let (mut g, (k, kv), mut h, d, mut now) = two_desktops(&store, a).await;
    let mut out = vec![];
    g.leave(k.sid, cause::DISCONNECT, now, &mut out);
    g.account_exit(&a, cause::BAN, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let asked: Vec<u8> = dues(&out, d.sid).iter().map(|(_, p)| p.kind).collect();
    assert_eq!(
        asked,
        vec![gk::due::EXITS],
        "its removal waits, its exit goes"
    );
    // Its session ends with the ban, and ann goes offline. Nobody follows, but the removal
    // only memory holds keeps the actor up until kim is back
    let mut out = vec![];
    g.leave(d.sid, cause::DISCONNECT, now, &mut out);
    g.leave(2, cause::DISCONNECT, now, &mut out);
    assert!(!g.idle(), "the removal waits in a running actor");
    g.follow(k.sid, Some([1; 16]));
    g.volunteer(k.sid, Some(kv), now, &mut out);
    now += 2_100;
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("a due");
    assert_eq!(
        (piece.kind, piece.remove.map(|r| r.kx)),
        (gk::due::REMOVE, Some(d.wire().kx()))
    );
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(entries(&g), vec![k.m()]);
    g.leave(k.sid, cause::DISCONNECT, now, &mut out);
    assert!(g.idle(), "and stops once it landed");
}

/// J4 review 1: an identity reset at a sign-in elsewhere ends none of the account's sessions,
/// so its desktop stays up with the old identity. Once its entry is removed it is neither
/// seated again with the old seat keys it volunteered with nor promoted, and asked nothing.
#[tokio::test]
async fn a_reset_accounts_session_from_before_is_not_seated_or_promoted_again() {
    let store = Store::memory();
    let a = [5; 16];
    let (mut g, (k, _), mut h, d, mut now) = two_desktops(&store, a).await;
    let mut out = vec![];
    g.account_exit(&a, cause::RESET, now, &mut out);
    for _ in 0..40 {
        now += 2_100;
        g.tick(now, &mut out);
        assert!(
            dues(&out, d.sid).is_empty(),
            "nothing asked of the old identity"
        );
        let Some((due, piece)) = dues(&out, k.sid).pop() else {
            continue;
        };
        assert_ne!(piece.kind, gk::due::PROMOTE);
        let b = match piece.kind {
            gk::due::JOIN => join(&g, &k, &mut h, &piece, now),
            _ => opening(&g, &k, &mut h, &piece, now),
        };
        out = vec![];
        let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
        land(&mut g, &store, t, now, &mut out).await;
        h.took(b);
    }
    assert_eq!(entries(&g), vec![k.m()]);
    assert!(
        !g.seats.keys().any(|s| s.m == MemberId::Account(a)),
        "not seated again"
    );
}

/// J4 review 2: the account's Promote out at its ban (or reset, deletion) goes, its keyholder
/// told: its commit would land an entry of the account nothing forces.
#[tokio::test]
async fn a_promote_of_the_account_out_at_its_ban_goes_and_lands_nothing() {
    let store = Store::memory();
    let a = [5; 16];
    let (mut g, (k, _), mut h, _, now, (due, piece)) = promote_out(&store, a).await;
    let mut out = vec![];
    g.account_exit(&a, cause::BAN, now, &mut out);
    let told = out.iter().any(|Out(sid, f)| {
        *sid == k.sid
            && f.iter().any(|m| match m {
                ServerMessage::EpochStale { due: x, reason, .. } => {
                    (*x, *reason) == (due, stale::NOT_DUE)
                }
                _ => false,
            })
    });
    assert!(told, "kim is told");
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    assert!(send(&mut g, k.sid, due, &b, now, &mut out).is_none());
    assert_eq!(entries(&g), vec![k.m()]);
}

/// J4 review 2: a Replace the account's own entry asked, out at its reset, goes too: it would
/// swap in an entry nothing forces.
#[tokio::test]
async fn a_replace_of_the_accounts_entry_out_at_its_reset_goes() {
    let store = Store::memory();
    let a = [5; 16];
    let (mut g, _, _, d, mut now) = two_desktops(&store, a).await;
    let ask = ReplaceAsk {
        old: kx_tag(&d.wire().kx()),
        pair: desktop(5, a).0.wire(),
    };
    let mut out = vec![];
    g.replace(d.sid, ask, now, &mut out);
    now += 2_100;
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, d.sid).pop().expect("its Replace");
    assert_eq!(piece.kind, gk::due::REPLACE);
    let mut out = vec![];
    g.account_exit(&a, cause::RESET, now, &mut out);
    assert!(!g.dues.iter().any(|x| x.id == due), "the Replace went");
    assert!(g.replaces.is_empty(), "and is not asked again");
}

/// K2 review 3, the relay's side: an account can hold keys of a group where it has no seat
/// and no actor runs; the row of its entry tells which. A ban, an identity reset (here, and
/// the shell's `reclaim`, which the relay hears of with the bans) and a deletion's tombstone
/// each start that group with the account's exit, which proposes the entries' removal: the
/// rows outlive the reset's and the deletion's forgetting until each Remove lands. J4 review
/// 3 and 4: a `ban` command's process leaves the shell's mark to the relay, and a reset in
/// the relay (the claim after `reclaim`) takes it.
#[tokio::test]
async fn a_ban_reset_or_deletion_reaches_each_group_the_account_holds_keys_of() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let groups = Arc::new(Groups::new(true));
    groups.attach(db.clone(), inc);
    let cfg = crate::config::AccountsConfig {
        mode: crate::config::AccountsMode::Optional,
        ..Default::default()
    };
    let relay = crate::accounts::Relay::open_with(&cfg, db.clone(), &[9u8; 32])
        .await
        .unwrap();
    relay.bind_gk(&groups);
    // The shell's relay knows no groups
    let shell = crate::accounts::Relay::open_with(&cfg, db.clone(), &[9u8; 32])
        .await
        .unwrap();
    let marks = "SELECT COUNT(*) FROM voipc_meta WHERE k LIKE 'gkr:%'";
    let mut reached = vec![];
    for path in 0..5u8 {
        let a = db_account(&db, 60 + UserId::from(path), None)
            .await
            .account
            .unwrap();
        let id = format!("c:kh-{path}");
        let m = MemberId::Account(a).seat_id();
        exec(
            &db,
            format!(
                "INSERT INTO voipc_gk_holders (grp, kx, m, rank, last_online, missed) VALUES ('{id}', {}, {}, 0, 0, {})",
                blob(&db, &[path + 1; 32]),
                blob(&db, &m),
                blob(&db, &[0, 0])
            ),
        )
        .await;
        match path {
            0 => {
                let ban = crate::bans::Ban {
                    id: 0,
                    label: "x".into(),
                    reason: String::new(),
                    by: "test".into(),
                    created_at: 0,
                    expires_at: None,
                    addr: None,
                    alias: None,
                };
                relay
                    .ban_put(&crate::bans::Key::Account(a), &ban)
                    .await
                    .unwrap();
            }
            1 => relay.gk_identity_reset(&a).await,
            2 => {
                shell.gk_identity_reset(&a).await;
                // A `ban` command reads the bans first: its groups (on, no database) reach
                // none, so it leaves the mark
                let banner = crate::accounts::Relay::open_with(&cfg, db.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                banner.bind_gk(&Arc::new(Groups::new(true)));
                banner.gk_shell_resets().await.unwrap();
                relay.gk_shell_resets().await.unwrap();
            }
            3 => {
                exec(
                    &db,
                    format!(
                        "INSERT INTO voipc_tombstones (account, at) VALUES ({}, 1)",
                        blob(&db, &a)
                    ),
                )
                .await;
                crate::accounts::log::sweep(&relay).await.unwrap();
            }
            _ => {
                // The claim after `reclaim` resets in the relay: the shell's mark is this
                // reset's, and read later it would take the new identity's seats and entries
                shell.gk_identity_reset(&a).await;
                relay.gk_identity_reset(&a).await;
                assert_eq!(count(&db, marks).await, 0, "the claim took the mark");
            }
        }
        reached.push(groups.get(&id).is_some());
        groups.on_purge(&id);
    }
    assert_eq!(
        reached,
        vec![true; 5],
        "ban, reset, shell reset, tombstone, claim"
    );
    drop_db(&file);
}

/// Review of 2026-11-18: a due's deadline started at the actor turn's clock read, before
/// the relay's own store writes. A commit that took 5 s to store sent the due asked at its
/// apply already past its deadline: a miss charged to the keyholder, and with only one a
/// 30 s stall. The deadline starts when the due goes out.
#[tokio::test(start_paused = true)]
async fn a_dues_deadline_starts_when_it_goes_out_not_before_the_relays_own_store_writes() {
    let mut net = Net::new();
    let id = net.groups.id_for(9, None);
    let k = net.guest(9, &id);
    let people: Vec<Person> = (0..2).map(|_| net.guest(9, &id)).collect();
    net.volunteer(&k).await;
    for p in &people {
        net.fetch(p, &id).await;
    }
    let out = net.frames(k.sid, 50).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("a Genesis due");
    let b = genesis(&k, &id, &piece, false, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    let first = b.header.clone();
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    let out = net.frames(k.sid, 2_500).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("then a Join due");
    let b = join_on(&k, &id, &first, &mut h, &piece, false, net.groups.now());
    let head = b.header.clone();
    net.commit(k.sid, &id, due, &b).await;
    h.took(b);
    // A third joiner's Join is out when a seated member leaves: the exit batch closes
    // behind it and its opening is asked at the Join's commit
    let q = net.guest(9, &id);
    net.fetch(&q, &id).await;
    let out = net.frames(k.sid, 2_500).await;
    let (due, piece) = dues(&out, k.sid).pop().expect("the third's Join due");
    assert_eq!(piece.joins.len(), 1);
    net.groups.on_unfollow(9, people[0].sid);
    net.frames(k.sid, 500).await;
    net.groups.get(&id).unwrap().slow_commits_for_test(6_000);
    let b = join_on_kh(
        &k,
        &id,
        &head,
        &first,
        &mut h,
        &piece,
        false,
        net.groups.now(),
    );
    net.commit(k.sid, &id, due, &b).await;
    let out = net.frames(k.sid, 7_000).await;
    let (exits, piece) = dues(&out, k.sid).pop().expect("the opening once stored");
    assert_eq!((piece.kind, piece.exits.len()), (gk::due::EXITS, 1));
    assert_eq!(
        stales(&out, k.sid),
        Vec::<u8>::new(),
        "not timed out on its way out"
    );
    // Its own 4 s from when it went out still count
    let out = net.frames(k.sid, 4_000).await;
    assert!(
        out.iter().flat_map(|o| &o.1).any(|f| matches!(
            f,
            ServerMessage::EpochStale { due, reason, .. }
                if *due == exits && *reason == stale::TIMED_OUT
        )),
        "timed out 4 s after it went out"
    );
}
