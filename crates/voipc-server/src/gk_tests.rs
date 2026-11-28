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

use crate::gk::due::{exit_cap, Exits, Joins, Waiting, EXIT_BATCH_MAX};
use crate::gk::group::{cause, Fetch, Fetched, GroupState, OpenCaps, Out};
use crate::gk::holders::{Holders, Volunteer};
use crate::gk::push;
use crate::gk::snapshot::HeadView;
use crate::gk::store::Store;

const ID: &str = "r:00112233445566778899aabbccddeeff:7";

#[path = "gk_rv_g6.rs"]
mod rv_g6;

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
    Group::new(g.kind, ID, g.gen().unwrap()).unwrap()
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
    assert_eq!(v.rank(GroupKind::Text), Some(3));
    v.platform = gk::platform::BROWSER;
    assert_eq!(v.rank(GroupKind::Text), Some(4));
    v.platform = gk::platform::BROWSER_BUSY;
    assert_eq!(v.rank(GroupKind::Text), Some(5));
    v.platform = gk::platform::PHONE;
    assert_eq!(v.rank(GroupKind::Text), None);
    v.m = MemberId::Account([1; 16]);
    v.platform = gk::platform::DESKTOP;
    assert_eq!(v.rank(GroupKind::Text), Some(0));
    v.platform = gk::platform::BROWSER_BUSY;
    assert_eq!(
        v.rank(GroupKind::Text),
        Some(2),
        "below every account volunteer, above every guest"
    );
}

/// Choice 31 (owner, 2026-11-19): a browser hidden or in a call (`BROWSER_BUSY`) holds
/// text keys as the fallback. It starts a group and is asked when it is the only text
/// volunteer; a desktop that comes online is promoted over two busy entries (the
/// hand-over), and it or a shown browser entry is asked before them whatever its misses.
#[test]
fn a_busy_browser_is_asked_only_when_no_better_volunteer_is_online_and_hands_over() {
    let text = GroupKind::Text;
    // Account browsers: their connection pair (0x02), the account's entry
    let browser = |sid: UserId| Person {
        account: Some([sid as u8; 16]),
        ..Person::guest(sid)
    };
    let (b1, b2, shown) = (browser(1), browser(2), browser(3));
    let busy = |p: &Person| p.volunteer(gk::platform::BROWSER_BUSY);
    let mut vols: HashMap<UserId, Volunteer> = [(1, busy(&b1))].into();
    let first = crate::gk::holders::starter(text, &vols, false, &Default::default()).map(|v| v.sid);
    assert_eq!(first, Some(1), "the only volunteer starts the group");
    let mut h = Holders::default();
    h.set_to(vec![b1.entry()], |_| None);
    assert_eq!(h.pick(text, &vols, &[], 1).map(|v| v.sid), Some(1));
    vols.insert(2, busy(&b2));
    assert_eq!(h.promotion(text, &vols, false, 10).map(|v| v.sid), Some(2));
    h.set_to(vec![b1.entry(), b2.entry()], |_| None);
    assert!(h.promotion(text, &vols, false, 10).is_none());

    // A shown browser comes online: no hand-over (a busy one would not resign for it); an
    // entry, it is asked first
    vols.insert(3, shown.volunteer(gk::platform::BROWSER));
    assert!(h.promotion(text, &vols, false, 10).is_none());
    h.set_to(vec![b1.entry(), b2.entry(), shown.entry()], |_| None);
    h.missed(&shown.wire().kx(), 2);
    for t in 3..6 {
        assert_eq!(h.pick(text, &vols, &[], t).map(|v| v.sid), Some(3));
    }
    let next = h.pick(text, &vols, &[3], 6).map(|v| v.sid);
    assert!(
        matches!(next, Some(1 | 2)),
        "passed over, the due goes on to a busy one"
    );

    // A desktop likewise
    vols.remove(&3);
    let (desk, d) = desktop(4, [4; 16]);
    vols.insert(4, d);
    h.set_to(vec![b1.entry(), b2.entry()], |_| None);
    assert_eq!(h.promotion(text, &vols, false, 10).map(|v| v.sid), Some(4));
    h.set_to(vec![b1.entry(), b2.entry(), desk.entry()], |_| None);
    h.missed(&desk.wire().kx(), 7);
    assert_eq!(h.pick(text, &vols, &[], 8).map(|v| v.sid), Some(4));
}

/// Choice 31: tabs that each show while every entry is busy, then go busy themselves, are
/// promoted only while fewer than two entries are online. A busy entry never resigns for a
/// shown browser, so a hand-over among browsers would fill the set with connected tabs, and
/// at eight an account desktop would find no room: it is promoted over the two.
#[test]
fn tabs_shown_and_hidden_in_turn_never_fill_the_set_and_a_desktop_still_gets_in() {
    let text = GroupKind::Text;
    let tabs: Vec<Person> = (1..=9)
        .map(|sid: UserId| Person {
            account: Some([sid as u8; 16]),
            ..Person::guest(sid)
        })
        .collect();
    let mut vols: HashMap<UserId, Volunteer> =
        [(1, tabs[0].volunteer(gk::platform::BROWSER_BUSY))].into();
    let mut h = Holders::default();
    h.set_to(vec![tabs[0].entry()], |_| None);
    for t in &tabs[1..] {
        vols.insert(t.sid, t.volunteer(gk::platform::BROWSER));
        if let Some(sid) = h.promotion(text, &vols, false, 10).map(|v| v.sid) {
            let mut set = h.set.clone();
            set.push(tabs[sid as usize - 1].entry());
            h.set_to(set, |_| None);
        }
        vols.insert(t.sid, t.volunteer(gk::platform::BROWSER_BUSY));
    }
    assert_eq!(
        h.set.len(),
        2,
        "promoted only while fewer than two were online"
    );
    let (_, d) = desktop(20, [20; 16]);
    vols.insert(20, d);
    assert_eq!(h.promotion(text, &vols, false, 10).map(|v| v.sid), Some(20));
}

/// Choice 31: on a relay without accounts a desktop is a guest. Two busy guest tabs hold
/// the keys (the cap of two guests); a guest desktop that comes online first has the lower
/// one removed, then is promoted. A shown guest tab is no hand-over: nothing goes for it.
#[test]
fn a_guest_desktop_takes_over_from_two_busy_guest_tabs_through_the_guests_cap() {
    let text = GroupKind::Text;
    let (t1, t2, desk, shown) = (
        Person::guest(1),
        Person::guest(2),
        Person::guest(3),
        Person::guest(4),
    );
    let mut h = Holders::default();
    h.set_to(vec![t1.entry(), t2.entry()], |_| None);
    let mut vols: HashMap<UserId, Volunteer> = [
        (1, t1.volunteer(gk::platform::BROWSER)),
        (2, t2.volunteer(gk::platform::BROWSER_BUSY)),
        (4, shown.volunteer(gk::platform::BROWSER)),
    ]
    .into();
    assert!(h.promotion(text, &vols, false, 10).is_none());
    assert!(h.swap_out(text, &vols, false, 10).is_none(), "a shown tab");
    vols.insert(1, t1.volunteer(gk::platform::BROWSER_BUSY));
    assert!(h.swap_out(text, &vols, false, 10).is_none(), "no better");
    vols.insert(3, desk.volunteer(gk::platform::DESKTOP));
    assert!(
        h.promotion(text, &vols, false, 10).is_none(),
        "no third guest"
    );
    let out = h
        .swap_out(text, &vols, false, 10)
        .expect("a busy tab goes first");
    let kept = [&t1, &t2]
        .into_iter()
        .find(|t| t.entry().kx != out.kx)
        .expect("one of the two");
    h.set_to(vec![kept.entry()], |_| None);
    assert_eq!(h.promotion(text, &vols, false, 10).map(|v| v.sid), Some(3));
    h.set_to(vec![kept.entry(), desk.entry()], |_| None);
    assert!(h.promotion(text, &vols, false, 10).is_none());
    assert!(h.swap_out(text, &vols, false, 10).is_none(), "settled");
    assert_eq!(h.pick(text, &vols, &[], 1).map(|v| v.sid), Some(3));
}

/// A browser offers again at each change of its page (`BROWSER` ↔ `BROWSER_BUSY`): the
/// group takes it as the same volunteer with its new rank.
#[test]
fn a_browsers_offer_again_changes_its_rank_and_adds_no_volunteer() {
    let mut g = new_group(false);
    let p = Person::guest(1);
    g.follow(1, None);
    let mut out = vec![];
    for (platform, rank) in [
        (gk::platform::BROWSER_BUSY, 5),
        (gk::platform::BROWSER, 4),
        (gk::platform::BROWSER_BUSY, 5),
    ] {
        g.volunteer(1, Some(p.volunteer(platform)), now_ms(), &mut out);
        assert_eq!(g.vols.len(), 1);
        assert_eq!(g.vols[&1].rank(GroupKind::Text), Some(rank));
    }
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
    let old = seat1.public().seat(MemberId::Account(a.0));
    // The eager seat is asked in the store before the actor hears of it (dive 4 F7)
    let ask = crate::accounts::gk::EagerAsk {
        account: a.0,
        seat: seat_record(&old),
    };
    assert_eq!(
        crate::accounts::gk::eager_asks(&db, &id).await.unwrap(),
        vec![ask]
    );
    let (due, piece) = due_within(&mut net, k.sid, 5_000)
        .await
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
    let (due, piece) = due_within(&mut net, k.sid, 10_000)
        .await
        .expect("a Join of the account's seat");
    assert_eq!(piece.joins[0].seat.m, gk::GkMember::Account(a.0));
    let b = join_on(&k, &id, &head, &mut h, &piece, true, net.groups.now());
    let gen = b.header.header().gen;
    net.commit(k.sid, &id, due, &b).await;
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
    // Seated: asked no more
    let mut left = vec![ask];
    for _ in 0..100 {
        left = crate::accounts::gk::eager_asks(&db, &id).await.unwrap();
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(left.is_empty(), "{left:?}");
    // A rotation: the old seat exits, the new one waits to be seated
    let (seat2, e2) = publish(2);
    let pair = Pair {
        keys: seat2.public(),
        endorsement: e2,
    };
    net.groups.on_seat_keys(a.0, pair, raw(&ann)).await;
    let new = seat2.public().seat(MemberId::Account(a.0));
    assert_eq!(
        crate::accounts::gk::eager_asks(&db, &id).await.unwrap(),
        vec![crate::accounts::gk::EagerAsk {
            account: a.0,
            seat: seat_record(&new),
        }],
        "the new seat is asked"
    );
    let reseated = |frames: Vec<ServerMessage>| {
        frames
            .into_iter()
            .filter_map(|f| match f {
                ServerMessage::EpochReseated { n, left } => Some((n, left)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    // Told once the group's store read is back, which takes what it takes (Postgres)
    let mut got = vec![];
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        got.extend(reseated(drain(net.rxs.get_mut(&asid).unwrap()).await));
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(got, vec![(2, 1)], "one group to re-seat");
    net.groups.reseat_done_for_test(&id, &new);
    let got = drain(net.rxs.get_mut(&asid).unwrap()).await;
    assert_eq!(reseated(got), vec![(2, 0)], "done: the old keys may go");
    let row = stats_until(&net, 7, |r| (r.exits_waiting, r.joins_waiting) == (1, 1)).await;
    assert_eq!((row.exits_waiting, row.joins_waiting), (1, 1));
    let (_, piece) = due_within(&mut net, k.sid, 5_000)
        .await
        .expect("the exits go first");
    assert_eq!(
        (piece.kind, piece.exits[0].seat),
        (gk::due::EXITS, old.into())
    );
    // The account is gone: its waiting seat with it
    net.groups.on_log_leave("lounge", a.0, cause::LEAVE).await;
    net.groups.on_account_gone(a.0, cause::DELETED).await;
    let row = stats_until(&net, 7, |r| r.joins_waiting == 0).await;
    assert_eq!(row.joins_waiting, 0);
    net.groups.on_purge("lounge");
    assert!(net.groups.get(&id).is_none());
    drop_db(&file);
}

/// An account with seat keys `seat1` at counter 1, seated in stored group `c:lounge` by a
/// guest keyholder `k`'s Join, and the account's identity: what a rotation starts from.
async fn an_account_seated_in_a_stored_group() -> (
    l4f_accounts::store::Store,
    std::path::PathBuf,
    Net,
    [u8; 16],
    IdentityKeyPair,
    SeatPair,
) {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("lounge"));
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
    let seat1 = SeatPair::generate();
    let e1 = vault_seat(&ann, a.0, 1, &seat1);
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
    net.groups.on_log_join("lounge", a.0, raw(&ann)).await;
    let (due, piece) = due_within(&mut net, k.sid, 5_000)
        .await
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
    let (due, piece) = due_within(&mut net, k.sid, 10_000)
        .await
        .expect("a Join of the account's seat");
    let b = join_on(&k, &id, &head, &mut h, &piece, true, net.groups.now());
    let gen = b.header.header().gen;
    net.commit(k.sid, &id, due, &b).await;
    let seat = seat1.public().seat(MemberId::Account(a.0));
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if !net.groups.row_makers(&id, &gen, &seat).await.is_empty() {
            break;
        }
    }
    (db, file, net, a.0, ann, seat1)
}

/// `pair`'s vault-seat endorsement (0x01) by `ik` for `account`, at counter `n`.
fn vault_seat(ik: &IdentityKeyPair, account: [u8; 16], n: u32, pair: &SeatPair) -> Endorsement {
    Endorsement::sign(
        ik,
        Origin::VaultSeat,
        MemberId::Account(account),
        n,
        now_ms() / 1000,
        &pair.public(),
    )
    .unwrap()
}

/// RV repair (q8-q11): a holder of the account's identity key published its own keys, and
/// every group where the account sat began to re-seat it under them: its seat exits, the
/// thief's waits. The account's app, mid-rotation, went above them with its own keys again
/// under a higher counter. Where those keys still sat, the relay sent nothing (the seat is
/// the same), so the thief's seat waiting there was seated at the next commit. A rotation
/// now drops the seats below its counter still waiting, there too.
#[tokio::test]
async fn the_same_keys_again_above_a_thiefs_drop_the_thiefs_seat_still_waiting() {
    let (_db, file, net, a, ann, seat1) = an_account_seated_in_a_stored_group().await;
    let thief = SeatPair::generate();
    let pair = Pair {
        keys: thief.public(),
        endorsement: vault_seat(&ann, a, 2, &thief),
    };
    net.groups.on_seat_keys(a, pair, raw(&ann)).await;
    let row = stats_until(&net, 7, |r| (r.exits_waiting, r.joins_waiting) == (1, 1)).await;
    assert_eq!(
        (row.exits_waiting, row.joins_waiting),
        (1, 1),
        "the account's seat exits, the thief's waits"
    );
    let pair = Pair {
        keys: seat1.public(),
        endorsement: vault_seat(&ann, a, 3, &seat1),
    };
    net.groups.on_seat_keys(a, pair, raw(&ann)).await;
    let row = stats_until(&net, 7, |r| r.joins_waiting == 0).await;
    assert_eq!(row.joins_waiting, 0, "the thief's seat waits no more");
    drop_db(&file);
}

/// The rotation's drop takes only the account's seats below its counter, waiting or being
/// seated: not another account's, not its own at the counter or above.
#[test]
fn a_rotation_drops_only_the_accounts_seats_below_its_counter() {
    let mut g = new_group(true);
    let mut out = vec![];
    let now = now_ms();
    let a = [2; 16];
    let ik = voipc_crypto::generate_identity_key_pair();
    let joiner = |n: u32, account: [u8; 16]| {
        let pair = SeatPair::generate();
        Joiner {
            seat: pair.public().seat(MemberId::Account(account)),
            ik: raw(&ik),
            keys: pair.public(),
            endorsement: vault_seat(&ik, account, n, &pair),
            returning: false,
        }
    };
    let (low, at, other) = (joiner(4, a), joiner(5, a), joiner(1, [3; 16]));
    for j in [&low, &at, &other] {
        let account = j.seat.m.account().unwrap();
        g.eager(j.clone(), account, now, &mut out);
    }
    assert_eq!(g.joins.len(), 3);
    g.supersede(&a, 5, now, &mut out);
    assert!(!g.joins.has(&low.seat), "below");
    assert!(g.joins.has(&at.seat) && g.joins.has(&other.seat));
}

/// RV repair: a thief's publish and the account's own above it each walk the account's
/// conversations in `on_seat_keys`, at once. Where the account's rotation came first, the
/// thief's eager seat queued after it waited, and was seated at the next commit. A seat
/// below a rotation the group heard of is not queued; an older rotation heard late moves
/// nothing back.
#[test]
fn a_seat_below_a_rotation_heard_is_not_queued_after_it() {
    let mut g = new_group(true);
    let mut out = vec![];
    let now = now_ms();
    let a = [2; 16];
    let ik = voipc_crypto::generate_identity_key_pair();
    let joiner = |n: u32| {
        let pair = SeatPair::generate();
        Joiner {
            seat: pair.public().seat(MemberId::Account(a)),
            ik: raw(&ik),
            keys: pair.public(),
            endorsement: vault_seat(&ik, a, n, &pair),
            returning: false,
        }
    };
    g.supersede(&a, 5, now, &mut out);
    let (late, at) = (joiner(4), joiner(5));
    g.eager(late.clone(), a, now, &mut out);
    g.eager(at.clone(), a, now, &mut out);
    assert!(!g.joins.has(&late.seat), "below the rotation");
    assert!(g.joins.has(&at.seat), "at it");
    g.supersede(&a, 3, now, &mut out);
    let late = joiner(4);
    g.eager(late.clone(), a, now, &mut out);
    assert!(!g.joins.has(&late.seat), "still below");
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
    let lists = g.names.answer(&all, &to).lists;
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
    let a = again.names.answer(&from, &to);
    assert_eq!(a.lists.len(), 1, "the list, from the database");
    let gone = a.gone.expect("a floor before the step: gone");
    assert_eq!((gone.before, gone.epoch, gone.join), ([3; 32], 0, 5));
    let after = gk::NamesRef {
        gen,
        epoch: 0,
        join: 5,
    };
    assert!(again.names.answer(&after, &to).gone.is_none());
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
        removed: vec![],
    };
    let h0 = names_start(&start);
    let join = NamesList {
        time: old,
        epoch: 3,
        join: 1,
        added: vec![],
        removed: vec![],
    };
    let kept = NamesList {
        time: now,
        epoch: 4,
        join: 0,
        added: vec![],
        removed: vec![],
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
    let a = n.answer(&from, &to);
    assert_eq!(a.gone, Some(step));
    assert_eq!(a.lists.len(), 1);
}

/// RV q9-q10:211: a `removed` list steps `names_hash` too, so the sweep counts a header that
/// carries one among the steps. The newest swept here is a removal: the step kept before the
/// oldest list kept is its, and the fold from it reaches the hash the next list carries.
#[test]
fn a_names_sweep_counts_a_removal_among_the_steps() {
    use crate::gk::names::{Kept, Names};
    use voipc_crypto::group_key::{
        names_start, names_step, Added, HeaderV1, NamesList, NamesStep, Removed, SignedHeader,
        NAMES_KEPT,
    };
    let gen = [1; 16];
    let now = 1_000_000_000;
    let old = now - NAMES_KEPT - 10;
    let start = NamesList {
        time: old,
        epoch: 3,
        join: 0,
        added: vec![],
        removed: vec![],
    };
    let h0 = names_start(&start);
    let gone = SeatRef {
        m: MemberId::Account([5; 16]),
        tag_sk: [1; 8],
        tag_sx: [2; 8],
    };
    let mut hd = HeaderV1 {
        group_kind: GroupKind::Text,
        group: "c:lounge-4".into(),
        gen,
        epoch: 4,
        join: 0,
        kind: Kind::Fresh,
        time: old + 1,
        parent: [9; 32],
        epoch_parent: [0; 32],
        kh_parent: [8; 32],
        signer: MemberId::Conn(1),
        keyholders: vec![],
        gated: true,
        seed: 1,
        seed_floor: 1,
        exits_upto: 1,
        seats: 1,
        buckets: 1,
        conn_seats: 0,
        bucket_root: [0; 32],
        keyring_hash: [0; 32],
        names_hash: [0; 32],
        added: Added::List(vec![]),
        removed: Removed::List(vec![gone]),
        confirm: [0; 32],
    };
    hd.names_hash = names_step(&h0, &NamesList::of(&hd));
    let h1 = hd.names_hash;
    assert_ne!(h1, h0, "the removal steps the hash");
    let removal = SignedHeader::sign(hd, &voipc_crypto::generate_identity_key_pair()).unwrap();
    let kept = NamesList {
        time: now,
        epoch: 4,
        join: 1,
        added: vec![],
        removed: vec![],
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
                list: (&kept).into(),
                hash: h1,
            },
        ],
        vec![(gen, removal.clone())],
        None,
    );
    // A writer gets the removal's list among the others, `removed` and all, as it steps
    // the hash
    let at = |epoch, join| gk::NamesRef { gen, epoch, join };
    let a = n.answer(&at(3, 0), &at(4, 1));
    let list = |l: &NamesList| gk::NamesListIn::from(l);
    assert_eq!(
        a.lists,
        vec![
            list(&start),
            list(&NamesList::of(removal.header())),
            list(&kept)
        ]
    );
    assert_eq!(
        names_step(&h0, &NamesList::try_from(&a.lists[1]).unwrap()),
        h1
    );
    n.sweep(&gen, now);
    let step = n.take_swept().expect("a step");
    assert_eq!((step.epoch, step.join, step.before), (4, 0, h0));
    assert_eq!(NamesStep::from(step).hash(), h1, "the removal's step");
    assert_eq!(names_step(&NamesStep::from(step).hash(), &kept), h1);
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
    let (due, piece) = due_within(&mut net, k.sid, 5_000).await.expect("a Genesis");
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

/// An account that keeps `id`'s log, offline, with its identity and seat keys first held by
/// the relay at `published` (unix ms), and its seat pair.
async fn log_member(
    db: &l4f_accounts::store::Store,
    id: &str,
    name: &str,
    published: u64,
) -> ([u8; 16], SeatPair) {
    let a = l4f_accounts::model::AccountId::new();
    db.create_user(
        &l4f_accounts::model::NewUser {
            id: a,
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
    let seat = SeatPair::generate();
    let e = Endorsement::sign(
        &ik,
        Origin::VaultSeat,
        MemberId::Account(a.0),
        1,
        published / 1000,
        &seat.public(),
    )
    .unwrap();
    assert!(crate::accounts::gk::put_seat_keys(
        db,
        &a.0,
        &crate::accounts::gk::SeatKeys {
            n: 1,
            kem: seat.public().kem_bytes().into(),
            dh: seat.public().dh_bytes().into(),
            made: e.made,
            sig: e.sig.to_vec(),
            published,
        },
    )
    .await
    .unwrap());
    let ik = [&[0x05u8][..], &raw(&ik)].concat();
    exec(
        db,
        format!(
            "INSERT INTO voipc_identity (account, identity_key, updated_at) VALUES ({}, {}, 0)",
            blob(db, &a.0),
            blob(db, &ik)
        ),
    )
    .await;
    exec(
        db,
        format!(
            "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{id}', {}, 0)",
            blob(db, &a.0)
        ),
    )
    .await;
    (a.0, seat)
}

/// RV r-attackers: every new start (Genesis, Regenesis) queued every log member with seat
/// keys, so an account whose seat had expired after 90 days offline was seated again with
/// its old keys and 90 more days, at each new start: the expiry was never final, for the
/// account or a thief of its old vault. An account that signs in rotates seat keys older than
/// 30 days, so keys first published more than 120 days ago are an account gone over 90
/// days: a new start leaves it out (it is seated again when it comes back and fetches), and
/// still queues one that signed in lately.
#[tokio::test]
async fn a_new_start_does_not_seat_again_an_account_gone_longer_than_the_seat_expiry() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("c:den"));
    let day = 24 * 60 * 60 * 1000;
    let (gone, gone_seat) = log_member(&db, &id, "ann", now_ms() - 121 * day).await;
    let (here, here_seat) = log_member(&db, &id, "bob", now_ms() - 119 * day).await;
    let gone_seat: gk::GkSeat = gone_seat.public().seat(MemberId::Account(gone)).into();
    let here_seat: gk::GkSeat = here_seat.public().seat(MemberId::Account(here)).into();
    // A guest's fetch starts the group: the volunteer's Genesis
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    let p = net.guest(7, &id);
    net.fetch(&p, &id).await;
    let (due, piece) = due_within(&mut net, k.sid, 5_000).await.expect("a Genesis");
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
    let mut joins: Vec<gk::GkSeat> = piece.joins.iter().map(|j| j.seat).collect();
    // The members are read beside the actor: one may go in the Join after it
    if !joins.contains(&here_seat) {
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
    assert!(joins.contains(&here_seat), "a member seen lately is queued");
    assert!(
        !joins.contains(&gone_seat),
        "a member gone over the seat expiry is not seated again"
    );
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
    assert_eq!(g.joins.len(), 1, "kept_seats");
    assert!(!g.idle(), "the actor stays while an eager seat waits");
}

/// Joiner `i` of one person's keys: as many seats as wanted, without a key pair each.
fn nth_joiner(p: &Person, i: u32) -> Joiner {
    let mut j = p.joiner();
    let mut a = [0xe0; 16];
    a[12..].copy_from_slice(&i.to_be_bytes());
    j.seat.m = MemberId::Account(a);
    j
}

/// The queue knows each seat's place and how many joiners no session waits for, through
/// every way a joiner comes, merges, loses its sessions and goes.
#[test]
fn the_join_queue_counts_its_eager_seats_through_merges_drops_and_takes() {
    let p = Person::account(2, [2; 16]);
    let waiting = |i: u32, sids: Vec<UserId>| Waiting {
        joiner: nth_joiner(&p, i),
        sids,
        account: Some([2; 16]),
    };
    let mut q = Joins::default();
    for i in 0..4 {
        q.add(waiting(i, vec![]), 1);
    }
    q.add(waiting(4, vec![7]), 1);
    assert_eq!((q.len(), q.eager()), (5, 4));
    q.add(waiting(0, vec![8]), 2);
    assert_eq!(
        (q.len(), q.eager()),
        (5, 3),
        "a session waits for seat 0 now"
    );
    q.add(waiting(1, vec![]), 2);
    assert_eq!((q.len(), q.eager()), (5, 3), "queued once");
    q.drop_sid(8);
    assert_eq!(q.eager(), 4, "seat 0 is eager again");
    q.take(&nth_joiner(&p, 2).seat);
    assert!(!q.has(&nth_joiner(&p, 2).seat));
    assert_eq!((q.len(), q.eager()), (4, 3));
    q.retain(|w| !w.sids.is_empty());
    assert_eq!((q.len(), q.eager()), (1, 0));
    assert!(q.has(&nth_joiner(&p, 4).seat) && !q.has(&nth_joiner(&p, 0).seat));
    for i in 10..300 {
        q.add(waiting(i, vec![]), 3);
    }
    let batch: Vec<SeatRef> = q.batch().iter().map(|w| w.joiner.seat).collect();
    assert_eq!(batch.len(), 256);
    assert_eq!(batch[0], nth_joiner(&p, 4).seat, "in arrival order");
    assert_eq!(batch[1], nth_joiner(&p, 10).seat);
    q.done(&batch, 4);
    assert_eq!((q.len(), q.eager()), (35, 35));
    assert_eq!(q.batch()[0].joiner.seat, nth_joiner(&p, 265).seat);
    assert_eq!(q.first_ms, Some(4));
}

/// 100k eager seats (an account's first seat keys, `kept_seats` 0) queue without a walk of
/// the queue per seat: that took about 19 s of one relay worker, and a Join due missed its
/// deadline. A queue walked per seat takes minutes here, even in a release build.
#[test]
fn a_hundred_thousand_eager_seats_queue_without_a_walk_of_the_queue_each() {
    let mut g = new_group(true);
    g.kept_seats = usize::MAX;
    let p = Person::account(2, [2; 16]);
    let joiners: Vec<Joiner> = (0..100_000).map(|i| nth_joiner(&p, i)).collect();
    let mut out = vec![];
    let now = now_ms();
    let t = std::time::Instant::now();
    for j in joiners {
        let a = j.seat.m.account().unwrap();
        g.eager(j, a, now, &mut out);
    }
    let took = t.elapsed();
    assert_eq!((g.joins.len(), g.joins.eager()), (100_000, 100_000));
    assert!(
        took < std::time::Duration::from_secs(20),
        "{took:?} for 100k eager seats"
    );
}

/// A leave takes the session off each joiner it waits for; then every joiner no session
/// waits for goes, the session's or not, but an account's in a stored group, whose eager
/// seat stays. The rest keep their order and the eager count holds.
#[test]
fn a_leave_drops_the_joiners_no_session_waits_for_but_a_stored_groups_account_seats() {
    let p = Person::account(2, [2; 16]);
    let waiting = |i: u32, sids: Vec<UserId>, account: bool| Waiting {
        joiner: nth_joiner(&p, i),
        sids,
        account: account.then_some([2; 16]),
    };
    let queued = |q: &Joins| -> Vec<SeatRef> { q.batch().iter().map(|w| w.joiner.seat).collect() };
    let seats =
        |is: &[u32]| -> Vec<SeatRef> { is.iter().map(|i| nth_joiner(&p, *i).seat).collect() };
    for stored in [true, false] {
        let mut q = Joins::default();
        q.add(waiting(0, vec![], true), 1);
        q.add(waiting(1, vec![7], true), 1);
        q.add(waiting(2, vec![7, 8], false), 1);
        q.add(waiting(3, vec![7], false), 1);
        q.add(waiting(4, vec![], false), 1);
        q.add(waiting(5, vec![9], true), 1);
        q.leave(7, stored);
        let (left, eager) = if stored {
            (seats(&[0, 1, 2, 5]), 2)
        } else {
            (seats(&[2, 5]), 0)
        };
        assert_eq!((queued(&q), q.eager()), (left, eager), "stored {stored}");
        assert!(!q.has(&nth_joiner(&p, 3).seat) && !q.has(&nth_joiner(&p, 4).seat));
        q.leave(8, stored);
        q.leave(9, stored);
        let (left, eager) = if stored {
            (seats(&[0, 1, 5]), 3)
        } else {
            (vec![], 0)
        };
        assert_eq!((queued(&q), q.eager()), (left, eager), "stored {stored}");
        q.add(waiting(3, vec![10], false), 2);
        assert!(
            q.has(&nth_joiner(&p, 3).seat),
            "a seat gone may queue again"
        );
        q.leave(10, stored);
        assert!(!q.has(&nth_joiner(&p, 3).seat));
    }
}

/// A mass disconnect beside a long eager queue: 50k sessions leave a stored group whose
/// queue holds 50k eager seats beside their own joiners, without a walk of the queue per
/// leave. Two walks a leave took minutes here, and a Join due missed its deadline behind
/// them.
#[test]
fn fifty_thousand_leaves_beside_a_long_eager_queue_walk_no_queue_each() {
    let p = Person::account(2, [2; 16]);
    let mut q = Joins::default();
    for i in 0..100_000u32 {
        let sids = if i % 2 == 0 { vec![] } else { vec![i] };
        let joiner = nth_joiner(&p, i);
        let account = joiner.seat.m.account();
        q.add(
            Waiting {
                joiner,
                sids,
                account,
            },
            1,
        );
    }
    assert_eq!((q.len(), q.eager()), (100_000, 50_000));
    let t = std::time::Instant::now();
    for sid in (1..100_000).step_by(2) {
        q.leave(sid, true);
    }
    let took = t.elapsed();
    assert_eq!((q.len(), q.eager()), (100_000, 100_000));
    assert!(
        took < std::time::Duration::from_secs(20),
        "{took:?} for 50k leaves"
    );
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
        parent: [0; 32],
        moved: false,
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
        Some(&3),
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
    let (due, piece) = due_within(&mut net, k.sid, 5_000).await.expect("a Genesis");
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
    let (due, piece) = due_within(&mut net, k.sid, 5_000).await.expect("a Genesis");
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
    let page = crate::gk::store::eager_page(&db, &id, 0, None, 10)
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
    groups.on_log_leave("c:den-off", a, cause::LEAVE).await;
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
    net.groups.on_log_leave(id, [1; 16], cause::LEAVE).await;
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
/// A fixed wait in its place failed on a CI runner's slower Postgres (PR #21, 2026-11-23).
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
        parent: [0; 32],
        moved: false,
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

/// GROUP-KEY §5.6, RV q1-q2:1210: a text roll ends 24 h after its start whatever the relay
/// says. A day on, with no page taken, the keyholder's next opening raises the floor though
/// every seat is behind, the relay takes it, and its pages go on until each seat holds the
/// seed.
#[tokio::test]
async fn a_text_roll_ends_at_its_24_h_and_the_pages_go_on_for_the_seats_behind() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group_back(&store, 25 * 3_600_000).await;
    g.rolls.removal = true;
    now += 61_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a refresh");
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    h.took(b);
    assert!(g.roll_runs(), "the refresh started a roll");
    let started = g.head.as_ref().unwrap().sh.header().time;
    assert_eq!(g.rolls.raised, started);

    now += 86_400_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a refresh");
    assert!(!piece.finish, "every seat is behind");
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let hd = g.head.as_ref().unwrap().sh.header().clone();
    assert_eq!((hd.seed, hd.seed_floor), (2, 2), "the roll ended");
    assert!(!g.roll_runs() && g.paging() && g.left_behind);
    assert!(g.snapshot().unwrap().left_behind);
    let want = g.page_wanted(now).expect("the pages go on");
    for p in &people {
        assert!(want.contains(&p.seat()));
    }
    g.seed_wanted(people[0].seat());
    assert!(
        g.seed_first.contains(&people[0].seat()),
        "first in the next page"
    );
    // A seat that fetches behind is asked at once, not at the next 10 s scan: a member
    // reading waits one page for the new epoch, not the sweep
    g.next_page = now + 10_000;
    assert_eq!(g.page_wanted(now), Some(vec![people[0].seat()]));

    // Each seat holds the seed: the next paced scan ends the sweep
    let all: Vec<(SeatRef, Vec<u8>)> = g.seats.keys().map(|s| (*s, vec![])).collect();
    let mut out = vec![];
    let by = HolderRef {
        m: k.m(),
        kx: k.wire().kx(),
    };
    g.seeded(by, 2, &all, now, &mut out);
    g.seed_first.clear();
    now += 60_000;
    assert_eq!(g.page_wanted(now), None);
    assert!(!g.left_behind && !g.paging());
}

// ── dive 3 P3: seed welcomes owed to eager seats ─────────────────────────

/// A stored text group on a memory store: guest keyholder 1's Genesis, dated `back` ms ago (a
/// seed old enough to roll), then a Join that seats account 2 with no session waiting for it
/// (an eager seat, plan 2d) and account 3 for its session's fetch.
async fn eager_seated(
    store: &Store,
    back: u64,
) -> (GroupState, Person, Holds, Person, Person, u64) {
    let mut g = new_group(true);
    let k = Person::guest(1);
    let mut now = now_ms();
    let mut out = vec![];
    g.follow(1, None);
    g.volunteer(1, Some(k.volunteer(gk::platform::DESKTOP)), now, &mut out);
    g.fetch(1, k.fetch(), now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Genesis due");
    let b = genesis(&k, ID, &piece, true, now - back);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, store, t, now, &mut out).await;
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    let (eager, waiting) = (Person::account(2, [2; 16]), Person::account(3, [3; 16]));
    let mut out = vec![];
    g.eager(eager.joiner(), [2; 16], now, &mut out);
    g.follow(3, Some([3; 16]));
    assert_eq!(g.fetch(3, waiting.fetch(), now, &mut out), Fetched::Not);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    assert_eq!((piece.kind, piece.joins.len()), (gk::due::JOIN, 2));
    let b = join(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, store, t, now, &mut out).await;
    h.took(b);
    (g, k, h, eager, waiting, now)
}

/// The page `out` sends keyholder 1, with its id.
fn page_out(out: &[Out]) -> (u64, DuePiece) {
    let (id, piece) = dues(out, 1).pop().expect("a page");
    assert_eq!(piece.kind, gk::due::SEED_WELCOMES);
    (id, piece)
}

/// dive 3 P3: an account seat a Join seated with no session waiting for it holds its member
/// secret under the head seed only in that seat welcome, which no device takes. It is owed a
/// seed welcome under the head seed, roll or not, and the relay pages it; the seat a session
/// waited for (its device takes its seat welcome and writes its self-row) is not. Once the
/// welcome is stored, nothing is owed.
#[tokio::test]
async fn an_eager_seat_is_paged_a_seed_welcome_under_the_head_seed_with_no_roll() {
    let store = Store::memory();
    let (mut g, k, _, eager, waiting, now) = eager_seated(&store, 0).await;
    assert!(!g.paging(), "no roll runs");
    assert_eq!(g.seed_owed, [eager.seat()].into(), "the eager seat alone");
    assert!(g.seats.contains_key(&waiting.seat()));
    assert_eq!(g.page_wanted(now), Some(vec![eager.seat()]));
    let mut out = vec![];
    g.ask_page(
        vec![(eager.seat(), raw(&eager.ik), eager.wire())],
        vec![],
        now,
        &mut out,
    );
    let (id, piece) = page_out(&out);
    assert_eq!(piece.seed_seats.len(), 1);
    assert_eq!(
        g.page.as_ref().map(|p| p.seed),
        Some(1),
        "under the head seed"
    );
    let gen = g.gen().unwrap();
    let w = gk::SeedWelcomeOut {
        seat: eager.seat().into(),
        bytes: vec![7; gk::SEED_WELCOME_BYTES],
    };
    let mut out = vec![];
    let (by, took) = g.take_welcomes(1, id, gen, 1, vec![w], &mut out).unwrap();
    store.seeds(ID, &gen, 1, &by, &took, now).await.unwrap();
    g.seeded(by, 1, &took, now, &mut out);
    assert!(g.seed_owed.is_empty() && g.page.is_none(), "owed no more");
    assert_eq!(g.page_wanted(now + 60_000), None, "nothing left to page");
    assert!(
        store
            .seed_welcome(ID, &gen, &eager.seat(), 1)
            .await
            .is_some(),
        "kept for the seat's next connection"
    );
    let _ = k;
}

/// dive 3 P3: a keyholder works one due of a group at a time, and a page is one (holder.rs
/// `on_due` drops what it had in hand). A due to the page's keyholder lets the page go, with
/// no miss (it waited out its 60 s and counted toward a healthy keyholder's removal), and no
/// page is asked of a keyholder while it has a due out (that dropped the due); the page is
/// asked again once the due landed.
#[tokio::test]
async fn a_due_to_the_pages_keyholder_lets_the_page_go_with_no_miss_and_waits_for_it() {
    let store = Store::memory();
    let (mut g, k, mut h, eager, _, mut now) = eager_seated(&store, 0).await;
    g.page_wanted(now).expect("a page");
    let mut out = vec![];
    g.ask_page(
        vec![(eager.seat(), raw(&eager.ik), eager.wire())],
        vec![],
        now,
        &mut out,
    );
    assert!(g.page.is_some());
    // A guest fetches: its Join goes to the only keyholder, the page's
    let p = Person::guest(5);
    g.follow(5, None);
    let mut out = vec![];
    g.fetch(5, p.fetch(), now, &mut out);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    assert_eq!(piece.kind, gk::due::JOIN);
    assert!(g.page.is_none(), "the page is let go");
    assert_eq!(g.next_page, now, "and asked again as soon as it may");
    assert!(stales(&out, 1).is_empty(), "no stale: it was no miss");
    assert_eq!(
        g.page_wanted(now),
        None,
        "no page while its keyholder has a due out"
    );
    let b = join(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(
        g.page_wanted(now),
        Some(vec![eager.seat()]),
        "asked again once the Join landed"
    );
    assert!(
        g.holders
            .stats
            .get(&k.wire().kx())
            .is_none_or(|s| s.missed.is_empty()),
        "no miss"
    );
}

/// Fix review P3-R3: a page keeps the head it was asked at, and a keyholder that fetches the
/// keyring builds it there only (holder.rs `advance`; the relay hands the ring at its head).
/// Another keyholder's commit landing first left it unbuildable: it waited out its 60 s and
/// counted a miss toward a healthy keyholder's removal. Now a head move under the page's seed
/// waits 5 s more for an answer on its way, then lets the page go with no miss and asks it
/// again at the head. The control: a page under an unmoved head still misses at 60 s.
#[tokio::test]
async fn a_page_the_head_moved_under_goes_soon_with_no_miss_and_is_asked_again() {
    let ask = |g: &mut GroupState, eager: &Person, now: u64| {
        g.page_wanted(now).expect("a page");
        let mut out = vec![];
        g.ask_page(
            vec![(eager.seat(), raw(&eager.ik), eager.wire())],
            vec![],
            now,
            &mut out,
        );
        // Out to a second keyholder (sid 9): a due to keyholder 1 does not drop it
        let p = g.page.as_mut().expect("asked");
        assert_eq!(
            p.parent,
            g.head.as_ref().unwrap().sh.d(),
            "asked at the head"
        );
        p.sid = 9;
        p.by = HolderRef {
            m: MemberId::Conn(9),
            kx: [9; 32],
        };
    };
    let misses = |g: &GroupState| g.holders.stats.get(&[9; 32]).map_or(0, |s| s.missed.len());
    // The control: nothing moves, the page misses at its 60 s
    let store = Store::memory();
    let (mut g, _, _, eager, _, now) = eager_seated(&store, 0).await;
    ask(&mut g, &eager, now);
    let mut out = vec![];
    g.tick(now + 59_000, &mut out);
    assert!(g.page.is_some(), "the control: still out at 59 s");
    g.tick(now + 60_000, &mut out);
    assert!(g.page.is_none());
    assert_eq!(misses(&g), 1, "the control: a miss at 60 s");
    // Keyholder 1 commits a guest's Join while the page is out: the head moves
    let store = Store::memory();
    let (mut g, k, mut h, eager, _, mut now) = eager_seated(&store, 0).await;
    ask(&mut g, &eager, now);
    let p = Person::guest(5);
    g.follow(5, None);
    let mut out = vec![];
    g.fetch(5, p.fetch(), now, &mut out);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    assert_eq!(piece.kind, gk::due::JOIN);
    assert!(
        g.page.is_some(),
        "a due to another keyholder leaves the page"
    );
    let b = join(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let p = g.page.as_ref().expect("still waited for");
    assert!(p.moved, "the head moved under it");
    assert_eq!(p.deadline, now + 5_000, "for 5 s more");
    let mut out = vec![];
    g.tick(now + 5_000, &mut out);
    assert!(g.page.is_none(), "let go");
    assert_eq!(
        stales(&out, 9),
        vec![stale::TIMED_OUT],
        "its keyholder told"
    );
    assert_eq!(misses(&g), 0, "no miss for it");
    assert_eq!(g.next_page, now + 5_000, "asked again as soon as it may");
    assert_eq!(
        g.page_wanted(now + 5_000),
        Some(vec![eager.seat()]),
        "asked again, at the head"
    );
}

/// dive 3 P3: once a roll starts, a seed welcome under the old seed can no longer be made
/// (keyholders page under the head's): the owed seats are behind, and the roll's pages take
/// them, under the new seed.
#[tokio::test]
async fn a_roll_start_leaves_the_owed_seats_to_the_rolls_pages() {
    let store = Store::memory();
    let (mut g, k, mut h, eager, _, mut now) = eager_seated(&store, 25 * 3_600_000).await;
    assert_eq!(g.seed_owed, [eager.seat()].into());
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
    assert!(g.seed_owed.is_empty(), "nothing owed under the old seed");
    let want = g.page_wanted(now).expect("the roll's page");
    assert!(want.contains(&eager.seat()), "the roll's page has the seat");
}

/// dive 3 P3: an owed seat whose keys the relay cannot find (rotated since, or no identity
/// key) gets no seed welcome, but it holds the head seed and so holds no roll open: it is let
/// go, not exited, as a seat behind a roll is.
#[tokio::test]
async fn an_owed_seat_with_no_keys_found_is_let_go_not_exited() {
    let store = Store::memory();
    let (mut g, _, _, eager, _, now) = eager_seated(&store, 0).await;
    let mut out = vec![];
    g.ask_page(vec![], vec![(eager.seat(), cause::ROTATION)], now, &mut out);
    assert!(g.seed_owed.is_empty(), "let go");
    assert!(!g.exits.has(&eager.seat()), "not exited");
    assert!(g.page.is_none());
}

/// The seats a stored group's load owes a seed welcome (dive 3 P3).
async fn owed_after_load(store: &Store, id: &str) -> std::collections::HashSet<SeatRef> {
    let mut g = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut g).await.unwrap();
    g.seed_owed
}

/// dive 3 P3: the seats owed a seed welcome outlive a restart or an idle stop before their
/// page lands. A stored group's load owes one to each account seat under the head seed whose
/// member secret is in no seed welcome and no self-row of its account, and to none once
/// either is stored.
#[tokio::test]
async fn a_loaded_stored_group_owes_a_seed_welcome_to_each_account_seat_whose_secret_is_nowhere() {
    let id = "c:lounge-p3";
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
    let head = b.header.clone();
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    let (x, y) = (Person::account(2, [2; 16]), Person::account(3, [3; 16]));
    let mut out = vec![];
    g.eager(x.joiner(), [2; 16], now, &mut out);
    g.eager(y.joiner(), [3; 16], now, &mut out);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    let b = join_on(&k, id, &head, &mut h, &piece, true, now);
    let mut out = vec![];
    let t = send_to(&mut g, id, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let both: std::collections::HashSet<SeatRef> = [x.seat(), y.seat()].into();
    assert_eq!(g.seed_owed, both, "owed as seated");
    assert_eq!(owed_after_load(&store, id).await, both, "and after a load");
    // x's seed welcome under seed 1, y's self-row for it: owed no more
    let gen = g.gen().unwrap();
    let by = HolderRef {
        m: k.m(),
        kx: k.wire().kx(),
    };
    let w = vec![(x.seat(), vec![7; gk::SEED_WELCOME_BYTES])];
    store.seeds(id, &gen, 1, &by, &w, now).await.unwrap();
    let row = gk::SelfRowIn {
        group: id.into(),
        gen,
        seed: 1,
        sk: y.seat().tag_sk,
        sx: y.seat().tag_sx,
        kind: gk::self_row::SELF_ROW,
        sealed: vec![7; gk::SELF_ROW_BYTES],
    };
    let kept = crate::accounts::gk::put_self_rows(&db, &[3; 16], &[row])
        .await
        .unwrap();
    assert_eq!(kept, 1);
    assert!(owed_after_load(&store, id).await.is_empty());
    drop_db(&file);
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

// ── Voice rooms (V2, plan part 5) ─────────────────────────────────────────

use crate::gk::voice::seats_frames;
use voipc_protocol::gk::VoiceSeatsPiece;

fn voice_group() -> GroupState {
    GroupState::new(
        ID.into(),
        GroupKind::Voice,
        false,
        Arc::new(OpenCaps::default()),
    )
}

impl Person {
    /// A signed-in member in a voice room: its connection's pair (0x02), endorsed by the
    /// account's identity naming the connection.
    fn voice_account(sid: UserId, a: [u8; 16]) -> Person {
        Person {
            account: Some(a),
            ..Person::guest(sid)
        }
    }

    fn voice_entry(&self) -> Keyholder {
        self.wire()
            .entry(GroupKind::Voice, self.m(), raw(&self.ik))
            .unwrap()
    }
}

/// The `VoiceSeats` `out` sends `sid`, each sequence merged as a member takes it.
fn rosters(out: &[Out], sid: UserId) -> Vec<VoiceSeatsPiece> {
    let mut parts: Parts<(), VoiceSeatsPiece> = Parts::new(Seq::VoiceSeats);
    let mut whole = vec![];
    for f in out.iter().filter(|o| o.0 == sid).flat_map(|o| &o.1) {
        if let ServerMessage::VoiceSeats {
            part, last, piece, ..
        } = f
        {
            let bytes = push::len(f);
            if let Part::Whole((), ps) = parts.take((), *part, *last, piece.clone(), bytes).part {
                let mut p = VoiceSeatsPiece {
                    whole: ps[0].whole,
                    ..VoiceSeatsPiece::default()
                };
                for q in ps {
                    p.seats.extend(q.seats);
                    p.gone.extend(q.gone);
                }
                whole.push(p);
            }
        }
    }
    whole
}

/// The keyholder among `ks` a due in `out` went to, with the due.
fn asked<'a>(out: &[Out], ks: &[&'a Person]) -> Option<(&'a Person, u64, DuePiece)> {
    ks.iter()
        .find_map(|k| dues(out, k.sid).pop().map(|(d, p)| (*k, d, p)))
}

/// The voice Genesis `piece` asks of `k`, with its connection pair.
fn voice_genesis(k: &Person, piece: &DuePiece, now: u64) -> Built {
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let st = Start {
        kind: GroupKind::Voice,
        id: ID,
        me: k.me(),
        ik: &k.ik,
        entry: k.voice_entry(),
        joiners: &[&joiner],
        gated: piece.gated,
        stored: false,
        now: now / 1000,
    };
    build_genesis(&st, &mut RowBases::new()).unwrap()
}

/// `k` builds the Join or opening `piece` asks; the commit lands. What the keyholders hold
/// moves with it (one keyring for the set).
async fn voice_commit(
    g: &mut GroupState,
    store: &Store,
    k: &Person,
    h: &mut Holds,
    (due, piece): (u64, DuePiece),
    now: u64,
) -> Vec<Out> {
    let b = match piece.kind {
        gk::due::JOIN => join(g, k, h, &piece, now),
        _ => opening(g, k, h, &piece, now),
    };
    let mut out = vec![];
    let t = send(g, k.sid, due, &b, now, &mut out).expect("taken");
    land(g, store, t, now, &mut out).await;
    h.took(b);
    out
}

/// A voice room of guests `sids` (lowest first), each following and fetching in turn: the
/// first starts it, one Join seats the rest, and the next lowest is promoted.
async fn voice_room(store: &Store, sids: &[UserId]) -> (GroupState, Vec<Person>, Holds, u64) {
    let people: Vec<Person> = sids.iter().map(|s| Person::guest(*s)).collect();
    voice_room_of(store, people, false).await
}

/// `voice_room` of `people` (lowest first), the room `anonymous` or not.
async fn voice_room_of(
    store: &Store,
    people: Vec<Person>,
    anonymous: bool,
) -> (GroupState, Vec<Person>, Holds, u64) {
    let mut g = voice_group();
    g.anonymous = anonymous;
    let sids: Vec<UserId> = people.iter().map(|p| p.sid).collect();
    let mut now = now_ms();
    let mut out = vec![];
    for p in &people {
        g.follow(p.sid, p.account);
        assert_eq!(g.fetch(p.sid, p.fetch(), now, &mut out), Fetched::Not);
    }
    let k = &people[0];
    let (due, piece) = dues(&out, k.sid).pop().expect("a Genesis due");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let b = voice_genesis(k, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, store, t, now, &mut out).await;
    let mut h = Holds {
        ring: b.ring,
        krk: b.krk,
        cache: RowBases::new(),
    };
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let join = dues(&out, k.sid).pop().expect("a Join due");
    assert_eq!(join.1.kind, gk::due::JOIN);
    let out = voice_commit(&mut g, store, k, &mut h, join, now).await;
    let promote = dues(&out, k.sid).pop().expect("then a promotion");
    assert_eq!(promote.1.kind, gk::due::PROMOTE);
    let named = promote.1.promote.as_ref().map(|c| c.m);
    assert_eq!(named, Some(people[1].m().into()), "the next lowest");
    voice_commit(&mut g, store, k, &mut h, promote, now).await;
    let us: Vec<Option<u32>> = g.holders.set.iter().map(|e| e.u).collect();
    assert_eq!(us, vec![Some(sids[0]), Some(sids[1])]);
    (g, people, h, now)
}

/// A voice seat is the member's connection pair, named by its account, or by the connection
/// for a guest and in an anonymous room that is not gated (open choice 11). The fetcher is
/// told the whole roster, its own seat in it; each member who has the roster, the new seat.
#[test]
fn a_voice_seat_is_named_by_the_account_but_by_the_connection_in_an_open_anonymous_room() {
    for (anonymous, gate, by_account) in [
        (false, false, true),
        (true, false, false),
        (true, true, true),
    ] {
        let mut g = voice_group();
        (g.anonymous, g.gate) = (anonymous, gate);
        let people = [
            Person::voice_account(2, [2; 16]),
            Person::voice_account(5, [5; 16]),
        ];
        let seat = |p: &Person| {
            let m = match by_account {
                true => p.m(),
                false => MemberId::Conn(p.sid),
            };
            p.pair.public().seat(m)
        };
        let now = now_ms();
        let mut out = vec![];
        for p in &people {
            g.follow(p.sid, p.account);
            out.clear();
            g.fetch(p.sid, p.fetch(), now, &mut out);
            assert_eq!(g.members[&p.sid].seat, Some(seat(p)));
        }
        let all: Vec<(UserId, gk::GkSeat)> =
            people.iter().map(|p| (p.sid, seat(p).into())).collect();
        let whole = rosters(&out, 5);
        assert_eq!(whole.len(), 1);
        assert!(whole[0].whole);
        assert_eq!(whole[0].seats, all, "every seat, its own among them");
        let one = VoiceSeatsPiece {
            seats: vec![all[1]],
            ..VoiceSeatsPiece::default()
        };
        assert_eq!(
            rosters(&out, 2),
            vec![one],
            "the new seat to who has the roster"
        );
    }
}

/// Any member holds a voice room's keys, whatever its platform or its "Help hold keys": the
/// relay takes no `KeyholdVolunteer` there, and starts the room with the lowest user id that
/// has its seat at hand, a phone's too. Text still ranks desktops first.
#[test]
fn a_voice_room_starts_with_its_lowest_user_id_on_any_platform_and_takes_no_volunteer() {
    let people: Vec<Person> = [6, 3, 4].into_iter().map(Person::guest).collect();
    let platforms = [
        gk::platform::DESKTOP,
        gk::platform::PHONE,
        gk::platform::BROWSER,
    ];
    let vols: HashMap<UserId, Volunteer> = people
        .iter()
        .zip(platforms)
        .map(|(p, platform)| (p.sid, p.volunteer(platform)))
        .collect();
    let first =
        |kind| crate::gk::holders::starter(kind, &vols, false, &Default::default()).map(|v| v.sid);
    assert_eq!(first(GroupKind::Voice), Some(3));
    assert_eq!(first(GroupKind::Text), Some(6));
    let mut g = voice_group();
    g.follow(3, None);
    let mut out = vec![];
    g.volunteer(
        3,
        Some(people[1].volunteer(gk::platform::PHONE)),
        now_ms(),
        &mut out,
    );
    assert!(
        g.vols.is_empty() && out.is_empty(),
        "its fetch offers its seat's pair"
    );
}

/// With fewer than two keyholders online the lowest seated member that holds none is
/// promoted (`voice_room` checks it); a later joiner with a lower user id displaces nobody.
#[tokio::test]
async fn a_later_voice_joiner_with_a_lower_user_id_displaces_no_keyholder() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) = voice_room(&store, &[2, 3, 4]).await;
    let late = Person::guest(1);
    g.follow(1, None);
    let mut out = vec![];
    g.fetch(1, late.fetch(), now, &mut out);
    now += 300;
    let mut out = vec![];
    g.tick(now, &mut out);
    let ks = [&people[0], &people[1]];
    let (k, due, piece) = asked(&out, &ks).expect("its Join");
    assert_eq!(piece.kind, gk::due::JOIN);
    let out = voice_commit(&mut g, &store, k, &mut h, (due, piece), now).await;
    now += 5_000;
    let mut more = vec![];
    g.tick(now, &mut more);
    assert!(asked(&out, &ks).is_none() && asked(&more, &ks).is_none());
    let us: Vec<Option<u32>> = g.holders.set.iter().map(|e| e.u).collect();
    assert_eq!(us, vec![Some(2), Some(3)]);
}

/// A voice keyholder that leaves is removed at once (§5.9): its leave closes the exit batch
/// with no 2 s wait, the other keyholder is asked a Remove carrying its seat's exit, and
/// that commit rolls the seed.
#[tokio::test]
async fn a_voice_keyholders_leave_is_a_remove_asked_at_once_that_rolls_the_seed() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) = voice_room(&store, &[2, 3, 4]).await;
    let seed = g.head.as_ref().unwrap().sh.header().seed;
    now += 2_000;
    let mut out = vec![];
    g.leave(3, cause::LEAVE, now, &mut out);
    let (due, piece) = dues(&out, 2).pop().expect("a due at once");
    assert_eq!(piece.kind, gk::due::REMOVE);
    assert_eq!(piece.remove.map(|r| r.m), Some(gk::GkMember::Conn(3)));
    let exits: Vec<SeatRef> = piece.exits.iter().map(|x| Exit::from(*x).seat).collect();
    assert_eq!(exits, vec![people[1].seat()], "its seat's exit rides along");
    voice_commit(&mut g, &store, &people[0], &mut h, (due, piece), now).await;
    let head = g.head.as_ref().unwrap().sh.header().clone();
    assert_eq!((head.kind, head.seed), (Kind::KeyholdersRemove, seed + 1));
    assert_eq!(g.holders.set.len(), 1);
    assert!(!g.seats.contains_key(&people[1].seat()));
}

/// Every voice seat exits when its session ends, an account's too: going offline keeps an
/// account's text seat, never its voice seat (part 15).
#[tokio::test]
async fn every_voice_seat_exits_at_disconnect_an_accounts_too() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) = voice_room(&store, &[2, 3]).await;
    let a = Person::voice_account(5, [5; 16]);
    g.follow(5, a.account);
    let mut out = vec![];
    g.fetch(5, a.fetch(), now, &mut out);
    now += 300;
    let mut out = vec![];
    g.tick(now, &mut out);
    let ks = [&people[0], &people[1]];
    let (k, due, piece) = asked(&out, &ks).expect("its Join");
    voice_commit(&mut g, &store, k, &mut h, (due, piece), now).await;
    assert!(g.seats.contains_key(&a.seat()));
    let mut out = vec![];
    g.leave(5, cause::DISCONNECT, now, &mut out);
    assert_eq!(g.exits.waiting(), 1);
    assert_eq!(
        rosters(&out, 2),
        vec![VoiceSeatsPiece {
            gone: vec![5],
            ..VoiceSeatsPiece::default()
        }],
        "the members hear it left"
    );
}

/// Both keyholders gone: the lowest user id left is asked a Genesis at once, and the relay
/// queues every other member whose pair it holds for the new generation, so nobody has to
/// fetch (part 5).
#[tokio::test]
async fn with_both_voice_keyholders_gone_the_lowest_left_starts_anew_and_every_member_is_queued() {
    let store = Store::memory();
    let (mut g, people, _, mut now) = voice_room(&store, &[2, 3, 4, 5]).await;
    let gen = g.gen();
    now += 2_000;
    let mut out = vec![];
    g.leave(2, cause::LEAVE, now, &mut out);
    let mut out = vec![];
    g.leave(3, cause::DISCONNECT, now, &mut out);
    let (due, piece) = dues(&out, 4).pop().expect("a Genesis of the lowest left");
    assert_eq!(piece.kind, gk::due::GENESIS);
    assert!(dues(&out, 5).is_empty());
    let b = voice_genesis(&people[2], &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 4, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert_ne!(g.gen(), gen, "a new generation");
    assert!(g.joins.has(&people[3].seat()), "queued with no fetch");
    now += 300;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (_, piece) = dues(&out, 4).pop().expect("its Join");
    let joined: Vec<SeatRef> = piece
        .joins
        .iter()
        .map(|j| Joiner::try_from(j).unwrap().seat)
        .collect();
    assert_eq!(joined, vec![people[3].seat()]);
}

/// An opening in a voice room reaches every seated member, writer or not, and each
/// keyholder as a member too: each push carries its seal, so nobody fetches to move.
#[tokio::test]
async fn a_voice_opening_reaches_every_member_and_keyholder_with_its_seal() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) = voice_room(&store, &[2, 3, 4, 5]).await;
    now += 2_000;
    let mut out = vec![];
    g.leave(5, cause::LEAVE, now, &mut out);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let ks = [&people[0], &people[1]];
    let (k, due, piece) = asked(&out, &ks).expect("the exit's opening");
    assert_eq!(piece.kind, gk::due::EXITS);
    let out = voice_commit(&mut g, &store, k, &mut h, (due, piece), now).await;
    for sid in [2, 3, 4] {
        let p = ins(&out, sid).pop().expect("a push");
        assert!(p.pushed && p.head.is_some() && p.seal.is_some(), "{sid}");
    }
    assert!(ins(&out, 5).is_empty());
}

/// `VoiceSeats` goes in parts of at most `VOICE_SEATS_PER_FRAME` entries, each a frame the
/// codec takes, `whole` on the first and `last` on the last: a routed room of 300 is told in
/// one frame, and a roster of any size comes back whole.
#[test]
fn voice_seats_go_in_frames_the_codec_takes_whatever_the_rooms_size() {
    let seat = |u: UserId| {
        let s = SeatRef {
            m: MemberId::Account([u as u8; 16]),
            tag_sk: [1; 8],
            tag_sx: [2; 8],
        };
        (u, gk::GkSeat::from(s))
    };
    for (n, gone, frames) in [(300, 0, 1), (2_500, 10, 4)] {
        let piece = VoiceSeatsPiece {
            seats: (1..=n).map(seat).collect(),
            gone: (n + 1..=n + gone).collect(),
            whole: true,
        };
        let out = vec![Out(9, seats_frames(ID, piece.clone()))];
        assert_eq!(out[0].1.len(), frames, "{n} seats");
        for (i, f) in out[0].1.iter().enumerate() {
            let ServerMessage::VoiceSeats {
                channel_id,
                part,
                last,
                piece,
                ..
            } = f
            else {
                panic!("VoiceSeats only");
            };
            assert_eq!((*channel_id, *part as usize), (7, i));
            assert_eq!((piece.whole, *last), (i == 0, i + 1 == frames));
            let bytes = voipc_protocol::codec::encode_server_msg(f).unwrap().len();
            assert!(bytes <= voipc_protocol::codec::MAX_MSG_SIZE as usize);
        }
        assert_eq!(rosters(&out, 9), vec![piece]);
    }
}

/// A voice room's group starts at its first join, under the room's `r:` id, and goes with
/// its keyring when the room empties; the lobby has none.
#[tokio::test]
async fn a_voice_rooms_group_goes_when_the_room_empties_and_the_lobby_has_none() {
    let groups = Groups::new(true);
    groups.on_room_join(0, 1, None, false);
    assert!(groups.stats().is_empty(), "no voice in the lobby");
    groups.on_room_join(7, 1, None, false);
    groups.on_room_join(7, 2, Some([2; 16]), false);
    let rooms = groups.stats();
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].kind, gk::group_kind::VOICE);
    assert!(groups.room_id(7).starts_with("r:"));
    groups.on_room_leave(7, 1, cause::LEAVE, false);
    assert_eq!(groups.stats().len(), 1);
    groups.on_room_leave(7, 2, cause::KICK, true);
    assert!(groups.stats().is_empty());
}

/// After a gate on: the three dues that follow (the Join of the renamed seats once its batch
/// closes, the exits' opening, the gated opening one epoch gap later), each landed; their
/// kinds.
async fn gate_dues(
    g: &mut GroupState,
    store: &Store,
    ks: &[&Person],
    h: &mut Holds,
    now: &mut u64,
) -> Vec<u8> {
    let mut kinds = vec![];
    let mut next = None;
    use voipc_crypto::group_key::timers::EPOCH_MIN_GAP_MS;
    for wait in [300, 2_000, EPOCH_MIN_GAP_MS] {
        *now += wait;
        let mut out = vec![];
        g.tick(*now, &mut out);
        let (k, due, piece) = next.take().or_else(|| asked(&out, ks)).expect("a due");
        kinds.push(piece.kind);
        let out = voice_commit(g, store, k, h, (due, piece), *now).await;
        next = asked(&out, ks);
    }
    kinds
}

/// The seat of `p`'s pair named by its connection.
fn conn_seat(p: &Person) -> SeatRef {
    p.pair.public().seat(MemberId::Conn(p.sid))
}

/// Signed-in members `sids`, each its own account.
fn voice_accounts(sids: &[UserId]) -> Vec<Person> {
    sids.iter()
        .map(|s| Person::voice_account(*s, [*s as u8; 16]))
        .collect()
}

/// A ban (or reset) exits every seat of the account, its voice seat named by its connection
/// in an anonymous room that is not gated among them: its sessions' seats, not only seats
/// named by the account, so the eject's leave after it finds a seat already gone.
#[tokio::test]
async fn a_banned_accounts_voice_seat_exits_though_its_connection_names_it() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) = voice_room(&store, &[2, 3]).await;
    g.anonymous = true;
    let a = Person::voice_account(5, [5; 16]);
    g.follow(5, a.account);
    let mut out = vec![];
    g.fetch(5, a.fetch(), now, &mut out);
    now += 300;
    let mut out = vec![];
    g.tick(now, &mut out);
    let ks = [&people[0], &people[1]];
    let (k, due, piece) = asked(&out, &ks).expect("its Join");
    voice_commit(&mut g, &store, k, &mut h, (due, piece), now).await;
    assert!(
        g.seats.contains_key(&conn_seat(&a)),
        "seated by its connection"
    );
    let mut out = vec![];
    g.account_exit(&[5; 16], cause::BAN, now, &mut out);
    assert!(g.exits.has(&conn_seat(&a)), "the ban exits it");
    g.leave(5, cause::DISCONNECT, now, &mut out);
    assert_eq!(g.exits.waiting(), 1);
}

/// A voice room turned anonymous names its signed-in members' seats by their connections at
/// once: each account seat exits and its pair is queued under the connection, every member
/// hears the new seats, and a newcomer's roster names no account (open choice 11).
#[tokio::test]
async fn an_anonymous_flip_names_every_voice_seat_by_its_connection_before_a_newcomer_looks() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) =
        voice_room_of(&store, voice_accounts(&[2, 3, 4]), false).await;
    let mut out = vec![];
    g.room_anonymous(true, now, &mut out);
    for p in &people {
        assert!(g.exits.has(&p.seat()), "{}'s account seat exits", p.sid);
        assert!(
            g.joins.has(&conn_seat(p)),
            "{}'s connection seat waits",
            p.sid
        );
        let told: Vec<(UserId, gk::GkSeat)> = rosters(&out, p.sid)
            .into_iter()
            .flat_map(|r| r.seats)
            .collect();
        let want: Vec<(UserId, gk::GkSeat)> = people
            .iter()
            .map(|q| (q.sid, conn_seat(q).into()))
            .collect();
        assert_eq!(told, want, "{} hears every new seat", p.sid);
    }
    let late = Person::voice_account(9, [9; 16]);
    g.follow(9, late.account);
    let mut out = vec![];
    g.fetch(9, late.fetch(), now, &mut out);
    let whole = rosters(&out, 9);
    assert!(whole[0].whole);
    assert!(
        whole[0]
            .seats
            .iter()
            .all(|(u, s)| s.m == gk::GkMember::Conn(*u)),
        "no account behind a pseudonym"
    );
    now += 300;
    let mut out = vec![];
    g.tick(now, &mut out);
    let ks = [&people[0], &people[1]];
    let (k, due, piece) = asked(&out, &ks).expect("the Join of the new seats");
    assert_eq!(piece.kind, gk::due::JOIN);
    voice_commit(&mut g, &store, k, &mut h, (due, piece), now).await;
    for p in &people {
        assert!(g.seats.contains_key(&conn_seat(p)));
    }
}

/// A gate on an anonymous voice room keeps every signed-in member in it: each connection
/// seat is swapped for its account's in the open group, so the members still take each
/// opening, and the gated opening finds no connection seat. Once the gate is off, the seats
/// stay the accounts' while the head is gated and go back to the connections at the opening
/// that opens it.
#[tokio::test]
async fn a_gate_on_an_anonymous_voice_room_seats_its_members_by_account_until_the_head_opens() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) =
        voice_room_of(&store, voice_accounts(&[2, 3, 4]), true).await;
    for p in &people {
        assert!(g.seats.contains_key(&conn_seat(p)));
    }
    let ks = [&people[0], &people[1]];
    let mut out = vec![];
    g.set_gate(true, now, &mut out);
    for p in &people {
        assert!(
            g.exits.has(&conn_seat(p)),
            "{}'s connection seat exits",
            p.sid
        );
        assert!(g.joins.has(&p.seat()), "{}'s account seat waits", p.sid);
    }
    // The Join of the account seats, the exits' opening, then the gated one
    let kinds = gate_dues(&mut g, &store, &ks, &mut h, &mut now).await;
    assert_eq!(kinds, vec![gk::due::JOIN, gk::due::EXITS, gk::due::GATE]);
    let head = g.head.as_ref().unwrap().sh.header().clone();
    assert!(head.gated);
    for p in &people {
        assert!(
            g.seats.contains_key(&p.seat()),
            "{} sits by its account",
            p.sid
        );
    }
    let mut out = vec![];
    g.set_gate(false, now, &mut out);
    assert!(g.joins.is_empty(), "a gated head seats no connection");
    // The next opening opens the head: the connections' seats wait again
    now += 2_000;
    let mut out = vec![];
    g.leave(4, cause::LEAVE, now, &mut out);
    now += 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (k, due, piece) = asked(&out, &ks).expect("the exit's opening");
    assert!(!piece.gated);
    voice_commit(&mut g, &store, k, &mut h, (due, piece), now).await;
    for p in &people[..2] {
        assert!(
            g.joins.has(&conn_seat(p)),
            "{} by its connection again",
            p.sid
        );
    }
}

/// A post in a voice room names its writer as the writer's app does, by the gate of the
/// post's epoch, not of the channel now: the blob is kept under that name, which readers ask
/// it by. Gate on, the head still open: by the connection; under the gated head: by the
/// account, and by the connection for the epoch before.
#[tokio::test]
async fn a_voice_posts_writer_is_named_by_its_epochs_gate_not_the_channels() {
    let store = Store::memory();
    let (mut g, people, mut h, mut now) =
        voice_room_of(&store, voice_accounts(&[2, 3, 4]), true).await;
    let a = &people[2];
    let gen = g.gen().unwrap();
    let mut out = vec![];
    g.set_gate(true, now, &mut out);
    let open = g.head.as_ref().unwrap().sh.header().epoch;
    let kept = |g: &GroupState, epoch: u32, m: MemberId| {
        let w = gk::GkWriter {
            m: m.into(),
            u: a.sid,
        };
        g.blobs.contains_key(&(epoch, w))
    };
    assert_eq!(
        g.post_blob(a.sid, gen, open, vec![1; 32], now, &mut out),
        Ok(())
    );
    assert!(
        kept(&g, open, MemberId::Conn(a.sid)),
        "the head is open still"
    );
    let ks = [&people[0], &people[1]];
    gate_dues(&mut g, &store, &ks, &mut h, &mut now).await;
    let gated = g.head.as_ref().unwrap().sh.header().clone();
    assert!(gated.gated);
    let account = a.account;
    assert_eq!(g.room_writer(a.sid, account, &gen, gated.epoch), a.m());
    assert_eq!(
        g.room_writer(a.sid, account, &gen, gated.epoch - 1),
        MemberId::Conn(a.sid),
        "the epoch before the gated opening"
    );
    let mut out = vec![];
    g.set_gate(false, now, &mut out);
    assert_eq!(
        g.room_writer(a.sid, account, &gen, gated.epoch),
        a.m(),
        "the gate is off, its epoch still gated"
    );
    assert_eq!(
        g.post_blob(a.sid, gen, gated.epoch, vec![2; 32], now, &mut out),
        Ok(())
    );
    assert!(kept(&g, gated.epoch, a.m()));
}

/// Review of RV q9-q10:211: every names answer carries the removals between, so each must
/// cost what §8 budgets, 33 B per exit plus its place: a whole header (0.4 KB) for each of
/// §8's 100 exit openings an hour at 100k put a writer that posts every 14 days past
/// `NAMES_IN_MAX_BYTES`, so it never folded again. A removal goes as its bare list.
#[test]
fn a_names_answer_carries_each_removal_at_the_cost_of_its_seats() {
    use crate::gk::names::{Kept, Names};
    use voipc_crypto::group_key::{
        names_start, names_step, Added, HeaderV1, NamesList, Removed, SignedHeader,
    };
    use voipc_protocol::gk::NAMES_IN_MAX_BYTES;
    let gen = [1; 16];
    let t = 1_000_000_000;
    let start = NamesList {
        time: t,
        epoch: 3,
        join: 0,
        added: vec![],
        removed: vec![],
    };
    let mut hash = names_start(&start);
    let ik = voipc_crypto::generate_identity_key_pair();
    let mut removals = vec![];
    const N: u32 = 16;
    for i in 0..N {
        let mut hd = HeaderV1 {
            group_kind: GroupKind::Text,
            group: "c:lounge-4".into(),
            gen,
            epoch: 4 + i,
            join: 0,
            kind: Kind::Fresh,
            time: t + 36 * u64::from(i + 1),
            parent: [9; 32],
            epoch_parent: [0; 32],
            kh_parent: [8; 32],
            signer: MemberId::Account([3; 16]),
            keyholders: vec![],
            gated: true,
            seed: 1,
            seed_floor: 1,
            exits_upto: u64::from(i + 1),
            seats: 100_000,
            buckets: 1613,
            conn_seats: 0,
            bucket_root: [0; 32],
            keyring_hash: [0; 32],
            names_hash: [0; 32],
            added: Added::List(vec![]),
            removed: Removed::List(vec![SeatRef {
                m: MemberId::Account([5 + i as u8; 16]),
                tag_sk: [1; 8],
                tag_sx: [2; 8],
            }]),
            confirm: [0; 32],
        };
        hd.names_hash = names_step(&hash, &NamesList::of(&hd));
        hash = hd.names_hash;
        removals.push((gen, SignedHeader::sign(hd, &ik).unwrap()));
    }
    let mut n = Names::default();
    let first = names_start(&start);
    n.restore(
        vec![Kept {
            gen,
            list: (&start).into(),
            hash: first,
        }],
        removals,
        None,
    );
    let at = |epoch, join| gk::NamesRef { gen, epoch, join };
    let bytes = |p: &gk::NamesPiece| postcard::to_allocvec(p).unwrap().len();
    let bare = bytes(&n.answer(&at(3, 0), &at(3, 0)));
    let all = bytes(&n.answer(&at(3, 0), &at(4 + N, 0)));
    let each = (all - bare) / N as usize;
    assert!(each <= 33 + 31, "{each} B for a removal of one seat");
    // And they are the steps: the fold from the start reaches the last removal's hash
    let a = n.answer(&at(3, 0), &at(4 + N, 0));
    let folded = a.lists[1..].iter().fold(first, |acc, l| {
        names_step(&acc, &NamesList::try_from(l).unwrap())
    });
    assert_eq!(folded, hash);
    // 14 days of §8's exits at 100k, one seat each, stay well inside the cap
    assert!(
        each * 100 * 24 * 14 < NAMES_IN_MAX_BYTES / 4,
        "{each} B a removal"
    );
}

/// J10-B option A (owner 2026-11-22): a stored group whose keyholder set in force holds
/// connection entries alone (here a guest's pair), none online, is asked a Regenesis as soon
/// as a seat waits, on that turn: its wait (`regenesis_at`) ends when the relay saw no
/// keyholder online, not 2 minutes on. The control: with the keyholder online the newcomer
/// waits for a Join, and nothing starts anew.
#[tokio::test]
async fn a_connection_held_stored_group_with_no_keyholder_online_is_asked_a_regenesis_at_once() {
    let store = Store::memory();
    let newcomer = Person::guest(4);
    let asked = |out: &[Out], sid: UserId| -> Vec<u8> {
        dues(out, sid).into_iter().map(|(_, p)| p.kind).collect()
    };

    // The control: the keyholder is online
    let (mut g, k, _h, people, mut now) = seated_group(&store).await;
    g.stored = true;
    g.follow(newcomer.sid, None);
    let mut out = vec![];
    assert_eq!(
        g.fetch(newcomer.sid, newcomer.fetch(), now, &mut out),
        Fetched::Not
    );
    assert_eq!(g.regenesis_at(), None, "a keyholder is online");
    now += 2_000;
    g.tick(now, &mut out);
    assert_eq!(asked(&out, k.sid), vec![gk::due::JOIN], "a Join seats it");
    for p in &people {
        assert!(asked(&out, p.sid).is_empty(), "nothing starts anew");
    }

    // The keyholder goes, its entry the set's only one
    let (mut g, k, _h, people, now) = seated_group(&store).await;
    g.stored = true;
    let set = &g.head.as_ref().unwrap().kh.header().keyholders;
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].origin, Origin::Connection as u8);
    let mut out = vec![];
    g.volunteer(k.sid, None, now, &mut out);
    assert_eq!(
        g.regenesis_at(),
        Some(now),
        "from when no keyholder was online"
    );
    let v = &people[0];
    g.volunteer(
        v.sid,
        Some(v.volunteer(gk::platform::DESKTOP)),
        now,
        &mut out,
    );
    g.follow(newcomer.sid, None);
    let mut out = vec![];
    assert_eq!(
        g.fetch(newcomer.sid, newcomer.fetch(), now, &mut out),
        Fetched::Not
    );
    assert_eq!(
        asked(&out, v.sid),
        vec![gk::due::REGENESIS],
        "a Regenesis at once"
    );
}

/// A volunteer's Regenesis for the due `piece`, on its clock `now` (ms).
fn regenesis(g: &GroupState, v: &Person, piece: &DuePiece, now: u64) -> Built {
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let exits: Vec<Exit> = piece.exits.iter().cloned().map(Exit::from).collect();
    let st = Start {
        kind: GroupKind::Text,
        id: ID,
        me: v.me(),
        ik: &v.ik,
        entry: v.entry(),
        joiners: &[&joiner],
        gated: piece.gated,
        stored: g.stored,
        now: now / 1000,
    };
    let head = &g.head.as_ref().unwrap().sh;
    voipc_crypto::group_key::build::build_regenesis(
        &st,
        head,
        &exits,
        piece.exits_upto,
        &mut RowBases::new(),
    )
    .unwrap()
}

/// An Exits opening of `seated_group`'s keyholder `k`, people[1]'s exit, landed at the
/// relay's `now` (returned) and built on the keyholder's clock `ahead` ms ahead of it.
async fn an_opening_landed(
    g: &mut GroupState,
    store: &Store,
    k: &Person,
    h: &mut Holds,
    people: &[Person],
    mut now: u64,
    ahead: u64,
) -> u64 {
    let mut out = vec![];
    g.leave(people[1].sid, cause::LEAVE, now, &mut out);
    now += 3 * 20 + 2_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("an exits due");
    assert_eq!(piece.kind, gk::due::EXITS);
    let b = opening(g, k, h, &piece, now + ahead);
    let mut out = vec![];
    let t = send(g, k.sid, due, &b, now, &mut out).expect("taken");
    land(g, store, t, now, &mut out).await;
    assert_eq!(g.last_opening, now);
    now
}

/// J10-B option A (repair): under a set of connection entries alone, a head dated ahead of
/// the relay's clock (its keyholder's clock runs ahead, within `KEYHOLDER_SKEW_SECS`) does
/// not hold back the at-once Regenesis. The volunteer dates it at its parent's `time`, which
/// is later than its own clock, and the relay takes it. Only the hour counts from the head's
/// `time`.
#[tokio::test]
async fn an_at_once_regenesis_waits_for_no_head_dated_ahead_of_the_relay_clock() {
    let store = Store::memory();
    let newcomer = Person::guest(4);
    let (mut g, k, mut h, people, now) = seated_group(&store).await;
    g.stored = true;
    let ahead = 180_000;
    let mut now = an_opening_landed(&mut g, &store, &k, &mut h, &people, now, ahead).await;
    let parent = g.head.as_ref().unwrap().sh.header().time;
    assert_eq!(
        parent,
        (now + ahead) / 1000,
        "dated on the keyholder's clock"
    );
    // Past the gap after that opening, the keyholder goes and a seat waits
    now += 2_000;
    let mut out = vec![];
    g.volunteer(k.sid, None, now, &mut out);
    assert_eq!(g.regenesis_at(), Some(now), "not the head's time");
    let v = &people[0];
    g.volunteer(
        v.sid,
        Some(v.volunteer(gk::platform::DESKTOP)),
        now,
        &mut out,
    );
    g.follow(newcomer.sid, None);
    let mut out = vec![];
    assert_eq!(
        g.fetch(newcomer.sid, newcomer.fetch(), now, &mut out),
        Fetched::Not
    );
    let (due, piece) = dues(&out, v.sid).pop().expect("a Regenesis at once");
    assert_eq!(piece.kind, gk::due::REGENESIS);
    // The volunteer on the relay's clock
    let b = regenesis(&g, v, &piece, now);
    assert_eq!(b.header.header().time, parent, "dated at its parent's time");
    let mut out = vec![];
    let t = send(&mut g, v.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    let hd = g.head.as_ref().unwrap().sh.header();
    assert_eq!((hd.kind, hd.time), (Kind::Regenesis, parent));
}

/// J10-B option A (repair): the at-once Regenesis keeps the relay's gap between openings
/// (`EPOCH_MIN_GAP_MS`, §4.1 "at most one opening commit per group every 2 s"). A sole
/// keyholder that goes half a second after its opening landed leaves the Regenesis to
/// `last_opening + EPOCH_MIN_GAP_MS`, and the actor wakes for it then.
#[tokio::test]
async fn an_at_once_regenesis_comes_no_sooner_than_the_gap_after_the_last_opening() {
    use voipc_crypto::group_key::timers::EPOCH_MIN_GAP_MS;
    let store = Store::memory();
    let newcomer = Person::guest(4);
    let (mut g, k, mut h, people, now) = seated_group(&store).await;
    g.stored = true;
    let opened = an_opening_landed(&mut g, &store, &k, &mut h, &people, now, 0).await;
    let now = opened + 500;
    let mut out = vec![];
    g.volunteer(k.sid, None, now, &mut out);
    let v = &people[0];
    g.volunteer(
        v.sid,
        Some(v.volunteer(gk::platform::DESKTOP)),
        now,
        &mut out,
    );
    g.follow(newcomer.sid, None);
    let mut out = vec![];
    assert_eq!(
        g.fetch(newcomer.sid, newcomer.fetch(), now, &mut out),
        Fetched::Not
    );
    assert!(dues(&out, v.sid).is_empty(), "not within the gap");
    let at = opened + EPOCH_MIN_GAP_MS;
    assert_eq!(g.regenesis_at(), Some(at));
    assert_eq!(g.wake(now), Some(at), "the actor wakes for it");
    let mut out = vec![];
    g.tick(at - 1, &mut out);
    assert!(dues(&out, v.sid).is_empty(), "not a millisecond early");
    let mut out = vec![];
    g.tick(at, &mut out);
    let kinds: Vec<u8> = dues(&out, v.sid).into_iter().map(|(_, p)| p.kind).collect();
    assert_eq!(kinds, vec![gk::due::REGENESIS], "once the gap is out");
}

// ── Dive 4 F7: the shutdown drain ─────────────────────────────────────────

/// The scratch database `file` names, connected again (after its pool was closed).
async fn reopen(file: &std::path::Path) -> l4f_accounts::store::Store {
    let url = match std::env::var("VOIPC_TEST_POSTGRES") {
        Ok(server) => {
            let id = file
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.rsplit('-').next())
                .unwrap();
            let (base, _) = server.rsplit_once('/').unwrap();
            format!("{base}/voipc_gkt_{id}")
        }
        Err(_) => format!("sqlite://{}?mode=rwc", file.display()),
    };
    l4f_accounts::store::Store::connect(&url).await.unwrap()
}

/// Dive 4 F7: a shutdown (or a self-update's exec) closed the pool 500 ms after its broadcast,
/// whatever the group actors still had queued: a message a hook had sent was never handled or
/// never written. `Groups::drain` waits until each stored group's actor handled and wrote what
/// was queued before it. Here the keyholder's seat exits as its connection unfollows, and the
/// relay shuts down at once: the exit is written before the pool closes.
#[tokio::test]
async fn a_shutdown_drains_what_the_stored_groups_had_queued_before_the_pool_closes() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("c:drain"));
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    let p = net.guest(7, &id);
    net.fetch(&p, &id).await;
    let (due, piece) = due_within(&mut net, k.sid, 5_000).await.expect("a Genesis");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let b = genesis(&k, &id, &piece, true, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    let mut moved = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if crate::accounts::gk::group(&db, &id)
            .await
            .unwrap()
            .is_some()
        {
            moved = true;
            break;
        }
    }
    assert!(moved, "the Genesis is stored");
    let seat = seat_record(&k.seat());
    // Its exit is queued, then the relay shuts down: `main`'s order
    net.groups.on_unfollow(7, k.sid);
    net.groups.drain(std::time::Duration::from_secs(3)).await;
    db.close().await;
    let db = reopen(&file).await;
    let rows = crate::accounts::gk::exits(&db, &id).await.unwrap();
    assert!(
        rows.iter().any(|e| e.seat == seat),
        "the exit queued before the shutdown was written before the pool closed: {rows:?}"
    );
    drop_db(&file);
}

/// Review P3 of dive 4's fixes: a new start's eager pages are read and asked by a task beside
/// the actor, a page at a time, once the head moved. A stop before they were all asked (a
/// crash, a shutdown, a page read that failed) left the rest unasked until the next new start:
/// asks are kept page by page, and a start asked again only the asks kept. Here the stop cuts
/// the pages before the first is read; the relay's next start asks them, from where they
/// stopped, and is done with them.
#[tokio::test]
async fn a_new_starts_eager_pages_cut_off_by_a_stop_are_asked_at_the_next_start() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("c:pages"));
    let (ann, ann_seat) = log_member(&db, &id, "ann", now_ms()).await;
    let ask = crate::accounts::gk::EagerAsk {
        account: ann,
        seat: seat_record(&ann_seat.public().seat(MemberId::Account(ann))),
    };
    net.groups.cut_eager_for_test();
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    let p = net.guest(7, &id);
    net.fetch(&p, &id).await;
    let (due, piece) = due_within(&mut net, k.sid, 5_000).await.expect("a Genesis");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let b = genesis(&k, &id, &piece, true, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    let mut stored = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if crate::accounts::gk::group(&db, &id)
            .await
            .unwrap()
            .is_some()
        {
            stored = true;
            break;
        }
    }
    assert!(stored, "the Genesis is stored");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let cut = crate::accounts::gk::eager_asks(&db, &id).await.unwrap();
    assert!(
        cut.is_empty(),
        "the stop came before ann was asked: {cut:?}"
    );
    // The relay stops, and starts again over the same database
    net.groups.on_purge(&id);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut again = Net::new();
    again.groups.attach(db.clone(), inc);
    let _q = again.guest(7, &id);
    let mut asks = vec![];
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        asks = crate::accounts::gk::eager_asks(&db, &id).await.unwrap();
        if !asks.is_empty() {
            break;
        }
    }
    let gen = b.header.header().gen;
    let mut left = Some(None);
    for _ in 0..100 {
        left = crate::accounts::gk::eager_after(&db, &id, &gen)
            .await
            .unwrap();
        if left.is_none() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        asks == vec![ask] && left.is_none(),
        "after the start ann is asked: {asks:?}; pages still to ask, from: {left:?}"
    );
    again.groups.on_purge(&id);
    drop_db(&file);
}

// ── Dive 4 round 2 (d4-r2-plan.md) ────────────────────────────────────────

/// The one-column rows `q` reads.
async fn blobs(db: &l4f_accounts::store::Store, q: &str) -> Vec<Vec<u8>> {
    let q = sqlx::AssertSqlSafe(q.to_string());
    match db {
        l4f_accounts::store::Store::Lite(b) => sqlx::query_scalar(q).fetch_all(&b.0).await.unwrap(),
        l4f_accounts::store::Store::Pg(b) => sqlx::query_scalar(q).fetch_all(&b.0).await.unwrap(),
    }
}

/// Polls up to 5 s until `done` holds of what `read` gives; the last read.
async fn until<T, F: std::future::Future<Output = T>>(
    read: impl Fn() -> F,
    done: impl Fn(&T) -> bool,
) -> T {
    let mut got = read().await;
    for _ in 0..100 {
        if done(&got) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        got = read().await;
    }
    got
}

/// Item 1, the live settle. ann's account joins the log while a guest keyholder is online: a
/// Genesis, then a Join due seating her. Her account leaves the log while that Join is out: the
/// hook asks her exit in the store, and the group enters it only once the Join lands
/// (`exit_late`, memory alone). The ask stays until then, so a stop meanwhile still exits her;
/// once the Join landed and her exit is written, the ask goes.
#[tokio::test]
async fn an_exit_asked_while_its_seat_is_being_seated_is_kept_until_the_exit_is_written() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
    let id = net.groups.id_for(7, Some("lounge"));
    let (a, seat1) = log_member(&db, &id, "ann", now_ms()).await;
    let q = format!(
        "SELECT identity_key FROM voipc_identity WHERE account = {}",
        blob(&db, &a)
    );
    let ik = crate::gk::store::ik_raw(&blobs(&db, &q).await[0]).unwrap();
    let k = net.guest(7, &id);
    net.volunteer(&k).await;
    net.groups.on_log_join("lounge", a, ik).await;
    let (due, piece) = due_within(&mut net, k.sid, 5_000)
        .await
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
    let (due, piece) = due_within(&mut net, k.sid, 10_000)
        .await
        .expect("a Join of the account's seat");
    // Out of the log while the Join is out
    net.groups.on_log_leave("lounge", a, cause::LEAVE).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let kept = crate::accounts::gk::exit_asks(&db, &id).await.unwrap();
    let b = join_on(&k, &id, &head, &mut h, &piece, true, net.groups.now());
    net.commit(k.sid, &id, due, &b).await;
    let rec = seat_record(&seat1.public().seat(MemberId::Account(a)));
    let written = until(
        || async {
            crate::accounts::gk::exits(&db, &id)
                .await
                .unwrap()
                .iter()
                .any(|e| e.seat == rec && e.cause == cause::LEAVE)
        },
        |w| *w,
    )
    .await;
    let left = until(
        || async { crate::accounts::gk::exit_asks(&db, &id).await.unwrap() },
        |l| l.is_empty(),
    )
    .await;
    net.groups.on_purge(&id);
    drop_db(&file);
    assert!(
        kept.len() == 1 && kept[0].account == a && written && left.is_empty(),
        "while the Join was out the ask was kept: {kept:?}; once it landed her exit was \
         written: {written}, asks left: {left:?}"
    );
}

/// Item 1: an exit whose write failed was never written again (`exits_entered` only warned),
/// and a restart before its opening had the seat back. The group writes it again at its next
/// turn once the database takes it; its ask is kept until then.
#[tokio::test]
async fn a_failed_exit_write_is_written_again_and_its_ask_kept_until_then() {
    let (db, file, net, a, _ann, seat1) = an_account_seated_in_a_stored_group().await;
    let id = "c:lounge";
    exec(
        &db,
        "ALTER TABLE voipc_gk_exits RENAME TO voipc_gk_exits_away".into(),
    )
    .await;
    net.groups.on_log_leave("lounge", a, cause::LEAVE).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let kept = crate::accounts::gk::exit_asks(&db, id).await.unwrap();
    exec(
        &db,
        "ALTER TABLE voipc_gk_exits_away RENAME TO voipc_gk_exits".into(),
    )
    .await;
    let rec = seat_record(&seat1.public().seat(MemberId::Account(a)));
    let written = until(
        || async {
            crate::accounts::gk::exits(&db, id)
                .await
                .unwrap()
                .iter()
                .any(|e| e.seat == rec)
        },
        |w| *w,
    )
    .await;
    let left = until(
        || async { crate::accounts::gk::exit_asks(&db, id).await.unwrap() },
        |l| l.is_empty(),
    )
    .await;
    net.groups.on_purge(id);
    drop_db(&file);
    assert!(
        kept.len() == 1 && written && left.is_empty(),
        "while the write failed the ask was kept: {kept:?}; once the database took it the exit \
         was written: {written}, asks left: {left:?}"
    );
}

/// Item 2: a device removed from its account marks the keyholder entries it made in the store
/// (`forced`) before any group hears of it, so a stop before a group's actor took the message
/// still proposes their removal at its next start. Another device's entry is left as it is.
#[tokio::test]
async fn a_device_removal_marks_its_entries_in_the_store_before_the_groups_hear() {
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let net = Net::new();
    net.groups.attach(db.clone(), inc);
    let a = [0x5a; 16];
    let entry = |kx: u8, device: &[u8]| crate::accounts::gk::Holder {
        kx: [kx; 32],
        m: MemberId::Account(a).seat_id(),
        device: Some(device.to_vec()),
        rank: 0,
        last_online: 5,
        missed: crate::accounts::gk::Misses::default(),
        pair: None,
    };
    for (grp, h) in [
        ("c:dev1", entry(7, b"laptop")),
        ("c:dev2", entry(8, b"laptop")),
        ("c:dev2", entry(9, b"phone")),
    ] {
        crate::accounts::gk::put_holder(&db, grp, &h).await.unwrap();
    }
    net.groups.on_device_removed(a, b"laptop").await;
    let marked = blobs(
        &db,
        "SELECT kx FROM voipc_gk_holders WHERE forced ORDER BY kx",
    )
    .await;
    for grp in ["c:dev1", "c:dev2"] {
        net.groups.on_purge(grp);
    }
    drop_db(&file);
    assert_eq!(
        marked,
        vec![vec![7u8; 32], vec![8u8; 32]],
        "the laptop's entries are marked as the hook returns, the phone's is not"
    );
}

/// Item 3, `moved_back`, with the stored group's actor running: its channel's group id moved
/// away (anonymous on) and back. While it was away a hook (a log leave) started the stored
/// group, so `start` never read the mark and the followers came back into the old generation:
/// a seat that should have gone meanwhile (a kick under the other id) stayed keyed. Back, a
/// new start is asked of the keyholder that volunteers, and the store keeps the mark until a
/// new generation is stored: a fresh load of the group asks one too.
#[tokio::test]
async fn a_stored_group_moved_back_to_starts_anew_with_its_actor_running_and_after_a_restart() {
    let (db, file, mut net, _a, _ann, _seat1) = an_account_seated_in_a_stored_group().await;
    let id = "c:lounge";
    let gen = crate::accounts::gk::group(&db, id)
        .await
        .unwrap()
        .unwrap()
        .head
        .gen;
    let away = net.groups.id_for(7, None);
    net.groups.on_group_moved(7, id, &away);
    net.groups
        .on_log_leave("lounge", [9; 16], cause::LEAVE)
        .await;
    assert!(
        net.groups.get(id).is_some(),
        "a hook started the stored group"
    );
    net.groups.on_group_moved(7, &away, id);
    let k2 = net.guest(7, id);
    net.volunteer(&k2).await;
    let p = net.guest(7, id);
    net.fetch(&p, id).await;
    let asked = due_within(&mut net, k2.sid, 5_000)
        .await
        .map(|(_, p)| p.kind);
    let marked = until(
        || async {
            crate::accounts::gk::moved_back(&db, id, &gen)
                .await
                .unwrap()
        },
        |m| *m,
    )
    .await;
    // A restart: the group loads anew
    let inc = crate::accounts::gk::gk_incarnation(&db)
        .await
        .unwrap()
        .unwrap();
    let store = Store::Db(Arc::new(crate::gk::store::DbStore {
        db: db.clone(),
        incarnation: inc,
    }));
    let mut g = new_group(true);
    g.id = id.into();
    store.load(&mut g).await.unwrap();
    net.groups.on_purge(id);
    drop_db(&file);
    assert!(
        asked == Some(gk::due::GENESIS) && marked && g.new_gen,
        "back under its stored id the keyholder was asked {:?}; the store keeps the mark: \
         {marked}; a fresh load asks a new generation: {}",
        asked.map(gk::due::name),
        g.new_gen
    );
}

/// Item 3, `moved_back`, nobody following: the channel's id came back to the stored group
/// while no actor ran it, so only memory knew a new generation was due, and a restart before
/// anyone followed resumed the old one. The mark is in the store now.
#[tokio::test]
async fn a_stored_group_moved_back_to_while_nobody_follows_starts_anew_after_a_restart() {
    let (db, file, net, _a, _ann, _seat1) = an_account_seated_in_a_stored_group().await;
    let id = "c:lounge";
    let gen = crate::accounts::gk::group(&db, id)
        .await
        .unwrap()
        .unwrap()
        .head
        .gen;
    let away = net.groups.id_for(7, None);
    net.groups.on_group_moved(7, id, &away);
    assert!(net.groups.get(id).is_none(), "the stored group stopped");
    net.groups.on_group_moved(7, &away, id);
    let marked = until(
        || async {
            crate::accounts::gk::moved_back(&db, id, &gen)
                .await
                .unwrap()
        },
        |m| *m,
    )
    .await;
    net.groups.on_purge(id);
    drop_db(&file);
    assert!(marked, "the store keeps that a new generation is due");
}
