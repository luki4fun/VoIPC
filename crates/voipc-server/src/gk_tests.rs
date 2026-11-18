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
            remove: None,
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
    let b = genesis(&k, ID, &piece, false, now);
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
        h.removal(&vols, 10, false, 10),
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
        h.removal(&vols, 10, false, 10).map(|r| r.kx),
        Some(a.wire().kx())
    );
    // An hour later they no longer count
    assert_eq!(h.removal(&vols, 10, false, 3_600_010), None);
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
    for suffix in ["", "-wal", "-shm", ".lock"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", file.display()));
    }
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
        kh: head,
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
    assert_eq!(net.groups.chain_epoch_ref(&id, &gen, 1), Ok(()));
    assert_eq!(
        net.groups.chain_epoch_ref(&id, &gen, 2),
        Err(refused_why::OLD_EPOCH)
    );
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
        cause::DEVICE,
        cause::RESTART,
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

#[test]
fn a_kept_chain_names_only_the_head_generation_up_to_its_epoch() {
    let groups = Groups::new(true);
    assert_eq!(
        groups.chain_epoch_ref("r:x:1", &[0; 16], 1),
        Err(refused_why::NOT_STORED)
    );
    assert_eq!(
        groups.chain_epoch_ref("c:none", &[0; 16], 1),
        Err(refused_why::NOT_MEMBER)
    );
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
    let (db, file) = scratch_db().await;
    let inc = crate::accounts::gk::gk_start(&db, true)
        .await
        .unwrap()
        .unwrap();
    let mut net = Net::new();
    net.groups.attach(db.clone(), inc);
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
    let out = net.frames(k.sid, 2_500).await;
    let (_, piece) = dues(&out, k.sid).pop().expect("a Join");
    assert_eq!(piece.kind, gk::due::JOIN);
    let ann_seat: gk::GkSeat = seat.public().seat(MemberId::Account(a.0)).into();
    assert!(
        piece.joins.iter().any(|j| j.seat == ann_seat),
        "the account is queued with the fetcher"
    );
    assert_eq!(piece.joins.len(), 2);
    net.groups.on_purge(&id);
    drop_db(&file);
}
