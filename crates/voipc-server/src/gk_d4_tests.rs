//! Dive 4 (relay crash, restart and storage failure): is a stored group's state in the
//! database still the state its actor holds?
//!
//! The harness is `gk_tests.rs`'s, copied (its helpers are private): the relay's real
//! `GroupState`, validator and database store, and keyholders that build honest commits with
//! `voipc_crypto::group_key::build` from the dues the relay sends. `Sim::turn` and
//! `Sim::commit` make the store calls one actor turn makes, in the actor's order
//! (`gk/mod.rs` `actor` and `handle_msg`); `Sim::reload` is an actor start (`Store::load`
//! into a new `GroupState`, then every connection seat exits), which is what a relay restart
//! or an idle stop and a later start do to a stored group.
//!
//! Nothing here changes product code. Some tests inject a failure, all inside this module:
//! `exits_write_fails` and `holders_write_fails` skip the one `exits_entered` or
//! `put_holders` call of a turn (both store calls only warn when their write fails, so a
//! skipped call is a failed one), `commit_whose_answer_is_lost` stores a commit and then
//! treats it as failed (the database applied the head move, the relay saw an error), and one
//! test renames a table for the moment of a `load` (a read that fails).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use voipc_crypto::group_key::build::{
    build_genesis, build_join, build_opening, build_regenesis, BuildError, Built, Holding,
    ListSeat, Lists, OpeningAsk, RowBases, Start,
};
use voipc_crypto::group_key::commit::{Candidate, DueKind, Exit, HolderRef, Joiner, Pair};
use voipc_crypto::group_key::{
    seat_record, Endorsement, Group, GroupKind, Keyholder, Keyring, Kind, Me, MemberId, Origin,
    SeatPair, SeatPublic, SeatRef,
};
use voipc_crypto::IdentityKeyPair;
use voipc_protocol::gk::{
    self, commit_frame_overhead, cut_commit, CommitPiece, DuePiece, Part, Parts, Seq,
    PIECE_MAX_BYTES,
};
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::UserId;
use zeroize::Zeroizing;

use crate::accounts::gk as db;
use crate::gk::group::{cause, Fetch, Fetched, GroupState, OpenCaps, Out};
use crate::gk::holders::Volunteer;
use crate::gk::push;
use crate::gk::store::{DbStore, Store};
use crate::gk_e2e_tests::{drop_db, scratch_db};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn raw(ik: &IdentityKeyPair) -> [u8; 32] {
    ik.public_key().public_key_bytes().try_into().unwrap()
}

/// A connection (a guest: its seat pair, 0x02, is also its keyholder pair), or a device of
/// an account with the account's seat keys (0x01).
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

/// An account's desktop that holds keys: its keyholder pair (0x03) as a `Person`, the
/// account's seat (its seat keys, 0x01) as another, and what it volunteers.
fn desktop(sid: UserId, a: [u8; 16]) -> (Person, Person, Volunteer) {
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
    (k, seat, v)
}

/// An account's browser page that holds keys: its keyholder pair is its connection's
/// (0x02, gone with the connection), its seat the account's (0x01, which stays when the
/// page closes). The keyholder pair as a `Person`, the seat, what it volunteers.
fn browser(sid: UserId, a: [u8; 16]) -> (Person, Person, Volunteer) {
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
        ..k.volunteer(gk::platform::BROWSER)
    };
    (k, seat, v)
}

/// What a keyholder holds once its commit was taken.
struct Holds {
    ring: Keyring,
    krk: Zeroizing<[u8; 32]>,
    cache: RowBases,
}

impl Holds {
    fn of(b: Built) -> Holds {
        Holds {
            ring: b.ring,
            krk: b.krk,
            cache: RowBases::new(),
        }
    }

    fn took(&mut self, b: Built) {
        self.ring = b.ring;
        self.krk = b.krk;
    }
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

/// Every `EpochStale` in `out`, as `reason detail`.
fn stales(out: &[Out]) -> Vec<String> {
    out.iter()
        .flat_map(|o| &o.1)
        .filter_map(|f| match f {
            ServerMessage::EpochStale { reason, detail, .. } => {
                Some(format!("{} {detail}", gk::stale::name(*reason)))
            }
            _ => None,
        })
        .collect()
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
                    // A seat the relay's lists name but its seats do not hold (what these
                    // tests look for) has no key here: the list digest then fails the build
                    dh: g.seats.get(s).map_or(vec![], |x| x.dh.to_vec()),
                })
                .collect();
            (l.version(), seats)
        })
        .collect()
}

fn holding<R>(
    g: &GroupState,
    k: &Person,
    h: &mut Holds,
    f: impl FnOnce(&Holding, &mut RowBases) -> R,
) -> R {
    let grp = Group::new(g.kind, &g.id, g.gen().unwrap()).unwrap();
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

/// The Genesis due `piece` asked of keyholder `k`.
fn genesis(k: &Person, id: &str, piece: &DuePiece, now: u64) -> Built {
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let st = Start {
        kind: GroupKind::Text,
        id,
        me: k.me(),
        ik: &k.ik,
        entry: k.entry(),
        joiners: &[&joiner],
        gated: piece.gated,
        stored: true,
        now: now / 1000,
    };
    build_genesis(&st, &mut RowBases::new()).unwrap()
}

/// The Regenesis due `piece` asked of volunteer `v`.
fn regenesis(g: &GroupState, v: &Person, piece: &DuePiece, now: u64) -> Built {
    let joiner = Joiner::try_from(&piece.joins[0]).unwrap();
    let exits: Vec<Exit> = piece.exits.iter().cloned().map(Exit::from).collect();
    let st = Start {
        kind: GroupKind::Text,
        id: &g.id,
        me: v.me(),
        ik: &v.ik,
        entry: v.entry(),
        joiners: &[&joiner],
        gated: piece.gated,
        stored: true,
        now: now / 1000,
    };
    let head = &g.head.as_ref().unwrap().sh;
    build_regenesis(&st, head, &exits, piece.exits_upto, &mut RowBases::new()).unwrap()
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

/// The opening due `piece` asked of keyholder `k`, or why an honest keyholder builds none.
fn try_opening(
    g: &GroupState,
    k: &Person,
    h: &mut Holds,
    piece: &DuePiece,
    now: u64,
) -> Result<Built, BuildError> {
    let exits: Vec<Exit> = piece.exits.iter().cloned().map(Exit::from).collect();
    let mut pairs: HashMap<[u8; 32], SeatPublic> = g
        .holders
        .pairs
        .iter()
        .map(|(kx, p)| (*kx, p.keys.clone()))
        .collect();
    let candidate = piece
        .promote
        .as_ref()
        .map(|c| Candidate::try_from(c).unwrap());
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
            remove: piece.remove.map(HolderRef::from),
            replace: None,
            finish: piece.finish,
            seed_seats: &seed_seats,
            pairs: &pair_of,
            now: now / 1000,
        };
        build_opening(hold, &ask, cache, None)
    })
}

fn opening(g: &GroupState, k: &Person, h: &mut Holds, piece: &DuePiece, now: u64) -> Built {
    try_opening(g, k, h, piece, now).unwrap_or_else(|e| panic!("the opening did not build: {e:?}"))
}

/// How many leaves of `g` name `seat`.
fn leaves_naming(g: &GroupState, seat: &SeatRef) -> usize {
    g.leaves.iter().filter(|l| l.seats.contains(seat)).count()
}

/// A stored group over a scratch database, run as its actor runs it.
struct Sim {
    id: String,
    g: GroupState,
    store: Store,
    db: l4f_accounts::store::Store,
    file: std::path::PathBuf,
    now: u64,
    /// The next turn that enters an exit does not get it written: `Store::exits_entered`
    /// only warns when `add_exits` fails, so the turn goes on as it does here.
    exits_write_fails: bool,
    /// What the relay sent in the last `commit` turn (a due asked again among it).
    sent: Vec<Out>,
    /// The keyholder set, who of it is online and whose removal is forced, as last written
    /// (`actor`'s `kh_was`).
    kh_was: HoldersNow,
    /// The next write of the keyholder entries fails (`Store::put_holders` only warns), or
    /// the relay stops right before it.
    holders_write_fails: bool,
}

/// The seats a taken commit dealt with, seated or refused (`handle_msg`'s `dealt`).
fn dealt(t: &crate::gk::group::Taken) -> Vec<SeatRef> {
    t.applied
        .seated
        .iter()
        .map(|(s, _)| *s)
        .chain(t.applied.refused.iter().map(|r| r.seat))
        .collect()
}

/// The keyholder set, its online entries and those whose removal is proposed outright, by
/// KX (`gk/mod.rs` `holders_now`).
type HoldersNow = (Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<[u8; 32]>);

fn holders_now(g: &GroupState) -> HoldersNow {
    (
        g.holders.set.iter().map(|k| k.kx).collect(),
        g.holders
            .online(&g.vols)
            .iter()
            .map(|v| v.pair.kx())
            .collect(),
        g.holders.forced.iter().map(|r| r.kx).collect(),
    )
}

impl Drop for Sim {
    fn drop(&mut self) {
        drop_db(&self.file);
    }
}

impl Sim {
    async fn new(id: &str) -> Sim {
        let (db, file) = scratch_db().await;
        let inc = db::gk_start(&db, true).await.unwrap().unwrap();
        let store = Store::Db(Arc::new(DbStore {
            db: db.clone(),
            incarnation: inc,
        }));
        Sim {
            id: id.into(),
            g: GroupState::new(
                id.into(),
                GroupKind::Text,
                true,
                Arc::new(OpenCaps::default()),
            ),
            store,
            db,
            file,
            now: now_ms(),
            exits_write_fails: false,
            sent: vec![],
            kh_was: (vec![], vec![], vec![]),
            holders_write_fails: false,
        }
    }

    /// What the actor's turn does after its message or timer (`gk/mod.rs` `actor`): the
    /// exits entered in it are kept, then the keyholder entries.
    async fn after(&mut self, exits_from: u64) {
        if self.g.exits.next != exits_from {
            if self.exits_write_fails {
                self.exits_write_fails = false;
            } else {
                self.store
                    .exits_entered(&self.id, &self.g, exits_from, self.now)
                    .await;
            }
        }
        // Written when the set, who of it is online or a forced removal changes
        let kh_now = holders_now(&self.g);
        if kh_now != self.kh_was {
            if self.holders_write_fails {
                self.holders_write_fails = false;
            } else {
                self.store.put_holders(&self.g, self.now).await;
            }
            self.kh_was = kh_now;
        }
    }

    /// One actor turn: `f` is the message's or the timer's work on the state.
    async fn turn(&mut self, f: impl FnOnce(&mut GroupState, u64, &mut Vec<Out>)) -> Vec<Out> {
        let from = self.g.exits.next;
        let mut out = vec![];
        f(&mut self.g, self.now, &mut out);
        self.after(from).await;
        out
    }

    /// A timer turn `ms` later.
    async fn tick(&mut self, ms: u64) -> Vec<Out> {
        self.now += ms;
        self.turn(|g, now, out| g.tick(now, out)).await
    }

    /// The commit `b` for `due` sent whole by `sid`, as `handle_msg` takes `Msg::Commit`:
    /// checked, stored, applied; a store failure tells the keyholder and asks again. Why
    /// the commit was not taken, if it was not; what the relay sent meanwhile is in `sent`.
    async fn commit(&mut self, sid: UserId, due: u64, b: &Built) -> Result<(), String> {
        let from = self.g.exits.next;
        let mut out = vec![];
        let piece = CommitPiece::try_from(b.commit.clone()).unwrap();
        let parts = cut_commit(piece, PIECE_MAX_BYTES - commit_frame_overhead(&self.id)).unwrap();
        let n = parts.len();
        let mut taken = None;
        for (i, p) in parts.into_iter().enumerate() {
            let bytes = push::len(&p);
            taken =
                self.g
                    .commit_part(sid, due, i as u16, i + 1 == n, p, bytes, self.now, &mut out);
        }
        let Some(t) = taken else {
            self.after(from).await;
            let why = format!("refused by the relay's check: {:?}", stales(&out));
            self.sent = out;
            return Err(why);
        };
        let r = match self.store.commit(&self.g, &t, self.now).await {
            Ok(()) => {
                let dealt = dealt(&t);
                self.g.apply(t, self.now, &mut out);
                self.store.prune(&self.g);
                self.store.eager_settled(&self.id, &dealt).await;
                Ok(())
            }
            Err(e) => {
                self.g.store_failed(t, self.now, &mut out);
                Err(format!("the store refused it: {e}"))
            }
        };
        self.after(from).await;
        self.sent = out;
        r
    }

    /// As `commit`, but the database applies the head move and the relay is told it failed
    /// (the answer to its COMMIT is lost with the connection): `store_failed`, as for any
    /// store error.
    async fn commit_whose_answer_is_lost(&mut self, sid: UserId, due: u64, b: &Built) -> Vec<Out> {
        let from = self.g.exits.next;
        let mut out = vec![];
        let piece = CommitPiece::try_from(b.commit.clone()).unwrap();
        let parts = cut_commit(piece, PIECE_MAX_BYTES - commit_frame_overhead(&self.id)).unwrap();
        let n = parts.len();
        let mut taken = None;
        for (i, p) in parts.into_iter().enumerate() {
            let bytes = push::len(&p);
            taken =
                self.g
                    .commit_part(sid, due, i as u16, i + 1 == n, p, bytes, self.now, &mut out);
        }
        let t = taken.expect("taken");
        // The database applies the head move and the answer is lost (`LOSE_ANSWER`); the
        // relay takes it as the actor does
        crate::gk::store::LOSE_ANSWER
            .lock()
            .unwrap()
            .insert(self.id.clone());
        match self.store.commit(&self.g, &t, self.now).await {
            Ok(()) => {
                let dealt = dealt(&t);
                self.g.apply(t, self.now, &mut out);
                self.store.prune(&self.g);
                self.store.eager_settled(&self.id, &dealt).await;
            }
            Err(_) => self.g.store_failed(t, self.now, &mut out),
        }
        self.after(from).await;
        out
    }

    /// An actor start over the same database (`actor`'s first lines): a new state, loaded,
    /// every connection seat an exit, then what account-path changes the database holds and
    /// the group never took (`Store::reconcile`). A relay restart, or an idle stop and the
    /// next start.
    async fn reload(&mut self) -> Vec<Out> {
        let mut g = GroupState::new(
            self.id.clone(),
            GroupKind::Text,
            true,
            Arc::new(OpenCaps::default()),
        );
        self.store.load(&mut g).await.expect("the group loads");
        g.restarted(self.now);
        let mut out = vec![];
        let conns: Vec<SeatRef> = g.seats.keys().filter(|s| s.m.is_conn()).copied().collect();
        for s in conns {
            g.exit(s, cause::RESTART, self.now, &mut out);
        }
        self.store.reconcile(&mut g, self.now, &mut out).await;
        self.kh_was = holders_now(&g);
        self.g = g;
        out
    }

    /// `p` follows and fetches: whether it is seated at once, and what the relay sent.
    async fn comes(&mut self, p: &Person) -> (Fetched, Vec<Out>) {
        let mut got = Fetched::Not;
        let (sid, account, f) = (p.sid, p.account, p.fetch());
        let out = self
            .turn(|g, now, out| {
                g.follow(sid, account);
                got = g.fetch(sid, f, now, out);
            })
            .await;
        (got, out)
    }

    /// `vol` follows and volunteers on its connection: what the relay sent.
    async fn volunteers(&mut self, vol: &Volunteer) -> Vec<Out> {
        let v = vol.clone();
        self.turn(|g, now, out| {
            g.follow(v.sid, v.m.account());
            g.volunteer(v.sid, Some(v), now, out);
        })
        .await
    }

    /// The seats the database holds as seated in the head's generation.
    async fn stored_seats(&self) -> Vec<[u8; 33]> {
        let gen = self.g.gen().expect("a head");
        let mut v: Vec<[u8; 33]> = db::seats(&self.db, &self.id, &gen)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.seat)
            .collect();
        v.sort_unstable();
        v
    }

    /// The exit rows the database holds: `(seq, seat)`.
    async fn stored_exits(&self) -> Vec<(u64, [u8; 33])> {
        db::exits(&self.db, &self.id)
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.seq, e.seat))
            .collect()
    }
}

/// The Genesis due in `out` for `k`, built and taken.
async fn start(s: &mut Sim, k: &Person, out: &[Out]) -> Holds {
    let (due, piece) = dues(out, k.sid).pop().expect("a Genesis due");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let id = s.id.clone();
    let b = genesis(k, &id, &piece, s.now);
    s.commit(k.sid, due, &b)
        .await
        .expect("the Genesis is taken");
    Holds::of(b)
}

/// The Join batch closes and `k` (on connection `sid`) seats whoever waits.
async fn seat_waiting(s: &mut Sim, k: &Person, sid: UserId, h: &mut Holds) {
    let out = s.tick(2_100).await;
    let (due, piece) = dues(&out, sid).pop().expect("a Join due");
    assert_eq!(piece.kind, gk::due::JOIN);
    let b = join(&s.g, k, h, &piece, s.now);
    s.commit(sid, due, &b).await.expect("the Join is taken");
    h.took(b);
}

const ANN: [u8; 16] = [0xa1; 16];
const BOB: [u8; 16] = [0xb0; 16];
const DEX: [u8; 16] = [0xd4; 16];

/// A stored channel whose keys a guest's desktop holds (a connection entry, as a browser
/// page's is: it dies with its connection), with ann and bob, two accounts, seated by a
/// Join. The keyholder, ann, bob.
async fn guest_held(id: &str) -> (Sim, Person, Person, Person) {
    let mut s = Sim::new(id).await;
    let k = Person::guest(1);
    let ann = Person::account(2, ANN);
    let bob = Person::account(3, BOB);
    s.volunteers(&k.volunteer(gk::platform::DESKTOP)).await;
    let (got, out) = s.comes(&ann).await;
    assert_eq!(got, Fetched::Not);
    let mut h = start(&mut s, &k, &out).await;
    assert_eq!(s.comes(&bob).await.0, Fetched::Not);
    seat_waiting(&mut s, &k, 1, &mut h).await;
    assert!(s.g.seats.contains_key(&ann.seat()) && s.g.seats.contains_key(&bob.seat()));
    (s, k, ann, bob)
}

/// A stored channel whose keys an account's desktop holds (its own pair, 0x03, which comes
/// back with the device after a restart), with ann and bob seated by a Join. The desktop's
/// keyholder pair, what it volunteers, what it holds, ann, bob.
async fn desktop_held(id: &str) -> (Sim, Person, Volunteer, Holds, Person, Person) {
    desktop_held_with(id, None).await
}

/// `desktop_held`, with `more` seated by the same Join (one bucket holds them all).
async fn desktop_held_with(
    id: &str,
    more: Option<&Person>,
) -> (Sim, Person, Volunteer, Holds, Person, Person) {
    let mut s = Sim::new(id).await;
    let (k, _, vol) = desktop(1, DEX);
    let ann = Person::account(2, ANN);
    let bob = Person::account(3, BOB);
    s.volunteers(&vol).await;
    let (got, out) = s.comes(&ann).await;
    assert_eq!(got, Fetched::Not);
    let mut h = start(&mut s, &k, &out).await;
    assert_eq!(s.comes(&bob).await.0, Fetched::Not);
    if let Some(p) = more {
        assert_eq!(s.comes(p).await.0, Fetched::Not);
    }
    seat_waiting(&mut s, &k, 1, &mut h).await;
    assert!(s.g.seats.contains_key(&ann.seat()) && s.g.seats.contains_key(&bob.seat()));
    (s, k, vol, h, ann, bob)
}

/// Whether ann is kicked while the Regenesis due is out (her exit is then in the open batch,
/// which the due does not carry) or before the batch closed that it carries.
#[derive(Clone, Copy, PartialEq)]
enum Kick {
    WhileTheRegenesisIsBuilt,
    BeforeItsBatchClosed,
}

/// The scene of the stale exit row. A channel held by a connection entry; the keyholder's
/// connection ends; ann is kicked (`when`); an account's desktop volunteers and makes the
/// Regenesis the relay asks at once ("Fast new start"); ann follows again and the new
/// keyholder seats her by a Join. Gives the new keyholder (pair, volunteer, holdings), ann
/// on her new connection, bob.
async fn regenesis_then_ann_again(
    id: &str,
    when: Kick,
) -> (Sim, Person, Volunteer, Holds, Person, Person) {
    let (mut s, k, ann, bob) = guest_held(id).await;
    // The keyholder's connection ends: its connection seat exits, its entry is offline for good
    s.turn(|g, now, out| g.leave(k.sid, cause::DISCONNECT, now, out))
        .await;
    if when == Kick::BeforeItsBatchClosed {
        s.turn(|g, now, out| g.leave(ann.sid, cause::KICK, now, out))
            .await;
    }
    s.tick(2_100).await;
    assert_eq!(
        s.g.exits.closed.len(),
        1,
        "the batch closed; nobody takes it"
    );
    // An account's desktop with "Help hold keys" comes: a Regenesis at once
    let (v, _, vol) = desktop(4, DEX);
    let out = s.volunteers(&vol).await;
    let (due, piece) = dues(&out, 4).pop().expect("a Regenesis due");
    assert_eq!(piece.kind, gk::due::REGENESIS);
    if when == Kick::WhileTheRegenesisIsBuilt {
        s.now += 300;
        s.turn(|g, now, out| g.leave(ann.sid, cause::KICK, now, out))
            .await;
    }
    assert_eq!(s.g.exits.waiting(), 2, "the old keyholder's seat and ann's");
    let b = regenesis(&s.g, &v, &piece, s.now);
    s.commit(4, due, &b).await.expect("the Regenesis is taken");
    let mut h = Holds::of(b);
    assert_eq!(s.g.head.as_ref().unwrap().sh.header().kind, Kind::Regenesis);
    assert_eq!(s.g.exits.waiting(), 0, "after the new start no exit waits");
    // A kick is no ban: ann follows again; bob, still there, fetches the new generation;
    // the new keyholder's Join seats both
    let ann = Person { sid: 5, ..ann };
    assert_eq!(s.comes(&ann).await.0, Fetched::Not);
    assert_eq!(s.comes(&bob).await.0, Fetched::Not);
    seat_waiting(&mut s, &v, 4, &mut h).await;
    assert!(s.g.seats.contains_key(&ann.seat()), "ann is seated again");
    assert!(s.g.seats.contains_key(&bob.seat()), "bob is seated again");
    assert_eq!(leaves_naming(&s.g, &ann.seat()), 1);
    (s, v, vol, h, ann, bob)
}

/// F1, first half. After the scene above the relay restarts (or the group idles out and is
/// loaded again). Nobody left since ann was seated again, so the first opening after the
/// restart must leave her seated. It does not: the exit of her kick is still a row in
/// `voipc_gk_exits` (the Regenesis kept the generation and its head move deleted only the
/// exits its due carried), `load` finds her seat seated and takes the row for an exit not
/// dealt with, and the relay asks the keyholder to remove her.
#[tokio::test]
async fn d4_a_seat_taken_again_after_a_regenesis_survives_a_restart() {
    let (mut s, v, vol, mut h, ann, _bob) =
        regenesis_then_ann_again("c:d4-f1a", Kick::WhileTheRegenesisIsBuilt).await;
    let rows_before = s.stored_exits().await;
    let waiting_before = s.g.exits.waiting();

    s.reload().await;
    let waiting_after = s.g.exits.waiting();
    // The desktop keyholder is back on a new connection, with the pair it kept
    let vol = Volunteer { sid: 6, ..vol };
    let mut out = s.volunteers(&vol).await;
    out.extend(s.tick(2_100).await);
    let mut asked = vec![];
    for (due, piece) in dues(&out, 6) {
        asked.push(gk::due::name(piece.kind));
        let b = opening(&s.g, &v, &mut h, &piece, s.now);
        s.commit(6, due, &b).await.expect("the opening is taken");
        h.took(b);
    }
    assert!(
        s.g.seats.contains_key(&ann.seat()),
        "ann was seated again after the new start and nobody left since, yet after a restart \
         the relay had her removed. Exits waiting before the restart: {waiting_before}; exit \
         rows in the database then: {} (ann's seat among them: {}); exits waiting after the \
         load: {waiting_after}; dues the relay asked the keyholder after the restart: {asked:?}",
        rows_before.len(),
        rows_before
            .iter()
            .any(|(_, r)| *r == seat_record(&ann.seat())),
    );
}

/// The control of the test above: the same scene, but ann's kick came before the exit batch
/// closed that the Regenesis due carried, so the Regenesis's head move deleted its row. The
/// restart then changes nothing.
#[tokio::test]
async fn d4_control_an_exit_the_regenesis_carried_leaves_no_row_and_a_restart_changes_nothing() {
    let (mut s, v, vol, mut h, ann, _bob) =
        regenesis_then_ann_again("c:d4-f1c", Kick::BeforeItsBatchClosed).await;
    assert!(s.stored_exits().await.is_empty(), "no exit row is left");
    s.reload().await;
    assert_eq!(s.g.exits.waiting(), 0);
    let vol = Volunteer { sid: 6, ..vol };
    let mut out = s.volunteers(&vol).await;
    out.extend(s.tick(2_100).await);
    for (due, piece) in dues(&out, 6) {
        let b = opening(&s.g, &v, &mut h, &piece, s.now);
        s.commit(6, due, &b).await.expect("the opening is taken");
        h.took(b);
    }
    assert!(s.g.seats.contains_key(&ann.seat()), "ann stays seated");
    assert_eq!(leaves_naming(&s.g, &ann.seat()), 1);
}

/// What the relay asks keyholder `v` (on `sid`) over the next `rounds` refresh periods, each
/// built as an honest keyholder builds it and taken: the kinds asked, and the first build
/// that failed.
async fn refreshes(
    s: &mut Sim,
    v: &Person,
    sid: UserId,
    h: &mut Holds,
    rounds: usize,
) -> (Vec<&'static str>, Option<String>) {
    let mut asked = vec![];
    for _ in 0..rounds {
        let out = s
            .tick(voipc_crypto::group_key::timers::REFRESH_MS + 1_000)
            .await;
        for (due, piece) in dues(&out, sid) {
            asked.push(gk::due::name(piece.kind));
            if piece.kind == gk::due::JOIN {
                let b = join(&s.g, v, h, &piece, s.now);
                s.commit(sid, due, &b).await.expect("the Join is taken");
                h.took(b);
                continue;
            }
            match try_opening(&s.g, v, h, &piece, s.now) {
                Ok(b) => match s.commit(sid, due, &b).await {
                    Ok(()) => h.took(b),
                    Err(e) => return (asked, Some(e)),
                },
                Err(e) => return (asked, Some(format!("the keyholder cannot build it: {e:?}"))),
            }
        }
    }
    (asked, None)
}

/// F1, second half. The same scene, and no restart yet: bob leaves, and the keyholder's
/// opening takes his exit. Its head move deletes the seats of every exit row up to bob's,
/// ann's stale one among them: the database no longer holds ann's seat, though the relay's
/// memory and the signed list do. After a restart the relay holds a list that names a seat
/// it does not hold. It serves that list to keyholders without the seat's key
/// (`GroupState::lists`), so no honest keyholder can build an opening that re-keys that
/// bucket: within an hour every opening does (`BUCKET_AGE_MAX_SECS`), and the channel opens
/// no epoch any more.
#[tokio::test]
async fn d4_a_later_opening_keeps_the_seat_row_of_a_seat_taken_again_after_a_regenesis() {
    let (mut s, v, vol, mut h, ann, bob) =
        regenesis_then_ann_again("c:d4-f1b", Kick::WhileTheRegenesisIsBuilt).await;
    s.turn(|g, now, out| g.leave(bob.sid, cause::LEAVE, now, out))
        .await;
    let out = s.tick(2_100).await;
    let (due, piece) = dues(&out, 4).pop().expect("an exits due");
    assert_eq!(piece.kind, gk::due::EXITS);
    assert_eq!(piece.exits.len(), 1, "bob's exit alone");
    let b = opening(&s.g, &v, &mut h, &piece, s.now);
    s.commit(4, due, &b).await.expect("the opening is taken");
    h.took(b);
    let rec = seat_record(&ann.seat());
    let live = s.g.seats.contains_key(&ann.seat());
    let stored = s.stored_seats().await.contains(&rec);

    s.reload().await;
    let named = leaves_naming(&s.g, &ann.seat());
    let loaded = s.g.seats.contains_key(&ann.seat());
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let (asked, failed) = refreshes(&mut s, &v, 6, &mut h, 14).await;
    assert!(
        live && stored && loaded && failed.is_none(),
        "ann was seated again after the new start and never left. After bob's exit was taken: \
         the relay holds her seat: {live}; the database holds her seat: {stored}. After a \
         restart: leaves naming her seat: {named}; the relay holds her seat: {loaded}. The \
         keyholder then built what the relay asked for 70 minutes ({asked:?}); the first that \
         failed: {failed:?}"
    );
}

/// The control of the test above: with no stale exit row (ann's kick was carried by the
/// Regenesis), bob's exit, a restart and 70 minutes of refreshes all go through.
#[tokio::test]
async fn d4_control_without_the_stale_row_the_openings_after_a_restart_go_through() {
    let (mut s, v, vol, mut h, ann, bob) =
        regenesis_then_ann_again("c:d4-f1d", Kick::BeforeItsBatchClosed).await;
    s.turn(|g, now, out| g.leave(bob.sid, cause::LEAVE, now, out))
        .await;
    let out = s.tick(2_100).await;
    let (due, piece) = dues(&out, 4).pop().expect("an exits due");
    let b = opening(&s.g, &v, &mut h, &piece, s.now);
    s.commit(4, due, &b).await.expect("the opening is taken");
    h.took(b);
    assert!(s.stored_seats().await.contains(&seat_record(&ann.seat())));
    s.reload().await;
    assert!(s.g.seats.contains_key(&ann.seat()));
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let (asked, failed) = refreshes(&mut s, &v, 6, &mut h, 14).await;
    assert_eq!(failed, None, "asked {asked:?}");
    assert!(asked.len() >= 10, "the refreshes came: {asked:?}");
}

const KAY: [u8; 16] = [0xca; 16];

/// F1, the common way in. A kept channel whose keys an account's browser page holds; dex,
/// an account's desktop, is an ordinary member. The page closes (its account's seat stays,
/// nothing waits, nothing is asked). dex turns "Help hold keys" on: nobody online can sign
/// its promotion. Then ann is kicked. Her exit is the first thing that waits, so the relay
/// asks dex a Regenesis in that same turn, while the exit is still in the open batch: the
/// due carries no exit, and the Regenesis's head move deletes none. ann follows again; the
/// relay restarts; dex comes back. Nobody left since ann was seated again, so she must
/// still be seated after the restart's first opening.
#[tokio::test]
async fn d4_an_exit_that_itself_starts_the_new_generation_is_over_with_it() {
    let mut s = Sim::new("c:d4-f1e").await;
    let (k, _, kvol) = browser(1, KAY);
    let ann = Person::account(2, ANN);
    let bob = Person::account(3, BOB);
    let (dex, dex_seat, dvol) = desktop(4, DEX);
    s.volunteers(&kvol).await;
    let (_, out) = s.comes(&ann).await;
    let mut h = start(&mut s, &k, &out).await;
    assert_eq!(s.comes(&bob).await.0, Fetched::Not);
    assert_eq!(s.comes(&dex_seat).await.0, Fetched::Not);
    seat_waiting(&mut s, &k, 1, &mut h).await;
    assert_eq!(s.g.seats.len(), 4, "kay, ann, bob and dex are seated");
    // The page closes; dex offers to hold keys
    s.now += 10_000;
    s.turn(|g, now, out| g.leave(1, cause::DISCONNECT, now, out))
        .await;
    assert_eq!(s.g.exits.waiting(), 0, "an account's seat stays");
    let out = s.volunteers(&dvol).await;
    assert!(dues(&out, 4).is_empty(), "nothing waits, nothing is asked");
    // ann is kicked
    s.now += 10_000;
    let out = s
        .turn(|g, now, out| g.leave(ann.sid, cause::KICK, now, out))
        .await;
    let (due, piece) = dues(&out, 4).pop().expect("a Regenesis due, at once");
    assert_eq!(piece.kind, gk::due::REGENESIS);
    let carried = piece.exits.len();
    let b = regenesis(&s.g, &dex, &piece, s.now);
    s.commit(4, due, &b).await.expect("the Regenesis is taken");
    let mut h = Holds::of(b);
    assert_eq!(s.g.exits.waiting(), 0, "after the new start no exit waits");
    // ann follows again, bob fetches the new generation
    let ann = Person { sid: 5, ..ann };
    assert_eq!(s.comes(&ann).await.0, Fetched::Not);
    assert_eq!(s.comes(&bob).await.0, Fetched::Not);
    seat_waiting(&mut s, &dex, 4, &mut h).await;
    assert!(s.g.seats.contains_key(&ann.seat()), "ann is seated again");
    let rows = s.stored_exits().await.len();

    s.reload().await;
    let waiting = s.g.exits.waiting();
    let dvol = Volunteer { sid: 6, ..dvol };
    let mut out = s.volunteers(&dvol).await;
    out.extend(s.tick(2_100).await);
    let mut asked = vec![];
    for (due, piece) in dues(&out, 6) {
        asked.push(gk::due::name(piece.kind));
        let b = opening(&s.g, &dex, &mut h, &piece, s.now);
        s.commit(6, due, &b).await.expect("the opening is taken");
        h.took(b);
    }
    assert!(
        s.g.seats.contains_key(&ann.seat()),
        "ann was seated again after the new start and nobody left since, yet after a restart \
         the relay had her removed. Exits the Regenesis due carried: {carried}; exit rows in \
         the database before the restart: {rows}; exits waiting after the load: {waiting}; \
         dues asked after the restart: {asked:?}"
    );
}

/// F2's scene. ann is kicked and the write of her exit fails once (`Store::exits_entered`
/// only warns; nothing writes it again). The keyholder's opening takes her exit: the head
/// move finds no exit row, so her seat row stays, in a bucket that still has a current
/// version. The relay restarts (or the group idles out and is loaded again); ann follows
/// again and fetches; then she is put out again and the relay asks the keyholder for that
/// exit. With `cat`, a third member shares the bucket. Whether the restart left her seat
/// gone and the keyholder's commit for her second exit was taken, and what was seen.
async fn exit_not_written(id: &str, cat: bool) -> (bool, String) {
    // With cat, one bucket holds the three of them (a Join's batch), as a larger channel's
    // buckets hold many seats
    let third = Person::account(8, [0xc7; 16]);
    let (mut s, k, vol, mut h, ann, _bob) = desktop_held_with(id, cat.then_some(&third)).await;
    if cat {
        let l = s.g.leaves.iter().find(|l| l.seats.contains(&ann.seat()));
        assert_eq!(
            l.map(|l| l.seats.len()),
            Some(3),
            "ann, bob and cat share a bucket"
        );
    }
    s.exits_write_fails = true;
    s.turn(|g, now, out| g.leave(ann.sid, cause::KICK, now, out))
        .await;
    assert!(s.stored_exits().await.is_empty(), "the write failed");
    let out = s.tick(2_100).await;
    let (due, piece) = dues(&out, 1).pop().expect("an exits due");
    assert_eq!(piece.kind, gk::due::EXITS);
    let b = opening(&s.g, &k, &mut h, &piece, s.now);
    s.commit(1, due, &b).await.expect("the opening is taken");
    h.took(b);
    assert!(!s.g.seats.contains_key(&ann.seat()), "her seat is gone");
    assert_eq!(leaves_naming(&s.g, &ann.seat()), 0, "and no list names it");
    assert_eq!(s.g.head.as_ref().unwrap().sh.header().exits_upto, 1);

    s.reload().await;
    let seated = s.g.seats.contains_key(&ann.seat());
    let named = leaves_naming(&s.g, &ann.seat());
    // The keyholder is back; ann follows again and fetches
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let ann = Person { sid: 7, ..ann };
    let (got, _) = s.comes(&ann).await;
    let got = matches!(got, Fetched::Seated(_));
    let leaf = s.g.snapshot().unwrap().version_of(&ann.seat()).is_some();
    // She is put out again: the relay asks the keyholder for that exit
    s.turn(|g, now, out| g.leave(7, cause::KICK, now, out))
        .await;
    let out = s.tick(2_100).await;
    let mut asked = vec![];
    for (due, piece) in dues(&out, 6) {
        // A Join for her seat, no longer held, is the right due; this harness builds openings
        if piece.kind == gk::due::JOIN {
            asked.push((gk::due::name(piece.kind), Ok(())));
            continue;
        }
        let r = match try_opening(&s.g, &k, &mut h, &piece, s.now) {
            Ok(b) => s.commit(6, due, &b).await,
            Err(e) => Err(format!("the keyholder cannot build it: {e:?}")),
        };
        asked.push((gk::due::name(piece.kind), r));
    }
    (
        !seated && asked.iter().all(|(_, r)| r.is_ok()),
        format!(
            "the head's opening removed ann's seat. After a restart the relay holds it: \
             {seated}; leaves naming it: {named}. Her fetch then is answered as seated: \
             {got}; with a leaf for her seat: {leaf}. Put out again, the relay asked: {asked:?}"
        ),
    )
}

/// F2: a seat that the head's opening removed is not seated after a restart, though the
/// write of its exit failed. (Here her bucket holds one other seat: the keyholder's opening
/// for her second exit drops that bucket, and the relay's check refuses it.)
#[tokio::test]
async fn d4_a_seat_whose_exit_was_not_written_is_still_gone_after_a_restart() {
    let (ok, seen) = exit_not_written("c:d4-f2a", false).await;
    assert!(ok, "{seen}");
}

/// F2 again with two other seats in her bucket: the same, and here no honest keyholder
/// builds the opening for her second exit at all.
#[tokio::test]
async fn d4_a_seat_whose_exit_was_not_written_is_still_gone_after_a_restart_with_more_seats() {
    let (ok, seen) = exit_not_written("c:d4-f2b", true).await;
    assert!(ok, "{seen}");
}

/// The control of the test above: the exit's write succeeds, and a restart finds her seat
/// gone as the head has it.
#[tokio::test]
async fn d4_control_a_seat_whose_exit_was_written_is_gone_after_a_restart() {
    let (mut s, k, _vol, mut h, ann, _bob) = desktop_held("c:d4-f2c").await;
    s.turn(|g, now, out| g.leave(ann.sid, cause::KICK, now, out))
        .await;
    assert_eq!(s.stored_exits().await.len(), 1);
    let out = s.tick(2_100).await;
    let (due, piece) = dues(&out, 1).pop().expect("an exits due");
    let b = opening(&s.g, &k, &mut h, &piece, s.now);
    s.commit(1, due, &b).await.expect("the opening is taken");
    h.took(b);
    s.reload().await;
    assert!(!s.g.seats.contains_key(&ann.seat()));
    assert!(s.stored_exits().await.is_empty());
}

/// F3. The database applies a head move, and the relay is told it failed (the answer to its
/// COMMIT is lost with the connection, as a Postgres connection can lose it). The relay
/// tells the keyholder `STORE` and asks the due again, as for any store error. From then on
/// the relay's head is behind the database's: every later commit is built on the relay's
/// head and refused by the store as built on another, with no end while the actor lives.
#[tokio::test]
async fn d4_a_head_move_whose_answer_was_lost_does_not_stop_every_later_commit() {
    let (mut s, k, _vol, mut h, ann, bob) = desktop_held("c:d4-f3a").await;
    s.turn(|g, now, out| g.leave(bob.sid, cause::LEAVE, now, out))
        .await;
    let out = s.tick(2_100).await;
    let (due, piece) = dues(&out, 1).pop().expect("an exits due");
    let b = opening(&s.g, &k, &mut h, &piece, s.now);
    let lost = b.header.d();
    let out = s.commit_whose_answer_is_lost(1, due, &b).await;
    let told = stales(&out);
    let stored_head = db::group(&s.db, &s.id).await.unwrap().unwrap().head.d;
    assert_eq!(
        stored_head, lost,
        "the database holds the commit as its head"
    );
    let relay_head = s.g.head.as_ref().map(|x| x.sh.d());
    h.took(b);
    // The next commit (ann's exit) is built on the head the relay shows, and taken
    s.turn(|g, now, out| g.leave(ann.sid, cause::LEAVE, now, out))
        .await;
    let out = s.tick(2_100).await;
    let mut tries = vec![];
    if let Some((due, piece)) = dues(&out, 1).pop() {
        let b = opening(&s.g, &k, &mut h, &piece, s.now);
        tries.push(match s.commit(1, due, &b).await {
            Ok(()) => "taken".to_string(),
            Err(e) => e,
        });
    }
    assert!(
        relay_head == Some(lost) && tries.last().map(String::as_str) == Some("taken"),
        "after a head move whose answer was lost (the keyholder was told {told:?}) the relay's \
         head is the stored one: {}; the next commit: {tries:?}",
        relay_head == Some(lost)
    );
}

/// The control of the test above: a new actor over the same database (a restart) loads the
/// head the database holds, and the group goes on.
#[tokio::test]
async fn d4_control_after_a_lost_answer_a_restart_loads_the_stored_head() {
    let (mut s, k, vol, mut h, ann, bob) = desktop_held("c:d4-f3c").await;
    s.turn(|g, now, out| g.leave(bob.sid, cause::LEAVE, now, out))
        .await;
    let out = s.tick(2_100).await;
    let (due, piece) = dues(&out, 1).pop().expect("an exits due");
    let b = opening(&s.g, &k, &mut h, &piece, s.now);
    let lost = b.header.d();
    s.commit_whose_answer_is_lost(1, due, &b).await;
    s.reload().await;
    assert_eq!(s.g.head.as_ref().unwrap().sh.d(), lost);
    assert!(!s.g.seats.contains_key(&bob.seat()) && s.g.seats.contains_key(&ann.seat()));
    // The keyholder holds what it built (its app takes the header when the relay shows it)
    h.took(b);
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let (asked, failed) = refreshes(&mut s, &k, 6, &mut h, 3).await;
    assert_eq!(failed, None, "asked {asked:?}");
    assert!(!asked.is_empty());
}

/// Runs one statement on the scratch database.
async fn sql(db: &l4f_accounts::store::Store, q: &'static str) {
    match db {
        l4f_accounts::store::Store::Lite(b) => {
            sqlx::query(q).execute(&b.0).await.unwrap();
        }
        l4f_accounts::store::Store::Pg(b) => {
            sqlx::query(q).execute(&b.0).await.unwrap();
        }
    }
}

/// F4. One read fails while the group's actor starts (here: the seats table is out of reach
/// for that moment, as a database is during a restart of its own or with its pool used up).
/// `actor` takes any `load` error for "a new generation is due". The database is back at
/// once and holds the group whole, but the actor never loads again: it asks a volunteer for
/// a Genesis over a group that has its head, and (dive 3's F6) the store refuses that Genesis
/// as built on another head, so the channel has no key until the actor stops.
#[tokio::test]
async fn d4_a_read_that_failed_at_the_actors_start_does_not_cost_the_group_its_head() {
    let (mut s, k, vol, _h, ann, _bob) = desktop_held("c:d4-f4a").await;
    let head = s.g.head.as_ref().unwrap().sh.d();
    // The actor starts while one read fails (`actor`'s first lines)
    sql(
        &s.db,
        "ALTER TABLE voipc_gk_seats RENAME TO voipc_gk_seats_away",
    )
    .await;
    let mut g = GroupState::new(
        s.id.clone(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    // The first read fails; the table is back a moment later, and the actor's load
    // (`gk::load_retrying`) tries again
    let failed = s.store.load(&mut g).await.err().map(|e| e.to_string());
    assert!(failed.is_some(), "the read failed");
    let g = GroupState::new(
        s.id.clone(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    let db = s.db.clone();
    let back = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        sql(
            &db,
            "ALTER TABLE voipc_gk_seats_away RENAME TO voipc_gk_seats",
        )
        .await;
    });
    let stop = tokio::sync::Notify::new();
    s.g = crate::gk::load_retrying(&s.store, g, crate::gk::Clock::new(), &stop)
        .await
        .expect("loaded");
    back.await.unwrap();
    // The database answers again. The keyholder and ann come back
    let vol = Volunteer { sid: 6, ..vol };
    let mut out = s.volunteers(&vol).await;
    let ann = Person { sid: 7, ..ann };
    let (got, more) = s.comes(&ann).await;
    out.extend(more);
    let asked: Vec<&str> = dues(&out, 6)
        .iter()
        .map(|(_, p)| gk::due::name(p.kind))
        .collect();
    // What the relay asked, built as asked
    let mut tries = vec![];
    for _ in 0..3 {
        let Some((due, piece)) = dues(&out, 6).pop() else {
            break;
        };
        if piece.kind != gk::due::GENESIS {
            break;
        }
        let id = s.id.clone();
        let b = genesis(&k, &id, &piece, s.now);
        match s.commit(6, due, &b).await {
            Ok(()) => {
                tries.push("taken".to_string());
                break;
            }
            Err(e) => {
                tries.push(e);
                out = std::mem::take(&mut s.sent);
            }
        }
    }
    let stored = db::group(&s.db, &s.id).await.unwrap().unwrap().head.d;
    assert!(
        s.g.head.as_ref().is_some_and(|h| h.sh.d() == head) && got == Fetched::Seated(ann.seat()),
        "one read failed while the group was loaded ({failed:?}); the database still holds the \
         group's head: {}. The relay's head is the stored one: {}; ann's fetch: {got:?}; the \
         relay asked the keyholder: {asked:?}; its commits: {tries:?}",
        stored == head,
        s.g.head.as_ref().is_some_and(|h| h.sh.d() == head),
    );
}

const CAT: [u8; 16] = [0xc7; 16];
const EVE: [u8; 16] = [0xee; 16];

/// `desktop_held`, then cat's desktop (account CAT) is seated and promoted: the set holds
/// two desktop entries. With `lose_write`, the keyholder entries are not written in the
/// turn that took the promotion. Gives cat's keyholder pair and what she volunteers too.
async fn two_desktops(
    id: &str,
    lose_write: bool,
) -> (Sim, Person, Volunteer, Holds, Person, Volunteer) {
    let (mut s, k, vol, mut h, _ann, _bob) = desktop_held(id).await;
    let (cat, cat_seat, cvol) = desktop(8, CAT);
    assert_eq!(s.comes(&cat_seat).await.0, Fetched::Not);
    seat_waiting(&mut s, &k, 1, &mut h).await;
    let mut out = s.volunteers(&cvol).await;
    out.extend(s.tick(2_100).await);
    let (due, piece) = dues(&out, 1).pop().expect("a promotion due");
    assert_eq!(piece.kind, gk::due::PROMOTE);
    let b = opening(&s.g, &k, &mut h, &piece, s.now);
    s.holders_write_fails = lose_write;
    s.commit(1, due, &b).await.expect("the promotion is taken");
    h.took(b);
    assert_eq!(s.g.holders.set.len(), 2, "two entries");
    assert!(s.g.holders.pairs.contains_key(&cvol.pair.kx()));
    (s, k, vol, h, cat, cvol)
}

/// What the relay asks keyholder `k` (on `sid`) once eve, a third desktop that offers to
/// hold keys, is seated: the due's kind, and whether an honest keyholder can build it.
async fn eve_volunteers(
    s: &mut Sim,
    k: &Person,
    sid: UserId,
    h: &mut Holds,
) -> Vec<(&'static str, Result<(), String>)> {
    let (_eve, eve_seat, evol) = desktop(9, EVE);
    assert_eq!(s.comes(&eve_seat).await.0, Fetched::Not);
    seat_waiting(s, k, sid, h).await;
    let mut out = s.volunteers(&evol).await;
    out.extend(s.tick(2_100).await);
    let mut asked = vec![];
    for (due, piece) in dues(&out, sid) {
        let r = match try_opening(&s.g, k, h, &piece, s.now) {
            Ok(b) => {
                let r = s.commit(sid, due, &b).await;
                if r.is_ok() {
                    h.took(b);
                }
                r
            }
            Err(e) => Err(format!("the keyholder cannot build it: {e:?}")),
        };
        asked.push((gk::due::name(piece.kind), r));
    }
    asked
}

/// F5. The relay stops between a promotion's head move and the write of the keyholder
/// entries that follows it in the same turn (or that write fails: `put_holders` only warns).
/// The head names the new entry; `voipc_gk_holders` does not hold its pair. After the
/// restart the new keyholder is not online. The relay then has no pair to send for it, so
/// no other keyholder can build any change of the set that keeps it (each needs every
/// entry's pair for its `KRK` welcome): here the next promotion.
#[tokio::test]
async fn d4_a_new_keyholders_pair_is_still_known_after_a_restart_right_after_its_promotion() {
    let (mut s, k, vol, mut h, _cat, cvol) = two_desktops("c:d4-f5a", true).await;
    s.reload().await;
    let known = s.g.holders.pairs.contains_key(&cvol.pair.kx());
    let named = s.g.holders.set.iter().any(|e| e.kx == cvol.pair.kx());
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let asked = eve_volunteers(&mut s, &k, 6, &mut h).await;
    assert!(
        known && asked.iter().all(|(_, r)| r.is_ok()),
        "the head names cat's entry: {named}; after the restart the relay knows its pair: \
         {known}. With cat offline, the relay asked the other keyholder: {asked:?}"
    );
}

/// The control of the test above: the entries were written, and after a restart the other
/// keyholder builds the next promotion with cat offline.
#[tokio::test]
async fn d4_control_a_new_keyholders_pair_written_is_known_after_a_restart() {
    let (mut s, k, vol, mut h, _cat, cvol) = two_desktops("c:d4-f5c", false).await;
    s.reload().await;
    assert!(s.g.holders.pairs.contains_key(&cvol.pair.kx()));
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let asked = eve_volunteers(&mut s, &k, 6, &mut h).await;
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0], (gk::due::name(gk::due::PROMOTE), Ok(())));
}

/// What the relay asks keyholder `k` (on `sid`) at its next timer turn: each due's kind and
/// whether it names `entry` for removal.
async fn asked_of(
    s: &mut Sim,
    sid: UserId,
    vol: &Volunteer,
    entry: [u8; 32],
) -> Vec<(&'static str, bool)> {
    let vol = Volunteer { sid, ..vol.clone() };
    let mut out = s.volunteers(&vol).await;
    out.extend(s.tick(2_100).await);
    dues(&out, sid)
        .into_iter()
        .map(|(_, p)| {
            let removes = p.remove.is_some_and(|r| HolderRef::from(r).kx == entry);
            (gk::due::name(p.kind), removes)
        })
        .collect()
}

/// F6's scene: two desktop entries; the first keyholder is offline when cat's account is
/// banned, so no entry online can sign the removal of cat's entry yet. With `restart`, the
/// relay restarts before the first keyholder is back. What the relay asks it then.
async fn ban_while_alone(id: &str, restart: bool) -> Vec<(&'static str, bool)> {
    let (mut s, _k, vol, _h, _cat, cvol) = two_desktops(id, false).await;
    s.turn(|g, now, out| g.leave(1, cause::DISCONNECT, now, out))
        .await;
    // The ban: the account's seats exit, its keyholder entries are to be removed, its
    // session ends
    s.turn(|g, now, out| g.account_exit(&CAT, cause::BAN, now, out))
        .await;
    s.turn(|g, now, out| g.leave(8, cause::BAN, now, out)).await;
    assert_eq!(s.g.holders.forced.len(), 1, "cat's entry is to be removed");
    assert!(!s.g.idle(), "the actor stays up for it");
    if restart {
        s.reload().await;
    }
    s.now += 60_000;
    asked_of(&mut s, 6, &vol, cvol.pair.kx()).await
}

/// F6. A banned account's keyholder entry is proposed for removal as soon as another entry
/// can sign it, also when the relay restarted in between. The proposal lives in memory only
/// (`Holders::forced`; `GroupState::idle` keeps the actor up for it, a restart does not).
#[tokio::test]
async fn d4_a_banned_accounts_keyholder_entry_is_still_removed_after_a_restart() {
    let asked = ban_while_alone("c:d4-f6a", true).await;
    assert!(
        asked.iter().any(|(_, removes)| *removes),
        "cat's account was banned while no other keyholder was online, and the relay \
         restarted. Back online, the other keyholder was asked (kind, removes cat's entry): \
         {asked:?}"
    );
}

/// The control of the test above: with no restart the other keyholder is asked the removal
/// as soon as it is back.
#[tokio::test]
async fn d4_control_a_banned_accounts_keyholder_entry_is_removed_without_a_restart() {
    let asked = ban_while_alone("c:d4-f6c", false).await;
    assert!(asked.iter().any(|(_, removes)| *removes), "{asked:?}");
}

// ── F7: account-path changes on their way when the relay stopped ─────────────

/// Runs `q` on the scratch database.
async fn exec(db: &l4f_accounts::store::Store, q: String) {
    match db {
        l4f_accounts::store::Store::Lite(b) => {
            sqlx::query(sqlx::AssertSqlSafe(q))
                .execute(&b.0)
                .await
                .unwrap();
        }
        l4f_accounts::store::Store::Pg(b) => {
            sqlx::query(sqlx::AssertSqlSafe(q))
                .execute(&b.0)
                .await
                .unwrap();
        }
    }
}

/// `b` as a literal of the scratch database's dialect.
fn blob(db: &l4f_accounts::store::Store, b: &[u8]) -> String {
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    match db {
        l4f_accounts::store::Store::Lite(_) => format!("x'{hex}'"),
        l4f_accounts::store::Store::Pg(_) => format!("'\\x{hex}'::bytea"),
    }
}

/// The account row of one of this module's accounts (a ban, an identity, seat keys and a
/// membership each name it by a foreign key), with `p`'s identity key when it has one.
async fn user(db: &l4f_accounts::store::Store, a: [u8; 16], ik: Option<&IdentityKeyPair>) {
    db.create_user(
        &l4f_accounts::model::NewUser {
            id: l4f_accounts::model::AccountId(a),
            username: format!("u{:02x}", a[0]),
            display_name: "u".into(),
            email_pending: None,
            password_hash: None,
            created_at: l4f_accounts::util::now(),
        },
        None,
    )
    .await
    .unwrap();
    if let Some(ik) = ik {
        let key = [&[0x05u8][..], &raw(ik)].concat();
        exec(
            db,
            format!(
                "INSERT INTO voipc_identity (account, identity_key, updated_at) VALUES ({}, {}, 0)",
                blob(db, &a),
                blob(db, &key)
            ),
        )
        .await;
    }
}

/// `p`'s seat keys published as its account's current ones (`SeatKeysPublish`).
async fn publish(db: &l4f_accounts::store::Store, p: &Person) {
    let public = p.pair.public();
    assert!(db::put_seat_keys(
        db,
        &p.account.unwrap(),
        &db::SeatKeys {
            n: p.endorsement.n,
            kem: public.kem_bytes().into(),
            dh: public.dh_bytes().into(),
            made: p.endorsement.made,
            sig: p.endorsement.sig.to_vec(),
            published: now_ms(),
        },
    )
    .await
    .unwrap());
}

/// `a` keeps the log of conversation `conv` (`voipc_members`).
async fn member(db: &l4f_accounts::store::Store, conv: &str, a: [u8; 16]) {
    exec(
        db,
        format!(
            "INSERT INTO voipc_members (conv, account, joined_at) VALUES ('{conv}', {}, 0)",
            blob(db, &a)
        ),
    )
    .await;
}

/// Whether `seat` is on its way out after a start: in an exit batch, and its exit written.
async fn exiting(s: &Sim, seat: &SeatRef) -> (bool, bool) {
    let rec = seat_record(seat);
    (
        s.g.exits.seats().contains(seat),
        s.stored_exits().await.iter().any(|(_, r)| *r == rec),
    )
}

/// F7, a lost exit. bob's account is banned: `ban_put` writes the ban and takes bob out of
/// every log in one transaction, then tells each group (`on_account_gone`), but the relay
/// stops before the group's actor writes bob's exit (a crash, or a message queued in a group
/// whose actor was still loading). After the restart nothing asks it again: bob's seat stays
/// seated and keyed at every opening until its 90-day expiry. The start checks the stored
/// seats against the bans: bob's seat exits, its exit written. ann, not banned, stays.
#[tokio::test]
async fn d4_f7_the_seat_of_an_account_banned_while_its_exit_was_on_its_way_exits_at_the_next_start()
{
    let (mut s, _k, _vol, _h, ann, bob) = desktop_held("c:d4-f7b").await;
    user(&s.db, BOB, None).await;
    user(&s.db, ANN, None).await;
    exec(
        &s.db,
        format!(
            "INSERT INTO voipc_bans (id, account, label, reason, by_name, created_at) VALUES (1, {}, 'bob', '', 'admin', 0)",
            blob(&s.db, &BOB)
        ),
    )
    .await;
    s.reload().await;
    let (bob_out, bob_row) = exiting(&s, &bob.seat()).await;
    let (ann_out, _) = exiting(&s, &ann.seat()).await;
    assert!(
        bob_out && bob_row && !ann_out,
        "after the restart bob, banned, is in an exit batch: {bob_out}, his exit written: \
         {bob_row}; ann, not banned, is: {ann_out}"
    );
}

/// F7, a lost rotation and a lost reset. ann published new seat keys (a rotation: her old
/// seat exits and the new one is seated eagerly, `on_seat_keys`), bob's identity was reset
/// (his seat keys are gone until his next publish: his seats exit, `gk_identity_reset`), and
/// the relay stopped before the group's actor took either. The start checks every account
/// seat against its account's current seat keys: ann's old seat exits and her new one waits
/// for the next Join; bob's exits. The keyholder's own account seat, its keys unknown here (no
/// identity in this database), is left as it is.
#[tokio::test]
async fn d4_f7_seats_whose_keys_were_rotated_or_reset_while_the_change_was_on_its_way_exit_at_the_next_start(
) {
    let (mut s, _k, vol, _h, ann, bob) = desktop_held("c:d4-f7k").await;
    let ann2 = Person::account(2, ANN);
    user(&s.db, ANN, Some(&ann2.ik)).await;
    publish(&s.db, &ann2).await;
    user(&s.db, BOB, Some(&bob.ik)).await;
    s.reload().await;
    let (ann_out, ann_row) = exiting(&s, &ann.seat()).await;
    let ann2_waits = s.g.joins.has(&ann2.seat());
    let (bob_out, bob_row) = exiting(&s, &bob.seat()).await;
    let own = vol.seat.as_ref().unwrap().seat;
    let (own_out, _) = exiting(&s, &own).await;
    assert!(
        ann_out && ann_row && ann2_waits && bob_out && bob_row && !own_out,
        "after the restart ann's old seat is in an exit batch: {ann_out}, written: {ann_row}, \
         her new seat waits: {ann2_waits}; bob's (reset) is in an exit batch: {bob_out}, \
         written: {bob_row}; the keyholder's own seat is: {own_out}"
    );
}

/// F7, a lost eager seat. eve joins the channel's log while no keyholder is online: the hook
/// asks her eager seat (`on_log_join`) and the actor queues it; it waits in memory for a
/// keyholder. The relay restarts before one comes. The start asks it again, and once the
/// keyholder is back its Join seats her, and her ask is gone.
#[tokio::test]
async fn d4_f7_an_eager_seat_waiting_for_a_keyholder_is_still_asked_after_a_restart() {
    let (mut s, k, vol, mut h, _ann, _bob) = desktop_held("c:d4-f7e").await;
    s.turn(|g, now, out| g.leave(1, cause::DISCONNECT, now, out))
        .await;
    let eve = Person::account(9, EVE);
    user(&s.db, EVE, Some(&eve.ik)).await;
    publish(&s.db, &eve).await;
    member(&s.db, &s.id, EVE).await;
    // `on_log_join`: the ask, then the actor's turn on `Eager`
    let ask = db::EagerAsk {
        account: EVE,
        seat: seat_record(&eve.seat()),
    };
    db::put_eager(&s.db, &s.id, &[ask], s.now).await.unwrap();
    let j = eve.joiner();
    s.turn(|g, now, out| g.eager(j, EVE, now, out)).await;
    assert!(s.g.joins.has(&eve.seat()), "she waits for a keyholder");
    s.reload().await;
    let waits = s.g.joins.has(&eve.seat());
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let out = s.tick(2_100).await;
    let seated = match dues(&out, 6).pop() {
        Some((due, piece)) if piece.kind == gk::due::JOIN => {
            let b = join(&s.g, &k, &mut h, &piece, s.now);
            s.commit(6, due, &b).await.expect("the Join is taken");
            s.g.seats.contains_key(&eve.seat())
        }
        _ => false,
    };
    let left = db::eager_asks(&s.db, &s.id).await.unwrap();
    assert!(
        waits && seated && left.is_empty(),
        "after the restart eve's eager seat waits: {waits}; the keyholder back, a Join seats \
         her: {seated}; asks left: {left:?}"
    );
}

// ── Review of the F5-F7 fixes ─────────────────────────────────────────────

impl Person {
    /// The account's seat keys rotated to counter `n`: a new pair under the same identity.
    fn rotated(&self, n: u32) -> Person {
        let pair = SeatPair::generate();
        let endorsement = Endorsement::sign(
            &self.ik,
            Origin::VaultSeat,
            self.m(),
            n,
            now_ms() / 1000,
            &pair.public(),
        )
        .unwrap();
        Person {
            sid: self.sid,
            ik: self.ik,
            pair,
            endorsement,
            account: self.account,
        }
    }

    /// Its eager seat's ask (`on_log_join`, `on_seat_keys`).
    fn ask(&self) -> db::EagerAsk {
        db::EagerAsk {
            account: self.account.unwrap(),
            seat: seat_record(&self.seat()),
        }
    }
}

impl Sim {
    /// Session `sid` leaves the group with `cause`, as `handle_msg` takes `Msg::Leave`: the
    /// eager join that went with it is settled once the turn is over.
    async fn leaves(&mut self, sid: UserId, cause: u8) {
        let from = self.g.exits.next;
        let mut out = vec![];
        let gone = crate::gk::leave(&mut self.g, sid, cause, self.now, &mut out);
        self.after(from).await;
        self.store
            .eager_settled(&self.id, &gone.into_iter().collect::<Vec<_>>())
            .await;
    }
}

/// What `tracing` writes on this thread while it is kept (tokio's test runtime is one thread).
#[derive(Clone, Default)]
struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Lines {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Lines {
    type Writer = Lines;
    fn make_writer(&'a self) -> Lines {
        self.clone()
    }
}

impl Lines {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Review P1. ann's seat keys rotated twice before the opening of her first seat's exit
/// landed: her first seat (exiting) and her second (seated by a Join) are both on superseded
/// keys, and her current ones have no seat yet (the keyholder went offline, the group idled
/// out, and the second rotation's hook wrote only its ask). The start's check against her
/// current keys asked the same new seat once per old seat, twice in one `put_eager`, which
/// Postgres refuses ("ON CONFLICT DO UPDATE command cannot affect row a second time"), and the
/// rest of the check was skipped. Meanwhile dex's identity was reset (its keyholder entry is to
/// go) and eve's eager seat waits. After the start: no warning, ann's new seat waits, dex's
/// entry is to be removed, eve's seat is asked again.
#[tokio::test]
async fn d4_review_an_account_with_two_seats_on_old_keys_is_seated_again_once_at_the_next_start() {
    let (mut s, k, vol, mut h, ann, _bob) = desktop_held("c:d4-r1").await;
    // The first rotation. ann's app publishes new seat keys and fetches with them on a new
    // connection; the rotation's hook, which goes through her groups one by one, reaches this
    // one just before the join batch closes: her first seat exits (its batch closes after
    // the Join is asked), the new one is asked eagerly, and the Join seats it
    let ann2 = Person {
        sid: 5,
        ..ann.rotated(2)
    };
    assert_eq!(s.comes(&ann2).await.0, Fetched::Not);
    s.now += 1_950;
    db::put_eager(&s.db, &s.id, &[ann2.ask()], s.now)
        .await
        .unwrap();
    let j = ann2.joiner();
    s.turn(|g, now, out| {
        g.account_exit(&ANN, cause::ROTATION, now, out);
        g.eager(j, ANN, now, out);
    })
    .await;
    let out = s.tick(50).await;
    let (due, piece) = dues(&out, 1).pop().expect("a Join due");
    assert_eq!(piece.kind, gk::due::JOIN);
    let b = join(&s.g, &k, &mut h, &piece, s.now);
    s.commit(1, due, &b).await.expect("the Join is taken");
    h.took(b);
    assert!(
        s.g.seats.contains_key(&ann2.seat()),
        "her second seat is seated"
    );
    assert!(
        s.g.seats.contains_key(&ann.seat()) && s.g.exits.seats().contains(&ann.seat()),
        "her first seat still waits for its opening"
    );
    // The keyholder goes offline before the opening
    s.turn(|g, now, out| g.leave(1, cause::DISCONNECT, now, out))
        .await;
    // The second rotation with the group's actor stopped: its hook writes the ask
    let ann3 = ann.rotated(3);
    user(&s.db, ANN, Some(&ann.ik)).await;
    publish(&s.db, &ann3).await;
    member(&s.db, &s.id, ANN).await;
    db::put_eager(&s.db, &s.id, &[ann3.ask()], s.now)
        .await
        .unwrap();
    // dex's identity reset, a new one and new seat keys published
    let dex2 = Person::account(1, DEX);
    user(&s.db, DEX, Some(&dex2.ik)).await;
    publish(&s.db, &dex2).await;
    // eve's eager seat asked, waiting for a keyholder
    let eve = Person::account(9, EVE);
    user(&s.db, EVE, Some(&eve.ik)).await;
    publish(&s.db, &eve).await;
    member(&s.db, &s.id, EVE).await;
    db::put_eager(&s.db, &s.id, &[eve.ask()], s.now)
        .await
        .unwrap();
    let lines = Lines::default();
    let logs = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(lines.clone())
        .finish();
    {
        let _on = tracing::subscriber::set_default(logs);
        s.reload().await;
    }
    let said = lines.text();
    let failed = said.contains("checking the group against its accounts failed");
    let ann3_waits = s.g.joins.has(&ann3.seat());
    let (old1, _) = exiting(&s, &ann.seat()).await;
    let (old2, _) = exiting(&s, &ann2.seat()).await;
    let dex_forced = s.g.holders.forced.iter().any(|r| r.kx == vol.pair.kx());
    let eve_waits = s.g.joins.has(&eve.seat());
    let asks = db::eager_asks(&s.db, &s.id).await.unwrap();
    assert!(
        !failed && ann3_waits && old1 && old2 && dex_forced && eve_waits,
        "after the start the check failed: {failed} ({said}); ann's current seat waits: \
         {ann3_waits}, her old seats exit: {old1} {old2}; dex's entry is to be removed: \
         {dex_forced}; eve's seat is asked again: {eve_waits}. Asks kept: {asks:?}"
    );
}

/// Review P1, for every caller of `put_eager`: asks that name one account twice keep its last
/// one (on Postgres one statement may not upsert a row twice).
#[tokio::test]
async fn d4_review_eager_asks_that_name_one_account_twice_keep_its_last() {
    let s = Sim::new("c:d4-r1p").await;
    let ann = Person::account(2, ANN);
    let ann2 = ann.rotated(2);
    let put = db::put_eager(&s.db, &s.id, &[ann.ask(), ann2.ask()], s.now).await;
    let kept = db::eager_asks(&s.db, &s.id).await.unwrap();
    assert!(
        put.is_ok() && kept == vec![ann2.ask()],
        "the write: {put:?}; kept: {kept:?}"
    );
}

/// Review P2's scene: eve's eager seat is asked (her log join) while no keyholder is online;
/// her session follows and fetches (it waits on that same join), then leaves with `cause`; the
/// group starts again. Whether her seat waits after the start, and the asks kept.
async fn eager_then_leave(id: &str, cause: u8) -> (bool, Vec<db::EagerAsk>) {
    let (mut s, _k, _vol, _h, _ann, _bob) = desktop_held(id).await;
    s.turn(|g, now, out| g.leave(1, cause::DISCONNECT, now, out))
        .await;
    let eve = Person::account(9, EVE);
    user(&s.db, EVE, Some(&eve.ik)).await;
    publish(&s.db, &eve).await;
    member(&s.db, &s.id, EVE).await;
    db::put_eager(&s.db, &s.id, &[eve.ask()], s.now)
        .await
        .unwrap();
    let j = eve.joiner();
    s.turn(|g, now, out| g.eager(j, EVE, now, out)).await;
    assert_eq!(s.comes(&eve).await.0, Fetched::Not, "she waits");
    s.leaves(eve.sid, cause).await;
    assert!(!s.g.joins.has(&eve.seat()) || cause == cause::DISCONNECT);
    s.reload().await;
    (
        s.g.joins.has(&eve.seat()),
        db::eager_asks(&s.db, &s.id).await.unwrap(),
    )
}

/// Review P2. A leave of the channel is an exit (§5.4): the live relay drops eve's join and
/// does not seat her. Her ask stayed, so the next start (an idle stop and a later one is
/// enough) seated her all the same. Her ask goes with the join.
#[tokio::test]
async fn d4_review_an_eager_seat_dropped_by_a_leave_is_not_asked_again_at_the_next_start() {
    let (waits, asks) = eager_then_leave("c:d4-r2l", cause::LEAVE).await;
    assert!(
        !waits && asks.is_empty(),
        "eve left the channel before a keyholder seated her; after the start her seat waits: \
         {waits}, asks kept: {asks:?}"
    );
}

/// Review P2, a kick: the same.
#[tokio::test]
async fn d4_review_an_eager_seat_dropped_by_a_kick_is_not_asked_again_at_the_next_start() {
    let (waits, asks) = eager_then_leave("c:d4-r2k", cause::KICK).await;
    assert!(
        !waits && asks.is_empty(),
        "eve was kicked before a keyholder seated her; after the start her seat waits: \
         {waits}, asks kept: {asks:?}"
    );
}

/// Review P2's control: going offline is no exit of an account's text seat (§5.4), so the
/// join and its ask stay, and the next start asks it again.
#[tokio::test]
async fn d4_review_control_an_eager_seat_whose_session_went_offline_is_still_asked() {
    let (waits, asks) = eager_then_leave("c:d4-r2d", cause::DISCONNECT).await;
    assert!(waits && asks.len() == 1, "{waits} {asks:?}");
}

/// F1 once more through the relay's real actor and the clients' real apps (`gk_e2e_j8h.rs`'s
/// world: a real `ServerState` over a database, members' apps stepped by the test). That
/// harness cannot bring a desktop keyholder back with the pair it kept, which a relay restart
/// needs here, so the desktop keyholder is this module's own (`Dex`: the same `GroupKeying`
/// calls as the harness's `App`, stepped next to the members).
mod real {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use l4f_accounts::store::Store as Db;
    use voipc_crypto::group_key::{Endorsement, GroupKind, MemberId, Origin, SeatKeys};
    use voipc_crypto::group_state::{
        GkCtx, GkEvent, GkOut, GkStart, GkTrack, GroupKeying, LocalGk, MemoryPins, Platform,
        VaultFloor,
    };
    use voipc_crypto::{IdentityKeyPair, SignalStores};
    use voipc_protocol::messages::ClientMessage;
    use voipc_protocol::types::UserId;

    use crate::accounts::gk as db;
    use crate::control::{ControlRx, ControlTx};
    use crate::gk::group::cause;
    use crate::gk_e2e_j8h::{handle, relay, Account, World, CHAN, CONV};
    use crate::gk_e2e_tests::{account_session, show, tracing_on};
    use crate::state::ServerState;

    fn wall_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// An account with its identity and published seat keys, as `gk_e2e_j8h.rs` makes one
    /// (its `Account` keeps its fields to itself).
    struct Acct {
        a: [u8; 16],
        ik: IdentityKeyPair,
        keys: SeatKeys,
    }

    impl Acct {
        async fn new(store: &Db, name: &str) -> Acct {
            let id = l4f_accounts::model::AccountId::new();
            store
                .create_user(
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
            db::put_seat_keys(
                store,
                &id.0,
                &db::SeatKeys {
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
            Acct { a: id.0, ik, keys }
        }
    }

    fn now_or_never<F: std::future::Future>(f: F) -> Option<F::Output> {
        let mut f = std::pin::pin!(tokio::task::unconstrained(f));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match std::future::Future::poll(f.as_mut(), &mut cx) {
            std::task::Poll::Ready(v) => Some(v),
            std::task::Poll::Pending => None,
        }
    }

    /// An account's desktop app with "Help hold keys" on (its own keyholder pair, 0x03, kept
    /// in its `LocalGk`), on one connection.
    struct Dex {
        sid: UserId,
        account: [u8; 16],
        keying: GroupKeying,
        st: SignalStores,
        pins: MemoryPins,
        tx: ControlTx,
        rx: ControlRx,
        last_tick: u64,
        events: Vec<GkEvent>,
        /// The self-rows its app hands its host to keep with the account. The host sends
        /// them as `SelfRowPut` on the account's session; here they go into the relay's
        /// table by the function that message ends in (`accounts::gk::put_self_rows`).
        /// Without them an app that starts again cannot open a seat keyed by a row.
        store: Db,
        rows: Vec<voipc_protocol::gk::SelfRowIn>,
    }

    impl Dex {
        /// The app starts on a new connection, with what the device kept (`local`).
        async fn start(
            state: &Arc<ServerState>,
            store: &Db,
            acc: &Acct,
            local: Option<LocalGk>,
        ) -> Dex {
            let (_, sid) =
                crate::state::test_support::add_user(state, &format!("u{}", rand::random::<u32>()));
            let (tx, rx) = crate::control::control_queue(Arc::default());
            {
                let mut s = state.sessions.get_mut(&sid).unwrap();
                let ik: [u8; 32] = acc.ik.public_key().public_key_bytes().try_into().unwrap();
                s.identity_key = Some([&[0x05u8][..], &ik].concat());
                s.control_tx = tx.clone();
                s.account = Some(account_session(acc.a));
            }
            state.gk.on_connect(sid, tx.clone());
            state
                .gk
                .on_follow(CHAN, CONV, GroupKind::Text, sid, Some(acc.a));
            let mut d = Dex {
                sid,
                account: acc.a,
                keying: GroupKeying::default(),
                st: SignalStores::new(&acc.ik, sid),
                pins: MemoryPins::default(),
                tx,
                rx,
                last_tick: 0,
                events: vec![],
                store: store.clone(),
                rows: vec![],
            };
            let now = state.gk.now();
            let out = d.keying.start(GkStart {
                on: true,
                run: state.gk.run,
                relay_clock: now / 1000,
                platform: Platform::Desktop,
                help_hold_keys: true,
                user_id: sid,
                identity: acc.ik,
                account: Some(acc.a),
                seat_keys: Some(SeatKeys::from_bytes(&acc.keys.to_bytes()).unwrap()),
                local,
                visible: true,
            });
            let mut send = d.took(out, now);
            let out = d.keying.track(
                GkTrack {
                    channel_id: CHAN,
                    group: CONV.into(),
                    kind: GroupKind::Text,
                    anonymous: false,
                    hide_members: false,
                    viewer_admin: false,
                    keeps_history: true,
                },
                VaultFloor::None,
            );
            send.extend(d.took(out, now));
            handle(state, sid, &d.tx, send).await;
            d
        }

        fn took(&mut self, out: GkOut, now: u64) -> Vec<ClientMessage> {
            let mut outs = vec![out];
            let mut send = vec![];
            while let Some(out) = outs.pop() {
                self.events.extend(out.events);
                send.extend(out.send);
                self.rows.extend(out.self_rows);
                while let Some(mut job) = self.keying.take_build() {
                    let b = loop {
                        if let Some(b) = job.step(Duration::from_millis(8)) {
                            break b;
                        }
                    };
                    let c = GkCtx {
                        pins: &mut self.pins,
                        now,
                    };
                    outs.push(self.keying.built(b, c));
                }
            }
            while let Some(m) = self.keying.next_frame(now, false) {
                send.push(m);
            }
            send
        }

        /// The frames that came are taken, a tick each 500 ms, what it sends handed over.
        async fn step(&mut self, state: &Arc<ServerState>) {
            let now = state.gk.now();
            let mut frames = vec![];
            while let Some(Some(b)) = now_or_never(self.rx.recv()) {
                frames.push(voipc_protocol::codec::decode_server_msg(&b[4..]).unwrap());
            }
            let mut send = vec![];
            for f in &frames {
                if tracing_on() {
                    eprintln!("[{now}] dex {} <- {}", self.sid, show(f));
                }
                let c = GkCtx {
                    pins: &mut self.pins,
                    now,
                };
                let out = self.keying.frame(&mut self.st, f, c);
                send.extend(self.took(out, now));
            }
            if now >= self.last_tick + 500 {
                self.last_tick = now;
                let c = GkCtx {
                    pins: &mut self.pins,
                    now,
                };
                let out = self.keying.tick(&mut self.st, c);
                send.extend(self.took(out, now));
            }
            if !self.rows.is_empty() {
                let rows = std::mem::take(&mut self.rows);
                db::put_self_rows(&self.store, &self.account, &rows)
                    .await
                    .unwrap();
            }
            handle(state, self.sid, &self.tx, send).await;
        }

        fn epoch(&self) -> Option<u32> {
            self.keying.current_epoch(CONV).map(|e| e.epoch)
        }

        /// Whether the newest keyholder set it was shown names its account.
        fn holds(&self) -> bool {
            self.events
                .iter()
                .rev()
                .find_map(|e| match e {
                    GkEvent::Keyholders { holders, .. } => {
                        Some(holders.contains(&Some(MemberId::Account(self.account))))
                    }
                    _ => None,
                })
                .unwrap_or(false)
        }

        /// The states and warnings its app was shown from event `from` on, each once.
        fn shown(&self, from: usize) -> Vec<String> {
            let mut v: Vec<String> = vec![];
            for e in &self.events[from.min(self.events.len())..] {
                let s = match e {
                    GkEvent::State { state, .. } => format!("{state:?}"),
                    GkEvent::Warning { kind, .. } => format!("warning {kind:?}"),
                    GkEvent::Anew { .. } => "made anew".to_string(),
                    _ => continue,
                };
                if !v.contains(&s) {
                    v.push(s);
                }
            }
            v
        }

        /// The app stops with its connection; what the device keeps.
        fn stop(mut self) -> Option<LocalGk> {
            let _ = self.keying.end();
            self.keying.local().cloned()
        }
    }

    /// The world runs for `ms` at most in steps of `every`, the desktop keyholder stepped
    /// with the members, until `done`.
    async fn run(
        w: &mut World,
        d: &mut Option<Dex>,
        ms: u64,
        every: u64,
        done: impl Fn(&World, Option<&Dex>) -> bool,
    ) -> bool {
        let start = w.now();
        while w.now() < start + ms {
            w.until(every, every, |_| false).await;
            if let Some(d) = d.as_mut() {
                let state = w.state.clone();
                d.step(&state).await;
            }
            if done(w, d.as_ref()) {
                return true;
            }
        }
        false
    }

    /// The exit rows the database holds for the channel: `(seq, seat)`.
    async fn exit_rows(w: &World) -> Vec<(u64, [u8; 33])> {
        db::exits(&w.db, CONV)
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.seq, e.seat))
            .collect()
    }

    /// The seats the database holds as seated in the head's generation.
    async fn seat_rows(w: &World) -> Vec<[u8; 33]> {
        let gen = db::group(&w.db, CONV).await.unwrap().unwrap().head.gen;
        db::seats(&w.db, CONV, &gen)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.seat)
            .collect()
    }

    /// `name` is kicked from the channel and its app closes; what its device keeps.
    fn kicked(w: &mut World, name: &'static str) -> Option<LocalGk> {
        let m = w.members.remove(name).expect("a member");
        let mut app = m.app;
        w.state.gk.on_kick(CHAN, app.sid, cause::KICK);
        let _ = app.keying.end();
        w.state.gk.on_session_end(app.sid);
        app.keying.local().cloned()
    }

    /// What the scene saw, for the tests' messages.
    struct Seen {
        /// The generation before and after the new start are the same one.
        same_gen: bool,
        /// Exit rows in the database right after the new start, and exits the relay had
        /// waiting then.
        rows_after_start: usize,
        waiting_after_start: u32,
        /// After nan's exit was taken: the kicked seat's row in the database, the seats the
        /// database holds, the seats the relay counts.
        row_then: bool,
        db_seats: usize,
        relay_seats: u32,
        /// After the restart.
        /// A few seconds after the restart: the epoch ann's app holds, and dex's.
        first: (Option<u32>, Option<u32>),
        /// Exit rows in the database right before the restart.
        rows_then: usize,
        /// The epoch ann's app holds at the end of the watch.
        ann_end: Option<u32>,
        /// At the end of the watch: the seats the relay counts, and whether the database
        /// holds the row of the seat kicked first.
        seats_end: u32,
        seat_row_end: bool,
        /// ann's app was away since the restart and came back after the watch: the stored
        /// head's epoch then and 15 minutes on, the epoch her app holds, the relay's seats.
        late: Option<(u32, u32, Option<u32>, u32)>,
        /// The stored head's epoch at the restart and at the end of the watch.
        head: (u32, u32),
        epochs: u32,
        quiet_min: u64,
        watched_min: u64,
        missed: u32,
        shown: Vec<String>,
        load: String,
    }

    /// A kept text channel whose keys kay's browser page holds; members ann, nan and oli.
    /// The page reloads (its entry is offline for good). One member is kicked: ann (`anns`),
    /// or oli, who never comes back (the control). That exit makes the relay ask the page on
    /// its new connection for a new start at once. dex's desktop then comes and is promoted;
    /// in the control ann is kicked now, under keyholders that are online. ann follows again
    /// and is seated. nan is kicked, and an opening takes that exit. The relay restarts over
    /// the same database; dex's desktop (with the pair it kept) and ann's come back, and the
    /// channel is watched for 75 minutes of the relay's clock.
    async fn scene(anns: bool, nan_leaves: bool, ann_back: bool) -> Seen {
        const WATCH_MIN: u64 = 75;
        let mut w = World::new().await;
        let kay = Account::new(&w.db, "kay").await;
        let ann = Account::new(&w.db, "ann").await;
        let nan = Account::new(&w.db, "nan").await;
        let oli = Account::new(&w.db, "oli").await;
        let dex = Acct::new(&w.db, "dex").await;
        w.started(&kay, &ann, &nan).await;
        w.member("oli", &oli, None).await;
        assert!(
            w.until(30_000, 10, |w| w.epoch("oli").is_some())
                .await
                .is_some(),
            "oli is seated"
        );
        w.reload(&kay).await;
        assert!(
            w.until(30_000, 10, |w| w.keyholder_epoch().is_some())
                .await
                .is_some(),
            "the page holds the head again"
        );
        let l = w.load().unwrap();
        assert_eq!(
            (l.keyholders, l.keyholders_online, l.exits_waiting),
            (1, 0, 0),
            "the page's old entry, offline; nothing waits"
        );
        let gen = db::group(&w.db, CONV).await.unwrap().unwrap().head.gen;
        assert!(exit_rows(&w).await.is_empty(), "no exit row yet");

        // The kick that starts the channel anew
        let first = if anns { "ann" } else { "oli" };
        let rest: Vec<&'static str> = ["ann", "nan", "oli"]
            .into_iter()
            .filter(|n| *n != first)
            .collect();
        let mut ann_local = kicked(&mut w, first);
        let mut d: Option<Dex> = None;
        let anew = run(&mut w, &mut d, 120_000, 20, |w, _| {
            let l = w.load().unwrap();
            let head = w.keyholder_epoch();
            l.keyholders_online == 1
                && l.joins_waiting == 0
                && head.is_some()
                && rest.iter().all(|n| w.epoch(n) == head)
        })
        .await;
        assert!(
            anew,
            "the page on its new connection started anew and seated the others again: {:?}",
            w.load()
        );
        let same_gen = db::group(&w.db, CONV).await.unwrap().unwrap().head.gen == gen;
        let rows = exit_rows(&w).await;
        let waiting_after_start = w.load().unwrap().exits_waiting;
        let seat = rows.first().map(|r| r.1);

        // dex's desktop comes with "Help hold keys" on and is promoted
        d = Some(Dex::start(&w.state, &w.db, &dex, None).await);
        let promoted = run(&mut w, &mut d, 180_000, 20, |_, d| {
            let d = d.unwrap();
            d.epoch().is_some() && d.holds()
        })
        .await;
        assert!(
            promoted,
            "dex's desktop is seated and holds keys: {:?}, shown {:?}",
            w.load(),
            d.as_ref().unwrap().shown(0)
        );

        if !anns {
            // The control: ann is kicked while keyholders are online, and an opening takes it
            ann_local = kicked(&mut w, "ann");
            let mut taken = false;
            for _ in 0..180 {
                run(&mut w, &mut d, 1_000, 20, |_, _| false).await;
                if exit_rows(&w).await.is_empty() && w.load().unwrap().exits_waiting == 0 {
                    taken = true;
                    break;
                }
            }
            assert!(taken, "ann's exit was taken by an opening: {:?}", w.load());
        }

        // ann follows again and is seated
        w.member("ann", &ann, ann_local).await;
        let back = run(&mut w, &mut d, 120_000, 20, |w, d| {
            let head = d.unwrap().epoch();
            head.is_some() && w.epoch("ann") == head && w.load().unwrap().joins_waiting == 0
        })
        .await;
        assert!(back, "ann is seated again: {:?}", w.load());

        // nan is kicked; an opening takes that exit
        if nan_leaves {
            if tracing_on() {
                eprintln!("### nan is kicked");
            }
            let _ = kicked(&mut w, "nan");
            let mut taken = false;
            for _ in 0..180 {
                run(&mut w, &mut d, 1_000, 20, |_, _| false).await;
                if exit_rows(&w).await.is_empty() && w.load().unwrap().exits_waiting == 0 {
                    taken = true;
                    break;
                }
            }
            assert!(taken, "nan's exit was taken by an opening: {:?}", w.load());
        }
        let rows_then = exit_rows(&w).await.len();
        let seats = seat_rows(&w).await;
        let row_then = seat.is_some_and(|s| seats.contains(&s));
        let relay_seats = w.load().unwrap().seats;

        // The relay stops: every connection ends with it, each desktop keeps what it kept
        if let Some(page) = w.keyholder.take() {
            let _ = page.stop().await;
        }
        let dex_local = d.take().unwrap().stop();
        let mut locals = HashMap::new();
        for (name, m) in w.members.drain() {
            let mut app = m.app;
            let _ = app.keying.end();
            locals.insert(name, app.keying.local().cloned());
        }
        w.state.gk.on_purge(CONV);

        // It starts again over the same database; dex's desktop and ann's come back
        if tracing_on() {
            eprintln!("### the relay restarts");
        }
        w.state = relay(&w.db).await;
        d = Some(Dex::start(&w.state, &w.db, &dex, dex_local).await);
        let ann_kept = locals.remove("ann").flatten();
        if ann_back {
            w.member("ann", &ann, ann_kept.clone()).await;
        }
        let from = d.as_ref().unwrap().events.len();
        let dex_back = run(&mut w, &mut d, 60_000, 20, |_, d| {
            d.unwrap().epoch().is_some()
        })
        .await;
        assert!(
            dex_back,
            "dex's desktop holds the head again: {:?}",
            w.load()
        );
        // What ann's app (if it came back, it fetched as it started) and dex's hold a few
        // seconds on
        run(&mut w, &mut d, 5_000, 20, |_, _| false).await;
        let first = (
            if ann_back { w.epoch("ann") } else { None },
            d.as_ref().unwrap().epoch(),
        );

        // The channel's progress is read from the stored head: an opening raises its epoch.
        // (A text channel's opening is pushed to its writers only, so ann's app, which
        // writes nothing here, holds what it fetched last.)
        w.pause();
        let start = w.now();
        let stored = db::group(&w.db, CONV).await.unwrap().unwrap().head.epoch;
        let mut last = (stored, start);
        let mut epochs = 0;
        let mut n = 0u32;
        while w.now() < start + WATCH_MIN * 60_000 {
            run(&mut w, &mut d, 500, 500, |_, _| false).await;
            n += 1;
            if n.is_multiple_of(20) {
                let head = db::group(&w.db, CONV).await.unwrap().unwrap().head.epoch;
                if head != last.0 {
                    last = (head, w.now());
                    epochs += 1;
                }
            }
        }
        let quiet_min = (w.now() - last.1) / 60_000;
        let ann_end = if ann_back { w.epoch("ann") } else { None };
        let l = w.load();
        let seats_end = l.as_ref().map_or(0, |l| l.seats);
        let seat_row_end = match seat {
            Some(x) => seat_rows(&w).await.contains(&x),
            None => false,
        };
        // ann's app was away since the restart: it comes back now. Does the channel open
        // epochs within the next 15 minutes?
        let mut late = None;
        if !ann_back {
            w.member("ann", &ann, ann_kept).await;
            let from = db::group(&w.db, CONV).await.unwrap().unwrap().head.epoch;
            let until = w.now() + 15 * 60_000;
            while w.now() < until {
                run(&mut w, &mut d, 500, 500, |_, _| false).await;
            }
            let to = db::group(&w.db, CONV).await.unwrap().unwrap().head.epoch;
            late = Some((from, to, w.epoch("ann"), w.load().map_or(0, |l| l.seats)));
        }
        Seen {
            same_gen,
            rows_after_start: rows.len(),
            waiting_after_start,
            row_then,
            db_seats: seats.len(),
            relay_seats,
            rows_then,
            first,
            ann_end,
            seats_end,
            seat_row_end,
            late,
            head: (stored, last.0),
            epochs,
            quiet_min,
            watched_min: WATCH_MIN,
            missed: l.as_ref().map_or(0, |l| l.missed_deadlines),
            shown: d.as_ref().unwrap().shown(from),
            load: format!("{l:?}"),
        }
    }

    fn told(s: &Seen) -> String {
        format!(
            "The new start kept the generation: {}; exit rows in the database right after it: \
             {} (exits the relay had waiting: {}). Right before the restart: exit rows in the \
             database: {}; the database holds the first kicked seat's row: {}; seats in the \
             database: {}; seats the relay counts: {}. Right after the restart ann's app \
             holds epoch {:?}, dex's {:?}. Watched {} min: the stored head went from epoch {} \
             to {}, in {} steps seen; minutes since the last one at the end: {}; seats the \
             relay counts then: {}; the database holds the first kicked seat's row: {}; \
             ann's app holds epoch {:?}; deadlines missed: {}; dex's app was shown {:?}; \
             load {}. ann's app back after the watch (stored head's epoch then, 15 min on, \
             her app's epoch, the relay's seats): {:?}",
            s.same_gen,
            s.rows_after_start,
            s.waiting_after_start,
            s.rows_then,
            s.row_then,
            s.db_seats,
            s.relay_seats,
            s.first.0,
            s.first.1,
            s.watched_min,
            s.head.0,
            s.head.1,
            s.epochs,
            s.quiet_min,
            s.seats_end,
            s.seat_row_end,
            s.ann_end,
            s.missed,
            s.shown,
            s.load,
            s.late
        )
    }

    /// What every scene wants: the channel goes on opening epochs after the restart (a
    /// refresh comes every 5 minutes at most), and the relay holds the seats it held before.
    fn fine(s: &Seen) -> bool {
        s.quiet_min <= 15 && s.seats_end == s.relay_seats
    }

    /// F1 through the real actor and real apps, second half: the kick that starts the
    /// channel anew is ann's, ann follows again, nan leaves later, the relay restarts, and
    /// ann's app is not online after the restart (her account's seat stays, as any offline
    /// member's does).
    #[tokio::test]
    async fn d4_real_a_channel_goes_on_opening_epochs_after_a_restart_when_a_kicked_member_came_back(
    ) {
        let s = scene(true, true, false).await;
        eprintln!("d4 real, ann kicked and back, nan left: {}", told(&s));
        assert!(
            fine(&s),
            "ann was kicked while no keyholder was online, the channel started anew, and ann \
             followed again; nan left later; the relay restarted while ann's app was closed. {}",
            told(&s)
        );
    }

    /// F1 through the real actor and real apps, first half: the same, but nobody leaves
    /// after ann was seated again. Wanted: the restart costs ann's account its seat no more
    /// than it costs anyone else's.
    #[tokio::test]
    async fn d4_real_a_kicked_member_who_came_back_keeps_her_seat_over_a_restart() {
        let s = scene(true, false, false).await;
        eprintln!("d4 real, ann kicked and back: {}", told(&s));
        assert!(
            fine(&s),
            "ann was kicked while no keyholder was online, the channel started anew, and ann \
             followed again; nobody left since; the relay restarted. {}",
            told(&s)
        );
    }

    /// The control: the same scene as the first test, but the kick that starts the channel
    /// anew is oli's, who never comes back; ann is kicked and follows again under keyholders
    /// that are online.
    #[tokio::test]
    async fn d4_real_control_the_channel_goes_on_opening_epochs_after_a_restart() {
        let s = scene(false, true, false).await;
        eprintln!("d4 real, control: {}", told(&s));
        assert!(fine(&s), "the control. {}", told(&s));
    }

    /// Where the first test's stop ends: the same scene, but ann's app is online again right
    /// after the restart. Her fetch finds no seat, a Join seats her again, and the openings
    /// go through.
    #[tokio::test]
    async fn d4_real_control_with_the_member_online_after_the_restart_a_join_seats_her_again() {
        let s = scene(true, true, true).await;
        eprintln!("d4 real, ann online after the restart: {}", told(&s));
        assert!(
            fine(&s),
            "ann's app was online after the restart. {}",
            told(&s)
        );
    }
}

// ── Round 2: what F7's fix left open (d4-r2-plan.md) ──────────────────────

/// Every due the timer asks of keyholder `k` on `sid` within `rounds` turns of `ms`, built and
/// taken (a Join as a Join, the rest as openings): their kinds.
async fn take_dues(
    s: &mut Sim,
    k: &Person,
    sid: UserId,
    h: &mut Holds,
    ms: u64,
    rounds: usize,
) -> Vec<&'static str> {
    let mut asked = vec![];
    for _ in 0..rounds {
        let out = s.tick(ms).await;
        for (due, piece) in dues(&out, sid) {
            asked.push(gk::due::name(piece.kind));
            let b = if piece.kind == gk::due::JOIN {
                join(&s.g, k, h, &piece, s.now)
            } else {
                opening(&s.g, k, h, &piece, s.now)
            };
            s.commit(sid, due, &b).await.expect("the due is taken");
            h.took(b);
        }
    }
    asked
}

/// `p` on connection `sid` (another device of its account, or the same app after a restart).
fn on(p: &Person, sid: UserId) -> Person {
    Person {
        sid,
        ik: p.ik,
        pair: p.pair.clone(),
        endorsement: p.endorsement.clone(),
        account: p.account,
    }
}

/// Item 1. ann's account leaves the channel's log (or a gate or a new password takes her out:
/// her membership row goes) and the hook asks her seats' exit (`on_log_leave` writes the ask,
/// then posts); the relay stops before the group's actor took it. Nothing in the database told
/// her seat from a live follower's after the restart, so it stayed seated and keyed at every
/// opening. The start enters the exit, its row written with the ask's cause, and the ask goes.
/// bob, not asked, stays.
#[tokio::test]
async fn d4_r2_an_exit_asked_before_a_stop_is_entered_at_the_next_start() {
    let (mut s, _k, _vol, _h, ann, bob) = desktop_held("c:d4-r2x").await;
    db::put_exit_asks(&s.db, &s.id, &[ANN], cause::LEAVE, s.now)
        .await
        .unwrap();
    s.reload().await;
    let (ann_out, ann_row) = exiting(&s, &ann.seat()).await;
    let (bob_out, _) = exiting(&s, &bob.seat()).await;
    let rec = seat_record(&ann.seat());
    let why: Vec<u8> = db::exits(&s.db, &s.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.seat == rec)
        .map(|e| e.cause)
        .collect();
    let left = db::exit_asks(&s.db, &s.id).await.unwrap();
    assert!(
        ann_out && ann_row && why == vec![cause::LEAVE] && !bob_out && left.is_empty(),
        "after the restart ann's seat is in an exit batch: {ann_out}, written: {ann_row} \
         (causes {why:?}); bob's is: {bob_out}; asks left: {left:?}"
    );
}

/// Item 1, the cost of an exit the replay did not need. ann (no cloud history: no membership)
/// follows on two devices, one seat. The first is kicked; her other device still holds the
/// seat, so the live relay keeps it, but `leave_log` asked the exit (it cannot tell), and the
/// relay stopped before the settle. The start exits her seat; her device's next connection is
/// answered from it until the opening takes the exit, then a Join seats her again: one
/// opening and one Join, and nothing is asked any more.
#[tokio::test]
async fn d4_r2_an_exit_the_replay_did_not_need_costs_one_opening_and_one_join() {
    let (mut s, k, vol, mut h, ann, _bob) = desktop_held("c:d4-r2d").await;
    let other = on(&ann, 7);
    assert!(matches!(s.comes(&other).await.0, Fetched::Seated(_)));
    s.leaves(ann.sid, cause::KICK).await;
    assert!(
        s.g.seats.contains_key(&ann.seat()) && !s.g.exits.has(&ann.seat()),
        "her other device holds the seat: no exit"
    );
    db::put_exit_asks(&s.db, &s.id, &[ANN], cause::LEAVE, s.now)
        .await
        .unwrap();
    s.reload().await;
    let replayed = s.g.exits.has(&ann.seat());
    // After the restart: the keyholder back, her device on a new connection
    let vol = Volunteer { sid: 6, ..vol };
    s.volunteers(&vol).await;
    let back = on(&ann, 8);
    let first = s.comes(&back).await.0;
    let asked = take_dues(&mut s, &k, 6, &mut h, 2_100, 3).await;
    let gone = !s.g.seats.contains_key(&ann.seat());
    let again = s.comes(&back).await.0;
    let more = take_dues(&mut s, &k, 6, &mut h, 2_100, 3).await;
    let seated = s.g.seats.contains_key(&ann.seat());
    let left = db::exit_asks(&s.db, &s.id).await.unwrap();
    assert!(
        replayed
            && matches!(first, Fetched::Seated(_))
            && gone
            && again == Fetched::Not
            && seated
            && left.is_empty(),
        "the start exits her seat: {replayed}; her next connection is answered seated: \
         {first:?}; the dues {asked:?} take her seat: {gone}; her fetch then waits: {again:?}; \
         {more:?} seat her again: {seated}; asks left: {left:?}"
    );
}

/// Item 1, order. eve keeps the log: she joins (an eager ask), then leaves (an exit ask, her
/// membership gone), and the relay stops before the group took either: the start exits her and
/// does not seat her again. bob left and joined again with new seat keys (his old seat's exit
/// asked first, then his new seat's eager ask, his membership back): the start exits the old
/// seat and asks the new one. ann left for good after her keys rotated: her old seat exits, and
/// the start's check against her current keys seats nobody in its place.
#[tokio::test]
async fn d4_r2_a_join_then_a_leave_ends_out_and_a_leave_then_a_join_ends_in() {
    let eve = Person::account(9, EVE);
    let (mut s, _k, _vol, _h, ann, _bob) = desktop_held_with("c:d4-r2o", Some(&eve)).await;
    assert!(s.g.seats.contains_key(&eve.seat()));
    // ann: new seat keys, then out of the log
    let ann2 = ann.rotated(2);
    user(&s.db, ANN, Some(&ann.ik)).await;
    publish(&s.db, &ann2).await;
    db::put_exit_asks(&s.db, &s.id, &[ANN], cause::LEAVE, s.now)
        .await
        .unwrap();
    user(&s.db, EVE, Some(&eve.ik)).await;
    publish(&s.db, &eve).await;
    // eve: join (eager), then leave (exit), membership gone
    db::put_eager(&s.db, &s.id, &[eve.ask()], s.now)
        .await
        .unwrap();
    db::put_exit_asks(&s.db, &s.id, &[EVE], cause::LEAVE, s.now + 1)
        .await
        .unwrap();
    // bob: leave with his old keys, then join with new ones, membership back
    let bob = Person::account(3, BOB);
    let bob_old =
        s.g.seats
            .keys()
            .find(|x| x.m.account() == Some(BOB))
            .copied()
            .unwrap();
    user(&s.db, BOB, Some(&bob.ik)).await;
    publish(&s.db, &bob).await;
    member(&s.db, &s.id, BOB).await;
    db::put_exit_asks(&s.db, &s.id, &[BOB], cause::LEAVE, s.now)
        .await
        .unwrap();
    db::put_eager(&s.db, &s.id, &[bob.ask()], s.now + 1)
        .await
        .unwrap();
    s.reload().await;
    let ann_out = s.g.exits.has(&ann.seat()) && !s.g.joins.has(&ann2.seat());
    let eve_out = s.g.exits.has(&eve.seat()) && !s.g.joins.has(&eve.seat());
    let bob_old_out = s.g.exits.has(&bob_old);
    let bob_new = s.g.joins.has(&bob.seat());
    let exits_left = db::exit_asks(&s.db, &s.id).await.unwrap();
    let eager_left = db::eager_asks(&s.db, &s.id).await.unwrap();
    assert!(
        ann_out
            && eve_out
            && bob_old_out
            && bob_new
            && exits_left.is_empty()
            && eager_left == vec![bob.ask()],
        "ann (rotated, then out) exits and her new seat is not asked: {ann_out}; eve (join, \
         then leave) exits and waits for no seat: {eve_out}; bob (leave, then join with new \
         keys): old seat exits {bob_old_out}, new one waits {bob_new}; exit asks left \
         {exits_left:?}, eager asks left {eager_left:?}"
    );
}

/// Item 1: a settled ask goes only while it is no newer than the message that settles it; an
/// ask of the same account made later (its own message still on its way) stays.
#[tokio::test]
async fn d4_r2_a_settle_takes_only_asks_no_newer_than_its_own() {
    let s = Sim::new("c:d4-r2s").await;
    db::put_exit_asks(&s.db, &s.id, &[ANN, BOB], cause::LEAVE, 100)
        .await
        .unwrap();
    db::put_exit_asks(&s.db, &s.id, &[BOB, BOB], cause::GATE, 200)
        .await
        .unwrap();
    db::settle_exit_asks(&s.db, &s.id, &[(ANN, 100), (BOB, 100)])
        .await
        .unwrap();
    let left = db::exit_asks(&s.db, &s.id).await.unwrap();
    assert_eq!(
        left,
        vec![db::ExitAsk {
            account: BOB,
            cause: cause::GATE,
            at: 200
        }]
    );
}

/// Item 2. cat's desktop is removed from her account while the other keyholder is offline, so
/// nobody online can sign her entry's removal; the hook marks the entry (`forced`) and posts,
/// and the relay stops before the group took the message. Before the stop, a turn of the
/// group wrote the keyholder entries from its memory, which knew of no removal yet (cat's own
/// session ended). After the restart, the other keyholder is asked to remove cat's entry.
#[tokio::test]
async fn d4_r2_a_device_removal_on_its_way_at_a_stop_is_asked_after_the_restart() {
    let (mut s, _k, vol, _h, cat, cvol) = two_desktops("c:d4-r2f", false).await;
    let dev = b"cat's desktop".to_vec();
    s.g.holders.device.insert(cvol.pair.kx(), dev.clone());
    s.store.put_holders(&s.g, s.now).await;
    s.turn(|g, now, out| g.leave(1, cause::DISCONNECT, now, out))
        .await;
    // `on_device_removed`: the mark, then the message (lost with the stop)
    let marked = db::force_device_holders(&s.db, &cat.m().seat_id(), &dev)
        .await
        .unwrap();
    // cat's session ends: who is online changed, the actor writes its entries
    s.turn(|g, now, out| g.leave(8, cause::DISCONNECT, now, out))
        .await;
    s.reload().await;
    s.now += 60_000;
    let asked = asked_of(&mut s, 6, &vol, cvol.pair.kx()).await;
    assert!(
        marked == 1 && asked.iter().any(|(_, removes)| *removes),
        "cat's entry marked: {marked}; after the restart the other keyholder was asked \
         (kind, removes cat's entry): {asked:?}"
    );
}

/// Item 3, `no_keyholder_since`. The desktop keyholder goes offline; 50 minutes later the
/// relay restarts (a self-update); 15 minutes after that a seat waits (a guest fetches) and
/// another desktop offers to hold keys. No keyholder was online for 65 minutes, past the hour a Regenesis
/// waits (§5.6): the relay asks it, and takes it. It counted the hour from the restart, so a
/// relay that restarts more often than hourly never started anew.
#[tokio::test]
async fn d4_r2_a_restart_does_not_start_the_hour_without_keyholders_again() {
    let (mut s, _k, _vol, _h, _ann, _bob) = desktop_held("c:d4-r2n").await;
    s.turn(|g, now, out| g.leave(1, cause::DISCONNECT, now, out))
        .await;
    s.now += 50 * 60_000;
    s.reload().await;
    s.now += 15 * 60_000;
    let (v, _, nvol) = desktop(4, EVE);
    let p = Person::guest(5);
    let (_, mut out) = s.comes(&p).await;
    out.extend(s.volunteers(&nvol).await);
    out.extend(s.tick(2_100).await);
    let asked: Vec<(u64, DuePiece)> = dues(&out, 4);
    let kinds: Vec<&str> = asked.iter().map(|(_, p)| gk::due::name(p.kind)).collect();
    let taken = match asked.iter().find(|(_, p)| p.kind == gk::due::REGENESIS) {
        Some((due, piece)) => {
            let b = regenesis(&s.g, &v, piece, s.now);
            s.commit(4, *due, &b).await
        }
        None => Err("none asked".into()),
    };
    assert!(
        taken.is_ok(),
        "65 minutes with no keyholder online, a restart 15 minutes ago: the relay asked \
         {kinds:?}; the Regenesis: {taken:?}"
    );
}

/// Dive 4 round 2 review R2-2: the relay's own downtime is no keyholder's absence. The desktop
/// keyholder is online when the relay stops (its entry's `last_online` the sweep's), and the
/// relay starts again 70 minutes later. Counted from that `last_online` alone, no keyholder had
/// been online for 70 minutes, past the hour a Regenesis waits (§5.6): the first volunteer back,
/// not a keyholder, was asked one before the keyholder could reconnect, and became the set. The
/// hour now ends no sooner than 10 minutes (the sweep's period) after a start: the keyholder
/// comes back within them and is asked what it would have been asked, no Regenesis.
#[tokio::test]
async fn d4_r2_review_a_long_stop_leaves_the_keyholders_time_to_come_back() {
    let (mut s, _k, vol, _h, _ann, _bob) = desktop_held("c:d4-r2w").await;
    s.store.sweep_live(&mut s.g, s.now, false).await;
    s.now += 70 * 60_000;
    s.reload().await;
    let (_, _, nvol) = desktop(4, EVE);
    let p = Person::guest(5);
    let (_, mut out) = s.comes(&p).await;
    out.extend(s.volunteers(&nvol).await);
    for _ in 0..18 {
        out.extend(s.tick(30_000).await);
    }
    let early: Vec<&str> = dues(&out, 4)
        .iter()
        .map(|(_, p)| gk::due::name(p.kind))
        .collect();
    // The keyholder's device reconnects 9 minutes after the start
    let vol = Volunteer { sid: 6, ..vol };
    let mut out = s.volunteers(&vol).await;
    out.extend(s.tick(2_100).await);
    let back: Vec<&str> = dues(&out, 6)
        .iter()
        .map(|(_, p)| gk::due::name(p.kind))
        .collect();
    let to_eve: Vec<&str> = dues(&out, 4)
        .iter()
        .map(|(_, p)| gk::due::name(p.kind))
        .collect();
    let regenesis = gk::due::name(gk::due::REGENESIS);
    assert!(
        early.is_empty() && !back.is_empty() && !back.contains(&regenesis) && to_eve.is_empty(),
        "in the 9 minutes after a 70-minute stop the volunteer was asked {early:?}; the \
         keyholder back was asked {back:?}, the volunteer then {to_eve:?}"
    );
}

/// Dive 4 round 2 review R2-3: a keyholder's page answer that names one seat twice. Postgres
/// refuses one INSERT .. ON CONFLICT DO UPDATE that meets a row twice, and a store failure is
/// the relay's (`page_unstored`: no miss, the page asked again): so the keyholder held those
/// seats' seed welcomes back for good, never counted a miss. The first welcome per seat is
/// taken: the page is stored and done.
#[tokio::test]
async fn d4_r2_review_a_page_naming_a_seat_twice_is_stored_once() {
    let (mut s, _k, _vol, _h, ann, _bob) = desktop_held("c:d4-r2q").await;
    let gen = s.g.gen().unwrap();
    let seed = s.g.head.as_ref().unwrap().sh.header().seed;
    s.g.seed_owed.insert(ann.seat());
    s.now += 20_000;
    assert_eq!(s.g.page_wanted(s.now), Some(vec![ann.seat()]));
    let mut out = vec![];
    let keyed = vec![(ann.seat(), raw(&ann.ik), ann.wire())];
    s.g.ask_page(keyed, vec![], s.now, &mut out);
    let (due, _) = dues(&out, 1).pop().expect("a page due");
    let w = |b: u8| gk::SeedWelcomeOut {
        seat: ann.seat().into(),
        bytes: vec![b; gk::SEED_WELCOME_BYTES],
    };
    let mut out = vec![];
    let (by, took) =
        s.g.take_welcomes(1, due, gen, seed, vec![w(7), w(8)], &mut out)
            .expect("the page's welcomes");
    let stored = s.store.seeds(&s.id, &gen, seed, &by, &took, s.now).await;
    if stored.is_ok() {
        s.g.seeded(by, seed, &took, s.now, &mut out);
    }
    let kept = s
        .store
        .seed_welcome(&s.id, &gen, &ann.seat(), seed)
        .await
        .map(|w| w.bytes);
    assert!(
        took.len() == 1
            && stored.is_ok()
            && s.g.page.is_none()
            && !s.g.seed_owed.contains(&ann.seat())
            && kept == Some(vec![7; gk::SEED_WELCOME_BYTES]),
        "welcomes taken: {}; stored: {stored:?}; page out still: {}; ann owed one still: {}; \
         kept the first: {}",
        took.len(),
        s.g.page.is_some(),
        s.g.seed_owed.contains(&ann.seat()),
        kept.as_deref().map(|b| b[0]).unwrap_or(0)
    );
}

/// Item 3, a seed-welcome page whose store write fails. The relay asks a page of the seats
/// owed a seed welcome; the keyholder answers; the database refuses the write. That is the
/// relay's failure: the keyholder is not counted a miss at the page's deadline (three in an
/// hour propose its removal), and the page is asked again at once, not 60 s later.
#[tokio::test]
async fn d4_r2_a_seed_page_the_store_failed_is_asked_again_at_once_with_no_miss() {
    let (mut s, k, _vol, _h, ann, _bob) = desktop_held("c:d4-r2p").await;
    let gen = s.g.gen().unwrap();
    let seed = s.g.head.as_ref().unwrap().sh.header().seed;
    s.g.seed_owed.insert(ann.seat());
    s.now += 20_000;
    let want = s.g.page_wanted(s.now).expect("a page is wanted");
    assert_eq!(want, vec![ann.seat()]);
    let mut out = vec![];
    let keyed = vec![(ann.seat(), raw(&ann.ik), ann.wire())];
    s.g.ask_page(keyed, vec![], s.now, &mut out);
    let (due, piece) = dues(&out, 1).pop().expect("a page due");
    assert_eq!(piece.kind, gk::due::SEED_WELCOMES);
    let w = gk::SeedWelcomeOut {
        seat: ann.seat().into(),
        bytes: vec![7; gk::SEED_WELCOME_BYTES],
    };
    let mut out = vec![];
    let (by, took) =
        s.g.take_welcomes(1, due, gen, seed, vec![w], &mut out)
            .expect("the page's welcomes");
    // The database refuses the write (`handle_msg`'s `Welcomes`)
    sql(
        &s.db,
        "ALTER TABLE voipc_gk_welcomes RENAME TO voipc_gk_welcomes_away",
    )
    .await;
    let stored = s.store.seeds(&s.id, &gen, seed, &by, &took, s.now).await;
    sql(
        &s.db,
        "ALTER TABLE voipc_gk_welcomes_away RENAME TO voipc_gk_welcomes",
    )
    .await;
    assert!(stored.is_err(), "the write failed");
    s.g.page_unstored(due, s.now);
    let again = s.g.page_wanted(s.now);
    s.now += 61_000;
    s.turn(|g, now, out| g.tick(now, out)).await;
    let missed =
        s.g.holders
            .stats
            .get(&k.wire().kx())
            .map_or(0, |st| st.missed.len());
    assert!(
        again.as_deref() == Some(&[ann.seat()][..]) && missed == 0,
        "the page is asked again at once: {again:?}; misses counted against the keyholder: \
         {missed}"
    );
}
