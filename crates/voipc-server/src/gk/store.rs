//! Where a group's material lives (plan 2a, 2g, 2h): `Memory` for `r:` groups and relays
//! without accounts (nothing reaches the database, a restart is a new generation), `Db`
//! over `accounts::gk` for stored `c:` groups. The actor stores a checked commit here
//! before anything is pushed; answers read seat keying, the keyring and `KRK` welcomes.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use l4f_accounts::store::Store as Db;
use voipc_crypto::group_key::commit::{HolderRef, Joiner, Listed, RowsOut, WelcomeOut};
use voipc_crypto::group_key::tree::BucketTree;
use voipc_crypto::group_key::{
    seat_record, Kind, Leaf, MemberId, Pool, SeatRef, SignedHeader, Via,
};
use voipc_protocol::gk::{self, HeaderIn, KrkIn, NamesListIn, NamesStepIn, RatchetStep};

use super::due::{Exits, Leaving};
use super::group::{GroupState, Head, Seat, Taken};
use super::names::{starts_names, Kept};
use super::snapshot::Ver;
use crate::accounts::gk as db;

/// Why kept, a bit each (`voipc_gk_headers.keep`).
pub const KEEP_RECENT: u32 = 1;
pub const KEEP_KH: u32 = 2;
pub const KEEP_START: u32 = 4;
pub const KEEP_PARENT: u32 = 8;

/// `voipc_gk_names.kind`: an `added` list (`list` its postcard), a header carrying `removed`
/// (`list` the postcard of its `HeaderIn`), the step before the oldest list kept (`names_hash`
/// the hash before it, `list` its list digest).
pub const NAMES_LIST: u8 = 0;
pub const NAMES_REMOVED: u8 = 1;
pub const NAMES_STEP: u8 = 2;

/// A store write that failed: `Check` is rule 16 (a version id used), anything else is
/// `EpochStale{STORE}`.
#[derive(Debug)]
pub enum Fail {
    Check(String),
    Store(String),
}

/// A memory group's material: welcomes until their `EpochIn` went out, rows of the versions
/// current seats reach their keys by, the head epoch's keyring, each keyholder's `KRK`
/// welcome.
#[derive(Default)]
pub struct Mem {
    welcomes: HashMap<SeatRef, (HolderRef, WelcomeOut)>,
    rows: HashMap<(u64, u64), (HolderRef, RowsOut)>,
    keyring: (u32, Vec<u8>),
    krk: HashMap<[u8; 32], KrkIn>,
}

pub struct DbStore {
    pub db: l4f_accounts::store::Store,
    /// This database's `gk_incarnation`.
    pub incarnation: [u8; 16],
}

pub enum Store {
    Memory(Mutex<Mem>),
    Db(Arc<DbStore>),
}

/// A seat's base: the seed, the maker, a welcome (`true`) or a row, and its bytes.
pub type Base = (u32, HolderRef, bool, Vec<u8>);

fn maker(h: &HolderRef) -> db::Maker {
    let mut m = [0u8; 49];
    m[..17].copy_from_slice(&h.m.seat_id());
    m[17..].copy_from_slice(&h.kx);
    m
}

fn member_of(id: &[u8]) -> Option<MemberId> {
    match id.first()? {
        0x01 => Some(MemberId::Account(id.get(1..17)?.try_into().ok()?)),
        0x02 => Some(MemberId::Conn(u32::from_be_bytes(
            id.get(13..17)?.try_into().ok()?,
        ))),
        _ => None,
    }
}

fn holder_of(m: &db::Maker) -> Option<HolderRef> {
    Some(HolderRef {
        m: member_of(&m[..17])?,
        kx: m[17..].try_into().ok()?,
    })
}

/// A seat record (§11.5) back to its seat.
pub fn seat_of(rec: &[u8; 33]) -> Option<SeatRef> {
    Some(SeatRef {
        m: member_of(&rec[..17])?,
        tag_sk: rec[17..25].try_into().ok()?,
        tag_sx: rec[25..].try_into().ok()?,
    })
}

fn stream_of(pieces: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut s = vec![];
    for p in pieces {
        let _ = gk::put_keyring_entry(&mut s, &p);
    }
    s
}

impl Store {
    pub fn memory() -> Store {
        Store::Memory(Mutex::default())
    }

    pub fn stored(&self) -> bool {
        matches!(self, Store::Db(_))
    }

    fn mem(&self) -> Option<std::sync::MutexGuard<'_, Mem>> {
        match self {
            Store::Memory(m) => Some(m.lock().unwrap_or_else(|e| e.into_inner())),
            Store::Db(_) => None,
        }
    }

    /// Writes a checked commit and moves the head (2g); nothing is pushed before this.
    pub async fn commit(&self, g: &GroupState, t: &Taken, now: u64) -> Result<(), Fail> {
        match self {
            Store::Memory(_) => {
                self.commit_mem(t);
                Ok(())
            }
            Store::Db(d) => commit_db(d, g, t, now)
                .await
                .map_err(|e| match e.downcast::<Fail>() {
                    Ok(f) => f,
                    Err(e) => Fail::Store(e.to_string()),
                }),
        }
    }

    fn commit_mem(&self, t: &Taken) {
        let mut m = self.mem().expect("memory");
        let h = t.applied.header.header();
        if h.kind.starts_anew() {
            *m = Mem::default();
        }
        for w in &t.commit.welcomes {
            m.welcomes.insert(w.seat, (t.maker, w.clone()));
        }
        for r in &t.commit.rows {
            m.rows.insert((r.b, r.v), (t.maker, r.clone()));
        }
        if h.kind.opens_epoch() {
            m.keyring = (h.epoch, stream_of([t.commit.keyring.clone()]));
        } else {
            let _ = gk::put_keyring_entry(&mut m.keyring.1, &t.commit.keyring);
        }
        if let Some(set) = &t.applied.keyholders {
            m.krk.retain(|kx, _| set.iter().any(|k| k.kx == *kx));
        }
        for k in &t.commit.krk {
            m.krk.insert(
                k.to.kx,
                KrkIn {
                    from: HolderRef {
                        m: h.signer,
                        kx: k.from_kx,
                    }
                    .into(),
                    bytes: k.bytes.clone(),
                },
            );
        }
    }

    /// Drops a memory group's rows no current version reaches its key by.
    pub fn prune(&self, g: &GroupState) {
        if let Some(mut m) = self.mem() {
            let bases: HashSet<(u64, u64)> =
                g.vers.iter().map(|((b, _), v)| (*b, v.base_v)).collect();
            m.rows.retain(|k, _| bases.contains(k));
            m.welcomes
                .retain(|s, (_, w)| g.seats.contains_key(s) && bases.contains(&(w.b, w.v)));
        }
    }

    /// The welcome or row `seat` reaches `(b, base_v)` by; `index` is its place in the
    /// list.
    pub async fn base(
        &self,
        grp: &str,
        gen: &[u8; 16],
        seat: &SeatRef,
        (b, base_v, index): (u64, u64, usize),
    ) -> Option<Base> {
        match self {
            Store::Memory(_) => {
                let m = self.mem()?;
                if let Some((from, w)) = m
                    .welcomes
                    .get(seat)
                    .filter(|(_, w)| (w.b, w.v) == (b, base_v))
                {
                    return Some((w.s, *from, true, w.bytes.clone()));
                }
                let (from, rows) = m.rows.get(&(b, base_v))?;
                let (row, s) = rows.row(index)?;
                Some((s as u32, *from, false, row.to_vec()))
            }
            Store::Db(d) => {
                let rec = seat_record(seat);
                let welcomes = db::welcomes_of(&d.db, grp, gen, &rec).await.ok()?;
                if let Some(w) = welcomes
                    .into_iter()
                    .find(|w| w.kind == db::WelcomeKind::Seat && w.version == Some((b, base_v)))
                {
                    return Some((w.s, holder_of(&w.maker)?, true, w.bytes));
                }
                let r = db::row(&d.db, grp, gen, b, base_v, &rec).await.ok()??;
                Some((r.s, holder_of(&r.maker)?, false, r.bytes))
            }
        }
    }

    /// Every session of `seat` had its answer queued: a memory group's welcome goes (2b).
    pub fn welcomed(&self, seat: &SeatRef) {
        if let Some(mut m) = self.mem() {
            m.welcomes.remove(seat);
        }
    }

    /// A seed welcome waiting for `seat` under `s` (stored groups; a memory group's went out
    /// at once).
    pub async fn seed_welcome(
        &self,
        grp: &str,
        gen: &[u8; 16],
        seat: &SeatRef,
        s: u32,
    ) -> Option<gk::SeedWelcomeIn> {
        let Store::Db(d) = self else { return None };
        let w = db::welcome(
            &d.db,
            grp,
            gen,
            &seat_record(seat),
            db::WelcomeKind::Seed,
            s,
        )
        .await
        .ok()??;
        Some(gk::SeedWelcomeIn {
            s,
            from: holder_of(&w.maker)?.into(),
            bytes: w.bytes,
        })
    }

    /// The head epoch's keyring stream from piece `from_j` on.
    pub async fn keyring(&self, grp: &str, gen: &[u8; 16], epoch: u32, from_j: u32) -> Vec<u8> {
        match self {
            Store::Memory(_) => {
                let m = self.mem().expect("memory");
                if m.keyring.0 != epoch {
                    return vec![];
                }
                gk::keyring_entries(&m.keyring.1)
                    .ok()
                    .and_then(|e| {
                        e.skip(from_j as usize)
                            .map(|x| x.map(<[u8]>::to_vec))
                            .collect::<Result<Vec<_>, _>>()
                            .ok()
                    })
                    .map(stream_of)
                    .unwrap_or_default()
            }
            Store::Db(d) => {
                let mut pieces = db::keyring(&d.db, grp, gen, epoch)
                    .await
                    .unwrap_or_default();
                pieces.sort_by_key(|p| p.j);
                stream_of(
                    pieces
                        .into_iter()
                        .filter(|p| p.j >= from_j)
                        .map(|p| p.bytes),
                )
            }
        }
    }

    /// The `KRK` welcome to the keyholder `kx`, made at `epoch` (the head's keyholder header).
    pub async fn krk(&self, grp: &str, gen: &[u8; 16], epoch: u32, kx: &[u8; 32]) -> Option<KrkIn> {
        match self {
            Store::Memory(_) => self.mem()?.krk.get(kx).cloned(),
            Store::Db(d) => {
                let k = db::krk(&d.db, grp, gen, epoch, kx).await.ok()??;
                Some(KrkIn {
                    from: holder_of(&k.maker)?.into(),
                    bytes: k.bytes,
                })
            }
        }
    }

    /// Exits entered since `from` (`seq`), kept so open batches survive a restart.
    pub async fn exits_entered(&self, grp: &str, g: &GroupState, from: u64, now: u64) {
        let (Store::Db(d), Some(gen)) = (self, g.gen()) else {
            return;
        };
        let new: Vec<db::Exit> = g
            .exits
            .closed
            .iter()
            .chain(g.exits.open.iter())
            .flat_map(|b| b.exits.iter())
            .filter(|l| l.exit.seq >= from)
            .map(|l| db::Exit {
                seq: l.exit.seq,
                gen,
                seat: seat_record(&l.exit.seat),
                cause: l.cause,
                at: now,
            })
            .collect();
        if !new.is_empty() {
            if let Err(e) = db::add_exits(&d.db, grp, &new).await {
                tracing::warn!(group = grp, "keeping exits failed: {e}");
            }
        }
    }

    /// The step before the oldest names list kept, made by a sweep (kind 2): a "gone" answer
    /// after a restart still has it.
    pub async fn names_step(&self, grp: &str, gen: &[u8; 16], step: &NamesStepIn) {
        let Store::Db(d) = self else { return };
        let n = db::Names {
            gen: *gen,
            epoch: step.epoch,
            j: step.join,
            kind: NAMES_STEP,
            time: step.time,
            names_hash: step.before,
            list: step.list.to_vec(),
        };
        if let Err(e) = db::put_names(&d.db, grp, &[n]).await {
            tracing::warn!(group = grp, "keeping a names step failed: {e}");
        }
    }

    /// The self-rows an account keeps for its seat `seat` under seed `s` (§3.11,
    /// `voipc_gk_self` kind 0): a session of the account that has lost `s_m` (a restart, a
    /// second device) opens its seat's row with them. Stored groups only.
    pub async fn self_rows(
        &self,
        grp: &str,
        gen: &[u8; 16],
        seat: &SeatRef,
        s: u32,
    ) -> Vec<gk::SelfRowIn> {
        let (Store::Db(d), Some(account)) = (self, seat.m.account()) else {
            return vec![];
        };
        const Q: &str = "SELECT sealed FROM voipc_gk_self WHERE grp = $1 AND account = $2
             AND gen = $3 AND seed = $4 AND tag_sk = $5 AND tag_sx = $6 AND kind = $7";
        let rows: Result<Vec<Vec<u8>>, sqlx::Error> = match &d.db {
            Db::Lite(b) => {
                sqlx::query_scalar(Q)
                    .bind(grp)
                    .bind(&account[..])
                    .bind(&gen[..])
                    .bind(i64::from(s))
                    .bind(&seat.tag_sk[..])
                    .bind(&seat.tag_sx[..])
                    .bind(i16::from(gk::self_row::SELF_ROW))
                    .fetch_all(&b.0)
                    .await
            }
            Db::Pg(b) => {
                sqlx::query_scalar(Q)
                    .bind(grp)
                    .bind(&account[..])
                    .bind(&gen[..])
                    .bind(i64::from(s))
                    .bind(&seat.tag_sk[..])
                    .bind(&seat.tag_sx[..])
                    .bind(i16::from(gk::self_row::SELF_ROW))
                    .fetch_all(&b.0)
                    .await
            }
        };
        rows.unwrap_or_default()
            .into_iter()
            .map(|sealed| gk::SelfRowIn {
                group: grp.to_string(),
                gen: *gen,
                seed: s,
                sk: seat.tag_sk,
                sx: seat.tag_sx,
                kind: gk::self_row::SELF_ROW,
                sealed,
            })
            .collect()
    }

    /// A page of the eager seats of a stored group's new start (plan 2d): the accounts that
    /// keep `conv`'s log with published seat keys, after `after`, each as a joiner with its
    /// identity key. An account with no identity key on file is skipped.
    pub async fn eager_seats(
        &self,
        conv: &str,
        after: Option<&[u8; 16]>,
        limit: u32,
    ) -> Result<Vec<([u8; 16], Joiner)>> {
        let Store::Db(d) = self else {
            return Ok(vec![]);
        };
        let page = db::members_with_seat_keys(&d.db, conv, after, limit).await?;
        let mut out = Vec::with_capacity(page.len());
        for (account, k) in page {
            let Some(ik) = identity_key(&d.db, &account).await? else {
                continue;
            };
            let wire = gk::EndorsedPair {
                origin: gk::origin::VAULT_SEAT,
                u: 0,
                kem: k.kem,
                dh: k.dh,
                n: k.n,
                made: k.made,
                sig: k.sig,
            };
            let Ok(pair) =
                voipc_crypto::group_key::wire::pair(&wire, gk::GkMember::Account(account))
            else {
                continue;
            };
            out.push((
                account,
                Joiner {
                    seat: pair.keys.seat(MemberId::Account(account)),
                    ik,
                    keys: pair.keys,
                    endorsement: pair.endorsement,
                    returning: false,
                },
            ));
        }
        Ok(out)
    }

    /// A stored group as the database holds it, into `g`. An old incarnation's group is
    /// reset and starts a new generation at its next fetch (2i). Every connection seat is
    /// an exit at start: its connection is gone.
    pub async fn load(&self, g: &mut GroupState) -> Result<()> {
        let Store::Db(d) = self else { return Ok(()) };
        let grp = g.id.clone();
        // Material of a commit that never moved the head: this actor is its only writer
        db::sweep_orphans(&d.db, &grp, None).await?;
        let Some(row) = db::group(&d.db, &grp).await? else {
            return Ok(());
        };
        let gens = db::gens(&d.db, &grp).await?;
        g.gens = gens.iter().map(|(gen, _)| *gen).collect();
        if !g.gens.contains(&row.head.gen) {
            g.gens.push(row.head.gen);
        }
        g.exits = Exits::new(row.head.exits_next);
        if row.head.incarnation != d.incarnation {
            while db::reset_step(&d.db, &grp, &row.head.gen).await? > 0 {}
            g.new_gen = true;
            return Ok(());
        }
        let gen = row.head.gen;
        let kind = g.kind;
        let decode = |h: &db::Header| SignedHeader::decode(&h.body, &h.sig, kind, &grp).ok();
        let mut headers: HashMap<[u8; 32], SignedHeader> = HashMap::new();
        for h in db::headers(&d.db, &grp, &gen).await? {
            if let Some(sh) = decode(&h) {
                headers.insert(sh.d(), sh);
            }
        }
        let Some(head) = headers.get(&row.head.d).cloned() else {
            g.new_gen = true;
            return Ok(());
        };
        let hd = head.header();
        let opening = match hd.kind {
            Kind::Join => db::opening(&d.db, &grp, &gen, hd.epoch)
                .await?
                .and_then(|h| decode(&h))
                .unwrap_or_else(|| head.clone()),
            _ => head.clone(),
        };
        let kh = headers
            .get(&head.kh())
            .cloned()
            .unwrap_or_else(|| head.clone());
        let parent_of = |sh: &SignedHeader| {
            (sh.header().kind == Kind::Regenesis)
                .then(|| headers.get(&sh.header().parent).cloned())
                .flatten()
        };
        g.khs = headers
            .values()
            .filter(|h| h.header().kind.sets_keyholders())
            .map(|h| (h.d(), (h.clone(), parent_of(h))))
            .collect();
        let mut recent: Vec<SignedHeader> = headers.values().cloned().collect();
        recent.sort_by_key(|h| (h.header().epoch, h.header().join));
        let from = recent.len().saturating_sub(64);
        g.recent = recent.into_iter().skip(from).collect();
        // Current versions, and how each is reached
        let lists = db::current_lists(&d.db, &grp, &gen).await?;
        let mut leaves = Vec::with_capacity(lists.len());
        for l in &lists {
            let seats: Vec<SeatRef> = l.seats.iter().filter_map(seat_of).collect();
            leaves.push(Listed {
                leaf: Leaf {
                    b: l.b,
                    v: l.v,
                    pool: l.pool,
                    seats: seats.len() as u16,
                    list: l.digest,
                    via: l.via.map_or(Via::Row, |from| Via::Ratchet { from }),
                },
                seats,
            });
            let mut ratchets = vec![];
            let (mut at, mut via, mut e) = (l.v, l.via, l.epoch_made);
            while let Some(from) = via {
                ratchets.push(RatchetStep { e, from, to: at });
                let Some(prev) = db::list(&d.db, &grp, &gen, l.b, from).await? else {
                    break;
                };
                (at, via, e) = (from, prev.via, prev.epoch_made);
            }
            ratchets.reverse();
            g.vers.insert(
                (l.b, l.v),
                Ver {
                    base_v: l.base_v,
                    ratchets,
                    made: (l.epoch_made, 0),
                    maker: HolderRef {
                        m: MemberId::Conn(0),
                        kx: [0; 32],
                    },
                },
            );
            g.used_v.insert(l.v);
        }
        leaves.sort_by_key(|l| l.leaf.b);
        let flat: Vec<Leaf> = leaves.iter().map(|l| l.leaf).collect();
        g.tree = Arc::new(BucketTree::new(&flat)?);
        g.leaves = Arc::new(leaves);
        for s in db::seats(&d.db, &grp, &gen).await? {
            if let Some(seat) = seat_of(&s.seat) {
                g.seats.insert(
                    seat,
                    Seat {
                        b: s.b,
                        seed: s.seed,
                        dh: s.dh,
                        account: s.account,
                    },
                );
            }
        }
        for s in db::seals(&d.db, &grp, &gen, hd.epoch).await? {
            g.seals.insert((s.b, s.v), s.bytes);
        }
        // Exits not dealt with, in batches of the cap; one whose seat no longer sits (a
        // Regenesis since) needs none
        let mut left = vec![];
        for x in db::exits(&d.db, &grp).await? {
            if x.gen != gen {
                continue;
            }
            let Some((seat, s)) = seat_of(&x.seat).and_then(|r| Some((r, g.seats.get(&r)?))) else {
                continue;
            };
            left.push(Leaving {
                exit: voipc_crypto::group_key::commit::Exit {
                    seq: x.seq,
                    seat,
                    b: s.b,
                },
                cause: x.cause,
            });
        }
        left.sort_by_key(|l| l.exit.seq);
        g.exits.push_closed(0, left, hd.gated);
        // A gated group's names: lists, removal headers, the step before the oldest
        let mut lists = vec![];
        let mut removals = vec![];
        let mut step: Option<NamesStepIn> = None;
        for n in db::names(&d.db, &grp, &gen, (0, 0), (hd.epoch, hd.join)).await? {
            match n.kind {
                NAMES_LIST => lists.push(Kept {
                    gen,
                    list: NamesListIn {
                        time: n.time,
                        epoch: n.epoch,
                        join: n.j,
                        added: n.list,
                    },
                    hash: n.names_hash,
                }),
                NAMES_REMOVED => {
                    if let Some(sh) = postcard::from_bytes::<HeaderIn>(&n.list)
                        .ok()
                        .and_then(|h| SignedHeader::decode(&h.body, &h.sig, kind, &grp).ok())
                    {
                        removals.push((gen, sh));
                    }
                }
                NAMES_STEP => {
                    if let Ok(list) = <[u8; 32]>::try_from(n.list.as_slice()) {
                        step = Some(NamesStepIn {
                            before: n.names_hash,
                            time: n.time,
                            epoch: n.epoch,
                            join: n.j,
                            list,
                        });
                    }
                }
                _ => {}
            }
        }
        g.names.restore(lists, removals, step.map(|s| (gen, s)));
        g.holders.set_to(kh.header().keyholders.clone(), |_| None);
        g.rolls = row.head.rolls;
        g.gen_time = row.head.gen_time;
        g.head = Some(Head {
            parent: parent_of(&head),
            kh,
            opening,
            opened_ms: row.updated,
            sh: head,
        });
        Ok(())
    }
}

async fn commit_db(d: &DbStore, g: &GroupState, t: &Taken, now: u64) -> Result<()> {
    let s = &d.db;
    let grp = g.id.as_str();
    let a = &t.applied;
    let sh = &a.header;
    let h = sh.header();
    let gen = h.gen;
    let maker_b = maker(&t.maker);
    let c = db::begin_commit(s, grp).await?;
    let vids: Vec<(u64, u64)> = a.made.iter().map(|l| (l.leaf.b, l.leaf.v)).collect();
    if let Some(v) = db::put_vids(s, grp, c, &gen, &vids).await? {
        return Err(Fail::Check(format!("rule 16: version id {v} was used")).into());
    }
    let vers: HashMap<(u64, u64), &Ver> = t.vers.iter().map(|(k, v)| (*k, v)).collect();
    let lists: Vec<db::List> = a
        .made
        .iter()
        .map(|l| db::List {
            b: l.leaf.b,
            v: l.leaf.v,
            pool: l.leaf.pool,
            via: match l.leaf.via {
                Via::Ratchet { from } => Some(from),
                Via::Row => None,
            },
            base_v: vers
                .get(&(l.leaf.b, l.leaf.v))
                .map_or(l.leaf.v, |v| v.base_v),
            epoch_made: h.epoch,
            epoch_until: None,
            seats: l.seats.iter().map(seat_record).collect(),
            digest: l.leaf.list,
            current: false,
        })
        .collect();
    if let Some((b, v)) = db::put_lists(s, grp, c, &gen, &lists).await? {
        return Err(Fail::Check(format!("rule 16: version ({b}, {v}) was stored")).into());
    }
    let seated: HashMap<SeatRef, u64> = a.seated.iter().map(|(s, v)| (*s, v.b)).collect();
    let keys: HashMap<SeatRef, [u8; 33]> = t
        .due
        .due
        .joiners
        .iter()
        .map(|j| (j.seat, j.keys.dh_bytes()[..].try_into().unwrap_or([0; 33])))
        .collect();
    let held: HashMap<SeatRef, u32> = a.held.iter().copied().collect();
    let new: Vec<db::Seat> = a
        .seated
        .iter()
        .map(|(seat, v)| db::Seat {
            seat: seat_record(seat),
            dh: keys.get(seat).copied().unwrap_or([0; 33]),
            b: v.b,
            pool: Pool::of(&seat.m),
            seed: held.get(seat).copied().unwrap_or(h.seed),
            last_use: now,
            account: seat.m.account(),
        })
        .collect();
    db::put_new_seats(s, grp, c, &gen, &new).await?;
    let moves: Vec<(db::SeatRec, u64)> = a
        .made
        .iter()
        .flat_map(|l| l.seats.iter().map(move |s| (s, l.leaf.b)))
        .filter(|(s, b)| !seated.contains_key(s) && g.seats.get(s).is_some_and(|x| x.b != *b))
        .map(|(s, b)| (seat_record(s), b))
        .collect();
    db::put_moves(s, grp, c, &gen, &moves).await?;
    let lists_by: HashMap<(u64, u64), &Listed> =
        a.made.iter().map(|l| ((l.leaf.b, l.leaf.v), l)).collect();
    let mut rows = vec![];
    for r in &t.commit.rows {
        let Some(l) = lists_by.get(&(r.b, r.v)) else {
            continue;
        };
        for (i, seat) in l.seats.iter().enumerate() {
            if let Some((bytes, seed)) = r.row(i) {
                rows.push(db::BucketRow {
                    b: r.b,
                    v: r.v,
                    seat: seat_record(seat),
                    s: seed as u32,
                    maker: maker_b,
                    bytes: bytes.to_vec(),
                    epoch_made: h.epoch,
                });
            }
        }
    }
    db::put_rows(s, grp, c, &gen, &rows).await?;
    let mut welcomes: Vec<db::Welcome> = t
        .commit
        .welcomes
        .iter()
        .map(|w| db::Welcome {
            seat: seat_record(&w.seat),
            kind: db::WelcomeKind::Seat,
            s: w.s,
            version: Some((w.b, w.v)),
            maker: maker_b,
            bytes: w.bytes.clone(),
            made: now,
        })
        .collect();
    welcomes.extend(t.commit.seed_welcomes.iter().map(|w| db::Welcome {
        seat: seat_record(&w.seat),
        kind: db::WelcomeKind::Seed,
        s: h.seed,
        version: None,
        maker: maker_b,
        bytes: w.bytes.clone(),
        made: now,
    }));
    db::put_welcomes(s, grp, c, &gen, &welcomes).await?;
    let seals: Vec<db::Seal> = t
        .commit
        .seals
        .iter()
        .map(|x| db::Seal {
            epoch: h.epoch,
            b: x.b,
            v: x.v,
            bytes: x.bytes.clone(),
        })
        .collect();
    db::put_seals(s, grp, c, &gen, &seals).await?;
    db::put_keyring(
        s,
        grp,
        c,
        &gen,
        &[db::KeyringPiece {
            epoch: h.epoch,
            j: h.join,
            bytes: t.commit.keyring.clone(),
        }],
    )
    .await?;
    let krk: Vec<db::Krk> = t
        .commit
        .krk
        .iter()
        .map(|k| db::Krk {
            epoch: h.epoch,
            holder: k.to.kx,
            maker: maker(&HolderRef {
                m: h.signer,
                kx: k.from_kx,
            }),
            bytes: k.bytes.clone(),
        })
        .collect();
    db::put_krk(s, grp, c, &gen, &krk).await?;
    let mut keep = KEEP_RECENT;
    if h.kind.sets_keyholders() {
        keep |= KEEP_KH;
    }
    if h.kind.starts_anew() {
        keep |= KEEP_START;
    }
    let header = db::Header {
        d: sh.d(),
        gen,
        epoch: h.epoch,
        j: h.join,
        kind: h.kind,
        time: h.time,
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
        keep,
    };
    let parent_keep: Vec<([u8; 32], u32)> = t
        .head
        .parent
        .iter()
        .map(|p| (p.d(), KEEP_PARENT | KEEP_RECENT))
        .collect();
    // A gated group's names (2g): the list of a Join and of each header a fold starts from
    // (the gate-on opening is both 0 and 1), and each header carrying a `removed` list
    let was_gated = g
        .head
        .as_ref()
        .is_some_and(|x| x.sh.header().gated && x.sh.header().gen == gen);
    let mut names: Vec<db::Names> = vec![];
    if h.gated && (h.kind == Kind::Join || starts_names(sh, was_gated)) {
        names.push(db::Names {
            gen,
            epoch: h.epoch,
            j: h.join,
            kind: NAMES_LIST,
            time: h.time,
            names_hash: h.names_hash,
            list: postcard::to_allocvec(h.added_list())?,
        });
    }
    if h.gated && matches!(&h.removed, voipc_crypto::group_key::Removed::List(l) if !l.is_empty()) {
        names.push(db::Names {
            gen,
            epoch: h.epoch,
            j: h.join,
            kind: NAMES_REMOVED,
            time: h.time,
            names_hash: h.names_hash,
            list: postcard::to_allocvec(&HeaderIn {
                body: sh.body().to_vec(),
                sig: sh.sig().to_vec(),
            })?,
        });
    }
    let upto = if h.kind.starts_anew() {
        a.exits_done.iter().copied().max().unwrap_or(0)
    } else {
        h.exits_upto
    };
    let head = db::Head {
        kind: g.kind,
        gen,
        gen_time: if t.new_gen { now } else { g.gen_time },
        incarnation: d.incarnation,
        d: sh.d(),
        epoch: h.epoch,
        join: h.join,
        exits_next: g.exits.next,
        rolls: a.rolls,
        gated: h.gated,
    };
    let drops: Vec<u64> = t.commit.drops.clone();
    let moved = db::move_head(
        s,
        grp,
        c,
        &head,
        &db::HeadMove {
            was: t.was,
            headers: &[header],
            keep: &parent_keep,
            drops: &drops,
            retire_all: h.kind == Kind::Regenesis,
            exits_upto: upto,
            names: &names,
        },
    )
    .await?;
    if moved != db::Moved::Done {
        return Err(Fail::Store(format!("{moved:?}")).into());
    }
    Ok(())
}

/// An account's identity key, raw (the 0x05 type byte dropped), as `voipc_identity` holds it.
async fn identity_key(db: &Db, account: &[u8; 16]) -> Result<Option<[u8; 32]>> {
    const Q: &str = "SELECT identity_key FROM voipc_identity WHERE account = $1";
    let key: Option<Vec<u8>> = match db {
        Db::Lite(b) => {
            sqlx::query_scalar(Q)
                .bind(&account[..])
                .fetch_optional(&b.0)
                .await?
        }
        Db::Pg(b) => {
            sqlx::query_scalar(Q)
                .bind(&account[..])
                .fetch_optional(&b.0)
                .await?
        }
    };
    Ok(key.and_then(|k| match k.as_slice() {
        [0x05, rest @ ..] if rest.len() == 32 => rest.try_into().ok(),
        k if k.len() == 32 => k.try_into().ok(),
        _ => None,
    }))
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Check(s) | Fail::Store(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Fail {}
