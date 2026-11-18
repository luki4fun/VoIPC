//! The head as the actor last took it (plan 2a): a `HeadSnapshot` published as an `Arc`
//! at each taken commit, from which seated fetches are answered outside the actor, and the
//! `HeadView` the plain-post check reads.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::sync::Arc;

use voipc_crypto::group_key::commit::{Commit, HolderRef, Listed};
use voipc_crypto::group_key::timers::HOLD_MS;
use voipc_crypto::group_key::tree::BucketTree;
use voipc_crypto::group_key::{seat_record, Kind, SeatRef, SignedHeader};
use voipc_protocol::gk::{
    FloorRef, HeaderIn, InPiece, LeafIn, PathIn, RatchetStep, SeatKeying, WalkLinkIn,
};

/// Keyholder headers of a generation by `D`, a Regenesis with its parent.
pub type Khs = HashMap<[u8; 32], (SignedHeader, Option<SignedHeader>)>;

/// How a version's seats reach its key: a welcome or a row to `(b, base_v)`, then the
/// ratchet steps since; and the `(epoch, join)` it was made at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ver {
    pub base_v: u64,
    pub ratchets: Vec<RatchetStep>,
    pub made: (u32, u32),
    /// Who made its welcomes or rows.
    pub maker: HolderRef,
}

pub fn header_in(sh: &SignedHeader) -> HeaderIn {
    HeaderIn {
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
    }
}

pub fn link(sh: &SignedHeader, parent: Option<&SignedHeader>) -> WalkLinkIn {
    WalkLinkIn {
        header: header_in(sh),
        parent: parent.map(header_in),
    }
}

/// What the plain-post check needs (rule 1f.1): the head's generation and epoch, and when
/// that epoch opened (relay ms), so the one before stays good for `HOLD_MS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeadView {
    pub gen: [u8; 16],
    pub epoch: u32,
    pub opened_ms: u64,
}

impl HeadView {
    /// Whether a post under `(gen, epoch)` may go out at `now`.
    pub fn post_ok(&self, gen: &[u8; 16], epoch: u32, now: u64) -> bool {
        *gen == self.gen
            && (epoch == self.epoch
                || (epoch.checked_add(1) == Some(self.epoch)
                    && now < self.opened_ms.saturating_add(HOLD_MS)))
    }
}

/// The head and everything a seated fetch is answered from.
#[derive(Clone)]
pub struct HeadSnapshot {
    pub head: SignedHeader,
    /// A Regenesis head's parent.
    pub parent: Option<SignedHeader>,
    pub opening: SignedHeader,
    /// Keyholder headers of this generation by `D`, a Regenesis with its parent.
    pub khs: Arc<Khs>,
    /// The headers kept in a row up to the head, oldest first.
    pub recent: Arc<Vec<SignedHeader>>,
    pub leaves: Arc<Vec<Listed>>,
    pub tree: Arc<BucketTree>,
    pub vers: Arc<HashMap<(u64, u64), Ver>>,
    pub seals: Arc<HashMap<(u64, u64), Vec<u8>>>,
}

impl HeadSnapshot {
    pub fn gen(&self) -> [u8; 16] {
        self.head.header().gen
    }

    /// The current version `seat` sits in, and its index in that list.
    pub fn version_of(&self, seat: &SeatRef) -> Option<(&Listed, usize)> {
        let rec = seat_record(seat);
        self.leaves.iter().find_map(|l| {
            l.seats
                .binary_search_by_key(&rec, seat_record)
                .ok()
                .map(|i| (l, i))
        })
    }

    /// The keyholder links from the one the head's `kh_parent` names back to the floor's
    /// (not included), or to the generation's start (included), newest first. None when the
    /// floor is the head, or a keyholder header met on the way (a floor at a kh-setting
    /// header names itself as its `kh`, which the walk from the head's `kh_parent` never
    /// meets).
    pub fn walk(&self, have: Option<&FloorRef>) -> Vec<WalkLinkIn> {
        let gen = self.gen();
        let floor = have.filter(|f| f.gen == gen);
        let mut out = Vec::new();
        let mut d = self.head.header().kh_parent;
        if self.head.header().kind == Kind::Genesis || floor.is_some_and(|f| f.d == self.head.d()) {
            return out;
        }
        while floor.is_none_or(|f| d != f.kh && d != f.d) {
            let Some((sh, parent)) = self.khs.get(&d) else {
                break;
            };
            out.push(link(sh, parent.as_ref()));
            if sh.header().kind == Kind::Genesis
                || (sh.header().kind == Kind::Regenesis && have.is_none())
            {
                break;
            }
            d = sh.header().kh_parent;
        }
        out
    }

    /// The headers after the floor up to the head (not included), oldest first: `None`
    /// when the floor is not among those kept in a row.
    pub fn chain(&self, have: &FloorRef) -> Option<Vec<HeaderIn>> {
        let at = self.recent.iter().position(|h| h.d() == have.d)?;
        let n = self.recent.len().saturating_sub(1);
        Some(
            self.recent
                .get(at + 1..n)
                .unwrap_or_default()
                .iter()
                .map(header_in)
                .collect(),
        )
    }

    /// The head part of an answer: the head (with a Regenesis's parent), the head epoch's
    /// opening when the head is a Join, the walk or chain since `have`, and `kh` unless the
    /// connection was last sent that very header (`kh_sent`): a restarted member, or one
    /// whose floor another device raised, needs it for `check_signer` (1c).
    pub fn head_piece(
        &self,
        have: Option<&FloorRef>,
        kh_sent: Option<[u8; 32]>,
        keyholder: bool,
    ) -> InPiece {
        let h = self.head.header();
        let chain = match have {
            Some(f) if keyholder && f.gen == self.gen() => self.chain(f),
            _ => None,
        };
        let walk = if chain.is_some() {
            vec![]
        } else {
            self.walk(have)
        };
        let kh = have
            .filter(|f| f.gen == self.gen() && kh_sent != Some(f.kh))
            .and_then(|f| self.khs.get(&f.kh))
            .map(|(sh, _)| header_in(sh));
        InPiece {
            chain: chain.unwrap_or_default(),
            walk,
            kh,
            head: Some(link(&self.head, self.parent.as_ref())),
            opening: (h.kind == Kind::Join).then(|| header_in(&self.opening)),
            ..InPiece::default()
        }
    }

    /// A seat's leaf, path and seal at the head.
    pub fn seat_piece(&self, seat: &SeatRef, piece: &mut InPiece) {
        let Some((l, _)) = self.version_of(seat) else {
            return;
        };
        piece.leaf = Some(LeafIn::from(l.leaf));
        piece.path = self
            .tree
            .path_of(l.leaf.b)
            .and_then(|p| PathIn::try_from(p).ok());
        piece.seal = self.seals.get(&(l.leaf.b, l.leaf.v)).cloned();
    }

    /// Whether `seat`'s version was made at or after the floor: it needs its keying again.
    /// At the floor too: a floor taken from a pushed header, or from another device's vault
    /// page, is no proof this connection holds that version's `BK`.
    pub fn moved_since(&self, seat: &SeatRef, have: Option<&FloorRef>) -> bool {
        let Some((l, _)) = self.version_of(seat) else {
            return false;
        };
        let made = self
            .vers
            .get(&(l.leaf.b, l.leaf.v))
            .map_or((0, 0), |v| v.made);
        match have {
            Some(f) if f.gen == self.gen() => made >= (f.epoch, f.join),
            _ => true,
        }
    }

    /// The keying of `seat` with what the store holds of its base (`welcome` or `row`),
    /// steps alone when it holds neither any more (part 13).
    pub fn keying(
        &self,
        seat: &SeatRef,
        base: Option<(u32, HolderRef, bool, Vec<u8>)>,
    ) -> Option<SeatKeying> {
        let (l, _) = self.version_of(seat)?;
        let ver = self.vers.get(&(l.leaf.b, l.leaf.v))?;
        let k = match base {
            Some((s, from, welcome, bytes)) => SeatKeying {
                b: l.leaf.b,
                base_v: ver.base_v,
                s,
                from: from.into(),
                welcome: welcome.then(|| bytes.clone()),
                row: (!welcome).then_some(bytes),
                ratchets: ver.ratchets.clone(),
            },
            None if !ver.ratchets.is_empty() => SeatKeying {
                b: l.leaf.b,
                base_v: ver.base_v,
                s: 0,
                from: ver.maker.into(),
                welcome: None,
                row: None,
                ratchets: ver.ratchets.clone(),
            },
            None => return None,
        };
        Some(k)
    }

    /// The keying a push of the header made at `at` carries to `seat` (2f, 3f): only when
    /// that header made its version, from the commit's own welcome or rows, or the one
    /// ratchet step from the version before (which the member held). A member pushed the
    /// header with no keying would move its floor and hold no `BK` of its version.
    pub fn pushed_keying(
        &self,
        seat: &SeatRef,
        at: (u32, u32),
        commit: &Commit,
        maker: HolderRef,
    ) -> Option<SeatKeying> {
        let (l, i) = self.version_of(seat)?;
        let (b, v) = (l.leaf.b, l.leaf.v);
        let ver = self.vers.get(&(b, v)).filter(|x| x.made == at)?;
        if ver.base_v != v {
            let step = *ver.ratchets.last()?;
            return Some(SeatKeying {
                b,
                base_v: step.from,
                s: 0,
                from: ver.maker.into(),
                welcome: None,
                row: None,
                ratchets: vec![step],
            });
        }
        if let Some(w) = commit
            .welcomes
            .iter()
            .find(|w| w.seat == *seat && (w.b, w.v) == (b, v))
        {
            return Some(SeatKeying {
                b,
                base_v: v,
                s: w.s,
                from: maker.into(),
                welcome: Some(w.bytes.clone()),
                row: None,
                ratchets: vec![],
            });
        }
        let (row, s) = commit.rows.iter().find(|r| (r.b, r.v) == (b, v))?.row(i)?;
        Some(SeatKeying {
            b,
            base_v: v,
            s: s as u32,
            from: maker.into(),
            welcome: None,
            row: Some(row.to_vec()),
            ratchets: vec![],
        })
    }

    /// Where `seat`'s base is: `(b, base_v)`, its index in the current list (the same in
    /// the base's, ratchets keep the seats), and the maker.
    pub fn base_of(&self, seat: &SeatRef) -> Option<(u64, u64, usize)> {
        let (l, i) = self.version_of(seat)?;
        let ver = self.vers.get(&(l.leaf.b, l.leaf.v))?;
        Some((l.leaf.b, ver.base_v, i))
    }
}
