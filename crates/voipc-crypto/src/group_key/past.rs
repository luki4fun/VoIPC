//! Past epochs, for kept history (plan open choice 22, part 4): a member
//! that reads a kept post from an epoch it never took takes that epoch's
//! key for reading only. Its floor never moves for it, and no header taken
//! here is ever a head.
//!
//! The header taken is the one whose bucket root holds the member's leaf
//! then (§5.10: "a reader opens it from its seat at epoch `e`"): the epoch's
//! opening header, or for a seat a Join added after it, one of the epoch's
//! Join headers together with the opening. Such a Join is that epoch's: it
//! names the opening as its `epoch_parent` in its own epoch and generation,
//! stands on the opening's keyholder set (`kh_parent`), keeps its gate and
//! seeds, and is signed by a keyholder of that set. Its `confirm` and the
//! opening's both hold for the key the seal gives.
//!
//! A past header is taken in one of two ways:
//! - **anchored**: the device holds a keyholder header of the same
//!   generation (its floor's `kh`) at or after the past epoch's own, and the
//!   keyholder headers the relay sent lead back from it by `kh_parent`
//!   digests to the past epoch's own. Each link is the very header its
//!   successor names, so the past epoch's set is the one the device's own
//!   chain stands on, and the past header is signed by that set (or is a
//!   link itself);
//! - **on the binding alone**, with no such anchor (a fresh device, a
//!   browser, an older generation, or an anchor older than the past epoch,
//!   which no backward walk reaches): the seal opens under the device's own
//!   `BK` for its leaf and `confirm` passes. The seal names `D_e`, so only a
//!   holder of that `BK` made it for this very opening, and `confirm` binds
//!   the `CK` it gives to the header's epoch. A Join taken this way is
//!   checked against the set the opening names: the opening's own, or the
//!   header whose digest is the opening's `kh_parent`, which the relay sends
//!   among the keyholder headers.
//!
//! "Own" is the whole of the binding (§5.10, `PastBk`): a `BK` from a row
//! under the `s_m` of the account's self-row (or an `RB` of its history
//! row), which only the account's devices open, or from a welcome whose
//! `s_m` is that self-row's. A welcome binds no more than its sender's `KX`,
//! and with no anchor the relay names the sender: it can make a keyholder
//! pair of its own, seat the account's published seat keys under a `BK` it
//! chose, and build every header around a `CK` it chose. Such a `BK`
//! (`PastBk::Relayed`) counts only where the walk from an anchor reaches the
//! header, whose signed `confirm` then names the epoch's real `CK`.
//!
//! Either way the leaf sits in the header's bucket root and the seal and
//! `confirm` pass: a past epoch's `CK` is never taken on a header alone.

use zeroize::Zeroizing;

use super::ctx::{Epoch, Group, GroupKind, Version};
use super::derive::{confirm_ok, open_seal};
use super::header::SignedHeader;
use super::merkle::{path_ok, Leaf, Path};
use super::rules::{check_signer, Refusal};
use super::MAX_WALK;

/// What the relay sends for one past epoch (`EpochIn` with `past` set),
/// each header past rule 1 (`check_form`).
pub struct PastIn<'a> {
    /// The header whose bucket root holds the member's leaf: the past
    /// epoch's opening header, or one of its Join headers (`take_past_at`).
    pub header: &'a SignedHeader,
    /// Keyholder headers back from the anchor, newest first, each the one
    /// the header before it names by `kh_parent`. With no anchor, for a Join
    /// whose opening sets no keyholders: the header the opening names.
    pub khs: &'a [SignedHeader],
    /// The member's leaf then, with its path.
    pub leaf: &'a Leaf,
    pub path: &'a Path,
    /// The seal of that epoch's `CK` to the leaf's version.
    pub seal: &'a [u8],
}

/// The device's bucket key for the leaf's version, by how it came.
#[derive(Clone, Copy)]
pub enum PastBk<'a> {
    /// The device's own (§5.10): from a row under the `s_m` of its account's
    /// self-row, or an `RB` of its history row, or from a welcome whose `s_m`
    /// is that self-row's. Taken on the binding alone too.
    Own(&'a [u8; 32]),
    /// On a sender the relay named alone (a seat welcome, or a seed
    /// welcome's `s_m`), or held this run: the relay may have chosen it.
    /// Taken only where the walk from an anchor reaches the header.
    Relayed(&'a [u8; 32]),
}

impl PastBk<'_> {
    fn key(&self) -> &[u8; 32] {
        match self {
            PastBk::Own(k) | PastBk::Relayed(k) => k,
        }
    }
}

/// A past epoch taken for reading.
pub struct PastEpoch {
    pub group: Group,
    pub epoch: Epoch,
    pub ck: Zeroizing<[u8; 32]>,
    /// Taken by the walk from an anchor, not on the binding alone.
    pub anchored: bool,
}

/// Takes a past epoch's `CK` at its opening header (open choice 22):
/// `take_past_at` with no Join, under a `BK` the caller holds as its own
/// (`PastBk::Own`).
pub fn take_past(
    kind: GroupKind,
    id: &str,
    anchor: Option<&SignedHeader>,
    past: &PastIn,
    bk: &[u8; 32],
) -> Result<PastEpoch, Refusal> {
    take_past_at(kind, id, anchor, past, None, PastBk::Own(bk))
}

/// Whether `take_past_at` walks back from `anchor` for `header` (with its
/// epoch's `opening` when `header` is a Join): an anchor of the header's
/// generation at or after its epoch, or the very set the epoch's opening
/// names. Otherwise the header is taken on the binding alone, and only under
/// a `PastBk::Own`.
pub fn anchors(
    anchor: Option<&SignedHeader>,
    header: &SignedHeader,
    opening: Option<&SignedHeader>,
) -> bool {
    let h = header.header();
    let open = if h.kind.opens_epoch() {
        Some(header)
    } else {
        opening
    };
    match (anchor, open) {
        (Some(a), Some(open)) => {
            a.header().gen == h.gen && (h.epoch <= a.header().epoch || open.kh() == a.d())
        }
        _ => false,
    }
}

/// Takes a past epoch's `CK` (open choice 22). `past.header` is the
/// epoch's opening header, or, for a seat a Join added after it, one of the
/// epoch's Join headers with `opening` the epoch's opening header (a Join
/// header comes with it, an opening header without). `anchor` is the
/// keyholder header this device holds for the group (its floor's `kh`), if
/// any; it counts only in the past header's own generation and at or after
/// the keyholder header the epoch names (`anchors`). `bk` is the device's
/// bucket key for the leaf's version, from its row or welcome then (or the
/// version it ratcheted from), by how it came: on the binding alone only its
/// own counts. The caller checks that the epoch taken is the one it asked
/// for.
pub fn take_past_at(
    kind: GroupKind,
    id: &str,
    anchor: Option<&SignedHeader>,
    past: &PastIn,
    opening: Option<&SignedHeader>,
    bk: PastBk,
) -> Result<PastEpoch, Refusal> {
    let h = past.header.header();
    if h.group_kind != kind || h.group != id {
        return Err(Refusal::WrongGroup);
    }
    // The epoch's opening: the header itself, or the one a Join names
    let open = match (h.kind.opens_epoch(), opening) {
        (true, None) => past.header,
        (true, Some(_)) => {
            return Err(Refusal::Chain(
                "an opening header comes with no other opening",
            ))
        }
        (false, None) => {
            return Err(Refusal::Chain(
                "a past Join header comes with its epoch's opening",
            ))
        }
        (false, Some(o)) => {
            join_of(o, past.header)?;
            o
        }
    };
    let joined = (!h.kind.opens_epoch()).then_some(past.header);
    let g = Group::new(kind, id, h.gen)
        .map_err(|_| Refusal::Form("the group id has no valid shape"))?;
    // An anchor older than the past epoch's own set reaches it by no
    // backward walk: no anchor for that epoch.
    let anchored = match anchor.filter(|_| anchors(anchor, past.header, Some(open))) {
        Some(a) => {
            let set = walk_back(a, past.khs, open)?;
            if let Some(j) = joined {
                check_signer(j, Some(set), &|_| None)?;
            }
            true
        }
        None => {
            // The binding holds only for a key the relay could not choose
            if let PastBk::Relayed(_) = bk {
                return Err(Refusal::Walk(
                    "no anchor reaches the past epoch, and its BK is not the device's own",
                ));
            }
            if let Some(j) = joined {
                // The opening is bound by the seal (its `D` is `D_e`), and the
                // set it names by its own body
                let set = if open.header().kind.sets_keyholders() {
                    open
                } else {
                    let want = open.kh();
                    past.khs
                        .iter()
                        .find(|k| k.d() == want)
                        .ok_or(Refusal::Walk(
                            "the keyholder header the opening names did not come",
                        ))?
                };
                check_signer(j, Some(set), &|_| None)?;
            }
            false
        }
    };
    if !path_ok(&h.bucket_root, h.buckets, past.leaf, past.path) {
        return Err(Refusal::Chain(
            "the leaf is not in the header's bucket root",
        ));
    }
    let epoch = Epoch {
        e: h.epoch,
        d_e: open.d(),
    };
    let at = Version {
        b: past.leaf.b,
        v: past.leaf.v,
    };
    let ck = open_seal(&g, &epoch, at, bk.key(), past.seal).map_err(|_| Refusal::Confirm)?;
    // The opening's `confirm`, and a Join's own, which binds its `join`
    if !confirm_ok(&g, h.epoch, 0, &ck, &open.header().confirm) {
        return Err(Refusal::Confirm);
    }
    if joined.is_some() && !confirm_ok(&g, h.epoch, h.join, &ck, &h.confirm) {
        return Err(Refusal::Confirm);
    }
    Ok(PastEpoch {
        group: g,
        epoch,
        ck,
        anchored,
    })
}

/// A Join header of the epoch `open` opens (rule 3 as far as the opening
/// reaches, `check_link` folded over the Joins between): the same group and
/// generation, the same epoch, `open` its `epoch_parent`, the set `open`
/// stands on its `kh_parent`; and as no Join changes them, the opening's
/// gate and seeds, `exits_upto` not below the opening's. Its signer is the
/// caller's to check, against that set.
fn join_of(open: &SignedHeader, join: &SignedHeader) -> Result<(), Refusal> {
    let (o, j) = (open.header(), join.header());
    let bad = |why| Err(Refusal::Chain(why));
    if !o.kind.opens_epoch() {
        return bad("the opening a Join comes with opens no epoch");
    }
    if o.group_kind != j.group_kind || o.group != j.group || o.gen != j.gen {
        return bad("a Join and its opening are of one group and generation");
    }
    if o.epoch != j.epoch || j.epoch_parent != open.d() {
        return bad("a Join names its epoch's opening");
    }
    if j.kh_parent != open.kh() {
        return bad("a Join stands on its opening's keyholder set");
    }
    if j.gated != o.gated {
        return Err(Refusal::GatedChanged);
    }
    if (j.seed, j.seed_floor) != (o.seed, o.seed_floor) {
        return bad("the seed does not follow");
    }
    if j.exits_upto < o.exits_upto {
        return bad("exits_upto went back");
    }
    Ok(())
}

/// From the anchor back to the keyholder header the past epoch's opening
/// names, by `kh_parent` digests, at most 4096 links; that header, the
/// epoch's set. An opening that sets keyholders is itself the walk's end;
/// any other is checked against the set the walk reached (rule 2).
fn walk_back<'a>(
    anchor: &'a SignedHeader,
    khs: &'a [SignedHeader],
    past: &SignedHeader,
) -> Result<&'a SignedHeader, Refusal> {
    if !anchor.header().kind.sets_keyholders() {
        return Err(Refusal::Walk("the anchor is no keyholder header"));
    }
    let gen = anchor.header().gen;
    let target = past.kh();
    let mut cur = anchor;
    let mut links = khs.iter();
    let mut steps = 0;
    while cur.d() != target {
        if steps >= MAX_WALK {
            return Err(Refusal::Walk("more than 4096 links"));
        }
        let want = cur.header().kh_parent;
        if want == [0; 32] {
            return Err(Refusal::Walk(
                "the keyholder chain ends before the past epoch's",
            ));
        }
        let next = links
            .next()
            .ok_or(Refusal::Walk("the keyholder chain stops short"))?;
        let n = next.header();
        if next.d() != want || !n.kind.sets_keyholders() || n.gen != gen {
            return Err(Refusal::Walk(
                "a link is not the header its successor names",
            ));
        }
        cur = next;
        steps += 1;
    }
    if !past.header().kind.sets_keyholders() {
        check_signer(past, Some(cur), &|_| None)?;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::group_key::build::world::*;
    use crate::group_key::build::Built;
    use crate::group_key::commit::DueKind;
    use crate::group_key::ctx::Version;
    use crate::group_key::derive::seal;
    use crate::group_key::merkle::inclusion_path;
    use crate::group_key::welcome::open_seat_welcome;

    /// A past epoch of alice's: a Fresh at epoch 2, then a promotion (the
    /// keyholder header the device holds) and another Fresh.
    struct Case {
        w: World,
        genesis: SignedHeader,
        past: SignedHeader,
        leaf: Leaf,
        path: Path,
        seal: Vec<u8>,
        bk: Zeroizing<[u8; 32]>,
        ck: Zeroizing<[u8; 32]>,
    }

    fn case() -> Case {
        let mut w = World::text(true, false);
        let genesis = w.head.clone();
        let alice = Member::account(10);
        let joined = w.join(&[&alice]);
        let at = joined.made[0].bucket.version();
        let (_, bk) = open_seat_welcome(
            &w.g,
            1,
            at,
            &alice.me(),
            &w.holders[0].holder(),
            &joined.commit.welcomes[0].bytes,
        )
        .unwrap();
        let due = w.due(DueKind::Exits);
        let fresh = w.open(&due);
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let i = leaves
            .iter()
            .position(|l| (l.b, l.v) == (at.b, at.v))
            .unwrap();
        let seal = fresh
            .commit
            .seals
            .iter()
            .find(|s| (s.b, s.v) == (at.b, at.v))
            .unwrap()
            .bytes
            .clone();
        w.promote(Holder::desktop(2));
        let due = w.due(DueKind::Exits);
        w.open(&due);
        Case {
            genesis,
            past: fresh.header.clone(),
            leaf: leaves[i],
            path: inclusion_path(&leaves, i).unwrap(),
            seal,
            bk,
            ck: fresh.ck.clone(),
            w,
        }
    }

    fn take(
        c: &Case,
        anchor: Option<&SignedHeader>,
        khs: &[SignedHeader],
        past: &SignedHeader,
        seal: &[u8],
    ) -> Result<PastEpoch, Refusal> {
        let p = PastIn {
            header: past,
            khs,
            leaf: &c.leaf,
            path: &c.path,
            seal,
        };
        take_past(GroupKind::Text, TEXT_ID, anchor, &p, &c.bk)
    }

    /// `past`'s body signed again, after `edit`, by `ik`.
    fn forged(
        past: &SignedHeader,
        ik: &libsignal_protocol::IdentityKeyPair,
        edit: impl FnOnce(&mut super::super::header::HeaderV1),
    ) -> SignedHeader {
        let mut h = past.header().clone();
        edit(&mut h);
        SignedHeader::sign(h, ik).unwrap()
    }

    #[test]
    fn a_past_header_reached_backward_by_kh_parent_digests_is_taken() {
        let c = case();
        let anchor = c.w.kh.clone();
        assert_eq!(
            anchor.header().kind,
            super::super::header::Kind::KeyholdersAdd
        );
        let khs = [c.genesis.clone()];
        let got = take(&c, Some(&anchor), &khs, &c.past, &c.seal).unwrap();
        assert!(got.anchored);
        assert_eq!(*got.ck, *c.ck);
        assert_eq!((got.epoch.e, got.epoch.d_e), (2, c.past.d()));
        // The anchor's own epoch's set, with no link to walk.
        let own = take(&c, Some(&c.genesis), &[], &c.past, &c.seal).unwrap();
        assert!(own.anchored);
    }

    #[test]
    fn a_walk_from_the_anchor_that_does_not_reach_the_past_epochs_set_is_refused() {
        let c = case();
        let anchor = c.w.kh.clone();
        assert!(matches!(
            take(&c, Some(&anchor), &[], &c.past, &c.seal),
            Err(Refusal::Walk(_))
        ));
        let wrong = [c.past.clone()];
        assert!(matches!(
            take(&c, Some(&anchor), &wrong, &c.past, &c.seal),
            Err(Refusal::Walk(_))
        ));
        assert!(matches!(
            take(&c, Some(&c.past), &[], &c.past, &c.seal),
            Err(Refusal::Walk("the anchor is no keyholder header"))
        ));
        // A header the walk's set never signed, even one whose seal opens.
        let outsider = Holder::desktop(9);
        let forged = forged(&c.past, &outsider.ik, |h| h.signer = outsider.m);
        let resealed = seal(
            &c.w.g,
            &crate::group_key::ctx::Epoch {
                e: 2,
                d_e: forged.d(),
            },
            Version {
                b: c.leaf.b,
                v: c.leaf.v,
            },
            &c.bk,
            &c.ck,
        );
        assert_eq!(
            take(
                &c,
                Some(&anchor),
                std::slice::from_ref(&c.genesis),
                &forged,
                &resealed
            )
            .err(),
            Some(Refusal::NotKeyholder)
        );
    }

    #[test]
    fn a_past_header_with_no_anchor_is_taken_only_when_its_seal_opens_and_confirm_passes() {
        let c = case();
        // A fresh device never met the signer: the binding alone takes it.
        let got = take(&c, None, &[], &c.past, &c.seal).unwrap();
        assert!(!got.anchored);
        assert_eq!(*got.ck, *c.ck);
        // An anchor of another generation is no anchor.
        let elsewhere = World::text(true, false);
        let got = take(&c, Some(&elsewhere.kh), &[], &c.past, &c.seal).unwrap();
        assert!(!got.anchored);
        // An unseen signer's header with the genuine seal: it names another
        // `D_e`, so it does not open.
        let outsider = Holder::desktop(9);
        let forged = forged(&c.past, &outsider.ik, |h| h.signer = outsider.m);
        assert_eq!(
            take(&c, None, &[], &forged, &c.seal).err(),
            Some(Refusal::Confirm)
        );
        // A seal under another bucket key does not open either.
        let other = Zeroizing::new([5u8; 32]);
        let p = PastIn {
            header: &c.past,
            khs: &[],
            leaf: &c.leaf,
            path: &c.path,
            seal: &c.seal,
        };
        assert_eq!(
            take_past(GroupKind::Text, TEXT_ID, None, &p, &other).err(),
            Some(Refusal::Confirm)
        );
    }

    #[test]
    fn a_past_epoch_whose_set_is_newer_than_the_anchor_is_taken_on_the_binding_alone() {
        // The device's floor stayed at the Genesis; it reads a kept epoch
        // after a promotion it never took.
        let mut c = case();
        let alice_leaf = c.leaf;
        let add = c.w.kh.clone();
        assert_eq!(add.header().kind, super::super::header::Kind::KeyholdersAdd);
        let fresh = c.w.head.clone();
        let leaves: Vec<Leaf> = c.w.leaves.iter().map(|l| l.leaf).collect();
        let i = leaves.iter().position(|l| l.b == alice_leaf.b).unwrap();
        let ring_bk =
            c.w.ring
                .buckets
                .iter()
                .find(|k| k.b == alice_leaf.b)
                .unwrap();
        let built_seal = seal(
            &c.w.g,
            &crate::group_key::ctx::Epoch {
                e: fresh.header().epoch,
                d_e: fresh.d(),
            },
            ring_bk.version(),
            &ring_bk.bk,
            c.w.ring.ck(),
        );
        c.leaf = leaves[i];
        c.path = inclusion_path(&leaves, i).unwrap();
        c.bk = ring_bk.bk.clone();
        let khs = [add.clone()];
        let got = take(&c, Some(&c.genesis), &khs, &fresh, &built_seal).unwrap();
        assert!(!got.anchored, "no backward walk reaches the newer set");
        assert_eq!(*got.ck, *c.w.ring.ck());
        // An anchor at or after that set still walks.
        let got = take(&c, Some(&add), &[], &fresh, &built_seal).unwrap();
        assert!(got.anchored);
        // And the binding still holds: a seal under another key is refused.
        let other = Zeroizing::new([5u8; 32]);
        let p = PastIn {
            header: &fresh,
            khs: &khs,
            leaf: &c.leaf,
            path: &c.path,
            seal: &built_seal,
        };
        assert_eq!(
            take_past(GroupKind::Text, TEXT_ID, Some(&c.genesis), &p, &other).err(),
            Some(Refusal::Confirm)
        );
    }

    #[test]
    fn a_past_header_whose_confirm_fails_is_refused() {
        let c = case();
        let k = &c.w.holders[0];
        let forged = forged(&c.past, &k.ik, |h| h.confirm = [7; 32]);
        let resealed = seal(
            &c.w.g,
            &crate::group_key::ctx::Epoch {
                e: 2,
                d_e: forged.d(),
            },
            Version {
                b: c.leaf.b,
                v: c.leaf.v,
            },
            &c.bk,
            &c.ck,
        );
        assert_eq!(
            take(&c, None, &[], &forged, &resealed).err(),
            Some(Refusal::Confirm)
        );
        let anchor = c.w.kh.clone();
        assert_eq!(
            take(
                &c,
                Some(&anchor),
                std::slice::from_ref(&c.genesis),
                &forged,
                &resealed
            )
            .err(),
            Some(Refusal::Confirm),
            "signed by the set, but its CK is not the one it names"
        );
    }

    #[test]
    fn a_past_join_header_without_its_opening_or_a_leaf_outside_its_root_is_refused() {
        let mut c = case();
        let join = c.w.join(&[&Member::account(40)]).header;
        assert_eq!(
            take(&c, None, &[], &join, &c.seal).err(),
            Some(Refusal::Chain(
                "a past Join header comes with its epoch's opening"
            ))
        );
        c.leaf.seats += 1;
        assert_eq!(
            take(&c, None, &[], &c.past, &c.seal).err(),
            Some(Refusal::Chain(
                "the leaf is not in the header's bucket root"
            ))
        );
        let p = PastIn {
            header: &c.past,
            khs: &[],
            leaf: &c.leaf,
            path: &c.path,
            seal: &c.seal,
        };
        assert_eq!(
            take_past(GroupKind::Voice, TEXT_ID, None, &p, &c.bk).err(),
            Some(Refusal::WrongGroup)
        );
    }

    // ── Seats a Join added (T1e A, §5.10 "from its seat at epoch e") ──────

    /// One reader's seat then: its leaf with a path in the header it is
    /// taken at, its version's seal, and its `BK` from its welcome.
    struct Seat {
        leaf: Leaf,
        path: Path,
        seal: Vec<u8>,
        bk: Zeroizing<[u8; 32]>,
    }

    /// Epoch 1 opened by the Genesis, alice seated by its one Join; epoch 2
    /// opened by a Fresh (which sets no keyholders: its set is the
    /// Genesis's), then bob seated by its first Join and carol by its
    /// second, its last. Then a promotion (a keyholder header a device may
    /// hold after) and a Join in epoch 3.
    struct JoinCase {
        w: World,
        genesis: SignedHeader,
        /// Epoch 1's Join, alice's.
        old_join: SignedHeader,
        alice: Seat,
        /// Alice's version at epoch 2's opening, sealed by it.
        alice_open: Seat,
        opening: SignedHeader,
        first: SignedHeader,
        last: SignedHeader,
        bob: Seat,
        carol: Seat,
        /// Bob's leaf with its path in his own Join's root.
        bob_at_first: Path,
        ck: Zeroizing<[u8; 32]>,
        /// Epoch 3's first Join, after the promotion.
        next_join: SignedHeader,
    }

    fn seat_of(w: &World, m: &Member, built: &Built, leaves: &[Leaf]) -> Seat {
        let x = built
            .commit
            .welcomes
            .iter()
            .find(|x| x.seat == m.seat)
            .unwrap();
        let at = Version { b: x.b, v: x.v };
        let (_, bk) =
            open_seat_welcome(&w.g, x.s, at, &m.me(), &w.holders[0].holder(), &x.bytes).unwrap();
        let i = leaves
            .iter()
            .position(|l| (l.b, l.v) == (at.b, at.v))
            .unwrap();
        let seal = built
            .commit
            .seals
            .iter()
            .find(|s| (s.b, s.v) == (at.b, at.v))
            .unwrap()
            .bytes
            .clone();
        Seat {
            leaf: leaves[i],
            path: inclusion_path(leaves, i).unwrap(),
            seal,
            bk,
        }
    }

    fn join_case() -> JoinCase {
        let mut w = World::text(true, false);
        let genesis = w.head.clone();
        let alice = Member::account(10);
        let a = w.join(&[&alice]);
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let alice_seat = seat_of(&w, &alice, &a, &leaves);
        let due = w.due(DueKind::Exits);
        let fresh = w.open(&due);
        assert_eq!(
            fresh.header.header().kind,
            super::super::header::Kind::Fresh
        );
        let at_open: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let i = at_open
            .iter()
            .position(|l| (l.b, l.v) == (alice_seat.leaf.b, alice_seat.leaf.v))
            .expect("alice's version stays at the Fresh");
        let alice_open = Seat {
            leaf: at_open[i],
            path: inclusion_path(&at_open, i).unwrap(),
            seal: fresh
                .commit
                .seals
                .iter()
                .find(|s| (s.b, s.v) == (at_open[i].b, at_open[i].v))
                .unwrap()
                .bytes
                .clone(),
            bk: alice_seat.bk.clone(),
        };
        let bob = Member::account(11);
        let b = w.join(&[&bob]);
        let at_first: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let carol = Member::account(12);
        let c = w.join(&[&carol]);
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        let bob_seat = seat_of(&w, &bob, &b, &leaves);
        let carol_seat = seat_of(&w, &carol, &c, &leaves);
        let i = at_first
            .iter()
            .position(|l| l.b == bob_seat.leaf.b)
            .unwrap();
        let bob_at_first = inclusion_path(&at_first, i).unwrap();
        assert_eq!((c.header.header().epoch, c.header.header().join), (2, 2));
        w.promote(Holder::desktop(2));
        let next_join = w.join(&[&Member::account(13)]).header;
        assert_eq!(next_join.header().epoch, 3);
        JoinCase {
            genesis,
            old_join: a.header.clone(),
            alice: alice_seat,
            alice_open,
            opening: fresh.header.clone(),
            first: b.header.clone(),
            last: c.header.clone(),
            bob: bob_seat,
            carol: carol_seat,
            bob_at_first,
            ck: c.ck.clone(),
            next_join,
            w,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn take_at(
        anchor: Option<&SignedHeader>,
        khs: &[SignedHeader],
        header: &SignedHeader,
        opening: Option<&SignedHeader>,
        seat: &Seat,
        path: &Path,
        seal: &[u8],
    ) -> Result<PastEpoch, Refusal> {
        let p = PastIn {
            header,
            khs,
            leaf: &seat.leaf,
            path,
            seal,
        };
        take_past_at(
            GroupKind::Text,
            TEXT_ID,
            anchor,
            &p,
            opening,
            PastBk::Own(&seat.bk),
        )
    }

    /// Takes `seat` at `header` with `opening`, its own seal and path.
    fn take_seat(
        anchor: Option<&SignedHeader>,
        khs: &[SignedHeader],
        header: &SignedHeader,
        opening: Option<&SignedHeader>,
        seat: &Seat,
    ) -> Result<PastEpoch, Refusal> {
        take_at(anchor, khs, header, opening, seat, &seat.path, &seat.seal)
    }

    #[test]
    fn a_seat_a_join_added_takes_its_epochs_key_at_a_join_with_the_epochs_opening() {
        let c = join_case();
        let gen = std::slice::from_ref(&c.genesis);
        for seat in [&c.carol, &c.bob] {
            // On the binding alone: the set the Fresh names comes along
            let got = take_seat(None, gen, &c.last, Some(&c.opening), seat).unwrap();
            assert!(!got.anchored);
            assert_eq!(*got.ck, *c.ck);
            assert_eq!((got.epoch.e, got.epoch.d_e), (2, c.opening.d()));
            // Walked back from a keyholder header after the epoch
            let got = take_seat(Some(&c.w.kh), gen, &c.last, Some(&c.opening), seat).unwrap();
            assert!(got.anchored);
            assert_eq!(*got.ck, *c.ck);
            // Anchored at the epoch's own set, no link to walk
            let got = take_seat(Some(&c.genesis), &[], &c.last, Some(&c.opening), seat).unwrap();
            assert!(got.anchored);
            assert_eq!((got.epoch.e, got.epoch.d_e), (2, c.opening.d()));
        }
        // Bob at the Join that seated him, too
        let got = take_at(
            None,
            gen,
            &c.first,
            Some(&c.opening),
            &c.bob,
            &c.bob_at_first,
            &c.bob.seal,
        )
        .unwrap();
        assert_eq!(*got.ck, *c.ck);
        // Under an opening that sets keyholders (the Genesis), nothing more comes
        let got = take_seat(None, &[], &c.old_join, Some(&c.genesis), &c.alice).unwrap();
        assert_eq!((got.epoch.e, got.epoch.d_e), (1, c.genesis.d()));
    }

    /// A seat the opening sealed to reads the epoch at the opening, as before,
    /// though Joins followed it.
    #[test]
    fn a_seat_at_the_opening_still_takes_the_epoch_there_after_joins_followed() {
        let c = join_case();
        for anchor in [None, Some(&c.genesis), Some(&c.w.kh)] {
            let khs = match anchor {
                Some(a) if a.d() != c.genesis.d() => std::slice::from_ref(&c.genesis),
                _ => &[],
            };
            let p = PastIn {
                header: &c.opening,
                khs,
                leaf: &c.alice_open.leaf,
                path: &c.alice_open.path,
                seal: &c.alice_open.seal,
            };
            let got = take_past(GroupKind::Text, TEXT_ID, anchor, &p, &c.alice_open.bk).unwrap();
            assert_eq!(got.anchored, anchor.is_some());
            assert_eq!(*got.ck, *c.ck);
            assert_eq!((got.epoch.e, got.epoch.d_e), (2, c.opening.d()));
        }
    }

    /// The hostile relay of the past path: a Join of another epoch, a Join
    /// whose set or signer is not the epoch's, a keyholder's Join moved to
    /// another epoch, an opening that is not the Join's: none gives a key.
    #[test]
    fn a_forged_or_out_of_epoch_join_header_is_refused() {
        let c = join_case();
        let gen = std::slice::from_ref(&c.genesis);
        let k = &c.w.holders[0];
        let both = |header: &SignedHeader, opening: Option<&SignedHeader>| {
            let alone = take_seat(None, gen, header, opening, &c.carol).err();
            let walked = take_seat(Some(&c.w.kh), gen, header, opening, &c.carol).err();
            (alone, walked)
        };
        // Joins of the epochs before and after, with epoch 2's opening
        for other in [&c.old_join, &c.next_join] {
            let named = Some(Refusal::Chain("a Join names its epoch's opening"));
            assert_eq!(both(other, Some(&c.opening)), (named.clone(), named));
        }
        // Epoch 2's last Join with another epoch's opening, or a Join as the opening
        let (a, _) = both(&c.last, Some(&c.genesis));
        assert_eq!(a, Some(Refusal::Chain("a Join names its epoch's opening")));
        let (a, w) = both(&c.last, Some(&c.first));
        assert_eq!(
            a,
            Some(Refusal::Chain(
                "the opening a Join comes with opens no epoch"
            ))
        );
        assert_eq!(a, w);
        // No opening, or an opening with an opening
        assert_eq!(
            both(&c.last, None).0,
            Some(Refusal::Chain(
                "a past Join header comes with its epoch's opening"
            ))
        );
        assert_eq!(
            take_seat(None, gen, &c.opening, Some(&c.genesis), &c.carol).err(),
            Some(Refusal::Chain(
                "an opening header comes with no other opening"
            ))
        );
        // Signed by someone outside the epoch's set, as itself or as the keyholder
        let outsider = Holder::desktop(9);
        let as_outsider = forged(&c.last, &outsider.ik, |h| h.signer = outsider.m);
        assert_eq!(
            both(&as_outsider, Some(&c.opening)),
            (Some(Refusal::NotKeyholder), Some(Refusal::NotKeyholder))
        );
        let as_keyholder = forged(&c.last, &outsider.ik, |_| {});
        assert_eq!(
            both(&as_keyholder, Some(&c.opening)),
            (Some(Refusal::Signature), Some(Refusal::Signature))
        );
        // On the binding alone, the set the opening names must come, and be that one
        assert_eq!(
            take_seat(None, &[], &c.last, Some(&c.opening), &c.carol).err(),
            Some(Refusal::Walk(
                "the keyholder header the opening names did not come"
            ))
        );
        assert_eq!(
            take_seat(
                None,
                std::slice::from_ref(&c.w.kh),
                &c.last,
                Some(&c.opening),
                &c.carol
            )
            .err(),
            Some(Refusal::Walk(
                "the keyholder header the opening names did not come"
            ))
        );
        // A Join on another set than its opening's
        let other_set = forged(&c.last, &k.ik, |h| h.kh_parent = c.w.kh.d());
        assert_eq!(
            both(&other_set, Some(&c.opening)).0,
            Some(Refusal::Chain(
                "a Join stands on its opening's keyholder set"
            ))
        );
        // Seeds a Join never changes
        let seeds = forged(&c.last, &k.ik, |h| h.seed += 1);
        assert_eq!(
            both(&seeds, Some(&c.opening)).0,
            Some(Refusal::Chain("the seed does not follow"))
        );
        // The epoch's own keyholder moves its Join to epoch 1, under epoch 1's opening:
        // every link holds, and the seal (which names epoch 2 and its opening) does not open
        let moved = forged(&c.last, &k.ik, |h| {
            h.epoch = 1;
            h.epoch_parent = c.genesis.d();
        });
        assert_eq!(
            take_seat(None, &[], &moved, Some(&c.genesis), &c.carol).err(),
            Some(Refusal::Confirm)
        );
        // A confirm that is not the key's
        let confirm = forged(&c.last, &k.ik, |h| h.confirm = [7; 32]);
        assert_eq!(
            both(&confirm, Some(&c.opening)),
            (Some(Refusal::Confirm), Some(Refusal::Confirm))
        );
        // A Join before the seat's own does not hold its leaf
        assert_eq!(
            take_seat(None, gen, &c.first, Some(&c.opening), &c.carol).err(),
            Some(Refusal::Chain(
                "the leaf is not in the header's bucket root"
            ))
        );
        // Another seat's seal
        assert_eq!(
            take_at(
                None,
                gen,
                &c.last,
                Some(&c.opening),
                &c.carol,
                &c.carol.path,
                &c.bob.seal
            )
            .err(),
            Some(Refusal::Confirm)
        );
        // A Join and an opening of another generation
        let mut elsewhere = World::text(true, false);
        let other_gen = elsewhere.join(&[&Member::account(14)]).header;
        assert_eq!(
            both(&other_gen, Some(&c.opening)).0,
            Some(Refusal::Chain(
                "a Join and its opening are of one group and generation"
            ))
        );
    }

    /// J8K review: on the binding alone the seal binds the header only under a
    /// `BK` the relay could not choose. A key that came on a sender the relay
    /// named (`PastBk::Relayed`) is refused there, at an opening or a Join, and
    /// taken where the walk from an anchor reaches the header; `anchors` says
    /// which, as `take_past_at` decides it.
    #[test]
    fn a_bk_the_relay_could_have_chosen_is_taken_only_where_an_anchor_reaches_the_header() {
        let refused = Some(Refusal::Walk(
            "no anchor reaches the past epoch, and its BK is not the device's own",
        ));
        let c = case();
        let elsewhere = World::text(true, false);
        let gen = std::slice::from_ref(&c.genesis);
        let opening = |anchor, khs: &[SignedHeader], bk| {
            let p = PastIn {
                header: &c.past,
                khs,
                leaf: &c.leaf,
                path: &c.path,
                seal: &c.seal,
            };
            take_past_at(GroupKind::Text, TEXT_ID, anchor, &p, None, bk)
        };
        let relayed = PastBk::Relayed(&c.bk);
        assert_eq!(opening(None, &[], relayed).err(), refused);
        assert_eq!(
            opening(Some(&elsewhere.kh), &[], relayed).err(),
            refused,
            "an anchor of another generation"
        );
        let got = opening(Some(&c.w.kh), gen, relayed).unwrap();
        assert!(got.anchored);
        assert_eq!(*got.ck, *c.ck);
        assert!(!opening(None, &[], PastBk::Own(&c.bk)).unwrap().anchored);
        assert!(!anchors(None, &c.past, None));
        assert!(!anchors(Some(&elsewhere.kh), &c.past, None));
        assert!(anchors(Some(&c.w.kh), &c.past, None));
        // A Join, with the set its opening names
        let j = join_case();
        let gen = std::slice::from_ref(&j.genesis);
        let join = |anchor, bk| {
            let p = PastIn {
                header: &j.last,
                khs: gen,
                leaf: &j.carol.leaf,
                path: &j.carol.path,
                seal: &j.carol.seal,
            };
            take_past_at(GroupKind::Text, TEXT_ID, anchor, &p, Some(&j.opening), bk)
        };
        let relayed = PastBk::Relayed(&j.carol.bk);
        assert_eq!(join(None, relayed).err(), refused);
        let got = join(Some(&j.w.kh), relayed).unwrap();
        assert!(got.anchored);
        assert_eq!(*got.ck, *j.ck);
        assert!(!anchors(None, &j.last, Some(&j.opening)));
        assert!(
            !anchors(Some(&j.w.kh), &j.last, None),
            "a Join with no opening"
        );
        assert!(anchors(Some(&j.w.kh), &j.last, Some(&j.opening)));
    }
}
