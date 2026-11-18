//! Past epochs, for kept history (plan open choice 22, part 4): a member
//! that reads a kept post from an epoch it never took takes that epoch's
//! opening header for reading only. Its floor never moves for it, and no
//! header taken here is ever a head.
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
//!   holder of that `BK` made it for this very header, and `confirm` binds
//!   the `CK` it gives to the header's epoch.
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
    /// The past epoch's opening header.
    pub header: &'a SignedHeader,
    /// Keyholder headers back from the anchor, newest first, each the one
    /// the header before it names by `kh_parent`.
    pub khs: &'a [SignedHeader],
    /// The member's leaf then, with its path.
    pub leaf: &'a Leaf,
    pub path: &'a Path,
    /// The seal of that epoch's `CK` to the leaf's version.
    pub seal: &'a [u8],
}

/// A past epoch taken for reading.
pub struct PastEpoch {
    pub group: Group,
    pub epoch: Epoch,
    pub ck: Zeroizing<[u8; 32]>,
    /// Taken by the walk from an anchor, not on the binding alone.
    pub anchored: bool,
}

/// Takes a past epoch's `CK` (open choice 22). `anchor` is the keyholder
/// header this device holds for the group (its floor's `kh`), if any; it
/// counts only in the past header's own generation and at or after the
/// keyholder header it names. `bk` is the device's own bucket key for the
/// leaf's version, from its row or welcome then (or the version it
/// ratcheted from). The caller checks that the epoch taken is the one it
/// asked for.
pub fn take_past(
    kind: GroupKind,
    id: &str,
    anchor: Option<&SignedHeader>,
    past: &PastIn,
    bk: &[u8; 32],
) -> Result<PastEpoch, Refusal> {
    let h = past.header.header();
    if h.group_kind != kind || h.group != id {
        return Err(Refusal::WrongGroup);
    }
    if !h.kind.opens_epoch() {
        return Err(Refusal::Chain(
            "a past epoch is taken at its opening header",
        ));
    }
    let g = Group::new(kind, id, h.gen)
        .map_err(|_| Refusal::Form("the group id has no valid shape"))?;
    // An anchor older than the past epoch's own set reaches it by no
    // backward walk: no anchor for that epoch.
    let anchored = match anchor {
        Some(a)
            if a.header().gen == h.gen
                && (h.epoch <= a.header().epoch || past.header.kh() == a.d()) =>
        {
            walk_back(a, past.khs, past.header)?;
            true
        }
        _ => false,
    };
    if !path_ok(&h.bucket_root, h.buckets, past.leaf, past.path) {
        return Err(Refusal::Chain(
            "the leaf is not in the header's bucket root",
        ));
    }
    let epoch = Epoch {
        e: h.epoch,
        d_e: past.header.d(),
    };
    let at = Version {
        b: past.leaf.b,
        v: past.leaf.v,
    };
    let ck = open_seal(&g, &epoch, at, bk, past.seal).map_err(|_| Refusal::Confirm)?;
    if !confirm_ok(&g, h.epoch, 0, &ck, &h.confirm) {
        return Err(Refusal::Confirm);
    }
    Ok(PastEpoch {
        group: g,
        epoch,
        ck,
        anchored,
    })
}

/// From the anchor back to the keyholder header the past header names, by
/// `kh_parent` digests, at most 4096 links. A past header that sets
/// keyholders is itself the walk's end; any other is checked against the
/// set the walk reached (rule 2).
fn walk_back(
    anchor: &SignedHeader,
    khs: &[SignedHeader],
    past: &SignedHeader,
) -> Result<(), Refusal> {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::group_key::build::world::*;
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
    fn a_past_join_header_or_a_leaf_outside_its_root_is_refused() {
        let mut c = case();
        let join = c.w.join(&[&Member::account(40)]).header;
        assert_eq!(
            take(&c, None, &[], &join, &c.seal).err(),
            Some(Refusal::Chain(
                "a past epoch is taken at its opening header"
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
}
