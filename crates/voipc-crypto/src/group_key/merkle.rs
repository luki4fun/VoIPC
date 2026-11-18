//! The bucket root and seat lists (§11.4, §11.5).
//!
//! Every header commits to every current bucket version through a Merkle
//! root over one leaf per version, each leaf carrying its seat-list digest.
//! A member gets its own leaf with an inclusion path; keyholders get every
//! leaf. The tree has the shape of RFC 6962 §2.1, with labels of our own in
//! place of its 0x00 and 0x01 prefixes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ctx::{list_ctx, Group, MemberId, SeatRef, Version, LEAF_LABEL, NODE_LABEL};
use super::GkError;

/// Most seats in one bucket version (§5.3).
pub const BUCKET_SEATS: u16 = 62;
/// Longest inclusion path taken: a tree of 2^64 leaves.
const MAX_PATH: usize = 64;

/// Which pool a bucket is in: accounts and connections never share one
/// (§5.2). Postcard: Accounts 0, Conns 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Pool {
    Accounts,
    Conns,
}

impl Pool {
    pub fn of(m: &MemberId) -> Pool {
        match m {
            MemberId::Account(_) => Pool::Accounts,
            MemberId::Conn(_) => Pool::Conns,
        }
    }
}

/// How a version got its key: rows to its seats, or a ratchet of version
/// `from` of the same bucket at a promotion (§3.5). Postcard: Row 0, Ratchet 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Via {
    Row,
    Ratchet { from: u64 },
}

/// One current bucket version, as the root commits to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Leaf {
    pub b: u64,
    pub v: u64,
    pub pool: Pool,
    pub seats: u16,
    pub list: [u8; 32],
    pub via: Via,
}

impl Leaf {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("a leaf encodes")
    }
}

/// `SHA-256("voipc-gk/v1/leaf|" ‖ postcard(leaf))`.
pub fn leaf_hash(leaf: &Leaf) -> [u8; 32] {
    Sha256::new()
        .chain_update(LEAF_LABEL)
        .chain_update(leaf.encode())
        .finalize()
        .into()
}

pub(super) fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(NODE_LABEL)
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The largest power of two below `n` (`n > 1`).
fn split(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

fn mth(hashes: &[[u8; 32]]) -> [u8; 32] {
    match hashes.len() {
        0 => Sha256::digest([]).into(),
        1 => hashes[0],
        n => {
            let k = split(n);
            node(&mth(&hashes[..k]), &mth(&hashes[k..]))
        }
    }
}

/// Whether the leaves are in the order the root takes them: by `b`, each
/// bucket once.
fn ordered(leaves: &[Leaf]) -> bool {
    leaves.windows(2).all(|w| w[0].b < w[1].b)
}

/// The root over every current version, sorted by `b` (§11.4). `Malformed`
/// when they are not in that order, or a bucket comes twice.
///
/// No leaves at all give `SHA-256("")`, RFC 6962's root of the empty tree:
/// §11.4 does not say, and a group whose last seat left has none.
pub fn bucket_root(leaves: &[Leaf]) -> Result<[u8; 32], GkError> {
    if !ordered(leaves) {
        return Err(GkError::Malformed);
    }
    let hashes: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    Ok(mth(&hashes))
}

/// An inclusion path (§11.4): the sibling hashes from the bottom up, with
/// the leaf's index and the leaf count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Path {
    pub index: u64,
    pub n: u64,
    pub siblings: Vec<[u8; 32]>,
}

fn path_of(m: usize, hashes: &[[u8; 32]], out: &mut Vec<[u8; 32]>) {
    let n = hashes.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        path_of(m, &hashes[..k], out);
        out.push(mth(&hashes[k..]));
    } else {
        path_of(m - k, &hashes[k..], out);
        out.push(mth(&hashes[..k]));
    }
}

/// The path of leaf `index` (RFC 6962 §2.1.1 `PATH`). `None` past the end or
/// for leaves out of order.
pub fn inclusion_path(leaves: &[Leaf], index: usize) -> Option<Path> {
    if index >= leaves.len() || !ordered(leaves) {
        return None;
    }
    let hashes: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    let mut siblings = Vec::new();
    path_of(index, &hashes, &mut siblings);
    Some(Path {
        index: index as u64,
        n: leaves.len() as u64,
        siblings,
    })
}

/// Whether `leaf` sits at `path.index` of the tree with `root` and
/// `buckets` leaves, both from the signed header (the check of RFC 9162
/// §2.1.3.2). The path must have exactly the length the tree's shape gives.
///
/// The leaf count comes from the header, not the path: a path for leaf 0 of
/// 3 also checks out as one of 4 leaves under the same root, since a sibling
/// is only a hash. The leaf and node labels keep a node from passing as a
/// leaf, so the count only places the leaf; it is still bound here.
pub fn path_ok(root: &[u8; 32], buckets: u32, leaf: &Leaf, path: &Path) -> bool {
    if path.n != u64::from(buckets) || path.index >= path.n || path.siblings.len() > MAX_PATH {
        return false;
    }
    let (mut f, mut s) = (path.index, path.n - 1);
    let mut r = leaf_hash(leaf);
    for p in &path.siblings {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

// ── Seat lists ────────────────────────────────────────────────────────────

/// A seat record (§11.5), 33 bytes: kind and id (17, `MemberId::seat_id`),
/// `tag_sk` (8), `tag_sx` (8).
pub fn seat_record(seat: &SeatRef) -> [u8; 33] {
    let mut r = [0u8; 33];
    r[..17].copy_from_slice(&seat.m.seat_id());
    r[17..25].copy_from_slice(&seat.tag_sk);
    r[25..].copy_from_slice(&seat.tag_sx);
    r
}

fn records(seats: &[SeatRef]) -> Vec<[u8; 33]> {
    let mut r: Vec<[u8; 33]> = seats.iter().map(seat_record).collect();
    r.sort_unstable();
    r.dedup();
    r
}

/// `list(b,v) = SHA-256(len(c) u32 BE ‖ c ‖ records)`, `c = ctx(list; k,
/// group, gen, b, v)`, the records sorted and each once, as `log.rs`
/// `list_digest` does. The context makes one set of people in two groups,
/// or two versions, two digests.
pub fn list_digest(g: &Group, at: Version, seats: &[SeatRef]) -> [u8; 32] {
    let c = list_ctx(g, at);
    let mut h = Sha256::new();
    h.update((c.len() as u32).to_be_bytes());
    h.update(c.as_bytes());
    for r in records(seats) {
        h.update(r);
    }
    h.finalize().into()
}

/// Before a keyholder re-versions, merges or re-keys a bucket (§5.3): the
/// list the relay gave for version `old` must match its digest in the
/// keyring, and the new version's seats must all be in it. Only Join
/// buckets hold new seats.
pub fn check_reversion(
    g: &Group,
    old: Version,
    old_digest: &[u8; 32],
    old_list: &[SeatRef],
    new_list: &[SeatRef],
) -> Result<(), GkError> {
    if list_digest(g, old, old_list) != *old_digest {
        return Err(GkError::Sealed);
    }
    let had = records(old_list);
    if records(new_list)
        .iter()
        .all(|r| had.binary_search(r).is_ok())
    {
        Ok(())
    } else {
        Err(GkError::Forged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: u64) -> Leaf {
        Leaf {
            b,
            v: b * 7,
            pool: if b.is_multiple_of(2) {
                Pool::Accounts
            } else {
                Pool::Conns
            },
            seats: (b % 62) as u16 + 1,
            list: [b as u8; 32],
            via: if b.is_multiple_of(3) {
                Via::Ratchet { from: b + 1 }
            } else {
                Via::Row
            },
        }
    }

    /// The shape of RFC 6962 §2.1, spelled out for small trees.
    #[test]
    fn the_root_splits_at_the_largest_power_of_two_below_n() {
        let l: Vec<Leaf> = (1..=7).map(leaf).collect();
        let h: Vec<[u8; 32]> = l.iter().map(leaf_hash).collect();
        assert_eq!(bucket_root(&l[..1]).unwrap(), h[0]);
        assert_eq!(bucket_root(&l[..2]).unwrap(), node(&h[0], &h[1]));
        assert_eq!(
            bucket_root(&l[..3]).unwrap(),
            node(&node(&h[0], &h[1]), &h[2])
        );
        let four = node(&node(&h[0], &h[1]), &node(&h[2], &h[3]));
        assert_eq!(bucket_root(&l[..4]).unwrap(), four);
        assert_eq!(
            bucket_root(&l[..7]).unwrap(),
            node(&four, &node(&node(&h[4], &h[5]), &h[6]))
        );
        assert_eq!(
            bucket_root(&[]).unwrap(),
            <[u8; 32]>::from(Sha256::digest([]))
        );
    }

    #[test]
    fn every_leaf_has_a_path_to_the_root_and_no_other_leaf_does() {
        for n in 1..=40usize {
            let l: Vec<Leaf> = (0..n as u64).map(|b| leaf(b * 3 + 1)).collect();
            let root = bucket_root(&l).unwrap();
            for i in 0..n {
                let p = inclusion_path(&l, i).unwrap();
                let n32 = n as u32;
                assert!(path_ok(&root, n32, &l[i], &p), "n {n} i {i}");
                let other = l[(i + 1) % n];
                if n > 1 {
                    assert!(
                        !path_ok(&root, n32, &other, &p),
                        "another leaf, n {n} i {i}"
                    );
                }
                let mut moved = p.clone();
                moved.index = (i as u64 + 1) % n as u64;
                if n > 1 {
                    assert!(!path_ok(&root, n32, &l[i], &moved), "another index");
                }
                let mut grown = p.clone();
                grown.n += 1;
                assert!(
                    !path_ok(&root, n32, &l[i], &grown),
                    "another size than the header's"
                );
                assert!(
                    !path_ok(&root, n32 + 1, &l[i], &p),
                    "another size than the path's"
                );
                let mut longer = p.clone();
                longer.siblings.push([0; 32]);
                assert!(!path_ok(&root, n32, &l[i], &longer), "a sibling too many");
                if let Some(short) = p.siblings.split_last().map(|(_, s)| s.to_vec()) {
                    let shorter = Path {
                        siblings: short,
                        ..p.clone()
                    };
                    assert!(!path_ok(&root, n32, &l[i], &shorter), "a sibling too few");
                }
                let mut changed = l[i];
                changed.seats ^= 1;
                assert!(!path_ok(&root, n32, &changed, &p), "a leaf changed");
            }
        }
    }

    #[test]
    fn leaves_out_of_order_or_twice_make_no_root() {
        let (a, b) = (leaf(1), leaf(2));
        assert!(bucket_root(&[a, b]).is_ok());
        assert_eq!(bucket_root(&[b, a]).err(), Some(GkError::Malformed));
        assert_eq!(bucket_root(&[a, a]).err(), Some(GkError::Malformed));
        assert!(inclusion_path(&[b, a], 0).is_none());
        assert!(!path_ok(
            &[0; 32],
            0,
            &a,
            &Path {
                index: 0,
                n: 0,
                siblings: vec![]
            }
        ));
    }
}
