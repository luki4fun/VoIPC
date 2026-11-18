//! The bucket tree, built once per head (plan 2a, part 10).
//!
//! `inclusion_path` re-hashes every leaf on each call: 321 µs at 1613 leaves,
//! so a 100k fetch burst would cost a relay's group actor about 32 s. This
//! keeps every level of the tree instead (334 µs to build at 1613 leaves) and
//! cuts any leaf's path from it in O(log n).
//!
//! The levels pair neighbours from the left and carry a lone last node up
//! unchanged. That is the tree of RFC 6962 §2.1, the one `bucket_root`
//! splits at the largest power of two: both give the same root and the same
//! paths (the tests compare them for every leaf of trees up to 130 leaves).

use sha2::{Digest, Sha256};

use super::merkle::{leaf_hash, node, Leaf, Path};
use super::GkError;

/// Every level of a head's bucket tree: level 0 holds the leaf hashes, the
/// last level the root. With the leaves' bucket ids, to find a leaf by `b`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketTree {
    levels: Vec<Vec<[u8; 32]>>,
    bs: Vec<u64>,
}

impl BucketTree {
    /// From a head's leaves, sorted by `b` and each bucket once, as
    /// `bucket_root` takes them; `Malformed` otherwise.
    pub fn new(leaves: &[Leaf]) -> Result<BucketTree, GkError> {
        if !leaves.windows(2).all(|w| w[0].b < w[1].b) {
            return Err(GkError::Malformed);
        }
        let mut levels = vec![leaves.iter().map(leaf_hash).collect::<Vec<_>>()];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let below = levels.last().expect("a level");
            let up = below
                .chunks(2)
                .map(|p| match p {
                    [l, r] => node(l, r),
                    [lone] => *lone,
                    _ => unreachable!("chunks of two"),
                })
                .collect();
            levels.push(up);
        }
        Ok(BucketTree {
            levels,
            bs: leaves.iter().map(|l| l.b).collect(),
        })
    }

    /// The root `bucket_root` gives for the same leaves: `SHA-256("")` for
    /// none.
    pub fn root(&self) -> [u8; 32] {
        match self.levels.last().and_then(|l| l.first()) {
            Some(r) => *r,
            None => Sha256::digest([]).into(),
        }
    }

    pub fn len(&self) -> usize {
        self.bs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bs.is_empty()
    }

    /// Where bucket `b` sits.
    pub fn index_of(&self, b: u64) -> Option<usize> {
        self.bs.binary_search(&b).ok()
    }

    /// The path of leaf `index`, equal to `inclusion_path`'s, cut from the
    /// kept levels: at each level the neighbour, or nothing for a lone node
    /// carried up.
    pub fn path(&self, index: usize) -> Option<Path> {
        if index >= self.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut i = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = i ^ 1;
            if sib < level.len() {
                siblings.push(level[sib]);
            }
            i >>= 1;
        }
        Some(Path {
            index: index as u64,
            n: self.len() as u64,
            siblings,
        })
    }

    /// The path of bucket `b`'s leaf.
    pub fn path_of(&self, b: u64) -> Option<Path> {
        self.path(self.index_of(b)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_key::merkle::{bucket_root, inclusion_path, path_ok, Pool, Via};

    fn leaves(n: u64) -> Vec<Leaf> {
        (0..n)
            .map(|i| Leaf {
                b: i * 5 + 3,
                v: i ^ 0x55,
                pool: if i % 3 == 0 {
                    Pool::Conns
                } else {
                    Pool::Accounts
                },
                seats: (i % 62) as u16 + 1,
                list: [i as u8; 32],
                via: Via::Row,
            })
            .collect()
    }

    #[test]
    fn a_bucket_tree_gives_the_root_and_every_path_inclusion_path_gives() {
        for n in 0..=130u64 {
            let l = leaves(n);
            let tree = BucketTree::new(&l).unwrap();
            let root = bucket_root(&l).unwrap();
            assert_eq!(tree.root(), root, "n {n}");
            assert_eq!(tree.len(), n as usize);
            assert_eq!(tree.is_empty(), n == 0);
            for i in 0..n as usize {
                let p = tree.path(i).unwrap();
                assert_eq!(Some(p.clone()), inclusion_path(&l, i), "n {n} i {i}");
                assert!(path_ok(&root, n as u32, &l[i], &p));
                assert_eq!(tree.path_of(l[i].b), Some(p));
            }
            assert_eq!(tree.path(n as usize), None);
        }
    }

    #[test]
    fn a_bucket_tree_finds_a_leaf_by_its_bucket_and_nothing_else() {
        let l = leaves(9);
        let tree = BucketTree::new(&l).unwrap();
        assert_eq!(tree.index_of(l[4].b), Some(4));
        assert_eq!(tree.index_of(l[4].b + 1), None);
        assert_eq!(tree.path_of(1), None);
    }

    #[test]
    fn leaves_out_of_order_or_twice_make_no_tree() {
        let mut l = leaves(3);
        l.swap(0, 2);
        assert_eq!(BucketTree::new(&l).err(), Some(GkError::Malformed));
        let mut twice = leaves(2);
        twice[1].b = twice[0].b;
        assert_eq!(BucketTree::new(&twice).err(), Some(GkError::Malformed));
    }
}
