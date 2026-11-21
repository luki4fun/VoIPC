//! The group key's wire (`voipc_protocol::gk`) to and from the types here. The wire's
//! types mirror these 1:1 and encode the same where they can (a `MemberId`, a `SeatRef`,
//! a `Leaf`); the conversions below are where they differ: a pool or origin as a bare
//! code, a path's `u32`s, a names list as its postcard bytes, a commit's header as one
//! field. A receiver runs the wire's own `check` first; what is left to refuse here is a
//! value no type here can hold.

use voipc_protocol::gk::{self, Bad};

use super::build::ListSeat;
use super::commit::{self, Commit, Make, Pair};
use super::keys::{self, Endorsement, Origin, SeatPublic};
use super::timers;
use super::{
    AddedSeat, Leaf, MemberId, NamesList, NamesStep, Path, Pool, SeatRef, Version, Via,
    BUCKET_SEATS, HEADER_MAX_BYTES, MAX_ADDED, MAX_GROUP_BYTES, MAX_KEYHOLDERS, MAX_REMOVED,
    ROW_BYTES, SEAT_WELCOME_BYTES, SMALL_WELCOME_BYTES,
};

// The wire's sizes are these.
const _: () = {
    assert!(gk::KEM_PUBLIC_BYTES == keys::KEM_PUBLIC_BYTES);
    assert!(gk::KEM_CT_BYTES == keys::KEM_CT_BYTES);
    assert!(gk::DH_PUBLIC_BYTES == keys::DH_PUBLIC_BYTES);
    assert!(gk::SEAT_WELCOME_BYTES == SEAT_WELCOME_BYTES);
    assert!(gk::SEED_WELCOME_BYTES == SMALL_WELCOME_BYTES);
    assert!(gk::KRK_WELCOME_BYTES == SMALL_WELCOME_BYTES);
    assert!(gk::ROW_BYTES == ROW_BYTES);
    assert!(gk::SEAL_BYTES == ROW_BYTES);
    assert!(gk::HEADER_MAX_BYTES == HEADER_MAX_BYTES);
    assert!(gk::MAX_GROUP_BYTES == MAX_GROUP_BYTES);
    assert!(gk::MAX_KEYHOLDERS == MAX_KEYHOLDERS);
    assert!(gk::MAX_REMOVED == MAX_REMOVED);
    assert!(gk::MAX_ADDED == MAX_ADDED);
    assert!(gk::BUCKET_SEATS == BUCKET_SEATS as usize);
    assert!(gk::MAX_JOINERS == timers::JOIN_BATCH_MAX);
    assert!(gk::COMMIT_MAX_BYTES == timers::COMMIT_MAX_BYTES);
    assert!(gk::CONN_OPEN_MAX_BYTES == timers::OPEN_PER_CONN_BYTES);
    assert!(gk::RELAY_OPEN_MAX_BYTES == timers::OPEN_PER_RELAY_BYTES);
    assert!(gk::PIECE_MAX_BYTES == timers::PIECE_MAX_BYTES);
    assert!(gk::BLOB_MAX_BYTES == timers::BLOB_MAX_BYTES);
    assert!(gk::BLOBS_MAX == timers::BLOBS_PER_WRITER);
    assert!(gk::WELCOMES_PER_FRAME == timers::SEED_WELCOMES_A_FRAME);
    assert!(gk::FETCH_AT_MAX == timers::PAST_A_FETCH);
};

fn pool(code: u8) -> Result<Pool, Bad> {
    match code {
        gk::pool::ACCOUNTS => Ok(Pool::Accounts),
        gk::pool::CONNS => Ok(Pool::Conns),
        _ => Err(Bad::Value("pool")),
    }
}

fn pool_code(p: Pool) -> u8 {
    match p {
        Pool::Accounts => gk::pool::ACCOUNTS,
        Pool::Conns => gk::pool::CONNS,
    }
}

// ── Members and seats ─────────────────────────────────────────────────────

impl From<gk::GkMember> for MemberId {
    fn from(m: gk::GkMember) -> MemberId {
        match m {
            gk::GkMember::Account(a) => MemberId::Account(a),
            gk::GkMember::Conn(u) => MemberId::Conn(u),
        }
    }
}

impl From<MemberId> for gk::GkMember {
    fn from(m: MemberId) -> gk::GkMember {
        match m {
            MemberId::Account(a) => gk::GkMember::Account(a),
            MemberId::Conn(u) => gk::GkMember::Conn(u),
        }
    }
}

impl From<gk::GkSeat> for SeatRef {
    fn from(s: gk::GkSeat) -> SeatRef {
        SeatRef {
            m: s.m.into(),
            tag_sk: s.sk,
            tag_sx: s.sx,
        }
    }
}

impl From<SeatRef> for gk::GkSeat {
    fn from(s: SeatRef) -> gk::GkSeat {
        gk::GkSeat {
            m: s.m.into(),
            sk: s.tag_sk,
            sx: s.tag_sx,
        }
    }
}

impl From<gk::HolderRef> for commit::HolderRef {
    fn from(h: gk::HolderRef) -> commit::HolderRef {
        commit::HolderRef {
            m: h.m.into(),
            kx: h.kx,
        }
    }
}

impl From<commit::HolderRef> for gk::HolderRef {
    fn from(h: commit::HolderRef) -> gk::HolderRef {
        gk::HolderRef {
            m: h.m.into(),
            kx: h.kx,
        }
    }
}

// ── Pairs ─────────────────────────────────────────────────────────────────

/// A pair the wire carries for member `m` (a seat's, a candidate's): its keys and its
/// endorsement, which names `Conn(u)` for a connection pair and `m` otherwise. Whether
/// `IK` endorsed it is the caller's to check (`Endorsement::verify`).
pub fn pair(p: &gk::EndorsedPair, m: gk::GkMember) -> Result<Pair, Bad> {
    p.check_for(&m)?;
    let origin = Origin::from_byte(p.origin).ok_or(Bad::Value("pair origin"))?;
    let m = match origin {
        Origin::Connection => MemberId::Conn(p.u),
        Origin::VaultSeat | Origin::Desktop => m.into(),
    };
    Ok(Pair {
        keys: SeatPublic::from_bytes(&p.kem, &p.dh).map_err(|_| Bad::Value("pair keys"))?,
        endorsement: Endorsement {
            origin,
            m,
            n: p.n,
            made: p.made,
            sig: p.sig[..].try_into().map_err(|_| Bad::Length("pair sig"))?,
        },
    })
}

impl From<&Pair> for gk::EndorsedPair {
    fn from(p: &Pair) -> gk::EndorsedPair {
        let e = &p.endorsement;
        gk::EndorsedPair {
            origin: e.origin as u8,
            u: match (e.origin, e.m) {
                (Origin::Connection, MemberId::Conn(u)) => u,
                _ => 0,
            },
            kem: p.keys.kem_bytes().into(),
            dh: p.keys.dh_bytes().into(),
            n: e.n,
            made: e.made,
            sig: e.sig.to_vec(),
        }
    }
}

// ── What a due asks ───────────────────────────────────────────────────────

impl TryFrom<&gk::Joiner> for commit::Joiner {
    type Error = Bad;
    fn try_from(j: &gk::Joiner) -> Result<commit::Joiner, Bad> {
        let Pair { keys, endorsement } = pair(&j.keys, j.seat.m)?;
        Ok(commit::Joiner {
            seat: j.seat.into(),
            ik: j.ik,
            keys,
            endorsement,
            returning: j.returning,
        })
    }
}

impl From<gk::ExitIn> for commit::Exit {
    fn from(x: gk::ExitIn) -> commit::Exit {
        commit::Exit {
            seq: x.seq,
            seat: x.seat.into(),
            b: x.b,
        }
    }
}

impl TryFrom<&gk::Candidate> for commit::Candidate {
    type Error = Bad;
    fn try_from(c: &gk::Candidate) -> Result<commit::Candidate, Bad> {
        Ok(commit::Candidate {
            m: c.m.into(),
            ik: c.ik,
            pair: pair(&c.pair, c.m)?,
        })
    }
}

/// A list `EpochLists` carried, as a keyholder's build takes it (`build::Lists`).
pub fn list(l: gk::ListIn) -> (Version, Vec<ListSeat>) {
    let seats = l
        .seats
        .into_iter()
        .map(|s| ListSeat {
            seat: s.seat.into(),
            dh: s.dh,
        })
        .collect();
    (Version { b: l.b, v: l.v }, seats)
}

// ── What a member takes ───────────────────────────────────────────────────

impl TryFrom<gk::LeafIn> for Leaf {
    type Error = Bad;
    fn try_from(l: gk::LeafIn) -> Result<Leaf, Bad> {
        Ok(Leaf {
            b: l.b,
            v: l.v,
            pool: pool(l.pool)?,
            seats: l.seats,
            list: l.list,
            via: l.via.map_or(Via::Row, |from| Via::Ratchet { from }),
        })
    }
}

impl From<Leaf> for gk::LeafIn {
    fn from(l: Leaf) -> gk::LeafIn {
        gk::LeafIn {
            b: l.b,
            v: l.v,
            pool: pool_code(l.pool),
            seats: l.seats,
            list: l.list,
            via: match l.via {
                Via::Row => None,
                Via::Ratchet { from } => Some(from),
            },
        }
    }
}

impl From<gk::PathIn> for Path {
    fn from(p: gk::PathIn) -> Path {
        Path {
            index: p.index.into(),
            n: p.n.into(),
            siblings: p.siblings,
        }
    }
}

impl TryFrom<Path> for gk::PathIn {
    type Error = Bad;
    /// A header's `buckets` is a `u32`, so a path past it is none of a header's.
    fn try_from(p: Path) -> Result<gk::PathIn, Bad> {
        Ok(gk::PathIn {
            index: p.index.try_into().map_err(|_| Bad::Value("path index"))?,
            n: p.n.try_into().map_err(|_| Bad::Value("path count"))?,
            siblings: p.siblings,
        })
    }
}

impl TryFrom<&gk::NamesListIn> for NamesList {
    type Error = Bad;
    /// `added` is the postcard of the list and nothing after it, at most `MAX_ADDED`.
    fn try_from(l: &gk::NamesListIn) -> Result<NamesList, Bad> {
        gk::names_added_count(&l.added)?;
        let (added, rest) = postcard::take_from_bytes::<Vec<AddedSeat>>(&l.added)
            .map_err(|_| Bad::Value("names list"))?;
        if !rest.is_empty() {
            return Err(Bad::Value("names list"));
        }
        Ok(NamesList {
            time: l.time,
            epoch: l.epoch,
            join: l.join,
            added,
        })
    }
}

impl From<&NamesList> for gk::NamesListIn {
    fn from(l: &NamesList) -> gk::NamesListIn {
        gk::NamesListIn {
            time: l.time,
            epoch: l.epoch,
            join: l.join,
            added: postcard::to_allocvec(&l.added).expect("a names list encodes"),
        }
    }
}

impl From<gk::NamesStepIn> for NamesStep {
    fn from(s: gk::NamesStepIn) -> NamesStep {
        NamesStep {
            before: s.before,
            time: s.time,
            epoch: s.epoch,
            join: s.join,
            list: s.list,
        }
    }
}

impl From<&NamesStep> for gk::NamesStepIn {
    fn from(s: &NamesStep) -> gk::NamesStepIn {
        gk::NamesStepIn {
            before: s.before,
            time: s.time,
            epoch: s.epoch,
            join: s.join,
            list: s.list,
        }
    }
}

// ── Commits ───────────────────────────────────────────────────────────────

impl TryFrom<gk::VersionOut> for commit::VersionOut {
    type Error = Bad;
    fn try_from(v: gk::VersionOut) -> Result<commit::VersionOut, Bad> {
        Ok(commit::VersionOut {
            b: v.b,
            v: v.v,
            pool: pool(v.pool)?,
            make: match v.make {
                gk::VersionMake::Ratchet { from_v } => Make::Ratchet { from_v },
                gk::VersionMake::Keep { from_v, mask } => Make::Keep { from_v, mask },
                gk::VersionMake::Seats(s) => Make::Seats(s.into_iter().map(Into::into).collect()),
            },
        })
    }
}

impl From<commit::VersionOut> for gk::VersionOut {
    fn from(v: commit::VersionOut) -> gk::VersionOut {
        gk::VersionOut {
            b: v.b,
            v: v.v,
            pool: pool_code(v.pool),
            make: match v.make {
                Make::Ratchet { from_v } => gk::VersionMake::Ratchet { from_v },
                Make::Keep { from_v, mask } => gk::VersionMake::Keep { from_v, mask },
                Make::Seats(s) => gk::VersionMake::Seats(s.into_iter().map(Into::into).collect()),
            },
        }
    }
}

/// A whole commit (`gk::join_commit`) as the validator takes it: its header split into
/// body and signature.
impl TryFrom<gk::CommitPiece> for Commit {
    type Error = Bad;
    fn try_from(c: gk::CommitPiece) -> Result<Commit, Bad> {
        let header = c.header.ok_or(Bad::Value("commit header"))?;
        Ok(Commit {
            body: header.body,
            sig: header.sig,
            versions: c
                .versions
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            drops: c.drops,
            welcomes: c
                .welcomes
                .into_iter()
                .map(|w| commit::WelcomeOut {
                    seat: w.seat.into(),
                    b: w.b,
                    v: w.v,
                    s: w.s,
                    bytes: w.bytes,
                })
                .collect(),
            rows: c
                .rows
                .into_iter()
                .map(|r| commit::RowsOut {
                    b: r.b,
                    v: r.v,
                    s: r.s,
                    up: r.up,
                    rows: r.rows,
                })
                .collect(),
            seals: c
                .seals
                .into_iter()
                .map(|s| commit::SealOut {
                    b: s.b,
                    v: s.v,
                    bytes: s.bytes,
                })
                .collect(),
            seed_welcomes: c
                .seed_welcomes
                .into_iter()
                .map(|w| commit::SeedWelcomeOut {
                    seat: w.seat.into(),
                    bytes: w.bytes,
                })
                .collect(),
            keyring: gk::commit_keyring(&c.keyring)?.to_vec(),
            krk: c
                .krk
                .into_iter()
                .map(|k| commit::KrkOut {
                    to: k.to.into(),
                    from_kx: k.from_kx,
                    bytes: k.bytes,
                })
                .collect(),
            refused: c
                .refused
                .into_iter()
                .map(|r| commit::Refused {
                    seat: r.seat.into(),
                    why: r.why,
                })
                .collect(),
        })
    }
}

/// A built commit as one whole piece for `gk::cut_commit`: its keyring part framed as the
/// one entry of the keyring stream.
impl TryFrom<Commit> for gk::CommitPiece {
    type Error = Bad;
    fn try_from(c: Commit) -> Result<gk::CommitPiece, Bad> {
        let mut keyring = Vec::new();
        gk::put_keyring_entry(&mut keyring, &c.keyring)?;
        Ok(gk::CommitPiece {
            header: Some(gk::HeaderIn {
                body: c.body,
                sig: c.sig,
            }),
            versions: c.versions.into_iter().map(Into::into).collect(),
            drops: c.drops,
            welcomes: c
                .welcomes
                .into_iter()
                .map(|w| gk::WelcomeOut {
                    seat: w.seat.into(),
                    b: w.b,
                    v: w.v,
                    s: w.s,
                    bytes: w.bytes,
                })
                .collect(),
            rows: c
                .rows
                .into_iter()
                .map(|r| gk::RowsOut {
                    b: r.b,
                    v: r.v,
                    s: r.s,
                    up: r.up,
                    rows: r.rows,
                })
                .collect(),
            seals: c
                .seals
                .into_iter()
                .map(|s| gk::SealOut {
                    b: s.b,
                    v: s.v,
                    bytes: s.bytes,
                })
                .collect(),
            seed_welcomes: c
                .seed_welcomes
                .into_iter()
                .map(|w| gk::SeedWelcomeOut {
                    seat: w.seat.into(),
                    bytes: w.bytes,
                })
                .collect(),
            keyring,
            krk: c
                .krk
                .into_iter()
                .map(|k| gk::KrkOut {
                    to: k.to.into(),
                    from_kx: k.from_kx,
                    bytes: k.bytes,
                })
                .collect(),
            refused: c
                .refused
                .into_iter()
                .map(|r| gk::JoinRefused {
                    seat: r.seat.into(),
                    why: r.why,
                })
                .collect(),
        })
    }
}

// ── Posts ─────────────────────────────────────────────────────────────────

/// An `EpochPost`'s name in `ServerMessage::EpochPostTaken`: the first 16 bytes of SHA-256 over
/// its `ciphertext`. The relay names the post it took by it, the writer's app finds the post's
/// kept copy by it (`group_state::Copies::taken`). One writer's two posts never seal to the
/// same bytes (each has its own message key and nonce), so the name is the post's.
pub fn post_digest(ciphertext: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(ciphertext);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_key::build::world::{Member, World};
    use crate::group_key::{bucket_root, inclusion_path, path_ok};
    use voipc_protocol::messages::ClientMessage;

    #[test]
    fn a_built_commit_survives_the_wire_and_the_validator_takes_it() {
        let mut w = World::text(true, false);
        let people: Vec<Member> = (1..=40).map(Member::numbered).collect();
        let due = w.join_due(&people.iter().collect::<Vec<_>>());
        let b = w.build_join(&due, None).unwrap();
        let whole = gk::CommitPiece::try_from(b.commit.clone()).unwrap();
        let max = gk::PIECE_MAX_BYTES - gk::commit_frame_overhead(w.id);
        let pieces = gk::cut_commit(whole, max).unwrap();
        assert!(pieces.len() > 1, "{} parts", pieces.len());
        let n = pieces.len();
        let mut parts: gk::Parts<u64, gk::CommitPiece> = gk::Parts::new(gk::Seq::Commit);
        let mut joined = None;
        for (i, piece) in pieces.into_iter().enumerate() {
            let msg = ClientMessage::EpochCommit {
                group: w.id.into(),
                due: 7,
                part: i as u16,
                last: i + 1 == n,
                piece,
            };
            let frame = voipc_protocol::codec::encode_client_msg(&msg).unwrap();
            assert!(frame.len() - 4 <= gk::PIECE_MAX_BYTES);
            let ClientMessage::EpochCommit {
                due,
                part,
                last,
                piece,
                ..
            } = voipc_protocol::codec::decode_client_msg(&frame[4..]).unwrap()
            else {
                panic!("not EpochCommit");
            };
            piece.check_items().unwrap();
            let took = parts.take(due, part, last, piece, frame.len() - 4);
            if let gk::Part::Whole(7, got) = took.part {
                joined = Some(gk::join_commit(got).unwrap());
            }
        }
        let back = Commit::try_from(joined.unwrap()).unwrap();
        assert_eq!(back, b.commit);
        assert!(w.check(&due, w.holders[0].by(), &back).is_ok());
    }

    #[test]
    fn a_commit_without_its_header_or_one_keyring_entry_is_refused() {
        let piece = gk::CommitPiece::default();
        assert_eq!(
            Commit::try_from(piece.clone()),
            Err(Bad::Value("commit header"))
        );
        let headed = gk::CommitPiece {
            header: Some(gk::HeaderIn {
                body: vec![1],
                sig: vec![0; 64],
            }),
            ..piece
        };
        assert_eq!(Commit::try_from(headed), Err(Bad::Count("commit keyring")));
    }

    #[test]
    fn a_joiners_pair_names_its_connection_or_its_account() {
        for m in [Member::numbered(1), Member::conn(9)] {
            let j = m.joiner();
            let p = Pair {
                keys: j.keys.clone(),
                endorsement: j.endorsement.clone(),
            };
            let wire = gk::Joiner {
                seat: j.seat.into(),
                ik: j.ik,
                keys: gk::EndorsedPair::from(&p),
                returning: true,
            };
            wire.check().unwrap();
            let back = commit::Joiner::try_from(&wire).unwrap();
            assert_eq!(back.seat, j.seat);
            assert_eq!(back.endorsement, j.endorsement);
            assert_eq!(back.keys.kem_bytes(), j.keys.kem_bytes());
            assert_eq!(back.keys.dh_bytes(), j.keys.dh_bytes());
            assert!(back.returning);
        }
        // A connection pair that names another connection than the seat's
        let j = Member::conn(9).joiner();
        let mut wire = gk::EndorsedPair::from(&Pair {
            keys: j.keys.clone(),
            endorsement: j.endorsement.clone(),
        });
        wire.u = 10;
        assert!(pair(&wire, j.seat.m.into()).is_err());
    }

    #[test]
    fn leaves_and_paths_cross_the_wire_unchanged() {
        let mut w = World::text(true, false);
        let people: Vec<Member> = (1..=130).map(Member::numbered).collect();
        w.join(&people.iter().collect::<Vec<_>>());
        let leaves: Vec<Leaf> = w.leaves.iter().map(|l| l.leaf).collect();
        assert!(leaves.len() > 2);
        let root = bucket_root(&leaves).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let wire = gk::LeafIn::from(*leaf);
            wire.check().unwrap();
            assert_eq!(postcard::to_allocvec(&wire).unwrap(), leaf.encode());
            assert_eq!(Leaf::try_from(wire).unwrap(), *leaf);
            let path = gk::PathIn::try_from(inclusion_path(&leaves, i).unwrap()).unwrap();
            path.check().unwrap();
            assert!(path_ok(&root, leaves.len() as u32, leaf, &Path::from(path)));
        }
        let ratchet = Leaf {
            via: Via::Ratchet { from: 5 },
            ..leaves[0]
        };
        assert_eq!(Leaf::try_from(gk::LeafIn::from(ratchet)).unwrap(), ratchet);
        let bad_pool = gk::LeafIn {
            pool: 2,
            ..gk::LeafIn::from(leaves[0])
        };
        assert_eq!(Leaf::try_from(bad_pool), Err(Bad::Value("pool")));
        let far = Path {
            index: 1 << 32,
            n: (1 << 32) + 1,
            siblings: vec![],
        };
        assert!(gk::PathIn::try_from(far).is_err());
    }

    #[test]
    fn a_names_list_is_its_postcard_and_nothing_after() {
        let list = NamesList {
            time: 5,
            epoch: 2,
            join: 1,
            added: (1..=3)
                .map(|i| Member::numbered(i).joiner().added())
                .collect(),
        };
        let wire = gk::NamesListIn::from(&list);
        wire.check().unwrap();
        assert_eq!(NamesList::try_from(&wire).unwrap(), list);
        let mut longer = wire.clone();
        longer.added.push(0);
        assert!(NamesList::try_from(&longer).is_err());
        let step = list.step_from(&[9; 32]);
        assert_eq!(NamesStep::from(gk::NamesStepIn::from(&step)), step);
    }

    /// The relay and the app name a post by these bytes: pinned, so neither side moves alone.
    #[test]
    fn a_posts_digest_is_the_start_of_its_sha256() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            post_digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23
            ]
        );
        assert_ne!(post_digest(b"abc"), post_digest(b"abd"));
    }
}
