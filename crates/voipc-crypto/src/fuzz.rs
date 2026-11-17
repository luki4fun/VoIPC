//! Fuzz targets: bytes another account or the relay controls, through the
//! parsers in front of each AEAD and signature check. `fuzz/fuzz_targets/
//! <name>.rs` calls `fuzz_<name>` under cargo-fuzz; the test below replays
//! `fuzz/regressions/<name>/*` on stable, so an input that once crashed stays
//! a test. Keys are fixed, so a crash replays the same way.

use crate::account::{self, Pins, Vault};
use crate::file::{self, FileMeta};
use crate::log::{self, LogKey};
use crate::pair;
use crate::{envelope, MediaKey};
use voipc_protocol::types::VaultBlob;

const RELAY: [u8; 16] = [0x5a; 16];

/// What a channel member sends inside a Signal message: chat envelopes,
/// history payloads (JSON) and media keys.
pub fn fuzz_envelope(data: &[u8]) {
    let _ = envelope::open_envelope(data);
    let _ = envelope::open_history_payload(1, data);
    let _ = MediaKey::from_bytes(data);
}

/// Keys and pins out of vault items, and a typed recovery key.
pub fn fuzz_keys(data: &[u8]) {
    let _ = LogKey::from_bytes(data);
    let _ = Pins::from_bytes(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = account::recovery_parse(text);
    }
}

/// Kept entries and epoch-key wraps from the relay: the first byte splits the
/// input into the sender's published log key and the sealed bytes.
pub fn fuzz_log(data: &[u8]) {
    let own = LogKey::from_bytes(&[0x11; 32]).expect("a fixed private key");
    let (sender_logkey, sealed) = match data.split_first() {
        Some((&n, rest)) => rest.split_at((n as usize).min(rest.len())),
        None => (&[][..], data),
    };
    let _ = log::open_entry(&[7; 32], "c:fuzz", &[1; 16], 1, sender_logkey, sealed);
    let _ = log::unwrap(&own, data, "c:fuzz", &[1; 16], 1, &[2; 16]);
    let _ = log::self_unwrap(&own, data, "c:fuzz", &[2; 16], 1);

    let chain = log::Chain {
        conv: "c:fuzz",
        owner: &[1; 16],
        chain: 1,
    };
    let bucket = log::Bucket {
        conv: "c:fuzz",
        owner: &[1; 16],
        id: 1,
        version: 2,
    };
    let key = [7; 32];
    let _ = log::open_chain_entry(&key, "c:fuzz", &[1; 16], 1, sender_logkey, sealed);
    let _ = log::self_open_state(&own, data, "c:fuzz", &[2; 16], 1);
    let _ = chain.follow(0, &key, data);
    let _ = chain.open_link(&key, 0, data);
    let _ = bucket.open_own_row(&own, data);
    let _ = bucket.open_list(&own, data, &[0; 32]);
    let _ = bucket.open_seal(&key, 1, 0, data);
    let _ = bucket.open_link_down(&key, 1, data);
    if let Some(peer) = log::StaticKey::new(&own, sender_logkey) {
        let _ = peer.open_seat(sealed, bucket, &[2; 16]);
        let _ = peer.open_state(sealed, "c:fuzz", &[1; 16], 1, &[2; 16]);
    }
}

/// Vault blobs as the relay hands them out: a slot opened with a fixed vault
/// key (no password stretching per input), and an item under a fixed DEK.
pub fn fuzz_vault(data: &[u8]) {
    let blobs: Vec<VaultBlob> = ["slot.pass", "item.fuzz"]
        .iter()
        .map(|k| VaultBlob {
            k: (*k).into(),
            v: data.to_vec(),
            version: 0,
        })
        .collect();
    let _ = Vault::open_with_password(RELAY, "fuzz", &blobs, &[7; 32]);
    let _ = Vault::from_dek(RELAY, "fuzz", [7; 32]).open_item(&blobs, "item.fuzz");
}

/// A file blob from the relay, and the claims its sender's message makes
/// about it. The first byte says whether the body is deflated, the next two
/// give the size (small, so each input inflates little). The rest goes three
/// ways: as a whole blob, behind a valid commitment (the framing and the
/// AEAD), and straight into the inflate, which only a sender reaches, since
/// a fuzzer cannot forge a GCM tag. A seal of it must open again.
pub fn fuzz_file(data: &[u8]) {
    const KEY: [u8; 32] = [7; 32];
    let (deflated, size, rest) = match data {
        [flags, a, b, rest @ ..] => (flags & 1 == 1, u16::from_be_bytes([*a, *b]), rest),
        _ => (false, 0, data),
    };
    let meta = |blob: &[u8]| FileMeta {
        hash: file::blob_hash(blob),
        key: KEY,
        size: size as u64,
        deflated,
    };
    let _ = file::open(&meta(rest), rest);
    let committed = [&file::commitment(&KEY, deflated, size as u64)[..], rest].concat();
    let _ = file::open(&meta(&committed), &committed);
    let _ = file::inflate(rest, size as usize);

    let (meta, blob) = file::seal_with(KEY, rest, true).expect("small enough");
    assert_eq!(file::open(&meta, &blob).as_deref(), Ok(rest));
}

/// What a pairing's frames carry, from the relay or the other device: a commitment, an
/// ephemeral key and its blind, the answer's key and a wrapped vault key (W3-35). The
/// request's own keys are drawn fresh, as a device draws them: no input reaches anything
/// that turns on them but the six digits.
pub fn fuzz_pair(data: &[u8]) {
    let mut rest = data;
    let mut take = |n: usize| {
        let (a, b) = rest.split_at(n.min(rest.len()));
        rest = b;
        a
    };
    let (commitment, ephemeral, blind, nonce) = (take(32), take(33), take(32), take(32));
    let wrapped = rest;
    let _ = pair::code(commitment, nonce, ephemeral);
    let _ = pair::reveal_ok(commitment, ephemeral, blind);
    let mut asks = pair::PairRequest::new();
    if asks.take_answer(nonce).is_some() {
        assert!(asks.take_answer(nonce).is_none(), "one answer");
        let _ = asks.open(wrapped, &RELAY, "fuzz");
    }
}

/// The group key's openers (`group_key`), its header decoder and the Merkle
/// path check, under fixed keys made once. Every input also goes through
/// the welcome openers at their exact lengths, so the Kyber decapsulation
/// and the KDF run on it. A header that decodes runs through the rules too,
/// which must not panic on any header that passes the form.
///
/// A fuzzer cannot forge a GCM tag, so, as `fuzz_file` does, the input is
/// also sealed under the fixed keys as a writer blob's, a history row's and
/// a keyring's plaintext, and the keyring under a head that commits to it:
/// that way the parsers behind each AEAD and behind the keyring's hash
/// chain run on it too.
pub fn fuzz_group(data: &[u8]) {
    use crate::group_key::fuzz_seal;
    use crate::group_key::*;
    use std::sync::OnceLock;

    struct Fixed {
        g: Group,
        voice: Group,
        member: SeatPair,
        holder: SeatPair,
        seat_keys: SeatKeys,
        ik: libsignal_protocol::IdentityKeyPair,
        /// The keyholder header the keyring's head names.
        genesis: SignedHeader,
    }
    static FIXED: OnceLock<Fixed> = OnceLock::new();
    let f = FIXED.get_or_init(|| {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x6b61);
        let gen = [0x11; 16];
        let member = SeatPair::generate_with(&mut rng);
        let holder = SeatPair::generate_with(&mut rng);
        let seat_keys = SeatKeys::generate_with(&mut rng, 1, 1);
        let ik = libsignal_protocol::IdentityKeyPair::generate(&mut rng);
        let genesis = SignedHeader::sign(fuzz_genesis(&ik, &holder.public()), &ik)
            .expect("a well-formed Genesis");
        Fixed {
            g: Group::new(GroupKind::Text, "c:fuzz", gen).expect("a valid id"),
            voice: Group::new(GroupKind::Voice, "c:fuzz", gen).expect("a valid id"),
            member,
            holder,
            seat_keys,
            ik,
            genesis,
        }
    });
    let g = &f.g;
    let m = MemberId::Account([1; 16]);
    let me = Me { m, keys: &f.member };
    let holder = Holder::new(MemberId::Account([2; 16]), &f.holder.public().dh_bytes())
        .expect("a fixed key");
    let at = Version { b: 1, v: 2 };
    let ep = Epoch { e: 3, d_e: [4; 32] };
    let key = [7u8; 32];

    let sized = |n: usize| {
        let mut v = data.to_vec();
        v.resize(n, 0);
        v
    };
    for w in [
        data,
        &sized(SEAT_WELCOME_BYTES),
        &sized(SMALL_WELCOME_BYTES),
    ] {
        let _ = open_seat_welcome(g, 1, at, &me, &holder, w);
        let _ = open_seed_welcome(g, 1, &me, &holder, w);
        let _ = open_keyring_welcome(g, 1, 3, &[5; 32], &me, &holder, w);
    }
    if let Ok(rb) = RowBase::member_side(g, 1, &me, &holder, &key) {
        let _ = rb.open_row(at, data);
    }
    let seat = me.keys.public().seat(m);
    let _ = open_seal(g, &ep, at, &key, data);
    let _ = open_chain_seal(g, &ep, &m, 1, 0, &key, data);
    let _ = open_self_row(g, 1, &seat, f.seat_keys.self_key(), data);
    let _ = open_history_row(g, 1, &seat, f.seat_keys.self_key(), data);
    let _ = open_writer_blob(g, &ep, &Writer { m, u: 1 }, &key, data);
    let _ = open_post(&[0x11; 16], &ep, data);
    let _ = media_key(&f.voice, &ep, &m, &[0; 8], 1, &key);
    let _ = SeatKeys::from_bytes(data);
    let (kem, dh) = data.split_at(data.len().min(1569));
    let _ = SeatPublic::from_bytes(kem, dh);
    let _ = Holder::new(m, data);
    let _ = open_keyring_part(g, 3, 1, &[5; 32], &key, KeyringPart::Base, data);
    let _ = open_keyring_part(g, 3, 1, &[5; 32], &key, KeyringPart::Delta(1), data);

    // Past the AEADs: the input as a blob's and a history row's plaintext.
    let w = Writer { m, u: 1 };
    let _ = open_writer_blob(g, &ep, &w, &key, &fuzz_seal::writer(g, &ep, &w, &key, data));
    let self_key = f.seat_keys.self_key();
    let _ = open_history_row(
        g,
        1,
        &seat,
        self_key,
        &fuzz_seal::history(g, 1, &seat, self_key, data),
    );
    fuzz_keyring(g, f.genesis.clone(), &f.ik, &key, data);

    // The Merkle path check: a root, a leaf, an index and a count, siblings.
    if data.len() >= 32 + 8 {
        let root: [u8; 32] = data[..32].try_into().expect("32 bytes");
        let index = u64::from(data[32]);
        let n = u32::from(data[33]);
        if let Ok((leaf, rest)) = postcard::take_from_bytes::<Leaf>(&data[34..]) {
            let siblings = rest.as_chunks::<32>().0.to_vec();
            let path = Path {
                index,
                n: u64::from(n),
                siblings,
            };
            let _ = path_ok(&root, n, &leaf, &path);
        }
    }
    // Leaves from the input, sorted: every leaf's path checks out, and only there.
    let mut leaves: Vec<Leaf> = data
        .chunks(9)
        .map(|c| Leaf {
            b: (u64::from(c[0]) << 8) | c.len() as u64,
            v: c.iter().map(|&b| u64::from(b)).sum(),
            pool: if c[0] & 1 == 0 {
                Pool::Accounts
            } else {
                Pool::Conns
            },
            seats: u16::from(c[0] % 62) + 1,
            list: [c[0]; 32],
            via: Via::Row,
        })
        .collect();
    leaves.sort_by_key(|l| l.b);
    leaves.dedup_by_key(|l| l.b);
    let root = bucket_root(&leaves).expect("sorted, each once");
    for (i, leaf) in leaves.iter().enumerate() {
        let path = inclusion_path(&leaves, i).expect("in range");
        assert!(path_ok(&root, leaves.len() as u32, leaf, &path));
    }

    // Headers: the body after a 64-byte signature.
    let (sig, body) = data.split_at(data.len().min(64));
    for (kind, group) in [(GroupKind::Text, "c:fuzz"), (GroupKind::Voice, "c:fuzz")] {
        let Ok(h) = SignedHeader::decode(body, sig, kind, group) else {
            continue;
        };
        assert_eq!(h.header().encode(), body, "only the one encoding decodes");
        let none = |_: &[u8; 16]| None;
        let floor = Floor::after(None, &h, h.header().time);
        let _ = check_link(&h, &h);
        let _ = check_on_floor(&floor, &h);
        let _ = check_signer(&h, Some(&h), &none);
        let top = |_: &[u8; 16]| {
            Some(Seen {
                n: u32::MAX,
                made: 0,
            })
        };
        let _ = check_gated(h.header(), Some(true));
        let _ = check_counters(h.header(), &[], &top, Some([1; 16]));
        let _ = check_added(h.header(), &none, &top, Some([1; 16]));
        let _ = check_keyholder_change(&h.header().keyholders, h.header());
        let _ = replaced_entry(&h.header().keyholders, h.header());
        let rolls = SeedRolls::at_start(h.header());
        let _ = check_roll(rolls, h.header(), h.header());
        let _ = row_seed(h.header().seed, h.header());
        let _ = check_time(h.header(), 0);
        let _ = epoch_bound_ok(0, 0, h.header());
        let _ = check_new_generation(
            Some(&floor),
            Clock {
                now: 0,
                taken: Some(0),
            },
            h.header(),
        );
        let _ = check_walk(
            WalkTo::Floor {
                floor: &floor,
                kh: &h,
            },
            &[WalkLink {
                header: &h,
                parent: Some(&h),
            }],
            WalkLink {
                header: &h,
                parent: Some(&h),
            },
            Clock {
                now: 0,
                taken: None,
            },
            &none,
        );
        let known = Known {
            pins: &|_, _| PinThen::Unknown,
            counters: &top,
            own: Some([1; 16]),
            now: u64::MAX,
        };
        let lists = [NamesList::of(h.header())];
        let removals = std::slice::from_ref(&h);
        let _ = fold_names(&NamesFrom::Start, &lists, removals, h.header(), &known);
        let names_floor = NamesFloor::of(h.header());
        let step = lists[0].step_from(&[0; 32]);
        for from in [
            NamesFrom::Floor(names_floor),
            NamesFrom::Gone {
                floor: names_floor,
                step,
            },
        ] {
            let _ = fold_names(&from, &lists, removals, h.header(), &known);
        }
        let _ = take_keyring(g, &h, &h, &key, body, &[]);
    }
}

/// The fixed Genesis of `c:fuzz`, with one desktop keyholder.
fn fuzz_genesis(
    ik: &libsignal_protocol::IdentityKeyPair,
    holder: &crate::group_key::SeatPublic,
) -> crate::group_key::HeaderV1 {
    use crate::group_key::*;
    HeaderV1 {
        group_kind: GroupKind::Text,
        group: "c:fuzz".into(),
        gen: [0x11; 16],
        epoch: 1,
        join: 0,
        kind: Kind::Genesis,
        time: 1,
        parent: [0; 32],
        epoch_parent: [0; 32],
        kh_parent: [0; 32],
        signer: MemberId::Account([2; 16]),
        keyholders: vec![Keyholder {
            m: MemberId::Account([2; 16]),
            u: None,
            origin: 3,
            n: 0,
            ik: ik
                .public_key()
                .public_key_bytes()
                .try_into()
                .expect("32 bytes"),
            kx: holder.dh_bytes()[1..].try_into().expect("32 bytes"),
            tag_kk: holder.tag_kem(),
        }],
        gated: false,
        seed: 1,
        seed_floor: 1,
        exits_upto: 0,
        seats: 1,
        buckets: 1,
        conn_seats: 0,
        bucket_root: [1; 32],
        keyring_hash: [2; 32],
        names_hash: [0; 32],
        added: Added::Count(1),
        removed: Removed::Count(0),
        confirm: [3; 32],
    }
}

/// The keyring past its AEADs and its hash chain: the input split into a
/// base and a delta's plaintext (the first byte says where), each sealed
/// under `krk` in the context of a Join head at `j = 1` after `genesis`, and
/// the head committing to both. Where the base decodes, the head also takes
/// its epoch, seed range, `ck` and buckets, so the input runs on into the
/// checks after `confirm` and the bucket root.
fn fuzz_keyring(
    g: &crate::group_key::Group,
    genesis: crate::group_key::SignedHeader,
    ik: &libsignal_protocol::IdentityKeyPair,
    krk: &[u8; 32],
    data: &[u8],
) {
    use crate::group_key::fuzz_seal;
    use crate::group_key::*;
    let (cut, rest) = match data.split_first() {
        Some((&c, rest)) => (usize::from(c) * 4, rest),
        None => (0, data),
    };
    let (base_plain, delta_plain) = rest.split_at(cut.min(rest.len()));
    let mut head = HeaderV1 {
        join: 1,
        kind: Kind::Join,
        time: 2,
        parent: genesis.d(),
        epoch_parent: genesis.d(),
        kh_parent: genesis.d(),
        keyholders: vec![],
        ..genesis.header().clone()
    };
    if let Ok(base) = postcard::from_bytes::<KeyringBase>(base_plain) {
        head.epoch = base.epoch.max(1);
        if let (Some((floor, _)), Some((seed, _))) = (base.seeds.first(), base.seeds.last()) {
            if (1..=*seed).contains(floor) {
                (head.seed_floor, head.seed) = (*floor, *seed);
            }
        }
        head.confirm = confirm(g, head.epoch, 1, &base.ck);
        let mut all = base.buckets.clone();
        if let Ok(delta) = postcard::from_bytes::<KeyringDelta>(delta_plain) {
            all.extend(delta.buckets.iter().cloned());
        }
        all.sort_by_key(|b| b.b);
        let leaves: Vec<Leaf> = all.iter().map(KeyringBucket::leaf).collect();
        head.bucket_root = bucket_root(&leaves).unwrap_or([0; 32]);
        let sum = |pool: Option<Pool>| {
            all.iter()
                .filter(|b| pool.is_none_or(|p| b.pool == p))
                .fold(0u32, |n, b| n.saturating_add(u32::from(b.seats)))
        };
        head.buckets = u32::try_from(all.len()).unwrap_or(u32::MAX);
        head.seats = sum(None);
        head.conn_seats = sum(Some(Pool::Conns));
    }
    let ks = keyholder_set_digest(&genesis.header().keyholders);
    let (e, s) = (head.epoch, head.seed);
    let base = fuzz_seal::keyring(g, e, s, &ks, krk, KeyringPart::Base, base_plain);
    let delta = fuzz_seal::keyring(g, e, s, &ks, krk, KeyringPart::Delta(1), delta_plain);
    head.keyring_hash = keyring_hash_next(&keyring_hash_start(&base), &delta);
    if let Ok(head) = SignedHeader::sign(head, ik) {
        let _ = take_keyring(g, &head, &genesis, krk, &base, &[delta]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Edge inputs, a valid one, and every file in fuzz/regressions/<target>/.
    fn replay(target: &str, valid: &[u8], f: fn(&[u8])) {
        for input in [&[][..], &[0xff; 64], &[0; 64], valid] {
            f(input);
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/regressions")
            .join(target);
        for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            f(&std::fs::read(file.path()).unwrap());
        }
    }

    /// A header the fuzz target decodes: a signature, then a body.
    fn group_input() -> Vec<u8> {
        use crate::group_key::*;
        let ik = libsignal_protocol::IdentityKeyPair::generate(&mut crate::rng());
        let kx = SeatPair::generate().public();
        let h = HeaderV1 {
            group_kind: GroupKind::Text,
            group: "c:fuzz".into(),
            gen: [0x11; 16],
            epoch: 1,
            join: 0,
            kind: Kind::Genesis,
            time: 1,
            parent: [0; 32],
            epoch_parent: [0; 32],
            kh_parent: [0; 32],
            signer: MemberId::Account([1; 16]),
            keyholders: vec![Keyholder {
                m: MemberId::Account([1; 16]),
                u: None,
                origin: 3,
                n: 0,
                ik: ik.public_key().public_key_bytes().try_into().unwrap(),
                kx: kx.dh_bytes()[1..].try_into().unwrap(),
                tag_kk: kx.tag_kem(),
            }],
            gated: false,
            seed: 1,
            seed_floor: 1,
            exits_upto: 0,
            seats: 1,
            buckets: 1,
            conn_seats: 0,
            bucket_root: [1; 32],
            keyring_hash: [2; 32],
            names_hash: [0; 32],
            added: Added::Count(1),
            removed: Removed::Count(0),
            confirm: [3; 32],
        };
        let h = SignedHeader::sign(h, &ik).unwrap();
        [&h.sig()[..], h.body()].concat()
    }

    #[test]
    fn the_fuzz_targets_replay_on_stable() {
        let vault = Vault::from_dek(RELAY, "fuzz", [7; 32]);
        replay(
            "envelope",
            br#"{"v":1,"kind":"chat","text":"hi"}"#,
            fuzz_envelope,
        );
        replay("keys", &[0x11; 32], fuzz_keys);
        replay("log", &[33; 64], fuzz_log);
        replay("file", &[1, 0, 64, 0x63, 0x60, 0xa0, 0x0c, 0, 0], fuzz_file);
        replay("pair", &[9; 200], fuzz_pair);
        replay("group", &group_input(), fuzz_group);
        replay(
            "vault",
            &vault.seal_item("item.fuzz", 1, b"payload").v,
            fuzz_vault,
        );
    }
}
