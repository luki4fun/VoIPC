//! Seat keys, keyholder keys, tags, endorsements and the XEdDSA wrapper
//! (§2, §11.2, §11.8).
//!
//! A seat key pair is Kyber1024 `SK` with X25519 `SX`; a keyholder pair is the
//! same shape (`KK`, `KX`) and the same type here, `SeatPair`. Which one a
//! pair is shows in its endorsement's origin and in where it is used.

use libsignal_protocol::kem;
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PrivateKey, PublicKey};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::ctx::{HolderId, MemberId, SeatRef, SEAT_LABEL, TAG_LABEL};
use super::{encode_secret, GkError};

/// The account's seat keys in its vault (§2): an item of its own.
pub const ITEM_SEAT_KEM: &str = "item.seat_kem";

/// `ser(Kyber1024 public)` and `ser(ct_q)`: the type byte and 1568 (§11.2).
pub(crate) const KEM_PUBLIC_BYTES: usize = 1569;
pub(crate) const KEM_CT_BYTES: usize = 1569;
/// `ser(X25519 public)`: `0x05` and 32.
pub(crate) const DH_PUBLIC_BYTES: usize = 33;

/// `tag(x)` of §2: the first 8 bytes of `SHA-256("voipc-gk/v1/tag|" ‖ ser(x))`,
/// over the key's serialization with its type byte.
pub fn tag(ser: &[u8]) -> [u8; 8] {
    let d = Sha256::new()
        .chain_update(TAG_LABEL)
        .chain_update(ser)
        .finalize();
    d[..8].try_into().expect("8 bytes")
}

/// An X25519 public key read from its 33 bytes: exactly those, of type `0x05`,
/// and not of low order (§3, as `log.rs` reads log keys).
pub(crate) fn dh_public(ser: &[u8]) -> Result<PublicKey, GkError> {
    if ser.len() != DH_PUBLIC_BYTES || ser[0] != 0x05 {
        return Err(GkError::Malformed);
    }
    crate::log::log_public(ser).ok_or(GkError::WeakKey)
}

/// An X25519 public key from the 32 raw bytes a header carries (§11.2).
pub(crate) fn dh_public_raw(raw: &[u8; 32]) -> Result<PublicKey, GkError> {
    dh_public(&[&[0x05u8][..], raw].concat())
}

/// A Kyber1024 public key: the type byte must say Kyber1024, which the
/// welcome context names (`kyber1024`), so no other KEM is taken under it.
fn kem_public(ser: &[u8]) -> Result<kem::PublicKey, GkError> {
    let key = kem::PublicKey::deserialize(ser).map_err(|_| GkError::Malformed)?;
    if key.key_type() != kem::KeyType::Kyber1024 || ser.len() != KEM_PUBLIC_BYTES {
        return Err(GkError::Malformed);
    }
    Ok(key)
}

/// X25519 between our private key and their public one: 32 raw bytes, never
/// all zero (libsignal refuses that).
pub(crate) fn agree(own: &PrivateKey, theirs: &PublicKey) -> Result<Zeroizing<Vec<u8>>, GkError> {
    own.calculate_agreement(theirs)
        .map(|s| Zeroizing::new(s.into_vec()))
        .map_err(|_| GkError::WeakKey)
}

// ── Pairs ─────────────────────────────────────────────────────────────────

/// A Kyber1024 and an X25519 key pair: a seat's `SK`/`SX`, a connection's
/// seat pair, or a desktop keyholder's `KK`/`KX`.
#[derive(Clone)]
pub struct SeatPair {
    pub(crate) kem: kem::KeyPair,
    pub(crate) dh: KeyPair,
}

impl SeatPair {
    pub fn generate() -> SeatPair {
        SeatPair::generate_with(&mut crate::rng())
    }

    /// From a given RNG: the known answers draw every key from a seeded one.
    pub(crate) fn generate_with<R: Rng + CryptoRng>(rng: &mut R) -> SeatPair {
        SeatPair {
            kem: kem::KeyPair::generate(kem::KeyType::Kyber1024, rng),
            dh: KeyPair::generate(rng),
        }
    }

    pub fn public(&self) -> SeatPublic {
        SeatPublic::new(self.kem.public_key.clone(), self.dh.public_key)
    }

    fn to_wire(&self) -> PairWire {
        PairWire {
            kem_public: self.kem.public_key.serialize().into_vec(),
            kem_secret: self.kem.secret_key.serialize().into_vec(),
            dh_private: self.dh.private_key.serialize(),
        }
    }

    fn from_wire(w: &PairWire) -> Option<SeatPair> {
        let kem = kem::KeyPair::from_public_and_private(&w.kem_public, &w.kem_secret).ok()?;
        if kem.public_key.key_type() != kem::KeyType::Kyber1024 {
            return None;
        }
        let private = PrivateKey::deserialize(&w.dh_private).ok()?;
        let public = private.public_key().ok()?;
        Some(SeatPair {
            kem,
            dh: KeyPair::new(public, private),
        })
    }

    /// The pair, private parts included, as a device keeps a desktop keyholder pair
    /// (`gk_local.bin`, plan 3d): postcard of the pairs as libsignal serializes them, the
    /// layout `SeatKeys` uses.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        encode_secret(&self.to_wire())
    }

    pub fn from_bytes(b: &[u8]) -> Option<SeatPair> {
        let wire: PairWire = postcard::from_bytes(b).ok()?;
        SeatPair::from_wire(&wire)
    }
}

/// The public half of a `SeatPair`, with its two tags.
#[derive(Clone)]
pub struct SeatPublic {
    pub(crate) kem: kem::PublicKey,
    pub(crate) dh: PublicKey,
    tag_kem: [u8; 8],
    tag_dh: [u8; 8],
}

impl SeatPublic {
    fn new(kem: kem::PublicKey, dh: PublicKey) -> SeatPublic {
        let tag_kem = tag(&kem.serialize());
        let tag_dh = tag(&dh.serialize());
        SeatPublic {
            kem,
            dh,
            tag_kem,
            tag_dh,
        }
    }

    /// From `ser(KEM.pub)` (1569) and `ser(DH.pub)` (33): Kyber1024 only, and
    /// no X25519 key of low order.
    pub fn from_bytes(kem: &[u8], dh: &[u8]) -> Result<SeatPublic, GkError> {
        Ok(SeatPublic::new(kem_public(kem)?, dh_public(dh)?))
    }

    pub fn kem_bytes(&self) -> Box<[u8]> {
        self.kem.serialize()
    }

    pub fn dh_bytes(&self) -> Box<[u8]> {
        self.dh.serialize()
    }

    /// `tag(SK)`, or `tag(KK)` for a keyholder pair.
    pub fn tag_kem(&self) -> [u8; 8] {
        self.tag_kem
    }

    /// `tag(SX)`, or `tag(KX)` for a keyholder pair.
    pub fn tag_dh(&self) -> [u8; 8] {
        self.tag_dh
    }

    /// The seat these keys make for `m`.
    pub fn seat(&self, m: MemberId) -> SeatRef {
        SeatRef {
            m,
            tag_sk: self.tag_kem,
            tag_sx: self.tag_dh,
        }
    }
}

/// Our own side of a welcome or a row: a member id and its private pair.
pub struct Me<'a> {
    pub m: MemberId,
    pub keys: &'a SeatPair,
}

impl Me<'_> {
    pub(crate) fn holder_id(&self) -> HolderId {
        HolderId {
            m: self.m,
            tag_kx: tag(&self.keys.dh.public_key.serialize()),
        }
    }

    pub(crate) fn seat(&self) -> SeatRef {
        self.keys.public().seat(self.m)
    }
}

/// The other side: a member id and its public pair.
pub struct Them<'a> {
    pub m: MemberId,
    pub keys: &'a SeatPublic,
}

/// A keyholder as a member meets it: its member id and its `KX`, from its
/// entry in a header. What a welcome or row from it is checked against.
#[derive(Clone)]
pub struct Holder {
    pub m: MemberId,
    pub(crate) kx: PublicKey,
}

impl Holder {
    /// From `ser(KX)` (33 bytes).
    pub fn new(m: MemberId, kx: &[u8]) -> Result<Holder, GkError> {
        Ok(Holder {
            m,
            kx: dh_public(kx)?,
        })
    }

    /// From the 32 raw bytes of a header's keyholder entry.
    pub fn from_raw(m: MemberId, kx: &[u8; 32]) -> Result<Holder, GkError> {
        Ok(Holder {
            m,
            kx: dh_public_raw(kx)?,
        })
    }

    pub fn id(&self) -> HolderId {
        HolderId {
            m: self.m,
            tag_kx: tag(&self.kx.serialize()),
        }
    }
}

// ── XEdDSA ────────────────────────────────────────────────────────────────

/// ℓ, the order of the Ed25519 base point, little-endian.
const ELL: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Whether a signature's `S` is below ℓ (§3.12). libsignal reduces `S` and
/// takes `(R, S + ℓ)` for nearly every signature, so without this anyone
/// could make a second valid signature over the same message. The top bit of
/// the last byte is libsignal's sign bit, not part of `S`.
pub(crate) fn s_canonical(sig: &[u8; 64]) -> bool {
    let mut s: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    s[31] &= 0x7f;
    for i in (0..32).rev() {
        if s[i] != ELL[i] {
            return s[i] < ELL[i];
        }
    }
    false
}

#[cfg(test)]
pub(crate) fn sign(key: &PrivateKey, msg: &[u8]) -> [u8; 64] {
    sign_with(key, msg, &mut crate::rng())
}

pub(crate) fn sign_with<R: Rng + CryptoRng>(key: &PrivateKey, msg: &[u8], rng: &mut R) -> [u8; 64] {
    sign_parts_with(key, &[msg], rng)
}

/// XEdDSA over the concatenation of `parts`, which is never built: a part
/// that holds a secret (a writer's SKDM) is not copied into a buffer that
/// would be freed unwiped.
pub(crate) fn sign_parts_with<R: Rng + CryptoRng>(
    key: &PrivateKey,
    parts: &[&[u8]],
    rng: &mut R,
) -> [u8; 64] {
    let sig = key
        .calculate_signature_for_multipart_message(parts, rng)
        .expect("sign");
    let sig: [u8; 64] = (*sig).try_into().expect("64 bytes");
    debug_assert!(s_canonical(&sig), "libsignal reduces S");
    sig
}

/// A signature check that also refuses `S ≥ ℓ`: every signature this module
/// checks goes through here.
pub(crate) fn verify(key: &PublicKey, msg: &[u8], sig: &[u8]) -> bool {
    verify_parts(key, &[msg], sig)
}

/// `verify` over the concatenation of `parts`.
pub(crate) fn verify_parts(key: &PublicKey, parts: &[&[u8]], sig: &[u8]) -> bool {
    let Ok(sig) = <&[u8; 64]>::try_from(sig) else {
        return false;
    };
    s_canonical(sig) && key.verify_signature_for_multipart_message(parts, sig)
}

/// An identity key from the 32 raw bytes a header carries, refused when of
/// low order (§3). XEdDSA under such a key takes `R = [S]B` for about half
/// of all messages, so whatever it "signed", anyone could have.
pub(crate) fn ik_raw(raw: &[u8; 32]) -> Result<PublicKey, GkError> {
    dh_public_raw(raw)
}

// ── Endorsements ──────────────────────────────────────────────────────────

/// What a pair is (§11.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Origin {
    /// An account's seat keys, the vault item.
    VaultSeat = 0x01,
    /// A connection's seat pair: a guest, a seat on a relay without
    /// accounts, every voice seat, and every connection keyholder.
    Connection = 0x02,
    /// A desktop app's keyholder pair.
    Desktop = 0x03,
}

impl Origin {
    pub fn from_byte(b: u8) -> Option<Origin> {
        match b {
            0x01 => Some(Origin::VaultSeat),
            0x02 => Some(Origin::Connection),
            0x03 => Some(Origin::Desktop),
            _ => None,
        }
    }

    /// Whether this origin may name `m` (§11.8). The vault and a desktop
    /// keyholder pair name the account. A connection pair always names its
    /// connection, `Conn(u)`, also a signed-in member's: its seat stays the
    /// account's, and only the endorsement says which connection the pair is
    /// for. Its counter is then the account's, signed by the account's `IK`;
    /// a guest's is 0 under the connection's own `IK`. Which of the two
    /// verified it is the caller's to know, so the counter is the caller's to
    /// check too.
    fn fits(self, m: &MemberId) -> bool {
        matches!(
            (self, m),
            (Origin::VaultSeat | Origin::Desktop, MemberId::Account(_))
                | (Origin::Connection, MemberId::Conn(_))
        )
    }
}

/// `IK`'s signature over a pair (§11.8), with the account's seat-key counter
/// and the time the pair was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endorsement {
    pub origin: Origin,
    pub m: MemberId,
    pub n: u32,
    pub made: u64,
    pub sig: [u8; 64],
}

/// `"voipc-gk/v1/seat|" ‖ origin ‖ seat id (17) ‖ n ‖ made ‖ ser(KEM.pub) ‖ ser(DH.pub)`.
pub(crate) fn endorsement_message(
    origin: Origin,
    m: &MemberId,
    n: u32,
    made: u64,
    keys: &SeatPublic,
) -> Vec<u8> {
    let mut msg = SEAT_LABEL.to_vec();
    msg.push(origin as u8);
    msg.extend_from_slice(&m.seat_id());
    msg.extend_from_slice(&n.to_be_bytes());
    msg.extend_from_slice(&made.to_be_bytes());
    msg.extend_from_slice(&keys.kem.serialize());
    msg.extend_from_slice(&keys.dh.serialize());
    msg
}

impl Endorsement {
    /// `None` for an origin that cannot name `m`.
    pub fn sign(
        ik: &IdentityKeyPair,
        origin: Origin,
        m: MemberId,
        n: u32,
        made: u64,
        keys: &SeatPublic,
    ) -> Option<Endorsement> {
        Endorsement::sign_with(ik, origin, m, n, made, keys, &mut crate::rng())
    }

    pub(crate) fn sign_with<R: Rng + CryptoRng>(
        ik: &IdentityKeyPair,
        origin: Origin,
        m: MemberId,
        n: u32,
        made: u64,
        keys: &SeatPublic,
        rng: &mut R,
    ) -> Option<Endorsement> {
        if !origin.fits(&m) {
            return None;
        }
        let msg = endorsement_message(origin, &m, n, made, keys);
        Some(Endorsement {
            origin,
            m,
            n,
            made,
            sig: sign_with(ik.private_key(), &msg, rng),
        })
    }

    /// Whether `ik` endorsed `keys` as this says. Who `ik` is (a pin, or the
    /// connection's own key) is the caller's to check. An `ik` of low order
    /// endorses nothing.
    pub fn verify(&self, ik: &IdentityKey, keys: &SeatPublic) -> bool {
        self.origin.fits(&self.m)
            && dh_public(&ik.serialize()).is_ok()
            && verify(
                ik.public_key(),
                &endorsement_message(self.origin, &self.m, self.n, self.made, keys),
                &self.sig,
            )
    }
}

// ── The vault item ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct PairWire {
    kem_public: Vec<u8>,
    kem_secret: Vec<u8>,
    dh_private: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SeatKeysWire {
    pair: PairWire,
    self_key: [u8; 32],
    made: u64,
    n: u32,
    old: Option<OldWire>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct OldWire {
    pair: PairWire,
    self_key: [u8; 32],
    made: u64,
    n: u32,
}

/// An account's seat keys (§2, §5.11): the vault item `item.seat_kem`.
///
/// It holds `SK`, `SX`, the self key (32 random bytes, what self-rows are
/// sealed under), the time it was made and the counter `n`. During a rotation
/// it also holds the previous seat's pair and self key, until the re-seat is
/// done or 7 days pass (`drop_old`).
///
/// The layout is not in §11, so it is chosen here: postcard of the pairs as
/// libsignal serializes them. The previous seat keeps its whole Kyber1024
/// pair, public half too, since a welcome still waiting for the old keys
/// salts its KEK with `ser(SK.pub)`. That makes the item about 9.7 KB during
/// a rotation, as §2 says (see the budget test).
pub struct SeatKeys {
    pub pair: SeatPair,
    self_key: Zeroizing<[u8; 32]>,
    pub made: u64,
    pub n: u32,
    pub old: Option<OldSeat>,
}

/// The seat keys a rotation replaced, kept until the re-seat is done.
pub struct OldSeat {
    pub pair: SeatPair,
    self_key: Zeroizing<[u8; 32]>,
    pub made: u64,
    pub n: u32,
}

impl OldSeat {
    pub fn self_key(&self) -> &[u8; 32] {
        &self.self_key
    }
}

impl SeatKeys {
    /// New seat keys with counter `n`, made at `made` (unix seconds).
    pub fn generate(n: u32, made: u64) -> SeatKeys {
        SeatKeys::generate_with(&mut crate::rng(), n, made)
    }

    /// From a given RNG: the fuzz target's keys are fixed.
    pub(crate) fn generate_with<R: Rng + CryptoRng>(rng: &mut R, n: u32, made: u64) -> SeatKeys {
        let pair = SeatPair::generate_with(rng);
        let mut self_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *self_key);
        SeatKeys {
            pair,
            self_key,
            made,
            n,
            old: None,
        }
    }

    /// A rotation (§5.11): new `SK`, `SX` and self key with counter `n + 1`;
    /// these become the old ones, and any older ones go. `None` at the top of
    /// the counter.
    pub fn rotate(self, made: u64) -> Option<SeatKeys> {
        let n = self.n.checked_add(1)?;
        Some(SeatKeys {
            pair: SeatPair::generate(),
            self_key: Zeroizing::new(crate::aead::random()),
            made,
            n,
            old: Some(OldSeat {
                pair: self.pair,
                self_key: self.self_key,
                made: self.made,
                n: self.n,
            }),
        })
    }

    /// Once the re-seat is done, or 7 days after the rotation (§5.11 step 4).
    pub fn drop_old(&mut self) {
        self.old = None;
    }

    pub fn self_key(&self) -> &[u8; 32] {
        &self.self_key
    }

    /// The item's plaintext, encoded into a buffer of its exact size
    /// (`encode_secret`): it holds the Kyber1024 and X25519 private keys.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let wire = SeatKeysWire {
            pair: self.pair.to_wire(),
            self_key: *self.self_key,
            made: self.made,
            n: self.n,
            old: self.old.as_ref().map(|o| OldWire {
                pair: o.pair.to_wire(),
                self_key: *o.self_key,
                made: o.made,
                n: o.n,
            }),
        };
        encode_secret(&wire)
    }

    pub fn from_bytes(b: &[u8]) -> Option<SeatKeys> {
        let wire: SeatKeysWire = postcard::from_bytes(b).ok()?;
        let old = match &wire.old {
            Some(o) => Some(OldSeat {
                pair: SeatPair::from_wire(&o.pair)?,
                self_key: Zeroizing::new(o.self_key),
                made: o.made,
                n: o.n,
            }),
            None => None,
        };
        Some(SeatKeys {
            pair: SeatPair::from_wire(&wire.pair)?,
            self_key: Zeroizing::new(wire.self_key),
            made: wire.made,
            n: wire.n,
            old,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Vault;

    /// What the relay takes for the whole vault (`VAULT_TOTAL_BYTES` in
    /// `voipc-server/src/accounts.rs`): it goes to a signing-in device in one
    /// `AuthStep::Vault` frame.
    const VAULT_TOTAL_BYTES: usize = 56 * 1024;
    /// And for one item (`VAULT_MAX_BYTES`).
    const VAULT_MAX_BYTES: usize = 48 * 1024;

    /// §2: the largest vault the app writes on a relay at protocol 21 or
    /// later (the only relays with a group key), plus `item.seat_kem` in the
    /// middle of a rotation, fits the sign-in frame, and by how much.
    ///
    /// Each item at its largest, sealed as the app seals it:
    /// - the two key slots and `slot.reset` (32 bytes);
    /// - `item.identity`, `item.logkey`, `item.prefs`;
    /// - `item.blocks` with `BLOCKS_MAX` (200) accounts, each named with the
    ///   64 characters the app keeps, all ASCII. Usernames are at most 32
    ///   bytes on the relay, so an honest relay never comes near this;
    /// - `item.pins` as the index of all 56 pages, each generation a 10-byte
    ///   varint. At 21 and later the pins themselves are pages outside the
    ///   sign-in frame;
    /// - `item.seat_kem` holding the old seat keys too;
    /// - `item.gk_floors`, the index of the group key's floor and counter pages, every page
    ///   at its widest generation (plan 3d: about 500 B inside the margin).
    #[test]
    fn the_largest_vault_with_seat_keys_fits_the_sign_in_frame() {
        let vault = Vault::from_dek([7; 16], "alice", [9; 32]);
        let identity = IdentityKeyPair::generate(&mut crate::rng());
        let logkey = crate::log::LogKey::generate();
        let mut blocks = Vec::new();
        blocks.extend_from_slice(&[0xc8, 0x01]);
        for i in 0..200u32 {
            let mut account = [0u8; 16];
            account[..4].copy_from_slice(&i.to_be_bytes());
            blocks.extend_from_slice(&account);
            blocks.push(64);
            blocks.extend_from_slice(&[b'n'; 64]);
        }
        blocks.push(0);
        blocks.resize(blocks.len().div_ceil(1024) * 1024, 0);
        let mut pins_index = vec![56u8];
        for _ in 0..56 {
            pins_index.extend_from_slice(&[0xff; 9]);
            pins_index.push(0x01);
        }
        let seat = SeatKeys::generate(41, 1_700_000_000)
            .rotate(1_702_592_000)
            .unwrap();
        let seat_item = vault.seal_item(ITEM_SEAT_KEM, 7, &seat.to_bytes());
        let gk_index = crate::sync::GkIndex {
            format: 1,
            floor_pages: vec![u64::MAX; crate::sync::FLOOR_PAGES as usize],
            counter_pages: vec![u64::MAX; crate::sync::COUNTER_PAGES as usize],
        };
        let gk_item = vault.seal_item(crate::sync::ITEM_GK_FLOORS, u64::MAX, &gk_index.to_bytes());
        let items = [
            vault.pass_slot(&[1; 32]).v,
            vault.recovery_slot(&[2; 32]).v,
            vec![3; 32],
            vault.seal_item("item.identity", 1, &identity.serialize()).v,
            vault.seal_item("item.logkey", 1, &logkey.to_bytes()).v,
            vault.seal_item("item.prefs", 1, &[1, 1]).v,
            vault.seal_item("item.blocks", 1, &blocks).v,
            vault.seal_item_as("item.pins", 1, 2, &pins_index).v,
            seat_item.v.clone(),
            gk_item.v.clone(),
        ];
        let seat_bytes = seat_item.v.len();
        let total: usize = items.iter().map(Vec::len).sum();
        assert!(
            (9_500..10_000).contains(&seat_bytes),
            "item.seat_kem in a rotation: {seat_bytes} bytes"
        );
        assert!(seat_bytes < VAULT_MAX_BYTES);
        let quiet = vault
            .seal_item(ITEM_SEAT_KEM, 8, &SeatKeys::generate(1, 1).to_bytes())
            .v
            .len();
        assert!(
            (4_800..5_000).contains(&quiet),
            "item.seat_kem alone: {quiet}"
        );
        assert!(
            total <= VAULT_TOTAL_BYTES,
            "{total} bytes of {VAULT_TOTAL_BYTES}"
        );
        assert!(
            (450..600).contains(&gk_item.v.len()),
            "item.gk_floors at its widest: {}",
            gk_item.v.len()
        );
        // The margin today: about 29.3 KB left, more than three more rotations' worth.
        assert!(
            VAULT_TOTAL_BYTES - total > 29_000,
            "margin {}",
            VAULT_TOTAL_BYTES - total
        );
    }

    #[test]
    fn seat_keys_come_back_from_their_vault_bytes_whole() {
        let keys = SeatKeys::generate(3, 1_700_000_000)
            .rotate(1_700_086_400)
            .unwrap();
        let again = SeatKeys::from_bytes(&keys.to_bytes()).unwrap();
        assert_eq!(again.n, 4);
        assert_eq!(again.made, 1_700_086_400);
        assert_eq!(again.self_key(), keys.self_key());
        assert_eq!(
            again.pair.public().kem_bytes(),
            keys.pair.public().kem_bytes()
        );
        assert_eq!(
            again.pair.public().dh_bytes(),
            keys.pair.public().dh_bytes()
        );
        let (old, was) = (again.old.as_ref().unwrap(), keys.old.as_ref().unwrap());
        assert_eq!((old.n, old.made), (3, 1_700_000_000));
        assert_eq!(old.self_key(), was.self_key());
        assert_eq!(old.pair.public().tag_kem(), was.pair.public().tag_kem());
        assert_ne!(
            old.self_key(),
            keys.self_key(),
            "a rotation draws a new self key"
        );
        assert!(SeatKeys::from_bytes(&keys.to_bytes()[..100]).is_none());
        let mut dropped = again;
        dropped.drop_old();
        assert!(SeatKeys::from_bytes(&dropped.to_bytes())
            .unwrap()
            .old
            .is_none());
    }

    #[test]
    fn an_endorsement_holds_for_its_identity_origin_counter_and_keys_only() {
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let other = IdentityKeyPair::generate(&mut crate::rng());
        let pair = SeatPair::generate().public();
        let a = MemberId::Account([4; 16]);
        let e = Endorsement::sign(&ik, Origin::VaultSeat, a, 5, 1_700_000_000, &pair).unwrap();
        assert!(e.verify(ik.identity_key(), &pair));
        assert!(!e.verify(other.identity_key(), &pair), "another identity");
        assert!(
            !e.verify(ik.identity_key(), &SeatPair::generate().public()),
            "other keys"
        );
        for changed in [
            Endorsement { n: 4, ..e.clone() },
            Endorsement {
                made: 1,
                ..e.clone()
            },
            Endorsement {
                origin: Origin::Desktop,
                ..e.clone()
            },
            Endorsement {
                m: MemberId::Account([5; 16]),
                ..e.clone()
            },
        ] {
            assert!(!changed.verify(ik.identity_key(), &pair), "{changed:?}");
        }
    }

    /// §11.8: a vault seat or a desktop pair names its account; a connection
    /// pair names its connection, a signed-in member's too, which then
    /// carries the account's counter and is signed by the account's `IK`.
    #[test]
    fn a_vault_seat_or_desktop_pair_names_its_account_and_a_connection_pair_its_connection() {
        let ik = IdentityKeyPair::generate(&mut crate::rng());
        let pair = SeatPair::generate().public();
        let (conn, account) = (MemberId::Conn(42), MemberId::Account([1; 16]));
        assert!(Endorsement::sign(&ik, Origin::VaultSeat, conn, 0, 1, &pair).is_none());
        assert!(Endorsement::sign(&ik, Origin::Desktop, conn, 0, 1, &pair).is_none());
        assert!(Endorsement::sign(&ik, Origin::Connection, account, 9, 1, &pair).is_none());
        for n in [0, 9] {
            let ok = Endorsement::sign(&ik, Origin::Connection, conn, n, 1, &pair).unwrap();
            assert!(ok.verify(ik.identity_key(), &pair));
            let msg = endorsement_message(Origin::Connection, &conn, n, 1, &pair);
            assert_eq!(msg[SEAT_LABEL.len() + 1..][..17], conn.seat_id());
        }
        let as_account = Endorsement {
            m: account,
            ..Endorsement::sign(&ik, Origin::Connection, conn, 9, 1, &pair).unwrap()
        };
        assert!(!as_account.verify(ik.identity_key(), &pair));
    }

    #[test]
    fn a_seat_key_of_another_kind_or_of_low_order_is_refused() {
        let good = SeatPair::generate().public();
        let (kem, dh) = (good.kem_bytes(), good.dh_bytes());
        assert!(SeatPublic::from_bytes(&kem, &dh).is_ok());
        assert_eq!(
            SeatPublic::from_bytes(&kem[..1568], &dh).err(),
            Some(GkError::Malformed)
        );
        let mut other_kind = kem.to_vec();
        other_kind[0] = 0x0a;
        assert_eq!(
            SeatPublic::from_bytes(&other_kind, &dh).err(),
            Some(GkError::Malformed)
        );
        let mut low = [0u8; 33];
        low[0] = 5;
        assert_eq!(
            SeatPublic::from_bytes(&kem, &low).err(),
            Some(GkError::WeakKey)
        );
        low[1] = 1;
        assert_eq!(
            SeatPublic::from_bytes(&kem, &low).err(),
            Some(GkError::WeakKey)
        );
        assert_eq!(
            SeatPublic::from_bytes(&kem, &[&dh[..], &[0]].concat()).err(),
            Some(GkError::Malformed)
        );
        assert!(Holder::from_raw(MemberId::Conn(1), &[0; 32]).is_err());
    }

    #[test]
    fn s_at_or_above_ell_is_not_canonical() {
        let mut sig = [0u8; 64];
        assert!(s_canonical(&sig));
        sig[32..].copy_from_slice(&ELL);
        assert!(!s_canonical(&sig), "S = ℓ");
        sig[32] -= 1;
        assert!(s_canonical(&sig), "S = ℓ - 1");
        sig[63] |= 0x80;
        assert!(s_canonical(&sig), "the sign bit is not S");
        sig[63] = 0x7f;
        assert!(!s_canonical(&sig));
    }
}
