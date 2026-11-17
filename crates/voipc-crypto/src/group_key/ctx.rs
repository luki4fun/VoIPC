//! Names and contexts (§2, §11.1).
//!
//! One encoder makes every context: `voipc-gk/v1/<name>`, then each field
//! after a `|`. Every context starts `|k|group|gen|`, so a text group and a
//! voice group, or two generations of one group, never share a key. No field
//! can hold a `|`: the group id is checked when a `Group` is made, and every
//! other field is a number, lowercase hex, a member id or a fixed word. So a
//! context string splits back into exactly the fields it was made from, and
//! two field tuples never give one string.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use voipc_protocol::conv::hex;

use super::GkError;

/// Every label starts with this; a label is this and the context's name.
pub(crate) const LABEL: &str = "voipc-gk/v1/";
/// Longest group id (§11.1).
pub const MAX_GROUP_BYTES: usize = 128;

/// Text channel or voice room (§2 `k`). Postcard: Text 0, Voice 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GroupKind {
    Text,
    Voice,
}

impl GroupKind {
    pub fn letter(self) -> &'static str {
        match self {
            GroupKind::Text => "t",
            GroupKind::Voice => "v",
        }
    }
}

/// A member id (§2 `m`): an account, or a connection's own seat by its user
/// id. Postcard: Account 0 (16 raw bytes), Conn 1 (varint).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemberId {
    Account([u8; 16]),
    Conn(u32),
}

impl MemberId {
    /// `a:<32 hex>` or `g:<decimal user id>` (§11.1).
    pub fn ctx(&self) -> String {
        match self {
            MemberId::Account(a) => format!("a:{}", hex(a)),
            MemberId::Conn(u) => format!("g:{u}"),
        }
    }

    /// The seat id of §11.5 and §11.8: the kind byte (0x01 account, 0x02
    /// connection), then the account id, or 12 zero bytes and the user id.
    pub fn seat_id(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        match self {
            MemberId::Account(a) => {
                out[0] = 0x01;
                out[1..].copy_from_slice(a);
            }
            MemberId::Conn(u) => {
                out[0] = 0x02;
                out[13..].copy_from_slice(&u.to_be_bytes());
            }
        }
        out
    }

    pub fn account(&self) -> Option<[u8; 16]> {
        match self {
            MemberId::Account(a) => Some(*a),
            MemberId::Conn(_) => None,
        }
    }

    pub fn is_conn(&self) -> bool {
        matches!(self, MemberId::Conn(_))
    }
}

/// A seat (§2): a member id with the tags of its two seat keys. New seat keys
/// on an account are a new seat. Also the `SeatRef` of §11.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SeatRef {
    pub m: MemberId,
    pub tag_sk: [u8; 8],
    pub tag_sx: [u8; 8],
}

/// A keyholder as contexts name it: its member id and the tag of its `KX`,
/// which tells two keyholder entries of one account apart (§2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HolderId {
    pub m: MemberId,
    pub tag_kx: [u8; 8],
}

/// A writer (§2 `w`): its seat's member id and its connection's user id.
/// Two devices of one account are two writers on one seat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Writer {
    pub m: MemberId,
    pub u: u32,
}

impl Writer {
    /// `<m>/<u>` (§11.1).
    pub fn ctx(&self) -> String {
        format!("{}/{}", self.m.ctx(), self.u)
    }
}

/// One bucket version `(b, v)`: two random u64 (§4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Version {
    pub b: u64,
    pub v: u64,
}

/// An epoch and the digest of its opening header, `D_e` (§4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Epoch {
    pub e: u32,
    pub d_e: [u8; 32],
}

/// A group in one generation: what every context starts with.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Group {
    kind: GroupKind,
    id: String,
    gen: [u8; 16],
}

impl Group {
    /// `Malformed` for an id of neither shape §11.1 allows.
    pub fn new(kind: GroupKind, id: &str, gen: [u8; 16]) -> Result<Group, GkError> {
        if !valid_group_id(id) {
            return Err(GkError::Malformed);
        }
        Ok(Group {
            kind,
            id: id.to_string(),
            gen,
        })
    }

    pub fn kind(&self) -> GroupKind {
        self.kind
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn gen(&self) -> [u8; 16] {
        self.gen
    }

    /// The label and the three fields every context starts with.
    pub(crate) fn ctx(&self, name: &str) -> Ctx {
        Ctx(format!("{LABEL}{name}"))
            .field(self.kind.letter())
            .field(&self.id)
            .hex(&self.gen)
    }
}

/// The two group id shapes of §11.1, and nothing else: `c:` and a channel
/// uid (1 to 64 letters, digits, `-` or `_`, which also covers the 32 hex
/// digits `log_conv` makes without one), or `r:<32 lowercase hex>:<decimal
/// channel id>`. Reading "any other is refused" strictly also keeps every id
/// ASCII, `|`-free and under 128 bytes.
pub fn valid_group_id(id: &str) -> bool {
    if id.len() > MAX_GROUP_BYTES {
        return false;
    }
    if let Some(uid) = id.strip_prefix("c:") {
        return (1..=64).contains(&uid.len())
            && uid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    }
    let Some(rest) = id.strip_prefix("r:") else {
        return false;
    };
    let Some((run, channel)) = rest.split_once(':') else {
        return false;
    };
    run.len() == 32
        && run.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && channel
            .parse::<u32>()
            .is_ok_and(|c| c.to_string() == channel)
}

/// A context under construction.
pub(crate) struct Ctx(String);

impl Ctx {
    pub(crate) fn field(mut self, f: impl std::fmt::Display) -> Ctx {
        write!(self.0, "|{f}").expect("a String takes any write");
        self
    }

    pub(crate) fn hex(self, b: &[u8]) -> Ctx {
        self.field(hex(b))
    }

    pub(crate) fn m(self, m: &MemberId) -> Ctx {
        self.field(m.ctx())
    }

    pub(crate) fn done(self) -> String {
        self.0
    }
}

// ── Every context of §11.1, in its order ─────────────────────────────────

pub(crate) fn member_ctx(g: &Group, s: u32, seat: &SeatRef) -> String {
    g.ctx("member")
        .field(s)
        .m(&seat.m)
        .hex(&seat.tag_sk)
        .hex(&seat.tag_sx)
        .done()
}

/// The words after `kyber1024` that tell the three welcomes apart.
pub(crate) enum WelcomeKind<'a> {
    Seat {
        at: Version,
        to: &'a SeatRef,
    },
    Seed {
        to: &'a SeatRef,
    },
    Keyring {
        e: u32,
        ks: &'a [u8; 32],
        to: &'a HolderId,
        tag_kk: &'a [u8; 8],
    },
}

pub(crate) fn welcome_ctx(g: &Group, s: u32, kind: WelcomeKind, from: &HolderId) -> String {
    let c = g.ctx("welcome").field(s).field("kyber1024");
    let c = match kind {
        WelcomeKind::Seat { at, to } => c
            .field("seat")
            .field(at.b)
            .field(at.v)
            .m(&to.m)
            .hex(&to.tag_sk)
            .hex(&to.tag_sx),
        WelcomeKind::Seed { to } => c.field("seed").m(&to.m).hex(&to.tag_sk).hex(&to.tag_sx),
        WelcomeKind::Keyring { e, ks, to, tag_kk } => c
            .field("keyring")
            .field(e)
            .hex(ks)
            .m(&to.m)
            .hex(tag_kk)
            .hex(&to.tag_kx),
    };
    c.m(&from.m).hex(&from.tag_kx).done()
}

pub(crate) fn rowbase_ctx(
    g: &Group,
    s: u32,
    m: &MemberId,
    tag_sx: &[u8; 8],
    k: &HolderId,
) -> String {
    g.ctx("rowbase")
        .field(s)
        .m(m)
        .hex(tag_sx)
        .m(&k.m)
        .hex(&k.tag_kx)
        .done()
}

pub(crate) fn row_ctx(g: &Group, s: u32, at: Version, m: &MemberId, k: &MemberId) -> String {
    g.ctx("row")
        .field(s)
        .field(at.b)
        .field(at.v)
        .m(m)
        .m(k)
        .done()
}

pub(crate) fn seal_ctx(g: &Group, ep: &Epoch, at: Version) -> String {
    g.ctx("seal")
        .field(ep.e)
        .hex(&ep.d_e)
        .field(at.b)
        .field(at.v)
        .done()
}

pub(crate) fn ratchet_ctx(g: &Group, e: u32, at: Version, v_new: u64) -> String {
    g.ctx("ratchet")
        .field(e)
        .field(at.b)
        .field(at.v)
        .field(v_new)
        .done()
}

pub(crate) fn confirm_ctx(g: &Group, e: u32, j: u32) -> String {
    g.ctx("confirm").field(e).field(j).done()
}

pub(crate) fn list_ctx(g: &Group, at: Version) -> String {
    g.ctx("list").field(at.b).field(at.v).done()
}

/// The last field of a keyring context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyringWord {
    Base,
    Delta,
}

pub(crate) fn keyring_ctx(
    g: &Group,
    e: u32,
    j: u32,
    s: u32,
    ks: &[u8; 32],
    word: KeyringWord,
) -> String {
    g.ctx("keyring")
        .field(e)
        .field(j)
        .field(s)
        .hex(ks)
        .field(match word {
            KeyringWord::Base => "base",
            KeyringWord::Delta => "delta",
        })
        .done()
}

pub(crate) fn writer_ctx(g: &Group, ep: &Epoch, w: &Writer) -> String {
    g.ctx("writer")
        .field(ep.e)
        .hex(&ep.d_e)
        .field(w.ctx())
        .done()
}

pub(crate) fn writer_sig_ctx(g: &Group, ep: &Epoch, w: &Writer) -> String {
    g.ctx("writer-sig")
        .field(ep.e)
        .hex(&ep.d_e)
        .field(w.ctx())
        .done()
}

pub(crate) fn dist_ctx(g: &Group, ep: &Epoch) -> String {
    g.ctx("dist").field(ep.e).hex(&ep.d_e).done()
}

pub(crate) fn chain_ctx(g: &Group, ep: &Epoch, owner: &MemberId, chain: u32, index: u32) -> String {
    g.ctx("chain")
        .field(ep.e)
        .hex(&ep.d_e)
        .m(owner)
        .field(chain)
        .field(index)
        .done()
}

pub(crate) fn media_ctx(
    g: &Group,
    ep: &Epoch,
    m: &MemberId,
    tag_sx: &[u8; 8],
    stream: u32,
) -> String {
    g.ctx("media")
        .field(ep.e)
        .hex(&ep.d_e)
        .m(m)
        .hex(tag_sx)
        .field(stream)
        .done()
}

pub(crate) fn self_ctx(g: &Group, s: u32, seat: &SeatRef) -> String {
    g.ctx("self")
        .field(s)
        .m(&seat.m)
        .hex(&seat.tag_sk)
        .hex(&seat.tag_sx)
        .done()
}

pub(crate) fn self_history_ctx(g: &Group, s: u32, seat: &SeatRef) -> String {
    g.ctx("self-history")
        .field(s)
        .m(&seat.m)
        .hex(&seat.tag_sk)
        .hex(&seat.tag_sx)
        .done()
}

// ── Labels that are not contexts: a byte prefix, then binary data ────────

pub(crate) const TAG_LABEL: &[u8] = b"voipc-gk/v1/tag|";
pub(crate) const DIGEST_LABEL: &[u8] = b"voipc-gk/v1/digest|";
pub(crate) const HEADER_SIG_LABEL: &[u8] = b"voipc-gk/v1/header-sig|";
pub(crate) const SEAT_LABEL: &[u8] = b"voipc-gk/v1/seat|";
pub(crate) const LEAF_LABEL: &[u8] = b"voipc-gk/v1/leaf|";
pub(crate) const NODE_LABEL: &[u8] = b"voipc-gk/v1/node|";
pub(crate) const KEYRING_HASH_LABEL: &[u8] = b"voipc-gk/v1/keyring-hash|";
pub(crate) const KEYHOLDERS_LABEL: &[u8] = b"voipc-gk/v1/keyholders|";
pub(crate) const NAMES_LABEL: &[u8] = b"voipc-gk/v1/names|";
