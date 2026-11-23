//! Seat keys (3e, §5.11). The connection's one seat pair: made at its first need (an unseated
//! fetch, a volunteer, a voice seat), endorsed 0x02 for `Conn(u)` with the account's counter
//! (else 0), and gone with the connection. An account's `item.seat_kem`: its publishing and
//! when it rotates, as `AccountSync` runs them.

use libsignal_protocol::IdentityKeyPair;
use voipc_protocol::gk;
use voipc_protocol::messages::AccountRequest;

use super::Who;
use crate::group_key::commit::Pair;
use crate::group_key::{Endorsement, GroupKind, Me, MemberId, Origin, SeatKeys, SeatPair};

/// An account's seat keys rotate at this age, and at sign-in once older (§5.11).
pub(crate) const ROTATE_AFTER_SECS: u64 = crate::group_key::timers::SEAT_KEYS_ROTATE_SECS;

/// The connection's seat pair and its endorsement, once made.
#[derive(Default)]
pub(crate) struct ConnSeat {
    pair: Option<(SeatPair, Pair)>,
}

impl ConnSeat {
    pub(super) fn pair(&self) -> Option<&SeatPair> {
        self.pair.as_ref().map(|(p, _)| p)
    }
}

/// The connection's pair as the wire carries it, made now at its first need. `None` for a
/// signed-in connection whose seat keys are not in: its endorsement carries the account's
/// counter, and 0 would read as an old seat.
pub(super) fn conn_pair(who: &mut Who, now: u64) -> Option<gk::EndorsedPair> {
    if who.conn.pair.is_none() {
        let n = match (who.account, who.seat_keys.as_ref()) {
            (None, _) => 0,
            (Some(_), Some(k)) => k.n,
            (Some(_), None) => return None,
        };
        let pair = SeatPair::generate();
        let keys = pair.public();
        let m = MemberId::Conn(who.user_id);
        let endorsement =
            Endorsement::sign(&who.identity, Origin::Connection, m, n, now / 1000, &keys)
                .expect("a connection pair names its connection");
        who.conn.pair = Some((pair, Pair { keys, endorsement }));
    }
    who.conn
        .pair
        .as_ref()
        .map(|(_, p)| gk::EndorsedPair::from(p))
}

/// Whether `conn_pair` can make the connection's pair now: not for an account whose seat
/// keys are not in.
pub(super) fn can_pair(who: &Who) -> bool {
    who.conn.pair.is_some() || who.account.is_none() || who.seat_keys.is_some()
}

/// Our seats in a group of `kind`, the current first (`me`), then in a text group the
/// account's old seat while a rotation keeps it: the relay serves it until the re-seat
/// (§5.11 step 3), and a welcome or row to it opens only under its keys.
pub(super) fn mine(who: &Who, kind: GroupKind) -> Vec<Me<'_>> {
    let mut seats: Vec<Me> = me(who, kind).into_iter().collect();
    // V1: a signed-in member's voice seat is named by the connection in an anonymous room
    // that is not gated (open choice 11), and the relay names it: a welcome to either opens
    // (the media key names the seat as `writer_m` does, voice.rs)
    if let (Some(_), GroupKind::Voice, Some(keys)) = (who.account, kind, who.conn.pair()) {
        seats.push(Me {
            m: MemberId::Conn(who.user_id),
            keys,
        });
    }
    let old = who.seat_keys.as_ref().and_then(|k| k.old.as_ref());
    if let (Some(a), GroupKind::Text, Some(old)) = (who.account, kind, old) {
        seats.push(Me {
            m: MemberId::Account(a),
            keys: &old.pair,
        });
    }
    seats
}

/// Our side of a welcome or a row in a group of `kind`: the account's seat keys in a text
/// group (every seat of a signed-in member there is its account's), else the connection's
/// pair, named by the account where there is one (§11.8).
fn me(who: &Who, kind: GroupKind) -> Option<Me<'_>> {
    match (who.account, kind) {
        (Some(a), GroupKind::Text) => Some(Me {
            m: MemberId::Account(a),
            keys: &who.seat_keys.as_ref()?.pair,
        }),
        (Some(a), GroupKind::Voice) => Some(Me {
            m: MemberId::Account(a),
            keys: who.conn.pair()?,
        }),
        (None, _) => Some(Me {
            m: MemberId::Conn(who.user_id),
            keys: who.conn.pair()?,
        }),
    }
}

/// `SeatKeysPublish` for the account's seat keys (origin 0x01), endorsed by its identity.
pub(crate) fn publish(
    keys: &SeatKeys,
    identity: &IdentityKeyPair,
    account: [u8; 16],
) -> AccountRequest {
    let public = keys.pair.public();
    let e = Endorsement::sign(
        identity,
        Origin::VaultSeat,
        MemberId::Account(account),
        keys.n,
        keys.made,
        &public,
    )
    .expect("a vault seat names its account");
    AccountRequest::SeatKeysPublish {
        kem: public.kem_bytes().into(),
        dh: public.dh_bytes().into(),
        n: e.n,
        made: e.made,
        sig: e.sig.to_vec(),
    }
}

/// Whether `held`, seat keys the relay says it holds for `account` (`SeatKeysBehind`), are
/// a vault seat (0x01) of `account` that its `identity` endorsed: a relay alone cannot name a
/// counter the account never published, and the app's would follow it to the top, where no
/// rotation goes on (RV q8-q11).
pub(crate) fn held_endorsed(
    held: &gk::EndorsedPair,
    identity: &IdentityKeyPair,
    account: [u8; 16],
) -> bool {
    crate::group_key::wire::pair(held, gk::GkMember::Account(account)).is_ok_and(|p| {
        p.endorsement.origin == Origin::VaultSeat
            && p.endorsement.verify(identity.identity_key(), &p.keys)
    })
}

/// Whether `held` are these keys, as `publish` sends them (a signature is new each time).
pub(crate) fn held_is(held: &gk::EndorsedPair, keys: &SeatKeys) -> bool {
    let public = keys.pair.public();
    (held.n, held.made) == (keys.n, keys.made)
        && held.kem[..] == public.kem_bytes()[..]
        && held.dh[..] == public.dh_bytes()[..]
}

/// Whether seat keys made at `made` are due to rotate at `now` (unix seconds).
pub(crate) fn due(keys: &SeatKeys, now: u64) -> bool {
    now >= keys.made.saturating_add(ROTATE_AFTER_SECS)
}

/// Keys made more than this past our clock count as dated ahead (`dated_ahead`). A day, so
/// clocks a little apart do not rotate each other's keys.
const MADE_AHEAD_SECS: u64 = 24 * 60 * 60;

/// Whether seat keys were made more than a day past `now` (unix seconds; `AccountSync` reads
/// it at the later of this device's clock and the relay's): a rotation on a clock far ahead,
/// or keys a holder of the account's identity key dated so. `due` alone would stop every
/// device's 30-day rotation until then (RV q8-q11), so they rotate at a sign-in
/// (`AccountSync::gk_on`), and only there.
pub(crate) fn dated_ahead(keys: &SeatKeys, now: u64) -> bool {
    keys.made > now.saturating_add(MADE_AHEAD_SECS)
}

/// A copy of seat keys (they hold private keys, so they are no `Clone`).
pub(crate) fn copy(keys: &SeatKeys) -> SeatKeys {
    SeatKeys::from_bytes(&keys.to_bytes()).expect("seat keys encode and decode")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RV q8-q11 (257): `due` reads only `made + 30 days`, so keys dated a year ahead (a fast
    /// clock at a rotation, or a holder of the account's identity key) stopped every device's
    /// 30-day rotation for that year. Keys dated more than a day ahead are `dated_ahead`, and
    /// rotate at a sign-in; a clock a little ahead is not.
    #[test]
    fn seat_keys_dated_ahead_rotate_at_a_sign_in() {
        let now = 1_700_000_000;
        let day = 24 * 60 * 60;
        let ahead = SeatKeys::generate(1, now + 365 * day);
        assert!(!due(&ahead, now + 31 * day) && dated_ahead(&ahead, now + 31 * day));
        let soon = SeatKeys::generate(1, now + 60 * 60);
        assert!(!due(&soon, now) && !dated_ahead(&soon, now));
        assert!(!due(&SeatKeys::generate(1, now - 29 * day), now));
        assert!(due(&SeatKeys::generate(1, now - 30 * day), now));
    }
}
