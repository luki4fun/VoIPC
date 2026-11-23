//! RV fixes, area g6 (2026-11-21): the relay's group lifecycle. A child of `gk_tests`, so its
//! helpers serve here as they are.

use voipc_crypto::group_key::timers::{refresh_ms, REGENESIS_FAST_AFTER_MS, SEAT_EXPIRY_SECS};
use voipc_crypto::group_key::{SignedHeader, REGENESIS_FAST_GAP};

use super::*;
use crate::gk::group::{KH_RESTART, KH_RESTART_RETRY_MS};

/// r-members:587: a stored group loaded after a restart (or an idle stop) whose head epoch is
/// past its refresh asks a Refresh once a keyholder is online, before any newcomer is seated
/// into that old epoch.
#[tokio::test]
async fn a_loaded_stored_group_asks_a_refresh_once_its_epoch_is_due() {
    let id = "c:lounge-rv587";
    let (_db, file, store, _g, k, now) = stored_genesis(id).await;
    let mut again = GroupState::new(
        id.into(),
        GroupKind::Text,
        true,
        Arc::new(OpenCaps::default()),
    );
    store.load(&mut again).await.unwrap();
    assert!(
        again.next_refresh.is_some(),
        "the load schedules its refresh"
    );
    let later = now + 2 * 3_600_000;
    let mut out = vec![];
    again.follow(1, None);
    again.volunteer(1, Some(k.volunteer(gk::platform::DESKTOP)), later, &mut out);
    again.tick(later + 2_000, &mut out);
    let (_, piece) = dues(&out, 1).pop().expect("a refresh due after the load");
    assert_eq!(piece.kind, gk::due::REFRESH);
    drop_db(&file);
}

/// q7:1031, r-members:1031: a Join still goes before a Refresh just due (lazy seating: the
/// newcomer opens the post that made it ask, decision 17), but a Refresh a whole refresh
/// period late goes first: a keyholder back from an absence (or the end of a join storm)
/// seats nobody into an epoch older than two refresh periods under an honest relay.
#[tokio::test]
async fn a_refresh_a_period_late_goes_before_a_closed_join_batch_and_a_join_before_one_just_due() {
    for late in [false, true] {
        let store = Store::memory();
        let (mut g, k, _h, _people, _) = seated_group(&store).await;
        let r = refresh_ms(g.head.as_ref().unwrap().sh.header().buckets);
        let due_at = g.next_refresh.expect("the Genesis set its refresh");
        let kv = k.volunteer(gk::platform::DESKTOP);
        let mut now = if late { due_at + r + 1 } else { due_at + 1 };
        let mut out = vec![];
        g.volunteer(k.sid, None, now, &mut out);
        let p = Person::guest(4);
        g.follow(p.sid, None);
        assert_eq!(g.fetch(p.sid, p.fetch(), now, &mut out), Fetched::Not);
        assert!(g.dues.is_empty(), "no keyholder online");
        now += 2_100;
        assert!(
            late || now < due_at + r,
            "the control stays within the period"
        );
        let mut out = vec![];
        g.volunteer(k.sid, Some(kv), now, &mut out);
        let (_, piece) = dues(&out, k.sid).pop().expect("a due");
        if late {
            assert_eq!(
                piece.kind,
                gk::due::REFRESH,
                "a refresh a period late opens the epoch before the newcomer is seated"
            );
        } else {
            assert_eq!(
                piece.kind,
                gk::due::JOIN,
                "a refresh just due waits for the Join"
            );
        }
    }
}

/// r-members:548: in a voice room where nobody wrote, every seated member hears of an exit,
/// so the app's 46 s warning can fire.
#[tokio::test]
async fn a_voice_exit_is_told_to_every_seated_member_writer_or_not() {
    let store = Store::memory();
    let (mut g, _people, _h, mut now) = voice_room(&store, &[2, 3, 4, 5]).await;
    now += 2_000;
    let mut out = vec![];
    g.leave(5, cause::LEAVE, now, &mut out);
    for sid in [2, 3, 4] {
        assert!(
            out.iter()
                .filter(|o| o.0 == sid)
                .flat_map(|o| &o.1)
                .any(|f| matches!(f, ServerMessage::EpochExit { .. })),
            "{sid} hears of the exit"
        );
    }
}

/// The head's header re-signed by `by` (its IK) as `signer`, one epoch past the head.
fn ahead_by(g: &GroupState, signer: MemberId, by: &IdentityKeyPair) -> gk::HeaderIn {
    let mut hv = g.head.as_ref().unwrap().sh.header().clone();
    hv.signer = signer;
    hv.epoch += 1;
    let sh = SignedHeader::sign(hv, by).unwrap();
    gk::HeaderIn {
        body: sh.body().to_vec(),
        sig: sh.sig().to_vec(),
    }
}

/// q6-q12:2119: a keyholder removed in this generation still holds its IK, and an earlier
/// set of the generation named it; its header past the head starts no new generation, but
/// warns the admins: an entry promoted again after the backup a relay was restored from
/// looks the same, and its members refuse every head until the operator acts. The head's
/// set still starts one (the control).
#[tokio::test]
async fn a_floor_ahead_signed_by_a_removed_keyholder_starts_nothing() {
    let store = Store::memory();
    let a = [5; 16];
    let (mut g, (k, _), mut h, d, mut now) = two_desktops(&store, a).await;
    let mut out = vec![];
    g.account_exit(&a, cause::BAN, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("the removal");
    assert_eq!(piece.kind, gk::due::REMOVE);
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(entries(&g), vec![k.m()]);
    g.follow(9, None);
    let removed = ahead_by(&g, d.m(), &d.ik);
    g.floor_ahead(9, &removed, now + 1_000, &mut out);
    assert!(
        !g.new_gen,
        "a removed keyholder's header forces no new generation"
    );
    assert_eq!(
        g.warnings(now + 1_000).len(),
        1,
        "the admins are told: a restore that lost a promotion looks so too"
    );
    let kept = ahead_by(&g, k.m(), &k.ik);
    g.floor_ahead(9, &kept, now + 2_000, &mut out);
    assert!(g.new_gen, "the head's set still does");
}

/// q6-q12:2120: a header past the head in this generation, signed by a keyholder the relay
/// holds no key of (one promoted after the backup it was restored from), changes nothing
/// and warns the admins, as a generation it does not know does.
#[tokio::test]
async fn a_floor_ahead_by_a_signer_the_relay_does_not_know_warns_its_admins() {
    let store = Store::memory();
    let (mut g, _k, _h, people, now) = seated_group(&store).await;
    let stranger = Person::account(9, [9; 16]);
    let hdr = ahead_by(&g, stranger.m(), &stranger.ik);
    let mut out = vec![];
    assert!(g.warnings(now).is_empty());
    g.floor_ahead(people[0].sid, &hdr, now + 1_000, &mut out);
    assert!(!g.new_gen);
    assert_eq!(g.warnings(now + 1_000).len(), 1, "the admins are told");
}

/// As if the generation had seen `n` keyholder changes in all (copies of the head's set,
/// under made-up digests `tag`).
fn long_chain(g: &mut GroupState, n: usize, tag: u8) {
    let kh = g.head.as_ref().unwrap().kh.clone();
    for i in 0..n.saturating_sub(g.khs.len()) as u32 {
        let mut key = [tag; 32];
        key[..4].copy_from_slice(&i.to_be_bytes());
        g.khs.insert(key, (kh.clone(), None));
    }
}

/// q6-q12:109: once a generation's keyholder headers near what a member walks
/// (`MAX_WALK`), the relay starts a new generation, asked at once though nobody waits for a
/// seat: past it a device with no floor could never take the head again. Until it lands the
/// head is served as it is.
#[tokio::test]
async fn a_keyholder_chain_near_the_walk_cap_starts_a_new_generation() {
    let store = Store::memory();
    let a = [5; 16];
    let (mut g, k, mut h, d, now, (due, piece)) = promote_out(&store, a).await;
    long_chain(&mut g, KH_RESTART - 1, 0xa5);
    let b = opening(&g, &k.0, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(g.khs.len(), KH_RESTART);
    let asked: Vec<u8> = [k.0.sid, d.sid]
        .iter()
        .flat_map(|s| dues(&out, *s))
        .map(|(_, p)| p.kind)
        .collect();
    assert_eq!(asked, vec![gk::due::GENESIS], "asked though nobody waits");
    assert!(!g.new_gen, "the head is served until the Genesis lands");
}

/// q6-q12:109: a long chain with no volunteer online to start anew keeps serving its head
/// (its walk is still within `MAX_WALK`); the new generation is asked once one is back.
#[tokio::test]
async fn a_long_keyholder_chain_with_no_volunteer_online_still_serves_its_head() {
    let store = Store::memory();
    let (mut g, k, _h, people, mut now) = seated_group(&store).await;
    let mut out = vec![];
    g.volunteer(k.sid, None, now, &mut out);
    long_chain(&mut g, KH_RESTART, 0x5a);
    now += 1_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    assert!(!g.new_gen, "nobody to start it: the head stays");
    let p = &people[0];
    assert_eq!(
        g.fetch(p.sid, p.fetch(), now, &mut out),
        Fetched::Seated(p.seat())
    );
    now += 1_000;
    let mut out = vec![];
    g.volunteer(
        k.sid,
        Some(k.volunteer(gk::platform::DESKTOP)),
        now,
        &mut out,
    );
    let (_, piece) = dues(&out, k.sid).pop().expect("a due");
    assert_eq!(
        piece.kind,
        gk::due::GENESIS,
        "a volunteer back: a new generation"
    );
}

/// q6-q12:109 (repair): a long chain's Genesis that nobody takes leaves the head served, and
/// what else is due goes on; the Genesis is asked again only `KH_RESTART_RETRY_MS` on.
#[tokio::test]
async fn a_long_chains_genesis_nobody_takes_leaves_the_head_served_and_the_dues_going() {
    let store = Store::memory();
    let (mut g, k, _h, people, mut now) = seated_group(&store).await;
    long_chain(&mut g, KH_RESTART, 0x6b);
    now += 1_000;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("a due");
    assert_eq!(piece.kind, gk::due::GENESIS);
    let p = &people[0];
    assert_eq!(
        g.fetch(p.sid, p.fetch(), now, &mut out),
        Fetched::Seated(p.seat()),
        "the head is served while the Genesis is out"
    );
    let mut out = vec![];
    g.decline(k.sid, due, gk::decline::NOT_READY, now, &mut out);
    let started = now;
    let mut next = None;
    for _ in 0..4 {
        now += 61_000;
        let mut out = vec![];
        g.tick(now, &mut out);
        if let Some((_, piece)) = dues(&out, k.sid).pop() {
            next = Some(piece.kind);
            break;
        }
    }
    assert_eq!(next, Some(gk::due::REFRESH), "the refresh goes on");
    assert!(!g.new_gen);
    assert_eq!(
        g.fetch(p.sid, p.fetch(), now, &mut out),
        Fetched::Seated(p.seat())
    );
    assert!(g.kh_restart_at >= started + KH_RESTART_RETRY_MS);
}

/// q6-q12:109 (repair): in a stored group whose keyholders are all away, a long chain starts
/// anew no sooner than a Regenesis would (the wait its set allows), whoever else volunteers
/// meanwhile; and then as a Genesis, since a Regenesis would only add to the chain. Under a
/// set of connection entries alone (the guest's pair here) that wait is none (J10-B option A,
/// owner 2026-11-22: 2 minutes before), so the Genesis is asked as the seat comes; under a set
/// with a desktop's pair, which may still come back, the hour.
#[tokio::test]
async fn a_long_chain_with_its_keyholders_away_waits_as_a_regenesis_would() {
    // A set of connection entries alone: at once
    let store = Store::memory();
    let (mut g, k, _h, people, now) = seated_group(&store).await;
    g.stored = true;
    long_chain(&mut g, KH_RESTART, 0x7c);
    let mut out = vec![];
    g.volunteer(k.sid, None, now, &mut out);
    let v = &people[0];
    g.volunteer(
        v.sid,
        Some(v.volunteer(gk::platform::DESKTOP)),
        now,
        &mut out,
    );
    let p = Person::guest(4);
    g.follow(p.sid, None);
    let mut out = vec![];
    assert_eq!(g.fetch(p.sid, p.fetch(), now, &mut out), Fetched::Not);
    let (_, piece) = dues(&out, v.sid).pop().expect("a new start at once");
    assert_eq!(
        piece.kind,
        gk::due::GENESIS,
        "not a Regenesis on a long chain"
    );

    // The set in force names a desktop's pair: the hour
    let store = Store::memory();
    let (mut g, k, _h, people, mut now) = seated_group(&store).await;
    g.stored = true;
    let head = g.head.as_mut().unwrap();
    let mut desk = head.kh.header().clone();
    let account = MemberId::Account([0x0d; 16]);
    desk.keyholders[0].m = account;
    desk.keyholders[0].origin = Origin::Desktop as u8;
    desk.signer = account;
    head.kh = SignedHeader::sign(desk, &k.ik).unwrap();
    long_chain(&mut g, KH_RESTART, 0x7c);
    let mut out = vec![];
    g.volunteer(k.sid, None, now, &mut out);
    let v = &people[0];
    g.volunteer(
        v.sid,
        Some(v.volunteer(gk::platform::DESKTOP)),
        now,
        &mut out,
    );
    let p = Person::guest(4);
    g.follow(p.sid, None);
    assert_eq!(g.fetch(p.sid, p.fetch(), now, &mut out), Fetched::Not);
    assert!(
        dues(&out, v.sid).is_empty(),
        "no new start while the keyholders may still come back"
    );
    let at = g.regenesis_at().expect("a time");
    assert_eq!(
        at,
        now + voipc_crypto::group_key::timers::REGENESIS_AFTER_MS,
        "the hour"
    );
    let mut out = vec![];
    g.tick(at - 1, &mut out);
    assert!(dues(&out, v.sid).is_empty(), "not before the wait is out");
    now = at;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (_, piece) = dues(&out, v.sid).pop().expect("a new start");
    assert_eq!(
        piece.kind,
        gk::due::GENESIS,
        "not a Regenesis on a long chain"
    );
}

/// r-members:55: a member that only read the epoch before the head was never pushed the
/// opening nor told of the exit it covers; its first chain there is refused `OLD_EPOCH`
/// (it fetches and writes under the head), while a writer of that epoch may still start
/// another chain for `HOLD_MS`.
#[tokio::test]
async fn a_readers_first_chain_under_the_epoch_before_the_head_is_refused() {
    let store = Store::memory();
    let (mut g, k, mut h, people, mut now) = seated_group(&store).await;
    let gen = g.gen().unwrap();
    let e = g.head.as_ref().unwrap().sh.header().epoch;
    let mut out = vec![];
    assert_eq!(g.post_blob(k.sid, gen, e, vec![1], now, &mut out), Ok(()));
    g.leave(people[1].sid, cause::LEAVE, now, &mut out);
    now += 2_100;
    let mut out = vec![];
    g.tick(now, &mut out);
    let (due, piece) = dues(&out, k.sid).pop().expect("the exits");
    let b = opening(&g, &k, &mut h, &piece, now);
    let mut out = vec![];
    let t = send(&mut g, k.sid, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    assert_eq!(g.head.as_ref().unwrap().sh.header().epoch, e + 1);
    let later = now + 30_000;
    let reader = people[0].sid;
    assert_eq!(
        g.post_blob(reader, gen, e, vec![2], later, &mut out),
        Err(refused_why::OLD_EPOCH),
        "a reader's first chain under the old epoch"
    );
    assert_eq!(
        g.post_blob(k.sid, gen, e, vec![3], later, &mut out),
        Ok(()),
        "a writer of it, pushed the opening"
    );
    assert_eq!(
        g.post_blob(reader, gen, e + 1, vec![4], later, &mut out),
        Ok(())
    );
}

/// r-attackers:1991: an account's text seat in a memory group survives a disconnect, but no
/// longer than a stored group's: unheld for 90 days, the daily sweep exits it.
#[tokio::test]
async fn a_memory_groups_account_seat_unheld_ninety_days_exits() {
    let store = Store::memory();
    let (mut g, a, now, due, b) = account_join(&store, false, &[2]).await;
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    g.leave(2, cause::DISCONNECT, now, &mut out);
    assert!(g.seats.contains_key(&a.seat()), "going offline is no exit");
    let day = 86_400_000;
    g.expire_away(now + SEAT_EXPIRY_SECS * 1000 - day, &mut out);
    assert!(!g.exits.has(&a.seat()), "not yet");
    g.expire_away(now + SEAT_EXPIRY_SECS * 1000 + day, &mut out);
    assert!(g.exits.has(&a.seat()), "unheld 90 days: an exit");
    // A seat held again is not expired
    let (mut g, a, now, due, b) = account_join(&store, false, &[2]).await;
    let mut out = vec![];
    let t = send(&mut g, 1, due, &b, now, &mut out).expect("taken");
    land(&mut g, &store, t, now, &mut out).await;
    g.leave(2, cause::DISCONNECT, now, &mut out);
    g.follow(3, Some([7; 16]));
    assert_eq!(
        g.fetch(3, a.fetch(), now, &mut out),
        Fetched::Seated(a.seat())
    );
    g.expire_away(now + SEAT_EXPIRY_SECS * 1000 + day, &mut out);
    assert!(!g.exits.has(&a.seat()), "a session holds it");
}

/// q6-q12:687 (§7 Q12, the owner's choice): the churn bound. After a Regenesis of a set of
/// connection entries, the relay promotes a second volunteer (fewer than 2 online), so the
/// set in force is no longer the Regenesis's and the relay, like every member, allows a
/// fast new start at once. This pins the gap: it fails until the owner picks how the
/// hour is kept (a relay rule alone, any set change in the hour, or a signed "last start").
#[tokio::test]
#[ignore = "owner choice Q12 (churn bound): fails until it is made"]
async fn a_set_promoted_after_a_regenesis_still_waits_the_churn_hour() {
    let store = Store::memory();
    let (mut g, k, _h, _people, now) = seated_group(&store).await;
    g.stored = true;
    let secs = now / 1000;
    let base = g.head.as_ref().unwrap().kh.header().clone();
    let forged = |kind: Kind, time: u64| {
        let mut x = base.clone();
        x.kind = kind;
        x.time = time;
        x.epoch += 1;
        x.parent = [1; 32];
        x.kh_parent = [1; 32];
        SignedHeader::sign(x, &k.ik).unwrap()
    };
    let regen = forged(Kind::Regenesis, secs);
    let add = forged(Kind::KeyholdersAdd, secs + 30);
    g.khs.insert(regen.d(), (regen, None));
    g.khs.insert(add.d(), (add.clone(), None));
    g.head.as_mut().unwrap().kh = add;
    let since = now + 60_000;
    g.no_keyholder_since = Some(since);
    let at = g.regenesis_at().expect("a time");
    assert!(
        at > since + REGENESIS_FAST_AFTER_MS,
        "not at once: {}",
        at - since
    );
    assert!(
        at >= (secs + REGENESIS_FAST_GAP) * 1000,
        "an hour after the Regenesis"
    );
}
