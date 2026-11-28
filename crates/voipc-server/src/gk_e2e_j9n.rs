//! End-to-end group-key scenarios added by wave-2 slice J9N (2026-11-19): fast new start (owner
//! 2026-11-19): a keyholder set of connection entries alone, none online, starts anew at once
//! (J10-B option A, owner 2026-11-22; 2 minutes before), not after an hour.
//! The relay's real `gk` code driven by the clients' real `voipc_crypto::group_state` code;
//! the harness is J8H's (`gk_e2e_j8h.rs`: a stored text channel, the keyholder's app on a task
//! of its own, members stepped by the test, the clock paused for what is measured).
//!
//! `gk_e2e_j8h`'s two tests show the fast start itself (a sole browser keyholder's reload, a
//! relay restart). These show what keeps the hour: a set with a desktop's pair (0x03), and the
//! churn bound (a set that a Regenesis itself started, for an hour after it); and pin what the
//! member's own floor path still lacks.

use voipc_crypto::group_key::timers::REGENESIS_AFTER_MS;
use voipc_crypto::group_state::GkEvent;

use super::gk_e2e_j8h::{minutes, Account, World, CONV, SEATED_AT_ONCE_MS};

/// A desktop's keyholder pair (0x03) comes back with its device: a set that holds one keeps
/// the hour. The desktop holds the keys alone and goes; its account's browser page volunteers
/// but nothing online can sign its promotion, so the relay waits `REGENESIS_AFTER_MS` before
/// it asks the page for a Regenesis. A newcomer is seated by it after about an hour, not at
/// once as under a set of connection entries.
#[tokio::test]
async fn e2e_j9n_a_desktop_held_channel_still_waits_the_hour_for_its_regenesis() {
    let mut w = World::new().await;
    let kay = Account::new(&w.db, "kay").await;
    let ann = Account::new(&w.db, "ann").await;
    let neo = Account::new(&w.db, "neo").await;
    w.desktop_keyholder(&kay).await;
    w.member("ann", &ann, None).await;
    let keyed = w
        .until(30_000, 10, |w| {
            w.epoch("ann").is_some() && w.keyholder_epoch().is_some()
        })
        .await;
    assert!(keyed.is_some(), "the group started: {:?}", w.load());
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online),
        (1, 1),
        "the desktop alone holds the keys"
    );

    // The desktop goes; the account's page comes and volunteers
    w.keyholder_goes().await;
    w.browser(&kay).await;
    let back = w.until(30_000, 10, |w| w.keyholder_epoch().is_some()).await;
    assert!(back.is_some(), "the page holds the head");
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online),
        (1, 0),
        "the desktop's entry stays, offline"
    );

    w.pause();
    let waited = w.newcomer_waits_as("neo", &neo, SEATED_AT_ONCE_MS).await;
    assert!(
        waited.is_some_and(|t| t > SEATED_AT_ONCE_MS),
        "a set with a desktop's pair starts anew no sooner than the hour: seated after {}",
        minutes(waited)
    );
    assert!(
        waited.is_some_and(|t| t >= REGENESIS_AFTER_MS - 60_000),
        "seated by the hour's Regenesis: after {}; load {:?}",
        minutes(waited),
        w.load()
    );
    let l = w.load().unwrap();
    assert_eq!(
        (l.keyholders, l.keyholders_online),
        (1, 1),
        "the page started anew and holds the keys"
    );
}

/// The churn bound: a set that a Regenesis started keeps the hour for an hour after it. The
/// sole browser keyholder reloads and the page starts anew at once (as in J8H's test); soon
/// after, it reloads again. The set in force is now the one that Regenesis started, so the
/// next newcomer waits for the second new start an hour after the first, not at once.
/// (The second reload comes before the page's first refresh by rows: a page on a new
/// connection opens its seat's row with the seat secret of its seed, which this harness keeps
/// in no vault.)
#[tokio::test]
async fn e2e_j9n_a_page_that_reloads_again_within_the_hour_of_its_regenesis_waits_the_hour() {
    let mut w = World::new().await;
    let kay = Account::new(&w.db, "kay").await;
    let ann = Account::new(&w.db, "ann").await;
    let nan = Account::new(&w.db, "nan").await;
    let neo = Account::new(&w.db, "neo").await;
    let ned = Account::new(&w.db, "ned").await;
    w.started(&kay, &ann, &nan).await;

    w.reload(&kay).await;
    let back = w.until(30_000, 10, |w| w.keyholder_epoch().is_some()).await;
    assert!(back.is_some(), "the page holds the head again");
    w.pause();
    let first = w.newcomer_waits_as("neo", &neo, SEATED_AT_ONCE_MS).await;
    assert!(
        first.is_some_and(|t| t <= SEATED_AT_ONCE_MS),
        "the first new start is fast: seated after {}",
        minutes(first)
    );
    let first_at = w.now();
    let l = w.load().unwrap();
    assert_eq!((l.keyholders, l.keyholders_online), (1, 1));

    // Twenty seconds on, the page reloads again
    w.until(20_000, 500, |_| false).await;
    w.reload(&kay).await;
    let back = w.until(30_000, 50, |w| w.keyholder_epoch().is_some()).await;
    assert!(back.is_some(), "the page holds the head again");
    let l = w.load().unwrap();
    assert_eq!((l.keyholders, l.keyholders_online), (1, 0));
    let second = w.newcomer_waits_as("ned", &ned, SEATED_AT_ONCE_MS).await;
    assert!(
        second.is_some_and(|t| t > SEATED_AT_ONCE_MS),
        "the set the Regenesis started keeps the hour: seated after {}",
        minutes(second)
    );
    // Seated by a second new start an hour after the first, and no later than the
    // Regenesis, a Join and a settle allow (the fast start's own bound)
    let apart = w.now() - first_at;
    assert!(
        second.is_some()
            && (REGENESIS_AFTER_MS - 60_000..=REGENESIS_AFTER_MS + SEATED_AT_ONCE_MS)
                .contains(&apart),
        "the second new start came {} after the first; load {:?}",
        minutes(Some(apart)),
        w.load()
    );
    let l = w.load().unwrap();
    assert_eq!((l.keyholders, l.keyholders_online), (1, 1));
}

/// Every member online through the stall is back on the new start soon after it: the page
/// that made the Regenesis takes it on its own floor (its floor is the Regenesis's parent),
/// and the members, whose floors are older, walk to it, are told the keys were made anew, and
/// hold the new epoch's key.
#[tokio::test]
async fn e2e_j9n_the_online_members_hold_the_new_start_soon_after_it() {
    let mut w = World::new().await;
    let kay = Account::new(&w.db, "kay").await;
    let ann = Account::new(&w.db, "ann").await;
    let nan = Account::new(&w.db, "nan").await;
    let neo = Account::new(&w.db, "neo").await;
    w.started(&kay, &ann, &nan).await;
    let before = w.epoch("ann").expect("ann holds a key");

    w.reload(&kay).await;
    let back = w.until(30_000, 10, |w| w.keyholder_epoch().is_some()).await;
    assert!(back.is_some(), "the page holds the head again");
    w.pause();
    let waited = w.newcomer_waits_as("neo", &neo, SEATED_AT_ONCE_MS).await;
    assert!(
        waited.is_some_and(|t| t <= SEATED_AT_ONCE_MS),
        "the newcomer was seated after {}",
        minutes(waited)
    );
    let neo_epoch = w.epoch("neo").unwrap();
    assert!(neo_epoch > before, "a new epoch");
    let back = w
        .until(SEATED_AT_ONCE_MS, 50, |w| {
            ["ann", "nan"]
                .iter()
                .all(|m| w.epoch(m).is_some_and(|e| e >= neo_epoch))
        })
        .await;
    assert!(
        back.is_some(),
        "the online members hold the new start's key: ann {:?}, nan {:?}, neo {neo_epoch}",
        w.epoch("ann"),
        w.epoch("nan")
    );
    for m in ["ann", "nan"] {
        let anew = w.members[m]
            .app
            .events
            .iter()
            .any(|e| matches!(e, GkEvent::Anew { .. }));
        assert!(anew, "{m} was told the keys were made anew");
    }
    let _ = CONV;
}
