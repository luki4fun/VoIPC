//! The stored-message log on the relay: sealed entries, wrapped epoch keys
//! and published log keys (`voipc_crypto::log` makes and opens them). The
//! relay checks who may read and write a conversation and keeps the bytes; it
//! cannot open any of them.
//!
//! A channel's writers keep their keys as chains and buckets (protocol 21): a chain
//! per stretch between two leaves, a bucket of about 62 seats holding a key every chain
//! is sealed to, a row per reader. What the relay holds to is below `chain_put`; who is
//! really in a bucket is the writer's word, in a list only the writer can read.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::store::Store;
use l4f_accounts::util;
use voipc_crypto::log::{endorsed, epoch_parts, OWN_ROW_BYTES, ROW_BYTES};
use voipc_protocol::conv::dm_parties;
use voipc_protocol::messages::{
    AccountReply, BucketIn, ChainAsk, ChainKeys, ChainRow, ChainSeal, LogEntry, LogKeyInfo,
    OwnBucket, OwnChain, WrapIn, WrapOut,
};

use super::{refused, Relay};

/// Longest entry the relay files (sealed): a chat message with room to spare.
pub(crate) const MAX_ENTRY: usize = 16 * 1024;
/// A page of entries, under the 64 KiB frame it travels in.
const PAGE_BYTES: usize = 44 * 1024;
const PAGE_ROWS: i64 = 200;
/// Most entries a first read may ask to start back from (`fetch`), past the window.
const MAX_TAIL: i64 = 5000;
const MAX_LOGKEY_LOOKUPS: usize = 64;
/// Most people in one `LogPending` or `LogMembersFound`, under the 64 KiB frame. Nothing to
/// do with how many a log may seat (`kept_seats`): a channel's writers page through those.
const MAX_MEMBERS: usize = 256;
/// Joiners one `LogIndex` hands a writer, who asks again once they are answered.
const PENDING_PER_INDEX: usize = 2048;
/// New epochs one writer may start in one conversation per hour: a rekey for
/// every member who joins or leaves, with room to spare. Each is a row per
/// member, so unbounded they filled the database at the message rate
/// (1.0 audit H1-03).
const NEW_EPOCHS_PER_HOUR: i64 = 60;
/// Wraps one fetch returns, under the 64 KiB frame.
const WRAPS_PER_FETCH: i64 = 400;
/// Before a flood can take older posts it must stand this long, and a post counts
/// towards the floor only if it will outlive that too: a raid's cleanup, or a timer
/// just past the grace, would otherwise take what is below it with nothing left to show.
const GRACE_MS: i64 = 3 * 86_400_000;
/// How long a chain being made is spared by the sweep, and how long one that is never
/// finished lasts.
const UNFINISHED_SECS: i64 = 3600;
/// A writer's newest chain stays this long past its last post, with no entry on it:
/// what spares someone who posts now and then a whole new chain each time.
const NEWEST_KEPT_HOURS: i64 = 30 * 24;
/// A chain's steps at most: past this a writer starts a new chain, so a reader walks
/// at most this many from wherever it holds a state.
const MAX_CHAIN_STEPS: u32 = 128;
/// New buckets in one `ChainPut`, unless the writer has no live bucket there: a new
/// bucket of existing seats is the honest merge, and without this the same frame aims
/// hundreds of one-seat buckets at one reader.
const MAX_NEW_BUCKETS: usize = 3;
/// One version's seats, the writer's own row among them: the buckets of 62 and a margin.
const MAX_BUCKET_SEATS: usize = 64;
/// A sealed list at that size: `iv | 24 B a seat | tag`.
const MAX_LIST_BYTES: usize = 28 + 24 * MAX_BUCKET_SEATS;
/// What one `ChainRekey` may name, under the 64 KiB frame.
const MAX_MISSING: usize = 256;
const MAX_ARRIVALS: usize = 2048;
const MAX_GONE: usize = 1024;
/// Ids in a `LogMemberIdsFound`.
const MEMBER_IDS_PAGE: i64 = 2048;
/// Asks in a `WrapsPage`, and how much its answer carries, under the 64 KiB frame.
const MAX_CHAIN_ASKS: usize = 64;
const KEYS_PAGE_BYTES: usize = 56 * 1024;
/// Chains of a run of links in one answer, whose hops are about 120 B each. A quiet
/// channel's run at the default window is a thousand.
const MAX_RUN_HOPS: usize = 256;
const OWN_CHAINS_PAGE: i64 = 400;
const OWN_BUCKETS_PAGE: usize = 400;
const OWN_ROWS_PAGE: usize = 256;
const MAX_LISTS: usize = 32;
const MAX_JOIN_MANY: usize = 512;
/// The wait for a seat in a log someone left holding a key, doubling each time they come
/// back, here or anywhere, up to a day. Each leave makes every writer there start a new
/// chain at their next post, so unbounded this is a raid, across every channel at once.
const RESEAT_WAIT_SECS: i64 = 600;
const RESEAT_WAIT_MAX_SECS: i64 = 86_400;
/// Writers one walk takes at a time (`walk`).
const WALK_BATCH: i64 = 500;
/// How often an account's log key may change: each change walks every writer.
const NEW_LOGKEY_SECS: i64 = 60;
const EMPTY: &[u8] = &[];
/// How long what a count left under the quota stands (`room_for`).
const ROOM_SECS: i64 = 3600;
/// Nearer the quota than this, every post is counted.
const ROOM_MARGIN: i64 = 1024 * 1024;

/// What an account keeps here: its entries and the keys it wrapped for them. Its chains'
/// keys come from a running count: a sum over seat rows per post would read every seat of
/// every channel it writes in.
async fn used_bytes(relay: &Relay, me: &AccountId) -> Result<i64> {
    let entries: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT CAST(COALESCE(SUM(LENGTH(ct)), 0) AS BIGINT) FROM voipc_log WHERE sender = $1")
            .bind(&me.0[..])
            .fetch_one(pool)
            .await?
    });
    let wraps: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT CAST(COALESCE(SUM(LENGTH(wrapped)), 0) AS BIGINT) FROM voipc_wraps WHERE owner = $1")
            .bind(&me.0[..])
            .fetch_one(pool)
            .await?
    });
    let chains: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT CAST(COALESCE(SUM(key_bytes + open_bytes), 0) AS BIGINT) FROM voipc_writers WHERE owner = $1")
            .bind(&me.0[..])
            .fetch_one(pool)
            .await?
    });
    Ok(entries + wraps + chains)
}

/// Whether a post of `adding` bytes fits. A count reads every entry the account kept, and
/// away from the quota it changes the answer far less often than people post, so what the
/// last one left stands for an hour. Only their own posts can fill it in that time, and a
/// key write counts again (`forget_room`); what a sweep frees shows at the next count.
async fn room_for(relay: &Relay, me: &AccountId, adding: i64) -> Result<bool> {
    let now = util::now();
    if let Some(mut room) = relay.kept_room.get_mut(&me.0) {
        let (left, at) = *room;
        if now - at < ROOM_SECS && left - adding > ROOM_MARGIN {
            *room = (left - adding, at);
            return Ok(true);
        }
    }
    let left = relay.quota - used_bytes(relay, me).await? - adding;
    relay.kept_room.insert(me.0, (left, now));
    Ok(left >= 0)
}

fn forget_room(relay: &Relay, me: &AccountId) {
    relay.kept_room.remove(&me.0);
}

/// Rows as they come back: an account's keys (name, identity, log key,
/// signature), an entry (seq, sender, epoch, server_at, sealed), and a
/// member (account, then its keys).
type KeyRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);
type EntryRow = (i64, Vec<u8>, i64, i64, Vec<u8>);
type MemberRow = (Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);
/// A seat row: recipient, bucket, version, dead. And a chain: number, top, done, self-wrap,
/// the chain it links to.
type SeatRow = (Vec<u8>, i64, i32, bool);
type OwnChainRow = (i32, i16, bool, Vec<u8>, Option<i32>);

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn id16(v: Vec<u8>) -> [u8; 16] {
    v.try_into().unwrap_or([0; 16])
}

fn is_channel(conv: &str) -> bool {
    conv.starts_with("c:")
}

/// Whether `me` may read `conv`, which is one key lookup: a read never needs every seat.
async fn is_member(relay: &Relay, conv: &str, me: &[u8; 16]) -> Result<bool> {
    if let Some((a, b)) = dm_parties(conv) {
        return Ok(a == *me || b == *me);
    }
    if !is_channel(conv) {
        return Ok(false);
    }
    let row: Option<i64> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT CAST(1 AS BIGINT) FROM voipc_members WHERE conv = $1 AND account = $2")
            .bind(conv)
            .bind(&me[..])
            .fetch_optional(pool)
            .await?
    });
    Ok(row.is_some())
}

/// The members of `conv` if `me` is one: the two parties of a direct
/// conversation, or the stored members of a channel's log.
async fn members(relay: &Relay, conv: &str, me: &[u8; 16]) -> Result<Option<Vec<[u8; 16]>>> {
    if let Some((a, b)) = dm_parties(conv) {
        return Ok((a == *me || b == *me).then(|| vec![a, b]));
    }
    if !is_channel(conv) {
        return Ok(None);
    }
    let rows: Vec<Vec<u8>> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT account FROM voipc_members WHERE conv = $1").bind(conv).fetch_all(pool).await?
    });
    let members: Vec<[u8; 16]> = rows.into_iter().map(id16).collect();
    Ok(members.contains(me).then_some(members))
}

pub(super) async fn publish(
    relay: &Relay,
    me: AccountId,
    logkey: &[u8],
    sig: &[u8],
) -> Result<AccountReply> {
    if logkey.len() != 33 || sig.len() != 64 {
        return Ok(refused("LogKeyPublish", "malformed log key"));
    }
    // One member's junk or low-order key would otherwise leave them unreachable, and
    // every writer in every channel they sit in would stop keeping anything there.
    let identity = relay.identity(me).await?;
    if !identity.is_some_and(|i| endorsed(&i, logkey, sig)) {
        return Ok(refused(
            "LogKeyPublish",
            "That log key is not one your identity vouches for.",
        ));
    }
    let old: Option<(Vec<u8>, i64)> = db!(relay.store(), pool => {
        sqlx::query_as("SELECT logkey, updated_at FROM voipc_logkeys WHERE account = $1")
            .bind(&me.0[..])
            .fetch_optional(pool)
            .await?
    });
    let changed = old.as_ref().is_some_and(|(o, _)| o != logkey);
    // A first key after seats taken without one: what writers gave them till now are blanks,
    // which must count as missing now there is a key to give a real row to. A new account
    // sits nowhere, and walks no writer.
    let blanks_held = old.is_none() && sat_anywhere(relay.store(), &me.0).await?;
    if changed && old.is_some_and(|(_, at)| util::now() - at < NEW_LOGKEY_SECS) {
        return Ok(refused(
            "LogKeyPublish",
            "That log key changed a moment ago; try again in a minute.",
        ));
    }
    // The mark goes in with the key: from here the walk is owed, whatever happens to it
    let walk_from = (changed || blanks_held).then_some(0i32);
    db!(relay.store(), pool => {
        sqlx::query(
            "INSERT INTO voipc_logkeys (account, logkey, sig, updated_at, walk_after) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (account) DO UPDATE SET logkey = excluded.logkey, sig = excluded.sig, updated_at = excluded.updated_at,
               walk_after = COALESCE(excluded.walk_after, voipc_logkeys.walk_after)",
        )
        .bind(&me.0[..])
        .bind(logkey)
        .bind(sig)
        .bind(util::now())
        .bind(walk_from)
        .execute(pool)
        .await?;
    });
    finish_walk(relay.store(), &me.0).await?;
    Ok(AccountReply::LogKeyStored)
}

/// Whether `account` holds or left a seat in any channel's log.
async fn sat_anywhere(store: &Store, account: &[u8; 16]) -> Result<bool> {
    let seat: Option<i64> = db!(store, pool => {
        sqlx::query_scalar(
            "SELECT CAST(1 AS BIGINT) FROM voipc_members WHERE account = $1
             UNION ALL SELECT CAST(1 AS BIGINT) FROM voipc_left WHERE account = $1 LIMIT 1",
        )
        .bind(&account[..])
        .fetch_optional(pool)
        .await?
    });
    Ok(seat.is_some())
}

/// Rows to `account` under every writer, marked dead and emptied: it has a new log key or
/// none, and whoever holds the old one is the only one they ever opened for. They stay,
/// since a row says someone holds that chain, and without it they could erase the mark
/// that makes the writer's next post a new chain (the row of a member who is gone) or
/// rotate their bucket. No index goes by recipient, so this is a probe per writer.
pub async fn walk(store: &Store, account: &[u8; 16]) -> Result<()> {
    let mut after = 0i32;
    while let Some(last) = walk_batch(store, account, after, false).await? {
        after = last;
    }
    Ok(())
}

/// The walk a new log key owes, from where the last one stopped: each batch commits with how
/// far it got, so a resume leaves alone the writers behind that, who may have rows under the
/// new key by now. A dying walk comes back here at that account's next publish, or the sweep.
async fn finish_walk(store: &Store, account: &[u8; 16]) -> Result<()> {
    loop {
        let after: Option<i32> = db!(store, pool => {
            sqlx::query_scalar::<_, Option<i32>>("SELECT walk_after FROM voipc_logkeys WHERE account = $1")
                .bind(&account[..])
                .fetch_optional(pool)
                .await?
        })
        .flatten();
        let Some(after) = after else {
            return Ok(());
        };
        if walk_batch(store, account, after, true).await?.is_some() {
            continue;
        }
        // Only if that is still the walk: a newer key starts it over
        let ended = db!(store, pool => {
            sqlx::query("UPDATE voipc_logkeys SET walk_after = NULL WHERE account = $1 AND walk_after = $2")
                .bind(&account[..])
                .bind(after)
                .execute(pool)
                .await?
                .rows_affected()
        });
        if ended > 0 {
            return Ok(());
        }
    }
}

/// One batch of `walk`, past writer `after`: the last writer it took, or `None` at the end.
/// `marked`: also moves the account's mark there, in the same transaction.
async fn walk_batch(
    store: &Store,
    account: &[u8; 16],
    after: i32,
    marked: bool,
) -> Result<Option<i32>> {
    let ids: Vec<i32> = db!(store, pool => {
        sqlx::query_scalar("SELECT id FROM voipc_writers WHERE id > $1 ORDER BY id LIMIT $2")
            .bind(after)
            .bind(WALK_BATCH)
            .fetch_all(pool)
            .await?
    });
    let Some(last) = ids.last().copied() else {
        return Ok(None);
    };
    db!(store, pool => {
        let mut tx = pool.begin().await?;
        for id in &ids {
            sqlx::query("UPDATE voipc_seats SET dead = TRUE, wrapped = $3 WHERE writer = $1 AND recipient = $2 AND dead = FALSE")
                .bind(id)
                .bind(&account[..])
                .bind(EMPTY)
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE voipc_chain_wraps SET dead = TRUE, wrapped = $3 WHERE writer = $1 AND recipient = $2 AND dead = FALSE")
                .bind(id)
                .bind(&account[..])
                .bind(EMPTY)
                .execute(&mut *tx)
                .await?;
        }
        if marked {
            sqlx::query("UPDATE voipc_logkeys SET walk_after = $1 WHERE account = $2 AND walk_after = $3")
                .bind(last)
                .bind(&account[..])
                .bind(after)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    });
    Ok(Some(last))
}

/// Whether a sealed message can be kept for `account`: it has published a log key.
pub(super) async fn has_key(relay: &Relay, account: &[u8; 16]) -> Result<bool> {
    let row: Option<(i64,)> = db!(relay.store(), pool => {
        sqlx::query_as("SELECT CAST(1 AS BIGINT) FROM voipc_logkeys WHERE account = $1")
            .bind(&account[..])
            .fetch_optional(pool)
            .await?
    });
    Ok(row.is_some())
}

pub(super) async fn keys(relay: &Relay, accounts: &[[u8; 16]]) -> Result<AccountReply> {
    if accounts.len() > MAX_LOGKEY_LOOKUPS {
        return Ok(refused("LogKeys", "too many accounts at once"));
    }
    let mut found = Vec::with_capacity(accounts.len());
    for a in accounts {
        let row: Option<KeyRow> = db!(relay.store(), pool => {
            sqlx::query_as(
                "SELECT u.username, i.identity_key, k.logkey, k.sig FROM voipc_logkeys k
                   JOIN voipc_identity i ON i.account = k.account JOIN acct_users u ON u.id = k.account
                  WHERE k.account = $1",
            )
            .bind(&a[..])
            .fetch_optional(pool)
            .await?
        });
        if let Some((name, identity, logkey, sig)) = row {
            found.push(LogKeyInfo {
                account: *a,
                name,
                identity,
                logkey,
                sig,
            });
        }
    }
    Ok(AccountReply::LogKeysFound { keys: found })
}

/// Files the wraps; also says which recipients to tell (`LogNews`).
pub(super) async fn epoch_put(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    epoch: u32,
    wraps: &[WrapIn],
) -> Result<(AccountReply, Vec<[u8; 16]>)> {
    let Some(members) = members(relay, conv, &me.0).await? else {
        return Ok((
            refused("EpochPut", "not a conversation of yours"),
            Vec::new(),
        ));
    };
    // On a channel this is part of an answer to joiners. Someone who left since it was made
    // is out of it, the rest are still owed it, and only its last chain frame ends their wait
    let on_channel = is_channel(conv);
    let still: Vec<WrapIn> = wraps
        .iter()
        .filter(|w| on_channel && members.contains(&w.recipient))
        .cloned()
        .collect();
    let stored = || AccountReply::EpochStored {
        conv: conv.to_string(),
        epoch,
    };
    if on_channel && still.is_empty() && !wraps.is_empty() {
        return Ok((stored(), Vec::new()));
    }
    let wraps = if on_channel { &still[..] } else { wraps };
    if wraps.is_empty()
        || wraps.len() > members.len()
        || wraps
            .iter()
            .any(|w| !members.contains(&w.recipient) || w.wrapped.len() > 128)
    {
        return Ok((
            refused("EpochPut", "wraps for somebody outside the conversation"),
            Vec::new(),
        ));
    }
    let now = util::now();
    let known: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT COUNT(*) FROM voipc_wraps WHERE conv = $1 AND owner = $2 AND epoch = $3")
            .bind(conv)
            .bind(&me.0[..])
            .bind(i64::from(epoch))
            .fetch_one(pool)
            .await?
    });
    if known == 0 {
        // A channel's keys go through `chain_put`. An epoch from a version before that can
        // still go to someone a writer shares with, as an old key to what it opens
        if is_channel(conv) {
            return Ok((
                refused("EpochPut", "a channel's new keys are chains"),
                Vec::new(),
            ));
        }
        let recent: i64 = db!(relay.store(), pool => {
            sqlx::query_scalar("SELECT COUNT(DISTINCT epoch) FROM voipc_wraps WHERE conv = $1 AND owner = $2 AND created_at > $3")
                .bind(conv)
                .bind(&me.0[..])
                .bind(now - 3600)
                .fetch_one(pool)
                .await?
        });
        if recent >= NEW_EPOCHS_PER_HOUR {
            return Ok((
                refused(
                    "EpochPut",
                    "Too many new keys for this conversation; try again later.",
                ),
                Vec::new(),
            ));
        }
    }
    let adding: i64 = wraps.iter().map(|w| w.wrapped.len() as i64).sum();
    forget_room(relay, &me);
    if used_bytes(relay, &me).await? + adding > relay.quota {
        return Ok((
            refused(
                "EpochPut",
                "Your stored messages are over this server's limit.",
            ),
            Vec::new(),
        ));
    }
    // One transaction: one commit for the whole epoch, not one per member
    db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        for w in wraps {
            // Insert only: an epoch key once handed out is never replaced, so
            // a second device minting the same epoch at the same moment loses
            // quietly and reads the first one's instead.
            sqlx::query(
                "INSERT INTO voipc_wraps (conv, owner, epoch, recipient, wrapped, created_at) VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT DO NOTHING",
            )
            .bind(conv)
            .bind(&me.0[..])
            .bind(i64::from(epoch))
            .bind(&w.recipient[..])
            .bind(&w.wrapped)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    });
    let told = wraps
        .iter()
        .map(|w| w.recipient)
        .filter(|r| *r != me.0 && !on_channel)
        .collect();
    Ok((stored(), told))
}

pub(super) async fn wraps(relay: &Relay, me: AccountId, conv: &str) -> Result<AccountReply> {
    if !is_member(relay, conv, &me.0).await? {
        return Ok(refused("WrapsFetch", "not a conversation of yours"));
    }
    // shortcut: the newest 400 only (wraps of epochs with nothing left in
    // them go with the sweep), but each writer's newest share of them: one
    // member minting epochs no longer pushes everybody else's keys out of the
    // window (1.0 audit H1-04). Paging if conversations outgrow the share.
    let owners: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT COUNT(DISTINCT owner) FROM voipc_wraps WHERE recipient = $1 AND conv = $2")
            .bind(&me.0[..])
            .bind(conv)
            .fetch_one(pool)
            .await?
    });
    let share = (WRAPS_PER_FETCH / owners.max(1)).max(8);
    let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT owner, epoch, wrapped FROM (
                 SELECT owner, epoch, wrapped, created_at,
                        ROW_NUMBER() OVER (PARTITION BY owner ORDER BY created_at DESC) AS rn
                 FROM voipc_wraps WHERE recipient = $1 AND conv = $2
             ) AS w WHERE rn <= $3 ORDER BY created_at DESC LIMIT $4",
        )
        .bind(&me.0[..])
        .bind(conv)
        .bind(share)
        .bind(WRAPS_PER_FETCH)
        .fetch_all(pool)
        .await?
    });
    let wraps = rows
        .into_iter()
        .map(|(owner, epoch, wrapped)| WrapOut {
            owner: id16(owner),
            epoch: epoch as u32,
            wrapped,
        })
        .collect();
    Ok(AccountReply::Wraps {
        conv: conv.to_string(),
        wraps,
    })
}

pub(super) async fn append(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    epoch: u32,
    ct: &[u8],
    ttl_secs: Option<u32>,
) -> Result<AccountReply> {
    if !relay.cloud {
        return Ok(refused("LogAppend", "This server keeps no messages."));
    }
    let Some(members) = members(relay, conv, &me.0).await? else {
        return Ok(refused("LogAppend", "not a conversation of yours"));
    };
    if ct.is_empty() || ct.len() > MAX_ENTRY {
        return Ok(refused("LogAppend", "That message is too long to keep."));
    }
    let writer = if is_channel(conv) {
        writer_of(relay.store(), conv, &me.0).await?
    } else {
        None
    };
    if let Some(w) = &writer {
        if let Some(rekey) = chain_gate(relay.store(), w, conv, &me.0, epoch, &members).await? {
            return Ok(rekey);
        }
    } else if is_channel(conv) {
        // A writer who has never put a chain here: a first post, to everyone
        if let Some(rekey) =
            owed_on_chain(relay.store(), conv, 0, None, &me.0, &members, Vec::new()).await?
        {
            return Ok(rekey);
        }
    }
    if !room_for(relay, &me, ct.len() as i64).await? {
        return Ok(refused(
            "LogAppend",
            "Your stored messages are over this server's limit.",
        ));
    }
    let server_at = now_ms();
    // The message's own timer when it has one, never past the relay's retention.
    let keep = ttl_secs
        .map(|t| i64::from(t) * 1000)
        .unwrap_or(i64::MAX)
        .min(relay.retention_ms);
    let keep_until = server_at.saturating_add(keep);
    let seq: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar(
            "INSERT INTO voipc_log (conv, sender, epoch, server_at, keep_until, ct) VALUES ($1, $2, $3, $4, $5, $6) RETURNING seq",
        )
        .bind(conv)
        .bind(&me.0[..])
        .bind(i64::from(epoch))
        .bind(server_at)
        .bind(keep_until)
        .bind(ct)
        .fetch_one(pool)
        .await?
    });
    if let Some(w) = writer {
        // A write per hour at most, for the sweep's "posted lately"
        let hour = util::now() / 3600;
        db!(relay.store(), pool => {
            sqlx::query("UPDATE voipc_writers SET last_post_hour = $1 WHERE id = $2 AND last_post_hour <> $1")
                .bind(hour)
                .bind(w.id)
                .execute(pool)
                .await?;
        });
    }
    Ok(AccountReply::LogAppended {
        conv: conv.to_string(),
        seq,
        server_at: server_at as u64,
    })
}

/// Where a read of `conv` starts. Negative: at the newest `|after|` entries, then page as
/// usual. A client holds a few hundred per conversation, and a browser reads them back
/// after every reload, so a year's log is not sent to be thrown away. A channel's read
/// starts no lower than the floor the sweep stored; a direct conversation has none.
/// Also says that floor.
async fn read_start(relay: &Relay, conv: &str, after: i64, now_ms: i64) -> Result<(i64, i64)> {
    let after = if after < 0 {
        let first: Option<i64> = db!(relay.store(), pool => {
            sqlx::query_scalar(
                "SELECT seq FROM voipc_log WHERE conv = $1 AND keep_until > $2 ORDER BY seq DESC LIMIT 1 OFFSET $3",
            )
            .bind(conv)
            .bind(now_ms)
            .bind(after.saturating_abs().min(relay.kept_window.max(MAX_TAIL)) - 1)
            .fetch_optional(pool)
            .await?
        });
        first.map_or(0, |seq| seq - 1)
    } else {
        after
    };
    if !is_channel(conv) {
        return Ok((after, 0));
    }
    let floor: Option<i64> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT floor FROM voipc_log_floors WHERE conv = $1")
            .bind(conv)
            .fetch_optional(pool)
            .await?
    });
    let floor = floor.unwrap_or(0);
    Ok((after.max(floor - 1), floor))
}

pub(super) async fn fetch(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    after: i64,
) -> Result<AccountReply> {
    if !is_member(relay, conv, &me.0).await? {
        return Ok(refused("LogFetch", "not a conversation of yours"));
    }
    let now_ms = now_ms();
    let (after, _) = read_start(relay, conv, after, now_ms).await?;
    let rows: Vec<EntryRow> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT seq, sender, epoch, server_at, ct FROM voipc_log WHERE conv = $1 AND seq > $2 AND keep_until > $3
              ORDER BY seq LIMIT $4",
        )
        .bind(conv)
        .bind(after)
        .bind(now_ms)
        .bind(PAGE_ROWS + 1)
        .fetch_all(pool)
        .await?
    });
    let mut more = rows.len() as i64 > PAGE_ROWS;
    let mut bytes = 0;
    let mut entries = Vec::new();
    for (seq, sender, epoch, server_at, ct) in rows.into_iter().take(PAGE_ROWS as usize) {
        bytes += ct.len() + 64;
        if bytes > PAGE_BYTES && !entries.is_empty() {
            more = true;
            break;
        }
        entries.push(LogEntry {
            seq,
            sender: id16(sender),
            epoch: epoch as u32,
            server_at: server_at as u64,
            ct,
        });
    }
    let owed: Vec<Vec<u8>> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT owner FROM voipc_pending WHERE conv = $1 AND recipient = $2").bind(conv).bind(&me.0[..]).fetch_all(pool).await?
    });
    Ok(AccountReply::LogPage {
        conv: conv.to_string(),
        entries,
        more,
        owed: owed.into_iter().map(id16).collect(),
    })
}

/// An account's direct conversations (`index`). The range keeps channels' rows out on both
/// databases: SQLite cannot narrow by a LIKE on a BINARY index, and a pattern starting
/// `d:%` narrows no further on Postgres. Within it this reads every direct row on the relay.
pub(super) const DIRECT_CONVS: &str = "SELECT conv, MAX(seq) FROM voipc_log
     WHERE conv >= 'd:' AND conv < 'd;' AND (conv LIKE $1 OR conv LIKE $2) AND keep_until > $3
     GROUP BY conv ORDER BY conv";

/// The conversations with something for us, direct ones first, past 512 in several
/// answers, and every joiner still waiting for our keys (one `LogPending` per
/// conversation). A channel's newest entry is a walk down its index, not a read of the
/// whole log: a channel keeps thousands, and this runs at every connect.
pub(super) async fn index(
    relay: &Relay,
    me: AccountId,
) -> Result<(AccountReply, Vec<AccountReply>)> {
    let hex = me.hex();
    let now_ms = now_ms();
    let mut convs: Vec<(String, i64)> = db!(relay.store(), pool => {
        sqlx::query_as(DIRECT_CONVS)
        .bind(format!("d:{hex}:%"))
        .bind(format!("d:%:{hex}"))
        .bind(now_ms)
        .fetch_all(pool)
        .await?
    });
    let channels: Vec<(String, Option<i64>)> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT m.conv, (SELECT l.seq FROM voipc_log l WHERE l.conv = m.conv AND l.keep_until > $2 ORDER BY l.seq DESC LIMIT 1)
               FROM voipc_members m WHERE m.account = $1 ORDER BY m.conv",
        )
        .bind(&me.0[..])
        .bind(now_ms)
        .fetch_all(pool)
        .await?
    });
    convs.extend(channels.into_iter().filter_map(|(c, n)| Some((c, n?))));
    let rows: Vec<(String, Vec<u8>)> = db!(relay.store(), pool => {
        sqlx::query_as("SELECT conv, recipient FROM voipc_pending WHERE owner = $1 ORDER BY conv LIMIT $2")
            .bind(&me.0[..])
            .bind(PENDING_PER_INDEX as i64 + 1)
            .fetch_all(pool)
            .await?
    });
    let more = rows.len() > PENDING_PER_INDEX;
    let mut pending: Vec<AccountReply> = Vec::new();
    for (conv, r) in rows.into_iter().take(PENDING_PER_INDEX) {
        match pending.last_mut() {
            Some(AccountReply::LogPending { conv: c, joiners })
                if *c == conv && joiners.len() < MAX_MEMBERS =>
            {
                joiners.push(id16(r))
            }
            _ => pending.push(AccountReply::LogPending {
                conv,
                joiners: vec![id16(r)],
            }),
        }
    }
    let mut pages: Vec<Vec<(String, i64)>> = convs.chunks(512).map(<[_]>::to_vec).collect();
    let last = pages.pop().unwrap_or_default();
    pending.extend(
        pages
            .into_iter()
            .map(|convs| AccountReply::LogConvs { convs }),
    );
    if more {
        pending.push(AccountReply::LogPendingMore);
    }
    Ok((AccountReply::LogConvs { convs: last }, pending))
}

/// What taking a seat came to.
enum Seat {
    Taken(Vec<[u8; 16]>),
    /// Already had it: nobody is told again.
    Held,
    Full,
    Wait,
}

/// Makes `me` a stored member of each of `convs`, in one transaction, up to `cap` seats in
/// a log (0: no limit), and says for each which writers to tell: those who share. Writers
/// who do not are told nothing, and give a joiner a fresh step at their next post.
async fn take_seats(relay: &Relay, me: &[u8; 16], convs: &[&str], cap: i64) -> Result<Vec<Seat>> {
    let now = util::now();
    let strikes: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT CAST(strikes AS BIGINT) FROM voipc_reseats WHERE account = $1 AND last_at > $2")
            .bind(&me[..])
            .bind(now - RESEAT_WAIT_MAX_SECS)
            .fetch_optional(pool)
            .await?
    })
    .unwrap_or(0);
    let wait = RESEAT_WAIT_SECS
        .saturating_mul(1i64 << strikes.clamp(0, 16))
        .min(RESEAT_WAIT_MAX_SECS);
    let mut out = Vec::with_capacity(convs.len());
    let mut strikes = strikes;
    db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        for conv in convs {
            // The write comes first: on SQLite a read and then a write in one
            // transaction fails if anyone wrote in between.
            let added = sqlx::query("INSERT INTO voipc_members (conv, account, joined_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(*conv)
                .bind(&me[..])
                .bind(now)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            if added == 0 {
                out.push(Seat::Held);
                continue;
            }
            let left: Option<i64> = sqlx::query_scalar("SELECT left_at FROM voipc_left WHERE account = $1 AND conv = $2")
                .bind(&me[..])
                .bind(*conv)
                .fetch_optional(&mut *tx)
                .await?;
            let count: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_members WHERE conv = $1")
                .bind(*conv)
                .fetch_one(&mut *tx)
                .await?;
            let waits = left.is_some_and(|at| now < at + wait);
            // ponytail: two at once can pass the count by one.
            if waits || (cap > 0 && count > cap) {
                sqlx::query("DELETE FROM voipc_members WHERE conv = $1 AND account = $2")
                    .bind(*conv)
                    .bind(&me[..])
                    .execute(&mut *tx)
                    .await?;
                out.push(if waits { Seat::Wait } else { Seat::Full });
                continue;
            }
            if left.is_some() {
                strikes += 1;
                sqlx::query("DELETE FROM voipc_left WHERE account = $1 AND conv = $2")
                    .bind(&me[..])
                    .bind(*conv)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(
                    "INSERT INTO voipc_reseats (account, strikes, last_at) VALUES ($1, $2, $3)
                     ON CONFLICT (account) DO UPDATE SET strikes = excluded.strikes, last_at = excluded.last_at",
                )
                .bind(&me[..])
                .bind(strikes.min(16) as i32)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "INSERT INTO voipc_pending (conv, owner, recipient, created_at)
                 SELECT w.conv, w.owner, $2, $3 FROM voipc_writers w
                   JOIN voipc_members m ON m.conv = w.conv AND m.account = w.owner
                  WHERE w.conv = $1 AND w.owner <> $2 AND w.shares = TRUE
                 ON CONFLICT DO NOTHING",
            )
            .bind(*conv)
            .bind(&me[..])
            .bind(now)
            .execute(&mut *tx)
            .await?;
            let owners: Vec<Vec<u8>> = sqlx::query_scalar("SELECT owner FROM voipc_pending WHERE conv = $1 AND recipient = $2")
                .bind(*conv)
                .bind(&me[..])
                .fetch_all(&mut *tx)
                .await?;
            out.push(Seat::Taken(owners.into_iter().map(id16).collect()));
        }
        tx.commit().await?;
    });
    Ok(out)
}

/// Makes `me` a stored member of a channel's log; `present` says the session
/// is in that channel now (the relay's own admission decided that). Also
/// says which writers to tell: each one that keeps keys here owes us an answer.
pub(crate) async fn join(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    present: bool,
) -> Result<(AccountReply, Vec<[u8; 16]>)> {
    if !relay.cloud {
        return Ok((
            refused("LogJoin", "This server keeps no messages."),
            Vec::new(),
        ));
    }
    if !is_channel(conv) || !present {
        return Ok((refused("LogJoin", "Join the channel first."), Vec::new()));
    }
    let joined = || AccountReply::LogJoined {
        conv: conv.to_string(),
    };
    let seat = take_seats(relay, &me.0, &[conv], relay.kept_seats).await?;
    Ok(match seat.into_iter().next() {
        Some(Seat::Taken(owners)) => (joined(), owners),
        Some(Seat::Full) => (
            refused(
                "LogJoin",
                "This channel keeps history for as many people as it can.",
            ),
            Vec::new(),
        ),
        Some(Seat::Wait) => (
            refused(
                "LogJoin",
                "You stopped keeping this channel a moment ago. It can keep it for you again later.",
            ),
            Vec::new(),
        ),
        _ => (joined(), Vec::new()),
    })
}

/// `join` for many channels at once, which a silent follow sends: those of `present` it
/// could seat, the rest in `refused`, one answer for all reasons. A silent follow takes a
/// log only up to half of `kept_seats`: the rest of its seats are for someone who asked.
/// A returning account is seated already, and writes nothing. Also says, per conversation,
/// the writers to tell.
pub(crate) async fn join_many(
    relay: &Relay,
    me: AccountId,
    convs: &[String],
    present: &[bool],
) -> Result<(AccountReply, Vec<(String, Vec<[u8; 16]>)>)> {
    if !relay.cloud {
        return Ok((
            refused("LogJoinMany", "This server keeps no messages."),
            Vec::new(),
        ));
    }
    if convs.len() > MAX_JOIN_MANY {
        return Ok((
            refused("LogJoinMany", "too many channels at once"),
            Vec::new(),
        ));
    }
    let held: HashSet<String> = db!(relay.store(), pool => {
        sqlx::query_scalar::<_, String>("SELECT conv FROM voipc_members WHERE account = $1")
            .bind(&me.0[..])
            .fetch_all(pool)
            .await?
    })
    .into_iter()
    .collect();
    let (mut joined, mut refused_here) = (Vec::new(), Vec::new());
    let mut wanted: Vec<&str> = Vec::new();
    for (conv, present) in convs.iter().zip(present) {
        if held.contains(conv) {
            joined.push(conv.clone());
        } else if *present && is_channel(conv) && !wanted.contains(&conv.as_str()) {
            wanted.push(conv);
        } else {
            refused_here.push(conv.clone());
        }
    }
    let mut told = Vec::new();
    if !wanted.is_empty() {
        let seats = take_seats(relay, &me.0, &wanted, relay.kept_seats / 2).await?;
        for (conv, seat) in wanted.into_iter().zip(seats) {
            match seat {
                Seat::Taken(owners) => {
                    joined.push(conv.to_string());
                    told.push((conv.to_string(), owners));
                }
                Seat::Held => joined.push(conv.to_string()),
                Seat::Full | Seat::Wait => refused_here.push(conv.to_string()),
            }
        }
    }
    Ok((
        AccountReply::LogJoinedMany {
            joined,
            refused: refused_here,
        },
        told,
    ))
}

pub(super) async fn leave(relay: &Relay, me: AccountId, conv: &str) -> Result<AccountReply> {
    if !is_channel(conv) {
        return Ok(refused("LogLeave", "not a channel's log"));
    }
    remove(relay.store(), conv, &me.0).await?;
    Ok(AccountReply::LogLeft {
        conv: conv.to_string(),
    })
}

/// Deletes what `me` wrote to the stored logs, in `conv` or everywhere, and
/// the keys it handed out for it. Other people's entries stay: they are
/// theirs. Its next post there starts a new key.
pub(super) async fn purge(
    relay: &Relay,
    me: AccountId,
    conv: Option<&str>,
) -> Result<AccountReply> {
    let entries: u64 = db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        let n = sqlx::query("DELETE FROM voipc_log WHERE sender = $1 AND ($2 IS NULL OR conv = $2)")
            .bind(&me.0[..])
            .bind(conv)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        sqlx::query("DELETE FROM voipc_wraps WHERE owner = $1 AND ($2 IS NULL OR conv = $2)").bind(&me.0[..]).bind(conv).execute(&mut *tx).await?;
        // Chains, buckets and every row in them, through their foreign keys
        sqlx::query("DELETE FROM voipc_writers WHERE owner = $1 AND ($2 IS NULL OR conv = $2)").bind(&me.0[..]).bind(conv).execute(&mut *tx).await?;
        tx.commit().await?;
        n
    });
    Ok(AccountReply::LogPurged {
        conv: conv.map(str::to_string),
        entries,
    })
}

/// Takes `account` out of a channel's log: it leaves, is kicked, or no longer
/// knows the channel's password. Every writer's next entry needs a new key, so if it
/// held one, a seat here waits (`take_seats`).
pub async fn remove(store: &Store, conv: &str, account: &[u8; 16]) -> Result<()> {
    let held: Option<i64> = db!(store, pool => {
        sqlx::query_scalar(
            "SELECT CAST(1 AS BIGINT) FROM voipc_writers w WHERE w.conv = $1 AND w.owner <> $2 AND (
                EXISTS (SELECT 1 FROM voipc_seats s WHERE s.writer = w.id AND s.recipient = $2)
                OR EXISTS (SELECT 1 FROM voipc_chain_wraps r WHERE r.writer = w.id AND r.recipient = $2)
             ) LIMIT 1",
        )
        .bind(conv)
        .bind(&account[..])
        .fetch_optional(pool)
        .await?
    });
    if held.is_some() {
        db!(store, pool => {
            // An account may be going as it leaves: then there is nobody to wait
            sqlx::query(
                "INSERT INTO voipc_left (account, conv, left_at) SELECT id, $2, $3 FROM acct_users WHERE id = $1
                 ON CONFLICT (account, conv) DO UPDATE SET left_at = excluded.left_at",
            )
            .bind(&account[..])
            .bind(conv)
            .bind(util::now())
            .execute(pool)
            .await?;
        });
    }
    unseat(store, conv, account).await
}

/// `remove` with no wait for a seat, for someone a gate put out. The wait stops a person
/// walking out and back at will, and this was someone else's doing: they follow the channel
/// again if they win it back, and each log would count against them, across every channel.
pub async fn unseat(store: &Store, conv: &str, account: &[u8; 16]) -> Result<()> {
    db!(store, pool => {
        sqlx::query("DELETE FROM voipc_members WHERE conv = $1 AND account = $2").bind(conv).bind(&account[..]).execute(pool).await?;
    });
    db!(store, pool => {
        sqlx::query("DELETE FROM voipc_pending WHERE conv = $1 AND (owner = $2 OR recipient = $2)").bind(conv).bind(&account[..]).execute(pool).await?;
    });
    Ok(())
}

/// Keeps only `keep` of a channel's stored members (a new password: those in
/// the channel now are the ones who knew it).
pub async fn keep_only(store: &Store, conv: &str, keep: &[[u8; 16]]) -> Result<()> {
    let rows: Vec<Vec<u8>> = db!(store, pool => {
        sqlx::query_scalar("SELECT account FROM voipc_members WHERE conv = $1").bind(conv).fetch_all(pool).await?
    });
    for a in rows.into_iter().map(id16).filter(|a| !keep.contains(a)) {
        remove(store, conv, &a).await?;
    }
    Ok(())
}

pub(super) async fn members_of(relay: &Relay, me: AccountId, conv: &str) -> Result<AccountReply> {
    if !is_channel(conv) || members(relay, conv, &me.0).await?.is_none() {
        return Ok(refused("LogMembers", "not a conversation of yours"));
    }
    let rows: Vec<MemberRow> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT u.id, u.username, i.identity_key, k.logkey, k.sig FROM voipc_members m
               JOIN voipc_logkeys k ON k.account = m.account
               JOIN voipc_identity i ON i.account = m.account
               JOIN acct_users u ON u.id = m.account
              WHERE m.conv = $1 ORDER BY m.account LIMIT $2",
        )
        .bind(conv)
        .bind(MAX_MEMBERS as i64)
        .fetch_all(pool)
        .await?
    });
    let members = rows
        .into_iter()
        .map(|(a, name, identity, logkey, sig)| LogKeyInfo {
            account: id16(a),
            name,
            identity,
            logkey,
            sig,
        })
        .collect();
    Ok(AccountReply::LogMembersFound {
        conv: conv.to_string(),
        members,
    })
}

/// Entries past their time, and the keys and pending answers nothing needs
/// any more; run with the hourly sweep.
pub async fn sweep(relay: &Relay) -> Result<u64> {
    let now_ms = now_ms();
    let store = relay.store();
    relay
        .kept_room
        .retain(|_, (_, at)| util::now() - *at < ROOM_SECS);
    let n = db!(store, pool => {
        sqlx::query("DELETE FROM voipc_log WHERE keep_until < $1").bind(now_ms).execute(pool).await?.rows_affected()
    });
    // A key older than anything kept that no entry uses: nothing to open with
    // it, and a writer still holding it is told to rekey at its next entry.
    let cutoff = util::now() - relay.retention_ms / 1000;
    db!(store, pool => {
        sqlx::query(
            "DELETE FROM voipc_wraps WHERE created_at < $1 AND NOT EXISTS (
               SELECT 1 FROM voipc_log l WHERE l.conv = voipc_wraps.conv AND l.sender = voipc_wraps.owner AND l.epoch = voipc_wraps.epoch)",
        )
        .bind(cutoff)
        .execute(pool)
        .await?;
    });
    db!(store, pool => {
        sqlx::query("DELETE FROM voipc_pending WHERE created_at < $1").bind(cutoff).execute(pool).await?;
    });
    let convs: Vec<String> = db!(store, pool => {
        sqlx::query_scalar("SELECT DISTINCT conv FROM voipc_log WHERE conv LIKE 'c:%' UNION SELECT conv FROM voipc_writers").fetch_all(pool).await?
    });
    let mut swept = n;
    for conv in convs {
        swept += sweep_channel(relay, &conv, now_ms).await?;
    }
    sweep_tombstones(store).await?;
    let walks: Vec<Vec<u8>> = db!(store, pool => {
        sqlx::query_scalar("SELECT account FROM voipc_logkeys WHERE walk_after IS NOT NULL").fetch_all(pool).await?
    });
    for account in walks {
        finish_walk(store, &id16(account)).await?;
    }
    let waited = util::now() - 2 * RESEAT_WAIT_MAX_SECS;
    db!(store, pool => {
        sqlx::query("DELETE FROM voipc_left WHERE left_at < $1").bind(waited).execute(pool).await?;
        sqlx::query("DELETE FROM voipc_reseats WHERE last_at < $1").bind(waited).execute(pool).await?;
    });
    Ok(swept)
}

// ── Chains and buckets (protocol 21) ──────────────────────────────────────

/// A writer's row for a channel: having one is what puts a writer on chains.
struct Writer {
    id: i32,
    newest: Option<i32>,
}

async fn writer_of(store: &Store, conv: &str, me: &[u8; 16]) -> Result<Option<Writer>> {
    let row: Option<(i32, Option<i32>)> = db!(store, pool => {
        sqlx::query_as("SELECT id, newest_chain FROM voipc_writers WHERE conv = $1 AND owner = $2")
            .bind(conv)
            .bind(&me[..])
            .fetch_optional(pool)
            .await?
    });
    Ok(row.map(|(id, newest)| Writer { id, newest }))
}

/// `(id, top, done)` of a writer's chain.
async fn chain_row(store: &Store, writer: i32, chain: i32) -> Result<Option<(i32, i16, bool)>> {
    Ok(db!(store, pool => {
        sqlx::query_as("SELECT id, top, done FROM voipc_chains WHERE writer = $1 AND chain = $2")
            .bind(writer)
            .bind(chain)
            .fetch_optional(pool)
            .await?
    }))
}

/// Someone a chain has reached. `bucket`: by a seat there; `None`: by a row of their own.
struct Holder {
    account: [u8; 16],
    bucket: Option<u64>,
    dead: bool,
}

/// Everyone who holds a state of a chain: a row in a bucket it is sealed to, at or above
/// the version of the seal (a crash between a rotation and its chain leaves the leaver's
/// row at the seal's version, and it must still count), and rows of their own. Read in
/// two passes rather than a join: the whole writer's seats are fewer rows than a join's
/// probes on SQLite.
async fn holders(store: &Store, writer: i32, chain_id: i32) -> Result<Vec<Holder>> {
    let seals: HashMap<i64, i32> = db!(store, pool => {
        sqlx::query_as::<_, (i64, i32)>("SELECT bucket, version FROM voipc_seals WHERE chain_id = $1")
            .bind(chain_id)
            .fetch_all(pool)
            .await?
    })
    .into_iter()
    .collect();
    let seats: Vec<SeatRow> = db!(store, pool => {
        sqlx::query_as("SELECT recipient, bucket, version, dead FROM voipc_seats WHERE writer = $1")
            .bind(writer)
            .fetch_all(pool)
            .await?
    });
    let direct: Vec<(Vec<u8>, bool)> = db!(store, pool => {
        sqlx::query_as("SELECT recipient, dead FROM voipc_chain_wraps WHERE writer = $1 AND chain_id = $2")
            .bind(writer)
            .bind(chain_id)
            .fetch_all(pool)
            .await?
    });
    let mut out: Vec<Holder> = seats
        .into_iter()
        .filter(|(_, bucket, version, _)| seals.get(bucket).is_some_and(|v| version >= v))
        .map(|(account, bucket, _, dead)| Holder {
            account: id16(account),
            bucket: Some(bucket as u64),
            dead,
        })
        .collect();
    out.extend(direct.into_iter().map(|(account, dead)| Holder {
        account: id16(account),
        bucket: None,
        dead,
    }));
    Ok(out)
}

/// What a writer must do before its newest chain takes a post, if anything: a new chain
/// if anyone holding this one is gone, a step and a row to each member it has not reached.
/// `gone` are more people to name. A member's dead row is no way in for them, but whoever
/// holds the old log key keeps that bucket's key, so a new chain rotates it too.
async fn owed_on_chain(
    store: &Store,
    conv: &str,
    writer: i32,
    chain_id: Option<i32>,
    me: &[u8; 16],
    members: &[[u8; 16]],
    mut gone: Vec<([u8; 16], u64)>,
) -> Result<Option<AccountReply>> {
    let held = match chain_id {
        Some(id) => holders(store, writer, id).await?,
        None => Vec::new(),
    };
    let listed: HashSet<&[u8; 16]> = members.iter().collect();
    let left = held
        .iter()
        .any(|h| h.account != *me && !listed.contains(&h.account));
    let alive = |seats_only: bool| -> HashSet<[u8; 16]> {
        held.iter()
            .filter(|h| !h.dead && (!seats_only || h.bucket.is_some()))
            .map(|h| h.account)
            .collect()
    };
    let without = |have: HashSet<[u8; 16]>, most: usize| -> Vec<[u8; 16]> {
        members
            .iter()
            .filter(|m| **m != *me && !have.contains(*m))
            .take(most)
            .copied()
            .collect()
    };
    if left || !gone.is_empty() || chain_id.is_none() {
        gone.extend(held.iter().filter_map(|h| {
            let out = h.account != *me && (h.dead || !listed.contains(&h.account));
            out.then(|| (h.account, h.bucket.unwrap_or(0)))
        }));
        gone.sort_unstable();
        gone.dedup();
        gone.truncate(MAX_GONE);
        return Ok(Some(AccountReply::ChainRekey {
            conv: conv.to_string(),
            new_chain: true,
            missing: without(alive(true), MAX_ARRIVALS),
            gone,
        }));
    }
    let missing = without(alive(false), MAX_MISSING);
    Ok((!missing.is_empty()).then(|| AccountReply::ChainRekey {
        conv: conv.to_string(),
        new_chain: false,
        missing,
        gone: Vec::new(),
    }))
}

/// Whether a post may go on `epoch` (`append`), and if not, what to do. It goes only on a
/// writer's newest chain, at its top, reaching exactly the members there are now.
async fn chain_gate(
    store: &Store,
    w: &Writer,
    conv: &str,
    me: &[u8; 16],
    epoch: u32,
    members: &[[u8; 16]],
) -> Result<Option<AccountReply>> {
    let (chain, index) = epoch_parts(epoch);
    let newest = match w.newest {
        Some(n) => chain_row(store, w.id, n).await?.map(|r| (n, r)),
        None => None,
    };
    let Some((n, (id, top, _))) = newest else {
        return owed_on_chain(store, conv, w.id, None, me, members, Vec::new()).await;
    };
    if chain as i32 != n || index as i16 != top {
        return Ok(Some(AccountReply::ChainRekey {
            conv: conv.to_string(),
            new_chain: false,
            missing: Vec::new(),
            gone: Vec::new(),
        }));
    }
    owed_on_chain(store, conv, w.id, Some(id), me, members, Vec::new()).await
}

/// A `ChainPut`'s content.
pub(super) struct ChainFrame {
    pub epoch: u32,
    pub self_wrap: Option<Vec<u8>>,
    pub step: Option<Vec<u8>>,
    pub link: Option<(u32, Vec<u8>)>,
    pub wraps: Vec<ChainRow>,
    pub buckets: Vec<BucketIn>,
    pub seals: Vec<ChainSeal>,
    pub last: bool,
}

/// Rows of the sizes `voipc_crypto::log` makes, and no other: the relay opens none of
/// them, but a row it cannot bound is a row a modified app sizes for it.
fn well_formed(put: &ChainFrame, me: &[u8; 16]) -> bool {
    let row = |r: &[u8]| r.len() == ROW_BYTES;
    put.self_wrap.as_deref().is_none_or(row)
        && put.step.as_deref().is_none_or(row)
        && put.link.as_ref().is_none_or(|(_, l)| row(l))
        && put
            .wraps
            .iter()
            .all(|w| row(&w.wrapped) && w.recipient != *me)
        && put.seals.iter().all(|s| row(&s.sealed))
        && put.buckets.iter().all(|b| {
            let mut seen = HashSet::new();
            (28..=MAX_LIST_BYTES).contains(&b.list.len())
                && b.seats.len() <= MAX_BUCKET_SEATS
                && b.seats.iter().filter(|s| s.recipient == *me).count() == 1
                && b.seats.iter().all(|s| seen.insert(s.recipient))
                && b.seats.iter().all(|s| {
                    s.wrapped.len()
                        == if s.recipient == *me {
                            OWN_ROW_BYTES
                        } else {
                            ROW_BYTES
                        }
                })
                && b.down.as_ref().is_none_or(|(_, l)| row(l))
                && i32::try_from(b.version).is_ok()
        })
        && put
            .seals
            .iter()
            .all(|s| i32::try_from(s.version).is_ok() && s.index <= MAX_CHAIN_STEPS)
        && put.wraps.iter().all(|w| w.index <= MAX_CHAIN_STEPS)
}

/// Whether this account's session shares history now, and whether it may.
pub(super) struct Sharing {
    pub shares: bool,
    pub may: bool,
}

/// Files a frame of one of `me`'s chains, whole or not at all; also says who to tell: those
/// whose wait for an answer this ends, so a rotation tells nobody. What it holds a writer to:
///
/// - A chain's number only goes up, and it is not the newest until its last frame, so a
///   mass leave that takes several frames, or a crash in one, leaves the old chain in charge.
/// - A step goes only at `top + 1` of the newest chain, and to someone it has not reached.
/// - A bucket never grows: a version comes whole in one frame, and a new one has strictly
///   fewer people than the last. A seal goes only to a bucket's newest version.
/// - A row or a seal reaches only members, and a seal never someone gone or on an old key.
/// - A link, or a state below the top of a finished chain to someone holding nothing lower,
///   takes the right to share history: an honest app would not, this binds a modified one.
///
/// Who is in a bucket, and who was named, stay the writer's word: the relay cannot read it.
pub(super) async fn chain_put(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    mut put: ChainFrame,
    sharing: Sharing,
) -> Result<(AccountReply, Vec<[u8; 16]>)> {
    let store = relay.store();
    let epoch = put.epoch;
    let (chain, index) = epoch_parts(epoch);
    let refuse = |why: &str| Ok((refused("ChainPut", why), Vec::new()));
    let behind = || {
        Ok((
            AccountReply::ChainStored {
                conv: conv.to_string(),
                epoch,
                behind: true,
            },
            Vec::new(),
        ))
    };
    if !relay.cloud {
        return refuse("This server keeps no messages.");
    }
    if !is_channel(conv) {
        return refuse("not a channel's log");
    }
    let Some(members) = members(relay, conv, &me.0).await? else {
        return refuse("not a conversation of yours");
    };
    if !well_formed(&put, &me.0) {
        return refuse("malformed");
    }
    if index > MAX_CHAIN_STEPS {
        return behind();
    }
    let chain_no = chain as i32;
    let writer = writer_of(store, conv, &me.0).await?;
    let row = match &writer {
        Some(w) => chain_row(store, w.id, chain_no).await?,
        None => None,
    };
    let (top, done) = row.map_or((0, false), |(_, t, d)| (t as u32, d));
    let newest = writer.as_ref().and_then(|w| w.newest);

    let now = util::now();
    let hour = now / 3600;
    if row.is_some() {
        if put.self_wrap.is_some() || put.link.is_some() {
            return behind();
        }
        if done && (!put.buckets.is_empty() || !put.seals.is_empty()) {
            return behind();
        }
    } else {
        if put.self_wrap.is_none() {
            return behind();
        }
        if let Some(w) = &writer {
            let highest: Option<i32> = db!(store, pool => {
                sqlx::query_scalar("SELECT MAX(chain) FROM voipc_chains WHERE writer = $1")
                    .bind(w.id)
                    .fetch_one(pool)
                    .await?
            });
            if highest.max(newest).is_some_and(|h| chain_no <= h) {
                return behind();
            }
            let (at, n): (i64, i32) = db!(store, pool => {
                sqlx::query_as("SELECT hour, new_this_hour FROM voipc_writers WHERE id = $1")
                    .bind(w.id)
                    .fetch_one(pool)
                    .await?
            });
            if at == hour && i64::from(n) >= NEW_EPOCHS_PER_HOUR {
                return refuse("Too many new keys for this conversation; try again later.");
            }
        }
        if put.link.is_some() && !sharing.may {
            return refuse("Sharing history takes a privilege you do not hold.");
        }
        if let Some((older, _)) = &put.link {
            let known = match &writer {
                Some(w) if *older < chain => chain_row(store, w.id, *older as i32).await?,
                _ => None,
            };
            if known.is_none() {
                return behind();
            }
        }
    }
    if put.step.is_some() {
        let on_the_newest = !done || newest == Some(chain_no);
        if index != top + 1 || !on_the_newest || (!done && index > 1) {
            return behind();
        }
    } else if index != top {
        return behind();
    }
    let listed: HashSet<&[u8; 16]> = members.iter().collect();
    // A frame of rows alone is an answer to joiners, made a moment ago: someone who left
    // since is out of it, and the rest are still owed it
    if row.is_some() && put.step.is_none() && put.buckets.is_empty() && put.seals.is_empty() {
        put.wraps.retain(|w| listed.contains(&w.recipient));
    }
    if put
        .wraps
        .iter()
        .any(|w| w.index > index || !listed.contains(&w.recipient))
    {
        return behind();
    }
    // On a finished chain: whoever a state reaches already holds it, or is new at the top.
    if let (Some((id, _, true)), Some(w)) = (row, &writer) {
        if put.step.is_some() {
            let alive: HashSet<[u8; 16]> = holders(store, w.id, id)
                .await?
                .into_iter()
                .filter(|h| !h.dead)
                .map(|h| h.account)
                .collect();
            if put.wraps.iter().all(|r| alive.contains(&r.recipient)) {
                return refuse("A step needs someone new to give it to.");
            }
        }
        if !sharing.may {
            for r in &put.wraps {
                if r.index > top {
                    continue;
                }
                let lowest = lowest_on_chain(store, w.id, id, &r.recipient).await?;
                if lowest.is_none_or(|l| i64::from(l) > i64::from(r.index)) {
                    return refuse("Sharing history takes a privilege you do not hold.");
                }
            }
        }
    }

    // What is there of the buckets, to hold this frame's against
    let (mut newest_version, seats_now): (HashMap<i64, i32>, Vec<SeatRow>) = match &writer {
        Some(w) if !put.buckets.is_empty() || !put.seals.is_empty() => {
            let versions: Vec<(i64, i32)> = db!(store, pool => {
                sqlx::query_as("SELECT bucket, MAX(version) FROM voipc_bucket_lists WHERE writer = $1 GROUP BY bucket")
                    .bind(w.id)
                    .fetch_all(pool)
                    .await?
            });
            let seats = db!(store, pool => {
                sqlx::query_as("SELECT recipient, bucket, version, dead FROM voipc_seats WHERE writer = $1")
                    .bind(w.id)
                    .fetch_all(pool)
                    .await?
            });
            (versions.into_iter().collect(), seats)
        }
        _ => (HashMap::new(), Vec::new()),
    };
    let mut new_buckets = 0;
    for b in &put.buckets {
        if b.seats
            .iter()
            .any(|s| s.recipient != me.0 && !listed.contains(&s.recipient))
        {
            return behind();
        }
        let (id, version) = (b.bucket as i64, b.version as i32);
        match newest_version.get(&id).copied() {
            None => {
                if b.down.is_some() {
                    return refuse("malformed");
                }
                new_buckets += 1;
            }
            Some(last) if version <= last => return behind(),
            Some(last) => {
                if !b
                    .down
                    .as_ref()
                    .is_some_and(|(old, _)| *old as i64 == i64::from(last))
                {
                    return refuse("A bucket's new version needs its way down.");
                }
                let was: HashSet<&[u8]> = seats_now
                    .iter()
                    .filter(|s| s.1 == id && s.2 == last && s.0.as_slice() != me.0)
                    .map(|s| s.0.as_slice())
                    .collect();
                let now_in: HashSet<&[u8]> = b
                    .seats
                    .iter()
                    .filter(|s| s.recipient != me.0)
                    .map(|s| &s.recipient[..])
                    .collect();
                if !now_in.is_subset(&was) || now_in.len() >= was.len() {
                    return refuse("A bucket's new version only ever loses people.");
                }
            }
        }
        newest_version.insert(id, version);
    }
    if new_buckets > MAX_NEW_BUCKETS {
        // Unless none is live: a first post is all buckets
        let live = match newest {
            Some(n) => {
                let w = writer.as_ref().map_or(0, |w| w.id);
                match chain_row(store, w, n).await? {
                    Some((id, ..)) => {
                        db!(store, pool => {
                            sqlx::query_scalar::<_, i64>("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_seals WHERE chain_id = $1")
                                .bind(id)
                                .fetch_one(pool)
                                .await?
                        }) > 0
                    }
                    None => false,
                }
            }
            None => false,
        };
        if live {
            return refuse("Too many new buckets at once.");
        }
    }
    let mut gone = Vec::new();
    for s in &put.seals {
        if s.index > index || newest_version.get(&(s.bucket as i64)) != Some(&(s.version as i32)) {
            return behind();
        }
        gone.extend(
            seats_now
                .iter()
                .filter(|r| r.1 == s.bucket as i64 && r.2 == s.version as i32)
                .filter(|r| {
                    let who = id16(r.0.clone());
                    who != me.0 && (r.3 || !listed.contains(&who))
                })
                .map(|r| (id16(r.0.clone()), s.bucket)),
        );
    }
    if !gone.is_empty() {
        let w = writer.as_ref().map_or(0, |w| w.id);
        let id = match newest {
            Some(n) => chain_row(store, w, n).await?.map(|r| r.0),
            None => None,
        };
        let answer = owed_on_chain(store, conv, w, id, &me.0, &members, gone).await?;
        return Ok((
            answer.unwrap_or_else(|| refused("ChainPut", "gone")),
            Vec::new(),
        ));
    }

    let len = |o: &Option<Vec<u8>>| o.as_ref().map_or(0, |v| v.len()) as i64;
    let seat_bytes: i64 = put
        .buckets
        .iter()
        .flat_map(|b| &b.seats)
        .map(|s| s.wrapped.len() as i64)
        .sum();
    let other_bytes: i64 = len(&put.self_wrap)
        + len(&put.step)
        + put.link.as_ref().map_or(0, |(_, l)| l.len() as i64)
        + put
            .wraps
            .iter()
            .map(|w| w.wrapped.len() as i64)
            .sum::<i64>()
        + put.seals.iter().map(|s| s.sealed.len() as i64).sum::<i64>()
        + put
            .buckets
            .iter()
            .map(|b| (b.list.len() + b.down.as_ref().map_or(0, |(_, l)| l.len())) as i64)
            .sum::<i64>();
    forget_room(relay, &me);
    if used_bytes(relay, &me).await? + seat_bytes + other_bytes > relay.quota {
        return refuse("Your stored messages are over this server's limit.");
    }
    let finishes = put.last && !done;
    if finishes && newest.is_some_and(|n| chain_no <= n) {
        return behind();
    }
    let mut told = Vec::new();
    let writer_id: i32 = db!(store, pool => {
        let mut tx = pool.begin().await?;
        let writer_id: i32 = sqlx::query_scalar(
            "INSERT INTO voipc_writers (conv, owner, shares) VALUES ($1, $2, $3)
             ON CONFLICT (conv, owner) DO UPDATE SET shares = excluded.shares RETURNING id",
        )
        .bind(conv)
        .bind(&me.0[..])
        .bind(sharing.shares)
        .fetch_one(&mut *tx)
        .await?;
        let chain_id: i32 = match row {
            Some((id, ..)) => id,
            None => {
                sqlx::query(
                    "UPDATE voipc_writers SET new_this_hour = CASE WHEN hour = $1 THEN new_this_hour + 1 ELSE 1 END, hour = $1 WHERE id = $2",
                )
                .bind(hour)
                .bind(writer_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query_scalar(
                    "INSERT INTO voipc_chains (writer, chain, top, self_wrap, older, link, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                )
                .bind(writer_id)
                .bind(chain_no)
                .bind(0i16)
                .bind(put.self_wrap.as_deref())
                .bind(put.link.as_ref().map(|(o, _)| *o as i32))
                .bind(put.link.as_ref().map(|(_, l)| l.as_slice()))
                .bind(now)
                .fetch_one(&mut *tx)
                .await?
            }
        };
        if let Some(step) = &put.step {
            sqlx::query("INSERT INTO voipc_chain_steps (chain_id, idx, sealed) VALUES ($1, $2, $3)")
                .bind(chain_id)
                .bind((index - 1) as i16)
                .bind(step.as_slice())
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE voipc_chains SET top = $1 WHERE id = $2")
                .bind(index as i16)
                .bind(chain_id)
                .execute(&mut *tx)
                .await?;
        }
        for w in &put.wraps {
            // The lowest index they ever held, and over a row their old key held
            sqlx::query(
                "INSERT INTO voipc_chain_wraps (writer, recipient, chain_id, idx, wrapped) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (writer, recipient, chain_id) DO UPDATE SET idx = excluded.idx, wrapped = excluded.wrapped, dead = FALSE
                 WHERE excluded.idx < voipc_chain_wraps.idx OR voipc_chain_wraps.dead",
            )
            .bind(writer_id)
            .bind(&w.recipient[..])
            .bind(chain_id)
            .bind(w.index as i16)
            .bind(w.wrapped.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        for b in &put.buckets {
            for s in &b.seats {
                sqlx::query("INSERT INTO voipc_seats (writer, recipient, bucket, version, wrapped) VALUES ($1, $2, $3, $4, $5)")
                    .bind(writer_id)
                    .bind(&s.recipient[..])
                    .bind(b.bucket as i64)
                    .bind(b.version as i32)
                    .bind(s.wrapped.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("INSERT INTO voipc_bucket_lists (writer, bucket, version, sealed, chain_id, created_at) VALUES ($1, $2, $3, $4, $5, $6)")
                .bind(writer_id)
                .bind(b.bucket as i64)
                .bind(b.version as i32)
                .bind(b.list.as_slice())
                .bind(chain_id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            if let Some((old, link)) = &b.down {
                sqlx::query("INSERT INTO voipc_bucket_links (writer, bucket, version, old, link) VALUES ($1, $2, $3, $4, $5)")
                    .bind(writer_id)
                    .bind(b.bucket as i64)
                    .bind(b.version as i32)
                    .bind(*old as i32)
                    .bind(link.as_slice())
                    .execute(&mut *tx)
                    .await?;
            }
        }
        for s in &put.seals {
            sqlx::query(
                "INSERT INTO voipc_seals (chain_id, bucket, version, idx, sealed) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind(chain_id)
            .bind(s.bucket as i64)
            .bind(s.version as i32)
            .bind(s.index as i16)
            .bind(s.sealed.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        // The last frame of an answer ends the wait of whom it names, and not a frame before:
        // the rest could be lost, and a reader told now reads past chains with no row yet. A
        // writer who does not share owes nobody more than the next post's row.
        if put.last && !sharing.shares {
            let answered: Vec<Vec<u8>> = sqlx::query_scalar("DELETE FROM voipc_pending WHERE conv = $1 AND owner = $2 RETURNING recipient")
                .bind(conv)
                .bind(&me.0[..])
                .fetch_all(&mut *tx)
                .await?;
            told.extend(answered.into_iter().map(id16));
        } else if put.last {
            for w in &put.wraps {
                let answered = sqlx::query("DELETE FROM voipc_pending WHERE conv = $1 AND owner = $2 AND recipient = $3")
                    .bind(conv)
                    .bind(&me.0[..])
                    .bind(&w.recipient[..])
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                if answered > 0 {
                    told.push(w.recipient);
                }
            }
        }
        sqlx::query("UPDATE voipc_writers SET key_bytes = key_bytes + $1, open_bytes = open_bytes + $2 WHERE id = $3")
            .bind(seat_bytes / 2 + other_bytes)
            .bind(seat_bytes - seat_bytes / 2)
            .bind(writer_id)
            .execute(&mut *tx)
            .await?;
        if finishes {
            sqlx::query("UPDATE voipc_chains SET done = TRUE WHERE id = $1")
                .bind(chain_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE voipc_writers SET newest_chain = $1, open_bytes = 0, last_post_hour = $2 WHERE id = $3")
                .bind(chain_no)
                .bind(hour)
                .bind(writer_id)
                .execute(&mut *tx)
                .await?;
            // Who stayed through a rotation reads the old version by its link: their
            // old row can go, and only a leaver's stays. Not before now, or a chain
            // that is never finished would take their way in with it.
            let made: HashMap<i64, i32> = sqlx::query_as::<_, (i64, i32)>("SELECT bucket, version FROM voipc_bucket_lists WHERE writer = $1 AND chain_id = $2")
                .bind(writer_id)
                .bind(chain_id)
                .fetch_all(&mut *tx)
                .await?
                .into_iter()
                .collect();
            if !made.is_empty() {
                let seats: Vec<(Vec<u8>, i64, i32)> = sqlx::query_as("SELECT recipient, bucket, version FROM voipc_seats WHERE writer = $1")
                    .bind(writer_id)
                    .fetch_all(&mut *tx)
                    .await?;
                let stayed: HashSet<(&[u8], i64)> = seats
                    .iter()
                    .filter(|s| made.get(&s.1) == Some(&s.2))
                    .map(|s| (s.0.as_slice(), s.1))
                    .collect();
                let replaced: Vec<&(Vec<u8>, i64, i32)> = seats
                    .iter()
                    .filter(|s| {
                        made.get(&s.1).is_some_and(|v| s.2 < *v)
                            && stayed.contains(&(s.0.as_slice(), s.1))
                    })
                    .collect();
                for s in replaced {
                    sqlx::query("DELETE FROM voipc_seats WHERE writer = $1 AND recipient = $2 AND bucket = $3 AND version = $4")
                        .bind(writer_id)
                        .bind(s.0.as_slice())
                        .bind(s.1)
                        .bind(s.2)
                        .execute(&mut *tx)
                        .await?;
                }
                for (b, v) in &made {
                    sqlx::query("DELETE FROM voipc_bucket_lists WHERE writer = $1 AND bucket = $2 AND version < $3")
                        .bind(writer_id)
                        .bind(*b)
                        .bind(*v)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }
        tx.commit().await?;
        writer_id
    });
    if finishes {
        recount(store, writer_id).await?;
    }
    Ok((
        AccountReply::ChainStored {
            conv: conv.to_string(),
            epoch,
            behind: false,
        },
        told,
    ))
}

/// A writer's rows, counted again: the running count only goes up between sweeps, and
/// this is what brings it back. Seat rows at half: a first post in 300 channels at 5000
/// seats is then 45 MB of a 50 MB quota, where whole it would stop at 166 channels, and
/// free it would be 354 MB on Postgres from one account with nothing to stop it.
async fn recount(store: &Store, writer: i32) -> Result<()> {
    db!(store, pool => {
        sqlx::query(
            "UPDATE voipc_writers SET key_bytes =
                COALESCE((SELECT CAST(SUM(LENGTH(wrapped)) AS BIGINT) FROM voipc_seats WHERE writer = $1), 0) / 2
              + COALESCE((SELECT CAST(SUM(LENGTH(wrapped)) AS BIGINT) FROM voipc_chain_wraps WHERE writer = $1), 0)
              + COALESCE((SELECT CAST(SUM(LENGTH(sealed)) AS BIGINT) FROM voipc_bucket_lists WHERE writer = $1), 0)
              + COALESCE((SELECT CAST(SUM(LENGTH(link)) AS BIGINT) FROM voipc_bucket_links WHERE writer = $1), 0)
              + COALESCE((SELECT CAST(SUM(LENGTH(self_wrap) + COALESCE(LENGTH(link), 0)) AS BIGINT) FROM voipc_chains WHERE writer = $1), 0)
              + COALESCE((SELECT CAST(SUM(LENGTH(s.sealed)) AS BIGINT) FROM voipc_seals s JOIN voipc_chains c ON c.id = s.chain_id WHERE c.writer = $1), 0)
              + COALESCE((SELECT CAST(SUM(LENGTH(s.sealed)) AS BIGINT) FROM voipc_chain_steps s JOIN voipc_chains c ON c.id = s.chain_id WHERE c.writer = $1), 0)
              WHERE id = $1",
        )
        .bind(writer)
        .execute(pool)
        .await?;
    });
    Ok(())
}

/// The lowest index `who` can start from on a chain, by a row of their own or a seat.
async fn lowest_on_chain(
    store: &Store,
    writer: i32,
    chain_id: i32,
    who: &[u8; 16],
) -> Result<Option<i16>> {
    let direct: Option<i16> = db!(store, pool => {
        sqlx::query_scalar("SELECT idx FROM voipc_chain_wraps WHERE writer = $1 AND recipient = $2 AND chain_id = $3 AND dead = FALSE")
            .bind(writer)
            .bind(&who[..])
            .bind(chain_id)
            .fetch_optional(pool)
            .await?
    });
    let sealed: Option<i16> = db!(store, pool => {
        sqlx::query_scalar(
            "SELECT MIN(s.idx) FROM voipc_seats t JOIN voipc_seals s ON s.chain_id = $3 AND s.bucket = t.bucket AND s.version <= t.version
              WHERE t.writer = $1 AND t.recipient = $2 AND t.dead = FALSE",
        )
        .bind(writer)
        .bind(&who[..])
        .bind(chain_id)
        .fetch_one(pool)
        .await?
    });
    Ok(match (direct, sealed) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    })
}

/// A writer's chains as far as reaching them goes: `(id, older)` by the wire's number.
async fn chain_map(store: &Store, writer: i32) -> Result<HashMap<i32, (i32, Option<i32>)>> {
    let rows: Vec<(i32, i32, Option<i32>)> = db!(store, pool => {
        sqlx::query_as("SELECT chain, id, older FROM voipc_chains WHERE writer = $1")
            .bind(writer)
            .fetch_all(pool)
            .await?
    });
    Ok(rows.into_iter().map(|(c, id, o)| (c, (id, o))).collect())
}

/// The chains of a writer `who` holds the start of, which is what a run of links opens down
/// from: a writer who shares, and someone who was given that. Empty if the writer never
/// wrote a link.
async fn starts_held(
    store: &Store,
    writer: i32,
    who: &[u8; 16],
    chains: &HashMap<i32, (i32, Option<i32>)>,
) -> Result<HashSet<i32>> {
    if chains.values().all(|(_, older)| older.is_none()) {
        return Ok(HashSet::new());
    }
    let direct: Vec<i32> = db!(store, pool => {
        sqlx::query_scalar("SELECT chain_id FROM voipc_chain_wraps WHERE writer = $1 AND recipient = $2 AND idx = 0 AND dead = FALSE")
            .bind(writer)
            .bind(&who[..])
            .fetch_all(pool)
            .await?
    });
    let sealed: Vec<i32> = db!(store, pool => {
        sqlx::query_scalar(
            "SELECT DISTINCT s.chain_id FROM voipc_seats t
               JOIN voipc_chains c ON c.writer = t.writer
               JOIN voipc_seals s ON s.chain_id = c.id AND s.bucket = t.bucket AND s.version <= t.version AND s.idx = 0
              WHERE t.writer = $1 AND t.recipient = $2 AND t.dead = FALSE",
        )
        .bind(writer)
        .bind(&who[..])
        .fetch_all(pool)
        .await?
    });
    Ok(direct.into_iter().chain(sealed).collect())
}

/// Chains a run of links opens from the starts `held`: only someone given the start of a
/// chain, never someone given a later state of it, which is what keeps a joiner under
/// share-off out of what came before them, even once that writer turns sharing on.
fn run_below(chains: &HashMap<i32, (i32, Option<i32>)>, held: &HashSet<i32>) -> HashSet<i32> {
    let mut out = HashSet::new();
    for (chain, (id, _)) in chains {
        if !held.contains(id) {
            continue;
        }
        let mut at = chains.get(chain).and_then(|(_, older)| *older);
        while let Some(c) = at {
            if !out.insert(c) {
                break;
            }
            at = chains.get(&c).and_then(|(_, older)| *older);
        }
    }
    out
}

/// The chains from just above `from` up to the nearest one whose start is `held`, or none.
/// Two can link down to one chain: a chain never finished, and the one its writer made instead,
/// which is why this goes up every way there is and not only the lowest.
fn run_up(chains: &HashMap<i32, (i32, Option<i32>)>, held: &HashSet<i32>, from: i32) -> Vec<i32> {
    let mut above: HashMap<i32, Vec<i32>> = HashMap::new();
    for (chain, (_, older)) in chains {
        if let Some(older) = older {
            above.entry(*older).or_default().push(*chain);
        }
    }
    let mut came_from: HashMap<i32, i32> = HashMap::new();
    let mut level = vec![from];
    while !level.is_empty() {
        let mut next = Vec::new();
        for at in level {
            let mut ups = above.remove(&at).unwrap_or_default();
            ups.sort_unstable();
            for up in ups {
                if came_from.contains_key(&up) {
                    continue;
                }
                came_from.insert(up, at);
                if chains.get(&up).is_some_and(|(id, _)| held.contains(id)) {
                    let mut path = vec![up];
                    let mut c = up;
                    while let Some(below) = came_from.get(&c).filter(|b| **b != from) {
                        path.push(*below);
                        c = *below;
                    }
                    path.reverse();
                    return path;
                }
                next.push(up);
            }
        }
        level = next;
    }
    Vec::new()
}

/// What a reader can open of one writer's entries, found as a page of them is read.
struct Reach {
    writer: Option<i32>,
    lowest: HashMap<i32, Option<i16>>,
    run: Option<HashSet<i32>>,
    /// Keys of a version before chains that this reader holds from this writer, the
    /// epochs: read once a writer, and almost always none.
    old: Option<HashSet<i64>>,
}

impl Reach {
    async fn of(store: &Store, conv: &str, owner: &[u8; 16]) -> Result<Reach> {
        let writer = writer_of(store, conv, owner).await?.map(|w| w.id);
        Ok(Reach {
            writer,
            lowest: HashMap::new(),
            run: None,
            old: None,
        })
    }

    /// Whether this reader may be able to open it: by a chain, or by a key of a version
    /// before chains, which every later version still opens.
    async fn opens(
        &mut self,
        store: &Store,
        conv: &str,
        owner: &[u8; 16],
        me: &[u8; 16],
        epoch: u32,
    ) -> Result<bool> {
        if self.on_chain(store, me, epoch).await? {
            return Ok(true);
        }
        if self.old.is_none() {
            let rows: Vec<i64> = db!(store, pool => {
                sqlx::query_scalar("SELECT epoch FROM voipc_wraps WHERE conv = $1 AND owner = $2 AND recipient = $3")
                    .bind(conv)
                    .bind(&owner[..])
                    .bind(&me[..])
                    .fetch_all(pool)
                    .await?
            });
            self.old = Some(rows.into_iter().collect());
        }
        Ok(self
            .old
            .as_ref()
            .is_some_and(|o| o.contains(&i64::from(epoch))))
    }

    async fn on_chain(&mut self, store: &Store, me: &[u8; 16], epoch: u32) -> Result<bool> {
        let (Some(writer), (chain, index)) = (self.writer, epoch_parts(epoch)) else {
            return Ok(false);
        };
        let chain = chain as i32;
        if let std::collections::hash_map::Entry::Vacant(e) = self.lowest.entry(chain) {
            e.insert(match chain_row(store, writer, chain).await? {
                Some((id, ..)) => lowest_on_chain(store, writer, id, me).await?,
                None => None,
            });
        }
        if self.lowest[&chain].is_some_and(|low| i64::from(low) <= i64::from(index)) {
            return Ok(true);
        }
        // Whole-writer reads, so only for what its own rows do not open
        if self.run.is_none() {
            let chains = chain_map(store, writer).await?;
            let held = starts_held(store, writer, me, &chains).await?;
            self.run = Some(run_below(&chains, &held));
        }
        Ok(self.run.as_ref().is_some_and(|r| r.contains(&chain)))
    }
}

/// `fetch` for a channel on chains: a page holds only what this reader can open, or may yet
/// be given a key to, so a newcomer in 300 logs downloads no ciphertext it will never read.
/// At most about a page's worth of rows are looked at per call, however many are left out.
pub(super) async fn chain_fetch(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    after: i64,
) -> Result<AccountReply> {
    let store = relay.store();
    if !is_channel(conv) {
        return Ok(refused("ChainFetch", "not a channel's log"));
    }
    if !is_member(relay, conv, &me.0).await? {
        return Ok(refused("ChainFetch", "not a conversation of yours"));
    }
    let now_ms = now_ms();
    let (start, floor) = read_start(relay, conv, after, now_ms).await?;
    let owed: Vec<[u8; 16]> = db!(store, pool => {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT owner FROM voipc_pending WHERE conv = $1 AND recipient = $2")
            .bind(conv)
            .bind(&me.0[..])
            .fetch_all(pool)
            .await?
    })
    .into_iter()
    .map(id16)
    .collect();
    let mut reach: HashMap<[u8; 16], Reach> = HashMap::new();
    let (mut entries, mut bytes, mut skipped) = (Vec::new(), 0, 0u32);
    let mut upto = start.max(0);
    let mut looked = 0;
    let mut more = false;
    'pages: while entries.is_empty() && looked < 2 * PAGE_ROWS {
        let rows: Vec<EntryRow> = db!(store, pool => {
            sqlx::query_as(
                "SELECT seq, sender, epoch, server_at, ct FROM voipc_log WHERE conv = $1 AND seq > $2 AND keep_until > $3
                  ORDER BY seq LIMIT $4",
            )
            .bind(conv)
            .bind(upto)
            .bind(now_ms)
            .bind(PAGE_ROWS + 1)
            .fetch_all(pool)
            .await?
        });
        more = rows.len() as i64 > PAGE_ROWS;
        for (seq, sender, epoch, server_at, ct) in rows.into_iter().take(PAGE_ROWS as usize) {
            looked += 1;
            let sender = id16(sender);
            let open = sender == me.0 || owed.contains(&sender) || {
                let r = match reach.entry(sender) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(Reach::of(store, conv, &sender).await?)
                    }
                };
                r.opens(store, conv, &sender, &me.0, epoch as u32).await?
            };
            if !open {
                skipped += 1;
                upto = seq;
                continue;
            }
            bytes += ct.len() + 64;
            if bytes > PAGE_BYTES && !entries.is_empty() {
                more = true;
                break 'pages;
            }
            upto = seq;
            entries.push(LogEntry {
                seq,
                sender,
                epoch: epoch as u32,
                server_at: server_at as u64,
                ct,
            });
        }
        if !more {
            break;
        }
    }
    Ok(AccountReply::ChainPage {
        conv: conv.to_string(),
        entries,
        more,
        owed: owed.clone(),
        skipped,
        upto,
        floor,
        window: relay.kept_window.clamp(0, i64::from(u32::MAX)) as u32,
    })
}

/// The keys of the chains a reader asks for. A seal or a row serves only someone it was
/// made for; at most one of each per chain, the lowest index, so however many buckets of
/// theirs a writer seals a chain to, a reader pays for the chains of what it reads. A
/// chain it holds nothing on it reaches, if at all, down a run of links from a chain it
/// holds the start of: those chains come first in the answer, from the top.
pub(super) async fn wraps_page(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    asks: &[ChainAsk],
) -> Result<AccountReply> {
    let store = relay.store();
    if !is_channel(conv) {
        return Ok(refused("WrapsPage", "not a channel's log"));
    }
    if !is_member(relay, conv, &me.0).await? {
        return Ok(refused("WrapsPage", "not a conversation of yours"));
    }
    if asks.len() > MAX_CHAIN_ASKS {
        return Ok(refused("WrapsPage", "too many chains at once"));
    }
    let mut keys: Vec<ChainKeys> = Vec::new();
    let mut bytes = 0;
    let mut served = 0;
    for ask in asks {
        let mut these = chain_keys(store, conv, &me.0, ask).await?;
        let size: usize = these.iter().map(keys_size).sum();
        if bytes + size > KEYS_PAGE_BYTES && served > 0 {
            break;
        }
        bytes += size;
        served += 1;
        keys.append(&mut these);
    }
    Ok(AccountReply::WrapsPage {
        conv: conv.to_string(),
        keys,
        served,
    })
}

fn keys_size(k: &ChainKeys) -> usize {
    let opt = |o: &Option<(u32, Vec<u8>)>| o.as_ref().map_or(0, |(_, v)| v.len() + 8);
    48 + k.self_wrap.as_ref().map_or(0, Vec::len)
        + opt(&k.direct)
        + k.seal.as_ref().map_or(0, |s| s.sealed.len() + 24)
        + opt(&k.seat)
        + opt(&k.link)
        + k.down.iter().map(|(_, _, l)| l.len() + 12).sum::<usize>()
        + k.steps.iter().map(|(_, s)| s.len() + 8).sum::<usize>()
}

/// A chain's link and steps from `from` up.
async fn chain_tail(store: &Store, chain_id: i32, from: i16) -> Result<ChainTail> {
    let link: Option<(Option<i32>, Option<Vec<u8>>)> = db!(store, pool => {
        sqlx::query_as("SELECT older, link FROM voipc_chains WHERE id = $1")
            .bind(chain_id)
            .fetch_optional(pool)
            .await?
    });
    let steps: Vec<(i16, Vec<u8>)> = db!(store, pool => {
        sqlx::query_as("SELECT idx, sealed FROM voipc_chain_steps WHERE chain_id = $1 AND idx >= $2 ORDER BY idx")
            .bind(chain_id)
            .bind(from)
            .fetch_all(pool)
            .await?
    });
    Ok(ChainTail {
        link: link.and_then(|(o, l)| Some((o? as u32, l?))),
        steps: steps.into_iter().map(|(i, s)| (i as u32, s)).collect(),
    })
}

struct ChainTail {
    link: Option<(u32, Vec<u8>)>,
    steps: Vec<(u32, Vec<u8>)>,
}

/// The state of one chain this reader can start from: its own row, and the best seal with
/// the seat and version links that reach it.
async fn chain_state(
    store: &Store,
    owner: &[u8; 16],
    chain: u32,
    writer: i32,
    chain_id: i32,
    me: &[u8; 16],
) -> Result<ChainKeys> {
    let direct: Option<(i16, Vec<u8>)> = db!(store, pool => {
        sqlx::query_as("SELECT idx, wrapped FROM voipc_chain_wraps WHERE writer = $1 AND recipient = $2 AND chain_id = $3 AND dead = FALSE")
            .bind(writer)
            .bind(&me[..])
            .bind(chain_id)
            .fetch_optional(pool)
            .await?
    });
    let seats: Vec<(i64, i32, Vec<u8>)> = db!(store, pool => {
        sqlx::query_as("SELECT bucket, version, wrapped FROM voipc_seats WHERE writer = $1 AND recipient = $2 AND dead = FALSE")
            .bind(writer)
            .bind(&me[..])
            .fetch_all(pool)
            .await?
    });
    let mut seal = None;
    let mut seat = None;
    if !seats.is_empty() {
        let seals: Vec<(i64, i32, i16, Vec<u8>)> = db!(store, pool => {
            sqlx::query_as("SELECT bucket, version, idx, sealed FROM voipc_seals WHERE chain_id = $1")
                .bind(chain_id)
                .fetch_all(pool)
                .await?
        });
        // The lowest index, then the fewest links to walk
        let best = seals
            .iter()
            .filter_map(|s| {
                let t = seats
                    .iter()
                    .filter(|t| t.0 == s.0 && t.1 >= s.1)
                    .min_by_key(|t| t.1)?;
                Some((s, t))
            })
            .min_by_key(|(s, t)| (s.2, t.1 - s.1));
        if let Some((s, t)) = best {
            seal = Some(ChainSeal {
                bucket: s.0 as u64,
                version: s.1 as u32,
                index: s.2 as u32,
                sealed: s.3.clone(),
            });
            seat = Some((t.1, t.2.clone()));
        }
    }
    let mut down = Vec::new();
    if let (Some(s), Some((v, _))) = (&seal, &seat) {
        let rows: Vec<(i32, i32, Vec<u8>)> = db!(store, pool => {
            sqlx::query_as(
                "SELECT version, old, link FROM voipc_bucket_links
                  WHERE writer = $1 AND bucket = $2 AND version <= $3 AND version > $4 ORDER BY version DESC",
            )
            .bind(writer)
            .bind(s.bucket as i64)
            .bind(*v)
            .bind(s.version as i32)
            .fetch_all(pool)
            .await?
        });
        down = rows
            .into_iter()
            .map(|(n, o, l)| (n as u32, o as u32, l))
            .collect();
    }
    Ok(ChainKeys {
        owner: *owner,
        chain,
        self_wrap: None,
        direct: direct.map(|(i, r)| (i as u32, r)),
        seal,
        seat: seat.map(|(v, r)| (v as u32, r)),
        down,
        link: None,
        steps: Vec::new(),
    })
}

/// What one ask is answered with: chains above it first, when a run of links is the way in.
async fn chain_keys(
    store: &Store,
    conv: &str,
    me: &[u8; 16],
    ask: &ChainAsk,
) -> Result<Vec<ChainKeys>> {
    let empty = || ChainKeys {
        owner: ask.owner,
        chain: ask.chain,
        self_wrap: None,
        direct: None,
        seal: None,
        seat: None,
        down: Vec::new(),
        link: None,
        steps: Vec::new(),
    };
    let Some(w) = writer_of(store, conv, &ask.owner).await? else {
        return Ok(vec![empty()]);
    };
    let chain_no = ask.chain as i32;
    let row: Option<(i32, Vec<u8>)> = db!(store, pool => {
        sqlx::query_as("SELECT id, self_wrap FROM voipc_chains WHERE writer = $1 AND chain = $2")
            .bind(w.id)
            .bind(chain_no)
            .fetch_optional(pool)
            .await?
    });
    let Some((chain_id, self_wrap)) = row else {
        return Ok(vec![empty()]);
    };
    // Holds a state there already, or it is ours: the rest is only walking up
    if ask.from.is_some() || ask.owner == *me {
        let from = ask.from.unwrap_or(0).min(MAX_CHAIN_STEPS) as i16;
        let tail = chain_tail(store, chain_id, from).await?;
        let mut k = empty();
        k.self_wrap = (ask.owner == *me && ask.from.is_none()).then_some(self_wrap);
        k.link = tail.link;
        k.steps = tail.steps;
        return Ok(vec![k]);
    }
    let mut k = chain_state(store, &ask.owner, ask.chain, w.id, chain_id, me).await?;
    let lowest = [
        k.direct.as_ref().map(|d| d.0),
        k.seal.as_ref().map(|s| s.index),
    ]
    .into_iter()
    .flatten()
    .min();
    let mut out = Vec::new();
    let mut from = lowest.unwrap_or(0);
    if lowest != Some(0) {
        let chains = chain_map(store, w.id).await?;
        let held = starts_held(store, w.id, me, &chains).await?;
        let path = run_up(&chains, &held, chain_no);
        for (i, c) in path.iter().enumerate().rev().take(MAX_RUN_HOPS) {
            let (id, _) = chains[c];
            let mut hop = if i + 1 == path.len() {
                chain_state(store, &ask.owner, *c as u32, w.id, id, me).await?
            } else {
                let mut e = empty();
                e.chain = *c as u32;
                e
            };
            hop.link = chain_tail(store, id, i16::MAX).await?.link;
            out.push(hop);
        }
        if path.len() > MAX_RUN_HOPS {
            return Ok(out);
        }
        if !path.is_empty() {
            from = 0;
        }
    }
    let tail = chain_tail(store, chain_id, from as i16).await?;
    k.link = tail.link;
    k.steps = tail.steps;
    out.push(k);
    Ok(out)
}

/// The members by id alone, for a writer's first post in a channel.
pub(super) async fn member_ids(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    after: Option<[u8; 16]>,
) -> Result<AccountReply> {
    if !is_channel(conv) || !is_member(relay, conv, &me.0).await? {
        return Ok(refused("LogMemberIds", "not a conversation of yours"));
    }
    let rows: Vec<Vec<u8>> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT account FROM voipc_members WHERE conv = $1 AND account > $2 ORDER BY account LIMIT $3")
            .bind(conv)
            .bind(after.as_ref().map_or(EMPTY, |a| &a[..]))
            .bind(MEMBER_IDS_PAGE + 1)
            .fetch_all(pool)
            .await?
    });
    let more = rows.len() as i64 > MEMBER_IDS_PAGE;
    Ok(AccountReply::LogMemberIdsFound {
        conv: conv.to_string(),
        ids: rows
            .into_iter()
            .take(MEMBER_IDS_PAGE as usize)
            .map(id16)
            .collect(),
        more,
    })
}

/// Our own chains, newest first: what a device goes on from. A self-wrap the device
/// cannot open is one it will not write under, whatever is claimed here.
pub(super) async fn own_chains(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    before: Option<u32>,
) -> Result<AccountReply> {
    if !is_channel(conv) || !is_member(relay, conv, &me.0).await? {
        return Ok(refused("OwnChains", "not a conversation of yours"));
    }
    let Some(w) = writer_of(relay.store(), conv, &me.0).await? else {
        return Ok(AccountReply::OwnChains {
            conv: conv.to_string(),
            newest: None,
            chains: Vec::new(),
            more: false,
        });
    };
    let rows: Vec<OwnChainRow> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT chain, top, done, self_wrap, older FROM voipc_chains WHERE writer = $1 AND chain < $2 ORDER BY chain DESC LIMIT $3",
        )
        .bind(w.id)
        .bind(before.map_or(i32::MAX, |b| b as i32))
        .bind(OWN_CHAINS_PAGE + 1)
        .fetch_all(pool)
        .await?
    });
    let more = rows.len() as i64 > OWN_CHAINS_PAGE;
    Ok(AccountReply::OwnChains {
        conv: conv.to_string(),
        newest: w.newest.map(|n| n as u32),
        chains: rows
            .into_iter()
            .take(OWN_CHAINS_PAGE as usize)
            .map(|(chain, top, done, self_wrap, older)| OwnChain {
                chain: chain as u32,
                top: top as u32,
                done,
                self_wrap,
                older: older.map(|o| o as u32),
            })
            .collect(),
        more,
    })
}

/// Our own buckets at their newest versions, those the newest chain is sealed to marked.
pub(super) async fn own_buckets(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    after: Option<u64>,
) -> Result<AccountReply> {
    let store = relay.store();
    if !is_channel(conv) || !is_member(relay, conv, &me.0).await? {
        return Ok(refused("OwnBuckets", "not a conversation of yours"));
    }
    let empty = || AccountReply::OwnBuckets {
        conv: conv.to_string(),
        buckets: Vec::new(),
        more: false,
    };
    let Some(w) = writer_of(store, conv, &me.0).await? else {
        return Ok(empty());
    };
    let newest: HashMap<i64, i32> = db!(store, pool => {
        sqlx::query_as::<_, (i64, i32)>("SELECT bucket, MAX(version) FROM voipc_bucket_lists WHERE writer = $1 GROUP BY bucket")
            .bind(w.id)
            .fetch_all(pool)
            .await?
    })
    .into_iter()
    .collect();
    let seats: Vec<(Vec<u8>, i64, i32, Vec<u8>)> = db!(store, pool => {
        sqlx::query_as("SELECT recipient, bucket, version, wrapped FROM voipc_seats WHERE writer = $1")
            .bind(w.id)
            .fetch_all(pool)
            .await?
    });
    let sealed: HashSet<i64> = match w.newest {
        Some(n) => match chain_row(store, w.id, n).await? {
            Some((id, ..)) => db!(store, pool => {
                sqlx::query_scalar::<_, i64>("SELECT bucket FROM voipc_seals WHERE chain_id = $1")
                    .bind(id)
                    .fetch_all(pool)
                    .await?
            })
            .into_iter()
            .collect(),
            None => HashSet::new(),
        },
        None => HashSet::new(),
    };
    let mut count: HashMap<i64, u32> = HashMap::new();
    let mut own: HashMap<i64, Vec<u8>> = HashMap::new();
    for (who, bucket, version, wrapped) in seats {
        if newest.get(&bucket) != Some(&version) {
            continue;
        }
        if who.as_slice() == me.0 {
            own.insert(bucket, wrapped);
        } else {
            *count.entry(bucket).or_default() += 1;
        }
    }
    let mut buckets: Vec<OwnBucket> = own
        .into_iter()
        .filter(|(b, _)| after.is_none_or(|a| *b as u64 > a))
        .map(|(b, own_row)| OwnBucket {
            bucket: b as u64,
            version: newest[&b] as u32,
            own_row,
            seats: count.get(&b).copied().unwrap_or(0),
            sealed: sealed.contains(&b),
        })
        .collect();
    buckets.sort_unstable_by_key(|b| b.bucket);
    let more = buckets.len() > OWN_BUCKETS_PAGE;
    buckets.truncate(OWN_BUCKETS_PAGE);
    Ok(AccountReply::OwnBuckets {
        conv: conv.to_string(),
        buckets,
        more,
    })
}

pub(super) async fn bucket_lists(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    wanted: &[(u64, u32)],
) -> Result<AccountReply> {
    if !is_channel(conv) || !is_member(relay, conv, &me.0).await? {
        return Ok(refused("BucketLists", "not a conversation of yours"));
    }
    if wanted.len() > MAX_LISTS {
        return Ok(refused("BucketLists", "too many lists at once"));
    }
    let mut lists = Vec::with_capacity(wanted.len());
    if let Some(w) = writer_of(relay.store(), conv, &me.0).await? {
        for (bucket, version) in wanted {
            let sealed: Option<Vec<u8>> = db!(relay.store(), pool => {
                sqlx::query_scalar("SELECT sealed FROM voipc_bucket_lists WHERE writer = $1 AND bucket = $2 AND version = $3")
                    .bind(w.id)
                    .bind(*bucket as i64)
                    .bind(*version as i32)
                    .fetch_optional(pool)
                    .await?
            });
            if let Some(sealed) = sealed {
                lists.push((*bucket, *version, sealed));
            }
        }
    }
    Ok(AccountReply::BucketLists {
        conv: conv.to_string(),
        lists,
    })
}

/// The rows of one of our own chains. A seal past what one frame holds is left out, and its
/// bucket then has no proof of having held the start: it fails to not index 0.
pub(super) async fn own_chain_rows(
    relay: &Relay,
    me: AccountId,
    conv: &str,
    chain: u32,
    after: Option<[u8; 16]>,
) -> Result<AccountReply> {
    let store = relay.store();
    if !is_channel(conv) || !is_member(relay, conv, &me.0).await? {
        return Ok(refused("OwnChainRows", "not a conversation of yours"));
    }
    let (mut seals, mut direct, mut links, mut more) = (Vec::new(), Vec::new(), Vec::new(), false);
    let writer = writer_of(store, conv, &me.0).await?;
    let row = match &writer {
        Some(w) => chain_row(store, w.id, chain as i32).await?,
        None => None,
    };
    if let (Some(w), Some((id, ..))) = (writer, row) {
        if after.is_none() {
            let rows: Vec<(i64, i32, i16, Vec<u8>)> = db!(store, pool => {
                sqlx::query_as("SELECT bucket, version, idx, sealed FROM voipc_seals WHERE chain_id = $1 ORDER BY bucket LIMIT 300")
                    .bind(id)
                    .fetch_all(pool)
                    .await?
            });
            let all_links: Vec<(i64, i32, i32, Vec<u8>)> = db!(store, pool => {
                sqlx::query_as("SELECT bucket, version, old, link FROM voipc_bucket_links WHERE writer = $1 ORDER BY bucket, version DESC")
                    .bind(w.id)
                    .fetch_all(pool)
                    .await?
            });
            let down_to: HashMap<i64, i32> = rows.iter().map(|s| (s.0, s.1)).collect();
            links = all_links
                .into_iter()
                .filter(|l| down_to.get(&l.0).is_some_and(|v| l.1 > *v))
                .take(100)
                .map(|(b, n, o, l)| (b as u64, n as u32, o as u32, l))
                .collect();
            seals = rows
                .into_iter()
                .map(|(b, v, i, s)| ChainSeal {
                    bucket: b as u64,
                    version: v as u32,
                    index: i as u32,
                    sealed: s,
                })
                .collect();
        }
        let rows: Vec<(Vec<u8>, i16, Vec<u8>)> = db!(store, pool => {
            sqlx::query_as(
                "SELECT recipient, idx, wrapped FROM voipc_chain_wraps WHERE writer = $1 AND chain_id = $2 AND recipient > $3 AND dead = FALSE
                  ORDER BY recipient LIMIT $4",
            )
            .bind(w.id)
            .bind(id)
            .bind(after.as_ref().map_or(EMPTY, |a| &a[..]))
            .bind(OWN_ROWS_PAGE as i64 + 1)
            .fetch_all(pool)
            .await?
        });
        more = rows.len() > OWN_ROWS_PAGE;
        direct = rows
            .into_iter()
            .take(OWN_ROWS_PAGE)
            .map(|(r, i, w)| ChainRow {
                recipient: id16(r),
                index: i as u32,
                wrapped: w,
            })
            .collect();
    }
    Ok(AccountReply::OwnChainRows {
        conv: conv.to_string(),
        chain,
        seals,
        direct,
        links,
        more,
    })
}

/// The share flag at rest, for `join`: it tells only writers who share. Set whenever a
/// session says or is told, so a switch turned off on another device reaches it too.
pub async fn set_shares(store: &Store, account: &[u8; 16], on: bool) -> Result<()> {
    db!(store, pool => {
        sqlx::query("UPDATE voipc_writers SET shares = $1 WHERE owner = $2 AND shares <> $1")
            .bind(on)
            .bind(&account[..])
            .execute(pool)
            .await?;
    });
    // Nobody waits on someone who will not answer: each reads past them at its next read
    if !on {
        db!(store, pool => {
            sqlx::query("DELETE FROM voipc_pending WHERE owner = $1")
                .bind(&account[..])
                .execute(pool)
                .await?;
        });
    }
    Ok(())
}

/// Writers marked as sharing who no longer hold the right, whether they are here or not:
/// a session's flag goes with the scope, but an account away has no session to clear.
pub async fn recheck_shares(relay: &Relay) -> Result<()> {
    let owners: Vec<Vec<u8>> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT DISTINCT owner FROM voipc_writers WHERE shares = TRUE").fetch_all(pool).await?
    });
    for owner in owners {
        let id = AccountId(id16(owner));
        let holds = match relay.store().user_by_id(id).await? {
            Some(user) => {
                let scopes = relay.accounts.effective_scopes(&user).await?;
                l4f_accounts::scope::allowed(&scopes, voipc_protocol::types::SHARE_HISTORY)
            }
            None => false,
        };
        if !holds {
            set_shares(relay.store(), &id.0, false).await?;
        }
    }
    Ok(())
}

// ── The sweep, per channel ────────────────────────────────────────────────

/// One channel's text and keys. The floor is the window's worth of entries back, counting
/// only entries settled and long-lived: past `GRACE_MS` old, and alive for at least that
/// much longer. Else a flood with a timer, or one a moderator cleans up, is gone by itself
/// after taking what is below it, and what it took never comes back.
async fn sweep_channel(relay: &Relay, conv: &str, now_ms: i64) -> Result<u64> {
    let store = relay.store();
    let floor: Option<i64> = db!(store, pool => {
        sqlx::query_scalar(
            "SELECT seq FROM voipc_log WHERE conv = $1 AND server_at < $2 AND keep_until > $3
              ORDER BY seq DESC LIMIT 1 OFFSET $4",
        )
        .bind(conv)
        .bind(now_ms - GRACE_MS)
        .bind(now_ms.saturating_add(GRACE_MS))
        .bind(relay.kept_window - 1)
        .fetch_optional(pool)
        .await?
    });
    let mut n = 0;
    if let Some(floor) = floor {
        n = db!(store, pool => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "INSERT INTO voipc_log_floors (conv, floor) VALUES ($1, $2)
                 ON CONFLICT (conv) DO UPDATE SET floor = excluded.floor WHERE excluded.floor > voipc_log_floors.floor",
            )
            .bind(conv)
            .bind(floor)
            .execute(&mut *tx)
            .await?;
            // The owner's call, 2026-11-06. Without this statement the floor still
            // drives the clamp and the keys.
            let gone = sqlx::query("DELETE FROM voipc_log WHERE conv = $1 AND seq < $2")
                .bind(conv)
                .bind(floor)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            tx.commit().await?;
            gone
        });
    }
    sweep_keys(relay, conv, floor.unwrap_or(0), now_ms).await?;
    Ok(n)
}

/// The keys of a channel that open nothing any more: a chain goes when no entry of it is
/// left, unless it is a writer's newest and they posted lately, it was made in the last
/// hour, or a chain below it in its run of links is still alive, which a reader walks
/// through it to reach. Self-wraps go with their chains. Direct conversations never come here.
async fn sweep_keys(relay: &Relay, conv: &str, floor: i64, now_ms: i64) -> Result<()> {
    let store = relay.store();
    let now = util::now();
    let live: HashSet<(Vec<u8>, i64)> = db!(store, pool => {
        sqlx::query_as::<_, (Vec<u8>, i64)>(
            "SELECT DISTINCT sender, CAST(epoch / 4096 AS BIGINT) FROM voipc_log WHERE conv = $1 AND seq >= $2 AND keep_until > $3",
        )
        .bind(conv)
        .bind(floor)
        .bind(now_ms)
        .fetch_all(pool)
        .await?
    })
    .into_iter()
    .collect();
    let writers: Vec<(i32, Vec<u8>, Option<i32>, i64)> = db!(store, pool => {
        sqlx::query_as("SELECT id, owner, newest_chain, last_post_hour FROM voipc_writers WHERE conv = $1")
            .bind(conv)
            .fetch_all(pool)
            .await?
    });
    for (writer, owner, newest, last_post_hour) in writers {
        let mut chains: Vec<(i32, i32, Option<i32>, bool, i64)> = db!(store, pool => {
            sqlx::query_as("SELECT id, chain, older, done, created_at FROM voipc_chains WHERE writer = $1")
                .bind(writer)
                .fetch_all(pool)
                .await?
        });
        chains.sort_unstable_by_key(|c| c.1);
        let mut alive_below: HashMap<i32, bool> = HashMap::new();
        let mut unfinished = Vec::new();
        let mut drop = Vec::new();
        for (id, chain, older, done, created_at) in chains {
            let young = created_at > now - UNFINISHED_SECS;
            if !done && !young {
                unfinished.push(id);
                continue;
            }
            let has = live.contains(&(owner.clone(), i64::from(chain)));
            let below = older.is_some_and(|o| alive_below.get(&o).copied().unwrap_or(false));
            alive_below.insert(chain, has || below);
            let recent = newest == Some(chain) && last_post_hour > now / 3600 - NEWEST_KEPT_HOURS;
            if !(has || below || young || recent) {
                drop.push(id);
            }
        }
        if drop.is_empty() && unfinished.is_empty() {
            continue;
        }
        db!(store, pool => {
            let mut tx = pool.begin().await?;
            for id in drop.iter().chain(&unfinished) {
                sqlx::query("DELETE FROM voipc_chain_wraps WHERE writer = $1 AND chain_id = $2")
                    .bind(writer)
                    .bind(*id)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM voipc_chains WHERE id = $1")
                    .bind(*id)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
        });
        sweep_buckets(store, writer, &unfinished, now).await?;
        recount(store, writer).await?;
        db!(store, pool => {
            // Nothing of it left, and it said nothing for a month: as if it never wrote
            sqlx::query(
                "DELETE FROM voipc_writers WHERE id = $1 AND last_post_hour <= $2
                  AND NOT EXISTS (SELECT 1 FROM voipc_chains c WHERE c.writer = $1)",
            )
            .bind(writer)
            .bind(now / 3600 - NEWEST_KEPT_HOURS)
            .execute(pool)
            .await?;
            sqlx::query(
                "UPDATE voipc_writers SET open_bytes = 0 WHERE id = $1
                  AND NOT EXISTS (SELECT 1 FROM voipc_chains c WHERE c.writer = $1 AND c.done = FALSE)",
            )
            .bind(writer)
            .execute(pool)
            .await?;
        });
    }
    Ok(())
}

/// A writer's bucket rows nothing needs now: a seat row or a link only opens seals at or
/// below its version, so once those seals have gone it can too. That is what clears a
/// leaver's frozen row. Whatever a chain never finished made goes with it, or a bucket
/// half made would count as live. Versions made in the last hour wait for their seals.
async fn sweep_buckets(store: &Store, writer: i32, unfinished: &[i32], now: i64) -> Result<()> {
    let lowest_seal: HashMap<i64, i32> = db!(store, pool => {
        sqlx::query_as::<_, (i64, i32)>(
            "SELECT s.bucket, MIN(s.version) FROM voipc_seals s JOIN voipc_chains c ON c.id = s.chain_id WHERE c.writer = $1 GROUP BY s.bucket",
        )
        .bind(writer)
        .fetch_all(pool)
        .await?
    })
    .into_iter()
    .collect();
    let highest_seal: HashMap<i64, i32> = db!(store, pool => {
        sqlx::query_as::<_, (i64, i32)>(
            "SELECT s.bucket, MAX(s.version) FROM voipc_seals s JOIN voipc_chains c ON c.id = s.chain_id WHERE c.writer = $1 GROUP BY s.bucket",
        )
        .bind(writer)
        .fetch_all(pool)
        .await?
    })
    .into_iter()
    .collect();
    let lists: Vec<(i64, i32, i32, i64)> = db!(store, pool => {
        sqlx::query_as("SELECT bucket, version, chain_id, created_at FROM voipc_bucket_lists WHERE writer = $1")
            .bind(writer)
            .fetch_all(pool)
            .await?
    });
    let made_by_dropped = |chain_id: i32| unfinished.contains(&chain_id);
    let young: HashSet<(i64, i32)> = lists
        .iter()
        .filter(|l| l.3 > now - UNFINISHED_SECS && !made_by_dropped(l.2))
        .map(|l| (l.0, l.1))
        .collect();
    // Unless a later chain went on from it: a device rereading after a crash seals to the
    // newest version there is, whoever made it, and people's way in runs through it.
    let aborted: HashSet<(i64, i32)> = lists
        .iter()
        .filter(|l| made_by_dropped(l.2) && highest_seal.get(&l.0).is_none_or(|s| *s < l.1))
        .map(|l| (l.0, l.1))
        .collect();
    let needed = |bucket: i64, version: i32| {
        young.contains(&(bucket, version))
            || (!aborted.contains(&(bucket, version))
                && lowest_seal.get(&bucket).is_some_and(|m| version >= *m))
    };
    let seats: Vec<(Vec<u8>, i64, i32)> = db!(store, pool => {
        sqlx::query_as::<_, (Vec<u8>, i64, i32)>("SELECT recipient, bucket, version FROM voipc_seats WHERE writer = $1")
            .bind(writer)
            .fetch_all(pool)
            .await?
    })
    .into_iter()
    .filter(|s| !needed(s.1, s.2))
    .collect();
    let links: Vec<(i64, i32)> = db!(store, pool => {
        sqlx::query_as::<_, (i64, i32, i32)>("SELECT bucket, version, old FROM voipc_bucket_links WHERE writer = $1")
            .bind(writer)
            .fetch_all(pool)
            .await?
    })
    .into_iter()
    .filter(|(b, v, old)| !young.contains(&(*b, *v)) && (aborted.contains(&(*b, *v)) || !needed(*b, *old)))
    .map(|(b, v, _)| (b, v))
    .collect();
    let lists: Vec<(i64, i32)> = lists
        .iter()
        .filter(|l| !needed(l.0, l.1))
        .map(|l| (l.0, l.1))
        .collect();
    db!(store, pool => {
        let mut tx = pool.begin().await?;
        for (who, bucket, version) in &seats {
            sqlx::query("DELETE FROM voipc_seats WHERE writer = $1 AND recipient = $2 AND bucket = $3 AND version = $4")
                .bind(writer)
                .bind(who.as_slice())
                .bind(*bucket)
                .bind(*version)
                .execute(&mut *tx)
                .await?;
        }
        for (bucket, version) in &links {
            sqlx::query("DELETE FROM voipc_bucket_links WHERE writer = $1 AND bucket = $2 AND version = $3")
                .bind(writer)
                .bind(*bucket)
                .bind(*version)
                .execute(&mut *tx)
                .await?;
        }
        for (bucket, version) in &lists {
            sqlx::query("DELETE FROM voipc_bucket_lists WHERE writer = $1 AND bucket = $2 AND version = $3")
                .bind(writer)
                .bind(*bucket)
                .bind(*version)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    });
    Ok(())
}

/// A deleted account's rows per writer: those frozen, on no newest chain, go now. One a
/// newest chain still reaches stays until that writer's next post has started a new chain
/// without it, since it is what says to. The stone goes when no row names the account.
async fn sweep_tombstones(store: &Store) -> Result<()> {
    let stones: Vec<Vec<u8>> = db!(store, pool => {
        sqlx::query_scalar("SELECT account FROM voipc_tombstones").fetch_all(pool).await?
    });
    for account in stones {
        let mut after = 0i32;
        let mut left = 0i64;
        loop {
            let writers: Vec<(i32, Option<i32>)> = db!(store, pool => {
                sqlx::query_as(
                    "SELECT w.id, c.id FROM voipc_writers w LEFT JOIN voipc_chains c ON c.writer = w.id AND c.chain = w.newest_chain
                      WHERE w.id > $1 ORDER BY w.id LIMIT $2",
                )
                .bind(after)
                .bind(WALK_BATCH)
                .fetch_all(pool)
                .await?
            });
            let Some(last) = writers.last().map(|w| w.0) else {
                break;
            };
            for (writer, newest) in writers {
                let newest = newest.unwrap_or(0);
                let seats: Vec<(i64, i32)> = db!(store, pool => {
                    sqlx::query_as("SELECT bucket, version FROM voipc_seats WHERE writer = $1 AND recipient = $2")
                        .bind(writer)
                        .bind(account.as_slice())
                        .fetch_all(pool)
                        .await?
                });
                let direct: i64 = db!(store, pool => {
                    sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_chain_wraps WHERE writer = $1 AND recipient = $2")
                        .bind(writer)
                        .bind(account.as_slice())
                        .fetch_one(pool)
                        .await?
                });
                if seats.is_empty() && direct == 0 {
                    continue;
                }
                let seals: HashMap<i64, i32> = db!(store, pool => {
                    sqlx::query_as::<_, (i64, i32)>("SELECT bucket, version FROM voipc_seals WHERE chain_id = $1")
                        .bind(newest)
                        .fetch_all(pool)
                        .await?
                })
                .into_iter()
                .collect();
                let (live, frozen): (Vec<_>, Vec<_>) = seats
                    .into_iter()
                    .partition(|(b, v)| seals.get(b).is_some_and(|s| v >= s));
                left += live.len() as i64;
                let direct_left: i64 = db!(store, pool => {
                    let mut tx = pool.begin().await?;
                    for (b, v) in &frozen {
                        sqlx::query("DELETE FROM voipc_seats WHERE writer = $1 AND recipient = $2 AND bucket = $3 AND version = $4")
                            .bind(writer)
                            .bind(account.as_slice())
                            .bind(*b)
                            .bind(*v)
                            .execute(&mut *tx)
                            .await?;
                    }
                    sqlx::query("DELETE FROM voipc_chain_wraps WHERE writer = $1 AND recipient = $2 AND chain_id <> $3")
                        .bind(writer)
                        .bind(account.as_slice())
                        .bind(newest)
                        .execute(&mut *tx)
                        .await?;
                    let n: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_chain_wraps WHERE writer = $1 AND recipient = $2")
                        .bind(writer)
                        .bind(account.as_slice())
                        .fetch_one(&mut *tx)
                        .await?;
                    tx.commit().await?;
                    n
                });
                left += direct_left;
            }
            after = last;
        }
        if left == 0 {
            db!(store, pool => {
                sqlx::query("DELETE FROM voipc_tombstones WHERE account = $1").bind(account.as_slice()).execute(pool).await?;
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chains(rows: &[(i32, Option<i32>)]) -> HashMap<i32, (i32, Option<i32>)> {
        rows.iter().map(|(c, o)| (*c, (*c * 10, *o))).collect()
    }

    #[test]
    fn a_run_up_finds_the_nearest_start_by_any_way_there_is() {
        // 2 was never finished, and 3 went on from 1 instead
        let map = chains(&[(1, None), (2, Some(1)), (3, Some(1)), (4, Some(3))]);
        let held = |c: &[i32]| c.iter().map(|c| c * 10).collect::<HashSet<i32>>();
        assert_eq!(run_up(&map, &held(&[4]), 1), [3, 4]);
        assert_eq!(run_up(&map, &held(&[3, 4]), 1), [3], "the nearest");
        assert_eq!(run_up(&map, &held(&[2]), 1), [2], "it can be the way too");
        assert!(run_up(&map, &held(&[1]), 1).is_empty(), "nothing above");
        assert!(run_up(&map, &held(&[]), 1).is_empty(), "nothing held");
        assert!(run_up(&map, &held(&[4]), 4).is_empty(), "the top");
    }
}
