//! The stored-message log on the relay: sealed entries, wrapped epoch keys
//! and published log keys (`voipc_crypto::log` makes and opens them). The
//! relay checks who may read and write a conversation and keeps the bytes; it
//! cannot open any of them.

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::store::Store;
use l4f_accounts::util;
use voipc_protocol::conv::dm_parties;
use voipc_protocol::messages::{AccountReply, LogEntry, LogKeyInfo, WrapIn, WrapOut};

use super::{refused, Relay};

/// Longest entry the relay files (sealed): a chat message with room to spare.
const MAX_ENTRY: usize = 16 * 1024;
/// A page of entries, under the 64 KiB frame it travels in.
const PAGE_BYTES: usize = 44 * 1024;
const PAGE_ROWS: i64 = 200;
const MAX_LOGKEY_LOOKUPS: usize = 64;
/// Most stored members a channel's log takes: a key goes to each of them in
/// one frame (`EpochPut`), and their keys come back in one (`LogMembersFound`).
const MAX_MEMBERS: i64 = 256;

/// Rows as they come back: an account's keys (name, identity, log key,
/// signature), an entry (seq, sender, epoch, server_at, sealed), and a
/// member (account, then its keys).
type KeyRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);
type EntryRow = (i64, Vec<u8>, i64, i64, Vec<u8>);
type MemberRow = (Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}

fn id16(v: Vec<u8>) -> [u8; 16] {
    v.try_into().unwrap_or([0; 16])
}

fn is_channel(conv: &str) -> bool {
    conv.starts_with("c:")
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

pub(super) async fn publish(relay: &Relay, me: AccountId, logkey: &[u8], sig: &[u8]) -> Result<AccountReply> {
    if logkey.len() != 33 || sig.len() != 64 {
        return Ok(refused("LogKeyPublish", "malformed log key"));
    }
    db!(relay.store(), pool => {
        sqlx::query(
            "INSERT INTO voipc_logkeys (account, logkey, sig, updated_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (account) DO UPDATE SET logkey = excluded.logkey, sig = excluded.sig, updated_at = excluded.updated_at",
        )
        .bind(&me.0[..])
        .bind(logkey)
        .bind(sig)
        .bind(util::now())
        .execute(pool)
        .await?;
    });
    Ok(AccountReply::LogKeyStored)
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
            found.push(LogKeyInfo { account: *a, name, identity, logkey, sig });
        }
    }
    Ok(AccountReply::LogKeysFound { keys: found })
}

/// Files the wraps; also says which recipients to tell (`LogNews`).
pub(super) async fn epoch_put(relay: &Relay, me: AccountId, conv: &str, epoch: u32, wraps: &[WrapIn]) -> Result<(AccountReply, Vec<[u8; 16]>)> {
    let Some(members) = members(relay, conv, &me.0).await? else { return Ok((refused("EpochPut", "not a conversation of yours"), Vec::new())) };
    if wraps.is_empty() || wraps.len() > members.len() || wraps.iter().any(|w| !members.contains(&w.recipient) || w.wrapped.len() > 128) {
        return Ok((refused("EpochPut", "wraps for somebody outside the conversation"), Vec::new()));
    }
    let now = util::now();
    for w in wraps {
        // Insert only: an epoch key once handed out is never replaced, so a
        // second device minting the same epoch at the same moment loses
        // quietly and reads the first one's instead.
        db!(relay.store(), pool => {
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
            .execute(pool)
            .await?;
        });
        // A key to somebody who joined is our answer to their joining.
        db!(relay.store(), pool => {
            sqlx::query("DELETE FROM voipc_pending WHERE conv = $1 AND owner = $2 AND recipient = $3")
                .bind(conv)
                .bind(&me.0[..])
                .bind(&w.recipient[..])
                .execute(pool)
                .await?;
        });
    }
    let told = wraps.iter().map(|w| w.recipient).filter(|r| *r != me.0).collect();
    Ok((AccountReply::EpochStored { conv: conv.to_string(), epoch }, told))
}

pub(super) async fn wraps(relay: &Relay, me: AccountId, conv: &str) -> Result<AccountReply> {
    if members(relay, conv, &me.0).await?.is_none() {
        return Ok(refused("WrapsFetch", "not a conversation of yours"));
    }
    // ponytail: the newest 400 only. Wraps of epochs with nothing left in
    // them go with the sweep, so this is a bound on keys still in use.
    let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = db!(relay.store(), pool => {
        sqlx::query_as("SELECT owner, epoch, wrapped FROM voipc_wraps WHERE recipient = $1 AND conv = $2 ORDER BY created_at DESC LIMIT 400")
            .bind(&me.0[..])
            .bind(conv)
            .fetch_all(pool)
            .await?
    });
    let wraps = rows.into_iter().map(|(owner, epoch, wrapped)| WrapOut { owner: id16(owner), epoch: epoch as u32, wrapped }).collect();
    Ok(AccountReply::Wraps { conv: conv.to_string(), wraps })
}

pub(super) async fn append(relay: &Relay, me: AccountId, conv: &str, epoch: u32, ct: &[u8], ttl_secs: Option<u32>) -> Result<AccountReply> {
    if !relay.cloud {
        return Ok(refused("LogAppend", "This server keeps no messages."));
    }
    let Some(members) = members(relay, conv, &me.0).await? else {
        return Ok(refused("LogAppend", "not a conversation of yours"));
    };
    if ct.is_empty() || ct.len() > MAX_ENTRY {
        return Ok(refused("LogAppend", "That message is too long to keep."));
    }
    if is_channel(conv) {
        // The epoch must reach exactly the members there are now: nobody who
        // left, and everybody who joined (or the writer's answer to them).
        let rows: Vec<Vec<u8>> = db!(relay.store(), pool => {
            sqlx::query_scalar("SELECT recipient FROM voipc_wraps WHERE conv = $1 AND owner = $2 AND epoch = $3")
                .bind(conv)
                .bind(&me.0[..])
                .bind(i64::from(epoch))
                .fetch_all(pool)
                .await?
        });
        let mut got: Vec<[u8; 16]> = rows.into_iter().map(id16).collect();
        let mut want = members;
        got.sort_unstable();
        want.sort_unstable();
        if got != want {
            return Ok(AccountReply::LogRekey { conv: conv.to_string() });
        }
    }
    let used: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT CAST(COALESCE(SUM(LENGTH(ct)), 0) AS BIGINT) FROM voipc_log WHERE sender = $1")
            .bind(&me.0[..])
            .fetch_one(pool)
            .await?
    });
    if used + ct.len() as i64 > relay.quota {
        return Ok(refused("LogAppend", "Your stored messages are over this server's limit."));
    }
    let server_at = now_ms();
    // The message's own timer when it has one, never past the relay's retention.
    let keep = ttl_secs.map(|t| i64::from(t) * 1000).unwrap_or(i64::MAX).min(relay.retention_ms);
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
    Ok(AccountReply::LogAppended { conv: conv.to_string(), seq, server_at: server_at as u64 })
}

pub(super) async fn fetch(relay: &Relay, me: AccountId, conv: &str, after: i64) -> Result<AccountReply> {
    if members(relay, conv, &me.0).await?.is_none() {
        return Ok(refused("LogFetch", "not a conversation of yours"));
    }
    let now_ms = now_ms();
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
        entries.push(LogEntry { seq, sender: id16(sender), epoch: epoch as u32, server_at: server_at as u64, ct });
    }
    let owed: Vec<Vec<u8>> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT owner FROM voipc_pending WHERE conv = $1 AND recipient = $2").bind(conv).bind(&me.0[..]).fetch_all(pool).await?
    });
    Ok(AccountReply::LogPage { conv: conv.to_string(), entries, more, owed: owed.into_iter().map(id16).collect() })
}

/// The conversations with something for us, and every joiner still waiting
/// for our keys (one `LogPending` per conversation).
pub(super) async fn index(relay: &Relay, me: AccountId) -> Result<(AccountReply, Vec<AccountReply>)> {
    let hex = me.hex();
    let now_ms = now_ms();
    let convs: Vec<(String, i64)> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT conv, MAX(seq) FROM voipc_log
              WHERE (conv LIKE $1 OR conv LIKE $2 OR conv IN (SELECT conv FROM voipc_members WHERE account = $4)) AND keep_until > $3
              GROUP BY conv ORDER BY conv LIMIT 512",
        )
        .bind(format!("d:{hex}:%"))
        .bind(format!("d:%:{hex}"))
        .bind(now_ms)
        .bind(&me.0[..])
        .fetch_all(pool)
        .await?
    });
    let rows: Vec<(String, Vec<u8>)> = db!(relay.store(), pool => {
        sqlx::query_as("SELECT conv, recipient FROM voipc_pending WHERE owner = $1 ORDER BY conv LIMIT 2048")
            .bind(&me.0[..])
            .fetch_all(pool)
            .await?
    });
    let mut pending: Vec<AccountReply> = Vec::new();
    for (conv, r) in rows {
        match pending.last_mut() {
            Some(AccountReply::LogPending { conv: c, joiners }) if *c == conv && joiners.len() < MAX_MEMBERS as usize => joiners.push(id16(r)),
            _ => pending.push(AccountReply::LogPending { conv, joiners: vec![id16(r)] }),
        }
    }
    Ok((AccountReply::LogConvs { convs }, pending))
}

/// Makes `me` a stored member of a channel's log; `present` says the session
/// is in that channel now (the relay's own admission decided that). Also
/// says which writers to tell: each one that keeps keys here owes us an answer.
pub(crate) async fn join(relay: &Relay, me: AccountId, conv: &str, present: bool) -> Result<(AccountReply, Vec<[u8; 16]>)> {
    if !relay.cloud {
        return Ok((refused("LogJoin", "This server keeps no messages."), Vec::new()));
    }
    if !is_channel(conv) || !present {
        return Ok((refused("LogJoin", "Join the channel first."), Vec::new()));
    }
    let count: i64 = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT COUNT(*) FROM voipc_members WHERE conv = $1").bind(conv).fetch_one(pool).await?
    });
    let now = util::now();
    let added = db!(relay.store(), pool => {
        sqlx::query("INSERT INTO voipc_members (conv, account, joined_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(conv)
            .bind(&me.0[..])
            .bind(now)
            .execute(pool)
            .await?
            .rows_affected()
    });
    if added == 0 {
        return Ok((AccountReply::LogJoined { conv: conv.to_string() }, Vec::new()));
    }
    if count >= MAX_MEMBERS {
        // ponytail: counted before the insert, so two at once can pass it by one.
        remove(relay.store(), conv, &me.0).await?;
        return Ok((refused("LogJoin", "This channel keeps history for as many people as it can."), Vec::new()));
    }
    db!(relay.store(), pool => {
        sqlx::query(
            "INSERT INTO voipc_pending (conv, owner, recipient, created_at)
             SELECT DISTINCT w.conv, w.owner, $2, $3 FROM voipc_wraps w
               JOIN voipc_members m ON m.conv = w.conv AND m.account = w.owner
              WHERE w.conv = $1 AND w.owner <> $2
             ON CONFLICT DO NOTHING",
        )
        .bind(conv)
        .bind(&me.0[..])
        .bind(now)
        .execute(pool)
        .await?;
    });
    let owners: Vec<Vec<u8>> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT owner FROM voipc_pending WHERE conv = $1 AND recipient = $2").bind(conv).bind(&me.0[..]).fetch_all(pool).await?
    });
    Ok((AccountReply::LogJoined { conv: conv.to_string() }, owners.into_iter().map(id16).collect()))
}

pub(super) async fn leave(relay: &Relay, me: AccountId, conv: &str) -> Result<AccountReply> {
    if !is_channel(conv) {
        return Ok(refused("LogLeave", "not a channel's log"));
    }
    remove(relay.store(), conv, &me.0).await?;
    Ok(AccountReply::LogLeft { conv: conv.to_string() })
}

/// Takes `account` out of a channel's log: it leaves, is kicked, or no longer
/// knows the channel's password. Every writer's next entry needs a new key.
pub async fn remove(store: &Store, conv: &str, account: &[u8; 16]) -> Result<()> {
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
              WHERE m.conv = $1",
        )
        .bind(conv)
        .fetch_all(pool)
        .await?
    });
    let members = rows.into_iter().map(|(a, name, identity, logkey, sig)| LogKeyInfo { account: id16(a), name, identity, logkey, sig }).collect();
    Ok(AccountReply::LogMembersFound { conv: conv.to_string(), members })
}

/// Entries past their time, and the keys and pending answers nothing needs
/// any more; run with the hourly sweep.
pub async fn sweep(relay: &Relay) -> Result<u64> {
    let now_ms = now_ms();
    let store = relay.store();
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
    Ok(n)
}
