//! `voipc_modlog` (1.10): who did what to whom, read by holders of `voipc:modlog`.
//!
//! Not l4f's audit: that is deleted with the account, reads one subject at a time
//! and needs `users:read`. A row here outlives the accounts it names, until
//! `modlog_days` takes it, and holds copies of their names. A step writes its row
//! first: no row, no step. Nothing updates a row, and the sweep is the only delete.
//! Whoever holds the database can still change it: this protects against
//! moderators, not the owner.

use std::collections::HashSet;

use anyhow::Result;
use l4f_accounts::scope;
use l4f_accounts::store::Store;
use l4f_accounts::util;
use tracing::warn;
use voipc_protocol::codec::encode_server_msg;
use voipc_protocol::discord::snowflake_floor;
use voipc_protocol::messages::{AccountReply, AdminReply, ServerMessage};
use voipc_protocol::types::{ChannelId, ModRow, PostsMark, UserId};

use super::archive::{self, counted};
use super::{holds_power, is_star, refused, Relay};
use crate::bans::Ban;
use crate::control::ControlTx;
use crate::state::{is_pseudonym, pick_name, ServerState};

/// Rows a page holds at most.
const PAGE_ROWS: usize = 200;
/// And bytes: a row can reach 2.7 KiB, and a reply over a frame is not sent at all.
const PAGE_BYTES: usize = 44 * 1024;
/// A row's numbers and the lengths of its strings, at most.
const ROW_OVERHEAD: usize = 64;
/// Notes one account writes in an hour. Only time ever removes a row, so a flood of
/// notes cannot push out a ban, but it could bury one.
const NOTES_PER_HOUR: i64 = 120;
/// What only the actor's own app says happened: the relay cannot see inside E2E.
const ADVISORY: [&str; 2] = ["hide", "unhide"];
/// What a moderator may remove in one go. Beyond it, or all that is kept, is `*`'s:
/// the rows are gone for good.
const REMOVAL_MAX_SECS: u32 = 7 * 86_400;
/// Removals told at connect: the newest. A device away for longer than that many is
/// not told of the rest, as one away past `modlog_days` is not.
const MARKS_AT_CONNECT: i64 = 2000;
/// What one `PostsHidden` holds at most, under the frame it travels in.
const MARK_BYTES: usize = 44 * 1024;
/// A mark's numbers and the lengths of its strings, at most.
const MARK_OVERHEAD: usize = 48;

/// A row to write. An empty string is no value. The actor is the session
/// (`put`), or the server's shell, never what a client says.
#[derive(Default)]
pub struct Entry<'a> {
    pub action: &'a str,
    pub actor: Option<[u8; 16]>,
    pub actor_name: &'a str,
    pub target: Option<[u8; 16]>,
    pub target_name: &'a str,
    pub channel_key: &'a str,
    pub channel_name: &'a str,
    pub reason: &'a str,
    pub detail: &'a str,
}

type MarkRow = (Option<Vec<u8>>, String, Option<i64>, Option<i64>, String);

pub(super) type Row = (
    i64,
    i64,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
);

/// VARCHAR limits hold on Postgres only, which also refuses a NUL.
pub(crate) fn clip(s: &str, chars: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(chars).collect()
}

/// What `secs` of a ban come to, in words (0: permanent).
fn lasting(secs: u64) -> String {
    let (n, unit) = match secs {
        0 => return "permanent".into(),
        86_400.. => (secs / 86_400, "day"),
        3_600.. => (secs / 3_600, "hour"),
        _ => (secs.div_ceil(60), "minute"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// A ban row's detail: what it covers and for how long.
pub fn ban_detail(covers: &str, secs: u64) -> String {
    format!("{covers}, {}", lasting(secs))
}

/// How far back a removal went, in words.
fn window_words(window_secs: u32) -> String {
    if window_secs == 0 {
        return "everything kept".into();
    }
    let span = lasting(u64::from(window_secs));
    format!("last {}", span.strip_prefix("1 ").unwrap_or(&span))
}

/// What a removal takes of what came from Discord, by when it was written.
pub(super) struct Imported<'a> {
    /// The Discord ids the account has linked.
    pub ids: &'a [i64],
    pub low: i64,
    pub high: i64,
    /// Whether the log's row may say how many. Next to a pseudonym, a count says something
    /// about who it is.
    pub say_how_many: bool,
}

impl Relay {
    /// What `account` wrote to channels' stored logs from `since_ms` to `before_ms`
    /// goes, and its row is written, or neither happens. `None` deletes nothing: a
    /// guest has nothing here. `window`: the row's words for how far back. What came from
    /// Discord is a wish in the same transaction: it stops being served at once, and a
    /// worker takes the rows, since a large channel would hold everyone's writes here.
    ///
    /// Not direct conversations: one is the other party's too, and may be the record
    /// of what got them banned. Not the wraps, unlike `log::purge`: the writer is told
    /// nothing, and goes on sealing under its keys when it is back.
    pub(super) async fn posts_remove(
        &self,
        account: Option<[u8; 16]>,
        imported: Imported<'_>,
        since_ms: i64,
        before_ms: i64,
        window: &str,
        e: &Entry<'_>,
    ) -> Result<u64> {
        let actor_name = clip(e.actor_name, 64);
        let target_name = clip(e.target_name, 64);
        let reason = clip(e.reason, 200);
        let entries = db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            let mut entries = 0;
            if let Some(a) = &account {
                entries = sqlx::query(
                    "DELETE FROM voipc_log WHERE sender = $1 AND conv LIKE 'c:%' AND server_at >= $2 AND server_at <= $3",
                )
                .bind(&a[..])
                .bind(since_ms)
                .bind(before_ms)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
            let plural = if entries == 1 { "" } else { "s" };
            let mut rows = 0i64;
            for id in imported.ids {
                sqlx::query(archive::WISH_UP)
                    .bind(*id)
                    .bind(0i64)
                    .bind(imported.low)
                    .bind(imported.high)
                    .bind(true)
                    .bind(util::now())
                    .execute(&mut *tx)
                    .await?;
                rows += sqlx::query_scalar::<_, i64>(archive::ROWS_BY)
                    .bind(*id)
                    .bind(1i64)
                    .bind(i64::MAX)
                    .bind(imported.low)
                    .bind(imported.high)
                    .fetch_one(&mut *tx)
                    .await?;
            }
            let from_discord = if rows > 0 && imported.say_how_many {
                format!(", {} imported", counted(rows as u64))
            } else {
                String::new()
            };
            sqlx::query(
                "INSERT INTO voipc_modlog (at, action, actor, actor_name, target, target_name, reason, detail, since_ms, before_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(util::now())
            .bind(e.action)
            .bind(e.actor.map(|a| a.to_vec()))
            .bind(&actor_name)
            .bind(e.target.map(|a| a.to_vec()))
            .bind(&target_name)
            .bind(&reason)
            .bind(format!("{entries} kept message{plural}, {window}{from_discord}"))
            .bind(since_ms)
            .bind(before_ms)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            entries
        });
        Ok(entries)
    }

    /// The removals still in the log, newest first, as a client is told of them.
    pub(super) async fn modlog_marks(&self) -> Result<Vec<PostsMark>> {
        let rows: Vec<MarkRow> = db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT target, target_name, since_ms, before_ms, actor_name
                 FROM voipc_modlog WHERE action = 'remove_posts' ORDER BY id DESC LIMIT $1",
            )
            .bind(MARKS_AT_CONNECT)
            .fetch_all(pool)
            .await?
        });
        Ok(rows
            .into_iter()
            .map(|(account, name, since_ms, before_ms, by)| PostsMark {
                account: account.and_then(|a| a.try_into().ok()),
                name,
                since_ms: since_ms.unwrap_or(0).max(0) as u64,
                before_ms: before_ms.unwrap_or(0).max(0) as u64,
                by,
            })
            .collect())
    }

    pub async fn modlog_put(&self, e: &Entry<'_>) -> Result<()> {
        let channel_key = (!e.channel_key.is_empty()).then(|| e.channel_key.to_string());
        let channel_name = (!e.channel_name.is_empty()).then(|| clip(e.channel_name, 64));
        let actor_name = clip(e.actor_name, 64);
        let target_name = clip(e.target_name, 64);
        let reason = clip(e.reason, 200);
        let detail = clip(e.detail, 255);
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_modlog (at, action, actor, actor_name, target, target_name, channel_key, channel_name, reason, detail)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(util::now())
            .bind(e.action)
            .bind(e.actor.map(|a| a.to_vec()))
            .bind(&actor_name)
            .bind(e.target.map(|a| a.to_vec()))
            .bind(&target_name)
            .bind(&channel_key)
            .bind(&channel_name)
            .bind(&reason)
            .bind(&detail)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// Newest first, older than id `before`; one row past `limit` says there is more.
    pub(super) async fn modlog_rows(&self, before: i64, limit: usize) -> Result<Vec<Row>> {
        let before = if before == 0 { i64::MAX } else { before };
        let rows: Vec<Row> = db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT id, at, action, actor_name, target_name, channel_key, channel_name, reason, detail
                 FROM voipc_modlog WHERE id < $1 ORDER BY id DESC LIMIT $2",
            )
            .bind(before)
            .bind(limit as i64 + 1)
            .fetch_all(pool)
            .await?
        });
        Ok(rows)
    }

    pub(super) async fn modlog_notes_since(&self, actor: [u8; 16], since: i64) -> Result<i64> {
        let n: i64 = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_modlog
                 WHERE actor = $1 AND at > $2 AND action IN ('hide', 'unhide')",
            )
            .bind(&actor[..])
            .bind(since)
            .fetch_one(pool)
            .await?
        });
        Ok(n)
    }
}

/// A step's row, written as `session_id`. `Err`: no row, so no step. A relay
/// without accounts has no database and no log.
pub async fn put(state: &ServerState, session_id: u32, entry: Entry<'_>) -> Result<()> {
    let Some(relay) = &state.accounts else {
        return Ok(());
    };
    let actor = state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.user.id.0));
    let actor_name = crate::session::banned_by(state, session_id);
    relay
        .modlog_put(&Entry {
            actor,
            actor_name: &actor_name,
            ..entry
        })
        .await
}

/// Someone a step acts on, as a row names them: as anyone but an admin sees them,
/// even when an admin acts, since people who are no admin read it later. Under a
/// pseudonym there is no account, so the database does not tie the two together.
/// `channel`: where they were acted on; a server-wide step goes by any.
pub async fn target_of(
    state: &ServerState,
    target: UserId,
    channel: Option<ChannelId>,
) -> (Option<[u8; 16]>, String) {
    let (real, alias) = match channel {
        Some(c) => state.names_of_in(c, target).await,
        None => state.names_of(target).await,
    };
    let account = state
        .sessions
        .get(&target)
        .and_then(|s| s.account.as_ref().map(|a| a.user.id.0))
        .filter(|_| alias.is_none());
    (account, pick_name(&real, &alias, false))
}

/// What `AdminOp::ModLog` answers. A channel goes by name only to `*`, or to a
/// reader who can see it now. One hiding its members is `*`'s alone: a row says who
/// was in it. Why someone was restricted goes only to holders of `voipc:restrict`,
/// as it does live.
pub async fn page(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    scopes: &[String],
    before: i64,
) -> AccountReply {
    let rows = match relay.modlog_rows(before, PAGE_ROWS).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!("reading the moderation log: {e:#}");
            return refused("Admin", "Could not read the moderation log.");
        }
    };
    let star = is_star(scopes);
    let reads_restrictions = scope::allowed(scopes, super::RESTRICT);
    let visible: HashSet<String> = state
        .channels
        .read()
        .await
        .values()
        .filter(|c| !c.gate_key.is_empty())
        .filter(|c| !c.info.hide_members && state.passes(session_id, &c.gate.groups))
        .map(|c| c.gate_key.clone())
        .collect();
    let mut more = rows.len() > PAGE_ROWS;
    let mut bytes = 0;
    let mut out = Vec::new();
    for (id, at, action, actor, target, key, name, mut reason, detail) in
        rows.into_iter().take(PAGE_ROWS)
    {
        let channel = name.filter(|_| star || key.is_some_and(|k| visible.contains(&k)));
        if action == "restrict" && !reads_restrictions {
            reason.clear();
        }
        bytes += ROW_OVERHEAD
            + action.len()
            + actor.len()
            + target.len()
            + channel.as_ref().map_or(0, String::len)
            + reason.len()
            + detail.len();
        if bytes > PAGE_BYTES {
            more = true;
            break;
        }
        out.push(ModRow {
            id,
            at,
            advisory: ADVISORY.contains(&action.as_str()),
            action,
            actor,
            target,
            channel,
            reason,
            detail,
        });
    }
    AccountReply::Admin(AdminReply::ModLog {
        before,
        rows: out,
        more,
        keep_days: relay.modlog_days,
    })
}

/// `AdminOp::ModNote`. It cannot accuse anyone else, since the actor is the session;
/// it can lie about its own hide, or be left out by a modified app. An anonymous
/// channel takes no note: a name in one could only be someone's pseudonym or the
/// real name behind it.
pub async fn note(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    channel_id: ChannelId,
    target: &str,
    message: &str,
    on: bool,
) -> AccountReply {
    let channel = state
        .channels
        .read()
        .await
        .get(&channel_id)
        .filter(|c| state.passes(session_id, &c.gate.groups))
        .map(|c| (c.gate_key.clone(), c.info.name.clone(), c.info.anonymous));
    let Some((key, name, anonymous)) = channel else {
        return refused("Admin", "channel does not exist");
    };
    if anonymous {
        return refused("Admin", "An anonymous channel takes no notes.");
    }
    let actor = state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.user.id.0));
    let Some(actor) = actor else {
        return refused("Admin", "Sign in with an account first.");
    };
    let kept = async {
        if relay.modlog_notes_since(actor, util::now() - 3600).await? >= NOTES_PER_HOUR {
            return Ok(false);
        }
        put(
            state,
            session_id,
            Entry {
                action: if on { "hide" } else { "unhide" },
                target_name: target,
                channel_key: &key,
                channel_name: &name,
                detail: &clip(message, 64),
                ..Default::default()
            },
        )
        .await
        .map(|()| true)
    };
    match kept.await {
        Ok(true) => AccountReply::Admin(AdminReply::ChannelDone { channel_id: None }),
        Ok(false) => refused("Admin", "Too many notes for one hour. Try again later."),
        Err(e) => {
            warn!("keeping a moderation note: {e:#}");
            refused("Admin", "That could not be kept.")
        }
    }
}

/// Who a removal is about, once it may go ahead.
pub struct Removal {
    /// Whose stored messages go. None: a guest, or a pseudonym, with none to go.
    account: Option<[u8; 16]>,
    /// The Discord ids that account has linked, for what came from there.
    discord: Vec<i64>,
    /// What the one asking knows them by, and is answered with.
    name: String,
    ban: Ban,
    window_secs: u32,
}

/// The checks of `AdminOp::RemovePosts` before it asks for a code: banned now, so that
/// no member in good standing is wiped quietly; nobody who holds a privilege unless an
/// admin asks, stricter than `scope::covers` because this cannot be undone; and how far
/// back. `Err`: why not.
///
/// Someone who is no admin goes by the name the ban shows them (`Ban::name_for`). Any
/// other name, the real one behind a pseudonym too, answers as for someone not banned,
/// so that this cannot test a guess, and nothing here hands the real name back.
pub async fn removal_of(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    scopes: &[String],
    name: &str,
    window_secs: u32,
) -> Result<Result<Removal, &'static str>> {
    let admin = state.is_admin(session_id);
    // A guest's name has a tag. An account can be called what a pseudonym is, in lower
    // case, so `guest-1234` is the account's and only `Guest-1234` the pseudonym.
    let user = match scope::normalize_username(name, &[]) {
        Ok(clean) if !is_pseudonym(name) => relay.store().user_by_username(&clean).await?,
        _ => None,
    };
    let (account, discord, name, ban) = match user {
        Some(user) => {
            let ban = crate::bans::account_ban(state, user.id.0)
                .filter(|ban| admin || ban.log_name() == user.username);
            let Some(ban) = ban else {
                return Ok(Err("Ban the account first."));
            };
            if !admin && holds_power(&relay.store().user_scopes(user.id).await?) {
                return Ok(Err(
                    "Only an admin can remove the posts of someone with privileges.",
                ));
            }
            // Whoever took Discord off first is still who those rows are filed under. Not in
            // `discord_ids`, which also says what is theirs to hide
            let mut discord = archive::discord_ids(relay, user.id).await?;
            discord.extend(relay.placeholder_dc_id(user.id).await?);
            discord.sort_unstable();
            discord.dedup();
            (Some(user.id.0), discord, user.username, ban)
        }
        None => {
            let Some(ban) = crate::bans::address_ban_as(state, name, admin) else {
                return Ok(Err("Nobody is banned under that name."));
            };
            (None, Vec::new(), ban.name_for(admin).to_string(), ban)
        }
    };
    if (window_secs == 0 || window_secs > REMOVAL_MAX_SECS) && !is_star(scopes) {
        return Ok(Err(
            "Only an admin can remove more than the last seven days.",
        ));
    }
    Ok(Ok(Removal {
        account,
        discord,
        name,
        ban,
        window_secs,
    }))
}

/// `AdminOp::RemovePosts`, past its checks and its code. Everybody is told, whatever
/// channels they are in, and the marks stay in the log for whoever connects later.
///
/// Someone banned behind a pseudonym stays behind it: their row has that name and no
/// account, like the ban's, and that is all anybody hears, online or connecting later.
/// Only the admin who asked by the real name is answered by it.
pub async fn remove_posts(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    who: Removal,
) -> AccountReply {
    let Removal {
        account,
        discord,
        name,
        ban,
        window_secs,
    } = who;
    let before_ms = super::log::now_ms();
    let since_ms = match window_secs {
        0 => 0,
        w => (before_ms - i64::from(w) * 1000).max(0),
    };
    let target = account.filter(|_| ban.log_name() == name);
    let by = crate::session::banned_by(state, session_id);
    let row = Entry {
        action: "remove_posts",
        actor: state
            .sessions
            .get(&session_id)
            .and_then(|s| s.account.as_ref().map(|a| a.user.id.0)),
        actor_name: &by,
        target,
        target_name: ban.log_name(),
        reason: &ban.reason,
        ..Default::default()
    };
    let window = window_words(window_secs);
    // By when it was written, as the dialog says. Everything is all of it
    let (low, high) = match window_secs {
        0 => (0, i64::MAX),
        _ => (snowflake_floor(since_ms), snowflake_floor(before_ms)),
    };
    let imported = Imported {
        ids: &discord,
        low,
        high,
        say_how_many: ban.log_name() == name,
    };
    let entries = match relay
        .posts_remove(account, imported, since_ms, before_ms, &window, &row)
        .await
    {
        Ok(entries) => entries,
        Err(e) => {
            warn!("removing posts: {e:#}");
            return refused("Admin", "That could not be kept, so nothing was removed.");
        }
    };
    if !discord.is_empty() {
        if let Err(e) = relay.archive_changed().await {
            warn!("reading the archive's wishes: {e:#}");
        }
    }
    let told = ServerMessage::PostsHidden {
        marks: vec![PostsMark {
            account: target,
            name: ban.log_name().to_string(),
            since_ms: since_ms as u64,
            before_ms: before_ms as u64,
            by,
        }],
    };
    match encode_server_msg(&told) {
        Ok(data) => state.broadcast_raw_to_all(&data).await,
        Err(e) => warn!("telling of a removal: {e:#}"),
    }
    AccountReply::Admin(AdminReply::PostsRemoved { name, entries })
}

/// `marks` in frames a client can take.
fn mark_frames(marks: Vec<PostsMark>) -> Vec<Vec<PostsMark>> {
    let mut frames = Vec::new();
    let mut frame = Vec::new();
    let mut bytes = 0;
    for mark in marks {
        let size = MARK_OVERHEAD + mark.name.len() + mark.by.len();
        if bytes + size > MARK_BYTES {
            frames.push(std::mem::take(&mut frame));
            bytes = 0;
        }
        bytes += size;
        frame.push(mark);
    }
    if !frame.is_empty() {
        frames.push(frame);
    }
    frames
}

/// A client that just connected: what this server says it removed. To guests too,
/// since a member can hand them a copy.
pub async fn send_marks(state: &ServerState, tx: &ControlTx) {
    let Some(relay) = &state.accounts else {
        return;
    };
    match relay.modlog_marks().await {
        Ok(marks) => {
            for marks in mark_frames(marks) {
                let _ = crate::session::send_msg(tx, &ServerMessage::PostsHidden { marks });
            }
        }
        Err(e) => warn!("reading what was removed: {e:#}"),
    }
}

/// Rows past `modlog_days`; run with the hourly sweep. By time alone: evicting by
/// count would let a moderator flush their own bans out with notes.
pub async fn sweep(relay: &Relay) -> Result<u64> {
    let cutoff = util::now() - i64::from(relay.modlog_days) * 86_400;
    let n = db!(relay.store(), pool => {
        sqlx::query("DELETE FROM voipc_modlog WHERE at < $1").bind(cutoff).execute(pool).await?.rows_affected()
    });
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ban_says_how_long_in_words() {
        assert_eq!(ban_detail("account", 0), "account, permanent");
        assert_eq!(ban_detail("address", 3600), "address, 1 hour");
        assert_eq!(
            ban_detail("address and account", 86_400 * 7),
            "address and account, 7 days"
        );
        assert_eq!(ban_detail("address", 90), "address, 2 minutes");
    }

    #[test]
    fn a_removal_says_how_far_back_in_words() {
        assert_eq!(window_words(0), "everything kept");
        assert_eq!(window_words(3600), "last hour");
        assert_eq!(window_words(86_400), "last day");
        assert_eq!(window_words(86_400 * 7), "last 7 days");
    }

    /// Everything a connect is told fits the frames it travels in, and nothing goes
    /// missing. The control: all of it in one message would not.
    #[test]
    fn the_longest_marks_fit_their_frames_and_lose_nothing() {
        let mark = |i: usize| PostsMark {
            account: Some([7; 16]),
            name: format!("{i:05}{}", "ü".repeat(59)),
            since_ms: u64::MAX,
            before_ms: u64::MAX,
            by: "ü".repeat(64),
        };
        let marks: Vec<PostsMark> = (0..MARKS_AT_CONNECT as usize).map(mark).collect();
        assert!(
            encode_server_msg(&ServerMessage::PostsHidden {
                marks: marks.clone()
            })
            .is_err(),
            "one message cannot hold them, or this tests nothing"
        );
        let frames = mark_frames(marks.clone());
        assert!(frames.len() > 1);
        for frame in &frames {
            encode_server_msg(&ServerMessage::PostsHidden {
                marks: frame.clone(),
            })
            .expect("fits a frame");
        }
        assert_eq!(frames.concat(), marks);
    }

    #[test]
    fn a_clip_counts_characters_and_takes_what_postgres_refuses() {
        assert_eq!(clip("ab\0c\nd", 3), "abc");
        assert_eq!(clip(&"ü".repeat(100), 64).chars().count(), 64);
    }
}
