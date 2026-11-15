//! `voipc_archive` (protocol v20): what came from Discord. The one thing here this relay can
//! read, labelled as such, and apart from every live message: a row is never a `ChatMessage`.
//!
//! A row names a Discord id, not an account, so what someone said about it lives apart
//! (`voipc_archive_wishes`, `voipc_import_excluded`) and outlives it, an undo and a new
//! import: nothing filed here can bring back what they deleted. Wishes are read from memory,
//! so filing and reading stop at once and the rows themselves can go in batches later.
//!
//! Who may read is who stands in the channel now, which its gate, password and kicks have
//! already decided. Who opens what, and what they search for, is new knowledge for the relay:
//! it goes in no log, no counter and no row.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::oauth::Kind;
use l4f_accounts::store::Store;
use l4f_accounts::util;
use serde::Serialize;
use tracing::warn;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;
use voipc_protocol::discord::{snowflake_floor, snowflake_ms};
use voipc_protocol::messages::{AccountReply, AdminReply};
use voipc_protocol::types::{
    ArchiveAction, ArchiveReaction, ArchiveRow, ArchiveScope, ArchiveTarget, ArchiveWish,
    ChannelId, ImportAttachment, ImportMessage, ImportReaction, ImportThread, SessionId,
    IMPORT_BODY_BYTES, IMPORT_FRAME_ROWS, IMPORT_MESSAGE_ROWS, THREAD_TAKEN_BACK,
};

use super::import::{no_frame, CURSOR_UP, KIND_THREAD_MADE};
use super::modlog::{self, clip};
use super::placeholder::id_ok;
use super::{is_star, log, refused, Relay};
use crate::session::bad_name_char;
use crate::state::ServerState;

/// VARCHAR limits hold on Postgres only: these are in characters, as those are.
const AUTHOR_CHARS: usize = 64;
const THREAD_CHARS: usize = 100;
const MAX_REACTIONS: usize = 20;
const EMOJI_CHARS: usize = 64;
const MAX_ATTACHMENTS: usize = 20;
const FILE_NAME_CHARS: usize = 128;
const MIME_CHARS: usize = 64;

const NOT_RIGHT: &str = "That frame cannot be right.";
const NOT_ACKNOWLEDGED: &str = "This run did not say yes to copying messages: begin it again.";
/// The same words for a channel not there, one behind a gate, and one not joined.
const JOIN_FIRST: &str = "Join the channel first.";
const NOT_AN_ID: &str = "That is not a Discord id.";
const LINK_FIRST: &str =
    "Link your Discord account first: that is how this server knows which posts are yours.";
const SHOW_THOSE_FIRST: &str = "This is hidden with the rest of yours here. Show those first.";
const WISHES_FULL: &str = "Hide or delete everything of yours here instead.";
const SEARCH_BUSY: &str = "The server is busy searching. Try again in a moment.";

/// How long what `archive_held` read holds. An import's end and an undo drop it, and their last
/// frame sends the layout, on which every app online asks again.
const HELD_KEPT: Duration = Duration::from_secs(60);
/// Rows a page holds at most.
const PAGE_ROWS: usize = 200;
/// And bytes: a reply over a frame is not sent at all.
const PAGE_BYTES: usize = 44 * 1024;
/// A row's numbers and the lengths of its strings, at most.
const ROW_OVERHEAD: usize = 96;
/// A reaction's count and the length of its emoji, at most.
const REACTION_OVERHEAD: usize = 8;
/// Searches at once on a relay.
pub(super) const SEARCHES: usize = 2;
/// Rows a search reads at a time. Small enough that its task yields often.
const SEARCH_CHUNK: i64 = 2000;
const SEARCH_HITS: usize = 50;
/// What holds on a slow disk: a request takes at most a chunk longer than this.
const SEARCH_TIME: Duration = Duration::from_millis(200);
const QUERY_BYTES: usize = 200;
const QUERY_WORDS: usize = 8;
/// What one account can say about single rows: every wish lives in memory.
const WISHES_PER_AUTHOR: i64 = 1000;
/// Rows of `AdminReply::ArchiveWishes` a reply holds: at most 37 bytes each, under one frame.
const WISHES_PAGE: i64 = 1000;
/// Rows a transaction of the worker takes, and its breath after: SQLite has one writer, and
/// everyone's sign-ins wait behind it.
pub(crate) const BATCH: i64 = 5000;
const BREATHE: Duration = Duration::from_millis(50);
const TIDY_EVERY: Duration = Duration::from_secs(3600);

/// What a reader may get of a row, in one order. Never `attachments`: those are names for a
/// later backfill. A macro so that each statement stays one `&'static str`.
macro_rules! reading {
    ($rest:literal) => {
        concat!(
            "SELECT thread, dc_id, author_dc_id, author_name, body, reply_to, reactions, \
             thread_name, replies, pinned FROM voipc_archive ",
            $rest
        )
    };
}

/// (thread, id, author, name, body, reply_to, reactions, thread_name, replies, pinned)
pub(super) type ReadRow = (
    i64,
    i64,
    Option<i64>,
    String,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    i32,
    bool,
);

/// What someone said, once. A hide can never soften a delete.
pub(super) const WISH_UP: &str = "INSERT INTO voipc_archive_wishes \
     (author_dc_id, channel, low, high, erase, at) VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (author_dc_id, channel, low, high) DO UPDATE \
     SET erase = voipc_archive_wishes.erase OR excluded.erase";

/// One author's rows in some channels and a span of ids.
pub(super) const ROWS_BY: &str = "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_archive \
     WHERE author_dc_id = $1 AND channel BETWEEN $2 AND $3 AND dc_id BETWEEN $4 AND $5";
const ROWS_ANYONE: &str = "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_archive \
     WHERE channel BETWEEN $1 AND $2 AND dc_id BETWEEN $3 AND $4";

/// A thread's opening row is not among these: `ROOT_BY` and `ROOT_ANYONE` have it.
const ERASE_BY: &str = "DELETE FROM voipc_archive WHERE (channel, thread, dc_id) IN \
     (SELECT channel, thread, dc_id FROM voipc_archive \
      WHERE author_dc_id = $1 AND channel BETWEEN $2 AND $3 AND dc_id BETWEEN $4 AND $5 \
      AND thread_name IS NULL LIMIT $6)";
/// By anyone, in one channel (`$1`) or in all (`ERASE_ANYONE_ALL`): two statements, so that
/// each is a range of an index, `(channel, dc_id)` or `(dc_id)`. With `channel BETWEEN` the
/// planner walked the primary key over the whole channel, every pass (W2-3).
const ERASE_ANYONE: &str = "DELETE FROM voipc_archive WHERE (channel, thread, dc_id) IN \
     (SELECT channel, thread, dc_id FROM voipc_archive \
      WHERE channel = $1 AND dc_id BETWEEN $2 AND $3 \
      AND thread_name IS NULL LIMIT $4)";
const ERASE_ANYONE_ALL: &str = "DELETE FROM voipc_archive WHERE (channel, thread, dc_id) IN \
     (SELECT channel, thread, dc_id FROM voipc_archive \
      WHERE dc_id BETWEEN $1 AND $2 \
      AND thread_name IS NULL LIMIT $3)";

/// A thread's opening row someone took back keeps only that a thread is here: the replies in
/// it are other people's, and it is the way in to them. A macro so that each statement stays
/// one `&'static str`. `$1` is the neutral name.
macro_rules! root_taken_back {
    ($which:literal) => {
        concat!(
            "UPDATE voipc_archive SET author_dc_id = NULL, author_name = '', body = '', \
             reply_to = NULL, reactions = NULL, attachments = NULL, pinned = FALSE, thread_name = $1 \
             WHERE (channel, thread, dc_id) IN (SELECT channel, thread, dc_id FROM voipc_archive \
             WHERE thread_name IS NOT NULL AND ",
            $which,
            ")"
        )
    };
}
const ROOT_BY: &str = root_taken_back!(
    "author_dc_id = $2 AND channel BETWEEN $3 AND $4 AND dc_id BETWEEN $5 AND $6 LIMIT $7"
);
/// Only what is not that already: this wish still covers the row afterwards. In one channel
/// or in all, as `ERASE_ANYONE`.
const ROOT_ANYONE: &str = root_taken_back!(
    "channel = $2 AND dc_id BETWEEN $3 AND $4 \
     AND (author_dc_id IS NOT NULL OR author_name <> '' OR body <> '' OR reply_to IS NOT NULL \
     OR reactions IS NOT NULL OR attachments IS NOT NULL OR pinned = TRUE OR thread_name <> $1) \
     LIMIT $5"
);
const ROOT_ANYONE_ALL: &str = root_taken_back!(
    "dc_id BETWEEN $2 AND $3 \
     AND (author_dc_id IS NOT NULL OR author_name <> '' OR body <> '' OR reply_to IS NOT NULL \
     OR reactions IS NOT NULL OR attachments IS NOT NULL OR pinned = TRUE OR thread_name <> $1) \
     LIMIT $4"
);
/// A row a frame dropped, if a thread opens on it: a run files its threads first.
const ROOT_ONE: &str = root_taken_back!("channel = $2 AND thread = 0 AND dc_id = $3");
const ERASE_CHANNEL: &str = "DELETE FROM voipc_archive WHERE (channel, thread, dc_id) IN \
     (SELECT channel, thread, dc_id FROM voipc_archive WHERE channel = $1 LIMIT $2)";
/// Past `archive_days`, but its thread has replies inside: it is the way in to them, so it
/// keeps that a thread is here, and none of its words (W2-7). Only what is not that already.
const ROOT_OLD: &str = root_taken_back!(
    "channel = $2 AND thread = 0 AND dc_id < $3 \
     AND EXISTS (SELECT 1 FROM voipc_archive r \
       WHERE r.channel = $2 AND r.thread = voipc_archive.dc_id AND r.dc_id >= $3) \
     AND (author_dc_id IS NOT NULL OR author_name <> '' OR body <> '' OR reply_to IS NOT NULL \
     OR reactions IS NOT NULL OR attachments IS NOT NULL OR pinned = TRUE OR thread_name <> $1) \
     LIMIT $4"
);
/// Past `archive_days`, but not a thread's opening row while its thread has replies inside.
const ERASE_OLD: &str = "DELETE FROM voipc_archive WHERE (channel, thread, dc_id) IN \
     (SELECT a.channel, a.thread, a.dc_id FROM voipc_archive a WHERE a.channel = $1 AND a.dc_id < $2 \
      AND NOT (a.thread = 0 AND a.thread_name IS NOT NULL AND EXISTS (SELECT 1 FROM voipc_archive r \
        WHERE r.channel = $1 AND r.thread = a.dc_id AND r.dc_id >= $2)) LIMIT $3)";

/// The statements a tidy pass repeats, for the Round C measurement's query plans.
#[cfg(test)]
pub(crate) const PLANNED: [&str; 8] = [
    ERASE_BY,
    ERASE_ANYONE,
    ERASE_ANYONE_ALL,
    ROOT_BY,
    ROOT_ANYONE,
    ROOT_ANYONE_ALL,
    ROOT_OLD,
    ERASE_OLD,
];

const FILE_ROW: &str =
    "INSERT INTO voipc_archive (channel, thread, dc_id, author_dc_id, author_name, \
     body, reply_to, reactions, attachments, pinned, import_id) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
     ON CONFLICT (channel, thread, dc_id) DO UPDATE SET \
     author_dc_id = excluded.author_dc_id, author_name = excluded.author_name, \
     body = excluded.body, reply_to = excluded.reply_to, reactions = excluded.reactions, \
     attachments = excluded.attachments, pinned = excluded.pinned";

/// `$7` is the neutral name. Who named a thread counts as its author only on a row with no name
/// and no words: words with no id on them are an anonymised person's or a webhook's. Filed
/// neutral, such a row is that from then on, and only its count moves: a later run names the
/// thread again, and its owner need not be who took the words back.
const FILE_THREAD: &str = "INSERT INTO voipc_archive (channel, thread, dc_id, author_dc_id, \
     author_name, body, thread_name, replies, import_id) VALUES ($1, 0, $2, $3, '', '', $4, $5, $6) \
     ON CONFLICT (channel, thread, dc_id) DO UPDATE SET author_dc_id = CASE \
     WHEN voipc_archive.author_name <> '' OR voipc_archive.body <> '' THEN voipc_archive.author_dc_id \
     WHEN voipc_archive.author_dc_id IS NULL AND voipc_archive.thread_name = $7 THEN NULL \
     WHEN excluded.author_dc_id IS NULL AND excluded.thread_name = $7 THEN NULL \
     ELSE COALESCE(voipc_archive.author_dc_id, excluded.author_dc_id) END, \
     thread_name = CASE WHEN voipc_archive.author_dc_id IS NULL AND voipc_archive.author_name = '' \
     AND voipc_archive.body = '' AND voipc_archive.thread_name = $7 \
     THEN voipc_archive.thread_name ELSE excluded.thread_name END, replies = excluded.replies";

/// What someone said about some rows. `channel` 0: every channel. `low..=high`: Discord ids,
/// so one message, a time span or everything. Without `erase`, hidden from all but its author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wish {
    pub channel: i64,
    pub low: i64,
    pub high: i64,
    pub erase: bool,
}

/// By author's Discord id. Key 0: whoever wrote it. Replaced whole on a change, and never
/// read across an await.
pub type Wishes = HashMap<i64, Vec<Wish>>;

/// What the wishes come to for one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Shown,
    /// To its author alone.
    Hidden,
    /// To nobody, and an import does not take it.
    Erased,
}

/// What a row `id` in `channel` by `author` (None: anonymised, or a webhook's) has come to.
/// Erased wins over hidden, whichever came first.
pub fn verdict(wishes: &Wishes, author: Option<i64>, channel: i64, id: i64) -> Verdict {
    let lists = [author.and_then(|a| wishes.get(&a)), wishes.get(&0)];
    let mut said = Verdict::Shown;
    for wish in lists.into_iter().flatten().flatten() {
        if (wish.channel == 0 || wish.channel == channel) && (wish.low..=wish.high).contains(&id) {
            if wish.erase {
                return Verdict::Erased;
            }
            said = Verdict::Hidden;
        }
    }
    said
}

impl Relay {
    pub(crate) fn wishes(&self) -> Arc<Wishes> {
        self.archive_wishes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) async fn archive_private(&self, conv: &str) -> Result<bool> {
        let row: Option<bool> = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT archive_private FROM voipc_channels WHERE conv = $1")
                .bind(conv)
                .fetch_optional(pool)
                .await?
        });
        Ok(row.unwrap_or(false))
    }

    /// From now on what this channel keeps counts as private. One way, as the column says.
    pub(crate) async fn archive_private_set(&self, conv: &str) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_channels SET archive_private = $1 WHERE conv = $2")
                .bind(true)
                .bind(conv)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// Whether this channel's key names a Discord channel with rows under it, hidden or wordless
    /// ones too. One made in the app has a random uid, and so none.
    pub(crate) async fn holds_archive(&self, conv: &str) -> Result<bool> {
        match dc_channel(conv) {
            Some(channel) => self.channel_holds_rows(channel).await,
            None => Ok(false),
        }
    }

    async fn channel_holds_rows(&self, channel: i64) -> Result<bool> {
        let row: Option<i64> = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT channel FROM voipc_archive WHERE channel = $1 LIMIT 1")
                .bind(channel)
                .fetch_optional(pool)
                .await?
        });
        Ok(row.is_some())
    }

    /// Which of these Discord channels hold rows. Read at most once a minute however many
    /// connect at once: a relay's restart is everyone asking in the same few seconds.
    async fn archive_held(&self, all: Vec<i64>) -> Result<Arc<HashSet<i64>>> {
        let mut held = self.archive_held.lock().await;
        if let Some((at, set)) = held.as_ref() {
            if at.elapsed() < HELD_KEPT {
                return Ok(set.clone());
            }
        }
        let mut set = HashSet::new();
        for channel in all {
            if self.channel_holds_rows(channel).await? {
                set.insert(channel);
            }
        }
        let set = Arc::new(set);
        *held = Some((Instant::now(), set.clone()));
        Ok(set)
    }

    /// An import ended or was undone: which channels hold rows is read afresh.
    pub(super) async fn archive_held_changed(&self) {
        *self.archive_held.lock().await = None;
    }

    /// What people said about rows changed: it holds from here on, and the rows go soon.
    pub(super) async fn archive_changed(&self) -> Result<()> {
        load(self).await?;
        self.archive_kick.notify_one();
        Ok(())
    }
}

/// The wishes from the database, whole. Someone left out who asked for it, or who deleted
/// their account, counts as a wish for everything; someone merely held does not, and their
/// posts keep arriving.
pub async fn load(relay: &Relay) -> Result<()> {
    type WishRow = (i64, i64, i64, i64, bool);
    let (rows, erased): (Vec<WishRow>, Vec<i64>) = db!(relay.store(), pool => {
        (
            sqlx::query_as(
                "SELECT CAST(author_dc_id AS BIGINT), CAST(channel AS BIGINT), CAST(low AS BIGINT),
                        CAST(high AS BIGINT), erase FROM voipc_archive_wishes",
            )
            .fetch_all(pool)
            .await?,
            sqlx::query_scalar("SELECT CAST(dc_id AS BIGINT) FROM voipc_import_excluded WHERE erase = $1")
                .bind(true)
                .fetch_all(pool)
                .await?,
        )
    });
    let mut wishes = Wishes::new();
    for (author, channel, low, high, erase) in rows {
        wishes.entry(author).or_default().push(Wish {
            channel,
            low,
            high,
            erase,
        });
    }
    // Key 0 is whoever wrote it: an id of 0, however it got here, must not mean everybody
    for id in erased.into_iter().filter(|id| *id != 0) {
        wishes.entry(id).or_default().push(Wish {
            channel: 0,
            low: 0,
            high: i64::MAX,
            erase: true,
        });
    }
    *relay
        .archive_wishes
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Arc::new(wishes);
    Ok(())
}

/// Whether rows may be filed under this Discord channel now: `Err` says why not, and a
/// driver skips that channel. A gate opened between runs comes here too: what was private
/// on Discord must not land where everyone can read it.
pub(crate) async fn may_file(
    state: &ServerState,
    relay: &Relay,
    channel: i64,
) -> Result<Result<(), &'static str>> {
    let conv = format!("c:dc-{channel}");
    let open = match state
        .channels
        .read()
        .await
        .values()
        .find(|c| c.gate_key == conv)
    {
        Some(c) => crate::gates::open_to_all(&c.gate.groups),
        None => return Ok(Err("That channel was removed here.")),
    };
    if !relay.cloud {
        return Ok(Err(
            "This server keeps no messages: set cloud = true first.",
        ));
    }
    if open && relay.archive_private(&conv).await? {
        return Ok(Err(
            "This channel was private on Discord. Give it a gate first.",
        ));
    }
    Ok(Ok(()))
}

/// A body as it is kept: what a person can read, with its lines. Postgres refuses a NUL, and
/// `clip` would eat the newlines.
fn clean_body(body: &str) -> String {
    body.chars()
        .filter(|c| *c >= ' ' || matches!(c, '\n' | '\t'))
        .collect()
}

/// A name as `session::bad_name_char` has names: nothing invisible, nothing it can hide behind.
fn clean_name(name: &str, chars: usize) -> String {
    let kept: String = name
        .chars()
        .filter(|c| !bad_name_char(*c))
        .take(chars)
        .collect();
    // One of only what draws nothing is none: a blank author, or a blank thread (W1-36)
    if voipc_protocol::names::draws_something(&kept) {
        kept.trim().to_string()
    } else {
        String::new()
    }
}

/// A thread's name as kept. One that shows nothing goes by the neutral name: an empty one
/// would be no way in to its replies (`thread_name` is what marks an opening row).
fn thread_title(name: &str) -> String {
    let name = clean_name(name, THREAD_CHARS);
    if name.is_empty() {
        THREAD_TAKEN_BACK.to_string()
    } else {
        name
    }
}

/// JSON, or NULL for nothing, so most rows pay nothing.
fn json_of<T: Serialize>(rows: Vec<T>) -> Result<Option<String>> {
    Ok(if rows.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&rows)?)
    })
}

/// A row ready for its table, whatever the importer did.
struct Filed {
    thread: i64,
    id: i64,
    author: Option<i64>,
    name: String,
    body: String,
    reply_to: Option<i64>,
    reactions: Option<String>,
    attachments: Option<String>,
    pinned: bool,
}

fn filed(row: &ImportMessage, thread: i64) -> Result<Filed> {
    let reactions = row
        .reactions
        .iter()
        .take(MAX_REACTIONS)
        .map(|r| ImportReaction {
            emoji: clip(&r.emoji, EMOJI_CHARS),
            count: r.count,
        })
        .collect();
    let attachments = row
        .attachments
        .iter()
        .take(MAX_ATTACHMENTS)
        .map(|a| ImportAttachment {
            id: a.id,
            name: clip(&a.name, FILE_NAME_CHARS),
            bytes: a.bytes,
            mime: clip(&a.mime, MIME_CHARS),
        })
        .collect();
    let id = row.id as i64;
    Ok(Filed {
        // A thread's first message can have the thread's id: it is the root, not filed twice
        thread: if id == thread { 0 } else { thread },
        id,
        author: row.author.map(|a| a as i64),
        name: clean_name(&row.author_name, AUTHOR_CHARS),
        body: clean_body(&row.body),
        reply_to: row.reply_to.map(|r| r as i64),
        reactions: json_of(reactions)?,
        attachments: json_of(attachments)?,
        pinned: row.pinned,
    })
}

/// One frame and its cursor (uid, high), all or nothing, so a crash cannot pass what was
/// stored. A row keeps the run that first brought it, so undoing a delta leaves it, and only
/// `archive_threads` writes a thread's name and count. Rows wished away are counted and
/// dropped, so neither a delta nor a run after an undo brings them back, and a thread opening on
/// one is left neutral, as the worker would: its name may be those words. `Ok`: (stored, skipped).
pub(super) async fn archive_put(
    relay: &Relay,
    import_id: i64,
    channel: i64,
    thread: i64,
    rows: &[ImportMessage],
    cursor: (i64, i64),
) -> Result<(u32, u32)> {
    let wishes = relay.wishes();
    let mut kept = Vec::with_capacity(rows.len());
    let mut wished_away = Vec::new();
    for row in rows {
        let (id, author) = (row.id as i64, row.author.map(|a| a as i64));
        if verdict(&wishes, author, channel, id) == Verdict::Erased {
            wished_away.push(id);
        } else {
            kept.push(filed(row, thread)?);
        }
    }
    let (stored, skipped) = (kept.len(), wished_away.len());
    db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        for f in &kept {
            sqlx::query(FILE_ROW)
                .bind(channel)
                .bind(f.thread)
                .bind(f.id)
                .bind(f.author)
                .bind(&f.name)
                .bind(&f.body)
                .bind(f.reply_to)
                .bind(f.reactions.as_deref())
                .bind(f.attachments.as_deref())
                .bind(f.pinned)
                .bind(import_id)
                .execute(&mut *tx)
                .await?;
        }
        for id in &wished_away {
            sqlx::query(ROOT_ONE)
                .bind(THREAD_TAKEN_BACK)
                .bind(channel)
                .bind(*id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(CURSOR_UP)
            .bind(cursor.0)
            .bind(import_id)
            .bind(cursor.1)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE voipc_imports SET archive_rows = archive_rows + $1 WHERE id = $2")
            .bind(stored as i64)
            .bind(import_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    });
    Ok((stored as u32, skipped as u32))
}

/// Each thread's root row: its name and count, on the message it started from if there is
/// one, whichever comes first, and with an empty body if there is none. Who named it counts as
/// its author if the row is no one's message, so that their wishes reach the name. A thread
/// opened on a message an earlier run filed goes in the ledger, for an undo.
pub(super) async fn archive_threads(
    relay: &Relay,
    import_id: i64,
    threads: &[ImportThread],
) -> Result<()> {
    db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        for t in threads {
            sqlx::query(
                "INSERT INTO voipc_import_items (kind, dc_id, import_id, local) \
                 SELECT $1, dc_id, $2, $3 FROM voipc_archive \
                 WHERE channel = $4 AND thread = 0 AND dc_id = $5 AND import_id <> $2 \
                   AND thread_name IS NULL \
                 ON CONFLICT (kind, dc_id) DO NOTHING",
            )
            .bind(KIND_THREAD_MADE)
            .bind(import_id)
            .bind(t.parent.to_string())
            .bind(t.parent as i64)
            .bind(t.id as i64)
            .execute(&mut *tx)
            .await?;
            sqlx::query(FILE_THREAD)
                .bind(t.parent as i64)
                .bind(t.id as i64)
                .bind(t.owner.map(|o| o as i64))
                .bind(thread_title(&t.name))
                .bind(t.replies.min(i32::MAX as u32) as i32)
                .bind(import_id)
                .bind(THREAD_TAKEN_BACK)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    });
    Ok(())
}

/// `AdminOp::ImportThreads`, past `import::frame`. One frame holds threads of many channels,
/// so one that may not take rows has its own skipped, and says why when its messages come. One
/// whose name was wished away counts as skipped and still leaves its neutral root.
pub(super) async fn threads(
    state: &ServerState,
    relay: &Relay,
    run: i64,
    rows: &[ImportThread],
) -> Result<AccountReply> {
    if !relay.run_takes_messages(run).await? {
        return Ok(no_frame(NOT_ACKNOWLEDGED));
    }
    let right = |t: &ImportThread| id_ok(t.id) && id_ok(t.parent) && t.owner.is_none_or(id_ok);
    if rows.len() > IMPORT_FRAME_ROWS || !rows.iter().all(right) {
        return Ok(no_frame(NOT_RIGHT));
    }
    let wishes = relay.wishes();
    let mut allowed: HashMap<u64, bool> = HashMap::new();
    let mut read_to: HashMap<i64, Option<i64>> = HashMap::new();
    let mut filing = Vec::with_capacity(rows.len());
    let mut stored = 0;
    for t in rows {
        let may = match allowed.get(&t.parent) {
            Some(may) => *may,
            None => {
                let may = may_file(state, relay, t.parent as i64).await?.is_ok();
                allowed.insert(t.parent, may);
                may
            }
        };
        if !may {
            continue;
        }
        let (parent, id) = (t.parent as i64, t.id as i64);
        let owner = t.owner.map(|o| o as i64);
        let taken_back = verdict(&wishes, owner, parent, id) == Verdict::Erased
            || (erased_by_anyone(&wishes, parent, id)
                && gone_from_read_part(relay, &mut read_to, parent, id).await?);
        filing.push(if taken_back {
            ImportThread {
                owner: None,
                name: THREAD_TAKEN_BACK.to_string(),
                ..t.clone()
            }
        } else {
            stored += 1;
            t.clone()
        });
    }
    archive_threads(relay, run, &filing).await?;
    Ok(AccountReply::Admin(AdminReply::ImportAcked {
        stored,
        skipped: rows.len() as u32 - stored,
    }))
}

/// Whether anyone's wish takes a row at `id` in `channel`. A thread's frame names who opened
/// it, not who wrote the message it opened on, so whose wish it was cannot be told here.
fn erased_by_anyone(wishes: &Wishes, channel: i64, id: i64) -> bool {
    wishes.values().flatten().any(|w| {
        w.erase && (w.channel == 0 || w.channel == channel) && (w.low..=w.high).contains(&id)
    })
}

/// Whether the message a thread opened on is missing from a part of `channel` a run has
/// already read (runs not undone). Then it was taken back before the thread opened, and the
/// worker took its row whole, since no thread was on it yet: the title Discord gives the
/// thread may be its words. A message this run has not reached is not missing. `read_to`
/// keeps each channel's cursor for the frame.
async fn gone_from_read_part(
    relay: &Relay,
    read_to: &mut HashMap<i64, Option<i64>>,
    channel: i64,
    id: i64,
) -> Result<bool> {
    let high = match read_to.get(&channel) {
        Some(high) => *high,
        None => {
            let high: Option<i64> = db!(relay.store(), pool => {
                sqlx::query_scalar(
                    "SELECT CAST(MAX(c.high) AS BIGINT) FROM voipc_import_cursors c \
                     JOIN voipc_imports i ON i.id = c.import_id \
                     WHERE c.uid = $1 AND i.undone_at IS NULL",
                )
                .bind(channel)
                .fetch_one(pool)
                .await?
            });
            read_to.insert(channel, high);
            high
        }
    };
    if high.is_none_or(|high| id > high) {
        return Ok(false);
    }
    let here: Option<i64> = db!(relay.store(), pool => {
        sqlx::query_scalar(
            "SELECT dc_id FROM voipc_archive WHERE channel = $1 AND thread = 0 AND dc_id = $2",
        )
        .bind(channel)
        .bind(id)
        .fetch_optional(pool)
        .await?
    });
    Ok(here.is_none())
}

/// What is wrong with a frame on its face, whatever the importer did.
fn frame_ok(channel: u64, thread: Option<u64>, high: u64, rows: &[ImportMessage]) -> bool {
    rows.len() <= IMPORT_MESSAGE_ROWS
        && id_ok(channel)
        && thread.is_none_or(id_ok)
        && id_ok(high)
        && rows.iter().all(|r| {
            id_ok(r.id)
                && r.author.is_none_or(id_ok)
                && r.reply_to.is_none_or(id_ok)
                && r.body.len() <= IMPORT_BODY_BYTES
        })
}

/// `AdminOp::ImportMessages`, past `import::frame`.
pub(super) async fn messages(
    state: &ServerState,
    relay: &Relay,
    run: i64,
    channel: u64,
    thread: Option<u64>,
    high: u64,
    rows: &[ImportMessage],
) -> Result<AccountReply> {
    if !relay.run_takes_messages(run).await? {
        return Ok(no_frame(NOT_ACKNOWLEDGED));
    }
    if !frame_ok(channel, thread, high, rows) {
        return Ok(no_frame(NOT_RIGHT));
    }
    if let Err(reason) = may_file(state, relay, channel as i64).await? {
        return Ok(AccountReply::Admin(AdminReply::ImportRefused {
            reason: reason.into(),
            channel: Some(channel),
        }));
    }
    let uid = thread.unwrap_or(channel) as i64;
    let thread = thread.map_or(0, |t| t as i64);
    let (stored, skipped) =
        archive_put(relay, run, channel as i64, thread, rows, (uid, high as i64)).await?;
    Ok(AccountReply::Admin(AdminReply::ImportAcked {
        stored,
        skipped,
    }))
}

/// A decimal Discord id from a front end, which has them as strings.
pub(super) fn id_of(text: &str) -> Option<i64> {
    text.parse::<u64>()
        .ok()
        .filter(|id| id_ok(*id))
        .map(|id| id as i64)
}

/// The Discord channel behind a channel's key: only one from an import has an archive.
pub(crate) fn dc_channel(gate_key: &str) -> Option<i64> {
    id_of(gate_key.strip_prefix("c:dc-")?)
}

/// Whether this session may read a channel's archive: it stands in it now. Not
/// `voipc_members`: that list is opt-in and capped by `kept_seats`, and reading an archive must not
/// be. Not `info.log` either, which is blank in an anonymous channel, in one hiding its
/// members and with `cloud` off. One answer for a gated channel and for none at all.
/// `None`: refused. `Some(None)`: may read, and it has no archive. `Some(Some(id))`: read that.
async fn readable(
    state: &ServerState,
    session_id: SessionId,
    channel_id: ChannelId,
) -> Option<Option<i64>> {
    let uid = state
        .sessions
        .get(&session_id)
        .filter(|s| s.account.is_some())?
        .user_id;
    let channels = state.channels.read().await;
    let c = channels.get(&channel_id)?;
    (c.members.contains(&uid) && !c.info.anonymous && state.passes(session_id, &c.gate.groups))
        .then(|| dc_channel(&c.gate_key))
}

/// `AccountRequest::ArchiveChannels`: of the channels this session stands in and may read,
/// which hold anything. Asked at connect, at a join and as an import ends, so that opening one
/// asks the relay nothing.
pub(super) async fn channels(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
) -> Result<AccountReply> {
    let Some(uid) = state
        .sessions
        .get(&session_id)
        .filter(|s| s.account.is_some())
        .map(|s| s.user_id)
    else {
        return Ok(refused("ArchiveChannels", JOIN_FIRST));
    };
    let (all, theirs) = {
        let channels = state.channels.read().await;
        let all: Vec<i64> = channels
            .values()
            .filter_map(|c| dc_channel(&c.gate_key))
            .collect();
        let theirs: Vec<(ChannelId, i64)> = channels
            .values()
            .filter(|c| {
                c.members.contains(&uid)
                    && !c.info.anonymous
                    && state.passes(session_id, &c.gate.groups)
            })
            .filter_map(|c| Some((c.info.channel_id, dc_channel(&c.gate_key)?)))
            .collect();
        (all, theirs)
    };
    let held = relay.archive_held(all).await?;
    Ok(AccountReply::ArchiveChannels {
        channels: theirs
            .into_iter()
            .filter(|(_, dc)| held.contains(dc))
            .map(|(id, _)| id)
            .collect(),
    })
}

/// The Discord ids this account has linked: what makes a row its own. A name proves nothing.
pub(super) async fn discord_ids(relay: &Relay, user: AccountId) -> Result<Vec<i64>> {
    let kind = Kind::Discord.credential_kind();
    let linked = relay.store().credentials_of(user, &kind).await?;
    Ok(linked
        .iter()
        .filter_map(|c| id_of(std::str::from_utf8(&c.ext_id).ok()?))
        .collect())
}

/// Who a row is being made ready for.
pub(crate) struct Viewer {
    pub ids: Vec<i64>,
    /// Holds `*`: gets a row's Discord id, which members have no use for.
    pub star: bool,
}

impl Viewer {
    async fn of(
        state: &ServerState,
        relay: &Relay,
        session_id: SessionId,
        user: AccountId,
    ) -> Result<Viewer> {
        let star = state
            .sessions
            .get(&session_id)
            .and_then(|s| s.account.as_ref().map(|a| is_star(&a.scopes)))
            .unwrap_or(false);
        Ok(Viewer {
            ids: discord_ids(relay, user).await?,
            star,
        })
    }
}

fn decimal_or_blank(id: Option<i64>) -> String {
    id.map(|i| i.to_string()).unwrap_or_default()
}

/// A row as this viewer gets it, if they get it. Erased goes for everyone, at once. Hidden
/// is for its author alone: not `*` either. A thread's opening row stays either way, as the
/// way in to the others' replies, with nothing of whoever took it back.
fn shown(wishes: &Wishes, viewer: &Viewer, channel: i64, row: ReadRow) -> Option<ArchiveRow> {
    let (thread, id, author, name, body, reply_to, reactions, thread_name, replies, pinned) = row;
    let mine = author.is_some_and(|a| viewer.ids.contains(&a));
    let hidden = match verdict(wishes, author, channel, id) {
        Verdict::Hidden if mine => true,
        Verdict::Shown => false,
        Verdict::Hidden | Verdict::Erased if thread_name.is_some() => {
            return Some(ArchiveRow {
                id: id.to_string(),
                author: String::new(),
                author_id: String::new(),
                at_ms: snowflake_ms(id).max(0) as u64,
                body: String::new(),
                thread: String::new(),
                reply_to: String::new(),
                reactions: Vec::new(),
                pinned: false,
                thread_name: THREAD_TAKEN_BACK.to_string(),
                replies: replies.max(0) as u32,
                mine: false,
                hidden: false,
            });
        }
        Verdict::Hidden | Verdict::Erased => return None,
    };
    Some(ArchiveRow {
        id: id.to_string(),
        author: name,
        author_id: decimal_or_blank(author.filter(|_| viewer.star)),
        at_ms: snowflake_ms(id).max(0) as u64,
        body,
        thread: decimal_or_blank(Some(thread).filter(|t| *t != 0)),
        reply_to: decimal_or_blank(reply_to),
        reactions: reactions
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or_default(),
        pinned,
        thread_name: thread_name.unwrap_or_default(),
        replies: replies.max(0) as u32,
        mine,
        hidden,
    })
}

/// A thread's opening row with nothing left of it: there to open the thread, and neither a pin
/// nor a search hit. What a search matched in it would say what was taken back.
fn taken_back(row: &ArchiveRow) -> bool {
    row.thread_name == THREAD_TAKEN_BACK && row.body.is_empty() && row.author.is_empty()
}

/// What a row can come to in a frame, at most.
fn row_bytes(row: &ArchiveRow) -> usize {
    let reactions: usize = row
        .reactions
        .iter()
        .map(|r: &ArchiveReaction| r.emoji.len() + REACTION_OVERHEAD)
        .sum();
    ROW_OVERHEAD
        + row.id.len()
        + row.author.len()
        + row.author_id.len()
        + row.body.len()
        + row.thread.len()
        + row.reply_to.len()
        + row.thread_name.len()
        + reactions
}

/// Rows below `below`, newest first, one past a page. Pins cross threads. `pinned = TRUE` is
/// a literal on purpose: a bound value does not match the partial index, and SQLite would
/// scan and sort.
pub(super) async fn read_page(
    relay: &Relay,
    channel: i64,
    thread: i64,
    below: i64,
    pinned: bool,
) -> Result<Vec<ReadRow>> {
    let limit = PAGE_ROWS as i64 + 1;
    Ok(db!(relay.store(), pool => {
        if pinned {
            sqlx::query_as(reading!(
                "WHERE channel = $1 AND pinned = TRUE AND dc_id < $2 ORDER BY dc_id DESC LIMIT $3"
            ))
            .bind(channel)
            .bind(below)
            .bind(limit)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as(reading!(
                "WHERE channel = $1 AND thread = $2 AND dc_id < $3 ORDER BY dc_id DESC LIMIT $4"
            ))
            .bind(channel)
            .bind(thread)
            .bind(below)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    }))
}

/// `AccountRequest::ArchiveFetch`. An empty first page is how a client learns a channel has
/// no archive, so nothing is broadcast and a channel's list is not reshaped for it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn fetch(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    user: AccountId,
    channel_id: ChannelId,
    thread: String,
    before: String,
    pinned: bool,
) -> Result<AccountReply> {
    const ME: &str = "ArchiveFetch";
    let Some(archive) = readable(state, session_id, channel_id).await else {
        return Ok(refused(ME, JOIN_FIRST));
    };
    let (Some(in_thread), Some(below)) = (
        if thread.is_empty() {
            Some(0)
        } else {
            id_of(&thread)
        },
        if before.is_empty() {
            Some(i64::MAX)
        } else {
            id_of(&before)
        },
    ) else {
        return Ok(refused(ME, NOT_AN_ID));
    };
    let (mut rows, mut next) = (Vec::new(), String::new());
    if let Some(channel) = archive {
        let read = read_page(relay, channel, in_thread, below, pinned).await?;
        let mut more = read.len() > PAGE_ROWS;
        let viewer = Viewer::of(state, relay, session_id, user).await?;
        let wishes = relay.wishes();
        let (mut bytes, mut last) = (0, 0);
        for row in read.into_iter().take(PAGE_ROWS) {
            let id = row.1;
            let row = shown(&wishes, &viewer, channel, row).filter(|r| !(pinned && taken_back(r)));
            if let Some(row) = row {
                bytes += row_bytes(&row);
                if bytes > PAGE_BYTES && !rows.is_empty() {
                    more = true;
                    break;
                }
                rows.push(row);
            }
            // Also when the filter took it: a page of erased rows still moves on
            last = id;
        }
        if more {
            next = last.to_string();
        }
    }
    Ok(AccountReply::ArchivePage {
        channel_id,
        thread,
        before,
        pinned,
        rows,
        next,
    })
}

/// Lower case, without accents: the same meaning as the device's own search, and on both
/// databases, which is why this is no `LIKE`.
fn fold(text: &str) -> String {
    if text.is_ascii() {
        return text.to_ascii_lowercase();
    }
    let bare: String = text.nfd().filter(|c| !is_combining_mark(*c)).collect();
    bare.to_lowercase()
}

/// Whether every word is somewhere in what a row says, who wrote it, or its thread's name.
fn found_in(row: &ReadRow, words: &[String]) -> bool {
    let (body, name, thread) = (&row.4, &row.3, row.7.as_deref().unwrap_or(""));
    let hay = fold(&format!("{body}\n{name}\n{thread}"));
    words.iter().all(|w| hay.contains(w.as_str()))
}

/// Where a search stands: the channel's own flow newest first, then its threads, newest
/// thread first. Past this row, in that order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SearchAt {
    Flow(i64),
    Threads(i64, i64),
}

impl SearchAt {
    fn of(thread: i64, id: i64) -> SearchAt {
        if thread == 0 {
            SearchAt::Flow(id)
        } else {
            SearchAt::Threads(thread, id)
        }
    }

    fn text(self) -> String {
        match self {
            SearchAt::Flow(id) => format!("0:{id}"),
            SearchAt::Threads(thread, id) => format!("{thread}:{id}"),
        }
    }

    fn parse(text: &str) -> Option<SearchAt> {
        if text.is_empty() {
            return Some(SearchAt::Flow(i64::MAX));
        }
        let (thread, id) = text.split_once(':')?;
        let id = id_of(id)?;
        match thread {
            "0" => Some(SearchAt::Flow(id)),
            thread => Some(SearchAt::Threads(id_of(thread)?, id)),
        }
    }
}

async fn read_chunk(relay: &Relay, channel: i64, at: SearchAt) -> Result<Vec<ReadRow>> {
    Ok(db!(relay.store(), pool => {
        match at {
            SearchAt::Flow(below) => {
                sqlx::query_as(reading!(
                    "WHERE channel = $1 AND thread = 0 AND dc_id < $2 ORDER BY dc_id DESC LIMIT $3"
                ))
                .bind(channel)
                .bind(below)
                .bind(SEARCH_CHUNK)
                .fetch_all(pool)
                .await?
            }
            SearchAt::Threads(thread, below) => {
                sqlx::query_as(reading!(
                    "WHERE channel = $1 AND thread > 0 AND (thread, dc_id) < ($2, $3) \
                     ORDER BY thread DESC, dc_id DESC LIMIT $4"
                ))
                .bind(channel)
                .bind(thread)
                .bind(below)
                .bind(SEARCH_CHUNK)
                .fetch_all(pool)
                .await?
            }
        }
    }))
}

/// Where a search answer stops, whichever comes first.
pub(crate) struct Budget {
    pub hits: usize,
    pub bytes: usize,
    pub until: Instant,
}

/// What a stretch of a search found: rows, where to carry on (`None`: the channel's end), and
/// how many rows it looked at. A scan in Rust and no index: one meaning on both databases and
/// no second code path. What the filter takes is not found by anyone else.
pub(crate) async fn scan(
    relay: &Relay,
    channel: i64,
    words: &[String],
    viewer: &Viewer,
    mut at: SearchAt,
    budget: Budget,
) -> Result<(Vec<ArchiveRow>, Option<SearchAt>, u32)> {
    let wishes = relay.wishes();
    let (mut rows, mut bytes, mut scanned) = (Vec::new(), 0, 0u32);
    loop {
        let chunk = read_chunk(relay, channel, at).await?;
        let whole = chunk.len() as i64 == SEARCH_CHUNK;
        for row in chunk {
            let place = SearchAt::of(row.0, row.1);
            if found_in(&row, words) {
                let row = shown(&wishes, viewer, channel, row).filter(|r| !taken_back(r));
                if let Some(row) = row {
                    let size = row_bytes(&row);
                    if bytes + size > budget.bytes && !rows.is_empty() {
                        return Ok((rows, Some(at), scanned));
                    }
                    bytes += size;
                    rows.push(row);
                }
            }
            scanned += 1;
            at = place;
            if rows.len() >= budget.hits {
                return Ok((rows, Some(at), scanned));
            }
        }
        if !whole {
            match at {
                SearchAt::Flow(_) => at = SearchAt::Threads(i64::MAX, i64::MAX),
                SearchAt::Threads(..) => return Ok((rows, None, scanned)),
            }
        }
        if Instant::now() >= budget.until {
            return Ok((rows, Some(at), scanned));
        }
    }
}

/// `AccountRequest::ArchiveSearch`.
pub(super) async fn search(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    user: AccountId,
    channel_id: ChannelId,
    query: String,
    from: String,
) -> Result<AccountReply> {
    const ME: &str = "ArchiveSearch";
    let Some(archive) = readable(state, session_id, channel_id).await else {
        return Ok(refused(ME, JOIN_FIRST));
    };
    let words: Vec<String> = fold(&query).split_whitespace().map(String::from).collect();
    if query.len() > QUERY_BYTES || words.is_empty() || words.len() > QUERY_WORDS {
        return Ok(refused(ME, "Search for one to eight words."));
    }
    let Some(at) = SearchAt::parse(&from) else {
        return Ok(refused(ME, "That is not where a search stopped."));
    };
    let (rows, next, scanned) = match archive {
        None => (Vec::new(), None, 0),
        Some(channel) => {
            let Ok(_turn) = relay.archive_searches.try_acquire() else {
                return Ok(refused(ME, SEARCH_BUSY));
            };
            let viewer = Viewer::of(state, relay, session_id, user).await?;
            let budget = Budget {
                hits: SEARCH_HITS,
                bytes: PAGE_BYTES,
                until: Instant::now() + SEARCH_TIME,
            };
            scan(relay, channel, &words, &viewer, at, budget).await?
        }
    };
    Ok(AccountReply::ArchiveHits {
        channel_id,
        query,
        from,
        rows,
        next: next.map(SearchAt::text).unwrap_or_default(),
        scanned,
    })
}

/// What a wish covers, channels as a range: 0 is every channel but no row's.
fn channels_of(channel: i64) -> (i64, i64) {
    if channel == 0 {
        (1, i64::MAX)
    } else {
        (channel, channel)
    }
}

/// How many rows a wish covers. `author` None: whoever wrote it.
pub(super) async fn rows_under(relay: &Relay, author: Option<i64>, wish: &Wish) -> Result<u64> {
    let (first, last) = channels_of(wish.channel);
    let n: i64 = db!(relay.store(), pool => {
        match author {
            Some(author) => {
                sqlx::query_scalar(ROWS_BY)
                    .bind(author)
                    .bind(first)
                    .bind(last)
                    .bind(wish.low)
                    .bind(wish.high)
                    .fetch_one(pool)
                    .await?
            }
            None => {
                sqlx::query_scalar(ROWS_ANYONE)
                    .bind(first)
                    .bind(last)
                    .bind(wish.low)
                    .bind(wish.high)
                    .fetch_one(pool)
                    .await?
            }
        }
    });
    Ok(n.max(0) as u64)
}

pub(super) async fn wish_put(relay: &Relay, authors: &[i64], wish: &Wish) -> Result<()> {
    db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        for author in authors {
            sqlx::query(WISH_UP)
                .bind(*author)
                .bind(wish.channel)
                .bind(wish.low)
                .bind(wish.high)
                .bind(wish.erase)
                .bind(util::now())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    });
    Ok(())
}

/// The hides inside this scope go, and how many did. A delete is for good.
pub(super) async fn hides_drop(relay: &Relay, authors: &[i64], scope: &Wish) -> Result<u64> {
    let (first, last) = match scope.channel {
        0 => (0, i64::MAX),
        c => (c, c),
    };
    Ok(db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        let mut gone = 0;
        for author in authors {
            gone += sqlx::query(
                "DELETE FROM voipc_archive_wishes WHERE author_dc_id = $1 AND erase = $2
                   AND channel BETWEEN $3 AND $4 AND low >= $5 AND high <= $6",
            )
            .bind(*author)
            .bind(false)
            .bind(first)
            .bind(last)
            .bind(scope.low)
            .bind(scope.high)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }
        tx.commit().await?;
        gone
    }))
}

pub(super) async fn wishes_of(relay: &Relay, author: i64) -> Result<i64> {
    Ok(db!(relay.store(), pool => {
        sqlx::query_scalar(
            "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_archive_wishes WHERE author_dc_id = $1",
        )
        .bind(author)
        .fetch_one(pool)
        .await?
    }))
}

/// Whether a hide wider than `scope`, which `Show` on `scope` would not reach, covers it.
fn under_a_wider_hide(wishes: &Wishes, authors: &[i64], scope: &Wish) -> bool {
    authors
        .iter()
        .filter_map(|a| wishes.get(a))
        .flatten()
        .any(|w| {
            let covers = (w.channel == 0 || w.channel == scope.channel)
                && w.low <= scope.low
                && w.high >= scope.high;
            let inside = w.channel == scope.channel && w.low >= scope.low && w.high <= scope.high;
            !w.erase && covers && !inside
        })
}

/// Whether all of `authors` have said this, or more: nothing to write, read again or wake for.
fn said_already(wishes: &Wishes, authors: &[i64], said: &Wish) -> bool {
    authors.iter().all(|a| {
        wishes.get(a).is_some_and(|list| {
            list.iter().any(|w| {
                (w.channel, w.low, w.high) == (said.channel, said.low, said.high)
                    && (w.erase || !said.erase)
            })
        })
    })
}

/// Whether everything by this author is going: gone for every reader already, whatever the
/// worker has reached. A count that went by the rows alone would still read the old number.
fn all_erased(wishes: &Wishes, author: i64) -> bool {
    wishes.get(&author).is_some_and(|list| {
        list.iter()
            .any(|w| w.erase && w.channel == 0 && w.low == 0 && w.high == i64::MAX)
    })
}

/// `AccountRequest::ArchiveMine`. Each wish is keyed by the person's own id, so one naming
/// someone else's row matches nothing: no ownership read is needed, and that is the safety of
/// it. `Everything` goes through no gate: someone who lost a channel can still erase what
/// they wrote in it. No row in the log and no code: it is their own and takes no privilege,
/// and it may be an account with no codes.
pub(super) async fn mine(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    user: AccountId,
    action: ArchiveAction,
    scope: ArchiveScope,
) -> Result<AccountReply> {
    const ME: &str = "ArchiveMine";
    let ids = discord_ids(relay, user).await?;
    if ids.is_empty() {
        return Ok(refused(ME, LINK_FIRST));
    }
    let erase = action == ArchiveAction::Delete;
    let whole = matches!(scope, ArchiveScope::Everything);
    let wish = match &scope {
        ArchiveScope::Everything => Some(Wish {
            channel: 0,
            low: 0,
            high: i64::MAX,
            erase,
        }),
        ArchiveScope::Channel { channel_id } => {
            let Some(archive) = readable(state, session_id, *channel_id).await else {
                return Ok(refused(ME, JOIN_FIRST));
            };
            archive.map(|channel| Wish {
                channel,
                low: 0,
                high: i64::MAX,
                erase,
            })
        }
        ArchiveScope::Message { channel_id, id } => {
            let Some(archive) = readable(state, session_id, *channel_id).await else {
                return Ok(refused(ME, JOIN_FIRST));
            };
            let Some(id) = id_of(id) else {
                return Ok(refused(ME, NOT_AN_ID));
            };
            archive.map(|channel| Wish {
                channel,
                low: id,
                high: id,
                erase,
            })
        }
    };
    let Some(wish) = wish else {
        return Ok(AccountReply::ArchiveMineDone { action, rows: 0 });
    };
    let mut rows = 0;
    for id in &ids {
        if action == ArchiveAction::Count && all_erased(&relay.wishes(), *id) {
            continue;
        }
        rows += rows_under(relay, Some(*id), &wish).await?;
    }
    match action {
        ArchiveAction::Count => {}
        ArchiveAction::Hide | ArchiveAction::Delete => {
            if said_already(&relay.wishes(), &ids, &wish) {
                return Ok(AccountReply::ArchiveMineDone { action, rows });
            }
            if !whole {
                for id in &ids {
                    if wishes_of(relay, *id).await? >= WISHES_PER_AUTHOR {
                        return Ok(refused(ME, WISHES_FULL));
                    }
                }
            }
            wish_put(relay, &ids, &wish).await?;
            // A hide only changes who reads: the worker has nothing to do for it
            if erase {
                relay.archive_changed().await?;
            } else {
                load(relay).await?;
            }
        }
        ArchiveAction::Show => {
            if under_a_wider_hide(&relay.wishes(), &ids, &wish) {
                return Ok(refused(ME, SHOW_THOSE_FIRST));
            }
            if hides_drop(relay, &ids, &wish).await? > 0 {
                load(relay).await?;
            }
        }
    }
    Ok(AccountReply::ArchiveMineDone { action, rows })
}

/// What `AdminOp::ArchiveDelete` would write, ahead of its code: whose rows (0: whoever wrote
/// it, the way to reach an anonymised row), and which.
pub(super) async fn delete_target(
    state: &ServerState,
    target: &ArchiveTarget,
) -> std::result::Result<(i64, Wish), &'static str> {
    match target {
        ArchiveTarget::Author { id } => {
            let author = id_of(id).ok_or(NOT_AN_ID)?;
            Ok((
                author,
                Wish {
                    channel: 0,
                    low: 0,
                    high: i64::MAX,
                    erase: true,
                },
            ))
        }
        ArchiveTarget::Message { channel_id, id } => {
            let id = id_of(id).ok_or(NOT_AN_ID)?;
            let channel = state
                .channels
                .read()
                .await
                .get(channel_id)
                .and_then(|c| dc_channel(&c.gate_key))
                .ok_or("That channel holds nothing from Discord.")?;
            Ok((
                0,
                Wish {
                    channel,
                    low: id,
                    high: id,
                    erase: true,
                },
            ))
        }
    }
}

/// In thousands, as a person reads a count in the log.
pub(super) fn counted(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, d) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(d);
    }
    out
}

fn imported_posts(n: u64) -> String {
    if n == 1 {
        "one imported post".to_string()
    } else {
        format!("{} imported posts", counted(n))
    }
}

/// `AdminOp::ArchiveDelete`, past its code. The row first, with no name and no target: it
/// outlives the person, and someone who asked to be removed should not be named for months.
pub(super) async fn delete(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    author: i64,
    wish: &Wish,
) -> Result<AccountReply> {
    let by = (author != 0).then_some(author);
    let rows = rows_under(relay, by, wish).await?;
    let row = modlog::Entry {
        action: "archive_delete",
        detail: &imported_posts(rows),
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, session_id, row).await {
        warn!("keeping a deletion from the archive: {e:#}");
        return Ok(refused(
            "Admin",
            "That could not be kept, so nothing was removed.",
        ));
    }
    wish_put(relay, &[author], wish).await?;
    relay.archive_changed().await?;
    Ok(AccountReply::Admin(AdminReply::ArchiveDeleted { rows }))
}

/// `AdminOp::ArchiveWishes`: by author, past `after`. For a driver about to anonymise, which
/// keeps them in memory for the run: nothing goes in any log. A wish for whoever wrote it, or
/// someone's exclusion, is no business of this: the relay and `MoveExcluded` have those.
pub(super) async fn wishes_page(relay: &Relay, after: Option<ArchiveWish>) -> Result<AccountReply> {
    type Row = (i64, i64, i64, i64, bool);
    let fits = |id: u64| i64::try_from(id).unwrap_or(i64::MAX);
    let at = after.map_or((0, -1, -1, -1), |w| {
        (fits(w.author), fits(w.channel), fits(w.low), fits(w.high))
    });
    let mut rows: Vec<Row> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT CAST(author_dc_id AS BIGINT), CAST(channel AS BIGINT), CAST(low AS BIGINT),
                    CAST(high AS BIGINT), erase
             FROM voipc_archive_wishes
             WHERE author_dc_id <> 0 AND (author_dc_id, channel, low, high) > ($1, $2, $3, $4)
             ORDER BY author_dc_id, channel, low, high LIMIT $5",
        )
        .bind(at.0)
        .bind(at.1)
        .bind(at.2)
        .bind(at.3)
        .bind(WISHES_PAGE + 1)
        .fetch_all(pool)
        .await?
    });
    let more = rows.len() as i64 > WISHES_PAGE;
    rows.truncate(WISHES_PAGE as usize);
    Ok(AccountReply::Admin(AdminReply::ArchiveWishes {
        rows: rows
            .into_iter()
            .map(|(author, channel, low, high, erase)| ArchiveWish {
                author: author as u64,
                channel: channel as u64,
                low: low as u64,
                high: high as u64,
                erase,
            })
            .collect(),
        more,
    }))
}

/// What the worker takes in batches.
#[derive(Clone, Copy)]
enum Going<'a> {
    /// A wish's threads' opening rows, which it leaves neutral rather than taking.
    Roots(i64, &'a Wish),
    Wished(i64, &'a Wish),
    Channel(i64),
    /// Opening rows past the floor whose threads go on inside it, left neutral.
    OldRoots(i64, i64),
    Older(i64, i64),
}

/// One batch, one transaction: at most `BATCH` rows.
async fn batch(relay: &Relay, going: Going<'_>) -> Result<u64> {
    Ok(db!(relay.store(), pool => {
        match going {
            Going::Roots(0, wish) if wish.channel == 0 => sqlx::query(ROOT_ANYONE_ALL)
                .bind(THREAD_TAKEN_BACK)
                .bind(wish.low)
                .bind(wish.high)
                .bind(BATCH)
                .execute(pool)
                .await?
                .rows_affected(),
            Going::Roots(0, wish) => sqlx::query(ROOT_ANYONE)
                .bind(THREAD_TAKEN_BACK)
                .bind(wish.channel)
                .bind(wish.low)
                .bind(wish.high)
                .bind(BATCH)
                .execute(pool)
                .await?
                .rows_affected(),
            Going::Roots(author, wish) => {
                let (first, last) = channels_of(wish.channel);
                sqlx::query(ROOT_BY)
                    .bind(THREAD_TAKEN_BACK)
                    .bind(author)
                    .bind(first)
                    .bind(last)
                    .bind(wish.low)
                    .bind(wish.high)
                    .bind(BATCH)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            Going::Wished(0, wish) if wish.channel == 0 => sqlx::query(ERASE_ANYONE_ALL)
                .bind(wish.low)
                .bind(wish.high)
                .bind(BATCH)
                .execute(pool)
                .await?
                .rows_affected(),
            Going::Wished(0, wish) => sqlx::query(ERASE_ANYONE)
                .bind(wish.channel)
                .bind(wish.low)
                .bind(wish.high)
                .bind(BATCH)
                .execute(pool)
                .await?
                .rows_affected(),
            Going::Wished(author, wish) => {
                let (first, last) = channels_of(wish.channel);
                sqlx::query(ERASE_BY)
                    .bind(author)
                    .bind(first)
                    .bind(last)
                    .bind(wish.low)
                    .bind(wish.high)
                    .bind(BATCH)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            Going::Channel(channel) => {
                sqlx::query(ERASE_CHANNEL)
                    .bind(channel)
                    .bind(BATCH)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            Going::OldRoots(channel, floor) => {
                sqlx::query(ROOT_OLD)
                    .bind(THREAD_TAKEN_BACK)
                    .bind(channel)
                    .bind(floor)
                    .bind(BATCH)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
            Going::Older(channel, floor) => {
                sqlx::query(ERASE_OLD)
                    .bind(channel)
                    .bind(floor)
                    .bind(BATCH)
                    .execute(pool)
                    .await?
                    .rows_affected()
            }
        }
    }))
}

/// All of it, with a breath between batches: no writer waits longer than one.
async fn all_of(relay: &Relay, going: Going<'_>) -> Result<u64> {
    let mut gone = 0;
    loop {
        let n = batch(relay, going).await?;
        gone += n;
        if (n as i64) < BATCH {
            return Ok(gone);
        }
        tokio::time::sleep(BREATHE).await;
    }
}

/// The next channel with rows, by id.
async fn channel_after(relay: &Relay, after: i64) -> Result<Option<i64>> {
    Ok(db!(relay.store(), pool => {
        sqlx::query_scalar(
            "SELECT channel FROM voipc_archive WHERE channel > $1 ORDER BY channel LIMIT 1",
        )
        .bind(after)
        .fetch_optional(pool)
        .await?
    }))
}

/// Whether a channel is here, in memory or its row: one from channels.json has no row and
/// is no orphan.
async fn channel_stands(state: &ServerState, relay: &Relay, conv: &str) -> Result<bool> {
    if state
        .channels
        .read()
        .await
        .values()
        .any(|c| c.gate_key == conv)
    {
        return Ok(true);
    }
    let row: Option<String> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT conv FROM voipc_channels WHERE conv = $1")
            .bind(conv)
            .fetch_optional(pool)
            .await?
    });
    Ok(row.is_some())
}

/// What one run first brought, walking each channel by its primary key: no index has
/// `import_id`. Looked at in stretches of `BATCH` with no write held, and a stretch holding
/// any goes in one transaction.
async fn run_rows_go(relay: &Relay, run: i64) -> Result<u64> {
    let mut gone = 0;
    let mut channel = 0;
    while let Some(here) = channel_after(relay, channel).await? {
        channel = here;
        let mut past = (-1i64, -1i64);
        loop {
            let keys: Vec<(i64, i64, i64)> = db!(relay.store(), pool => {
                sqlx::query_as(
                    "SELECT thread, dc_id, import_id FROM voipc_archive
                     WHERE channel = $1 AND (thread, dc_id) > ($2, $3)
                     ORDER BY thread, dc_id LIMIT $4",
                )
                .bind(channel)
                .bind(past.0)
                .bind(past.1)
                .bind(BATCH)
                .fetch_all(pool)
                .await?
            });
            let Some(&(thread, id, _)) = keys.last() else {
                break;
            };
            if keys.iter().any(|k| k.2 == run) {
                gone += db!(relay.store(), pool => {
                    sqlx::query(
                        "DELETE FROM voipc_archive WHERE channel = $1
                           AND (thread, dc_id) > ($2, $3) AND (thread, dc_id) <= ($4, $5)
                           AND import_id = $6",
                    )
                    .bind(channel)
                    .bind(past.0)
                    .bind(past.1)
                    .bind(thread)
                    .bind(id)
                    .bind(run)
                    .execute(pool)
                    .await?
                    .rows_affected()
                });
                tokio::time::sleep(BREATHE).await;
            }
            if (keys.len() as i64) < BATCH {
                break;
            }
            past = (thread, id);
        }
    }
    Ok(gone)
}

/// Everything that must go, in batches. Safe to stop anywhere: each part starts over from
/// what the database says.
pub async fn tidy(state: &ServerState, relay: &Relay) -> Result<u64> {
    // The server's shell is another process, and what it did is in the database
    load(relay).await?;
    let mut gone = 0;
    let any: Option<i64> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT channel FROM voipc_archive LIMIT 1")
            .fetch_optional(pool)
            .await?
    });
    if any.is_some() {
        // 1. What people asked to have gone. Every time: it is an index probe each, and it
        // catches a crash and a frame that raced a wish.
        let wishes = relay.wishes();
        for (author, list) in wishes.iter() {
            for wish in list.iter().filter(|w| w.erase) {
                all_of(relay, Going::Roots(*author, wish)).await?;
                gone += all_of(relay, Going::Wished(*author, wish)).await?;
            }
        }
        // 2. Channels that are gone: deleting one's row is what commits its archive, so
        // neither `ChannelDelete` nor an undo needs archive code. 3. Past `archive_days`.
        let floor = (relay.archive_days > 0)
            .then(|| snowflake_floor(log::now_ms() - i64::from(relay.archive_days) * 86_400_000));
        let mut channel = 0;
        while let Some(here) = channel_after(relay, channel).await? {
            channel = here;
            if !channel_stands(state, relay, &format!("c:dc-{channel}")).await? {
                gone += all_of(relay, Going::Channel(channel)).await?;
            } else if let Some(floor) = floor {
                all_of(relay, Going::OldRoots(channel, floor)).await?;
                gone += all_of(relay, Going::Older(channel, floor)).await?;
            }
        }
    }
    // 4. What undone runs filed. Empty or not, or a new run would wait for ever.
    for run in relay.runs_with_rows_to_go().await? {
        gone += run_rows_go(relay, run).await?;
        relay.run_rows_gone(run).await?;
    }
    Ok(gone)
}

/// One task: every hour, and when something is to go. It does not stop reading of what was
/// wished away, which the read filter has already done, so it is in no hurry.
pub async fn worker(state: Arc<ServerState>) {
    let Some(relay) = state.accounts.clone() else {
        return;
    };
    let mut every = tokio::time::interval(TIDY_EVERY);
    loop {
        tokio::select! {
            _ = every.tick() => {}
            () = relay.archive_kick.notified() => {}
        }
        if let Err(e) = tidy(&state, &relay).await {
            warn!("tidying what came from Discord: {e:#}");
        }
    }
}

/// A row as its table holds it, for tests.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ArchivedRow {
    pub author: Option<i64>,
    pub name: String,
    pub body: String,
    pub reply_to: Option<i64>,
    pub reactions: Option<String>,
    pub attachments: Option<String>,
    pub thread_name: Option<String>,
    pub replies: i32,
    pub pinned: bool,
    pub import_id: i64,
}

#[cfg(test)]
pub(crate) async fn archived_row(
    relay: &Relay,
    channel: i64,
    thread: i64,
    id: i64,
) -> Result<Option<ArchivedRow>> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        Option<i64>,
        String,
        String,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        i32,
        bool,
        i64,
    )> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT author_dc_id, author_name, body, reply_to, reactions, attachments, thread_name,
                    replies, pinned, import_id
             FROM voipc_archive WHERE channel = $1 AND thread = $2 AND dc_id = $3",
        )
        .bind(channel)
        .bind(thread)
        .bind(id)
        .fetch_optional(pool)
        .await?
    });
    Ok(row.map(
        |(
            author,
            name,
            body,
            reply_to,
            reactions,
            attachments,
            thread_name,
            replies,
            pinned,
            import_id,
        )| {
            ArchivedRow {
                author,
                name,
                body,
                reply_to,
                reactions,
                attachments,
                thread_name,
                replies,
                pinned,
                import_id,
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wish(channel: i64, low: i64, high: i64, erase: bool) -> Wish {
        Wish {
            channel,
            low,
            high,
            erase,
        }
    }

    #[test]
    fn a_wish_reaches_its_author_its_channel_and_its_span() {
        let mut w = Wishes::new();
        w.insert(7, vec![wish(100, 10, 20, true)]);
        assert_eq!(verdict(&w, Some(7), 100, 10), Verdict::Erased);
        assert_eq!(verdict(&w, Some(7), 100, 20), Verdict::Erased);
        // The controls, one each: another span, channel, author, or no author at all
        assert_eq!(verdict(&w, Some(7), 100, 21), Verdict::Shown);
        assert_eq!(verdict(&w, Some(7), 100, 9), Verdict::Shown);
        assert_eq!(verdict(&w, Some(7), 101, 15), Verdict::Shown);
        assert_eq!(verdict(&w, Some(8), 100, 15), Verdict::Shown);
        assert_eq!(verdict(&w, None, 100, 15), Verdict::Shown);
    }

    #[test]
    fn channel_0_is_every_channel_and_author_0_is_whoever_wrote_it() {
        let mut w = Wishes::new();
        w.insert(7, vec![wish(0, 0, i64::MAX, true)]);
        assert_eq!(verdict(&w, Some(7), 555, i64::MAX), Verdict::Erased);
        w.clear();
        w.insert(0, vec![wish(100, 15, 15, true)]);
        assert_eq!(verdict(&w, None, 100, 15), Verdict::Erased, "anonymised");
        assert_eq!(verdict(&w, Some(9), 100, 15), Verdict::Erased);
        assert_eq!(verdict(&w, None, 100, 16), Verdict::Shown);
    }

    #[test]
    fn a_hide_never_softens_an_erase() {
        let mut w = Wishes::new();
        w.insert(7, vec![wish(100, 0, 50, false)]);
        assert_eq!(verdict(&w, Some(7), 100, 15), Verdict::Hidden);
        for list in [
            vec![wish(100, 0, 50, false), wish(0, 15, 15, true)],
            vec![wish(0, 15, 15, true), wish(100, 0, 50, false)],
        ] {
            w.insert(7, list);
            assert_eq!(verdict(&w, Some(7), 100, 15), Verdict::Erased);
        }
    }

    #[test]
    fn a_body_keeps_its_newlines_and_loses_nul() {
        assert_eq!(
            clean_body("a\u{0}b\nc\td\u{1}e\r\u{1F389}"),
            "ab\nc\tde\u{1F389}"
        );
        // The control: what names go through would have eaten the lines
        assert_eq!(clip("a\nb", 10), "ab");
    }

    #[test]
    fn search_folds_as_the_devices_does() {
        assert_eq!(fold("Caf\u{E9} STRASSE"), "cafe strasse");
        assert_eq!(fold("cafe\u{301}"), "cafe");
        assert_eq!(fold("\u{C5}NGSTR\u{D6}M"), "angstrom");
        assert_eq!(fold("Plain_100%"), "plain_100%");
    }

    #[test]
    fn a_search_says_where_it_stopped_and_takes_nothing_else() {
        for at in [SearchAt::Flow(7), SearchAt::Threads(9, 7)] {
            assert_eq!(SearchAt::parse(&at.text()), Some(at));
        }
        assert_eq!(SearchAt::parse(""), Some(SearchAt::Flow(i64::MAX)));
        for bad in ["x", "1", "0:", ":5", "0:x", "-1:5", "0:-5", "0:0", "1:0"] {
            assert_eq!(SearchAt::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn only_a_channel_from_an_import_has_an_archive() {
        assert_eq!(dc_channel("c:dc-601"), Some(601));
        for key in [
            "", "c:abc", "c:dc-", "c:dc-x", "c:dc-0", "c:dc--5", "d:dc-5",
        ] {
            assert_eq!(dc_channel(key), None, "{key}");
        }
    }

    #[test]
    fn a_count_reads_as_a_person_writes_it() {
        assert_eq!(counted(0), "0");
        assert_eq!(counted(999), "999");
        assert_eq!(counted(1_204), "1,204");
        assert_eq!(counted(1_000_000), "1,000,000");
        assert_eq!(imported_posts(1), "one imported post");
        assert_eq!(imported_posts(1_204), "1,204 imported posts");
    }

    /// What `Show` on a row or a channel cannot reach must not read as shown.
    #[test]
    fn a_narrow_show_says_when_a_wider_hide_still_covers_it() {
        let mut w = Wishes::new();
        let row = wish(100, 15, 15, false);
        let channel = wish(100, 0, i64::MAX, false);
        let all = wish(0, 0, i64::MAX, false);
        w.insert(7, vec![row.clone()]);
        assert!(!under_a_wider_hide(&w, &[7], &row), "only itself");
        w.insert(7, vec![row.clone(), channel.clone()]);
        assert!(under_a_wider_hide(&w, &[7], &row));
        assert!(!under_a_wider_hide(&w, &[7], &channel), "takes the row too");
        w.insert(7, vec![channel.clone(), all.clone()]);
        assert!(under_a_wider_hide(&w, &[7], &channel));
        assert!(!under_a_wider_hide(&w, &[7], &all));
        // The controls: another channel's, an erase, someone else's
        w.insert(7, vec![wish(101, 0, i64::MAX, false)]);
        assert!(!under_a_wider_hide(&w, &[7], &row));
        w.insert(7, vec![wish(100, 0, i64::MAX, true)]);
        assert!(!under_a_wider_hide(&w, &[7], &row));
        w.insert(8, vec![channel]);
        w.remove(&7);
        assert!(!under_a_wider_hide(&w, &[7], &row));
    }

    #[test]
    fn a_name_shows_all_it_says() {
        assert_eq!(clean_name("  a\u{200B}\u{202E}b\u{0} ", 64), "ab");
        // W1-36: one of only what draws nothing is none, and a thread still has a name
        assert_eq!(clean_name("\u{2800} \u{fe0f}", 64), "");
        assert_eq!(thread_title("\u{2800}"), THREAD_TAKEN_BACK);
        assert_eq!(thread_title("Plans"), "Plans");
        let wide = "\u{1F389}".repeat(70);
        assert_eq!(clean_name(&wide, 64).chars().count(), 64);
    }
}
