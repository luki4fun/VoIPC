//! One run of the importer on the relay (protocol v20): its row in `voipc_imports`, the
//! copy of the database before it, and the check in front of every frame.
//!
//! The importer reads Discord on the operator's machine and sends what it read here, a
//! frame at a time, on one session. A run takes hours and a step-up lasts ten minutes, so
//! the code is asked once, at `ImportBegin`, and the session then holds the run: a cut
//! needs `ImportBegin` again, which proves it is still them. `*` is read anew for each
//! frame, so losing it stops the next one.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::service::{Actor, Ctx, Host};
use l4f_accounts::store::Store;
use l4f_accounts::util;
use tokio::sync::MutexGuard;
use tracing::warn;
use voipc_protocol::messages::{AccountReply, AdminReply, ServerMessage};
use voipc_protocol::types::{
    ImportFacts, ImportOptions, ImportUndoCounts, ProviderKind, SessionId,
};

use super::modlog::{self, clip};
use super::{is_star, placeholder, refused, sqlite_backup, Relay};
use crate::state::ServerState;

/// `ImportEnd.report` at most, and what `ImportReport` then has to fit in a frame.
const REPORT_BYTES: usize = 40 * 1024;
/// Copies of the database a relay keeps: each holds everything, so not many.
const COPIES_KEPT: usize = 2;
const NOT_OPEN: &str = "That run is not open on this connection: begin it again.";
const NOT_KEPT: &str = "That could not be kept.";
const NO_SUCH_RUN: &str = "No such run.";
/// What a run's copy is named, after the database file's own name.
const COPY_INFIX: &str = ".before-import-";
/// A resumed run's, when its first copy was dropped meanwhile: it holds what the run did
/// before it stopped, so it is no copy from before the run (W2-26).
const AGAIN_INFIX: &str = ".before-resuming-import-";
const PART: &str = ".part";
/// `voipc_import_items.kind`, a `SMALLINT` on Postgres, so bound as `i16`.
pub(crate) const KIND_CATEGORY: i16 = 1;
pub(crate) const KIND_CHANNEL: i16 = 2;
const KIND_EMOTE: i16 = 3;
/// A plain group and a twin someone deleted here: by Discord's role, with nothing to remove,
/// so that no later run makes them again.
pub(super) const KIND_GROUP_DELETED: i16 = 4;
pub(super) const KIND_TWIN_DELETED: i16 = 5;
/// A thread a run opened on a message an earlier run filed: by the thread's id, `local` its
/// channel. The row stays the earlier run's, so only this says the name and count are this
/// run's, for its undo to take off again (W2-25).
pub(super) const KIND_THREAD_MADE: i16 = 6;
/// Rows of `ImportCursors` a reply holds: about 18 bytes each, under one frame.
const CURSOR_ROWS: i64 = 2000;
/// Channels one `ImportUndo` call takes: each puts its members out, and a call runs in the
/// session's read loop.
const UNDO_CHANNELS: i64 = 16;
/// Accounts one `ImportUndo` call takes.
const UNDO_ACCOUNTS: i64 = 500;
/// How far something is read, in a run. Only ever up: a frame sent again cannot lower it.
pub(super) const CURSOR_UP: &str = "INSERT INTO voipc_import_cursors (uid, import_id, high) \
     VALUES ($1, $2, $3) ON CONFLICT (uid, import_id) DO UPDATE \
     SET high = excluded.high WHERE excluded.high > voipc_import_cursors.high";

/// The run this relay is on, one at a time. Only in memory: a restart ends it, and
/// `ImportBegin` takes the row up again. The session's being there, and its frames, are
/// what make it running: a run whose session is gone, or that sent nothing for
/// `RUN_IDLE`, is free to take over.
pub struct ActiveRun {
    pub run: i64,
    pub session_id: SessionId,
    /// Its copy of the database is made, or it needs none: frames may come.
    pub ready: bool,
    /// Its last frame, or when it became ready.
    pub last: Instant,
    /// The number its `ImportBegin` was asked with: `ImportBegun` after the copy carries it.
    pub ask: Option<u32>,
}

/// How long a ready run may send nothing before another session may take its place. Stop on
/// the desktop ends only the driver, its session stays, and the wire has no word for a stop
/// (W2-6). A driver waiting out Discord can be quiet longer: once taken over, its next frame
/// is refused and it stops, and the next run goes on from what was stored.
pub(crate) const RUN_IDLE: Duration = Duration::from_secs(15 * 60);

/// What a session hears while another's run holds the relay.
const RUNNING: &str =
    "Another admin's import is running here. One that sends nothing for 15 minutes can be taken over.";

impl ActiveRun {
    /// Whether this run stands in `session_id`'s way.
    fn holds_against(&self, state: &ServerState, session_id: SessionId) -> bool {
        self.session_id != session_id
            && state.sessions.contains_key(&self.session_id)
            && (!self.ready || self.last.elapsed() < RUN_IDLE)
    }
}

/// What `ImportBegin` found, before it asks for the code.
pub(super) struct Begin {
    guild: i64,
    /// This guild's unfinished run, and the copy it has.
    resumes: Option<(i64, Option<String>)>,
}

/// Postgres has no copy from here: the operator says they ran `pg_dump`, for a new run.
fn no_copy_from_here(backup_here: bool, resumed: bool, backup_taken: bool) -> Option<&'static str> {
    (!backup_here && !resumed && !backup_taken).then_some("Run pg_dump first, then tick this.")
}

/// A refused frame: the driver stops, and a panel's error is no business of its.
pub(super) fn no_frame(reason: &str) -> AccountReply {
    AccountReply::Admin(AdminReply::ImportRefused {
        reason: reason.into(),
        channel: None,
    })
}

/// A frame that failed here says so, so the driver stops now and can resume: an `Err` is
/// only logged by the read loop, and it would wait two minutes for an answer.
pub(super) fn frame_failed(e: anyhow::Error) -> AccountReply {
    warn!("a frame of an import: {e:#}");
    no_frame("The server could not keep that. Try again.")
}

/// The toggles that are on, in words, for the log.
fn on_words(o: &ImportOptions) -> String {
    let all = [
        ("channels", o.channels),
        ("roles", o.roles),
        ("permissions", o.permissions),
        ("members", o.members),
        ("bans", o.bans),
        ("emotes", o.emotes),
        ("messages", o.messages),
        ("threads", o.threads),
        ("pins", o.pins),
        ("reactions", o.reactions),
        ("anonymised", o.anonymise),
        ("acknowledged", o.acknowledged),
    ];
    let on: Vec<&str> = all.iter().filter(|(_, on)| *on).map(|(w, _)| *w).collect();
    on.join(", ")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut p: OsString = path.as_os_str().to_owned();
    p.push(suffix);
    PathBuf::from(p)
}

/// Where a run's copy goes: next to the database, named here. Nothing of it comes from a
/// client.
fn copy_path(db: &Path, run: i64, again: bool) -> PathBuf {
    let infix = if again { AGAIN_INFIX } else { COPY_INFIX };
    with_suffix(db, &format!("{infix}{run}"))
}

/// Keeps `COPIES_KEPT` copies of this database: `made`, whatever its run (a resumed run's
/// comes after newer runs' copies, and went at once), then the newest by run; and what a
/// crash left of a copy at the newest run or later. Goes by the exact name: anything else
/// beside it is not ours to touch.
fn prune_copies(db: &Path, made: &Path) {
    let Some(name) = db.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let dir = db
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let prefixes = [
        format!("{name}{COPY_INFIX}"),
        format!("{name}{AGAIN_INFIX}"),
    ];
    let run_of = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<i64>().ok())
            .flatten()
    };
    let (mut whole, mut parts) = (Vec::new(), Vec::new());
    for entry in entries.flatten() {
        let file = entry.file_name();
        let Some(rest) = file
            .to_str()
            .and_then(|f| prefixes.iter().find_map(|p| f.strip_prefix(p.as_str())))
        else {
            continue;
        };
        if let Some(run) = rest.strip_suffix(PART).and_then(run_of) {
            parts.push((run, entry.path()));
        } else if let Some(run) = run_of(rest) {
            whole.push((run, entry.path()));
        }
    }
    let newest = whole.iter().map(|(run, _)| *run).max().unwrap_or(0);
    // The one just made first, then by run
    whole.sort_by_key(|(run, path)| {
        (
            path.file_name() != made.file_name(),
            std::cmp::Reverse(*run),
        )
    });
    let gone = whole
        .into_iter()
        .skip(COPIES_KEPT)
        .chain(parts.into_iter().filter(|(run, _)| *run < newest));
    for (_, path) in gone {
        if let Err(e) = std::fs::remove_file(&path) {
            warn!("removing an old copy {}: {e}", path.display());
        }
    }
}

/// The copy of the database before a run, or `again` before the rest of it: private from
/// the start, under its real name only once it is whole. Its name goes on the run's row.
async fn take_copy(relay: &Relay, db: &Path, run: i64, again: bool) -> Result<String> {
    let to = copy_path(db, run, again);
    let part = with_suffix(&to, PART);
    // What a crash left of this one: SQLite copies only into an empty file
    match std::fs::remove_file(&part) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if let Err(e) = sqlite_backup(relay.store(), &part).await {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, &to)?;
    let text = to.to_string_lossy().into_owned();
    db!(relay.store(), pool => {
        sqlx::query("UPDATE voipc_imports SET backup = $1 WHERE id = $2")
            .bind(&text)
            .bind(run)
            .execute(pool)
            .await?;
    });
    prune_copies(db, &to);
    Ok(text)
}

impl Relay {
    /// The file this relay's SQLite database is in; Postgres has none.
    fn db_file(&self) -> Option<PathBuf> {
        match self.store() {
            Store::Lite(b) => Some(b.0.connect_options().get_filename().to_path_buf()),
            Store::Pg(_) => None,
        }
    }

    /// The guild's run nobody finished, with the copy it has.
    pub(super) async fn run_unfinished(&self, guild: i64) -> Result<Option<(i64, Option<String>)>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT CAST(id AS BIGINT), backup FROM voipc_imports
                 WHERE guild_id = $1 AND finished_at IS NULL AND undone_at IS NULL
                 ORDER BY id DESC LIMIT 1",
            )
            .bind(guild)
            .fetch_optional(pool)
            .await?
        }))
    }

    /// An undo of this guild's that has not finished clearing. A channel that comes back
    /// under the same key before then would keep the old rows the undo still has to take.
    pub(super) async fn run_clearing(&self, guild: i64) -> Result<bool> {
        let n: i64 = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_imports i
                 WHERE i.guild_id = $1 AND i.undone_at IS NOT NULL
                   AND (i.archive_done_at IS NULL
                        OR EXISTS (SELECT 1 FROM voipc_import_items t WHERE t.import_id = i.id))",
            )
            .bind(guild)
            .fetch_one(pool)
            .await?
        });
        Ok(n > 0)
    }

    /// Undone runs whose archive rows are still to go.
    pub(super) async fn runs_with_rows_to_go(&self) -> Result<Vec<i64>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(id AS BIGINT) FROM voipc_imports
                 WHERE undone_at IS NOT NULL AND archive_done_at IS NULL ORDER BY id",
            )
            .fetch_all(pool)
            .await?
        }))
    }

    pub(super) async fn run_rows_gone(&self, run: i64) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_imports SET archive_done_at = $1 WHERE id = $2")
                .bind(util::now())
                .bind(run)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// An emote an import brought goes by another name now, or `to` is empty, which is
    /// nothing for an undo to remove.
    pub(crate) async fn emote_item_moved(&self, from: &str, to: &str) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_import_items SET local = $1 WHERE kind = $2 AND local = $3")
                .bind(to)
                .bind(KIND_EMOTE)
                .bind(from)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// (guild, stored count of archive rows, whether it is undone) of a run.
    async fn run_for_undo(&self, run: i64) -> Result<Option<(i64, i64, bool)>> {
        let row: Option<(i64, i64, Option<i64>)> = db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT CAST(guild_id AS BIGINT), CAST(archive_rows AS BIGINT), CAST(undone_at AS BIGINT)
                 FROM voipc_imports WHERE id = $1",
            )
            .bind(run)
            .fetch_optional(pool)
            .await?
        });
        Ok(row.map(|(guild, rows, undone)| (guild, rows, undone.is_some())))
    }

    /// Runs of this guild after this one that stand: a delta's rows mean nothing without the
    /// channels they live in, so those go first.
    async fn runs_after(&self, guild: i64, run: i64) -> Result<i64> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_imports
                 WHERE guild_id = $1 AND id > $2 AND undone_at IS NULL",
            )
            .bind(guild)
            .bind(run)
            .fetch_one(pool)
            .await?
        }))
    }

    /// What the run still has of a kind, with something to remove: Discord's id and the local
    /// name. Blanking `local` is what an undo goes on from.
    async fn undo_items(&self, run: i64, kind: i16, limit: i64) -> Result<Vec<(i64, String)>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT CAST(dc_id AS BIGINT), local FROM voipc_import_items
                 WHERE import_id = $1 AND kind = $2 AND local <> '' ORDER BY dc_id LIMIT $3",
            )
            .bind(run)
            .bind(kind)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }))
    }

    async fn undo_item_done(&self, kind: i16, dc_id: i64) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_import_items SET local = '' WHERE kind = $1 AND dc_id = $2")
                .bind(kind)
                .bind(dc_id)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// This run's accounts `drop_unclaimed` would take. One a moderator banned here stays,
    /// and goes by expiry once that is lifted.
    async fn undo_unclaimed(&self, run: i64) -> Result<Vec<Vec<u8>>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT p.account FROM voipc_placeholders p
                 WHERE p.import_id = $1 AND p.claimed_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM voipc_identity i WHERE i.account = p.account)
                   AND NOT EXISTS (SELECT 1 FROM voipc_bans b WHERE b.account = p.account)
                 LIMIT $2",
            )
            .bind(run)
            .bind(UNDO_ACCOUNTS)
            .fetch_all(pool)
            .await?
        }))
    }

    /// Someone who opened their account keeps everything, the mark too. It blocks nothing: a new
    /// import finds whoever still has Discord by their credential and leaves them as opened. And
    /// it is all that says who they were on Discord once they take it off, before or after this:
    /// without it a new import would link it back, and a ban's removal would find no rows. How
    /// many there are.
    pub(super) async fn undo_claimed(&self, run: i64) -> Result<u64> {
        let kept: i64 = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders
                 WHERE import_id = $1 AND claimed_at IS NOT NULL",
            )
            .bind(run)
            .fetch_one(pool)
            .await?
        });
        Ok(kept as u64)
    }

    /// The groups the run made: name, and whether it is a twin.
    async fn undo_groups(&self, run: i64) -> Result<Vec<(String, bool)>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT r.name, g.power FROM voipc_import_groups g
                 JOIN acct_roles r ON r.id = g.role WHERE g.import_id = $1",
            )
            .bind(run)
            .fetch_all(pool)
            .await?
        }))
    }

    /// The end of an undo: the threads it opened on earlier runs' messages, the ledger's rows
    /// and how far the run read. With these gone, and its archive rows, a new run may begin.
    async fn undo_ledger_drop(&self, run: i64) -> Result<()> {
        db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "UPDATE voipc_archive SET thread_name = NULL, replies = 0 \
                 WHERE thread = 0 AND import_id <> $1 AND (channel, dc_id) IN \
                 (SELECT CAST(t.local AS BIGINT), t.dc_id FROM voipc_import_items t \
                  WHERE t.import_id = $1 AND t.kind = $2)",
            )
            .bind(run)
            .bind(KIND_THREAD_MADE)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM voipc_import_items WHERE import_id = $1")
                .bind(run)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM voipc_import_cursors WHERE import_id = $1")
                .bind(run)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        });
        Ok(())
    }

    pub(super) async fn run_new(&self, guild: i64, by: &str, options: &str) -> Result<i64> {
        let by = clip(by, 64);
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar(
                "INSERT INTO voipc_imports (guild_id, by_name, started_at, options)
                 VALUES ($1, $2, $3, $4) RETURNING CAST(id AS BIGINT)",
            )
            .bind(guild)
            .bind(&by)
            .bind(util::now())
            .bind(options)
            .fetch_one(pool)
            .await?
        }))
    }

    /// What a resumed run runs under now: what `ImportMessages` holds a run to.
    pub(super) async fn run_options_put(&self, run: i64, options: &str) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_imports SET options = $1 WHERE id = $2")
                .bind(options)
                .bind(run)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// The run's guild, while it takes rows.
    pub(super) async fn run_open_guild(&self, run: i64) -> Result<Option<i64>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(guild_id AS BIGINT) FROM voipc_imports
                 WHERE id = $1 AND finished_at IS NULL AND undone_at IS NULL",
            )
            .bind(run)
            .fetch_optional(pool)
            .await?
        }))
    }

    /// Accounts, groups and bans the run made, for its row in the log. A twin is not
    /// counted: it holds back what its group's role could do.
    pub(super) async fn run_counts(&self, run: i64) -> Result<(i64, i64, i64)> {
        Ok(db!(self.store(), pool => {
            let people = |banned: bool| {
                sqlx::query_scalar::<_, i64>(
                    "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders WHERE import_id = $1 AND banned = $2",
                )
                .bind(run)
                .bind(banned)
                .fetch_one(pool)
            };
            let accounts = people(false).await?;
            let bans = people(true).await?;
            let groups = sqlx::query_scalar::<_, i64>(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_import_groups WHERE import_id = $1 AND power = $2",
            )
            .bind(run)
            .bind(false)
            .fetch_one(pool)
            .await?;
            (accounts, groups, bans)
        }))
    }

    /// Whether this ended the run. Finished once: the answer to a second is no.
    pub(super) async fn run_finish(&self, run: i64, report: &str) -> Result<bool> {
        let n = db!(self.store(), pool => {
            sqlx::query(
                "UPDATE voipc_imports SET finished_at = $1, report = $2
                 WHERE id = $3 AND finished_at IS NULL AND undone_at IS NULL",
            )
            .bind(util::now())
            .bind(report)
            .bind(run)
            .execute(pool)
            .await?
            .rows_affected()
        });
        Ok(n == 1)
    }

    /// Whether a run said yes to messages and to what copying them means: checked here as
    /// well, so that it is more than one client's checkbox.
    pub(super) async fn run_takes_messages(&self, run: i64) -> Result<bool> {
        let options: Option<String> = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT options FROM voipc_imports WHERE id = $1")
                .bind(run)
                .fetch_optional(pool)
                .await?
        });
        Ok(options
            .and_then(|o| serde_json::from_str::<ImportOptions>(&o).ok())
            .is_some_and(|o| o.messages && o.acknowledged))
    }

    /// What the runs made of this kind and still own: Discord's id, and the local name.
    pub(crate) async fn import_items(&self, kind: i16) -> Result<HashMap<i64, String>> {
        let rows: Vec<(i64, String)> = db!(self.store(), pool => {
            sqlx::query_as("SELECT CAST(dc_id AS BIGINT), local FROM voipc_import_items WHERE kind = $1")
                .bind(kind)
                .fetch_all(pool)
                .await?
        });
        Ok(rows.into_iter().collect())
    }

    /// (run, guild) of the newest unfinished run, and the options of the newest not undone.
    pub(super) async fn runs_for_facts(&self) -> Result<(Option<(i64, i64)>, Option<String>)> {
        Ok(db!(self.store(), pool => {
            (
                sqlx::query_as(
                    "SELECT CAST(id AS BIGINT), CAST(guild_id AS BIGINT) FROM voipc_imports
                     WHERE finished_at IS NULL AND undone_at IS NULL ORDER BY id DESC LIMIT 1",
                )
                .fetch_optional(pool)
                .await?,
                sqlx::query_scalar(
                    "SELECT options FROM voipc_imports WHERE undone_at IS NULL ORDER BY id DESC LIMIT 1",
                )
                .fetch_optional(pool)
                .await?,
            )
        }))
    }
}

/// `AdminOp::ImportFacts`: what the dry-run needs of this relay. `running` is someone else's
/// run: a session's own stopped one does not stand in its way, as `before_the_code` has it.
pub(super) async fn facts(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
) -> Result<AccountReply> {
    let db_file = relay.db_file();
    let (unfinished, options) = relay.runs_for_facts().await?;
    let channels = state.channel_list().await;
    let list = postcard::to_allocvec(&channels)?;
    let running = state
        .import
        .lock()
        .await
        .as_ref()
        .filter(|a| a.holds_against(state, session_id))
        .map(|a| a.run);
    let cfg = relay.accounts.host.config();
    let (_, accounts) = relay.store().list_users(None, 1, 0).await?;
    let facts = ImportFacts {
        backup_here: db_file.is_some(),
        db_bytes: db_file
            .and_then(|f| std::fs::metadata(f).ok())
            .map(|m| m.len()),
        max_users: state.max_users,
        online: state.user_count() as u32,
        registration: relay.info().registration,
        discord_sign_in: relay.provider_kinds().contains(&ProviderKind::Discord),
        public_url: cfg.oauth_base_url.clone(),
        takes_guests: !relay.required,
        accounts: accounts.clamp(0, i64::from(u32::MAX)) as u32,
        channel_list_bytes: list.len() as u32,
        // None here: a list too long for one frame comes in several (`send_channel_list`).
        // An older relay names its one frame, and the importer fits a list to that.
        channel_list_limit: u32::MAX,
        categories: state.layout.read().await.categories.len() as u32,
        max_categories: crate::layout::MAX_CATEGORIES as u32,
        emotes: state.emotes.as_ref().map_or(0, |e| e.count()) as u32,
        running,
        unfinished: unfinished.map(|(run, guild)| (run, guild.to_string())),
        cloud: relay.cloud,
        last_options: options.and_then(|o| serde_json::from_str(&o).ok()),
    };
    Ok(AccountReply::Admin(AdminReply::ImportFacts { facts }))
}

/// What can refuse `ImportBegin`, ahead of its code. `active` stays locked from here to
/// the run's row, so that two admins cannot both begin.
pub(super) async fn before_the_code(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    active: &Option<ActiveRun>,
    guild_id: &str,
    options: &ImportOptions,
    backup_taken: bool,
) -> Result<Result<Begin, String>> {
    let guild = match guild_id.parse::<u64>().ok().filter(|g| *g != 0) {
        Some(g) if g <= i64::MAX as u64 => g as i64,
        _ => return Ok(Err("That is not a Discord server's id.".into())),
    };
    if !relay.provider_kinds().contains(&ProviderKind::Discord) {
        return Ok(Err(
            "Nobody could sign in to what this makes: set public_url and the Discord application first."
                .into(),
        ));
    }
    if options.messages && !relay.cloud {
        return Ok(Err(
            "This server keeps no messages: set cloud = true first.".into(),
        ));
    }
    if active
        .as_ref()
        .is_some_and(|a| a.holds_against(state, session_id))
    {
        return Ok(Err(RUNNING.into()));
    }
    if relay.run_clearing(guild).await? {
        return Ok(Err("Still clearing the last undo.".into()));
    }
    let resumes = relay.run_unfinished(guild).await?;
    let here = relay.db_file().is_some();
    if let Some(reason) = no_copy_from_here(here, resumes.is_some(), backup_taken) {
        return Ok(Err(reason.into()));
    }
    Ok(Ok(Begin { guild, resumes }))
}

/// `AdminOp::ImportBegin`, past its code: the row in the log first, the run's row, then
/// its copy of the database, in a task: it can take minutes, and this session's read
/// loop waits on what runs here.
#[allow(clippy::too_many_arguments)]
pub(super) async fn begin(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: SessionId,
    by: &str,
    mut active: MutexGuard<'_, Option<ActiveRun>>,
    begin: Begin,
    options: &ImportOptions,
    ask: Option<u32>,
) -> Result<AccountReply> {
    let Begin { guild, resumes } = begin;
    let detail = match &resumes {
        Some((run, _)) => format!("guild {guild}, again, run {run}: {}", on_words(options)),
        None => format!("guild {guild}: {}", on_words(options)),
    };
    let row = modlog::Entry {
        action: "import",
        detail: &detail,
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, session_id, row).await {
        warn!("keeping an import's row: {e:#}");
        return Ok(refused("Admin", NOT_KEPT));
    }
    let options = serde_json::to_string(options)?;
    let resumed = resumes.is_some();
    let (run, backup) = match resumes {
        Some((run, backup)) => {
            relay.run_options_put(run, &options).await?;
            (run, backup)
        }
        None => (relay.run_new(guild, by, &options).await?, None),
    };
    // Its copy may be gone by now: only so many are kept. One made now holds what it did
    let again = backup.is_some();
    let backup = backup.filter(|b| Path::new(b).exists());
    let copying = active.as_ref().is_some_and(|a| a.run == run && !a.ready);
    let needs_copy = relay.db_file().filter(|_| backup.is_none());
    *active = Some(ActiveRun {
        run,
        session_id,
        ready: !copying && needs_copy.is_none(),
        last: Instant::now(),
        ask,
    });
    drop(active);
    let Some(db) = needs_copy else {
        return Ok(AccountReply::Admin(AdminReply::ImportBegun {
            run,
            resumed,
            backup,
        }));
    };
    // The task tells whoever holds the run by then
    if !copying {
        copy_then_tell(state.clone(), db, run, resumed, again);
    }
    Ok(AccountReply::Admin(AdminReply::ImportBackingUp { run }))
}

fn copy_then_tell(state: Arc<ServerState>, db: PathBuf, run: i64, resumed: bool, again: bool) {
    let Some(relay) = state.accounts.clone() else {
        return;
    };
    tokio::spawn(async move {
        let made = take_copy(&relay, &db, run, again).await;
        let mut active = state.import.lock().await;
        let Some(a) = active.as_mut().filter(|a| a.run == run) else {
            return;
        };
        let tx = state
            .sessions
            .get(&a.session_id)
            .map(|s| s.control_tx.clone());
        let ask = a.ask;
        let answer = match made {
            Ok(path) => {
                a.ready = true;
                a.last = Instant::now();
                AccountReply::Admin(AdminReply::ImportBegun {
                    run,
                    resumed,
                    backup: Some(path),
                })
            }
            Err(e) => {
                warn!("copying the database before an import: {e:#}");
                *active = None;
                refused(
                    "Admin",
                    "The database could not be copied, so nothing was imported. The server's log says why.",
                )
            }
        };
        if let Some(tx) = tx {
            let answer = super::asked(ask, answer);
            let _ = crate::session::send_msg(&tx, &ServerMessage::Account(answer));
        }
    });
}

/// In front of every frame of a run: `*`, and the run is this session's, its copy made,
/// and not finished or undone. `Ok`: the run's guild.
pub(super) async fn frame(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    scopes: &[String],
    run: i64,
) -> Result<Result<i64, AccountReply>> {
    if !is_star(scopes) {
        return Ok(Err(no_frame("Only an admin may import.")));
    }
    match state.import.lock().await.as_mut() {
        Some(a) if a.run == run && a.session_id == session_id => {
            if !a.ready {
                return Ok(Err(no_frame(
                    "The copy of the database is still being made.",
                )));
            }
            a.last = Instant::now();
        }
        _ => return Ok(Err(no_frame(NOT_OPEN))),
    }
    Ok(relay
        .run_open_guild(run)
        .await?
        .ok_or_else(|| no_frame(NOT_OPEN)))
}

/// `AdminOp::ImportEnd`, past `frame`. The log's row first. What every frame left for
/// the end then happens once: gates, who sees what, and the groups' looks.
pub(super) async fn end(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: SessionId,
    run: i64,
    report: &str,
) -> Result<AccountReply> {
    if report.len() > REPORT_BYTES {
        return Ok(no_frame("That report is over 40 KiB."));
    }
    // Which also keeps out what Postgres would refuse in a TEXT column
    if serde_json::from_str::<serde_json::Value>(report).is_err() {
        return Ok(no_frame("That report is not JSON."));
    }
    let (accounts, groups, bans) = relay.run_counts(run).await?;
    let detail = format!("{accounts} accounts, {groups} groups, {bans} bans");
    let row = modlog::Entry {
        action: "import_done",
        detail: &detail,
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, session_id, row).await {
        warn!("keeping an import's end: {e:#}");
        return Ok(no_frame(NOT_KEPT));
    }
    if !relay.run_finish(run, report).await? {
        return Ok(no_frame(NOT_OPEN));
    }
    {
        let mut active = state.import.lock().await;
        if active.as_ref().is_some_and(|a| a.run == run) {
            *active = None;
        }
    }
    placeholder::load(relay).await?;
    crate::gates::prune_soon(state);
    relay.archive_held_changed().await;
    // Which also tells everybody who holds what now
    super::revalidate(state).await;
    crate::layout::send_styles_all(state).await;
    crate::layout::send_all(state).await;
    Ok(AccountReply::Admin(AdminReply::ImportEnded { run }))
}

/// `AdminOp::ImportEmote`. A ledger row, so an undo finds it, and a cursor, so a delta
/// skips it: one removed here by hand stays removed.
pub(super) async fn emote(relay: &Relay, run: i64, dc_id: u64, name: &str) -> Result<AccountReply> {
    let made = db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        let made = sqlx::query(
            "INSERT INTO voipc_import_items (kind, dc_id, import_id, local) VALUES ($1, $2, $3, $4)
             ON CONFLICT (kind, dc_id) DO NOTHING",
        )
        .bind(KIND_EMOTE)
        .bind(dc_id as i64)
        .bind(run)
        .bind(name)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query(CURSOR_UP)
            .bind(dc_id as i64)
            .bind(run)
            .bind(1i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        made
    }) as u32;
    Ok(AccountReply::Admin(AdminReply::ImportAcked {
        stored: made,
        skipped: 1 - made,
    }))
}

/// `AdminOp::ImportCursors`: how far each channel, thread and emote is read over the runs
/// not undone, and a channel of theirs never walked at 0: "messages off" to a delta, with
/// nothing else on the relay to say so. Past `after`, in order. Asks for no run, so the
/// dry-run can read it.
pub(super) async fn cursors(relay: &Relay, after: u64) -> Result<AccountReply> {
    let after = i64::try_from(after).unwrap_or(i64::MAX);
    let mut rows: Vec<(i64, i64)> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT CAST(s.uid AS BIGINT), CAST(MAX(s.high) AS BIGINT) FROM (
                SELECT c.uid AS uid, c.high AS high FROM voipc_import_cursors c
                  JOIN voipc_imports i ON i.id = c.import_id WHERE i.undone_at IS NULL
                UNION ALL
                SELECT t.dc_id AS uid, 0 AS high FROM voipc_import_items t
                  JOIN voipc_imports i ON i.id = t.import_id
                 WHERE t.kind = $1 AND i.undone_at IS NULL
             ) s WHERE s.uid > $2 GROUP BY s.uid ORDER BY s.uid LIMIT $3",
        )
        .bind(KIND_CHANNEL)
        .bind(after)
        .bind(CURSOR_ROWS + 1)
        .fetch_all(pool)
        .await?
    });
    let more = rows.len() as i64 > CURSOR_ROWS;
    rows.truncate(CURSOR_ROWS as usize);
    Ok(AccountReply::Admin(AdminReply::ImportCursors {
        rows: rows
            .into_iter()
            .map(|(uid, high)| (uid as u64, high as u64))
            .collect(),
        more,
    }))
}

/// `AdminOp::ImportUndoPreview`: what an undo would take, for the dialog that asks. The
/// archive's count is the stored one: no index has `import_id`, and a person's deletion since
/// makes it read a little high, which the dialog says as "about".
pub(super) async fn undo_preview(relay: &Relay, run: i64) -> Result<AccountReply> {
    let Some((guild, archive_rows, _)) = relay.run_for_undo(run).await? else {
        return Ok(refused("Admin", NO_SUCH_RUN));
    };
    let later_runs = relay.runs_after(guild, run).await?;
    let (channels, live_posts, groups, placeholders, claimed_kept, emotes): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = db!(relay.store(), pool => {
        let people = |claimed: &'static str| {
            sqlx::query_scalar::<_, i64>(claimed).bind(run).fetch_one(pool)
        };
        (
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_import_items t
                 JOIN voipc_channels c ON c.conv = t.local WHERE t.import_id = $1 AND t.kind = $2",
            )
            .bind(run)
            .bind(KIND_CHANNEL)
            .fetch_one(pool)
            .await?,
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_log l WHERE l.conv IN
                 (SELECT t.local FROM voipc_import_items t WHERE t.import_id = $1 AND t.kind = $2)",
            )
            .bind(run)
            .bind(KIND_CHANNEL)
            .fetch_one(pool)
            .await?,
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_import_groups WHERE import_id = $1 AND power = $2",
            )
            .bind(run)
            .bind(false)
            .fetch_one(pool)
            .await?,
            people("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders WHERE import_id = $1 AND claimed_at IS NULL").await?,
            people("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders WHERE import_id = $1 AND claimed_at IS NOT NULL").await?,
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_import_items
                 WHERE import_id = $1 AND kind = $2 AND local <> ''",
            )
            .bind(run)
            .bind(KIND_EMOTE)
            .fetch_one(pool)
            .await?,
        )
    });
    let n = |v: i64| v.clamp(0, i64::from(u32::MAX)) as u32;
    Ok(AccountReply::Admin(AdminReply::ImportUndoPreview {
        run,
        counts: ImportUndoCounts {
            channels: n(channels),
            live_posts: live_posts.max(0) as u64,
            groups: n(groups),
            placeholders: n(placeholders),
            claimed_kept: n(claimed_kept),
            archive_rows: archive_rows.max(0) as u64,
            emotes: n(emotes),
            later_runs: n(later_runs),
        },
    }))
}

/// What refuses `AdminOp::ImportUndo`, ahead of its code. A run someone else is on goes on
/// sending frames; a later run's rows mean nothing without this one's channels.
pub(super) async fn undo_refusal(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    active: &Option<ActiveRun>,
    run: i64,
) -> Result<Option<&'static str>> {
    let Some((guild, _, _)) = relay.run_for_undo(run).await? else {
        return Ok(Some(NO_SUCH_RUN));
    };
    if relay.runs_after(guild, run).await? > 0 {
        return Ok(Some("A later run of this server stands: undo that first."));
    }
    if active
        .as_ref()
        .is_some_and(|a| a.run == run && a.holds_against(state, session_id))
    {
        return Ok(Some(RUNNING));
    }
    Ok(None)
}

/// What one call of an undo did, for the panel to add up.
#[derive(Default)]
struct Undone {
    accounts: u32,
    kept_claimed: u32,
    groups: u32,
    groups_kept: Vec<String>,
    channels: u32,
    emotes: u32,
}

/// `AdminOp::ImportUndo`, past its code. A call does one step and says if there is more, since
/// each runs in this session's read loop; each goes on from what the database says, so an undo
/// that dies is taken up again. Channels first, because gates name groups. The first call marks
/// the run, and from then no cursor or frame counts it. What it filed in the archive is not
/// done here: a channel's rows go with the channel's row, and the worker takes the rest.
pub(super) async fn undo(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: SessionId,
    ctx: &Ctx,
    actor: Actor<'_>,
    mut active: MutexGuard<'_, Option<ActiveRun>>,
    run: i64,
) -> Result<AccountReply> {
    let Some((_, archive_rows, marked)) = relay.run_for_undo(run).await? else {
        return Ok(refused("Admin", NO_SUCH_RUN));
    };
    if !marked {
        let detail = format!("run {run}");
        let row = modlog::Entry {
            action: "import_undo",
            detail: &detail,
            ..Default::default()
        };
        if let Err(e) = modlog::put(state, session_id, row).await {
            warn!("keeping an undo's row: {e:#}");
            return Ok(refused("Admin", NOT_KEPT));
        }
        db!(relay.store(), pool => {
            sqlx::query("UPDATE voipc_imports SET undone_at = $1 WHERE id = $2 AND undone_at IS NULL")
                .bind(util::now())
                .bind(run)
                .execute(pool)
                .await?;
        });
    }
    if active.as_ref().is_some_and(|a| a.run == run) {
        *active = None;
    }
    drop(active);
    let answer = |done: Undone, more: bool| {
        Ok(AccountReply::Admin(AdminReply::ImportUndone {
            run,
            more,
            accounts: done.accounts,
            kept_claimed: done.kept_claimed,
            groups: done.groups,
            groups_kept: done.groups_kept,
            channels: done.channels,
            emotes: done.emotes,
            archive_rows: archive_rows.max(0) as u64,
        }))
    };
    let mut done = Undone::default();

    let channels = relay.undo_items(run, KIND_CHANNEL, UNDO_CHANNELS).await?;
    if !channels.is_empty() {
        for (dc_id, conv) in channels {
            if crate::layout::import_purge(state, relay, &conv).await? {
                done.channels += 1;
            }
            relay.undo_item_done(KIND_CHANNEL, dc_id).await?;
        }
        return answer(done, true);
    }

    let categories = relay.undo_items(run, KIND_CATEGORY, i64::MAX).await?;
    let emotes = relay.undo_items(run, KIND_EMOTE, i64::MAX).await?;
    if !categories.is_empty() || !emotes.is_empty() {
        for (dc_id, local) in categories {
            if let Ok(id) = local.parse::<u32>() {
                crate::layout::import_category_purge(state, relay, id).await?;
            }
            relay.undo_item_done(KIND_CATEGORY, dc_id).await?;
        }
        if let Some(store) = &state.emotes {
            let names: Vec<String> = emotes.iter().map(|(_, name)| name.clone()).collect();
            let unknown = store.remove(&names);
            if unknown.len() < names.len() {
                store.changed(state);
            }
            done.emotes = (names.len() - unknown.len()) as u32;
        }
        for (dc_id, _) in emotes {
            relay.undo_item_done(KIND_EMOTE, dc_id).await?;
        }
        return answer(done, true);
    }

    let open = relay.undo_unclaimed(run).await?;
    if !open.is_empty() {
        for account in &open {
            if let Ok(id) = <[u8; 16]>::try_from(account.as_slice()) {
                if relay.drop_unclaimed(AccountId(id)).await? {
                    done.accounts += 1;
                }
            }
        }
        return answer(done, true);
    }

    done.kept_claimed = relay.undo_claimed(run).await? as u32;
    // In one go: Discord gives a server 250 roles, so twins and all this is no long list. One
    // kept stays in the ledger, so that the next run takes it up instead of making its twin.
    for (name, twin) in relay.undo_groups(run).await? {
        if crate::gates::uses(state, session_id, &name).await.is_some() {
            done.groups_kept.push(name);
            continue;
        }
        match relay.accounts.delete_role(ctx, actor, &name).await {
            Ok(()) => done.groups += u32::from(!twin),
            Err(e) => {
                warn!("taking back a group: {}", e.message());
                done.groups_kept.push(name);
            }
        }
    }
    relay.undo_ledger_drop(run).await?;
    placeholder::load(relay).await?;
    crate::gates::prune_soon(state);
    relay.archive_held_changed().await;
    // Which also tells everybody who holds what now
    super::revalidate(state).await;
    crate::layout::send_styles_all(state).await;
    crate::layout::send_all(state).await;
    relay.archive_kick.notify_one();
    answer(done, false)
}

/// `AdminOp::ImportReport`.
pub(super) async fn report(relay: &Relay, run: i64) -> Result<AccountReply> {
    let row: Option<Option<String>> = db!(relay.store(), pool => {
        sqlx::query_scalar("SELECT report FROM voipc_imports WHERE id = $1")
            .bind(run)
            .fetch_optional(pool)
            .await?
    });
    Ok(match row {
        Some(report) => AccountReply::Admin(AdminReply::ImportReport {
            run,
            report: report.unwrap_or_default(),
        }),
        None => refused("Admin", NO_SUCH_RUN),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_needs_backup_taken() {
        // There, a new run needs the tick
        assert!(no_copy_from_here(false, false, false).is_some());
        assert!(no_copy_from_here(false, false, true).is_none());
        // A resumed one had it, and SQLite makes its own
        assert!(no_copy_from_here(false, true, false).is_none());
        assert!(no_copy_from_here(true, false, false).is_none());
    }

    #[test]
    fn only_the_newest_two_copies_stay_and_nothing_else_is_touched() {
        let dir = std::env::temp_dir().join(format!("voipc-copies-{:08x}", rand::random::<u32>()));
        std::fs::create_dir(&dir).unwrap();
        let db = dir.join("voipc.db");
        let names = [
            "voipc.db",
            "voipc.db-wal",
            // Two copies stay, however their names sort
            "voipc.db.before-import-9",
            "voipc.db.before-import-10",
            "voipc.db.before-import-11",
            // A dead attempt older than the newest copy goes, one at it stays
            "voipc.db.before-import-3.part",
            "voipc.db.before-import-11.part",
            // Not ours
            "voipc.db.before-import-notes",
            "voipc.db.before-import-",
            "voipc.db.before-import-9.bak",
            "other.db.before-import-1",
            "voipc.db.before-resuming-import-",
            // A resumed run's copy counts as a copy, and the one just made stays
            "voipc.db.before-resuming-import-4",
            "voipc.db.before-resuming-import-5",
        ];
        for n in names {
            std::fs::write(dir.join(n), b"x").unwrap();
        }
        prune_copies(&db, &dir.join("voipc.db.before-resuming-import-5"));
        let gone = [
            "voipc.db.before-import-9",
            "voipc.db.before-import-10",
            "voipc.db.before-import-3.part",
            "voipc.db.before-resuming-import-4",
        ];
        for n in names {
            assert_eq!(dir.join(n).exists(), !gone.contains(&n), "{n}");
        }
        for n in names {
            let _ = std::fs::remove_file(dir.join(n));
        }
        std::fs::remove_dir(&dir).unwrap();
    }
}
