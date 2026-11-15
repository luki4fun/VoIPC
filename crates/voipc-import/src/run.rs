//! The run: what the wizard chose, read from Discord and sent to the relay. The page has
//! begun it (`ImportBegin`, with its code and the relay's copy); this does the rest, in the
//! order the relay needs: roles, categories, channels, members, bans, emotes, threads,
//! messages, the end.
//!
//! One frame is in flight at a time and the control stream is reliable, so there are no
//! sequence numbers and nothing is sent twice. A frame answered is stored; one that was not
//! is read again by the next run, which starts from the relay's cursors. So everything that
//! stops a run, a cut or the Stop button included, loses nothing.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{sleep, sleep_until, timeout, Duration, Instant};
use voipc_protocol::discord;
use voipc_protocol::messages::{AdminOp, AdminReply};
use voipc_protocol::types::{
    ImportFacts, ImportOptions, ImportThread, MoveFilter, THREAD_TAKEN_BACK,
};

use crate::api::{Api, Fail, Transport};
use crate::batch;
use crate::model::{Application, Ban, Member, Message, User, FORUM, MEDIA};
use crate::plan::{self, Choices, Here, Layout, PlannedEmote, Read, Report};
use crate::rewrite::{
    ban_row, blank_page_proves_it, member_row, page_is_blank, role_row, row_of, Names,
};
use crate::Note;

/// Channels or threads walked at once, over the one writer.
const WALKERS: usize = 4;
/// Frames waiting for the writer. With a page being split per walker, this is all a run
/// holds of anyone's messages, and in RAM.
const FRAMES_WAITING: usize = 8;
/// One frame every so long: 8 a second, under the relay's `account_rate` (burst 30, 10 a
/// second), so a panel click beside a run still gets through.
pub const FRAME_PACE: Duration = Duration::from_millis(125);
/// No answer in this long: the connection is gone in all but name.
const REPLY_WAIT: Duration = Duration::from_secs(120);
/// How long `Too many requests` takes to pass.
const SLOW_DOWN: Duration = Duration::from_secs(1);
/// `handle_request`'s refusal, ahead of any op: the one thing that sends a frame again.
const SLOW_DOWN_SAYS: &str = "Too many requests";
/// Off by more than this against Discord's own count, in percent: worth a line.
const COUNT_OFF_PERCENT: u64 = 2;
/// How far ahead this machine's clock may be, against Discord's ids. Going back further only
/// costs a question about someone who posted just before the member list was read.
const CLOCK_SLACK_MS: i64 = 10 * 60 * 1000;

const STOPPED: &str = "Stopped. Nothing is lost: run it again to go on from here.";
const NOT_ACKNOWLEDGED: &str = "Tick what copying members' messages means first.";
const NO_REPLY: &str = "The server stopped answering. Nothing is lost: run it again to go on.";
const ODD_REPLY: &str =
    "The server answered something else. Nothing is lost: run it again to go on.";
const NO_MEMBERS: &str = "The member list would not come, and without it everyone would go in \
                          as a former member. Run it again, or turn Anonymise off.";

/// Why a channel's first page stopped the run.
fn blank(name: &str) -> String {
    format!(
        "#{name}: Discord is sending blank messages: Message Content is off. Turn it on in the \
         Developer Portal, then run this again."
    )
}

/// Why the relay did not answer a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// `AccountReply::Error`: it said no, in words.
    Said(String),
    /// The connection is gone.
    Gone(String),
}

/// The way to the relay: one frame at a time, its reply back.
pub trait RelayLink: Send {
    fn call(&mut self, op: AdminOp) -> impl Future<Output = Result<AdminReply, Stop>> + Send;
}

/// Where an emote or a sticker goes: into the relay's own store, by the way any other does.
/// `Err`: why it did not, and the run goes on without it.
pub trait EmoteSink: Send {
    /// Into the relay's store. `Ok`: the name it is listed under, `emote.name` unless an
    /// earlier run put it there under another (W2-27).
    fn add(&mut self, emote: &PlannedEmote) -> impl Future<Output = Result<String, String>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Starting,
    Roles,
    Channels,
    Members,
    Bans,
    Emotes,
    Threads,
    Messages,
    Ending,
}

/// What the page shows of a run: counts and a channel's name, never anything anyone wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Progress {
    pub phase: Phase,
    pub done: u64,
    /// 0: not known.
    pub total: u64,
    pub channel: String,
}

impl Default for Progress {
    fn default() -> Self {
        Progress {
            phase: Phase::Starting,
            done: 0,
            total: 0,
            channel: String::new(),
        }
    }
}

/// One run, as the wizard left it.
pub struct Job {
    pub run: i64,
    pub choices: Choices,
    /// `FRAME_PACE`, but for a test.
    pub pace: Duration,
    /// True: stop.
    pub stop: watch::Receiver<bool>,
    pub progress: watch::Sender<Progress>,
}

impl Job {
    fn say(&self, phase: Phase, done: u64, total: u64, channel: &str) {
        self.progress.send_replace(Progress {
            phase,
            done,
            total,
            channel: channel.to_string(),
        });
    }
}

/// How a run came out. The report is what it has so far, either way.
#[derive(Debug)]
pub struct Outcome {
    pub report: Report,
    /// None: it finished. Otherwise why not, and everything stored stays.
    pub stopped: Option<String>,
}

/// One frame in flight, paced.
struct Writer<'a, L> {
    link: &'a mut L,
    pace: Duration,
    next: Instant,
}

impl<L: RelayLink> Writer<'_, L> {
    /// The answer to a frame. `ImportRefused` with no channel is an `Err`: it stops the run.
    async fn ask(&mut self, op: AdminOp) -> Result<AdminReply, String> {
        loop {
            sleep_until(self.next).await;
            self.next = Instant::now() + self.pace;
            match timeout(REPLY_WAIT, self.link.call(op.clone())).await {
                Err(_) => return Err(NO_REPLY.into()),
                Ok(Err(Stop::Gone(words))) => return Err(words),
                Ok(Err(Stop::Said(reason))) if reason.starts_with(SLOW_DOWN_SAYS) => {
                    sleep(SLOW_DOWN).await;
                }
                Ok(Err(Stop::Said(reason))) => return Err(reason),
                Ok(Ok(AdminReply::ImportRefused {
                    reason,
                    channel: None,
                })) => return Err(reason),
                Ok(Ok(reply)) => return Ok(reply),
            }
        }
    }
}

async fn facts_of<L: RelayLink>(w: &mut Writer<'_, L>) -> Result<ImportFacts, String> {
    match w.ask(AdminOp::ImportFacts).await? {
        AdminReply::ImportFacts { facts } => Ok(facts),
        _ => Err(ODD_REPLY.into()),
    }
}

/// All pages of `ImportCursors`.
async fn cursors_of<L: RelayLink>(w: &mut Writer<'_, L>) -> Result<HashMap<u64, u64>, String> {
    let mut all = HashMap::new();
    let mut after = 0;
    loop {
        match w.ask(AdminOp::ImportCursors { after }).await? {
            AdminReply::ImportCursors { rows, more } => {
                after = rows.last().map_or(after, |(uid, _)| *uid);
                let empty = rows.is_empty();
                all.extend(rows);
                if !more || empty {
                    return Ok(all);
                }
            }
            _ => return Err(ODD_REPLY.into()),
        }
    }
}

/// When the newest run of this guild that was not undone started: a delta goes by it.
async fn last_started_ms<L: RelayLink>(
    w: &mut Writer<'_, L>,
    guild: u64,
) -> Result<Option<i64>, String> {
    match w.ask(AdminOp::MoveStatus).await? {
        AdminReply::MoveStatus { runs, .. } => {
            let guild = guild.to_string();
            Ok(runs
                .iter()
                .filter(|r| r.undone_at.is_none() && r.guild_id == guild)
                .map(|r| r.started_at.saturating_mul(1000))
                .max())
        }
        _ => Err(ODD_REPLY.into()),
    }
}

/// What the relay can say for a dry-run. `channels` and `emote_names` are what the app holds
/// already: `(name, is text)` of each channel, and each emote's name.
pub async fn here_of<L: RelayLink>(
    link: &mut L,
    guild: u64,
    channels: Vec<(String, bool)>,
    emote_names: Vec<String>,
) -> Result<Here, String> {
    let mut w = Writer {
        link,
        pace: Duration::ZERO,
        next: Instant::now(),
    };
    Ok(Here {
        facts: facts_of(&mut w).await?,
        channels,
        emote_names,
        cursors: cursors_of(&mut w).await?,
        last_started_ms: last_started_ms(&mut w, guild).await?,
    })
}

/// Who no import takes, as the relay has it now.
async fn excluded<L: RelayLink>(w: &mut Writer<'_, L>, names: &mut Names) -> Result<(), String> {
    let mut after = String::new();
    loop {
        match w
            .ask(AdminOp::MoveExcluded {
                after: after.clone(),
            })
            .await?
        {
            AdminReply::MoveExcluded { ids, more } => {
                for (id, own, erase, _) in &ids {
                    names.add_excluded(id, *own, *erase);
                }
                match ids.last() {
                    Some((last, ..)) if more => after.clone_from(last),
                    _ => return Ok(()),
                }
            }
            _ => return Err(ODD_REPLY.into()),
        }
    }
}

/// All that people said of their rows: in RAM, for what cannot carry an id. Without anonymise
/// every row has one, and the relay goes by these itself.
async fn wishes<L: RelayLink>(w: &mut Writer<'_, L>, names: &mut Names) -> Result<(), String> {
    let mut after = None;
    loop {
        let reply = w
            .ask(AdminOp::ArchiveWishes {
                after: after.clone(),
            })
            .await?;
        let AdminReply::ArchiveWishes { rows, more } = reply else {
            return Err(ODD_REPLY.into());
        };
        after = rows.last().cloned();
        for wish in rows {
            names.wishes.entry(wish.author).or_default().push(wish);
        }
        if !more || after.is_none() {
            return Ok(());
        }
    }
}

fn add(report: &mut Report, count: &str, n: u64) {
    if n > 0 {
        *report.counts.entry(count.to_string()).or_default() += n;
    }
}

/// Top roles first: what one group list cannot hold is the bottom of Discord's list.
async fn send_roles<L: RelayLink>(
    w: &mut Writer<'_, L>,
    read: &Read,
    run: i64,
    report: &mut Report,
) -> Result<(), String> {
    let mut rows: Vec<_> = read
        .roles
        .iter()
        .filter_map(|r| role_row(r, read.guild.id))
        .collect();
    rows.sort_by_key(|r| (std::cmp::Reverse(r.position), r.dc_id));
    for op in batch::roles(run, rows) {
        let AdminReply::ImportRolesDone {
            made,
            updated,
            skipped,
            power_changed,
        } = w.ask(op).await?
        else {
            return Err(ODD_REPLY.into());
        };
        add(report, "groups_made", u64::from(made));
        add(report, "groups_updated", u64::from(updated));
        for role in skipped {
            report.notes.push(Note::screen(
                "role_no_room",
                None,
                format!("@{role}: it did not come. Either one group list cannot hold it, or someone deleted its group here. A gate naming it stays closed."),
            ));
        }
        for role in power_changed {
            report.notes.push(Note::kept(
                "power_changed",
                None,
                format!(
                    "@{role}: what it can do on Discord changed. Here that stays yours to change."
                ),
            ));
        }
    }
    Ok(())
}

/// Categories and channels. What the relay would not make or no longer has is not walked.
async fn send_channels<L: RelayLink>(
    w: &mut Writer<'_, L>,
    layout: &Layout,
    run: i64,
    report: &mut Report,
) -> Result<HashSet<u64>, String> {
    let category: HashMap<u64, &str> = layout
        .categories
        .iter()
        .map(|c| (c.dc_id, c.name.as_str()))
        .collect();
    for op in batch::categories(run, layout.categories.clone()) {
        let AdminReply::ImportChannelsDone { refused } = w.ask(op).await? else {
            return Err(ODD_REPLY.into());
        };
        for (id, why) in refused {
            let name = category.get(&id).copied().unwrap_or("a category");
            report.notes.push(Note::screen(
                "category_refused",
                None,
                format!("{name}: {why} Its channels sit outside any category."),
            ));
        }
    }
    let name: HashMap<u64, &str> = layout
        .channels
        .iter()
        .map(|c| (c.row.dc_id, c.row.name.as_str()))
        .collect();
    let rows = layout.channels.iter().map(|c| c.row.clone()).collect();
    let mut gone = HashSet::new();
    for op in batch::channels(run, rows) {
        let AdminReply::ImportChannelsDone { refused } = w.ask(op).await? else {
            return Err(ODD_REPLY.into());
        };
        for (id, why) in refused {
            let name = name.get(&id).copied().unwrap_or("a channel");
            report.notes.push(Note::screen(
                "channel_refused",
                Some(id),
                format!("#{name}: {why}"),
            ));
            report.left_out.insert(id);
            gone.insert(id);
        }
    }
    let new = layout
        .channels
        .iter()
        .filter(|c| !c.in_ledger && !gone.contains(&c.row.dc_id))
        .count();
    add(report, "channels", new as u64);
    Ok(gone)
}

/// All of `/members`, whatever comes of it: telling a member from an ex-member takes it, and
/// so does saying who a mention was. Nobody left out, no bot and nobody in screening is sent.
async fn members<T: Transport, L: RelayLink>(
    api: &Api<T>,
    w: &mut Writer<'_, L>,
    guild: u64,
    layout: &Layout,
    run: i64,
    names: &mut Names,
    report: &mut Report,
) -> Result<(), String> {
    let (send, anonymise) = (layout.options.members, layout.options.anonymise);
    if !send && !anonymise {
        return Ok(());
    }
    let mut after = 0;
    loop {
        let path = format!("/guilds/{guild}/members?limit=1000&after={after}");
        let page: Vec<Member> = match api.get(&path).await {
            Ok(page) => page,
            Err(Fail::Stop(words)) => return Err(words),
            Err(Fail::Skip { .. }) if anonymise => return Err(NO_MEMBERS.into()),
            Err(Fail::Skip { note, .. }) => {
                report.notes.push(Note::screen(
                    "members_not_read",
                    None,
                    format!("Some of the member list did not come. {note}"),
                ));
                return Ok(());
            }
        };
        let high = page
            .iter()
            .filter_map(|m| m.user.as_ref().map(|u| u.id))
            .max();
        let Some(high) = high.filter(|h| *h > after) else {
            // The bot is a member itself, so nobody at all is not the list
            if after == 0 && anonymise {
                return Err(NO_MEMBERS.into());
            }
            return Ok(());
        };
        for member in &page {
            names.add_member(member);
        }
        if send {
            let rows = page.iter().filter_map(|m| member_row(m, names)).collect();
            for op in batch::members(run, rows) {
                let AdminReply::ImportMembersDone {
                    made,
                    updated,
                    left_out,
                    nicknames_dropped,
                    unlinked,
                    kept_power,
                    failed,
                } = w.ask(op).await?
                else {
                    return Err(ODD_REPLY.into());
                };
                add(report, "accounts_made", u64::from(made));
                add(report, "accounts_updated", u64::from(updated));
                add(report, "accounts_left_out", u64::from(left_out));
                add(report, "nicknames_dropped", u64::from(nicknames_dropped));
                add(report, "accounts_unlinked", u64::from(unlinked));
                add(report, "accounts_kept_power", u64::from(kept_power));
                for who in failed {
                    report.notes.push(Note::screen(
                        "account_failed",
                        None,
                        format!("{who}: could not be made here."),
                    ));
                }
            }
        }
        after = high;
    }
}

/// Bans, as an id each. Names and reasons stay on this screen. Someone no longer banned on
/// Discord is only said: lifting one is the owner's to do.
async fn bans<T: Transport, L: RelayLink>(
    api: &Api<T>,
    w: &mut Writer<'_, L>,
    guild: u64,
    run: i64,
    names: &Names,
    report: &mut Report,
) -> Result<(), String> {
    let list: Vec<Ban> = match plan::all_bans(api, guild).await {
        Ok(list) => list,
        Err(Fail::Stop(words)) => return Err(words),
        Err(Fail::Skip { note, .. }) => {
            // Not an empty list: nobody here may read as no longer banned there
            report.notes.push(Note::screen(
                "bans_not_read",
                None,
                format!("The ban list did not come, so no ban did. {note}"),
            ));
            return Ok(());
        }
    };
    let rows = list.iter().filter_map(|b| ban_row(b, names)).collect();
    for op in batch::bans(run, rows) {
        let AdminReply::ImportBansDone {
            made,
            converted,
            claimed,
            names_kept,
        } = w.ask(op).await?
        else {
            return Err(ODD_REPLY.into());
        };
        add(report, "bans_made", u64::from(made));
        add(report, "bans_converted", u64::from(converted));
        for who in claimed {
            report.notes.push(Note::screen(
                "ban_of_a_claimed_account",
                None,
                format!("{who} is banned on Discord and has opened their account here. It is left alone: yours to judge."),
            ));
        }
        for who in names_kept {
            report.notes.push(Note::screen(
                "ban_kept_a_name",
                None,
                format!("{who} is banned on Discord and keeps that name here: every other was taken. Anyone who can read the Users tab sees it."),
            ));
        }
    }
    let banned: HashSet<String> = list.iter().map(|b| b.user.id.to_string()).collect();
    let mut offset = 0u32;
    loop {
        let reply = w
            .ask(AdminOp::MoveAccounts {
                search: String::new(),
                offset,
                filter: MoveFilter::Banned,
            })
            .await?;
        let AdminReply::MoveAccounts { rows, total, .. } = reply else {
            return Err(ODD_REPLY.into());
        };
        let empty = rows.is_empty();
        offset = offset.saturating_add(rows.len() as u32);
        for row in rows {
            if !banned.contains(&row.dc_id) {
                report.notes.push(Note::screen(
                    "no_longer_banned",
                    None,
                    format!(
                        "{}: no longer banned on Discord, still banned here. Lifting it is yours to do.",
                        row.user.name
                    ),
                ));
            }
        }
        if empty || offset >= total {
            return Ok(());
        }
    }
}

/// Each into the relay's store, and only then in the ledger: one that did not come is tried
/// again next time. `adding` holds off Stop: an emote the relay has listed and its ledger frame
/// go together, or no undo would ever remove it. Stop is taken here, between two.
async fn emotes<L: RelayLink, E: EmoteSink>(
    w: &mut Writer<'_, L>,
    sink: &mut E,
    job: &Job,
    layout: &Layout,
    names: &mut Names,
    adding: &watch::Sender<bool>,
    report: &mut Report,
) -> Result<(), String> {
    let total = layout.emotes.len() as u64;
    for (done, emote) in layout.emotes.iter().enumerate() {
        if *job.stop.borrow() {
            return Err(STOPPED.into());
        }
        job.say(Phase::Emotes, done as u64, total, "");
        adding.send_replace(true);
        let listed = match sink.add(emote).await {
            Ok(listed) => listed,
            Err(why) => {
                adding.send_replace(false);
                report.notes.push(Note::screen(
                    "emote_failed",
                    None,
                    format!(":{}: did not come. {why}", emote.raw),
                ));
                continue;
            }
        };
        // A run cut before its ledger frame left it listed under the name an earlier read
        // gave it, and a new read named it anew: the ledger and the posts go by the first
        if listed != emote.name {
            names.emotes.insert(emote.id, listed.clone());
        }
        let op = AdminOp::ImportEmote {
            run: job.run,
            dc_id: emote.id,
            name: listed,
        };
        let reply = w.ask(op).await;
        adding.send_replace(false);
        let AdminReply::ImportAcked { stored, .. } = reply? else {
            return Err(ODD_REPLY.into());
        };
        add(report, "emotes", u64::from(stored));
    }
    Ok(())
}

/// One channel's own messages, or one thread's.
struct Walk {
    channel: u64,
    thread: Option<u64>,
    name: Arc<str>,
    last: Option<u64>,
    after: u64,
    /// What Discord says it holds, for one read from the start.
    counted: Option<u64>,
}

/// What the walkers tell the writer.
enum Walked {
    Frame {
        op: AdminOp,
        name: Arc<str>,
    },
    /// Threads whose first message does not come. Counted when the threads went.
    TakenBack(AdminOp),
    Note(Note),
    /// A channel's own messages were read from the start to the end, this many.
    Read {
        walk: Walk,
        read: u64,
    },
    Stop(String),
}

struct Walkers<T> {
    api: Arc<Api<T>>,
    names: Arc<Names>,
    options: ImportOptions,
    run: i64,
    guild: u64,
    queue: Arc<Mutex<VecDeque<Walk>>>,
    /// The threads the relay was told of, and how many replies each holds.
    threads: Arc<HashMap<u64, u32>>,
    /// Channels the relay refused: nothing more of them.
    skip: Arc<Mutex<HashSet<u64>>>,
    /// Who has been asked after. Held across the question: nobody is asked twice, and a walker
    /// with a row of theirs waits for the answer.
    asked: Arc<tokio::sync::Mutex<HashSet<u64>>>,
    tx: mpsc::Sender<Walked>,
}

fn locked<V>(mutex: &Mutex<V>) -> MutexGuard<'_, V> {
    // Held across no await, and nothing under it panics
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<T: Transport + 'static> Walkers<T> {
    fn clone_of(&self) -> Self {
        Walkers {
            api: self.api.clone(),
            names: self.names.clone(),
            options: self.options.clone(),
            run: self.run,
            guild: self.guild,
            queue: self.queue.clone(),
            threads: self.threads.clone(),
            skip: self.skip.clone(),
            asked: self.asked.clone(),
            tx: self.tx.clone(),
        }
    }

    /// Until the queue is empty, or the writer is gone, which only happens when it stopped.
    async fn work(self) {
        loop {
            let next = locked(&self.queue).pop_front();
            let Some(walk) = next else { return };
            if locked(&self.skip).contains(&walk.channel) {
                continue;
            }
            if self.walk(walk).await.is_none() {
                return;
            }
        }
    }

    /// `high` 1 says it was walked and found empty: 0 would read as messages off, next time.
    async fn found_empty(&self, walk: &Walk) -> Option<()> {
        if walk.thread.is_some() || walk.after != 0 {
            return Some(());
        }
        let op = batch::walked_empty(self.run, walk.channel, None);
        self.send(Walked::Frame {
            op,
            name: walk.name.clone(),
        })
        .await
    }

    async fn send(&self, walked: Walked) -> Option<()> {
        self.tx.send(walked).await.ok()
    }

    /// Why a first page stops the run, if it does. Few rows prove nothing, as a quiet channel's
    /// only post may be empty for reasons of its own, so then Discord says. Stopping loses
    /// nothing and a blank is stored for good, so one that will not say stops it too.
    async fn blank_page_stops(&self, page: &[Message], name: &str) -> Option<String> {
        if !page_is_blank(page) {
            return None;
        }
        if blank_page_proves_it(page) {
            return Some(blank(name));
        }
        match self.api.get::<Application>("/applications/@me").await {
            Ok(app) if app.content_intent() => None,
            Err(Fail::Stop(words)) => Some(words),
            _ => Some(blank(name)),
        }
    }

    /// Whoever wrote this page since the member list was read, or was mentioned in it, and is
    /// not on the list, may have joined since. Only a 404 says they have left. None: the run is
    /// over, or stopping.
    async fn ask_who_joined(&self, page: &[Message], walk: &Walk) -> Option<()> {
        let people: Vec<&User> = page
            .iter()
            .flat_map(|m| {
                let wrote = self.names.may_have_joined_since(m).then_some(&m.author);
                wrote.into_iter().chain(self.names.mentioned_since(m))
            })
            .collect();
        for who in people {
            let mut asked = self.asked.lock().await;
            if !asked.insert(who.id) {
                continue;
            }
            let path = format!("/guilds/{}/members/{}", self.guild, who.id);
            match self.api.get::<Member>(&path).await {
                Ok(member) => self.names.add_late(&member, who),
                Err(Fail::Stop(words)) => {
                    let _ = self.send(Walked::Stop(words)).await;
                    return None;
                }
                Err(Fail::Skip {
                    status: Some(404), ..
                }) => {}
                Err(Fail::Skip { note, .. }) => {
                    let text = format!(
                        "#{}: Discord would not say whether someone who wrote or was mentioned \
                         during the run is a member, so they went in as a former member. {note}",
                        walk.name
                    );
                    let note = Note::screen("member_not_asked", Some(walk.channel), text);
                    self.send(Walked::Note(note)).await?;
                }
            }
        }
        Some(())
    }

    /// A thread's first message that does not come leaves the thread's name to be taken back
    /// here, as `archive_put` does for a row it drops. Ahead of the page's frames: its cursor
    /// goes past this message, and no later run reads it again.
    async fn take_back_threads(&self, page: &[Message], walk: &Walk) -> Option<()> {
        let rows = page
            .iter()
            .filter(|m| self.names.taken_back(m, walk.channel))
            .filter_map(|m| {
                Some(ImportThread {
                    id: m.id,
                    parent: walk.channel,
                    owner: None,
                    name: THREAD_TAKEN_BACK.to_string(),
                    replies: *self.threads.get(&m.id)?,
                })
            })
            .collect();
        for op in batch::threads(self.run, rows) {
            self.send(Walked::TakenBack(op)).await?;
        }
        Some(())
    }

    /// None: the run is over, or stopping.
    async fn walk(&self, walk: Walk) -> Option<()> {
        let uid = walk.thread.unwrap_or(walk.channel);
        // It may point at nothing, the docs say: so it may skip a walk and never ends one
        if walk.last.is_none_or(|last| last <= walk.after) {
            return self.found_empty(&walk).await;
        }
        let mut after = walk.after;
        let mut read = 0;
        loop {
            if locked(&self.skip).contains(&walk.channel) {
                return Some(());
            }
            let path = format!("/channels/{uid}/messages?limit=100&after={after}");
            let page: Vec<Message> = match self.api.get(&path).await {
                Ok(page) => page,
                Err(Fail::Stop(words)) => {
                    let _ = self.send(Walked::Stop(words)).await;
                    return None;
                }
                Err(Fail::Skip { note, .. }) => {
                    let text = format!("#{}: {note}", walk.name);
                    let note = Note::kept("walk_skipped", Some(walk.channel), text);
                    self.send(Walked::Note(note)).await?;
                    // Its cursor stays. But 0 would read as messages off, and the next run is
                    // what is to take this: 1 reads all of it, as 0 does
                    return if read == 0 {
                        self.found_empty(&walk).await
                    } else {
                        Some(())
                    };
                }
            };
            if read == 0 {
                if let Some(words) = self.blank_page_stops(&page, &walk.name).await {
                    let _ = self.send(Walked::Stop(words)).await;
                    return None;
                }
            }
            // Past the cursor, or it would ask the same thing for ever
            let Some(high) = page.iter().map(|m| m.id).max().filter(|h| *h > after) else {
                break;
            };
            read += page.len() as u64;
            self.ask_who_joined(&page, &walk).await?;
            self.take_back_threads(&page, &walk).await?;
            let rows = page
                .iter()
                .filter(|m| !self.names.wished_away(m, walk.channel))
                .filter_map(|m| row_of(m, &self.names, &self.options))
                .collect();
            drop(page);
            let frames = batch::messages(self.run, walk.channel, walk.thread, rows, high);
            for op in frames {
                self.send(Walked::Frame {
                    op,
                    name: walk.name.clone(),
                })
                .await?;
            }
            after = high;
        }
        if read == 0 {
            self.found_empty(&walk).await?;
        }
        if walk.counted.is_some() {
            self.send(Walked::Read { walk, read }).await?;
        }
        Some(())
    }
}

fn is_forum(kind: u8) -> bool {
    matches!(kind, FORUM | MEDIA)
}

/// What comes of the channels that are walked: their threads, the walks, and the forums to
/// close when those are done. A forum has no messages of its own, and it must still say it
/// was walked, or the next delta reads it as messages off and its threads stop coming.
fn walks_of(
    read: &Read,
    here: &Here,
    layout: &Layout,
    names: &Names,
    gone: &HashSet<u64>,
) -> (Vec<ImportThread>, Vec<Walk>, Vec<u64>) {
    let after = |uid: u64| here.cursors.get(&uid).copied().unwrap_or(0);
    let threads: Vec<ImportThread> = layout
        .threads_of(read, names)
        .into_iter()
        .filter(|t| !gone.contains(&t.parent))
        .collect();
    let mut name_of: HashMap<u64, Arc<str>> = HashMap::new();
    let mut walks = Vec::new();
    let mut forums = Vec::new();
    for planned in layout.channels.iter().filter(|c| c.walk) {
        let id = planned.row.dc_id;
        if gone.contains(&id) {
            continue;
        }
        let name: Arc<str> = planned.row.name.as_str().into();
        name_of.insert(id, name.clone());
        if is_forum(planned.kind) {
            if after(id) == 0 {
                forums.push(id);
            }
            continue;
        }
        walks.push(Walk {
            channel: id,
            thread: None,
            name,
            last: planned.last_message_id,
            after: after(id),
            counted: if after(id) == 0 {
                read.counts.get(&id).copied()
            } else {
                None
            },
        });
    }
    let last_of: HashMap<u64, Option<u64>> = read
        .threads
        .iter()
        .map(|t| (t.id, t.last_message_id))
        .collect();
    for thread in &threads {
        let Some(name) = name_of.get(&thread.parent) else {
            continue;
        };
        walks.push(Walk {
            channel: thread.parent,
            thread: Some(thread.id),
            name: name.clone(),
            last: last_of.get(&thread.id).copied().flatten(),
            after: after(thread.id),
            counted: None,
        });
    }
    (threads, walks, forums)
}

/// About as many as will come: only what a walk reads from the start is known.
fn total_of(read: &Read, walks: &[Walk]) -> u64 {
    let replies: HashMap<u64, u64> = read
        .threads
        .iter()
        .map(|t| (t.id, u64::from(t.message_count)))
        .collect();
    walks
        .iter()
        .filter(|w| w.after == 0)
        .map(|w| match w.thread {
            Some(thread) => replies.get(&thread).copied().unwrap_or(0),
            None => w.counted.unwrap_or(0),
        })
        .sum()
}

/// The walkers read and split; this alone talks to the relay, one frame at a time.
#[allow(clippy::too_many_arguments)]
async fn messages<T: Transport + 'static, L: RelayLink>(
    api: &Arc<Api<T>>,
    w: &mut Writer<'_, L>,
    job: &Job,
    layout: &Layout,
    names: Names,
    guild: u64,
    walks: Vec<Walk>,
    threads: HashMap<u64, u32>,
    total: u64,
    report: &mut Report,
) -> Result<HashSet<u64>, String> {
    let (tx, mut rx) = mpsc::channel(FRAMES_WAITING);
    let skip = Arc::new(Mutex::new(HashSet::new()));
    let walkers = Walkers {
        api: api.clone(),
        names: Arc::new(names),
        options: layout.options.clone(),
        run: job.run,
        guild,
        queue: Arc::new(Mutex::new(walks.into())),
        threads: Arc::new(threads),
        skip: skip.clone(),
        asked: Arc::default(),
        tx,
    };
    let mut pool = JoinSet::new();
    for _ in 1..WALKERS {
        pool.spawn(walkers.clone_of().work());
    }
    pool.spawn(walkers.work());
    let mut done = 0u64;
    while let Some(walked) = rx.recv().await {
        match walked {
            Walked::Stop(words) => return Err(words),
            Walked::Note(note) => report.notes.push(note),
            Walked::TakenBack(op) => {
                let AdminReply::ImportAcked { .. } = w.ask(op).await? else {
                    return Err(ODD_REPLY.into());
                };
            }
            Walked::Read { walk, read } => {
                let counted = walk.counted.unwrap_or(read);
                let off = counted.abs_diff(read);
                if off * 100 > counted.max(1) * COUNT_OFF_PERCENT {
                    report.notes.push(Note::kept(
                        "count_differs",
                        Some(walk.channel),
                        format!(
                            "#{}: read {read} messages, and Discord counted {counted}.",
                            walk.name
                        ),
                    ));
                }
            }
            Walked::Frame { op, name } => {
                let channel = match &op {
                    AdminOp::ImportMessages { channel, .. } => *channel,
                    _ => 0,
                };
                // Split before the refusal, and still in the queue: it goes no further
                if locked(&skip).contains(&channel) {
                    continue;
                }
                match w.ask(op).await? {
                    AdminReply::ImportAcked { stored, skipped } => {
                        add(report, "messages", u64::from(stored));
                        add(report, "messages_skipped", u64::from(skipped));
                        done += u64::from(stored) + u64::from(skipped);
                        job.say(Phase::Messages, done, total, &name);
                    }
                    AdminReply::ImportRefused {
                        reason,
                        channel: Some(refused),
                    } => {
                        locked(&skip).insert(refused);
                        report.left_out.insert(refused);
                        report.notes.push(Note::screen(
                            "channel_refused",
                            Some(refused),
                            format!("#{name}: {reason}"),
                        ));
                    }
                    _ => return Err(ODD_REPLY.into()),
                }
            }
        }
    }
    // The queue ran out, unless a walker died, and then it did not
    while let Some(walker) = pool.join_next().await {
        walker.map_err(|_| ODD_REPLY.to_string())?;
    }
    let skipped = locked(&skip).clone();
    Ok(skipped)
}

/// Where someone off the member list starts to be worth asking about: from before it began to
/// be read, or someone who joined once it was past their place would read as gone.
fn list_read_from_now() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    discord::snowflake_floor(now - CLOCK_SLACK_MS) as u64
}

#[allow(clippy::too_many_arguments)]
async fn drive<T: Transport + 'static, L: RelayLink, E: EmoteSink>(
    api: &Arc<Api<T>>,
    w: &mut Writer<'_, L>,
    sink: &mut E,
    dry_run: &Read,
    mut here: Here,
    job: &Job,
    adding: &watch::Sender<bool>,
    report: &mut Report,
) -> Result<(), String> {
    let run = job.run;
    let guild = dry_run.guild.id;
    job.say(Phase::Starting, 0, 0, "");
    // What the relay says now, not when the dry-run asked: a resume starts from these
    here.facts = facts_of(w).await?;
    here.cursors = cursors_of(w).await?;
    let delta = !here.cursors.is_empty();
    // And what Discord says now: a dry-run kept for an hour, or through a cut, says what was
    let read = &plan::as_it_is_now(api, dry_run).await?;
    let (choices, closed_since) = plan::without_closed_since(dry_run, read, &job.choices);
    let layout = plan::layout(read, &here, &choices);
    *report = layout.report();
    report.notes.extend(closed_since);
    if delta {
        report.notes.push(Note::kept(
            "delta",
            None,
            "New messages only: edits, deletions, reactions and pins on older ones stay as \
             first read."
                .to_string(),
        ));
    }
    let mut names = layout.names(read, &here);
    excluded(w, &mut names).await?;
    if names.anonymise {
        wishes(w, &mut names).await?;
    }
    if layout.options.roles {
        job.say(Phase::Roles, 0, 0, "");
        send_roles(w, read, run, report).await?;
    }
    job.say(Phase::Channels, 0, 0, "");
    let gone = send_channels(w, &layout, run, report).await?;
    job.say(Phase::Members, 0, 0, "");
    names.list_read = list_read_from_now();
    members(api, w, guild, &layout, run, &mut names, report).await?;
    if layout.options.bans {
        job.say(Phase::Bans, 0, 0, "");
        bans(api, w, guild, run, &names, report).await?;
    }
    if layout.options.emotes {
        emotes(w, sink, job, &layout, &mut names, adding, report).await?;
    }
    if layout.options.messages {
        let (threads, walks, forums) = walks_of(read, &here, &layout, &names, &gone);
        let replies = threads.iter().map(|t| (t.id, t.replies)).collect();
        job.say(Phase::Threads, 0, 0, "");
        for op in batch::threads(run, threads) {
            // A thread its parent may not take is `skipped` here, and the reason comes with
            // that channel's messages: one reply could name only one of a frame's channels
            let AdminReply::ImportAcked { stored, .. } = w.ask(op).await? else {
                return Err(ODD_REPLY.into());
            };
            add(report, "threads", u64::from(stored));
        }
        let total = total_of(read, &walks);
        job.say(Phase::Messages, 0, total, "");
        let refused = messages(
            api, w, job, &layout, names, guild, walks, replies, total, report,
        )
        .await?;
        for forum in forums {
            if refused.contains(&forum) {
                continue;
            }
            match w.ask(batch::walked_empty(run, forum, None)).await? {
                AdminReply::ImportAcked { .. } => {}
                AdminReply::ImportRefused { reason, .. } => {
                    report.left_out.insert(forum);
                    report.notes.push(Note::screen(
                        "channel_refused",
                        Some(forum),
                        format!("A forum: {reason}"),
                    ));
                }
                _ => return Err(ODD_REPLY.into()),
            }
        }
    }
    job.say(Phase::Ending, 0, 0, "");
    let end = AdminOp::ImportEnd {
        run,
        report: report.kept(),
    };
    match w.ask(end).await? {
        AdminReply::ImportEnded { .. } => Ok(()),
        _ => Err(ODD_REPLY.into()),
    }
}

async fn pressed(stop: &mut watch::Receiver<bool>, adding: &mut watch::Receiver<bool>) {
    // With nobody left to press it, it stays unpressed
    if stop.wait_for(|on| *on).await.is_err() {
        std::future::pending::<()>().await;
    }
    let _ = adding.wait_for(|busy| !*busy).await;
}

/// A run, from the frame after `ImportBegin` to `ImportEnd`, or to whatever stops it first.
/// `read` is the dry-run's; everything the relay knows is asked again here, because this may
/// be a resume, and so is who Discord lets into each channel. A channel closed once this has
/// asked is not noticed. The rows stay in RAM, and nothing goes to a file or a log.
pub async fn run<T: Transport + 'static, L: RelayLink, E: EmoteSink>(
    api: Arc<Api<T>>,
    link: &mut L,
    sink: &mut E,
    read: &Read,
    here: Here,
    job: Job,
) -> Outcome {
    let options = plan::effective(&job.choices.options);
    let mut report = Report::default();
    if options.messages && !options.acknowledged {
        return Outcome {
            report,
            stopped: Some(NOT_ACKNOWLEDGED.into()),
        };
    }
    let mut stop = job.stop.clone();
    let (adding, mut adding_seen) = watch::channel(false);
    let mut w = Writer {
        link,
        pace: job.pace,
        next: Instant::now(),
    };
    let stopped = tokio::select! {
        biased;
        () = pressed(&mut stop, &mut adding_seen) => Some(STOPPED.to_string()),
        out = drive(&api, &mut w, sink, read, here, &job, &adding, &mut report) => out.err(),
    };
    Outcome { report, stopped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::RateGate;
    use crate::fixture;
    use crate::mock::{Mock, Scripted};
    use crate::plan::{default_choices, read as read_all};
    use voipc_protocol::discord::{READ_MESSAGE_HISTORY, VIEW_CHANNEL};
    use voipc_protocol::types::{ArchiveWish, ImportGate, MoveAccount, MoveRun, Registration};

    /// The relay's words for a channel of its own that Discord closed (`layout.rs`).
    const PRIVATE_NOW: &str =
        "Private on Discord now and open here. Give it a gate, then run again.";
    const G: u64 = fixture::GUILD;
    /// In `#lounge`, by a member of the fixture.
    const LOUNGE_FIRST: u64 = 1_200_000_000_000_005_001;

    /// A relay that says yes, and remembers.
    #[derive(Default)]
    struct FakeRelay {
        frames: Vec<AdminOp>,
        at: Vec<Instant>,
        cursors: Vec<(u64, u64)>,
        excluded: Vec<(String, bool, bool, i64)>,
        wishes: Vec<ArchiveWish>,
        banned_here: Vec<String>,
        banned_who_came: Vec<String>,
        banned_kept_a_name: Vec<String>,
        /// Refuse this channel's messages.
        refuse: Option<u64>,
        refuse_stop: Option<usize>,
        too_many_at: Option<usize>,
        silent_at: Option<usize>,
        gone_at: Option<usize>,
        said_no_at: Option<usize>,
        calls: usize,
        removed_here: Vec<u64>,
        /// Made by an earlier run, with no gate: a row no longer open is refused.
        open_here: Vec<u64>,
    }

    impl FakeRelay {
        fn sent_rows(&self, channel: u64, thread: Option<u64>) -> Vec<u64> {
            self.message_frames(channel, thread)
                .into_iter()
                .flat_map(|(_, rows)| rows)
                .collect()
        }

        fn message_frames(&self, channel: u64, thread: Option<u64>) -> Vec<(u64, Vec<u64>)> {
            self.frames
                .iter()
                .filter_map(|op| match op {
                    AdminOp::ImportMessages {
                        channel: c,
                        thread: t,
                        high,
                        rows,
                        ..
                    } if *c == channel && *t == thread => {
                        Some((*high, rows.iter().map(|r| r.id).collect()))
                    }
                    _ => None,
                })
                .collect()
        }

        fn kinds(&self) -> Vec<&'static str> {
            let mut kinds: Vec<&'static str> = Vec::new();
            for op in &self.frames {
                let kind = match op {
                    AdminOp::ImportRoles { .. } => "roles",
                    AdminOp::ImportCategories { .. } => "categories",
                    AdminOp::ImportChannels { .. } => "channels",
                    AdminOp::ImportMembers { .. } => "members",
                    AdminOp::ImportBans { .. } => "bans",
                    AdminOp::ImportEmote { .. } => "emote",
                    AdminOp::ImportThreads { .. } => "threads",
                    AdminOp::ImportMessages { .. } => "messages",
                    AdminOp::ImportEnd { .. } => "end",
                    _ => continue,
                };
                if kinds.last() != Some(&kind) {
                    kinds.push(kind);
                }
            }
            kinds
        }
    }

    fn facts() -> ImportFacts {
        fixture::here().facts
    }

    impl RelayLink for FakeRelay {
        fn call(&mut self, op: AdminOp) -> impl Future<Output = Result<AdminReply, Stop>> + Send {
            self.calls += 1;
            let call = self.calls;
            let answer = self.answer(op, call);
            let silent = self.silent_at == Some(call);
            async move {
                if silent {
                    std::future::pending::<()>().await;
                }
                answer
            }
        }
    }

    impl FakeRelay {
        fn answer(&mut self, op: AdminOp, call: usize) -> Result<AdminReply, Stop> {
            if self.gone_at == Some(call) {
                return Err(Stop::Gone("cut".into()));
            }
            if self.too_many_at == Some(call) {
                return Err(Stop::Said("Too many requests at once; slow down.".into()));
            }
            if self.said_no_at == Some(call) {
                return Err(Stop::Said("Only an admin may import.".into()));
            }
            if self.refuse_stop == Some(call) {
                return Ok(AdminReply::ImportRefused {
                    reason: "no".into(),
                    channel: None,
                });
            }
            self.at.push(Instant::now());
            let frame = op.clone();
            let reply = match op {
                AdminOp::ImportFacts => AdminReply::ImportFacts { facts: facts() },
                AdminOp::ImportCursors { after } => AdminReply::ImportCursors {
                    rows: self
                        .cursors
                        .iter()
                        .filter(|(uid, _)| *uid > after)
                        .copied()
                        .collect(),
                    more: false,
                },
                // Two a page, so that a run has to go on to the next
                AdminOp::ArchiveWishes { after } => {
                    let from = after.map_or(0, |last| {
                        1 + self.wishes.iter().position(|w| *w == last).unwrap()
                    });
                    let to = self.wishes.len().min(from + 2);
                    AdminReply::ArchiveWishes {
                        rows: self.wishes[from..to].to_vec(),
                        more: to < self.wishes.len(),
                    }
                }
                AdminOp::MoveStatus => AdminReply::MoveStatus {
                    claimed: 0,
                    waiting: 0,
                    banned: 0,
                    power_waiting: 0,
                    excluded: 0,
                    unclaimed_days: 90,
                    runs: vec![
                        MoveRun {
                            id: 1,
                            guild_id: G.to_string(),
                            by: "ann".into(),
                            started_at: 1_700_000_000,
                            finished_at: Some(1_700_000_100),
                            undone_at: None,
                            accounts: 0,
                            groups: 0,
                            clearing: false,
                        },
                        MoveRun {
                            id: 2,
                            guild_id: G.to_string(),
                            by: "ann".into(),
                            started_at: 1_800_000_000,
                            finished_at: None,
                            undone_at: Some(1_800_000_100),
                            accounts: 0,
                            groups: 0,
                            clearing: false,
                        },
                        MoveRun {
                            id: 3,
                            guild_id: "5".into(),
                            by: "ann".into(),
                            started_at: 1_900_000_000,
                            finished_at: None,
                            undone_at: None,
                            accounts: 0,
                            groups: 0,
                            clearing: false,
                        },
                    ],
                },
                AdminOp::MoveExcluded { .. } => AdminReply::MoveExcluded {
                    ids: self.excluded.clone(),
                    more: false,
                },
                AdminOp::ImportRoles { .. } => AdminReply::ImportRolesDone {
                    made: 1,
                    updated: 0,
                    skipped: vec![],
                    power_changed: vec![],
                },
                AdminOp::ImportCategories { .. } => {
                    AdminReply::ImportChannelsDone { refused: vec![] }
                }
                AdminOp::ImportChannels { rows, .. } => AdminReply::ImportChannelsDone {
                    refused: rows
                        .iter()
                        .filter_map(|r| {
                            let why = if self.removed_here.contains(&r.dc_id) {
                                "Removed here."
                            } else if self.open_here.contains(&r.dc_id) && r.see != ImportGate::Open
                            {
                                PRIVATE_NOW
                            } else {
                                return None;
                            };
                            Some((r.dc_id, why.to_string()))
                        })
                        .collect(),
                },
                AdminOp::ImportMembers { .. } => AdminReply::ImportMembersDone {
                    made: 1,
                    updated: 0,
                    left_out: 0,
                    nicknames_dropped: 0,
                    unlinked: 0,
                    kept_power: 0,
                    failed: vec![],
                },
                AdminOp::ImportBans { .. } => AdminReply::ImportBansDone {
                    made: 1,
                    converted: 0,
                    claimed: self.banned_who_came.clone(),
                    names_kept: self.banned_kept_a_name.clone(),
                },
                AdminOp::MoveAccounts { offset, filter, .. } => {
                    assert_eq!(filter, MoveFilter::Banned);
                    let rows: Vec<MoveAccount> = if offset == 0 {
                        self.banned_here.iter().map(|id| banned_row(id)).collect()
                    } else {
                        vec![]
                    };
                    AdminReply::MoveAccounts {
                        search: String::new(),
                        offset,
                        filter,
                        total: self.banned_here.len() as u32,
                        rows,
                    }
                }
                AdminOp::ImportEmote { .. } => AdminReply::ImportAcked {
                    stored: 1,
                    skipped: 0,
                },
                AdminOp::ImportThreads { ref rows, .. } => AdminReply::ImportAcked {
                    stored: rows.len() as u32,
                    skipped: 0,
                },
                AdminOp::ImportMessages {
                    channel, ref rows, ..
                } => {
                    if self.refuse == Some(channel) {
                        AdminReply::ImportRefused {
                            reason: "That channel was removed here.".into(),
                            channel: Some(channel),
                        }
                    } else {
                        AdminReply::ImportAcked {
                            stored: rows.len() as u32,
                            skipped: 0,
                        }
                    }
                }
                AdminOp::ImportEnd { run, .. } => AdminReply::ImportEnded { run },
                other => panic!("the driver has no business asking this: {other:?}"),
            };
            self.frames.push(frame);
            Ok(reply)
        }
    }

    fn banned_row(dc_id: &str) -> MoveAccount {
        MoveAccount {
            user: voipc_protocol::types::AdminUser {
                id: [1; 16],
                name: format!("dc-{dc_id}"),
                totp: false,
                created_at: 0,
            },
            state: voipc_protocol::types::MoveState::Banned,
            dc_id: dc_id.to_string(),
            expires_at: 0,
        }
    }

    #[derive(Default)]
    struct FakeSink {
        added: Vec<String>,
        fail: Option<String>,
        /// Listed already under these names, by an earlier run.
        listed: HashMap<u64, String>,
    }

    impl EmoteSink for FakeSink {
        fn add(
            &mut self,
            emote: &PlannedEmote,
        ) -> impl Future<Output = Result<String, String>> + Send {
            let out = if self.fail.as_deref() == Some(&emote.raw) {
                Err("It would not download.".to_string())
            } else {
                self.added.push(emote.name.clone());
                Ok(self
                    .listed
                    .get(&emote.id)
                    .cloned()
                    .unwrap_or_else(|| emote.name.clone()))
            };
            async move { out }
        }
    }

    struct Scene {
        mock: Arc<Mock>,
        api: Arc<Api<Arc<Mock>>>,
        read: Read,
        relay: FakeRelay,
        sink: FakeSink,
        choices: Choices,
        /// What the dry-run asked, which is not the run's doing.
        dry_run_asked: usize,
    }

    impl Scene {
        /// Every path the run asked.
        fn asked(&self) -> Vec<String> {
            self.mock.asked().split_off(self.dry_run_asked)
        }
    }

    async fn scene_of(mock: Mock) -> Scene {
        let mock = Arc::new(mock);
        let api = Arc::new(Api::with_gate(mock.clone(), RateGate::new(7)));
        let read = read_all(&api, G).await.unwrap();
        let mut choices = default_choices(&read, &fixture::here());
        choices.options.acknowledged = true;
        let dry_run_asked = mock.asked().len();
        Scene {
            dry_run_asked,
            mock,
            api,
            read,
            relay: FakeRelay::default(),
            sink: FakeSink::default(),
            choices,
        }
    }

    async fn scene() -> Scene {
        scene_of(fixture::mock()).await
    }

    fn job(choices: Choices) -> (Job, watch::Sender<bool>, watch::Receiver<Progress>) {
        let (stop_tx, stop) = watch::channel(false);
        let (progress, seen) = watch::channel(Progress::default());
        (
            Job {
                run: 7,
                choices,
                pace: Duration::ZERO,
                stop,
                progress,
            },
            stop_tx,
            seen,
        )
    }

    async fn run_it(s: &mut Scene) -> Outcome {
        let (job, _stop, _seen) = job(s.choices.clone());
        run(
            s.api.clone(),
            &mut s.relay,
            &mut s.sink,
            &s.read,
            fixture::here(),
            job,
        )
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn a_run_goes_in_the_order_the_relay_needs() {
        let mut s = scene().await;
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert_eq!(
            s.relay.kinds(),
            [
                "roles",
                "categories",
                "channels",
                "members",
                "bans",
                "emote",
                "threads",
                "messages",
                "end"
            ]
        );
        // Top roles first, across frames too: what one group list cannot hold is the bottom
        let places: Vec<u32> = s
            .relay
            .frames
            .iter()
            .filter_map(|f| match f {
                AdminOp::ImportRoles { roles, .. } => Some(roles.iter().map(|r| r.position)),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(places.len() > 20);
        assert!(places.windows(2).all(|w| w[0] >= w[1]), "{places:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_walk_reads_all_of_a_channel_in_order_across_pages() {
        let mock = fixture::mock();
        mock.add_messages(fixture::LOUNGE, 250, 10);
        let mut s = scene_of(mock).await;
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        let frames = s.relay.message_frames(fixture::LOUNGE, None);
        assert!(frames.len() >= 3, "{}", frames.len());
        // Each `high` only rises and each row is sent once, in order
        let mut high = 0;
        let mut last_row = 0;
        for (h, rows) in &frames {
            assert!(*h > high);
            high = *h;
            for row in rows {
                assert!(*row > last_row, "{row}");
                last_row = *row;
            }
        }
        assert_eq!(high, last_row);
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).len() > 250);
        // With a page of 100, a short answer still needs the empty one that says it is over
        let lounge = format!("/channels/{}/messages?", fixture::LOUNGE);
        let asked = s.asked();
        let walked: Vec<&String> = asked.iter().filter(|p| p.starts_with(&lounge)).collect();
        assert!(walked.iter().any(|p| p.ends_with("&after=0")));
        assert!(walked.last().unwrap().ends_with(&format!("&after={high}")));
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_sent_but_through_the_pace() {
        let mut s = scene().await;
        let (mut job, _stop, _seen) = job(s.choices.clone());
        job.pace = FRAME_PACE;
        let out = run(
            s.api.clone(),
            &mut s.relay,
            &mut s.sink,
            &s.read,
            fixture::here(),
            job,
        )
        .await;
        assert_eq!(out.stopped, None);
        assert!(s.relay.at.len() > 20);
        for pair in s.relay.at.windows(2) {
            assert!(pair[1] - pair[0] >= FRAME_PACE, "{:?}", pair[1] - pair[0]);
        }
        // Under what `account_rate` lets through for ever, whatever is spent beside it
        assert!(FRAME_PACE > Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn too_many_requests_waits_a_second_and_sends_the_same_frame() {
        let mut s = scene().await;
        s.relay.too_many_at = Some(9);
        let started = Instant::now();
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert!(started.elapsed() >= SLOW_DOWN);
        // One end, with every row once: the frame went again and nothing was lost
        let ends = s
            .relay
            .frames
            .iter()
            .filter(|f| matches!(f, AdminOp::ImportEnd { .. }))
            .count();
        assert_eq!(ends, 1);
        let mut clean = scene().await;
        run_it(&mut clean).await;
        assert_eq!(s.relay.frames.len(), clean.relay.frames.len());
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_stops_answering_stops_the_run_after_120_seconds() {
        let mut s = scene().await;
        s.relay.silent_at = Some(9);
        let started = Instant::now();
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped.as_deref(), Some(NO_REPLY));
        assert!(started.elapsed() >= REPLY_WAIT, "{:?}", started.elapsed());
        assert!(
            started.elapsed() < REPLY_WAIT + Duration::from_secs(30),
            "{:?}",
            started.elapsed()
        );
        assert!(!s.relay.kinds().contains(&"end"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_with_no_channel_stops_the_run_and_a_cut_too() {
        let mut s = scene().await;
        s.relay.refuse_stop = Some(9);
        assert_eq!(run_it(&mut s).await.stopped.as_deref(), Some("no"));
        assert!(!s.relay.kinds().contains(&"end"));

        let mut s = scene().await;
        s.relay.gone_at = Some(9);
        assert_eq!(run_it(&mut s).await.stopped.as_deref(), Some("cut"));
        assert!(!s.relay.kinds().contains(&"end"));

        // What a session without `*` hears, ahead of any frame
        let mut s = scene().await;
        s.relay.said_no_at = Some(1);
        assert_eq!(
            run_it(&mut s).await.stopped.as_deref(),
            Some("Only an admin may import.")
        );
        assert_eq!(s.mock.non_gets(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_channel_is_skipped_and_the_run_goes_on() {
        let mock = fixture::mock();
        mock.add_messages(fixture::GENERAL, 250, 10);
        let mut s = scene_of(mock).await;
        s.relay.refuse = Some(fixture::GENERAL);
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert!(s.relay.kinds().contains(&"end"));
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        // Once told, nothing more of it goes, though it has more frames than that
        assert_eq!(s.relay.message_frames(fixture::GENERAL, None).len(), 1);
        // It said why, once, on the screen. The stored report says nothing of that channel
        let text = out.report.end_screen().join("\n");
        let said = "#general: That channel was removed here.";
        assert_eq!(text.matches(said).count(), 1, "{text}");
        let kept = out.report.kept();
        assert!(!kept.contains("That channel was removed"), "{kept}");
        assert!(!kept.contains("#general"), "{kept}");
        // The control: its other notes are there when it is not refused
        let mut s = scene().await;
        let kept = run_it(&mut s).await.report.kept();
        assert!(kept.contains("#general"), "{kept}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_channel_removed_here_is_not_walked_and_stops_nothing() {
        let mut s = scene().await;
        s.relay.removed_here.push(fixture::LOUNGE);
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert!(s.relay.kinds().contains(&"end"));
        let lounge = format!("/channels/{}/messages?", fixture::LOUNGE);
        assert!(!s.asked().iter().any(|p| p.starts_with(&lounge)));
        // It did not come, and the count says so
        assert_eq!(out.report.counts["channels"], 13);
        // A thread of it neither: not told of, not walked
        let thread = format!("/channels/{}/", fixture::LOUNGE_THREAD);
        assert!(!s.asked().iter().any(|p| p.starts_with(&thread)));
        assert!(s.relay.frames.iter().all(|f| match f {
            AdminOp::ImportThreads { rows, .. } => rows.iter().all(|t| t.parent != fixture::LOUNGE),
            _ => true,
        }));
        // The control: others were
        let general = format!("/channels/{}/messages?", fixture::GENERAL);
        assert!(s.asked().iter().any(|p| p.starts_with(&general)));

        // One an earlier run made is no fewer new ones
        let mut s = scene().await;
        s.relay.removed_here.push(fixture::LOUNGE);
        s.relay.cursors = vec![(fixture::LOUNGE, 1)];
        let out = run_it(&mut s).await;
        assert_eq!(out.report.counts["channels"], 13);
    }

    #[tokio::test(start_paused = true)]
    async fn a_403_skips_the_channel_keeps_its_cursor_and_the_run_goes_on() {
        let mock = fixture::mock();
        let route = format!("/channels/{}/messages", fixture::GENERAL);
        let mut s = scene_of(mock).await;
        s.mock.script(Scripted::new(
            &route,
            1,
            403,
            &[],
            r#"{"message":"Missing Access","code":50001}"#,
        ));
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        // No row, and a cursor from which all of it is still to read: not 0, which a delta
        // would take for messages off, against what the note says
        assert_eq!(
            s.relay.message_frames(fixture::GENERAL, None),
            [(1, vec![])]
        );
        assert!(s.relay.kinds().contains(&"end"));
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(text.contains("#general:"), "{text}");
        // So the next run reads it all
        let mut next = scene().await;
        next.relay.cursors = vec![(fixture::GENERAL, 1)];
        run_it(&mut next).await;
        assert_eq!(next.relay.sent_rows(fixture::GENERAL, None).len(), 5);

        // A channel with a real cursor keeps it where it was: nothing says it moved
        let mut s = scene().await;
        s.mock.script(Scripted::new(
            &route,
            1,
            403,
            &[],
            r#"{"message":"Missing Access","code":50001}"#,
        ));
        s.relay.cursors = vec![(fixture::GENERAL, 1_200_000_000_000_001_001)];
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert!(s.relay.message_frames(fixture::GENERAL, None).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_401_stops_at_once() {
        let mut s = scene().await;
        let route = format!("/channels/{}/messages", fixture::LOUNGE);
        s.mock.script(Scripted::new(&route, 1, 401, &[], "{}"));
        let out = run_it(&mut s).await;
        assert!(out.stopped.unwrap().contains("token"));
        assert!(!s.relay.kinds().contains(&"end"));
    }

    #[tokio::test(start_paused = true)]
    async fn last_message_id_at_the_cursor_skips_and_a_dangling_one_does_not_advance() {
        let mut s = scene().await;
        // At the cursor: skipped with no request. A dangling id above it asks, and an empty
        // page does not advance it
        let last_lounge = 1_200_000_000_000_005_019;
        s.relay.cursors = vec![
            (fixture::LOUNGE, last_lounge),
            (fixture::GENERAL, 1_200_000_000_000_001_005 - 1),
        ];
        s.read
            .channels
            .iter_mut()
            .find(|c| c.id == fixture::GENERAL)
            .unwrap()
            .last_message_id = Some(u64::MAX >> 1);
        run_it(&mut s).await;
        let lounge = format!("/channels/{}/messages?", fixture::LOUNGE);
        assert!(!s.asked().iter().any(|p| p.starts_with(&lounge)));
        assert!(s.relay.message_frames(fixture::LOUNGE, None).is_empty());
        // Its last row, and nothing more
        let frames = s.relay.message_frames(fixture::GENERAL, None);
        assert_eq!(frames.len(), 1, "{frames:?}");
        assert_eq!(frames[0].0, 1_200_000_000_000_001_005);

        // And a dangling id with nothing past it: nothing is said at all, and `high` stays
        let mut s = scene().await;
        s.relay.cursors = vec![(fixture::GENERAL, 1_200_000_000_000_001_005)];
        s.read
            .channels
            .iter_mut()
            .find(|c| c.id == fixture::GENERAL)
            .unwrap()
            .last_message_id = Some(u64::MAX >> 1);
        run_it(&mut s).await;
        assert!(s.relay.message_frames(fixture::GENERAL, None).is_empty());
        let general = format!("/channels/{}/messages?", fixture::GENERAL);
        assert!(s.asked().iter().any(|p| p.starts_with(&general)));
    }

    #[tokio::test(start_paused = true)]
    async fn the_walk_of_a_new_channel_starts_at_0() {
        let mut s = scene().await;
        run_it(&mut s).await;
        // A forum post's first message has the thread's id: `after` that would lose it
        let forum_post: u64 = 1_200_000_000_000_006_001;
        let path = format!("/channels/{forum_post}/messages?limit=100&after=0");
        assert!(s.asked().contains(&path));
        let rows = s
            .relay
            .sent_rows(1_190_000_000_000_000_230, Some(forum_post));
        assert!(rows.contains(&forum_post), "{rows:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn what_was_walked_and_empty_says_so_and_what_was_not_stays_at_0() {
        const FORUM: u64 = 1_190_000_000_000_000_230;
        const MEDIA_ROOM: u64 = 1_190_000_000_000_000_231;
        const QUIET_VOICE: u64 = 1_190_000_000_000_000_221;
        let mut s = scene().await;
        run_it(&mut s).await;
        let high_of = |relay: &FakeRelay, c: u64| relay.message_frames(c, None);
        // No messages of its own: `high` 1, and no rows
        for empty in [FORUM, MEDIA_ROOM, QUIET_VOICE] {
            assert_eq!(high_of(&s.relay, empty), [(1, vec![])], "{empty}");
        }
        // A channel with its messages off was never walked, and stays at 0
        assert!(!s.choices.messages_on.contains(&fixture::STAFF));
        assert!(high_of(&s.relay, fixture::STAFF).is_empty());
        // A forum says so only after its threads
        let at = |pred: &dyn Fn(&AdminOp) -> bool| s.relay.frames.iter().position(pred).unwrap();
        let closed = at(
            &|f| matches!(f, AdminOp::ImportMessages { channel, thread: None, .. } if *channel == FORUM),
        );
        s.relay.frames.iter().enumerate().for_each(|(i, f)| {
            if matches!(f, AdminOp::ImportMessages { channel, thread: Some(_), .. } if *channel == FORUM) {
                assert!(i < closed);
            }
        });
        assert!(!s
            .relay
            .message_frames(FORUM, Some(1_200_000_000_000_006_001))
            .is_empty());

        // An empty first page, though Discord named a last message, says the same
        let mut s = scene().await;
        s.read
            .channels
            .iter_mut()
            .find(|c| c.id == QUIET_VOICE)
            .unwrap()
            .last_message_id = Some(1_200_000_000_000_009_000);
        run_it(&mut s).await;
        assert_eq!(high_of(&s.relay, QUIET_VOICE), [(1, vec![])]);

        // On a delta it has a cursor already, and nothing more is said
        let mut s = scene().await;
        s.relay.cursors = vec![(FORUM, 1), (QUIET_VOICE, 1)];
        run_it(&mut s).await;
        assert!(high_of(&s.relay, FORUM).is_empty());
        assert!(high_of(&s.relay, QUIET_VOICE).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_blank_first_page_stops_the_run_and_stores_nothing_of_it() {
        let files = fixture::files();
        let page = String::from_utf8(files["blank-page.json"].clone()).unwrap();
        let mut s = scene().await;
        let route = format!("/channels/{}/messages", fixture::LOUNGE);
        s.mock.script(Scripted::new(&route, 1, 200, &[], &page));
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, Some(blank("lounge")));
        assert!(out.stopped.unwrap().contains("Message Content"));
        assert!(s.relay.message_frames(fixture::LOUNGE, None).is_empty());
        assert!(!s.relay.kinds().contains(&"end"));
        // A page that long says so itself: Discord was not asked again
        let asked = s.asked();
        assert!(!asked.iter().any(|p| p == "/applications/@me"), "{asked:?}");
    }

    const APP_ROUTE: &str = "/applications/@me";

    fn lounge_empty_row(fields: &str) -> String {
        format!(
            r#"{{"id":"{LOUNGE_FIRST}","type":0,"author":{{"id":"{}","username":"eva.e"}},
                 "content":""{fields}}}"#,
            fixture::EVA
        )
    }

    /// One Rich Presence invite, or a bot's post with its embeds off, is all a channel's new
    /// messages may hold, with Message Content on. Nothing to ask anyone about.
    #[tokio::test(start_paused = true)]
    async fn a_message_empty_of_itself_stops_nothing() {
        for fields in [r#","activity":{"type":1,"party_id":"x"}"#, r#","flags":4"#] {
            let mut s = scene().await;
            script_page(&s, fixture::LOUNGE, &[lounge_empty_row(fields)]);
            let out = run_it(&mut s).await;
            assert_eq!(out.stopped, None, "{fields}");
            assert!(s.relay.kinds().contains(&"end"));
            assert!(
                s.relay
                    .sent_rows(fixture::LOUNGE, None)
                    .contains(&LOUNGE_FIRST),
                "{fields}"
            );
            let asked = s.asked();
            assert!(!asked.iter().any(|p| p == APP_ROUTE), "{asked:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_channels_blank_page_goes_by_what_discord_says() {
        // Message Content is on: this one post is empty for reasons of its own
        let mut s = scene().await;
        script_page(&s, fixture::LOUNGE, &[lounge_empty_row("")]);
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert_eq!(s.asked().iter().filter(|p| *p == APP_ROUTE).count(), 1);
        assert!(s
            .relay
            .sent_rows(fixture::LOUNGE, None)
            .contains(&LOUNGE_FIRST));

        // The control: the same page, and it has been turned off since the dry-run
        let mut s = scene().await;
        script_page(&s, fixture::LOUNGE, &[lounge_empty_row("")]);
        let off = r#"{"id":"1190000000000000002","flags":0}"#;
        s.mock
            .script(Scripted::new(APP_ROUTE, 1, 200, &[], off).always());
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, Some(blank("lounge")));
        assert!(s.relay.message_frames(fixture::LOUNGE, None).is_empty());
        assert!(!s.relay.kinds().contains(&"end"));

        // It will not say: stopping loses nothing, and a blank stored is there for good
        let mut s = scene().await;
        script_page(&s, fixture::LOUNGE, &[lounge_empty_row("")]);
        s.mock
            .script(Scripted::new(APP_ROUTE, 1, 403, &[], "{}").always());
        assert_eq!(run_it(&mut s).await.stopped, Some(blank("lounge")));
    }

    /// Only a first page says Message Content is off: a run of files further on says nothing.
    #[tokio::test(start_paused = true)]
    async fn a_blank_page_further_on_stops_nothing() {
        let top: u64 = 1_200_000_000_000_001_005;
        let later = top + 1;
        let body = format!(
            r#"[{{"id":"{later}","type":0,"author":{{"id":"{}","username":"eva.e"}},"content":""}}]"#,
            fixture::EVA
        );
        let route = format!(
            "/channels/{}/messages?limit=100&after={top}",
            fixture::GENERAL
        );
        let mut s = scene().await;
        s.mock.script(Scripted::new(&route, 1, 200, &[], &body));
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        let frames = s.relay.message_frames(fixture::GENERAL, None);
        assert_eq!(frames.last().unwrap().0, later, "{frames:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_member_list_that_will_not_come_stops_before_anyone_is_anonymised() {
        let route = format!("/guilds/{G}/members?");
        let mut s = scene().await;
        s.mock.script(
            Scripted::new(
                &route,
                1,
                403,
                &[],
                r#"{"message":"Missing Access","code":50001}"#,
            )
            .always(),
        );
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped.as_deref(), Some(NO_MEMBERS));
        assert!(!s.relay.kinds().contains(&"messages"));

        // The control: with anonymise off it is only noted, and nobody becomes a former member
        let mut s = scene().await;
        s.mock.script(
            Scripted::new(
                &route,
                1,
                403,
                &[],
                r#"{"message":"Missing Access","code":50001}"#,
            )
            .always(),
        );
        s.choices.options.anonymise = false;
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert!(s.relay.kinds().contains(&"messages"));
        assert!(!s.relay.kinds().contains(&"members"));
        assert!(out.report.end_screen().join("\n").contains("member list"));
        let first = s
            .relay
            .frames
            .iter()
            .find_map(|f| match f {
                AdminOp::ImportMessages { rows, .. } => rows.iter().find(|r| r.id == LOUNGE_FIRST),
                _ => None,
            })
            .unwrap();
        assert!(first.author.is_some());
    }

    /// 200 and nothing, which is how the docs say the list can fail. The bot is a member.
    #[tokio::test(start_paused = true)]
    async fn an_empty_member_list_stops_before_anyone_is_anonymised() {
        let route = format!("/guilds/{G}/members?");
        let mut s = scene().await;
        s.mock.script(Scripted::new(&route, 1, 200, &[], "[]"));
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped.as_deref(), Some(NO_MEMBERS));
        assert!(!s.relay.kinds().contains(&"messages"));
        assert!(!s.relay.kinds().contains(&"end"));

        // The control: with anonymise off it hurts nobody, and the run goes on
        let mut s = scene().await;
        s.mock.script(Scripted::new(&route, 1, 200, &[], "[]"));
        s.choices.options.anonymise = false;
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert!(s.relay.kinds().contains(&"messages"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_member_list_is_read_for_anonymising_with_members_off() {
        let mut s = scene().await;
        s.choices.options.members = false;
        run_it(&mut s).await;
        assert!(s.asked().iter().any(|p| p.contains("/members?")));
        assert!(!s.relay.kinds().contains(&"members"));
        let first = s
            .relay
            .frames
            .iter()
            .find_map(|f| match f {
                AdminOp::ImportMessages { rows, .. } => rows.iter().find(|r| r.id == LOUNGE_FIRST),
                _ => None,
            })
            .unwrap();
        assert!(first.author.is_some(), "a member is no former member");

        // With both off there is no call for it
        let mut s = scene().await;
        s.choices.options.members = false;
        s.choices.options.anonymise = false;
        run_it(&mut s).await;
        assert!(!s.asked().iter().any(|p| p.contains("/members?")));
    }

    #[tokio::test(start_paused = true)]
    async fn only_what_is_on_goes() {
        let off = |set: &dyn Fn(&mut ImportOptions)| {
            let mut options = plan::default_options(&fixture::here());
            options.acknowledged = true;
            set(&mut options);
            options
        };
        let mut s = scene().await;
        s.choices.options = off(&|o| o.roles = false);
        run_it(&mut s).await;
        assert!(!s.relay.kinds().contains(&"roles"));
        let mut s = scene().await;
        s.choices.options = off(&|o| o.bans = false);
        run_it(&mut s).await;
        assert!(!s.relay.kinds().contains(&"bans"));
        assert!(!s.asked().iter().any(|p| p.contains("/bans?")));
        let mut s = scene().await;
        s.choices.options = off(&|o| o.emotes = false);
        run_it(&mut s).await;
        assert!(!s.relay.kinds().contains(&"emote"));
        assert!(s.sink.added.is_empty());
        let mut s = scene().await;
        s.choices.options = off(&|o| o.threads = false);
        run_it(&mut s).await;
        assert!(!s.relay.kinds().contains(&"threads"));
        assert!(s
            .relay
            .message_frames(1_190_000_000_000_000_230, Some(1_200_000_000_000_006_001))
            .is_empty());
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let mut s = scene().await;
        s.choices.options = off(&|o| o.messages = false);
        run_it(&mut s).await;
        let kinds = s.relay.kinds();
        assert!(
            !kinds.contains(&"messages") && !kinds.contains(&"threads"),
            "{kinds:?}"
        );
        assert!(kinds.contains(&"end"));
        assert!(!s.asked().iter().any(|p| p.contains("/messages?")));
        // Channels off takes messages with it, or every frame would be refused
        let mut s = scene().await;
        s.choices.options = off(&|o| o.channels = false);
        run_it(&mut s).await;
        let kinds = s.relay.kinds();
        assert!(
            !kinds.contains(&"channels") && !kinds.contains(&"messages"),
            "{kinds:?}"
        );
        assert!(kinds.contains(&"members"), "{kinds:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_run_without_the_tick_asks_nothing_of_anyone() {
        let mut s = scene().await;
        s.choices.options.acknowledged = false;
        let before = s.mock.requests();
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped.as_deref(), Some(NOT_ACKNOWLEDGED));
        assert_eq!(s.relay.calls, 0);
        assert_eq!(s.mock.requests(), before);
        // With messages off, there is nothing to tick
        let mut s = scene().await;
        s.choices.options.acknowledged = false;
        s.choices.options.messages = false;
        assert_eq!(run_it(&mut s).await.stopped, None);
    }

    #[tokio::test(start_paused = true)]
    async fn stop_is_there_while_discord_keeps_it_waiting() {
        let mut s = scene().await;
        // Discord asks for an hour
        let route = format!("/channels/{}/messages", fixture::GENERAL);
        s.mock.script(Scripted::new(
            &route,
            1,
            429,
            &[("retry-after", "3600")],
            r#"{"message":"slow","retry_after":3600,"global":false}"#,
        ));
        let (job, stop, _seen) = job(s.choices.clone());
        let started = Instant::now();
        let press = async {
            sleep(Duration::from_secs(5)).await;
            stop.send_replace(true);
            std::future::pending::<()>().await;
        };
        let out = tokio::select! {
            out = run(s.api.clone(), &mut s.relay, &mut s.sink, &s.read, fixture::here(), job) => out,
            () = press => unreachable!(),
        };
        assert_eq!(out.stopped.as_deref(), Some(STOPPED));
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{:?}",
            started.elapsed()
        );
        assert!(!s.relay.kinds().contains(&"end"));
        // The report so far is still there
        assert!(!out.report.notes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_emote_that_did_not_come_is_not_in_the_ledger() {
        let mut s = scene().await;
        s.sink.fail = Some("pog".into());
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        let named: Vec<&str> = s
            .relay
            .frames
            .iter()
            .filter_map(|f| match f {
                AdminOp::ImportEmote { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert!(!named.contains(&"pog"), "{named:?}");
        assert!(named.contains(&"party_blob"), "{named:?}");
        assert_eq!(s.sink.added.len(), named.len());
        assert!(out
            .report
            .end_screen()
            .join("\n")
            .contains(":pog: did not come"));
    }

    /// W2-27: a run cut between an emote's upload and its ledger frame, then the server read
    /// again: its name was taken by then, so the plan named it anew. The sink finds the first
    /// still listed, and the ledger and the posts go by that.
    #[tokio::test(start_paused = true)]
    async fn an_emote_listed_under_an_earlier_name_is_filed_under_it() {
        let mut s = scene().await;
        let pog = s.read.emojis.iter().find(|e| e.name == "pog").unwrap().id;
        s.sink.listed.insert(pog, "pog_first".into());
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        let named: Vec<&str> = s
            .relay
            .frames
            .iter()
            .filter_map(|f| match f {
                AdminOp::ImportEmote { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert!(named.contains(&"pog_first"), "{named:?}");
        assert!(!named.contains(&"pog"), "{named:?}");
        let body = &s.relay.row(1_200_000_000_000_005_007).unwrap().body;
        assert!(body.starts_with(":pog_first: and :party_blob:"), "{body}");
    }

    /// Stop lands while the relay has been told of an emote and its ledger frame has not gone.
    #[tokio::test(start_paused = true)]
    async fn stop_waits_for_the_emote_in_hand_and_takes_no_more() {
        struct Held {
            added: Vec<String>,
            inside: Option<tokio::sync::oneshot::Sender<()>>,
            go: watch::Receiver<bool>,
        }

        impl EmoteSink for Held {
            fn add(
                &mut self,
                emote: &PlannedEmote,
            ) -> impl Future<Output = Result<String, String>> + Send {
                self.added.push(emote.name.clone());
                let inside = self.inside.take();
                let mut go = self.go.clone();
                let name = emote.name.clone();
                async move {
                    if let Some(inside) = inside {
                        let _ = inside.send(());
                    }
                    let _ = go.wait_for(|on| *on).await;
                    Ok(name)
                }
            }
        }

        let mut s = scene().await;
        let (let_go, go) = watch::channel(false);
        let (inside, is_inside) = tokio::sync::oneshot::channel();
        let mut sink = Held {
            added: Vec::new(),
            inside: Some(inside),
            go,
        };
        let (job, stop, _seen) = job(s.choices.clone());
        let press = async {
            is_inside.await.unwrap();
            stop.send_replace(true);
            // It waits, however long this one takes
            sleep(Duration::from_secs(60)).await;
            let_go.send_replace(true);
            std::future::pending::<()>().await;
        };
        let started = Instant::now();
        let out = tokio::select! {
            out = run(s.api.clone(), &mut s.relay, &mut sink, &s.read, fixture::here(), job) => out,
            () = press => unreachable!(),
        };
        assert_eq!(out.stopped.as_deref(), Some(STOPPED));
        assert!(started.elapsed() >= Duration::from_secs(60));
        let filed: Vec<String> = s
            .relay
            .frames
            .iter()
            .filter_map(|f| match f {
                AdminOp::ImportEmote { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(sink.added.len(), 1, "no more were begun");
        assert_eq!(filed, sink.added, "and the one in hand reached the ledger");
        assert!(!s.relay.kinds().contains(&"threads"));
    }

    fn row_by(id: u64, author: u64) -> String {
        format!(
            r#"{{"id":"{id}","type":0,"author":{{"id":"{author}","username":"someone"}},
                 "content":"words"}}"#
        )
    }

    fn script_page(s: &Scene, channel: u64, rows: &[String]) {
        let route = format!("/channels/{channel}/messages");
        let body = format!("[{}]", rows.join(","));
        s.mock.script(Scripted::new(&route, 1, 200, &[], &body));
    }

    impl FakeRelay {
        fn row(&self, id: u64) -> Option<&voipc_protocol::types::ImportMessage> {
            self.frames.iter().find_map(|f| match f {
                AdminOp::ImportMessages { rows, .. } => rows.iter().find(|r| r.id == id),
                _ => None,
            })
        }

        fn asked_for_wishes(&self) -> usize {
            self.frames
                .iter()
                .filter(|f| matches!(f, AdminOp::ArchiveWishes { .. }))
                .count()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_wish_holds_for_a_row_that_would_go_in_with_no_name() {
        const BEA: u64 = 1_190_000_000_000_007_001;
        const CAL: u64 = 1_190_000_000_000_007_002;
        const FEW: u64 = 1_190_000_000_000_007_003;
        const OFF: u64 = 1_190_000_000_000_007_004;
        const NOT_YET: u64 = 1_190_000_000_000_007_005;
        const NOBODY: u64 = 1_190_000_000_000_007_006;
        const TOP: u64 = i64::MAX as u64;
        let at = |n: u64| LOUNGE_FIRST + n;
        let thread_row = fixture::LOUNGE_THREAD + 100;
        let wish = |author, channel, low, high, erase| ArchiveWish {
            author,
            channel,
            low,
            high,
            erase,
        };
        let mut s = scene().await;
        script_page(
            &s,
            fixture::LOUNGE,
            &[
                row_by(at(0), BEA),
                row_by(at(1), CAL),
                row_by(at(2), FEW),
                row_by(at(3), OFF),
                row_by(at(4), NOT_YET),
                row_by(at(5), NOBODY),
                row_by(at(6), fixture::EVA),
            ],
        );
        // In a thread, a wish goes by the channel it hangs off
        script_page(&s, fixture::LOUNGE_THREAD, &[row_by(thread_row, CAL)]);
        s.relay.wishes = vec![
            wish(fixture::EVA, 0, 0, TOP, true),
            wish(BEA, 0, 0, TOP, true),
            wish(CAL, fixture::LOUNGE, 0, TOP, false),
            wish(FEW, 0, at(2), at(2), false),
            wish(OFF, fixture::GENERAL, 0, TOP, true),
            wish(NOT_YET, 0, 0, at(3), true),
        ];
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert_eq!(s.relay.asked_for_wishes(), 3, "every page of them");
        // Hidden or deleted, it comes to nothing here. Hiding it for all but its author could
        // not be done with no author on it
        for gone in [at(0), at(1), at(2), thread_row] {
            assert!(s.relay.row(gone).is_none(), "{gone}");
        }
        // Another channel's, a span that stops short, and someone with no wish beside them
        for stays in [at(3), at(4), at(5)] {
            let row = s.relay.row(stays).unwrap();
            assert_eq!(row.author, None, "{stays}");
            assert_eq!(row.author_name, "Former member");
        }
        // A member's goes with an id, and the relay goes by that
        assert_eq!(s.relay.row(at(6)).unwrap().author, Some(fixture::EVA));
        // Read past either way, so that the next run does not read it all again
        let frames = s.relay.message_frames(fixture::LOUNGE, None);
        assert!(frames.iter().any(|(high, _)| *high == at(6)), "{frames:?}");
        let frames = s
            .relay
            .message_frames(fixture::LOUNGE, Some(fixture::LOUNGE_THREAD));
        assert!(
            frames.iter().any(|(high, _)| *high == thread_row),
            "{frames:?}"
        );

        // Anonymise off: no row lacks an id, so nothing need be held here
        let mut s = scene().await;
        script_page(&s, fixture::LOUNGE, &[row_by(at(0), BEA)]);
        s.relay.wishes = vec![wish(BEA, 0, 0, TOP, true)];
        s.choices.options.anonymise = false;
        run_it(&mut s).await;
        assert_eq!(s.relay.asked_for_wishes(), 0);
        assert_eq!(s.relay.row(at(0)).unwrap().author, Some(BEA));
    }

    /// What `#lounge`'s thread says of whoever started it, when that is `owner`.
    async fn owner_sent(owner: u64, set: impl FnOnce(&mut Scene)) -> Option<u64> {
        let mut s = scene().await;
        s.read
            .threads
            .iter_mut()
            .find(|t| t.id == fixture::LOUNGE_THREAD)
            .unwrap()
            .owner_id = Some(owner);
        set(&mut s);
        assert_eq!(run_it(&mut s).await.stopped, None);
        let thread = s.relay.frames.iter().find_map(|f| match f {
            AdminOp::ImportThreads { rows, .. } => {
                rows.iter().find(|t| t.id == fixture::LOUNGE_THREAD)
            }
            _ => None,
        });
        thread.unwrap().owner
    }

    #[tokio::test(start_paused = true)]
    async fn a_thread_goes_by_who_started_it_unless_that_would_name_an_ex_member() {
        const GONE: u64 = 1_190_000_000_000_007_001;
        let wish = |channel, high| ArchiveWish {
            author: GONE,
            channel,
            low: 0,
            high,
            erase: false,
        };
        assert_eq!(owner_sent(fixture::EVA, |_| {}).await, Some(fixture::EVA));
        assert_eq!(owner_sent(GONE, |_| {}).await, None);
        // A wish of theirs that reaches it, or their being erased: the relay has the id, and
        // only by the id does the wish reach the row
        let covers = wish(fixture::LOUNGE, i64::MAX as u64);
        let out = owner_sent(GONE, |s| s.relay.wishes = vec![covers]).await;
        assert_eq!(out, Some(GONE));
        let out = owner_sent(GONE, |s| {
            s.relay.excluded = vec![(GONE.to_string(), false, true, 1)];
        })
        .await;
        assert_eq!(out, Some(GONE));
        // The controls: one that does not reach it, in place or in span, and a lifted ban
        let elsewhere = wish(fixture::GENERAL, i64::MAX as u64);
        let out = owner_sent(GONE, |s| s.relay.wishes = vec![elsewhere]).await;
        assert_eq!(out, None);
        let older = wish(fixture::LOUNGE, fixture::LOUNGE_THREAD - 1);
        let out = owner_sent(GONE, |s| s.relay.wishes = vec![older]).await;
        assert_eq!(out, None);
        let out = owner_sent(GONE, |s| {
            s.relay.excluded = vec![(GONE.to_string(), false, false, 1)];
        })
        .await;
        assert_eq!(out, None);
        // With anonymise off, a row of theirs would have the id too
        let out = owner_sent(GONE, |s| s.choices.options.anonymise = false).await;
        assert_eq!(out, Some(GONE));
    }

    /// From the year 2040, so newer than any member list a test reads.
    const LATER: u64 = 3_310_000_000_000_005_001;

    #[tokio::test(start_paused = true)]
    async fn someone_who_joined_since_the_list_goes_in_as_a_member() {
        const JOINED: u64 = 1_190_000_000_000_008_001;
        const LEFT_NOW: u64 = 1_190_000_000_000_008_002;
        const OUT_OF_REACH: u64 = 1_190_000_000_000_008_003;
        let mut s = scene().await;
        s.mock.add_messages(fixture::GENERAL, 3, 5);
        let mention = format!(
            r#"{{"id":"{}","type":0,"author":{{"id":"{}","username":"eva.e"}},
                 "content":"hi <@{JOINED}>"}}"#,
            LATER + 4,
            fixture::EVA
        );
        script_page(
            &s,
            fixture::LOUNGE,
            &[
                row_by(LATER, JOINED),
                row_by(LATER + 1, LEFT_NOW),
                row_by(LATER + 2, OUT_OF_REACH),
                row_by(LATER + 3, JOINED),
                mention,
                row_by(LATER + 6, LEFT_NOW),
                row_by(LATER + 7, OUT_OF_REACH),
            ],
        );
        // In another walker too: asked once, and that one waits for the answer
        script_page(&s, fixture::NEWS, &[row_by(LATER + 5, JOINED)]);
        let found = format!(
            r#"{{"user":{{"id":"{JOINED}","username":"newcomer"}},"nick":"Newbie","roles":[]}}"#
        );
        let member = |id: u64| format!("/guilds/{G}/members/{id}");
        s.mock
            .script(Scripted::new(&member(JOINED), 1, 200, &[], &found));
        s.mock.script(
            Scripted::new(
                &member(OUT_OF_REACH),
                1,
                403,
                &[],
                r#"{"message":"Missing Access","code":50001}"#,
            )
            .always(),
        );
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        let row = s.relay.row(LATER).unwrap();
        assert_eq!(row.author, Some(JOINED));
        assert_eq!(row.author_name, "Newbie");
        assert_eq!(s.relay.row(LATER + 3).unwrap().author, Some(JOINED));
        assert_eq!(s.relay.row(LATER + 5).unwrap().author, Some(JOINED));
        assert_eq!(s.relay.row(LATER + 4).unwrap().body, "hi @Newbie");
        // A 404: they have left. Anything else cannot say so, and it goes on the screen
        for gone in [LATER + 1, LATER + 2] {
            let row = s.relay.row(gone).unwrap();
            assert_eq!(
                (row.author, row.author_name.as_str()),
                (None, "Former member")
            );
        }
        let asked = s.asked();
        let times = |id: u64| asked.iter().filter(|p| **p == member(id)).count();
        assert_eq!((times(JOINED), times(LEFT_NOW)), (1, 1), "{asked:?}");
        let says = "would not say whether someone who wrote or was mentioned during the run";
        assert_eq!(out.report.end_screen().join("\n").matches(says).count(), 1);
        assert!(!out.report.kept().contains(says));
        // Older than the list: gone, and nobody is asked. That is every ex-member there is
        assert!(!asked
            .iter()
            .any(|p| p.contains("/members/1190000000100000000")));
        assert!(s.relay.sent_rows(fixture::GENERAL, None).len() > 3);

        // With anonymise off nothing turns on it, and nobody is asked
        let mut s = scene().await;
        script_page(&s, fixture::LOUNGE, &[row_by(LATER, JOINED)]);
        s.choices.options.anonymise = false;
        run_it(&mut s).await;
        assert!(!s.asked().iter().any(|p| *p == member(JOINED)));
        assert_eq!(s.relay.row(LATER).unwrap().author, Some(JOINED));

        // A dead token stops the run here as anywhere
        let mut s = scene().await;
        script_page(&s, fixture::LOUNGE, &[row_by(LATER, JOINED)]);
        s.mock
            .script(Scripted::new(&member(JOINED), 1, 401, &[], "{}"));
        assert!(run_it(&mut s).await.stopped.unwrap().contains("token"));
    }

    /// A welcome is the usual case: no row of the newcomer's says who they are.
    #[tokio::test(start_paused = true)]
    async fn someone_who_joined_since_and_is_only_mentioned_goes_in_by_their_name() {
        const JOINED: u64 = 1_190_000_000_000_008_001;
        const LEFT_NOW: u64 = 1_190_000_000_000_008_002;
        const A_BOT: u64 = 1_190_000_000_000_008_003;
        const ERASED: u64 = 1_190_000_000_000_008_004;
        const HELD: u64 = 1_190_000_000_000_008_005;
        let member = |id: u64| format!("/guilds/{G}/members/{id}");
        let saying = |id: u64, names: &[u64]| {
            let content: Vec<String> = names.iter().map(|n| format!("<@{n}>")).collect();
            let mentions: Vec<String> = names
                .iter()
                .map(|n| {
                    let bot = *n == A_BOT;
                    format!(r#"{{"id":"{n}","username":"someone","bot":{bot}}}"#)
                })
                .collect();
            format!(
                r#"{{"id":"{id}","type":0,"author":{{"id":"{}","username":"eva.e"}},
                     "content":"{}","mentions":[{}]}}"#,
                fixture::EVA,
                content.join(" "),
                mentions.join(",")
            )
        };
        let found = format!(
            r#"{{"user":{{"id":"{JOINED}","username":"newcomer"}},"nick":"Newbie","roles":[]}}"#
        );
        let mut s = scene().await;
        script_page(
            &s,
            fixture::LOUNGE,
            &[
                saying(LATER, &[JOINED]),
                saying(LATER + 1, &[JOINED, LEFT_NOW]),
                saying(LATER + 2, &[A_BOT, ERASED, HELD]),
                saying(LATER + 3, &[fixture::EVA]),
                // Older than the list says nothing to ask about
                saying(LOUNGE_FIRST, &[LEFT_NOW + 100]),
            ],
        );
        s.mock
            .script(Scripted::new(&member(JOINED), 1, 200, &[], &found));
        s.relay.excluded = vec![
            (ERASED.to_string(), false, true, 1),
            (HELD.to_string(), false, false, 1),
        ];
        assert_eq!(run_it(&mut s).await.stopped, None);
        assert_eq!(s.relay.row(LATER).unwrap().body, "@Newbie");
        assert_eq!(
            s.relay.row(LATER + 1).unwrap().body,
            "@Newbie @Former member",
            "a 404 says they have left"
        );
        assert_eq!(
            s.relay.row(LATER + 2).unwrap().body,
            "@someone @unknown @unknown"
        );
        let asked = s.asked();
        let times = |id: u64| asked.iter().filter(|p| **p == member(id)).count();
        assert_eq!((times(JOINED), times(LEFT_NOW)), (1, 1), "{asked:?}");
        // The controls: nothing a member's question could change
        for id in [A_BOT, ERASED, HELD, LEFT_NOW + 100, fixture::EVA] {
            assert_eq!(times(id), 0, "{id}");
        }

        // With anonymise off nothing turns on it, and nobody is asked
        let mut s = scene().await;
        script_page(&s, fixture::LOUNGE, &[saying(LATER, &[JOINED])]);
        s.choices.options.anonymise = false;
        assert_eq!(run_it(&mut s).await.stopped, None);
        assert!(!s.asked().contains(&member(JOINED)));
    }

    impl FakeRelay {
        /// The threads sent as having no name but the neutral one.
        fn threads_taken_back(&self) -> Vec<&ImportThread> {
            let frames = self.frames.iter().filter_map(|f| match f {
                AdminOp::ImportThreads { rows, .. } => Some(rows),
                _ => None,
            });
            frames
                .flatten()
                .filter(|t| t.name == THREAD_TAKEN_BACK)
                .collect()
        }
    }

    /// Her words may be its name. The relay never hears of a row the driver drops, and the thread
    /// went first, under whoever started it.
    #[tokio::test(start_paused = true)]
    async fn a_threads_first_message_that_does_not_come_takes_its_name_with_it() {
        const GONE: u64 = 1_190_000_000_000_007_001;
        const FORUM_POST: u64 = 1_200_000_000_000_006_001;
        const HELP_FORUM: u64 = 1_190_000_000_000_000_230;
        let opening = fixture::LOUNGE_THREAD;
        let wish = |erase| ArchiveWish {
            author: GONE,
            channel: 0,
            low: 0,
            high: i64::MAX as u64,
            erase,
        };
        /// `#lounge`, whose first page is this one row.
        async fn walked(row: String, set: impl FnOnce(&mut Scene)) -> (Scene, Outcome) {
            let mut s = scene().await;
            script_page(&s, fixture::LOUNGE, &[row]);
            set(&mut s);
            let out = run_it(&mut s).await;
            assert_eq!(out.stopped, None);
            (s, out)
        }
        let by_gone = row_by(opening, GONE);
        // A delete and a hide alike: an anonymised row can be neither, so it does not come
        let (clean, clean_out) = walked(by_gone.clone(), |_| {}).await;
        for erase in [true, false] {
            let (s, out) = walked(by_gone.clone(), |s| s.relay.wishes = vec![wish(erase)]).await;
            assert!(s.relay.row(opening).is_none());
            let sent = s.relay.threads_taken_back();
            assert_eq!(sent.len(), 1, "{sent:?}");
            let thread = s.read.threads.iter().find(|t| t.id == opening).unwrap();
            assert_eq!(sent[0].id, opening);
            assert_eq!(sent[0].parent, fixture::LOUNGE);
            assert_eq!(sent[0].owner, None, "under nobody's name");
            assert_eq!(sent[0].replies, thread.message_count);
            // A thread that was counted once, and not as a message
            assert_eq!(
                out.report.counts["threads"],
                clean_out.report.counts["threads"]
            );
            assert_eq!(
                out.report.counts["messages"] + 1,
                clean_out.report.counts["messages"]
            );
            // Ahead of the frame whose cursor goes past it: no later run reads that row again
            let at = |is: &dyn Fn(&AdminOp) -> bool| s.relay.frames.iter().position(is).unwrap();
            let neutral = at(&|f| {
                matches!(f, AdminOp::ImportThreads { rows, .. }
                         if rows[0].name == THREAD_TAKEN_BACK)
            });
            let past = at(&|f| {
                matches!(f, AdminOp::ImportMessages { high, thread: None, channel, .. }
                         if *channel == fixture::LOUNGE && *high >= opening)
            });
            assert!(neutral < past, "{neutral} {past}");
        }
        // The control: nobody took anything back, and the row and its thread's name stay
        assert!(clean.relay.threads_taken_back().is_empty());
        assert!(clean.relay.row(opening).is_some());

        // Left out and erased: the same, with or without anonymise
        let erased = (GONE.to_string(), false, true, 1);
        for anonymise in [true, false] {
            let (s, _) = walked(by_gone.clone(), |s| {
                s.relay.excluded = vec![erased.clone()];
                s.choices.options.anonymise = anonymise;
            })
            .await;
            assert!(s.relay.row(opening).is_none());
            assert_eq!(s.relay.threads_taken_back().len(), 1);
        }
        // A forum post's first message is in its own thread, and its parent is what a wish holds
        let (s, _) = walked(row_by(LOUNGE_FIRST, fixture::EVA), |s| {
            script_page(s, FORUM_POST, &[row_by(FORUM_POST, GONE)]);
            s.relay.wishes = vec![ArchiveWish {
                channel: HELP_FORUM,
                ..wish(true)
            }];
        })
        .await;
        assert!(s.relay.row(FORUM_POST).is_none());
        let sent = s.relay.threads_taken_back();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!((sent[0].id, sent[0].parent), (FORUM_POST, HELP_FORUM));

        // The controls. A row dropped that no thread opens on: nothing made out of nothing
        let (s, _) = walked(row_by(LOUNGE_FIRST, GONE), |s| {
            s.relay.wishes = vec![wish(true)];
        })
        .await;
        assert!(s.relay.row(LOUNGE_FIRST).is_none());
        assert!(s.relay.threads_taken_back().is_empty());
        // A held person's row comes, and the relay can go by it
        let (s, _) = walked(by_gone.clone(), |s| {
            s.relay.excluded = vec![(GONE.to_string(), false, false, 1)];
        })
        .await;
        assert!(s.relay.row(opening).is_some());
        assert!(s.relay.threads_taken_back().is_empty());
        // A webhook's row is nobody's, whoever has that id
        let hook = format!(
            r#"{{"id":"{opening}","type":0,"webhook_id":"5",
                 "author":{{"id":"{GONE}","username":"hook"}},"content":"words"}}"#
        );
        let (s, _) = walked(hook, |s| s.relay.excluded = vec![erased.clone()]).await;
        assert!(s.relay.row(opening).is_some());
        assert!(s.relay.threads_taken_back().is_empty());
        // Threads off: none was told of, so none is made here
        let (s, _) = walked(by_gone, |s| {
            s.relay.wishes = vec![wish(true)];
            s.choices.options.threads = false;
        })
        .await;
        assert!(s.relay.row(opening).is_none());
        assert!(!s.relay.kinds().contains(&"threads"));
    }

    /// `#lounge`, made by an earlier run with no gate, and read this far.
    async fn lounge_in_the_ledger() -> Scene {
        let mut s = scene().await;
        s.relay.cursors = vec![(fixture::LOUNGE, 1)];
        s.relay.open_here = vec![fixture::LOUNGE];
        s
    }

    fn lounge_row_sent(s: &Scene) -> voipc_protocol::types::ImportChannel {
        let rows = s.relay.frames.iter().find_map(|f| match f {
            AdminOp::ImportChannels { rows, .. } => {
                rows.iter().find(|r| r.dc_id == fixture::LOUNGE)
            }
            _ => None,
        });
        rows.unwrap().clone()
    }

    /// The fresh read, of the same thing: the dry-run says open and Discord does not. Everything
    /// here goes through `relay.open_here`, which is the relay's rule for a row of its own.
    #[tokio::test(start_paused = true)]
    async fn a_channel_closed_after_the_dry_run_is_refused() {
        let mut s = lounge_in_the_ledger().await;
        assert_eq!(
            s.read
                .channels
                .iter()
                .find(|c| c.id == fixture::LOUNGE)
                .unwrap()
                .permission_overwrites
                .len(),
            0,
            "the dry-run saw it open"
        );
        s.mock.deny_everyone(fixture::LOUNGE, VIEW_CHANNEL);
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None, "the run goes on");
        assert_ne!(lounge_row_sent(&s).see, ImportGate::Open);
        assert!(out.report.left_out.contains(&fixture::LOUNGE));
        let text = out.report.end_screen().join("\n");
        assert!(text.contains(&format!("#lounge: {PRIVATE_NOW}")), "{text}");
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let in_thread = Some(fixture::LOUNGE_THREAD);
        assert!(s.relay.sent_rows(fixture::LOUNGE, in_thread).is_empty());
        assert!(!s.relay.sent_rows(fixture::GENERAL, None).is_empty());

        // The control: left open, the same run takes it
        let mut s = lounge_in_the_ledger().await;
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert_eq!(lounge_row_sent(&s).see, ImportGate::Open);
        assert!(!out.report.left_out.contains(&fixture::LOUNGE));
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        assert!(!s
            .relay
            .sent_rows(fixture::LOUNGE, Some(fixture::LOUNGE_THREAD))
            .is_empty());
    }

    /// Closed by what `@everyone` may do at all, with no channel's rules touched.
    #[tokio::test(start_paused = true)]
    async fn a_channel_closed_by_a_role_after_the_dry_run_is_refused() {
        let mut s = lounge_in_the_ledger().await;
        let mut roles: Vec<serde_json::Value> =
            serde_json::from_slice(&fixture::files()["roles.json"]).unwrap();
        let guild = G.to_string();
        let everyone = roles
            .iter_mut()
            .find(|r| r["id"] == guild.as_str())
            .unwrap();
        let bits: u64 = everyone["permissions"].as_str().unwrap().parse().unwrap();
        everyone["permissions"] = (bits & !VIEW_CHANNEL).to_string().into();
        let body = serde_json::to_string(&roles).unwrap();
        let route = format!("/guilds/{G}/roles");
        s.mock.script(Scripted::new(&route, 1, 200, &[], &body));
        let out = run_it(&mut s).await;
        assert_ne!(lounge_row_sent(&s).see, ImportGate::Open);
        assert!(out.report.left_out.contains(&fixture::LOUNGE));
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
    }

    /// The tick was for it open. A cursor does not change that: it is only the relay's word.
    #[tokio::test(start_paused = true)]
    async fn a_channel_closed_since_the_dry_run_stays_off_whatever_the_relay_says_of_it() {
        let mut s = scene().await;
        s.relay.cursors = vec![(fixture::LOUNGE, 1)];
        s.mock.deny_everyone(fixture::LOUNGE, VIEW_CHANNEL);
        let out = run_it(&mut s).await;
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(text.contains("#lounge: closed on Discord"), "{text}");
    }

    /// The control: ticked with the dry-run showing it closed, the tick is for that, and the gate
    /// here, set by hand or by a run, is what guards the rows.
    #[tokio::test(start_paused = true)]
    async fn a_channel_ticked_closed_goes_on_behind_its_gate_here() {
        let mock = fixture::mock();
        mock.deny_everyone(fixture::LOUNGE, VIEW_CHANNEL);
        let mut s = scene_of(mock).await;
        s.relay.cursors = vec![(fixture::LOUNGE, 1)];
        assert!(!s.choices.messages_on.contains(&fixture::LOUNGE));
        s.choices.messages_on.insert(fixture::LOUNGE);
        let out = run_it(&mut s).await;
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(!text.contains("#lounge: closed on Discord"), "{text}");
    }

    /// What a hostile relay would ask for: a cursor on a channel the operator never ticked.
    #[tokio::test(start_paused = true)]
    async fn a_private_channel_with_a_cursor_sends_nothing_without_its_tick() {
        let mut s = scene().await;
        s.relay.cursors = vec![(fixture::STAFF, 1)];
        let mut here = fixture::here();
        here.cursors.insert(fixture::STAFF, 1);
        s.choices = default_choices(&s.read, &here);
        s.choices.options.acknowledged = true;
        run_it(&mut s).await;
        assert!(s.relay.sent_rows(fixture::STAFF, None).is_empty());
        // The control: ticked, its rows go
        let mut s = scene().await;
        s.relay.cursors = vec![(fixture::STAFF, 1)];
        s.choices.messages_on.insert(fixture::STAFF);
        run_it(&mut s).await;
        assert!(!s.relay.sent_rows(fixture::STAFF, None).is_empty());
    }

    /// Presses Stop on the way through the emotes: the channels have gone by then.
    struct PressesStop(watch::Sender<bool>);

    impl EmoteSink for PressesStop {
        fn add(
            &mut self,
            emote: &PlannedEmote,
        ) -> impl Future<Output = Result<String, String>> + Send {
            self.0.send_replace(true);
            std::future::ready(Ok(emote.name.clone()))
        }
    }

    /// Stopped with `#lounge` open, as a person does, and nothing of it filed yet.
    async fn stopped_with_lounge_open() -> Scene {
        let mut s = lounge_in_the_ledger().await;
        let (job, stop, _seen) = job(s.choices.clone());
        let out = run(
            s.api.clone(),
            &mut s.relay,
            &mut PressesStop(stop),
            &s.read,
            fixture::here(),
            job,
        )
        .await;
        assert_eq!(out.stopped.as_deref(), Some(STOPPED));
        assert_eq!(lounge_row_sent(&s).see, ImportGate::Open);
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        s.relay.frames.clear();
        s
    }

    /// Go on keeps the dry-run, with its read and its ticks, so it asks as a first go does.
    #[tokio::test(start_paused = true)]
    async fn a_channel_closed_between_stop_and_go_on_is_refused() {
        let mut s = stopped_with_lounge_open().await;
        s.mock.deny_everyone(fixture::LOUNGE, VIEW_CHANNEL);
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert_ne!(lounge_row_sent(&s).see, ImportGate::Open);
        let text = out.report.end_screen().join("\n");
        assert!(text.contains(&format!("#lounge: {PRIVATE_NOW}")), "{text}");
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());

        // The control: left open, Go on takes it
        let mut s = stopped_with_lounge_open().await;
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert_eq!(lounge_row_sent(&s).see, ImportGate::Open);
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn opened_again_since_goes_by_what_discord_says_too() {
        let mut s = lounge_in_the_ledger().await;
        s.mock.deny_everyone(fixture::LOUNGE, VIEW_CHANNEL);
        assert!(!run_it(&mut s).await.report.left_out.is_empty());
        s.relay.frames.clear();
        s.mock.deny_everyone(fixture::LOUNGE, 0);
        let out = run_it(&mut s).await;
        assert!(!out.report.left_out.contains(&fixture::LOUNGE));
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
    }

    /// Nothing filed on a read that did not come, and nothing on what the dry-run said instead.
    #[tokio::test(start_paused = true)]
    async fn a_failed_read_before_a_run_stops_it_before_anything_is_filed() {
        let no_access = r#"{"message":"Missing Access","code":50001}"#;
        for (route, says) in [
            (format!("/guilds/{G}/channels"), "its channels"),
            (format!("/guilds/{G}/roles"), "its roles"),
        ] {
            let mut s = scene().await;
            s.mock
                .script(Scripted::new(&route, 1, 403, &[], no_access).always());
            let out = run_it(&mut s).await;
            let words = out.stopped.unwrap();
            assert!(words.contains(says), "{words}");
            assert!(s.relay.kinds().is_empty(), "{:?}", s.relay.kinds());
            assert!(!s
                .relay
                .frames
                .iter()
                .any(|f| matches!(f, AdminOp::ImportEnd { .. })));
        }
        // A dead token stops it too, in its own words
        let mut s = scene().await;
        let route = format!("/guilds/{G}/channels");
        s.mock.script(Scripted::new(&route, 1, 401, &[], "{}"));
        let out = run_it(&mut s).await;
        assert!(out.stopped.unwrap().contains("token"));
        assert!(s.relay.kinds().is_empty());
    }

    /// A role with nobody in it takes no place in a gate. It has someone now, so what it was kept
    /// from counts. The counts are the one thing a run can do without, as a dry-run can.
    #[tokio::test(start_paused = true)]
    async fn a_role_that_has_someone_since_the_dry_run_counts_in_the_gate() {
        const MUTED: u64 = 1_190_000_000_000_000_104;
        let route = format!("/guilds/{G}/roles/member-counts");
        let mock = fixture::mock();
        let counts: HashMap<String, u64> =
            serde_json::from_slice(&fixture::files()["role-counts.json"]).unwrap();
        let without = counts
            .into_iter()
            .filter(|(role, _)| *role != MUTED.to_string())
            .collect::<HashMap<_, _>>();
        let without = serde_json::to_string(&without).unwrap();
        mock.script(Scripted::new(&route, 1, 200, &[], &without));
        let after_dark = |s: &Scene| {
            let rows = s.relay.frames.iter().find_map(|f| match f {
                AdminOp::ImportChannels { rows, .. } => {
                    rows.iter().find(|r| r.dc_id == fixture::AFTER_DARK)
                }
                _ => None,
            });
            rows.unwrap().see.clone()
        };
        let mut s = scene_of(mock).await;
        assert!(
            s.choices.messages_on.contains(&fixture::AFTER_DARK),
            "open, as the dry-run read it"
        );
        s.relay.cursors = vec![(fixture::AFTER_DARK, 1)];
        s.relay.open_here = vec![fixture::AFTER_DARK];
        let out = run_it(&mut s).await;
        assert_ne!(after_dark(&s), ImportGate::Open);
        assert!(out.report.left_out.contains(&fixture::AFTER_DARK));

        // Discord will not say: every role counts, and nothing stops
        let mut s = scene().await;
        s.mock
            .script(Scripted::new(&route, 1, 403, &[], "{}").always());
        assert_eq!(run_it(&mut s).await.stopped, None);
        assert_ne!(after_dark(&s), ImportGate::Open);
    }

    /// Only its history closed since: the relay sees an open channel and cannot refuse it, and
    /// nobody ticked this. One the dry-run showed that way has had its tick looked at.
    #[tokio::test(start_paused = true)]
    async fn a_history_closed_since_the_dry_run_comes_only_by_a_tick_given_since() {
        let mut s = lounge_in_the_ledger().await;
        s.mock.deny_everyone(fixture::LOUNGE, READ_MESSAGE_HISTORY);
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        assert_eq!(
            lounge_row_sent(&s).see,
            ImportGate::Open,
            "not for the relay"
        );
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(text.contains("#lounge: closed on Discord since"), "{text}");
        assert!(
            !out.report.kept().contains("closed on Discord"),
            "{}",
            out.report.kept()
        );
        assert!(!s.relay.sent_rows(fixture::GENERAL, None).is_empty());

        // Closed before the dry-run, which showed it, and ticked: that tick holds
        let mock = fixture::mock();
        mock.deny_everyone(fixture::LOUNGE, READ_MESSAGE_HISTORY);
        let mut s = scene_of(mock).await;
        assert!(
            !s.choices.messages_on.contains(&fixture::LOUNGE),
            "off, as it starts"
        );
        s.choices.messages_on.insert(fixture::LOUNGE);
        let out = run_it(&mut s).await;
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(!text.contains("#lounge: closed on Discord"), "{text}");

        // Off by the operator's own choice, one way or another: nothing to say of it
        let off: [fn(&mut Choices); 3] = [
            |c| {
                c.messages_on.remove(&fixture::LOUNGE);
            },
            |c| {
                c.left_out.insert(fixture::LOUNGE);
            },
            |c| c.options.messages = false,
        ];
        for set in off {
            let mut s = scene().await;
            set(&mut s.choices);
            s.mock.deny_everyone(fixture::LOUNGE, READ_MESSAGE_HISTORY);
            let out = run_it(&mut s).await;
            let text = out.report.end_screen().join("\n");
            assert!(!text.contains("#lounge: closed on Discord"), "{text}");
        }
    }

    /// New here, so the relay makes it with whatever gate it is given and refuses nothing. It gets
    /// the gate of now, and no history: the tick for that was never asked.
    #[tokio::test(start_paused = true)]
    async fn a_new_channel_closed_since_is_made_closed_and_no_rows_go_in() {
        // A public row must not say what it is called now, either
        let naming = |lounge: u64| {
            format!(
                r#"{{"id":"{LATER}","type":0,"author":{{"id":"{}","username":"eva.e"}},
                     "content":"see <#{lounge}>"}}"#,
                fixture::EVA
            )
        };
        let mut s = scene().await;
        script_page(&s, fixture::GENERAL, &[naming(fixture::LOUNGE)]);
        run_it(&mut s).await;
        assert_eq!(s.relay.row(LATER).unwrap().body, "see #lounge");

        let mut s = scene().await;
        script_page(&s, fixture::GENERAL, &[naming(fixture::LOUNGE)]);
        s.mock.deny_everyone(fixture::LOUNGE, VIEW_CHANNEL);
        let out = run_it(&mut s).await;
        assert_eq!(s.relay.row(LATER).unwrap().body, "see #unknown");
        assert_eq!(out.stopped, None);
        assert_ne!(lounge_row_sent(&s).see, ImportGate::Open);
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let in_thread = Some(fixture::LOUNGE_THREAD);
        assert!(s.relay.sent_rows(fixture::LOUNGE, in_thread).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(text.contains("#lounge: closed on Discord since"), "{text}");

        // The control: ticked at a dry-run that showed it private, that tick holds
        let mock = fixture::mock();
        mock.deny_everyone(fixture::LOUNGE, VIEW_CHANNEL);
        let mut s = scene_of(mock).await;
        assert!(!s.choices.messages_on.contains(&fixture::LOUNGE));
        s.choices.messages_on.insert(fixture::LOUNGE);
        let out = run_it(&mut s).await;
        assert!(!s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(!text.contains("#lounge: closed on Discord"), "{text}");
    }

    /// Gone, or closed to a bot that is no Administrator: no way to tell, and neither comes.
    #[tokio::test(start_paused = true)]
    async fn a_channel_discord_no_longer_lists_does_not_come() {
        let mut s = scene().await;
        let shown: Vec<serde_json::Value> = fixture::files()
            .get("channels.json")
            .map(|b| serde_json::from_slice(b).unwrap())
            .unwrap();
        let lounge = fixture::LOUNGE.to_string();
        let listed: Vec<_> = shown
            .into_iter()
            .filter(|c| c["id"] != lounge.as_str())
            .collect();
        let body = serde_json::to_string(&listed).unwrap();
        let route = format!("/guilds/{G}/channels");
        s.mock.script(Scripted::new(&route, 1, 200, &[], &body));
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        let rows = s.relay.frames.iter().filter_map(|f| match f {
            AdminOp::ImportChannels { rows, .. } => Some(rows),
            _ => None,
        });
        assert!(!rows.flatten().any(|r| r.dc_id == fixture::LOUNGE));
        assert!(s.relay.sent_rows(fixture::LOUNGE, None).is_empty());
        let text = out.report.end_screen().join("\n");
        assert!(
            text.contains("#lounge: Discord no longer lists it"),
            "{text}"
        );
        assert!(!out.report.kept().contains("no longer lists"));
        assert!(!s.relay.sent_rows(fixture::GENERAL, None).is_empty());
    }

    /// One made since waits for the next dry-run, which shows it.
    #[tokio::test(start_paused = true)]
    async fn a_channel_made_since_the_dry_run_waits_for_the_next() {
        let mut s = scene().await;
        s.mock.use_v2();
        assert_eq!(run_it(&mut s).await.stopped, None);
        let rows = s.relay.frames.iter().filter_map(|f| match f {
            AdminOp::ImportChannels { rows, .. } => Some(rows),
            _ => None,
        });
        assert!(!rows.flatten().any(|r| r.dc_id == fixture::NEW_ROOM));
    }

    /// What a note says of a gate holds of one made now. The relay leaves its own as it stands.
    #[tokio::test(start_paused = true)]
    async fn a_channel_of_the_relays_has_no_word_about_a_gate_it_did_not_get() {
        let says = "#general: ";
        let mut s = scene().await;
        let made = run_it(&mut s).await;
        assert!(made.report.end_screen().join("\n").contains(says));
        assert!(made.report.kept().contains(says));

        let mut s = scene().await;
        s.relay.cursors = vec![(fixture::GENERAL, 1)];
        let delta = run_it(&mut s).await;
        assert_eq!(delta.stopped, None);
        let text = delta.report.end_screen().join("\n");
        assert!(!text.contains(says), "{text}");
        assert!(
            !delta.report.kept().contains(says),
            "{}",
            delta.report.kept()
        );
        // The control: another channel, new to it, still says
        assert!(text.contains("#old-logs: "), "{text}");
    }

    #[tokio::test(start_paused = true)]
    async fn who_is_left_out_goes_from_every_list_and_rows_of_the_erased_too() {
        const DAN: u64 = 1_190_000_000_000_001_001;
        const BEA: u64 = 1_190_000_000_000_001_003;
        const BANNED: u64 = 1_190_000_000_000_002_001;
        let mut s = scene().await;
        s.relay.excluded = vec![
            (DAN.to_string(), false, true, 1),
            (BEA.to_string(), false, false, 1),
            (BANNED.to_string(), false, false, 1),
        ];
        run_it(&mut s).await;
        let mut sent_members = Vec::new();
        let mut sent_bans = Vec::new();
        let mut authors = HashSet::new();
        for frame in &s.relay.frames {
            match frame {
                AdminOp::ImportMembers { members, .. } => {
                    sent_members.extend(members.iter().map(|m| m.dc_id));
                }
                AdminOp::ImportBans { bans, .. } => {
                    sent_bans.extend(bans.iter().map(|b| b.dc_id));
                }
                AdminOp::ImportMessages { rows, .. } => {
                    authors.extend(rows.iter().filter_map(|r| r.author));
                }
                _ => {}
            }
        }
        assert!(!sent_members.contains(&DAN) && !sent_members.contains(&BEA));
        assert!(!sent_bans.contains(&BANNED));
        // Held: no account, and their posts still come. Erased: nothing comes
        assert!(!authors.contains(&DAN), "{authors:?}");
        assert!(authors.contains(&BEA), "{authors:?}");
        // The control: their neighbours are all there
        assert!(sent_members.contains(&fixture::EVA), "{sent_members:?}");
        assert!(authors.contains(&fixture::EVA), "{authors:?}");
        assert!(sent_bans.contains(&(BANNED + 1)), "{sent_bans:?}");
    }

    /// The relay's own rule: deleting an account does not stop a ban. Its other arm, someone
    /// who asked to be out, stays with the driver as it did.
    #[tokio::test(start_paused = true)]
    async fn an_own_exit_stays_on_the_ban_frame() {
        const BANNED: u64 = 1_190_000_000_000_002_001;
        let mut s = scene().await;
        s.relay.excluded = vec![
            (BANNED.to_string(), true, true, 1),
            ((BANNED + 1).to_string(), false, true, 1),
        ];
        run_it(&mut s).await;
        let sent: Vec<u64> = s
            .relay
            .frames
            .iter()
            .filter_map(|f| match f {
                AdminOp::ImportBans { bans, .. } => Some(bans.iter().map(|b| b.dc_id)),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(sent.contains(&BANNED), "{sent:?}");
        assert!(!sent.contains(&(BANNED + 1)), "{sent:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn someone_no_longer_banned_there_is_said_and_only_on_the_screen() {
        let still = "1190000000000002001";
        let lifted = "1190000000000009999";
        let mut s = scene().await;
        s.relay.banned_here = vec![still.into(), lifted.into()];
        let out = run_it(&mut s).await;
        let text = out.report.end_screen().join("\n");
        assert!(
            text.contains(&format!("dc-{lifted}: no longer banned")),
            "{text}"
        );
        assert!(
            !text.contains(&format!("dc-{still}: no longer banned")),
            "{text}"
        );
        assert!(!out.report.kept().contains(lifted));

        // A ban list that would not come says nothing of anyone
        let mut s = scene().await;
        s.relay.banned_here = vec![still.into(), lifted.into()];
        let route = format!("/guilds/{G}/bans?");
        s.mock.script(
            Scripted::new(
                &route,
                1,
                403,
                &[],
                r#"{"message":"Missing Access","code":50001}"#,
            )
            .always(),
        );
        // `read` holds the list from before: the run asks again
        let out = run_it(&mut s).await;
        assert_eq!(out.stopped, None);
        let text = out.report.end_screen().join("\n");
        assert!(!text.contains("no longer banned"), "{text}");
        assert!(text.contains("The ban list did not come"), "{text}");
        assert!(!s.relay.kinds().contains(&"bans"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_kept_report_has_counts_and_no_person_and_nothing_left_out() {
        let mut s = scene().await;
        s.choices.left_out.insert(fixture::VAULT);
        let out = run_it(&mut s).await;
        let kept = out.report.kept();
        let AdminOp::ImportEnd { report: sent, .. } = s.relay.frames.last().unwrap().clone() else {
            panic!("no end");
        };
        assert_eq!(sent, kept, "what went is what `kept` says");
        let value: serde_json::Value = serde_json::from_str(&kept).unwrap();
        assert!(value["counts"]["messages"].as_u64().unwrap() > 0, "{kept}");
        assert!(value["counts"]["channels"].as_u64().unwrap() > 0, "{kept}");
        assert!(!kept.contains("vault"), "{kept}");
        assert!(!kept.contains(&fixture::EVA.to_string()), "{kept}");
    }

    #[tokio::test(start_paused = true)]
    async fn someone_banned_who_opened_their_account_is_named_only_on_the_screen() {
        let mut s = scene().await;
        s.relay.banned_who_came = vec!["dan_d".into()];
        let out = run_it(&mut s).await;
        let screen = out.report.end_screen().join("\n");
        assert!(screen.contains("dan_d is banned on Discord"), "{screen}");
        assert!(!out.report.kept().contains("dan_d"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_banned_row_that_kept_its_name_is_named_only_on_the_screen() {
        let mut s = scene().await;
        s.relay.banned_kept_a_name = vec!["mallory".into()];
        let out = run_it(&mut s).await;
        let screen = out.report.end_screen().join("\n");
        assert!(screen.contains("mallory is banned on Discord"), "{screen}");
        assert!(!out.report.kept().contains("mallory"));
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_run_after_another_says_it_took_new_messages_only() {
        let says = "New messages only";
        let mut s = scene().await;
        assert!(!run_it(&mut s).await.report.kept().contains(says));
        let mut s = scene().await;
        s.relay.cursors = vec![(fixture::LOUNGE, 1)];
        assert!(run_it(&mut s).await.report.kept().contains(says));
    }

    #[tokio::test(start_paused = true)]
    async fn a_count_off_by_more_than_two_percent_is_noted() {
        let mut s = scene().await;
        s.read.counts.insert(fixture::LOUNGE, 1000);
        s.read.counts.insert(fixture::GENERAL, 5);
        let out = run_it(&mut s).await;
        let text = out.report.end_screen().join("\n");
        assert!(
            text.contains("#lounge: read 19 messages, and Discord counted 1000."),
            "{text}"
        );
        // The control: one that agrees says nothing
        assert!(!text.contains("#general: read"), "{text}");
        // A count that says there is something, and nothing came: the docs' silent case, of a
        // bot that may not read a channel's history
        let mut s = scene().await;
        s.read.counts.insert(fixture::GENERAL, 5);
        let route = format!("/channels/{}/messages", fixture::GENERAL);
        s.mock.script(Scripted::new(&route, 1, 200, &[], "[]"));
        let out = run_it(&mut s).await;
        let text = out.report.end_screen().join("\n");
        assert!(text.contains("#general: read 0 messages"), "{text}");
    }

    #[tokio::test(start_paused = true)]
    async fn here_of_asks_the_relay_and_goes_by_this_guilds_runs_not_undone() {
        let mut relay = FakeRelay {
            cursors: vec![(5, 9), (6, 0)],
            ..FakeRelay::default()
        };
        let here = here_of(
            &mut relay,
            G,
            vec![("General".into(), false)],
            vec!["pog".into()],
        )
        .await
        .unwrap();
        assert_eq!(here.facts, facts());
        assert_eq!(here.facts.registration, Registration::Invite);
        assert_eq!(here.cursors, HashMap::from([(5, 9), (6, 0)]));
        // Not the undone run, and not the other server's
        assert_eq!(here.last_started_ms, Some(1_700_000_000_000));
        assert_eq!(here.emote_names, ["pog"]);
    }

    #[tokio::test(start_paused = true)]
    async fn progress_says_counts_and_a_channel_and_no_one_s_words() {
        let mut s = scene().await;
        let (job, _stop, seen) = job(s.choices.clone());
        let out = run(
            s.api.clone(),
            &mut s.relay,
            &mut s.sink,
            &s.read,
            fixture::here(),
            job,
        )
        .await;
        assert_eq!(out.stopped, None);
        let last = seen.borrow().clone();
        assert_eq!(last.phase, Phase::Ending);
        let json = serde_json::to_string(&last).unwrap();
        assert!(json.contains("\"phase\":\"ending\""), "{json}");
    }
}
