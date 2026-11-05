//! The dry-run: what a Discord server would come to here, with nothing written anywhere.
//! `read` asks Discord, `layout` works out what a set of choices makes of it, and `build`
//! gives the page its `Plan`, in RAM only and with every id a string: a JS number cannot
//! hold one. A warning stops nothing; nothing here is a limit on members.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use tokio::time::{Duration, Instant};
use voipc_protocol::discord;
use voipc_protocol::types::{
    ImportCategory, ImportChannel, ImportFacts, ImportGate, ImportOptions, ImportThread,
    Registration, MAX_EMOTES,
};

use crate::api::{Api, Fail, Transport};
use crate::fit::{self, FitRow, TOPIC_BYTES};
use crate::gates::{self, ChannelGates, Server};
use crate::model::{
    self, Application, Ban, Channel, Emoji, Guild, GuildBrief, Member, Message, Overwrite, Role,
    Search, Sticker, ThreadList, User, ANNOUNCEMENT, ANNOUNCEMENT_THREAD, CATEGORY, PRIVATE_THREAD,
    PUBLIC_THREAD, STAGE,
};
use crate::names::{self, clip_bytes, clip_chars, Taken};
use crate::rewrite::Names;
use crate::Note;

/// What `/messages/search` may take, one channel after another. Past it, a count shows as
/// unknown: the estimate is not worth more of the operator's time.
const SEARCH_BUDGET: Duration = Duration::from_secs(120);
/// With the docs' 2^53: the largest number the page can hold exactly.
const SAFE_NUMBER: u64 = (1 << 53) - 1;
/// A thread's name (`voipc_archive.thread_name`).
const THREAD_NAME_CHARS: usize = 100;
/// `format_type` of a Lottie sticker, which nothing here can draw.
const LOTTIE: u8 = 3;
/// `encode(AdminReply::Groups)` of what a role makes: a group, and a twin if it has power.
const GROUP_BYTES: u64 = 70;
const TWIN_BYTES: u64 = 290;
const GROUPS_LIMIT: u64 = 60 * 1024;
/// What a row costs beyond its text, measured on each database (3-archive's table).
const ROW_SQLITE: u64 = 108;
const ROW_POSTGRES: u64 = 189;
/// When Discord has not shown one to go by.
const MEAN_BODY: u64 = 80;
/// The stored report's limits.
pub const REPORT_BYTES: usize = 40 * 1024;
const REPORT_NOTES: usize = 200;
const NOTE_CHARS: usize = 500;

fn safe(n: u64) -> u64 {
    n.min(SAFE_NUMBER)
}

fn id(n: u64) -> String {
    n.to_string()
}

/// `import_open`: what a token can reach.
#[derive(Debug, Clone, Serialize)]
pub struct Opening {
    pub bot_name: String,
    pub app_id: String,
    pub member_intent: bool,
    pub content_intent: bool,
    pub guilds: Vec<OpenGuild>,
    pub invite: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenGuild {
    pub id: String,
    pub name: String,
    pub admin: bool,
}

pub async fn open<T: Transport>(api: &Api<T>) -> Result<Opening, String> {
    let me: User = must(api.get("/users/@me").await, "the bot")?;
    let app: Application = must(api.get("/applications/@me").await, "the application")?;
    let guilds: Vec<GuildBrief> = must(api.get("/users/@me/guilds").await, "its servers")?;
    Ok(Opening {
        bot_name: me.username,
        app_id: id(app.id),
        member_intent: app.member_intent(),
        content_intent: app.content_intent(),
        guilds: guilds
            .into_iter()
            .map(|g| OpenGuild {
                id: id(g.id),
                name: g.name,
                admin: g.permissions & discord::ADMINISTRATOR != 0,
            })
            .collect(),
        invite: format!(
            "https://discord.com/oauth2/authorize?client_id={}&scope=bot&permissions=8",
            app.id
        ),
    })
}

fn must<R>(out: Result<R, Fail>, what: &str) -> Result<R, String> {
    out.map_err(|fail| match fail {
        Fail::Stop(words) => words,
        Fail::Skip { note, .. } => format!("Could not read {what}. {note}"),
    })
}

/// A list the run can do without: a note, and on. Only a stop stops.
fn may<R: Default>(out: Result<R, Fail>, what: &str, notes: &mut Vec<Note>) -> Result<R, String> {
    match out {
        Ok(value) => Ok(value),
        Err(Fail::Stop(words)) => Err(words),
        Err(Fail::Skip { note, .. }) => {
            notes.push(Note::screen(
                "not_read",
                None,
                format!("Could not read {what}. {note}"),
            ));
            Ok(R::default())
        }
    }
}

/// Everything a dry-run read: in RAM, for as long as the wizard is open.
#[derive(Clone, Default)]
pub struct Read {
    pub guild: Guild,
    pub bot: User,
    pub app: Application,
    pub bot_roles: Vec<u64>,
    pub channels: Vec<Channel>,
    pub roles: Vec<Role>,
    /// None: Discord would not say.
    pub role_counts: Option<HashMap<u64, u64>>,
    pub emojis: Vec<Emoji>,
    pub stickers: Vec<Sticker>,
    pub bans: Vec<Ban>,
    /// Active and archived public threads, and private ones to count.
    pub threads: Vec<Channel>,
    /// A channel's messages. Missing: not known.
    pub counts: HashMap<u64, u64>,
    pub mean_body: Option<u64>,
    /// Requests a second, from Discord's own answers. None: nothing said.
    pub pace: Option<f64>,
    pub notes: Vec<Note>,
}

impl Read {
    fn bot_reads(&self, ch: &Channel) -> bool {
        gates::bot_reads(self.guild.id, &self.roles, self.bot.id, &self.bot_roles, ch)
    }
}

/// A channel's archived public threads, newest first. `not_before` stops the walk at
/// threads archived before it: a delta has read those.
pub async fn archived_threads<T: Transport>(
    api: &Api<T>,
    parent: u64,
    not_before: Option<&str>,
) -> Result<Vec<Channel>, Fail> {
    let mut all = Vec::new();
    let mut before = String::new();
    loop {
        let query = if before.is_empty() {
            String::new()
        } else {
            // An ISO date holds a `+`, which in a query would read as a space
            format!("&before={}", before.replace('+', "%2B"))
        };
        let page: ThreadList = api
            .get(&format!(
                "/channels/{parent}/threads/archived/public?limit=100{query}"
            ))
            .await?;
        let stamp = |t: &Channel| -> String {
            t.thread_metadata
                .as_ref()
                .map(|m| m.archive_timestamp.clone())
                .unwrap_or_default()
        };
        let last = page.threads.last().map(stamp).unwrap_or_default();
        let moved_on = !last.is_empty() && last != before;
        let more = page.has_more;
        for thread in page.threads {
            if not_before.is_some_and(|floor| stamp(&thread).as_str() < floor) {
                return Ok(all);
            }
            all.push(thread);
        }
        // A page with nothing to go on from would ask the same thing for ever
        if !more || !moved_on {
            return Ok(all);
        }
        before = last;
    }
}

/// All of `/bans`, ascending by id. They stay on this machine.
pub async fn all_bans<T: Transport>(api: &Api<T>, guild: u64) -> Result<Vec<Ban>, Fail> {
    let mut all: Vec<Ban> = Vec::new();
    loop {
        let after = all.last().map_or(0, |b| b.user.id);
        let page: Vec<Ban> = api
            .get(&format!("/guilds/{guild}/bans?limit=1000&after={after}"))
            .await?;
        if page.is_empty() || page.last().map(|b| b.user.id) == Some(after) {
            return Ok(all);
        }
        all.extend(page);
    }
}

/// `import_plan`'s half that asks Discord. Reads, and writes nothing.
pub async fn read<T: Transport>(api: &Api<T>, guild_id: u64) -> Result<Read, String> {
    let mut notes = Vec::new();
    let bot: User = must(api.get("/users/@me").await, "the bot")?;
    let app: Application = must(api.get("/applications/@me").await, "the application")?;
    let g = format!("/guilds/{guild_id}");
    let guild: Guild = must(
        api.get(&format!("{g}?with_counts=true")).await,
        "the server",
    )?;
    let member: Member = must(
        api.get(&format!("{g}/members/{}", bot.id)).await,
        "the bot's place in the server",
    )?;
    let channels: Vec<Channel> = must(api.get(&format!("{g}/channels")).await, "its channels")?;
    let roles: Vec<Role> = must(api.get(&format!("{g}/roles")).await, "its roles")?;
    let role_counts = role_counts_of(api, &g).await?;
    let emojis = may(
        api.get(&format!("{g}/emojis")).await,
        "its emoji",
        &mut notes,
    )?;
    let stickers = may(
        api.get(&format!("{g}/stickers")).await,
        "its stickers",
        &mut notes,
    )?;
    let bans = may(all_bans(api, guild_id).await, "its bans", &mut notes)?;
    let active: ThreadList = may(
        api.get(&format!("{g}/threads/active")).await,
        "its active threads",
        &mut notes,
    )?;

    let mut read = Read {
        guild,
        bot,
        app,
        bot_roles: member.roles,
        channels,
        roles,
        role_counts,
        emojis,
        stickers,
        bans,
        threads: active.threads,
        notes,
        ..Read::default()
    };

    let mut parents: Vec<u64> = read
        .channels
        .iter()
        .filter(|c| c.has_threads() && read.bot_reads(c))
        .map(|c| c.id)
        .collect();
    parents.sort_unstable();
    for parent in parents {
        let archived = may(
            archived_threads(api, parent, None).await,
            "a channel's archived threads",
            &mut read.notes,
        )?;
        read.threads.extend(archived);
    }
    let mut seen = HashSet::new();
    read.threads.retain(|t| seen.insert(t.id));

    count_messages(api, guild_id, &mut read).await?;
    sample(api, &mut read).await?;
    Ok(read)
}

/// None: Discord would not say.
async fn role_counts_of<T: Transport>(
    api: &Api<T>,
    guild_path: &str,
) -> Result<Option<HashMap<u64, u64>>, String> {
    match api
        .get::<HashMap<String, u64>>(&format!("{guild_path}/roles/member-counts"))
        .await
    {
        Ok(raw) => Ok(Some(model::role_counts(raw))),
        Err(Fail::Stop(words)) => Err(words),
        Err(Fail::Skip { .. }) => Ok(None),
    }
}

/// The dry-run's read, with who each channel takes as Discord has it now: a run asks this before
/// it files anything, and stops if it cannot. Only that is asked again. What comes was chosen
/// from what the dry-run showed, so a channel made since waits for the next one, and one no
/// longer listed does not come: it is gone, or closed to a bot that is no Administrator.
pub async fn as_it_is_now<T: Transport>(api: &Api<T>, read: &Read) -> Result<Read, String> {
    let g = format!("/guilds/{}", read.guild.id);
    let channels: Vec<Channel> = must(api.get(&format!("{g}/channels")).await, "its channels")?;
    let mut rules: HashMap<u64, Vec<Overwrite>> = channels
        .into_iter()
        .map(|c| (c.id, c.permission_overwrites))
        .collect();
    let roles = must(api.get(&format!("{g}/roles")).await, "its roles")?;
    let role_counts = role_counts_of(api, &g).await?;
    let mut now = read.clone();
    now.roles = roles;
    now.role_counts = role_counts;
    let mut notes = Vec::new();
    now.channels.retain_mut(|ch| {
        let Some(list) = rules.remove(&ch.id) else {
            notes.push(Note::screen(
                "gone_since",
                Some(ch.id),
                format!(
                    "#{}: Discord no longer lists it, so it did not come.",
                    ch.name
                ),
            ));
            return false;
        };
        ch.permission_overwrites = list;
        true
    });
    now.notes.extend(notes);
    Ok(now)
}

/// The choices with the messages off of each channel Discord closed since the dry-run showed it
/// open: nobody ticked that history. A new dry-run shows it as it is, for a tick then. A channel
/// the relay has goes by its gate there instead, as `start_of` has it, unless only its history
/// was closed, which the relay cannot see.
pub fn without_closed_since(
    dry_run: &Read,
    now: &Read,
    here: &Here,
    choices: &Choices,
) -> (Choices, Vec<Note>) {
    let mut choices = choices.clone();
    let mut notes = Vec::new();
    if !effective(&choices.options).messages {
        return (choices, notes);
    }
    let then = Server::new(
        dry_run.guild.id,
        &dry_run.roles,
        dry_run.role_counts.as_ref(),
    );
    let server = Server::new(now.guild.id, &now.roles, now.role_counts.as_ref());
    let was: HashMap<u64, &Channel> = dry_run.channels.iter().map(|c| (c.id, c)).collect();
    for ch in &now.channels {
        let on = choices.messages_on.contains(&ch.id) && !choices.left_out.contains(&ch.id);
        let Some(old) = was.get(&ch.id).filter(|_| on) else {
            continue;
        };
        let (before, after) = (gates::gates_of(&then, old), gates::gates_of(&server, ch));
        let private = after.private && !before.private && !here.cursors.contains_key(&ch.id);
        if private || (after.history_off && !before.history_off) {
            choices.messages_on.remove(&ch.id);
            notes.push(Note::screen(
                "closed_since",
                Some(ch.id),
                format!(
                    "#{}: closed on Discord since the dry-run, so its messages did not come. A new \
                     dry-run shows it as it is.",
                    ch.name
                ),
            ));
        }
    }
    (choices, notes)
}

/// One `/messages/search` a channel, one after another, for as long as the budget lasts.
async fn count_messages<T: Transport>(
    api: &Api<T>,
    guild: u64,
    read: &mut Read,
) -> Result<(), String> {
    let started = Instant::now();
    let readable: Vec<(u64, bool, bool)> = read
        .channels
        .iter()
        .filter(|c| c.comes_over() && read.bot_reads(c))
        .map(|c| (c.id, c.is_forum(), c.last_message_id.is_some()))
        .collect();
    for (channel, forum, has_any) in readable {
        if forum {
            // Its posts are threads, and those come with a count of their own
            continue;
        }
        if !has_any {
            read.counts.insert(channel, 0);
            continue;
        }
        if started.elapsed() > SEARCH_BUDGET {
            continue;
        }
        let path = format!(
            "/guilds/{guild}/messages/search?channel_id={channel}&limit=1&include_nsfw=true"
        );
        for attempt in 0..2 {
            let found = match api.get::<Search>(&path).await {
                Ok(found) => found,
                Err(Fail::Stop(words)) => return Err(words),
                Err(Fail::Skip { .. }) => break,
            };
            if let Some(total) = found.total_results {
                read.counts.insert(channel, total);
                break;
            }
            // 202: not indexed yet. One wait, then it stays unknown
            if attempt == 0 {
                let secs = found.retry_after.clamp(0.0, 30.0);
                tokio::time::sleep(Duration::from_secs_f64(secs.max(0.5))).await;
            }
        }
    }
    Ok(())
}

/// One real page, for how long messages run and how fast Discord will go. Only those
/// two numbers are kept of it.
async fn sample<T: Transport>(api: &Api<T>, read: &mut Read) -> Result<(), String> {
    let busiest = read
        .channels
        .iter()
        .filter(|c| c.comes_over() && !c.is_forum() && c.last_message_id.is_some())
        .filter(|c| read.bot_reads(c))
        .max_by_key(|c| read.counts.get(&c.id).copied().unwrap_or(0))
        .map(|c| c.id);
    let Some(channel) = busiest else {
        return Ok(());
    };
    let resp = match api
        .get_raw(&format!("/channels/{channel}/messages?limit=100"))
        .await
    {
        Ok(resp) => resp,
        Err(Fail::Stop(words)) => return Err(words),
        Err(Fail::Skip { .. }) => return Ok(()),
    };
    let per_window: Option<f64> = resp
        .header("x-ratelimit-limit")
        .and_then(|v| v.parse().ok());
    let window: Option<f64> = resp
        .header("x-ratelimit-reset-after")
        .and_then(|v| v.parse().ok());
    if let (Some(limit), Some(window)) = (per_window, window) {
        if window > 0.0 {
            // Four walkers at a time
            read.pace = Some(40f64.min(4.0 * limit / window));
        }
    }
    if let Ok(page) = model::parse::<Vec<Message>>(&resp.body) {
        if !page.is_empty() {
            let total: usize = page.iter().map(|m| m.content.len()).sum();
            read.mean_body = Some((total / page.len()) as u64);
        }
    }
    Ok(())
}

/// What the relay and the machine can say about earlier runs.
#[derive(Debug, Clone)]
pub struct Here {
    pub facts: ImportFacts,
    /// `(name, is text)` of each channel on the relay now.
    pub channels: Vec<(String, bool)>,
    /// Emote names on the relay now.
    pub emote_names: Vec<String>,
    /// `ImportCursors`, all pages of it. A channel made by a run with 0: never walked.
    pub cursors: HashMap<u64, u64>,
    /// When the newest run not undone started, in Unix milliseconds. None: first run.
    pub last_started_ms: Option<i64>,
}

/// Ids as strings, for the page.
mod id_strings {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashSet;

    pub fn serialize<S: Serializer>(ids: &HashSet<u64>, s: S) -> Result<S::Ok, S::Error> {
        let mut ids: Vec<u64> = ids.iter().copied().collect();
        ids.sort_unstable();
        let ids: Vec<String> = ids.iter().map(u64::to_string).collect();
        ids.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<HashSet<u64>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|id| id.parse().map_err(D::Error::custom))
            .collect()
    }
}

/// What the wizard's toggles came to. It stays on this machine: only `options` reach the
/// relay, and nothing about a channel left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choices {
    pub options: ImportOptions,
    #[serde(with = "id_strings")]
    pub left_out: HashSet<u64>,
    /// Whose messages come. A list of yes: a channel on it by mistake is one the operator
    /// sees ticked, and one missing from it stays where it is, on Discord.
    #[serde(with = "id_strings")]
    pub messages_on: HashSet<u64>,
}

/// What needs what: messages need channels; threads, pins and reactions need messages;
/// permissions need channels. Else every frame would be refused for a channel that is not
/// there.
pub fn effective(options: &ImportOptions) -> ImportOptions {
    let mut o = options.clone();
    o.messages &= o.channels;
    o.permissions &= o.channels;
    o.threads &= o.messages;
    o.pins &= o.messages;
    o.reactions &= o.messages;
    o
}

/// One channel, as it would be made. In the order of the list.
#[derive(Debug, Clone)]
pub struct Planned {
    pub row: ImportChannel,
    pub kind: u8,
    /// Its messages come, and its threads' too.
    pub walk: bool,
    /// An earlier run made it. The relay leaves it alone, whatever the row says.
    pub in_ledger: bool,
    pub last_message_id: Option<u64>,
}

/// An emote or sticker that would come, in the order it would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEmote {
    pub id: u64,
    /// Discord's.
    pub raw: String,
    /// Its name here.
    pub name: String,
    pub sticker: bool,
}

/// What a set of choices makes of a server.
#[derive(Debug, Clone)]
pub struct Layout {
    pub options: ImportOptions,
    pub categories: Vec<ImportCategory>,
    pub channels: Vec<Planned>,
    /// By choice, or because no list would hold them.
    pub left_out: HashSet<u64>,
    /// Topics that lost some of their words to fit.
    pub clipped: u32,
    /// Named in the report, on the screen only.
    pub no_room: Vec<u64>,
    pub emotes: Vec<PlannedEmote>,
    pub notes: Vec<Note>,
}

impl Layout {
    /// What a `<#id>` may name: only channels that come and that anyone can see.
    pub fn open_names(&self) -> HashMap<u64, String> {
        self.channels
            .iter()
            .filter(|c| c.row.see == ImportGate::Open)
            .map(|c| (c.row.dc_id, c.row.name.clone()))
            .collect()
    }

    /// What rows may call things: only what comes, and of channels only what anyone can see.
    /// Members and who is left out are the run's to add, once it has read them.
    pub fn names(&self, read: &Read, here: &Here) -> Names {
        let mut names = Names {
            channels: self.open_names(),
            anonymise: self.options.anonymise,
            ..Names::default()
        };
        if self.options.roles {
            for role in read
                .roles
                .iter()
                .filter(|r| !r.managed && r.id != read.guild.id)
            {
                names.add_role(role.id, &role.name);
            }
        }
        if self.options.emotes {
            for emoji in &read.emojis {
                // One an earlier run made goes by its own name, near enough
                if here.cursors.contains_key(&emoji.id) {
                    if let Some(name) = names::emote_name(&emoji.name, emoji.id, |_| false) {
                        names.emotes.insert(emoji.id, name);
                    }
                }
            }
            for emote in &self.emotes {
                names.emotes.insert(emote.id, emote.name.clone());
            }
        }
        names
    }

    /// Public threads to tell the relay of. Only of a channel whose messages come: a thread's
    /// name is what the tick is for, as much as its messages are.
    pub fn threads_of(&self, read: &Read, names: &Names) -> Vec<ImportThread> {
        if !self.options.threads {
            return Vec::new();
        }
        let parents: HashSet<u64> = self
            .channels
            .iter()
            .filter(|c| c.walk)
            .map(|c| c.row.dc_id)
            .collect();
        read.threads
            .iter()
            .filter(|t| matches!(t.kind, ANNOUNCEMENT_THREAD | PUBLIC_THREAD))
            .filter(|t| t.parent_id.is_some_and(|p| parents.contains(&p)))
            .map(|t| {
                let parent = t.parent_id.unwrap_or(0);
                ImportThread {
                    id: t.id,
                    parent,
                    owner: t.owner_id.and_then(|o| names.thread_owner(o, parent, t.id)),
                    name: names::clean_chars(&t.name, THREAD_NAME_CHARS),
                    replies: t.message_count,
                }
            })
            .collect()
    }

    /// The report so far: the run adds what it counts and meets.
    pub fn report(&self) -> Report {
        Report {
            notes: self.notes.clone(),
            left_out: self.left_out.clone(),
            ..Report::default()
        }
    }
}

/// How a channel starts out in the wizard.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Start {
    /// Why it is left out, if it is.
    left_out: Option<String>,
    /// Why its messages are off, if they are.
    messages_off: Option<String>,
}

/// Whether a channel missing from the ledger was left out by anyone: only if the last run was
/// making channels and got to some of this server's. Otherwise this is as good as a first run.
fn runs_made_channels(read: &Read, here: &Here) -> bool {
    here.facts.last_options.as_ref().is_some_and(|o| o.channels)
        && read
            .channels
            .iter()
            .any(|c| here.cursors.contains_key(&c.id))
}

/// A delta remembers with no new data on either side: what is in the ledger, how far it was
/// walked, and when the channel was made, against when the last run started.
fn start_of(
    ch: &Channel,
    private: &ChannelGates,
    reads: bool,
    made_channels: bool,
    here: &Here,
) -> Start {
    let high = here.cursors.get(&ch.id).copied();
    let left_out = match (high, here.last_started_ms) {
        (None, Some(started)) if made_channels && discord::snowflake_ms(ch.id as i64) < started => {
            Some(if here.facts.unfinished.is_some() {
                "Left out last time, or the last run did not reach it.".to_string()
            } else {
                "Left out last time.".to_string()
            })
        }
        _ => None,
    };
    let messages_off = if !reads {
        Some("The bot cannot read its history.".to_string())
    } else if high == Some(0) {
        Some(if here.facts.unfinished.is_some() {
            "Off last time, or the last run did not reach it.".to_string()
        } else {
            "Off last time.".to_string()
        })
    } else if private.private && high.is_none() {
        Some(private.private_why.clone())
    } else if private.history_off {
        // A cursor does not settle this one: closing the history alone leaves `see` open, so
        // the relay's refusal of a channel closed since never sees it.
        Some("Some could see it without reading its history.".to_string())
    } else {
        None
    };
    Start {
        left_out,
        messages_off,
    }
}

fn gates_with_toggles(server: &Server, ch: &Channel, o: &ImportOptions) -> ChannelGates {
    let mut g = gates::gates_of(server, ch);
    gates::with_toggles(&mut g, o.permissions, o.roles, ch);
    g
}

/// In the order of the list here: categories by Discord's place, and in each, text before
/// voice.
fn in_order(read: &Read) -> Vec<&Channel> {
    let mut categories: Vec<&Channel> = read
        .channels
        .iter()
        .filter(|c| c.kind == CATEGORY)
        .collect();
    categories.sort_by_key(|c| (c.position, c.id));
    let place: HashMap<u64, usize> = categories
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id, i + 1))
        .collect();
    let mut channels: Vec<&Channel> = read.channels.iter().filter(|c| c.comes_over()).collect();
    channels.sort_by_key(|c| {
        (
            c.parent_id
                .and_then(|p| place.get(&p).copied())
                .unwrap_or(0),
            c.is_voice(),
            c.position,
            c.id,
        )
    });
    channels
}

/// What these choices would make: the same for the preview and for the run.
pub fn layout(read: &Read, here: &Here, choices: &Choices) -> Layout {
    let options = effective(&choices.options);
    let mut notes = read.notes.clone();
    let server = Server::new(read.guild.id, &read.roles, read.role_counts.as_ref());
    let ordered = in_order(read);
    let mut left_out = choices.left_out.clone();

    for ch in &read.channels {
        if !ch.comes_over() && ch.kind != CATEGORY {
            notes.push(Note::screen(
                "skipped_kind",
                Some(ch.id),
                format!("#{}: this kind of channel does not come.", ch.name),
            ));
        }
    }

    let mut taken = Taken::new(here.channels.iter().map(|(n, t)| (n.as_str(), *t)));
    for ch in &ordered {
        if here.cursors.contains_key(&ch.id) {
            taken.hold(
                &Taken::base_name(&ch.name, ch.id, !ch.is_voice()),
                !ch.is_voice(),
            );
        }
    }
    let mut rows: Vec<(&Channel, String, String, ChannelGates)> = Vec::new();
    if options.channels {
        for ch in &ordered {
            if left_out.contains(&ch.id) {
                continue;
            }
            let text = !ch.is_voice();
            let name = if here.cursors.contains_key(&ch.id) {
                Taken::base_name(&ch.name, ch.id, text)
            } else {
                taken.channel_name(&ch.name, ch.id, text)
            };
            let topic = names::clean_topic(&ch.topic);
            rows.push((ch, name, topic, gates_with_toggles(&server, ch, &options)));
        }
    }

    // A channel that was here before is on the relay's list already
    let fresh: Vec<FitRow> = rows
        .iter()
        .filter(|(ch, ..)| !here.cursors.contains_key(&ch.id))
        .map(|(ch, name, topic, _)| FitRow {
            id: ch.id,
            name: name.clone(),
            topic: topic.clone(),
            text: !ch.is_voice(),
        })
        .collect();
    let fitted = fit::fit(
        &fresh,
        here.facts.channel_list_bytes as usize,
        here.facts.channel_list_limit as usize,
    );
    for gone in &fitted.left_out {
        left_out.insert(*gone);
        if let Some((_, name, ..)) = rows.iter().find(|(ch, ..)| ch.id == *gone) {
            notes.push(Note::screen(
                "no_room",
                Some(*gone),
                format!("#{name}: one channel list cannot hold it, so it stays out."),
            ));
        }
    }

    let mut channels = Vec::with_capacity(rows.len());
    for (ch, name, topic, gate) in rows {
        if fitted.left_out.contains(&ch.id) {
            continue;
        }
        let description = match fitted.topics.get(&ch.id) {
            Some(fit) => fit.clone(),
            None => clip_bytes(&topic, TOPIC_BYTES).trim_end().to_string(),
        };
        if ch.is_forum() {
            notes.push(Note::kept(
                "forum",
                Some(ch.id),
                format!("#{name}: a text channel here, its posts threads in its archive. Tags do not come."),
            ));
        }
        if ch.kind == STAGE {
            notes.push(Note::kept(
                "stage",
                Some(ch.id),
                format!("#{name}: a voice channel here, where a stage's moderators may speak."),
            ));
        }
        // What these say of its gate holds only of one made now: the relay leaves its own as it is
        if !here.cursors.contains_key(&ch.id) {
            // They name roles, which the relay is not told of with roles off
            notes.extend(gate.notes.iter().map(|n| Note {
                keep: n.keep && options.roles,
                ..n.clone()
            }));
        }
        channels.push(Planned {
            walk: options.messages && choices.messages_on.contains(&ch.id),
            in_ledger: here.cursors.contains_key(&ch.id),
            kind: ch.kind,
            last_message_id: ch.last_message_id,
            row: ImportChannel {
                dc_id: ch.id,
                name,
                description,
                text: !ch.is_voice(),
                category: ch.parent_id,
                max_users: ch.user_limit,
                slow_mode_secs: ch.rate_limit_per_user.min(voipc_max_slow()),
                nsfw: ch.nsfw,
                announce: ch.kind == ANNOUNCEMENT,
                screen_share: gate.screen_share,
                see: gate.see,
                speak: gate.speak,
            },
        });
    }

    // A category only of channels left out would say what it was hiding, as a name
    let mut categories: Vec<&Channel> = if options.channels {
        read.channels
            .iter()
            .filter(|c| c.kind == CATEGORY)
            .collect()
    } else {
        Vec::new()
    };
    categories.sort_by_key(|c| (c.position, c.id));
    let categories = categories
        .into_iter()
        .filter(|cat| {
            let has_some = read.channels.iter().any(|c| c.parent_id == Some(cat.id));
            let has_kept = channels.iter().any(|c| c.row.category == Some(cat.id));
            !has_some || has_kept
        })
        .map(|c| ImportCategory {
            dc_id: c.id,
            name: names::category_name(&c.name, c.id),
        })
        .collect();

    role_notes(read, &options, &mut notes);
    let emotes = plan_emotes(read, here, &options, &mut notes);
    Layout {
        options,
        categories,
        channels,
        left_out,
        clipped: fitted.clipped,
        no_room: fitted.left_out,
        emotes,
        notes,
    }
}

/// `MAX_SLOW_MODE_SECS` on the relay, and Discord's own maximum.
const fn voipc_max_slow() -> u32 {
    6 * 60 * 60
}

fn role_notes(read: &Read, options: &ImportOptions, notes: &mut Vec<Note>) {
    for role in &read.roles {
        if role.id == read.guild.id {
            let scopes = discord::scopes_of(role.permissions);
            if !scopes.is_empty() {
                notes.push(Note::kept(
                    "everyone_power",
                    None,
                    "@everyone could do more on Discord than a member can here by default: \
                     that comes to nothing."
                        .to_string(),
                ));
            }
        } else if role.managed {
            notes.push(Note::screen(
                "managed_role",
                None,
                format!("@{}: a bot's own role, which does not come.", role.name),
            ));
        } else {
            let lost = discord::lossy(role.permissions);
            if !lost.is_empty() {
                let text = format!("@{}: nothing here for {}.", role.name, lost.join(", "));
                notes.push(if options.roles {
                    Note::kept("lossy", None, text)
                } else {
                    Note::screen("lossy", None, text)
                });
            }
        }
    }
    notes.push(Note::kept(
        "owner",
        None,
        "The Discord server's owner had power by owning it, not by a role: nothing waits for \
         them."
            .to_string(),
    ));
    let private = read
        .threads
        .iter()
        .filter(|t| t.kind == PRIVATE_THREAD)
        .count();
    if private > 0 {
        notes.push(Note::kept(
            "private_threads",
            None,
            format!("Private threads do not come, {private} of them: no gate here can say who was in one."),
        ));
    }
}

fn plan_emotes(
    read: &Read,
    here: &Here,
    options: &ImportOptions,
    notes: &mut Vec<Note>,
) -> Vec<PlannedEmote> {
    if !options.emotes {
        return Vec::new();
    }
    let room = MAX_EMOTES.saturating_sub(here.facts.emotes as usize);
    let mut names_here: HashSet<String> = here.emote_names.iter().cloned().collect();
    let mut out = Vec::new();
    let mut add = |id: u64, raw: &str, sticker: bool, notes: &mut Vec<Note>| -> bool {
        // One an earlier run made has a cursor, and one removed by hand stays removed
        if here.cursors.contains_key(&id) {
            return false;
        }
        if out.len() >= room {
            notes.push(Note::screen(
                "emote_no_room",
                None,
                format!(":{raw}: did not fit: a server has {MAX_EMOTES} at most."),
            ));
            return false;
        }
        let Some(name) = names::emote_name(raw, id, |n| names_here.contains(n)) else {
            return false;
        };
        names_here.insert(name.clone());
        out.push(PlannedEmote {
            id,
            raw: raw.to_string(),
            name,
            sticker,
        });
        true
    };
    for e in &read.emojis {
        if !add(e.id, &e.name, false, notes) {
            continue;
        }
        if !e.roles.is_empty() {
            notes.push(Note::kept(
                "emoji_roles",
                None,
                format!(
                    ":{}: only some roles had it. Here every member has it.",
                    e.name
                ),
            ));
        }
        if e.available == Some(false) {
            notes.push(Note::kept(
                "emoji_unavailable",
                None,
                format!(":{}: Discord had it switched off. Here it works.", e.name),
            ));
        }
    }
    for s in &read.stickers {
        if s.format_type == LOTTIE {
            notes.push(Note::screen(
                "lottie",
                None,
                format!("{}: a Lottie sticker cannot come.", s.name),
            ));
            continue;
        }
        add(s.id, &s.name, true, notes);
    }
    out
}

/// What the toggles start at: as last time, and every one on the first time. The tick for
/// what copying people's messages means is always given again.
pub fn default_options(here: &Here) -> ImportOptions {
    let mut options = here.facts.last_options.clone().unwrap_or(ImportOptions {
        channels: true,
        roles: true,
        permissions: true,
        members: true,
        bans: true,
        emotes: true,
        messages: true,
        threads: true,
        pins: true,
        reactions: true,
        anonymise: true,
        acknowledged: false,
    });
    options.acknowledged = false;
    options
}

/// What the wizard starts with: on a first run all but the private channels' history, on a
/// later one what the last one chose, and on for anything new.
pub fn default_choices(read: &Read, here: &Here) -> Choices {
    let server = Server::new(read.guild.id, &read.roles, read.role_counts.as_ref());
    let made_channels = runs_made_channels(read, here);
    let mut left_out = HashSet::new();
    let mut messages_on = HashSet::new();
    for ch in in_order(read) {
        let raw = gates::gates_of(&server, ch);
        let start = start_of(ch, &raw, read.bot_reads(ch), made_channels, here);
        if start.left_out.is_some() {
            left_out.insert(ch.id);
        }
        if start.messages_off.is_none() {
            messages_on.insert(ch.id);
        }
    }
    Choices {
        options: default_options(here),
        left_out,
        messages_on,
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GateView {
    pub open: bool,
    /// Discord's role ids. Empty and not open: closed to all but admins.
    pub roles: Vec<String>,
}

impl From<&ImportGate> for GateView {
    fn from(gate: &ImportGate) -> Self {
        match gate {
            ImportGate::Open => GateView {
                open: true,
                roles: Vec::new(),
            },
            ImportGate::Closed => GateView::default(),
            ImportGate::Roles(roles) => GateView {
                open: false,
                roles: roles.iter().copied().map(id).collect(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanGuild {
    pub id: String,
    pub name: String,
    pub members: u64,
    pub online: u64,
    pub mfa: bool,
    /// Where a move post goes first.
    pub post_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanBot {
    pub admin: bool,
    pub member_intent: bool,
    pub content_intent: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanChannel {
    pub id: String,
    pub name: String,
    pub final_name: String,
    #[serde(rename = "type")]
    pub kind: u8,
    pub category: Option<String>,
    pub private: bool,
    pub private_why: String,
    pub bot_can_read: bool,
    /// None: not known.
    pub messages: Option<u64>,
    /// An earlier run made it, so the relay leaves its gate as it stands there: `see` and
    /// `speak` say what would be made, and only that.
    pub in_ledger: bool,
    pub see: GateView,
    pub speak: GateView,
    pub lossy: Vec<String>,
    /// What its two toggles start at, and why.
    pub left_out: bool,
    pub left_out_why: String,
    pub messages_on: bool,
    pub messages_why: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanCategory {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanRole {
    pub id: String,
    pub name: String,
    /// None: not known.
    pub members: Option<u64>,
    pub power: Vec<String>,
    pub unmapped: Vec<String>,
    /// A bot's own: it does not come.
    pub managed: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PlanThreads {
    pub active: u32,
    pub archived: u32,
    pub private_skipped: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Estimate {
    pub messages: u64,
    /// Some channel's count is not known, so all of this is at least.
    pub at_least: bool,
    pub requests: u64,
    pub secs_low: u64,
    pub secs_high: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warn,
    Red,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub level: Level,
    pub code: &'static str,
    pub text: String,
}

/// A toggle that cannot be on, or `run`: nothing can start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Block {
    pub toggle: &'static str,
    pub text: String,
}

/// The dry-run, for the page.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub guild: PlanGuild,
    pub bot: PlanBot,
    /// What the toggles start at.
    pub options: ImportOptions,
    /// An earlier run stands, so this is a delta and takes new messages only.
    pub delta: bool,
    pub channels: Vec<PlanChannel>,
    pub categories: Vec<PlanCategory>,
    pub roles: Vec<PlanRole>,
    pub emojis: u32,
    pub stickers: u32,
    pub emote_room: u32,
    pub bans: u32,
    pub threads: PlanThreads,
    pub estimate: Estimate,
    pub warnings: Vec<Warning>,
    pub blocks: Vec<Block>,
    pub report_preview: Vec<String>,
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} bytes")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn estimate(read: &Read, here: &Here, layout: &Layout) -> Estimate {
    let mut messages = 0u64;
    let mut at_least = false;
    for c in layout
        .channels
        .iter()
        .filter(|c| c.walk && !model_is_forum(c.kind))
    {
        match read.counts.get(&c.row.dc_id) {
            Some(n) => messages = messages.saturating_add(*n),
            None => at_least = true,
        }
    }
    let threads = layout.threads_of(read, &Names::default());
    for t in &threads {
        messages = messages.saturating_add(u64::from(t.replies));
    }
    let requests = messages / 100 + threads.len() as u64 + read.channels.len() as u64;
    let pace = read.pace.unwrap_or(40.0).clamp(0.1, 40.0);
    let secs = (requests as f64 / pace).ceil() as u64;
    let per_row = if here.facts.backup_here {
        ROW_SQLITE
    } else {
        ROW_POSTGRES
    };
    let mean = read.mean_body.unwrap_or(MEAN_BODY);
    Estimate {
        messages: safe(messages),
        at_least,
        requests: safe(requests),
        secs_low: safe(secs),
        secs_high: safe(secs.saturating_mul(2)),
        bytes: safe(messages.saturating_mul(per_row + mean)),
    }
}

fn model_is_forum(kind: u8) -> bool {
    matches!(kind, model::FORUM | model::MEDIA)
}

fn warnings(read: &Read, here: &Here, layout: &Layout, est: &Estimate) -> Vec<Warning> {
    let f = &here.facts;
    let online = read.guild.approximate_presence_count;
    let members = read.guild.approximate_member_count;
    let mut out = Vec::new();
    let mut say = |level: Level, code: &'static str, text: String| {
        out.push(Warning { level, code, text });
    };
    if online >= 789 {
        say(
            Level::Warn,
            "member_list",
            "One member list holds 789 accounts with three badges (1598 with none). Past that in \
             one channel the list never arrives and people start in General."
                .to_string(),
        );
    }
    if online >= 500 {
        say(
            Level::Warn,
            "join_burst",
            "Joining takes the client 3N control messages at 50 a second: 30 s at 500, 120 s at \
             2000."
                .to_string(),
        );
    }
    if online > 2000 {
        say(
            Level::Warn,
            "unmeasured",
            "Measured up to 2000 connections on one relay. Past that is unmeasured. Each costs \
             about 0.3 MiB."
                .to_string(),
        );
    }
    if f.max_users > 0 && online > u64::from(f.max_users) {
        say(
            Level::Red,
            "max_users",
            format!(
                "max_users is {}: the rest are turned away. Raise it in server.toml.",
                f.max_users
            ),
        );
    }
    if members > 256 {
        say(
            Level::Info,
            "history_256",
            "Kept history is for 256 members a channel. Imported history is not bound by it."
                .to_string(),
        );
    }
    if members > 650 {
        say(
            Level::Info,
            "pins_650",
            "A person's pins fit about 650 accounts.".to_string(),
        );
    }
    if layout.clipped > 0 {
        say(
            Level::Warn,
            "topics_clipped",
            format!(
                "One channel list holds all of this only with {} topics clipped.",
                layout.clipped
            ),
        );
    }
    if !layout.no_room.is_empty() {
        say(
            Level::Warn,
            "channels_no_room",
            format!(
                "{} channels do not fit one channel list here, and stay out. The report names them.",
                layout.no_room.len()
            ),
        );
    }
    let room_for_categories = f.max_categories.saturating_sub(f.categories) as usize;
    if layout.categories.len() > room_for_categories {
        say(
            Level::Warn,
            "categories",
            format!(
                "A server has {} categories at most. The rest stay outside any category.",
                f.max_categories
            ),
        );
    }
    let room = MAX_EMOTES.saturating_sub(f.emotes as usize);
    if read.emojis.len() + read.stickers.len() > room {
        say(
            Level::Warn,
            "emotes",
            format!("Room for {room} emotes and stickers. The rest are named, not fetched."),
        );
    }
    if members >= 10_000 {
        say(
            Level::Warn,
            "intent_review",
            "Over 10,000 users Discord tells you in the Developer Portal and you have 90 days to \
             apply; intents keep working during review. Toggle both on before inviting the bot."
                .to_string(),
        );
    }
    if !is_admin(read) {
        say(
            Level::Red,
            "not_admin",
            "The bot is not an Administrator. Private channels are invisible from 2026-11-16 and \
             nothing tells you which. Run stays possible for public ones."
                .to_string(),
        );
    }
    match f.registration {
        Registration::Open => say(
            Level::Info,
            "registration",
            "Moved members sign in with Discord whatever this is; newcomers can sign up freely."
                .to_string(),
        ),
        Registration::Invite => say(
            Level::Info,
            "registration",
            "Moved members sign in with Discord whatever this is; newcomers need an invite."
                .to_string(),
        ),
        Registration::Closed => say(
            Level::Info,
            "registration",
            "Moved members sign in with Discord whatever this is; sign-up is closed to newcomers."
                .to_string(),
        ),
    }
    if f.accounts > 0 {
        say(
            Level::Info,
            "accounts_here",
            format!(
                "{} accounts exist here: anyone who has one should link Discord first.",
                f.accounts
            ),
        );
    }
    let group_bytes: u64 = read
        .roles
        .iter()
        .filter(|r| r.id != read.guild.id && !r.managed)
        .map(|r| {
            GROUP_BYTES
                + if discord::scopes_of(r.permissions).is_empty() {
                    0
                } else {
                    TWIN_BYTES
                }
        })
        .sum();
    if group_bytes > GROUPS_LIMIT {
        say(
            Level::Warn,
            "groups",
            "These roles are past what one group list holds. Top roles are kept, the rest named. \
             This is not a limit on members."
                .to_string(),
        );
    }
    if !f.backup_here {
        say(
            Level::Info,
            "postgres",
            "Run pg_dump now; there is no copy from here.".to_string(),
        );
    }
    if f.takes_guests {
        say(
            Level::Info,
            "guests",
            "Public channels will be open to guests. The archive is not.".to_string(),
        );
    }
    let lossy = read
        .roles
        .iter()
        .filter(|r| {
            r.id != read.guild.id && !r.managed && !discord::lossy(r.permissions).is_empty()
        })
        .count();
    if lossy > 0 {
        say(
            Level::Info,
            "lossy",
            format!("{lossy} roles could do things with no match here: the list is below."),
        );
    }
    if f.unfinished.is_some() {
        say(
            Level::Warn,
            "unfinished",
            "The last run did not finish. A channel shown left out or with its messages off \
             was either set that way, or the run never reached it: set the ones you want."
                .to_string(),
        );
    }
    if !f.cloud && layout.options.messages {
        say(
            Level::Warn,
            "cloud_off",
            "This server keeps no messages: set cloud = true first, or turn messages off."
                .to_string(),
        );
    }
    say(
        Level::Info,
        "disk",
        format!(
            "{}Needs about {} on the relay's disk: check it. A copy of the database for a backup \
             needs as much again.",
            match f.db_bytes {
                Some(now) => format!("The database is {} now. ", human_bytes(now)),
                None => String::new(),
            },
            human_bytes(est.bytes)
        ),
    );
    out
}

fn is_admin(read: &Read) -> bool {
    read.roles
        .iter()
        .filter(|r| read.bot_roles.contains(&r.id) || r.id == read.guild.id)
        .any(|r| r.permissions & discord::ADMINISTRATOR != 0)
}

fn blocks(read: &Read, here: &Here) -> Vec<Block> {
    let mut out = Vec::new();
    if !read.app.content_intent() {
        out.push(Block {
            toggle: "messages",
            text: "Message Content is off for this bot: every message would come back blank. Turn \
                   it on in the Developer Portal."
                .to_string(),
        });
    }
    if !read.app.member_intent() {
        out.push(Block {
            toggle: "members",
            text: "Server Members is off for this bot: no member list can be read. Turn it on in \
                   the Developer Portal."
                .to_string(),
        });
        out.push(Block {
            toggle: "anonymise",
            text: "Telling ex-members from members takes the member list. Turn Server Members on, \
                   or turn this off."
                .to_string(),
        });
    }
    if !here.facts.discord_sign_in {
        out.push(Block {
            toggle: "run",
            text:
                "Nobody could claim anything: this server has no Discord sign-in. Set public_url \
                   and the Discord app."
                    .to_string(),
        });
    }
    out
}

/// `import_plan`'s other half, with nothing asked of anyone.
pub fn build(read: &Read, here: &Here) -> Plan {
    let choices = default_choices(read, here);
    // The preview shows the list with nothing left out, so that one can be put back
    let shown = layout(
        read,
        here,
        &Choices {
            left_out: HashSet::new(),
            ..choices.clone()
        },
    );
    let made = layout(read, here, &choices);
    let server = Server::new(read.guild.id, &read.roles, read.role_counts.as_ref());
    let made_channels = runs_made_channels(read, here);
    let channels = in_order(read)
        .into_iter()
        .map(|ch| {
            let planned = shown.channels.iter().find(|p| p.row.dc_id == ch.id);
            let raw = gates::gates_of(&server, ch);
            let reads = read.bot_reads(ch);
            let start = start_of(ch, &raw, reads, made_channels, here);
            let messages = if ch.is_forum() {
                Some(safe(
                    read.threads
                        .iter()
                        .filter(|t| t.parent_id == Some(ch.id) && t.kind != PRIVATE_THREAD)
                        .map(|t| u64::from(t.message_count))
                        .sum(),
                ))
            } else {
                read.counts.get(&ch.id).copied().map(safe)
            };
            PlanChannel {
                id: id(ch.id),
                name: ch.name.clone(),
                final_name: planned.map_or_else(|| ch.name.clone(), |p| p.row.name.clone()),
                kind: ch.kind,
                category: ch.parent_id.map(id),
                private: raw.private,
                private_why: raw.private_why.clone(),
                bot_can_read: reads,
                messages,
                in_ledger: here.cursors.contains_key(&ch.id),
                see: planned.map_or_else(|| (&raw.see).into(), |p| (&p.row.see).into()),
                speak: planned.map_or_else(|| (&raw.speak).into(), |p| (&p.row.speak).into()),
                lossy: raw.notes.iter().map(|n| n.text.clone()).collect(),
                left_out: start.left_out.is_some(),
                left_out_why: start.left_out.unwrap_or_default(),
                messages_on: start.messages_off.is_none(),
                messages_why: start.messages_off.unwrap_or_default(),
            }
        })
        .collect();
    let mut categories: Vec<&Channel> = read
        .channels
        .iter()
        .filter(|c| c.kind == CATEGORY)
        .collect();
    categories.sort_by_key(|c| (c.position, c.id));
    let categories = categories
        .into_iter()
        .map(|c| PlanCategory {
            id: id(c.id),
            name: names::category_name(&c.name, c.id),
        })
        .collect();
    let mut roles: Vec<&Role> = read
        .roles
        .iter()
        .filter(|r| r.id != read.guild.id)
        .collect();
    roles.sort_by_key(|r| (std::cmp::Reverse(r.position), r.id));
    let roles = roles
        .into_iter()
        .map(|r| PlanRole {
            id: id(r.id),
            name: r.name.clone(),
            members: read
                .role_counts
                .as_ref()
                .map(|c| safe(c.get(&r.id).copied().unwrap_or(0))),
            power: discord::scopes_of(r.permissions)
                .iter()
                .map(|s| s.to_string())
                .collect(),
            unmapped: discord::lossy(r.permissions)
                .iter()
                .map(|s| s.to_string())
                .collect(),
            managed: r.managed,
        })
        .collect();
    let is_public = |t: &&Channel| t.kind != PRIVATE_THREAD;
    let is_archived = |t: &&Channel| t.thread_metadata.as_ref().is_some_and(|m| m.archived);
    let threads = PlanThreads {
        active: read
            .threads
            .iter()
            .filter(is_public)
            .filter(|t| !is_archived(t))
            .count() as u32,
        archived: read
            .threads
            .iter()
            .filter(is_public)
            .filter(is_archived)
            .count() as u32,
        private_skipped: read
            .threads
            .iter()
            .filter(|t| t.kind == PRIVATE_THREAD)
            .count() as u32,
    };
    let est = estimate(read, here, &made);
    let warnings = warnings(read, here, &made, &est);
    let blocks = blocks(read, here);
    Plan {
        guild: PlanGuild {
            id: id(read.guild.id),
            name: read.guild.name.clone(),
            members: safe(read.guild.approximate_member_count),
            online: safe(read.guild.approximate_presence_count),
            mfa: read.guild.mfa_level != 0,
            post_channel: read
                .guild
                .rules_channel_id
                .or(read.guild.system_channel_id)
                .map(id),
        },
        bot: PlanBot {
            admin: is_admin(read),
            member_intent: read.app.member_intent(),
            content_intent: read.app.content_intent(),
        },
        options: choices.options.clone(),
        delta: here.last_started_ms.is_some(),
        channels,
        categories,
        roles,
        emojis: read.emojis.len() as u32,
        stickers: read.stickers.len() as u32,
        emote_room: MAX_EMOTES.saturating_sub(here.facts.emotes as usize) as u32,
        bans: read.bans.len() as u32,
        threads,
        estimate: est,
        warnings,
        blocks,
        report_preview: made.report().end_screen(),
    }
}

/// What a run has to say at its end. Two forms: all of it for the screen, in RAM, and what
/// may be stored on the relay, which names no person and nothing left out.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub counts: BTreeMap<String, u64>,
    pub notes: Vec<Note>,
    pub left_out: HashSet<u64>,
}

impl Report {
    /// All of it, for the end screen. No save button: this holds what must not be kept.
    pub fn end_screen(&self) -> Vec<String> {
        self.notes.iter().map(|n| n.text.clone()).collect()
    }

    fn may_keep(&self, note: &Note) -> bool {
        note.keep && !note.channel.is_some_and(|c| self.left_out.contains(&c))
    }

    /// For `ImportEnd.report`: JSON, at most `REPORT_BYTES`, counts and notes about what was
    /// imported and nothing else.
    pub fn kept(&self) -> String {
        let room = REPORT_BYTES - 4096;
        let mut notes = Vec::new();
        let mut bytes = 0;
        let mut more: BTreeMap<&str, u32> = BTreeMap::new();
        for note in self.notes.iter().filter(|n| self.may_keep(n)) {
            let text = clip_chars(&note.text, NOTE_CHARS);
            // As it will be in the JSON, where a quote or a control character grows
            let cost = serde_json::to_string(text).map_or(usize::MAX, |t| t.len() + 1);
            if notes.len() >= REPORT_NOTES || cost > room - bytes {
                *more.entry(note.kind).or_default() += 1;
                continue;
            }
            bytes += cost;
            notes.push(text.to_string());
        }
        for (kind, n) in more {
            let mut line = String::new();
            let _ = write!(line, "and {n} more of this kind: {kind}");
            notes.push(line);
        }
        serde_json::json!({ "counts": self.counts, "notes": notes }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::RateGate;
    use crate::fixture;
    use crate::mock::{Mock, BIG_GUILD};
    use serde_json::Value;
    use std::sync::Arc;

    const G: u64 = fixture::GUILD;

    async fn read_fixture() -> Read {
        let api = Api::with_gate(Arc::new(fixture::mock()), RateGate::new(7));
        read(&api, G).await.unwrap()
    }

    async fn read_v2() -> Read {
        let mock = Arc::new(fixture::mock());
        mock.use_v2();
        let api = Api::with_gate(mock, RateGate::new(7));
        read(&api, G).await.unwrap()
    }

    fn by_name<'a>(plan: &'a Plan, name: &str) -> &'a PlanChannel {
        plan.channels
            .iter()
            .find(|c| c.final_name == name)
            .unwrap_or_else(|| panic!("no channel called {name}"))
    }

    fn planned(layout: &Layout, id: u64) -> &Planned {
        layout
            .channels
            .iter()
            .find(|c| c.row.dc_id == id)
            .unwrap_or_else(|| panic!("no channel {id}"))
    }

    #[tokio::test(start_paused = true)]
    async fn the_fixture_shows_each_of_its_traps() {
        let read = read_fixture().await;
        let here = fixture::here();
        let plan = build(&read, &here);
        assert_eq!(plan.guild.id, G.to_string());
        assert!(plan.bot.admin && plan.bot.member_intent && plan.bot.content_intent);
        assert!(plan.blocks.is_empty(), "{:?}", plan.blocks);
        assert!(!plan.delta);

        // Text `general` keeps its name; voice `General` cannot have it. A clash is numbered
        assert_eq!(by_name(&plan, "general").id, fixture::GENERAL.to_string());
        assert_eq!(by_name(&plan, "General voice").name, "General");
        assert_eq!(by_name(&plan, "lounge-2").name, "lounge");
        // Text in a category before its voice, categories in Discord's order
        let order: Vec<&str> = plan
            .channels
            .iter()
            .map(|c| c.final_name.as_str())
            .collect();
        let at = |name: &str| order.iter().position(|n| *n == name).unwrap();
        assert!(at("general") < at("lounge"));
        assert!(at("lounge") < at("General voice"));
        assert!(at("General voice") < at("help"));

        // A private channel nobody passes: closed, never open, and needing the tick
        let vault = by_name(&plan, "vault");
        assert!(vault.private);
        assert!(!vault.see.open && vault.see.roles.is_empty());
        assert!(!vault.messages_on);
        assert!(!vault.left_out);
        // A gated one lists who passes, and neither the managed role nor the memberless one
        let staff = by_name(&plan, "staff");
        assert!(staff.private && !staff.messages_on);
        assert!(!staff.see.open);
        assert_eq!(staff.see.roles.len(), 3, "{:?}", staff.see.roles);
        assert!(staff
            .lossy
            .iter()
            .any(|l| l.contains(&fixture::EVA.to_string())));
        // 20 allowed roles: the 16 largest
        let teams = by_name(&plan, "teams");
        assert_eq!(teams.see.roles.len(), 16);
        // A role with a VIEW deny turns a public channel private, and it starts off
        let dark = by_name(&plan, "after-dark");
        assert!(dark.private && !dark.messages_on);
        assert!(dark.private_why.contains("@Muted"));
        // A SEND deny does not
        let general = by_name(&plan, "general");
        assert!(general.see.open && general.speak.open);
        assert!(general.messages_on && !general.private);
        assert!(general.lossy.iter().any(|l| l.contains("@Muted")));
        // Read-only: only who could write
        let news = by_name(&plan, "news");
        assert!(news.see.open);
        assert_eq!(news.speak.roles, [fixture::MODERATORS.to_string()]);
        // View without history
        let logs = by_name(&plan, "old-logs");
        assert!(!logs.messages_on);
        // Forums, media and stages
        assert_eq!(by_name(&plan, "help").kind, model::FORUM);
        assert!(by_name(&plan, "help").messages.unwrap() > 0);
        assert!(by_name(&plan, "help").messages_on);
        // A directory is noted and not listed
        assert!(!order.contains(&"directory"));
        assert!(plan.report_preview.iter().any(|n| n.contains("directory")));
        // The role named Admin is a role like any other, its power spelled out
        let admin = plan.roles.iter().find(|r| r.name == "Admin").unwrap();
        assert!(admin.power.contains(&"voipc:kick".to_string()));
        assert!(!admin.power.iter().any(|p| p.contains('*')));
        let managed = plan.roles.iter().find(|r| r.managed).unwrap();
        assert_eq!(managed.members, Some(1));
        // Counts
        assert_eq!(plan.bans, 3);
        assert_eq!(plan.threads.private_skipped, 1);
        assert!(
            plan.threads.active >= 2 && plan.threads.archived >= 2,
            "{:?}",
            plan.threads
        );
        assert!(plan.estimate.messages > 0);
        assert!(plan.estimate.bytes > 0 && plan.estimate.secs_low > 0);
        assert!(plan.estimate.secs_high >= plan.estimate.secs_low);
    }

    #[tokio::test(start_paused = true)]
    async fn a_channel_row_says_what_the_docs_say_it_should() {
        let read = read_fixture().await;
        let here = fixture::here();
        let made = layout(&read, &here, &default_choices(&read, &here));
        let news = planned(&made, fixture::NEWS);
        assert!(news.row.announce && news.row.text);
        let dark = planned(&made, fixture::AFTER_DARK);
        assert!(dark.row.nsfw);
        let lounge = planned(&made, fixture::LOUNGE);
        assert_eq!(lounge.row.slow_mode_secs, 5);
        assert_eq!(lounge.row.category, Some(fixture::TALK));
        let voice = made
            .channels
            .iter()
            .find(|c| c.row.name == "General voice")
            .unwrap();
        assert!(!voice.row.text);
        assert_eq!(voice.row.max_users, 10);
        assert_eq!(made.categories.len(), 3);
        // Discord's own maximum is ours too, and past it is clipped rather than refused
        let mut fast = read.channels[0].clone();
        fast.rate_limit_per_user = 100_000;
        assert_eq!(fast.rate_limit_per_user.min(voipc_max_slow()), 21_600);
    }

    #[tokio::test(start_paused = true)]
    async fn the_open_names_are_what_may_be_spoken_of() {
        let read = read_fixture().await;
        let here = fixture::here();
        let choices = Choices {
            left_out: HashSet::from([fixture::LOUNGE]),
            ..default_choices(&read, &here)
        };
        let made = layout(&read, &here, &choices);
        let open = made.open_names();
        assert_eq!(open[&fixture::GENERAL], "general");
        // Left out, and private: no `<#id>` of either says what it is called
        assert!(!open.contains_key(&fixture::LOUNGE));
        assert!(!open.contains_key(&fixture::STAFF));
        assert!(!open.contains_key(&fixture::VAULT));
    }

    #[tokio::test(start_paused = true)]
    async fn the_names_of_a_run_hold_only_what_comes() {
        let read = read_fixture().await;
        let here = fixture::here();
        let choices = default_choices(&read, &here);
        let names = layout(&read, &here, &choices).names(&read, &here);
        assert!(names.anonymise);
        assert_eq!(names.channels[&fixture::GENERAL], "general");
        assert!(!names.channels.contains_key(&fixture::STAFF));
        assert_eq!(names.roles[&fixture::MODERATORS], "Moderators");
        // A bot's own role does not come, nor @everyone
        assert!(read
            .roles
            .iter()
            .filter(|r| r.managed)
            .all(|r| !names.roles.contains_key(&r.id)));
        assert!(!names.roles.contains_key(&G));
        assert_eq!(names.emotes.len(), 6);
        // With their toggles off, none of them is spoken of
        let mut off = choices.clone();
        off.options.roles = false;
        off.options.emotes = false;
        off.options.anonymise = false;
        let names = layout(&read, &here, &off).names(&read, &here);
        assert!(names.roles.is_empty() && names.emotes.is_empty());
        assert!(!names.anonymise);
        // An emote from an earlier run still reads as itself
        let pog = read.emojis.iter().find(|e| e.name == "pog").unwrap().id;
        let mut here = fixture::here();
        here.cursors.insert(pog, 1);
        let made = layout(&read, &here, &default_choices(&read, &here));
        assert!(made.emotes.iter().all(|e| e.id != pog));
        assert_eq!(made.names(&read, &here).emotes[&pog], "pog");
    }

    #[tokio::test(start_paused = true)]
    async fn with_roles_off_the_kept_report_names_no_role() {
        let read = read_fixture().await;
        let here = fixture::here();
        let mut choices = default_choices(&read, &here);
        let on = layout(&read, &here, &choices).report().kept();
        assert!(on.contains("@Muted") && on.contains("@Moderators"), "{on}");
        choices.options.roles = false;
        let made = layout(&read, &here, &choices);
        let off = made.report().kept();
        assert!(
            !off.contains("@Muted") && !off.contains("@Moderators"),
            "{off}"
        );
        // They are still on the screen
        let screen = made.report().end_screen().join("\n");
        assert!(screen.contains("@Muted") && screen.contains("@Moderators"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_left_out_channel_stays_out_on_a_delta() {
        let read = read_fixture().await;
        let mut here = fixture::here();
        // Everything was imported but `lounge`, left out, whose rows the relay never heard of
        for ch in read.channels.iter().filter(|c| c.comes_over()) {
            if ch.id != fixture::LOUNGE {
                here.cursors.insert(ch.id, 5);
            }
        }
        here.last_started_ms = Some(fixture::NOW_MS);
        here.facts.last_options = Some(default_options(&here));
        let choices = default_choices(&read, &here);
        assert!(choices.left_out.contains(&fixture::LOUNGE));
        let made = layout(&read, &here, &choices);
        assert!(made.channels.iter().all(|c| c.row.dc_id != fixture::LOUNGE));
        let plan = build(&read, &here);
        assert!(plan.delta);
        let row = plan
            .channels
            .iter()
            .find(|c| c.id == fixture::LOUNGE.to_string())
            .unwrap();
        assert!(row.left_out);
        assert!(row.left_out_why.contains("Left out last time"));
        // It shows, so it can be put back; and only `lounge` went that way
        assert!(plan.channels.iter().filter(|c| c.left_out).count() == 1);
        // The control: on a first run there is no such memory
        let first = fixture::here();
        assert!(!default_choices(&read, &first)
            .left_out
            .contains(&fixture::LOUNGE));
    }

    /// "What does not come" speaks of what a run makes. The relay leaves a row of its own as it
    /// stands, whatever the gate it is sent, so nothing lost from that gate is lost.
    #[tokio::test(start_paused = true)]
    async fn a_gate_the_relay_would_not_take_is_not_said_to_lose_anything() {
        let read = read_fixture().await;
        let says = |plan: &Plan, channel: &str| {
            let about = format!("#{channel}: ");
            plan.report_preview.iter().any(|n| n.starts_with(&about))
        };
        let first = build(&read, &fixture::here());
        assert!(says(&first, "general"), "{:?}", first.report_preview);
        let mut here = fixture::here();
        here.cursors.insert(fixture::GENERAL, 5);
        let delta = build(&read, &here);
        assert!(!says(&delta, "general"), "{:?}", delta.report_preview);
        // The control: one that is still to be made, by this same dry-run
        assert!(says(&delta, "old-logs"), "{:?}", delta.report_preview);
    }

    /// A run stands, older than every channel, and nothing has been left out by anyone.
    fn after_a_run(last: impl FnOnce(&mut ImportOptions)) -> Here {
        let mut here = fixture::here();
        let mut options = default_options(&here);
        last(&mut options);
        here.facts.last_options = Some(options);
        here.last_started_ms = Some(fixture::NOW_MS);
        here
    }

    #[tokio::test(start_paused = true)]
    async fn a_run_that_made_no_channels_left_none_out() {
        let read = read_fixture().await;
        let lounge = |plan: &Plan| {
            plan.channels
                .iter()
                .find(|c| c.id == fixture::LOUNGE.to_string())
                .cloned()
                .unwrap()
        };
        // Channels off, so nothing is in the ledger, and it finished
        let here = after_a_run(|o| o.channels = false);
        assert!(default_choices(&read, &here).left_out.is_empty());
        assert!(!lounge(&build(&read, &here)).left_out);
        // Nor does an earlier run's ledger make it so
        let mut here = after_a_run(|o| o.channels = false);
        here.cursors.insert(fixture::GENERAL, 5);
        assert!(default_choices(&read, &here).left_out.is_empty());
        // A run that stopped ahead of its channels. Nothing here to go by but ids of things
        // that are not channels
        let mut here = after_a_run(|_| {});
        here.facts.unfinished = Some((1, G.to_string()));
        here.cursors.insert(read.emojis[0].id, 1);
        assert!(default_choices(&read, &here).left_out.is_empty());
        // Which says nothing of what the row is otherwise: messages start as on a first run
        assert_eq!(
            default_choices(&read, &here).messages_on,
            default_choices(&read, &fixture::here()).messages_on
        );

        // The controls: a channel in the ledger is what says a run made them
        let mut here = after_a_run(|_| {});
        here.cursors.insert(fixture::GENERAL, 5);
        assert!(default_choices(&read, &here)
            .left_out
            .contains(&fixture::LOUNGE));
        let row = lounge(&build(&read, &here));
        assert!(row.left_out);
        assert_eq!(row.left_out_why, "Left out last time.");
        // Stopped partway through them: it cannot tell the two apart, and says so
        here.facts.unfinished = Some((1, G.to_string()));
        let plan = build(&read, &here);
        let row = lounge(&plan);
        assert!(row.left_out);
        assert_eq!(
            row.left_out_why,
            "Left out last time, or the last run did not reach it."
        );
        let unfinished = plan.warnings.iter().find(|w| w.code == "unfinished");
        assert!(unfinished.unwrap().text.contains("left out"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_row_says_whether_an_earlier_run_made_it() {
        let read = read_fixture().await;
        let mut here = after_a_run(|_| {});
        here.cursors.insert(fixture::GENERAL, 0);
        let plan = build(&read, &here);
        let in_ledger = |id: u64| {
            plan.channels
                .iter()
                .find(|c| c.id == id.to_string())
                .unwrap()
                .in_ledger
        };
        assert!(in_ledger(fixture::GENERAL));
        assert!(!in_ledger(fixture::LOUNGE));
    }

    #[tokio::test(start_paused = true)]
    async fn a_threads_name_keeps_all_that_fits() {
        let mut read = read_fixture().await;
        let here = fixture::here();
        let thread = read
            .threads
            .iter_mut()
            .find(|t| t.id == fixture::LOUNGE_THREAD)
            .unwrap();
        let name_of = |read: &Read, here: &Here| {
            let made = layout(read, here, &default_choices(read, here));
            made.threads_of(read, &Names::default())
                .into_iter()
                .find(|t| t.id == fixture::LOUNGE_THREAD)
                .unwrap()
                .name
        };
        thread.name = "é".repeat(100);
        assert_eq!(name_of(&read, &here).chars().count(), 100);
        let thread = read
            .threads
            .iter_mut()
            .find(|t| t.id == fixture::LOUNGE_THREAD)
            .unwrap();
        thread.name = format!("  \u{200b}{} ", "é".repeat(101));
        let name = name_of(&read, &here);
        assert_eq!(name.chars().count(), 100);
        assert!(name.starts_with('é'));
    }

    #[tokio::test(start_paused = true)]
    async fn a_thread_is_read_with_who_started_it() {
        let read = read_fixture().await;
        let here = fixture::here();
        let made = layout(&read, &here, &default_choices(&read, &here));
        let names = made.names(&read, &here);
        let thread = |names: &Names| {
            made.threads_of(&read, names)
                .into_iter()
                .find(|t| t.id == fixture::LOUNGE_THREAD)
                .unwrap()
                .owner
        };
        const DAN: u64 = 1_190_000_000_000_001_001;
        // Nobody read as a member yet: an ex-member, as far as this knows
        assert_eq!(thread(&names), None);
        assert_eq!(thread(&Names::default()), Some(DAN));
    }

    #[tokio::test(start_paused = true)]
    async fn a_channel_whose_history_was_closed_since_starts_off_on_a_delta() {
        let mut read = read_fixture().await;
        let mut here = fixture::here();
        for ch in read.channels.iter().filter(|c| c.comes_over()) {
            here.cursors.insert(ch.id, 5);
        }
        here.last_started_ms = Some(fixture::NOW_MS);
        // The control: the same channel with the same cursor, before anyone closed anything
        assert!(default_choices(&read, &here)
            .messages_on
            .contains(&fixture::LOUNGE));

        let lounge = read
            .channels
            .iter_mut()
            .find(|c| c.id == fixture::LOUNGE)
            .unwrap();
        lounge.permission_overwrites.push(model::Overwrite {
            id: G,
            kind: 0,
            allow: 0,
            deny: discord::READ_MESSAGE_HISTORY,
        });
        let choices = default_choices(&read, &here);
        assert!(!choices.messages_on.contains(&fixture::LOUNGE));
        assert!(!choices.left_out.contains(&fixture::LOUNGE));
        let plan = build(&read, &here);
        let row = plan
            .channels
            .iter()
            .find(|c| c.id == fixture::LOUNGE.to_string())
            .unwrap();
        assert!(row.see.open, "why the relay's refusal misses it");
        assert!(!row.messages_on);
        assert_eq!(
            row.messages_why,
            "Some could see it without reading its history."
        );
        // A neighbour keeps its tick, and a channel the operator turned off keeps its words
        assert!(choices.messages_on.contains(&fixture::GENERAL));
        here.cursors.insert(fixture::LOUNGE, 0);
        let plan = build(&read, &here);
        let row = plan
            .channels
            .iter()
            .find(|c| c.id == fixture::LOUNGE.to_string())
            .unwrap();
        assert_eq!(row.messages_why, "Off last time.");
    }

    #[tokio::test(start_paused = true)]
    async fn messages_off_stays_off_on_a_delta() {
        let read = read_fixture().await;
        let mut here = fixture::here();
        for ch in read.channels.iter().filter(|c| c.comes_over()) {
            here.cursors.insert(ch.id, 5);
        }
        // In the ledger and never walked: off. Everything else was walked
        here.cursors.insert(fixture::GENERAL, 0);
        here.last_started_ms = Some(fixture::NOW_MS);
        let choices = default_choices(&read, &here);
        assert!(!choices.messages_on.contains(&fixture::GENERAL));
        assert!(!choices.left_out.contains(&fixture::GENERAL));
        let plan = build(&read, &here);
        let row = plan
            .channels
            .iter()
            .find(|c| c.id == fixture::GENERAL.to_string())
            .unwrap();
        assert!(!row.messages_on);
        assert_eq!(row.messages_why, "Off last time.");
        // The control: a neighbour that was walked stays on
        assert!(choices.messages_on.contains(&fixture::LOUNGE));
        // A private channel ticked last time is walked now too: it holds a cursor
        assert!(choices.messages_on.contains(&fixture::STAFF));
        // Walked and found empty is `high` 1, which is not 0
        here.cursors.insert(fixture::GENERAL, 1);
        assert!(default_choices(&read, &here)
            .messages_on
            .contains(&fixture::GENERAL));
        // After a run that did not finish, it cannot tell the two apart, and says so
        here.cursors.insert(fixture::GENERAL, 0);
        here.facts.unfinished = Some((1, G.to_string()));
        let plan = build(&read, &here);
        let row = plan
            .channels
            .iter()
            .find(|c| c.id == fixture::GENERAL.to_string())
            .unwrap();
        assert!(!row.messages_on);
        assert!(
            row.messages_why.contains("did not reach it"),
            "{}",
            row.messages_why
        );
        assert!(plan.warnings.iter().any(|w| w.code == "unfinished"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_channel_made_since_the_last_run_comes() {
        let read = read_v2().await;
        let mut here = fixture::here();
        for ch in read.channels.iter().filter(|c| c.comes_over()) {
            if ch.id != fixture::NEW_ROOM && ch.id != fixture::NEW_PRIVATE {
                here.cursors.insert(ch.id, 5);
            }
        }
        here.last_started_ms = Some(fixture::NOW_MS);
        here.facts.last_options = Some(default_options(&here));
        let choices = default_choices(&read, &here);
        // New and on
        assert!(!choices.left_out.contains(&fixture::NEW_ROOM));
        assert!(choices.messages_on.contains(&fixture::NEW_ROOM));
        // New and private: it comes, and its history waits for the tick
        assert!(!choices.left_out.contains(&fixture::NEW_PRIVATE));
        assert!(!choices.messages_on.contains(&fixture::NEW_PRIVATE));
        // The control: the same id "made" before the last run reads as left out
        here.last_started_ms = Some(discord::snowflake_ms(fixture::NEW_ROOM as i64) + 1);
        assert!(default_choices(&read, &here)
            .left_out
            .contains(&fixture::NEW_ROOM));
    }

    #[tokio::test(start_paused = true)]
    async fn a_channel_already_made_costs_no_room_and_keeps_its_name() {
        let read = read_fixture().await;
        let mut here = fixture::here();
        here.channels.push(("general".into(), true));
        here.cursors.insert(fixture::GENERAL, 5);
        let made = layout(&read, &here, &default_choices(&read, &here));
        assert_eq!(planned(&made, fixture::GENERAL).row.name, "general");
        assert!(planned(&made, fixture::GENERAL).in_ledger);
        // With no ledger row, the relay's `general` is a clash
        here.cursors.clear();
        let made = layout(&read, &here, &default_choices(&read, &here));
        assert_eq!(planned(&made, fixture::GENERAL).row.name, "general-2");
    }

    #[tokio::test(start_paused = true)]
    async fn toggles_need_what_they_need() {
        let read = read_fixture().await;
        let here = fixture::here();
        let all = default_options(&here);
        let mut o = all.clone();
        o.channels = false;
        let e = effective(&o);
        assert!(!e.messages && !e.permissions && !e.threads && !e.pins && !e.reactions);
        let mut o = all.clone();
        o.messages = false;
        let e = effective(&o);
        assert!(!e.threads && !e.pins && !e.reactions);
        // The control: all on stays on, and others are left alone
        let e = effective(&all);
        assert!(e.messages && e.threads && e.pins && e.reactions && e.permissions);
        let mut o = all.clone();
        o.messages = false;
        assert!(effective(&o).channels && effective(&o).roles && effective(&o).permissions);
        // `layout` uses it: channels off, nothing at all
        let mut choices = default_choices(&read, &here);
        choices.options.channels = false;
        let made = layout(&read, &here, &choices);
        assert!(made.channels.is_empty() && made.categories.is_empty());
        assert!(made.threads_of(&read, &Names::default()).is_empty());
        // Messages off: channels, none walked
        let mut choices = default_choices(&read, &here);
        choices.options.messages = false;
        let made = layout(&read, &here, &choices);
        assert!(!made.channels.is_empty());
        assert!(made.channels.iter().all(|c| !c.walk));
        assert!(made.threads_of(&read, &Names::default()).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unticked_private_channels_threads_send_nothing() {
        let read = read_fixture().await;
        let here = fixture::here();
        let choices = default_choices(&read, &here);
        let made = layout(&read, &here, &choices);
        let parents: HashSet<u64> = made
            .threads_of(&read, &Names::default())
            .iter()
            .map(|t| t.parent)
            .collect();
        assert!(!parents.contains(&fixture::STAFF));
        // The control: tick it, and its thread comes
        let mut ticked = choices.clone();
        ticked.messages_on.insert(fixture::STAFF);
        let made = layout(&read, &here, &ticked);
        let parents: HashSet<u64> = made
            .threads_of(&read, &Names::default())
            .iter()
            .map(|t| t.parent)
            .collect();
        assert!(parents.contains(&fixture::STAFF));
        assert!(planned(&made, fixture::STAFF).walk);
        // A channel's messages-off covers its threads
        assert!(parents.contains(&fixture::LOUNGE));
        let mut off = choices.clone();
        off.messages_on.remove(&fixture::LOUNGE);
        let made = layout(&read, &here, &off);
        assert!(!made
            .threads_of(&read, &Names::default())
            .iter()
            .any(|t| t.parent == fixture::LOUNGE));
    }

    #[tokio::test(start_paused = true)]
    async fn a_private_thread_is_counted_and_never_sent() {
        let read = read_fixture().await;
        let here = fixture::here();
        assert!(read.threads.iter().any(|t| t.kind == PRIVATE_THREAD));
        let made = layout(&read, &here, &default_choices(&read, &here));
        let ids: HashSet<u64> = made
            .threads_of(&read, &Names::default())
            .iter()
            .map(|t| t.id)
            .collect();
        assert!(!ids.contains(&fixture::PRIVATE_THREAD_ID));
        assert!(ids.contains(&fixture::LOUNGE_THREAD));
        assert!(!ids.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_category_of_only_what_was_left_out_does_not_come() {
        let read = read_fixture().await;
        let here = fixture::here();
        let mut choices = default_choices(&read, &here);
        let help: Vec<u64> = read
            .channels
            .iter()
            .filter(|c| c.parent_id == Some(fixture::HELP_CATEGORY))
            .map(|c| c.id)
            .collect();
        assert!(!help.is_empty());
        choices.left_out.extend(help);
        let made = layout(&read, &here, &choices);
        assert!(!made
            .categories
            .iter()
            .any(|c| c.dc_id == fixture::HELP_CATEGORY));
        // The control: its neighbour stays
        assert!(made.categories.iter().any(|c| c.dc_id == fixture::TALK));
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_relay_says_what_stays_out_and_walks_none_of_it() {
        let read = read_fixture().await;
        let mut here = fixture::here();
        // Room for a handful of rows and no more
        here.facts.channel_list_bytes = here.facts.channel_list_limit - 2048 - 300;
        let made = layout(&read, &here, &default_choices(&read, &here));
        assert!(!made.no_room.is_empty());
        assert!(made.no_room.iter().all(|id| made.left_out.contains(id)));
        assert!(made
            .channels
            .iter()
            .all(|c| !made.no_room.contains(&c.row.dc_id)));
        // Voice went first, so what is left is text
        assert!(made.channels.iter().all(|c| c.row.text));
        let plan = build(&read, &here);
        assert!(plan.warnings.iter().any(|w| w.code == "channels_no_room"));
        // Topics give way before channels do
        let mut here = fixture::here();
        here.facts.channel_list_bytes = here.facts.channel_list_limit - 2048 - 2000;
        let made = layout(&read, &here, &default_choices(&read, &here));
        assert!(made.no_room.is_empty(), "{:?}", made.no_room);
        assert!(made.clipped > 0);
        assert!(build(&read, &here)
            .warnings
            .iter()
            .any(|w| w.code == "topics_clipped"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_million_members_warn_and_stop_nothing() {
        let api = Api::with_gate(Arc::new(Mock::big(1_000_000, 5, 3, 3)), RateGate::new(7));
        let read = read(&api, BIG_GUILD).await.unwrap();
        let mut here = fixture::here();
        here.facts.max_users = 500;
        let plan = build(&read, &here);
        assert_eq!(plan.guild.members, 1_000_000);
        for code in [
            "member_list",
            "join_burst",
            "unmeasured",
            "max_users",
            "history_256",
            "pins_650",
            "intent_review",
        ] {
            assert!(plan.warnings.iter().any(|w| w.code == code), "no {code}");
        }
        // This is the no-member-cap test: all of that, and not one thing stops
        assert!(plan.blocks.is_empty(), "{:?}", plan.blocks);
        assert!(plan.channels.iter().all(|c| !c.left_out));
        // The control: a small server warns of none of them
        let api = Api::with_gate(Arc::new(Mock::big(10, 0, 1, 1)), RateGate::new(7));
        let small = build(
            &super::read(&api, BIG_GUILD).await.unwrap(),
            &fixture::here(),
        );
        assert!(!small
            .warnings
            .iter()
            .any(|w| w.code == "member_list" || w.code == "intent_review"));
        // The dry-run never lists members: that is what lets this hold
        assert!(!api
            .transport()
            .asked()
            .iter()
            .any(|p| p.ends_with("/members") || p.contains("/members?")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_plan_without_content_intent_blocks_messages_only() {
        let mut read = read_fixture().await;
        let here = fixture::here();
        read.app.flags = 1 << 15;
        let plan = build(&read, &here);
        let blocked: Vec<&str> = plan.blocks.iter().map(|b| b.toggle).collect();
        assert_eq!(blocked, ["messages"]);
        // Without the member list, members and anonymise go, and messages do not
        read.app.flags = 1 << 19;
        let blocked: Vec<&str> = build(&read, &here)
            .blocks
            .iter()
            .map(|b| b.toggle)
            .collect();
        assert_eq!(blocked, ["members", "anonymise"]);
        // With both, nothing
        read.app.flags = (1 << 15) | (1 << 19);
        assert!(build(&read, &here).blocks.is_empty());
        // The other form of each flag counts as much
        read.app.flags = (1 << 14) | (1 << 18);
        assert!(build(&read, &here).blocks.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn no_discord_sign_in_blocks_the_run() {
        let read = read_fixture().await;
        let mut here = fixture::here();
        here.facts.discord_sign_in = false;
        let blocked: Vec<String> = build(&read, &here)
            .blocks
            .iter()
            .map(|b| b.toggle.to_string())
            .collect();
        assert_eq!(blocked, ["run"]);
    }

    fn numbers_past_2_53(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::Number(n) => {
                if n.as_u64().is_none_or(|n| n > SAFE_NUMBER) {
                    found.push(n.to_string());
                }
            }
            Value::Array(list) => list.iter().for_each(|v| numbers_past_2_53(v, found)),
            Value::Object(map) => map.values().for_each(|v| numbers_past_2_53(v, found)),
            _ => {}
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ids_in_the_plan_are_strings() {
        let read = read_fixture().await;
        let json = serde_json::to_value(build(&read, &fixture::here())).unwrap();
        let mut found = Vec::new();
        numbers_past_2_53(&json, &mut found);
        assert!(found.is_empty(), "{found:?}");
        assert!(json["channels"][0]["id"].is_string());
        assert!(json["roles"][0]["id"].is_string());
        assert!(json["guild"]["id"].is_string());
        // The fixture's ids are past 2^53, so this looked at real ones
        const { assert!(G > SAFE_NUMBER) };
        // The control: the checker catches what a raw gate would have said
        let raw = serde_json::to_value(ImportGate::Roles(vec![G])).unwrap();
        let mut found = Vec::new();
        numbers_past_2_53(&raw, &mut found);
        assert_eq!(found, [G.to_string()]);
        // Numbers that could run away are held under it
        let mut read = read;
        read.counts.insert(fixture::GENERAL, u64::MAX);
        let json = serde_json::to_value(build(&read, &fixture::here())).unwrap();
        let mut found = Vec::new();
        numbers_past_2_53(&json, &mut found);
        assert!(found.is_empty(), "{found:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn choices_hold_ids_as_strings_there_and_back() {
        let read = read_fixture().await;
        let choices = default_choices(&read, &fixture::here());
        let json = serde_json::to_value(&choices).unwrap();
        let mut found = Vec::new();
        numbers_past_2_53(&json, &mut found);
        assert!(found.is_empty(), "{found:?}");
        assert!(json["messages_on"][0].is_string());
        let back: Choices = serde_json::from_value(json).unwrap();
        assert_eq!(back, choices);
        // Not an id: refused, rather than quietly reading as nothing
        let bad =
            serde_json::json!({ "options": choices.options, "left_out": ["x"], "messages_on": [] });
        assert!(serde_json::from_value::<Choices>(bad).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn the_kept_report_names_nothing_left_out() {
        let read = read_fixture().await;
        let here = fixture::here();
        let mut choices = default_choices(&read, &here);
        choices.left_out.insert(fixture::AFTER_DARK);
        let made = layout(&read, &here, &choices);
        let mut report = made.report();
        // A channel left out as a run is ending
        report.notes.push(Note::kept(
            "skipped",
            Some(fixture::VAULT),
            "#vault: Discord refused it.".into(),
        ));
        report.left_out.insert(fixture::VAULT);
        report.counts.insert("messages".into(), 12);
        let kept = report.kept();
        let eva = fixture::EVA.to_string();
        // Who a rule named, a bot's role, a directory, and what was left out
        for never in [
            eva.as_str(),
            "VoIPC Importer",
            "directory",
            "after-dark",
            "#vault",
        ] {
            assert!(!kept.contains(never), "{never} in {kept}");
        }
        // The control: the end screen does name them
        let screen = report.end_screen().join("\n");
        for all in [eva.as_str(), "VoIPC Importer", "directory", "#vault"] {
            assert!(screen.contains(all), "{all} not on the screen");
        }
        // ... and the stored one is about what came
        let json: Value = serde_json::from_str(&kept).unwrap();
        assert_eq!(json["counts"]["messages"], 12);
        assert!(json["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap().contains("@Muted")));
    }

    #[test]
    fn the_kept_report_stays_under_its_limit() {
        let mut report = Report::default();
        for i in 0..1000 {
            // Quotes and newlines cost twice in JSON
            report.notes.push(Note::kept(
                if i % 2 == 0 { "lossy" } else { "over_16" },
                None,
                format!("{i} \"\n\u{1F389}").repeat(100),
            ));
        }
        let kept = report.kept();
        assert!(kept.len() <= REPORT_BYTES, "{}", kept.len());
        let json: Value = serde_json::from_str(&kept).unwrap();
        let notes = json["notes"].as_array().unwrap();
        assert!(notes.len() <= REPORT_NOTES + 2);
        let last: Vec<&str> = notes
            .iter()
            .rev()
            .take(2)
            .map(|n| n.as_str().unwrap())
            .collect();
        assert!(
            last.iter().any(|n| n.contains("more of this kind: lossy")),
            "{last:?}"
        );
        assert!(
            last.iter()
                .any(|n| n.contains("more of this kind: over_16")),
            "{last:?}"
        );
        // A character JSON writes as six bytes cannot pass it either
        let mut report = Report::default();
        for _ in 0..300 {
            report
                .notes
                .push(Note::kept("x", None, "\u{7}".repeat(NOTE_CHARS)));
        }
        assert!(report.kept().len() <= REPORT_BYTES);
        // A short one loses nothing
        let mut short = Report::default();
        short.notes.push(Note::kept("x", None, "one".into()));
        assert!(!short.kept().contains("more of this kind"));
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_move_post_writes() {
        let mock = Arc::new(fixture::mock());
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        open(&api).await.unwrap();
        read(&api, G).await.unwrap();
        assert!(mock.requests() > 10);
        assert_eq!(mock.non_gets(), 0);
        api.move_post(fixture::GENERAL, "We are moving.", false)
            .await
            .unwrap();
        assert_eq!(mock.non_gets(), 1);
        assert_eq!(mock.posted().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn opening_says_what_a_token_can_reach() {
        let api = Api::with_gate(Arc::new(fixture::mock()), RateGate::new(7));
        let opening = open(&api).await.unwrap();
        assert!(opening.member_intent && opening.content_intent);
        assert!(opening
            .invite
            .starts_with("https://discord.com/oauth2/authorize?client_id="));
        assert!(opening.invite.ends_with("&scope=bot&permissions=8"));
        assert_eq!(opening.guilds[0].id, G.to_string());
        assert!(opening.guilds[0].admin);
        // A dead token stops it, and says so
        let mock = Arc::new(fixture::mock());
        mock.script(crate::mock::Scripted::new("/users/@me", 1, 401, &[], "{}"));
        let api = Api::with_gate(mock, RateGate::new(7));
        assert!(open(&api).await.unwrap_err().contains("token"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_list_it_cannot_have_is_noted_and_the_rest_comes() {
        let mock = Arc::new(fixture::mock());
        mock.script(
            crate::mock::Scripted::new(&format!("/guilds/{G}/bans"), 1, 403, &[], "{}").always(),
        );
        mock.script(
            crate::mock::Scripted::new(
                &format!("/guilds/{G}/roles/member-counts"),
                1,
                403,
                &[],
                "{}",
            )
            .always(),
        );
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        let read = read(&api, G).await.unwrap();
        assert!(read.bans.is_empty());
        assert!(read.notes.iter().any(|n| n.text.contains("bans")));
        // Discord would not say who has what: every role counts, and no gate lost them
        assert_eq!(read.role_counts, None);
        let plan = build(&read, &fixture::here());
        assert!(by_name(&plan, "staff").see.roles.len() >= 2);
        // The server itself is not something to go on without
        let mock = Arc::new(fixture::mock());
        mock.script(
            crate::mock::Scripted::new(&format!("/guilds/{G}/channels"), 1, 403, &[], "{}")
                .always(),
        );
        let api = Api::with_gate(mock, RateGate::new(7));
        assert!(super::read(&api, G)
            .await
            .err()
            .unwrap()
            .contains("channels"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_count_not_indexed_waits_once_then_stays_unknown() {
        let mock = Arc::new(fixture::mock());
        // Never done indexing
        mock.script(
            crate::mock::Scripted::new(
                &format!("/guilds/{G}/messages/search?channel_id={}", fixture::GENERAL),
                1,
                202,
                &[],
                r#"{"message":"Index not yet available. Try again later","code":110000,"retry_after":2}"#,
            )
            .always(),
        );
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        let started = Instant::now();
        let read = read(&api, G).await.unwrap();
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert_eq!(read.counts.get(&fixture::GENERAL), None);
        let asked = mock
            .asked()
            .iter()
            .filter(|p| p.contains("search") && p.contains(&fixture::GENERAL.to_string()))
            .count();
        assert_eq!(asked, 2);
        assert!(read.counts.contains_key(&fixture::LOUNGE));
        // search.json's own: one 202, and then a number
        assert_eq!(read.counts.get(&fixture::NEWS), Some(&40));
        // Unknown shows as such, and the estimate says it is a floor
        let plan = build(&read, &fixture::here());
        assert_eq!(by_name(&plan, "general").messages, None);
        assert!(plan.estimate.at_least);
    }

    #[tokio::test(start_paused = true)]
    async fn counting_stops_at_its_budget() {
        let mock = Arc::new(fixture::mock());
        // The first count takes all the time there is
        let slow = format!(
            "/guilds/{G}/messages/search?channel_id={}",
            fixture::GENERAL
        );
        mock.script(crate::mock::Scripted::new(
            &slow,
            1,
            429,
            &[("retry-after", "125")],
            "{}",
        ));
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        let read = read(&api, G).await.unwrap();
        // That one came in the end, and nothing after it was asked
        assert!(read.counts.contains_key(&fixture::GENERAL));
        assert!(!read.counts.contains_key(&fixture::LOUNGE));
        let plan = build(&read, &fixture::here());
        assert!(plan.estimate.at_least);
    }

    #[tokio::test(start_paused = true)]
    async fn the_estimate_goes_by_discords_own_pace_and_by_the_database() {
        let mut read = read_fixture().await;
        // 5 requests in a 1 s window, four walkers
        assert_eq!(read.pace, Some(20.0));
        assert!(read.mean_body.is_some());
        read.counts.clear();
        read.threads.clear();
        read.counts.insert(fixture::GENERAL, 1_000_000);
        read.mean_body = Some(100);
        let channels = read.channels.len() as u64;
        let mut here = fixture::here();
        let sqlite = build(&read, &here).estimate;
        assert_eq!(sqlite.messages, 1_000_000);
        assert_eq!(sqlite.bytes, 1_000_000 * (108 + 100));
        assert_eq!(sqlite.requests, 10_000 + channels);
        assert_eq!(sqlite.secs_low, (10_000 + channels).div_ceil(20));
        assert_eq!(sqlite.secs_high, sqlite.secs_low * 2);
        here.facts.backup_here = false;
        assert_eq!(build(&read, &here).estimate.bytes, 1_000_000 * (189 + 100));
        // Nothing is counted for what stays off
        let mut off = default_choices(&read, &here);
        off.messages_on.remove(&fixture::GENERAL);
        let made = layout(&read, &here, &off);
        assert_eq!(estimate(&read, &here, &made).messages, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_warnings_are_the_tables() {
        let mut read = read_fixture().await;
        let mut here = fixture::here();
        let codes = |read: &Read, here: &Here| -> Vec<&'static str> {
            build(read, here).warnings.iter().map(|w| w.code).collect()
        };
        assert!(codes(&read, &here).contains(&"disk"));
        assert!(codes(&read, &here).contains(&"registration"));
        here.facts.backup_here = false;
        here.facts.takes_guests = true;
        here.facts.accounts = 3;
        here.facts.cloud = false;
        here.facts.emotes = 399;
        here.facts.categories = 199;
        let got = codes(&read, &here);
        for code in [
            "postgres",
            "guests",
            "accounts_here",
            "cloud_off",
            "emotes",
            "categories",
            "lossy",
        ] {
            assert!(got.contains(&code), "no {code} in {got:?}");
        }
        // Not an admin: red, and Run stays possible
        read.bot_roles.clear();
        let plan = build(&read, &here);
        let warn = plan
            .warnings
            .iter()
            .find(|w| w.code == "not_admin")
            .unwrap();
        assert_eq!(warn.level, Level::Red);
        assert!(plan.blocks.is_empty());
        // The control: nothing of the kind on a plain relay with a plain bot
        let read = read_fixture().await;
        let got = codes(&read, &fixture::here());
        for code in [
            "postgres",
            "guests",
            "accounts_here",
            "cloud_off",
            "emotes",
            "categories",
            "not_admin",
        ] {
            assert!(!got.contains(&code), "{code} in {got:?}");
        }
        // Too many roles for one group list
        let mut read = read;
        let role = read.roles[3].clone();
        assert!(!role.managed);
        for i in 0..250 {
            read.roles.push(Role {
                id: 7000 + i,
                permissions: discord::KICK_MEMBERS,
                ..role.clone()
            });
        }
        assert!(codes(&read, &fixture::here()).contains(&"groups"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_emotes_come_in_discords_order_until_there_is_no_room() {
        let read = read_fixture().await;
        let mut here = fixture::here();
        let made = layout(&read, &here, &default_choices(&read, &here));
        let names: Vec<&str> = made.emotes.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "pog",
                "party_blob",
                "cool_emote",
                "old_one",
                "wave",
                "dance"
            ]
        );
        assert!(made.emotes[4].sticker && !made.emotes[0].sticker);
        // A Lottie sticker is said, and does not come
        assert!(made
            .report()
            .end_screen()
            .iter()
            .any(|n| n.contains("Lottie")));
        // A name the relay has takes a number
        here.emote_names.push("pog".into());
        let made = layout(&read, &here, &default_choices(&read, &here));
        assert_eq!(made.emotes[0].name, "pog_2");
        // Room for two
        here.facts.emotes = MAX_EMOTES as u32 - 2;
        let made = layout(&read, &here, &default_choices(&read, &here));
        assert_eq!(made.emotes.len(), 2);
        assert!(made
            .report()
            .end_screen()
            .iter()
            .any(|n| n.contains("did not fit")));
        // One an earlier run made, or that was removed by hand, is not fetched again
        let mut here = fixture::here();
        here.cursors.insert(made.emotes[0].id, 1);
        let again = layout(&read, &here, &default_choices(&read, &here));
        assert!(!again.emotes.iter().any(|e| e.id == made.emotes[0].id));
        // The toggle
        let mut choices = default_choices(&read, &here);
        choices.options.emotes = false;
        assert!(layout(&read, &here, &choices).emotes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_toggles_start_as_last_time_and_the_tick_is_given_again() {
        let mut here = fixture::here();
        assert!(default_options(&here).messages);
        assert!(!default_options(&here).acknowledged);
        let mut last = default_options(&here);
        last.bans = false;
        last.acknowledged = true;
        here.facts.last_options = Some(last);
        let options = default_options(&here);
        assert!(!options.bans);
        assert!(!options.acknowledged);
    }

    #[tokio::test(start_paused = true)]
    async fn archived_threads_walk_every_page_and_stop_where_a_delta_says() {
        let api = Api::with_gate(Arc::new(fixture::mock()), RateGate::new(7));
        let all = archived_threads(&api, fixture::LOUNGE, None).await.unwrap();
        assert!(all.len() >= 2);
        let stamps: Vec<String> = all
            .iter()
            .map(|t| {
                t.thread_metadata
                    .as_ref()
                    .unwrap()
                    .archive_timestamp
                    .clone()
            })
            .collect();
        assert!(stamps.windows(2).all(|w| w[0] >= w[1]), "{stamps:?}");
        // Past the floor, nothing older is read
        let some = archived_threads(&api, fixture::LOUNGE, Some(&stamps[0]))
            .await
            .unwrap();
        assert_eq!(some.len(), 1);
        // A page that goes nowhere ends the walk: it would ask the same thing for ever
        let mock = Arc::new(fixture::mock());
        let same = r#"{"threads":[{"id":"1","type":11,"thread_metadata":{"archive_timestamp":"2024-01-01T00:00:00+00:00"}}],"has_more":true}"#;
        mock.script(crate::mock::Scripted::new("/channels/1/threads", 1, 200, &[], same).always());
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        let got = archived_threads(&api, 1, None).await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(mock.requests(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn all_the_bans_come_a_page_at_a_time() {
        let mock = Arc::new(Mock::big(0, 2500, 0, 0));
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        let bans = all_bans(&api, BIG_GUILD).await.unwrap();
        assert_eq!(bans.len(), 2500);
        assert_eq!(mock.requests(), 4);
        let unique: HashSet<u64> = bans.iter().map(|b| b.user.id).collect();
        assert_eq!(unique.len(), 2500);
    }

    #[tokio::test(start_paused = true)]
    async fn a_rate_scripted_dry_run_gets_the_same_plan() {
        let quiet = read_fixture().await;
        let mock = Arc::new(fixture::mock());
        mock.use_rate_script();
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        let started = Instant::now();
        let bumpy = read(&api, G).await.unwrap();
        // It was told to wait, and did
        assert!(started.elapsed() >= Duration::from_secs(2));
        let plan = |r: &Read| serde_json::to_string(&build(r, &fixture::here())).unwrap();
        assert_eq!(plan(&quiet), plan(&bumpy));
        // The script did fire: more asked than a quiet run does
        let quiet_mock = Arc::new(fixture::mock());
        let api = Api::with_gate(quiet_mock.clone(), RateGate::new(7));
        read_after(&api).await;
        assert!(mock.requests() > quiet_mock.requests());
    }

    /// The app runs these on its own task, which can move between threads.
    #[test]
    fn a_dry_run_can_move_between_threads() {
        fn sends<T: Send>(_: &T) {}
        fn shares<T: Send + Sync>() {}
        let api = Api::with_gate(Arc::new(Mock::big(0, 0, 0, 0)), RateGate::new(7));
        sends(&open(&api));
        sends(&read(&api, G));
        sends(&archived_threads(&api, 1, None));
        sends(&api.move_post(1, "", false));
        shares::<Api<Arc<Mock>>>();
        shares::<Read>();
        shares::<Layout>();
    }

    async fn read_after<T: Transport>(api: &Api<T>) {
        read(api, G).await.unwrap();
    }

    /// `plan.json` is what the wizard's selftest shows, so it must be what the code says
    /// of the fixture. `VOIPC_WRITE_PLAN=1` writes it.
    #[tokio::test(start_paused = true)]
    async fn the_wizards_plan_is_what_the_fixture_gives() {
        let read = read_fixture().await;
        let plan = serde_json::to_string_pretty(&build(&read, &fixture::here())).unwrap() + "\n";
        fixture::check_plan_json(&plan);
    }
}
