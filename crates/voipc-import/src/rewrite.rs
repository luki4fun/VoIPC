//! A message as it reaches the relay. Discord's tokens become plain words for the archive
//! pane, which draws them as text and never as a live mention. A hand parser with no
//! backtracking: a message is someone's input, and it stays linear on anything.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock};

use voipc_protocol::types::{
    ArchiveWish, ImportAttachment, ImportBan, ImportMember, ImportMessage, ImportOptions,
    ImportReaction, ImportRole, IMPORT_BODY_BYTES,
};

use crate::model::{self, Ban, Member, Message, Role, User, SUPPRESS_EMBEDS, TEXT};
use crate::names::{bad_name_char, clip_bytes, clip_chars, display_name};

/// The name an ex-member's posts go under when they are anonymised.
pub const FORMER_MEMBER: &str = "Former member";
/// Kinds of message that give a row: default, reply, slash command, context menu.
const KEPT_KINDS: [u8; 4] = [TEXT, 19, 20, 23];
/// What the relay takes of a row (`archive_put`).
const MAX_REACTIONS: usize = 20;
const MAX_ATTACHMENTS: usize = 20;
const ATTACHMENT_NAME_CHARS: usize = 128;
const MIME_CHARS: usize = 64;
const MAX_ROLES: usize = 250;
const ROLE_NAME_CHARS: usize = 100;
/// `MAX_EMOJI_BYTES`.
const EMOJI_BYTES: usize = 32;
const BADGE_CHARS: usize = 32;
/// Discord's own limit on an emoji's name.
const EMOJI_NAME_BYTES: usize = 32;
/// More digits than a u64 has, so a run of digits stops being read here.
const ID_DIGITS: usize = 20;
/// Plain rows that say Message Content is off without asking anyone: fewer may just be quiet.
const BLANK_PAGE_PROVES: usize = 20;

/// What a token may turn into. Only what the relay is told of anyway belongs in here.
#[derive(Debug, Default, Clone)]
pub struct Names {
    /// Everyone read from `/members` this run, bots too, as they are shown.
    pub members: HashMap<u64, String>,
    /// Asked to be out, or deleted their account: no account, and no row of theirs.
    pub erased: HashSet<u64>,
    /// Lifted ban, or held while they link: no account, and their posts stay.
    pub held: HashSet<u64>,
    /// Those of both whose own doing it is, in deleting their account: that stops no ban.
    pub own_exit: HashSet<u64>,
    /// What people said of their rows, by author. Read only where anonymising needs it: with
    /// an id on a row, the relay goes by these itself.
    pub wishes: HashMap<u64, Vec<ArchiveWish>>,
    /// Ids at or past this were written since the member list began to be read.
    pub list_read: u64,
    /// Who joined since then, as they are shown: found by asking, by any of the walkers.
    pub late: Arc<RwLock<HashMap<u64, String>>>,
    /// Roles that come, as their badge reads.
    pub roles: HashMap<u64, String>,
    /// Channels that come and that anyone can see, by the name they have here. A public
    /// message must not say what a private channel or one left out is called.
    pub channels: HashMap<u64, String>,
    /// Emotes that come, by the name they have here.
    pub emotes: HashMap<u64, String>,
    pub anonymise: bool,
}

impl Names {
    pub fn excluded(&self, id: u64) -> bool {
        self.erased.contains(&id) || self.held.contains(&id)
    }

    /// Someone read from `/members`, whatever else becomes of them.
    pub fn add_member(&mut self, m: &Member) {
        if let Some(user) = &m.user {
            self.members
                .insert(user.id, shown_as(m.nick.as_deref(), user));
        }
    }

    /// A row of `AdminReply::MoveExcluded`. None: not an id, which the relay would not send.
    pub fn add_excluded(&mut self, dc_id: &str, own: bool, erase: bool) -> Option<()> {
        let id = dc_id.parse().ok()?;
        if own {
            self.own_exit.insert(id);
        }
        if erase {
            self.erased.insert(id);
        } else {
            self.held.insert(id);
        }
        Some(())
    }

    /// Someone found after the list was read. `who` in case Discord leaves `user` out.
    pub fn add_late(&self, m: &Member, who: &User) {
        let user = m.user.as_ref().unwrap_or(who);
        self.late
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(who.id, shown_as(m.nick.as_deref(), user));
    }

    /// The name of someone a member, however that came to be known.
    fn member(&self, id: u64) -> Option<String> {
        self.members.get(&id).cloned().or_else(|| {
            self.late
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&id)
                .cloned()
        })
    }

    /// Would this row go in with no name on it?
    fn anonymises(&self, m: &Message) -> bool {
        self.anonymise
            && m.webhook_id.is_none()
            && !m.author.bot
            && self.member(m.author.id).is_none()
    }

    /// A wish of `author`'s reaches this row, as the relay's `verdict` has it.
    fn wished(&self, author: u64, channel: u64, id: u64) -> bool {
        self.wishes.get(&author).is_some_and(|list| {
            list.iter()
                .any(|w| (w.channel == 0 || w.channel == channel) && (w.low..=w.high).contains(&id))
        })
    }

    /// A row its author has hidden or deleted, which would go in with no name on it. There no
    /// wish could reach it any more, so it does not come, for a hide too: an anonymised row
    /// cannot be hidden from all but its author. `channel` is what a wish holds: a thread's
    /// parent, for a thread's rows.
    pub fn wished_away(&self, m: &Message, channel: u64) -> bool {
        self.anonymises(m) && self.wished(m.author.id, channel, m.id)
    }

    /// A row that does not come because of what its author asked. If a thread opens on it, the
    /// thread's name may be its words, and the relay never hears of the row to take them back.
    pub fn taken_back(&self, m: &Message, channel: u64) -> bool {
        self.wished_away(m, channel)
            || (m.webhook_id.is_none() && self.erased.contains(&m.author.id))
    }

    /// Who a thread may say started it, by the rule for a row's author: not an ex-member under
    /// anonymise, unless something of theirs covers it, of which the relay holds the id already
    /// and which only reaches the row by that id.
    pub fn thread_owner(&self, owner: u64, parent: u64, thread: u64) -> Option<u64> {
        (!self.anonymise
            || self.member(owner).is_some()
            || self.erased.contains(&owner)
            || self.wished(owner, parent, thread))
        .then_some(owner)
    }

    /// Worth asking Discord who wrote this: it is newer than the member list, so its author
    /// not being on that list says nothing yet.
    pub fn may_have_joined_since(&self, m: &Message) -> bool {
        KEPT_KINDS.contains(&m.kind)
            && m.id >= self.list_read
            && self.anonymises(m)
            && !self.erased.contains(&m.author.id)
    }

    /// Those a row names, by the same rule: a mention of a newcomer has no other way to be right,
    /// as a later delta does not read the row again. A bot goes by its name either way, and
    /// someone left out reads as unknown.
    pub fn mentioned_since<'a>(&'a self, m: &'a Message) -> impl Iterator<Item = &'a User> {
        let may = self.anonymise && KEPT_KINDS.contains(&m.kind) && m.id >= self.list_read;
        m.mentions
            .iter()
            .filter(move |u| may && !u.bot && !self.excluded(u.id) && self.member(u.id).is_none())
    }

    pub fn add_role(&mut self, id: u64, name: &str) {
        let badge = display_name(name);
        self.roles
            .insert(id, clip_chars(&badge, BADGE_CHARS).to_string());
    }
}

/// The name a member goes by: nick, else `global_name`, else `username`.
pub fn shown_as(nick: Option<&str>, user: &User) -> String {
    let wanted = nick.or(user.global_name.as_deref()).unwrap_or_default();
    let name = display_name(wanted);
    if !name.is_empty() {
        return name;
    }
    display_name(&user.username)
}

fn digits(s: &str) -> Option<(u64, usize)> {
    let len = s
        .bytes()
        .take(ID_DIGITS)
        .take_while(u8::is_ascii_digit)
        .count();
    if len == 0 {
        return None;
    }
    Some((s[..len].parse().ok()?, len))
}

/// A token's id and what closes it, from just past its opening.
fn id_then_close(s: &str) -> Option<(u64, usize)> {
    let (id, len) = digits(s)?;
    (s.as_bytes().get(len) == Some(&b'>')).then_some((id, len + 1))
}

/// One of Discord's tokens, once it is sure to be one.
enum Token<'a> {
    Member(u64),
    Role(u64),
    Channel(u64),
    Emoji(u64, &'a str),
    Time(String),
}

/// `name:id>`, the end of `<:name:id>` or `<a:name:id>`.
fn custom_emoji(s: &str) -> Option<(Token<'_>, usize)> {
    let len = s
        .bytes()
        .take(EMOJI_NAME_BYTES + 1)
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if len == 0 || len > EMOJI_NAME_BYTES || s.as_bytes().get(len) != Some(&b':') {
        return None;
    }
    let (id, end) = id_then_close(&s[len + 1..])?;
    Some((Token::Emoji(id, &s[..len]), len + 1 + end))
}

/// `123>` or `123:R>`, the end of `<t:123>` or `<t:123:R>`.
fn timestamp(s: &str) -> Option<(Token<'_>, usize)> {
    let (secs, len) = digits(s)?;
    let bytes = s.as_bytes();
    let end = match bytes.get(len)? {
        b'>' => len + 1,
        b':' if bytes.get(len + 1)?.is_ascii_alphabetic() && bytes.get(len + 2)? == &b'>' => {
            len + 3
        }
        _ => return None,
    };
    Some((Token::Time(model::iso_of(i64::try_from(secs).ok()?)?), end))
}

/// A token at the start of `s`, which starts with `<`, and how long it is. Reads only as far
/// as a token can go, so a text of nothing but false starts stays linear.
fn token(s: &str) -> Option<(Token<'_>, usize)> {
    let rest = &s[1..];
    let (tok, opening, end) = if let Some(after) = rest.strip_prefix("@&") {
        let (id, end) = id_then_close(after)?;
        (Token::Role(id), 3, end)
    } else if let Some(after) = rest.strip_prefix("@!") {
        let (id, end) = id_then_close(after)?;
        (Token::Member(id), 3, end)
    } else if let Some(after) = rest.strip_prefix('@') {
        let (id, end) = id_then_close(after)?;
        (Token::Member(id), 2, end)
    } else if let Some(after) = rest.strip_prefix('#') {
        let (id, end) = id_then_close(after)?;
        (Token::Channel(id), 2, end)
    } else if let Some(after) = rest.strip_prefix(':') {
        let (tok, end) = custom_emoji(after)?;
        (tok, 2, end)
    } else if let Some(after) = rest.strip_prefix("a:") {
        let (tok, end) = custom_emoji(after)?;
        (tok, 3, end)
    } else {
        let (tok, end) = timestamp(rest.strip_prefix("t:")?)?;
        (tok, 3, end)
    };
    Some((tok, opening + end))
}

/// Whether the `.` or `:` at `at` is what makes a bare address a link in the pane's Markdown:
/// `www.` anywhere in a word, as much as at its start, and a scheme's `://`.
fn makes_a_bare_link(name: &str, at: usize) -> bool {
    let (written, rest) = name.split_at(at);
    let www = written.as_bytes().rchunks(3).next();
    rest.starts_with("://")
        || (rest.starts_with('.') && www.is_some_and(|w| w.eq_ignore_ascii_case(b"www")))
}

/// A name going in a body, which the pane draws as Markdown: someone's nickname must not
/// become a link in another's row, or change how the rest of it is drawn. An `_` between two
/// letters does nothing there and stays as it is, so that `dan_d` can still be searched for.
fn push_name(name: &str, out: &mut String) {
    let mut before = None;
    let mut rest = name.char_indices().peekable();
    while let Some((at, c)) = rest.next() {
        let inert = c == '_'
            && before.is_some_and(char::is_alphanumeric)
            && rest.peek().is_some_and(|(_, next)| next.is_alphanumeric());
        let special = matches!(
            c,
            '\\' | '`' | '*' | '_' | '~' | '|' | '[' | ']' | '(' | ')' | '<' | '>'
        );
        // `@` too: `ceo@evil.xy` is a mailto link there (W1-37)
        if (special && !inert) || c == '@' || makes_a_bare_link(name, at) {
            out.push('\\');
        }
        out.push(c);
        before = Some(c);
    }
}

fn write_member(id: u64, names: &Names, mentions: &[User], out: &mut String) {
    out.push('@');
    if names.excluded(id) {
        out.push_str("unknown");
    } else if let Some(name) = names.member(id) {
        push_name(&name, out);
    } else {
        match mentions.iter().find(|u| u.id == id) {
            Some(u) if !names.anonymise || u.bot => push_name(&shown_as(None, u), out),
            Some(_) => out.push_str(FORMER_MEMBER),
            None => out.push_str("unknown"),
        }
    }
}

fn write_token(tok: Token, names: &Names, mentions: &[User], out: &mut String) {
    let or_unknown = |name: Option<&String>| name.map_or("unknown", |n| n.as_str()).to_string();
    match tok {
        Token::Member(id) => write_member(id, names, mentions, out),
        Token::Role(id) => {
            out.push_str("@&");
            push_name(&or_unknown(names.roles.get(&id)), out);
        }
        Token::Channel(id) => {
            out.push('#');
            push_name(&or_unknown(names.channels.get(&id)), out);
        }
        Token::Emoji(id, written) => {
            out.push(':');
            out.push_str(names.emotes.get(&id).map_or(written, |n| n.as_str()));
            out.push(':');
        }
        Token::Time(iso) => out.push_str(&iso),
    }
}

fn rewrite_words(part: &str, names: &Names, mentions: &[User], out: &mut String) {
    let mut from = 0;
    let mut at = 0;
    while let Some(found) = part[at..].find('<') {
        let start = at + found;
        match token(&part[start..]) {
            Some((tok, len)) => {
                out.push_str(&part[from..start]);
                write_token(tok, names, mentions, out);
                at = start + len;
                from = at;
            }
            None => at = start + 1,
        }
    }
    out.push_str(&part[from..]);
}

/// How long the code starting at `s`'s first byte is, as `CODE` in emote-rules.ts reads
/// it: fenced by ``` or ~~~ up to its close or the end, or inline on one line.
fn code_len(s: &str) -> Option<usize> {
    for fence in ["```", "~~~"] {
        if let Some(rest) = s.strip_prefix(fence) {
            return Some(rest.find(fence).map_or(s.len(), |end| end + 6));
        }
    }
    if let Some(rest) = s.strip_prefix("``") {
        let line = rest.find('\n').unwrap_or(rest.len());
        if let Some(end) = rest[..line].find("``") {
            return Some(end + 4);
        }
    }
    let rest = s.strip_prefix('`')?;
    let next = rest.find(['`', '\n'])?;
    (rest.as_bytes()[next] == b'`').then_some(next + 2)
}

/// `content` with its tokens turned to words. Code is left as it was written.
pub fn rewrite(content: &str, names: &Names, mentions: &[User]) -> String {
    let mut out = String::with_capacity(content.len());
    let mut from = 0;
    let mut at = 0;
    while let Some(found) = content[at..].find(['`', '~']) {
        let start = at + found;
        match code_len(&content[start..]) {
            Some(len) => {
                rewrite_words(&content[from..start], names, mentions, &mut out);
                out.push_str(&content[start..start + len]);
                at = start + len;
                from = at;
            }
            None => at = start + 1,
        }
    }
    rewrite_words(&content[from..], names, mentions, &mut out);
    out
}

/// A name going in a line such as `[attachment: name]`. It loses what could turn that line
/// into a link or a definition when the pane draws it.
pub fn label(raw: &str, max_chars: usize) -> String {
    let kept: String = raw
        .chars()
        .filter(|c| {
            !matches!(c, '[' | ']' | '(' | ')' | '<' | '>' | '\\' | '`') && !bad_name_char(*c)
        })
        .collect();
    let kept = clip_chars(kept.trim(), max_chars).trim();
    if kept.is_empty() {
        "unnamed".to_string()
    } else {
        kept.to_string()
    }
}

/// `label`, for a line of the body, which the pane draws as Markdown: an address in it is
/// words, not a link (W1-37). The file's own name and type keep `label`, since no Markdown
/// draws them.
fn label_line(raw: &str, max_chars: usize) -> String {
    let kept = label(raw, max_chars);
    let mut out = String::with_capacity(kept.len() + 4);
    for (at, c) in kept.char_indices() {
        if c == '@' || makes_a_bare_link(&kept, at) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn push_line(out: &mut String, line: &str) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(line);
}

/// A message's text, whatever it was made of: at most `IMPORT_BODY_BYTES`.
fn body_of(m: &Message, names: &Names) -> String {
    let mut body = rewrite(&m.content, names, &m.mentions);
    if m.content.is_empty() {
        if let Some(embed) = m.embeds.first() {
            let mut text = rewrite(&embed.title, names, &m.mentions);
            let description = rewrite(&embed.description, names, &m.mentions);
            if !description.is_empty() {
                push_line(&mut text, &description);
            }
            push_line(&mut body, if text.is_empty() { "[embed]" } else { &text });
        }
    }
    for snapshot in &m.message_snapshots {
        push_line(&mut body, "[forwarded]");
        let text = rewrite(&snapshot.message.content, names, &snapshot.message.mentions);
        if !text.is_empty() {
            push_line(&mut body, &text);
        }
    }
    for a in &m.attachments {
        let name = label_line(&a.filename, ATTACHMENT_NAME_CHARS);
        push_line(&mut body, &format!("[attachment: {name}]"));
    }
    for s in &m.sticker_items {
        let name = label_line(&s.name, ATTACHMENT_NAME_CHARS);
        push_line(&mut body, &format!("[sticker: {name}]"));
    }
    if let Some(poll) = &m.poll {
        let question = label_line(&poll.question.text, ATTACHMENT_NAME_CHARS);
        push_line(&mut body, &format!("[poll: {question}]"));
    }
    body.truncate(clip_bytes(&body, IMPORT_BODY_BYTES).len());
    body
}

/// Who a row says wrote it. None: the row does not come.
fn author_of(m: &Message, names: &Names) -> Option<(Option<u64>, String)> {
    if m.webhook_id.is_some() {
        let name = display_name(&m.author.username);
        return Some((
            None,
            if name.is_empty() {
                "Webhook".into()
            } else {
                name
            },
        ));
    }
    if names.erased.contains(&m.author.id) {
        return None;
    }
    if let Some(name) = names.member(m.author.id) {
        return Some((Some(m.author.id), name));
    }
    // Not in the list read this run, so they left or their account is gone. Done here,
    // before the row leaves this machine: the relay never holds that id or name.
    if names.anonymise && !m.author.bot {
        return Some((None, FORMER_MEMBER.to_string()));
    }
    let name = shown_as(None, &m.author);
    Some((
        Some(m.author.id),
        if name.is_empty() {
            "unknown".into()
        } else {
            name
        },
    ))
}

fn reactions_of(m: &Message, names: &Names) -> Vec<ImportReaction> {
    m.reactions
        .iter()
        .filter_map(|r| {
            let emoji = match r.emoji.id {
                Some(id) => match names.emotes.get(&id) {
                    Some(name) => format!(":{name}:"),
                    None => format!(":{}:", r.emoji.name),
                },
                None => r.emoji.name.clone(),
            };
            let emoji = clip_bytes(&emoji, EMOJI_BYTES);
            (!emoji.is_empty() && emoji != "::").then(|| ImportReaction {
                emoji: emoji.to_string(),
                count: r.count,
            })
        })
        .take(MAX_REACTIONS)
        .collect()
}

/// The row of one message. None: no row, and it still counts as read. A system message
/// gives none, nor does one by somebody whose posts must not come.
pub fn row_of(m: &Message, names: &Names, options: &ImportOptions) -> Option<ImportMessage> {
    if !KEPT_KINDS.contains(&m.kind) {
        return None;
    }
    let (author, author_name) = author_of(m, names)?;
    Some(ImportMessage {
        id: m.id,
        author,
        author_name,
        body: body_of(m, names),
        reply_to: (m.kind == 19)
            .then(|| m.message_reference.as_ref()?.message_id)
            .flatten(),
        pinned: options.pins && m.pinned,
        reactions: if options.reactions {
            reactions_of(m, names)
        } else {
            Vec::new()
        },
        attachments: m
            .attachments
            .iter()
            .take(MAX_ATTACHMENTS)
            .map(|a| ImportAttachment {
                id: a.id,
                name: label(&a.filename, ATTACHMENT_NAME_CHARS),
                bytes: a.size,
                mime: label(&a.content_type, MIME_CHARS),
            })
            .collect(),
    })
}

/// Whether the docs' silent failure has struck: without Message Content, every message
/// comes back with its text gone, and no error says so.
fn looks_blank(m: &Message) -> bool {
    m.kind == TEXT
        && !empty_of_itself(m)
        && m.content.is_empty()
        && m.attachments.is_empty()
        && m.embeds.is_empty()
        && m.sticker_items.is_empty()
        && m.message_snapshots.is_empty()
        && m.poll.is_none()
        && m.components.is_empty()
}

/// Holds no words with Message Content on too, so it says nothing either way: a Rich Presence
/// invite, or a bot's post with its embeds taken off.
fn empty_of_itself(m: &Message) -> bool {
    m.activity.is_some() || m.flags & SUPPRESS_EMBEDS != 0
}

fn plain_rows(page: &[Message]) -> usize {
    page.iter()
        .filter(|m| m.kind == TEXT && !empty_of_itself(m))
        .count()
}

/// Over 95% of a first page's plain messages hold nothing: otherwise an archive of blanks is
/// stored, with a cursor saying that part is done.
pub fn page_is_blank(page: &[Message]) -> bool {
    let blank = page.iter().filter(|m| looks_blank(m)).count();
    blank * 100 > plain_rows(page) * 95
}

/// A page that is blank has enough rows to say so alone. With fewer, ask Discord.
pub fn blank_page_proves_it(page: &[Message]) -> bool {
    plain_rows(page) >= BLANK_PAGE_PROVES
}

/// A member's row. None for a bot, someone still in Membership Screening, or someone left
/// out, of either kind: the relay never gets to skip them.
pub fn member_row(m: &Member, names: &Names) -> Option<ImportMember> {
    let user = m.user.as_ref()?;
    if user.id == 0 || user.bot || m.pending || names.excluded(user.id) {
        return None;
    }
    let shown = m.nick.as_deref().or(user.global_name.as_deref());
    let mut roles = m.roles.clone();
    roles.truncate(MAX_ROLES);
    Some(ImportMember {
        dc_id: user.id,
        username: user.username.clone(),
        shown_as: shown.map(display_name).unwrap_or_default(),
        joined_at: m.joined_at.as_deref().and_then(model::unix_of).unwrap_or(0),
        roles,
    })
}

/// A ban's row: the id and nothing else. None for someone left out, unless it is their own
/// doing: having deleted an account does not stop a ban, and the relay knows what to do.
pub fn ban_row(b: &Ban, names: &Names) -> Option<ImportBan> {
    let id = b.user.id;
    (id != 0 && (!names.excluded(id) || names.own_exit.contains(&id)))
        .then_some(ImportBan { dc_id: id })
}

/// A role's row. None for @everyone and for a bot's own role.
pub fn role_row(r: &Role, guild: u64) -> Option<ImportRole> {
    if r.id == guild || r.managed {
        return None;
    }
    Some(ImportRole {
        dc_id: r.id,
        name: clip_chars(&r.name, ROLE_NAME_CHARS).to_string(),
        color: if r.colors.primary_color != 0 {
            r.colors.primary_color
        } else {
            r.color
        },
        position: r.position,
        hoist: r.hoist,
        permissions: r.permissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::parse;
    use std::time::{Duration, Instant};

    const DAN: u64 = 1001;
    const ZED: u64 = 1099;
    const LEFT: u64 = 1050;
    const OPEN: u64 = 210;
    const PRIVATE: u64 = 212;

    fn names() -> Names {
        let mut n = Names {
            members: HashMap::from([(DAN, "Dan D".to_string()), (LEFT, "Left Out".to_string())]),
            erased: HashSet::from([LEFT]),
            channels: HashMap::from([(OPEN, "general".to_string())]),
            emotes: HashMap::from([(7, "pog_2".to_string())]),
            anonymise: true,
            ..Names::default()
        };
        n.add_role(50, "Moderators");
        n
    }

    fn zed() -> User {
        User {
            id: ZED,
            username: "zed".into(),
            global_name: Some("Zed Z".into()),
            bot: false,
        }
    }

    fn all_on() -> ImportOptions {
        ImportOptions {
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
            acknowledged: true,
        }
    }

    fn message(json: &str) -> Message {
        parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn the_table() {
        let n = names();
        let table: &[(&str, &str)] = &[
            ("plain words", "plain words"),
            ("", ""),
            ("<@1001>", "@Dan D"),
            ("<@!1001>", "@Dan D"),
            ("hi <@1001>, hi", "hi @Dan D, hi"),
            ("<@424242>", "@unknown"),
            ("<@&50>", "@&Moderators"),
            ("<@&51>", "@&unknown"),
            ("<#210>", "#general"),
            ("<#999>", "#unknown"),
            ("<:pog:7>", ":pog_2:"),
            ("<a:pog:7>", ":pog_2:"),
            ("<:other_one:8>", ":other_one:"),
            ("<a:other:8>", ":other:"),
            ("<t:1618953630>", "2021-04-20T21:20:30Z"),
            ("<t:1618953630:R>", "2021-04-20T21:20:30Z"),
            // Past what a date can say: left as it is
            ("<t:99999999999999>", "<t:99999999999999>"),
            ("<t:1618953630:Rx>", "<t:1618953630:Rx>"),
            // Not tokens at all
            ("<https://example.net>", "<https://example.net>"),
            ("</command:123>", "</command:123>"),
            ("<id:customize>", "<id:customize>"),
            ("a < b > c", "a < b > c"),
            ("<@>", "<@>"),
            ("<@&>", "<@&>"),
            ("<#>", "<#>"),
            ("<@1001", "<@1001"),
            ("<:pog:>", "<:pog:>"),
            ("<:pog:7", "<:pog:7"),
            ("<::7>", "<::7>"),
            // An id too long for a u64 is no id
            ("<@99999999999999999999999>", "<@99999999999999999999999>"),
            // Words beside multi-byte letters keep both
            ("\u{e9}<@1001>\u{e9}", "\u{e9}@Dan D\u{e9}"),
            ("<\u{e9}>", "<\u{e9}>"),
            // Pings stay plain words: the pane never honours them
            ("@everyone", "@everyone"),
            // Two in a row, and a false start before a real one
            ("<@1001><@1001>", "@Dan D@Dan D"),
            ("<<@1001>", "<@Dan D"),
        ];
        for (input, want) in table {
            assert_eq!(rewrite(input, &n, &[]), *want, "{input}");
        }
    }

    #[test]
    fn hostile_input_stays_linear() {
        let n = names();
        let big = 1024 * 1024;
        let hostile = [
            "<".repeat(big),
            "<@".repeat(big / 2),
            "<@&".repeat(big / 3),
            "<t:".repeat(big / 3),
            "<a:".repeat(big / 3),
            "<:x".repeat(big / 3),
            "<@1".repeat(big / 3),
            "`".repeat(big),
            "``a".repeat(big / 3),
            "`a\n".repeat(big / 3),
            "~".repeat(big),
            "``` ".repeat(big / 4),
            "~~~ ".repeat(big / 4),
            format!("{}{}", "<".repeat(big / 2), "`".repeat(big / 2)),
        ];
        let started = Instant::now();
        for input in &hostile {
            rewrite(input, &n, &[]);
        }
        // Quadratic on a megabyte is hours. This is far over what linear takes, on any machine
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{:?}",
            started.elapsed()
        );
        // What is no token comes out as it went in
        let s = "<".repeat(16 * 1024);
        assert_eq!(rewrite(&s, &n, &[]), s);
        let s = "<@".repeat(8 * 1024);
        assert_eq!(rewrite(&s, &n, &[]), s);
    }

    #[test]
    fn an_ex_members_mention_does_not_name_them() {
        let n = names();
        // Discord's own message says who it was: with anonymise on, that is not used
        let said = rewrite("<@1099>", &n, &[zed()]);
        assert_eq!(said, "@Former member");
        assert!(!said.contains("Zed"));
        // The control: a member's does name them
        assert_eq!(rewrite("<@1001>", &n, &[zed()]), "@Dan D");
        // ... and so does an ex-member's, with anonymise off, from the message's own list
        let off = Names {
            anonymise: false,
            ..names()
        };
        assert_eq!(rewrite("<@1099>", &off, &[zed()]), "@Zed Z");
        // A bot that left is not a person to protect
        let bot = User { bot: true, ..zed() };
        assert_eq!(rewrite("<@1099>", &n, &[bot]), "@Zed Z");
    }

    #[test]
    fn someone_left_out_is_never_named() {
        let n = names();
        // Read this run, on the list, and left out: an erased one and a held one
        assert_eq!(rewrite("<@1050>", &n, &[]), "@unknown");
        let held = Names {
            erased: HashSet::new(),
            held: HashSet::from([LEFT]),
            ..names()
        };
        assert_eq!(rewrite("<@1050>", &held, &[]), "@unknown");
        // The control: without the exclusion, the same id is named
        let in_again = Names {
            erased: HashSet::new(),
            ..names()
        };
        assert_eq!(rewrite("<@1050>", &in_again, &[]), "@Left Out");
    }

    #[test]
    fn a_private_channels_name_does_not_leak() {
        let n = names();
        assert_eq!(rewrite("see <#212> now", &n, &[]), "see #unknown now");
        // The control: a public one is named
        assert_eq!(rewrite("see <#210> now", &n, &[]), "see #general now");
        // Whoever fills the map keeps it to that (plan.rs: `open_names`); the pane has
        // nothing more to go on
        assert!(!n.channels.contains_key(&PRIVATE));
    }

    #[test]
    fn code_is_left_alone() {
        let n = names();
        for code in [
            "`<@1001>`",
            "``<@1001>``",
            "``` <@1001>\n<#210> ```",
            "~~~\n<@1001>\n~~~",
            // Never closed: to the end, as `CODE` reads it
            "```\n<@1001>",
            "~~~<@1001>",
        ] {
            assert_eq!(rewrite(code, &n, &[]), code);
        }
        // The control: outside it, in the same text, it is rewritten
        assert_eq!(
            rewrite("<@1001> `<@1001>` <@1001>", &n, &[]),
            "@Dan D `<@1001>` @Dan D"
        );
        assert_eq!(
            rewrite("```x``` <#210> ~~~y~~~ <#210>", &n, &[]),
            "```x``` #general ~~~y~~~ #general"
        );
        // A backtick with no partner on its line is no code
        assert_eq!(
            rewrite("` <@1001>\n` <@1001>", &n, &[]),
            "` @Dan D\n` @Dan D"
        );
        // One tilde is no fence
        assert_eq!(
            rewrite("~ <@1001> ~~ <@1001>", &n, &[]),
            "~ @Dan D ~~ @Dan D"
        );
    }

    #[test]
    fn a_file_name_makes_no_link_and_no_definition() {
        let n = names();
        for evil in [
            r#"x](http://evil"#,
            r#"x]: http://evil"#,
            "x\n[y]: http://evil",
            r#"[a](b)<c>\`d"#,
        ] {
            let m = message(&format!(
                r#"{{"id":"1","author":{{"id":"1001"}},"attachments":[{{"id":"2","filename":{}}}]}}"#,
                serde_json::to_string(evil).unwrap()
            ));
            let row = row_of(&m, &n, &all_on()).unwrap();
            let line = row.body.strip_prefix("[attachment: ").unwrap();
            let name = line.strip_suffix(']').unwrap();
            // A `\` only of our own, before what would make an address a link (W1-37)
            let unescaped = name
                .replace("\\:", ":")
                .replace("\\.", ".")
                .replace("\\@", "@");
            for c in ['[', ']', '(', ')', '<', '>', '\\', '`', '\n'] {
                assert!(!unescaped.contains(c), "{c} in {name}");
            }
            assert_eq!(row.body.lines().count(), 1, "{}", row.body);
            assert_eq!(row.attachments[0].name, unescaped);
        }
        // An address in such a line is no link either (W1-37), and the file's own name, which
        // no Markdown draws, keeps what it said
        for (evil, line) in [
            ("https://evil.xy", r"[attachment: https\://evil.xy]"),
            ("www.evil.xy", r"[attachment: www\.evil.xy]"),
            ("ceo@evil.xy", r"[attachment: ceo\@evil.xy]"),
        ] {
            let m = message(&format!(
                r#"{{"id":"1","author":{{"id":"1001"}},"attachments":[{{"id":"2","filename":{}}}]}}"#,
                serde_json::to_string(evil).unwrap()
            ));
            let row = row_of(&m, &n, &all_on()).unwrap();
            assert_eq!(row.body, line);
            assert_eq!(row.attachments[0].name, evil);
        }
        // The same goes for what else makes such a line
        let m = message(
            r#"{"id":"1","author":{"id":"1001"},"sticker_items":[{"name":"s](x)"}],
                "poll":{"question":{"text":"q](http://evil)"}}}"#,
        );
        assert_eq!(
            row_of(&m, &n, &all_on()).unwrap().body,
            "[sticker: sx]\n[poll: qhttp\\://evil]"
        );
    }

    #[test]
    fn a_body_is_made_of_what_the_message_had() {
        let n = names();
        let body = |json: &str| row_of(&message(json), &n, &all_on()).unwrap().body;
        assert_eq!(
            body(r#"{"id":"1","author":{"id":"1001"},"content":"hi <@1001>"}"#),
            "hi @Dan D"
        );
        // Empty content with an embed: its title and description, the first one's
        assert_eq!(
            body(
                r##"{"id":"1","author":{"id":"1001"},"embeds":[
                    {"title":"T","description":"D <#210>"},{"title":"other"}]}"##
            ),
            "T\nD #general"
        );
        assert_eq!(
            body(r#"{"id":"1","author":{"id":"1001"},"embeds":[{"url":"https://x"}]}"#),
            "[embed]"
        );
        // Words beside an embed: the words are what was written
        assert_eq!(
            body(r#"{"id":"1","author":{"id":"1001"},"content":"w","embeds":[{"title":"T"}]}"#),
            "w"
        );
        assert_eq!(
            body(
                r#"{"id":"1","author":{"id":"1001"},"message_snapshots":[
                    {"message":{"content":"from <@1099>","mentions":[{"id":"1099","username":"zed"}]}}]}"#
            ),
            "[forwarded]\nfrom @Former member"
        );
        assert_eq!(
            body(
                r#"{"id":"1","author":{"id":"1001"},"content":"look",
                    "attachments":[{"id":"2","filename":"a.png"},{"id":"3","filename":"b.png"}]}"#
            ),
            "look\n[attachment: a.png]\n[attachment: b.png]"
        );
        // A mention growing past the limit cuts cleanly
        let long = "\u{1F389}".repeat(8000);
        let got = body(&format!(
            r#"{{"id":"1","author":{{"id":"1001"}},"content":"{long}"}}"#
        ));
        assert!(got.len() <= IMPORT_BODY_BYTES);
        assert!(got.len() > IMPORT_BODY_BYTES - 4);
    }

    #[test]
    fn anonymise_removes_id_and_name() {
        let m = message(
            r#"{"id":"1","author":{"id":"1099","username":"zed","global_name":"Zed Z"},"content":"x"}"#,
        );
        let row = row_of(&m, &names(), &all_on()).unwrap();
        assert_eq!(row.author, None);
        assert_eq!(row.author_name, FORMER_MEMBER);
        let wire = postcard::to_allocvec(&row).unwrap();
        assert!(!wire.windows(3).any(|w| w == b"zed" || w == b"Zed"));
        // A deleted account is the same
        let m = message(
            r#"{"id":"1","author":{"id":"456226577798135808","username":"Deleted User"},"content":"x"}"#,
        );
        let row = row_of(&m, &names(), &all_on()).unwrap();
        assert_eq!(
            (row.author, row.author_name.as_str()),
            (None, FORMER_MEMBER)
        );
        // A member is not
        let m = message(r#"{"id":"1","author":{"id":"1001","username":"dan"},"content":"x"}"#);
        let row = row_of(&m, &names(), &all_on()).unwrap();
        assert_eq!((row.author, row.author_name.as_str()), (Some(DAN), "Dan D"));
        // A bot that has left is not a person
        let m = message(r#"{"id":"1","author":{"id":"77","username":"oldbot","bot":true}}"#);
        let row = row_of(&m, &names(), &all_on()).unwrap();
        assert_eq!((row.author, row.author_name.as_str()), (Some(77), "oldbot"));
    }

    #[test]
    fn anonymise_off_keeps_them() {
        let off = Names {
            anonymise: false,
            ..names()
        };
        let m = message(
            r#"{"id":"1","author":{"id":"1099","username":"zed","global_name":"Zed Z"},"content":"x"}"#,
        );
        let row = row_of(&m, &off, &all_on()).unwrap();
        assert_eq!((row.author, row.author_name.as_str()), (Some(ZED), "Zed Z"));
    }

    #[test]
    fn a_webhook_goes_under_its_own_name_and_no_id() {
        let m = message(
            r#"{"id":"1","webhook_id":"66","author":{"id":"66","username":"CI bot"},"content":"x"}"#,
        );
        let row = row_of(&m, &names(), &all_on()).unwrap();
        assert_eq!((row.author, row.author_name.as_str()), (None, "CI bot"));
    }

    #[test]
    fn who_asked_to_be_out_gives_no_row_and_who_is_held_does() {
        let erased = Names {
            members: HashMap::new(),
            ..names()
        };
        let m = message(r#"{"id":"1","author":{"id":"1050","username":"l"},"content":"x"}"#);
        assert!(row_of(&m, &erased, &all_on()).is_none());
        // Held: their posts keep coming
        let held = Names {
            erased: HashSet::new(),
            held: HashSet::from([LEFT]),
            ..names()
        };
        let row = row_of(&m, &held, &all_on()).unwrap();
        assert_eq!(row.author, Some(LEFT));
        // Even under a webhook's name there is no id to drop by, so that one comes
        let hook =
            message(r#"{"id":"1","webhook_id":"1050","author":{"id":"1050"},"content":"x"}"#);
        assert!(row_of(&hook, &erased, &all_on()).is_some());
    }

    #[test]
    fn system_messages_advance_high_with_no_row() {
        let n = names();
        for kind in [1, 2, 3, 6, 7, 8, 9, 18, 21] {
            let m = message(&format!(
                r#"{{"id":"1","type":{kind},"author":{{"id":"1001"}},"content":"x"}}"#
            ));
            assert!(row_of(&m, &n, &all_on()).is_none(), "type {kind}");
        }
        for kind in KEPT_KINDS {
            let m = message(&format!(
                r#"{{"id":"1","type":{kind},"author":{{"id":"1001"}},"content":"x"}}"#
            ));
            assert!(row_of(&m, &n, &all_on()).is_some(), "type {kind}");
        }
        // Unset reads as 0, as the docs say
        assert!(row_of(
            &message(r#"{"id":"1","author":{"id":"1001"}}"#),
            &n,
            &all_on()
        )
        .is_some());
    }

    #[test]
    fn a_reply_says_what_it_answers() {
        let n = names();
        let m = message(
            r#"{"id":"2","type":19,"author":{"id":"1001"},"message_reference":{"message_id":"1"}}"#,
        );
        assert_eq!(row_of(&m, &n, &all_on()).unwrap().reply_to, Some(1));
        // A forward has a reference too, and answers nothing
        let m = message(
            r#"{"id":"2","type":0,"author":{"id":"1001"},"message_reference":{"message_id":"1","type":1}}"#,
        );
        assert_eq!(row_of(&m, &n, &all_on()).unwrap().reply_to, None);
    }

    #[test]
    fn pins_and_reactions_follow_their_toggles() {
        let n = names();
        let m = message(
            r#"{"id":"1","author":{"id":"1001"},"pinned":true,"reactions":[
                {"count":3,"emoji":{"name":"👍"}},
                {"count":2,"emoji":{"id":"7","name":"pog"}},
                {"count":1,"emoji":{"id":"8","name":"other"}}]}"#,
        );
        let row = row_of(&m, &n, &all_on()).unwrap();
        assert!(row.pinned);
        let got: Vec<(&str, u32)> = row
            .reactions
            .iter()
            .map(|r| (r.emoji.as_str(), r.count))
            .collect();
        assert_eq!(got, [("\u{1F44D}", 3), (":pog_2:", 2), (":other:", 1)]);
        let off = ImportOptions {
            pins: false,
            reactions: false,
            ..all_on()
        };
        let row = row_of(&m, &n, &off).unwrap();
        assert!(!row.pinned);
        assert!(row.reactions.is_empty());
    }

    #[test]
    fn a_row_is_clipped_to_what_the_relay_takes() {
        let n = names();
        let reactions: Vec<String> = (0..30)
            .map(|i| {
                format!(
                    r#"{{"count":1,"emoji":{{"id":"{}","name":"{}"}}}}"#,
                    900 + i,
                    "x".repeat(40)
                )
            })
            .collect();
        let attachments: Vec<String> = (0..30)
            .map(|i| {
                format!(
                    r#"{{"id":"{i}","filename":"{}","content_type":"{}"}}"#,
                    "f".repeat(300),
                    "m".repeat(100)
                )
            })
            .collect();
        let m = message(&format!(
            r#"{{"id":"1","author":{{"id":"1001"}},"reactions":[{}],"attachments":[{}]}}"#,
            reactions.join(","),
            attachments.join(",")
        ));
        let row = row_of(&m, &n, &all_on()).unwrap();
        assert_eq!(row.reactions.len(), MAX_REACTIONS);
        assert!(row.reactions.iter().all(|r| r.emoji.len() <= EMOJI_BYTES));
        assert_eq!(row.attachments.len(), MAX_ATTACHMENTS);
        assert!(row
            .attachments
            .iter()
            .all(|a| a.name.chars().count() <= 128));
        assert!(row.attachments.iter().all(|a| a.mime.chars().count() <= 64));
    }

    #[test]
    fn attachment_record_has_no_url() {
        let m = message(
            r#"{"id":"1","author":{"id":"1001"},"content":"x","attachments":[{
                "id":"2","filename":"a.png","size":5,"content_type":"image/png",
                "url":"https://cdn.discordapp.com/attachments/1/2/a.png?ex=1&is=2&hm=3",
                "proxy_url":"https://media.discordapp.net/attachments/1/2/a.png"}]}"#,
        );
        let row = row_of(&m, &names(), &all_on()).unwrap();
        assert_eq!(row.attachments[0].id, 2);
        assert_eq!(row.attachments[0].bytes, 5);
        assert_eq!(row.attachments[0].mime, "image/png");
        let wire = postcard::to_allocvec(&row).unwrap();
        assert!(!wire.windows(4).any(|w| w == b"http"));
        let json = format!("{row:?}");
        assert!(
            !json.contains("http") && !json.contains("discordapp"),
            "{json}"
        );
    }

    fn blank(id: u64) -> String {
        format!(r#"{{"id":"{id}","type":0,"author":{{"id":"1001"}},"content":""}}"#)
    }

    fn page(rows: Vec<String>) -> Vec<Message> {
        parse(format!("[{}]", rows.join(",")).as_bytes()).unwrap()
    }

    #[test]
    fn a_blank_first_page_stops_the_run() {
        let rows: Vec<String> = (0..100).map(blank).collect();
        assert!(page_is_blank(&page(rows)));
        // 96 of 100 is over the line, and 95 is not
        let mixed = |blanks: u64| {
            let mut rows: Vec<String> = (0..blanks).map(blank).collect();
            rows.extend((blanks..100).map(|id| {
                format!(r#"{{"id":"{id}","type":0,"author":{{"id":"1001"}},"content":"words"}}"#)
            }));
            page(rows)
        };
        assert!(page_is_blank(&mixed(96)));
        assert!(!page_is_blank(&mixed(95)));
        // A very quiet channel with one blank is still blank
        assert!(page_is_blank(&page(vec![blank(1)])));
    }

    #[test]
    fn one_blank_message_among_real_ones_does_not() {
        let mut rows = vec![blank(0)];
        rows.extend((1..50).map(|id| {
            format!(r#"{{"id":"{id}","type":0,"author":{{"id":"1001"}},"content":"words"}}"#)
        }));
        assert!(!page_is_blank(&page(rows)));
        // Nothing to go on is not blank
        assert!(!page_is_blank(&[]));
        // System messages hold no content on any server, and say nothing either way
        let system: Vec<String> = (0..100)
            .map(|id| format!(r#"{{"id":"{id}","type":7,"author":{{"id":"1001"}}}}"#))
            .collect();
        assert!(!page_is_blank(&page(system)));
        // Everything that can stand in for words does
        for full in [
            r#""attachments":[{"id":"1"}]"#,
            r#""embeds":[{"title":"t"}]"#,
            r#""sticker_items":[{"name":"s"}]"#,
            r#""poll":{"question":{"text":"q"}}"#,
            r#""components":[{"type":1}]"#,
            r#""message_snapshots":[{"message":{"content":"c"}}]"#,
        ] {
            let m = format!(r#"{{"id":"1","type":0,"author":{{"id":"1001"}},{full}}}"#);
            assert!(!page_is_blank(&page(vec![m])), "{full}");
        }
    }

    /// With Message Content on, these hold nothing either. They say nothing either way, so
    /// they count neither as blank nor as what a share of blanks is taken of.
    #[test]
    fn what_is_empty_of_itself_says_nothing_either_way() {
        for own in [
            r#","activity":{"type":1}"#,
            r#","flags":4"#,
            r#","flags":6"#,
        ] {
            let m = format!(r#"{{"id":"1","type":0,"author":{{"id":"1001"}},"content":""{own}}}"#);
            assert!(!page_is_blank(&page(vec![m.clone()])), "{own}");
            // Beside 19 blanks, those still are all of what counts
            let mut rows: Vec<String> = (0..19).map(blank).collect();
            rows.push(m);
            let rows = page(rows);
            assert!(page_is_blank(&rows), "{own}");
            assert!(!blank_page_proves_it(&rows), "{own}");
        }
        // Another flag says nothing of the kind, and the control is that it reads as blank
        let m = r#"{"id":"1","type":0,"author":{"id":"1001"},"content":"","flags":1}"#;
        assert!(page_is_blank(&page(vec![m.to_string()])));
    }

    #[test]
    fn a_page_has_to_be_long_enough_to_prove_it_alone() {
        let rows = |n: u64| page((0..n).map(blank).collect());
        assert!(!blank_page_proves_it(&rows(19)));
        assert!(blank_page_proves_it(&rows(20)));
    }

    fn body_with(n: &Names, content: &str) -> String {
        rewrite(content, n, &[])
    }

    /// Their nick is theirs. What it says in someone else's row must stay words.
    #[test]
    fn a_name_cannot_change_how_a_body_is_drawn() {
        let named = |name: &str| Names {
            members: HashMap::from([(DAN, name.to_string())]),
            ..Names::default()
        };
        for (name, written) in [
            (
                "[Support](https://evil.xy)",
                r"@\[Support\]\(https\://evil.xy\)",
            ),
            ("`tick", r"@\`tick"),
            ("**bold**", r"@\*\*bold\*\*"),
            ("||spoiler||", r"@\|\|spoiler\|\|"),
            ("~~gone~~", r"@\~\~gone\~\~"),
            ("<b>", r"@\<b\>"),
            (r"back\slash", r"@back\\slash"),
            ("_alice_", r"@\_alice\_"),
            ("a_ b", r"@a\_ b"),
            // A bare address would be a link its author never wrote
            ("https://evil.xy", r"@https\://evil.xy"),
            ("HTTP://evil.xy", r"@HTTP\://evil.xy"),
            ("ftp://evil.xy", r"@ftp\://evil.xy"),
            ("www.evil.xy", r"@www\.evil.xy"),
            ("WWW.evil.xy", r"@WWW\.evil.xy"),
            ("see www.evil.xy", r"@see www\.evil.xy"),
            ("xwww.evil.xy", r"@xwww\.evil.xy"),
            // An address is a mailto link there (W1-37)
            ("ceo@evil.xy", r"@ceo\@evil.xy"),
            // The controls: nothing to say, and an `_` inside a name does nothing there
            ("Dan D", "@Dan D"),
            ("dan_d", "@dan_d"),
            ("é_ü", "@é_ü"),
            // Nor does a `.` or a `:` of no address
            ("dr. dan: ok", "@dr. dan: ok"),
            ("evil.xy", "@evil.xy"),
            ("www", "@www"),
            ("ww.dan", "@ww.dan"),
            ("a:/b", "@a:/b"),
            ("é.www", "@é.www"),
        ] {
            assert_eq!(body_with(&named(name), "<@1001>"), written, "{name}");
        }
        // Whoever a mention says it is, however it knows
        let bot = User {
            id: ZED,
            username: "[bot](https://evil.xy)".into(),
            bot: true,
            ..User::default()
        };
        assert_eq!(
            rewrite("<@1099>", &Names::default(), &[bot]),
            r"@\[bot\]\(https\://evil.xy\)"
        );
        // A role's name and a channel's alike. An emote's is a name to look up: it stays
        let mut n = Names::default();
        n.roles.insert(50, "[mods](x)".into());
        n.channels.insert(OPEN, "my_*room*".into());
        n.emotes.insert(7, "pog_2".into());
        assert_eq!(body_with(&n, "<@&50>"), r"@&\[mods\]\(x\)");
        assert_eq!(body_with(&n, "<#210>"), r"#my\_\*room\*");
        assert_eq!(body_with(&n, "<:pog:7>"), ":pog_2:");
        // Code is left as it was written
        assert_eq!(
            body_with(&named("[x](y)"), "`<@1001>` <@1001>"),
            r"`<@1001>` @\[x\]\(y\)"
        );
        // Who wrote a row is not drawn as Markdown, so that stays as they have it
        let m = message(r#"{"id":"1","type":0,"author":{"id":"1001"},"content":"x"}"#);
        let row = row_of(&m, &named("[x](y)"), &all_on()).unwrap();
        assert_eq!(row.author_name, "[x](y)");
    }

    #[test]
    fn a_ban_of_someone_who_left_by_their_own_doing_still_goes() {
        let ban = |id: u64| -> Ban {
            parse(format!(r#"{{"user":{{"id":"{id}"}}}}"#).as_bytes()).unwrap()
        };
        let mut n = Names::default();
        n.add_excluded("1", true, true).unwrap();
        n.add_excluded("2", true, false).unwrap();
        n.add_excluded("3", false, true).unwrap();
        n.add_excluded("4", false, false).unwrap();
        assert!(ban_row(&ban(1), &n).is_some());
        assert!(ban_row(&ban(2), &n).is_some());
        // The controls: asked to be out, and a lifted ban
        assert!(ban_row(&ban(3), &n).is_none());
        assert!(ban_row(&ban(4), &n).is_none());
        assert!(ban_row(&ban(5), &n).is_some());
        // Left out, either way, on every other list
        assert!(n.erased.contains(&1) && n.held.contains(&2));
    }

    #[test]
    fn someone_off_the_list_is_worth_asking_about_only_if_newer_than_it() {
        const LIST: u64 = 5000;
        let m = |json: &str| message(json);
        let by = |id: u64, author: &str| {
            m(&format!(
                r#"{{"id":"{id}","type":0,"author":{{"id":"{author}"}},"content":"x"}}"#
            ))
        };
        let mut n = names();
        n.list_read = LIST;
        assert!(n.may_have_joined_since(&by(LIST, "7")));
        assert!(!n.may_have_joined_since(&by(LIST - 1, "7")));
        // A member, someone erased, a bot, a webhook and a system message have no need
        assert!(!n.may_have_joined_since(&by(LIST, "1001")));
        assert!(!n.may_have_joined_since(&by(LIST, "1050")));
        let bot = r#"{"id":"5000","type":0,"author":{"id":"7","bot":true}}"#;
        assert!(!n.may_have_joined_since(&m(bot)));
        let hook = r#"{"id":"5000","type":0,"webhook_id":"9","author":{"id":"7"}}"#;
        assert!(!n.may_have_joined_since(&m(hook)));
        let join = r#"{"id":"5000","type":7,"author":{"id":"7"}}"#;
        assert!(!n.may_have_joined_since(&m(join)));
        // Nor once they are known
        let found: Member = parse(br#"{"nick":"Late"}"#).unwrap();
        n.add_late(&found, &zed_as(7));
        assert!(!n.may_have_joined_since(&by(LIST, "7")));
        let row = row_of(&by(LIST, "7"), &n, &all_on()).unwrap();
        assert_eq!((row.author, row.author_name.as_str()), (Some(7), "Late"));
        // Off, a row has its id anyway
        n.anonymise = false;
        assert!(!n.may_have_joined_since(&by(LIST, "8")));
    }

    fn zed_as(id: u64) -> User {
        User { id, ..zed() }
    }

    #[test]
    fn bots_pending_and_excluded_are_never_sent() {
        let member = |json: &str| -> Member { parse(json.as_bytes()).unwrap() };
        let n = Names {
            erased: HashSet::from([LEFT]),
            held: HashSet::from([1051]),
            ..Names::default()
        };
        let row = member_row(
            &member(
                r#"{"user":{"id":"1001","username":"dan_d","global_name":"Dan D"},"nick":null,
                    "roles":["50","51"],"joined_at":"2021-04-20T21:20:30.000000+00:00"}"#,
            ),
            &n,
        )
        .unwrap();
        assert_eq!(row.dc_id, DAN);
        assert_eq!(row.username, "dan_d");
        assert_eq!(row.shown_as, "Dan D");
        assert_eq!(row.joined_at, 1_618_953_630);
        assert_eq!(row.roles, [50, 51]);
        // A nickname wins; a null join is 0
        let row = member_row(
            &member(
                r#"{"user":{"id":"1001","username":"dan_d","global_name":"Dan D"},"nick":"Danny"}"#,
            ),
            &n,
        )
        .unwrap();
        assert_eq!((row.shown_as.as_str(), row.joined_at), ("Danny", 0));
        // Nothing but the handle
        let row = member_row(&member(r#"{"user":{"id":"1001","username":"dan_d"}}"#), &n).unwrap();
        assert_eq!(row.shown_as, "");
        for never in [
            r#"{"user":{"id":"1002","username":"b","bot":true}}"#,
            r#"{"user":{"id":"1002","username":"p"},"pending":true}"#,
            r#"{"user":{"id":"1050","username":"erased"}}"#,
            r#"{"user":{"id":"1051","username":"held"}}"#,
            r#"{"roles":["50"]}"#,
        ] {
            assert!(member_row(&member(never), &n).is_none(), "{never}");
        }
        // Bans likewise, and a ban carries no name and no reason
        let ban = |json: &str| -> Ban { parse(json.as_bytes()).unwrap() };
        let row = ban_row(
            &ban(r#"{"user":{"id":"1001","username":"dan_d"},"reason":"spam"}"#),
            &n,
        )
        .unwrap();
        assert_eq!(row.dc_id, DAN);
        let wire = postcard::to_allocvec(&row).unwrap();
        assert!(wire.len() <= 10, "only the id: {} bytes", wire.len());
        assert!(ban_row(&ban(r#"{"user":{"id":"1050"}}"#), &n).is_none());
        assert!(ban_row(&ban(r#"{"reason":"no user"}"#), &n).is_none());
    }

    #[test]
    fn a_roles_row_is_raw_bits_and_never_everyone_or_a_bots() {
        let role = |json: &str| -> Role { parse(json.as_bytes()).unwrap() };
        const GUILD: u64 = 9;
        let row = role_row(
            &role(
                r#"{"id":"5","name":"Admin","color":1,"colors":{"primary_color":2},
                    "position":3,"hoist":true,"permissions":"8"}"#,
            ),
            GUILD,
        )
        .unwrap();
        assert_eq!(row.color, 2);
        assert_eq!(row.permissions, 8);
        assert_eq!(row.position, 3);
        assert!(row.hoist);
        assert_eq!(
            role_row(&role(r#"{"id":"5","color":1}"#), GUILD)
                .unwrap()
                .color,
            1
        );
        assert!(role_row(&role(r#"{"id":"9"}"#), GUILD).is_none());
        assert!(role_row(&role(r#"{"id":"5","managed":true}"#), GUILD).is_none());
        let long = format!(r#"{{"id":"5","name":"{}"}}"#, "\u{e9}".repeat(150));
        assert_eq!(
            role_row(&role(&long), GUILD).unwrap().name.chars().count(),
            100
        );
    }
}
