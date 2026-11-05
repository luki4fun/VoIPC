//! Who a channel takes here, from who it took on Discord. Discord adds up everything a
//! person holds; a gate here is a flat list of groups, each role its own. So this asks
//! role by role, in Discord's own order (topics/permissions), and every doubt closes: a
//! channel someone was kept out of may hold what they were kept from.

use std::collections::HashMap;

use voipc_protocol::discord::{
    ADMINISTRATOR, CONNECT, MANAGE_CHANNELS, MOVE_MEMBERS, MUTE_MEMBERS, READ_MESSAGE_HISTORY,
    SEND_MESSAGES, SPEAK, STREAM, VIEW_CHANNEL,
};
use voipc_protocol::types::ImportGate;

use crate::model::{Channel, Overwrite, Role, STAGE, VOICE};
use crate::Note;

/// The most groups one gate holds (`gates::MAX_GROUPS` on the relay).
pub const MAX_GROUPS: usize = 16;

/// From Discord's help pages, not its API docs: the run on a real server checks it.
const STAGE_MODERATOR: u64 = MANAGE_CHANNELS | MUTE_MEMBERS | MOVE_MEMBERS;
/// What the lists here carry. An overwrite of anything else is only noted.
const CARRIED: u64 = VIEW_CHANNEL | SEND_MESSAGES | READ_MESSAGE_HISTORY | CONNECT | SPEAK | STREAM;

fn apply(p: u64, overwrite: Option<&Overwrite>) -> u64 {
    match overwrite {
        Some(o) => (p & !o.deny) | o.allow,
        None => p,
    }
}

/// Discord's order for one role alone, or with `role` 0 for @everyone alone.
pub fn one_role(
    everyone: u64,
    role: u64,
    of_everyone: Option<&Overwrite>,
    of_role: Option<&Overwrite>,
) -> u64 {
    let base = everyone | role;
    if base & ADMINISTRATOR != 0 {
        return u64::MAX;
    }
    apply(apply(base, of_everyone), of_role)
}

/// Discord's order for a whole member: what the bot itself can do.
pub fn of_member(
    guild: u64,
    roles: &[Role],
    member: u64,
    held: &[u64],
    overwrites: &[Overwrite],
) -> u64 {
    let bits_of = |id: u64| {
        roles
            .iter()
            .find(|r| r.id == id)
            .map_or(0, |r| r.permissions)
    };
    let mut base = bits_of(guild);
    for id in held {
        base |= bits_of(*id);
    }
    if base & ADMINISTRATOR != 0 {
        return u64::MAX;
    }
    let mut p = apply(base, overwrite_of(overwrites, guild, 0));
    let (mut allow, mut deny) = (0, 0);
    for o in overwrites
        .iter()
        .filter(|o| o.kind == 0 && held.contains(&o.id))
    {
        allow |= o.allow;
        deny |= o.deny;
    }
    p = (p & !deny) | allow;
    apply(p, overwrite_of(overwrites, member, 1))
}

fn overwrite_of(overwrites: &[Overwrite], id: u64, kind: u8) -> Option<&Overwrite> {
    overwrites.iter().find(|o| o.id == id && o.kind == kind)
}

/// Whether the bot can read this channel's history. Asking one it cannot is a 403, and
/// Discord counts those; without READ_MESSAGE_HISTORY it would answer nothing, silently.
pub fn bot_reads(guild: u64, roles: &[Role], bot: u64, held: &[u64], ch: &Channel) -> bool {
    let p = of_member(guild, roles, bot, held, &ch.permission_overwrites);
    let needs = VIEW_CHANNEL
        | READ_MESSAGE_HISTORY
        | if matches!(ch.kind, VOICE | STAGE) {
            CONNECT
        } else {
            0
        };
    p & needs == needs
}

/// A role that takes a place in a gate.
#[derive(Debug, Clone)]
pub struct Seat<'a> {
    pub role: &'a Role,
    pub members: u64,
}

/// What the roles of a server come to, for every channel.
#[derive(Debug, Clone)]
pub struct Server<'a> {
    pub guild: u64,
    pub everyone: u64,
    pub seats: Vec<Seat<'a>>,
}

impl<'a> Server<'a> {
    /// A managed role is a bot's, and a role with no members would only use up a place.
    /// `counts` None: Discord would not say, so every role counts as having someone.
    pub fn new(guild: u64, roles: &'a [Role], counts: Option<&HashMap<u64, u64>>) -> Self {
        let everyone = roles
            .iter()
            .find(|r| r.id == guild)
            .map_or(0, |r| r.permissions);
        let seats = roles
            .iter()
            .filter(|r| r.id != guild && !r.managed)
            .map(|role| Seat {
                role,
                members: counts.map_or(1, |c| c.get(&role.id).copied().unwrap_or(0)),
            })
            .filter(|s| s.members > 0)
            .collect();
        Server {
            guild,
            everyone,
            seats,
        }
    }
}

/// A channel's two lists, and what could not be carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelGates {
    pub see: ImportGate,
    pub speak: ImportGate,
    /// Someone was kept out on Discord, so its history needs the operator's tick.
    pub private: bool,
    /// Why, for the tick screen. "" when it is not private.
    pub private_why: String,
    /// Someone here could read what they could not on Discord: its messages start off.
    pub history_off: bool,
    pub screen_share: bool,
    pub notes: Vec<Note>,
}

fn sees(p: u64, voice: bool) -> bool {
    p & VIEW_CHANNEL != 0 && (!voice || p & CONNECT != 0)
}

fn speaks(p: u64, kind: u8) -> bool {
    let voice = matches!(kind, VOICE | STAGE);
    // Who cannot see cannot speak, whatever the bit says
    sees(p, voice)
        && match kind {
            VOICE => p & SPEAK != 0,
            STAGE => p & STAGE_MODERATOR == STAGE_MODERATOR,
            _ => p & SEND_MESSAGES != 0,
        }
}

fn names(seats: &[&Seat]) -> String {
    let names: Vec<String> = seats.iter().map(|s| format!("@{}", s.role.name)).collect();
    names.join(", ")
}

/// The largest roles, up to what a gate holds. Those over go without: closed, not open.
fn list_of(passing: Vec<&Seat>, label: &str, ch: &Channel, notes: &mut Vec<Note>) -> ImportGate {
    if passing.is_empty() {
        return ImportGate::Closed;
    }
    let mut passing = passing;
    passing.sort_by(|a, b| {
        b.members
            .cmp(&a.members)
            .then(b.role.position.cmp(&a.role.position))
            .then(a.role.id.cmp(&b.role.id))
    });
    if passing.len() > MAX_GROUPS {
        notes.push(Note::kept(
            "over_16",
            Some(ch.id),
            format!(
                "#{}: one gate holds {MAX_GROUPS} groups. These lose {label} here: {}",
                ch.name,
                names(&passing[MAX_GROUPS..])
            ),
        ));
        passing.truncate(MAX_GROUPS);
    }
    ImportGate::Roles(passing.iter().map(|s| s.role.id).collect())
}

/// The lists of one channel, with every toggle on.
pub fn gates_of(server: &Server, ch: &Channel) -> ChannelGates {
    let voice = ch.is_voice();
    let of_everyone = overwrite_of(&ch.permission_overwrites, server.guild, 0);
    let everyone = one_role(server.everyone, 0, of_everyone, None);
    let bits: Vec<(&Seat, u64)> = server
        .seats
        .iter()
        .map(|seat| {
            let of_role = overwrite_of(&ch.permission_overwrites, seat.role.id, 0);
            (
                seat,
                one_role(server.everyone, seat.role.permissions, of_everyone, of_role),
            )
        })
        .collect();
    let mut notes = Vec::new();

    let seeing: Vec<&Seat> = bits
        .iter()
        .filter(|(_, p)| sees(*p, voice))
        .map(|(s, _)| *s)
        .collect();
    let kept_out: Vec<&Seat> = bits
        .iter()
        .filter(|(_, p)| !sees(*p, voice))
        .map(|(s, _)| *s)
        .collect();
    let everyone_sees = sees(everyone, voice);
    let (see, private, private_why) = if everyone_sees && kept_out.is_empty() {
        (ImportGate::Open, false, String::new())
    } else {
        let why = if everyone_sees {
            notes.push(Note::kept(
                "view_denied",
                Some(ch.id),
                format!(
                    "#{}: {} could not see it on Discord, so it is closed here, and people \
                     with no role lose it. Someone holding that role and another passes here.",
                    ch.name,
                    names(&kept_out)
                ),
            ));
            format!("Hidden from {} on Discord.", names(&kept_out))
        } else {
            "Hidden from @everyone on Discord.".to_string()
        };
        (list_of(seeing.clone(), "it", ch, &mut notes), true, why)
    };

    let speaking: Vec<&Seat> = bits
        .iter()
        .filter(|(_, p)| speaks(*p, ch.kind))
        .map(|(s, _)| *s)
        .collect();
    let speak = if speaks(everyone, ch.kind) {
        // The "Muted" role: nothing is revealed, `voipc:restrict` covers it, and closing
        // would leave everyone without a role read-only
        let muted: Vec<&Seat> = bits
            .iter()
            .filter(|(_, p)| sees(*p, voice) && !speaks(*p, ch.kind))
            .map(|(s, _)| *s)
            .collect();
        if !muted.is_empty() {
            notes.push(Note::kept(
                "speak_denied",
                Some(ch.id),
                format!(
                    "#{}: {} could not write on Discord, and can here until a moderator acts.",
                    ch.name,
                    names(&muted)
                ),
            ));
        }
        ImportGate::Open
    } else {
        list_of(speaking.clone(), "writing", ch, &mut notes)
    };

    let no_history = (everyone_sees && everyone & READ_MESSAGE_HISTORY == 0)
        || seeing.iter().any(|seat| {
            bits.iter()
                .any(|(s, p)| s.role.id == seat.role.id && p & READ_MESSAGE_HISTORY == 0)
        });
    if no_history {
        notes.push(Note::kept(
            "no_history",
            Some(ch.id),
            format!(
                "#{}: some could see it without reading its history, so its messages start off.",
                ch.name
            ),
        ));
    }

    // A voice channel either takes a screen share or not. One a list could do on Discord stays on
    let screen_share = !voice
        || everyone & STREAM != 0
        || speaking.iter().any(|seat| {
            bits.iter()
                .any(|(s, p)| s.role.id == seat.role.id && p & STREAM != 0)
        });
    if voice && (everyone & STREAM == 0 && bits.iter().any(|(_, p)| p & STREAM != 0)) {
        notes.push(Note::kept(
            "partial_stream",
            Some(ch.id),
            format!(
                "#{}: only some could share a screen on Discord. Here it is on or off for all.",
                ch.name
            ),
        ));
    }

    for o in &ch.permission_overwrites {
        if o.kind == 1 {
            // Only ever the id: the dry-run lists no members
            notes.push(Note::screen(
                "member_overwrite",
                Some(ch.id),
                format!(
                    "#{}: Discord account {} had a rule of their own, which does not come.",
                    ch.name, o.id
                ),
            ));
        }
    }
    if ch
        .permission_overwrites
        .iter()
        .any(|o| (o.allow | o.deny) & !CARRIED != 0)
    {
        notes.push(Note::kept(
            "other_overwrite",
            Some(ch.id),
            format!(
                "#{}: rules on other things (reactions, files and the like) do not come.",
                ch.name
            ),
        ));
    }

    ChannelGates {
        see,
        speak,
        private,
        private_why,
        history_off: no_history,
        screen_share,
        notes,
    }
}

/// What the toggles do to the lists. With permissions off, what was open stays open and
/// all else closes, so it opens nothing that was not. With roles off no group exists for a
/// list to name, so it closes too.
pub fn with_toggles(gates: &mut ChannelGates, permissions: bool, roles: bool, ch: &Channel) {
    let was = (gates.see.clone(), gates.speak.clone());
    for gate in [&mut gates.see, &mut gates.speak] {
        if matches!(gate, ImportGate::Roles(_)) && !(permissions && roles) {
            *gate = ImportGate::Closed;
        }
    }
    if was != (gates.see.clone(), gates.speak.clone()) {
        gates.notes.push(Note::kept(
            "gate_closed",
            Some(ch.id),
            format!(
                "#{}: closed to all but admins until you set its gate.",
                ch.name
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUILD: u64 = 1000;
    const BASICS: u64 = VIEW_CHANNEL | SEND_MESSAGES | READ_MESSAGE_HISTORY | CONNECT | SPEAK;

    fn role(id: u64, name: &str, permissions: u64) -> Role {
        Role {
            id,
            name: name.into(),
            permissions,
            position: id as u32,
            ..Role::default()
        }
    }

    fn everyone(bits: u64) -> Role {
        role(GUILD, "@everyone", bits)
    }

    fn deny(id: u64, bits: u64) -> Overwrite {
        Overwrite {
            id,
            kind: 0,
            allow: 0,
            deny: bits,
        }
    }

    fn allow(id: u64, bits: u64) -> Overwrite {
        Overwrite {
            id,
            kind: 0,
            allow: bits,
            deny: 0,
        }
    }

    fn channel(kind: u8, overwrites: Vec<Overwrite>) -> Channel {
        Channel {
            id: 5,
            kind,
            name: "room".into(),
            permission_overwrites: overwrites,
            ..Channel::default()
        }
    }

    fn all_have_members(roles: &[Role]) -> HashMap<u64, u64> {
        roles.iter().map(|r| (r.id, 3)).collect()
    }

    fn gates(roles: &[Role], ch: &Channel) -> ChannelGates {
        let counts = all_have_members(roles);
        gates_of(&Server::new(GUILD, roles, Some(&counts)), ch)
    }

    #[test]
    fn the_order_is_discords_everyone_deny_then_allow_then_role() {
        let e = |allow: u64, deny: u64| Overwrite {
            id: GUILD,
            kind: 0,
            allow,
            deny,
        };
        let r = |allow: u64, deny: u64| Overwrite {
            id: 1,
            kind: 0,
            allow,
            deny,
        };
        const A: u64 = 1 << 10;
        const B: u64 = 1 << 11;
        // (base of @everyone, of the role, its overwrite, the role's overwrite, want)
        type Case = (u64, u64, Option<Overwrite>, Option<Overwrite>, u64);
        let table: &[Case] = &[
            (A, 0, None, None, A),
            (0, A, None, None, A),
            // A role's base does not beat @everyone's deny: the deny goes on the sum
            (0, A, Some(e(0, A)), None, 0),
            (A, 0, Some(e(0, A)), None, 0),
            // Allow after deny, in one overwrite
            (A, 0, Some(e(A, A)), None, A),
            // The role's overwrite comes last: its allow beats @everyone's deny
            (A, 0, Some(e(0, A)), Some(r(A, 0)), A),
            // ... and its deny beats @everyone's allow
            (0, 0, Some(e(A, 0)), Some(r(0, A)), 0),
            // Allow after deny, on the role too
            (0, 0, None, Some(r(A, A)), A),
            // Only the bits named move
            (A | B, 0, Some(e(0, A)), None, B),
            (A | B, 0, None, Some(r(0, B)), A),
        ];
        for (base, role, of_everyone, of_role, want) in table {
            assert_eq!(
                one_role(*base, *role, of_everyone.as_ref(), of_role.as_ref()),
                *want,
                "{base} {role} {of_everyone:?} {of_role:?}"
            );
        }
    }

    #[test]
    fn administrator_passes_every_overwrite() {
        let of_everyone = deny(GUILD, u64::MAX);
        let of_role = deny(1, u64::MAX);
        assert_eq!(
            one_role(0, ADMINISTRATOR, Some(&of_everyone), Some(&of_role)),
            u64::MAX
        );
        // So it takes a place in every list, even one denying it outright
        let roles = [
            everyone(BASICS),
            role(1, "Root", ADMINISTRATOR),
            role(2, "Plain", 0),
        ];
        let got = gates(
            &roles,
            &channel(0, vec![deny(GUILD, VIEW_CHANNEL), deny(1, VIEW_CHANNEL)]),
        );
        assert_eq!(got.see, ImportGate::Roles(vec![1]));
        // The control: without the bit, the same deny keeps it out
        let roles = [everyone(BASICS), role(1, "Root", 0), role(2, "Plain", 0)];
        let got = gates(
            &roles,
            &channel(0, vec![deny(GUILD, VIEW_CHANNEL), deny(1, VIEW_CHANNEL)]),
        );
        assert_eq!(got.see, ImportGate::Closed);
    }

    #[test]
    fn the_bot_is_read_as_a_whole_member() {
        let roles = [
            everyone(BASICS),
            role(1, "Bots", 0),
            role(2, "Other", ADMINISTRATOR),
        ];
        let plain = channel(0, vec![]);
        assert!(bot_reads(GUILD, &roles, 9, &[1], &plain));
        // A denied @everyone, with the bot's role allowed
        let ch = channel(0, vec![deny(GUILD, VIEW_CHANNEL), allow(1, VIEW_CHANNEL)]);
        assert!(bot_reads(GUILD, &roles, 9, &[1], &ch));
        assert!(!bot_reads(GUILD, &roles, 9, &[], &ch));
        // No history means Discord answers nothing, silently: that is not reading
        let ch = channel(0, vec![deny(GUILD, READ_MESSAGE_HISTORY)]);
        assert!(!bot_reads(GUILD, &roles, 9, &[1], &ch));
        // A rule of its own comes last
        let ch = channel(
            0,
            vec![Overwrite {
                id: 9,
                kind: 1,
                allow: 0,
                deny: VIEW_CHANNEL,
            }],
        );
        assert!(!bot_reads(GUILD, &roles, 9, &[1], &ch));
        // Administrator passes all of it
        assert!(bot_reads(GUILD, &roles, 9, &[2], &ch));
        // A voice channel also takes CONNECT
        let ch = channel(VOICE, vec![deny(GUILD, CONNECT)]);
        assert!(!bot_reads(GUILD, &roles, 9, &[1], &ch));
    }

    #[test]
    fn an_open_channel_is_open() {
        let roles = [everyone(BASICS), role(1, "A", 0)];
        let got = gates(&roles, &channel(0, vec![]));
        assert_eq!(got.see, ImportGate::Open);
        assert_eq!(got.speak, ImportGate::Open);
        assert!(!got.private);
        assert!(!got.history_off);
    }

    #[test]
    fn a_private_channel_nobody_passes_is_closed_not_open() {
        let roles = [everyone(BASICS), role(1, "A", 0), role(2, "B", 0)];
        let got = gates(&roles, &channel(0, vec![deny(GUILD, VIEW_CHANNEL)]));
        assert_eq!(got.see, ImportGate::Closed);
        assert_eq!(got.speak, ImportGate::Closed);
        assert!(got.private);
        assert!(got.private_why.contains("@everyone"));
    }

    #[test]
    fn an_empty_role_list_reads_as_closed() {
        // Every way to reach a list with nobody on it
        for ch in [
            channel(0, vec![deny(GUILD, VIEW_CHANNEL)]),
            channel(0, vec![deny(GUILD, SEND_MESSAGES)]),
        ] {
            let got = gates(&[everyone(BASICS)], &ch);
            assert_ne!(got.see, ImportGate::Roles(vec![]));
            assert_ne!(got.speak, ImportGate::Roles(vec![]));
            assert_ne!(got.speak, ImportGate::Open);
        }
    }

    #[test]
    fn a_role_allowed_where_everyone_is_denied_is_listed() {
        let roles = [everyone(BASICS), role(1, "A", 0), role(2, "B", 0)];
        let got = gates(
            &roles,
            &channel(0, vec![deny(GUILD, VIEW_CHANNEL), allow(1, VIEW_CHANNEL)]),
        );
        assert_eq!(got.see, ImportGate::Roles(vec![1]));
        // Who cannot see cannot write, whatever else they hold
        assert_eq!(got.speak, ImportGate::Roles(vec![1]));
    }

    #[test]
    fn more_than_16_keep_the_largest_and_name_the_rest() {
        let mut roles = vec![everyone(BASICS)];
        let mut overwrites = vec![deny(GUILD, VIEW_CHANNEL)];
        let mut counts = HashMap::new();
        for i in 1..=20u64 {
            roles.push(role(i, &format!("R{i}"), 0));
            overwrites.push(allow(i, VIEW_CHANNEL));
            counts.insert(i, i * 10);
        }
        let got = gates_of(
            &Server::new(GUILD, &roles, Some(&counts)),
            &channel(0, overwrites),
        );
        let ImportGate::Roles(list) = &got.see else {
            panic!("{:?}", got.see);
        };
        assert_eq!(list.len(), MAX_GROUPS);
        assert_eq!(list[0], 20);
        assert!(list.contains(&5));
        assert!(!list.contains(&4));
        let note = got.notes.iter().find(|n| n.kind == "over_16").unwrap();
        assert!(
            note.text.contains("@R1") && note.text.contains("@R4"),
            "{}",
            note.text
        );
        assert!(!note.text.contains("@R5"), "{}", note.text);
    }

    #[test]
    fn exactly_16_lose_nobody() {
        let mut roles = vec![everyone(BASICS)];
        let mut overwrites = vec![deny(GUILD, VIEW_CHANNEL)];
        for i in 1..=16u64 {
            roles.push(role(i, &format!("R{i}"), 0));
            overwrites.push(allow(i, VIEW_CHANNEL));
        }
        let got = gates(&roles, &channel(0, overwrites));
        assert!(matches!(&got.see, ImportGate::Roles(l) if l.len() == 16));
        assert!(!got.notes.iter().any(|n| n.kind == "over_16"));
    }

    #[test]
    fn managed_and_memberless_roles_take_no_place() {
        let mut managed = role(1, "Bot", 0);
        managed.managed = true;
        let roles = [
            everyone(BASICS),
            managed,
            role(2, "Nobody", 0),
            role(3, "Real", 0),
        ];
        let counts = HashMap::from([(1, 5), (3, 5)]);
        let server = Server::new(GUILD, &roles, Some(&counts));
        let got = gates_of(
            &server,
            &channel(
                0,
                vec![
                    deny(GUILD, VIEW_CHANNEL),
                    allow(1, VIEW_CHANNEL),
                    allow(2, VIEW_CHANNEL),
                    allow(3, VIEW_CHANNEL),
                ],
            ),
        );
        assert_eq!(got.see, ImportGate::Roles(vec![3]));
        // A deny on either makes nothing private: nobody here is kept out by it
        let got = gates_of(
            &server,
            &channel(0, vec![deny(1, VIEW_CHANNEL), deny(2, VIEW_CHANNEL)]),
        );
        assert_eq!(got.see, ImportGate::Open);
        // Discord would not say who has what: they all count, and none is lost
        let unknown = Server::new(GUILD, &roles, None);
        assert_eq!(unknown.seats.len(), 2);
    }

    #[test]
    fn a_view_deny_on_a_public_channel_needs_the_tick_and_stays_closed() {
        let roles = [everyone(BASICS), role(1, "Muted", 0), role(2, "Mods", 0)];
        let got = gates(&roles, &channel(0, vec![deny(1, VIEW_CHANNEL)]));
        assert!(got.private);
        assert!(got.private_why.contains("@Muted"));
        // Every other role; people with no role lose it, and that is said
        assert_eq!(got.see, ImportGate::Roles(vec![2]));
        let note = got.notes.iter().find(|n| n.kind == "view_denied").unwrap();
        assert!(note.text.contains("no role lose it"));
        // Only one role, and that one is the denied one: nobody passes
        let roles = [everyone(BASICS), role(1, "Muted", 0)];
        let got = gates(&roles, &channel(0, vec![deny(1, VIEW_CHANNEL)]));
        assert_eq!(got.see, ImportGate::Closed);
    }

    #[test]
    fn a_send_deny_on_a_public_channel_stays_open_and_is_noted() {
        let roles = [everyone(BASICS), role(1, "Muted", 0), role(2, "Mods", 0)];
        let got = gates(&roles, &channel(0, vec![deny(1, SEND_MESSAGES)]));
        assert_eq!(got.see, ImportGate::Open);
        assert_eq!(got.speak, ImportGate::Open);
        assert!(!got.private);
        let note = got.notes.iter().find(|n| n.kind == "speak_denied").unwrap();
        assert!(note.text.contains("@Muted"));
        assert!(!note.text.contains("@Mods"));
        // The control: nobody denied, nothing noted
        let got = gates(&roles, &channel(0, vec![]));
        assert!(!got.notes.iter().any(|n| n.kind == "speak_denied"));
    }

    #[test]
    fn a_read_only_channel_lists_who_may_write() {
        let roles = [everyone(BASICS), role(1, "Editors", 0), role(2, "Plain", 0)];
        let got = gates(
            &roles,
            &channel(5, vec![deny(GUILD, SEND_MESSAGES), allow(1, SEND_MESSAGES)]),
        );
        assert_eq!(got.see, ImportGate::Open);
        assert_eq!(got.speak, ImportGate::Roles(vec![1]));
    }

    #[test]
    fn permissions_off_closes_private_channels_and_opens_nothing_new() {
        let roles = [everyone(BASICS), role(1, "Staff", 0)];
        let private = channel(0, vec![deny(GUILD, VIEW_CHANNEL), allow(1, VIEW_CHANNEL)]);
        let mut got = gates(&roles, &private);
        assert_eq!(got.see, ImportGate::Roles(vec![1]));
        with_toggles(&mut got, false, true, &private);
        assert_eq!(got.see, ImportGate::Closed);
        assert_eq!(got.speak, ImportGate::Closed);
        assert!(got.notes.iter().any(|n| n.kind == "gate_closed"));
        // Public stays public
        let public = channel(0, vec![]);
        let mut got = gates(&roles, &public);
        with_toggles(&mut got, false, true, &public);
        assert_eq!(got.see, ImportGate::Open);
        assert_eq!(got.speak, ImportGate::Open);
        assert!(!got.notes.iter().any(|n| n.kind == "gate_closed"));
        // A public channel only some could write in: writing does not open
        let read_only = channel(0, vec![deny(GUILD, SEND_MESSAGES), allow(1, SEND_MESSAGES)]);
        let mut got = gates(&roles, &read_only);
        with_toggles(&mut got, false, true, &read_only);
        assert_eq!(got.see, ImportGate::Open);
        assert_eq!(got.speak, ImportGate::Closed);
    }

    #[test]
    fn roles_off_turns_every_list_of_roles_closed() {
        let roles = [everyone(BASICS), role(1, "Staff", 0)];
        let private = channel(0, vec![deny(GUILD, VIEW_CHANNEL), allow(1, VIEW_CHANNEL)]);
        let mut got = gates(&roles, &private);
        with_toggles(&mut got, true, false, &private);
        assert_eq!(got.see, ImportGate::Closed);
        assert_eq!(got.speak, ImportGate::Closed);
        // What was open needs no group
        let public = channel(0, vec![]);
        let mut got = gates(&roles, &public);
        with_toggles(&mut got, true, false, &public);
        assert_eq!(got.see, ImportGate::Open);
        // Both on: nothing moves
        let mut got = gates(&roles, &private);
        with_toggles(&mut got, true, true, &private);
        assert_eq!(got.see, ImportGate::Roles(vec![1]));
    }

    #[test]
    fn can_see_cannot_connect_closes_a_voice_channel() {
        let roles = [everyone(BASICS), role(1, "Members", 0)];
        let got = gates(
            &roles,
            &channel(VOICE, vec![deny(GUILD, CONNECT), allow(1, CONNECT)]),
        );
        assert_eq!(got.see, ImportGate::Roles(vec![1]));
        assert!(got.private);
        // A text channel has no such bit to mind
        let got = gates(&roles, &channel(0, vec![deny(GUILD, CONNECT)]));
        assert_eq!(got.see, ImportGate::Open);
    }

    #[test]
    fn voice_speaks_by_speak_and_a_stage_by_its_moderators() {
        let roles = [
            everyone(BASICS),
            role(1, "Hosts", STAGE_MODERATOR),
            role(2, "Almost", MANAGE_CHANNELS | MUTE_MEMBERS),
        ];
        let got = gates(&roles, &channel(VOICE, vec![]));
        assert_eq!(got.speak, ImportGate::Open);
        let got = gates(
            &roles,
            &channel(VOICE, vec![deny(GUILD, SPEAK), allow(2, SPEAK)]),
        );
        assert_eq!(got.speak, ImportGate::Roles(vec![2]));
        let got = gates(&roles, &channel(STAGE, vec![]));
        assert_eq!(got.see, ImportGate::Open);
        assert_eq!(got.speak, ImportGate::Roles(vec![1]));
    }

    #[test]
    fn view_without_history_starts_messages_off() {
        let roles = [everyone(BASICS), role(1, "A", 0)];
        let got = gates(&roles, &channel(0, vec![deny(GUILD, READ_MESSAGE_HISTORY)]));
        assert!(got.history_off);
        assert!(got.notes.iter().any(|n| n.kind == "no_history"));
        // One listed role without it is enough
        let got = gates(
            &roles,
            &channel(
                0,
                vec![
                    deny(GUILD, VIEW_CHANNEL),
                    Overwrite {
                        id: 1,
                        kind: 0,
                        allow: VIEW_CHANNEL,
                        deny: READ_MESSAGE_HISTORY,
                    },
                ],
            ),
        );
        assert!(got.history_off);
        // A role that cannot see at all, with no history either, changes nothing
        let got = gates(
            &roles,
            &channel(
                0,
                vec![
                    deny(GUILD, VIEW_CHANNEL | READ_MESSAGE_HISTORY),
                    allow(1, VIEW_CHANNEL | READ_MESSAGE_HISTORY),
                ],
            ),
        );
        assert!(!got.history_off);
    }

    #[test]
    fn a_stream_someone_had_keeps_the_share_on() {
        let roles = [everyone(BASICS), role(1, "Streamers", STREAM)];
        let got = gates(&roles, &channel(VOICE, vec![]));
        assert!(got.screen_share);
        assert!(got.notes.iter().any(|n| n.kind == "partial_stream"));
        // Nobody had it
        let roles = [everyone(BASICS), role(1, "Plain", 0)];
        let got = gates(&roles, &channel(VOICE, vec![]));
        assert!(!got.screen_share);
        // Everyone had it
        let roles = [everyone(BASICS | STREAM), role(1, "Plain", 0)];
        let got = gates(&roles, &channel(VOICE, vec![]));
        assert!(got.screen_share);
        assert!(!got.notes.iter().any(|n| n.kind == "partial_stream"));
        // It means nothing on a text channel
        assert!(gates(&roles, &channel(0, vec![])).screen_share);
    }

    #[test]
    fn a_rule_for_one_person_is_noted_for_the_screen_and_carries_nothing() {
        let roles = [everyone(BASICS), role(1, "A", 0)];
        let ch = channel(
            0,
            vec![
                deny(GUILD, VIEW_CHANNEL),
                Overwrite {
                    id: 777,
                    kind: 1,
                    allow: VIEW_CHANNEL,
                    deny: 0,
                },
            ],
        );
        let got = gates(&roles, &ch);
        assert_eq!(got.see, ImportGate::Closed);
        let note = got
            .notes
            .iter()
            .find(|n| n.kind == "member_overwrite")
            .unwrap();
        assert!(note.text.contains("777"));
        // It names someone, so it never goes to the relay
        assert!(!note.keep);
    }

    #[test]
    fn rules_on_what_has_no_list_are_noted() {
        const ADD_REACTIONS: u64 = 1 << 6;
        let roles = [everyone(BASICS), role(1, "A", 0)];
        let got = gates(&roles, &channel(0, vec![deny(1, ADD_REACTIONS)]));
        assert!(got.notes.iter().any(|n| n.kind == "other_overwrite"));
        assert_eq!(got.see, ImportGate::Open);
        let got = gates(&roles, &channel(0, vec![deny(1, SEND_MESSAGES)]));
        assert!(!got.notes.iter().any(|n| n.kind == "other_overwrite"));
    }

    #[test]
    fn no_everyone_role_read_opens_nothing() {
        // @everyone missing from the answer: no base bits, so closed rather than open
        let roles = [role(1, "A", 0)];
        let got = gates(&roles, &channel(0, vec![]));
        assert_eq!(got.see, ImportGate::Closed);
    }
}
