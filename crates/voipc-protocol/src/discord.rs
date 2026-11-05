//! What Discord's ids and permission bits come to here (protocol v20). One table: the
//! relay turns a role's raw `permissions` into privileges with it, so that a client
//! can never name one, and the desktop importer's dry-run says beforehand what it
//! will be. Bits as docs.discord.com/developers/topics/permissions has them (2026-11-04).

/// When Discord's ids start: a snowflake holds its millisecond, counted from here.
pub const DISCORD_EPOCH_MS: i64 = 1_420_070_400_000;

/// The millisecond a Discord id was made in, Unix time.
pub fn snowflake_ms(id: i64) -> i64 {
    (id >> 22) + DISCORD_EPOCH_MS
}

/// The lowest id a millisecond can have: ids at or past it are that old or newer.
pub fn snowflake_floor(ms: i64) -> i64 {
    (ms - DISCORD_EPOCH_MS).clamp(0, i64::MAX >> 22) << 22
}

pub const KICK_MEMBERS: u64 = 1 << 1;
pub const BAN_MEMBERS: u64 = 1 << 2;
pub const ADMINISTRATOR: u64 = 1 << 3;
pub const MANAGE_CHANNELS: u64 = 1 << 4;
pub const MANAGE_GUILD: u64 = 1 << 5;
pub const VIEW_AUDIT_LOG: u64 = 1 << 7;
pub const PRIORITY_SPEAKER: u64 = 1 << 8;
pub const STREAM: u64 = 1 << 9;
pub const VIEW_CHANNEL: u64 = 1 << 10;
pub const SEND_MESSAGES: u64 = 1 << 11;
pub const MANAGE_MESSAGES: u64 = 1 << 13;
pub const READ_MESSAGE_HISTORY: u64 = 1 << 16;
pub const MENTION_EVERYONE: u64 = 1 << 17;
pub const VIEW_GUILD_INSIGHTS: u64 = 1 << 19;
pub const CONNECT: u64 = 1 << 20;
pub const SPEAK: u64 = 1 << 21;
pub const MUTE_MEMBERS: u64 = 1 << 22;
pub const DEAFEN_MEMBERS: u64 = 1 << 23;
pub const MOVE_MEMBERS: u64 = 1 << 24;
pub const MANAGE_NICKNAMES: u64 = 1 << 27;
pub const MANAGE_ROLES: u64 = 1 << 28;
pub const MANAGE_WEBHOOKS: u64 = 1 << 29;
pub const MANAGE_GUILD_EXPRESSIONS: u64 = 1 << 30;
pub const MANAGE_EVENTS: u64 = 1 << 33;
pub const MANAGE_THREADS: u64 = 1 << 34;
pub const MODERATE_MEMBERS: u64 = 1 << 40;
pub const CREATE_GUILD_EXPRESSIONS: u64 = 1 << 43;
pub const PIN_MESSAGES: u64 = 1 << 51;
pub const BYPASS_SLOWMODE: u64 = 1 << 52;

/// Every privilege there is, one by one, which is what ADMINISTRATOR comes to: never `*`
/// and no wildcard, since `*` also sees behind anonymous channels. A test in the relay
/// holds this to what it registers.
pub const FINE_SCOPES: &[&str] = &[
    "roles:admin",
    "users:admin",
    "users:read",
    "voipc:ban",
    "voipc:bans",
    "voipc:channels",
    "voipc:emotes",
    "voipc:hide",
    "voipc:kick",
    "voipc:mention_all",
    "voipc:modlog",
    "voipc:profiles",
    "voipc:reports",
    "voipc:restrict",
];

/// The power bits with a home here.
const MAPPED: &[(u64, &[&str])] = &[
    (KICK_MEMBERS, &["voipc:kick"]),
    (BAN_MEMBERS, &["voipc:ban", "voipc:bans"]),
    (MANAGE_CHANNELS, &["voipc:channels"]),
    (VIEW_AUDIT_LOG, &["users:read", "voipc:modlog"]),
    (MANAGE_MESSAGES, &["voipc:hide", "voipc:reports"]),
    (MENTION_EVERYONE, &["voipc:mention_all"]),
    (MUTE_MEMBERS, &["voipc:restrict"]),
    (MODERATE_MEMBERS, &["voipc:restrict"]),
    (MANAGE_NICKNAMES, &["voipc:profiles"]),
    (MANAGE_ROLES, &["roles:admin", "users:admin", "users:read"]),
    (MANAGE_GUILD_EXPRESSIONS, &["voipc:emotes"]),
];

/// The power bits with nothing here, for the dry-run and the report.
const LOSSY: &[(u64, &str)] = &[
    (MANAGE_GUILD, "MANAGE_GUILD"),
    (PRIORITY_SPEAKER, "PRIORITY_SPEAKER"),
    (VIEW_GUILD_INSIGHTS, "VIEW_GUILD_INSIGHTS"),
    (DEAFEN_MEMBERS, "DEAFEN_MEMBERS"),
    (MOVE_MEMBERS, "MOVE_MEMBERS"),
    (MANAGE_WEBHOOKS, "MANAGE_WEBHOOKS"),
    (MANAGE_EVENTS, "MANAGE_EVENTS"),
    (MANAGE_THREADS, "MANAGE_THREADS"),
    (CREATE_GUILD_EXPRESSIONS, "CREATE_GUILD_EXPRESSIONS"),
    (PIN_MESSAGES, "PIN_MESSAGES"),
    (BYPASS_SLOWMODE, "BYPASS_SLOWMODE"),
];

/// What a role's `permissions` come to here, sorted, each once.
pub fn scopes_of(bits: u64) -> Vec<&'static str> {
    if bits & ADMINISTRATOR != 0 {
        return FINE_SCOPES.to_vec();
    }
    let mut scopes: Vec<&'static str> = MAPPED
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .flat_map(|(_, names)| names.iter().copied())
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    scopes
}

/// The power in `bits` that comes to nothing here, by Discord's names.
pub fn lossy(bits: u64) -> Vec<&'static str> {
    LOSSY
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_bits_map_to_a_wildcard() {
        let every_bit = (0..64).map(|b| 1u64 << b).chain([u64::MAX]);
        for bits in every_bit {
            for scope in scopes_of(bits) {
                assert!(!scope.contains('*'), "{bits:#x} gave {scope}");
            }
        }
        // ... and the loop above had something to look at
        assert!(!scopes_of(u64::MAX).is_empty());
    }

    #[test]
    fn administrator_is_every_fine_scope() {
        assert_eq!(scopes_of(ADMINISTRATOR), FINE_SCOPES);
        // Whatever else the role holds
        assert_eq!(scopes_of(ADMINISTRATOR | KICK_MEMBERS), FINE_SCOPES);
        // Every other bit together reaches them too: no privilege lacks a row in the table
        assert_eq!(scopes_of(!ADMINISTRATOR), FINE_SCOPES);
        assert_ne!(scopes_of(KICK_MEMBERS), FINE_SCOPES);
    }

    /// The owner's map, row by row, with today's bit values written out so that a typo
    /// in a constant cannot agree with itself.
    #[test]
    fn each_row_of_the_table() {
        let rows: &[(u64, &[&str])] = &[
            (1 << 1, &["voipc:kick"]),
            (1 << 2, &["voipc:ban", "voipc:bans"]),
            (1 << 4, &["voipc:channels"]),
            (1 << 7, &["users:read", "voipc:modlog"]),
            (1 << 13, &["voipc:hide", "voipc:reports"]),
            (1 << 17, &["voipc:mention_all"]),
            (1 << 22, &["voipc:restrict"]),
            (1 << 40, &["voipc:restrict"]),
            (1 << 27, &["voipc:profiles"]),
            (1 << 28, &["roles:admin", "users:admin", "users:read"]),
            (1 << 30, &["voipc:emotes"]),
        ];
        for (bit, want) in rows {
            assert_eq!(&scopes_of(*bit), want, "{bit:#x}");
        }
        assert_eq!(rows.len(), MAPPED.len());
        // Two rows reaching one privilege name it once
        assert_eq!(scopes_of((1 << 22) | (1 << 40)), ["voipc:restrict"]);
        assert_eq!(
            scopes_of((1 << 7) | (1 << 28)),
            ["roles:admin", "users:admin", "users:read", "voipc:modlog"]
        );
        // What is not power comes to nothing
        assert!(scopes_of(VIEW_CHANNEL | SEND_MESSAGES | CONNECT | SPEAK | STREAM).is_empty());
        assert!(scopes_of(0).is_empty());
    }

    #[test]
    fn lossy_names_what_has_no_home() {
        let rows: &[(u64, &str)] = &[
            (1 << 5, "MANAGE_GUILD"),
            (1 << 8, "PRIORITY_SPEAKER"),
            (1 << 19, "VIEW_GUILD_INSIGHTS"),
            (1 << 23, "DEAFEN_MEMBERS"),
            (1 << 24, "MOVE_MEMBERS"),
            (1 << 29, "MANAGE_WEBHOOKS"),
            (1 << 33, "MANAGE_EVENTS"),
            (1 << 34, "MANAGE_THREADS"),
            (1 << 43, "CREATE_GUILD_EXPRESSIONS"),
            (1 << 51, "PIN_MESSAGES"),
            (1 << 52, "BYPASS_SLOWMODE"),
        ];
        for (bit, name) in rows {
            assert_eq!(lossy(*bit), [*name]);
            assert!(scopes_of(*bit).is_empty(), "{name} has a home after all");
        }
        assert_eq!(rows.len(), LOSSY.len());
        // A bit with a home, and one that is no power, are not lost
        assert!(lossy(KICK_MEMBERS | VIEW_CHANNEL).is_empty());
        assert_eq!(lossy(KICK_MEMBERS | MOVE_MEMBERS), ["MOVE_MEMBERS"]);
    }

    #[test]
    fn a_snowflake_holds_its_millisecond() {
        // Discord's own example, topics/reference: 2016-04-30 11:18:25.796 UTC
        assert_eq!(snowflake_ms(175_928_847_299_117_063), 1_462_015_105_796);
        let id = snowflake_floor(1_462_015_105_796);
        assert_eq!(snowflake_ms(id), 1_462_015_105_796);
        assert!(id <= 175_928_847_299_117_063);
        assert!(snowflake_floor(1_462_015_105_797) > 175_928_847_299_117_063);
        // Before Discord: every id is newer. Far ahead: every id is older, and no wrap
        assert_eq!(snowflake_floor(0), 0);
        assert!(snowflake_floor(i64::MAX) > 175_928_847_299_117_063);
    }
}
