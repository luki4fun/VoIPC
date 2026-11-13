//! Opt-in relay accounts (`[accounts]` in the config), on l4f-accounts.
//!
//! What the relay keeps for an account, and nothing more:
//! - its name and an Argon2id hash of a secret the client derives from the
//!   password (`AuthContinue::Secret`), never the password itself;
//! - the second-factor secret, sealed under the key file, which lives outside
//!   the database;
//! - device public keys, roles, an audit log with hashed addresses;
//! - the account's vault: items the client encrypted under a key derived
//!   from the password, which the relay never sees;
//! - the public half of the account's identity key.
//!
//! Guests are untouched. With `mode = "off"` (the default) none of this exists.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use dashmap::DashMap;
use l4f_accounts::keys::Keys;
use l4f_accounts::model::{AccountId, SessionInfo, User};
use l4f_accounts::scope::ScopeDef;
use l4f_accounts::service::{
    Accounts, Config, Ctx, Host, InviteForm, LoginStep, NewSession, RegisterForm,
};
use l4f_accounts::store::{PutBlob, PutLimited, Store, StoreConn};
use l4f_accounts::{pow, scope, util, IpMode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use voipc_crypto::bind::Binding;
use voipc_protocol::codec::{decode_client_msg, encode_server_msg};
use voipc_protocol::conv::dm_parties;
use voipc_protocol::messages::{
    AccountReply, AccountRequest, AuthContinue, AuthStep, ClientMessage, ServerMessage,
};
use voipc_protocol::types::{
    AccountInfo, AccountStart, ChatMod, PowChallenge, PreKeyBundleData, Registration,
    RelayAccounts, ReportTaker, VaultBlob, PIN_PAGES,
};

use crate::config::{AccountsConfig, AccountsMode, RegistrationMode};
use crate::control::ControlTx;
use crate::state::ServerState;

/// The privileges this relay checks (1.7). Each is a scope a group (an l4f
/// role) can hand out; `*` holds them all and alone sees behind anonymity.
pub const KICK: &str = "voipc:kick";
pub const BAN: &str = "voipc:ban";
pub const BANS: &str = "voipc:bans";
pub const RESTRICT: &str = "voipc:restrict";
pub const HIDE: &str = "voipc:hide";
pub const REPORTS: &str = "voipc:reports";
pub const MODLOG: &str = "voipc:modlog";
pub const CHANNELS: &str = "voipc:channels";
pub const PROFILES: &str = "voipc:profiles";
pub const MENTION_ALL: &str = "voipc:mention_all";
pub const EMOTES: &str = "voipc:emotes";
pub use voipc_protocol::types::SHARE_HISTORY;
const APP_SCOPES: &[ScopeDef] = &[
    ScopeDef {
        name: MENTION_ALL,
        description: "Call on everybody with @everyone, @here and a group's @&badge",
    },
    ScopeDef {
        name: PROFILES,
        description: "Clear display names and profile pictures of accounts holding no more",
    },
    ScopeDef {
        name: KICK,
        description: "Kick people from the server and from any channel",
    },
    ScopeDef {
        name: BAN,
        description: "Ban people, by address and account, and remove the posts of someone banned",
    },
    ScopeDef {
        name: BANS,
        description:
            "See the ban list, lift bans, ban an account by name, and remove the posts of someone banned",
    },
    ScopeDef {
        name: RESTRICT,
        description: "Mute someone's voice or stop their channel posts for a while",
    },
    ScopeDef {
        name: HIDE,
        description: "Hide a message from its readers, who can still open it",
    },
    ScopeDef {
        name: REPORTS,
        description: "Receive what people report",
    },
    ScopeDef {
        name: MODLOG,
        description: "Read the moderation log",
    },
    ScopeDef {
        name: CHANNELS,
        description: "Change the settings and gates of the channels you can see, and invite people to the one you stand in",
    },
    ScopeDef {
        name: EMOTES,
        description: "Add, rename and remove the server's emotes and stickers",
    },
    ScopeDef {
        name: SHARE_HISTORY,
        description: "Share your own history with newcomers, once you turn that on",
    },
];
/// Before 1.7, the moderator's one scope: what it became. Frozen: a group from
/// then keeps what it granted, and never gains what it did not.
const MODERATE_WAS: &str = "voipc:moderate";
const MODERATE_BECAME: [&str; 3] = [BAN, CHANNELS, KICK];
/// The moderator group of a database made now, sorted as a role keeps them.
const MODERATOR: [&str; 7] = [BAN, CHANNELS, HIDE, KICK, MODLOG, REPORTS, RESTRICT];
const MODERATOR_SAYS: &str =
    "Kick, ban, restrict, hide messages, read the moderation log, take reports and change the channels' settings";
/// What the group said before 1.10.
const MODERATOR_SAID: &str = "Kick, ban and change the channels' settings";

/// What a session may do, one bit per privilege (`UserSession::can`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Powers(u16);

impl Powers {
    pub const KICK: Powers = Powers(1);
    pub const BAN: Powers = Powers(1 << 1);
    pub const BANS: Powers = Powers(1 << 2);
    pub const CHANNELS: Powers = Powers(1 << 3);
    pub const EMOTES: Powers = Powers(1 << 4);
    pub const USERS_READ: Powers = Powers(1 << 5);
    pub const USERS_ADMIN: Powers = Powers(1 << 6);
    pub const ROLES_ADMIN: Powers = Powers(1 << 7);
    pub const RESTRICT: Powers = Powers(1 << 8);

    pub fn of(scopes: &[String]) -> Powers {
        [
            (KICK, Powers::KICK),
            (BAN, Powers::BAN),
            (BANS, Powers::BANS),
            (RESTRICT, Powers::RESTRICT),
            (CHANNELS, Powers::CHANNELS),
            (EMOTES, Powers::EMOTES),
            ("users:read", Powers::USERS_READ),
            ("users:admin", Powers::USERS_ADMIN),
            ("roles:admin", Powers::ROLES_ADMIN),
        ]
        .into_iter()
        .filter(|(s, _)| scope::allowed(scopes, s))
        .fold(Powers::default(), |a, (_, p)| Powers(a.0 | p.0))
    }

    pub fn has(self, p: Powers) -> bool {
        self.0 & p.0 == p.0
    }
}

/// The groups an account counts in, and the badges they show (1.7). A group
/// counts only once its privileges apply (`scope::covers` by the effective
/// scopes), so one waiting for codes neither opens a gated channel nor shows
/// its badge; a group with no privileges always counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Standing {
    pub groups: Vec<String>,
    pub badges: Vec<String>,
    /// All of them; `badges` is what a row shows. Told only to the account.
    pub my_badges: Vec<String>,
}

/// `*`: every privilege. `allowed` never answers for it (a wildcard is no
/// requirement); `covers` does.
pub fn is_star(scopes: &[String]) -> bool {
    scope::covers(scopes, &["*".to_string()])
}

/// The vault's blobs, in l4f's storage under this namespace.
const VAULT_NS: &str = "voipc";
const VAULT_MAX_ITEMS: i64 = 64;
/// Under the 64 KiB control frame a write travels in, with room for its name.
const VAULT_MAX_BYTES: usize = 48 * 1024;
/// The whole vault: it goes to a signing-in device in one `AuthStep::Vault`
/// frame, so it must fit in one with every item's framing (about 80 bytes
/// each at most) on top.
const VAULT_TOTAL_BYTES: usize = 56 * 1024;
/// Pins past what that frame holds (`pins.N`), each page a vault item at most, asked for
/// one at a time after sign-in.
pub(crate) const PINS_NS: &str = "voipc.pins";
const PINS_TOTAL_BYTES: usize = PIN_PAGES as usize * VAULT_MAX_BYTES;

/// The derived secret is 32 bytes; l4f stores it as if it were a password.
const SECRET_LEN: usize = 32;
/// Sign-in answers a connection may send before it is dropped: a mistyped
/// code or two, not a guessing loop (l4f limits wrong codes per account too).
const MAX_CONTINUES: u32 = 6;
/// A step the client answers by itself.
const STEP_WAIT: Duration = Duration::from_secs(30);
/// A person typing a code from their phone.
const TOTP_WAIT: Duration = Duration::from_secs(120);
/// The proof of work and making a vault.
const REGISTER_WAIT: Duration = Duration::from_secs(60);
/// Sign-in work at once: a password hash, a device signature, the database.
/// Held only while the relay works, never while it waits for the client or a
/// person typing a code: held across those, a few addresses re-dialling every
/// minute kept every permit and nobody could sign in (1.0 audit H1-02). The
/// connections themselves are bounded by the pre-authentication pool.
const PENDING_SIGN_INS: usize = 32;
/// Of those, at most this many from one address (IPv6: one /64), so one
/// address cannot hold them all.
const PENDING_PER_ADDRESS: usize = 4;
/// Closes a connection that only asked something (`AccountStart::Providers`,
/// `Provider`); its `AuthStep` was the answer.
const ANSWERED: &str = "Answered.";
/// What a sign-in hears when no permit is free.
pub const BUSY: &str = "the server is busy signing people in — try again in a moment";
/// How often every signed-in connection is checked against the database: a
/// role taken away, codes reset or a session ended from the server's shell
/// (a separate process) reaches a live connection within this.
pub const REVALIDATE_MINUTES: u64 = 5;

/// Dispatch over the two backends the relay is built with: the statement text
/// is the same (`$N` binds by number on both), the pool types are not.
macro_rules! db {
    ($store:expr, $pool:ident => $body:block) => {
        match $store {
            Store::Pg(b) => {
                let $pool = &b.0;
                $body
            }
            Store::Lite(b) => {
                let $pool = &b.0;
                $body
            }
        }
    };
}

mod admin;
pub mod archive;
pub mod at_connect;
pub mod bans;
pub mod gates;
pub mod import;
#[cfg(test)]
mod kept_sync_tests;
pub mod layout;
pub mod links;
pub mod log;
pub mod modlog;
pub mod placeholder;
pub mod profile;
pub mod provider;
pub mod restrict;

/// What l4f calls back into.
pub struct RelayHost {
    cfg: Arc<Config>,
    store: Store,
}

impl Host for RelayHost {
    fn config(&self) -> Arc<Config> {
        self.cfg.clone()
    }

    async fn export(&self, user: AccountId) -> Vec<(String, serde_json::Value)> {
        let identity = identity_of(&self.store, user).await.ok().flatten();
        let mut entries = vec![(
            "identity_key".into(),
            serde_json::json!(identity.map(hex::encode)),
        )];
        // What the move holds on them. The archive's rows have a way of their own, `ArchiveMine`
        match placeholder::discord_member(&self.store, user).await {
            Ok(Some(member)) => entries.push(("discord_member".into(), member)),
            Ok(None) => {}
            // Not left out without a word: that would read as nothing being held
            Err(e) => {
                tracing::warn!("reading what the move holds for an export: {e:#}");
                entries.push((
                    "discord_member".into(),
                    serde_json::json!("could not be read"),
                ));
            }
        }
        // Discord ids unlinked from it, kept so that deleting it takes their posts (W1-34)
        let unlinked: sqlx::Result<Vec<i64>> = db!(&self.store, pool => {
            sqlx::query_scalar(
                "SELECT CAST(dc_id AS BIGINT) FROM voipc_dc_unlinked WHERE account = $1 ORDER BY dc_id",
            )
            .bind(&user.0[..])
            .fetch_all(pool)
            .await
        });
        match unlinked {
            Ok(ids) if ids.is_empty() => {}
            Ok(ids) => entries.push((
                "discord_unlinked".into(),
                serde_json::json!(ids.iter().map(i64::to_string).collect::<Vec<_>>()),
            )),
            Err(e) => {
                tracing::warn!("reading unlinked Discord ids for an export: {e:#}");
                entries.push((
                    "discord_unlinked".into(),
                    serde_json::json!("could not be read"),
                ));
            }
        }
        entries
    }

    /// The relay's rows go with the account through their foreign keys. What outlives it
    /// is that no import makes them again, nor brings back what they wrote: someone who
    /// deleted their account stays gone, whether they are in the move's table, or linked
    /// Discord only later, or unlinked it first and are only in the other.
    async fn delete_user(
        &self,
        tx: StoreConn<'_>,
        user: AccountId,
        _delete_owned: bool,
    ) -> sqlx::Result<()> {
        macro_rules! keep_them_out {
            ($c:expr) => {{
                let c = $c;
                let mut ids: Vec<i64> = sqlx::query_scalar(
                    "SELECT CAST(dc_id AS BIGINT) FROM voipc_placeholders WHERE account = $1",
                )
                .bind(&user.0[..])
                .fetch_all(&mut *c)
                .await?;
                let linked: Vec<Vec<u8>> = sqlx::query_scalar(
                    "SELECT ext_id FROM acct_credentials WHERE user_id = $1 AND kind = $2",
                )
                .bind(&user.0[..])
                .bind(l4f_accounts::oauth::Kind::Discord.credential_kind())
                .fetch_all(&mut *c)
                .await?;
                ids.extend(linked.iter().filter_map(|s| {
                    std::str::from_utf8(s).ok()?.parse::<i64>().ok()
                }));
                // And the ones it unlinked before (W1-34)
                let unlinked: Vec<i64> = sqlx::query_scalar(
                    "SELECT CAST(dc_id AS BIGINT) FROM voipc_dc_unlinked WHERE account = $1",
                )
                .bind(&user.0[..])
                .fetch_all(&mut *c)
                .await?;
                ids.extend(unlinked);
                for id in ids {
                    sqlx::query(
                        "INSERT INTO voipc_import_excluded (dc_id, own, erase, at) VALUES ($1, $2, $3, $4)
                         ON CONFLICT (dc_id) DO UPDATE SET own = excluded.own, erase = excluded.erase",
                    )
                    .bind(id)
                    .bind(true)
                    .bind(true)
                    .bind(util::now())
                    .execute(&mut *c)
                    .await?;
                }
            }};
        }
        // Rows naming them that only the sweep can reach (`log::sweep_tombstones`)
        macro_rules! stone {
            ($c:expr) => {
                sqlx::query("INSERT INTO voipc_tombstones (account, at) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                    .bind(&user.0[..])
                    .bind(util::now())
                    .execute(&mut *$c)
                    .await?
            };
        }
        match tx {
            StoreConn::Pg(c) => {
                keep_them_out!(&mut *c);
                stone!(c);
            }
            StoreConn::Lite(c) => {
                keep_them_out!(&mut *c);
                stone!(c);
            }
        }
        Ok(())
    }
}

pub struct Relay {
    pub accounts: Accounts<RelayHost>,
    pub relay_id: [u8; 16],
    pub required: bool,
    pub registration: RegistrationMode,
    pub cloud: bool,
    /// Bytes per account: its vault, and its stored messages again.
    pub quota: i64,
    /// The longest a stored message is kept.
    pub retention_ms: i64,
    /// How many messages a channel keeps at most.
    pub kept_window: i64,
    /// How many accounts a channel keeps messages for; 0 for no limit.
    pub kept_seats: i64,
    /// What each account that posted lately has left under `quota`, and when it was counted.
    pub kept_room: DashMap<[u8; 16], (i64, i64)>,
    /// Each account's log key changes lately: how many, and the last (`log::publish`). In
    /// memory: a restart forgets them, which costs one more change at the short wait.
    pub(crate) logkey_changes: DashMap<[u8; 16], (u32, i64)>,
    /// How long the moderation log keeps a row.
    pub modlog_days: u32,
    /// How long an account the move made waits for someone to open it. 0: for good.
    pub unclaimed_days: u32,
    /// The groups the move made that hold no privileges (`placeholder::load`). In memory,
    /// so the new-member wait costs no query.
    pub imported_groups: DashMap<String, ()>,
    /// How long what came from Discord is kept, by when it was written. 0: until removed.
    pub archive_days: u32,
    /// What people said about the archive's rows (`archive::load`).
    archive_wishes: std::sync::RwLock<Arc<archive::Wishes>>,
    /// Which Discord channels hold rows, and when that was read (`archive::channels`).
    archive_held:
        tokio::sync::Mutex<Option<(std::time::Instant, Arc<std::collections::HashSet<i64>>)>>,
    /// Something in the archive is to go: `archive::tidy` looks now.
    pub(crate) archive_kick: tokio::sync::Notify,
    /// Searches of the archive at once, whatever the number of members.
    pub(crate) archive_searches: Semaphore,
    pending: Arc<Semaphore>,
    pending_by_address: Arc<DashMap<String, usize>>,
    pow_key: Vec<u8>,
    /// One sign-up with a link at a time, from the gate's peek to its commit.
    link_lock: tokio::sync::Mutex<()>,
    /// What address bans are hashed with (`crate::bans`).
    ban_key: Vec<u8>,
    /// What an account the move made gets its id from, and what `Reset` shows for it.
    placeholder_key: Vec<u8>,
    /// Recovery-key resets per address (`ConnLimits` key): each fetches a
    /// vault's recovery slot, so they are few (5, then one per 3 minutes).
    resets: DashMap<IpAddr, crate::state::RateLimiter>,
    /// Sign-ins out at a provider's page.
    providers: provider::Flows,
    /// Pairings in progress, and how often each account may ask for one.
    pairs: DashMap<u64, provider::PairLink>,
    pair_asks: DashMap<AccountId, crate::state::RateLimiter>,
    /// One claim of a provider's account at a time (`provider::claim`).
    claiming: tokio::sync::Mutex<()>,
    /// What every connect is told before its join, kept a while (W2-16).
    pub(crate) at_connect: at_connect::AtConnect,
}

/// A key slot as `voipc_crypto::account::Vault` writes it: version byte,
/// salt (32), DEK id (8), nonce (12), the wrapped DEK and its tag (48).
const SLOT_LEN: usize = 1 + 32 + 8 + 12 + 48;
/// `slot.reset`: the reset key's public half (Ed25519).
const SLOT_RESET: &str = voipc_crypto::account::SLOT_RESET;
const RESET_KEY_LEN: usize = 32;
/// What a recovery key that does not open the account hears, on a real one and a decoy.
const NOT_THIS_KEY: &str = "That recovery key is not this account's.";

/// One sign-in in progress: a share of the relay's slots and of its
/// address's, both given back when it ends.
pub struct PendingSlot {
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    by_address: Arc<DashMap<String, usize>>,
    key: String,
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        if let Some(mut n) = self.by_address.get_mut(&self.key) {
            *n = n.saturating_sub(1);
        }
        self.by_address.remove_if(&self.key, |_, n| *n == 0);
    }
}

impl Relay {
    /// Connects, migrates, and reads or makes the relay id and the master key.
    pub async fn open(cfg: &AccountsConfig) -> Result<Relay> {
        let store = Store::connect(&cfg.database)
            .await
            .with_context(|| format!("accounts database {}", redact(&cfg.database)))?;
        owner_only_sqlite(&cfg.database);
        // Migrated first: whether this database was made with a key decides
        // whether a key file that is not there may be made anew.
        l4f_accounts::migrate::run(&store)
            .await
            .context("account migrations")?;
        migrate_relay(&store).await.context("relay migrations")?;
        let made_with_key = db!(&store, pool => {
            sqlx::query_scalar::<_, Vec<u8>>("SELECT v FROM voipc_meta WHERE k = 'key_check'").fetch_optional(pool).await?
        })
        .is_some();
        let master = master_key(&cfg.key_file, made_with_key)?;
        let mut relay = Self::open_with(cfg, store, &master).await?;
        if !cfg.public_url.is_empty() {
            match provider::from_env()? {
                Some(oauth) => relay = relay.with_providers(oauth),
                None => warn!(
                    "[accounts] public_url is set, but no VOIPC_OAUTH_<PROVIDER>_ID and _SECRET are"
                ),
            }
        }
        Ok(relay)
    }

    pub async fn open_with(cfg: &AccountsConfig, store: Store, master: &[u8]) -> Result<Relay> {
        l4f_accounts::migrate::run(&store)
            .await
            .context("account migrations")?;
        migrate_relay(&store).await.context("relay migrations")?;
        let relay_id = relay_id(&store).await?;
        let keys = Keys::new(master, None).map_err(|e| anyhow!("accounts master key: {e:?}"))?;
        check_key(&store, &keys).await?;
        let pow_key = keys.subkey("voipc-pow").to_vec();
        let ban_key = keys.subkey("voipc-ban").to_vec();
        let placeholder_key = keys.subkey("voipc-placeholder").to_vec();
        let ip_salt = keys.subkey("voipc-ip").to_vec();
        let host = RelayHost {
            cfg: Arc::new(l4f_config(cfg, relay_id)),
            store: store.clone(),
        };
        // l4f seeds `user` with what `default_user_scopes` names, on a database with no such
        // row. Here that list says what needs no codes, so the row is made first, empty.
        // It never regrows (l4f: builtin_roles_are_seeded_once_and_never_regrow).
        store
            .ensure_builtin_roles(&[])
            .await
            .context("built-in groups")?;
        let accounts = Accounts::build(
            store.clone(),
            keys,
            Arc::default(),
            host,
            APP_SCOPES,
            Some(pow_key.clone()),
            ip_salt,
        )
        .await?;
        ensure_moderator(&store).await?;
        let relay = Relay {
            accounts,
            relay_id,
            required: cfg.mode == AccountsMode::Required,
            registration: cfg.registration,
            cloud: cfg.cloud,
            quota: i64::from(cfg.quota_mb) * 1024 * 1024,
            retention_ms: i64::from(cfg.retention_days) * 86_400_000,
            kept_window: i64::from(cfg.kept_window.max(1)),
            kept_seats: i64::from(cfg.kept_seats),
            kept_room: DashMap::new(),
            modlog_days: cfg.modlog_days,
            unclaimed_days: cfg.unclaimed_days,
            imported_groups: DashMap::new(),
            archive_days: cfg.archive_days,
            archive_wishes: std::sync::RwLock::default(),
            archive_held: tokio::sync::Mutex::default(),
            archive_kick: tokio::sync::Notify::new(),
            archive_searches: Semaphore::new(archive::SEARCHES),
            pending: Arc::new(Semaphore::new(PENDING_SIGN_INS)),
            pending_by_address: Arc::default(),
            pow_key,
            link_lock: tokio::sync::Mutex::new(()),
            ban_key,
            placeholder_key,
            resets: DashMap::new(),
            providers: provider::Flows::default(),
            pairs: DashMap::new(),
            pair_asks: DashMap::new(),
            claiming: tokio::sync::Mutex::new(()),
            logkey_changes: DashMap::new(),
            at_connect: Default::default(),
        };
        placeholder::load(&relay).await?;
        archive::load(&relay).await?;
        Ok(relay)
    }

    pub fn store(&self) -> &Store {
        &self.accounts.store
    }
}

/// A copy of a SQLite accounts database at `path`, a new file private from
/// the start; safe while the relay runs (`VACUUM INTO`). Postgres has pg_dump.
pub async fn sqlite_backup(store: &Store, path: &std::path::Path) -> Result<()> {
    let Store::Lite(b) = store else {
        bail!("this is Postgres: back it up with pg_dump");
    };
    // Made empty and private first: SQLite copies into an empty file
    crate::fsutil::create_private(path, &[])
        .with_context(|| format!("creating {}", path.display()))?;
    let to = path.to_string_lossy();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "VACUUM INTO '{}'",
        to.replace('\'', "''")
    )))
    .execute(&b.0)
    .await
    .with_context(|| format!("backing up to {to}"))?;
    crate::fsutil::owner_only(path)
        .with_context(|| format!("making {to} readable by this user only"))
}

impl Relay {
    /// A slot for a sign-in from `ip`, or `None` while the relay, or that
    /// address, has as many open as it takes.
    pub fn pending_slot(&self, ip: IpAddr) -> Option<PendingSlot> {
        let key = util::ip_key(ip);
        {
            let mut n = self.pending_by_address.entry(key.clone()).or_insert(0);
            if *n >= PENDING_PER_ADDRESS {
                return None;
            }
            *n += 1;
        }
        // From here on, dropping the slot gives the address's share back.
        let mut slot = PendingSlot {
            _permit: None,
            by_address: self.pending_by_address.clone(),
            key,
        };
        slot._permit = Some(self.pending.clone().try_acquire_owned().ok()?);
        Some(slot)
    }

    pub fn info(&self) -> RelayAccounts {
        RelayAccounts {
            required: self.required,
            registration: match self.registration {
                RegistrationMode::Open => Registration::Open,
                RegistrationMode::Invite => Registration::Invite,
                RegistrationMode::Closed => Registration::Closed,
            },
            cloud: self.cloud,
            relay_id: self.relay_id,
        }
    }

    pub fn ctx(&self, ip: IpAddr, app_version: &str) -> Ctx {
        Ctx {
            ip,
            ua: format!("VoIPC {app_version}"),
            sec_fetch_site: String::new(),
        }
    }

    /// Whether a guest's name (without its #tag) is an account's here.
    pub async fn is_account_name(&self, name: &str) -> Result<bool> {
        let Ok(name) = scope::normalize_username(name, &[]) else {
            return Ok(false);
        };
        Ok(self.store().user_by_username(&name).await?.is_some())
    }

    pub async fn vault(&self, user: AccountId) -> Result<Vec<VaultBlob>> {
        Ok(self
            .store()
            .blobs(user, VAULT_NS)
            .await?
            .into_iter()
            .map(|b| VaultBlob {
                k: b.k,
                v: b.v,
                version: b.version,
            })
            .collect())
    }

    /// One page of an account's pins.
    pub async fn vault_page(&self, user: AccountId, k: &str) -> Result<AccountReply> {
        if !is_pin_page(k) {
            return Ok(refused("VaultPage", "No such page."));
        }
        let blob = self
            .store()
            .blob(user, PINS_NS, k)
            .await?
            .map(|b| VaultBlob {
                k: b.k,
                v: b.v,
                version: b.version,
            });
        Ok(AccountReply::VaultPageFound {
            k: k.to_string(),
            blob,
        })
    }

    /// What an account holds in `ns`. l4f adds up all of an account's blobs against the
    /// quota it is handed, and each namespace here has a bound of its own.
    async fn blob_bytes(&self, user: AccountId, ns: &str) -> Result<i64> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar("SELECT CAST(COALESCE(SUM(LENGTH(v)), 0) AS BIGINT) FROM acct_blobs WHERE user_id = $1 AND ns = $2")
                .bind(&user.0[..])
                .bind(ns)
                .fetch_one(pool)
                .await?
        }))
    }

    /// One vault item or page of pins, compare-and-set on `expect` (0 = new).
    pub async fn vault_put(
        &self,
        user: AccountId,
        k: &str,
        v: &[u8],
        expect: i64,
    ) -> Result<AccountReply> {
        if let Err(reason) = vault_item_ok(k, v) {
            return Ok(refused("VaultPut", reason));
        }
        // The key slots and the identity (voipc_crypto::account) are written
        // once, at sign-up; no client writes them after that. Refused, so a
        // session somebody else got hold of cannot lock the owner out.
        if k.starts_with("slot.") || k == "item.identity" {
            return Ok(refused(
                "VaultPut",
                "That part of the vault is only written when the account is made.",
            ));
        }
        // The count and the size are checked inside the write's transaction, so
        // two writes at once cannot both pass. The vault and the pins are all an
        // account keeps in l4f's storage, each with its own total there, and the pins'
        // leave room in the quota for a vault at its fullest: a password change writes
        // there under the quota alone.
        let (ns, other, max_items, room) = if k.starts_with("pins.") {
            if !is_pin_page(k) {
                return Ok(refused("VaultPut", "No such page."));
            }
            let room = (self.quota - VAULT_TOTAL_BYTES as i64).clamp(0, PINS_TOTAL_BYTES as i64);
            (PINS_NS, VAULT_NS, i64::from(PIN_PAGES), room)
        } else {
            let room = self.quota.min(VAULT_TOTAL_BYTES as i64);
            (VAULT_NS, PINS_NS, VAULT_MAX_ITEMS, room)
        };
        let quota = room + self.blob_bytes(user, other).await?;
        Ok(
            match self
                .store()
                .put_blob_limited(user, ns, k, v, expect, quota, Some(max_items), false)
                .await?
            {
                PutLimited::Put(PutBlob::Done(version)) => AccountReply::VaultStored {
                    k: k.to_string(),
                    version,
                },
                PutLimited::Put(PutBlob::Conflict) => {
                    let blob = self.store().blob(user, ns, k).await?.map(|b| VaultBlob {
                        k: b.k,
                        v: b.v,
                        version: b.version,
                    });
                    AccountReply::VaultConflict {
                        k: k.to_string(),
                        blob,
                    }
                }
                PutLimited::Put(PutBlob::Quota) | PutLimited::Full | PutLimited::SyncOff => {
                    refused("VaultPut", "The vault is full.")
                }
            },
        )
    }

    pub async fn identity(&self, user: AccountId) -> Result<Option<Vec<u8>>> {
        Ok(identity_of(self.store(), user).await?)
    }

    pub async fn set_identity(&self, user: AccountId, key: &[u8]) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_identity (account, identity_key, updated_at) VALUES ($1, $2, $3)
                 ON CONFLICT (account) DO UPDATE SET identity_key = excluded.identity_key, updated_at = excluded.updated_at",
            )
            .bind(&user.0[..])
            .bind(key)
            .bind(util::now())
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// The account as the client is told about it.
    /// The account's `Standing`: one read of its roles.
    pub async fn standing(&self, user: &User, scopes: &[String]) -> Result<Standing> {
        let mut standing = Standing::default();
        let roles = self.store().user_roles(user.id).await?;
        let counted = counted(&roles, scopes);
        standing.groups = counted.iter().map(|r| r.name.clone()).collect();
        standing.my_badges = self.badges_in_order(counted).await?;
        // The top ones, when there are more than a row shows
        standing.badges = standing.my_badges.clone();
        standing.badges.truncate(voipc_protocol::types::MAX_BADGES);
        Ok(standing)
    }

    pub async fn info_of(&self, user: &User, scopes: &[String]) -> Result<AccountInfo> {
        Ok(AccountInfo {
            id: user.id.0,
            name: user.username.clone(),
            scopes: scopes.to_vec(),
            needs_2fa: self.accounts.needs_2fa(user).await?,
            totp_enabled: user.totp_enabled,
        })
    }
}

/// The groups of `roles` that count: those whose scopes `scopes` (the account's effective
/// ones) cover. A group a missing second factor withholds counts for nothing, a gate included.
pub(crate) fn counted<'a>(
    roles: &'a [l4f_accounts::model::Role],
    scopes: &[String],
) -> Vec<&'a l4f_accounts::model::Role> {
    roles
        .iter()
        .filter(|r| scope::covers(scopes, &r.scopes))
        .collect()
}

async fn identity_of(store: &Store, user: AccountId) -> sqlx::Result<Option<Vec<u8>>> {
    db!(store, pool => {
        sqlx::query_scalar("SELECT identity_key FROM voipc_identity WHERE account = $1").bind(&user.0[..]).fetch_optional(pool).await
    })
}

/// The relay's own tables, under l4f's boot lock and in its own bookkeeping
/// table, so two boots never interleave and l4f's checksums never see ours.
async fn migrate_relay(store: &Store) -> Result<()> {
    fn ours(mut m: sqlx::migrate::Migrator) -> sqlx::migrate::Migrator {
        m.dangerous_set_table_name("voipc_migrations");
        m.set_locking(false);
        m
    }
    let mut held = l4f_accounts::migrate::lock(store).await?;
    let r = match held.conn() {
        StoreConn::Pg(c) => ours(sqlx::migrate!("migrations/postgres")).run(c).await,
        StoreConn::Lite(c) => ours(sqlx::migrate!("migrations/sqlite")).run(c).await,
    };
    l4f_accounts::migrate::unlock(held).await;
    Ok(r?)
}

/// The key this database was made with, recognised again: a check value
/// from it sits in `voipc_meta`, so a relay started with another key (another
/// key file, another working directory) stops instead of leaving every
/// two-factor secret, which that key seals, unreadable.
async fn check_key(store: &Store, keys: &Keys) -> Result<()> {
    let check = keys.subkey("voipc-key-check")[..16].to_vec();
    let v: Vec<u8> = db!(store, pool => {
        sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ('key_check', $1) ON CONFLICT DO NOTHING").bind(&check[..]).execute(pool).await?;
        sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = 'key_check'").fetch_one(pool).await?
    });
    if v != check {
        bail!("the accounts key is not the one this database was made with, and two-factor secrets are sealed under that one: point key_file at it, or set VOIPC_ACCOUNTS_KEY");
    }
    Ok(())
}

/// A SQLite database file readable by this user only: it holds the secret
/// hashes, the sealed two-factor secrets and the audit log.
fn owner_only_sqlite(url: &str) {
    let Some(path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return;
    };
    let path = path.split('?').next().unwrap_or(path);
    if let Err(e) = crate::fsutil::owner_only(std::path::Path::new(path)) {
        warn!("could not make {path} readable by this user only: {e}");
    }
}

/// Made once with the database; a relay keeps it when it moves.
async fn relay_id(store: &Store) -> Result<[u8; 16]> {
    let fresh: [u8; 16] = rand::random();
    let v: Vec<u8> = db!(store, pool => {
        sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ('relay_id', $1) ON CONFLICT DO NOTHING").bind(&fresh[..]).execute(pool).await?;
        sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = 'relay_id'").fetch_one(pool).await?
    });
    v.try_into()
        .map_err(|_| anyhow!("voipc_meta.relay_id is not 16 bytes"))
}

async fn ensure_moderator(store: &Store) -> Result<()> {
    // Every boot: a role given `voipc:moderate` before 1.7 keeps what it
    // granted, under the scopes that replaced it. Writes nothing once done.
    for role in store.roles().await? {
        if role.scopes.iter().any(|s| s == MODERATE_WAS) {
            let mut scopes: Vec<String> = role
                .scopes
                .iter()
                .filter(|s| *s != MODERATE_WAS)
                .cloned()
                .chain(MODERATE_BECAME.iter().map(|s| s.to_string()))
                .collect();
            scopes.sort();
            scopes.dedup();
            store
                .set_role_scopes(role.id, &scopes)
                .await
                .map_err(|e| anyhow!("moving {} off voipc:moderate: {e:?}", role.name))?;
        }
    }
    // 1.10's tools reach a group still exactly at the old default, once. Written
    // on every first boot, a new database's too, so a group trimmed back to the
    // old three later is left there. A crash before the widening below errs
    // towards less: the group keeps the old three.
    let first_boot = db!(store, pool => {
        sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ('moderator_1_10', $1) ON CONFLICT DO NOTHING")
            .bind(&[1u8][..])
            .execute(pool)
            .await?
            .rows_affected()
            == 1
    });
    let Some(role) = store.role_by_name("moderator").await? else {
        // None: another boot made it first. The scopes come in the same
        // transaction, so a crash never leaves a moderator role that grants nothing.
        store
            .create_role_with_scopes(
                "moderator",
                MODERATOR_SAYS,
                Some("mod"),
                &MODERATOR.map(String::from),
            )
            .await?;
        return Ok(());
    };
    let mut held = role.scopes.clone();
    held.sort();
    if first_boot && held == MODERATE_BECAME {
        store
            .set_role_scopes(role.id, &MODERATOR.map(String::from))
            .await
            .map_err(|e| anyhow!("widening the moderator group: {e:?}"))?;
        if role.description == MODERATOR_SAID {
            store
                .update_role(role.id, MODERATOR_SAYS, role.badge.as_deref())
                .await?;
        }
        info!(
            "[accounts] the moderator group was untouched, so it now also hands out {RESTRICT}, \
             {HIDE}, {REPORTS} and {MODLOG}. This happens once: take them away in the group \
             editor and they stay away"
        );
    }
    Ok(())
}

/// l4f's settings as a relay needs them.
pub(crate) fn l4f_config(cfg: &AccountsConfig, relay_id: [u8; 16]) -> Config {
    // The client solves the proof of work; there is no form to fill slowly.
    // People behind one address sign up together on a voice relay (a
    // household, a LAN party): more than l4f's two a day, still bounded.
    let signup = l4f_accounts::pow::Limits {
        min_form_seconds: 0,
        max_accounts_per_ip_day: 20,
        max_accounts_per_hour: cfg.signups_per_hour as usize,
        // Each sign-up is an attempt too, so never fewer of those: at l4f's 60 a
        // move past that stops at "Too many attempts" whatever the setting says.
        max_attempts_per_hour: (cfg.signups_per_hour as usize).max(60),
        ..Default::default()
    };
    Config {
        enabled: true,
        registration_open: cfg.registration == RegistrationMode::Open,
        // Every connection signs in again (device key or password) and its
        // session ends with it; these only bound a session a crash left behind.
        session_idle_days: 30,
        session_max_days: 90,
        // What needs no codes, not what every account holds (`Relay::open_with` seeds
        // `user` empty). Sharing history reaches no one: the password opened it already.
        default_user_scopes: vec![SHARE_HISTORY.to_string()],
        require_2fa_for_privileged: true,
        signup,
        // Every new device signs in with the password once: a LAN party does
        // that together. The per-account cap still stops guessing at one name.
        login_per_15min: 30,
        login_per_15min_global: 1000,
        reserved_usernames: vec![
            "voipc".into(),
            "guest".into(),
            "moderator".into(),
            "general".into(),
            // What `@everyone` and `@here` mean
            "everyone".into(),
            "here".into(),
        ],
        storage_quota_bytes: i64::from(cfg.quota_mb) * 1024 * 1024,
        totp_issuer: "VoIPC".into(),
        // Device keys sign for this origin; it names the relay, not its address.
        base_url: format!("voipc://{}", hex::encode(relay_id)),
        oauth_base_url: cfg.public_url.clone(),
        cookie_secure: false,
        ip_mode: IpMode::Hash,
        ..Config::default()
    }
}

/// `VOIPC_ACCOUNTS_KEY`, else the key file, else — only for a database not
/// made with a key yet — a new key file (readable by this user only) and a
/// log line saying to back it up.
fn master_key(path: &str, made_with_key: bool) -> Result<Vec<u8>> {
    if let Ok(k) = std::env::var("VOIPC_ACCOUNTS_KEY") {
        if k.len() < l4f_accounts::keys::MIN_MASTER_LEN {
            bail!(
                "VOIPC_ACCOUNTS_KEY needs at least {} characters",
                l4f_accounts::keys::MIN_MASTER_LEN
            );
        }
        return Ok(k.into_bytes());
    }
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let k = s.trim();
            if k.len() < l4f_accounts::keys::MIN_MASTER_LEN {
                bail!("{path} is too short to be an accounts key");
            }
            Ok(k.as_bytes().to_vec())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && made_with_key => Err(e).with_context(|| {
            format!(
                "{path} is not here, but this database was made with an accounts key, which seals the two-factor secrets: \
                 start where {path} is, give key_file its full path, or set VOIPC_ACCOUNTS_KEY"
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let k = hex::encode(rand::random::<[u8; 32]>());
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            std::io::Write::write_all(&mut o.open(path).with_context(|| format!("creating {path}"))?, k.as_bytes())?;
            warn!("made the accounts key {path}: back it up with the database — without it two-factor codes stop working");
            Ok(k.into_bytes())
        }
        Err(e) => Err(e).with_context(|| format!("reading {path}")),
    }
}

/// A database URL for the log, without its password (in the user part or in
/// the query).
fn redact(url: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((base, _)) => (base, "?…"),
        None => (url, ""),
    };
    match (base.split_once("://"), base.rfind('@')) {
        (Some((scheme, _)), Some(at)) => format!("{scheme}://…{}{query}", &base[at..]),
        _ => format!("{base}{query}"),
    }
}

/// `pins.0` to `pins.55`, written one way, so one page has one name.
fn is_pin_page(k: &str) -> bool {
    k.strip_prefix("pins.")
        .and_then(|n| n.parse::<u16>().ok().filter(|n| k == format!("pins.{n}")))
        .is_some_and(|n| n < PIN_PAGES)
}

fn vault_item_ok(k: &str, v: &[u8]) -> Result<(), &'static str> {
    if !(1..=64).contains(&k.len())
        || !k
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        return Err("A vault item's name is 1 to 64 characters of a-z, 0-9, '.', '_' and '-'.");
    }
    if v.len() > VAULT_MAX_BYTES {
        return Err("A vault item is at most 48 KiB.");
    }
    Ok(())
}

/// `reply`, with the number it was asked with, if any (`AccountRequest::AdminAsk`).
pub(crate) fn asked(ask: Option<u32>, reply: AccountReply) -> AccountReply {
    match ask {
        Some(ask) => voipc_protocol::codec::encode_asked(ask, &reply).unwrap_or(reply),
        None => reply,
    }
}

fn refused(request: &str, reason: &str) -> AccountReply {
    AccountReply::Error {
        request: request.into(),
        reason: reason.into(),
    }
}

/// A database error reading the log: answered, since the client waits for
/// this reply before it reads its next conversation, and in the words that
/// make it try again (`voipc_crypto::sync`).
fn read_failed(request: &str, e: anyhow::Error) -> AccountReply {
    warn!("{request}: {e:#}");
    refused(
        request,
        "The stored messages could not be read just now; slow down.",
    )
}

/// The derived secret as l4f's password field: base64url, 43 characters.
fn secret_text(secret: &[u8]) -> Result<String, String> {
    if secret.len() != SECRET_LEN {
        return Err("malformed sign-in secret".into());
    }
    Ok(util::b64u(secret))
}

// ── Sign-in ───────────────────────────────────────────────────────────────

/// A connection that signed in to an account.
pub struct SignedIn {
    pub user: User,
    pub token: String,
    pub info: SessionInfo,
    pub scopes: Vec<String>,
    pub standing: Standing,
    pub account: AccountInfo,
    pub identity_key: Vec<u8>,
    pub prekey_bundle: PreKeyBundleData,
    /// This connection's device opened the vault (`AccountSession::vault_proven`).
    pub vault_proven: bool,
    /// This connection signed in with the password's secret, or proved it again since
    /// (`confirm_again`): it may move the password to its login key
    /// (`AccountRequest::LoginKeySet` without a slot), once.
    pub by_secret: bool,
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, msg: &ServerMessage) -> Result<(), String> {
    crate::session::write_msg(stream, msg)
        .await
        .map_err(|_| "connection lost during sign-in".to_string())
}

async fn step<S: AsyncWrite + Unpin>(stream: &mut S, s: AuthStep) -> Result<(), String> {
    send(stream, &ServerMessage::AuthStep(s)).await
}

/// The client's next sign-in answer, within `wait`.
async fn next<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut BytesMut,
    wait: Duration,
    answers: &mut u32,
) -> Result<AuthContinue, String> {
    *answers += 1;
    if *answers > MAX_CONTINUES {
        return Err("Too many sign-in attempts on one connection.".into());
    }
    let payload = crate::session::read_frame(stream, buf, wait)
        .await
        .map_err(|e| match e {
            crate::session::NoFrame::TimedOut => "Sign-in timed out.".to_string(),
            crate::session::NoFrame::Malformed => "malformed frame".to_string(),
            crate::session::NoFrame::Closed => "connection closed during sign-in".to_string(),
        })?;
    match decode_client_msg(&payload) {
        Ok(ClientMessage::AuthContinue(c)) => Ok(c),
        _ => Err("unexpected message during sign-in".into()),
    }
}

fn unexpected() -> String {
    "unexpected sign-in step".into()
}

/// l4f's credential kind for a device key (`devkey_add`).
const DEVKEY_KIND: &str = "devkey";

/// A proof bound to another connection than this one: a server between the app and this
/// relay passed it on (W1-24), or the device's key is gone.
pub(crate) const NOT_THIS_CONNECTION: &str =
    "This sign-in was not made on this connection. If you used a link, open the server's \
     own address in VoIPC instead.";

/// Runs an account sign-in on a connection whose `Authenticate` named one, up
/// to the keys. `Err` is the reason for the client (`AuthError`). A session
/// made on the way is ended again when a later step fails.
#[allow(clippy::too_many_arguments)]
pub async fn sign_in<S: AsyncRead + AsyncWrite + Unpin>(
    state: &ServerState,
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    name: &str,
    start: AccountStart,
    ip: IpAddr,
    app_version: &str,
    binding: Option<[u8; voipc_crypto::bind::BIND_LEN]>,
) -> Result<SignedIn, String> {
    let ctx = relay.ctx(ip, app_version);
    let mut answers = 0u32;
    let mut registered = false;
    let mut by_secret = false;
    let work = || relay.pending_slot(ip).ok_or_else(|| BUSY.to_string());
    let session: NewSession = match start {
        AccountStart::Login => {
            // An account whose password is its login key (22) proves it over this
            // connection; any other name, and an account that has not moved yet, as before
            let keyed = {
                let _work = work()?;
                match scope::normalize_username(name, &[]) {
                    Ok(clean) => match relay.store().user_by_username(&clean).await {
                        Ok(Some(u)) => relay.accounts.hostkey(u.id).await.ok().flatten().is_some(),
                        _ => false,
                    },
                    Err(_) => false,
                }
            };
            let login = if keyed {
                // Kept here and never sent, as for a device key
                let nonce: [u8; 16] = rand::random();
                let challenge = relay.accounts.hostkey_challenge(None, &nonce);
                step(
                    stream,
                    AuthStep::KeyChallenge {
                        relay_id: relay.relay_id,
                        challenge: challenge.clone(),
                    },
                )
                .await?;
                let AuthContinue::KeySig { signature, web } =
                    next(stream, buf, STEP_WAIT, &mut answers).await?
                else {
                    return Err(unexpected());
                };
                let Some(b) = Binding::claimed(web, binding) else {
                    return Err(NOT_THIS_CONNECTION.into());
                };
                let _work = work()?;
                relay
                    .accounts
                    .login_hostkey(&ctx, name, &challenge, &nonce, None, |key| {
                        voipc_crypto::bind::login_ok(
                            key,
                            &relay.relay_id,
                            name,
                            &challenge,
                            &b,
                            &signature,
                        )
                    })
                    .await
            } else {
                step(
                    stream,
                    AuthStep::Salt {
                        relay_id: relay.relay_id,
                        pow: None,
                    },
                )
                .await?;
                let AuthContinue::Secret { auth_secret } =
                    next(stream, buf, STEP_WAIT, &mut answers).await?
                else {
                    return Err(unexpected());
                };
                let pw = secret_text(&auth_secret)?;
                let _work = work()?;
                by_secret = true;
                relay.accounts.login_password(&ctx, name, &pw, None).await
            };
            match login {
                Ok(LoginStep::Done(s)) => s,
                Ok(LoginStep::NeedMfa(pending)) => {
                    second_factor(relay, stream, buf, &ctx, pending, &mut answers, ip).await?
                }
                Err(e) => return Err(e.message().into()),
            }
        }
        AccountStart::DeviceKey { device_id } => {
            // Kept here and never sent: a challenge replayed on another
            // connection, even after a restart, carries the wrong nonce.
            let nonce: [u8; 16] = rand::random();
            let challenge = relay.accounts.devkey_challenge(None, &nonce);
            step(
                stream,
                AuthStep::DeviceChallenge {
                    relay_id: relay.relay_id,
                    challenge: challenge.clone(),
                },
            )
            .await?;
            // Only the bound answer (22): an unbound one is what a server passing the
            // sign-in on would hold (W1-24)
            let AuthContinue::DeviceSigBound {
                signature,
                bind,
                web,
            } = next(stream, buf, STEP_WAIT, &mut answers).await?
            else {
                return Err(unexpected());
            };
            let _work = work()?;
            // Before l4f makes a session: the device's own key over this connection
            let key = relay
                .store()
                .credential(DEVKEY_KIND, &device_id)
                .await
                .map_err(|e| e.to_string())?
                .and_then(|c| c.public_key);
            let bound = Binding::claimed(web, binding).is_some_and(|b| {
                key.as_deref().is_some_and(|k| {
                    voipc_crypto::bind::devkey_ok(
                        k,
                        &relay.relay_id,
                        &device_id,
                        &challenge,
                        &b,
                        &bind,
                    )
                })
            });
            if !bound {
                return Err(NOT_THIS_CONNECTION.into());
            }
            relay
                .accounts
                .devkey_login(&ctx, &challenge, &nonce, &device_id, &signature)
                .await
                .map_err(|e| e.message().to_string())?
        }
        AccountStart::Reset => {
            return reset(
                state,
                relay,
                stream,
                buf,
                name,
                &ctx,
                ip,
                &mut answers,
                binding,
            )
            .await
        }
        AccountStart::Providers => {
            let kinds = relay.provider_kinds();
            step(stream, AuthStep::Providers { kinds }).await?;
            return Err(ANSWERED.into());
        }
        AccountStart::Provider { kind } => {
            relay.provider_open(stream, kind, ip, binding).await?;
            return Err(ANSWERED.into());
        }
        AccountStart::ProviderResume { ticket } => {
            return provider::resume(
                state,
                relay,
                stream,
                buf,
                &ticket,
                None,
                &ctx,
                ip,
                &mut answers,
                binding,
            )
            .await;
        }
        AccountStart::ProviderResumeInvited { ticket, invite } => {
            return provider::resume(
                state,
                relay,
                stream,
                buf,
                &ticket,
                Some(&invite),
                &ctx,
                ip,
                &mut answers,
                binding,
            )
            .await;
        }
        AccountStart::ProviderStatus { ticket } => {
            let answer = if provider::ready(relay, &ticket)? {
                AuthStep::ProviderReady
            } else {
                AuthStep::ProviderPending
            };
            step(stream, answer).await?;
            return Err(ANSWERED.into());
        }
        AccountStart::Register { invite } => {
            // A shape, so it says nothing about who is here (W1-30)
            if placeholder::kept_for_the_move(name) {
                return Err(placeholder::KEPT_FOR_THE_MOVE.into());
            }
            let invite = invite.filter(|c| !c.trim().is_empty());
            if invite.is_none() && relay.registration != RegistrationMode::Open {
                return Err("Making an account here needs an invite.".into());
            }
            // A link is told from a code by its length. Many people use one, so
            // unlike a code it does not stand in for the proof of work
            let linked = invite.as_deref().filter(|c| links::is_link_code(c));
            if let Some(code) = linked {
                if !relay.link_usable(code).await.unwrap_or(false) {
                    return Err(links::GONE.into());
                }
            }
            let pow = if invite.is_none() || linked.is_some() {
                let cfg = relay.accounts.host.config();
                let ch = pow::issue(
                    &relay.pow_key,
                    cfg.signup.pow_maxnumber,
                    cfg.signup.pow_ttl_minutes.saturating_mul(60),
                );
                Some(PowChallenge {
                    altcha: serde_json::to_string(&ch).map_err(|e| e.to_string())?,
                    ts: pow::stamp(&relay.pow_key, util::now_secs()),
                })
            } else {
                None
            };
            step(
                stream,
                AuthStep::Salt {
                    relay_id: relay.relay_id,
                    pow,
                },
            )
            .await?;
            // The password's login key, never its secret (22)
            let AuthContinue::RegisterKey {
                login_key,
                altcha,
                ts,
                vault,
            } = next(stream, buf, REGISTER_WAIT, &mut answers).await?
            else {
                return Err(unexpected());
            };
            let login_key: [u8; 32] = login_key.try_into().map_err(|_| unexpected())?;
            if vault.len() as i64 > VAULT_MAX_ITEMS
                || vault.iter().map(|b| b.v.len()).sum::<usize>() > VAULT_TOTAL_BYTES
            {
                return Err("The new vault is too big.".into());
            }
            if let Some(reason) = vault.iter().find_map(|b| vault_item_ok(&b.k, &b.v).err()) {
                return Err(reason.into());
            }
            // The reset key, which only the recovery key derives: a reset is
            // checked against it, never against what a device holds (S-006)
            if !vault
                .iter()
                .any(|b| b.k == SLOT_RESET && b.v.len() == RESET_KEY_LEN)
            {
                return Err(unexpected());
            }
            let _work = work()?;
            let s = if let Some(code) = invite.as_deref().filter(|c| links::is_link_code(c)) {
                links::register(
                    relay,
                    &ctx,
                    code,
                    name,
                    links::How::HostKey(&login_key),
                    &altcha,
                    &ts,
                )
                .await
                .map_err(links::Refused::text)?
            } else {
                match &invite {
                    Some(code) => {
                        let form = InviteForm {
                            code,
                            username: name,
                            password: "",
                            email: None,
                            display_name: None,
                        };
                        relay
                            .accounts
                            .register_invite_hostkey(&ctx, form, &login_key)
                            .await
                    }
                    None => {
                        // l4f takes an empty one as a browser without JavaScript;
                        // every VoIPC client solves the puzzle.
                        if altcha.is_empty() {
                            return Err("The sign-up puzzle was not solved.".into());
                        }
                        let proof = pow::Proof {
                            altcha: &altcha,
                            ts: &ts,
                            ..Default::default()
                        };
                        let form = RegisterForm {
                            username: name,
                            password: "",
                            email: None,
                            display_name: None,
                            proof,
                        };
                        relay
                            .accounts
                            .register_hostkey(&ctx, form, &login_key)
                            .await
                    }
                }
                .map_err(|e| e.message().to_string())?
            };
            for b in &vault {
                // Anything but a write (over quota, a conflict) is a failure
                // too: an account without its vault cannot be opened on
                // another device, nor on this one after a reinstall
                // (1.0 audit H1-06)
                match relay
                    .store()
                    .put_blob(s.info.user_id, VAULT_NS, &b.k, &b.v, 0, relay.quota)
                    .await
                {
                    Ok(l4f_accounts::store::PutBlob::Done(_)) => {}
                    other => {
                        let _ = relay.accounts.logout(&s.token).await;
                        warn!("storing a new account's vault: {other:?}");
                        return Err("Something went wrong. Please try again.".into());
                    }
                }
            }
            registered = true;
            s
        }
    };
    let token = session.token.clone();
    let r = finish(
        relay,
        stream,
        buf,
        name,
        session,
        registered,
        &mut answers,
        ip,
    )
    .await
    .map(|s| SignedIn { by_secret, ..s });
    if r.is_err() {
        let _ = relay.accounts.logout(&token).await;
    }
    r
}

/// A code from the authenticator app or a recovery code. A wrong one asks
/// again (another `NeedTotp`) until the connection's answers run out.
/// A forgotten password, set anew with the recovery key (`AccountStart::Reset`).
/// Ends with `ResetDone`, then an `Err` that closes the connection: the person
/// signs in with the new password, as on any other device.
#[allow(clippy::too_many_arguments)]
async fn reset<S: AsyncRead + AsyncWrite + Unpin>(
    state: &ServerState,
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    name: &str,
    ctx: &Ctx,
    ip: IpAddr,
    answers: &mut u32,
    binding: Option<[u8; voipc_crypto::bind::BIND_LEN]>,
) -> Result<SignedIn, String> {
    let gone = || "Something went wrong. Please try again.".to_string();
    let allowed = relay
        .resets
        .entry(crate::limit_key(ip))
        .or_insert_with(|| crate::state::RateLimiter::new(5.0, 1.0 / 180.0))
        .try_consume();
    if !allowed {
        return Err("Too many resets from your address. Try again later.".into());
    }
    let (user, identity, vault) = {
        let _work = relay.pending_slot(ip).ok_or_else(|| BUSY.to_string())?;
        let Ok(clean) = scope::normalize_username(name, &[]) else {
            return Err("No account of that name.".into());
        };
        let user = relay
            .store()
            .user_by_username(&clean)
            .await
            .map_err(|_| gone())?
            .ok_or("No account of that name.")?;
        let identity = relay.identity(user.id).await.map_err(|_| gone())?;
        let vault = relay.vault(user.id).await.map_err(|_| gone())?;
        (user, identity, vault)
    };
    // Nobody has opened it: this answers as if someone had, since anyone can find out the
    // name exists (a guest asking for it hears so), and the two together would say that
    // nobody holds it yet.
    let Some(identity) = identity else {
        return decoy_reset(relay, stream, buf, user.id, answers).await;
    };
    // Never the password slot: with it anyone could guess the password offline
    let blobs: Vec<VaultBlob> = vault
        .iter()
        .filter(|b| b.k == "slot.recovery" || b.k == "item.identity")
        .cloned()
        .collect();
    if !blobs.iter().any(|b| b.k == "slot.recovery") {
        return Err("This account has no recovery key.".into());
    }
    let challenge: [u8; 32] = rand::random();
    let second_factor = l4f_accounts::service::has_second_factor(&user);
    step(
        stream,
        AuthStep::ResetChallenge {
            relay_id: relay.relay_id,
            challenge: challenge.to_vec(),
            blobs,
            second_factor,
        },
    )
    .await?;
    // Only the bound shape (22): over this connection and the new password's login key,
    // which goes in place of a secret (W1-24)
    let AuthContinue::ResetBound {
        signature,
        key_signature,
        login_key,
        pass_slot,
        totp,
        recovery_code,
        web,
    } = next(stream, buf, TOTP_WAIT, answers).await?
    else {
        return Err(unexpected());
    };
    let Some(b) = Binding::claimed(web, binding) else {
        return Err(NOT_THIS_CONNECTION.into());
    };
    let login_key: [u8; 32] = login_key.try_into().map_err(|_| unexpected())?;
    // An account with a reset key proves the recovery key itself; one made
    // before 1.3 has only its identity, which the vault's DEK opens too
    let proved = match vault.iter().find(|b| b.k == SLOT_RESET) {
        Some(reset_key) => voipc_crypto::account::reset_key_proof_bound_ok(
            &reset_key.v,
            &relay.relay_id,
            &user.username,
            &challenge,
            &login_key,
            &b,
            &key_signature,
        ),
        None => voipc_crypto::account::reset_proof_bound_ok(
            &identity,
            &relay.relay_id,
            &user.username,
            &challenge,
            &login_key,
            &b,
            &signature,
        ),
    };
    if !proved {
        return Err(NOT_THIS_KEY.into());
    }
    if pass_slot.len() != SLOT_LEN {
        return Err(unexpected());
    }
    let _work = relay.pending_slot(ip).ok_or_else(|| BUSY.to_string())?;
    if second_factor {
        let factor = match (&totp, &recovery_code) {
            (Some(code), _) => l4f_accounts::service::SecondFactor::Totp(code),
            (None, Some(code)) => l4f_accounts::service::SecondFactor::Recovery(code),
            (None, None) => {
                return Err(
                    "This account needs a code from the authenticator app, or a recovery code."
                        .into(),
                )
            }
        };
        relay
            .accounts
            .second_factor_check(ctx, &user, factor)
            .await
            .map_err(|e| e.message().to_string())?;
    }
    replace_pass_slot(relay, user.id, &vault, &pass_slot, || {
        relay.accounts.hostkey_set_as_host(ctx, user.id, &login_key)
    })
    .await?;
    info!(user = %user.id.hex(), "account password reset with the recovery key");
    sign_out_account(state, user.id).await;
    step(stream, AuthStep::ResetDone).await?;
    Err("Your password was reset. Sign in with the new one.".into())
}

/// What `reset` does for an account with no identity: the same steps as a real one, with
/// blobs no key opens, ending as a wrong key ends.
async fn decoy_reset<S: AsyncRead + AsyncWrite + Unpin>(
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    user: AccountId,
    answers: &mut u32,
) -> Result<SignedIn, String> {
    let challenge: [u8; 32] = rand::random();
    step(
        stream,
        AuthStep::ResetChallenge {
            relay_id: relay.relay_id,
            challenge: challenge.to_vec(),
            blobs: relay.decoy_blobs(user),
            second_factor: false,
        },
    )
    .await?;
    match next(stream, buf, TOTP_WAIT, answers).await? {
        AuthContinue::ResetBound { .. } => Err(NOT_THIS_KEY.into()),
        _ => Err(unexpected()),
    }
}

/// `slot.pass` and the password change together: the slot first
/// (compare-and-set), then `change`; the old slot goes back if `change`
/// fails, so the vault keeps opening with whichever password signs in. (A
/// crash between the two is left to the recovery key.)
pub(crate) async fn replace_pass_slot<F, Fut>(
    relay: &Relay,
    user: AccountId,
    vault: &[VaultBlob],
    slot: &[u8],
    change: F,
) -> Result<(), String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<(), l4f_accounts::service::Error>>,
{
    let gone = || "Something went wrong. Please try again.".to_string();
    let old = vault.iter().find(|b| b.k == "slot.pass");
    let written = match relay
        .store()
        .put_blob(
            user,
            VAULT_NS,
            "slot.pass",
            slot,
            old.map_or(0, |b| b.version),
            relay.quota,
        )
        .await
    {
        Ok(PutBlob::Done(v)) => v,
        _ => return Err(gone()),
    };
    if let Err(e) = change().await {
        if let Some(old) = old {
            let _ = relay
                .store()
                .put_blob(user, VAULT_NS, "slot.pass", &old.v, written, relay.quota)
                .await;
        }
        return Err(e.message().to_string());
    }
    Ok(())
}

async fn second_factor<S: AsyncRead + AsyncWrite + Unpin>(
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    ctx: &Ctx,
    pending: NewSession,
    answers: &mut u32,
    ip: IpAddr,
) -> Result<NewSession, String> {
    let Ok(Some(user)) = relay.store().user_by_id(pending.info.user_id).await else {
        return Err("Wrong username or password.".into());
    };
    let r = async {
        loop {
            step(stream, AuthStep::NeedTotp).await?;
            let answer = next(stream, buf, TOTP_WAIT, answers).await?;
            let _work = relay.pending_slot(ip).ok_or_else(|| BUSY.to_string())?;
            let r = match answer {
                AuthContinue::Totp { code } => {
                    relay
                        .accounts
                        .mfa_totp(ctx, &user, &pending.info, &code)
                        .await
                }
                AuthContinue::Recovery { code } => relay
                    .accounts
                    .mfa_recovery(ctx, &user, &pending.info, &code)
                    .await
                    .map(|(s, _)| s),
                _ => return Err(unexpected()),
            };
            match r {
                Ok(s) => return Ok(s),
                Err(l4f_accounts::service::Error::Invalid(_)) => continue,
                Err(e) => return Err(e.message().to_string()),
            }
        }
    }
    .await;
    // The half-made session waiting for the code goes now, not with the sweep.
    if r.is_err() {
        let _ = relay.accounts.logout(&pending.token).await;
    }
    r
}

#[allow(clippy::too_many_arguments)]
async fn finish<S: AsyncRead + AsyncWrite + Unpin>(
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    name: &str,
    session: NewSession,
    registered: bool,
    answers: &mut u32,
    ip: IpAddr,
) -> Result<SignedIn, String> {
    let gone = || "Something went wrong. Please try again.".to_string();
    let work = || relay.pending_slot(ip).ok_or_else(|| BUSY.to_string());
    let (user, info, scopes, blobs) = {
        let _work = work()?;
        let (user, info, scopes) = relay
            .accounts
            .session_from_token(&session.token, util::now())
            .await
            .map_err(|_| gone())?
            .ok_or_else(gone)?;
        let blobs = if registered {
            None
        } else {
            Some(relay.vault(user.id).await.map_err(|_| gone())?)
        };
        (user, info, scopes, blobs)
    };
    // A device key names its account itself; the name typed must be it.
    if !user.username.eq_ignore_ascii_case(name.trim()) {
        return Err("That device belongs to another account.".into());
    }
    if let Some(blobs) = blobs {
        step(stream, AuthStep::Vault { blobs }).await?;
    }
    let AuthContinue::Keys {
        identity_key,
        prekey_bundle,
        reset_identity,
    } = next(stream, buf, STEP_WAIT, answers).await?
    else {
        return Err(unexpected());
    };
    // Stored for good, so bounded here (the bundle is checked by the caller).
    if identity_key.is_empty() || identity_key.len() > 64 {
        return Err("malformed identity key".into());
    }
    let _work = work()?;
    match relay.identity(user.id).await.map_err(|_| gone())? {
        Some(known) if known == identity_key => {}
        Some(_) if !reset_identity => {
            return Err("This device's identity key is not your account's. Open your vault, or reset your identity in the account settings.".into());
        }
        // Replacing the identity every peer pinned takes the password (and
        // codes), not a remembered device's key: one stolen device must not
        // turn every contact's pin into a warning (1.0 audit H1-14).
        Some(_) if !relay.accounts.fresh(&info, util::now()) => {
            return Err("Sign in with your password to reset your identity.".into());
        }
        _ => relay
            .set_identity(user.id, &identity_key)
            .await
            .map_err(|_| gone())?,
    }
    let account = relay.info_of(&user, &scopes).await.map_err(|_| gone())?;
    let standing = relay.standing(&user, &scopes).await.map_err(|_| gone())?;
    info!(user = %user.id.hex(), method = %info.method, "account signed in");
    Ok(SignedIn {
        user,
        token: session.token,
        info,
        scopes,
        standing,
        account,
        identity_key,
        prekey_bundle,
        vault_proven: false,
        by_secret: false,
    })
}

// ── After sign-in ─────────────────────────────────────────────────────────

/// A signed-in account's new password: the old one checked, a fresh session
/// (the second factor where there is one), the vault's password slot and the
/// password together. This session stays; every other l4f session and every
/// remembered device goes.
#[allow(clippy::too_many_arguments)]
async fn password_change(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    ctx: &Ctx,
    user: &User,
    info: &SessionInfo,
    (old_secret, new_secret, pass_slot): (Vec<u8>, Vec<u8>, Vec<u8>),
    (totp, recovery_code): (Option<String>, Option<String>),
) -> Result<(), String> {
    let (old, new) = (secret_text(&old_secret)?, secret_text(&new_secret)?);
    if pass_slot.len() != SLOT_LEN {
        return Err("malformed password slot".into());
    }
    let (user, fresh) = confirm_again(
        state,
        relay,
        session_id,
        ctx,
        user,
        info,
        &old,
        (totp, recovery_code),
    )
    .await?;
    let vault = relay.vault(user.id).await.map_err(|e| e.to_string())?;
    replace_pass_slot(relay, user.id, &vault, &pass_slot, || {
        relay
            .accounts
            .password_change(ctx, &user, &fresh.info, &new)
    })
    .await?;
    info!(user = %user.id.hex(), "account password changed");
    Ok(())
}

/// `RecoveryKeyNew`: the password (and the second factor) again, then the
/// new `slot.recovery` and `slot.reset` in place of the old. If the second
/// write fails the first is put back, so the old recovery key keeps working
/// until both are in. (A crash between the two leaves the new slot with the
/// old reset key: the person still has the old key's text, so a reset needs
/// a new key made again.)
#[allow(clippy::too_many_arguments)]
async fn recovery_key_new(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    ctx: &Ctx,
    user: &User,
    info: &SessionInfo,
    secret: &[u8],
    (recovery_slot, reset_key): (&[u8], &[u8]),
    (totp, recovery_code): (Option<String>, Option<String>),
) -> Result<(), String> {
    if recovery_slot.len() != SLOT_LEN || reset_key.len() != RESET_KEY_LEN {
        return Err("malformed recovery key".into());
    }
    let secret = (!secret.is_empty()).then_some(secret);
    let user = prove_recent(
        state,
        relay,
        session_id,
        ctx,
        user,
        info,
        secret,
        (totp, recovery_code),
    )
    .await?;
    let gone = || "Something went wrong. Please try again.".to_string();
    let vault = relay.vault(user.id).await.map_err(|_| gone())?;
    let version = |k: &str| vault.iter().find(|b| b.k == k).map_or(0, |b| b.version);
    let put = |k: &'static str, v: &[u8], expect: i64| {
        let v = v.to_vec();
        async move {
            match relay
                .store()
                .put_blob(user.id, VAULT_NS, k, &v, expect, relay.quota)
                .await
            {
                Ok(PutBlob::Done(written)) => Ok(written),
                _ => Err(gone()),
            }
        }
    };
    let written = put("slot.recovery", recovery_slot, version("slot.recovery")).await?;
    if let Err(e) = put(SLOT_RESET, reset_key, version(SLOT_RESET)).await {
        if let Some(old) = vault.iter().find(|b| b.k == "slot.recovery") {
            let _ = put("slot.recovery", &old.v, written).await;
        }
        return Err(e);
    }
    info!(user = %user.id.hex(), "account recovery key replaced");
    Ok(())
}

/// The person at this connection proves it again before an account-wide
/// change: the password, and the second factor where the account has one.
/// The session comes out fresh, with a new token this connection now holds.
/// Returns the account as the database has it now (codes turned on from
/// another device since this connection signed in count).
#[allow(clippy::too_many_arguments)]
async fn confirm_again(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    ctx: &Ctx,
    user: &User,
    info: &SessionInfo,
    password: &str,
    (totp, recovery_code): (Option<String>, Option<String>),
) -> Result<(User, NewSession), String> {
    let msg = |e: l4f_accounts::service::Error| e.message().to_string();
    let user = relay
        .store()
        .user_by_id(user.id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("This account is gone.")?;
    let fresh = if l4f_accounts::service::has_second_factor(&user) {
        relay
            .accounts
            .confirm_password(ctx, &user, password)
            .await
            .map_err(msg)?;
        match (&totp, &recovery_code) {
            (Some(code), _) => relay.accounts.step_up_totp(ctx, &user, info, code).await,
            (None, Some(code)) => {
                relay
                    .accounts
                    .step_up_recovery(ctx, &user, info, code)
                    .await
            }
            (None, None) => {
                return Err(
                    "This account needs a code from the authenticator app, or a recovery code."
                        .into(),
                )
            }
        }
    } else {
        relay.accounts.step_up(ctx, &user, info, password).await
    }
    .map_err(msg)?;
    // The step-up gave this session a new token; the old one no longer
    // resolves, so `revalidate` would end this connection
    if let Some(a) = state
        .sessions
        .get_mut(&session_id)
        .as_mut()
        .and_then(|s| s.account.as_mut())
    {
        a.token = fresh.token.clone();
        a.info = fresh.info.clone();
        // The password's secret, proven on this connection as at a sign-in with it: an
        // account that signs in only by device or provider moves to its login key here
        // (the client's `LoginKeySet` right behind this request)
        a.by_secret = true;
    }
    Ok((user, fresh))
}

/// A login-key answer to a challenge this session asked for (`KeyStepUp`).
struct KeyProof<'a> {
    challenge: &'a str,
    nonce: &'a [u8; 16],
    binding: &'a Binding,
    signature: &'a [u8],
}

/// How long a `KeyStepUp` stands in for the password in the next request that wants it.
const KEY_STEPPED: Duration = Duration::from_secs(120);

/// `confirm_again` with the login key (protocol v22): the key over the challenge and this
/// connection, then the second factor where there is one. This session is a recent
/// sign-in after it, with a new token.
#[allow(clippy::too_many_arguments)]
async fn confirm_again_key(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    ctx: &Ctx,
    user: &User,
    info: &SessionInfo,
    proof: KeyProof<'_>,
    (totp, recovery_code): (Option<String>, Option<String>),
) -> Result<User, String> {
    let msg = |e: l4f_accounts::service::Error| e.message().to_string();
    let user = relay
        .store()
        .user_by_id(user.id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("This account is gone.")?;
    let verify = |key: &[u8; 32]| {
        voipc_crypto::bind::login_ok(
            key,
            &relay.relay_id,
            &user.username,
            proof.challenge,
            proof.binding,
            proof.signature,
        )
    };
    let fresh = if l4f_accounts::service::has_second_factor(&user) {
        relay
            .accounts
            .confirm_hostkey(ctx, &user, proof.challenge, proof.nonce, verify)
            .await
            .map_err(msg)?;
        match (&totp, &recovery_code) {
            (Some(code), _) => relay.accounts.step_up_totp(ctx, &user, info, code).await,
            (None, Some(code)) => {
                relay
                    .accounts
                    .step_up_recovery(ctx, &user, info, code)
                    .await
            }
            (None, None) => {
                return Err(
                    "This account needs a code from the authenticator app, or a recovery code."
                        .into(),
                )
            }
        }
    } else {
        relay
            .accounts
            .step_up_hostkey(ctx, &user, info, proof.challenge, proof.nonce, verify)
            .await
    }
    .map_err(msg)?;
    if let Some(a) = state
        .sessions
        .get_mut(&session_id)
        .as_mut()
        .and_then(|s| s.account.as_mut())
    {
        a.token = fresh.token.clone();
        a.info = fresh.info.clone();
    }
    Ok(user)
}

/// Takes this session's `KeyStepUp`, if it is recent: the password, proved again.
fn take_key_stepped(state: &ServerState, session_id: u32) -> bool {
    state
        .sessions
        .get_mut(&session_id)
        .and_then(|mut s| s.account.as_mut().and_then(|a| a.key_stepped.take()))
        .is_some_and(|at| at.elapsed() <= KEY_STEPPED)
}

/// `LoginKeySet`: the identity's signature over the key (and the slot), bound to this
/// connection. Without a slot, the password moves to its key: only on a connection that
/// just signed in with the password's secret, so that nobody who got in another way (a
/// provider and the vault) picks the password. With one, a new password: after a
/// `KeyStepUp` with the old one, as `PasswordChange` takes the old secret. True for a new
/// password.
#[allow(clippy::too_many_arguments)]
async fn login_key_set(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    ctx: &Ctx,
    user: &User,
    info: &SessionInfo,
    (key, identity_sig, pass_slot): (&[u8], &[u8], Option<&[u8]>),
    binding: Option<Binding>,
) -> Result<bool, String> {
    let msg = |e: l4f_accounts::service::Error| e.message().to_string();
    let gone = || "Something went wrong. Please try again.".to_string();
    let b = binding.ok_or(NOT_THIS_CONNECTION)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| "malformed login key".to_string())?;
    let identity = relay
        .identity(user.id)
        .await
        .map_err(|_| gone())?
        .ok_or_else(gone)?;
    if !voipc_crypto::account::login_key_proof_ok(
        &identity,
        &relay.relay_id,
        &user.username,
        &key,
        pass_slot,
        &b,
        identity_sig,
    ) {
        return Err("That key was not signed by this account.".into());
    }
    let user = relay
        .store()
        .user_by_id(user.id)
        .await
        .map_err(|_| gone())?
        .ok_or("This account is gone.")?;
    match pass_slot {
        None => {
            let by_secret = state
                .sessions
                .get_mut(&session_id)
                .and_then(|mut s| s.account.as_mut().map(|a| std::mem::take(&mut a.by_secret)))
                .unwrap_or(false);
            if !by_secret {
                return Err("Sign in with your password first.".into());
            }
            relay
                .accounts
                .hostkey_upgrade(ctx, &user, info, &key)
                .await
                .map_err(msg)?;
            info!(user = %user.id.hex(), "account password moved to its login key");
            Ok(false)
        }
        Some(slot) => {
            if slot.len() != SLOT_LEN {
                return Err("malformed password slot".into());
            }
            if !take_key_stepped(state, session_id) {
                return Err("Enter your password.".into());
            }
            let vault = relay.vault(user.id).await.map_err(|e| e.to_string())?;
            replace_pass_slot(relay, user.id, &vault, slot, || {
                relay.accounts.hostkey_change(ctx, &user, info, &key)
            })
            .await?;
            info!(user = %user.id.hex(), "account password changed");
            Ok(true)
        }
    }
}

/// Deletes the account at this connection, once it proved itself again. Its
/// vault, identity, log key, what it wrote to the stored logs, the keys to
/// and from it, its memberships, sessions and device keys go (the database's
/// cascades); what others wrote to it stays theirs until it expires (D9).
/// The name is free again.
#[allow(clippy::too_many_arguments)]
async fn delete_account(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    ctx: &Ctx,
    user: &User,
    info: &SessionInfo,
    secret: &[u8],
    second: (Option<String>, Option<String>),
) -> Result<(), String> {
    let secret = (!secret.is_empty()).then_some(secret);
    let user = prove_recent(state, relay, session_id, ctx, user, info, secret, second).await?;
    let scopes = state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.scopes.clone()))
        .unwrap_or_default();
    let actor = l4f_accounts::service::Actor {
        user: &user,
        scopes: &scopes,
    };
    relay
        .accounts
        .delete_account(ctx, actor, user.id, false)
        .await
        .map_err(|e| match e {
            l4f_accounts::service::Error::LastAdmin => {
                "This is the last admin account here: make another admin first.".to_string()
            }
            e => e.message().to_string(),
        })?;
    if let Err(e) = log::walk(relay.store(), &user.id.0).await {
        warn!("marking a deleted account's rows: {e:#}");
    }
    // `Host::delete_user` left them out for good: a frame coming now must know, and no
    // reader gets what they wrote from here on
    if let Err(e) = archive::load(relay).await {
        warn!("reading the archive's wishes: {e:#}");
    }
    relay.archive_kick.notify_one();
    info!(user = %user.id.hex(), "account deleted by its owner");
    Ok(())
}

/// A recent sign-in for what a provider link, an unlink, or (without a password)
/// a new recovery key or deleting the account takes: the password and the second
/// factor where there is a password; without one the second factor; without
/// that, a provider's proof already on this connection. The sign-in that got a
/// connection in does not count, so neither a stolen device nor a provider account
/// alone is enough. Returns the account as the database has it now.
#[allow(clippy::too_many_arguments)]
async fn prove_recent(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    ctx: &Ctx,
    user: &User,
    info: &SessionInfo,
    secret: Option<&[u8]>,
    (totp, recovery_code): (Option<String>, Option<String>),
) -> Result<User, String> {
    let now_user = relay
        .store()
        .user_by_id(user.id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("This account is gone.")?;
    // A login key is the password: `KeyStepUp` proved it (and the second factor) just now
    if relay
        .accounts
        .hostkey(now_user.id)
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        if !take_key_stepped(state, session_id) {
            return Err("Enter your password.".into());
        }
        return Ok(now_user);
    }
    if now_user.has_password {
        let secret = secret.ok_or("Enter your password.")?;
        let password = secret_text(secret)?;
        let (user, _) = confirm_again(
            state,
            relay,
            session_id,
            ctx,
            &now_user,
            info,
            &password,
            (totp, recovery_code),
        )
        .await?;
        return Ok(user);
    }
    if l4f_accounts::service::has_second_factor(&now_user) {
        let fresh = match (&totp, &recovery_code) {
            (Some(code), _) => {
                relay
                    .accounts
                    .step_up_totp(ctx, &now_user, info, code)
                    .await
            }
            (None, Some(code)) => {
                relay
                    .accounts
                    .step_up_recovery(ctx, &now_user, info, code)
                    .await
            }
            (None, None) => {
                return Err(
                    "This account needs a code from the authenticator app, or a recovery code."
                        .into(),
                )
            }
        }
        .map_err(|e| e.message().to_string())?;
        if let Some(a) = state
            .sessions
            .get_mut(&session_id)
            .as_mut()
            .and_then(|s| s.account.as_mut())
        {
            a.token = fresh.token;
            a.info = fresh.info;
        }
        return Ok(now_user);
    }
    if !relay.accounts.fresh(info, util::now()) {
        return Err("Confirm it's you with a provider you have linked first.".into());
    }
    Ok(now_user)
}

/// Ends this relay's connection of an account whose sessions l4f just ended,
/// now rather than at the next `revalidate`. (One at most: a sign-in takes
/// an account's connection over.)
async fn sign_out_account(state: &ServerState, user: AccountId) {
    let ids: Vec<u32> = state
        .sessions
        .iter()
        .filter(|e| {
            e.value()
                .account
                .as_ref()
                .is_some_and(|a| a.user.id == user)
        })
        .map(|e| *e.key())
        .collect();
    for id in ids {
        crate::session::force_disconnect(
            state,
            id,
            "Your password was changed. Sign in with the new one.",
        )
        .await;
    }
}

/// One `AccountRequest` from a signed-in connection.
pub async fn handle_request(
    state: &Arc<ServerState>,
    session_id: u32,
    req: AccountRequest,
    tx: &ControlTx,
) -> Result<()> {
    // `AdminAsk` is `Admin` with a number of the client's that every answer carries back,
    // a refusal too (protocol v22, W2-31)
    let (req, ask) = match req {
        AccountRequest::AdminAsk { ask, op, code } => {
            (AccountRequest::Admin { op, code }, Some(ask))
        }
        req => (req, None),
    };
    let reply = |r: AccountReply| ServerMessage::Account(asked(ask, r));
    let Some(relay) = state.accounts.clone() else {
        return crate::session::send_msg(
            tx,
            &reply(refused("Account", "This relay has no accounts.")),
        );
    };
    let Some((user, info, peer_ip, vault_proven, binding)) =
        state.sessions.get(&session_id).and_then(|s| {
            s.account.as_ref().map(|a| {
                (
                    a.user.clone(),
                    a.info.clone(),
                    s.peer_ip,
                    a.vault_proven,
                    a.binding,
                )
            })
        })
    else {
        return crate::session::send_msg(
            tx,
            &reply(refused("Account", "Sign in with an account first.")),
        );
    };
    // Database work, so budgeted on its own beside the 50 messages a second
    // every message shares (1.0 audit H1-03). The variant's name is what a
    // client's error handling goes by.
    let reads_log = matches!(
        req,
        AccountRequest::WrapsFetch { .. }
            | AccountRequest::LogFetch { .. }
            | AccountRequest::LogKeys { .. }
            | AccountRequest::LogIndex
            | AccountRequest::ArchiveFetch { .. }
            | AccountRequest::ArchiveChannels
            | AccountRequest::LogMemberIds { .. }
            | AccountRequest::ChainFetch { .. }
            | AccountRequest::WrapsPage { .. }
            | AccountRequest::OwnChains { .. }
            | AccountRequest::OwnBuckets { .. }
            | AccountRequest::BucketLists { .. }
            | AccountRequest::OwnChainRows { .. }
            | AccountRequest::VaultPage { .. }
    );
    let searches = matches!(req, AccountRequest::ArchiveSearch { .. });
    let allowed = state.sessions.get_mut(&session_id).is_some_and(|mut s| {
        if searches {
            s.archive_search_rate.try_consume()
        } else if reads_log {
            s.log_read_rate.try_consume()
        } else {
            s.account_rate.try_consume()
        }
    });
    if !allowed {
        let name = format!("{req:?}");
        let name = name.split([' ', '{', '(']).next().unwrap_or("Account");
        return crate::session::send_msg(
            tx,
            &reply(refused(name, "Too many requests at once; slow down.")),
        );
    }
    let ctx = relay.ctx(peer_ip, voipc_protocol::codec::APP_VERSION);
    let now = util::now();
    let out = match req {
        AccountRequest::DeviceChallenge => {
            if !relay.accounts.fresh(&info, now) && !vault_proven {
                refused(
                    "DeviceChallenge",
                    "Sign in with your password again to remember this device.",
                )
            } else if relay.accounts.needs_2fa(&user).await? {
                refused("DeviceChallenge", "Set up two-factor codes first.")
            } else {
                let nonce: [u8; 16] = rand::random();
                let challenge = relay.accounts.devkey_challenge(Some(&user), &nonce);
                if let Some(mut s) = state.sessions.get_mut(&session_id) {
                    if let Some(a) = s.account.as_mut() {
                        a.device_challenge = Some((challenge.clone(), nonce));
                    }
                }
                AccountReply::DeviceChallenge { challenge }
            }
        }
        AccountRequest::DeviceAdd {
            device_id,
            public_key,
            signature,
        } => {
            let pending = state
                .sessions
                .get_mut(&session_id)
                .and_then(|mut s| s.account.as_mut().and_then(|a| a.device_challenge.take()));
            match pending {
                None => refused("DeviceAdd", "Ask for a challenge first."),
                Some((challenge, nonce)) => {
                    let key = l4f_accounts::service::NewDeviceKey {
                        device_id: &device_id,
                        public_key: &public_key,
                        signature: &signature,
                    };
                    match relay
                        .accounts
                        .devkey_add(&ctx, &user, &challenge, &nonce, key)
                        .await
                    {
                        Ok(()) => AccountReply::DeviceAdded,
                        Err(e) => refused("DeviceAdd", e.message()),
                    }
                }
            }
        }
        AccountRequest::TotpSetup => {
            let s = relay.accounts.totp_setup(&user);
            AccountReply::TotpSetup {
                secret: s.secret,
                uri: s.uri,
                sealed: s.sealed,
            }
        }
        AccountRequest::TotpEnable { sealed, code } => {
            if !relay.accounts.fresh(&info, now) && !vault_proven {
                refused(
                    "TotpEnable",
                    if user.has_password {
                        "Sign in with your password again to turn codes on."
                    } else {
                        "Confirm it's you with a provider you have linked first."
                    },
                )
            } else {
                match relay
                    .accounts
                    .totp_enable(&ctx, &user, &info, &sealed, &code)
                    .await
                {
                    Ok((recovery_codes, rotated)) => {
                        // The account's first second factor: l4f ended its other
                        // sessions and gave this one a new token. The old one no
                        // longer resolves, so `revalidate` would end this
                        // connection.
                        if let Some(new) = rotated {
                            if let Some(a) = state
                                .sessions
                                .get_mut(&session_id)
                                .as_mut()
                                .and_then(|s| s.account.as_mut())
                            {
                                a.token = new.token;
                                a.info = new.info;
                            }
                        }
                        crate::session::send_msg(
                            tx,
                            &reply(AccountReply::TotpEnabled { recovery_codes }),
                        )?;
                        refresh(state, &relay, session_id, user.id).await?;
                        return Ok(());
                    }
                    Err(e) => refused("TotpEnable", e.message()),
                }
            }
        }
        AccountRequest::VaultPut { k, v, expect } => {
            relay.vault_put(user.id, &k, &v, expect).await?
        }
        AccountRequest::VaultPage { k } => relay.vault_page(user.id, &k).await?,
        AccountRequest::ProviderList => provider::list(&relay, &user).await?,
        AccountRequest::ProviderStart {
            kind,
            link,
            secret,
            totp,
            recovery_code,
        } => {
            // A proof with a provider is the provider's page itself
            let proved = if link {
                prove_recent(
                    state,
                    &relay,
                    session_id,
                    &ctx,
                    &user,
                    &info,
                    secret.as_deref(),
                    (totp, recovery_code),
                )
                .await
                .map(|_| ())
            } else {
                Ok(())
            };
            match proved {
                Ok(()) => provider::start_for_account(
                    &relay, session_id, &user, kind, link, peer_ip, binding,
                ),
                Err(reason) => refused("ProviderStart", &reason),
            }
        }
        AccountRequest::ProviderUnlink {
            kind,
            secret,
            totp,
            recovery_code,
        } => {
            match prove_recent(
                state,
                &relay,
                session_id,
                &ctx,
                &user,
                &info,
                secret.as_deref(),
                (totp, recovery_code),
            )
            .await
            {
                Ok(now_user) => {
                    // The session the proof just made, not the one this began with
                    let info = state
                        .sessions
                        .get(&session_id)
                        .and_then(|s| s.account.as_ref().map(|a| a.info.clone()))
                        .unwrap_or(info);
                    provider::unlink(&relay, &ctx, &now_user, &info, kind).await?
                }
                Err(reason) => refused("ProviderUnlink", &reason),
            }
        }
        AccountRequest::PairNonce { pair, nonce } => {
            if nonce.len() == voipc_crypto::pair::NONCE_LEN {
                relay
                    .pair_event(user.id, pair, provider::PairEvent::Nonce(nonce))
                    .await;
            }
            return Ok(());
        }
        AccountRequest::PairApprove { pair, wrapped } => {
            if wrapped.len() <= 256 {
                relay
                    .pair_event(user.id, pair, provider::PairEvent::Wrapped(wrapped))
                    .await;
            }
            return Ok(());
        }
        AccountRequest::PairDecline { pair } => {
            relay
                .pair_event(user.id, pair, provider::PairEvent::Declined)
                .await;
            return Ok(());
        }
        AccountRequest::LogPurge { conv } => log::purge(&relay, user.id, conv.as_deref()).await?,
        AccountRequest::DeleteAccount {
            secret,
            totp,
            recovery_code,
        } => {
            match delete_account(
                state,
                &relay,
                session_id,
                &ctx,
                &user,
                &info,
                &secret,
                (totp, recovery_code),
            )
            .await
            {
                Ok(()) => {
                    crate::session::send_msg(tx, &reply(AccountReply::AccountDeleted))?;
                    crate::session::eject(state, session_id, "Your account was deleted.").await;
                    return Ok(());
                }
                Err(reason) => refused("DeleteAccount", &reason),
            }
        }
        AccountRequest::RecoveryKeyNew {
            secret,
            recovery_slot,
            reset_key,
            totp,
            recovery_code,
        } => {
            match recovery_key_new(
                state,
                &relay,
                session_id,
                &ctx,
                &user,
                &info,
                &secret,
                (&recovery_slot, &reset_key),
                (totp, recovery_code),
            )
            .await
            {
                Ok(()) => AccountReply::RecoveryKeyChanged,
                Err(reason) => refused("RecoveryKeyNew", &reason),
            }
        }
        AccountRequest::PasswordChange {
            old_secret,
            new_secret,
            pass_slot,
            totp,
            recovery_code,
        } => {
            match password_change(
                state,
                &relay,
                session_id,
                &ctx,
                &user,
                &info,
                (old_secret, new_secret, pass_slot),
                (totp, recovery_code),
            )
            .await
            {
                Ok(()) => AccountReply::PasswordChanged,
                Err(reason) => refused("PasswordChange", &reason),
            }
        }
        AccountRequest::LogKeyPublish { logkey, sig } => {
            log::publish(&relay, user.id, &logkey, &sig).await?
        }
        AccountRequest::LogKeys { accounts } => log::keys(&relay, &accounts)
            .await
            .unwrap_or_else(|e| read_failed("LogKeys", e)),
        AccountRequest::EpochPut { conv, epoch, wraps } => {
            let (out, told) = log::epoch_put(&relay, user.id, &conv, epoch, &wraps).await?;
            // A direct conversation's news, told the moment its writer goes by a pseudonym,
            // would tie the two for the other party: the keys wait for its next read
            let behind = !conv.starts_with("c:")
                && match state.sessions.get(&session_id).map(|s| s.user_id) {
                    Some(uid) => state.names_of(uid).await.1.is_some(),
                    None => false,
                };
            if !behind {
                for r in told {
                    tell(state, &r, AccountReply::LogNews { conv: conv.clone() }).await;
                }
            }
            out
        }
        AccountRequest::WrapsFetch { conv } => log::wraps(&relay, user.id, &conv)
            .await
            .unwrap_or_else(|e| read_failed("WrapsFetch", e)),
        AccountRequest::LogAppend {
            conv,
            epoch,
            ct,
            ttl_secs,
        } => match kept_post_ok(state, session_id, &conv).await {
            Err(reason) => refused("LogAppend", &reason),
            Ok(channel) => {
                let out = log::append(&relay, user.id, &conv, epoch, &ct, ttl_secs).await?;
                // Slow mode's clock starts with what was filed. A `ChainRekey` filed nothing
                // and the same post comes straight back; two connections at once can each
                // get one through, which the clock is not there to stop.
                if let (AccountReply::LogAppended { .. }, Some((user_id, channel_id))) =
                    (&out, channel)
                {
                    let _ = state
                        .post_rules(
                            session_id,
                            user_id,
                            channel_id,
                            crate::state::PostStamp::Kept,
                        )
                        .await;
                }
                // The other party, if online, reads it now: a live copy that
                // missed them (they just reloaded, or sit on no list the
                // writer sees) has nothing else to bring it before their next
                // sign-in. A channel's members read it on entering instead.
                if let (AccountReply::LogAppended { .. }, Some((a, b))) = (&out, dm_parties(&conv))
                {
                    let other = if a == user.id.0 { b } else { a };
                    tell(state, &other, AccountReply::LogNews { conv: conv.clone() }).await;
                }
                out
            }
        },
        AccountRequest::LogFetch { conv, after } => log::fetch(&relay, user.id, &conv, after)
            .await
            .unwrap_or_else(|e| read_failed("LogFetch", e)),
        AccountRequest::LogIndex => {
            let (convs, pending) = log::index(&relay, user.id).await?;
            for p in pending {
                crate::session::send_msg(tx, &reply(p))?;
            }
            convs
        }
        AccountRequest::LogJoin { conv } => {
            let user_id = state.sessions.get(&session_id).map(|s| s.user_id);
            let present = match user_id {
                Some(uid) => state.channels.read().await.values().any(|c| {
                    !c.info.log.is_empty() && c.info.log == conv && c.members.contains(&uid)
                }),
                None => false,
            };
            let (out, owners) = log::join(&relay, user.id, &conv, present).await?;
            for o in owners {
                tell(
                    state,
                    &o,
                    AccountReply::LogPending {
                        conv: conv.clone(),
                        joiners: vec![user.id.0],
                    },
                )
                .await;
            }
            out
        }
        AccountRequest::LogJoinMany { convs } => {
            let user_id = state.sessions.get(&session_id).map(|s| s.user_id);
            let here: std::collections::HashSet<String> = match user_id {
                Some(uid) => state
                    .channels
                    .read()
                    .await
                    .values()
                    .filter(|c| !c.info.log.is_empty() && c.members.contains(&uid))
                    .map(|c| c.info.log.clone())
                    .collect(),
                None => Default::default(),
            };
            let present: Vec<bool> = convs.iter().map(|c| here.contains(c)).collect();
            let (out, told) = log::join_many(&relay, user.id, &convs, &present).await?;
            for (conv, owners) in told {
                for o in owners {
                    tell(
                        state,
                        &o,
                        AccountReply::LogPending {
                            conv: conv.clone(),
                            joiners: vec![user.id.0],
                        },
                    )
                    .await;
                }
            }
            out
        }
        AccountRequest::ChainPut {
            conv,
            epoch,
            self_wrap,
            step,
            link,
            wraps,
            buckets,
            seals,
            last,
        } => {
            let sharing = state
                .sessions
                .get(&session_id)
                .map(|s| log::Sharing {
                    shares: s.shares_history,
                    may: holds_share_history(&s),
                })
                .unwrap_or(log::Sharing {
                    shares: false,
                    may: false,
                });
            let frame = log::ChainFrame {
                epoch,
                self_wrap,
                step,
                link,
                wraps,
                buckets,
                seals,
                last,
            };
            let (out, told) = log::chain_put(&relay, user.id, &conv, frame, sharing).await?;
            for r in told {
                tell(state, &r, AccountReply::LogNews { conv: conv.clone() }).await;
            }
            out
        }
        AccountRequest::LogMemberIds { conv, after } => {
            log::member_ids(&relay, user.id, &conv, after)
                .await
                .unwrap_or_else(|e| read_failed("LogMemberIds", e))
        }
        AccountRequest::ChainFetch { conv, after } => {
            log::chain_fetch(&relay, user.id, &conv, after)
                .await
                .unwrap_or_else(|e| read_failed("ChainFetch", e))
        }
        AccountRequest::WrapsPage { conv, asks } => log::wraps_page(&relay, user.id, &conv, &asks)
            .await
            .unwrap_or_else(|e| read_failed("WrapsPage", e)),
        AccountRequest::OwnChains { conv, before } => {
            log::own_chains(&relay, user.id, &conv, before)
                .await
                .unwrap_or_else(|e| read_failed("OwnChains", e))
        }
        AccountRequest::OwnBuckets { conv, after } => {
            log::own_buckets(&relay, user.id, &conv, after)
                .await
                .unwrap_or_else(|e| read_failed("OwnBuckets", e))
        }
        AccountRequest::BucketLists { conv, wanted } => {
            log::bucket_lists(&relay, user.id, &conv, &wanted)
                .await
                .unwrap_or_else(|e| read_failed("BucketLists", e))
        }
        AccountRequest::OwnChainRows { conv, chain, after } => {
            log::own_chain_rows(&relay, user.id, &conv, chain, after)
                .await
                .unwrap_or_else(|e| read_failed("OwnChainRows", e))
        }
        AccountRequest::LogLeave { conv } => log::leave(&relay, user.id, &conv).await?,
        AccountRequest::LogMembers { conv } => log::members_of(&relay, user.id, &conv)
            .await
            .unwrap_or_else(|e| read_failed("LogMembers", e)),
        AccountRequest::Admin { op, code } => {
            admin::handle(state, &relay, session_id, &user, &ctx, op, code, ask).await?
        }
        // Made `Admin` above
        AccountRequest::AdminAsk { .. } => refused("Admin", "Something went wrong."),
        AccountRequest::KeyChallenge if relay.accounts.hostkey(user.id).await?.is_none() => {
            refused("KeyChallenge", voipc_protocol::messages::NOT_KEYED)
        }
        AccountRequest::KeyChallenge => {
            let nonce: [u8; 16] = rand::random();
            let challenge = relay.accounts.hostkey_challenge(Some(&user), &nonce);
            if let Some(mut s) = state.sessions.get_mut(&session_id) {
                if let Some(a) = s.account.as_mut() {
                    a.key_challenge = Some((challenge.clone(), nonce));
                }
            }
            AccountReply::KeyChallenge { challenge }
        }
        AccountRequest::KeyStepUp {
            challenge,
            signature,
            totp,
            recovery_code,
            web,
        } => {
            let pending = state
                .sessions
                .get_mut(&session_id)
                .and_then(|mut s| s.account.as_mut().and_then(|a| a.key_challenge.take()));
            let proof = match (pending, Binding::claimed(web, binding)) {
                (Some((issued, nonce)), Some(b)) if issued == challenge => Ok((nonce, b)),
                (_, None) => Err(NOT_THIS_CONNECTION.to_string()),
                _ => Err("That took too long. Try again.".to_string()),
            };
            let stepped = match proof {
                Ok((nonce, b)) => {
                    let check = KeyProof {
                        challenge: &challenge,
                        nonce: &nonce,
                        binding: &b,
                        signature: &signature,
                    };
                    confirm_again_key(
                        state,
                        &relay,
                        session_id,
                        &ctx,
                        &user,
                        &info,
                        check,
                        (totp, recovery_code),
                    )
                    .await
                }
                Err(reason) => Err(reason),
            };
            match stepped {
                Ok(_) => {
                    if let Some(mut s) = state.sessions.get_mut(&session_id) {
                        if let Some(a) = s.account.as_mut() {
                            a.key_stepped = Some(std::time::Instant::now());
                        }
                    }
                    AccountReply::SteppedUp
                }
                Err(reason) => refused("KeyStepUp", &reason),
            }
        }
        AccountRequest::LoginKeySet {
            login_key,
            identity_sig,
            pass_slot,
            web,
        } => match login_key_set(
            state,
            &relay,
            session_id,
            &ctx,
            &user,
            &info,
            (&login_key, &identity_sig, pass_slot.as_deref()),
            Binding::claimed(web, binding),
        )
        .await
        {
            Ok(true) => AccountReply::PasswordChanged,
            Ok(false) => AccountReply::LoginKeySaved,
            Err(reason) => refused("LoginKeySet", &reason),
        },
        AccountRequest::ProfileSet { name } => {
            profile::set_name(state, &relay, session_id, &user, name).await?
        }
        AccountRequest::ProfilePictureSet { image } => {
            profile::set_picture(state, &relay, session_id, &user, image).await?
        }
        // Who reads what here, and what they look for, goes in no log and no counter
        AccountRequest::ArchiveFetch {
            channel_id,
            thread,
            before,
            pinned,
        } => archive::fetch(
            state, &relay, session_id, user.id, channel_id, thread, before, pinned,
        )
        .await
        .unwrap_or_else(|e| read_failed("ArchiveFetch", e)),
        AccountRequest::ArchiveSearch {
            channel_id,
            query,
            from,
        } => archive::search(state, &relay, session_id, user.id, channel_id, query, from)
            .await
            .unwrap_or_else(|e| read_failed("ArchiveSearch", e)),
        AccountRequest::ArchiveMine { action, scope } => {
            archive::mine(state, &relay, session_id, user.id, action, scope)
                .await
                .unwrap_or_else(|e| read_failed("ArchiveMine", e))
        }
        AccountRequest::ArchiveChannels => archive::channels(state, &relay, session_id)
            .await
            .unwrap_or_else(|e| read_failed("ArchiveChannels", e)),
    };
    crate::session::send_msg(tx, &reply(out))
}

/// A channel's stored copy is held to the channel's own rules, as the live
/// post is (`ServerState::post_rules`): written from inside the channel, by a
/// manager in an announcement channel, at slow mode's pace. A direct
/// conversation has its two parties, which `log::append` checks; a copy there
/// carries the writer's account, so none is kept behind a pseudonym, where the
/// live message goes out under the alias and the copy would tie the two.
///
/// Starts no clock. For a channel, says whose and where, so the caller can once it is filed.
async fn kept_post_ok(
    state: &ServerState,
    session_id: u32,
    conv: &str,
) -> Result<Option<(u32, u32)>, String> {
    let user_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.user_id)
        .ok_or("Sign in with an account first.")?;
    if !conv.starts_with("c:") {
        if state.names_of(user_id).await.1.is_some() {
            return Err("nothing is kept while you write under a pseudonym.".into());
        }
        if state
            .sessions
            .get(&session_id)
            .is_some_and(|s| s.silence.direct())
        {
            return Err(crate::restrict::DIRECT_HELD.into());
        }
        return Ok(None);
    }
    let channel_id = {
        let channels = state.channels.read().await;
        channels
            .iter()
            .find(|(_, c)| {
                !c.info.log.is_empty()
                    && c.info.log == conv
                    && state.passes(session_id, &c.gate.groups)
            })
            .map(|(id, _)| *id)
    };
    // An anonymous channel, or one hiding its members, offers no log; nor does one outside
    // its gate, in the same words.
    let channel_id = channel_id.ok_or("That channel keeps no messages.")?;
    state
        .post_rules(
            session_id,
            user_id,
            channel_id,
            crate::state::PostStamp::KeptCheck,
        )
        .await?;
    Ok(Some((user_id, channel_id)))
}

/// The account behind `session_id` leaves `channel_id`'s log: kicked from
/// the channel, or it left a text channel (1.0, D10: the relay does it, so a
/// modified client cannot stay a reader), so what is written there from now
/// on is not for them. Moving between voice channels keeps a log; "Stop
/// keeping this channel" (`LogLeave`) ends it there.
pub async fn out_of_log(state: &ServerState, channel_id: u32, session_id: u32) {
    leave_log(state, channel_id, session_id, true).await;
}

/// `out_of_log` for someone a gate put out, who waits for nothing to come back
/// (`log::unseat`).
pub async fn gated_out_of_log(state: &ServerState, channel_id: u32, session_id: u32) {
    leave_log(state, channel_id, session_id, false).await;
}

async fn leave_log(state: &ServerState, channel_id: u32, session_id: u32, waits: bool) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    let Some(account) = state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.user.id.0))
    else {
        return;
    };
    let conv = state
        .channels
        .read()
        .await
        .get(&channel_id)
        .map(|c| c.info.log.clone())
        .unwrap_or_default();
    if conv.is_empty() {
        return;
    }
    let out = if waits {
        log::remove(relay.store(), &conv, &account).await
    } else {
        log::unseat(relay.store(), &conv, &account).await
    };
    if let Err(e) = out {
        warn!("log membership after a kick: {e}");
    }
}

/// At boot: each persistent channel's password against the one its log was
/// kept under (a fingerprint in `voipc_meta`). A channel locked or given a new
/// password in channels.json while the relay was down keeps none of its
/// stored members — nobody was there to show they know the new one — and they
/// come back the next time they join it with the password.
pub async fn locked_logs_at_boot(state: &ServerState) -> Result<()> {
    let Some(relay) = state.accounts.as_ref() else {
        return Ok(());
    };
    let logs: Vec<(String, Option<String>)> = {
        let channels = state.channels.read().await;
        channels
            .values()
            // One made in the app changes its password only while running, where
            // `locked_log` has already done this: its fingerprint is never written.
            .filter(|c| c.persistent && !c.kept && !c.log_conv.is_empty())
            .map(|c| {
                (
                    c.log_conv.clone(),
                    c.password.as_ref().map(|p| p.to_string()),
                )
            })
            .collect()
    };
    for (conv, password) in logs {
        use sha2::{Digest, Sha256};
        let k = format!("pw:{}", &hex::encode(Sha256::digest(conv.as_bytes()))[..29]);
        let fp: Vec<u8> = password
            .map(|p| Sha256::digest(format!("voipc-lock/v1|{p}").as_bytes()).to_vec())
            .unwrap_or_default();
        let was: Option<Vec<u8>> = db!(relay.store(), pool => {
            sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = $1").bind(&k).fetch_optional(pool).await?
        });
        if was.as_deref().unwrap_or_default() == fp {
            continue;
        }
        if !fp.is_empty() {
            log::keep_only(relay.store(), &conv, &[]).await?;
            info!(conv, "a channel's password changed while the server was down: its stored members join again");
        }
        db!(relay.store(), pool => {
            sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = excluded.v").bind(&k).bind(&fp[..]).execute(pool).await?;
        });
    }
    Ok(())
}

/// `channel_id` has a new password: of its log's members, only those in the
/// channel now (who were let in) stay.
pub async fn locked_log(state: &ServerState, channel_id: u32) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    let (conv, users) = {
        let channels = state.channels.read().await;
        let Some(c) = channels.get(&channel_id) else {
            return;
        };
        (
            c.info.log.clone(),
            c.members.iter().copied().collect::<Vec<_>>(),
        )
    };
    if conv.is_empty() {
        return;
    }
    let keep: Vec<[u8; 16]> = users
        .iter()
        .filter_map(|u| state.sessions.contains_key(u).then_some(*u))
        .filter_map(|sid| {
            state
                .sessions
                .get(&sid)
                .and_then(|s| s.account.as_ref().map(|a| a.user.id.0))
        })
        .collect();
    if let Err(e) = log::keep_only(relay.store(), &conv, &keep).await {
        warn!("log membership after a new password: {e}");
    }
}

/// A statement against the relay's database, for tests that play a relay
/// doing what it should not, or age rows.
#[cfg(test)]
pub(crate) async fn raw(relay: &Relay, sql: &str) -> Result<i64> {
    let n = db!(relay.store(), pool => {
        sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.to_string())).fetch_optional(pool).await?.unwrap_or(0)
    });
    Ok(n)
}

/// An account reply to whichever session `account` has here, if any.
async fn tell(state: &ServerState, account: &[u8; 16], r: AccountReply) {
    let tx = state
        .account_sessions
        .get(account)
        .and_then(|sid| state.sessions.get(&*sid).map(|s| s.control_tx.clone()));
    if let Some(tx) = tx {
        let _ = crate::session::send_msg(&tx, &ServerMessage::Account(r));
    }
}

/// Re-reads the account after a change (codes on, a role granted) and tells
/// the client; an admin it became is announced to everyone as before.
pub async fn refresh(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: u32,
    user: AccountId,
) -> Result<()> {
    let read = scope_read(state, session_id);
    let Some(user) = relay.store().user_by_id(user).await? else {
        return Ok(());
    };
    let scopes = relay.accounts.effective_scopes(&user).await?;
    apply_scopes(state, relay, session_id, user, scopes, read).await
}

/// A read of an account's scopes is about to start. Between it and the write there
/// are more reads, and two at once on one session must not finish in the wrong
/// order: a grant would be undone by the older answer until the next pass of
/// `revalidate`. So a read older than the last one written is dropped. Whatever
/// changed a role starts a read after changing it, so that one has seen the change.
pub(crate) fn scope_read(state: &ServerState, session_id: u32) -> u64 {
    state.sessions.get_mut(&session_id).map_or(0, |mut s| {
        s.scope_read += 1;
        s.scope_read
    })
}

/// Every signed-in connection against the database, each
/// `REVALIDATE_MINUTES`: what the server's shell (another process) changed — a
/// role given or taken away, codes reset, the sessions ended — reaches
/// connections already open.
pub async fn revalidate(state: &Arc<ServerState>) {
    let Some(relay) = state.accounts.clone() else {
        return;
    };
    let live: Vec<(u32, String, Vec<String>, bool, Standing)> = state
        .sessions
        .iter()
        .filter_map(|e| {
            e.value().account.as_ref().map(|a| {
                (
                    *e.key(),
                    a.token.clone(),
                    a.scopes.clone(),
                    a.needs_2fa,
                    a.standing.clone(),
                )
            })
        })
        .collect();
    for (session_id, token, scopes, needs_2fa, standing) in live {
        let read = scope_read(state, session_id);
        match relay.accounts.session_from_token(&token, util::now()).await {
            Ok(None) => {
                // The token may have been rotated while this pass ran (turning
                // codes on does that): only the token the session still holds
                // counts (1.0 audit H1-11)
                let current = state
                    .sessions
                    .get(&session_id)
                    .and_then(|s| s.account.as_ref().map(|a| a.token.clone()));
                if current.as_deref() == Some(token.as_str()) {
                    crate::session::eject(state, session_id, "You were signed out of this server.")
                        .await;
                }
            }
            Ok(Some((user, _, now))) => {
                // A role given to an account without codes changes no scope
                // (its rights wait for them), only what the account is asked.
                // A group without privileges changes standing alone
                let changed = now != scopes
                    || relay
                        .accounts
                        .needs_2fa(&user)
                        .await
                        .is_ok_and(|n| n != needs_2fa)
                    || relay
                        .standing(&user, &now)
                        .await
                        .is_ok_and(|s| s != standing);
                if changed {
                    // The list of who holds what is read once, below
                    if let Err(e) =
                        apply_scopes_then(state, &relay, session_id, user, now, read).await
                    {
                        warn!("a change from the server's shell: {e}");
                    }
                }
            }
            Err(e) => warn!("checking a signed-in connection: {e}"),
        }
    }
    // Holders who are not here too, and every change above: a stored hide is read
    // against them
    refresh_chat_mods(state).await;
    // And the share flag of someone away, whose session cannot clear it
    if let Err(e) = log::recheck_shares(&relay).await {
        warn!("rechecking who shares: {e:#}");
    }
}

/// The session's powers as `scopes` say, and the account told. A change of
/// groups reaches what they see and where they may be (`gates`), one of
/// badges or privileges the rosters showing them.
/// Holds power over others, which spares it from a kick and an address ban.
/// Calling on everybody, taking reports, reading the log and sharing history act
/// on nobody: a helper holding only those can still be kicked.
pub fn holds_power(scopes: &[String]) -> bool {
    scopes
        .iter()
        .any(|s| ![MENTION_ALL, REPORTS, MODLOG, SHARE_HISTORY].contains(&s.as_str()))
}

/// What counts when asking "holds no more than I do": someone who shares is no harder
/// to act on for it.
pub(crate) fn without_share(scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .filter(|s| s.as_str() != SHARE_HISTORY)
        .cloned()
        .collect()
}

/// A group that gives nobody power over anyone: nothing, or only sharing what its
/// holder already holds. May start a link, and sit on what the move made.
pub(crate) fn no_power_over_anyone(scopes: &[String]) -> bool {
    scopes.iter().all(|s| s == SHARE_HISTORY)
}

/// Whether this session's account may call on everybody.
pub fn holds_mention_power(s: &crate::state::UserSession) -> bool {
    s.account
        .as_ref()
        .is_some_and(|a| scope::allowed(&a.scopes, MENTION_ALL))
}

/// Whether this session's switch counts on a relay with accounts. A guest, or a token
/// admin not signed in, holds no privileges.
pub fn holds_share_history(s: &crate::state::UserSession) -> bool {
    s.account
        .as_ref()
        .is_some_and(|a| scope::allowed(&a.scopes, SHARE_HISTORY))
}

/// Whether this session's account may hide messages.
pub fn holds_hide(s: &crate::state::UserSession) -> bool {
    s.account
        .as_ref()
        .is_some_and(|a| scope::allowed(&a.scopes, HIDE))
}

/// Holders of `voipc:reports` who are away and could read a sealed copy: a role
/// that grants it (not one still waiting for codes), a log key to wrap to, not
/// banned. Group by group until there are `want`, so what this reads stays small.
pub async fn takers_away(
    state: &ServerState,
    relay: &Relay,
    want: usize,
) -> Result<Vec<ReportTaker>> {
    const PER_GROUP: u32 = 8;
    let mut read = std::collections::BTreeSet::new();
    let mut away = Vec::new();
    for role in relay.store().roles().await? {
        if away.len() >= want {
            break;
        }
        if !scope::allowed(&role.scopes, REPORTS) {
            continue;
        }
        let (users, _) = relay.store().role_members(role.id, PER_GROUP, 0).await?;
        for user in users {
            let id = user.id.0;
            if !read.insert(id)
                || state.account_sessions.contains_key(&id)
                || crate::bans::account_ban(state, id).is_some()
                || !scope::allowed(&relay.accounts.effective_scopes(&user).await?, REPORTS)
                || !log::has_key(relay, &id).await?
            {
                continue;
            }
            away.push(ReportTaker {
                user_id: None,
                account: Some(id),
                name: user.username.clone(),
            });
        }
    }
    Ok(away)
}

/// Accounts one `ChatMods` lists at most: about 54 KiB, one frame.
pub(crate) const CHAT_MODS_MAX: usize = 3000;

/// Every account holding a privilege (`holds_power`), whether or not it is here,
/// by account id so that repeated reads compare equal.
pub async fn read_chat_mods(relay: &Relay) -> Result<Vec<ChatMod>> {
    let page = chat_mods_page();
    let mut read = std::collections::BTreeSet::new();
    let mut mods = std::collections::BTreeMap::new();
    for role in relay.store().roles().await? {
        if !holds_power(&role.scopes) {
            continue;
        }
        let mut offset = 0;
        loop {
            let (users, total) = relay.store().role_members(role.id, page, offset).await?;
            for user in &users {
                if !read.insert(user.id.0) {
                    continue;
                }
                // Not the group's: one waiting for codes grants nothing yet
                let scopes = relay.accounts.effective_scopes(user).await?;
                if holds_power(&scopes) {
                    let row = ChatMod {
                        account: user.id.0,
                        hide: scope::allowed(&scopes, HIDE),
                        admin: is_star(&scopes),
                    };
                    mods.insert(user.id.0, row);
                }
            }
            offset += users.len() as u32;
            if users.is_empty() || i64::from(offset) >= total {
                break;
            }
        }
    }
    if mods.len() > CHAT_MODS_MAX {
        warn!(
            held = mods.len(),
            "more accounts hold privileges than clients can be told of: \
             those past the first {CHAT_MODS_MAX} are not spared from a hide"
        );
    }
    Ok(mods.into_values().take(CHAT_MODS_MAX).collect())
}

/// Holders are read a page at a time: 500, and two in tests, to see the pages join up (a
/// measurement sets the real one with `ROUND_C_PAGE`). One function for both, so what the
/// tests run is what the relay runs.
fn chat_mods_page() -> u32 {
    if !cfg!(test) {
        return 500;
    }
    std::env::var("ROUND_C_PAGE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
}

/// Reads who holds what and tells everybody, if that changed. One read at a time, so that
/// two at once cannot end with the older one's answer; a connect waits for the list only
/// while it is swapped and told, never while it is read (W2-2).
pub async fn refresh_chat_mods(state: &ServerState) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    let _reading = state.chat_mods_reading.lock().await;
    #[cfg(test)]
    state
        .chat_mods_reads
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mods = match read_chat_mods(relay).await {
        Ok(mods) => mods,
        Err(e) => {
            warn!("reading who holds privileges: {e:#}");
            return;
        }
    };
    let mut held = state.chat_mods.write().await;
    if *held == mods {
        return;
    }
    *held = mods;
    match encode_server_msg(&ServerMessage::ChatMods { mods: held.clone() }) {
        Ok(data) => state.broadcast_raw_to_all(&data).await,
        Err(e) => warn!("telling who holds privileges: {e:#}"),
    }
}

/// A client that just connected: who holds what. Before it can ask for any stored
/// log, whose hides are read against this.
pub async fn chat_mods_at_connect(state: &ServerState, tx: &ControlTx) {
    let mods = state.chat_mods.read().await.clone();
    if !mods.is_empty() {
        let _ = crate::session::send_msg(tx, &ServerMessage::ChatMods { mods });
    }
}

/// A client that just connected: who may call on everybody, its own badges, and
/// to everybody else, itself if it may.
pub async fn mention_power_at_connect(
    state: &ServerState,
    session_id: u32,
    user_id: u32,
    tx: &crate::control::ControlTx,
) {
    let holders: Vec<u32> = state
        .sessions
        .iter()
        .filter(|s| holds_mention_power(s))
        .map(|s| s.user_id)
        .collect();
    if holders.contains(&user_id) {
        if let Ok(data) = encode_server_msg(&ServerMessage::MentionPower {
            user_ids: vec![user_id],
            on: true,
        }) {
            state.broadcast_raw_to_all(&data).await;
        }
    }
    if !holders.is_empty() {
        let _ = crate::session::send_msg(
            tx,
            &ServerMessage::MentionPower {
                user_ids: holders,
                on: true,
            },
        );
    }
    let badges = state.sessions.get(&session_id).and_then(|s| {
        s.account
            .as_ref()
            .map(|a| a.standing.my_badges.clone())
            .filter(|b| !b.is_empty())
    });
    if let Some(badges) = badges {
        let _ = crate::session::send_msg(tx, &ServerMessage::MyBadges { badges });
    }
}

pub(crate) async fn apply_scopes(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: u32,
    user: User,
    scopes: Vec<String>,
    read: u64,
) -> Result<()> {
    if apply_scopes_then(state, relay, session_id, user, scopes, read).await? {
        refresh_chat_mods(state).await;
    }
    Ok(())
}

/// `apply_scopes`, leaving the list of who holds what to the caller: true when it is to be
/// read again. A pass over many sessions reads it once at its end, not once each (W2-2).
async fn apply_scopes_then(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: u32,
    user: User,
    scopes: Vec<String>,
    read: u64,
) -> Result<bool> {
    let info = relay.info_of(&user, &scopes).await?;
    let account = info.id;
    let standing = relay.standing(&user, &scopes).await?;
    let (my_badges, calls, called_before, editor_changed, listed_changed, reads_restrictions);
    let stopped_sharing;
    let (tx, user_id, channel_id, is_admin, became_admin, regated, shown) = {
        let Some(mut s) = state.sessions.get_mut(&session_id) else {
            return Ok(false);
        };
        if read < s.scope_written {
            return Ok(false);
        }
        s.scope_written = read;
        let (was_admin, was_editor) = (s.is_admin, s.powers.has(Powers::CHANNELS));
        let could_call = holds_mention_power(&s);
        let was_listed = (s.is_moderator, holds_hide(&s));
        let could_restrict = s.can(Powers::RESTRICT);
        s.set_scopes(user, scopes);
        // The relay only ever clears this: only the client may ask for it
        stopped_sharing = s.shares_history && !holds_share_history(&s);
        if stopped_sharing {
            s.shares_history = false;
        }
        listed_changed = was_listed != (s.is_moderator, holds_hide(&s)) || s.is_admin != was_admin;
        reads_restrictions = s.can(Powers::RESTRICT) && !could_restrict;
        let mut old = Standing::default();
        if let Some(a) = s.account.as_mut() {
            a.needs_2fa = info.needs_2fa;
            old = std::mem::replace(&mut a.standing, standing);
        }
        let new = s.account.as_ref().map(|a| &a.standing);
        my_badges = new
            .filter(|n| n.my_badges != old.my_badges)
            .map(|n| n.my_badges.clone());
        calls = holds_mention_power(&s);
        called_before = could_call;
        editor_changed = s.powers.has(Powers::CHANNELS) != was_editor;
        (
            s.control_tx.clone(),
            s.user_id,
            s.channel_id,
            s.is_admin,
            s.is_admin != was_admin,
            s.is_admin != was_admin || new.is_some_and(|n| n.groups != old.groups),
            s.powers.has(Powers::CHANNELS) != was_editor
                || new.is_some_and(|n| n.badges != old.badges),
        )
    };
    crate::session::send_msg(&tx, &ServerMessage::Account(AccountReply::Info(info)))?;
    if let Some(badges) = my_badges {
        crate::session::send_msg(&tx, &ServerMessage::MyBadges { badges })?;
    }
    if calls != called_before {
        let data = encode_server_msg(&ServerMessage::MentionPower {
            user_ids: vec![user_id],
            on: calls,
        })?;
        state.broadcast_raw_to_all(&data).await;
    }
    if stopped_sharing {
        log::set_shares(relay.store(), &account, false).await?;
        let data = encode_server_msg(&ServerMessage::UserHistorySharing {
            user_id,
            enabled: false,
        })?;
        state.broadcast_raw_to_all(&data).await;
    }
    if became_admin {
        let data = encode_server_msg(&ServerMessage::AdminStatus { user_id, is_admin })?;
        state.broadcast_raw_to_all(&data).await;
    }
    if regated {
        crate::gates::standing_changed(state, session_id).await;
    }
    // Who manages channels also sees the empty categories
    if editor_changed {
        crate::layout::send(state, session_id).await;
    }
    if shown {
        let info = crate::session::user_info_for(state, user_id, session_id, channel_id);
        crate::session::broadcast_user_updated(state, info).await;
    }
    crate::restrict::standing_changed(state, session_id).await;
    if reads_restrictions {
        crate::restrict::reasons_for(state, &tx);
    }
    Ok(listed_changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_url_is_logged_without_its_password() {
        assert_eq!(
            redact("postgres://u:pw@db.example/voipc"),
            "postgres://…@db.example/voipc"
        );
        assert_eq!(
            redact("postgres://u@db.example/voipc?password=pw"),
            "postgres://…@db.example/voipc?…"
        );
        assert_eq!(redact("sqlite://voipc.db?mode=rwc"), "sqlite://voipc.db?…");
        assert_eq!(redact("sqlite://voipc.db"), "sqlite://voipc.db");
    }

    #[test]
    fn a_missing_key_file_is_made_only_for_a_new_database() {
        let path = std::env::temp_dir().join(format!("voipc-key-{:08x}", rand::random::<u32>()));
        let p = path.to_str().unwrap();
        let e = master_key(p, true).unwrap_err().to_string();
        assert!(e.contains("not here"), "{e}");
        assert!(
            !path.exists(),
            "no new key next to a database made with another"
        );
        let k = master_key(p, false).unwrap();
        assert_eq!(master_key(p, true).unwrap(), k, "read back");
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn a_database_refuses_another_accounts_key() {
        let db =
            std::env::temp_dir().join(format!("voipc-keycheck-{:08x}.db", rand::random::<u32>()));
        let url = format!("sqlite://{}?mode=rwc", db.display());
        let cfg = AccountsConfig {
            mode: AccountsMode::Optional,
            ..Default::default()
        };
        let store = Store::connect(&url).await.unwrap();
        Relay::open_with(&cfg, store.clone(), &[9u8; 32])
            .await
            .unwrap();
        let e = Relay::open_with(&cfg, store.clone(), &[8u8; 32])
            .await
            .err()
            .expect("refused")
            .to_string();
        assert!(e.contains("not the one this database was made with"), "{e}");
        Relay::open_with(&cfg, store, &[9u8; 32])
            .await
            .expect("its own key still opens it");
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
        }
    }

    #[tokio::test]
    async fn a_role_made_before_fine_scopes_keeps_what_it_granted() {
        let db =
            std::env::temp_dir().join(format!("voipc-moderate-{:08x}.db", rand::random::<u32>()));
        let url = format!("sqlite://{}?mode=rwc", db.display());
        let cfg = AccountsConfig {
            mode: AccountsMode::Optional,
            ..Default::default()
        };
        let store = Store::connect(&url).await.unwrap();
        Relay::open_with(&cfg, store.clone(), &[9u8; 32])
            .await
            .unwrap();
        // As a 1.6 relay left them: its moderator, and a role of the owner's
        let moderator = store.role_by_name("moderator").await.unwrap().unwrap();
        store
            .set_role_scopes(moderator.id, &[MODERATE_WAS.to_string()])
            .await
            .unwrap();
        store
            .create_role_with_scopes(
                "helpers",
                "",
                None,
                &[MODERATE_WAS.to_string(), "users:read".to_string()],
            )
            .await
            .unwrap();
        Relay::open_with(&cfg, store.clone(), &[9u8; 32])
            .await
            .unwrap();
        let scopes = |name: &'static str| {
            let store = store.clone();
            async move { store.role_by_name(name).await.unwrap().unwrap().scopes }
        };
        assert_eq!(
            scopes("moderator").await,
            ["voipc:ban", "voipc:channels", "voipc:kick"]
        );
        assert_eq!(
            scopes("helpers").await,
            ["users:read", "voipc:ban", "voipc:channels", "voipc:kick"]
        );
        let p = Powers::of(&scopes("moderator").await);
        assert!(p.has(Powers::KICK) && p.has(Powers::BAN) && p.has(Powers::CHANNELS));
        assert!(!p.has(Powers::BANS) && !p.has(Powers::EMOTES));
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
        }
    }

    /// The relay reads the right through `scope::allowed`, the app through
    /// `may_share_history`. A wildcard they disagree on is a flag the relay refuses, or one
    /// the app never asks for.
    #[test]
    fn the_two_readings_of_the_right_agree() {
        use voipc_protocol::types::may_share_history;
        for (grant, want) in [
            ("*", true),
            ("voipc:*", true),
            (SHARE_HISTORY, true),
            ("voipc:share_historyx", false),
            ("voipcx:*", false),
            ("voipc:share_history:*", false),
            ("voipc:kick", false),
            ("users:*", false),
            ("voipc*", false),
            ("", false),
        ] {
            let held = [grant.to_string()];
            assert_eq!(scope::allowed(&held, SHARE_HISTORY), want, "relay: {grant}");
            assert_eq!(
                may_share_history(21, true, Some(&held)),
                want,
                "app: {grant}"
            );
        }
    }

    /// `discord::FINE_SCOPES` is what ADMINISTRATOR comes to: all of them, one by one, and
    /// never `*`. A privilege added here and forgotten there fails this.
    #[test]
    fn the_fine_scopes_are_exactly_the_registered_privileges() {
        use std::collections::BTreeSet;
        use voipc_protocol::discord::FINE_SCOPES;
        let fine: BTreeSet<&str> = FINE_SCOPES.iter().copied().collect();
        let registered: BTreeSet<&str> = APP_SCOPES
            .iter()
            .map(|s| s.name)
            .filter(|s| *s != SHARE_HISTORY)
            .chain(["users:read", "users:admin", "roles:admin"])
            .collect();
        assert_eq!(fine, registered);
        // Only an admin applies this one: Discord's ADMINISTRATOR does not bring it
        assert!(!FINE_SCOPES.contains(&SHARE_HISTORY));
        assert_eq!(fine.len(), FINE_SCOPES.len(), "each once");
        let held: Vec<String> = FINE_SCOPES.iter().map(|s| s.to_string()).collect();
        assert!(!is_star(&held), "all of them together are not `*`");
        assert!(is_star(&["*".to_string()]));
        // ... and every privilege a session can hold is in it
        let p = Powers::of(&held);
        for one in [
            Powers::KICK,
            Powers::BAN,
            Powers::BANS,
            Powers::CHANNELS,
            Powers::EMOTES,
            Powers::USERS_READ,
            Powers::USERS_ADMIN,
            Powers::ROLES_ADMIN,
            Powers::RESTRICT,
        ] {
            assert!(p.has(one));
        }
    }

    #[test]
    fn powers_follow_wildcards_and_nothing_else() {
        let p = |s: &[&str]| Powers::of(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(p(&["voipc:*"]).has(Powers::EMOTES));
        assert!(!p(&["voipc:*"]).has(Powers::USERS_READ));
        assert!(p(&["*"]).has(Powers::ROLES_ADMIN));
        assert_eq!(p(&["voipc:kickx", "voipcx:kick"]), Powers::default());
        assert!(is_star(&["*".into()]) && !is_star(&["voipc:*".into()]));
        // The ninth bit, past what a byte held
        assert!(p(&["voipc:*"]).has(Powers::RESTRICT) && p(&["*"]).has(Powers::RESTRICT));
        assert!(p(&["voipc:restrict"]).has(Powers::RESTRICT));
        assert!(!p(&["voipc:restrict"]).has(Powers::KICK));
        assert!(!p(&["voipc:kick", "roles:admin"]).has(Powers::RESTRICT));
        // These three read the scopes themselves
        assert_eq!(
            p(&["voipc:hide", "voipc:reports", "voipc:modlog"]),
            Powers::default()
        );
    }

    /// The moderator group's rules, on every database a relay can run on.
    mod moderator_group {
        use super::*;

        const OLD: [&str; 3] = ["voipc:ban", "voipc:channels", "voipc:kick"];
        const NEW: [&str; 7] = [
            "voipc:ban",
            "voipc:channels",
            "voipc:hide",
            "voipc:kick",
            "voipc:modlog",
            "voipc:reports",
            "voipc:restrict",
        ];

        /// New databases: a SQLite file, and with `VOIPC_TEST_POSTGRES` also one on
        /// that server (`postgres://user@host:port/postgres`, a throwaway; no CI
        /// job runs one, so this is the only check of that SQL).
        struct Databases {
            stores: Vec<Store>,
            file: std::path::PathBuf,
        }

        impl Drop for Databases {
            fn drop(&mut self) {
                for suffix in ["", "-wal", "-shm", ".lock"] {
                    let _ = std::fs::remove_file(format!("{}{suffix}", self.file.display()));
                }
            }
        }

        async fn databases() -> Databases {
            let id = rand::random::<u32>();
            let file = std::env::temp_dir().join(format!("voipc-moderator-{id:08x}.db"));
            let url = format!("sqlite://{}?mode=rwc", file.display());
            let mut stores = vec![Store::connect(&url).await.unwrap()];
            if let Ok(server) = std::env::var("VOIPC_TEST_POSTGRES") {
                let name = format!("voipc_moderator_{id:08x}");
                let admin = Store::connect(&server).await.unwrap();
                db!(&admin, pool => {
                    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                        .execute(pool)
                        .await
                        .unwrap();
                });
                let (base, _) = server.rsplit_once('/').unwrap();
                stores.push(Store::connect(&format!("{base}/{name}")).await.unwrap());
            }
            Databases { stores, file }
        }

        async fn boot(store: &Store) {
            let cfg = AccountsConfig {
                mode: AccountsMode::Optional,
                ..Default::default()
            };
            Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                .await
                .unwrap();
        }

        async fn group(store: &Store) -> l4f_accounts::model::Role {
            store.role_by_name("moderator").await.unwrap().unwrap()
        }

        async fn set(store: &Store, scopes: &[&str]) {
            let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
            let id = group(store).await.id;
            store.set_role_scopes(id, &scopes).await.unwrap();
        }

        /// As a relay before 1.10 left it: the group holding `scopes`, the old
        /// words, and the question of widening it not yet decided.
        async fn before_1_10(store: &Store, scopes: &[&str]) {
            set(store, scopes).await;
            let m = group(store).await;
            store
                .update_role(m.id, MODERATOR_SAID, m.badge.as_deref())
                .await
                .unwrap();
            db!(store, pool => {
                sqlx::query("DELETE FROM voipc_meta WHERE k = 'moderator_1_10'")
                    .execute(pool)
                    .await
                    .unwrap();
            });
        }

        #[tokio::test]
        async fn a_new_moderator_group_has_the_new_privileges() {
            let dbs = databases().await;
            for store in &dbs.stores {
                boot(store).await;
                let m = group(store).await;
                assert_eq!(m.scopes, NEW);
                assert_eq!(m.description, MODERATOR_SAYS);
                assert_eq!(m.badge.as_deref(), Some("mod"));
                assert!(Powers::of(&m.scopes).has(Powers::RESTRICT));
                // Its very first boot decided too: trimmed before any other, it is
                // not taken for an upgrade at the next
                set(store, &OLD).await;
                boot(store).await;
                assert_eq!(group(store).await.scopes, OLD);
            }
        }

        #[tokio::test]
        async fn an_untouched_moderator_gains_them_once_on_upgrade() {
            let dbs = databases().await;
            for store in &dbs.stores {
                boot(store).await;
                before_1_10(store, &OLD).await;
                let before = group(store).await;
                assert_eq!(before.scopes, OLD, "control: nothing has widened it yet");
                boot(store).await;
                let m = group(store).await;
                assert_eq!(m.scopes, NEW);
                assert_eq!(m.id, before.id, "the same group, with its members");
                assert_eq!(m.description, MODERATOR_SAYS);
                assert_eq!(m.badge.as_deref(), Some("mod"));
                boot(store).await;
                assert_eq!(group(store).await.scopes, NEW);
            }
        }

        /// From 1.6 in one step: what the old scope became is the old default.
        /// Any other group keeps exactly what the old scope granted.
        #[tokio::test]
        async fn a_moderator_from_before_1_7_gains_them_too_and_other_groups_do_not() {
            let dbs = databases().await;
            for store in &dbs.stores {
                boot(store).await;
                before_1_10(store, &[MODERATE_WAS]).await;
                store
                    .create_role_with_scopes("helpers", "", None, &[MODERATE_WAS.to_string()])
                    .await
                    .unwrap();
                boot(store).await;
                assert_eq!(group(store).await.scopes, NEW);
                let helpers = store.role_by_name("helpers").await.unwrap().unwrap();
                assert_eq!(helpers.scopes, OLD);
            }
        }

        #[tokio::test]
        async fn an_edited_moderator_is_left_alone() {
            let edits: [&[&str]; 4] = [
                &[],
                &["voipc:ban", "voipc:kick"],
                &["voipc:ban", "voipc:bans", "voipc:channels", "voipc:kick"],
                &["voipc:ban", "voipc:channels", "voipc:emotes"],
            ];
            for edited in edits {
                let dbs = databases().await;
                for store in &dbs.stores {
                    boot(store).await;
                    before_1_10(store, edited).await;
                    boot(store).await;
                    let m = group(store).await;
                    assert_eq!(m.scopes, edited);
                    assert_eq!(m.description, MODERATOR_SAID, "{edited:?}");
                    // The one chance has passed: back at the old three is the owner's choice
                    set(store, &OLD).await;
                    boot(store).await;
                    assert_eq!(group(store).await.scopes, OLD, "after {edited:?}");
                }
            }
        }

        /// The owner's own words are theirs; only the privileges were the default.
        #[tokio::test]
        async fn a_group_with_other_words_keeps_them() {
            let dbs = databases().await;
            for store in &dbs.stores {
                boot(store).await;
                before_1_10(store, &OLD).await;
                let id = group(store).await.id;
                store
                    .update_role(id, "Our helpers", Some("crew"))
                    .await
                    .unwrap();
                boot(store).await;
                let m = group(store).await;
                assert_eq!(m.scopes, NEW);
                assert_eq!(
                    (m.description.as_str(), m.badge.as_deref()),
                    ("Our helpers", Some("crew"))
                );
            }
        }

        /// The log's own SQL on each database: i64 ids and times, and the longest
        /// names, which only Postgres holds to their VARCHAR limits.
        #[tokio::test]
        async fn the_restrictions_round_trip_on_both_backends() {
            use crate::bans::Key;
            use crate::restrict::Held;
            let dbs = databases().await;
            for store in &dbs.stores {
                let cfg = AccountsConfig {
                    mode: AccountsMode::Optional,
                    ..Default::default()
                };
                let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                let id = AccountId([7; 16]);
                store
                    .create_user(
                        &l4f_accounts::model::NewUser {
                            id,
                            username: "kim".into(),
                            display_name: "kim".into(),
                            email_pending: None,
                            password_hash: None,
                            created_at: 1,
                        },
                        None,
                    )
                    .await
                    .unwrap();
                let wide = "\u{1F600}";
                let voice = Held {
                    voice: true,
                    text: false,
                    by: wide.repeat(64),
                    reason: wide.repeat(200),
                    expires_at: None,
                };
                let posts = Held {
                    voice: false,
                    text: true,
                    expires_at: Some(1000),
                    ..voice.clone()
                };
                let (account, address) = (Key::Account(id.0), Key::Addr([9; 32]));
                relay.restriction_put(&account, &posts, 1).await.unwrap();
                relay.restriction_put(&account, &voice, 2).await.unwrap();
                relay.restriction_put(&address, &posts, 3).await.unwrap();

                let rows = relay.restriction_rows(999).await.unwrap();
                assert_eq!(rows.len(), 2, "one each: a second replaces the first");
                let (_, of_account) = rows.iter().find(|(k, _)| *k == account).unwrap();
                assert!(of_account.voice && !of_account.text);
                assert_eq!(of_account.expires_at, None);
                assert_eq!(of_account.reason.chars().count(), 200);
                let (_, of_address) = rows.iter().find(|(k, _)| *k == address).unwrap();
                assert!(!of_address.voice && of_address.text);
                assert_eq!(of_address.expires_at, Some(1000));

                // What ran out goes, and only that
                let rows = relay.restriction_rows(1000).await.unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].0, account);
                relay.restriction_put(&address, &posts, 3).await.unwrap();
                relay.restrictions_sweep(1000).await.unwrap();
                assert_eq!(relay.restriction_rows(0).await.unwrap().len(), 1);
                relay.restriction_delete(&account).await.unwrap();
                assert!(relay.restriction_rows(0).await.unwrap().is_empty());
            }
        }

        /// What says a sealed report can be kept for someone away.
        #[tokio::test]
        async fn a_log_key_is_found_on_both_backends() {
            let dbs = databases().await;
            for store in &dbs.stores {
                let cfg = AccountsConfig {
                    mode: AccountsMode::Optional,
                    ..Default::default()
                };
                let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                let id = AccountId([7; 16]);
                store
                    .create_user(
                        &l4f_accounts::model::NewUser {
                            id,
                            username: "kim".into(),
                            display_name: "kim".into(),
                            email_pending: None,
                            password_hash: None,
                            created_at: 1,
                        },
                        None,
                    )
                    .await
                    .unwrap();
                assert!(!log::has_key(&relay, &id.0).await.unwrap());
                use voipc_crypto::log::LogKey;
                let identity = voipc_crypto::generate_identity_key_pair();
                relay
                    .set_identity(id, &identity.identity_key().serialize())
                    .await
                    .unwrap();
                let key = LogKey::generate();
                assert!(matches!(
                    log::publish(&relay, id, &key.public(), &key.endorse(&identity))
                        .await
                        .unwrap(),
                    AccountReply::LogKeyStored
                ));
                assert!(log::has_key(&relay, &id.0).await.unwrap());
                assert!(!log::has_key(&relay, &[8; 16]).await.unwrap());
            }
        }

        /// A page of pins, what counts them against the vault's bound, and what pages a
        /// writer's joiners: every vault write runs through the first of these.
        #[tokio::test]
        async fn the_pin_pages_run_on_both_backends() {
            let dbs = databases().await;
            for store in &dbs.stores {
                let cfg = AccountsConfig {
                    mode: AccountsMode::Optional,
                    ..Default::default()
                };
                let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                let id = AccountId([1; 16]);
                relay
                    .store()
                    .create_user(
                        &l4f_accounts::model::NewUser {
                            id,
                            username: "kim".into(),
                            display_name: "kim".into(),
                            email_pending: None,
                            password_hash: None,
                            created_at: 1,
                        },
                        None,
                    )
                    .await
                    .unwrap();
                for k in ["pins.0", "item.prefs"] {
                    assert!(matches!(
                        relay.vault_put(id, k, &[1; 100], 0).await.unwrap(),
                        AccountReply::VaultStored { version: 1, .. }
                    ));
                }
                assert!(matches!(
                    relay.vault_put(id, "pins.0", &[2; 100], 0).await.unwrap(),
                    AccountReply::VaultConflict { blob: Some(_), .. }
                ));
                assert!(matches!(
                    relay.vault_page(id, "pins.0").await.unwrap(),
                    AccountReply::VaultPageFound { blob: Some(_), .. }
                ));
                assert_eq!(relay.vault(id).await.unwrap().len(), 1);
                let (convs, pending) = log::index(&relay, id).await.unwrap();
                assert!(matches!(convs, AccountReply::LogConvs { .. }));
                assert!(pending.is_empty());
                let (joined, _) = log::join(&relay, id, "c:lounge", true).await.unwrap();
                assert!(matches!(joined, AccountReply::LogJoined { .. }));
                assert!(matches!(
                    log::members_of(&relay, id, "c:lounge").await.unwrap(),
                    AccountReply::LogMembersFound { .. }
                ));
            }
        }

        async fn kept_relay(store: &Store, people: u8) -> Relay {
            let cfg = AccountsConfig {
                mode: AccountsMode::Optional,
                ..Default::default()
            };
            let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                .await
                .unwrap();
            for n in 1..=people {
                store
                    .create_user(
                        &l4f_accounts::model::NewUser {
                            id: AccountId([n; 16]),
                            username: format!("kept{n}"),
                            display_name: format!("kept{n}"),
                            email_pending: None,
                            password_hash: None,
                            created_at: 1,
                        },
                        None,
                    )
                    .await
                    .unwrap();
            }
            relay
        }

        /// `writer`'s first chain in `conv`, with a seat and a row of its own to `reader`.
        async fn chain_reaching(relay: &Relay, conv: &str, writer: AccountId, reader: [u8; 16]) {
            use voipc_crypto::log::{OWN_ROW_BYTES, ROW_BYTES};
            use voipc_protocol::messages::{BucketIn, ChainRow, ChainSeal, WrapIn};
            let row = || vec![0xAB; ROW_BYTES];
            let (out, _) = log::chain_put(
                relay,
                writer,
                conv,
                log::ChainFrame {
                    epoch: 1 << 12,
                    self_wrap: Some(row()),
                    step: None,
                    link: None,
                    wraps: vec![ChainRow {
                        recipient: reader,
                        index: 0,
                        wrapped: row(),
                    }],
                    buckets: vec![BucketIn {
                        bucket: 9,
                        version: 0,
                        list: vec![1; 28 + 24],
                        seats: vec![
                            WrapIn {
                                recipient: reader,
                                wrapped: row(),
                            },
                            WrapIn {
                                recipient: writer.0,
                                wrapped: vec![0xEE; OWN_ROW_BYTES],
                            },
                        ],
                        down: None,
                    }],
                    seals: vec![ChainSeal {
                        bucket: 9,
                        version: 0,
                        index: 0,
                        sealed: row(),
                    }],
                    last: true,
                },
                log::Sharing {
                    shares: true,
                    may: true,
                },
            )
            .await
            .unwrap();
            assert!(
                matches!(out, AccountReply::ChainStored { behind: false, .. }),
                "{out:?}"
            );
        }

        /// A new log key's walk that dies leaves the key stored and rows under the old one
        /// live. They do not stay: the mark brings it back at the next publish or sweep,
        /// from where it stopped.
        #[tokio::test]
        async fn a_walk_that_died_is_finished_by_a_retry_and_by_the_sweep() {
            use voipc_crypto::log::LogKey;
            let dbs = databases().await;
            for store in &dbs.stores {
                let relay = kept_relay(store, 3).await;
                let id = |n: u8| AccountId([n; 16]);
                let (me, conv) = (id(1), "c:aa");
                let identity = voipc_crypto::generate_identity_key_pair();
                relay
                    .set_identity(me, &identity.identity_key().serialize())
                    .await
                    .unwrap();
                let publish = async |key: &LogKey| {
                    log::publish(&relay, me, &key.public(), &key.endorse(&identity)).await
                };
                let stand = async || {
                    raw(&relay, "UPDATE voipc_logkeys SET updated_at = 0")
                        .await
                        .unwrap();
                };
                let count = async |sql: &str| raw(&relay, sql).await.unwrap();
                let first = LogKey::generate();
                assert!(publish(&first).await.is_ok());
                for who in [me, id(2), id(3)] {
                    log::join(&relay, who, conv, true).await.unwrap();
                }
                chain_reaching(&relay, conv, id(2), me.0).await;
                chain_reaching(&relay, conv, id(3), me.0).await;
                let to_me = hex::encode(me.0);
                let live_seats = format!(
                    "SELECT COUNT(*) FROM voipc_seats WHERE dead = FALSE AND {}",
                    recipient_is(store, &to_me)
                );
                let live_rows = format!(
                    "SELECT COUNT(*) FROM voipc_chain_wraps WHERE dead = FALSE AND {}",
                    recipient_is(store, &to_me)
                );
                assert_eq!(count(&live_seats).await, 2);
                assert_eq!(count(&live_rows).await, 2);

                // The walk's first statement fails: the key is stored, and the walk is owed
                let second = LogKey::generate();
                stand().await;
                raw(&relay, "ALTER TABLE voipc_seats RENAME TO voipc_seats_away")
                    .await
                    .unwrap();
                assert!(publish(&second).await.is_err());
                raw(&relay, "ALTER TABLE voipc_seats_away RENAME TO voipc_seats")
                    .await
                    .unwrap();
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_logkeys WHERE walk_after = 0").await,
                    1
                );
                assert_eq!(count(&live_seats).await, 2, "nothing done yet");

                // The app's retry names the same key, so no change: the mark is what walks
                assert!(matches!(
                    publish(&second).await.unwrap(),
                    AccountReply::LogKeyStored
                ));
                assert_eq!(count(&live_seats).await, 0);
                assert_eq!(count(&live_rows).await, 0);
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_logkeys WHERE walk_after IS NOT NULL").await,
                    0,
                    "the mark ends with the walk"
                );

                // Died past the first writer: the sweep takes it on from there, and what is
                // behind that stays, since it may be under the new key by now.
                raw(&relay, "UPDATE voipc_seats SET dead = FALSE")
                    .await
                    .unwrap();
                raw(&relay, "UPDATE voipc_chain_wraps SET dead = FALSE")
                    .await
                    .unwrap();
                let lowest = count("SELECT CAST(MIN(id) AS BIGINT) FROM voipc_writers").await;
                raw(
                    &relay,
                    &format!("UPDATE voipc_logkeys SET walk_after = {lowest}"),
                )
                .await
                .unwrap();
                log::sweep(&relay).await.unwrap();
                assert_eq!(count(&live_seats).await, 1);
                assert_eq!(count(&live_rows).await, 1);
                assert_eq!(
                    count(&format!(
                        "SELECT COUNT(*) FROM voipc_chain_wraps WHERE dead = FALSE AND writer = {lowest}"
                    ))
                    .await,
                    1
                );
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_logkeys WHERE walk_after IS NOT NULL").await,
                    0
                );

                // An ordinary change walks all of it, and leaves no mark
                raw(&relay, "UPDATE voipc_seats SET dead = FALSE")
                    .await
                    .unwrap();
                raw(&relay, "UPDATE voipc_chain_wraps SET dead = FALSE")
                    .await
                    .unwrap();
                stand().await;
                assert!(publish(&LogKey::generate()).await.is_ok());
                assert_eq!(count(&live_seats).await, 0);
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_logkeys WHERE walk_after IS NOT NULL").await,
                    0
                );
            }
        }

        fn recipient_is(store: &Store, hex: &str) -> String {
            match store {
                Store::Pg(_) => format!("recipient = '\\x{hex}'"),
                Store::Lite(_) => format!("recipient = X'{hex}'"),
            }
        }

        /// Two chains can link down to one, a chain never finished and the one its writer
        /// made instead. A reader holding the start of the second gets down past the first.
        #[tokio::test]
        async fn a_run_of_links_goes_past_a_chain_never_finished() {
            use voipc_crypto::log::ROW_BYTES;
            use voipc_protocol::messages::{ChainAsk, ChainRow};
            let dbs = databases().await;
            for store in &dbs.stores {
                let relay = kept_relay(store, 2).await;
                let (writer, reader, conv) = (AccountId([1; 16]), AccountId([2; 16]), "c:aa");
                log::join(&relay, writer, conv, true).await.unwrap();
                let row = || vec![0xAB; ROW_BYTES];
                let put =
                    async |chain: u32, link: Option<u32>, wraps: Vec<ChainRow>, last: bool| {
                        let (out, _) = log::chain_put(
                            &relay,
                            writer,
                            conv,
                            log::ChainFrame {
                                epoch: chain << 12,
                                self_wrap: Some(row()),
                                step: None,
                                link: link.map(|older| (older, row())),
                                wraps,
                                buckets: vec![],
                                seals: vec![],
                                last,
                            },
                            log::Sharing {
                                shares: true,
                                may: true,
                            },
                        )
                        .await
                        .unwrap();
                        assert!(
                            matches!(out, AccountReply::ChainStored { behind: false, .. }),
                            "{out:?}"
                        );
                    };
                put(1, None, vec![], true).await;
                log::join(&relay, reader, conv, true).await.unwrap();
                // A crash: its last frame never comes, and it lasts up to the sweep's hour
                put(2, Some(1), vec![], false).await;
                put(
                    3,
                    Some(1),
                    vec![ChainRow {
                        recipient: reader.0,
                        index: 0,
                        wrapped: row(),
                    }],
                    true,
                )
                .await;
                let asks = [ChainAsk {
                    owner: writer.0,
                    chain: 1,
                    from: None,
                }];
                let out = log::wraps_page(&relay, reader, conv, &asks).await.unwrap();
                let AccountReply::WrapsPage { keys, served, .. } = out else {
                    panic!("{out:?}");
                };
                assert_eq!(served, 1);
                let chains: Vec<u32> = keys.iter().map(|k| k.chain).collect();
                assert_eq!(chains, [3, 1], "from the start it holds, down its link");
                assert!(keys[0].direct.is_some() && keys[0].link.is_some());
            }
        }

        /// Round C measurement, not a check: `log::index` (every connect) with `ROUND_C_N`
        /// direct rows, 50 a conversation, among 250 accounts. `TMPDIR=$PWD/target/scratch/
        /// tmpdisk ROUND_C_N=1000000 cargo test -p voipc-server --bin voipc-server -- --ignored
        /// measure_log_index --nocapture`.
        #[tokio::test]
        #[ignore]
        async fn measure_log_index() {
            let n: usize = std::env::var("ROUND_C_N")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100_000);
            let dbs = databases().await;
            let store = &dbs.stores[0];
            let relay = kept_relay(store, 250).await;
            let Store::Lite(b) = store else {
                panic!("SQLite")
            };
            let t = std::time::Instant::now();
            let mut tx = b.0.begin().await.unwrap();
            let mut convs = 0;
            'fill: for a in 1..=250u8 {
                for c in (a + 1)..=250u8 {
                    let conv = voipc_protocol::conv::dm_conv(&[a; 16], &[c; 16]);
                    for i in 0..50 {
                        if convs * 50 + i >= n {
                            break 'fill;
                        }
                        sqlx::query("INSERT INTO voipc_log (conv, sender, epoch, server_at, keep_until, ct) VALUES ($1, $2, 0, 1, 9007199254740991, $3)")
                            .bind(&conv)
                            .bind(&[if i % 2 == 0 { a } else { c }; 16][..])
                            .bind(&[1u8; 64][..])
                            .execute(&mut *tx)
                            .await
                            .unwrap();
                    }
                    convs += 1;
                }
            }
            tx.commit().await.unwrap();
            eprintln!(
                "filled {n} rows, {convs} conversations in {:?}",
                t.elapsed()
            );
            for who in [1u8, 125, 250] {
                log::index(&relay, AccountId([who; 16])).await.unwrap();
                let t = std::time::Instant::now();
                let (out, _) = log::index(&relay, AccountId([who; 16])).await.unwrap();
                let AccountReply::LogConvs { convs } = out else {
                    panic!("{out:?}");
                };
                eprintln!(
                    "ROUND-C LogIndex n={n}: account {who} ({} conversations) {:?}",
                    convs.len(),
                    t.elapsed()
                );
            }
        }

        /// Listing someone's direct conversations reads no channel's rows, and finds them
        /// wherever the account's id falls in the conversation's name.
        #[tokio::test]
        async fn the_direct_conversations_read_keeps_out_of_channels_rows() {
            let dbs = databases().await;
            for store in &dbs.stores {
                let relay = kept_relay(store, 4).await;
                let id = |n: u8| AccountId([n; 16]);
                let me = id(2);
                for (who, conv) in [
                    (id(1), voipc_protocol::conv::dm_conv(&id(1).0, &me.0)),
                    (id(3), voipc_protocol::conv::dm_conv(&id(3).0, &me.0)),
                    (id(1), voipc_protocol::conv::dm_conv(&id(1).0, &id(3).0)),
                    (id(1), "c:aa".to_string()),
                ] {
                    db!(store, pool => {
                        sqlx::query("INSERT INTO voipc_log (conv, sender, epoch, server_at, keep_until, ct) VALUES ($1, $2, 0, 1, 9007199254740991, $3)")
                            .bind(&conv)
                            .bind(&who.0[..])
                            .bind(&[1u8; 8][..])
                            .execute(pool)
                            .await
                            .unwrap();
                    });
                }
                let (out, _) = log::index(&relay, me).await.unwrap();
                let AccountReply::LogConvs { convs } = out else {
                    panic!("{out:?}");
                };
                let names: Vec<&str> = convs.iter().map(|(c, _)| c.as_str()).collect();
                assert_eq!(
                    names,
                    [
                        voipc_protocol::conv::dm_conv(&id(1).0, &me.0),
                        voipc_protocol::conv::dm_conv(&me.0, &id(3).0)
                    ]
                );
                // Only SQLite's plan says so on a table this small
                if let Store::Lite(b) = store {
                    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(
                        format!("EXPLAIN QUERY PLAN {}", log::DIRECT_CONVS),
                    ))
                    .bind("d:aa:")
                    .bind("d:aa;")
                    .bind("aa")
                    .bind(0i64)
                    .fetch_all(&b.0)
                    .await
                    .unwrap();
                    // Each half a range of an index, neither a read of every direct row
                    assert!(
                        plan.iter()
                            .any(|p| p.3.contains("voipc_log_conv_seq (conv>? AND conv<?)")),
                        "{plan:?}"
                    );
                    assert!(
                        plan.iter()
                            .any(|p| p.3.contains("voipc_log_dm_second (<expr>=?")),
                        "{plan:?}"
                    );
                    assert!(!plan.iter().any(|p| p.3.starts_with("SCAN")), "{plan:?}");
                    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
                        "EXPLAIN QUERY PLAN SELECT SUM(LENGTH(wrapped)) FROM voipc_wraps WHERE owner = $1",
                    )
                    .bind(&me.0[..])
                    .fetch_all(&b.0)
                    .await
                    .unwrap();
                    assert!(
                        plan.iter().any(|p| p.3.contains("voipc_wraps_owner")),
                        "{plan:?}"
                    );
                }
            }
        }

        /// Every statement of the kept path, once, with what comes back read in the types
        /// the code reads: a column type wrong on one dialect fails only there, at run time.
        #[tokio::test]
        async fn the_kept_path_runs_on_both_backends() {
            use voipc_crypto::log::{LogKey, OWN_ROW_BYTES, ROW_BYTES};
            use voipc_protocol::messages::{BucketIn, ChainAsk, ChainRow, ChainSeal, WrapIn};
            let row = || vec![0xAB; ROW_BYTES];
            let frame = |epoch: u32, self_wrap: bool, last: bool| log::ChainFrame {
                epoch,
                self_wrap: self_wrap.then(row),
                step: None,
                link: None,
                wraps: vec![],
                buckets: vec![],
                seals: vec![],
                last,
            };
            let seal = |bucket: u64, version: u32, index: u32| ChainSeal {
                bucket,
                version,
                index,
                sealed: row(),
            };
            let bucket = |id: u64, version: u32, me: [u8; 16], seats: &[[u8; 16]]| BucketIn {
                bucket: id,
                version,
                list: vec![1; 28 + 24 * seats.len()],
                seats: seats
                    .iter()
                    .map(|r| WrapIn {
                        recipient: *r,
                        wrapped: row(),
                    })
                    .chain([WrapIn {
                        recipient: me,
                        wrapped: vec![0xEE; OWN_ROW_BYTES],
                    }])
                    .collect(),
                down: None,
            };
            let dbs = databases().await;
            for store in &dbs.stores {
                let cfg = AccountsConfig {
                    mode: AccountsMode::Optional,
                    kept_window: 2,
                    ..Default::default()
                };
                let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                let id = |n: u8| AccountId([n; 16]);
                for n in 1..=5u8 {
                    store
                        .create_user(
                            &l4f_accounts::model::NewUser {
                                id: id(n),
                                username: format!("kept{n}"),
                                display_name: format!("kept{n}"),
                                email_pending: None,
                                password_hash: None,
                                created_at: 1,
                            },
                            None,
                        )
                        .await
                        .unwrap();
                }
                let (a, b, c, d, e) = (id(1), id(2), id(3), id(4), id(5));
                let conv = "c:aa";
                let count = async |sql: &str| raw(&relay, sql).await.unwrap();
                let may = || log::Sharing {
                    shares: true,
                    may: true,
                };
                for who in [a, b, c, d] {
                    let (out, _) = log::join(&relay, who, conv, true).await.unwrap();
                    assert!(matches!(out, AccountReply::LogJoined { .. }), "{out:?}");
                }
                let (out, _) = log::join_many(&relay, e, &[conv.to_string()], &[true])
                    .await
                    .unwrap();
                assert!(matches!(out, AccountReply::LogJoinedMany { .. }), "{out:?}");
                log::leave(&relay, e, conv).await.unwrap();

                // A chain with a bucket of two and a row of its own
                let mut f = frame(1 << 12, true, true);
                f.buckets = vec![bucket(u64::MAX - 7, 0, a.0, &[b.0, c.0])];
                f.seals = vec![seal(u64::MAX - 7, 0, 0)];
                f.wraps = vec![ChainRow {
                    recipient: d.0,
                    index: 0,
                    wrapped: row(),
                }];
                let (out, _) = log::chain_put(&relay, a, conv, f, may()).await.unwrap();
                assert!(
                    matches!(out, AccountReply::ChainStored { behind: false, .. }),
                    "{out:?}"
                );
                let out = log::append(&relay, a, conv, 1 << 12, &[1; 64], None)
                    .await
                    .unwrap();
                assert!(matches!(out, AccountReply::LogAppended { .. }), "{out:?}");

                // A step and a row to someone new, once they are
                log::join(&relay, e, conv, true).await.unwrap();
                run_wait_over(&relay).await;
                let out = log::append(&relay, a, conv, 1 << 12, &[1; 64], None)
                    .await
                    .unwrap();
                assert!(
                    matches!(&out, AccountReply::ChainRekey { new_chain: false, missing, .. } if missing == &[e.0]),
                    "{out:?}"
                );
                // ... which, as the last of an answer, ends the wait on this writer
                let mut f = frame(1 << 12 | 1, false, true);
                f.step = Some(row());
                f.wraps = vec![ChainRow {
                    recipient: e.0,
                    index: 1,
                    wrapped: row(),
                }];
                let (out, _) = log::chain_put(&relay, a, conv, f, may()).await.unwrap();
                assert!(
                    matches!(out, AccountReply::ChainStored { behind: false, .. }),
                    "{out:?}"
                );

                // The reads
                let out = log::append(&relay, a, conv, 1 << 12 | 1, &[1; 64], None)
                    .await
                    .unwrap();
                assert!(matches!(out, AccountReply::LogAppended { .. }), "{out:?}");
                let out = log::chain_fetch(&relay, e, conv, -500).await.unwrap();
                assert!(
                    matches!(&out, AccountReply::ChainPage { entries, skipped: 1, .. } if entries.len() == 1),
                    "{out:?}"
                );
                let out = log::fetch(&relay, b, conv, 0).await.unwrap();
                assert!(matches!(out, AccountReply::LogPage { .. }), "{out:?}");
                let ask = ChainAsk {
                    owner: a.0,
                    chain: 1,
                    from: None,
                };
                let out = log::wraps_page(&relay, b, conv, std::slice::from_ref(&ask))
                    .await
                    .unwrap();
                assert!(
                    matches!(&out, AccountReply::WrapsPage { keys, .. } if keys[0].seal.is_some() && keys[0].steps.len() == 1),
                    "{out:?}"
                );
                let out = log::wraps_page(&relay, a, conv, std::slice::from_ref(&ask))
                    .await
                    .unwrap();
                assert!(
                    matches!(&out, AccountReply::WrapsPage { keys, .. } if keys[0].self_wrap.is_some()),
                    "{out:?}"
                );
                assert!(matches!(
                    log::member_ids(&relay, a, conv, None).await.unwrap(),
                    AccountReply::LogMemberIdsFound { .. }
                ));
                assert!(matches!(
                    log::member_ids(&relay, a, conv, Some(b.0)).await.unwrap(),
                    AccountReply::LogMemberIdsFound { .. }
                ));
                let out = log::own_chains(&relay, a, conv, None).await.unwrap();
                assert!(
                    matches!(&out, AccountReply::OwnChains { chains, newest: Some(1), .. } if chains[0].top == 1),
                    "{out:?}"
                );
                let out = log::own_buckets(&relay, a, conv, None).await.unwrap();
                assert!(
                    matches!(&out, AccountReply::OwnBuckets { buckets, .. } if buckets[0].bucket == u64::MAX - 7 && buckets[0].seats == 2),
                    "{out:?}"
                );
                let out = log::bucket_lists(&relay, a, conv, &[(u64::MAX - 7, 0)])
                    .await
                    .unwrap();
                assert!(
                    matches!(&out, AccountReply::BucketLists { lists, .. } if lists.len() == 1),
                    "{out:?}"
                );
                let out = log::own_chain_rows(&relay, a, conv, 1, None).await.unwrap();
                assert!(
                    matches!(&out, AccountReply::OwnChainRows { seals, direct, .. } if seals.len() == 1 && direct.len() == 2),
                    "{out:?}"
                );
                let out = log::own_chain_rows(&relay, a, conv, 1, Some(d.0))
                    .await
                    .unwrap();
                assert!(matches!(out, AccountReply::OwnChainRows { .. }), "{out:?}");

                // Someone leaves: a new chain, a rotation, a link. Then the way down.
                log::leave(&relay, b, conv).await.unwrap();
                assert_eq!(count("SELECT COUNT(*) FROM voipc_left").await, 1);
                let out = log::append(&relay, a, conv, 1 << 12 | 1, &[1; 64], None)
                    .await
                    .unwrap();
                assert!(
                    matches!(&out, AccountReply::ChainRekey { new_chain: true, gone, .. } if gone == &[(b.0, u64::MAX - 7)]),
                    "{out:?}"
                );
                let mut f = frame(2 << 12, true, true);
                f.link = Some((1, row()));
                f.buckets = vec![BucketIn {
                    down: Some((0, row())),
                    ..bucket(u64::MAX - 7, 1, a.0, &[c.0])
                }];
                f.seals = vec![seal(u64::MAX - 7, 1, 0)];
                f.wraps = vec![
                    ChainRow {
                        recipient: d.0,
                        index: 0,
                        wrapped: row(),
                    },
                    ChainRow {
                        recipient: e.0,
                        index: 0,
                        wrapped: row(),
                    },
                ];
                let (out, _) = log::chain_put(&relay, a, conv, f, may()).await.unwrap();
                assert!(
                    matches!(out, AccountReply::ChainStored { behind: false, .. }),
                    "{out:?}"
                );
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_seats WHERE version = 0").await,
                    1,
                    "a leaver's frozen row, and only that"
                );
                let out = log::wraps_page(&relay, c, conv, std::slice::from_ref(&ask))
                    .await
                    .unwrap();
                assert!(
                    matches!(&out, AccountReply::WrapsPage { keys, .. } if keys[0].down.len() == 1),
                    "{out:?}"
                );
                // e holds index 1 of chain 1 by a row, and the start of chain 2 which links
                // down to it: the entry at index 0 opens now, and the path comes with it
                let out = log::chain_fetch(&relay, e, conv, 0).await.unwrap();
                assert!(
                    matches!(&out, AccountReply::ChainPage { entries, skipped: 0, .. } if entries.len() == 2),
                    "{out:?}"
                );
                let out = log::wraps_page(&relay, e, conv, std::slice::from_ref(&ask))
                    .await
                    .unwrap();
                assert!(
                    matches!(&out, AccountReply::WrapsPage { keys, .. } if keys.len() == 2 && keys[0].chain == 2 && keys[0].direct.is_some() && keys[0].link.is_some()),
                    "{out:?}"
                );
                let (out, _) = log::index(&relay, e).await.unwrap();
                assert!(
                    matches!(&out, AccountReply::LogConvs { convs } if convs.len() == 1),
                    "{out:?}"
                );

                // A new log key, a share flag, a tombstone
                let identity = voipc_crypto::generate_identity_key_pair();
                relay
                    .set_identity(d, &identity.identity_key().serialize())
                    .await
                    .unwrap();
                let key = LogKey::generate();
                let out = log::publish(&relay, d, &key.public(), &key.endorse(&identity))
                    .await
                    .unwrap();
                assert!(matches!(out, AccountReply::LogKeyStored), "{out:?}");
                raw(&relay, "UPDATE voipc_logkeys SET updated_at = 0")
                    .await
                    .unwrap();
                let key = LogKey::generate();
                let out = log::publish(&relay, d, &key.public(), &key.endorse(&identity))
                    .await
                    .unwrap();
                assert!(matches!(out, AccountReply::LogKeyStored), "{out:?}");
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_chain_wraps WHERE dead = TRUE").await,
                    2
                );
                log::set_shares(store, &a.0, false).await.unwrap();
                raw(&relay, "UPDATE voipc_writers SET shares = TRUE")
                    .await
                    .unwrap();
                log::recheck_shares(&relay).await.unwrap();
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_writers WHERE shares = TRUE").await,
                    0
                );
                // Someone who does not share owes nobody: any last frame ends a wait on them
                db!(store, pool => {
                    sqlx::query("INSERT INTO voipc_pending (conv, owner, recipient, created_at) VALUES ($1, $2, $3, 1)")
                        .bind(conv)
                        .bind(&a.0[..])
                        .bind(&e.0[..])
                        .execute(pool)
                        .await
                        .unwrap();
                });
                let none = log::Sharing {
                    shares: false,
                    may: false,
                };
                let f = frame(1 << 12 | 1, false, true);
                let (out, told) = log::chain_put(&relay, a, conv, f, none).await.unwrap();
                assert!(
                    matches!(out, AccountReply::ChainStored { behind: false, .. }),
                    "{out:?}"
                );
                assert_eq!(told, [e.0]);
                db!(store, pool => {
                    sqlx::query("INSERT INTO voipc_tombstones (account, at) VALUES ($1, 1)")
                        .bind(&b.0[..])
                        .execute(pool)
                        .await
                        .unwrap();
                });

                // The sweep: a floor, text and keys under it, an unfinished chain, the stone
                let mut f = frame(3 << 12, true, false);
                f.buckets = vec![bucket(9, 0, a.0, &[c.0])];
                let (out, _) = log::chain_put(&relay, a, conv, f, may()).await.unwrap();
                assert!(
                    matches!(out, AccountReply::ChainStored { behind: false, .. }),
                    "{out:?}"
                );
                raw(&relay, "UPDATE voipc_log SET server_at = 1")
                    .await
                    .unwrap();
                let mut f = frame(2 << 12 | 1, false, false);
                f.step = Some(row());
                f.wraps = vec![ChainRow {
                    recipient: d.0,
                    index: 1,
                    wrapped: row(),
                }];
                let (out, _) = log::chain_put(&relay, a, conv, f, may()).await.unwrap();
                assert!(
                    matches!(out, AccountReply::ChainStored { behind: false, .. }),
                    "{out:?}"
                );
                let out = log::append(&relay, a, conv, 2 << 12 | 1, &[1; 64], None)
                    .await
                    .unwrap();
                assert!(matches!(out, AccountReply::LogAppended { .. }), "{out:?}");
                raw(&relay, "UPDATE voipc_log SET server_at = 1")
                    .await
                    .unwrap();
                raw(&relay, "UPDATE voipc_chains SET created_at = 1")
                    .await
                    .unwrap();
                raw(&relay, "UPDATE voipc_bucket_lists SET created_at = 1")
                    .await
                    .unwrap();
                log::sweep(&relay).await.unwrap();
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_log").await,
                    2,
                    "the window"
                );
                assert!(count("SELECT floor FROM voipc_log_floors").await > 0);
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_chains WHERE chain = 3").await,
                    0
                );
                assert_eq!(
                    count("SELECT COUNT(*) FROM voipc_seats WHERE bucket = 9").await,
                    0
                );
                assert_eq!(count("SELECT COUNT(*) FROM voipc_tombstones").await, 0);
                let out = log::chain_fetch(&relay, a, conv, 0).await.unwrap();
                assert!(matches!(out, AccountReply::ChainPage { .. }), "{out:?}");

                // Delete what I wrote, and a channel going
                let out = log::purge(&relay, a, Some(conv)).await.unwrap();
                assert!(matches!(out, AccountReply::LogPurged { .. }), "{out:?}");
                assert_eq!(count("SELECT COUNT(*) FROM voipc_chains").await, 0);
                assert_eq!(count("SELECT COUNT(*) FROM voipc_seats").await, 0);
                relay.channel_purge(conv).await.unwrap();
                assert_eq!(count("SELECT COUNT(*) FROM voipc_log_floors").await, 0);
            }
        }

        /// Lets a rejoin through at once: the wait has its own test.
        async fn run_wait_over(relay: &Relay) {
            raw(relay, "UPDATE voipc_left SET left_at = 0")
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn the_modlog_round_trips_on_both_backends() {
            let dbs = databases().await;
            for store in &dbs.stores {
                let cfg = AccountsConfig {
                    mode: AccountsMode::Optional,
                    ..Default::default()
                };
                let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                let wide = "\u{1F600}x\0".repeat(400);
                let key = format!("c:{}", "k".repeat(78));
                let entry = |action| modlog::Entry {
                    action,
                    actor: Some([1; 16]),
                    actor_name: &wide,
                    target: Some([2; 16]),
                    target_name: &wide,
                    channel_key: &key,
                    channel_name: &wide,
                    reason: &wide,
                    detail: &wide,
                };
                relay.modlog_put(&entry("ban")).await.unwrap();
                relay.modlog_put(&entry("hide")).await.unwrap();
                relay
                    .modlog_put(&modlog::Entry {
                        action: "kick",
                        actor_name: "server shell",
                        target_name: "kim",
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let rows = relay.modlog_rows(0, 200).await.unwrap();
                assert_eq!(rows.len(), 3);
                assert!(rows[0].0 > rows[1].0 && rows[1].0 > rows[2].0);
                assert!(rows[0].1 > 1_700_000_000, "seconds: {}", rows[0].1);
                let (_, _, action, actor, target, k, name, reason, detail) = &rows[1];
                assert_eq!(action, "hide");
                assert_eq!(k.as_deref(), Some(key.as_str()));
                for (text, chars) in [
                    (actor, 64),
                    (target, 64),
                    (name.as_ref().unwrap(), 64),
                    (reason, 200),
                    (detail, 255),
                ] {
                    assert_eq!(text.chars().count(), chars, "{text}");
                    assert!(!text.contains('\0'));
                }
                // An empty channel is none at all
                assert!(rows[0].5.is_none() && rows[0].6.is_none());
                assert_eq!(relay.modlog_rows(rows[1].0, 200).await.unwrap().len(), 1);
                assert_eq!(
                    relay.modlog_notes_since([1; 16], 0).await.unwrap(),
                    1,
                    "the note, not the ban, and only this actor's"
                );
                assert_eq!(relay.modlog_notes_since([2; 16], 0).await.unwrap(), 0);
                assert_eq!(modlog::sweep(&relay).await.unwrap(), 0);
                // The bind of a cutoff in the past takes what is older, on both
                let old = util::now() - 181 * 86_400;
                db!(store, pool => {
                    sqlx::query("UPDATE voipc_modlog SET at = $1 WHERE action = 'kick'")
                        .bind(old)
                        .execute(pool)
                        .await
                        .unwrap();
                });
                assert_eq!(modlog::sweep(&relay).await.unwrap(), 1);

                // What the log calls someone an admin banned, across a restart
                let ban = crate::bans::Ban {
                    id: 0,
                    label: "tom".into(),
                    reason: String::new(),
                    by: "boss".into(),
                    created_at: 1,
                    expires_at: None,
                    addr: None,
                    alias: Some("Guest-0001".into()),
                };
                relay
                    .ban_put(&crate::bans::Key::Addr([7; 32]), &ban)
                    .await
                    .unwrap();
                let rows = relay.ban_rows(2).await.unwrap();
                assert_eq!(rows[0].1.log_name(), "Guest-0001");
                assert_eq!(rows[0].1.label, "tom");
            }
        }

        /// What a shell ban takes out of the logs, on both: its statements are `ban_put`'s.
        #[tokio::test]
        async fn a_banned_account_leaves_the_logs_on_both_backends() {
            let dbs = databases().await;
            for store in &dbs.stores {
                let cfg = AccountsConfig {
                    mode: AccountsMode::Optional,
                    ..Default::default()
                };
                let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                let (dan, cat) = ([7u8; 16], [8u8; 16]);
                for (id, username) in [(dan, "dan"), (cat, "cat")] {
                    store
                        .create_user(
                            &l4f_accounts::model::NewUser {
                                id: AccountId(id),
                                username: username.into(),
                                display_name: username.into(),
                                email_pending: None,
                                password_hash: None,
                                created_at: 1,
                            },
                            None,
                        )
                        .await
                        .unwrap();
                }
                db!(store, pool => {
                    for id in [dan, cat] {
                        sqlx::query("INSERT INTO voipc_members (conv, account, joined_at) VALUES ('c:aa', $1, 1)")
                            .bind(&id[..])
                            .execute(pool)
                            .await
                            .unwrap();
                    }
                    for (owner, recipient) in [(dan, cat), (cat, dan), (cat, cat)] {
                        sqlx::query("INSERT INTO voipc_pending (conv, owner, recipient, created_at) VALUES ('c:aa', $1, $2, 1)")
                            .bind(&owner[..])
                            .bind(&recipient[..])
                            .execute(pool)
                            .await
                            .unwrap();
                    }
                });
                relay.ban_out_of_logs(&dan).await.unwrap();
                let (members, pending): (i64, i64) = db!(store, pool => {
                    let members = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_members")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                    let pending = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_pending")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                    (members, pending)
                });
                assert_eq!((members, pending), (1, 1), "the other member's stay");

                // A reason with a NUL in it, which Postgres would refuse in the bind
                let ban = crate::bans::Ban {
                    id: 0,
                    label: "dan".into(),
                    reason: crate::session::ban_reason("a\0b".into()),
                    by: "boss".into(),
                    created_at: 1,
                    expires_at: None,
                    addr: None,
                    alias: None,
                };
                relay
                    .ban_put(&crate::bans::Key::Account(dan), &ban)
                    .await
                    .unwrap();
                assert_eq!(relay.ban_rows(2).await.unwrap()[0].1.reason, "ab");
            }
        }

        #[tokio::test]
        async fn a_removal_round_trips_on_both_backends() {
            let dbs = databases().await;
            for store in &dbs.stores {
                let cfg = AccountsConfig {
                    mode: AccountsMode::Optional,
                    ..Default::default()
                };
                let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                    .await
                    .unwrap();
                let id = AccountId([7; 16]);
                store
                    .create_user(
                        &l4f_accounts::model::NewUser {
                            id,
                            username: "kim".into(),
                            display_name: "kim".into(),
                            email_pending: None,
                            password_hash: None,
                            created_at: 1,
                        },
                        None,
                    )
                    .await
                    .unwrap();
                for (conv, server_at) in [
                    ("c:aa", 2000_i64),
                    ("c:bb", 3000),
                    ("c:aa", 1),
                    ("c:aa", 5000),
                    ("d:aa", 2000),
                ] {
                    db!(store, pool => {
                        sqlx::query(
                            "INSERT INTO voipc_log (conv, sender, epoch, server_at, keep_until, ct) VALUES ($1, $2, 1, $3, $3, $4)",
                        )
                        .bind(conv)
                        .bind(&id.0[..])
                        .bind(server_at)
                        .bind(&[0u8][..])
                        .execute(pool)
                        .await
                        .unwrap();
                    });
                }
                let wide = "\u{1F600}x\0".repeat(400);
                let row = modlog::Entry {
                    action: "remove_posts",
                    actor: Some([1; 16]),
                    actor_name: &wide,
                    target: Some(id.0),
                    target_name: &wide,
                    reason: &wide,
                    ..Default::default()
                };
                let window = "last hour";
                // What came from Discord: a wish, and the row counts what it covers
                db!(store, pool => {
                    for (channel, dc_id, author) in [(5i64, 10i64, 77i64), (6, 11, 77), (5, 90, 77), (5, 12, 78)] {
                        sqlx::query(
                            "INSERT INTO voipc_archive (channel, dc_id, author_dc_id, author_name, body, import_id)
                             VALUES ($1, $2, $3, 'x', 'y', 1)",
                        )
                        .bind(channel)
                        .bind(dc_id)
                        .bind(author)
                        .execute(pool)
                        .await
                        .unwrap();
                    }
                });
                let imported = modlog::Imported {
                    ids: &[77],
                    low: 10,
                    high: 50,
                    say_how_many: true,
                };
                assert_eq!(
                    relay
                        .posts_remove(Some(id.0), imported, 1000, 4000, window, &row)
                        .await
                        .unwrap(),
                    2,
                    "in the window, in channels"
                );
                let left: i64 = db!(store, pool => {
                    sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_log")
                        .fetch_one(pool)
                        .await
                        .unwrap()
                });
                assert_eq!(left, 3);
                // A guest's deletes nothing, and has no account to name
                let guest = modlog::Entry {
                    action: "remove_posts",
                    actor_name: "boss",
                    target_name: "gus#0001",
                    ..Default::default()
                };
                let imported = modlog::Imported {
                    ids: &[],
                    low: 0,
                    high: 0,
                    say_how_many: true,
                };
                assert_eq!(
                    relay
                        .posts_remove(None, imported, 0, 4000, window, &guest)
                        .await
                        .unwrap(),
                    0
                );
                let marks = relay.modlog_marks().await.unwrap();
                assert_eq!(marks.len(), 2);
                assert_eq!(
                    (
                        marks[0].account,
                        marks[0].name.as_str(),
                        marks[0].since_ms,
                        marks[0].before_ms,
                        marks[0].by.as_str()
                    ),
                    (None, "gus#0001", 0, 4000, "boss")
                );
                assert_eq!(
                    (marks[1].account, marks[1].since_ms, marks[1].before_ms),
                    (Some(id.0), 1000, 4000)
                );
                assert_eq!(marks[1].name.chars().count(), 64);
                assert_eq!(marks[1].by.chars().count(), 64);
                let rows = relay.modlog_rows(0, 200).await.unwrap();
                assert_eq!(rows[1].8, "2 kept messages, last hour, 2 imported");
                archive::load(&relay).await.unwrap();
                let wishes = relay.wishes();
                use archive::{verdict, Verdict};
                assert_eq!(verdict(&wishes, Some(77), 6, 11), Verdict::Erased);
                assert_eq!(verdict(&wishes, Some(77), 5, 90), Verdict::Shown);
                assert_eq!(verdict(&wishes, Some(78), 5, 12), Verdict::Shown);
                // Others' rows are no removals
                relay
                    .modlog_put(&modlog::Entry {
                        action: "ban",
                        target_name: "kim",
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert_eq!(relay.modlog_marks().await.unwrap().len(), 2);
            }
        }

        #[tokio::test]
        async fn a_privilege_removed_after_the_upgrade_is_not_given_back() {
            let dbs = databases().await;
            for store in &dbs.stores {
                boot(store).await;
                before_1_10(store, &OLD).await;
                boot(store).await;
                assert_eq!(group(store).await.scopes, NEW, "control: it did widen");
                set(store, &OLD).await;
                boot(store).await;
                assert_eq!(group(store).await.scopes, OLD);
                let fewer = &NEW[..NEW.len() - 1];
                set(store, fewer).await;
                boot(store).await;
                assert_eq!(group(store).await.scopes, fewer);
            }
        }

        /// The move's tables on each database: the longest text, ids past what a JS number
        /// holds, the statements the steps after this rest on (Postgres has no two-argument
        /// `max`, and no CI job runs it), and what goes with an account or a group.
        #[tokio::test]
        async fn the_move_tables_round_trip_on_both_backends() {
            macro_rules! run {
                ($store:expr, $sql:expr $(, $bind:expr)* $(,)?) => {
                    db!($store, pool => {
                        sqlx::query($sql)$(.bind($bind))*.execute(pool).await.map(|r| r.rows_affected())
                    })
                };
            }
            macro_rules! row {
                ($store:expr, $ty:ty, $sql:expr $(, $bind:expr)* $(,)?) => {
                    db!($store, pool => {
                        sqlx::query_as::<_, $ty>($sql)$(.bind($bind))*.fetch_one(pool).await.unwrap()
                    })
                };
            }
            const SNOWFLAKE: i64 = 1_454_987_148_113_234_751;
            const CURSOR: &str = "INSERT INTO voipc_import_cursors (uid, import_id, high) \
                VALUES ($1, $2, $3) ON CONFLICT (uid, import_id) DO UPDATE \
                SET high = excluded.high WHERE excluded.high > voipc_import_cursors.high";
            const CURSORS: &str = "SELECT CAST(MAX(c.high) AS BIGINT) FROM voipc_import_cursors c \
                JOIN voipc_imports i ON i.id = c.import_id WHERE c.uid = $1 AND i.undone_at IS NULL";
            const WISH: &str = "INSERT INTO voipc_archive_wishes \
                (author_dc_id, channel, low, high, erase, at) VALUES ($1, $2, $3, $4, $5, $6) \
                ON CONFLICT (author_dc_id, channel, low, high) DO UPDATE \
                SET erase = voipc_archive_wishes.erase OR excluded.erase";
            const MESSAGE: &str = "INSERT INTO voipc_archive (channel, thread, dc_id, author_dc_id, \
                author_name, body, reply_to, reactions, attachments, pinned, import_id) \
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                ON CONFLICT (channel, thread, dc_id) DO UPDATE SET \
                author_dc_id = excluded.author_dc_id, author_name = excluded.author_name, \
                body = excluded.body, reply_to = excluded.reply_to, reactions = excluded.reactions, \
                attachments = excluded.attachments, pinned = excluded.pinned";
            const THREAD: &str = "INSERT INTO voipc_archive (channel, thread, dc_id, author_name, \
                body, thread_name, replies, import_id) VALUES ($1, 0, $2, '', '', $3, $4, $5) \
                ON CONFLICT (channel, thread, dc_id) DO UPDATE \
                SET thread_name = excluded.thread_name, replies = excluded.replies";
            type Page = (
                i64,
                Option<i64>,
                String,
                String,
                Option<String>,
                Option<String>,
                i32,
                bool,
                i64,
            );
            const PAGE: &str = "SELECT dc_id, author_dc_id, author_name, body, reactions, \
                thread_name, replies, pinned, import_id FROM voipc_archive \
                WHERE channel = $1 AND thread = $2 AND dc_id < $3 ORDER BY dc_id DESC LIMIT $4";

            let dbs = databases().await;
            for store in &dbs.stores {
                boot(store).await;
                let wide = "\u{1F600}";

                // A run: ids go up, and marking one undone happens once
                let (first, second) = {
                    let mut ids = Vec::new();
                    for _ in 0..2 {
                        ids.push(row!(
                            store,
                            (i64,),
                            "INSERT INTO voipc_imports (guild_id, by_name, started_at, options) \
                             VALUES ($1, $2, $3, $4) RETURNING CAST(id AS BIGINT)",
                            SNOWFLAKE,
                            wide.repeat(64),
                            100i64,
                            "{\"messages\":true}",
                        ));
                    }
                    (ids[0].0, ids[1].0)
                };
                assert!(second > first);
                run!(
                    store,
                    "UPDATE voipc_imports SET archive_rows = archive_rows + $1 WHERE id = $2",
                    5i64,
                    first
                )
                .unwrap();
                let (guild, by, options, report, backup, rows, undone, done) = row!(
                    store,
                    (
                        i64,
                        String,
                        String,
                        Option<String>,
                        Option<String>,
                        i64,
                        Option<i64>,
                        Option<i64>
                    ),
                    "SELECT guild_id, by_name, options, report, backup, archive_rows, undone_at, \
                     archive_done_at FROM voipc_imports WHERE id = $1",
                    first
                );
                assert_eq!(
                    (guild, by, options.as_str(), rows),
                    (SNOWFLAKE, wide.repeat(64), "{\"messages\":true}", 5)
                );
                assert_eq!((report, backup, undone, done), (None, None, None, None));

                // What a run made: a row stays as the run that made it left it
                for (run, local) in [(first, "c:dc-1"), (second, "changed")] {
                    run!(
                        store,
                        "INSERT INTO voipc_import_items (kind, dc_id, import_id, local) \
                         VALUES ($1, $2, $3, $4) ON CONFLICT (kind, dc_id) DO NOTHING",
                        2i16,
                        SNOWFLAKE,
                        run,
                        local
                    )
                    .unwrap();
                }
                let (import_id, local) = row!(
                    store,
                    (i64, String),
                    "SELECT import_id, local FROM voipc_import_items WHERE kind = $1 AND dc_id = $2",
                    2i16,
                    SNOWFLAKE
                );
                assert_eq!((import_id, local.as_str()), (first, "c:dc-1"));

                // A cursor only rises, and undoing a delta falls back to the run before
                for high in [50i64, 40, 60] {
                    run!(store, CURSOR, SNOWFLAKE, first, high).unwrap();
                }
                run!(store, CURSOR, SNOWFLAKE, second, SNOWFLAKE).unwrap();
                let reached = row!(store, (i64,), CURSORS, SNOWFLAKE).0;
                assert_eq!(reached, SNOWFLAKE);
                let undo =
                    "UPDATE voipc_imports SET undone_at = $1 WHERE id = $2 AND undone_at IS NULL";
                let once = run!(store, undo, 200i64, second).unwrap();
                let twice = run!(store, undo, 300i64, second).unwrap();
                assert_eq!((once, twice), (1, 0));
                let reached = row!(store, (i64,), CURSORS, SNOWFLAKE).0;
                assert_eq!(reached, 60, "40 did not lower it");

                // An account the move knows, and its group and twin
                let id = AccountId([7; 16]);
                store
                    .create_user(
                        &l4f_accounts::model::NewUser {
                            id,
                            username: "kim".into(),
                            display_name: "kim".into(),
                            email_pending: None,
                            password_hash: None,
                            created_at: 1,
                        },
                        None,
                    )
                    .await
                    .unwrap();
                let placeholder = "INSERT INTO voipc_placeholders \
                    (account, dc_id, import_id, banned, joined_at, imported_at) \
                    VALUES ($1, $2, $3, $4, $5, $6)";
                let unknown_run = run!(
                    store,
                    placeholder,
                    &id.0[..],
                    SNOWFLAKE,
                    i64::MAX,
                    false,
                    None::<i64>,
                    100i64
                );
                assert!(unknown_run.is_err(), "a row names a run that exists");
                run!(
                    store,
                    placeholder,
                    &id.0[..],
                    SNOWFLAKE,
                    first,
                    false,
                    Some(50i64),
                    100i64
                )
                .unwrap();
                let (dc_id, banned, joined, imported, claimed) = row!(
                    store,
                    (i64, bool, Option<i64>, i64, Option<i64>),
                    "SELECT p.dc_id, p.banned, p.joined_at, p.imported_at, p.claimed_at \
                     FROM voipc_placeholders p \
                     WHERE NOT p.banned AND p.claimed_at IS NULL AND p.imported_at <= $1 \
                     ORDER BY p.imported_at LIMIT 200",
                    100i64
                );
                assert_eq!(
                    (dc_id, banned, joined, imported, claimed),
                    (SNOWFLAKE, false, Some(50), 100, None)
                );
                let role = store.create_role("crew", "", None).await.unwrap().unwrap();
                let twin = store
                    .create_role("crew-power", "", None)
                    .await
                    .unwrap()
                    .unwrap();
                let group = "INSERT INTO voipc_import_groups (role, dc_role_id, power, import_id) \
                    VALUES ($1, $2, $3, $4)";
                run!(store, group, &role.0[..], SNOWFLAKE, false, first).unwrap();
                run!(store, group, &twin.0[..], SNOWFLAKE, true, first).unwrap();
                let another = store.create_role("crew2", "", None).await.unwrap().unwrap();
                let same_role = run!(store, group, &another.0[..], SNOWFLAKE, false, first);
                assert!(same_role.is_err(), "one zero-scope group for a role");
                let waiting = "INSERT INTO voipc_power_waiting (account, role) VALUES ($1, $2)";
                run!(store, waiting, &id.0[..], &twin.0[..]).unwrap();

                // Who is left out: `erase` is always said, since it destroys posts
                let excluded = "INSERT INTO voipc_import_excluded (dc_id, own, erase, at) \
                    VALUES ($1, $2, $3, $4) ON CONFLICT (dc_id) DO UPDATE \
                    SET own = excluded.own, erase = excluded.erase";
                let unsaid = run!(
                    store,
                    "INSERT INTO voipc_import_excluded (dc_id, own, at) VALUES ($1, $2, $3)",
                    1i64,
                    false,
                    1i64
                );
                assert!(unsaid.is_err(), "no default for `erase`");
                run!(store, excluded, SNOWFLAKE, false, false, 1i64).unwrap();
                run!(store, excluded, SNOWFLAKE, true, true, 2i64).unwrap();
                let (own, erase) = row!(
                    store,
                    (bool, bool),
                    "SELECT own, erase FROM voipc_import_excluded WHERE dc_id = $1",
                    SNOWFLAKE
                );
                assert_eq!((own, erase), (true, true));

                // A row of the archive: an upsert leaves its first run, a thread's name and
                // count, and a thread's upsert leaves its text
                let channel = SNOWFLAKE - 1;
                let body = format!("first line\nsecond\t{}", "x".repeat(16_000));
                let reactions = Some("[{\"emoji\":\"x\",\"count\":1}]");
                run!(
                    store,
                    MESSAGE,
                    channel,
                    0i64,
                    SNOWFLAKE,
                    Some(SNOWFLAKE),
                    wide.repeat(64),
                    "soon replaced",
                    None::<i64>,
                    None::<&str>,
                    None::<&str>,
                    false,
                    first
                )
                .unwrap();
                run!(
                    store,
                    THREAD,
                    channel,
                    SNOWFLAKE,
                    wide.repeat(100),
                    12i32,
                    second
                )
                .unwrap();
                run!(
                    store,
                    MESSAGE,
                    channel,
                    0i64,
                    SNOWFLAKE,
                    Some(SNOWFLAKE),
                    wide.repeat(64),
                    body.clone(),
                    Some(SNOWFLAKE - 5),
                    reactions,
                    None::<&str>,
                    true,
                    second
                )
                .unwrap();
                // An anonymised row in a thread, and a thread with no such message
                run!(
                    store,
                    MESSAGE,
                    channel,
                    SNOWFLAKE,
                    SNOWFLAKE - 3,
                    None::<i64>,
                    "Former member",
                    "older",
                    None::<i64>,
                    None::<&str>,
                    None::<&str>,
                    false,
                    second
                )
                .unwrap();
                run!(store, THREAD, channel, SNOWFLAKE - 9, "lone", 0i32, first).unwrap();
                let page = db!(store, pool => {
                    sqlx::query_as::<_, Page>(PAGE)
                        .bind(channel)
                        .bind(0i64)
                        .bind(i64::MAX)
                        .bind(200i64)
                        .fetch_all(pool)
                        .await
                        .unwrap()
                });
                assert_eq!(page.len(), 2, "newest first: {page:?}");
                assert_eq!(page[1].0, SNOWFLAKE - 9);
                assert_eq!((page[1].2.as_str(), page[1].3.as_str()), ("", ""));
                let top = &page[0];
                assert_eq!((top.0, top.1), (SNOWFLAKE, Some(SNOWFLAKE)));
                assert_eq!(top.2, wide.repeat(64));
                assert_eq!(top.3, body, "its newlines kept");
                assert_eq!(top.5.as_deref(), Some(wide.repeat(100).as_str()));
                assert_eq!(top.4.as_deref(), reactions);
                assert_eq!((top.6, top.7), (12, true));
                assert_eq!(
                    top.8, first,
                    "a row belongs to the run that first brought it"
                );

                // The queries reading depends on, each on both
                let pin = row!(
                    store,
                    (i64,),
                    "SELECT dc_id FROM voipc_archive WHERE channel = $1 AND pinned = TRUE \
                     AND dc_id < $2 ORDER BY dc_id DESC LIMIT $3",
                    channel,
                    i64::MAX,
                    200i64
                );
                assert_eq!(pin.0, SNOWFLAKE);
                let thread_row = row!(
                    store,
                    (i64, Option<i64>),
                    "SELECT dc_id, author_dc_id FROM voipc_archive WHERE channel = $1 AND thread > 0 \
                     AND (thread, dc_id) < ($2, $3) ORDER BY thread DESC, dc_id DESC LIMIT 2000",
                    channel,
                    i64::MAX,
                    i64::MAX
                );
                assert_eq!(thread_row, (SNOWFLAKE - 3, None));

                // A wish outlives its rows: a hide never softens a delete, and the widest fits
                let wish = |erase: bool| (SNOWFLAKE, 0i64, 0i64, i64::MAX, erase, 1i64);
                for (a, c, l, h, e, at) in [wish(false), wish(true), wish(false)] {
                    run!(store, WISH, a, c, l, h, e, at).unwrap();
                }
                let (high, erase) = row!(
                    store,
                    (i64, bool),
                    "SELECT high, erase FROM voipc_archive_wishes WHERE author_dc_id = $1",
                    SNOWFLAKE
                );
                assert_eq!((high, erase), (i64::MAX, true));

                // The worker's one statement: at most a batch, and only what it names
                let taken = run!(
                    store,
                    "DELETE FROM voipc_archive WHERE (channel, thread, dc_id) IN \
                     (SELECT channel, thread, dc_id FROM voipc_archive \
                      WHERE author_dc_id = $1 LIMIT 5000)",
                    SNOWFLAKE
                )
                .unwrap();
                assert_eq!(taken, 1);
                let left = row!(
                    store,
                    (i64,),
                    "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_archive"
                );
                assert_eq!(left.0, 2, "the anonymised row and the lone root stay");

                // A channel keeps its place and starts as not private; its reader still works
                run!(
                    store,
                    "INSERT INTO voipc_channels (conv, position) VALUES ($1, $2)",
                    "c:dc-1454987148113234751",
                    0i32
                )
                .unwrap();
                let private = "SELECT archive_private FROM voipc_channels WHERE conv = $1";
                let conv = "c:dc-1454987148113234751";
                assert!(!row!(store, (bool,), private, conv).0);
                run!(
                    store,
                    "UPDATE voipc_channels SET archive_private = $1 WHERE conv = $2",
                    true,
                    conv
                )
                .unwrap();
                assert!(row!(store, (bool,), private, conv).0);

                // What goes with a group, and with an account. Nothing here is theirs to take
                // but the marker: runs, cursors, what was left out and the archive stay
                let count = |table: &'static str| {
                    let store = store.clone();
                    async move {
                        let sql = format!("SELECT CAST(COUNT(*) AS BIGINT) FROM {table}");
                        let (n,): (i64,) = db!(&store, pool => {
                            sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_one(pool).await.unwrap()
                        });
                        n
                    }
                };
                assert!(store.delete_role(role).await.unwrap());
                assert_eq!(count("voipc_import_groups").await, 1, "the twin stays");
                assert_eq!(count("voipc_power_waiting").await, 1);
                assert!(store.delete_role(twin).await.unwrap());
                assert_eq!(count("voipc_import_groups").await, 0);
                assert_eq!(count("voipc_power_waiting").await, 0, "with the twin");
                run!(store, waiting, &id.0[..], &another.0[..]).unwrap();
                let mut tx = store.begin().await.unwrap();
                assert!(Store::delete_user(tx.conn(), id).await.unwrap());
                tx.commit().await.unwrap();
                assert_eq!(count("voipc_placeholders").await, 0);
                assert_eq!(count("voipc_power_waiting").await, 0, "with the account");
                assert_eq!(count("voipc_imports").await, 2);
                assert_eq!(count("voipc_import_items").await, 1);
                assert_eq!(count("voipc_import_cursors").await, 2);
                assert_eq!(count("voipc_import_excluded").await, 1);
                assert_eq!(count("voipc_archive_wishes").await, 1);
                assert_eq!(count("voipc_archive").await, 2);
            }
        }
    }
}
