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
use voipc_protocol::codec::{decode_client_msg, encode_server_msg};
use voipc_protocol::conv::dm_parties;
use voipc_protocol::messages::{
    AccountReply, AccountRequest, AuthContinue, AuthStep, ClientMessage, ServerMessage,
};
use voipc_protocol::types::{
    AccountInfo, AccountStart, ChatMod, PowChallenge, PreKeyBundleData, Registration,
    RelayAccounts, ReportTaker, VaultBlob,
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
pub mod bans;
pub mod gates;
pub mod layout;
pub mod links;
pub mod log;
pub mod modlog;
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
        vec![(
            "identity_key".into(),
            serde_json::json!(identity.map(hex::encode)),
        )]
    }

    /// The relay's rows go with the account through their foreign keys.
    async fn delete_user(
        &self,
        _tx: StoreConn<'_>,
        _user: AccountId,
        _delete_owned: bool,
    ) -> sqlx::Result<()> {
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
    /// How long the moderation log keeps a row.
    pub modlog_days: u32,
    pending: Arc<Semaphore>,
    pending_by_address: Arc<DashMap<String, usize>>,
    pow_key: Vec<u8>,
    /// One sign-up with a link at a time, from the gate's peek to its commit.
    link_lock: tokio::sync::Mutex<()>,
    /// What address bans are hashed with (`crate::bans`).
    ban_key: Vec<u8>,
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
}

/// A key slot as `voipc_crypto::account::Vault` writes it: version byte,
/// salt (32), DEK id (8), nonce (12), the wrapped DEK and its tag (48).
const SLOT_LEN: usize = 1 + 32 + 8 + 12 + 48;
/// `slot.reset`: the reset key's public half (Ed25519).
const SLOT_RESET: &str = voipc_crypto::account::SLOT_RESET;
const RESET_KEY_LEN: usize = 32;

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
        let ip_salt = keys.subkey("voipc-ip").to_vec();
        let host = RelayHost {
            cfg: Arc::new(l4f_config(cfg, relay_id)),
            store: store.clone(),
        };
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
        Ok(Relay {
            accounts,
            relay_id,
            required: cfg.mode == AccountsMode::Required,
            registration: cfg.registration,
            cloud: cfg.cloud,
            quota: i64::from(cfg.quota_mb) * 1024 * 1024,
            retention_ms: i64::from(cfg.retention_days) * 86_400_000,
            modlog_days: cfg.modlog_days,
            pending: Arc::new(Semaphore::new(PENDING_SIGN_INS)),
            pending_by_address: Arc::default(),
            pow_key,
            link_lock: tokio::sync::Mutex::new(()),
            ban_key,
            resets: DashMap::new(),
            providers: provider::Flows::default(),
            pairs: DashMap::new(),
            pair_asks: DashMap::new(),
            claiming: tokio::sync::Mutex::new(()),
        })
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

    /// One vault item, compare-and-set on `expect` (0 = new).
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
        // two writes at once cannot both pass. The vault is all an account
        // keeps in l4f's storage, so its total is the quota there.
        let quota = self.quota.min(VAULT_TOTAL_BYTES as i64);
        Ok(
            match self
                .store()
                .put_blob_limited(
                    user,
                    VAULT_NS,
                    k,
                    v,
                    expect,
                    quota,
                    Some(VAULT_MAX_ITEMS),
                    false,
                )
                .await?
            {
                PutLimited::Put(PutBlob::Done(version)) => AccountReply::VaultStored {
                    k: k.to_string(),
                    version,
                },
                PutLimited::Put(PutBlob::Conflict) => {
                    let blob = self
                        .store()
                        .blob(user, VAULT_NS, k)
                        .await?
                        .map(|b| VaultBlob {
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
        let counted: Vec<_> = roles
            .iter()
            .filter(|r| scope::covers(scopes, &r.scopes))
            .collect();
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
        // Nothing is free of the second-factor rule but having no role at all.
        default_user_scopes: Vec::new(),
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
) -> Result<SignedIn, String> {
    let ctx = relay.ctx(ip, app_version);
    let mut answers = 0u32;
    let mut registered = false;
    let work = || relay.pending_slot(ip).ok_or_else(|| BUSY.to_string());
    let session: NewSession = match start {
        AccountStart::Login => {
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
            let login = {
                let _work = work()?;
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
            let AuthContinue::DeviceSig { signature } =
                next(stream, buf, STEP_WAIT, &mut answers).await?
            else {
                return Err(unexpected());
            };
            let _work = work()?;
            relay
                .accounts
                .devkey_login(&ctx, &challenge, &nonce, &device_id, &signature)
                .await
                .map_err(|e| e.message().to_string())?
        }
        AccountStart::Reset => {
            return reset(state, relay, stream, buf, name, &ctx, ip, &mut answers).await
        }
        AccountStart::Providers => {
            let kinds = relay.provider_kinds();
            step(stream, AuthStep::Providers { kinds }).await?;
            return Err(ANSWERED.into());
        }
        AccountStart::Provider { kind } => {
            relay.provider_open(stream, kind, ip).await?;
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
            let AuthContinue::Register {
                auth_secret,
                altcha,
                ts,
                vault,
            } = next(stream, buf, REGISTER_WAIT, &mut answers).await?
            else {
                return Err(unexpected());
            };
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
            let pw = secret_text(&auth_secret)?;
            let _work = work()?;
            let s = if let Some(code) = invite.as_deref().filter(|c| links::is_link_code(c)) {
                links::register(
                    relay,
                    &ctx,
                    code,
                    name,
                    links::How::Password(&pw),
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
                            password: &pw,
                            email: None,
                            display_name: None,
                        };
                        relay.accounts.register_invite(&ctx, form).await
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
                            password: &pw,
                            email: None,
                            display_name: None,
                            proof,
                        };
                        relay.accounts.register(&ctx, form).await
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
    .await;
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
        let identity = relay
            .identity(user.id)
            .await
            .map_err(|_| gone())?
            .ok_or("This account cannot be reset.")?;
        let vault = relay.vault(user.id).await.map_err(|_| gone())?;
        (user, identity, vault)
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
    let AuthContinue::Reset {
        signature,
        key_signature,
        auth_secret,
        pass_slot,
        totp,
        recovery_code,
    } = next(stream, buf, TOTP_WAIT, answers).await?
    else {
        return Err(unexpected());
    };
    // An account with a reset key proves the recovery key itself; one made
    // before 1.3 has only its identity, which the vault's DEK opens too
    let proved = match vault.iter().find(|b| b.k == SLOT_RESET) {
        Some(reset_key) => voipc_crypto::account::reset_key_proof_ok(
            &reset_key.v,
            &relay.relay_id,
            &user.username,
            &challenge,
            &key_signature,
        ),
        None => voipc_crypto::account::reset_proof_ok(
            &identity,
            &relay.relay_id,
            &user.username,
            &challenge,
            &signature,
        ),
    };
    if !proved {
        return Err("That recovery key is not this account's.".into());
    }
    if pass_slot.len() != SLOT_LEN {
        return Err(unexpected());
    }
    let pw = secret_text(&auth_secret)?;
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
        relay.accounts.password_set_as_host(ctx, user.id, &pw)
    })
    .await?;
    info!(user = %user.id.hex(), "account password reset with the recovery key");
    sign_out_account(state, user.id).await;
    step(stream, AuthStep::ResetDone).await?;
    Err("Your password was reset. Sign in with the new one.".into())
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
    }
    Ok((user, fresh))
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
    let reply = |r: AccountReply| ServerMessage::Account(r);
    let Some(relay) = state.accounts.clone() else {
        return crate::session::send_msg(
            tx,
            &reply(refused("Account", "This relay has no accounts.")),
        );
    };
    let Some((user, info, peer_ip, vault_proven)) = state.sessions.get(&session_id).and_then(|s| {
        s.account
            .as_ref()
            .map(|a| (a.user.clone(), a.info.clone(), s.peer_ip, a.vault_proven))
    }) else {
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
    );
    let allowed = state.sessions.get_mut(&session_id).is_some_and(|mut s| {
        if reads_log {
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
                    "Sign in with your password again to turn codes on.",
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
                Ok(()) => {
                    provider::start_for_account(&relay, session_id, &user, kind, link, peer_ip)
                }
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
                    crate::session::force_disconnect(
                        state,
                        session_id,
                        "Your account was deleted.",
                    )
                    .await;
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
            for r in told {
                tell(state, &r, AccountReply::LogNews { conv: conv.clone() }).await;
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
            Ok(()) => {
                let out = log::append(&relay, user.id, &conv, epoch, &ct, ttl_secs).await?;
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
        AccountRequest::LogLeave { conv } => log::leave(&relay, user.id, &conv).await?,
        AccountRequest::LogMembers { conv } => log::members_of(&relay, user.id, &conv)
            .await
            .unwrap_or_else(|e| read_failed("LogMembers", e)),
        AccountRequest::Admin { op, code } => {
            admin::handle(state, &relay, session_id, &user, &ctx, op, code).await?
        }
        AccountRequest::ProfileSet { name } => {
            profile::set_name(state, &relay, session_id, &user, name).await?
        }
        AccountRequest::ProfilePictureSet { image } => {
            profile::set_picture(state, &relay, session_id, &user, image).await?
        }
    };
    crate::session::send_msg(tx, &reply(out))
}

/// A channel's stored copy is held to the channel's own rules, as the live
/// post is (`ServerState::post_rules`): written from inside the channel, by a
/// manager in an announcement channel, at slow mode's pace. A direct
/// conversation has its two parties, which `log::append` checks; a copy there
/// carries the writer's account, so none is kept behind a pseudonym, where the
/// live message goes out under the alias and the copy would tie the two.
async fn kept_post_ok(state: &ServerState, session_id: u32, conv: &str) -> Result<(), String> {
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
        return Ok(());
    }
    let channel_id = {
        let channels = state.channels.read().await;
        channels
            .iter()
            .find(|(_, c)| !c.info.log.is_empty() && c.info.log == conv)
            .map(|(id, _)| *id)
    };
    // An anonymous channel, or one hiding its members, offers no log.
    let channel_id = channel_id.ok_or("That channel keeps no messages.")?;
    state
        .post_rules(
            session_id,
            user_id,
            channel_id,
            crate::state::PostStamp::Kept,
        )
        .await
}

/// The account behind `session_id` leaves `channel_id`'s log: kicked from
/// the channel, or it left a text channel (1.0, D10: the relay does it, so a
/// modified client cannot stay a reader), so what is written there from now
/// on is not for them. Moving between voice channels keeps a log; "Stop
/// keeping this channel" (`LogLeave`) ends it there.
pub async fn out_of_log(state: &ServerState, channel_id: u32, session_id: u32) {
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
    if let Err(e) = log::remove(relay.store(), &conv, &account).await {
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
                    crate::session::force_disconnect(
                        state,
                        session_id,
                        "You were signed out of this server.",
                    )
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
                    if let Err(e) = apply_scopes(state, &relay, session_id, user, now, read).await {
                        warn!("a change from the server's shell: {e}");
                    }
                }
            }
            Err(e) => warn!("checking a signed-in connection: {e}"),
        }
    }
    // Holders who are not here too: a stored hide is read against them
    refresh_chat_mods(state).await;
}

/// The session's powers as `scopes` say, and the account told. A change of
/// groups reaches what they see and where they may be (`gates`), one of
/// badges or privileges the rosters showing them.
/// Holds power over others, which spares it from a kick and an address ban.
/// Calling on everybody, taking reports and reading the log act on nobody: a
/// helper holding only those can still be kicked.
pub fn holds_power(scopes: &[String]) -> bool {
    scopes
        .iter()
        .any(|s| ![MENTION_ALL, REPORTS, MODLOG].contains(&s.as_str()))
}

/// Whether this session's account may call on everybody.
pub fn holds_mention_power(s: &crate::state::UserSession) -> bool {
    s.account
        .as_ref()
        .is_some_and(|a| scope::allowed(&a.scopes, MENTION_ALL))
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
    const PAGE: u32 = if cfg!(test) { 2 } else { 500 };
    let mut read = std::collections::BTreeSet::new();
    let mut mods = std::collections::BTreeMap::new();
    for role in relay.store().roles().await? {
        if !holds_power(&role.scopes) {
            continue;
        }
        let mut offset = 0;
        loop {
            let (users, total) = relay.store().role_members(role.id, PAGE, offset).await?;
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

/// Reads who holds what and tells everybody, if that changed. The list stays locked
/// throughout, so that two reads at once cannot end with the older one's answer.
pub async fn refresh_chat_mods(state: &ServerState) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    let mut held = state.chat_mods.write().await;
    let mods = match read_chat_mods(relay).await {
        Ok(mods) => mods,
        Err(e) => {
            warn!("reading who holds privileges: {e:#}");
            return;
        }
    };
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
    let info = relay.info_of(&user, &scopes).await?;
    let standing = relay.standing(&user, &scopes).await?;
    let (my_badges, calls, called_before, editor_changed, listed_changed, reads_restrictions);
    let (tx, user_id, channel_id, is_admin, became_admin, regated, shown) = {
        let Some(mut s) = state.sessions.get_mut(&session_id) else {
            return Ok(());
        };
        if read < s.scope_written {
            return Ok(());
        }
        s.scope_written = read;
        let (was_admin, was_editor) = (s.is_admin, s.powers.has(Powers::CHANNELS));
        let could_call = holds_mention_power(&s);
        let was_listed = (s.is_moderator, holds_hide(&s));
        let could_restrict = s.can(Powers::RESTRICT);
        s.set_scopes(user, scopes);
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
    if listed_changed {
        refresh_chat_mods(state).await;
    }
    Ok(())
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
                log::publish(&relay, id, &[1; 33], &[2; 64]).await.unwrap();
                assert!(log::has_key(&relay, &id.0).await.unwrap());
                assert!(!log::has_key(&relay, &[8; 16]).await.unwrap());
            }
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
                assert_eq!(
                    relay
                        .posts_remove(Some(id.0), 1000, 4000, window, &row)
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
                assert_eq!(
                    relay
                        .posts_remove(None, 0, 4000, window, &guest)
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
                assert_eq!(rows[1].8, "2 kept messages, last hour");
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
    }
}
