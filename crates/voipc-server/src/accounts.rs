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
use tokio::sync::{mpsc, Semaphore};
use tracing::{info, warn};
use voipc_protocol::codec::{decode_client_msg, encode_server_msg};
use voipc_protocol::messages::{
    AccountReply, AccountRequest, AuthContinue, AuthStep, ClientMessage, ServerMessage,
};
use voipc_protocol::types::{
    AccountInfo, AccountStart, PowChallenge, PreKeyBundleData, Registration, RelayAccounts,
    VaultBlob,
};

use crate::config::{AccountsConfig, AccountsMode, RegistrationMode};
use crate::state::ServerState;

/// Kick, ban, and every channel's settings.
pub const MODERATE: &str = "voipc:moderate";
const APP_SCOPES: &[ScopeDef] = &[ScopeDef {
    name: MODERATE,
    description: "Kick, ban and change any channel's settings",
}];

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

pub mod bans;
pub mod log;

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
    pending: Arc<Semaphore>,
    pending_by_address: Arc<DashMap<String, usize>>,
    pow_key: Vec<u8>,
    /// What address bans are hashed with (`crate::bans`).
    ban_key: Vec<u8>,
    /// Recovery-key resets per address (`ConnLimits` key): each fetches a
    /// vault's recovery slot, so they are few (5, then one per 3 minutes).
    resets: DashMap<IpAddr, crate::state::RateLimiter>,
}

/// A key slot as `voipc_crypto::account::Vault` writes it: version byte,
/// salt (32), DEK id (8), nonce (12), the wrapped DEK and its tag (48).
const SLOT_LEN: usize = 1 + 32 + 8 + 12 + 48;

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
        Self::open_with(cfg, store, &master).await
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
            pending: Arc::new(Semaphore::new(PENDING_SIGN_INS)),
            pending_by_address: Arc::default(),
            pow_key,
            ban_key,
            resets: DashMap::new(),
        })
    }

    pub fn store(&self) -> &Store {
        &self.accounts.store
    }

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
    if store.role_by_name("moderator").await?.is_some() {
        return Ok(());
    }
    // None: another boot made it first. The scope comes in the same
    // transaction, so a crash never leaves a moderator role that grants nothing.
    store
        .create_role_with_scopes(
            "moderator",
            "Kick, ban and change any channel's settings",
            Some("mod"),
            &[MODERATE.to_string()],
        )
        .await?;
    Ok(())
}

/// l4f's settings as a relay needs them.
fn l4f_config(cfg: &AccountsConfig, relay_id: [u8; 16]) -> Config {
    // The client solves the proof of work; there is no form to fill slowly.
    // People behind one address sign up together on a voice relay (a
    // household, a LAN party): more than l4f's two a day, still bounded.
    let signup = l4f_accounts::pow::Limits {
        min_form_seconds: 0,
        max_accounts_per_ip_day: 20,
        max_accounts_per_hour: 60,
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
        ],
        storage_quota_bytes: i64::from(cfg.quota_mb) * 1024 * 1024,
        totp_issuer: "VoIPC".into(),
        // Device keys sign for this origin; it names the relay, not its address.
        base_url: format!("voipc://{}", hex::encode(relay_id)),
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
    pub account: AccountInfo,
    pub identity_key: Vec<u8>,
    pub prekey_bundle: PreKeyBundleData,
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, msg: &ServerMessage) -> Result<(), String> {
    crate::tcp::write_msg(stream, msg)
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
    let payload = crate::tcp::read_frame(stream, buf, wait)
        .await
        .map_err(|e| match e {
            crate::tcp::NoFrame::TimedOut => "Sign-in timed out.".to_string(),
            crate::tcp::NoFrame::Malformed => "malformed frame".to_string(),
            crate::tcp::NoFrame::Closed => "connection closed during sign-in".to_string(),
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
        AccountStart::Register { invite } => {
            let invite = invite.filter(|c| !c.trim().is_empty());
            if invite.is_none() && relay.registration != RegistrationMode::Open {
                return Err("Making an account here needs an invite.".into());
            }
            let pow = if invite.is_none() {
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
            let pw = secret_text(&auth_secret)?;
            let _work = work()?;
            let s = match &invite {
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
            .map_err(|e| e.message().to_string())?;
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
        auth_secret,
        pass_slot,
        totp,
        recovery_code,
    } = next(stream, buf, TOTP_WAIT, answers).await?
    else {
        return Err(unexpected());
    };
    if !voipc_crypto::account::reset_proof_ok(
        &identity,
        &relay.relay_id,
        &user.username,
        &challenge,
        &signature,
    ) {
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
    info!(user = %user.id.hex(), method = %info.method, "account signed in");
    Ok(SignedIn {
        user,
        token: session.token,
        info,
        scopes,
        account,
        identity_key,
        prekey_bundle,
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
    let password = secret_text(secret)?;
    let (user, _) =
        confirm_again(state, relay, session_id, ctx, user, info, &password, second).await?;
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
        crate::tcp::force_disconnect(
            state,
            id,
            "Your password was changed. Sign in with the new one.",
        )
        .await;
    }
}

/// `is_admin` / `is_moderator` as the scopes say.
pub fn powers(scopes: &[String]) -> (bool, bool) {
    // `allowed` never answers for `*` (a wildcard is no requirement); `covers` does.
    (
        scope::covers(scopes, &["*".to_string()]),
        scope::allowed(scopes, MODERATE),
    )
}

/// One `AccountRequest` from a signed-in connection.
pub async fn handle_request(
    state: &ServerState,
    session_id: u32,
    req: AccountRequest,
    tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let reply = |r: AccountReply| ServerMessage::Account(r);
    let Some(relay) = state.accounts.clone() else {
        return crate::tcp::send_msg(
            tx,
            &reply(refused("Account", "This relay has no accounts.")),
        )
        .await;
    };
    let Some((user, info, peer_ip)) = state.sessions.get(&session_id).and_then(|s| {
        s.account
            .as_ref()
            .map(|a| (a.user.clone(), a.info.clone(), s.peer_ip))
    }) else {
        return crate::tcp::send_msg(
            tx,
            &reply(refused("Account", "Sign in with an account first.")),
        )
        .await;
    };
    // Database work, so budgeted on its own beside the 50 messages a second
    // every message shares (1.0 audit H1-03). The variant's name is what a
    // client's error handling goes by.
    let allowed = state
        .sessions
        .get_mut(&session_id)
        .is_some_and(|mut s| s.account_rate.try_consume());
    if !allowed {
        let name = format!("{req:?}");
        let name = name.split([' ', '{', '(']).next().unwrap_or("Account");
        return crate::tcp::send_msg(
            tx,
            &reply(refused(name, "Too many requests at once; slow down.")),
        )
        .await;
    }
    let ctx = relay.ctx(peer_ip, voipc_protocol::codec::APP_VERSION);
    let now = util::now();
    let out = match req {
        AccountRequest::DeviceChallenge => {
            if !relay.accounts.fresh(&info, now) {
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
            if !relay.accounts.fresh(&info, now) {
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
                        crate::tcp::send_msg(
                            tx,
                            &reply(AccountReply::TotpEnabled { recovery_codes }),
                        )
                        .await?;
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
                    crate::tcp::send_msg(tx, &reply(AccountReply::AccountDeleted)).await?;
                    crate::tcp::force_disconnect(state, session_id, "Your account was deleted.")
                        .await;
                    return Ok(());
                }
                Err(reason) => refused("DeleteAccount", &reason),
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
        AccountRequest::LogKeys { accounts } => log::keys(&relay, &accounts).await?,
        AccountRequest::EpochPut { conv, epoch, wraps } => {
            let (out, told) = log::epoch_put(&relay, user.id, &conv, epoch, &wraps).await?;
            for r in told {
                tell(state, &r, AccountReply::LogNews { conv: conv.clone() }).await;
            }
            out
        }
        AccountRequest::WrapsFetch { conv } => log::wraps(&relay, user.id, &conv).await?,
        AccountRequest::LogAppend {
            conv,
            epoch,
            ct,
            ttl_secs,
        } => match kept_post_ok(state, session_id, &conv).await {
            Err(reason) => refused("LogAppend", &reason),
            Ok(()) => log::append(&relay, user.id, &conv, epoch, &ct, ttl_secs).await?,
        },
        AccountRequest::LogFetch { conv, after } => {
            log::fetch(&relay, user.id, &conv, after).await?
        }
        AccountRequest::LogIndex => {
            let (convs, pending) = log::index(&relay, user.id).await?;
            for p in pending {
                crate::tcp::send_msg(tx, &reply(p)).await?;
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
        AccountRequest::LogMembers { conv } => log::members_of(&relay, user.id, &conv).await?,
    };
    crate::tcp::send_msg(tx, &reply(out)).await
}

/// A channel's stored copy is held to the channel's own rules, as the live
/// post is (`ServerState::post_rules`): written from inside the channel, by a
/// manager in an announcement channel, at slow mode's pace. A direct
/// conversation has its two parties, which `log::append` checks.
async fn kept_post_ok(state: &ServerState, session_id: u32, conv: &str) -> Result<(), String> {
    if !conv.starts_with("c:") {
        return Ok(());
    }
    let user_id = state
        .sessions
        .get(&session_id)
        .map(|s| s.user_id)
        .ok_or("Sign in with an account first.")?;
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
            .filter(|c| c.persistent && !c.log_conv.is_empty())
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
        .filter_map(|u| state.user_to_session.get(u).map(|sid| *sid))
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
        .and_then(|sid| state.sessions.get(&*sid).map(|s| s.tcp_tx.clone()));
    if let Some(tx) = tx {
        let _ = crate::tcp::send_msg(&tx, &ServerMessage::Account(r)).await;
    }
}

/// Re-reads the account after a change (codes on, a role granted) and tells
/// the client; an admin it became is announced to everyone as before.
pub async fn refresh(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    user: AccountId,
) -> Result<()> {
    let Some(user) = relay.store().user_by_id(user).await? else {
        return Ok(());
    };
    let scopes = relay.accounts.effective_scopes(&user).await?;
    apply_scopes(state, relay, session_id, user, scopes).await
}

/// Every signed-in connection against the database, each
/// `REVALIDATE_MINUTES`: what the server's shell (another process) changed — a
/// role given or taken away, codes reset, the sessions ended — reaches
/// connections already open.
pub async fn revalidate(state: &Arc<ServerState>) {
    let Some(relay) = state.accounts.clone() else {
        return;
    };
    let live: Vec<(u32, String, Vec<String>, bool)> = state
        .sessions
        .iter()
        .filter_map(|e| {
            e.value()
                .account
                .as_ref()
                .map(|a| (*e.key(), a.token.clone(), a.scopes.clone(), a.needs_2fa))
        })
        .collect();
    for (session_id, token, scopes, needs_2fa) in live {
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
                    crate::tcp::force_disconnect(
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
                let changed = now != scopes
                    || relay
                        .accounts
                        .needs_2fa(&user)
                        .await
                        .is_ok_and(|n| n != needs_2fa);
                if changed {
                    if let Err(e) = apply_scopes(state, &relay, session_id, user, now).await {
                        warn!("a change from the server's shell: {e}");
                    }
                }
            }
            Err(e) => warn!("checking a signed-in connection: {e}"),
        }
    }
}

/// The session's powers as `scopes` say, and the account told.
async fn apply_scopes(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    user: User,
    scopes: Vec<String>,
) -> Result<()> {
    let info = relay.info_of(&user, &scopes).await?;
    let (tx, user_id, is_admin, became_admin) = {
        let Some(mut s) = state.sessions.get_mut(&session_id) else {
            return Ok(());
        };
        let was_admin = s.is_admin;
        s.set_scopes(user, scopes);
        if let Some(a) = s.account.as_mut() {
            a.needs_2fa = info.needs_2fa;
        }
        (
            s.tcp_tx.clone(),
            s.user_id,
            s.is_admin,
            s.is_admin != was_admin,
        )
    };
    crate::tcp::send_msg(&tx, &ServerMessage::Account(AccountReply::Info(info))).await?;
    if became_admin {
        let data = encode_server_msg(&ServerMessage::AdminStatus { user_id, is_admin })?;
        state.broadcast_raw_to_all(&data).await;
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
}
