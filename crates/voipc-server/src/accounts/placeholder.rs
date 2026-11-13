//! `voipc_placeholders`: an account the move from Discord made for someone who has not
//! come yet, and its power, which waits. Real `acct_users` rows with no password and no
//! vault: only a sign-in through Discord reaches one, and whoever does opens it.
//!
//! **Power is never automatic.** Each Discord role makes a group holding no privileges,
//! which carries the badge and the gates, and when the role could do anything a twin
//! holding what it maps to (`discord::scopes_of`, from the raw bits; no client names a
//! privilege). Members get the plain group. A twin goes on `voipc_power_waiting`, and only
//! `*` gives it, to someone who has opened their account. A hijacked Discord account can
//! open a placeholder; it holds a name and a badge then, and nothing over anyone.
//!
//! What counts is `claimed_at`, never whether an identity row is there: `admin reclaim`
//! takes that away from an account someone did open.
//!
//! Any other group with privileges an account of the move holds when someone opens it waits
//! too, however it came to hold it: `hold_power`, at the claim and at `admin reclaim`.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use l4f_accounts::model::{AccountId, Credential, NewUser, Role, UserStatus};
use l4f_accounts::oauth::Kind;
use l4f_accounts::scope;
use l4f_accounts::service::{Actor, Ctx, Error, Host, RoleForm};
use l4f_accounts::store::{CreateUserError, Store, WriteError};
use l4f_accounts::util;
use tracing::warn;
use voipc_protocol::codec::encode_server_msg;
use voipc_protocol::discord;
use voipc_protocol::messages::{AccountReply, AdminReply, ServerMessage};
use voipc_protocol::types::{
    AdminUser, GroupInfo, ImportBan, ImportMember, ImportRole, MoveAccount, MoveFilter, MoveRun,
    MoveState, PowerRow, SessionId, VaultBlob, IMPORT_FRAME_ROWS,
};

use super::modlog::{self, clip, Entry};
use super::{archive, import, log, refused, Relay, SLOT_LEN};
use crate::state::ServerState;

/// One member's roles on Discord, at most: what a frame may say.
const MEMBER_ROLES: usize = 250;
/// Rows of `PowerWaiting` a page holds.
const POWER_PAGE: i64 = 50;
/// Accounts one pass of the sweep takes, under one row in the log.
const SWEEP_BATCH: usize = 200;
/// Rows of `MoveAccounts` a page holds.
const ACCOUNTS_PAGE: i64 = 50;
/// Runs `MoveStatus` tells of, the newest.
const RUNS_SHOWN: i64 = 50;
/// Rows of `MoveExcluded` a reply holds: some 32 bytes each, under one frame.
const EXCLUDED_PAGE: i64 = 1000;
/// The groups' list goes in one frame: a group past this is left out and named.
const GROUPS_BYTES: usize = 60 * 1024;
/// A group's name never gets a built-in's, whatever the role is called.
const BUILT_IN: [&str; 3] = ["admin", "user", "moderator"];
/// `item.identity` as a real vault has it: `0x02 | dek_id(8) | iv(12) |` the sealed
/// identity key pair. A test holds this to `voipc_crypto::account::Vault`.
const ITEM_IDENTITY_LEN: usize = 1 + 8 + 12 + 2 + 8 + 69 + 16;

type Place = (Vec<u8>, bool, Option<i64>);
type GroupRow = (Vec<u8>, i64, bool);
type WaitRow = (Vec<u8>, String, Vec<u8>, i64);
/// (id, name, codes on, created, Discord's id, banned, claimed, imported)
type AccountRow = (
    Vec<u8>,
    String,
    bool,
    i64,
    Option<i64>,
    Option<bool>,
    Option<i64>,
    Option<i64>,
);
/// (id, guild, by, started, finished, undone, accounts, groups, clearing)
type RunRow = (
    i64,
    i64,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    i64,
    i64,
    i64,
);

/// `MoveAccounts`' statements for one filter: a constant, no client text. `!` escapes, as l4f's
/// own search has it.
macro_rules! accounts_query {
    ($filter:literal) => {
        (
            concat!(
                "SELECT u.id, u.username, u.totp_enc IS NOT NULL, CAST(u.created_at AS BIGINT),
                        CAST(p.dc_id AS BIGINT), p.banned, CAST(p.claimed_at AS BIGINT),
                        CAST(p.imported_at AS BIGINT)
                 FROM acct_users u LEFT JOIN voipc_placeholders p ON p.account = u.id
                 WHERE u.username LIKE $1 ESCAPE '!' ",
                $filter,
                " ORDER BY u.created_at DESC, u.id LIMIT $2 OFFSET $3"
            ),
            concat!(
                "SELECT CAST(COUNT(*) AS BIGINT)
                 FROM acct_users u LEFT JOIN voipc_placeholders p ON p.account = u.id
                 WHERE u.username LIKE $1 ESCAPE '!' ",
                $filter
            ),
        )
    };
}

/// A Discord id that fits the BIGINT columns: snowflakes do until 2084.
pub(crate) fn id_ok(id: u64) -> bool {
    id != 0 && id <= i64::MAX as u64
}

/// The last `n` digits of a Discord id, which is what tells two equal names apart.
fn tail(dc_id: u64, n: usize) -> String {
    let d = dc_id.to_string();
    d[d.len().saturating_sub(n)..].to_string()
}

/// `first` bytes of something `clean_name` made, which is ASCII.
fn first(s: &str, n: usize) -> &str {
    &s[..s.len().min(n)]
}

/// What a Discord name comes to in the account alphabet. A `.` becomes `_`: dropping it
/// would merge `a.b` with `ab`.
fn clean_name(raw: &str) -> String {
    let kept: String = raw
        .chars()
        .map(|c| {
            if c == '.' {
                '_'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .filter(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
        .take(32)
        .collect();
    kept.trim_start_matches(['_', '-']).to_string()
}

/// The names to try in turn for someone. What the rules refuse (reserved, its look-alike
/// such as `1uki`, too short, all digits, nothing left) is `member-<last 6>`, and so
/// never `admin-123456`, which would read as staff. The bare name only if cleaning took
/// nothing away: `_alice` must not take `alice` from whoever is called that.
pub fn username_candidates(raw: &str, dc_id: u64, reserved: &[&str]) -> Vec<String> {
    let clean = clean_name(raw);
    let (six, ten) = (tail(dc_id, 6), tail(dc_id, 10));
    let mut names = match scope::normalize_username(&clean, reserved) {
        Ok(name) => {
            let whole = raw.to_ascii_lowercase().replace('.', "_") == clean;
            let bare = whole.then_some(name);
            bare.into_iter()
                .chain([
                    format!("{}-{six}", first(&clean, 25)),
                    format!("{}-{ten}", first(&clean, 21)),
                ])
                .collect()
        }
        Err(_) => vec![format!("member-{six}"), format!("member-{ten}")],
    };
    names.push(format!("dc-{dc_id}"));
    let mut seen = HashSet::new();
    names.retain(|n| scope::normalize_username(n, reserved).is_ok() && seen.insert(n.clone()));
    names
}

/// A group's name from a role's, leaving room for `-power`. No prefix, so a gate's list
/// stays readable: whatever must know a group came from Discord reads the table.
pub fn group_base(raw: &str, dc_id: u64) -> String {
    let clean = clean_name(raw);
    if clean.len() < 2 {
        return format!("role-{}", tail(dc_id, 6));
    }
    first(&clean, 26).to_string()
}

/// The names to try for the plain group. `create_role` answers `RoleTaken` for a taken
/// one, and there is no adopting by name.
fn group_names(base: &str, dc_id: u64) -> Vec<String> {
    let other = format!("{}-{}", first(base, 19), tail(dc_id, 6));
    if BUILT_IN.contains(&base) {
        vec![other]
    } else {
        vec![base.to_string(), other]
    }
}

fn twin_names(group: &str, dc_id: u64) -> Vec<String> {
    vec![
        format!("{group}-power"),
        format!("{}-{}-power", first(group, 19), tail(dc_id, 6)),
    ]
}

/// A role's name as a badge: `None` if it could not show as one.
fn badge_of(name: &str) -> Option<String> {
    let short: String = name.chars().take(32).collect();
    scope::clean_display_name(&short).ok()
}

/// When the wait starts for someone the move knows. Whoever had been in the Discord for
/// the whole wait when the import ran has served it. Everyone else counts from when they
/// opened the account here, never from when the row was made, which says nothing of who
/// came.
pub fn wait_start(joined_at: Option<i64>, imported_at: i64, claimed_at: i64, wait: i64) -> i64 {
    if joined_at.is_some_and(|j| imported_at.saturating_sub(j) >= wait) {
        0
    } else {
        claimed_at
    }
}

fn roles_fit(groups: &[GroupInfo]) -> bool {
    let frame = ServerMessage::Account(AccountReply::Admin(AdminReply::Groups {
        groups: groups.to_vec(),
    }));
    encode_server_msg(&frame).is_ok_and(|b| b.len() <= GROUPS_BYTES)
}

fn info_of(role: &Role) -> GroupInfo {
    GroupInfo {
        name: role.name.clone(),
        description: role.description.clone(),
        badge: role.badge.clone().unwrap_or_default(),
        scopes: role.scopes.clone(),
        builtin: role.builtin,
    }
}

fn account_of(bytes: &[u8]) -> Option<AccountId> {
    bytes.try_into().ok().map(AccountId)
}

/// The groups one guild's roles made: by Discord's id, the plain one and the twin.
#[derive(Default)]
struct Ledger {
    plain: HashMap<u64, AccountId>,
    twin: HashMap<u64, AccountId>,
    /// What a role is to this guild: Discord's id, and whether it is a twin.
    of: HashMap<AccountId, (u64, bool)>,
}

/// What making an account came to.
enum Made {
    Account,
    /// Someone signed up with that Discord this instant: ours went, theirs stays.
    Lost,
    NoName,
    /// Someone opened it, by this name, and took Discord off: nothing was written.
    Opened(String),
}

impl Relay {
    /// Keyed, so an id says nothing, and the same every time, so a crash between
    /// writes heals: the next run finds the account again, where a new id would leave one
    /// holding a name with no way in.
    pub(crate) fn placeholder_id(&self, dc_id: u64) -> AccountId {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.placeholder_key);
        let tag = ring::hmac::sign(&key, &dc_id.to_be_bytes());
        let mut id = [0u8; 16];
        id.copy_from_slice(&tag.as_ref()[..16]);
        AccountId(id)
    }

    /// What a banned row is called, in turn: `dc-<id>` can be signed up for by anyone who
    /// knows the id, so the second is one nobody can tell in advance. At most 27 characters.
    fn banned_names(&self, dc_id: u64) -> [String; 2] {
        let keyed = self.placeholder_id(dc_id).0;
        [
            format!("dc-{dc_id}"),
            format!("dc-{dc_id}-{:02x}{:02x}", keyed[0], keyed[1]),
        ]
    }

    /// A row that turned out banned goes by what one made banned goes by, everywhere a name
    /// of theirs was. False: both are taken, and it keeps what it has.
    async fn banned_rename(&self, ctx: &Ctx, id: AccountId, dc_id: u64) -> Result<bool> {
        for name in self.banned_names(dc_id) {
            match self.accounts.rename_as_host(ctx, id, &name).await {
                Ok(name) => {
                    db!(self.store(), pool => {
                        let mut tx = pool.begin().await?;
                        sqlx::query("UPDATE acct_users SET display_name = $1 WHERE id = $2")
                            .bind(&name)
                            .bind(&id.0[..])
                            .execute(&mut *tx)
                            .await?;
                        sqlx::query("UPDATE acct_credentials SET name = $1 WHERE user_id = $2 AND kind = $3")
                            .bind(&name)
                            .bind(&id.0[..])
                            .bind(Kind::Discord.credential_kind())
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                    });
                    return Ok(true);
                }
                Err(Error::UsernameTaken) => {}
                Err(e) => return Err(anyhow!("renaming a banned account: {}", e.message())),
            }
        }
        Ok(false)
    }

    /// The Discord id the move knows this account by, whether or not it is still linked.
    pub(super) async fn placeholder_dc_id(&self, id: AccountId) -> Result<Option<i64>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar("SELECT CAST(dc_id AS BIGINT) FROM voipc_placeholders WHERE account = $1")
                .bind(&id.0[..])
                .fetch_optional(pool)
                .await?
        }))
    }

    /// A group's row in the ledger, while its run stands: (Discord's role, a twin, the run).
    pub(super) async fn group_ledger_row(&self, name: &str) -> Result<Option<(i64, bool, i64)>> {
        let name = name.trim().to_ascii_lowercase();
        Ok(db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT CAST(g.dc_role_id AS BIGINT), g.power, CAST(g.import_id AS BIGINT)
                 FROM voipc_import_groups g
                 JOIN acct_roles r ON r.id = g.role
                 JOIN voipc_imports i ON i.id = g.import_id
                 WHERE r.name = $1 AND i.undone_at IS NULL",
            )
            .bind(&name)
            .fetch_optional(pool)
            .await?
        }))
    }

    /// One removed here stays removed, as a channel, a category and an emote do: the row
    /// goes with the run that made the group. Its own row in `voipc_import_groups` is gone.
    pub(super) async fn group_deleted_here(&self, row: (i64, bool, i64)) -> Result<()> {
        let (dc_role, twin, run) = row;
        let kind = if twin {
            import::KIND_TWIN_DELETED
        } else {
            import::KIND_GROUP_DELETED
        };
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_import_items (kind, dc_id, import_id, local) VALUES ($1, $2, $3, '')
                 ON CONFLICT (kind, dc_id) DO NOTHING",
            )
            .bind(kind)
            .bind(dc_role)
            .bind(run)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// A row of the move's that nobody has opened.
    pub(crate) async fn placeholder_open(&self, id: AccountId) -> Result<bool> {
        let n: i64 = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders WHERE account = $1 AND claimed_at IS NULL",
            )
            .bind(&id.0[..])
            .fetch_one(pool)
            .await?
        });
        Ok(n > 0)
    }

    /// A row of the move's for someone banned on Discord.
    pub(super) async fn banned_place(&self, id: AccountId) -> Result<bool> {
        let n: i64 = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders WHERE account = $1 AND banned = TRUE",
            )
            .bind(&id.0[..])
            .fetch_one(pool)
            .await?
        });
        Ok(n > 0)
    }

    /// Whether power given to this account now would go to whoever opens it next: one of
    /// the move's nobody has opened, or that `admin reclaim` put back. Here, and only for
    /// power, a missing identity counts: an OK given in between is not for them.
    pub async fn power_would_wait(&self, id: AccountId) -> Result<bool> {
        let n: i64 = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders p
                 WHERE p.account = $1
                   AND (p.claimed_at IS NULL
                        OR NOT EXISTS (SELECT 1 FROM voipc_identity i WHERE i.account = p.account))",
            )
            .bind(&id.0[..])
            .fetch_one(pool)
            .await?
        });
        Ok(n > 0)
    }

    /// The identity and the mark that the account was opened, both or neither: the sweep
    /// and the dashboard go by the mark.
    pub(super) async fn claim_done(&self, user: AccountId, key: &[u8]) -> Result<()> {
        let now = util::now();
        db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "INSERT INTO voipc_identity (account, identity_key, updated_at) VALUES ($1, $2, $3)
                 ON CONFLICT (account) DO UPDATE SET identity_key = excluded.identity_key, updated_at = excluded.updated_at",
            )
            .bind(&user.0[..])
            .bind(key)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE voipc_placeholders SET claimed_at = $1 WHERE account = $2")
                .bind(now)
                .bind(&user.0[..])
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        });
        Ok(())
    }

    /// `name` for an account nobody has opened. Under the lock `claim` holds: a vault is
    /// bound to the name, so a rename slipping past a claim would leave one that never
    /// opens again. `Ok(Err(..))`: what the name screen says, for another try.
    pub(super) async fn placeholder_rename(
        &self,
        ctx: &Ctx,
        id: AccountId,
        name: &str,
    ) -> Result<Result<String, String>, String> {
        let gone = |_| "Something went wrong. Please try again.".to_string();
        let _one = self.claiming.lock().await;
        if !self.placeholder_open(id).await.map_err(gone)?
            || self.identity(id).await.map_err(gone)?.is_some()
        {
            return Err("This account was opened just now, somewhere else.".into());
        }
        match self.accounts.rename_as_host(ctx, id, name).await {
            Ok(new) => Ok(Ok(new)),
            Err(e @ (Error::UsernameTaken | Error::Invalid(_))) => Ok(Err(e.message().to_string())),
            Err(e) => Err(e.message().to_string()),
        }
    }

    /// The account of a Discord id the move has made a row for.
    async fn place_of(&self, dc_id: i64) -> Result<Option<Place>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT account, banned, CAST(claimed_at AS BIGINT) FROM voipc_placeholders WHERE dc_id = $1",
            )
            .bind(dc_id)
            .fetch_optional(pool)
            .await?
        }))
    }

    /// Whether a ban on this id stays lifted: a lifted ban (`own` off), or one lifted for
    /// someone who deleted their own account (`lifted`, W1-31).
    async fn ban_lifted(&self, dc_id: i64) -> Result<bool> {
        let row: Option<(bool, bool)> = db!(self.store(), pool => {
            sqlx::query_as("SELECT own, lifted FROM voipc_import_excluded WHERE dc_id = $1")
                .bind(dc_id)
                .fetch_optional(pool)
                .await?
        });
        Ok(row.is_some_and(|(own, lifted)| !own || lifted))
    }

    /// `Some(own)` for an id no import touches.
    async fn excluded_own(&self, dc_id: i64) -> Result<Option<bool>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar("SELECT own FROM voipc_import_excluded WHERE dc_id = $1")
                .bind(dc_id)
                .fetch_optional(pool)
                .await?
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn place_put(
        &self,
        id: AccountId,
        dc_id: i64,
        run: i64,
        banned: bool,
        joined_at: Option<i64>,
        now: i64,
        claimed_at: Option<i64>,
    ) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_placeholders (account, dc_id, import_id, banned, joined_at, imported_at, claimed_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
            )
            .bind(&id.0[..])
            .bind(dc_id)
            .bind(run)
            .bind(banned)
            .bind(joined_at)
            .bind(now)
            .bind(claimed_at)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// The bytes a sign-in looks the Discord account up by (`Identity.subject`), written
    /// for `id`. False: another account has them.
    async fn discord_link(&self, id: AccountId, dc_id: u64, handle: &str) -> Result<bool> {
        let credential = Credential {
            kind: Kind::Discord.credential_kind(),
            ext_id: dc_id.to_string().into_bytes(),
            user_id: id,
            public_key: None,
            alg: 0,
            sign_count: 0,
            flags: 0,
            name: scope::clean_display_name(handle).unwrap_or_else(|_| "Discord".into()),
            created_at: util::now(),
            last_used_at: None,
            public: false,
        };
        Ok(self.store().insert_credential(&credential).await?)
    }

    /// An account with no way in but Discord's, from `dc_id`. Or the one a run that died
    /// left behind, never one someone opened. A banned one is `dc-<id>`, so that it squats no
    /// real name, and disabled before it can be signed in to at all.
    async fn make_account(
        &self,
        dc_id: u64,
        handle: &str,
        joined_at: Option<i64>,
        run: i64,
        banned: bool,
    ) -> Result<Made> {
        let id = self.placeholder_id(dc_id);
        let now = util::now();
        let user = self.store().user_by_id(id).await?;
        if let (Some(user), Some(_)) = (&user, self.identity(id).await?) {
            return Ok(Made::Opened(user.username.clone()));
        }
        if user.is_none() {
            let cfg = self.accounts.host.config();
            let reserved: Vec<&str> = cfg.reserved_usernames.iter().map(String::as_str).collect();
            let names = if banned {
                self.banned_names(dc_id).to_vec()
            } else {
                username_candidates(handle, dc_id, &reserved)
            };
            let mut made = false;
            for username in names {
                let new = NewUser {
                    id,
                    username: username.clone(),
                    display_name: username,
                    email_pending: None,
                    password_hash: None,
                    // Never older than it is: the wait does not read it for these rows
                    created_at: now,
                };
                match self.store().create_user(&new, Some("user")).await {
                    Ok(()) => {
                        made = true;
                        break;
                    }
                    Err(CreateUserError::UsernameTaken) => {}
                    Err(CreateUserError::Db(e)) => return Err(e.into()),
                }
            }
            if !made {
                return Ok(Made::NoName);
            }
        }
        if banned {
            self.store()
                .set_status(id, UserStatus::Disabled)
                .await
                .map_err(|e| anyhow!("disabling a banned account: {e:?}"))?;
        }
        self.place_put(id, dc_id as i64, run, banned, joined_at, now, None)
            .await?;
        if !self.discord_link(id, dc_id, handle).await? {
            self.delete_quietly(id).await?;
            return Ok(Made::Lost);
        }
        Ok(Made::Account)
    }

    /// `Store::delete_user` itself, so that `Host::delete_user` does not run: this is
    /// nobody asking to be left out.
    async fn delete_quietly(&self, id: AccountId) -> Result<bool> {
        let mut tx = self.store().begin().await?;
        let gone = Store::delete_user(tx.conn(), id)
            .await
            .map_err(|e| anyhow!("deleting an unopened account: {e:?}"))?;
        tx.commit().await?;
        Ok(gone)
    }

    /// An account nobody opened goes, if that is still so with `claiming` held. False: it
    /// was opened meanwhile, or a moderator banned it in the app, which would cascade away.
    pub(crate) async fn drop_unclaimed(&self, id: AccountId) -> Result<bool> {
        let _one = self.claiming.lock().await;
        let still: i64 = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_placeholders p
                 WHERE p.account = $1 AND p.claimed_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM voipc_identity i WHERE i.account = p.account)
                   AND NOT EXISTS (SELECT 1 FROM voipc_bans b WHERE b.account = p.account)",
            )
            .bind(&id.0[..])
            .fetch_one(pool)
            .await?
        });
        if still == 0 {
            return Ok(false);
        }
        self.delete_quietly(id).await
    }

    /// What `AccountSession.wait_from` is for this account, `None` if the move does not
    /// know it.
    pub async fn wait_from(&self, user: AccountId, wait: i64) -> Result<Option<i64>> {
        let row: Option<(Option<i64>, i64, Option<i64>)> = db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT CAST(joined_at AS BIGINT), CAST(imported_at AS BIGINT), CAST(claimed_at AS BIGINT)
                 FROM voipc_placeholders WHERE account = $1",
            )
            .bind(&user.0[..])
            .fetch_optional(pool)
            .await?
        });
        Ok(row.map(|(joined, imported, claimed)| {
            wait_start(joined, imported, claimed.unwrap_or_else(util::now), wait)
        }))
    }

    async fn ledger(&self, guild: i64) -> Result<Ledger> {
        let rows: Vec<GroupRow> = db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT g.role, CAST(g.dc_role_id AS BIGINT), g.power FROM voipc_import_groups g
                 JOIN voipc_imports i ON i.id = g.import_id WHERE i.guild_id = $1",
            )
            .bind(guild)
            .fetch_all(pool)
            .await?
        });
        let mut ledger = Ledger::default();
        for (role, dc_role, power) in rows {
            let Some(role) = account_of(&role) else {
                continue;
            };
            let map = if power {
                &mut ledger.twin
            } else {
                &mut ledger.plain
            };
            map.insert(dc_role as u64, role);
            ledger.of.insert(role, (dc_role as u64, power));
        }
        Ok(ledger)
    }

    /// The group a Discord role made that holds no privileges, by name: all a gate can name
    /// from an import, so that no client can name a group, and no gate lets power through.
    pub(crate) async fn zero_group_of(&self, dc_role: u64) -> Result<Option<String>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT r.name FROM voipc_import_groups g JOIN acct_roles r ON r.id = g.role
                 WHERE g.dc_role_id = $1 AND g.power = $2",
            )
            .bind(dc_role as i64)
            .bind(false)
            .fetch_optional(pool)
            .await?
        }))
    }

    /// Whether the groups' list would still fit one frame with `group` saved: past that the
    /// panel silently stops getting it, and nobody could see what to shorten.
    pub(super) async fn group_save_fits(&self, create: bool, group: &GroupInfo) -> Result<bool> {
        let mut groups: Vec<GroupInfo> = self
            .groups_in_order()
            .await?
            .iter()
            .map(|(r, _)| info_of(r))
            .collect();
        match groups.iter_mut().find(|g| g.name == group.name.trim()) {
            Some(held) if !create => {
                held.description = group.description.clone();
                held.badge = group.badge.clone();
                held.scopes = group.scopes.clone();
            }
            _ => groups.push(group.clone()),
        }
        Ok(roles_fit(&groups))
    }

    /// A group a run made and then stopped before its ledger row: `name`, just as `form`
    /// makes it, in no run's ledger and holding nobody. The next run takes it up, where it
    /// made `<name>-<tail>` beside it and the first stayed for good (W2-24). One made by hand
    /// differs in its description, its badge, its privileges or its people.
    async fn stopped_group(&self, name: &str, form: &RoleForm<'_>) -> Result<Option<AccountId>> {
        let Some(role) = self.store().role_by_name(name).await? else {
            return Ok(None);
        };
        let mut scopes = form.scopes.to_vec();
        scopes.sort();
        scopes.dedup();
        if role.builtin
            || role.description != form.description
            || role.badge.as_deref().unwrap_or("") != form.badge
            || role.scopes != scopes
        {
            return Ok(None);
        }
        let ledgered: i64 = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_import_groups WHERE role = $1")
                .bind(&role.id.0[..])
                .fetch_one(pool)
                .await?
        });
        if ledgered > 0 {
            return Ok(None);
        }
        let (_, people) = self.store().role_members(role.id, 1, 0).await?;
        Ok((people == 0).then_some(role.id))
    }

    async fn ledger_put(&self, role: AccountId, dc_role: u64, power: bool, run: i64) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_import_groups (role, dc_role_id, power, import_id)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(&role.0[..])
            .bind(dc_role as i64)
            .bind(power)
            .bind(run)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// A group an undo kept is this run's once it takes it up: a delete from then on is kept
    /// under a run that stands, and the group goes with this run's undo.
    async fn ledger_take_up(&self, dc_role: u64, run: i64) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "UPDATE voipc_import_groups SET import_id = $1 WHERE dc_role_id = $2
                 AND import_id IN (SELECT id FROM voipc_imports WHERE undone_at IS NOT NULL)",
            )
            .bind(run)
            .bind(dc_role as i64)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    async fn waiting_put(&self, account: AccountId, role: AccountId) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_power_waiting (account, role) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(&account.0[..])
            .bind(&role.0[..])
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    async fn waiting_roles(&self, account: AccountId) -> Result<Vec<AccountId>> {
        let rows: Vec<Vec<u8>> = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT role FROM voipc_power_waiting WHERE account = $1")
                .bind(&account.0[..])
                .fetch_all(pool)
                .await?
        });
        Ok(rows.iter().filter_map(|r| account_of(r)).collect())
    }

    pub(super) async fn waiting_drop(&self, account: AccountId, role: AccountId) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("DELETE FROM voipc_power_waiting WHERE account = $1 AND role = $2")
                .bind(&account.0[..])
                .bind(&role.0[..])
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// The role and the person's name, if `group` waits for this account's OK.
    pub(super) async fn waiting_row(
        &self,
        account: AccountId,
        group: &str,
    ) -> Result<Option<(AccountId, String)>> {
        let row: Option<(Vec<u8>, String)> = db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT w.role, u.username FROM voipc_power_waiting w
                 JOIN acct_roles r ON r.id = w.role
                 JOIN acct_users u ON u.id = w.account
                 WHERE w.account = $1 AND r.name = $2",
            )
            .bind(&account.0[..])
            .bind(group.trim())
            .fetch_optional(pool)
            .await?
        });
        Ok(row.and_then(|(role, name)| Some((account_of(&role)?, name))))
    }

    /// Every group with privileges an account of the move's holds goes to waiting: whoever
    /// opens it may be anyone. An account the move does not know keeps its groups. By its
    /// scopes, not `holds_power`, which skips reports, the log and mentioning everyone; a group
    /// holding only Share history gives nothing over anyone, and gates may name it. `user`
    /// stays, since it goes to every account, moved or not. `Err`, in words for whoever can act
    /// on them: it holds the last `*`, and nothing changed.
    pub(super) async fn hold_power(&self, id: AccountId) -> Result<()> {
        if self.placeholder_dc_id(id).await?.is_none() {
            return Ok(());
        }
        let mut held: Vec<Role> = self.store().user_roles(id).await?;
        held.retain(|r| !super::no_power_over_anyone(&r.scopes) && r.name != "user");
        // `*` first: a last-admin refusal then comes before anything has changed
        held.sort_by_key(|r| !super::is_star(&r.scopes));
        for role in held {
            // Revoked first: a crash loses a hold, and never leaves power on
            match self.store().revoke_role(id, role.id).await {
                Ok(_) => {}
                Err(WriteError::LastAdmin) => {
                    return Err(anyhow!(
                        "{} holds the last admin group here: give it to another account first.",
                        role.name
                    ));
                }
                Err(e) => return Err(anyhow!("taking back a held-back group: {e:?}")),
            }
            self.waiting_put(id, role.id).await?;
            self.store()
                .audit(
                    Some(id),
                    None,
                    "role_revoke",
                    &format!("{}: waits for an admin's OK", role.name),
                    "",
                )
                .await?;
        }
        Ok(())
    }

    /// Back to waiting, for an account of the move's that `admin reclaim` wipes. Someone
    /// else may hold that Discord login next, and what the owner said OK to was for the
    /// person before.
    pub(super) async fn power_back_to_waiting(&self, id: AccountId) -> Result<()> {
        self.hold_power(id).await?;
        // The next to open it may be someone else: tenure does not carry over
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_placeholders SET joined_at = NULL WHERE account = $1")
                .bind(&id.0[..])
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// `slot.recovery` and `item.identity` for an account with no vault to hand out,
    /// shaped like the real thing and the same at every ask and after a restart, so that
    /// `Reset` does not say whether anyone has opened it. Whatever key is tried, the
    /// client reads a wrong one, as with a real account.
    pub(super) fn decoy_blobs(&self, user: AccountId) -> Vec<VaultBlob> {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.placeholder_key);
        let bytes = |label: &str, n: usize| {
            let mut out = Vec::with_capacity(n + 32);
            let mut block = 0u8;
            while out.len() < n {
                let mut ctx = ring::hmac::Context::with_key(&key);
                ctx.update(&user.0);
                ctx.update(label.as_bytes());
                ctx.update(&[block]);
                out.extend_from_slice(ctx.sign().as_ref());
                block += 1;
            }
            out.truncate(n);
            out
        };
        // The same data key's id in both, as a real vault has it
        let dek_id = bytes("dek", 8);
        let mut item = vec![0x02];
        item.extend_from_slice(&dek_id);
        item.extend_from_slice(&bytes("item", ITEM_IDENTITY_LEN - item.len()));
        let mut slot = vec![0x01];
        slot.extend_from_slice(&bytes("salt", 32));
        slot.extend_from_slice(&dek_id);
        slot.extend_from_slice(&bytes("slot", SLOT_LEN - slot.len()));
        [("item.identity", item), ("slot.recovery", slot)]
            .into_iter()
            .map(|(k, v)| VaultBlob {
                k: k.into(),
                v,
                version: 1,
            })
            .collect()
    }

    /// The accounts past `imported_at <= before`. The clock is the first import's: a
    /// delta does not restart it.
    async fn unclaimed_past(&self, before: i64) -> Result<Vec<AccountId>> {
        let rows: Vec<Vec<u8>> = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT p.account FROM voipc_placeholders p
                 WHERE p.banned = $1 AND p.claimed_at IS NULL AND p.imported_at <= $2
                   AND NOT EXISTS (SELECT 1 FROM voipc_identity i WHERE i.account = p.account)
                   AND NOT EXISTS (SELECT 1 FROM voipc_bans b WHERE b.account = p.account)
                 ORDER BY p.imported_at LIMIT $3",
            )
            .bind(false)
            .bind(before)
            .bind(SWEEP_BATCH as i64)
            .fetch_all(pool)
            .await?
        });
        Ok(rows.iter().filter_map(|r| account_of(r)).collect())
    }
}

/// The names of the plain groups the move made, which do not lift the new-member wait:
/// Discord's autorole bots give one to every joiner, where a group given here took a
/// person choosing. Read at the open, and after anything that changes them.
pub async fn load(relay: &Relay) -> Result<()> {
    let names: Vec<String> = db!(relay.store(), pool => {
        sqlx::query_scalar(
            "SELECT r.name FROM voipc_import_groups g JOIN acct_roles r ON r.id = g.role WHERE g.power = $1",
        )
        .bind(false)
        .fetch_all(pool)
        .await?
    });
    let keep: HashSet<&str> = names.iter().map(String::as_str).collect();
    relay
        .imported_groups
        .retain(|name, _| keep.contains(name.as_str()));
    for name in &names {
        relay.imported_groups.insert(name.clone(), ());
    }
    Ok(())
}

/// Hourly: accounts nobody opened in `unclaimed_days`. 0 is never, so a mistyped 0 cannot
/// wipe an import. A row in the log for each batch, before it. No exclusion comes of it:
/// this is no request to be left out, and the next import makes them again.
pub async fn sweep(relay: &Relay) -> Result<u64> {
    if relay.unclaimed_days == 0 {
        return Ok(0);
    }
    let days = i64::from(relay.unclaimed_days);
    let before = util::now().saturating_sub(days.saturating_mul(86_400));
    let mut gone = 0;
    loop {
        let batch = relay.unclaimed_past(before).await?;
        if batch.is_empty() {
            return Ok(gone);
        }
        let plural = if batch.len() == 1 { "" } else { "s" };
        let detail = format!(
            "{} account{plural} nobody opened in {days} days",
            batch.len()
        );
        relay
            .modlog_put(&Entry {
                action: "unclaimed_expired",
                actor_name: "server",
                detail: &detail,
                ..Default::default()
            })
            .await?;
        let mut dropped = 0;
        for id in &batch {
            if relay.drop_unclaimed(*id).await? {
                dropped += 1;
            }
        }
        gone += dropped;
        // None went: each was taken meanwhile, and the next pass finds them gone from the list
        if dropped == 0 || batch.len() < SWEEP_BATCH {
            return Ok(gone);
        }
    }
}

/// `AdminOp::ImportRoles`, past `import::frame`. Each role is a plain group and, when it
/// could do anything, a twin. A delta moves badge, colour and order; the name stays, since
/// gates name groups by it. It never touches what a twin holds, and says if that differs.
pub(super) async fn roles(
    relay: &Relay,
    ctx: &Ctx,
    actor: Actor<'_>,
    run: i64,
    guild: i64,
    mut rows: Vec<ImportRole>,
) -> Result<AdminReply> {
    // The top ones first: what does not fit is the bottom of the list
    rows.sort_by_key(|r| std::cmp::Reverse(r.position));
    let ledger = relay.ledger(guild).await?;
    let in_order = relay.groups_in_order().await?;
    let mut groups: Vec<GroupInfo> = in_order.iter().map(|(r, _)| info_of(r)).collect();
    // A group with no place sorts after every group with one, so whoever has none gets
    // it first: the built-in groups stay on top
    let ours: HashSet<[u8; 16]> = ledger
        .plain
        .values()
        .chain(ledger.twin.values())
        .map(|r| r.0)
        .collect();
    let mut after = 0i64;
    for (role, _) in &in_order {
        if !ours.contains(&role.id.0) {
            relay.group_position_put(role.id, after).await?;
            after += 1;
        }
    }
    let held: HashMap<[u8; 16], Role> = in_order.into_iter().map(|(r, _)| (r.id.0, r)).collect();
    let deleted = relay.import_items(import::KIND_GROUP_DELETED).await?;
    let twin_deleted = relay.import_items(import::KIND_TWIN_DELETED).await?;
    let (mut made, mut updated) = (0u32, 0u32);
    let (mut skipped, mut power_changed) = (Vec::new(), Vec::new());
    for r in &rows {
        let said = clip(&r.name, 32);
        if r.dc_id == guild as u64 || !id_ok(r.dc_id) || deleted.contains_key(&(r.dc_id as i64)) {
            skipped.push(said);
            continue;
        }
        relay.ledger_take_up(r.dc_id, run).await?;
        let badge = badge_of(&r.name);
        let color = (r.color != 0).then_some(r.color);
        // In Discord's order, below all that was here
        let position = after + i64::from(u16::MAX) - i64::from(r.position.min(u32::from(u16::MAX)));
        let existing = ledger.plain.get(&r.dc_id).and_then(|id| held.get(&id.0));
        let (plain, name) = match existing {
            Some(role) => {
                if role.badge != badge {
                    relay
                        .store()
                        .update_role(role.id, &role.description, badge.as_deref())
                        .await?;
                }
                updated += 1;
                (role.id, role.name.clone())
            }
            None => {
                let form = RoleForm {
                    name: "",
                    description: "From Discord",
                    badge: badge.as_deref().unwrap_or(""),
                    scopes: &[],
                };
                let names = group_names(&group_base(&r.name, r.dc_id), r.dc_id);
                let Some((id, name)) =
                    make_group(relay, ctx, actor, form, &names, &mut groups).await?
                else {
                    skipped.push(said);
                    continue;
                };
                relay.ledger_put(id, r.dc_id, false, run).await?;
                made += 1;
                (id, name)
            }
        };
        relay.group_style_put(plain, color, r.hoist).await?;
        relay.group_position_put(plain, position).await?;

        let scopes: Vec<String> = discord::scopes_of(r.permissions)
            .into_iter()
            .map(String::from)
            .collect();
        match ledger.twin.get(&r.dc_id).and_then(|id| held.get(&id.0)) {
            Some(twin) => {
                // Discord never says Share history: an admin added it, and it is no change
                if super::without_share(&twin.scopes) != scopes {
                    power_changed.push(twin.name.clone());
                }
            }
            None if scopes.is_empty() => {}
            None if twin_deleted.contains_key(&(r.dc_id as i64)) => skipped.push(said),
            None => {
                let shown = badge.as_deref().unwrap_or("role");
                let description =
                    format!("Held back for the owner's OK: what Discord's {shown} could do");
                let form = RoleForm {
                    name: "",
                    description: &description,
                    badge: "",
                    scopes: &scopes,
                };
                let names = twin_names(&name, r.dc_id);
                match make_group(relay, ctx, actor, form, &names, &mut groups).await? {
                    Some((id, _)) => {
                        relay.ledger_put(id, r.dc_id, true, run).await?;
                        // No section: a row shows the plain group
                        relay.group_style_put(id, None, false).await?;
                        made += 1;
                    }
                    None => skipped.push(said),
                }
            }
        }
    }
    load(relay).await?;
    Ok(AdminReply::ImportRolesDone {
        made,
        updated,
        skipped,
        power_changed,
    })
}

/// The first of `names` not taken, as long as the groups' list still fits one frame.
/// `None`: the role is left out, and the owner told. A gate naming it loses those people:
/// narrower, never wider.
async fn make_group(
    relay: &Relay,
    ctx: &Ctx,
    actor: Actor<'_>,
    form: RoleForm<'_>,
    names: &[String],
    groups: &mut Vec<GroupInfo>,
) -> Result<Option<(AccountId, String)>> {
    for name in names {
        let info = GroupInfo {
            name: name.clone(),
            description: form.description.to_string(),
            badge: form.badge.to_string(),
            scopes: form.scopes.to_vec(),
            builtin: false,
        };
        groups.push(info);
        if !roles_fit(groups) {
            groups.pop();
            return Ok(None);
        }
        let this = RoleForm { name, ..form };
        match relay.accounts.create_role(ctx, actor, this).await {
            Ok(id) => return Ok(Some((id, name.clone()))),
            Err(Error::RoleTaken) => {
                groups.pop();
                if let Some(id) = relay
                    .stopped_group(name, &RoleForm { name, ..form })
                    .await?
                {
                    return Ok(Some((id, name.clone())));
                }
            }
            Err(e) => {
                groups.pop();
                return Err(anyhow!("making a group from a role: {}", e.message()));
            }
        }
    }
    Ok(None)
}

/// `AdminOp::ImportMembers`, past `import::frame`.
pub(super) async fn members(
    relay: &Relay,
    by: AccountId,
    run: i64,
    guild: i64,
    rows: &[ImportMember],
) -> Result<AdminReply> {
    let kind = Kind::Discord.credential_kind();
    let mut ledger = relay.ledger(guild).await?;
    // Members only ever get a group holding nothing over anyone. One that has come to hold
    // more, past `AdminOp::GroupSave`'s refusal, is for the owner to give
    let no_power: HashSet<[u8; 16]> = relay
        .store()
        .roles()
        .await?
        .into_iter()
        .filter(|r| super::no_power_over_anyone(&r.scopes))
        .map(|r| r.id.0)
        .collect();
    ledger.plain.retain(|_, role| no_power.contains(&role.0));
    let (mut made, mut updated, mut left_out) = (0u32, 0u32, 0u32);
    let (mut nicknames_dropped, mut unlinked, mut kept_power) = (0u32, 0u32, 0u32);
    let mut failed = Vec::new();
    for m in rows {
        let said = || clip(&m.username, 32);
        let dc = m.dc_id as i64;
        if relay.excluded_own(dc).await?.is_some() {
            left_out += 1;
            continue;
        }
        let joined = (m.joined_at != 0).then_some(m.joined_at);
        let ext_id = m.dc_id.to_string();
        let mut cred = relay.store().credential(&kind, ext_id.as_bytes()).await?;
        let mut row = relay.place_of(dc).await?;
        if cred.is_none() && row.is_none() {
            match relay
                .make_account(m.dc_id, &m.username, joined, run, false)
                .await?
            {
                Made::Account => made += 1,
                Made::NoName => {
                    failed.push(said());
                    continue;
                }
                // Theirs now: as someone who had linked it already
                Made::Lost => {}
                Made::Opened(_) => {
                    unlinked += 1;
                    continue;
                }
            }
            cred = relay.store().credential(&kind, ext_id.as_bytes()).await?;
            row = relay.place_of(dc).await?;
        } else {
            updated += 1;
        }
        let account = match (cred, row) {
            // Theirs may differ from the row only if someone unlinked and linked again
            (Some(c), Some((account, banned, claimed_at))) => {
                if banned {
                    failed.push(said());
                    continue;
                }
                let open = claimed_at.is_none() && account_of(&account) == Some(c.user_id);
                Some((c.user_id, open))
            }
            // An account here had linked it already: that counts as opened, and keeps its name
            (Some(c), None) => {
                let user = relay.store().user_by_id(c.user_id).await?;
                let Some(user) = user.filter(|u| u.status == UserStatus::Active) else {
                    failed.push(said());
                    continue;
                };
                relay
                    .place_put(
                        c.user_id,
                        dc,
                        run,
                        false,
                        joined,
                        util::now(),
                        Some(user.created_at),
                    )
                    .await?;
                Some((c.user_id, false))
            }
            // They took it off on purpose: never linked again
            (None, Some((_, _, Some(_)))) => {
                unlinked += 1;
                None
            }
            // A run that died between the row and the credential
            (None, Some((account, banned, None))) => {
                let Some(id) = account_of(&account) else {
                    failed.push(said());
                    continue;
                };
                if !relay.discord_link(id, m.dc_id, &m.username).await? {
                    failed.push(said());
                    continue;
                }
                (!banned).then_some((id, true))
            }
            (None, None) => {
                failed.push(said());
                None
            }
        };
        let Some((account, open)) = account else {
            continue;
        };
        if open {
            db!(relay.store(), pool => {
                sqlx::query("UPDATE voipc_placeholders SET joined_at = $1 WHERE account = $2")
                    .bind(joined)
                    .bind(&account.0[..])
                    .execute(pool)
                    .await?;
            });
            let Some(user) = relay.store().user_by_id(account).await? else {
                continue;
            };
            match relay.display_name_ok(&user, &m.shown_as).await {
                Ok(name) => relay.profile_name_put(account, name.as_deref()).await?,
                Err(_) => nicknames_dropped += 1,
            }
        }
        kept_power += groups_of(relay, &ledger, by, account, &m.roles).await?;
    }
    Ok(AdminReply::ImportMembersDone {
        made,
        updated,
        left_out,
        nicknames_dropped,
        unlinked,
        kept_power,
        failed,
    })
}

/// Plain groups follow Discord both ways, for what this guild made: gates must. A twin
/// waits for the owner. One they hold already stays, whatever Discord says now: a hijacked
/// Discord admin stripping roles before a routine delta must not demote every moderator.
/// Returns how many they kept that way.
async fn groups_of(
    relay: &Relay,
    ledger: &Ledger,
    by: AccountId,
    account: AccountId,
    discord_roles: &[u64],
) -> Result<u32> {
    let holds: HashSet<u64> = discord_roles.iter().copied().collect();
    let now = relay.store().user_roles(account).await?;
    let held: HashSet<[u8; 16]> = now.iter().map(|r| r.id.0).collect();
    for dc_role in &holds {
        if let Some(plain) = ledger.plain.get(dc_role) {
            if !held.contains(&plain.0) {
                relay.store().grant_role(account, *plain, Some(by)).await?;
            }
        }
        if let Some(twin) = ledger.twin.get(dc_role) {
            if !held.contains(&twin.0) {
                relay.waiting_put(account, *twin).await?;
            }
        }
    }
    let mut kept = 0;
    for role in &now {
        match ledger.of.get(&role.id).copied() {
            Some((dc_role, false)) if !holds.contains(&dc_role) => {
                relay
                    .store()
                    .revoke_role(account, role.id)
                    .await
                    .map_err(|e| anyhow!("taking a plain group away: {e:?}"))?;
            }
            Some((dc_role, true)) if !holds.contains(&dc_role) => kept += 1,
            _ => {}
        }
    }
    for role in relay.waiting_roles(account).await? {
        if matches!(ledger.of.get(&role), Some((dc_role, true)) if !holds.contains(dc_role)) {
            relay.waiting_drop(account, role).await?;
        }
    }
    Ok(kept)
}

/// `AdminOp::ImportBans`, past `import::frame`. An import never acts on someone who has
/// opened an account: those are named, and the owner bans by name if they mean it. A
/// lifted ban stays lifted, since a lift leaves the id on the excluded list; someone's own
/// exclusion (they deleted their account) does not stop a ban, until one was lifted for them
/// (`lifted`, W1-31).
pub(super) async fn bans(
    relay: &Relay,
    ctx: &Ctx,
    run: i64,
    rows: &[ImportBan],
) -> Result<AdminReply> {
    let kind = Kind::Discord.credential_kind();
    let (mut made, mut converted) = (0u32, 0u32);
    let (mut claimed, mut names_kept) = (Vec::new(), Vec::new());
    for b in rows {
        let dc = b.dc_id as i64;
        if relay.ban_lifted(dc).await? {
            continue;
        }
        let ext_id = b.dc_id.to_string();
        let cred = relay.store().credential(&kind, ext_id.as_bytes()).await?;
        let place = relay.place_of(dc).await?;
        let handle = format!("dc-{}", b.dc_id);
        match (cred, place) {
            (None, None) => {
                match relay
                    .make_account(b.dc_id, &handle, None, run, true)
                    .await?
                {
                    Made::Account => made += 1,
                    Made::NoName | Made::Lost => claimed.push(handle),
                    Made::Opened(name) => claimed.push(name),
                }
            }
            (cred, Some((account, banned, None))) => {
                let Some(id) = account_of(&account) else {
                    continue;
                };
                // `claim` waits for this: a vault is bound to the name it was made under
                let _one = relay.claiming.lock().await;
                if !banned {
                    // Opened this instant: left alone, and the next run names them
                    if relay.identity(id).await?.is_some() {
                        continue;
                    }
                    relay
                        .store()
                        .set_status(id, UserStatus::Disabled)
                        .await
                        .map_err(|e| anyhow!("disabling a banned account: {e:?}"))?;
                    db!(relay.store(), pool => {
                        // This run's now, so that undoing it undoes this too
                        sqlx::query("UPDATE voipc_placeholders SET banned = $1, import_id = $2 WHERE account = $3")
                            .bind(true)
                            .bind(run)
                            .bind(&id.0[..])
                            .execute(pool)
                            .await?;
                        sqlx::query("DELETE FROM voipc_power_waiting WHERE account = $1")
                            .bind(&id.0[..])
                            .execute(pool)
                            .await?;
                    });
                    converted += 1;
                }
                // The name after the mark, and again on a later run while it is not yet a
                // banned one's: stopped in between, a run left the real name squatted on a
                // banned row, which the mark then skipped (W2-23)
                let user = relay.store().user_by_id(id).await?;
                let names = relay.banned_names(b.dc_id);
                if !user.as_ref().is_some_and(|u| names.contains(&u.username)) {
                    relay.profile_name_put(id, None).await?;
                    if !relay.banned_rename(ctx, id, b.dc_id).await? {
                        names_kept.extend(user.map(|u| u.username));
                    }
                }
                if cred.is_none() {
                    relay.discord_link(id, b.dc_id, &handle).await?;
                }
            }
            (cred, place) => {
                let id = cred
                    .map(|c| c.user_id)
                    .or_else(|| place.and_then(|(account, _, _)| account_of(&account)));
                let name = match id {
                    Some(id) => relay.store().user_by_id(id).await?.map(|u| u.username),
                    None => None,
                };
                claimed.push(name.unwrap_or(handle));
            }
        }
    }
    Ok(AdminReply::ImportBansDone {
        made,
        converted,
        claimed,
        names_kept,
    })
}

/// Why a name of the move's shape is refused, to anyone, whoever holds one.
pub(crate) const KEPT_FOR_THE_MOVE: &str =
    "Names like dc-<number> are kept for accounts moved from Discord: pick another.";

/// `dc-` and a digit: the move's own names (`names_for`, `banned_names`). Nobody else takes
/// one, as a guest, at sign-up or as a display name, whether or not such an account exists:
/// an answer that turned on that would tell anyone who knows a Discord id that it was banned
/// there (W1-30). A look-alike in another script is checked by its ASCII spelling.
pub(crate) fn kept_for_the_move(name: &str) -> bool {
    let name = name.trim().as_bytes();
    name.len() > 3 && name[..3].eq_ignore_ascii_case(b"dc-") && name[3].is_ascii_digit()
}

/// What refuses `AdminOp::MoveExclude`, ahead of its code. Someone who opened their account
/// can delete it themselves, and someone who did that stays out: nobody may let them back. A
/// ban by name here holds the account, name and Discord id with it, which leaving out would
/// then keep while saying done (W1-32): the ban is lifted first, on purpose.
pub(super) async fn exclude_refusal(
    relay: &Relay,
    dc_id: i64,
    on: bool,
) -> Result<Option<&'static str>> {
    if on {
        let place = relay.place_of(dc_id).await?;
        if matches!(place, Some((_, _, Some(_)))) {
            return Ok(Some(
                "They have opened their account: they can delete it themselves.",
            ));
        }
        if let Some((account, _, None)) = place {
            let banned: Option<i64> = db!(relay.store(), pool => {
                sqlx::query_scalar("SELECT id FROM voipc_bans WHERE account = $1")
                    .bind(&account)
                    .fetch_optional(pool)
                    .await?
            });
            if banned.is_some() {
                return Ok(Some(
                    "They are banned here by name, and the ban holds their account. Lift it under Bans first, then leave them out.",
                ));
            }
        }
    } else if relay.excluded_own(dc_id).await? == Some(true) {
        return Ok(Some(
            "They deleted their account themselves: nobody can let them back in.",
        ));
    }
    Ok(None)
}

/// `AdminOp::MoveExclude`, past its code. The log's row first, naming nobody: it outlives the
/// person, and the point of being left out is not being named. Holding (`erase` off) makes no
/// account and leaves their posts; leaving out takes those for good. Letting someone back in
/// after that leaves it so, by a wish up to now: their new posts come, the old ones never.
pub(super) async fn exclude(
    state: &ServerState,
    relay: &Relay,
    session_id: SessionId,
    dc_id: i64,
    on: bool,
    erase: bool,
) -> Result<AccountReply> {
    let held = db!(relay.store(), pool => {
        sqlx::query_scalar::<_, bool>("SELECT erase FROM voipc_import_excluded WHERE dc_id = $1")
            .bind(dc_id)
            .fetch_optional(pool)
            .await?
    });
    if !on && held.is_none() {
        return excluded_page(relay, 0).await;
    }
    let row = Entry {
        action: if on {
            "import_exclude"
        } else {
            "import_include"
        },
        detail: "one member",
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, session_id, row).await {
        warn!("keeping someone's leaving out: {e:#}");
        return Ok(refused("Admin", "That could not be kept."));
    }
    let now = util::now();
    db!(relay.store(), pool => {
        let mut tx = pool.begin().await?;
        if on {
            sqlx::query(
                // On someone who deleted their own account, holding is all a lift can be: it
                // stays lifted (W1-31)
                "INSERT INTO voipc_import_excluded (dc_id, own, erase, at) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (dc_id) DO UPDATE SET erase = voipc_import_excluded.erase OR excluded.erase,
                   lifted = voipc_import_excluded.lifted
                     OR (voipc_import_excluded.own AND NOT excluded.erase)",
            )
            .bind(dc_id)
            .bind(false)
            .bind(erase)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("DELETE FROM voipc_import_excluded WHERE dc_id = $1")
                .bind(dc_id)
                .execute(&mut *tx)
                .await?;
            if held == Some(true) {
                sqlx::query(archive::WISH_UP)
                    .bind(dc_id)
                    .bind(0i64)
                    .bind(0i64)
                    .bind(discord::snowflake_floor(log::now_ms()))
                    .bind(true)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
    });
    if on {
        if let Some(id) = relay
            .place_of(dc_id)
            .await?
            .and_then(|(account, _, _)| account_of(&account))
        {
            relay.drop_unclaimed(id).await?;
        }
    }
    relay.archive_changed().await?;
    excluded_page(relay, 0).await
}

/// `AdminOp::MoveExcluded`: by id, past `after`.
pub(super) async fn excluded_page(relay: &Relay, after: i64) -> Result<AccountReply> {
    let mut rows: Vec<(i64, bool, bool, i64)> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT CAST(dc_id AS BIGINT), own, erase, CAST(at AS BIGINT) FROM voipc_import_excluded
             WHERE dc_id > $1 ORDER BY dc_id LIMIT $2",
        )
        .bind(after)
        .bind(EXCLUDED_PAGE + 1)
        .fetch_all(pool)
        .await?
    });
    let more = rows.len() as i64 > EXCLUDED_PAGE;
    rows.truncate(EXCLUDED_PAGE as usize);
    Ok(AccountReply::Admin(AdminReply::MoveExcluded {
        ids: rows
            .into_iter()
            .map(|(id, own, erase, at)| (id.to_string(), own, erase, at))
            .collect(),
        more,
    }))
}

/// `%`, `_` and the escape itself are plain characters in a search box.
fn like_pattern(search: &str) -> String {
    let mut pattern = String::from("%");
    for c in search.trim().to_lowercase().chars() {
        if matches!(c, '!' | '%' | '_') {
            pattern.push('!');
        }
        pattern.push(c);
    }
    pattern.push('%');
    pattern
}

/// A page of one of `accounts_query!`'s pairs of statements, with the total.
async fn account_rows(
    relay: &Relay,
    (select, count): (&'static str, &'static str),
    search: &str,
    offset: u32,
) -> Result<(Vec<AccountRow>, i64)> {
    let like = like_pattern(search);
    Ok(db!(relay.store(), pool => {
        (
            sqlx::query_as(select)
                .bind(&like)
                .bind(ACCOUNTS_PAGE)
                .bind(i64::from(offset))
                .fetch_all(pool)
                .await?,
            sqlx::query_scalar(count).bind(&like).fetch_one(pool).await?,
        )
    }))
}

/// `AdminOp::MoveAccounts`: a Discord id goes only to `star`, and so does who was banned there,
/// by the mark and never by the name. `AdminUser` and its op stay as they are, which would need
/// a row for every older protocol.
pub(super) async fn move_accounts(
    relay: &Relay,
    star: bool,
    search: String,
    offset: u32,
    filter: MoveFilter,
) -> Result<AccountReply> {
    let statements = match (filter, star) {
        (MoveFilter::Banned, false) => {
            return Ok(refused(
                "Admin",
                "Only an admin may see who was banned on Discord.",
            ));
        }
        (MoveFilter::All, true) => accounts_query!(""),
        (MoveFilter::All, false) => accounts_query!("AND (p.banned IS NULL OR p.banned = FALSE)"),
        (MoveFilter::Waiting, _) => {
            accounts_query!("AND p.claimed_at IS NULL AND p.banned = FALSE")
        }
        (MoveFilter::Claimed, _) => accounts_query!("AND p.claimed_at IS NOT NULL"),
        (MoveFilter::Banned, true) => accounts_query!("AND p.banned = TRUE"),
    };
    let (rows, total) = account_rows(relay, statements, &search, offset).await?;
    let wait = i64::from(relay.unclaimed_days).saturating_mul(86_400);
    let rows = rows
        .into_iter()
        .filter_map(
            |(id, name, totp, created_at, dc_id, banned, claimed, imported)| {
                let state = match (dc_id, banned, claimed) {
                    (None, _, _) => MoveState::NotImported,
                    (_, Some(true), _) => MoveState::Banned,
                    (_, _, Some(_)) => MoveState::Claimed,
                    _ => MoveState::Waiting,
                };
                let expires_at = match (state, imported) {
                    (MoveState::Waiting, Some(at)) if wait > 0 => at.saturating_add(wait),
                    _ => 0,
                };
                Some(MoveAccount {
                    user: AdminUser {
                        id: account_of(&id)?.0,
                        name,
                        totp,
                        created_at,
                    },
                    state,
                    dc_id: dc_id
                        .filter(|_| star)
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                    expires_at,
                })
            },
        )
        .collect();
    Ok(AccountReply::Admin(AdminReply::MoveAccounts {
        search,
        offset,
        filter,
        total: total.clamp(0, i64::from(u32::MAX)) as u32,
        rows,
    }))
}

/// `AdminOp::Users` past `*`: the list less those banned on Discord. What is typed looks at the
/// name only, as `move_accounts` does: this app asks that op, and only an older one asks this.
pub(super) async fn users_page(relay: &Relay, search: String, offset: u32) -> Result<AccountReply> {
    let statements = accounts_query!("AND (p.banned IS NULL OR p.banned = FALSE)");
    let (rows, total) = account_rows(relay, statements, &search, offset).await?;
    Ok(AccountReply::Admin(AdminReply::Users {
        search,
        offset,
        total: total.clamp(0, i64::from(u32::MAX)) as u32,
        users: rows
            .into_iter()
            .filter_map(|(id, name, totp, created_at, ..)| {
                Some(AdminUser {
                    id: account_of(&id)?.0,
                    name,
                    totp,
                    created_at,
                })
            })
            .collect(),
    }))
}

/// `AdminOp::GroupMembers` past `*`: a banned row holds `user` and keeps its plain groups.
/// l4f has said the group exists and that this may be read.
pub(super) async fn members_not_banned(
    relay: &Relay,
    group: &str,
    offset: u32,
) -> Result<(Vec<AdminUser>, i64)> {
    let group = group.trim().to_ascii_lowercase();
    let Some(role) = relay.store().role_by_name(&group).await? else {
        return Ok((Vec::new(), 0));
    };
    type MemberRow = (Vec<u8>, String, bool, i64);
    let (rows, total): (Vec<MemberRow>, i64) = db!(relay.store(), pool => {
        (
            sqlx::query_as(
                "SELECT u.id, u.username, u.totp_enc IS NOT NULL, CAST(u.created_at AS BIGINT)
                 FROM acct_users u
                 JOIN acct_user_roles ur ON ur.user_id = u.id
                 LEFT JOIN voipc_placeholders p ON p.account = u.id
                 WHERE ur.role_id = $1 AND (p.banned IS NULL OR p.banned = FALSE)
                 ORDER BY u.username LIMIT $2 OFFSET $3",
            )
            .bind(&role.id.0[..])
            .bind(ACCOUNTS_PAGE)
            .bind(i64::from(offset))
            .fetch_all(pool)
            .await?,
            sqlx::query_scalar(
                "SELECT CAST(COUNT(*) AS BIGINT)
                 FROM acct_user_roles ur
                 LEFT JOIN voipc_placeholders p ON p.account = ur.user_id
                 WHERE ur.role_id = $1 AND (p.banned IS NULL OR p.banned = FALSE)",
            )
            .bind(&role.id.0[..])
            .fetch_one(pool)
            .await?,
        )
    });
    let users = rows
        .into_iter()
        .filter_map(|(id, name, totp, created_at)| {
            Some(AdminUser {
                id: account_of(&id)?.0,
                name,
                totp,
                created_at,
            })
        })
        .collect();
    Ok((users, total))
}

/// `AdminOp::MoveStatus`: what the dashboard shows, the newest runs first.
pub(super) async fn move_status(relay: &Relay) -> Result<AccountReply> {
    let ((claimed, waiting, banned), power_waiting, excluded, runs): (
        (i64, i64, i64),
        i64,
        i64,
        Vec<RunRow>,
    ) = db!(relay.store(), pool => {
        (
            sqlx::query_as(
                "SELECT CAST(COALESCE(SUM(CASE WHEN claimed_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS BIGINT),
                        CAST(COALESCE(SUM(CASE WHEN claimed_at IS NULL AND banned = FALSE THEN 1 ELSE 0 END), 0) AS BIGINT),
                        CAST(COALESCE(SUM(CASE WHEN claimed_at IS NULL AND banned = TRUE THEN 1 ELSE 0 END), 0) AS BIGINT)
                 FROM voipc_placeholders",
            )
            .fetch_one(pool)
            .await?,
            sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_power_waiting")
                .fetch_one(pool)
                .await?,
            sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_import_excluded")
                .fetch_one(pool)
                .await?,
            sqlx::query_as(
                "SELECT CAST(i.id AS BIGINT), CAST(i.guild_id AS BIGINT), i.by_name,
                        CAST(i.started_at AS BIGINT), CAST(i.finished_at AS BIGINT),
                        CAST(i.undone_at AS BIGINT),
                        CAST((SELECT COUNT(*) FROM voipc_placeholders p
                               WHERE p.import_id = i.id AND p.banned = FALSE) AS BIGINT),
                        CAST((SELECT COUNT(*) FROM voipc_import_groups g
                               WHERE g.import_id = i.id AND g.power = FALSE) AS BIGINT),
                        CAST(CASE WHEN i.undone_at IS NOT NULL
                                   AND (i.archive_done_at IS NULL
                                        OR EXISTS (SELECT 1 FROM voipc_import_items t WHERE t.import_id = i.id))
                             THEN 1 ELSE 0 END AS BIGINT)
                 FROM voipc_imports i ORDER BY i.id DESC LIMIT $1",
            )
            .bind(RUNS_SHOWN)
            .fetch_all(pool)
            .await?,
        )
    });
    let n = |v: i64| v.clamp(0, i64::from(u32::MAX)) as u32;
    Ok(AccountReply::Admin(AdminReply::MoveStatus {
        claimed: n(claimed),
        waiting: n(waiting),
        banned: n(banned),
        power_waiting: n(power_waiting),
        excluded: n(excluded),
        unclaimed_days: relay.unclaimed_days,
        runs: runs
            .into_iter()
            .map(
                |(
                    id,
                    guild,
                    by,
                    started_at,
                    finished_at,
                    undone_at,
                    accounts,
                    groups,
                    clearing,
                )| {
                    MoveRun {
                        id,
                        guild_id: guild.to_string(),
                        by,
                        started_at,
                        finished_at,
                        undone_at,
                        accounts: n(accounts),
                        groups: n(groups),
                        clearing: clearing != 0,
                    }
                },
            )
            .collect(),
    }))
}

/// `AdminOp::PowerWaiting`: who has opened their account first, then by name.
pub(super) async fn waiting_page(relay: &Relay, offset: u32) -> Result<AccountReply> {
    let (rows, total): (Vec<WaitRow>, i64) = db!(relay.store(), pool => {
        (
            sqlx::query_as(
                "SELECT w.account, u.username, w.role,
                        CAST(CASE WHEN i.account IS NOT NULL AND (p.account IS NULL OR p.claimed_at IS NOT NULL)
                                  THEN 1 ELSE 0 END AS BIGINT) AS opened
                 FROM voipc_power_waiting w
                 JOIN acct_users u ON u.id = w.account
                 LEFT JOIN voipc_placeholders p ON p.account = w.account
                 LEFT JOIN voipc_identity i ON i.account = w.account
                 ORDER BY opened DESC, u.username, w.role LIMIT $1 OFFSET $2",
            )
            .bind(POWER_PAGE)
            .bind(i64::from(offset))
            .fetch_all(pool)
            .await?,
            sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_power_waiting")
                .fetch_one(pool)
                .await?,
        )
    });
    let roles: HashMap<[u8; 16], Role> = relay
        .store()
        .roles()
        .await?
        .into_iter()
        .map(|r| (r.id.0, r))
        .collect();
    // What the twin's plain group shows, since a twin has no badge of its own
    let siblings: Vec<(Vec<u8>, Vec<u8>)> = db!(relay.store(), pool => {
        sqlx::query_as(
            "SELECT t.role, z.role FROM voipc_import_groups t
             JOIN voipc_import_groups z ON z.dc_role_id = t.dc_role_id AND z.power = $1
             WHERE t.power = $2",
        )
        .bind(false)
        .bind(true)
        .fetch_all(pool)
        .await?
    });
    let badge_of_twin = |twin: &[u8]| {
        siblings
            .iter()
            .find(|(t, _)| t == twin)
            .and_then(|(_, z)| <[u8; 16]>::try_from(z.as_slice()).ok())
            .and_then(|z| roles.get(&z))
            .and_then(|z| z.badge.clone())
    };
    let rows = rows
        .into_iter()
        .filter_map(|(account, name, role, opened)| {
            let id: [u8; 16] = role.as_slice().try_into().ok()?;
            let twin = roles.get(&id)?;
            Some(PowerRow {
                account: account.as_slice().try_into().ok()?,
                name,
                claimed: opened == 1,
                group: twin.name.clone(),
                badge: badge_of_twin(&role)
                    .or_else(|| twin.badge.clone())
                    .unwrap_or_default(),
                scopes: twin.scopes.clone(),
            })
        })
        .collect();
    Ok(AccountReply::Admin(AdminReply::PowerWaiting {
        offset,
        total: total.clamp(0, i64::from(u32::MAX)) as u32,
        rows,
    }))
}

/// Whether a frame's rows are of a size and shape this takes at all. Refused whole.
pub(super) fn members_ok(rows: &[ImportMember]) -> bool {
    rows.len() <= IMPORT_FRAME_ROWS
        && rows
            .iter()
            .all(|m| id_ok(m.dc_id) && m.roles.len() <= MEMBER_ROLES)
}

pub(super) fn bans_ok(rows: &[ImportBan]) -> bool {
    rows.len() <= IMPORT_FRAME_ROWS && rows.iter().all(|b| id_ok(b.dc_id))
}

/// `Host::export`'s entry: what the move holds on an account, with the id in decimal, as
/// everything reaching a page has it. None: nothing.
pub(super) async fn discord_member(
    store: &Store,
    user: AccountId,
) -> sqlx::Result<Option<serde_json::Value>> {
    let row: Option<(i64, Option<i64>, i64, Option<i64>)> = db!(store, pool => {
        sqlx::query_as(
            "SELECT CAST(dc_id AS BIGINT), CAST(joined_at AS BIGINT), CAST(imported_at AS BIGINT),
                    CAST(claimed_at AS BIGINT)
             FROM voipc_placeholders WHERE account = $1",
        )
        .bind(&user.0[..])
        .fetch_optional(pool)
        .await
    })?;
    Ok(row.map(|(dc_id, joined_at, imported_at, claimed_at)| {
        serde_json::json!({
            "dc_id": dc_id.to_string(),
            "joined_at": joined_at,
            "imported_at": imported_at,
            "claimed_at": claimed_at,
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: u64 = 175_928_847_299_117_063;

    #[test]
    fn a_discord_name_becomes_an_account_name() {
        let reserved = ["voipc", "guest", "moderator", "general", "everyone", "here"];
        let top = |raw: &str| username_candidates(raw, ID, &reserved).remove(0);
        for (raw, want) in [
            ("alice", "alice"),
            ("Alice.B", "alice_b"),
            ("a.b", "a_b"),
            ("ab", "member-117063"),
            ("___x", "member-117063"),
            // Cleaning took something away: not `xyz`, which is someone else's
            ("__xyz", "xyz-117063"),
            (".xyz", "xyz-117063"),
            ("-xyz", "xyz-117063"),
            ("xy\u{e9}z", "xyz-117063"),
            ("管理", "member-117063"),
            ("admin", "member-117063"),
            ("1uki", "member-117063"),
            ("moderator", "member-117063"),
            ("general", "member-117063"),
            ("12345", "member-117063"),
            ("", "member-117063"),
        ] {
            assert_eq!(top(raw), want, "{raw}");
        }
        // Never a staff-looking name with a number on it
        assert!(!username_candidates("admin", ID, &reserved)
            .iter()
            .any(|n| n.starts_with("admin")));
        let long = "a".repeat(32);
        let tries = username_candidates(&long, ID, &reserved);
        assert_eq!(tries[0], "a".repeat(32));
        assert_eq!(tries[1], format!("{}-117063", "a".repeat(25)));
        assert_eq!(tries[2], format!("{}-7299117063", "a".repeat(21)));
        assert_eq!(tries[3], format!("dc-{ID}"));
        // Past what a name holds, some of it is gone
        let cut = username_candidates(&"a".repeat(40), ID, &reserved);
        assert_eq!(cut[0], format!("{}-117063", "a".repeat(25)));
        for name in &tries {
            assert!(name.len() <= 32, "{name}");
        }
        // A short id: nothing to cut, and still legal
        let short = username_candidates("admin", 1001, &reserved);
        assert_eq!(short, ["member-1001", "dc-1001"]);
    }

    #[test]
    fn group_base_leaves_room_for_power() {
        assert_eq!(group_base("Team Lead", ID), "teamlead");
        assert_eq!(group_base("a.b", ID), "a_b");
        // Nothing left, or too little: a name that says so
        assert_eq!(group_base("管理", ID), "role-117063");
        assert_eq!(group_base("-", ID), "role-117063");
        assert_eq!(group_base("x", ID), "role-117063");
        let long = group_base(&"a".repeat(100), ID);
        assert_eq!(long.len(), 26);
        for name in twin_names(&long, ID) {
            assert!(name.len() <= 32, "{name}");
            assert!(name.ends_with("-power"));
        }
        // The built-in groups are never adopted by name
        assert_eq!(group_names("admin", ID), ["admin-117063"]);
        assert_eq!(group_names("user", ID), ["user-117063"]);
        assert_eq!(group_names("moderator", ID), ["moderator-117063"]);
        assert_eq!(group_names("crew", ID), ["crew", "crew-117063"]);
    }

    #[test]
    fn the_wait_starts_as_it_should() {
        const WAIT: i64 = 7 * 86_400;
        let (imported, claimed) = (100 * 86_400, 200 * 86_400);
        // Years in the Discord: served it
        assert_eq!(wait_start(Some(0), imported, claimed, WAIT), 0);
        // In for exactly the wait, when the import ran
        assert_eq!(
            wait_start(Some(imported - WAIT), imported, claimed, WAIT),
            0
        );
        // A second short of it
        assert_eq!(
            wait_start(Some(imported - WAIT + 1), imported, claimed, WAIT),
            claimed
        );
        // Discord gave no date, or they left and came back after the run
        assert_eq!(wait_start(None, imported, claimed, WAIT), claimed);
        assert_eq!(
            wait_start(Some(imported + 1), imported, claimed, WAIT),
            claimed
        );
        // A row made long ago says nothing of whoever opens it now
        assert_eq!(
            wait_start(Some(imported - 1), imported, claimed, WAIT),
            claimed
        );
    }

    #[test]
    fn a_badge_is_what_can_show_as_one() {
        assert_eq!(badge_of("Admin").as_deref(), Some("Admin"));
        assert_eq!(badge_of(&"x".repeat(100)).unwrap().len(), 32);
        assert_eq!(badge_of("a\u{202e}b"), None, "turns text around");
        assert_eq!(badge_of("   "), None);
    }

    /// New databases: a SQLite file, and with `VOIPC_TEST_POSTGRES` also one on that
    /// server, a throwaway (`postgres://user@host:port/postgres`). No CI job runs one, so
    /// this is the only check of this SQL there.
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
        let file = std::env::temp_dir().join(format!("voipc-placeholder-{id:08x}.db"));
        let url = format!("sqlite://{}?mode=rwc", file.display());
        let mut stores = vec![Store::connect(&url).await.unwrap()];
        if let Ok(server) = std::env::var("VOIPC_TEST_POSTGRES") {
            let name = format!("voipc_placeholder_{id:08x}");
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

    struct Scene {
        relay: Relay,
        ctx: Ctx,
        admin: l4f_accounts::model::User,
        scopes: Vec<String>,
        run: i64,
    }

    const GUILD: i64 = 81_384_788_765_712_384;

    /// A relay with an admin account, and a run of `GUILD`.
    async fn scene(store: &Store) -> Scene {
        let cfg = crate::config::AccountsConfig {
            mode: crate::config::AccountsMode::Optional,
            ..Default::default()
        };
        let relay = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
            .await
            .unwrap();
        let id = AccountId::new();
        let new = NewUser {
            id,
            username: "ann".into(),
            display_name: "ann".into(),
            email_pending: None,
            password_hash: None,
            created_at: util::now(),
        };
        store.create_user(&new, Some("user")).await.unwrap();
        let admin = store.user_by_id(id).await.unwrap().unwrap();
        let ctx = relay.ctx("127.0.0.1".parse().unwrap(), "test");
        let run = relay.run_new(GUILD, "ann", "{}").await.unwrap();
        Scene {
            relay,
            ctx,
            admin,
            scopes: vec!["*".to_string()],
            run,
        }
    }

    impl Scene {
        fn actor(&self) -> Actor<'_> {
            Actor {
                user: &self.admin,
                scopes: &self.scopes,
            }
        }
    }

    fn a_member(dc_id: u64, username: &str, roles: &[u64]) -> ImportMember {
        ImportMember {
            dc_id,
            username: username.into(),
            shown_as: "Shown".into(),
            joined_at: 1_400_000_000,
            roles: roles.to_vec(),
        }
    }

    fn a_role(dc_id: u64, name: &str, permissions: u64) -> ImportRole {
        ImportRole {
            dc_id,
            name: name.into(),
            color: 5,
            position: 3,
            hoist: true,
            permissions,
        }
    }

    /// Someone signs up with that Discord in the instant after the lookup: their account
    /// stays, ours goes, and their groups land on theirs.
    #[tokio::test]
    async fn a_signup_racing_the_import_keeps_the_signup() {
        let dbs = databases().await;
        for store in &dbs.stores {
            let s = scene(store).await;
            let r = &s.relay;
            let ours = r.placeholder_id(2002);
            assert!(r.discord_link(s.admin.id, 2002, "theirs").await.unwrap());
            let made = r
                .make_account(2002, "wendy", Some(1), s.run, false)
                .await
                .unwrap();
            assert!(matches!(made, Made::Lost));
            assert!(store.user_by_id(ours).await.unwrap().is_none(), "ours went");
            assert!(store.user_by_id(s.admin.id).await.unwrap().is_some());
            assert!(r.place_of(2002).await.unwrap().is_none());

            let reply = roles(
                r,
                &s.ctx,
                s.actor(),
                s.run,
                GUILD,
                vec![a_role(11, "Crew", 0)],
            );
            reply.await.unwrap();
            let done = members(
                r,
                s.admin.id,
                s.run,
                GUILD,
                &[a_member(2002, "wendy", &[11])],
            )
            .await
            .unwrap();
            let AdminReply::ImportMembersDone { made, failed, .. } = done else {
                panic!("{done:?}")
            };
            assert_eq!((made, failed.len()), (0, 0));
            let held = store.user_roles(s.admin.id).await.unwrap();
            assert!(held.iter().any(|r| r.name == "crew"), "on theirs");
            // ... and it counts as opened
            assert!(!r.placeholder_open(s.admin.id).await.unwrap());
            assert!(r.place_of(2002).await.unwrap().is_some());
        }
    }

    /// All this file's statements, and `import.rs`'s, on every database a relay can run on.
    #[tokio::test]
    async fn the_moves_statements_run_on_both_backends() {
        let dbs = databases().await;
        for store in &dbs.stores {
            let s = scene(store).await;
            let r = &s.relay;

            // A run's row
            assert!(!r.run_clearing(GUILD).await.unwrap());
            assert_eq!(r.run_unfinished(GUILD).await.unwrap(), Some((s.run, None)));
            r.run_options_put(s.run, r#"{"x":1}"#).await.unwrap();
            assert_eq!(r.run_open_guild(s.run).await.unwrap(), Some(GUILD));
            let (open, options) = r.runs_for_facts().await.unwrap();
            assert_eq!(open, Some((s.run, GUILD)));
            assert_eq!(options.as_deref(), Some(r#"{"x":1}"#));

            // Roles, members, bans
            let rows = vec![
                a_role(11, "Mods", discord::KICK_MEMBERS | discord::BAN_MEMBERS),
                a_role(12, "Crew", 0),
            ];
            let done = roles(r, &s.ctx, s.actor(), s.run, GUILD, rows)
                .await
                .unwrap();
            let AdminReply::ImportRolesDone { made, .. } = done else {
                panic!("{done:?}")
            };
            assert_eq!(made, 3);
            assert!(r.imported_groups.contains_key("crew"));
            assert!(
                !r.imported_groups.contains_key("mods-power"),
                "a twin vouches"
            );
            let ledger = r.ledger(GUILD).await.unwrap();
            assert_eq!((ledger.plain.len(), ledger.twin.len()), (2, 1));
            let twin = ledger.twin[&11];
            assert_eq!(ledger.of.get(&twin), Some(&(11, true)));

            let rows = [
                a_member(1001, "dee", &[11, 12]),
                a_member(1002, "eve", &[11]),
            ];
            let done = members(r, s.admin.id, s.run, GUILD, &rows).await.unwrap();
            let AdminReply::ImportMembersDone { made, .. } = done else {
                panic!("{done:?}")
            };
            assert_eq!(made, 2);
            let dee = r.placeholder_id(1001);
            let eve = r.placeholder_id(1002);
            assert!(r.placeholder_open(dee).await.unwrap());
            assert!(r.power_would_wait(dee).await.unwrap());
            assert_eq!(
                r.profiles(&[dee.0]).await.unwrap()[0].name.as_deref(),
                Some("Shown")
            );
            // What an account's export says of it
            let said = discord_member(r.store(), dee).await.unwrap().unwrap();
            assert_eq!(said["dc_id"], "1001");
            assert!(said["imported_at"].as_i64().unwrap() > 0);
            assert!(said["joined_at"].is_i64() && said["claimed_at"].is_null());
            assert_eq!(discord_member(r.store(), s.admin.id).await.unwrap(), None);
            assert_eq!(r.excluded_own(1001).await.unwrap(), None);

            let done = bans(
                r,
                &s.ctx,
                s.run,
                &[ImportBan { dc_id: 1003 }, ImportBan { dc_id: 1002 }],
            )
            .await
            .unwrap();
            let AdminReply::ImportBansDone {
                made, converted, ..
            } = done
            else {
                panic!("{done:?}")
            };
            assert_eq!((made, converted), (1, 1));
            let banned = store.user_by_id(eve).await.unwrap().unwrap();
            assert_eq!(banned.status, UserStatus::Disabled);
            assert_eq!(r.run_counts(s.run).await.unwrap(), (1, 2, 2));

            // The OK list, and an answer's rows
            let page = waiting_page(r, 0).await.unwrap();
            let AccountReply::Admin(AdminReply::PowerWaiting { total, rows, .. }) = page else {
                panic!("{page:?}")
            };
            assert_eq!((total, rows.len()), (1, 1));
            assert!(!rows[0].claimed);
            assert_eq!(rows[0].badge, "Mods");
            assert_eq!(rows[0].scopes, ["voipc:ban", "voipc:bans", "voipc:kick"]);
            let (role, name) = r.waiting_row(dee, "mods-power").await.unwrap().unwrap();
            assert_eq!((role, name.as_str()), (twin, "dee"));
            assert!(r.waiting_row(dee, "crew").await.unwrap().is_none());

            // A claim, the wait, and the marks
            r.claim_done(dee, &[5; 33]).await.unwrap();
            assert!(!r.placeholder_open(dee).await.unwrap());
            assert!(!r.power_would_wait(dee).await.unwrap());
            assert_eq!(
                r.wait_from(dee, 60).await.unwrap(),
                Some(0),
                "joined long ago"
            );
            assert_eq!(r.wait_from(s.admin.id, 60).await.unwrap(), None);
            let page = waiting_page(r, 0).await.unwrap();
            let AccountReply::Admin(AdminReply::PowerWaiting { rows, .. }) = page else {
                panic!("{page:?}")
            };
            assert!(rows[0].claimed);
            r.waiting_drop(dee, twin).await.unwrap();
            store.grant_role(dee, twin, None).await.unwrap();
            assert!(r.waiting_row(dee, "mods-power").await.unwrap().is_none());

            // A delta: plain groups follow, what the owner gave stays
            let done = members(r, s.admin.id, s.run, GUILD, &[a_member(1001, "dee", &[])])
                .await
                .unwrap();
            let AdminReply::ImportMembersDone { kept_power, .. } = done else {
                panic!("{done:?}")
            };
            assert_eq!(kept_power, 1);
            let held: Vec<String> = store
                .user_roles(dee)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.name)
                .collect();
            assert!(
                held.contains(&"mods-power".to_string()) && !held.contains(&"crew".to_string())
            );

            // A reclaim: back to waiting, a claim still sticks
            r.power_back_to_waiting(dee).await.unwrap();
            assert!(r.waiting_row(dee, "mods-power").await.unwrap().is_some());
            assert!(!store
                .user_roles(dee)
                .await
                .unwrap()
                .iter()
                .any(|r| r.name == "mods-power"));
            db!(store, pool => {
                sqlx::query("DELETE FROM voipc_identity WHERE account = $1")
                    .bind(&dee.0[..])
                    .execute(pool)
                    .await
                    .unwrap();
            });
            assert!(!r.placeholder_open(dee).await.unwrap());
            assert!(r.power_would_wait(dee).await.unwrap());

            // The sweep, and what it spares
            db!(store, pool => {
                sqlx::query("UPDATE voipc_placeholders SET imported_at = imported_at - $1")
                    .bind(100 * 86_400i64)
                    .execute(pool)
                    .await
                    .unwrap();
            });
            members(r, s.admin.id, s.run, GUILD, &[a_member(1004, "fay", &[])])
                .await
                .unwrap();
            let fay = r.placeholder_id(1004);
            assert!(r
                .unclaimed_past(util::now() - 90 * 86_400)
                .await
                .unwrap()
                .is_empty());
            db!(store, pool => {
                sqlx::query("UPDATE voipc_placeholders SET imported_at = imported_at - $1 WHERE dc_id = $2")
                    .bind(100 * 86_400i64)
                    .bind(1004i64)
                    .execute(pool)
                    .await
                    .unwrap();
            });
            assert_eq!(sweep(r).await.unwrap(), 1);
            assert!(store.user_by_id(fay).await.unwrap().is_none());
            assert!(
                store.user_by_id(dee).await.unwrap().is_some(),
                "it was opened once"
            );
            assert!(
                store.user_by_username("dc-1003").await.unwrap().is_some(),
                "banned"
            );
            assert_eq!(r.excluded_own(1004).await.unwrap(), None, "nobody asked");

            // Someone leaving, by either road
            let dee_user = store.user_by_id(dee).await.unwrap().unwrap();
            let by_self = Actor {
                user: &dee_user,
                scopes: &[],
            };
            r.accounts
                .delete_account(&s.ctx, by_self, dee, false)
                .await
                .unwrap();
            assert_eq!(r.excluded_own(1001).await.unwrap(), Some(true));
            let linked = NewUser {
                id: AccountId::new(),
                username: "linked".into(),
                display_name: "linked".into(),
                email_pending: None,
                password_hash: None,
                created_at: util::now(),
            };
            store.create_user(&linked, Some("user")).await.unwrap();
            assert!(r.discord_link(linked.id, 2002, "x").await.unwrap());
            let linked_user = store.user_by_id(linked.id).await.unwrap().unwrap();
            let by_self = Actor {
                user: &linked_user,
                scopes: &[],
            };
            r.accounts
                .delete_account(&s.ctx, by_self, linked.id, false)
                .await
                .unwrap();
            assert_eq!(r.excluded_own(2002).await.unwrap(), Some(true));
            // Asked again, it holds
            members(
                r,
                s.admin.id,
                s.run,
                GUILD,
                &[a_member(2002, "linked", &[])],
            )
            .await
            .unwrap();
            assert!(store.user_by_username("linked").await.unwrap().is_none());

            // The end of a run, and an undo's mark
            assert!(r.run_finish(s.run, "{}").await.unwrap());
            let kept = crate::accounts::import::report(r, s.run).await.unwrap();
            assert!(
                matches!(kept, AccountReply::Admin(AdminReply::ImportReport { ref report, .. }) if report == "{}"),
                "{kept:?}"
            );
            assert!(!r.run_finish(s.run, "{}").await.unwrap(), "once");
            assert_eq!(r.run_open_guild(s.run).await.unwrap(), None);
            db!(store, pool => {
                sqlx::query("UPDATE voipc_imports SET undone_at = $1 WHERE id = $2")
                    .bind(5i64)
                    .bind(s.run)
                    .execute(pool)
                    .await
                    .unwrap();
            });
            assert!(r.run_clearing(GUILD).await.unwrap());
            load(r).await.unwrap();
        }
    }

    /// What reads the archive, what takes rows away, the dashboard and a whole undo, on every
    /// database a relay can run on.
    #[tokio::test]
    async fn the_archives_reads_the_dashboard_and_an_undo_run_on_both_backends() {
        use crate::accounts::archive::{self, Budget, SearchAt, Viewer, Wish};
        use crate::accounts::import;
        use crate::settings::ServerSettings;
        use crate::state::ServerState;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use voipc_protocol::types::{
            ImportCategory, ImportChannel, ImportGate, ImportMessage, ImportReaction, ImportThread,
        };

        let dbs = databases().await;
        for store in &dbs.stores {
            let s = scene(store).await;
            let rows = vec![
                a_role(11, "Mods", discord::KICK_MEMBERS),
                a_role(12, "Crew", 0),
            ];
            roles(&s.relay, &s.ctx, s.actor(), s.run, GUILD, rows)
                .await
                .unwrap();
            let run = s.run;
            let actor = Actor {
                user: &s.admin,
                scopes: &s.scopes,
            };
            let relay = Arc::new(s.relay);
            let mut config = crate::config::ServerConfig::default();
            config.accounts.mode = crate::config::AccountsMode::Optional;
            let mut state = ServerState::new(
                &config,
                ServerSettings::default(),
                Vec::new(),
                "test-admin-token".into(),
            );
            state.accounts = Some(relay.clone());
            let state = Arc::new(state);
            let r = &*relay;

            members(
                r,
                s.admin.id,
                run,
                GUILD,
                &[
                    a_member(1001, "dee", &[11, 12]),
                    a_member(1002, "eve", &[12]),
                ],
            )
            .await
            .unwrap();
            bans(r, &s.ctx, run, &[ImportBan { dc_id: 1003 }])
                .await
                .unwrap();
            let opened = store.user_by_username("dee").await.unwrap().unwrap().id;
            r.claim_done(opened, &[7u8; 32]).await.unwrap();

            let cats = [ImportCategory {
                dc_id: 501,
                name: "Rooms".into(),
            }];
            crate::layout::import_categories(&state, r, run, &cats)
                .await
                .unwrap();
            let channel = |dc_id, name: &str, see| ImportChannel {
                dc_id,
                name: name.into(),
                description: String::new(),
                text: true,
                category: Some(501),
                max_users: 0,
                slow_mode_secs: 0,
                nsfw: false,
                announce: false,
                screen_share: false,
                see,
                speak: ImportGate::Open,
            };
            const TOP: u64 = 1_454_987_148_113_234_751;
            let (a, b) = (TOP, TOP + 1);
            let left = crate::layout::import_channels(
                &state,
                r,
                run,
                &[
                    channel(a, "open", ImportGate::Open),
                    channel(b, "shut", ImportGate::Roles(vec![12])),
                ],
            )
            .await
            .unwrap();
            assert!(left.is_empty(), "{left:?}");
            import::emote(r, run, 701, "wave").await.unwrap();

            let row = |id: u64, author: u64, body: &str, pinned| ImportMessage {
                id,
                author: Some(author),
                author_name: "Dan\u{E9}".into(),
                body: body.into(),
                reply_to: Some(id - 1),
                pinned,
                reactions: vec![ImportReaction {
                    emoji: ":wave:".into(),
                    count: 2,
                }],
                attachments: vec![],
            };
            let (ca, cb) = (a as i64, b as i64);
            let (top, thread) = (TOP + 100, TOP + 50);
            archive::archive_threads(
                r,
                run,
                &[ImportThread {
                    id: thread,
                    parent: a,
                    owner: None,
                    name: "Talk".into(),
                    replies: 1,
                }],
            )
            .await
            .unwrap();
            let flow = [
                row(top, 1001, "Caf\u{E9} needle", true),
                row(top + 1, 1002, "hay", false),
            ];
            archive::archive_put(r, run, ca, 0, &flow, (ca, top as i64 + 1))
                .await
                .unwrap();
            let replies = [row(top + 2, 1002, "needle in a thread", true)];
            archive::archive_put(
                r,
                run,
                ca,
                thread as i64,
                &replies,
                (thread as i64, top as i64 + 2),
            )
            .await
            .unwrap();
            let other = [row(top + 3, 1001, "in the other channel", false)];
            archive::archive_put(r, run, cb, 0, &other, (cb, top as i64 + 3))
                .await
                .unwrap();

            // Reading, in each of its shapes
            let ids_of = |rows: &[archive::ReadRow]| rows.iter().map(|r| r.1).collect::<Vec<_>>();
            let t = top as i64;
            let page = archive::read_page(r, ca, 0, i64::MAX, false).await.unwrap();
            assert_eq!(ids_of(&page), [t + 1, t, thread as i64]);
            assert_eq!(page[1].4, "Caf\u{E9} needle");
            assert_eq!(page[1].5, Some(t - 1));
            assert!(page[1].9);
            assert_eq!(page[2].7.as_deref(), Some("Talk"));
            assert_eq!(page[2].8, 1);
            let page = archive::read_page(r, ca, thread as i64, i64::MAX, false)
                .await
                .unwrap();
            assert_eq!(ids_of(&page), [t + 2]);
            let page = archive::read_page(r, ca, 0, i64::MAX, true).await.unwrap();
            assert_eq!(ids_of(&page), [t + 2, t], "pins, across threads");
            let page = archive::read_page(r, ca, 0, t, false).await.unwrap();
            assert_eq!(ids_of(&page), [thread as i64]);

            // A search, flow and threads, and its row comes out whole
            let viewer = Viewer {
                ids: vec![1002],
                star: true,
            };
            let budget = || Budget {
                hits: 50,
                bytes: 1 << 20,
                until: Instant::now() + Duration::from_secs(60),
            };
            let words = vec!["needle".to_string()];
            let (hits, next, scanned) =
                archive::scan(r, ca, &words, &viewer, SearchAt::Flow(i64::MAX), budget())
                    .await
                    .unwrap();
            assert_eq!(next, None);
            assert_eq!(scanned, 4);
            assert_eq!(hits.len(), 2);
            assert_eq!(hits[0].body, "Caf\u{E9} needle");
            assert_eq!(hits[0].author_id, "1001");
            assert_eq!(hits[0].reactions[0].emoji, ":wave:");
            assert!(!hits[0].mine && hits[1].mine);
            assert_eq!(hits[1].thread, thread.to_string());
            let (hits, _, _) = archive::scan(
                r,
                ca,
                &words,
                &viewer,
                SearchAt::Threads(thread as i64, i64::MAX),
                budget(),
            )
            .await
            .unwrap();
            assert_eq!(
                hits.len(),
                1,
                "the row-value comparison, past a thread's top"
            );

            // Wishes: counted, kept, softened by nothing, and a hide taken back
            let hide = Wish {
                channel: ca,
                low: t,
                high: t,
                erase: false,
            };
            assert_eq!(archive::rows_under(r, Some(1001), &hide).await.unwrap(), 1);
            assert_eq!(archive::rows_under(r, None, &hide).await.unwrap(), 1);
            archive::wish_put(r, &[1001], &hide).await.unwrap();
            assert_eq!(archive::wishes_of(r, 1001).await.unwrap(), 1);
            archive::hides_drop(r, &[1001], &hide).await.unwrap();
            assert_eq!(archive::wishes_of(r, 1001).await.unwrap(), 0);
            archive::wish_put(
                r,
                &[1001],
                &Wish {
                    erase: true,
                    ..hide.clone()
                },
            )
            .await
            .unwrap();
            archive::wish_put(r, &[1001], &hide).await.unwrap();
            archive::hides_drop(r, &[1001], &hide).await.unwrap();
            assert_eq!(
                archive::wishes_of(r, 1001).await.unwrap(),
                1,
                "an erase stays"
            );
            archive::load(r).await.unwrap();
            assert_eq!(archive::tidy(&state, r).await.unwrap(), 1);
            assert_eq!(archive::rows_under(r, Some(1001), &hide).await.unwrap(), 0);

            // Whoever wrote it: one message, and who may be left out
            let one = Wish {
                channel: ca,
                low: t + 1,
                high: t + 1,
                erase: true,
            };
            archive::wish_put(r, &[0], &one).await.unwrap();
            archive::load(r).await.unwrap();
            assert_eq!(archive::tidy(&state, r).await.unwrap(), 1);
            let flow_left = archive::read_page(r, ca, 0, i64::MAX, false).await.unwrap();
            assert_eq!(ids_of(&flow_left), [thread as i64]);

            // Past a retention, on a relay that has one, and a channel with no row or memory
            let cfg = crate::config::AccountsConfig {
                mode: crate::config::AccountsMode::Optional,
                archive_days: 1,
                ..Default::default()
            };
            let aged = Relay::open_with(&cfg, store.clone(), &[9u8; 32])
                .await
                .unwrap();
            let old = discord::snowflake_floor(1_500_000_000_000) as u64;
            let frame = [row(old, 1002, "from long ago", false)];
            archive::archive_put(r, run, cb, 0, &frame, (cb, old as i64))
                .await
                .unwrap();
            let frame = [row(old + 5, 1002, "in nothing", false)];
            archive::archive_put(r, run, 42, 0, &frame, (42, old as i64 + 5))
                .await
                .unwrap();
            let young = discord::snowflake_floor(log::now_ms()) as u64;
            let frame = [row(young, 1002, "from today", false)];
            archive::archive_put(r, run, cb, 0, &frame, (cb, young as i64))
                .await
                .unwrap();
            // The root and its reply, the other channel's old two, and the one in nothing
            assert_eq!(archive::tidy(&state, &aged).await.unwrap(), 5);
            let today = archive::read_page(r, cb, 0, i64::MAX, false).await.unwrap();
            assert_eq!(ids_of(&today), [young as i64]);

            // Who is left out, both ways, and the list of them
            exclude_refusal(r, 1001, true).await.unwrap().unwrap();
            assert!(exclude_refusal(r, 1002, true).await.unwrap().is_none());
            // Banned here by name (W1-32): leaving out could not take the account, so it says
            // so rather than answering done. Without the ban, the control, it goes ahead.
            let eve = store.user_by_username("eve").await.unwrap().unwrap().id;
            let ban = |sql: &'static str| async move {
                db!(store, pool => {
                    sqlx::query(sql).bind(&eve.0[..]).execute(pool).await.unwrap();
                });
            };
            ban(
                "INSERT INTO voipc_bans (id, account, label, reason, by_name, created_at)
                 VALUES (77, $1, 'eve', '', 'mod', 1)",
            )
            .await;
            let why = exclude_refusal(r, 1002, true).await.unwrap().unwrap();
            assert!(why.contains("banned here"), "{why}");
            assert!(exclude_refusal(r, 1002, false).await.unwrap().is_none());
            ban("DELETE FROM voipc_bans WHERE account = $1").await;
            assert!(exclude_refusal(r, 1002, true).await.unwrap().is_none());
            let page = exclude(&state, r, 0, 2222, true, true).await.unwrap();
            assert!(
                matches!(page, AccountReply::Admin(AdminReply::MoveExcluded { ref ids, more: false }) if ids.len() == 1),
                "{page:?}"
            );
            assert_eq!(r.excluded_own(2222).await.unwrap(), Some(false));
            // Holding afterwards softens nothing
            exclude(&state, r, 0, 2222, true, false).await.unwrap();
            let held: bool = db!(store, pool => {
                sqlx::query_scalar("SELECT erase FROM voipc_import_excluded WHERE dc_id = $1")
                    .bind(2222i64)
                    .fetch_one(pool)
                    .await
                    .unwrap()
            });
            assert!(held);
            exclude(&state, r, 0, 2222, false, false).await.unwrap();
            assert_eq!(r.excluded_own(2222).await.unwrap(), None);
            assert_eq!(
                archive::wishes_of(r, 2222).await.unwrap(),
                1,
                "what went stays gone"
            );
            exclude(&state, r, 0, 3333, true, false).await.unwrap();
            let AccountReply::Admin(AdminReply::MoveExcluded { ids, more }) =
                excluded_page(r, 0).await.unwrap()
            else {
                panic!()
            };
            assert_eq!(
                (ids.len(), more, ids[0].0.as_str(), ids[0].1, ids[0].2),
                (1, false, "3333", false, false)
            );
            let AccountReply::Admin(AdminReply::MoveExcluded { ids, .. }) =
                excluded_page(r, 3333).await.unwrap()
            else {
                panic!()
            };
            assert!(ids.is_empty());

            // The dashboard: each filter, the search, the counts
            for (filter, want) in [
                (MoveFilter::All, 4),
                (MoveFilter::Waiting, 1),
                (MoveFilter::Claimed, 1),
                (MoveFilter::Banned, 1),
            ] {
                let got = move_accounts(r, true, String::new(), 0, filter)
                    .await
                    .unwrap();
                let AccountReply::Admin(AdminReply::MoveAccounts { total, rows, .. }) = got else {
                    panic!("{got:?}")
                };
                assert_eq!((total, rows.len()), (want, want as usize), "{filter:?}");
            }
            let got = move_accounts(r, false, "D_E!%".into(), 0, MoveFilter::All)
                .await
                .unwrap();
            assert!(
                matches!(
                    got,
                    AccountReply::Admin(AdminReply::MoveAccounts { total: 0, .. })
                ),
                "{got:?}"
            );
            let got = move_accounts(r, true, "DE".into(), 0, MoveFilter::All)
                .await
                .unwrap();
            let AccountReply::Admin(AdminReply::MoveAccounts { rows, .. }) = got else {
                panic!("{got:?}")
            };
            assert_eq!(rows[0].user.name, "dee");
            assert_eq!(rows[0].state, MoveState::Claimed);
            assert_eq!(rows[0].dc_id, "1001");
            assert!(!rows[0].user.totp);

            let got = move_status(r).await.unwrap();
            let AccountReply::Admin(AdminReply::MoveStatus {
                claimed,
                waiting,
                banned,
                excluded,
                runs,
                ..
            }) = got
            else {
                panic!("{got:?}")
            };
            assert_eq!((claimed, waiting, banned, excluded), (1, 1, 1, 1));
            assert_eq!(
                (
                    runs[0].id,
                    runs[0].accounts,
                    runs[0].groups,
                    runs[0].clearing
                ),
                (run, 2, 2, false)
            );
            assert_eq!(runs[0].guild_id, GUILD.to_string());

            // The preview, and a whole undo, a call at a time
            assert!(r.run_finish(run, "{}").await.unwrap());
            let got = import::undo_preview(r, run).await.unwrap();
            let AccountReply::Admin(AdminReply::ImportUndoPreview { counts, .. }) = got else {
                panic!("{got:?}")
            };
            assert_eq!(
                (
                    counts.channels,
                    counts.groups,
                    counts.placeholders,
                    counts.claimed_kept,
                    counts.emotes,
                    counts.later_runs
                ),
                (2, 2, 2, 1, 1, 0)
            );
            assert_eq!(
                counts.archive_rows, 7,
                "all it filed, whatever has gone since"
            );
            assert_eq!(counts.live_posts, 0);
            let later = r.run_new(GUILD, "ann", "{}").await.unwrap();
            let active = state.import.lock().await;
            assert!(import::undo_refusal(&state, r, 0, &active, run)
                .await
                .unwrap()
                .is_some());
            drop(active);
            db!(store, pool => {
                sqlx::query("UPDATE voipc_imports SET undone_at = $1, archive_done_at = $1 WHERE id = $2")
                    .bind(5i64)
                    .bind(later)
                    .execute(pool)
                    .await
                    .unwrap();
            });
            let mut calls = 0;
            loop {
                let active = state.import.lock().await;
                assert!(import::undo_refusal(&state, r, 0, &active, run)
                    .await
                    .unwrap()
                    .is_none());
                let got = import::undo(&state, r, 0, &s.ctx, actor, active, run)
                    .await
                    .unwrap();
                calls += 1;
                let AccountReply::Admin(AdminReply::ImportUndone { more, .. }) = got else {
                    panic!("{got:?}")
                };
                if !more {
                    break;
                }
                assert!(calls < 10);
            }
            assert!(r.run_clearing(GUILD).await.unwrap());
            archive::tidy(&state, r).await.unwrap();
            assert!(!r.run_clearing(GUILD).await.unwrap());
            let left: i64 = db!(store, pool => {
                sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM voipc_archive")
                    .fetch_one(pool)
                    .await
                    .unwrap()
            });
            assert_eq!(left, 0);
            assert!(store.user_by_username("eve").await.unwrap().is_none());
            assert!(store.user_by_username("dee").await.unwrap().is_some());
            assert!(store.role_by_name("crew").await.unwrap().is_none());
            let imported = |c: &crate::state::Channel| c.gate_key.starts_with("c:dc-");
            assert!(!state.channels.read().await.values().any(imported));

            // A run that left rows in a channel still here: the walk by key, and the rest stay
            let run2 = r.run_new(GUILD + 1, "ann", "{}").await.unwrap();
            let run3 = r.run_new(GUILD + 1, "ann", "{}").await.unwrap();
            crate::layout::import_channels(
                &state,
                r,
                run2,
                &[channel(a, "open", ImportGate::Open)],
            )
            .await
            .unwrap();
            let frame = [
                row(top + 10, 7, "kept", false),
                row(top + 11, 7, "kept too", false),
            ];
            archive::archive_put(r, run2, ca, 0, &frame, (ca, t + 11))
                .await
                .unwrap();
            let frame = [row(top + 12, 7, "taken", false)];
            archive::archive_put(r, run3, ca, 0, &frame, (ca, t + 12))
                .await
                .unwrap();
            archive::archive_put(r, run3, ca, 9, &frame, (9, t + 12))
                .await
                .unwrap();
            db!(store, pool => {
                sqlx::query("UPDATE voipc_imports SET undone_at = $1 WHERE id = $2")
                    .bind(5i64)
                    .bind(run3)
                    .execute(pool)
                    .await
                    .unwrap();
            });
            assert_eq!(archive::tidy(&state, r).await.unwrap(), 2);
            assert_eq!(r.runs_with_rows_to_go().await.unwrap(), Vec::<i64>::new());
            let page = archive::read_page(r, ca, 0, i64::MAX, false).await.unwrap();
            assert_eq!(ids_of(&page), [t + 11, t + 10]);

            // The ledger follows an emote's new name, or its removal
            import::emote(r, run2, 702, "hey").await.unwrap();
            r.emote_item_moved("hey", "hello").await.unwrap();
            let got = r.import_items(3).await.unwrap();
            assert_eq!(got[&702], "hello");
            r.emote_item_moved("hello", "").await.unwrap();
            assert_eq!(r.import_items(3).await.unwrap()[&702], "");
            load(r).await.unwrap();
        }
    }

    /// What the review of the move changed, on every database a relay can run on.
    #[tokio::test]
    async fn the_review_fixes_statements_run_on_both_backends() {
        use crate::accounts::{archive, import};
        use crate::settings::ServerSettings;
        use crate::state::ServerState;
        use std::sync::Arc;
        use voipc_protocol::types::{
            ArchiveWish, ImportChannel, ImportGate, ImportMessage, ImportThread, THREAD_TAKEN_BACK,
        };

        const TOP: u64 = 1_454_987_148_113_234_751;
        let dbs = databases().await;
        for store in &dbs.stores {
            let s = scene(store).await;
            let run = s.run;
            let actor = Actor {
                user: &s.admin,
                scopes: &s.scopes,
            };
            let rows = vec![
                a_role(11, "Mods", discord::KICK_MEMBERS),
                a_role(12, "Crew", 0),
            ];
            let relay = Arc::new(s.relay);
            let r = &*relay;
            roles(r, &s.ctx, actor, run, GUILD, rows.clone())
                .await
                .unwrap();
            let mut config = crate::config::ServerConfig::default();
            config.accounts.mode = crate::config::AccountsMode::Optional;
            let mut state = ServerState::new(
                &config,
                ServerSettings::default(),
                Vec::new(),
                "test-admin-token".into(),
            );
            state.accounts = Some(relay.clone());
            let state = Arc::new(state);

            // A role's group removed here, and what the next frame makes of that
            for (name, want) in [("crew", (12, false, run)), ("mods-power", (11, true, run))] {
                let row = r.group_ledger_row(name).await.unwrap().unwrap();
                assert_eq!(row, want);
                r.group_deleted_here(row).await.unwrap();
                r.group_deleted_here(row).await.unwrap();
            }
            assert_eq!(r.group_ledger_row("no such").await.unwrap(), None);
            for (kind, id) in [
                (import::KIND_GROUP_DELETED, 12),
                (import::KIND_TWIN_DELETED, 11),
            ] {
                assert_eq!(r.import_items(kind).await.unwrap()[&id], "");
            }

            // Who came, who took Discord off, who holds a banned row's name
            let rows = [
                a_member(1001, "dee", &[]),
                a_member(1002, "eve", &[]),
                a_member(1003, "mal", &[]),
                a_member(1004, "nan", &[]),
            ];
            members(r, s.admin.id, run, GUILD, &rows).await.unwrap();
            let (dee, eve) = (r.placeholder_id(1001), r.placeholder_id(1002));
            r.claim_done(dee, &[5; 33]).await.unwrap();
            r.claim_done(eve, &[6; 33]).await.unwrap();
            let kind = Kind::Discord.credential_kind();
            assert!(store.delete_credential(dee, &kind, b"1001").await.unwrap());
            assert_eq!(r.placeholder_dc_id(dee).await.unwrap(), Some(1001));
            assert_eq!(r.placeholder_dc_id(s.admin.id).await.unwrap(), None);

            // A waiting row turns out banned, in a later run
            let later = r.run_new(GUILD, "ann", "{}").await.unwrap();
            let done = bans(r, &s.ctx, later, &[ImportBan { dc_id: 1003 }])
                .await
                .unwrap();
            assert!(matches!(
                done,
                AdminReply::ImportBansDone { converted: 1, .. }
            ));
            let mal = store.user_by_username("dc-1003").await.unwrap().unwrap();
            assert_eq!(mal.display_name, "dc-1003");
            assert_eq!(mal.status, UserStatus::Disabled);
            let held = store.credential(&kind, b"1003").await.unwrap().unwrap();
            assert_eq!(held.name, "dc-1003");
            let at: i64 = db!(store, pool => {
                sqlx::query_scalar(
                    "SELECT CAST(import_id AS BIGINT) FROM voipc_placeholders WHERE dc_id = $1",
                )
                .bind(1003i64)
                .fetch_one(pool)
                .await
                .unwrap()
            });
            assert_eq!(at, later);
            assert!(r
                .banned_rename(&s.ctx, r.placeholder_id(1004), 1004)
                .await
                .unwrap());
            assert_eq!(
                store.user_by_username("dc-1004").await.unwrap().unwrap().id,
                r.placeholder_id(1004)
            );

            // Everyone keeps the mark, and all of them count
            assert_eq!(r.undo_claimed(run).await.unwrap(), 2);
            assert!(r.place_of(1001).await.unwrap().is_some());
            assert!(r.place_of(1002).await.unwrap().is_some());
            // However it went, an account someone opened is not adopted
            let made = r.make_account(1001, "dee", Some(1), run, false).await;
            assert!(matches!(made.unwrap(), Made::Opened(name) if name == "dee"));

            // A group an undo kept, which a later run takes up, and only that
            let kept = r.group_ledger_row("mods").await.unwrap().unwrap();
            assert_eq!(kept, (11, false, run));
            r.ledger_take_up(11, later).await.unwrap();
            assert_eq!(r.group_ledger_row("mods").await.unwrap(), Some(kept));
            db!(store, pool => {
                sqlx::query("UPDATE voipc_imports SET undone_at = $1 WHERE id = $2")
                    .bind(1i64)
                    .bind(run)
                    .execute(pool)
                    .await
                    .unwrap();
            });
            assert_eq!(r.group_ledger_row("mods").await.unwrap(), None);
            r.ledger_take_up(11, later).await.unwrap();
            let moved = r.group_ledger_row("mods").await.unwrap();
            assert_eq!(moved, Some((11, false, later)));
            assert_eq!(
                r.group_ledger_row("mods-power").await.unwrap(),
                Some((11, true, later)),
                "its twin too"
            );
            assert_eq!(
                r.group_ledger_row("crew").await.unwrap(),
                None,
                "the control"
            );
            db!(store, pool => {
                sqlx::query("UPDATE voipc_imports SET undone_at = NULL WHERE id = $1")
                    .bind(run)
                    .execute(pool)
                    .await
                    .unwrap();
            });

            // A thread's owner, and the worker on an opening row
            let channel = ImportChannel {
                dc_id: TOP,
                name: "open".into(),
                description: String::new(),
                text: true,
                category: None,
                max_users: 0,
                slow_mode_secs: 0,
                nsfw: false,
                announce: false,
                screen_share: false,
                see: ImportGate::Open,
                speak: ImportGate::Open,
            };
            let left =
                crate::layout::import_channels(&state, r, run, std::slice::from_ref(&channel))
                    .await
                    .unwrap();
            assert!(left.is_empty(), "{left:?}");
            let closed = ImportChannel {
                see: ImportGate::Closed,
                ..channel
            };
            let left = crate::layout::import_channels(&state, r, run, &[closed])
                .await
                .unwrap();
            assert_eq!(left.len(), 1, "open here, and closed there");
            let c = TOP as i64;
            let thread = |id: u64, owner: Option<u64>, name: &str| ImportThread {
                id,
                parent: TOP,
                owner,
                name: name.into(),
                replies: 2,
            };
            let row = ImportMessage {
                id: TOP + 3,
                author: Some(55),
                author_name: "x".into(),
                body: "y".into(),
                reply_to: Some(TOP + 1),
                pinned: true,
                reactions: vec![],
                attachments: vec![],
            };
            archive::archive_put(r, run, c, 0, std::slice::from_ref(&row), (c, c + 3))
                .await
                .unwrap();
            let threads = [
                thread(TOP + 1, Some(55), "by the owner"),
                thread(TOP + 2, None, "nobody's"),
                thread(TOP + 3, Some(66), "on someone's row"),
            ];
            archive::archive_threads(r, run, &threads).await.unwrap();
            let got = |id: u64| archive::archived_row(r, c, 0, id as i64);
            assert_eq!(got(TOP + 1).await.unwrap().unwrap().author, Some(55));
            assert_eq!(got(TOP + 2).await.unwrap().unwrap().author, None);
            assert_eq!(
                got(TOP + 3).await.unwrap().unwrap().author,
                Some(55),
                "its own"
            );

            let everything = archive::Wish {
                channel: 0,
                low: 0,
                high: i64::MAX,
                erase: true,
            };
            archive::wish_put(r, &[55], &everything).await.unwrap();
            let one = archive::Wish {
                channel: c,
                low: c + 2,
                high: c + 2,
                erase: true,
            };
            archive::wish_put(r, &[0], &one).await.unwrap();
            let hide = archive::Wish {
                channel: c,
                low: 1,
                high: 2,
                erase: false,
            };
            archive::wish_put(r, &[77], &hide).await.unwrap();
            assert_eq!(archive::hides_drop(r, &[77], &hide).await.unwrap(), 1);
            assert_eq!(archive::hides_drop(r, &[77], &hide).await.unwrap(), 0);
            archive::load(r).await.unwrap();
            let plain = ImportMessage {
                id: TOP + 4,
                ..row.clone()
            };
            archive::wish_put(r, &[88], &everything).await.unwrap();
            let by_88 = ImportMessage {
                author: Some(88),
                ..plain
            };
            archive::archive_put(r, run, c, 0, &[by_88], (c, c + 4))
                .await
                .unwrap();
            archive::load(r).await.unwrap();
            assert_eq!(
                archive::tidy(&state, r).await.unwrap(),
                1,
                "a plain row goes"
            );
            for id in [TOP + 1, TOP + 2, TOP + 3] {
                let row = got(id).await.unwrap().unwrap();
                assert_eq!(row.thread_name.as_deref(), Some(THREAD_TAKEN_BACK), "{id}");
                assert_eq!(
                    (row.author, row.name.as_str(), row.body.as_str()),
                    (None, "", "")
                );
                assert_eq!(
                    (row.reply_to, row.reactions, row.pinned),
                    (None, None, false)
                );
                assert_eq!(row.replies, 2);
            }
            assert_eq!(archive::tidy(&state, r).await.unwrap(), 0, "settled");

            let neutral = |row: archive::ArchivedRow, replies: i32| {
                assert_eq!(row.thread_name.as_deref(), Some(THREAD_TAKEN_BACK));
                assert_eq!(
                    (
                        row.author,
                        row.name.as_str(),
                        row.body.as_str(),
                        row.replies
                    ),
                    (None, "", "", replies)
                );
            };
            // Neutral stays so whoever a later run names, and only the count moves
            let again = ImportThread {
                replies: 9,
                ..thread(TOP + 1, Some(66), "back again")
            };
            archive::archive_threads(r, run, &[again]).await.unwrap();
            neutral(got(TOP + 1).await.unwrap().unwrap(), 9);
            // Words with no id on them are nobody's to take
            let no_id = ImportMessage {
                id: TOP + 5,
                author: None,
                ..row.clone()
            };
            archive::archive_put(r, run, c, 0, &[no_id], (c, c + 5))
                .await
                .unwrap();
            archive::archive_threads(r, run, &[thread(TOP + 5, Some(66), "a title")])
                .await
                .unwrap();
            let got_row = got(TOP + 5).await.unwrap().unwrap();
            assert_eq!((got_row.author, got_row.body.as_str()), (None, "y"));
            assert_eq!(got_row.thread_name.as_deref(), Some("a title"));
            // A root with no words, filed neutral, is that from then on
            archive::archive_threads(r, run, &[thread(TOP + 6, Some(66), "a title")])
                .await
                .unwrap();
            assert_eq!(got(TOP + 6).await.unwrap().unwrap().author, Some(66));
            let taken = [
                thread(TOP + 6, None, THREAD_TAKEN_BACK),
                thread(TOP + 6, Some(66), "a title"),
            ];
            archive::archive_threads(r, run, &taken[..1]).await.unwrap();
            archive::archive_threads(r, run, &taken[1..]).await.unwrap();
            neutral(got(TOP + 6).await.unwrap().unwrap(), 2);
            // A frame's dropped row takes the thread's name with it
            archive::archive_threads(r, run, &[thread(TOP + 7, Some(66), "his words")])
                .await
                .unwrap();
            let dropped = ImportMessage {
                id: TOP + 7,
                author: Some(88),
                ..row.clone()
            };
            archive::archive_put(r, run, c, 0, &[dropped], (c, c + 7))
                .await
                .unwrap();
            neutral(got(TOP + 7).await.unwrap().unwrap(), 2);

            // The wishes, a page at a time, on the whole key
            let AccountReply::Admin(AdminReply::ArchiveWishes { rows, more }) =
                archive::wishes_page(r, None).await.unwrap()
            else {
                panic!()
            };
            assert!(!more);
            let all_of = |author| ArchiveWish {
                author,
                channel: 0,
                low: 0,
                high: i64::MAX as u64,
                erase: true,
            };
            assert_eq!(rows, [all_of(55), all_of(88)], "not whoever-wrote-it's");
            let AccountReply::Admin(AdminReply::ArchiveWishes { rows, .. }) =
                archive::wishes_page(r, Some(all_of(55))).await.unwrap()
            else {
                panic!()
            };
            assert_eq!(rows, [all_of(88)]);
        }
    }

    /// What a run files, on every database a relay can run on: `layout.rs`'s frames,
    /// `archive.rs`'s, and `import.rs`'s ledger and cursors.
    #[tokio::test]
    async fn the_archives_statements_run_on_both_backends() {
        use crate::accounts::{archive, import};
        use crate::settings::ServerSettings;
        use crate::state::ServerState;
        use std::sync::Arc;
        use voipc_protocol::types::{
            ImportAttachment, ImportCategory, ImportChannel, ImportGate, ImportMessage,
            ImportOptions, ImportReaction, ImportThread, IMPORT_BODY_BYTES,
        };

        let dbs = databases().await;
        for store in &dbs.stores {
            let s = scene(store).await;
            let rows = vec![
                a_role(11, "Mods", discord::KICK_MEMBERS),
                a_role(12, "Crew", 0),
            ];
            roles(&s.relay, &s.ctx, s.actor(), s.run, GUILD, rows)
                .await
                .unwrap();
            let run = s.run;
            let relay = Arc::new(s.relay);
            let mut config = crate::config::ServerConfig::default();
            config.accounts.mode = crate::config::AccountsMode::Optional;
            let mut state = ServerState::new(
                &config,
                ServerSettings::default(),
                Vec::new(),
                "test-admin-token".into(),
            );
            state.accounts = Some(relay.clone());
            let r = &*relay;

            // The options a frame is held to
            assert!(!r.run_takes_messages(run).await.unwrap());
            let options = ImportOptions {
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
            };
            let text = serde_json::to_string(&options).unwrap();
            r.run_options_put(run, &text).await.unwrap();
            assert!(r.run_takes_messages(run).await.unwrap());

            // Groups by Discord's id, and only those holding nothing
            assert_eq!(r.zero_group_of(11).await.unwrap().as_deref(), Some("mods"));
            assert_eq!(r.zero_group_of(12).await.unwrap().as_deref(), Some("crew"));
            assert_eq!(r.zero_group_of(99).await.unwrap(), None);
            let info = GroupInfo {
                name: "another".into(),
                description: String::new(),
                badge: String::new(),
                scopes: vec![],
                builtin: false,
            };
            assert!(r.group_save_fits(true, &info).await.unwrap());

            // Categories and channels: what the ledger holds is left alone
            let wide = "\u{1F600}";
            let cats = [
                ImportCategory {
                    dc_id: 501,
                    name: wide.repeat(16),
                },
                ImportCategory {
                    dc_id: 502,
                    name: "Rooms".into(),
                },
            ];
            let left = crate::layout::import_categories(&state, r, run, &cats)
                .await
                .unwrap();
            assert!(left.is_empty(), "{left:?}");
            let left = crate::layout::import_categories(&state, r, run, &cats)
                .await
                .unwrap();
            assert!(left.is_empty(), "{left:?}");
            assert_eq!(state.layout.read().await.categories.len(), 2);
            assert_eq!(
                r.import_items(import::KIND_CATEGORY).await.unwrap().len(),
                2
            );

            let channel = |dc_id, name: &str, see, category| ImportChannel {
                dc_id,
                name: name.into(),
                description: wide.repeat(64),
                text: true,
                category,
                max_users: 3,
                slow_mode_secs: 21_600,
                nsfw: true,
                announce: true,
                screen_share: false,
                see,
                speak: ImportGate::Roles(vec![12]),
            };
            const TOP: u64 = 1_454_987_148_113_234_751;
            let rows = [
                channel(TOP, &wide.repeat(16), ImportGate::Open, Some(501)),
                channel(TOP + 1, "gated", ImportGate::Roles(vec![11, 12]), Some(502)),
                channel(TOP + 2, "closed", ImportGate::Closed, None),
            ];
            // One has a place already, as a channel from a file can: its row stays one row
            r.layout_put(&format!("c:dc-{}", TOP + 2), None, 0, None)
                .await
                .unwrap();
            let left = crate::layout::import_channels(&state, r, run, &rows)
                .await
                .unwrap();
            assert!(left.is_empty(), "{left:?}");
            let left = crate::layout::import_channels(&state, r, run, &rows)
                .await
                .unwrap();
            assert!(left.is_empty(), "{left:?}");
            let items = r.import_items(import::KIND_CHANNEL).await.unwrap();
            assert_eq!(items[&(TOP as i64)], format!("c:dc-{TOP}"));
            let rows_read = r.layout_rows().await.unwrap();
            assert_eq!(rows_read.rows.len(), 3);
            assert_eq!(rows_read.rows[0].category, Some(1));
            assert!(rows_read.rows[0].entry.is_some());
            let gates = r.gates().await.unwrap();
            let of = |key: String| {
                gates
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, g)| g.clone())
            };
            let gated = of(format!("c:dc-{}", TOP + 1)).unwrap();
            assert_eq!(gated.groups, ["crew", "mods"]);
            assert_eq!(gated.speakers, ["crew"]);
            assert_eq!(of(format!("c:dc-{}", TOP + 2)).unwrap().groups, ["admin"]);

            // A new order is one transaction, rows and categories together (W2-14)
            let one = voipc_protocol::types::ChannelCategory {
                id: 1,
                name: "first".into(),
            };
            r.layout_write(
                &[(format!("c:dc-{}", TOP + 2), None, -5, Some(1))],
                &[(one.clone(), 7)],
            )
            .await
            .unwrap();
            let back = r.layout_rows().await.unwrap();
            assert_eq!(back.rows[0].conv, format!("c:dc-{}", TOP + 2));
            assert_eq!(back.rows[0].category, Some(1));
            assert_eq!(back.categories.last().map(|c| c.id), Some(1));

            // A category gone by hand: the ledger keeps its row, naming nothing, and the rest
            // take the places the list gives them
            r.category_delete(2, std::slice::from_ref(&one))
                .await
                .unwrap();
            let held = r.import_items(import::KIND_CATEGORY).await.unwrap();
            assert_eq!((held[&501].as_str(), held[&502].as_str()), ("1", ""));
            let back = r.layout_rows().await.unwrap();
            assert_eq!(back.categories, [one]);

            // A private channel with its gate opened takes nothing; one that was open does
            let top = TOP as i64;
            assert_eq!(archive::may_file(&state, r, top).await.unwrap(), Ok(()));
            assert_eq!(archive::may_file(&state, r, top + 1).await.unwrap(), Ok(()));
            {
                let mut channels = state.channels.write().await;
                let key = format!("c:dc-{}", TOP + 1);
                let c = channels.values_mut().find(|c| c.gate_key == key).unwrap();
                c.gate.groups.clear();
            }
            let said = archive::may_file(&state, r, top + 1).await.unwrap();
            assert!(said.unwrap_err().contains("private"));
            let said = archive::may_file(&state, r, top + 9).await.unwrap();
            assert!(said.unwrap_err().contains("removed"));

            // The longest row there is, in characters: VARCHAR counts those on Postgres
            let body = format!("a\nb\u{0}c{}", "b".repeat(IMPORT_BODY_BYTES - 6));
            let longest = ImportMessage {
                id: TOP + 10,
                author: Some(TOP),
                author_name: wide.repeat(80),
                body,
                reply_to: Some(TOP),
                pinned: true,
                reactions: vec![ImportReaction {
                    emoji: wide.repeat(70),
                    count: u32::MAX,
                }],
                attachments: vec![ImportAttachment {
                    id: u64::MAX,
                    name: wide.repeat(130),
                    bytes: u64::MAX,
                    mime: wide.repeat(70),
                }],
            };
            let high = top + 10;
            let got = archive::archive_put(r, run, top, 0, &[longest], (top, high))
                .await
                .unwrap();
            assert_eq!(got, (1, 0));
            let row = archive::archived_row(r, top, 0, high)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.name, wide.repeat(64));
            assert!(
                row.body.starts_with("a\nbc"),
                "a NUL would not get this far"
            );
            assert_eq!(
                (row.author, row.reply_to, row.pinned),
                (Some(top), Some(top), true)
            );
            assert_eq!(row.import_id, run);
            assert!(row.reactions.is_some() && row.attachments.is_some());

            // A thread on that row, and one with no message; a thread's first message
            let threads = [
                ImportThread {
                    id: TOP + 10,
                    parent: TOP,
                    owner: None,
                    name: wide.repeat(120),
                    replies: u32::MAX,
                },
                ImportThread {
                    id: TOP + 11,
                    parent: TOP,
                    owner: None,
                    name: "lone".into(),
                    replies: 0,
                },
            ];
            archive::archive_threads(r, run, &threads).await.unwrap();
            let root = archive::archived_row(r, top, 0, high)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(root.body, row.body, "only its name and count");
            assert_eq!(root.thread_name, Some(wide.repeat(100)));
            assert_eq!(root.replies, i32::MAX);
            let lone = archive::archived_row(r, top, 0, top + 11).await.unwrap();
            assert_eq!(lone.unwrap().author, None);
            let plain = ImportMessage {
                id: TOP + 11,
                author: None,
                author_name: "Former member".into(),
                body: "first".into(),
                reply_to: None,
                pinned: false,
                reactions: vec![],
                attachments: vec![],
            };
            let reply = ImportMessage {
                id: TOP + 12,
                ..plain.clone()
            };
            let got =
                archive::archive_put(r, run, top, top + 11, &[plain, reply], (top + 11, top + 12))
                    .await
                    .unwrap();
            assert_eq!(got, (2, 0));
            let lone = archive::archived_row(r, top, 0, top + 11)
                .await
                .unwrap()
                .unwrap();
            assert_eq!((lone.body.as_str(), lone.replies), ("first", 0));
            assert!(lone.thread_name.is_some(), "kept by the upsert");
            assert!(archive::archived_row(r, top, top + 11, top + 12)
                .await
                .unwrap()
                .is_some());

            // Wishes: from their table and from who asked to be out, and a frame obeys them
            db!(store, pool => {
                sqlx::query(
                    "INSERT INTO voipc_archive_wishes (author_dc_id, channel, low, high, erase, at)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(55i64)
                .bind(0i64)
                .bind(0i64)
                .bind(i64::MAX)
                .bind(true)
                .bind(1i64)
                .execute(pool)
                .await
                .unwrap();
                for (id, erase) in [(66i64, true), (77i64, false)] {
                    sqlx::query(
                        "INSERT INTO voipc_import_excluded (dc_id, own, erase, at) VALUES ($1, $2, $3, $4)",
                    )
                    .bind(id)
                    .bind(false)
                    .bind(erase)
                    .bind(1i64)
                    .execute(pool)
                    .await
                    .unwrap();
                }
            });
            archive::load(r).await.unwrap();
            let by = |id: u64, author: u64| ImportMessage {
                id,
                author: Some(author),
                author_name: "x".into(),
                body: "y".into(),
                reply_to: None,
                pinned: false,
                reactions: vec![],
                attachments: vec![],
            };
            let frame = [
                by(TOP + 20, 55),
                by(TOP + 21, 66),
                by(TOP + 22, 77),
                by(TOP + 23, 88),
            ];
            let got = archive::archive_put(r, run, top, 0, &frame, (top, top + 23))
                .await
                .unwrap();
            assert_eq!(got, (2, 2), "the one held stays");

            // An emote, and how far everything is
            let emote = import::emote(r, run, 701, "wave").await.unwrap();
            assert!(matches!(
                emote,
                AccountReply::Admin(AdminReply::ImportAcked {
                    stored: 1,
                    skipped: 0
                })
            ));
            let emote = import::emote(r, run, 701, "wave").await.unwrap();
            assert!(matches!(
                emote,
                AccountReply::Admin(AdminReply::ImportAcked {
                    stored: 0,
                    skipped: 1
                })
            ));
            let AccountReply::Admin(AdminReply::ImportCursors { rows, more }) =
                import::cursors(r, 0).await.unwrap()
            else {
                panic!()
            };
            assert!(!more);
            assert_eq!(
                rows,
                [
                    (701, 1),
                    (TOP, TOP + 23),
                    (TOP + 1, 0),
                    (TOP + 2, 0),
                    (TOP + 11, TOP + 12),
                ]
            );
            let (counted,): (i64,) = db!(store, pool => {
                sqlx::query_as("SELECT CAST(archive_rows AS BIGINT) FROM voipc_imports WHERE id = $1")
                    .bind(run)
                    .fetch_one(pool)
                    .await
                    .unwrap()
            });
            assert_eq!(counted, 5);
        }
    }

    #[test]
    fn the_decoy_lengths_match_a_real_vault() {
        use voipc_crypto::account::{Vault, ITEM_IDENTITY};
        let vault = Vault::create([7; 16], "alice");
        let identity = voipc_crypto::generate_identity_key_pair();
        let item = vault.seal_item(ITEM_IDENTITY, 1, &identity.serialize());
        assert_eq!(item.v.len(), ITEM_IDENTITY_LEN);
        assert_eq!(vault.recovery_slot(&[3; 32]).v.len(), SLOT_LEN);
    }
}
