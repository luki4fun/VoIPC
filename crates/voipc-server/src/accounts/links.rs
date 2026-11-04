//! Reusable invite links (1.9): one code many people sign up with, on a relay of
//! any sign-up mode but `closed`, for a community's move post or its website.
//!
//! A link cannot be l4f's invite: that is single-use, and a list of them is what
//! the panel shows row by row. So each sign-up mints one bound to the name, spends
//! it at once and deletes it. A link is public by nature, so unlike a code it does
//! not stand in for the proof of work and counts against the same sign-up caps.
//!
//! Its starting group holds no privileges: anyone with the link gets it. That is
//! checked when it is made and again at each use, since a group can be given
//! power later, and then the link stops handing it out.

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::pow;
use l4f_accounts::scope;
use l4f_accounts::service::{Ctx, Error, Host, InviteForm, NewSession};
use l4f_accounts::store::Store;
use l4f_accounts::util;
use sha2::{Digest, Sha256};
use tracing::warn;
use voipc_protocol::types::InviteLinkInfo;

use super::Relay;
use crate::config::RegistrationMode;

/// 32 bytes as unpadded base64url. l4f's own codes are 22.
const CODE_LEN: usize = 43;
/// Links kept at once: one frame lists them.
pub const MAX_LINKS: i64 = 100;
pub const MAX_USES: u32 = 100_000;
pub const MAX_DAYS: u32 = 365;
pub const GONE: &str = "That invite link is not valid any more.";

pub fn is_link_code(code: &str) -> bool {
    code.trim().len() == CODE_LEN
}

fn hash_of(code: &str) -> Option<[u8; 32]> {
    let raw: [u8; 32] = util::b64u_dec(code.trim())?.try_into().ok()?;
    Some(Sha256::digest(raw).into())
}

type Row = (Vec<u8>, i64, i64, Option<i64>, Option<String>);

struct CountsUnlessRefused<'a> {
    permit: Option<pow::Permit>,
    limiter: &'a l4f_accounts::limit::RateLimiter,
}

impl Drop for CountsUnlessRefused<'_> {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            permit.commit(self.limiter);
        }
    }
}

/// What a use of a link is on: its name in the audit, its starting group and who made it.
struct Taken {
    id: String,
    group: Option<String>,
    made_by: Option<AccountId>,
}

impl Relay {
    /// A new link, its code shown once, and its id. `None`: the list is full.
    pub async fn link_new(
        &self,
        max_uses: u32,
        days: u32,
        group: Option<&str>,
        made_by: AccountId,
    ) -> Result<Option<(String, String)>> {
        let now = util::now();
        let raw: [u8; 32] = rand::random();
        let hash = Sha256::digest(raw).to_vec();
        let expires_at = (days > 0).then(|| now + i64::from(days) * 86_400);
        let inserted = db!(self.store(), pool => {
            // What ran out goes first, and the list stays what the panel can show
            sqlx::query("DELETE FROM voipc_invite_links WHERE expires_at IS NOT NULL AND expires_at <= $1")
                .bind(now)
                .execute(pool)
                .await?;
            sqlx::query(
                "INSERT INTO voipc_invite_links (hash, max_uses, uses, expires_at, role_name, created_at, created_by) \
                 SELECT $1, $2, 0, $3, $4, $5, $6 \
                 WHERE (SELECT COUNT(*) FROM voipc_invite_links) < $7",
            )
            .bind(&hash)
            .bind(max_uses as i32)
            .bind(expires_at)
            .bind(group)
            .bind(now)
            .bind(&made_by.0[..])
            .bind(MAX_LINKS)
            .execute(pool)
            .await?
            .rows_affected()
        });
        Ok((inserted == 1).then(|| (util::b64u(&raw), hex::encode(&hash[..8]))))
    }

    pub async fn links(&self) -> Result<Vec<InviteLinkInfo>> {
        let rows: Vec<Row> = db!(self.store(), pool => {
            sqlx::query_as(
                "SELECT hash, CAST(max_uses AS BIGINT), CAST(uses AS BIGINT), expires_at, role_name \
                 FROM voipc_invite_links ORDER BY created_at DESC",
            )
            .fetch_all(pool)
            .await?
        });
        Ok(rows
            .into_iter()
            .map(|(hash, max_uses, uses, expires_at, group)| InviteLinkInfo {
                id: hex::encode(&hash[..8]),
                max_uses: max_uses as u32,
                uses: uses as u32,
                expires_at,
                group,
            })
            .collect())
    }

    /// Whether there was such a link.
    pub async fn link_revoke(&self, id: &str) -> Result<bool> {
        let Some(hash) = self
            .links_hashes()
            .await?
            .into_iter()
            .find(|h| hex::encode(&h[..8]) == id)
        else {
            return Ok(false);
        };
        db!(self.store(), pool => {
            sqlx::query("DELETE FROM voipc_invite_links WHERE hash = $1")
                .bind(&hash)
                .execute(pool)
                .await?;
        });
        Ok(true)
    }

    async fn links_hashes(&self) -> Result<Vec<Vec<u8>>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar("SELECT hash FROM voipc_invite_links")
                .fetch_all(pool)
                .await?
        }))
    }

    /// Whether it would let one more person in right now.
    pub async fn link_usable(&self, code: &str) -> Result<bool> {
        let Some(hash) = hash_of(code) else {
            return Ok(false);
        };
        if self.registration == RegistrationMode::Closed {
            return Ok(false);
        }
        let found: Option<i64> = db!(self.store(), pool => {
            sqlx::query_scalar(
                "SELECT CAST(1 AS BIGINT) FROM voipc_invite_links WHERE hash = $1 AND uses < max_uses \
                 AND (expires_at IS NULL OR expires_at > $2)",
            )
            .bind(&hash[..])
            .bind(util::now())
            .fetch_optional(pool)
            .await?
        });
        Ok(found.is_some())
    }

    /// Takes one use. Two people on the last use: one gets it.
    async fn link_take(&self, hash: &[u8; 32]) -> Result<Option<Taken>> {
        let taken = db!(self.store(), pool => {
            sqlx::query(
                "UPDATE voipc_invite_links SET uses = uses + 1 WHERE hash = $1 AND uses < max_uses \
                 AND (expires_at IS NULL OR expires_at > $2)",
            )
            .bind(&hash[..])
            .bind(util::now())
            .execute(pool)
            .await?
            .rows_affected()
        });
        if taken != 1 {
            return Ok(None);
        }
        let row: Option<(Option<String>, Option<Vec<u8>>)> = db!(self.store(), pool => {
            sqlx::query_as("SELECT role_name, created_by FROM voipc_invite_links WHERE hash = $1")
                .bind(&hash[..])
                .fetch_optional(pool)
                .await?
        });
        let (group, made_by) = row.unwrap_or_default();
        Ok(Some(Taken {
            id: hex::encode(&hash[..8]),
            group,
            made_by: made_by.and_then(|b| b.try_into().ok()).map(AccountId),
        }))
    }

    #[cfg(test)]
    pub async fn links_all_expired(&self) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_invite_links SET expires_at = 1")
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    async fn link_refund(&self, hash: &[u8; 32]) {
        let r: Result<()> = async {
            db!(self.store(), pool => {
                sqlx::query("UPDATE voipc_invite_links SET uses = uses - 1 WHERE hash = $1 AND uses > 0")
                    .bind(&hash[..])
                    .execute(pool)
                    .await?;
            });
            Ok(())
        }
        .await;
        if let Err(e) = r {
            warn!("giving an invite link's use back: {e:#}");
        }
    }
}

/// What vouches for the new account.
pub enum How<'a> {
    Password(&'a str),
    /// The provider's sealed identity (`SocialOutcome::Signup`, `NoAccount`).
    Provider(&'a str),
}

/// Why a sign-up with a link did not go through.
pub enum Refused {
    /// The name: another may do.
    Name(String),
    End(String),
}

impl Refused {
    pub fn text(self) -> String {
        match self {
            Refused::Name(t) | Refused::End(t) => t,
        }
    }
}

fn the_end(reason: impl Into<String>) -> Refused {
    Refused::End(reason.into())
}

/// A sign-up with a link: the proof of work and caps of an open sign-up, then the
/// account, in its starting group. In `register`'s order: a taken or invalid name
/// costs neither the caps nor a use, or someone with the link could shut sign-up for
/// everybody with names that make no account. And one at a time, as there.
#[allow(clippy::too_many_arguments)]
pub async fn register(
    relay: &Relay,
    ctx: &Ctx,
    code: &str,
    name: &str,
    how: How<'_>,
    altcha: &str,
    ts: &str,
) -> Result<NewSession, Refused> {
    let hash = hash_of(code).ok_or_else(|| the_end(GONE))?;
    if relay.registration == RegistrationMode::Closed {
        return Err(the_end(GONE));
    }
    if altcha.is_empty() {
        return Err(the_end("The sign-up puzzle was not solved."));
    }
    let cfg = relay.accounts.host.config();
    let bucket = util::ip_key(ctx.ip);
    let gate = pow::Gate {
        limiter: &relay.accounts.limiter,
        key: &relay.pow_key,
        limits: &cfg.signup,
        ns: "acct-reg",
        bucket: &bucket,
    };
    let proof = pow::Proof {
        altcha,
        ts,
        ..Default::default()
    };
    let turn = relay.link_lock.lock().await;
    let no_js = gate.precheck(proof, true).map_err(|d| the_end(d.message))?;
    let reserved: Vec<&str> = cfg.reserved_usernames.iter().map(String::as_str).collect();
    let username =
        scope::normalize_username(name, &reserved).map_err(|e| Refused::Name(e.to_string()))?;
    let taken = relay.store().user_by_username(&username).await;
    if !matches!(taken, Ok(None)) {
        return Err(Refused::Name("That name is taken.".into()));
    }
    let permit = gate.caps(no_js).map_err(|d| the_end(d.message))?;
    let Some(link) = relay
        .link_take(&hash)
        .await
        .map_err(|_| the_end("Something went wrong. Please try again."))?
    else {
        return Err(the_end(GONE));
    };
    // Counted unless it was refused: Argon2 being busy with someone's login makes no
    // account and must cost none. A client that hangs up drops this future, maybe
    // after the account was made, so that counts too.
    let mut count = CountsUnlessRefused {
        permit: Some(permit),
        limiter: &relay.accounts.limiter,
    };
    let session = match with_minted_code(relay, ctx, name, how).await {
        Ok(s) => s,
        Err(e) => {
            count.permit = None;
            relay.link_refund(&hash).await;
            let text = e.message().to_string();
            return Err(match e {
                Error::UsernameTaken | Error::Invalid(_) => Refused::Name(text),
                _ => Refused::End(text),
            });
        }
    };
    drop(count);
    drop(turn);
    let new = session.info.user_id;
    // What l4f writes says the shell did this: here is who it really was
    let _ = relay
        .store()
        .audit(Some(new), link.made_by, "invite_link_used", &link.id, "")
        .await;
    if let Some(group) = link.group {
        // Holding nothing, this use too: it may have been given power since
        let empty =
            matches!(relay.store().role_by_name(&group).await, Ok(Some(r)) if r.scopes.is_empty());
        if empty {
            if let Err(e) = relay.accounts.grant_role_as_host(ctx, new, &group).await {
                warn!("an invite link's starting group: {}", e.message());
            }
        }
    }
    Ok(session)
}

async fn with_minted_code(
    relay: &Relay,
    ctx: &Ctx,
    name: &str,
    how: How<'_>,
) -> Result<NewSession, Error> {
    let code = relay
        .accounts
        .invite_create_as_host(ctx, Some(name), 1)
        .await?;
    let r = match how {
        How::Password(password) => {
            let form = InviteForm {
                code: &code,
                username: name,
                password,
                email: None,
                display_name: None,
            };
            relay.accounts.register_invite(ctx, form).await
        }
        How::Provider(cookie) => {
            relay
                .accounts
                .oauth_signup_invite(ctx, cookie, &code, name)
                .await
        }
    };
    // Spent or refused, it was only ever a step of this sign-up
    if let Some(raw) = util::b64u_dec(&code) {
        let hash: [u8; 32] = Sha256::digest(raw).into();
        let _ = relay.store().delete_invite(&hash).await;
    }
    r
}
