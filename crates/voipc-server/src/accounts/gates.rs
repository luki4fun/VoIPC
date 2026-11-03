//! `voipc_gates`: the database half of `crate::gates`, and its stored-log
//! members.

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::store::Store;
use voipc_protocol::types::ChannelGate;

use super::{is_star, log, Relay};

fn split(list: &str) -> Vec<String> {
    list.split_whitespace().map(String::from).collect()
}

impl Relay {
    /// Every kept gate, by its channel's key (`Channel::gate_key`).
    pub async fn gates(&self) -> Result<Vec<(String, ChannelGate)>> {
        let rows: Vec<(String, String, String)> = db!(self.store(), pool => {
            sqlx::query_as("SELECT conv, may_join, may_speak FROM voipc_gates").fetch_all(pool).await?
        });
        Ok(rows
            .into_iter()
            .map(|(k, join, speak)| {
                (
                    k,
                    ChannelGate {
                        groups: split(&join),
                        speakers: split(&speak),
                    },
                )
            })
            .collect())
    }

    /// Keeps `gate` for the channel under `key`; an open gate is no row.
    pub async fn gate_put(&self, key: &str, gate: &ChannelGate) -> Result<()> {
        let (join, speak) = (gate.groups.join(" "), gate.speakers.join(" "));
        db!(self.store(), pool => {
            if join.is_empty() && speak.is_empty() {
                sqlx::query("DELETE FROM voipc_gates WHERE conv = $1").bind(key).execute(pool).await?;
            } else {
                sqlx::query(
                    "INSERT INTO voipc_gates (conv, may_join, may_speak) VALUES ($1, $2, $3)
                     ON CONFLICT (conv) DO UPDATE SET may_join = excluded.may_join, may_speak = excluded.may_speak",
                )
                .bind(key)
                .bind(&join)
                .bind(&speak)
                .execute(pool)
                .await?;
            }
        });
        Ok(())
    }

    /// Whether an account, signed in or not, passes `groups` now.
    pub async fn passes_offline(&self, account: AccountId, groups: &[String]) -> Result<bool> {
        let Some(user) = self.store().user_by_id(account).await? else {
            return Ok(false);
        };
        let scopes = self.accounts.effective_scopes(&user).await?;
        if is_star(&scopes) {
            return Ok(true);
        }
        let standing = self.standing(&user, &scopes).await?;
        Ok(standing.groups.iter().any(|g| groups.contains(g)))
    }

    /// The stored members of `conv` outside `groups`, out of it.
    pub async fn prune_log(&self, conv: &str, groups: &[String]) -> Result<()> {
        let members: Vec<Vec<u8>> = members_of(self.store(), conv).await?;
        for m in members {
            let Ok(id) = <[u8; 16]>::try_from(m.as_slice()) else {
                continue;
            };
            if !self.passes_offline(AccountId(id), groups).await? {
                log::remove(self.store(), conv, &id).await?;
            }
        }
        Ok(())
    }
}

async fn members_of(store: &Store, conv: &str) -> Result<Vec<Vec<u8>>> {
    Ok(db!(store, pool => {
        sqlx::query_scalar("SELECT account FROM voipc_members WHERE conv = $1").bind(conv).fetch_all(pool).await?
    }))
}
