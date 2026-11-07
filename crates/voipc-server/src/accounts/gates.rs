//! `voipc_gates`: the database half of `crate::gates`, and its stored-log
//! members.

use std::collections::hash_map::{Entry, HashMap};

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::store::Store;
use voipc_protocol::types::ChannelGate;

use super::{is_star, log, Relay};

fn split(list: &str) -> Vec<String> {
    list.split_whitespace().map(String::from).collect()
}

/// What gates ask of an account, signed in or not.
pub enum Held {
    /// `*`.
    Everything,
    Groups(Vec<String>),
}

impl Held {
    fn passes(&self, groups: &[String]) -> bool {
        match self {
            Held::Everything => true,
            Held::Groups(held) => held.iter().any(|g| groups.contains(g)),
        }
    }
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

    async fn held_by(&self, account: AccountId) -> Result<Held> {
        let Some(user) = self.store().user_by_id(account).await? else {
            return Ok(Held::Groups(Vec::new()));
        };
        let scopes = self.accounts.effective_scopes(&user).await?;
        if is_star(&scopes) {
            return Ok(Held::Everything);
        }
        Ok(Held::Groups(self.standing(&user, &scopes).await?.groups))
    }

    /// The stored members of `conv` outside `groups`, out of it. `decided` is shared across a
    /// pass: most of the same accounts sit in every gated log, and each is four queries.
    pub async fn prune_log(
        &self,
        conv: &str,
        groups: &[String],
        decided: &mut HashMap<[u8; 16], Held>,
    ) -> Result<()> {
        let members: Vec<Vec<u8>> = members_of(self.store(), conv).await?;
        for m in members {
            let Ok(id) = <[u8; 16]>::try_from(m.as_slice()) else {
                continue;
            };
            let held = match decided.entry(id) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => e.insert(self.held_by(AccountId(id)).await?),
            };
            if !held.passes(groups) {
                log::unseat(self.store(), conv, &id).await?;
            }
        }
        Ok(())
    }

    /// `account` out of those of `convs` it holds a seat in.
    pub async fn out_of_logs(&self, account: &[u8; 16], convs: &[String]) -> Result<()> {
        let seats: Vec<String> = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT conv FROM voipc_members WHERE account = $1")
                .bind(&account[..])
                .fetch_all(pool)
                .await?
        });
        for conv in seats.iter().filter(|s| convs.contains(s)) {
            log::unseat(self.store(), conv, account).await?;
        }
        Ok(())
    }
}

async fn members_of(store: &Store, conv: &str) -> Result<Vec<Vec<u8>>> {
    Ok(db!(store, pool => {
        sqlx::query_scalar("SELECT account FROM voipc_members WHERE conv = $1").bind(conv).fetch_all(pool).await?
    }))
}
