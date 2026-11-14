//! `voipc_gates`: the database half of `crate::gates`, and its stored-log
//! members.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use l4f_accounts::model::AccountId;
use l4f_accounts::store::Store;
use tokio::task::JoinSet;
use tracing::warn;
use voipc_protocol::types::ChannelGate;

use super::{is_star, log, Relay};

/// Accounts a gate pass decides at once: reads side by side, on SQLite's WAL as on Postgres.
const DECIDE_AT_ONCE: usize = 8;

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
        // `standing`'s groups, without the badges it also reads (W2-1)
        let roles = self.store().user_roles(user.id).await?;
        Ok(Held::Groups(
            super::counted(&roles, &scopes)
                .into_iter()
                .map(|r| r.name.clone())
                .collect(),
        ))
    }

    /// The stored members of each gated log (its conv, its gate's groups) outside its
    /// groups, out of it. Each account is decided once a pass, `DECIDE_AT_ONCE` at a time:
    /// most of the same accounts sit in every gated log, and each is three reads (W2-1).
    /// One that cannot be decided keeps its seats until the next pass.
    pub async fn prune_gated(self: &Arc<Self>, gated: &[(String, Vec<String>)]) {
        let mut seats = Vec::new();
        for (i, (conv, _)) in gated.iter().enumerate() {
            match members_of(self.store(), conv).await {
                Ok(m) => seats.extend(
                    m.iter()
                        .filter_map(|a| <[u8; 16]>::try_from(a.as_slice()).ok())
                        .map(|a| (i, a)),
                ),
                Err(e) => warn!("keeping {conv} to its gate: {e:#}"),
            }
        }
        let accounts: HashSet<[u8; 16]> = seats.iter().map(|(_, a)| *a).collect();
        let decided = self.decide(accounts).await;
        for (i, account) in seats {
            let (conv, groups) = &gated[i];
            if decided.get(&account).is_some_and(|h| !h.passes(groups)) {
                if let Err(e) = log::unseat(self.store(), conv, &account).await {
                    warn!("keeping {conv} to its gate: {e:#}");
                }
            }
        }
    }

    /// What gates ask of each of `accounts`; those whose reads failed are not in it.
    async fn decide(self: &Arc<Self>, accounts: HashSet<[u8; 16]>) -> HashMap<[u8; 16], Held> {
        let mut out = HashMap::with_capacity(accounts.len());
        let mut failed = 0usize;
        let mut running = JoinSet::new();
        let mut left = accounts.into_iter();
        loop {
            while running.len() < DECIDE_AT_ONCE {
                let Some(a) = left.next() else { break };
                let relay = self.clone();
                running.spawn(async move { (a, relay.held_by(AccountId(a)).await) });
            }
            let Some(done) = running.join_next().await else {
                break;
            };
            match done {
                Ok((a, Ok(held))) => {
                    out.insert(a, held);
                }
                Ok((_, Err(e))) => {
                    if failed == 0 {
                        warn!("reading who passes the gates: {e:#}");
                    }
                    failed += 1;
                }
                Err(_) => failed += 1,
            }
        }
        if failed > 0 {
            warn!("{failed} accounts keep their seats in gated logs until the next pass");
        }
        out
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
