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

use super::{is_star, Relay};
use crate::gk::group::cause::GATE;

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
    /// groups, out of it, and out of its group: those seated there by a live follow alone
    /// too, whose seats outlive their connections (plan 2d). Each account is decided once a
    /// pass, `DECIDE_AT_ONCE` at a time: most of the same accounts sit in every gated log, and
    /// each is three reads (W2-1). One that cannot be decided keeps its seats until the next
    /// pass.
    pub async fn prune_gated(self: &Arc<Self>, gated: &[(String, Vec<String>)]) {
        let mut seats = HashSet::new();
        for (i, (conv, _)) in gated.iter().enumerate() {
            match self.held_in(conv).await {
                Ok(m) => seats.extend(m.into_iter().map(|a| (i, a))),
                Err(e) => warn!("keeping {conv} to its gate: {e:#}"),
            }
        }
        let accounts: HashSet<[u8; 16]> = seats.iter().map(|(_, a)| *a).collect();
        let decided = self.decide(accounts).await;
        // Each log's accounts out at once: one exit asked and one message to its group
        let mut out: HashMap<usize, Vec<[u8; 16]>> = HashMap::new();
        for (i, account) in seats {
            let (_, groups) = &gated[i];
            if decided.get(&account).is_some_and(|h| !h.passes(groups)) {
                out.entry(i).or_default().push(account);
            }
        }
        for (i, accounts) in out {
            let (conv, _) = &gated[i];
            if let Err(e) = self.gate_out(conv, &accounts).await {
                warn!("keeping {conv} to its gate: {e:#}");
            }
        }
    }

    /// Who holds a seat in `conv`'s log or, with the group key on, in its stored group
    /// (whose id is the conversation's).
    async fn held_in(&self, conv: &str) -> Result<Vec<[u8; 16]>> {
        let mut held: Vec<[u8; 16]> = members_of(self.store(), conv)
            .await?
            .iter()
            .filter_map(|a| <[u8; 16]>::try_from(a.as_slice()).ok())
            .collect();
        if self.gk().is_some() {
            held.extend(super::gk::seated_accounts(self.store(), conv).await?);
        }
        Ok(held)
    }

    /// `accounts` out of `conv`'s log and their seats in the conversation's group exit,
    /// whichever of the two each holds. The exit is asked first, so a stop while they are
    /// taken out still exits them at the group's next start (dive 4 F7), and goes to the group
    /// as one message, whatever a membership's delete did (the gate is the decision).
    async fn gate_out(&self, conv: &str, accounts: &[[u8; 16]]) -> Result<()> {
        let asked = self.gk_ask_exit(conv, accounts, GATE).await;
        let mut done = Ok(());
        for a in accounts {
            if let Err(e) = super::log::unseat(self.store(), conv, a).await {
                done = done.and(Err(e));
            }
        }
        if let Some(gk) = self.gk() {
            gk.exit_from_log(conv, accounts.to_vec(), GATE, asked);
        }
        done
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

    /// `account` out of those of `convs` it holds a seat in: in the log, or in the group by a
    /// live follow alone.
    pub async fn out_of_logs(&self, account: &[u8; 16], convs: &[String]) -> Result<()> {
        let mut seats: Vec<String> = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT conv FROM voipc_members WHERE account = $1")
                .bind(&account[..])
                .fetch_all(pool)
                .await?
        });
        if self.gk().is_some() {
            let groups = super::gk::seats_of_account(self.store(), account).await?;
            seats.extend(groups.into_iter().map(|(grp, _, _)| grp));
            seats.sort_unstable();
            seats.dedup();
        }
        for conv in seats.iter().filter(|s| convs.contains(s)) {
            self.gate_out(conv, &[*account]).await?;
        }
        Ok(())
    }
}

async fn members_of(store: &Store, conv: &str) -> Result<Vec<Vec<u8>>> {
    Ok(db!(store, pool => {
        sqlx::query_scalar("SELECT account FROM voipc_members WHERE conv = $1").bind(conv).fetch_all(pool).await?
    }))
}
