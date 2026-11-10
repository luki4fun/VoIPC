//! `voipc_bans`: the database half of `crate::bans`.

use anyhow::Result;
use l4f_accounts::store::Store;

use super::Relay;
use crate::bans::{Ban, Key};

/// Out of every channel's log, or the writers go on wrapping each new key to them. A
/// direct conversation is not in these and stays.
const OUT_OF_LOGS: [&str; 2] = [
    "DELETE FROM voipc_members WHERE account = $1",
    "DELETE FROM voipc_pending WHERE owner = $1 OR recipient = $1",
];

type Row = (
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<String>,
);

impl Relay {
    /// The key address bans are hashed with.
    pub fn ban_key(&self) -> &[u8] {
        &self.ban_key
    }

    /// Keeps `ban` under `key`, in place of an earlier ban of the same
    /// address or account. Returns its id.
    pub async fn ban_put(&self, key: &Key, ban: &Ban) -> Result<u64> {
        let (addr, account) = match key {
            Key::Addr(h) => (Some(h.to_vec()), None),
            Key::Account(a) => (None, Some(a.to_vec())),
        };
        let id: i64 = db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            sqlx::query("DELETE FROM voipc_bans WHERE addr_key = $1 OR account = $2")
                .bind(addr.clone())
                .bind(account.clone())
                .execute(&mut *tx)
                .await?;
            if let Some(a) = &account {
                for q in OUT_OF_LOGS {
                    sqlx::query(q).bind(a).execute(&mut *tx).await?;
                }
            }
            let id: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(MAX(id), 0) + 1 AS BIGINT) FROM voipc_bans").fetch_one(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO voipc_bans (id, addr_key, account, label, reason, by_name, created_at, expires_at, alias)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(id)
            .bind(addr)
            .bind(account)
            .bind(&ban.label)
            .bind(&ban.reason)
            .bind(&ban.by)
            .bind(ban.created_at)
            .bind(ban.expires_at)
            .bind(&ban.alias)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            id
        });
        Ok(id as u64)
    }

    /// A banned account out of every channel's log, for a ban `ban_put` wrote in another
    /// process.
    pub async fn ban_out_of_logs(&self, account: &[u8; 16]) -> Result<()> {
        db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            for q in OUT_OF_LOGS {
                sqlx::query(q).bind(&account[..]).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        });
        Ok(())
    }

    /// Whether ban `id` was there.
    pub async fn ban_delete(&self, id: u64) -> Result<bool> {
        let n = db!(self.store(), pool => {
            sqlx::query("DELETE FROM voipc_bans WHERE id = $1").bind(id as i64).execute(pool).await?.rows_affected()
        });
        Ok(n > 0)
    }

    /// The bans still running at `now`; the expired ones are deleted.
    pub async fn ban_rows(&self, now: i64) -> Result<Vec<(Key, Ban)>> {
        let rows: Vec<Row> = db!(self.store(), pool => {
            sqlx::query("DELETE FROM voipc_bans WHERE expires_at IS NOT NULL AND expires_at <= $1").bind(now).execute(pool).await?;
            sqlx::query_as("SELECT id, addr_key, account, label, reason, by_name, created_at, expires_at, alias FROM voipc_bans").fetch_all(pool).await?
        });
        Ok(rows
            .into_iter()
            .filter_map(
                |(id, addr, account, label, reason, by, created_at, expires_at, alias)| {
                    let key = match (addr, account) {
                        (Some(h), None) => Key::Addr(h.try_into().ok()?),
                        (None, Some(a)) => Key::Account(a.try_into().ok()?),
                        _ => return None,
                    };
                    Some((
                        key,
                        Ban {
                            id: id as u64,
                            label,
                            reason,
                            by,
                            created_at,
                            expires_at,
                            addr: None,
                            alias,
                        },
                    ))
                },
            )
            .collect())
    }
}
