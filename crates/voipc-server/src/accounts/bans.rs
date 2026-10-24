//! `voipc_bans`: the database half of `crate::bans`.

use anyhow::Result;
use l4f_accounts::store::Store;

use super::Relay;
use crate::bans::{Ban, Key};

type Row = (i64, Option<Vec<u8>>, Option<Vec<u8>>, String, String, String, i64, Option<i64>);

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
            let id: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(MAX(id), 0) + 1 AS BIGINT) FROM voipc_bans").fetch_one(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO voipc_bans (id, addr_key, account, label, reason, by_name, created_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(id)
            .bind(addr)
            .bind(account)
            .bind(&ban.label)
            .bind(&ban.reason)
            .bind(&ban.by)
            .bind(ban.created_at)
            .bind(ban.expires_at)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            id
        });
        Ok(id as u64)
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
            sqlx::query_as("SELECT id, addr_key, account, label, reason, by_name, created_at, expires_at FROM voipc_bans").fetch_all(pool).await?
        });
        Ok(rows
            .into_iter()
            .filter_map(|(id, addr, account, label, reason, by, created_at, expires_at)| {
                let key = match (addr, account) {
                    (Some(h), None) => Key::Addr(h.try_into().ok()?),
                    (None, Some(a)) => Key::Account(a.try_into().ok()?),
                    _ => return None,
                };
                Some((key, Ban { id: id as u64, label, reason, by, created_at, expires_at, addr: None }))
            })
            .collect())
    }
}
