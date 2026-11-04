//! `voipc_restrictions`: the database half of `crate::restrict`.

use anyhow::Result;
use l4f_accounts::store::Store;

use super::Relay;
use crate::bans::Key;
use crate::restrict::Held;

type Row = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    bool,
    bool,
    String,
    String,
    Option<i64>,
);

fn columns(key: &Key) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    match key {
        Key::Addr(h) => (Some(h.to_vec()), None),
        Key::Account(a) => (None, Some(a.to_vec())),
    }
}

impl Relay {
    /// Keeps `held` under `key`, in place of an earlier one.
    pub async fn restriction_put(&self, key: &Key, held: &Held, now: i64) -> Result<()> {
        let (addr, account) = columns(key);
        db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            sqlx::query("DELETE FROM voipc_restrictions WHERE addr_key = $1 OR account = $2")
                .bind(addr.clone())
                .bind(account.clone())
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO voipc_restrictions (addr_key, account, no_voice, no_text, by_name, reason, created_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(addr)
            .bind(account)
            .bind(held.voice)
            .bind(held.text)
            .bind(&held.by)
            .bind(&held.reason)
            .bind(now)
            .bind(held.expires_at)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        });
        Ok(())
    }

    pub async fn restriction_delete(&self, key: &Key) -> Result<()> {
        let (addr, account) = columns(key);
        db!(self.store(), pool => {
            sqlx::query("DELETE FROM voipc_restrictions WHERE addr_key = $1 OR account = $2")
                .bind(addr)
                .bind(account)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    pub async fn restrictions_sweep(&self, now: i64) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("DELETE FROM voipc_restrictions WHERE expires_at IS NOT NULL AND expires_at <= $1")
                .bind(now)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// The restrictions still running at `now`; the rest are deleted.
    pub async fn restriction_rows(&self, now: i64) -> Result<Vec<(Key, Held)>> {
        self.restrictions_sweep(now).await?;
        let rows: Vec<Row> = db!(self.store(), pool => {
            sqlx::query_as("SELECT addr_key, account, no_voice, no_text, by_name, reason, expires_at FROM voipc_restrictions").fetch_all(pool).await?
        });
        Ok(rows
            .into_iter()
            .filter_map(|(addr, account, voice, text, by, reason, expires_at)| {
                let key = match (addr, account) {
                    (Some(h), None) => Key::Addr(h.try_into().ok()?),
                    (None, Some(a)) => Key::Account(a.try_into().ok()?),
                    _ => return None,
                };
                Some((
                    key,
                    Held {
                        voice,
                        text,
                        by,
                        reason,
                        expires_at,
                    },
                ))
            })
            .collect())
    }
}
