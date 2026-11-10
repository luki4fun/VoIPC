//! `voipc_channels`, `voipc_categories`: the database half of `crate::layout`.

use std::collections::HashMap;

use anyhow::Result;
use l4f_accounts::model::{AccountId, Role};
use l4f_accounts::store::Store;
use voipc_protocol::types::{ChannelCategory, ChannelGate, GroupStyle};

use super::import::{KIND_CATEGORY, KIND_CHANNEL};
use super::Relay;
use crate::channels::ChannelEntry;

type Row = (String, Option<String>, i64, Option<i64>);
type Rows = (Vec<Row>, Vec<(i64, String)>, Option<Vec<u8>>);

/// A row of `voipc_channels`.
pub struct KeptRow {
    pub conv: String,
    pub entry: Option<String>,
    pub position: i64,
    pub category: Option<u32>,
}

/// What the rows say at a start.
#[derive(Default)]
pub struct KeptRows {
    pub rows: Vec<KeptRow>,
    pub categories: Vec<ChannelCategory>,
    pub welcome: Option<String>,
}

/// One frame holds this many, at the largest a badge can be (32 characters).
const MAX_STYLED_GROUPS: usize = 400;

type StyleColumns = (Vec<u8>, Option<i64>, Option<i64>, bool);

struct StyleRow {
    color: Option<u32>,
    position: Option<i64>,
    no_section: bool,
}

/// How a group looks, as `groups_in_order` tells it.
pub struct GroupLook {
    pub color: Option<u32>,
    pub section: bool,
}

/// The sort key of a group: where it was put. Then, for one nobody has placed, those
/// with privileges and the built-in ones first: a name is no way to climb, and
/// someone who may make groups could otherwise call theirs `00-mine`.
fn rank(rows: &HashMap<Vec<u8>, StyleRow>, role: &Role) -> (i64, bool, bool, String) {
    let position = rows.get(&role.id.0[..]).and_then(|r| r.position);
    (
        position.unwrap_or(i64::MAX),
        role.scopes.is_empty(),
        !role.builtin,
        role.name.clone(),
    )
}

impl Relay {
    async fn style_rows(&self) -> Result<HashMap<Vec<u8>, StyleRow>> {
        let rows: Vec<StyleColumns> = db!(self.store(), pool => {
            sqlx::query_as("SELECT role, CAST(color AS BIGINT), CAST(position AS BIGINT), no_section FROM voipc_group_style")
                .fetch_all(pool)
                .await?
        });
        Ok(rows
            .into_iter()
            .map(|(role, color, position, no_section)| {
                let color = color.map(|c| c as u32 & 0xff_ffff);
                (
                    role,
                    StyleRow {
                        color,
                        position,
                        no_section,
                    },
                )
            })
            .collect())
    }

    /// Every group in the server's order, with how it looks.
    pub async fn groups_in_order(&self) -> Result<Vec<(Role, GroupLook)>> {
        let rows = self.style_rows().await?;
        let mut roles = self.store().roles().await?;
        roles.sort_by_cached_key(|r| rank(&rows, r));
        Ok(roles
            .into_iter()
            .map(|r| {
                let row = rows.get(&r.id.0[..]);
                let look = GroupLook {
                    color: row.and_then(|s| s.color),
                    section: !row.is_some_and(|s| s.no_section),
                };
                (r, look)
            })
            .collect())
    }

    /// What `ServerMessage::GroupStyles` says.
    pub async fn group_styles(&self) -> Result<Vec<GroupStyle>> {
        // Nothing stops two groups having one badge: the higher one speaks for it
        let mut seen = std::collections::HashSet::new();
        Ok(self
            .groups_in_order()
            .await?
            .into_iter()
            .filter_map(|(r, look)| {
                let badge = r.badge.filter(|b| !b.is_empty())?;
                seen.insert(badge.clone()).then_some(GroupStyle {
                    badge,
                    color: look.color,
                    section: look.section,
                })
            })
            .take(MAX_STYLED_GROUPS)
            .collect())
    }

    /// `roles`' badges, the ones to show first first.
    pub async fn badges_in_order(&self, roles: Vec<&Role>) -> Result<Vec<String>> {
        let rows = self.style_rows().await?;
        let mut roles = roles;
        roles.sort_by_cached_key(|r| rank(&rows, r));
        // A row draws its badges keyed by their text: two groups with one badge
        // would stop every client that shows this member
        let mut seen = std::collections::HashSet::new();
        Ok(roles
            .into_iter()
            .filter_map(|r| r.badge.clone().filter(|b| !b.is_empty()))
            .filter(|b| seen.insert(b.clone()))
            .collect())
    }

    pub async fn group_style_put(
        &self,
        role: AccountId,
        color: Option<u32>,
        section: bool,
    ) -> Result<()> {
        let color = color.map(|c| (c & 0xff_ffff) as i32);
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_group_style (role, color, no_section) VALUES ($1, $2, $3) \
                 ON CONFLICT (role) DO UPDATE SET color = excluded.color, no_section = excluded.no_section",
            )
            .bind(&role.0[..])
            .bind(color)
            .bind(!section)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    pub async fn group_position_put(&self, role: AccountId, position: i64) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_group_style (role, position) VALUES ($1, $2) \
                 ON CONFLICT (role) DO UPDATE SET position = excluded.position",
            )
            .bind(&role.0[..])
            .bind(position as i32)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    pub async fn layout_rows(&self) -> Result<KeptRows> {
        let (rows, categories, welcome): Rows = db!(self.store(), pool => {
            (
                sqlx::query_as("SELECT conv, entry, CAST(position AS BIGINT), CAST(category AS BIGINT) FROM voipc_channels ORDER BY position, conv")
                    .fetch_all(pool)
                    .await?,
                sqlx::query_as("SELECT CAST(id AS BIGINT), name FROM voipc_categories ORDER BY position, id")
                    .fetch_all(pool)
                    .await?,
                sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = 'welcome'")
                    .fetch_optional(pool)
                    .await?,
            )
        });
        Ok(KeptRows {
            rows: rows
                .into_iter()
                .map(|(conv, entry, position, category)| KeptRow {
                    conv,
                    entry,
                    position,
                    category: category.map(|c| c as u32),
                })
                .collect(),
            categories: categories
                .into_iter()
                .map(|(id, name)| ChannelCategory {
                    id: id as u32,
                    name,
                })
                .collect(),
            welcome: welcome.and_then(|v| String::from_utf8(v).ok()),
        })
    }

    /// A channel's row, its entry (`None`: only placed) and place.
    pub async fn layout_put(
        &self,
        conv: &str,
        entry: Option<&ChannelEntry>,
        position: i64,
        category: Option<u32>,
    ) -> Result<()> {
        let entry = entry.map(serde_json::to_string).transpose()?;
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_channels (conv, entry, position, category) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (conv) DO UPDATE SET entry = excluded.entry, position = excluded.position, category = excluded.category",
            )
            .bind(conv)
            .bind(&entry)
            .bind(position as i32)
            .bind(category.map(|c| c as i32))
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// A channel made in the app is gone: its row, its gate, its stored messages
    /// and the keys to them, all or none. Without its row a failure could not be
    /// tried again, and without its gate it would come back open.
    pub async fn channel_purge(&self, conv: &str) -> Result<()> {
        db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            for q in [
                "DELETE FROM voipc_channels WHERE conv = $1",
                "DELETE FROM voipc_gates WHERE conv = $1",
                "DELETE FROM voipc_log WHERE conv = $1",
                "DELETE FROM voipc_wraps WHERE conv = $1",
                "DELETE FROM voipc_writers WHERE conv = $1",
                "DELETE FROM voipc_log_floors WHERE conv = $1",
                "DELETE FROM voipc_left WHERE conv = $1",
                "DELETE FROM voipc_members WHERE conv = $1",
                "DELETE FROM voipc_pending WHERE conv = $1",
            ] {
                sqlx::query(q).bind(conv).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        });
        Ok(())
    }

    /// A channel the importer made: its gate, its row and the ledger's, all or none. Nothing
    /// half made is left for the next run to trip over, nor a channel with no gate on it.
    /// `archive_private` goes one way: an import never clears it.
    #[allow(clippy::too_many_arguments)]
    pub async fn import_channel_put(
        &self,
        run: i64,
        dc_id: u64,
        entry: &ChannelEntry,
        gate: &ChannelGate,
        position: i64,
        category: Option<u32>,
        private: bool,
    ) -> Result<()> {
        let conv = entry.log_conv();
        let text = serde_json::to_string(entry)?;
        let (join, speak) = (gate.groups.join(" "), gate.speakers.join(" "));
        db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            if join.is_empty() && speak.is_empty() {
                sqlx::query("DELETE FROM voipc_gates WHERE conv = $1").bind(&conv).execute(&mut *tx).await?;
            } else {
                sqlx::query(
                    "INSERT INTO voipc_gates (conv, may_join, may_speak) VALUES ($1, $2, $3)
                     ON CONFLICT (conv) DO UPDATE SET may_join = excluded.may_join, may_speak = excluded.may_speak",
                )
                .bind(&conv)
                .bind(&join)
                .bind(&speak)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "INSERT INTO voipc_channels (conv, entry, position, category, archive_private)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (conv) DO UPDATE SET entry = excluded.entry, position = excluded.position,
                   category = excluded.category,
                   archive_private = voipc_channels.archive_private OR excluded.archive_private",
            )
            .bind(&conv)
            .bind(&text)
            .bind(position as i32)
            .bind(category.map(|c| c as i32))
            .bind(private)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO voipc_import_items (kind, dc_id, import_id, local) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (kind, dc_id) DO NOTHING",
            )
            .bind(KIND_CHANNEL)
            .bind(dc_id as i64)
            .bind(run)
            .bind(&conv)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        });
        Ok(())
    }

    /// Categories the importer made, each with its Discord id and place, in one write.
    pub async fn import_categories_put(
        &self,
        run: i64,
        rows: &[(u64, ChannelCategory, i64)],
    ) -> Result<()> {
        db!(self.store(), pool => {
            let mut tx = pool.begin().await?;
            for (dc_id, c, position) in rows {
                sqlx::query(
                    "INSERT INTO voipc_categories (id, name, position) VALUES ($1, $2, $3)
                     ON CONFLICT (id) DO UPDATE SET name = excluded.name, position = excluded.position",
                )
                .bind(c.id as i32)
                .bind(&c.name)
                .bind(*position as i32)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO voipc_import_items (kind, dc_id, import_id, local) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (kind, dc_id) DO NOTHING",
                )
                .bind(KIND_CATEGORY)
                .bind(*dc_id as i64)
                .bind(run)
                .bind(c.id.to_string())
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        });
        Ok(())
    }

    pub async fn category_put(&self, c: &ChannelCategory, position: i64) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_categories (id, name, position) VALUES ($1, $2, $3)
                 ON CONFLICT (id) DO UPDATE SET name = excluded.name, position = excluded.position",
            )
            .bind(c.id as i32)
            .bind(&c.name)
            .bind(position as i32)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// The category goes; its channels stay, outside any. An import's row stays too, so that
    /// a delta does not make it again, but names nothing now: the next category made may
    /// get this id, and is nobody's import.
    pub async fn category_delete(&self, id: u32) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query("UPDATE voipc_channels SET category = NULL WHERE category = $1").bind(id as i32).execute(pool).await?;
            sqlx::query("DELETE FROM voipc_categories WHERE id = $1").bind(id as i32).execute(pool).await?;
            sqlx::query("UPDATE voipc_import_items SET local = '' WHERE kind = $1 AND local = $2")
                .bind(KIND_CATEGORY)
                .bind(id.to_string())
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    pub async fn welcome_put(&self, conv: Option<&str>) -> Result<()> {
        db!(self.store(), pool => {
            match conv {
                Some(conv) => {
                    sqlx::query("INSERT INTO voipc_meta (k, v) VALUES ('welcome', $1) ON CONFLICT (k) DO UPDATE SET v = excluded.v")
                        .bind(conv.as_bytes())
                        .execute(pool)
                        .await?;
                }
                None => {
                    sqlx::query("DELETE FROM voipc_meta WHERE k = 'welcome'").execute(pool).await?;
                }
            }
        });
        Ok(())
    }
}
