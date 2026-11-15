//! `voipc_profiles`: how a member chooses to be shown (1.9). Apart from l4f's
//! `display_name`, which a provider sign-up fills with a real name from Google:
//! only what somebody typed here becomes public.
//!
//! Asked for by account, and a change is told to everyone connected (`tell`): a
//! channel that hides its members, or names them by alias, shows no account, and a
//! change that goes to all puts a display name to none of its rows.
//!
//! The relay never decodes a picture. It checks what kind of file it says it is
//! and how big; every client sanitizes what it receives before showing it.

use std::sync::Arc;

use anyhow::Result;
use l4f_accounts::model::{AccountId, User};
use l4f_accounts::scope;
use l4f_accounts::store::Store;
use sha2::{Digest, Sha256};
use tracing::warn;
use voipc_protocol::messages::{AccountReply, ServerMessage};
use voipc_protocol::types::{
    ProfileInfo, SessionId, MAX_DISPLAY_NAME_CHARS, MAX_PROFILES_ASKED, MAX_PROFILE_PICTURE,
    MAX_SERVER_DESCRIPTION_CHARS, MAX_SERVER_NAME_CHARS,
};

use super::{refused, Relay};
use crate::control::ControlTx;
use crate::session::{ascii_look_alike, bad_name_char, send_msg};
use crate::state::ServerState;
use voipc_protocol::names::draws_nothing;

type Row = (Vec<u8>, Option<String>, Option<Vec<u8>>);

pub(super) const TOO_FAST: &str = "That was a lot of changes. Give it a moment.";
const SRV_NAME: &str = "srv_name";
const SRV_DESCRIPTION: &str = "srv_description";
const SRV_ICON: &str = "srv_icon";
const SRV_ICON_HASH: &str = "srv_icon_hash";

impl Relay {
    /// Everyone asked about is answered, so nobody asks again, and an account that
    /// does not exist reads the same as one with no profile.
    pub async fn profiles(&self, accounts: &[[u8; 16]]) -> Result<Vec<ProfileInfo>> {
        if accounts.is_empty() {
            return Ok(Vec::new());
        }
        let marks: Vec<String> = (1..=accounts.len()).map(|i| format!("${i}")).collect();
        let sql = format!(
            "SELECT account, display_name, picture_hash FROM voipc_profiles WHERE account IN ({})",
            marks.join(", ")
        );
        let rows: Vec<Row> = db!(self.store(), pool => {
            // Numbered marks and nothing a client said
            let mut q = sqlx::query_as(sqlx::AssertSqlSafe(sql.clone()));
            for a in accounts {
                q = q.bind(&a[..]);
            }
            q.fetch_all(pool).await?
        });
        Ok(accounts
            .iter()
            .map(|a| {
                let row = rows.iter().find(|r| r.0 == a[..]);
                ProfileInfo {
                    account: *a,
                    name: row.and_then(|r| r.1.clone()),
                    picture: row
                        .and_then(|r| r.2.as_deref())
                        .and_then(|h| h.try_into().ok()),
                }
            })
            .collect())
    }

    pub async fn profile_name_put(&self, account: AccountId, name: Option<&str>) -> Result<()> {
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_profiles (account, display_name) VALUES ($1, $2) \
                 ON CONFLICT (account) DO UPDATE SET display_name = excluded.display_name",
            )
            .bind(&account.0[..])
            .bind(name)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    pub async fn profile_picture_put(
        &self,
        account: AccountId,
        image: Option<&[u8]>,
    ) -> Result<()> {
        let hash = image.map(|i| Sha256::digest(i).to_vec());
        db!(self.store(), pool => {
            sqlx::query(
                "INSERT INTO voipc_profiles (account, picture_hash, picture) VALUES ($1, $2, $3) \
                 ON CONFLICT (account) DO UPDATE SET picture_hash = excluded.picture_hash, \
                 picture = excluded.picture",
            )
            .bind(&account.0[..])
            .bind(hash.as_deref())
            .bind(image)
            .execute(pool)
            .await?;
        });
        Ok(())
    }

    /// A profile picture by its hash, or the server's icon.
    pub async fn profile_picture(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let image: Option<Option<Vec<u8>>> = db!(self.store(), pool => {
            sqlx::query_scalar("SELECT picture FROM voipc_profiles WHERE picture_hash = $1 LIMIT 1")
                .bind(&hash[..])
                .fetch_optional(pool)
                .await?
        });
        if let Some(image) = image.flatten() {
            return Ok(Some(image));
        }
        if self.meta_of(SRV_ICON_HASH).await?.as_deref() == Some(&hash[..]) {
            return self.meta_of(SRV_ICON).await;
        }
        Ok(None)
    }

    async fn meta_of(&self, k: &str) -> Result<Option<Vec<u8>>> {
        Ok(db!(self.store(), pool => {
            sqlx::query_scalar("SELECT v FROM voipc_meta WHERE k = $1")
                .bind(k)
                .fetch_optional(pool)
                .await?
        }))
    }

    /// Writes `v`, or deletes the row.
    async fn meta_put(&self, k: &str, v: Option<&[u8]>) -> Result<()> {
        db!(self.store(), pool => {
            match v {
                Some(v) => {
                    sqlx::query(
                        "INSERT INTO voipc_meta (k, v) VALUES ($1, $2) \
                         ON CONFLICT (k) DO UPDATE SET v = excluded.v",
                    )
                    .bind(k)
                    .bind(v)
                    .execute(pool)
                    .await?;
                }
                None => {
                    sqlx::query("DELETE FROM voipc_meta WHERE k = $1")
                        .bind(k)
                        .execute(pool)
                        .await?;
                }
            }
        });
        Ok(())
    }

    pub async fn server_profile_put(&self, name: &str, description: &str) -> Result<()> {
        self.meta_put(SRV_NAME, Some(name.as_bytes())).await?;
        self.meta_put(SRV_DESCRIPTION, Some(description.as_bytes()))
            .await
    }

    pub async fn server_icon_put(&self, image: Option<&[u8]>) -> Result<()> {
        let hash = image.map(|i| Sha256::digest(i).to_vec());
        self.meta_put(SRV_ICON, image).await?;
        self.meta_put(SRV_ICON_HASH, hash.as_deref()).await
    }

    /// The name to keep, `None` to clear it, or why not.
    pub(super) async fn display_name_ok(
        &self,
        user: &User,
        name: &str,
    ) -> Result<Option<String>, String> {
        let name = name.trim();
        if name.is_empty() {
            return Ok(None);
        }
        if name.chars().count() > MAX_DISPLAY_NAME_CHARS {
            return Err(format!("Keep it to {MAX_DISPLAY_NAME_CHARS} characters."));
        }
        if name.chars().any(refused_in_a_display_name) || scope::clean_display_name(name).is_err() {
            return Err("That name has characters that cannot be shown.".into());
        }
        // It stands next to the real `@name`, and these would pass for one
        let bare: String = name.chars().filter(|c| !draws_nothing(*c)).collect();
        let bare = bare.trim();
        if bare
            .chars()
            .any(|c| matches!(c, '@' | '\u{ff20}' | '\u{fe6b}'))
            || has_tag_tail(bare)
        {
            return Err("A display name cannot hold an @ or end in a #tag.".into());
        }
        let like = ascii_look_alike(bare);
        for shape in [Some(bare), like.as_deref()].into_iter().flatten() {
            let someone_else = !shape.eq_ignore_ascii_case(&user.username);
            if someone_else && super::placeholder::kept_for_the_move(shape) {
                return Err(super::placeholder::KEPT_FOR_THE_MOVE.into());
            }
            if someone_else && self.is_account_name(shape).await.unwrap_or(true) {
                return Err("That is another account's name.".into());
            }
        }
        Ok(Some(name.to_string()))
    }
}

/// `bad_name_char`, but for what joins an emoji or spells a word in some scripts:
/// those are read without when comparing (`draws_nothing`), and refused nowhere else
/// a display name goes.
fn refused_in_a_display_name(c: char) -> bool {
    bad_name_char(c) && !matches!(c, '\u{200c}' | '\u{200d}')
}

/// Ends like `#1234`, in full width too.
fn has_tag_tail(name: &str) -> bool {
    let tail: Vec<char> = name.chars().rev().take(5).collect();
    tail.len() == 5
        && matches!(tail[4], '#' | '\u{ff03}' | '\u{fe5f}')
        && tail[..4].iter().all(|c| c.is_numeric())
}

/// A PNG or a WebP, by its first bytes, and small enough to hand around.
pub fn picture_ok(image: &[u8]) -> bool {
    let png = image.starts_with(b"\x89PNG\r\n\x1a\n");
    let webp = image.len() >= 12 && image.starts_with(b"RIFF") && &image[8..12] == b"WEBP";
    (png || webp) && image.len() <= MAX_PROFILE_PICTURE
}

/// A name or a picture is public text. Clearing one's own stays open.
const HELD: &str = "You cannot set a display name or picture on this server for now.";

fn held(state: &ServerState, session_id: SessionId) -> bool {
    state
        .sessions
        .get(&session_id)
        .is_some_and(|s| s.silence.text())
}

/// `AccountRequest::ProfileSet`.
pub async fn set_name(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: SessionId,
    user: &User,
    name: Option<String>,
) -> Result<AccountReply> {
    let name = match relay
        .display_name_ok(user, name.as_deref().unwrap_or(""))
        .await
    {
        Ok(name) => name,
        Err(reason) => return Ok(refused("ProfileSet", &reason)),
    };
    if name.is_some() && held(state, session_id) {
        return Ok(refused("ProfileSet", HELD));
    }
    // Cheap to store and expensive to announce, like all a client says about itself
    let now = relay.profiles(&[user.id.0]).await?;
    if now[0].name == name {
        return Ok(AccountReply::ProfileDone);
    }
    if !state.spend(session_id, |s| &mut s.state_change_rate) {
        return Ok(refused("ProfileSet", TOO_FAST));
    }
    relay.profile_name_put(user.id, name.as_deref()).await?;
    tell(state, relay, user.id.0).await;
    Ok(AccountReply::ProfileDone)
}

/// `AccountRequest::ProfilePictureSet`.
pub async fn set_picture(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: SessionId,
    user: &User,
    image: Option<Vec<u8>>,
) -> Result<AccountReply> {
    if image.as_deref().is_some_and(|i| !picture_ok(i)) {
        return Ok(refused(
            "ProfilePictureSet",
            "A profile picture is a PNG or WebP of at most 32 KB.",
        ));
    }
    if image.is_some() && held(state, session_id) {
        return Ok(refused("ProfilePictureSet", HELD));
    }
    let hash: Option<[u8; 32]> = image.as_deref().map(|i| Sha256::digest(i).into());
    if relay.profiles(&[user.id.0]).await?[0].picture == hash {
        return Ok(AccountReply::ProfileDone);
    }
    if !state.spend(session_id, |s| &mut s.state_change_rate) {
        return Ok(refused("ProfilePictureSet", TOO_FAST));
    }
    relay.profile_picture_put(user.id, image.as_deref()).await?;
    tell(state, relay, user.id.0).await;
    Ok(AccountReply::ProfileDone)
}

/// `ClientMessage::ProfilesGet`. Guests may ask: they see the same names on rows.
pub async fn answer_profiles(
    state: &ServerState,
    session_id: SessionId,
    accounts: &[[u8; 16]],
    tx: &ControlTx,
) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    if accounts.len() > MAX_PROFILES_ASKED || !state.spend(session_id, |s| &mut s.profile_rate) {
        return;
    }
    match relay.profiles(accounts).await {
        Ok(profiles) => {
            let _ = send_msg(tx, &ServerMessage::Profiles { profiles });
        }
        Err(e) => warn!("reading profiles: {e:#}"),
    }
}

/// `ClientMessage::ProfilePictureGet`. Empty when there is no such picture.
pub async fn answer_picture(
    state: &ServerState,
    session_id: SessionId,
    hash: [u8; 32],
    tx: &ControlTx,
) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    if !state.spend(session_id, |s| &mut s.profile_rate) {
        return;
    }
    match relay.profile_picture(&hash).await {
        Ok(image) => {
            let image = image.unwrap_or_default();
            let _ = send_msg(tx, &ServerMessage::ProfilePicture { hash, image });
        }
        Err(e) => warn!("reading a profile picture: {e:#}"),
    }
}

/// A change, to everyone connected, also when the account has gone (a moderator's clear).
/// Whoever may ask about it is anyone, since `ProfilesGet` answers any id, and whoever sees the
/// account may stand outside its channels: under a public roster, or with its old messages
/// open (W3-21). Going to all, it says nothing of where that account stands, so it ties no
/// row of a channel that hides its people, or names them by alias, to the account.
pub async fn tell(state: &ServerState, relay: &Relay, account: [u8; 16]) {
    match relay.profiles(&[account]).await {
        Ok(profiles) => {
            let msg = ServerMessage::Profiles { profiles };
            crate::session::broadcast_to_all(state, &msg, None).await;
        }
        Err(e) => warn!("reading a profile: {e:#}"),
    }
}

/// A server's name, or why not. It stands beside the address, so it may not look
/// like another address: a client ignores one that does.
pub fn server_name_ok(name: &str) -> Result<&str, String> {
    let name = name.trim();
    if name.chars().count() > MAX_SERVER_NAME_CHARS {
        return Err(format!(
            "Keep the name to {MAX_SERVER_NAME_CHARS} characters."
        ));
    }
    if name.chars().any(bad_name_char) {
        return Err("That name has characters that cannot be shown.".into());
    }
    if name.split_whitespace().any(looks_like_an_address) {
        return Err("A name that looks like an address would be mistaken for one.".into());
    }
    Ok(name)
}

/// A word that reads as where a server is: `chat.example.org`, `10.0.0.1:9987`, `:443`,
/// `[::1]:9987`, `https://anything`, `chat.example.org/join`. `v1.2`, `St.` and `A:B` do
/// not. `looksLikeAnAddress` in profile-rules.ts is this, and both are tested on one list.
fn looks_like_an_address(word: &str) -> bool {
    let word = word.trim_matches(|c| "()[],;.<>\"'".contains(c));
    if word.contains("://") {
        return true;
    }
    let word = word.split('/').next().unwrap_or("");
    if word.chars().filter(|c| *c == ':').count() >= 2 {
        return true;
    }
    let (host, port) = word.rsplit_once(':').unwrap_or((word, ""));
    if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let plain = labels
        .iter()
        .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    let last = labels[labels.len() - 1];
    let dotted_quad =
        labels.len() == 4 && labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit()));
    labels.len() >= 2
        && plain
        && (dotted_quad || (last.len() >= 2 && last.chars().all(|c| c.is_ascii_alphabetic())))
}

/// Plain text: line breaks, and otherwise what a name may hold.
pub fn server_description_ok(text: &str) -> Result<&str, String> {
    let text = text.trim();
    if text.chars().count() > MAX_SERVER_DESCRIPTION_CHARS {
        return Err(format!(
            "Keep it to {MAX_SERVER_DESCRIPTION_CHARS} characters."
        ));
    }
    if text.chars().any(|c| c != '\n' && bad_name_char(c)) {
        return Err("That text has characters that cannot be shown.".into());
    }
    Ok(text)
}

/// What the server says about itself right now. Settings are the fallback, and
/// are held to the same rules: a bad one reads as none.
pub async fn server_profile(state: &ServerState) -> ServerMessage {
    let mut name = state
        .settings
        .server_name
        .as_deref()
        .and_then(|n| server_name_ok(n).ok())
        .unwrap_or_default()
        .to_string();
    let mut description = state
        .settings
        .server_description
        .as_deref()
        .and_then(|d| server_description_ok(d).ok())
        .unwrap_or_default()
        .to_string();
    let mut icon = None;
    if let Some(relay) = state.accounts.as_ref() {
        let text = |v: Option<Vec<u8>>| v.and_then(|b| String::from_utf8(b).ok());
        if let Ok(Some(n)) = relay.meta_of(SRV_NAME).await.map(text) {
            name = n;
        }
        if let Ok(Some(d)) = relay.meta_of(SRV_DESCRIPTION).await.map(text) {
            description = d;
        }
        icon = relay
            .meta_of(SRV_ICON_HASH)
            .await
            .ok()
            .flatten()
            .and_then(|h| h.as_slice().try_into().ok());
    }
    ServerMessage::ServerProfile {
        name,
        description,
        icon,
    }
}

/// At connect, when it says anything.
pub async fn send_server_profile(state: &ServerState, tx: &ControlTx) {
    let read = || async {
        let msg = server_profile(state).await;
        if !matches!(&msg, ServerMessage::ServerProfile { name, description, icon }
            if !name.is_empty() || !description.is_empty() || icon.is_some())
        {
            return Some(Vec::new());
        }
        voipc_protocol::codec::encode_server_msg(&msg)
            .inspect_err(|e| warn!("telling the server's profile: {e:#}"))
            .ok()
            .map(|data| vec![data])
    };
    // Read once for all who connect a while (`at_connect`)
    let frames = match state.accounts.as_ref() {
        Some(relay) => relay.at_connect.profile.frames(read).await,
        None => read().await.map(Arc::new),
    };
    for data in frames.iter().flat_map(|f| f.iter()) {
        let _ = tx.try_send(data.clone());
    }
}

/// After a change, to everybody. Those who connect next read again.
pub async fn send_server_profile_all(state: &ServerState) {
    if let Some(relay) = state.accounts.as_ref() {
        relay.at_connect.profile.changed();
    }
    let msg = server_profile(state).await;
    for s in state.sessions.iter() {
        let _ = send_msg(&s.control_tx, &msg);
    }
}
