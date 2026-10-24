//! Bans that outlive a restart (1.0, A5). An address ban matches the address
//! as the connection limits see it (an IPv4 address, or an IPv6 /64); an
//! account ban matches the account wherever it signs in from.
//!
//! With accounts the list lives in the database (`voipc_bans`), which holds
//! a keyed hash of each address, never the address. A relay without accounts
//! has no database and no key: it keeps `bans.json` (0600) next to
//! `channels.json`, with the plain addresses. Either way the list is read at
//! start and again every `REVALIDATE_MINUTES`, which is how a ban made from
//! the shell (`voipc-server ban …`) reaches a running server.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use voipc_protocol::types::BanInfo;

use crate::state::ServerState;

/// What a ban matches.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Key {
    /// A keyed hash of the address as `limit_key` sees it.
    Addr([u8; 32]),
    Account([u8; 16]),
}

/// What gets banned.
pub enum Target {
    Addr(IpAddr),
    Account([u8; 16]),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ban {
    pub id: u64,
    /// The account's name, or the name the user went by when banned.
    pub label: String,
    pub reason: String,
    /// An account's name, "admin token" or "server shell".
    pub by: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; None = permanent.
    pub expires_at: Option<i64>,
    /// A relay without accounts: the address itself, for `bans.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<IpAddr>,
}

impl Ban {
    fn active(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|t| t > now)
    }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

/// The address's key: an HMAC under the relay's ban key (from the accounts
/// master key) or, without accounts, a key made at start (`bans.json` holds
/// the addresses, so nothing stored depends on it).
pub fn addr_key(state: &ServerState, ip: IpAddr) -> [u8; 32] {
    let secret = state.accounts.as_ref().map_or(&state.ban_salt[..], |r| r.ban_key());
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    ring::hmac::sign(&key, crate::limit_key(ip).to_string().as_bytes()).as_ref().try_into().expect("32 bytes")
}

fn key_of(state: &ServerState, target: &Target) -> Key {
    match target {
        Target::Addr(ip) => Key::Addr(addr_key(state, *ip)),
        Target::Account(a) => Key::Account(*a),
    }
}

/// The ban `key` falls under now, if any.
fn active(state: &ServerState, key: &Key) -> Option<Ban> {
    state.bans.get(key).map(|b| b.clone()).filter(|b| b.active(now_secs()))
}

/// At accept: an address ban refuses at once on a relay without accounts.
/// With accounts it waits for the sign-in, since someone holding a role here
/// gets past an address ban (people share addresses; 1.0 audit H1-07).
pub fn refused_at_accept(state: &ServerState, ip: IpAddr) -> bool {
    state.accounts.is_none() && !state.bans.is_empty() && active(state, &Key::Addr(addr_key(state, ip))).is_some()
}

/// Why a connection may not stay: its account's ban, else its address's,
/// unless the account (`account`: its id, and whether it holds a role here)
/// holds a role.
pub fn refusal(state: &ServerState, ip: IpAddr, account: Option<([u8; 16], bool)>) -> Option<String> {
    if state.bans.is_empty() {
        return None;
    }
    if let Some(b) = account.and_then(|(id, _)| active(state, &Key::Account(id))) {
        return Some(format!("This account is banned from this server: {}{}", b.reason, until(&b)));
    }
    if account.is_some_and(|(_, role)| role) {
        return None;
    }
    active(state, &Key::Addr(addr_key(state, ip))).map(|b| format!("You are banned from this server: {}{}", b.reason, until(&b)))
}

fn until(b: &Ban) -> String {
    match b.expires_at.map(|t| t - now_secs()) {
        None => String::new(),
        Some(s) if s < 3600 => format!(" (for {} more minutes)", (s / 60).max(1)),
        Some(s) if s < 2 * 86400 => format!(" (for {} more hours)", s / 3600),
        Some(s) => format!(" (for {} more days)", s / 86400),
    }
}

/// Bans `target` for `duration` (None = permanent) and keeps it. Replaces an
/// earlier ban of the same address or account.
pub async fn add(state: &ServerState, target: Target, label: &str, reason: &str, by: &str, duration: Option<Duration>) -> Result<Ban> {
    let now = now_secs();
    let key = key_of(state, &target);
    let mut ban = Ban {
        id: 0,
        label: label.chars().take(64).collect(),
        reason: reason.chars().take(200).collect(),
        by: by.chars().take(64).collect(),
        created_at: now,
        expires_at: duration.map(|d| now.saturating_add(d.as_secs().min(i64::MAX as u64) as i64)),
        addr: None,
    };
    if let Some(relay) = &state.accounts {
        ban.id = relay.ban_put(&key, &ban).await?;
    } else {
        let Target::Addr(ip) = target else { anyhow::bail!("this server has no accounts") };
        ban.addr = Some(crate::limit_key(ip));
        let _held = state.bans_writer.lock().unwrap_or_else(|p| p.into_inner());
        let mut list = read_file(state)?;
        list.retain(|b| b.addr != ban.addr);
        ban.id = list.iter().map(|b| b.id).max().unwrap_or(0) + 1;
        list.push(ban.clone());
        write_file(state, &list)?;
    }
    state.bans.insert(key, ban.clone());
    Ok(ban)
}

/// Lifts ban `id`. Whether there was one.
pub async fn remove(state: &ServerState, id: u64) -> Result<bool> {
    let found = if let Some(relay) = &state.accounts {
        relay.ban_delete(id).await?
    } else {
        let _held = state.bans_writer.lock().unwrap_or_else(|p| p.into_inner());
        let mut list = read_file(state)?;
        let before = list.len();
        list.retain(|b| b.id != id);
        write_file(state, &list)?;
        list.len() != before
    };
    let was_here = state.bans.iter().find(|e| e.value().id == id).map(|e| *e.key());
    if let Some(key) = was_here {
        state.bans.remove(&key);
    }
    Ok(found || was_here.is_some())
}

/// The active bans, accounts first, newest first within each.
pub fn list(state: &ServerState) -> Vec<BanInfo> {
    let now = now_secs();
    let mut bans: Vec<BanInfo> = state
        .bans
        .iter()
        .filter(|e| e.value().active(now))
        .map(|e| {
            let b = e.value();
            BanInfo {
                id: b.id,
                account: matches!(e.key(), Key::Account(_)),
                label: b.label.clone(),
                reason: b.reason.clone(),
                by: b.by.clone(),
                created_at: b.created_at.max(0) as u64,
                expires_in_secs: b.expires_at.map(|t| (t - now).max(0) as u64),
            }
        })
        .collect();
    bans.sort_by(|a, b| b.account.cmp(&a.account).then(b.created_at.cmp(&a.created_at)));
    bans
}

/// Reads the list again (at start, and every `REVALIDATE_MINUTES`): what the
/// shell added or lifted meanwhile, without the expired ones, which are
/// deleted where they are kept.
pub async fn load(state: &ServerState) -> Result<()> {
    let now = now_secs();
    let fresh: Vec<(Key, Ban)> = if let Some(relay) = &state.accounts {
        relay.ban_rows(now).await?
    } else if state.bans_file.is_some() {
        let _held = state.bans_writer.lock().unwrap_or_else(|p| p.into_inner());
        let list = read_file(state)?;
        let (keep, gone): (Vec<Ban>, Vec<Ban>) = list.into_iter().partition(|b| b.active(now));
        if !gone.is_empty() {
            write_file(state, &keep)?;
        }
        keep.into_iter().filter_map(|b| Some((Key::Addr(addr_key(state, b.addr?)), b))).collect()
    } else {
        Vec::new()
    };
    state.bans.retain(|k, _| fresh.iter().any(|(f, _)| f == k));
    for (k, b) in fresh {
        state.bans.insert(k, b);
    }
    Ok(())
}

/// Ends the connections a ban covers now (but `skip`, already told): one the
/// shell added, or one that came in while a sign-in was under way.
pub async fn enforce(state: &Arc<ServerState>, skip: Option<u32>) {
    if state.bans.is_empty() {
        return;
    }
    let covered: Vec<(u32, String)> = state
        .sessions
        .iter()
        .filter(|e| Some(*e.key()) != skip)
        .filter_map(|e| {
            let s = e.value();
            let account = s.account.as_ref().map(|a| (a.user.id.0, !a.scopes.is_empty()));
            refusal(state, s.peer_ip, account).map(|why| (*e.key(), why))
        })
        .collect();
    for (sid, why) in covered {
        crate::tcp::force_disconnect(state, sid, &why).await;
    }
}

// ── bans.json (relays without accounts) ──

#[derive(Serialize, Deserialize)]
struct File {
    format: u32,
    bans: Vec<Ban>,
}

const FILE_FORMAT: u32 = 1;

fn read_file(state: &ServerState) -> Result<Vec<Ban>> {
    let Some(path) = &state.bans_file else { return Ok(Vec::new()) };
    read_path(path)
}

pub fn read_path(path: &Path) -> Result<Vec<Ban>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let file: File = serde_json::from_str(&text).with_context(|| format!("{} does not read", path.display()))?;
    anyhow::ensure!(file.format <= FILE_FORMAT, "{} was written by a newer VoIPC", path.display());
    Ok(file.bans)
}

fn write_file(state: &ServerState, list: &[Ban]) -> Result<()> {
    let Some(path) = &state.bans_file else { return Ok(()) };
    write_path(path, list)
}

pub fn write_path(path: &Path, list: &[Ban]) -> Result<()> {
    let text = serde_json::to_string_pretty(&File { format: FILE_FORMAT, bans: list.to_vec() })?;
    crate::fsutil::atomic_write(path, text.as_bytes(), true).with_context(|| format!("writing {}", path.display()))
}
