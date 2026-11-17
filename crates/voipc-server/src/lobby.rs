//! The lobby on a big relay (protocol v25): never sent whole. Everyone stands in it, so a
//! list of it to each connection, and each join there told to everyone, was work that grew
//! with the square of who is online. Now:
//!
//! - its people come a page at a time (`RequestLobbyPage`), from a snapshot sorted as the
//!   member list shows them: sections first, then A-Z;
//! - an app looks people up by id, name or account (`LookupUsers`);
//! - how many stand in each channel goes out once a second (`ChannelCounts`);
//! - a join or leave there is told by name only to the apps showing the lobby's list
//!   (`WatchLobby`), and only while it is small (`live_lobby`): a small relay looks as it
//!   always did.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashSet;
use voipc_protocol::codec::encode_server_msg;
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{ChannelId, LobbyCursor, UserId, UserInfo, MAX_LOOKUP};

use crate::session::send_msg;
use crate::state::{
    account_shown, list_is_public, masked_flags, row_bytes, ServerState, UserSession, PAGE_BYTES,
};

/// The section of someone under no sectioned group: last.
pub const REST: u16 = u16::MAX;
/// How old a snapshot may be before a page asks for a new one.
const SNAPSHOT_LIFE: Duration = Duration::from_secs(1);

pub struct Lobby {
    snapshot: tokio::sync::Mutex<Snapshot>,
    /// Sessions showing the lobby's list.
    pub watchers: DashSet<UserId>,
    /// While the lobby holds at most this many, its watchers hear each join and leave.
    pub live_max: u32,
}

#[derive(Default)]
struct Snapshot {
    built: Option<Instant>,
    sorted: Arc<Vec<LobbyCursor>>,
    sections: Arc<Vec<(u16, u32)>>,
}

impl Lobby {
    pub fn new(live_max: u32) -> Lobby {
        Lobby {
            snapshot: Default::default(),
            watchers: DashSet::new(),
            live_max,
        }
    }
}

/// Each sectioned group's rank, as the apps rank them (`member-sections.ts`).
async fn section_ranks(state: &ServerState) -> HashMap<String, u16> {
    let Some(relay) = state.accounts.as_ref() else {
        return HashMap::new();
    };
    match relay.group_styles().await {
        Ok(styles) => styles
            .into_iter()
            .filter(|s| s.section)
            .enumerate()
            .map(|(rank, s)| (s.badge, rank.min(REST as usize - 1) as u16))
            .collect(),
        Err(e) => {
            tracing::warn!("reading group styles for the lobby: {e:#}");
            HashMap::new()
        }
    }
}

/// Where someone stands in the list.
fn cursor_of(session: &UserSession, ranks: &HashMap<String, u16>) -> LobbyCursor {
    LobbyCursor {
        section: session
            .badges_with(session.account_id())
            .iter()
            .filter_map(|b| ranks.get(b))
            .min()
            .copied()
            .unwrap_or(REST),
        name: session.username.to_lowercase(),
        user_id: session.user_id,
    }
}

/// The lobby, sorted, and each section's count: at most a second old.
async fn snapshot(state: &ServerState) -> (Arc<Vec<LobbyCursor>>, Arc<Vec<(u16, u32)>>) {
    let mut snap = state.lobby.snapshot.lock().await;
    if snap.built.is_some_and(|t| t.elapsed() < SNAPSHOT_LIFE) {
        return (snap.sorted.clone(), snap.sections.clone());
    }
    let ranks = section_ranks(state).await;
    let ids: Vec<UserId> = state
        .channels
        .read()
        .await
        .get(&0)
        .map(|c| c.members.iter().copied().collect())
        .unwrap_or_default();
    let mut sorted: Vec<LobbyCursor> = ids
        .into_iter()
        .filter_map(|uid| Some(cursor_of(&*state.sessions.get(&uid)?, &ranks)))
        .collect();
    sorted.sort_unstable();
    let mut sections: Vec<(u16, u32)> = Vec::new();
    for c in sorted.iter() {
        match sections.last_mut() {
            Some((s, n)) if *s == c.section => *n += 1,
            _ => sections.push((c.section, 1)),
        }
    }
    *snap = Snapshot {
        built: Some(Instant::now()),
        sorted: Arc::new(sorted),
        sections: Arc::new(sections),
    };
    (snap.sorted.clone(), snap.sections.clone())
}

/// A lobby row: the lobby has no pseudonyms, so the name and account are the real ones.
fn lobby_row(session: &UserSession) -> UserInfo {
    session.row_in(
        0,
        session.username.clone(),
        account_shown(session.account_id(), true, false),
    )
}

/// One page of the lobby from past `after`; with a `prefix`, of the names that start with it.
pub async fn page(state: &ServerState, after: Option<LobbyCursor>, prefix: &str) -> ServerMessage {
    let (sorted, sections) = snapshot(state).await;
    let asked = prefix.to_string();
    let prefix = prefix.to_lowercase();
    let matches = |c: &&LobbyCursor| prefix.is_empty() || c.name.starts_with(&prefix);
    let total = if prefix.is_empty() {
        sorted.len()
    } else {
        sorted.iter().filter(matches).count()
    } as u32;
    let from = after
        .as_ref()
        .map_or(0, |after| sorted.partition_point(|c| c <= after));
    let (mut rows, mut bytes, mut last, mut next) = (Vec::new(), 0, None, None);
    for c in sorted[from..].iter().filter(matches) {
        // Gone since the snapshot: left out, the next one goes on
        let Some(session) = state.sessions.get(&c.user_id) else {
            continue;
        };
        let row = lobby_row(&session);
        bytes += row_bytes(&row);
        if bytes > PAGE_BYTES && !rows.is_empty() {
            next = last;
            break;
        }
        rows.push(row);
        last = Some(c.clone());
    }
    ServerMessage::LobbyPage {
        rows,
        next,
        total,
        sections: sections.to_vec(),
        prefix: asked,
    }
}

/// Who these are, if online. A row says the room only where that room's list is open to
/// everyone, and an anonymous room's switches never, as a text channel's page shows them.
pub async fn lookup(
    state: &ServerState,
    ids: &[UserId],
    names: &[String],
    accounts: &[[u8; 16]],
) -> ServerMessage {
    // At most MAX_LOOKUP asked in all, in this order
    let ids = &ids[..ids.len().min(MAX_LOOKUP)];
    let names = &names[..names.len().min(MAX_LOOKUP - ids.len())];
    let accounts = &accounts[..accounts.len().min(MAX_LOOKUP - ids.len() - names.len())];
    let mut found: Vec<UserId> = ids.to_vec();
    found.extend(
        names
            .iter()
            .filter_map(|n| state.username_to_session.get(&n.to_lowercase()).map(|s| *s)),
    );
    found.extend(
        accounts
            .iter()
            .filter_map(|a| state.account_sessions.get(a).map(|s| *s)),
    );
    let channels = state.channels.read().await;
    let (mut rows, mut gone, mut seen) = (Vec::new(), Vec::new(), HashSet::new());
    for uid in found {
        if !seen.insert(uid) {
            continue;
        }
        let Some(session) = state.sessions.get(&uid) else {
            gone.push(uid);
            continue;
        };
        let room = channels.get(&session.channel_id);
        let open = session.channel_id == 0 || room.is_some_and(list_is_public);
        let mut row = session.row_in(
            if open { session.channel_id } else { 0 },
            session.username.clone(),
            account_shown(session.account_id(), true, false),
        );
        if room.is_some_and(|c| c.info.anonymous) {
            masked_flags(&mut row);
        }
        rows.push(row);
    }
    ServerMessage::Users { rows, gone }
}

/// The sessions to tell a join or leave in the lobby by name: its watchers, while it is small.
pub async fn hearers(state: &ServerState) -> Vec<UserId> {
    let size = state
        .channels
        .read()
        .await
        .get(&0)
        .map_or(0, |c| c.members.len());
    if size > state.lobby.live_max as usize {
        return Vec::new();
    }
    state.lobby.watchers.iter().map(|u| *u).collect()
}

/// Each second: the channels whose count changed since `last`, to whoever sees them. One
/// frame shared by all for the ungated ones, a small one more for those inside a gate.
pub async fn send_counts(state: &ServerState, last: &mut HashMap<ChannelId, u32>) {
    let (open, gated) = {
        let channels = state.channels.read().await;
        let (mut open, mut gated) = (Vec::new(), Vec::new());
        for (id, channel) in channels.iter() {
            let n = channel.members.len() as u32;
            if last.insert(*id, n) == Some(n) {
                continue;
            }
            if channel.gate.groups.is_empty() {
                open.push((*id, n));
            } else {
                gated.push((*id, n, channel.gate.groups.clone()));
            }
        }
        last.retain(|id, _| channels.contains_key(id));
        (open, gated)
    };
    if open.is_empty() && gated.is_empty() {
        return;
    }
    let shared = (!open.is_empty())
        .then(|| encode_server_msg(&ServerMessage::ChannelCounts { counts: open }).ok())
        .flatten()
        .map(Bytes::from);
    let to: Vec<(crate::control::ControlTx, Vec<(ChannelId, u32)>)> = state
        .sessions
        .iter()
        .map(|entry| {
            let session = entry.value();
            let theirs = gated
                .iter()
                .filter(|(_, _, groups)| crate::gates::passes(session, groups))
                .map(|(id, n, _)| (*id, *n))
                .collect();
            (session.control_tx.clone(), theirs)
        })
        .collect();
    // Spread over about a second: every connection acks what it got, and 2000 every 5 ms
    // still dropped 66,000 datagrams on an 8 MiB buffer at 25,000 online (none without)
    for (i, (tx, theirs)) in to.into_iter().enumerate() {
        if i > 0 && i % COUNTS_AT_ONCE == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if let Some(frame) = &shared {
            let _ = tx.try_send(frame.clone());
        }
        if !theirs.is_empty() {
            let _ = send_msg(&tx, &ServerMessage::ChannelCounts { counts: theirs });
        }
    }
}

/// Connections `send_counts` tells before it waits a moment.
const COUNTS_AT_ONCE: usize = 500;

/// How many seconds apart counts go out: each second up to 10,000 online, then as many
/// seconds as there are ten thousands, so a big relay's counts cost what a small one's do.
pub fn counts_every(online: usize) -> u64 {
    (online as u64 / 10_000).max(1)
}
