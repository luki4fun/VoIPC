//! Channels made in the app and where every channel sits (1.9), on relays with
//! accounts. A channel from channels.json stays the file's: it can be placed in a
//! category and its options changed as ever, but only the file renames or removes
//! it. One made in the app (`Channel::kept`) is a row of `voipc_channels` and is
//! otherwise the same thing: a persistent channel, with a log and a gate.
//!
//! `ServerMessage::ChannelLayout` carries the order and the categories apart from
//! `ChannelInfo`, and shows only what a member may see: a category named after a
//! gated channel would otherwise say what the gate is hiding.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tracing::{error, warn};
use voipc_protocol::codec::encode_server_msg;
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{
    ChannelCategory, ChannelGate, ChannelId, ChannelInfo, ChannelPlace, SessionId,
};

use crate::accounts::layout::KeptRows;
use crate::accounts::{Powers, Relay};
use crate::channels::{validate_entries, ChannelEntry};
use crate::control::ControlTx;
use crate::session::send_msg;
use crate::state::{Channel, ServerState};

/// One message holds the whole channel list, and one that does not fit is not
/// sent: everybody would arrive at a server with no channels.
const LIST_LIMIT: usize = 60 * 1024;
const GONE: &str = "Something went wrong. Please try again.";
const NOT_THE_APPS: &str = "This channel comes from channels.json: change it there.";
/// Categories a server may have. With its channels' places they fit one message
/// (some 70 bytes each), and one that does not fit is not sent: whoever manages
/// channels would see nothing to delete, and it would hold until someone edits the database.
const MAX_CATEGORIES: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub position: i64,
    pub category: Option<u32>,
}

/// Where channels sit, by log conversation id, which outlives their ids.
#[derive(Default)]
pub struct Layout {
    /// In order.
    pub categories: Vec<ChannelCategory>,
    pub places: HashMap<String, Place>,
    pub welcome: Option<String>,
}

/// The channels the app made, added to the file's before the state is built. One
/// that does not parse or collides with the file (edited since) is left out with
/// an error, and its row stays, so that it comes back when the clash is gone. Says
/// which it took: only those are the app's, whatever else has a row.
pub fn merge_kept(rows: &KeptRows, entries: &mut Vec<ChannelEntry>) -> Vec<String> {
    let mut accepted = Vec::new();
    for row in &rows.rows {
        let Some(text) = &row.entry else { continue };
        let entry: ChannelEntry = match serde_json::from_str(text) {
            Ok(e) => e,
            Err(e) => {
                error!(conv = %row.conv, "a kept channel does not read, left out: {e}");
                continue;
            }
        };
        let lower = entry.name.trim().to_lowercase();
        let clash = entries
            .iter()
            .any(|o| o.name.trim().to_lowercase() == lower || o.log_conv() == entry.log_conv());
        if let Err(e) = validate_entries(std::slice::from_ref(&entry)).map(|_| clash) {
            error!(conv = %row.conv, "a kept channel is not valid, left out: {e}");
            continue;
        }
        if clash {
            error!(channel = %entry.name, "a kept channel clashes with channels.json, left out");
            continue;
        }
        accepted.push(row.conv.clone());
        entries.push(entry);
    }
    accepted
}

/// What the rows say, onto the state. Past what one channel list holds, the newest
/// channels made in the app wait with an error: the file's are not touched, and
/// with the file alone too big the start fails as it always did.
pub async fn load(state: &ServerState, kept: KeptRows, apps: &[String]) {
    let mut layout = Layout {
        categories: kept.categories,
        welcome: kept.welcome,
        ..Layout::default()
    };
    for row in kept.rows {
        layout.places.insert(
            row.conv,
            Place {
                position: row.position,
                category: row.category,
            },
        );
    }
    {
        let mut channels = state.channels.write().await;
        for c in channels.values_mut() {
            c.kept = apps.contains(&c.gate_key);
        }
        while list_len(channels.values().map(|c| &c.info)) > LIST_LIMIT {
            let newest = channels
                .values()
                .filter(|c| c.kept)
                .max_by_key(|c| layout.places.get(&c.gate_key).map_or(0, |p| p.position))
                .map(|c| (c.info.channel_id, c.info.name.clone()));
            let Some((id, name)) = newest else { break };
            error!(channel = %name, "more channels than one list holds: left out until there is room");
            channels.remove(&id);
        }
    }
    *state.layout.write().await = layout;
}

/// How a category stands to someone managing channels.
#[derive(PartialEq)]
enum CategoryView {
    /// They see all there is in it.
    Whole,
    /// It holds something they can see, and something they cannot.
    Partly,
    /// It holds only what they cannot see: to them it does not exist.
    Hidden,
}

fn category_view(
    state: &ServerState,
    session_id: SessionId,
    layout: &Layout,
    channels: &HashMap<ChannelId, Channel>,
    id: u32,
) -> CategoryView {
    let (mut shown, mut hidden) = (false, false);
    for c in channels.values() {
        if layout.places.get(&c.gate_key).and_then(|p| p.category) == Some(id) {
            if state.passes(session_id, &c.gate.groups) {
                shown = true;
            } else {
                hidden = true;
            }
        }
    }
    match (shown, hidden) {
        (_, false) => CategoryView::Whole,
        (true, true) => CategoryView::Partly,
        (false, true) => CategoryView::Hidden,
    }
}

fn list_len<'a>(infos: impl Iterator<Item = &'a ChannelInfo>) -> usize {
    let channels: Vec<ChannelInfo> = infos.cloned().collect();
    encode_server_msg(&ServerMessage::ChannelList { channels }).map_or(usize::MAX, |b| b.len())
}

/// What `session_id` may know of the order: the persistent channels they see, in
/// order, and the categories those are in. Someone who manages channels sees the
/// really empty ones too, to put something there; never one holding only what is
/// hidden from them, which would say what the gate is hiding.
pub async fn for_session(state: &ServerState, session_id: SessionId) -> ServerMessage {
    let layout = state.layout.read().await;
    let channels = state.channels.read().await;
    let mut seen: Vec<(i64, ChannelPlace)> = channels
        .values()
        .filter(|c| {
            c.persistent && c.info.channel_id != 0 && state.passes(session_id, &c.gate.groups)
        })
        .map(|c| {
            let place = layout.places.get(&c.gate_key);
            (
                place.map_or(i64::MAX, |p| p.position),
                ChannelPlace {
                    channel_id: c.info.channel_id,
                    category: place.and_then(|p| p.category),
                    kept: c.kept,
                    welcome: layout.welcome.as_deref() == Some(c.gate_key.as_str()),
                },
            )
        })
        .collect();
    seen.sort_by_key(|(position, p)| (*position, p.channel_id));
    let manages = state.can(session_id, Powers::CHANNELS);
    ServerMessage::ChannelLayout {
        categories: layout
            .categories
            .iter()
            .filter(|c| {
                seen.iter().any(|(_, p)| p.category == Some(c.id))
                    || (manages
                        && category_view(state, session_id, &layout, &channels, c.id)
                            != CategoryView::Hidden)
            })
            .cloned()
            .collect(),
        channels: seen.into_iter().map(|(_, p)| p).collect(),
    }
}

/// Tells one member. Nothing on a relay without accounts: nothing to say.
pub async fn send(state: &ServerState, session_id: SessionId) {
    if state.accounts.is_none() {
        return;
    }
    let msg = for_session(state, session_id).await;
    if let Some(s) = state.sessions.get(&session_id) {
        let _ = send_msg(&s.control_tx, &msg);
    }
}

/// After a change: rare, so once per member and no cleverer.
pub async fn send_all(state: &ServerState) {
    let everyone: Vec<SessionId> = state.sessions.iter().map(|e| *e.key()).collect();
    for session_id in everyone {
        send(state, session_id).await;
    }
}

/// The groups' colours and order, to one connection.
pub async fn send_styles(state: &ServerState, tx: &ControlTx) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    match relay.group_styles().await {
        Ok(groups) => {
            let _ = send_msg(tx, &ServerMessage::GroupStyles { groups });
        }
        Err(e) => warn!("reading group styles: {e:#}"),
    }
}

/// After a change, to everybody: one read and one message.
pub async fn send_styles_all(state: &ServerState) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    match relay.group_styles().await {
        Ok(groups) => {
            let msg = ServerMessage::GroupStyles { groups };
            for s in state.sessions.iter() {
                let _ = send_msg(&s.control_tx, &msg);
            }
        }
        Err(e) => warn!("reading group styles: {e:#}"),
    }
}

/// An edit made through `SetChannelOptions` and the like reaches a channel made in
/// the app's row too: otherwise it would be undone by the next start.
pub async fn keep_through(state: &ServerState, channel_id: ChannelId) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    let entry = {
        let channels = state.channels.read().await;
        match channels.get(&channel_id) {
            Some(c) if c.kept => c.to_entry(),
            _ => return,
        }
    };
    if let Err(e) = put(state, relay, &entry).await {
        warn!(channel = %entry.name, "keeping a channel's change: {e}");
    }
}

async fn put(state: &ServerState, relay: &Relay, entry: &ChannelEntry) -> anyhow::Result<()> {
    let conv = entry.log_conv();
    let place = state.layout.read().await.places.get(&conv).copied();
    let place = place.unwrap_or(Place {
        position: next_position(state).await,
        category: None,
    });
    relay
        .layout_put(&conv, Some(entry), place.position, place.category)
        .await?;
    state.layout.write().await.places.insert(conv, place);
    Ok(())
}

async fn next_position(state: &ServerState) -> i64 {
    let layout = state.layout.read().await;
    layout
        .places
        .values()
        .map(|p| p.position)
        .max()
        .unwrap_or(0)
        + 1
}

/// The channel, if the editor may reach it at all (`gates::set` says the same).
async fn reachable(
    state: &ServerState,
    session_id: SessionId,
    channel_id: ChannelId,
) -> Result<(ChannelInfo, ChannelGate, bool, String), String> {
    let channels = state.channels.read().await;
    channels
        .get(&channel_id)
        .filter(|c| state.passes(session_id, &c.gate.groups))
        .map(|c| (c.info.clone(), c.gate.clone(), c.kept, c.gate_key.clone()))
        .ok_or_else(|| "channel does not exist".to_string())
}

/// For this editor: one holding only what is hidden from them does not exist, and
/// moving something into it would make them a viewer of its name.
async fn category_exists(
    state: &ServerState,
    session_id: SessionId,
    category: Option<u32>,
) -> Result<(), String> {
    let Some(id) = category else {
        return Ok(());
    };
    let layout = state.layout.read().await;
    let channels = state.channels.read().await;
    if layout.categories.iter().any(|c| c.id == id)
        && category_view(state, session_id, &layout, &channels, id) != CategoryView::Hidden
    {
        return Ok(());
    }
    Err("There is no such category.".into())
}

/// What `ChannelSave` says, as a channel's own checks read it.
fn checked_entry(
    name: &str,
    description: &str,
    text: bool,
    auto_join: bool,
) -> Result<ChannelEntry, String> {
    let entry = ChannelEntry {
        name: name.trim().to_string(),
        description: description.trim().to_string(),
        text,
        auto_join: auto_join && text,
        ..ChannelEntry::default()
    };
    validate_entries(std::slice::from_ref(&entry)).map_err(|e| e.to_string())?;
    Ok(entry)
}

/// A new channel, or changes to one made in the app.
#[allow(clippy::too_many_arguments)]
pub async fn channel_save(
    state: &Arc<ServerState>,
    session_id: SessionId,
    id: Option<ChannelId>,
    name: &str,
    description: &str,
    text: bool,
    auto_join: bool,
    category: Option<u32>,
    gate: Option<ChannelGate>,
) -> Result<ChannelId, String> {
    category_exists(state, session_id, category).await?;
    match id {
        None => {
            channel_create(
                state,
                session_id,
                name,
                description,
                text,
                auto_join,
                category,
                gate,
            )
            .await
        }
        Some(id) => {
            channel_edit(
                state,
                session_id,
                id,
                name,
                description,
                text,
                auto_join,
                category,
                gate,
            )
            .await?;
            Ok(id)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn channel_create(
    state: &Arc<ServerState>,
    session_id: SessionId,
    name: &str,
    description: &str,
    text: bool,
    auto_join: bool,
    category: Option<u32>,
    gate: Option<ChannelGate>,
) -> Result<ChannelId, String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    let mut entry = checked_entry(name, description, text, auto_join)?;
    // Its log and gate stay with it through renames, and are never another's
    entry.uid = Some(hex::encode(rand::random::<[u8; 16]>()));
    let gate = crate::gates::checked(state, session_id, &[], gate.unwrap_or_default()).await?;
    let conv = entry.log_conv();
    let channel_id = state.next_channel_id();
    let mut channel = Channel::from_entry(
        &entry,
        channel_id,
        relay.cloud,
        state.settings.proximity_enabled,
    );
    channel.kept = true;
    channel.gate = gate.clone();
    channel.refresh_log();
    let info = channel.info.clone();
    {
        let mut channels = state.channels.write().await;
        let lower = entry.name.to_lowercase();
        if channels
            .values()
            .any(|c| c.info.name.to_lowercase() == lower)
        {
            return Err("a channel with that name already exists".into());
        }
        if list_len(channels.values().map(|c| &c.info).chain([&info])) > LIST_LIMIT {
            return Err("One channel list cannot hold another channel: shorten some descriptions or remove one.".into());
        }
        channels.insert(channel_id, channel);
    }
    let position = next_position(state).await;
    // The gate first: a crash between the two leaves a gate naming nothing, where
    // the other order would bring back a channel meant to be private, open to all
    let stored = async {
        relay.gate_put(&conv, &gate).await?;
        relay
            .layout_put(&conv, Some(&entry), position, category)
            .await
    }
    .await;
    if let Err(e) = stored {
        warn!("keeping a new channel: {e:#}");
        state.channels.write().await.remove(&channel_id);
        let _ = relay.channel_purge(&conv).await;
        return Err(GONE.into());
    }
    state.channel_budget.fetch_add(1, Ordering::Relaxed);
    state
        .layout
        .write()
        .await
        .places
        .insert(conv, Place { position, category });
    // Told only to who may see it: announcing it first and gating it after would
    // say that it exists.
    for s in state.sessions.iter() {
        if crate::gates::passes(s.value(), &gate.groups) {
            let _ = send_msg(
                &s.value().control_tx,
                &ServerMessage::ChannelCreated {
                    channel: info.clone(),
                },
            );
        }
    }
    send_all(state).await;
    Ok(channel_id)
}

#[allow(clippy::too_many_arguments)]
async fn channel_edit(
    state: &Arc<ServerState>,
    session_id: SessionId,
    channel_id: ChannelId,
    name: &str,
    description: &str,
    text: bool,
    auto_join: bool,
    category: Option<u32>,
    gate: Option<ChannelGate>,
) -> Result<(), String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    let (info, old_gate, kept, conv) = reachable(state, session_id, channel_id).await?;
    if !kept {
        return Err(NOT_THE_APPS.into());
    }
    if info.text != text {
        return Err("A channel cannot change between text and voice.".into());
    }
    let wanted = checked_entry(name, description, text, auto_join)?;
    // Whatever can refuse comes first: a refusal changes nothing
    let gate = match gate.filter(|g| *g != old_gate) {
        Some(g) => Some(crate::gates::checked(state, session_id, &old_gate.groups, g).await?),
        None => None,
    };
    let (entry, after) = {
        let channels = state.channels.read().await;
        let lower = wanted.name.to_lowercase();
        if channels
            .values()
            .any(|c| c.info.channel_id != channel_id && c.info.name.to_lowercase() == lower)
        {
            return Err("a channel with that name already exists".into());
        }
        let mut after = info.clone();
        after.name = wanted.name.clone();
        after.description = wanted.description.clone();
        after.auto_join = wanted.auto_join;
        let others = channels
            .values()
            .filter(|c| c.info.channel_id != channel_id)
            .map(|c| &c.info);
        if list_len(others.chain([&after])) > LIST_LIMIT {
            return Err(
                "One channel list cannot hold that: shorten some descriptions or remove a channel."
                    .into(),
            );
        }
        let mut entry = channels
            .get(&channel_id)
            .map(Channel::to_entry)
            .ok_or("channel does not exist")?;
        entry.name = wanted.name.clone();
        entry.description = wanted.description.clone();
        entry.auto_join = wanted.auto_join;
        (entry, after)
    };
    let position = state
        .layout
        .read()
        .await
        .places
        .get(&conv)
        .map(|p| p.position);
    let position = match position {
        Some(p) => p,
        None => next_position(state).await,
    };
    let place = Place { position, category };
    // The row, then memory: what people are told is what a restart will say
    relay
        .layout_put(&conv, Some(&entry), place.position, place.category)
        .await
        .map_err(|_| GONE.to_string())?;
    state
        .layout
        .write()
        .await
        .places
        .insert(conv.clone(), place);
    let changed = {
        let mut channels = state.channels.write().await;
        // Someone else may have taken the name during that write: a start would then
        // leave one of the two out, its log out of reach
        let lower = after.name.to_lowercase();
        if channels
            .values()
            .any(|c| c.info.channel_id != channel_id && c.info.name.to_lowercase() == lower)
        {
            let before = channels.get(&channel_id).map(Channel::to_entry);
            drop(channels);
            let _ = relay
                .layout_put(&conv, before.as_ref(), place.position, place.category)
                .await;
            return Err("a channel with that name already exists".into());
        }
        let c = channels
            .get_mut(&channel_id)
            .ok_or("channel does not exist")?;
        let changed = c.info.name != after.name
            || c.info.description != after.description
            || c.info.auto_join != after.auto_join;
        c.info.name = after.name;
        c.info.description = after.description;
        c.info.auto_join = after.auto_join;
        changed.then_some(c.info.clone())
    };
    // What has changed by now is told, whatever the gate's own write comes to
    let gated = match gate {
        Some(gate) => crate::gates::set(state, session_id, channel_id, gate)
            .await
            .map(|_| ()),
        None => Ok(()),
    };
    if let Some(info) = changed {
        crate::session::channel_updated(state, info).await;
    }
    send_all(state).await;
    gated
}

/// A channel made in the app goes, with everything kept in it.
pub async fn channel_delete(
    state: &Arc<ServerState>,
    session_id: SessionId,
    channel_id: ChannelId,
) -> Result<(), String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    let (info, gate, kept, conv) = reachable(state, session_id, channel_id).await?;
    if !kept {
        return Err(NOT_THE_APPS.into());
    }
    let row = crate::accounts::modlog::Entry {
        action: "channel_delete",
        channel_key: &conv,
        channel_name: &info.name,
        ..Default::default()
    };
    if let Err(e) = crate::accounts::modlog::put(state, session_id, row).await {
        warn!(conv, "keeping a channel's deletion: {e:#}");
        return Err("That could not be kept.".into());
    }
    // All of it first, in one go: a failure here leaves a channel that can be
    // deleted again, and a crash after it one that does not come back
    relay
        .channel_purge(&conv)
        .await
        .map_err(|_| GONE.to_string())?;
    state.channel_budget.fetch_sub(1, Ordering::Relaxed);
    // Its rows are gone: nothing may write them back, and nobody new gets in while
    // those here are put out. (A group nobody holds: only `*` passes it.)
    if let Some(c) = state.channels.write().await.get_mut(&channel_id) {
        c.kept = false;
        c.gate.groups = vec!["\u{0}being deleted".into()];
    }
    // Someone joining meanwhile is put out the next time round
    for _ in 0..8 {
        let members: Vec<_> = {
            let channels = state.channels.read().await;
            channels
                .get(&channel_id)
                .map(|c| c.members.iter().copied().collect())
                .unwrap_or_default()
        };
        for uid in &members {
            crate::session::evict(state, channel_id, *uid).await;
        }
        let mut channels = state.channels.write().await;
        if channels
            .get(&channel_id)
            .is_some_and(|c| c.members.is_empty())
        {
            channels.remove(&channel_id);
            break;
        }
    }
    // However that went: everyone is about to be told it is gone
    state.channels.write().await.remove(&channel_id);
    state.routing.clear_channel(channel_id, []);
    for s in state.sessions.iter() {
        if crate::gates::passes(s.value(), &gate.groups) {
            let _ = send_msg(
                &s.value().control_tx,
                &ServerMessage::ChannelDeleted { channel_id },
            );
        }
    }
    {
        let mut layout = state.layout.write().await;
        layout.places.remove(&conv);
        if layout.welcome.as_deref() == Some(conv.as_str()) {
            layout.welcome = None;
            let _ = relay.welcome_put(None).await;
        }
    }
    send_all(state).await;
    // Whatever a member still in it wrote while they were being put out
    if let Err(e) = relay.channel_purge(&conv).await {
        warn!(conv, "clearing a deleted channel's last messages: {e}");
    }
    Ok(())
}

/// A new category, or a new name.
pub async fn category_save(
    state: &ServerState,
    session_id: SessionId,
    id: Option<u32>,
    name: &str,
) -> Result<u32, String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || name.chars().any(crate::session::bad_name_char) {
        return Err("A category's name is 1 to 64 characters, none of them invisible.".into());
    }
    let mut layout = state.layout.write().await;
    let channels = state.channels.read().await;
    let id = match id {
        Some(id)
            if layout.categories.iter().any(|c| c.id == id)
                && category_view(state, session_id, &layout, &channels, id)
                    != CategoryView::Hidden =>
        {
            id
        }
        Some(_) => return Err("There is no such category.".into()),
        None if layout.categories.len() >= MAX_CATEGORIES => {
            return Err(format!("A server has {MAX_CATEGORIES} categories at most."));
        }
        None => layout.categories.iter().map(|c| c.id).max().unwrap_or(0) + 1,
    };
    drop(channels);
    let category = ChannelCategory {
        id,
        name: name.to_string(),
    };
    let position = layout
        .categories
        .iter()
        .position(|c| c.id == id)
        .unwrap_or(layout.categories.len());
    relay
        .category_put(&category, position as i64)
        .await
        .map_err(|_| GONE.to_string())?;
    match layout.categories.iter_mut().find(|c| c.id == id) {
        Some(c) => *c = category,
        None => layout.categories.push(category),
    }
    drop(layout);
    send_all(state).await;
    Ok(id)
}

pub async fn category_delete(
    state: &ServerState,
    session_id: SessionId,
    id: u32,
) -> Result<(), String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    let mut layout = state.layout.write().await;
    if !layout.categories.iter().any(|c| c.id == id) {
        return Err("There is no such category.".into());
    }
    {
        // Deleting moves its channels out, and a channel they cannot see is not
        // theirs to move
        let channels = state.channels.read().await;
        match category_view(state, session_id, &layout, &channels, id) {
            CategoryView::Whole => {}
            CategoryView::Partly => {
                return Err("Someone who sees all of this category can delete it.".into());
            }
            CategoryView::Hidden => return Err("There is no such category.".into()),
        }
    }
    relay
        .category_delete(id)
        .await
        .map_err(|_| GONE.to_string())?;
    layout.categories.retain(|c| c.id != id);
    for p in layout.places.values_mut() {
        if p.category == Some(id) {
            p.category = None;
        }
    }
    // Positions stay what the list says: a tie would flip the order at a restart
    for (i, c) in layout.categories.iter().enumerate() {
        relay
            .category_put(c, i as i64)
            .await
            .map_err(|_| GONE.to_string())?;
    }
    drop(layout);
    send_all(state).await;
    Ok(())
}

/// A new order. The list names channels in the order wanted, each with its category.
/// It covers what the editor can see: those take the places they held between
/// themselves, and a gated channel they cannot see stays exactly where it is.
pub async fn layout_set(
    state: &ServerState,
    session_id: SessionId,
    categories: &[u32],
    wanted: &[(ChannelId, Option<u32>)],
) -> Result<(), String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    // One frame can name one id 60,000 times: this all runs under the layout's lock,
    // which everyone connecting waits for. The first naming of each counts.
    let mut named = HashSet::new();
    let wanted: Vec<_> = wanted.iter().filter(|(id, _)| named.insert(*id)).collect();
    let listed: Vec<(String, Option<u32>, Option<ChannelEntry>)> = {
        let channels = state.channels.read().await;
        wanted
            .iter()
            .filter_map(|(id, category)| {
                let c = channels.get(id)?;
                (c.persistent && !c.gate_key.is_empty() && state.passes(session_id, &c.gate.groups))
                    .then(|| (c.gate_key.clone(), *category, c.kept.then(|| c.to_entry())))
            })
            .collect()
    };
    let mut layout = state.layout.write().await;
    {
        let channels = state.channels.read().await;
        if listed.iter().filter_map(|(_, c, _)| *c).any(|c| {
            !layout.categories.iter().any(|k| k.id == c)
                || category_view(state, session_id, &layout, &channels, c) == CategoryView::Hidden
        }) {
            return Err("There is no such category.".into());
        }
    }
    // The slots these channels hold, and new ones past the end for those with none
    let mut slots: Vec<i64> = listed
        .iter()
        .filter_map(|(conv, _, _)| layout.places.get(conv).map(|p| p.position))
        .collect();
    slots.sort_unstable();
    let top = layout
        .places
        .values()
        .map(|p| p.position)
        .max()
        .unwrap_or(0);
    let spare = (1..=listed.len() as i64).map(|i| top + i);
    let slots: Vec<i64> = slots.into_iter().chain(spare).collect();
    for ((conv, category, entry), position) in listed.iter().zip(slots) {
        let place = Place {
            position,
            category: *category,
        };
        if layout.places.get(conv) == Some(&place) {
            continue;
        }
        relay
            .layout_put(conv, entry.as_ref(), position, *category)
            .await
            .map_err(|_| GONE.to_string())?;
        layout.places.insert(conv.clone(), place);
    }
    // Categories: those named go first, in that order, then the rest they can see.
    // One holding only what is hidden from them keeps its slot, as such a channel does.
    let hidden: Vec<u32> = {
        let channels = state.channels.read().await;
        layout
            .categories
            .iter()
            .map(|c| c.id)
            .filter(|id| {
                category_view(state, session_id, &layout, &channels, *id) == CategoryView::Hidden
            })
            .collect()
    };
    let mut seen = HashSet::new();
    let mut free: VecDeque<ChannelCategory> = categories
        .iter()
        .filter(|id| !hidden.contains(id) && seen.insert(**id))
        .filter_map(|id| layout.categories.iter().find(|c| c.id == *id).cloned())
        .collect();
    for c in &layout.categories {
        if !hidden.contains(&c.id) && !free.iter().any(|o| o.id == c.id) {
            free.push_back(c.clone());
        }
    }
    let order: Vec<ChannelCategory> = layout
        .categories
        .iter()
        .map(|c| {
            if hidden.contains(&c.id) {
                c.clone()
            } else {
                free.pop_front().unwrap_or_else(|| c.clone())
            }
        })
        .collect();
    for (i, c) in order.iter().enumerate() {
        if layout.categories.get(i).map(|k| k.id) != Some(c.id) {
            relay
                .category_put(c, i as i64)
                .await
                .map_err(|_| GONE.to_string())?;
        }
    }
    layout.categories = order;
    drop(layout);
    send_all(state).await;
    Ok(())
}

/// The channel someone lands in the first time they come here, or none.
pub async fn welcome_set(
    state: &ServerState,
    session_id: SessionId,
    channel_id: Option<ChannelId>,
) -> Result<(), String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    let conv = match channel_id {
        None => None,
        Some(id) => {
            let (info, _, _, conv) = reachable(state, session_id, id).await?;
            if !info.text || info.has_password || conv.is_empty() {
                return Err(
                    "The welcome channel is a text channel from here, with no password.".into(),
                );
            }
            Some(conv)
        }
    };
    relay
        .welcome_put(conv.as_deref())
        .await
        .map_err(|_| GONE.to_string())?;
    state.layout.write().await.welcome = conv;
    send_all(state).await;
    Ok(())
}
