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
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{
    ChannelCategory, ChannelGate, ChannelId, ChannelInfo, ChannelPlace, ImportCategory,
    ImportChannel, ImportGate, SessionId,
};

use crate::accounts::import::{KIND_CATEGORY, KIND_CHANNEL};
use crate::accounts::layout::KeptRows;
use crate::accounts::placeholder::id_ok;
use crate::accounts::{Powers, Relay};
use crate::channels::{validate_entries, ChannelEntry, MAX_SLOW_MODE_SECS};
use crate::control::ControlTx;
use crate::session::send_msg;
use crate::state::{Channel, ServerState};

const GONE: &str = "Something went wrong. Please try again.";
const NOT_THE_APPS: &str = "This channel comes from channels.json: change it there.";
const NAME_TAKEN: &str = "a channel with that name already exists";
/// In bytes, unlike a channel's name: every category goes in one frame of the layout. Said so,
/// where it read "characters" and refused 25 Japanese ones (W3-22).
const BAD_CATEGORY: &str =
    "A category's name is 1 to 64 bytes: 64 letters of the Latin alphabet, about 21 Chinese or Japanese characters. None of them may be invisible.";
const PRIVATE_NOW: &str = "Private on Discord now and open here. Give it a gate, then run again.";
/// Categories a server may have. With its channels' places they fit one message
/// (some 70 bytes each), and one that does not fit is not sent: whoever manages
/// channels would see nothing to delete, and it would hold until someone edits the database.
pub(crate) const MAX_CATEGORIES: usize = 200;
/// Channels kept here at most, from the file, the app and moves alike. Every place goes in one
/// layout frame, about 7 bytes each, so past some 7,000 it framed no more and every member's
/// layout quietly stopped updating; nothing refused a holder of `voipc:channels` on the way
/// (R2 F10). Four times Discord's own 500. The file's are counted, never refused: a start
/// takes channels.json as it is.
pub(crate) const MAX_KEPT_CHANNELS: usize = 2000;

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
    let unplaced: Vec<String> = {
        let mut channels = state.channels.write().await;
        for c in channels.values_mut() {
            c.kept = apps.contains(&c.gate_key);
        }
        let mut unplaced: Vec<_> = channels
            .values()
            .filter(|c| {
                c.persistent
                    && c.info.channel_id != 0
                    && !c.gate_key.is_empty()
                    && !layout.places.contains_key(&c.gate_key)
            })
            .map(|c| (c.info.channel_id, c.gate_key.clone()))
            .collect();
        unplaced.sort();
        unplaced.into_iter().map(|(_, conv)| conv).collect()
    };
    // A file channel with no row sorted after every row, so each channel made since, at the
    // next position, went above them all (W3-23). Rows now, after the rest, in the order
    // they showed in: once, and the same at every start after
    let mut next = layout
        .places
        .values()
        .map(|p| p.position)
        .max()
        .unwrap_or(0);
    for conv in unplaced {
        next += 1;
        if let Some(relay) = &state.accounts {
            if let Err(e) = relay.layout_put(&conv, None, next, None).await {
                warn!(conv, "placing a channel from the file: {e:#}");
            }
        }
        layout.places.insert(
            conv,
            Place {
                position: next,
                category: None,
            },
        );
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

/// One more channel to budget for, on sessions already here too: a limiter keeps the burst
/// it was made with, so theirs start again, or the new channel's first keys could be refused.
fn one_more_channel(state: &ServerState) {
    state.channel_budget.fetch_add(1, Ordering::Relaxed);
    for mut s in state.sessions.iter_mut() {
        s.key_relay_burst += 1.0;
        s.key_relay_rate.clear();
    }
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
    // What this person's sidebar lists (`visibleChannels`): a hidden channel only for
    // whoever manages channels or stands in it. A category of hidden ones showed everyone
    // else its name over nothing (W3-20)
    let here = state.sessions.get(&session_id).map(|s| s.channel_id);
    let listed = |id: ChannelId| {
        manages || here == Some(id) || channels.get(&id).is_some_and(|c| !c.info.hidden)
    };
    ServerMessage::ChannelLayout {
        categories: layout
            .categories
            .iter()
            .filter(|c| {
                seen.iter()
                    .any(|(_, p)| p.category == Some(c.id) && listed(p.channel_id))
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

/// Whether a channel of this kind could not take `lower`, a lowercase name. A text channel
/// may share the lobby's: the most common name a server has, and `validate_entries` says why
/// it cannot be confused with it.
pub(crate) fn name_taken(
    channels: &HashMap<ChannelId, Channel>,
    lower: &str,
    text: bool,
    except: Option<ChannelId>,
) -> bool {
    channels.values().any(|c| {
        Some(c.info.channel_id) != except
            && !(text && c.info.channel_id == 0)
            && c.info.name.to_lowercase() == lower
    })
}

fn category_name_ok(name: &str) -> bool {
    name.len() <= 64
        && !name.chars().any(crate::session::bad_name_char)
        && voipc_protocol::names::draws_something(name)
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
    let conv = entry.log_conv();
    let gate =
        crate::gates::checked(state, session_id, &conv, &[], gate.unwrap_or_default()).await?;
    let (channel_id, channel) = kept(state, &relay, &entry, &gate);
    let info = channel.info.clone();
    take_place(state, channel_id, channel).await?;
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
    placed(state, conv, Place { position, category }).await;
    tell_who_passes(
        state,
        &gate.groups,
        &ServerMessage::ChannelCreated { channel: info },
    );
    send_all(state).await;
    Ok(channel_id)
}

// What a channel made in the panel and one a move makes go through alike (W3-31): written
// twice, a rule added to one missed the other.

/// A channel the database keeps, as the state holds it.
fn kept(
    state: &ServerState,
    relay: &Relay,
    entry: &ChannelEntry,
    gate: &ChannelGate,
) -> (ChannelId, Channel) {
    let channel_id = state.next_channel_id();
    let mut channel = Channel::from_entry(
        entry,
        channel_id,
        relay.cloud,
        state.settings.proximity_enabled,
    );
    channel.kept = true;
    channel.gate = gate.clone();
    channel.refresh_log();
    (channel_id, channel)
}

/// Into the state, unless its log or its name is another's, or the server is full.
async fn take_place(
    state: &ServerState,
    channel_id: ChannelId,
    channel: Channel,
) -> Result<(), String> {
    let mut channels = state.channels.write().await;
    if channels.values().filter(|c| c.persistent).count() >= MAX_KEPT_CHANNELS {
        return Err(format!(
            "A server has {MAX_KEPT_CHANNELS} channels at most."
        ));
    }
    if channels.values().any(|c| c.gate_key == channel.gate_key) {
        return Err("A channel here already goes by this id.".into());
    }
    if name_taken(
        &channels,
        &channel.info.name.to_lowercase(),
        channel.info.text,
        None,
    ) {
        return Err(NAME_TAKEN.into());
    }
    channels.insert(channel_id, channel);
    Ok(())
}

/// Stored: counted, and given its place in the list.
async fn placed(state: &ServerState, conv: String, place: Place) {
    one_more_channel(state);
    state.layout.write().await.places.insert(conv, place);
}

/// To each session the gate lets see the channel, and nobody else: told first and gated
/// after, a channel would say that it exists.
fn tell_who_passes(state: &ServerState, groups: &[String], msg: &ServerMessage) {
    for s in state.sessions.iter() {
        if crate::gates::passes(s.value(), groups) {
            let _ = send_msg(&s.value().control_tx, msg);
        }
    }
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
        Some(g) => {
            Some(crate::gates::checked(state, session_id, &conv, &old_gate.groups, g).await?)
        }
        None => None,
    };
    let (entry, after) = {
        let channels = state.channels.read().await;
        let lower = wanted.name.to_lowercase();
        if name_taken(&channels, &lower, text, Some(channel_id)) {
            return Err(NAME_TAKEN.into());
        }
        let mut after = info.clone();
        after.name = wanted.name.clone();
        after.description = wanted.description.clone();
        after.auto_join = wanted.auto_join;
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
        if name_taken(&channels, &lower, text, Some(channel_id)) {
            let before = channels.get(&channel_id).map(Channel::to_entry);
            drop(channels);
            let _ = relay
                .layout_put(&conv, before.as_ref(), place.position, place.category)
                .await;
            return Err(NAME_TAKEN.into());
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

/// What an imported list comes to. The importer names Discord's roles and the relay finds
/// its own groups, so a client cannot name one. Nothing it knows, or `Closed`, is only
/// `*`: never empty, since empty is open. Past `MAX_GROUPS`: narrower, never wider.
async fn import_list(relay: &Relay, gate: &ImportGate) -> anyhow::Result<Vec<String>> {
    let roles: &[u64] = match gate {
        ImportGate::Open => return Ok(Vec::new()),
        ImportGate::Closed => &[],
        ImportGate::Roles(roles) => roles,
    };
    let mut names = Vec::new();
    for role in roles {
        if names.len() == crate::gates::MAX_GROUPS {
            break;
        }
        names.extend(relay.zero_group_of(*role).await?);
    }
    names.sort();
    names.dedup();
    if names.is_empty() {
        names.push("admin".to_string());
    }
    Ok(names)
}

/// A channel the importer named and nobody here has yet: `channel_create`, with what the row
/// says in place of `checked`. `Err`: why it is not made, and nothing of it was.
async fn import_channel(
    state: &ServerState,
    relay: &Relay,
    run: i64,
    row: &ImportChannel,
    categories: &HashMap<i64, String>,
) -> anyhow::Result<Result<(), String>> {
    let entry = ChannelEntry {
        name: row.name.trim().to_string(),
        description: row.description.trim().to_string(),
        max_users: row.max_users,
        screen_share: row.screen_share,
        text: row.text,
        // A member's app follows it from the first connect, and a gate still decides who
        // may. A later run leaves a channel it already made, so an untick stays.
        auto_join: row.text,
        announce: row.announce && row.text,
        slow_mode_secs: row.slow_mode_secs.min(MAX_SLOW_MODE_SECS),
        nsfw: row.nsfw,
        uid: Some(format!("dc-{}", row.dc_id)),
        ..ChannelEntry::default()
    };
    if let Err(e) = validate_entries(std::slice::from_ref(&entry)) {
        return Ok(Err(e.to_string()));
    }
    // channels.json is the operator's own and keeps what it had; a move's is not (W1-36)
    if !voipc_protocol::names::draws_something(&entry.name) {
        return Ok(Err(format!(
            "channel {} has a name that shows nothing",
            row.dc_id
        )));
    }
    let gate = ChannelGate {
        groups: import_list(relay, &row.see).await?,
        speakers: import_list(relay, &row.speak).await?,
    };
    let category = row
        .category
        .and_then(|c| categories.get(&(c as i64)))
        .and_then(|local| local.parse::<u32>().ok());
    // One removed by hand stays removed: its channels sit outside any
    let category = match category {
        Some(id)
            if state
                .layout
                .read()
                .await
                .categories
                .iter()
                .any(|c| c.id == id) =>
        {
            Some(id)
        }
        _ => None,
    };
    let conv = entry.log_conv();
    let (channel_id, channel) = kept(state, relay, &entry, &gate);
    let info = channel.info.clone();
    if let Err(e) = take_place(state, channel_id, channel).await {
        return Ok(Err(e));
    }
    let position = next_position(state).await;
    let private = row.see != ImportGate::Open;
    if let Err(e) = relay
        .import_channel_put(run, row.dc_id, &entry, &gate, position, category, private)
        .await
    {
        state.channels.write().await.remove(&channel_id);
        return Err(e);
    }
    placed(state, conv, Place { position, category }).await;
    tell_who_passes(
        state,
        &gate.groups,
        &ServerMessage::ChannelCreated { channel: info },
    );
    Ok(Ok(()))
}

/// `AdminOp::ImportChannels`: makes what is missing, in the order given, and says what it did
/// not make and why. What the ledger holds is left alone, so that a name or a gate fixed by
/// hand survives a delta, and one deleted here stays deleted and is named, so nobody walks it.
/// So is one Discord closed since while it is open here: its new messages would be for
/// everyone. Nothing is stored for that, since a brief closure there must not block it for good.
/// One closed there and gated here counts as private from now on: that gate is all that keeps
/// its new messages from everyone.
pub async fn import_channels(
    state: &ServerState,
    relay: &Relay,
    run: i64,
    rows: &[ImportChannel],
) -> anyhow::Result<Vec<(u64, String)>> {
    let mut made = relay.import_items(KIND_CHANNEL).await?;
    let categories = relay.import_items(KIND_CATEGORY).await?;
    let mut refused = Vec::new();
    let mut any = false;
    for row in rows {
        if !id_ok(row.dc_id) {
            refused.push((row.dc_id, "That is not a Discord id.".to_string()));
            continue;
        }
        if let Some(conv) = made.get(&(row.dc_id as i64)) {
            let open = state
                .channels
                .read()
                .await
                .values()
                .find(|c| c.gate_key == *conv)
                .map(|c| crate::gates::open_to_all(&c.gate.groups));
            match open {
                None => refused.push((row.dc_id, "Removed here.".to_string())),
                Some(true) if row.see != ImportGate::Open => {
                    refused.push((row.dc_id, PRIVATE_NOW.to_string()));
                }
                Some(false) if row.see != ImportGate::Open => {
                    relay.archive_private_set(conv).await?;
                }
                Some(_) => {}
            }
            continue;
        }
        match import_channel(state, relay, run, row, &categories).await? {
            Ok(()) => {
                any = true;
                made.insert(row.dc_id as i64, format!("c:dc-{}", row.dc_id));
            }
            Err(reason) => refused.push((row.dc_id, reason)),
        }
    }
    if any {
        send_all(state).await;
    }
    Ok(refused)
}

/// `AdminOp::ImportCategories`: as `import_channels`. A category removed here stays removed,
/// and past `MAX_CATEGORIES` the rest are named: their channels sit outside any.
pub async fn import_categories(
    state: &ServerState,
    relay: &Relay,
    run: i64,
    rows: &[ImportCategory],
) -> anyhow::Result<Vec<(u64, String)>> {
    let mut made = relay.import_items(KIND_CATEGORY).await?;
    let mut refused = Vec::new();
    let mut layout = state.layout.write().await;
    let mut next = layout.categories.iter().map(|c| c.id).max().unwrap_or(0) + 1;
    let mut count = layout.categories.len();
    let mut new = Vec::new();
    for row in rows {
        if !id_ok(row.dc_id) {
            refused.push((row.dc_id, "That is not a Discord id.".to_string()));
            continue;
        }
        if made.contains_key(&(row.dc_id as i64)) {
            continue;
        }
        let name = row.name.trim();
        if !category_name_ok(name) {
            refused.push((row.dc_id, BAD_CATEGORY.to_string()));
            continue;
        }
        if count >= MAX_CATEGORIES {
            refused.push((
                row.dc_id,
                format!("A server has {MAX_CATEGORIES} categories at most."),
            ));
            continue;
        }
        let category = ChannelCategory {
            id: next,
            name: name.to_string(),
        };
        made.insert(row.dc_id as i64, next.to_string());
        new.push((row.dc_id, category, count as i64));
        next += 1;
        count += 1;
    }
    relay.import_categories_put(run, &new).await?;
    let any = !new.is_empty();
    layout
        .categories
        .extend(new.into_iter().map(|(_, category, _)| category));
    drop(layout);
    if any {
        send_all(state).await;
    }
    Ok(refused)
}

/// Why this session may not delete this channel, if so. Before the code is asked for: nothing
/// asks for what it will refuse. What came from Discord goes with the channel, and no later run
/// brings it back, so that is `*`'s, as `ArchiveDelete` is.
pub async fn channel_delete_refusal(
    state: &ServerState,
    session_id: SessionId,
    channel_id: ChannelId,
) -> Result<(), String> {
    let relay = state.accounts.as_ref().ok_or(GONE)?;
    let (_, _, kept, conv) = reachable(state, session_id, channel_id).await?;
    if !kept {
        return Err(NOT_THE_APPS.into());
    }
    if !state.is_admin(session_id)
        && relay
            .holds_archive(&conv)
            .await
            .map_err(|_| GONE.to_string())?
    {
        return Err(
            "This channel holds what came from Discord: only an admin can delete it.".into(),
        );
    }
    Ok(())
}

/// A channel made in the app goes, with everything kept in it.
pub async fn channel_delete(
    state: &Arc<ServerState>,
    session_id: SessionId,
    channel_id: ChannelId,
) -> Result<(), String> {
    let relay = state.accounts.clone().ok_or(GONE)?;
    channel_delete_refusal(state, session_id, channel_id).await?;
    let (info, gate, _, conv) = reachable(state, session_id, channel_id).await?;
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
    // The rest in its own task, so that it ends however this session does: a handler is
    // aborted 10 s after its connection ends (`web.rs`), and one stopped halfway left a
    // channel nobody could delete until a restart (W2-21)
    let state = state.clone();
    tokio::spawn(async move {
        channel_gone(&state, &relay, channel_id, &conv, &gate)
            .await
            .map_err(|_| GONE.to_string())?;
        send_all(&state).await;
        // Whatever a member still in it wrote while they were being put out
        if let Err(e) = relay.channel_purge(&conv).await {
            warn!(conv, "clearing a deleted channel's last messages: {e}");
        }
        // What it kept from Discord: nobody can reach that any more, and it need not wait
        relay.archive_kick.notify_one();
        Ok(())
    })
    .await
    .unwrap_or_else(|_| Err(GONE.into()))
}

/// A channel of the app's goes for good, and everybody who could see it is told. The list's
/// new shape is the caller's to send.
async fn channel_gone(
    state: &Arc<ServerState>,
    relay: &Relay,
    channel_id: ChannelId,
    conv: &str,
    gate: &ChannelGate,
) -> anyhow::Result<()> {
    // All of it first, in one go: a failure here leaves a channel that can be
    // deleted again, and a crash after it one that does not come back
    relay.channel_purge(conv).await?;
    state.channel_budget.fetch_sub(1, Ordering::Relaxed);
    // Its rows are gone: nothing may write them back, and nobody new gets in while
    // those here are put out. (A group nobody holds: only `*` passes it.)
    //
    // Whoever follows on the live path goes under this one write: the one `ChannelDeleted`
    // below is all they hear, with no mark and no toast. An undo takes 300 channels at
    // 2000 people, which one eviction each would make 600,000 writes and as many queries.
    let followers: Vec<_> = match state.channels.write().await.get_mut(&channel_id) {
        Some(c) => {
            c.kept = false;
            c.gate.groups = vec!["\u{0}being deleted".into()];
            let follow = std::mem::take(&mut c.follow);
            let out: Vec<_> = follow
                .joined
                .keys()
                .chain(follow.quiet.keys())
                .copied()
                .collect();
            for uid in &out {
                c.members.remove(uid);
            }
            out
        }
        None => Vec::new(),
    };
    for uid in followers {
        if let Some(mut s) = state.sessions.get_mut(&uid) {
            s.listen_only.remove(&channel_id);
        }
    }
    crate::files::channel_gone(state, channel_id);
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
    tell_who_passes(
        state,
        &gate.groups,
        &ServerMessage::ChannelDeleted { channel_id },
    );
    let mut layout = state.layout.write().await;
    layout.places.remove(conv);
    if layout.welcome.as_deref() == Some(conv) {
        layout.welcome = None;
        let _ = relay.welcome_put(None).await;
    }
    Ok(())
}

/// A channel an undo takes: as `channel_delete`, with nobody to ask and no list told, which
/// the undo does once at its end. What it filed in the archive goes with its row
/// (`archive::tidy`). One from channels.json is the file's. Whether there was one to take.
pub async fn import_purge(
    state: &Arc<ServerState>,
    relay: &Relay,
    conv: &str,
) -> anyhow::Result<bool> {
    let found = state
        .channels
        .read()
        .await
        .values()
        .find(|c| c.gate_key == conv)
        .map(|c| (c.info.channel_id, c.gate.clone(), c.kept));
    let Some((channel_id, gate, kept)) = found else {
        // A row a start left out of the list has nothing here to put anyone out of
        relay.channel_purge(conv).await?;
        return Ok(false);
    };
    if !kept {
        return Ok(false);
    }
    // In its own task, as `channel_delete`'s: an undo step stopped halfway left the channel
    // here with `kept` off, which the next step then skipped
    let (state, conv) = (state.clone(), conv.to_string());
    tokio::spawn(async move {
        let relay = state
            .accounts
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no accounts"))?;
        channel_gone(&state, &relay, channel_id, &conv, &gate).await?;
        relay.channel_purge(&conv).await?;
        Ok(true)
    })
    .await?
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
    if !category_name_ok(name) {
        return Err(BAD_CATEGORY.into());
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
    category_gone(&relay, &mut layout, id)
        .await
        .map_err(|_| GONE.to_string())?;
    drop(layout);
    send_all(state).await;
    Ok(())
}

/// A category goes; its channels stay, outside any.
async fn category_gone(relay: &Relay, layout: &mut Layout, id: u32) -> anyhow::Result<()> {
    relay.category_delete(id).await?;
    layout.categories.retain(|c| c.id != id);
    for p in layout.places.values_mut() {
        if p.category == Some(id) {
            p.category = None;
        }
    }
    // Positions stay what the list says: a tie would flip the order at a restart
    for (i, c) in layout.categories.iter().enumerate() {
        relay.category_put(c, i as i64).await?;
    }
    Ok(())
}

/// A category an undo takes, with no list told, which the undo does once at its end. One
/// removed by hand since is not there to take.
pub async fn import_category_purge(
    state: &ServerState,
    relay: &Relay,
    id: u32,
) -> anyhow::Result<bool> {
    let mut layout = state.layout.write().await;
    if !layout.categories.iter().any(|c| c.id == id) {
        return Ok(false);
    }
    category_gone(relay, &mut layout, id).await?;
    Ok(true)
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
/// A password on the welcome channel ends it as the welcome: new devices would land on a
/// channel they cannot open, and the rule `welcome_set` asks for held no more (W3-19).
pub async fn welcome_locked(state: &ServerState, channel_id: ChannelId) {
    let Some(relay) = state.accounts.clone() else {
        return;
    };
    let Some(conv) = state
        .channels
        .read()
        .await
        .get(&channel_id)
        .map(|c| c.gate_key.clone())
    else {
        return;
    };
    {
        let mut layout = state.layout.write().await;
        if conv.is_empty() || layout.welcome.as_deref() != Some(conv.as_str()) {
            return;
        }
        if let Err(e) = relay.welcome_put(None).await {
            warn!(conv, "unsetting a locked welcome channel: {e:#}");
            return;
        }
        layout.welcome = None;
    }
    send_all(state).await;
}

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
