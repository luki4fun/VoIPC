//! Channel gates (1.7): which groups (account roles) may see and join a
//! channel, and which of those may speak in it. Outside the first list the
//! channel is not there: not in the list, not in a count, "does not exist" on
//! a join. Outside the second, a member listens and reads: the relay drops
//! their voice, posts and shares, and tells them so (`ListenOnly`).
//!
//! A gate of a channel from channels.json is kept in the accounts database
//! (`voipc_gates`); one on a channel people made lives as long as it does.
//! `*` passes every gate; a guest passes none that names a group.

use std::collections::HashSet;
use std::sync::Arc;

use tracing::warn;
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{ChannelGate, ChannelId, SessionId, UserId};

use crate::session::send_msg;
use crate::state::{ServerState, UserSession};

/// Groups one gate list names at most.
pub const MAX_GROUPS: usize = 16;

/// Whether this member passes a list of groups: an empty list passes
/// everyone, `*` passes every list, a guest passes no other.
pub fn passes(session: &UserSession, groups: &[String]) -> bool {
    groups.is_empty()
        || session.is_admin
        || session
            .account
            .as_ref()
            .is_some_and(|a| a.standing.groups.iter().any(|g| groups.contains(g)))
}

/// Puts `channel` in or out of `set`; whether that changed it.
pub fn mark(set: &mut HashSet<ChannelId>, channel: ChannelId, on: bool) -> bool {
    if on {
        set.insert(channel)
    } else {
        set.remove(&channel)
    }
}

/// The gates kept for channels from channels.json, onto those channels.
pub async fn load(state: &ServerState) -> anyhow::Result<()> {
    let Some(relay) = state.accounts.clone() else {
        return Ok(());
    };
    let kept = relay.gates().await?;
    let mut channels = state.channels.write().await;
    for (key, gate) in kept {
        if let Some(c) = channels
            .values_mut()
            .find(|c| !c.gate_key.is_empty() && c.gate_key == key)
        {
            c.gate = gate;
        }
    }
    Ok(())
}

/// A new gate for `channel_id`, set by `session_id`: checked, kept, and
/// applied to everyone it changes something for. The editor must pass the
/// gate before and after (`*` excepted): one cannot reach into a channel
/// one cannot see, nor shut oneself out of it.
pub async fn set(
    state: &Arc<ServerState>,
    session_id: SessionId,
    channel_id: ChannelId,
    gate: ChannelGate,
) -> Result<ChannelGate, String> {
    let Some(relay) = state.accounts.clone() else {
        return Err("This relay has no accounts, so no groups.".into());
    };
    if channel_id == 0 {
        return Err("The General channel is open to everyone.".into());
    }
    let (old, key) = {
        let channels = state.channels.read().await;
        let Some(c) = channels.get(&channel_id) else {
            return Err("channel does not exist".into());
        };
        (c.gate.clone(), c.gate_key.clone())
    };
    let gate = checked(state, session_id, &key, &old.groups, gate).await?;
    if old == gate {
        return Ok(gate);
    }
    if !key.is_empty() {
        relay
            .gate_put(&key, &gate)
            .await
            .map_err(|_| "Something went wrong. Please try again.".to_string())?;
    }
    {
        let mut channels = state.channels.write().await;
        match channels.get_mut(&channel_id) {
            Some(c) => c.gate = gate.clone(),
            None => return Err("channel does not exist".into()),
        }
    }
    gate_changed(state, channel_id, &old).await;
    prune_logs(state).await;
    Ok(gate)
}

/// Whether `new` lets in no one `old` kept out: open was everyone, and any list is narrower.
/// Empty is open, and every account holds `user`, so "empty" alone is not the test.
fn only_narrows(old: &[String], new: &[String]) -> bool {
    old.is_empty() || (!new.is_empty() && new.iter().all(|g| old.contains(g)))
}

/// A gate as an editor may set it, in place of one with `old` as its groups, on the channel
/// under `key`: its lists tidied and short enough, its groups real, and the editor passing
/// both. What the channel kept from Discord was private, if it says so: past `*`, whoever
/// edits it may only narrow who reads that.
pub async fn checked(
    state: &ServerState,
    session_id: SessionId,
    key: &str,
    old: &[String],
    gate: ChannelGate,
) -> Result<ChannelGate, String> {
    let Some(relay) = state.accounts.clone() else {
        return Err("This relay has no accounts, so no groups.".into());
    };
    let clean = |list: Vec<String>| -> Vec<String> {
        let mut l: Vec<String> = list.into_iter().map(|g| g.trim().to_string()).collect();
        l.retain(|g| !g.is_empty());
        l.sort();
        l.dedup();
        l
    };
    let gate = ChannelGate {
        groups: clean(gate.groups),
        speakers: clean(gate.speakers),
    };
    if gate.groups.len() > MAX_GROUPS || gate.speakers.len() > MAX_GROUPS {
        return Err(format!("A gate names at most {MAX_GROUPS} groups."));
    }
    let known: Vec<String> = relay
        .store()
        .roles()
        .await
        .map_err(|_| "Something went wrong. Please try again.".to_string())?
        .into_iter()
        .map(|r| r.name)
        .collect();
    if let Some(g) = gate
        .groups
        .iter()
        .chain(&gate.speakers)
        .find(|g| !known.contains(g))
    {
        return Err(format!("There is no group named {g}."));
    }
    if !state.passes(session_id, old) {
        return Err("channel does not exist".into());
    }
    if !state.passes(session_id, &gate.groups) {
        return Err(
            "This would shut you out of the channel. Keep one of your groups in it.".into(),
        );
    }
    if !only_narrows(old, &gate.groups)
        && !state.is_admin(session_id)
        && relay
            .archive_private(key)
            .await
            .map_err(|_| "Something went wrong. Please try again.".to_string())?
    {
        return Err(
            "What this channel kept from Discord was private: only an admin can open it.".into(),
        );
    }
    Ok(gate)
}

/// Whether any gate names `group` (a group in use is not deleted: that would
/// open what it closed).
pub async fn uses(state: &ServerState, group: &str) -> Option<String> {
    let channels = state.channels.read().await;
    channels
        .values()
        .find(|c| {
            c.gate
                .groups
                .iter()
                .chain(&c.gate.speakers)
                .any(|g| g == group)
        })
        .map(|c| c.info.name.clone())
}

/// After a channel's gate changed from `old`: whoever lost it sees the
/// channel go (and leaves it), whoever gained it sees it come, and the
/// members are told where they may now only listen.
async fn gate_changed(state: &Arc<ServerState>, channel_id: ChannelId, old: &ChannelGate) {
    let Some((info, gate, members)) = state
        .channels
        .read()
        .await
        .get(&channel_id)
        .map(|c| (c.info.clone(), c.gate.clone(), c.members.clone()))
    else {
        return;
    };
    let everyone: Vec<UserId> = state.sessions.iter().map(|e| *e.key()).collect();
    for uid in everyone {
        let was = state.passes(uid, &old.groups);
        let now = state.passes(uid, &gate.groups);
        if was && !now {
            if members.contains(&uid) {
                crate::session::evict(state, channel_id, uid).await;
            } else if let Some(s) = state.sessions.get(&uid) {
                let _ = send_msg(&s.control_tx, &ServerMessage::ChannelDeleted { channel_id });
            }
            // A category holding only that channel is not theirs to see any more
            crate::layout::send(state, uid).await;
            continue;
        }
        if !was && now {
            if let Some(s) = state.sessions.get(&uid) {
                let _ = send_msg(
                    &s.control_tx,
                    &ServerMessage::ChannelCreated {
                        channel: info.clone(),
                    },
                );
            }
        }
        if was != now {
            crate::layout::send(state, uid).await;
        }
        if now && members.contains(&uid) {
            speech(state, uid, channel_id).await;
        }
    }
}

/// After a member's groups changed: the channels they now see, out of the
/// ones they may no longer enter, and where they may speak.
pub async fn standing_changed(state: &Arc<ServerState>, session_id: SessionId) {
    let channels = state.channel_list_for(session_id).await;
    if let Some(s) = state.sessions.get(&session_id) {
        let _ = send_msg(&s.control_tx, &ServerMessage::ChannelList { channels });
    }
    crate::layout::send(state, session_id).await;
    let theirs: Vec<(ChannelId, Vec<String>)> = state
        .channels
        .read()
        .await
        .iter()
        .filter(|(_, c)| c.members.contains(&session_id))
        .map(|(id, c)| (*id, c.gate.groups.clone()))
        .collect();
    for (channel_id, groups) in theirs {
        if state.passes(session_id, &groups) {
            speech(state, session_id, channel_id).await;
        } else {
            crate::session::evict(state, channel_id, session_id).await;
        }
    }
}

/// Whether `uid` may speak in `channel_id` now; told when that changed, and
/// a share they run there stops when they may not.
async fn speech(state: &Arc<ServerState>, uid: UserId, channel_id: ChannelId) {
    let speakers = state
        .channels
        .read()
        .await
        .get(&channel_id)
        .filter(|c| c.members.contains(&uid))
        .map(|c| c.gate.speakers.clone());
    let Some(speakers) = speakers else {
        return;
    };
    let listen = !state.passes(uid, &speakers);
    let Some((changed, tx, sharing)) = state.sessions.get_mut(&uid).map(|mut s| {
        let changed = mark(&mut s.listen_only, channel_id, listen);
        let sharing = s.is_screen_sharing && s.channel_id == channel_id;
        (changed, s.control_tx.clone(), sharing)
    }) else {
        return;
    };
    if !changed {
        return;
    }
    let _ = send_msg(
        &tx,
        &ServerMessage::ListenOnly {
            channel_id,
            on: listen,
        },
    );
    if listen && sharing {
        // Their share only: what they watch goes on, since they may still listen
        let _ = crate::session::handle_stop_screen_share(state, uid, uid, &tx).await;
        // Tell the sharer's own client to stop capturing
        let _ = send_msg(
            &tx,
            &ServerMessage::ScreenShareError {
                reason: "you can only listen in this channel now".into(),
            },
        );
    }
}

/// The stored members of a gated channel's log who no longer pass its gate,
/// signed in or not, out of it: they would go on getting its keys. Run after
/// every change to groups or gates, at boot and with the hourly sweep.
pub async fn prune_logs(state: &ServerState) {
    let Some(relay) = state.accounts.clone() else {
        return;
    };
    let gated: Vec<(String, Vec<String>)> = state
        .channels
        .read()
        .await
        .values()
        .filter(|c| !c.log_conv.is_empty() && !c.gate.groups.is_empty())
        .map(|c| (c.log_conv.clone(), c.gate.groups.clone()))
        .collect();
    for (conv, groups) in gated {
        if let Err(e) = relay.prune_log(&conv, &groups).await {
            warn!("keeping {conv} to its gate: {e:#}");
        }
    }
}
