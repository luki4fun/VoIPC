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
use std::sync::atomic::{AtomicBool, Ordering};
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
    session.is_admin || passes_without_star(session, groups)
}

/// `passes`, without `*`'s pass: what someone's app follows by itself. `*` walks into a
/// gated channel by a click, as a person's own act, and is never pulled in silently.
pub fn passes_without_star(session: &UserSession, groups: &[String]) -> bool {
    groups.is_empty()
        || session
            .account
            .as_ref()
            .is_some_and(|a| a.standing.groups.iter().any(|g| groups.contains(g)))
}

/// Whether a list of groups keeps out no one with an account: every account holds `user`.
/// For what was private on Discord, where a guest passing or not is beside the point.
pub fn open_to_all(groups: &[String]) -> bool {
    groups.is_empty() || groups.iter().any(|g| g == "user")
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
    prune_soon(state);
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
    if !state.passes(session_id, old) {
        return Err("channel does not exist".into());
    }
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
/// open what it closed). `Some(Some(name))` is a channel naming it that this
/// session can see, ahead of any it cannot; `Some(None)`, only hidden ones.
pub async fn uses(
    state: &ServerState,
    session_id: SessionId,
    group: &str,
) -> Option<Option<String>> {
    let channels = state.channels.read().await;
    let mut hidden = false;
    for c in channels.values() {
        if c.gate
            .groups
            .iter()
            .chain(&c.gate.speakers)
            .any(|g| g == group)
        {
            if state.passes(session_id, &c.gate.groups) {
                return Some(Some(c.info.name.clone()));
            }
            hidden = true;
        }
    }
    hidden.then_some(None)
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
            let channel = state.channel_seen_by(&info, uid);
            if let Some(s) = state.sessions.get(&uid) {
                let _ = send_msg(&s.control_tx, &ServerMessage::ChannelCreated { channel });
            }
        }
        if was != now {
            crate::layout::send(state, uid).await;
        }
        if now && members.contains(&uid) {
            speech(state, uid, channel_id).await;
        }
    }
    if old.groups.is_empty() != gate.groups.is_empty() {
        tell_followers_gate(state, channel_id).await;
    }
}

/// A gate came or went: those following on the live path hold a `gated` bit from when they
/// joined, and open channels and gated ones are drawn differently.
async fn tell_followers_gate(state: &ServerState, channel_id: ChannelId) {
    let channels = state.channels.read().await;
    let Some(channel) = channels.get(&channel_id) else {
        return;
    };
    let followers = channel.follow.joined.keys();
    for uid in followers.chain(channel.follow.quiet.keys()) {
        if let Some(s) = state.sessions.get(uid) {
            let _ = send_msg(
                &s.control_tx,
                &ServerMessage::TextJoined {
                    joined: vec![channel.seat_row(s.listen_only.contains(&channel_id))],
                    refused: Vec::new(),
                },
            );
        }
    }
}

/// After a member's groups changed: the channels they now see, out of the
/// ones they may no longer enter, and where they may speak.
pub async fn standing_changed(state: &Arc<ServerState>, session_id: SessionId) {
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
    prune_own(state, session_id).await;
    // After the evictions: the app names what it was put out of, and gives up that channel's
    // log, by the list it still holds
    let channels = state.channel_list_for(session_id).await;
    if let Some(s) = state.sessions.get(&session_id) {
        crate::session::send_channel_list(&s.control_tx, channels);
    }
    crate::layout::send(state, session_id).await;
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

/// This session's seats in gated logs it does not pass now, out of them, for those of a
/// channel it is not in, which no eviction reaches. Someone who lost a group from the shell
/// while away is back before the hourly pass, and a seat is all a read of the log asks for.
pub async fn prune_own(state: &ServerState, session_id: SessionId) {
    let Some(relay) = state.accounts.as_ref() else {
        return;
    };
    let Some(account) = state.sessions.get(&session_id).and_then(|s| s.account_id()) else {
        return;
    };
    let shut: Vec<String> = state
        .channels
        .read()
        .await
        .values()
        .filter(|c| {
            !c.log_conv.is_empty()
                && !c.gate.groups.is_empty()
                && !state.passes(session_id, &c.gate.groups)
        })
        .map(|c| c.log_conv.clone())
        .collect();
    if shut.is_empty() {
        return;
    }
    if let Err(e) = relay.out_of_logs(&account, &shut).await {
        warn!("keeping an account to its gates: {e:#}");
    }
}

/// `prune_soon`'s two facts: a pass is running, and another is wanted.
#[derive(Default)]
pub struct PruneAsks {
    running: AtomicBool,
    asked: AtomicBool,
}

/// A pass of `prune_logs` in the background, since it reads a large relay's whole list and
/// whoever changed a group is waiting on their own frame. One runs at a time: what asks during
/// one gets one more after it, which reads what that one may have missed.
pub fn prune_soon(state: &Arc<ServerState>) {
    state.prune_asks.asked.store(true, Ordering::SeqCst);
    if state.prune_asks.running.swap(true, Ordering::SeqCst) {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let asks = &state.prune_asks;
        loop {
            while asks.asked.swap(false, Ordering::SeqCst) {
                prune_logs(&state).await;
            }
            asks.running.store(false, Ordering::SeqCst);
            // An ask between the last look and that store saw a pass running, and left
            if !asks.asked.load(Ordering::SeqCst) || asks.running.swap(true, Ordering::SeqCst) {
                return;
            }
        }
    });
}

/// The stored members of a gated channel's log who no longer pass its gate,
/// signed in or not, out of it: they would go on getting its keys. Run after
/// every change to groups or gates, at boot and hourly for what the server's
/// shell changed. Each account is read once a pass.
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
    relay.prune_gated(&gated).await;
}
