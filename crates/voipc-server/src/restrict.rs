//! Who may not speak for now (1.10): a moderator's mute or timeout, and the wait
//! for new members. A moderator's row goes by account or, for a guest, by address
//! as the connection limits see it, the keys `crate::bans` uses; it is kept in
//! `voipc_restrictions`, or in memory on a relay without accounts. Each session
//! holds what applies to it now (`Silence`), read beside `listen_only` wherever
//! speech passes, so a voice packet looks nothing further up.
//!
//! The relay stops holding someone exactly at `until`: the check reads the clock.
//! One tick for the whole relay then tells everyone, within `TICK_SECS`.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use l4f_accounts::scope;
use tracing::{info, warn};
use voipc_protocol::codec::encode_server_msg;
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{Restriction, SessionId, UserId};

use crate::accounts::{holds_power, modlog, without_share, Powers};
use crate::bans::{addr_key, now_secs, Key};
use crate::control::ControlTx;
use crate::session::{admin_error, ban_reason, banned_by, handle_stop_screen_share, send_msg};
use crate::state::{ServerState, UserSession};

/// How often the relay tells everyone what ran out.
pub const TICK_SECS: u64 = 5;
/// What a guest's restriction lasts at most: it goes by address, and addresses
/// change hands.
pub const GUEST_MAX_SECS: u32 = 86_400;
/// Rows in one `Restrictions` frame. One is at most about 1.1 KiB (a name of 64
/// characters and a reason of 200, four bytes each), so these stay under a frame.
const ROWS_PER_FRAME: usize = 50;

/// Posts, pokes, invites and new channels, while `text` holds.
pub const TEXT_HELD: &str = "you cannot write on this server for now";
/// Direct messages and their kept copies, while `direct` holds.
pub const DIRECT_HELD: &str = "new members cannot send direct messages on this server yet";
/// Guest addresses with a clock, at most: the one thing here a stranger can make grow,
/// by visiting from one /64 after another. Each costs a few dozen bytes.
pub const CLOCKS_MAX: usize = 100_000;

/// A guest address's place in the wait for new members, in unix seconds. Only `admit`
/// starts or moves one, and `prune_clocks` for whoever is still here: working out what
/// holds a session only reads it.
#[derive(Clone, Copy, Debug)]
pub struct GuestClock {
    pub(crate) first: i64,
    pub(crate) last: i64,
}

/// A moderator's restriction, as kept.
#[derive(Clone, Debug)]
pub struct Held {
    pub voice: bool,
    pub text: bool,
    /// An account's name or "admin token".
    pub by: String,
    pub reason: String,
    /// Unix seconds; None: until lifted.
    pub expires_at: Option<i64>,
}

impl Held {
    fn active(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|t| t > now)
    }
}

/// What holds a member now. Its own field and not `listen_only`, which every
/// recalculation of a gate overwrites. Times are unix seconds: 0 is free,
/// `i64::MAX` until someone lifts it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Silence {
    pub(crate) voice_until: i64,
    pub(crate) text_until: i64,
    pub(crate) direct_until: i64,
    pub(crate) by: String,
    pub(crate) reason: String,
}

/// The clock is read only for someone held: this runs per voice packet.
fn held(until: i64) -> bool {
    until != 0 && until > now_secs()
}

impl Silence {
    pub fn voice(&self) -> bool {
        held(self.voice_until)
    }

    pub fn text(&self) -> bool {
        held(self.text_until)
    }

    pub fn direct(&self) -> bool {
        held(self.direct_until)
    }

    fn untils(&self) -> [i64; 3] {
        [self.voice_until, self.text_until, self.direct_until]
    }

    /// Anything of it ran out by `now`, and everyone is still to be told.
    fn lapsed(&self, now: i64) -> bool {
        self.untils().into_iter().any(|u| u != 0 && u <= now)
    }

    fn holds_at(&self, now: i64) -> bool {
        self.untils().into_iter().any(|u| u > now)
    }

    /// As a row on the wire. With several ends, the nearest: that is when the row
    /// next changes.
    fn row(&self, user_id: UserId, now: i64) -> Restriction {
        let next = self
            .untils()
            .into_iter()
            .filter(|u| *u > now && *u != i64::MAX)
            .min();
        Restriction {
            user_id,
            voice: self.voice_until > now,
            text: self.text_until > now,
            direct: self.direct_until > now,
            expires_in_secs: next.map(|u| (u - now).min(i64::from(u32::MAX)) as u32),
            by: self.by.clone(),
            reason: self.reason.clone(),
        }
    }
}

fn key_of(state: &ServerState, s: &UserSession) -> Key {
    match s.account_id() {
        Some(a) => Key::Account(a),
        None => Key::Addr(addr_key(state, s.peer_ip)),
    }
}

/// When the new-member wait ends for this session, if it still holds them. Admins,
/// holders of a privilege and anyone in a group given here do not wait: not the built-in
/// `user`, which every account is in, nor a group the move made, since a Discord bot may
/// give one to every joiner. Someone the move knows has their own start (`wait_from`). A
/// guest's clock goes by address, so a reload does not restart it. No clock is no wait,
/// unless `admit` found no room for one and set an end itself.
fn wait_ends(state: &ServerState, s: &UserSession, now: i64) -> Option<i64> {
    let mins = state.settings.new_member_wait_mins;
    if mins == 0 || s.is_admin || s.is_moderator {
        return None;
    }
    let wait = i64::from(mins) * 60;
    let end = match &s.account {
        Some(a)
            if a.standing
                .groups
                .iter()
                .any(|g| g != "user" && !from_the_move(state, g)) =>
        {
            return None
        }
        Some(a) => a
            .wait_from
            .unwrap_or(a.user.created_at)
            .saturating_add(wait),
        None => state
            .guest_clocks
            .get(&crate::limit_key(s.peer_ip))
            .map_or(s.silence.direct_until, |c| c.first.saturating_add(wait)),
    };
    (end > now).then_some(end)
}

fn from_the_move(state: &ServerState, group: &str) -> bool {
    state
        .accounts
        .as_ref()
        .is_some_and(|r| r.imported_groups.contains_key(group))
}

/// What holds this session at `now`. A row on an address is for the guests there, and
/// a token admin is none: otherwise a moderator could hold them through another guest.
fn worked_out(state: &ServerState, s: &UserSession, now: i64) -> Silence {
    let mut out = Silence::default();
    if !state.restrictions.is_empty() && (s.account.is_some() || !s.is_admin) {
        if let Some(r) = state
            .restrictions
            .get(&key_of(state, s))
            .filter(|r| r.active(now))
        {
            let until = r.expires_at.unwrap_or(i64::MAX);
            out.voice_until = if r.voice { until } else { 0 };
            out.text_until = if r.text { until } else { 0 };
            out.by.clone_from(&r.by);
            out.reason.clone_from(&r.reason);
        }
    }
    if let Some(until) = wait_ends(state, s, now) {
        out.voice_until = out.voice_until.max(until);
        out.text_until = out.text_until.max(until);
        out.direct_until = until;
    }
    out
}

/// The rows as frames, each under the limit.
fn frames(rows: &[Restriction]) -> Vec<Vec<u8>> {
    rows.chunks(ROWS_PER_FRAME)
        .filter_map(|list| {
            encode_server_msg(&ServerMessage::Restrictions {
                list: list.to_vec(),
            })
            .ok()
        })
        .collect()
}

/// `rows` without a reason, but the row of `of`.
fn blanked(rows: &[Restriction], of: Option<UserId>) -> Vec<Restriction> {
    let mut rows = rows.to_vec();
    for r in rows.iter_mut().filter(|r| Some(r.user_id) != of) {
        r.reason.clear();
    }
    rows
}

/// To everyone but `skip`. The reason goes to the member and to holders of
/// `voipc:restrict`; everyone else sees who and until when.
fn tell(state: &ServerState, rows: &[Restriction], skip: Option<UserId>) {
    if rows.is_empty() {
        return;
    }
    let full = frames(rows);
    let plain = frames(&blanked(rows, None));
    for entry in state.sessions.iter() {
        let s = entry.value();
        if Some(s.user_id) == skip {
            continue;
        }
        let own;
        let to_them = if s.can(Powers::RESTRICT) {
            &full
        } else if rows
            .iter()
            .any(|r| r.user_id == s.user_id && !r.reason.is_empty())
        {
            own = frames(&blanked(rows, Some(s.user_id)));
            &own
        } else {
            &plain
        };
        for frame in to_them {
            let _ = s.control_tx.try_send(frame.clone());
        }
    }
}

/// Works out again what holds these sessions: whoever that changed for is told to
/// everyone, and a share stops if they just lost their voice.
pub async fn settle_all(state: &Arc<ServerState>, sessions: &[SessionId], now: i64) {
    let mut rows = Vec::new();
    let mut sharers = Vec::new();
    for sid in sessions {
        let Some(mut s) = state.sessions.get_mut(sid) else {
            continue;
        };
        // The map is read and the session written under one guard, so an older
        // reading cannot land on top of a newer one
        let new = worked_out(state, &s, now);
        if new == s.silence {
            continue;
        }
        let lost_voice = new.voice_until > now && s.silence.voice_until <= now;
        s.silence = new;
        rows.push(s.silence.row(s.user_id, now));
        if lost_voice && s.is_screen_sharing {
            sharers.push((*sid, s.user_id, s.control_tx.clone()));
        }
    }
    tell(state, &rows, None);
    for (sid, uid, tx) in sharers {
        let _ = handle_stop_screen_share(state, uid, sid, &tx).await;
        // Viewers are told by that; this stops the sharer's own capture
        let _ = send_msg(
            &tx,
            &ServerMessage::ScreenShareError {
                reason: "you cannot share your screen on this server for now".into(),
            },
        );
    }
}

pub async fn settle(state: &Arc<ServerState>, session_id: SessionId) {
    settle_all(state, &[session_id], now_secs()).await;
}

/// A member's groups or privileges changed: the wait may hold them no longer, or
/// hold them again. A grant lifts it at once.
pub async fn standing_changed(state: &Arc<ServerState>, session_id: SessionId) {
    if state.settings.new_member_wait_mins > 0 {
        settle(state, session_id).await;
    }
}

/// A session just listed, before its media can flow, so the first packet is held
/// already. After the insert: `handle` writes the map and then walks the sessions,
/// so one of the two always sees the other.
pub fn admit(state: &ServerState, session_id: SessionId) {
    let wait = i64::from(state.settings.new_member_wait_mins) * 60;
    if state.restrictions.is_empty() && wait == 0 {
        return;
    }
    let now = now_secs();
    if let Some(mut s) = state.sessions.get_mut(&session_id) {
        if wait > 0 && s.account.is_none() && !clock_seen(state, s.peer_ip, now) {
            // No room to keep it: they wait from now, and a reload starts that again
            s.silence.direct_until = now.saturating_add(wait);
        }
        s.silence = worked_out(state, &s, now);
    }
}

/// A guest from `ip` came: their clock starts, or its last-seen moves. False: there was
/// no room for one. No clock's guard is held over the length, which walks them all.
fn clock_seen(state: &ServerState, ip: IpAddr, now: i64) -> bool {
    let key = crate::limit_key(ip);
    let known = state.guest_clocks.get_mut(&key).map(|mut c| c.last = now);
    if known.is_some() {
        return true;
    }
    if state.guest_clocks.len() >= CLOCKS_MAX {
        return false;
    }
    state.guest_clocks.entry(key).or_insert(GuestClock {
        first: now,
        last: now,
    });
    true
}

/// Whether a moderator has guests at `ip` off posts now.
pub fn guest_text_held(state: &ServerState, ip: IpAddr) -> bool {
    !state.restrictions.is_empty()
        && state
            .restrictions
            .get(&Key::Addr(addr_key(state, ip)))
            .is_some_and(|r| r.text && r.active(now_secs()))
}

/// Everyone held at `now`.
fn running(state: &ServerState, now: i64) -> Vec<Restriction> {
    state
        .sessions
        .iter()
        .filter(|e| e.value().silence.holds_at(now))
        .map(|e| e.value().silence.row(e.value().user_id, now))
        .collect()
}

fn send_rows(tx: &ControlTx, rows: &[Restriction]) {
    for list in rows.chunks(ROWS_PER_FRAME) {
        let _ = send_msg(
            tx,
            &ServerMessage::Restrictions {
                list: list.to_vec(),
            },
        );
    }
}

/// A client that just connected: everyone held, and to everybody else, itself if
/// it is.
pub fn at_connect(state: &ServerState, session_id: SessionId, user_id: UserId, tx: &ControlTx) {
    let now = now_secs();
    let reads_reasons = state.can(session_id, Powers::RESTRICT);
    let mut held = running(state, now);
    if let Some(own) = held.iter().find(|r| r.user_id == user_id) {
        tell(state, std::slice::from_ref(own), Some(user_id));
    }
    if !reads_reasons {
        held = blanked(&held, Some(user_id));
    }
    send_rows(tx, &held);
}

/// Someone who just came to hold `voipc:restrict`: what is running, with the reasons
/// `at_connect` left out. `tell` gives them only what changes from now on.
pub fn reasons_for(state: &ServerState, tx: &ControlTx) {
    send_rows(tx, &running(state, now_secs()));
}

/// The restrictions kept, at boot. There is no shell command for them, so nothing
/// else writes the table behind a running relay's back.
pub async fn load(state: &ServerState) -> Result<()> {
    let Some(relay) = &state.accounts else {
        return Ok(());
    };
    for (key, row) in relay.restriction_rows(now_secs()).await? {
        state.restrictions.insert(key, row);
    }
    Ok(())
}

/// What ran out by `now`: its rows go, and everyone is told about whoever it held.
pub async fn tick(state: &Arc<ServerState>, now: i64) {
    if state.restrictions.is_empty() && state.settings.new_member_wait_mins == 0 {
        return;
    }
    let before = state.restrictions.len();
    state.restrictions.retain(|_, r| r.active(now));
    let ran_out = state.restrictions.len() != before;
    if ran_out {
        if let Some(relay) = &state.accounts {
            if let Err(e) = relay.restrictions_sweep(now).await {
                warn!("dropping restrictions that ran out: {e:#}");
            }
        }
    }
    // A moderator's row ending inside the wait lapses no time of theirs, and its
    // name must still go
    let lapsed: Vec<SessionId> = state
        .sessions
        .iter()
        .filter(|e| {
            let silence = &e.value().silence;
            silence.lapsed(now) || (ran_out && !silence.by.is_empty())
        })
        .map(|e| *e.key())
        .collect();
    settle_all(state, &lapsed, now).await;
}

/// Clocks of addresses not seen for a day past the wait: a guest counts as new again
/// that long after their last visit, and someone still here is on one. Full, only
/// clocks still inside the wait stay, since those are what the wait is for.
pub fn prune_clocks(state: &ServerState, now: i64) {
    // Each clock's guard on its own, after the walk: `admit` takes one under a session's
    let online: Vec<IpAddr> = state
        .sessions
        .iter()
        .filter(|e| e.value().account.is_none())
        .map(|e| crate::limit_key(e.value().peer_ip))
        .collect();
    for ip in online {
        if let Some(mut clock) = state.guest_clocks.get_mut(&ip) {
            clock.last = now;
        }
    }
    let wait = i64::from(state.settings.new_member_wait_mins) * 60;
    state
        .guest_clocks
        .retain(|_, c| now - c.last < wait + 86_400);
    if state.guest_clocks.len() >= CLOCKS_MAX {
        state
            .guest_clocks
            .retain(|_, c| c.first.saturating_add(wait) > now);
    }
}

/// `ClientMessage::AdminRestrict`, from someone holding `voipc:restrict`. An account's
/// restriction binds that account, a guest's the guests at that address or /64 and
/// never an account there nor a token admin. A holder of `voipc:restrict` acts on anyone
/// holding no more than they do; an admin on anyone, themselves included.
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    state: &Arc<ServerState>,
    session_id: SessionId,
    target_id: UserId,
    voice: bool,
    text: bool,
    duration_secs: u32,
    reason: String,
    tx: &ControlTx,
) {
    // Each cloned off its own guard: never two at once
    let actor = state.sessions.get(&session_id).map(|s| {
        let scopes = s.account.as_ref().map(|a| a.scopes.clone());
        (s.is_admin, scopes.unwrap_or_default())
    });
    let Some((by_admin, actor_scopes)) = actor else {
        return;
    };
    if target_id == session_id && !by_admin {
        admin_error(tx, "you cannot restrict yourself").await;
        return;
    }
    let target = state.sessions.get(&target_id).map(|s| {
        let account = s.account.as_ref().map(|a| a.scopes.clone());
        (s.is_admin, account, key_of(state, &s))
    });
    let Some((is_admin, target_scopes, key)) = target else {
        admin_error(tx, "user not found").await;
        return;
    };
    let is_guest = target_scopes.is_none();
    let target_scopes = target_scopes.unwrap_or_default();
    let spared = !by_admin
        && (is_admin
            || (holds_power(&target_scopes)
                && !scope::covers(&actor_scopes, &without_share(&target_scopes))));
    if spared {
        admin_error(
            tx,
            "only someone holding at least as much can restrict them",
        )
        .await;
        return;
    }
    let (row_target, row_name) = modlog::target_of(state, target_id, None).await;
    let kept = if voice || text {
        restrict(
            state,
            session_id,
            key,
            Ask {
                voice,
                text,
                is_guest,
                duration_secs,
                reason,
            },
            (row_target, &row_name),
            tx,
        )
        .await
    } else {
        lift(state, session_id, key, (row_target, &row_name), tx).await
    };
    if !kept {
        return;
    }
    info!(
        actor = session_id,
        target = target_id,
        voice,
        text,
        duration_secs,
        "restriction"
    );
    let covered: Vec<SessionId> = state
        .sessions
        .iter()
        .filter(|e| key_of(state, e.value()) == key)
        .map(|e| *e.key())
        .collect();
    settle_all(state, &covered, now_secs()).await;
}

struct Ask {
    voice: bool,
    text: bool,
    is_guest: bool,
    duration_secs: u32,
    reason: String,
}

/// Row in the log, then the table, then the map: what cannot be kept does not
/// happen. Whether it did.
async fn restrict(
    state: &ServerState,
    session_id: SessionId,
    key: Key,
    ask: Ask,
    (row_target, row_name): (Option<[u8; 16]>, &str),
    tx: &ControlTx,
) -> bool {
    let duration = if !ask.is_guest {
        ask.duration_secs
    } else if ask.duration_secs == 0 {
        admin_error(
            tx,
            "a guest's restriction needs an end: it goes by address, and addresses change hands",
        )
        .await;
        return false;
    } else {
        ask.duration_secs.min(GUEST_MAX_SECS)
    };
    let what = match (ask.voice, ask.text) {
        (true, true) => "voice and posts",
        (true, false) => "voice",
        _ => "posts",
    };
    let covers = if ask.is_guest {
        format!("{what} at their address")
    } else {
        what.to_string()
    };
    let reason = ban_reason(ask.reason);
    let row = modlog::Entry {
        action: "restrict",
        target: row_target,
        target_name: row_name,
        reason: &reason,
        detail: &modlog::ban_detail(&covers, u64::from(duration)),
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, session_id, row).await {
        warn!("keeping a restriction: {e:#}");
        admin_error(tx, "the restriction could not be kept").await;
        return false;
    }
    let now = now_secs();
    let held = Held {
        voice: ask.voice,
        text: ask.text,
        by: modlog::clip(&banned_by(state, session_id), 64),
        reason,
        expires_at: (duration > 0).then(|| now.saturating_add(i64::from(duration))),
    };
    if let Some(relay) = &state.accounts {
        if let Err(e) = relay.restriction_put(&key, &held, now).await {
            warn!("keeping a restriction: {e:#}");
            admin_error(tx, "the restriction could not be kept").await;
            return false;
        }
    }
    state.restrictions.insert(key, held);
    true
}

/// As `restrict`. There has to be a moderator's restriction to lift: the wait is
/// waived only by giving a group.
async fn lift(
    state: &ServerState,
    session_id: SessionId,
    key: Key,
    (row_target, row_name): (Option<[u8; 16]>, &str),
    tx: &ControlTx,
) -> bool {
    if !state.restrictions.contains_key(&key) {
        admin_error(tx, "no moderator has restricted them").await;
        return false;
    }
    let row = modlog::Entry {
        action: "unrestrict",
        target: row_target,
        target_name: row_name,
        ..Default::default()
    };
    if let Err(e) = modlog::put(state, session_id, row).await {
        warn!("keeping a lifted restriction: {e:#}");
        admin_error(tx, "lifting the restriction could not be kept").await;
        return false;
    }
    if let Some(relay) = &state.accounts {
        if let Err(e) = relay.restriction_delete(&key).await {
            warn!("lifting a restriction: {e:#}");
            admin_error(tx, "lifting the restriction could not be kept").await;
            return false;
        }
    }
    state.restrictions.remove(&key);
    true
}
