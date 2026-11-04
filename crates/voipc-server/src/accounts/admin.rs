//! `AccountRequest::Admin` (1.7): users, groups (l4f roles) and their
//! privileges (scopes), invites and channel gates, from the app. l4f checks
//! every scope (`Actor`); this adds the step-up and what a change does to
//! the people online.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use l4f_accounts::model::{AccountId, User};
use l4f_accounts::service::{Actor, Ctx, Error, RoleForm, SecondFactor};
use voipc_protocol::messages::{AccountReply, AdminOp, AdminReply};
use voipc_protocol::types::{AdminUser, AuditRow, GroupInfo, InviteInfo};

use super::{refused, Powers, Relay};
use crate::config::RegistrationMode;
use crate::state::ServerState;

/// Accounts a page of the user list holds.
const PAGE: u32 = 50;
/// How long a code given for a step-up lasts.
const STEP_UP: Duration = Duration::from_secs(10 * 60);
/// What an account's history shows here: what admins and the account did
/// to its access, not every sign-in.
const AUDIT_EVENTS: &[&str] = &[
    "account_delete",
    "devkey_add",
    "devkey_revoke",
    "disable",
    "enable",
    "invite_create",
    "invite_revoke",
    "password_change",
    "recovery_new",
    "register",
    "role_grant",
    "role_revoke",
    "totp_off",
    "totp_on",
    "totp_reset",
];

fn no(e: Error) -> AccountReply {
    refused("Admin", e.message())
}

fn admin_user(u: &User) -> AdminUser {
    AdminUser {
        id: u.id.0,
        name: u.username.clone(),
        totp: u.totp_enabled,
        created_at: u.created_at,
    }
}

pub(super) async fn handle(
    state: &Arc<ServerState>,
    relay: &Relay,
    session_id: u32,
    user: &User,
    ctx: &Ctx,
    op: AdminOp,
    code: Option<String>,
) -> Result<AccountReply> {
    let scopes = state
        .sessions
        .get(&session_id)
        .and_then(|s| s.account.as_ref().map(|a| a.scopes.clone()))
        .unwrap_or_default();
    let actor = Actor {
        user,
        scopes: &scopes,
    };
    let a = &relay.accounts;
    let out = |r: AdminReply| Ok(AccountReply::Admin(r));
    // A step that hands out power asks for a fresh code first
    macro_rules! step_up {
        () => {
            if let Some(r) = step_up(state, relay, session_id, user, ctx, code.as_deref()).await {
                return Ok(r);
            }
        };
    }
    match op {
        AdminOp::Users { search, offset } => {
            let q = Some(search.trim()).filter(|s| !s.is_empty());
            match a.list_users(actor, q, PAGE, offset).await {
                Ok((users, total)) => out(AdminReply::Users {
                    search,
                    offset,
                    total: total.clamp(0, u32::MAX as i64) as u32,
                    users: users.iter().map(admin_user).collect(),
                }),
                Err(e) => Ok(no(e)),
            }
        }
        AdminOp::User { id } => Ok(user_reply(relay, actor, AccountId(id)).await),
        AdminOp::Grant { id, group } => {
            if holds_power(relay, &group).await {
                step_up!();
            }
            if let Err(e) = a.grant_role(ctx, actor, AccountId(id), &group).await {
                return Ok(no(e));
            }
            if let Some(sid) = online(state, &id) {
                super::refresh(state, relay, sid, AccountId(id)).await?;
            }
            crate::gates::prune_logs(state).await;
            Ok(user_reply(relay, actor, AccountId(id)).await)
        }
        AdminOp::Revoke { id, group } => {
            let power = holds_power(relay, &group).await;
            if power {
                step_up!();
            }
            if let Err(e) = a.revoke_role(ctx, actor, AccountId(id), &group).await {
                return Ok(no(e));
            }
            if let Some(sid) = online(state, &id) {
                if power {
                    // l4f ended its sessions: the connection's too
                    crate::session::force_disconnect(
                        state,
                        sid,
                        "Your groups on this server changed. Sign in again.",
                    )
                    .await;
                } else {
                    super::refresh(state, relay, sid, AccountId(id)).await?;
                }
            }
            crate::gates::prune_logs(state).await;
            Ok(user_reply(relay, actor, AccountId(id)).await)
        }
        AdminOp::Reset2fa { id } => {
            step_up!();
            if let Err(e) = a.reset_2fa(ctx, actor, AccountId(id)).await {
                return Ok(no(e));
            }
            if let Some(sid) = online(state, &id) {
                crate::session::force_disconnect(
                    state,
                    sid,
                    "An admin reset your two-factor codes. Sign in with your password.",
                )
                .await;
            }
            Ok(user_reply(relay, actor, AccountId(id)).await)
        }
        AdminOp::Groups => Ok(groups_reply(relay, actor).await),
        AdminOp::GroupSave { create, group } => {
            step_up!();
            let form = RoleForm {
                name: &group.name,
                description: &group.description,
                badge: &group.badge,
                scopes: &group.scopes,
            };
            let r = if create {
                a.create_role(ctx, actor, form).await.map(|_| ())
            } else {
                a.update_role(ctx, actor, form).await
            };
            if let Err(e) = r {
                return Ok(no(e));
            }
            // Its holders' privileges and badges, wherever they are
            super::revalidate(state).await;
            crate::gates::prune_logs(state).await;
            Ok(groups_reply(relay, actor).await)
        }
        AdminOp::GroupDelete { name } => {
            step_up!();
            if let Some(channel) = crate::gates::uses(state, &name).await {
                return Ok(refused(
                    "Admin",
                    &format!(
                        "#{channel} lets in or speaks by this group. Change that channel first."
                    ),
                ));
            }
            if let Err(e) = a.delete_role(ctx, actor, &name).await {
                return Ok(no(e));
            }
            super::revalidate(state).await;
            Ok(groups_reply(relay, actor).await)
        }
        AdminOp::GroupMembers { name, offset } => {
            match a.role_members(actor, &name, PAGE, offset).await {
                Ok((users, total)) => out(AdminReply::Members {
                    name,
                    offset,
                    total: total.clamp(0, u32::MAX as i64) as u32,
                    users: users.iter().map(admin_user).collect(),
                }),
                Err(e) => Ok(no(e)),
            }
        }
        AdminOp::Invites => Ok(invites_reply(relay, actor).await),
        AdminOp::InviteNew { name, days } => {
            let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
            if relay.registration == RegistrationMode::Closed && name.is_none() {
                return Ok(refused(
                    "Admin",
                    "Sign-up is closed here: an invite names the account it makes.",
                ));
            }
            match a
                .invite_create(ctx, actor, name.as_deref(), i64::from(days))
                .await
            {
                Ok(code) => out(AdminReply::InviteCode { code }),
                Err(e) => Ok(no(e)),
            }
        }
        AdminOp::InviteRevoke { id } => {
            if let Err(e) = a.invite_revoke(ctx, actor, &id).await {
                return Ok(no(e));
            }
            Ok(invites_reply(relay, actor).await)
        }
        AdminOp::GateGet { channel_id } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels' gates."));
            }
            let gate = state
                .channels
                .read()
                .await
                .get(&channel_id)
                .filter(|c| state.passes(session_id, &c.gate.groups))
                .map(|c| c.gate.clone());
            let Some(gate) = gate else {
                return Ok(refused("Admin", "channel does not exist"));
            };
            gate_reply(relay, channel_id, gate).await
        }
        AdminOp::GateSet { channel_id, gate } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels' gates."));
            }
            match crate::gates::set(state, session_id, channel_id, gate).await {
                Ok(gate) => gate_reply(relay, channel_id, gate).await,
                Err(reason) => Ok(refused("Admin", &reason)),
            }
        }
    }
}

/// `None` once the session has a fresh step-up (now, with `code`, or within
/// the last ten minutes); otherwise what to answer.
async fn step_up(
    state: &ServerState,
    relay: &Relay,
    session_id: u32,
    user: &User,
    ctx: &Ctx,
    code: Option<&str>,
) -> Option<AccountReply> {
    let fresh = state.sessions.get(&session_id).is_some_and(|s| {
        s.account
            .as_ref()
            .and_then(|a| a.step_up_at)
            .is_some_and(|t| t.elapsed() < STEP_UP)
    });
    if fresh {
        return None;
    }
    let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Some(AccountReply::Admin(AdminReply::StepUp));
    };
    if let Err(e) = relay
        .accounts
        .second_factor_check(ctx, user, SecondFactor::Totp(code))
        .await
    {
        return Some(no(e));
    }
    if let Some(mut s) = state.sessions.get_mut(&session_id) {
        if let Some(a) = s.account.as_mut() {
            a.step_up_at = Some(Instant::now());
        }
    }
    None
}

/// Whether the group hands out privileges (an unknown one is checked by l4f).
async fn holds_power(relay: &Relay, group: &str) -> bool {
    !matches!(relay.store().role_by_name(group.trim()).await, Ok(Some(r)) if r.scopes.is_empty())
}

fn online(state: &ServerState, account: &[u8; 16]) -> Option<u32> {
    state.account_sessions.get(account).map(|s| *s)
}

/// An account's name, looked up once per reply.
async fn name_of(
    relay: &Relay,
    names: &mut HashMap<AccountId, Option<String>>,
    a: Option<AccountId>,
) -> Option<String> {
    let a = a?;
    if let Some(n) = names.get(&a) {
        return n.clone();
    }
    let n = relay
        .store()
        .user_by_id(a)
        .await
        .ok()
        .flatten()
        .map(|u| u.username);
    names.insert(a, n.clone());
    n
}

async fn user_reply(relay: &Relay, actor: Actor<'_>, id: AccountId) -> AccountReply {
    let detail = match relay.accounts.user_detail(actor, id).await {
        Ok(d) => d,
        Err(e) => return no(e),
    };
    let mut names: HashMap<AccountId, Option<String>> = HashMap::new();
    let mut audit = Vec::new();
    for e in detail
        .audit
        .iter()
        .filter(|e| AUDIT_EVENTS.contains(&e.event.as_str()))
    {
        let actor = name_of(relay, &mut names, e.actor_id.filter(|a| *a != id)).await;
        audit.push(AuditRow {
            event: e.event.clone(),
            actor,
            detail: e.detail.clone(),
            at: e.at,
        });
    }
    AccountReply::Admin(AdminReply::User {
        user: admin_user(&detail.user),
        groups: detail.roles.into_iter().map(|r| r.name).collect(),
        audit,
    })
}

async fn groups_reply(relay: &Relay, actor: Actor<'_>) -> AccountReply {
    match relay.accounts.roles(actor).await {
        Ok(roles) => AccountReply::Admin(AdminReply::Groups {
            groups: roles
                .into_iter()
                .map(|r| GroupInfo {
                    name: r.name,
                    description: r.description,
                    badge: r.badge.unwrap_or_default(),
                    scopes: r.scopes,
                    builtin: r.builtin,
                })
                .collect(),
        }),
        Err(e) => no(e),
    }
}

async fn invites_reply(relay: &Relay, actor: Actor<'_>) -> AccountReply {
    let invites = match relay.accounts.invites(actor).await {
        Ok(i) => i,
        Err(e) => return no(e),
    };
    let mut names = HashMap::new();
    let mut out = Vec::new();
    for i in invites {
        out.push(InviteInfo {
            id: i.id,
            name: i.username,
            created_by: name_of(relay, &mut names, i.created_by).await,
            expires_at: i.expires_at,
            used_by: name_of(relay, &mut names, i.used_by).await,
        });
    }
    AccountReply::Admin(AdminReply::Invites { invites: out })
}

async fn gate_reply(
    relay: &Relay,
    channel_id: u32,
    gate: voipc_protocol::types::ChannelGate,
) -> Result<AccountReply> {
    let groups = relay
        .store()
        .roles()
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();
    Ok(AccountReply::Admin(AdminReply::Gate {
        channel_id,
        gate,
        groups,
    }))
}
