//! `AccountRequest::Admin` (1.7): users, groups (l4f roles) and their
//! privileges (scopes), invites and channel gates, from the app. l4f checks
//! every scope (`Actor`); this adds the step-up and what a change does to
//! the people online.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use l4f_accounts::model::{AccountId, User};
use l4f_accounts::scope;
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
    "invite_link_new",
    "invite_link_revoke",
    "invite_link_used",
    "password_change",
    "profile_reset",
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
            crate::layout::send_styles_all(state).await;
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
            crate::layout::send_styles_all(state).await;
            Ok(groups_reply(relay, actor).await)
        }
        AdminOp::GroupStyle { name, color } => {
            if !scope::covers(&scopes, &["roles:admin".to_string()]) {
                return Ok(refused("Admin", "You may not change groups."));
            }
            if color.is_some_and(|c| c > 0xff_ffff) {
                return Ok(refused("Admin", "That is not a colour."));
            }
            let Some(role) = relay
                .store()
                .roles()
                .await?
                .into_iter()
                .find(|r| r.name == name)
            else {
                return Ok(refused("Admin", "No such group."));
            };
            if !scope::covers(&scopes, &role.scopes) {
                return Ok(refused("Admin", "You may not change that group."));
            }
            relay.group_color_put(role.id, color).await?;
            crate::layout::send_styles_all(state).await;
            Ok(groups_reply(relay, actor).await)
        }
        AdminOp::ProfileReset { id, name, picture } => {
            if !scope::allowed(&scopes, super::PROFILES) {
                return Ok(refused("Admin", "You may not change profiles."));
            }
            let target = relay.store().user_scopes(AccountId(id)).await?;
            if !scope::covers(&scopes, &target) {
                return Ok(refused("Admin", "You may not change that account."));
            }
            if !name && !picture {
                return Ok(refused("Admin", "That clears nothing."));
            }
            if name {
                relay.profile_name_put(AccountId(id), None).await?;
            }
            if picture {
                relay.profile_picture_put(AccountId(id), None).await?;
            }
            relay
                .store()
                .audit(
                    Some(AccountId(id)),
                    Some(user.id),
                    "profile_reset",
                    match (name, picture) {
                        (true, true) => "name and picture",
                        (true, false) => "name",
                        _ => "picture",
                    },
                    "",
                )
                .await?;
            super::profile::tell(state, relay, id).await;
            Ok(AccountReply::ProfileDone)
        }
        AdminOp::ServerProfileSet { name, description } => {
            if !super::is_star(&scopes) {
                return Ok(refused("Admin", "Only an admin may change that."));
            }
            step_up!();
            let checked = super::profile::server_name_ok(&name)
                .and_then(|n| Ok((n, super::profile::server_description_ok(&description)?)));
            let (name, description) = match checked {
                Ok(c) => c,
                Err(reason) => return Ok(refused("Admin", &reason)),
            };
            relay.server_profile_put(name, description).await?;
            super::profile::send_server_profile_all(state).await;
            Ok(AccountReply::ProfileDone)
        }
        AdminOp::ServerIconSet { image } => {
            if !super::is_star(&scopes) {
                return Ok(refused("Admin", "Only an admin may change that."));
            }
            step_up!();
            if image
                .as_deref()
                .is_some_and(|i| !super::profile::picture_ok(i))
            {
                return Ok(refused(
                    "Admin",
                    "An icon is a PNG or WebP of at most 32 KB.",
                ));
            }
            relay.server_icon_put(image.as_deref()).await?;
            super::profile::send_server_profile_all(state).await;
            Ok(AccountReply::ProfileDone)
        }
        AdminOp::InviteLinks => {
            if !scope::allowed(&scopes, "users:admin") {
                return Ok(refused("Admin", "You may not manage invites."));
            }
            links_reply(relay).await
        }
        AdminOp::InviteLinkNew {
            max_uses,
            days,
            group,
        } => {
            if !scope::allowed(&scopes, "users:admin") {
                return Ok(refused("Admin", "You may not manage invites."));
            }
            if relay.registration == RegistrationMode::Closed {
                return Ok(refused(
                    "Admin",
                    "Sign-up is closed here: a link would let nobody in.",
                ));
            }
            if !(1..=super::links::MAX_USES).contains(&max_uses) || days > super::links::MAX_DAYS {
                return Ok(refused("Admin", "That is outside what a link can be."));
            }
            let group = group.filter(|g| !g.trim().is_empty());
            if let Some(name) = &group {
                let role = relay.store().role_by_name(name).await?;
                if !role.is_some_and(|r| r.scopes.is_empty()) {
                    return Ok(refused(
                        "Admin",
                        "A link's starting group must hold no privileges: anyone with the link gets it.",
                    ));
                }
            }
            match relay.link_new(max_uses, days, group.as_deref(), user.id).await? {
                Some((code, id)) => {
                    let what = format!(
                        "{id}: {max_uses} people{}",
                        group.as_deref().map(|g| format!(", starting in {g}")).unwrap_or_default()
                    );
                    relay
                        .store()
                        .audit(Some(user.id), Some(user.id), "invite_link_new", &what, "")
                        .await?;
                    out(AdminReply::InviteLinkCode { code })
                }
                None => Ok(refused(
                    "Admin",
                    "This server keeps 100 links at most. Revoke one first.",
                )),
            }
        }
        AdminOp::InviteLinkRevoke { id } => {
            if !scope::allowed(&scopes, "users:admin") {
                return Ok(refused("Admin", "You may not manage invites."));
            }
            if relay.link_revoke(&id).await? {
                relay
                    .store()
                    .audit(Some(user.id), Some(user.id), "invite_link_revoke", &id, "")
                    .await?;
            }
            links_reply(relay).await
        }
        AdminOp::GroupOrder { names } => {
            if !scope::covers(&scopes, &["roles:admin".to_string()]) {
                return Ok(refused("Admin", "You may not change groups."));
            }
            let now = relay.groups_in_order().await?;
            let mut asked = names.clone();
            asked.sort();
            let mut held: Vec<&str> = now.iter().map(|(r, _)| r.name.as_str()).collect();
            held.sort();
            if asked != held {
                return Ok(refused("Admin", "The groups changed meanwhile. Try again."));
            }
            // A row's top badge and its section go by this: a group they could not
            // have made themselves stays where it is, and nothing crosses it
            let mut side = HashMap::new();
            let mut crossed = 0;
            for (i, (role, _)) in now.iter().enumerate() {
                if !scope::covers(&scopes, &role.scopes) {
                    if names[i] != role.name {
                        return Ok(refused(
                            "Admin",
                            &format!(
                                "You may not move {}, or put a group in its place.",
                                role.name
                            ),
                        ));
                    }
                    crossed += 1;
                }
                side.insert(role.name.as_str(), crossed);
            }
            let mut crossed = 0;
            for (i, (role, _)) in now.iter().enumerate() {
                if !scope::covers(&scopes, &role.scopes) {
                    crossed += 1;
                }
                if side.get(names[i].as_str()) != Some(&crossed) {
                    return Ok(refused(
                        "Admin",
                        "A group cannot move past one you could not have made.",
                    ));
                }
            }
            for (i, name) in names.iter().enumerate() {
                if let Some((role, _)) = now.iter().find(|(r, _)| r.name == *name) {
                    relay.group_position_put(role.id, i as i64).await?;
                }
            }
            // Not a whole server's rows again: clients sort what they have
            crate::layout::send_styles_all(state).await;
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
        AdminOp::ChannelSave {
            id,
            name,
            description,
            text,
            auto_join,
            category,
            gate,
        } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels."));
            }
            Ok(done(
                crate::layout::channel_save(
                    state,
                    session_id,
                    id,
                    &name,
                    &description,
                    text,
                    auto_join,
                    category,
                    gate,
                )
                .await
                .map(Some),
            ))
        }
        AdminOp::ChannelDelete { id } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels."));
            }
            // Everything kept in it goes: not a step for one stolen session
            step_up!();
            Ok(done(
                crate::layout::channel_delete(state, session_id, id)
                    .await
                    .map(|()| None),
            ))
        }
        AdminOp::CategorySave { id, name } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels."));
            }
            Ok(done(
                crate::layout::category_save(state, session_id, id, &name)
                    .await
                    .map(|_| None),
            ))
        }
        AdminOp::CategoryDelete { id } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels."));
            }
            Ok(done(
                crate::layout::category_delete(state, session_id, id)
                    .await
                    .map(|()| None),
            ))
        }
        AdminOp::LayoutSet {
            categories,
            channels,
        } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels."));
            }
            Ok(done(
                crate::layout::layout_set(state, session_id, &categories, &channels)
                    .await
                    .map(|()| None),
            ))
        }
        AdminOp::WelcomeSet { channel_id } => {
            if !state.can(session_id, Powers::CHANNELS) {
                return Ok(refused("Admin", "You may not change channels."));
            }
            Ok(done(
                crate::layout::welcome_set(state, session_id, channel_id)
                    .await
                    .map(|()| None),
            ))
        }
    }
}

async fn links_reply(relay: &Relay) -> Result<AccountReply> {
    Ok(AccountReply::Admin(AdminReply::InviteLinks {
        links: relay.links().await?,
    }))
}

/// What a channel step came to.
fn done(r: Result<Option<u32>, String>) -> AccountReply {
    match r {
        Ok(channel_id) => AccountReply::Admin(AdminReply::ChannelDone { channel_id }),
        Err(reason) => refused("Admin", &reason),
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

/// In the server's order.
async fn groups_reply(relay: &Relay, actor: Actor<'_>) -> AccountReply {
    if let Err(e) = relay.accounts.roles(actor).await {
        return no(e);
    }
    match relay.groups_in_order().await {
        Ok(roles) => AccountReply::Admin(AdminReply::Groups {
            groups: roles
                .into_iter()
                .map(|(r, _)| GroupInfo {
                    name: r.name,
                    description: r.description,
                    badge: r.badge.unwrap_or_default(),
                    scopes: r.scopes,
                    builtin: r.builtin,
                })
                .collect(),
        }),
        Err(e) => {
            tracing::warn!("reading groups: {e:#}");
            refused("Admin", "Could not read the groups.")
        }
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
