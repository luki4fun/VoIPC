//! Who takes a report of a message (1.10). A report is a direct message to each of
//! them, which the relay passes like any other and cannot read: it keeps no report
//! and knows of none. All it does for one is answer who holds `voipc:reports`.

use l4f_accounts::scope;
use rand::seq::SliceRandom;
use tracing::warn;
use voipc_protocol::types::{ReportTaker, SessionId, UserId, MAX_REPORT_TAKERS};

use crate::accounts::{takers_away, REPORTS};
use crate::state::ServerState;

/// `ClientMessage::ReportTakersGet` past `report_rate`.
pub const ASKED_TOO_OFTEN: &str = "you asked who takes reports too often: try again in a minute";

/// Those here, in no order the asker can lean on, so that the load is shared; then
/// those away, for an account (a guest cannot keep anything for them) that is not
/// behind a pseudonym itself (the relay refuses that copy).
///
/// Someone under a pseudonym is not named: this answer pairs a user id with a real
/// name, and an anonymous channel's roster shows that id under the pseudonym.
pub async fn takers_for(
    state: &ServerState,
    session_id: SessionId,
    asker: UserId,
) -> Vec<ReportTaker> {
    // Collected first: `names_of` takes the channels lock and a shard
    let holders: Vec<(UserId, Option<[u8; 16]>)> = state
        .sessions
        .iter()
        .filter(|s| {
            s.user_id != asker
                && (s.is_admin
                    || s.account
                        .as_ref()
                        .is_some_and(|a| scope::allowed(&a.scopes, REPORTS)))
        })
        .map(|s| (s.user_id, s.account.as_ref().map(|a| a.user.id.0)))
        .collect();
    let mut takers = Vec::with_capacity(holders.len());
    for (user_id, account) in holders {
        let (name, alias) = state.names_of(user_id).await;
        if alias.is_none() && !name.is_empty() {
            takers.push(ReportTaker {
                user_id: Some(user_id),
                account,
                name,
            });
        }
    }
    takers.shuffle(&mut rand::thread_rng());
    takers.truncate(MAX_REPORT_TAKERS);

    let room = MAX_REPORT_TAKERS - takers.len();
    let keeps = state
        .sessions
        .get(&session_id)
        .is_some_and(|s| s.account.is_some());
    let Some(relay) = state
        .accounts
        .as_ref()
        .filter(|r| r.cloud && keeps && room > 0)
    else {
        return takers;
    };
    if state.names_of(asker).await.1.is_some() {
        return takers;
    }
    match takers_away(state, relay, room).await {
        Ok(mut away) => {
            away.shuffle(&mut rand::thread_rng());
            away.truncate(room);
            takers.append(&mut away);
        }
        Err(e) => warn!("reading who takes reports: {e:#}"),
    }
    takers
}
