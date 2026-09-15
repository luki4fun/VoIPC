//! Who may hear whom, in a channel whose `routed` flag is on.
//!
//! Everywhere else — which is everywhere, by default — this module holds
//! nothing and voice fans out to the whole channel exactly as it did before it
//! existed. Routing is opt-in per channel because it is the **only** state in
//! which this server is told anything about who hears whom, and that is a
//! trade the operator (and the people in the channel, who are told) should be
//! making deliberately.
//!
//! ## The two writers
//!
//! 1. **The client**, with `SetAudioFilter`: "these are the people I want to
//!    hear". Self-declared, so it is not a security boundary — a patched
//!    client asks for everyone. It exists for scale: in a channel a game has
//!    spread across a map, every listener would otherwise receive and decode
//!    every talker, and both halves of that grow with the room.
//! 2. **The game server**, with `POST /game/v1/routes`: "these are the people
//!    who *may* hear each other". Authoritative — it overrides what a client
//!    asks for, so a patched one gains nothing.
//!
//! ## What this server learns, and what it must never learn
//!
//! It learns a set of session ids per listener, changing a few times a second.
//! It does **not** learn positions, ranges, distances, cell sizes, radio
//! channel names, or job names. The game server hashes its own buses (salted
//! per boot, which is what `boot` is for) before sending them, and this module
//! resolves them to "who hears whom" on receipt and then forgets them — there
//! is no map from a bus id to anything here, and the ids mean nothing between
//! one boot and the next.
//!
//! And it is not cryptographic separation: the channel still shares one media
//! key, so this stops packets reaching a cheat client, not a cheat client from
//! decrypting the packets it does get. Per-bus keying would need a second
//! stream per talker; the `key_id` in the media header is where it would go.

use std::collections::{HashMap, HashSet};

use dashmap::DashMap;
use tokio::time::Instant;
use voipc_protocol::types::{ChannelId, SessionId, UserId};

/// Longest a game server may ask us to hold a table for. A table is meant to
/// be refreshed a few times a second; one that is not being refreshed is a
/// game server that has gone away, and holding its answer any longer would
/// silence a channel nobody is driving.
pub const MAX_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// One game server's answer for one channel.
#[derive(Debug)]
struct Table {
    /// listener user id -> the user ids they may hear.
    hear: HashMap<UserId, HashSet<UserId>>,
    /// Highest `epoch` accepted for this `boot`; an older one is a stale POST
    /// arriving out of order.
    epoch: u64,
    /// The game server's own identifier for this run. A new one resets the
    /// epoch, so a game server whose epoch is a tick counter can restart
    /// without being refused for ever.
    boot: String,
    expires: Instant,
}

/// Per-channel routing state.
#[derive(Default)]
pub struct Routing {
    /// What each client asked to hear, by session. Absent = everybody.
    filters: DashMap<SessionId, HashSet<UserId>>,
    /// What each game server says may be heard, by channel.
    tables: DashMap<ChannelId, Table>,
    /// Channels whose current run of stale POSTs has already been logged.
    /// A refusal a few times a second is a log a remote party can grow.
    refusals_logged: DashMap<ChannelId, ()>,
}

/// What a game server is telling us, once its buses have been resolved.
pub struct Routes {
    pub epoch: u64,
    pub boot: String,
    pub ttl: std::time::Duration,
    /// listener -> who they may hear.
    pub hear: HashMap<UserId, HashSet<UserId>>,
}

/// Why a `POST /game/v1/routes` was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum RoutesError {
    /// An epoch we have already seen for this boot: a POST arriving late.
    Stale,
}

impl Routing {
    /// What this client asked to hear. `None` clears it.
    pub fn set_filter(&self, session_id: SessionId, allow: Option<Vec<UserId>>) {
        match allow {
            Some(ids) => {
                self.filters.insert(session_id, ids.into_iter().collect());
            }
            None => {
                self.filters.remove(&session_id);
            }
        }
    }

    /// Take a game server's answer for one channel.
    pub fn set_routes(&self, channel_id: ChannelId, routes: Routes, now: Instant) -> Result<(), RoutesError> {
        if let Some(existing) = self.tables.get(&channel_id) {
            // Same run, and an epoch we have already passed: a POST that
            // overtook its successor. A *different* run starts over, which is
            // what lets a game server restart with a tick counter for an epoch.
            //
            // An expired table has nothing to protect, so it does not get a
            // vote: a game server that restarts without changing `boot` — and
            // `boot` is optional — would otherwise be refused for ever, and the
            // channel would fall back to full fan-out with nothing to see but a
            // 409 a second.
            if existing.expires > now && existing.boot == routes.boot && routes.epoch <= existing.epoch
            {
                return Err(RoutesError::Stale);
            }
        }
        self.tables.insert(
            channel_id,
            Table {
                hear: routes.hear,
                epoch: routes.epoch,
                boot: routes.boot,
                expires: now + routes.ttl.min(MAX_TTL),
            },
        );
        Ok(())
    }

    /// Forget everything about one channel: it stopped being routed, or its
    /// last member left. `sessions` are the members whose own requests go with
    /// it — switching routing off has to hand *everybody* back at once, and a
    /// filter left lying about would be enforced again the moment somebody
    /// switched it back on.
    pub fn clear_channel(&self, channel_id: ChannelId, sessions: impl IntoIterator<Item = SessionId>) {
        self.tables.remove(&channel_id);
        // Including whether its refusals have been logged: a channel that is
        // gone leaves nothing behind, and the next one to take the id starts
        // its own run of them.
        self.refusals_logged.remove(&channel_id);
        for session_id in sessions {
            self.filters.remove(&session_id);
        }
    }

    /// Forget one session's filter (it disconnected, or changed channel).
    pub fn clear_session(&self, session_id: SessionId) {
        self.filters.remove(&session_id);
    }

    /// May `listener` hear `speaker` in this channel?
    ///
    /// Two rules, in this order, and the order is the whole design:
    ///
    /// 1. **A live table decides, and it fails closed per session.** Somebody
    ///    the game server did not list hears nobody and is heard by nobody —
    ///    that is the enforcement half, and it has to hold for a client that
    ///    simply stops asking.
    /// 2. **No table, or an expired one, forwards everything** the client
    ///    asked for. Failing closed *here* would make "keep the game server
    ///    from POSTing" the whole attack: kill it, and the channel goes
    ///    silent. A channel nobody is driving behaves as it did in 0.7.
    pub fn may_hear(
        &self,
        channel_id: ChannelId,
        listener: UserId,
        listener_session: SessionId,
        speaker: UserId,
        now: Instant,
    ) -> bool {
        if let Some(table) = self.tables.get(&channel_id) {
            if table.expires > now {
                return table.hear.get(&listener).is_some_and(|s| s.contains(&speaker));
            }
        }
        match self.filters.get(&listener_session) {
            Some(allow) => allow.contains(&speaker),
            None => true,
        }
    }

    /// Should this refusal be logged? True once per run of them, so a game
    /// server stuck behind its own epoch is visible without letting it write a
    /// line a few times a second for as long as it is running.
    pub fn log_refused(&self, channel_id: ChannelId) -> bool {
        self.refusals_logged.insert(channel_id, ()).is_none()
    }

    /// A POST went through, so the next refusal is news again.
    pub fn log_accepted(&self, channel_id: ChannelId) {
        self.refusals_logged.remove(&channel_id);
    }

    /// Whether a live table is driving this channel; the admin-visible answer
    /// to "is the game server actually talking to us".
    #[allow(dead_code)]
    pub fn table_live(&self, channel_id: ChannelId, now: Instant) -> bool {
        self.tables
            .get(&channel_id)
            .is_some_and(|t| t.expires > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hear(pairs: &[(UserId, &[UserId])]) -> HashMap<UserId, HashSet<UserId>> {
        pairs
            .iter()
            .map(|(k, v)| (*k, v.iter().copied().collect()))
            .collect()
    }

    fn routes(epoch: u64, boot: &str, pairs: &[(UserId, &[UserId])]) -> Routes {
        Routes {
            epoch,
            boot: boot.into(),
            ttl: std::time::Duration::from_secs(3),
            hear: hear(pairs),
        }
    }

    #[test]
    fn with_nothing_configured_everyone_hears_everyone() {
        let r = Routing::default();
        let now = Instant::now();
        assert!(r.may_hear(5, 1, 1, 2, now), "a quiet router must not silence anybody");
    }

    #[test]
    fn a_client_filter_is_only_a_request() {
        let r = Routing::default();
        let now = Instant::now();
        r.set_filter(1, Some(vec![2, 3]));
        assert!(r.may_hear(5, 1, 1, 2, now));
        assert!(!r.may_hear(5, 1, 1, 9, now), "an unlisted speaker was forwarded");
        // It is the listener's own filter, not anybody else's
        assert!(r.may_hear(5, 7, 7, 9, now));
        // And clearing it restores the whole channel
        r.set_filter(1, None);
        assert!(r.may_hear(5, 1, 1, 9, now));
    }

    #[test]
    fn a_live_table_overrides_what_a_client_asks_for() {
        let r = Routing::default();
        let now = Instant::now();
        // The client asks for everybody by asking for nothing
        r.set_filter(1, None);
        r.set_routes(5, routes(1, "boot-a", &[(1, &[2]), (2, &[1])]), now).unwrap();
        assert!(r.may_hear(5, 1, 1, 2, now));
        // A patched client cannot widen it
        assert!(!r.may_hear(5, 1, 1, 9, now), "a client widened the game server's table");
        // Fails closed per session, in both directions
        assert!(!r.may_hear(5, 9, 9, 1, now), "an unlisted listener heard somebody");
        assert!(!r.may_hear(5, 1, 1, 9, now), "an unlisted speaker was heard");
    }

    #[test]
    fn an_expired_table_hands_the_channel_back_rather_than_silencing_it() {
        // Fail *open* at the table level. The other way round, "stop the game
        // server from posting" is the whole attack: kill it and the channel
        // goes quiet.
        let r = Routing::default();
        let now = Instant::now();
        r.set_routes(5, routes(1, "boot-a", &[(1, &[2])]), now).unwrap();
        assert!(!r.may_hear(5, 1, 1, 9, now));
        let later = now + std::time::Duration::from_secs(4);
        assert!(r.may_hear(5, 1, 1, 9, later), "an expired table kept culling");
        assert!(!r.table_live(5, later));
    }

    #[test]
    fn a_ttl_cannot_be_asked_to_outlive_the_cap() {
        let r = Routing::default();
        let now = Instant::now();
        let mut long = routes(1, "boot-a", &[(1, &[2])]);
        long.ttl = std::time::Duration::from_secs(86_400);
        r.set_routes(5, long, now).unwrap();
        assert!(!r.table_live(5, now + MAX_TTL + std::time::Duration::from_secs(1)));
    }

    #[test]
    fn a_restarted_game_server_is_not_refused_for_ever() {
        let r = Routing::default();
        let now = Instant::now();
        r.set_routes(5, routes(100, "boot-a", &[(1, &[2])]), now).unwrap();
        // A POST that overtook its successor is dropped
        assert_eq!(
            r.set_routes(5, routes(99, "boot-a", &[(1, &[9])]), now),
            Err(RoutesError::Stale)
        );
        assert!(r.may_hear(5, 1, 1, 2, now));
        // …but a new run starts over, however low its epoch counter is. The
        // other way round, a game server whose epoch is a tick counter would
        // be refused for ever after a restart, and the channel would fall back
        // to full fan-out with nothing to notice.
        r.set_routes(5, routes(1, "boot-b", &[(1, &[9])]), now).unwrap();
        assert!(r.may_hear(5, 1, 1, 9, now));
        assert!(!r.may_hear(5, 1, 1, 2, now));
    }

    #[test]
    fn switching_routing_off_hands_everybody_back() {
        let r = Routing::default();
        let now = Instant::now();
        r.set_routes(5, routes(1, "boot-a", &[(1, &[2])]), now).unwrap();
        // And the members' own requests go with the table: a filter left lying
        // about would be enforced again the moment somebody switched routing
        // back on, and nobody would be able to tell why they could not hear.
        r.set_filter(1, Some(vec![2]));
        r.clear_channel(5, [1]);
        assert!(r.may_hear(5, 1, 1, 9, now), "a filter outlived the routing it belonged to");
    }

    #[test]
    fn a_restart_is_not_refused_for_ever_once_the_old_table_has_expired() {
        // `boot` is optional, and a tick counter for an epoch is exactly what
        // the docs warn about — so a game server that restarts without changing
        // either would post a lower epoch for ever. Refusing it leaves the
        // channel in full fan-out with nothing to see but a 409 a second.
        let r = Routing::default();
        let now = Instant::now();
        r.set_routes(5, routes(500, "", &[(1, &[2])]), now).unwrap();
        assert_eq!(
            r.set_routes(5, routes(9, "", &[(1, &[9])]), now),
            Err(RoutesError::Stale),
            "a late POST overwrote a newer one"
        );
        // …but once the table it was protecting has expired, it has nothing
        // left to protect
        let later = now + std::time::Duration::from_secs(4);
        r.set_routes(5, routes(1, "", &[(1, &[9])]), later).unwrap();
        assert!(r.may_hear(5, 1, 1, 9, later));
    }
}
