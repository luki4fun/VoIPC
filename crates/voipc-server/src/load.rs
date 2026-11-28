//! What the relay carries now, for its admin's Load view (protocol v25): who is here, the
//! shares and the video they cost against `[media]`, memory, processor, the UDP socket's
//! drops, the last minute's refusals, and plain warnings where a limit is near. With
//! `[pool]`, its media edges too (protocol v26).

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

use voipc_crypto::group_key::timers::EPOCH_AGE_MAX_SECS;
use voipc_protocol::types::{ChannelId, GroupLoad, LoadReport, ShareLoad};

use crate::state::ServerState;

/// A group this large has a row in Load whatever its state (plan 2j).
const GROUP_ROW_SEATS: u32 = 1000;
/// Groups' rows at most.
const GROUP_ROWS: usize = 50;
/// The group key's warnings listed at most, the rest counted: each live group raises up to
/// four, and the whole report goes in one frame (64 KiB).
const GK_WARNINGS: usize = 50;

/// `(RSS in MiB, CPU seconds)` of this process, from /proc; zeros off Linux.
pub(crate) fn own_usage() -> (u32, u64) {
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.trim().trim_end_matches(" kB").parse::<u64>().ok())
        })
        .map_or(0, |kb| (kb / 1024) as u32);
    let cpu = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|stat| {
            // After the name, which may hold spaces: utime and stime are the 12th and 13th
            let mut after = stat.rsplit(')').next()?.split_whitespace();
            let utime: u64 = after.nth(11)?.parse().ok()?;
            let stime: u64 = after.next()?.parse().ok()?;
            Some((utime + stime) / 100)
        })
        .unwrap_or(0);
    (rss, cpu)
}

pub async fn report(state: &ServerState) -> LoadReport {
    let media = &state.media;
    let (lobby, mut shares, rooms_full, video_kbps) = {
        let channels = state.channels.read().await;
        let lobby = channels.get(&0).map_or(0, |c| c.members.len()) as u32;
        let mut shares = Vec::new();
        for (id, channel) in channels.iter() {
            for share in channel.screen_shares.values() {
                shares.push(ShareLoad {
                    channel_id: *id,
                    sharer: state
                        .sessions
                        .get(&share.sharer_session_id)
                        .map(|s| s.username.clone())
                        .unwrap_or_default(),
                    viewers: share.viewers.len() as u32,
                    cap: media.share_viewers,
                    kbps: share.ceiling_kbps,
                    on_edges: share.on_edge.len() as u32,
                });
            }
        }
        let rooms_full: Vec<String> = channels
            .values()
            .filter(|c| !c.info.text && c.info.channel_id != 0 && !c.info.routed)
            .filter(|c| {
                let cap = match c.info.max_users {
                    0 => media.voice_room,
                    own => own,
                };
                cap > 0 && c.members.len() >= cap as usize
            })
            .map(|c| c.info.name.clone())
            .collect();
        // A viewer on an edge costs this relay nothing past the one copy that edge is sent
        let video_kbps = crate::state::video_egress_kbps(&channels);
        (lobby, shares, rooms_full, video_kbps)
    };
    shares.sort_by_key(|s| std::cmp::Reverse(s.viewers));
    let online = state.sessions.len() as u32;
    let video_budget_kbps = media.video_egress_mbit as u64 * 1000;
    let (rss_mib, cpu_secs) = own_usage();
    let last_minute = state.limits.last_minute();

    let mut warnings = Vec::new();
    if video_budget_kbps > 0 && video_kbps * 10 >= video_budget_kbps * 9 {
        warnings.push(format!(
            "Screen shares use {}% of the video this server may send ([media] video_egress_mbit): the next viewers are refused.",
            video_kbps * 100 / video_budget_kbps
        ));
    }
    // The cap is of the viewers this relay serves itself: edges carry the rest
    for s in shares
        .iter()
        .filter(|s| s.cap > 0 && s.viewers - s.on_edges >= s.cap)
    {
        warnings.push(format!(
            "{}'s share has {} viewers on this server, the most it takes ([media] share_viewers).",
            s.sharer,
            s.viewers - s.on_edges
        ));
    }
    for room in &rooms_full {
        warnings.push(format!(
            "{room} is full ([media] voice_room or its own limit)."
        ));
    }
    if state.max_users > 0 && online * 10 >= state.max_users * 9 {
        warnings.push(format!(
            "{online} of max_users {} are online.",
            state.max_users
        ));
    }
    if lobby > state.lobby.live_max {
        warnings.push(format!(
            "{lobby} stand in General, past live_lobby ({}): its list comes in pages and counts, not live.",
            state.lobby.live_max
        ));
    }
    if last_minute
        .iter()
        .any(|l| l.starts_with("UDP datagrams dropped"))
    {
        warnings.push(
            "The UDP socket dropped datagrams in the last minute: raise net.core.rmem_max (OPERATING.md 10a)."
                .into(),
        );
    }
    let edges = match &state.pool {
        Some(pool) => {
            let (edges, said) = pool.report();
            warnings.extend(said);
            if last_minute
                .iter()
                .any(|l| l.starts_with("edge: feed dropped frames"))
            {
                warnings.push(
                    "Feeds to edges dropped frames in the last minute: the way from this server to its edges is too slow for the shares they carry."
                        .into(),
                );
            }
            edges
        }
        None => Vec::new(),
    };
    // The group key's warnings (plan 2j), each naming the channel whose group shows a row:
    // the largest groups' first, as the table lists them, at most `GK_WARNINGS`
    let groups = state.gk.stats();
    let mut gk_warned = state.gk.warnings();
    let named: HashSet<ChannelId> = gk_warned.iter().map(|(c, _)| *c).collect();
    let seats: HashMap<ChannelId, u32> = groups.iter().map(|g| (g.channel_id, g.seats)).collect();
    gk_warned.sort_by_cached_key(|(c, w)| (Reverse(seats.get(c).copied()), *c, w.clone()));
    let more = gk_warned.len().saturating_sub(GK_WARNINGS);
    warnings.extend(gk_warned.into_iter().take(GK_WARNINGS).map(|(_, w)| w));
    if more > 0 {
        warnings.push(format!(
            "{more} more group key warnings: the server's log has each."
        ));
    }
    if state.sqlite_accounts && state.max_users > 10_000 {
        warnings.push(
            "Accounts are on SQLite, which signs people in one at a time: above 10,000 use Postgres."
                .into(),
        );
    }
    LoadReport {
        online,
        max_users: state.max_users,
        in_rooms: online.saturating_sub(lobby),
        lobby,
        live_lobby: state.lobby.live_max,
        shares,
        video_kbps,
        video_budget_kbps,
        rss_mib,
        cpu_secs,
        udp_dropped: crate::web::udp_drops(state.udp_port).unwrap_or(0),
        last_minute,
        warnings,
        edges,
        groups: groups_shown(groups, &named),
    }
}

/// The groups worth a row (plan 2j): those with something amiss or a warning naming their
/// channel first, then the largest from `GROUP_ROW_SEATS` seats, at most `GROUP_ROWS`.
fn groups_shown(mut all: Vec<GroupLoad>, named: &HashSet<ChannelId>) -> Vec<GroupLoad> {
    let flagged = |g: &GroupLoad| amiss(g) || named.contains(&g.channel_id);
    all.retain(|g| g.seats >= GROUP_ROW_SEATS || flagged(g));
    all.sort_by_key(|g| (!flagged(g), Reverse(g.seats)));
    all.truncate(GROUP_ROWS);
    all
}

/// No keyholder online for seated members, a head older than writers wait for (70 min), or
/// missed deadlines: what the relay's warnings name.
fn amiss(g: &GroupLoad) -> bool {
    (g.seats > 0 && g.keyholders_online == 0)
        || u64::from(g.last_commit_secs) > EPOCH_AGE_MAX_SECS
        || g.missed_deadlines > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(channel_id: u32, seats: u32, keyholders_online: u32) -> GroupLoad {
        GroupLoad {
            channel_id,
            seats,
            keyholders_online,
            ..GroupLoad::default()
        }
    }

    #[test]
    fn load_shows_large_groups_and_amiss_ones_first_and_at_most_fifty() {
        let mut all = vec![
            group(1, 10, 1),
            group(2, 2000, 1),
            group(3, 5, 0),
            group(4, 1000, 2),
            GroupLoad {
                missed_deadlines: 1,
                ..group(5, 3, 1)
            },
            GroupLoad {
                last_commit_secs: 71 * 60,
                ..group(6, 4, 1)
            },
        ];
        let shown: Vec<u32> = groups_shown(all.clone(), &HashSet::new())
            .iter()
            .map(|g| g.channel_id)
            .collect();
        assert_eq!(
            shown,
            vec![3, 6, 5, 2, 4],
            "a small healthy group has no row"
        );
        all.extend((100..200).map(|c| group(c, 5000, 1)));
        assert_eq!(groups_shown(all, &HashSet::new()).len(), GROUP_ROWS);
    }

    #[test]
    fn load_shows_a_small_group_a_warning_names_among_the_first() {
        let all = vec![group(1, 10, 1), group(2, 2000, 1), group(7, 4, 1)];
        let shown: Vec<u32> = groups_shown(all, &HashSet::from([7]))
            .iter()
            .map(|g| g.channel_id)
            .collect();
        assert_eq!(
            shown,
            vec![7, 2],
            "the group a warning names, then the large one"
        );
    }

    /// The group key's warnings reach Load's list, as `#<channel id>: <what>`.
    #[tokio::test]
    async fn load_lists_the_group_keys_warnings() {
        let state = crate::state::test_support::make_state();
        // Raised by a group's actor (gk_tests), with no seats: only the warning shows it
        state.gk.warn_for_test(7, "no keyholder online for 11 min");
        let load = report(&state).await;
        assert!(load
            .warnings
            .contains(&"#7: no keyholder online for 11 min".to_string()));
        assert!(load.groups.iter().any(|g| g.channel_id == 7));
    }

    /// Finding: every live group's warnings went into the report, whose one frame a
    /// keyholder of thousands of groups gone quiet would overflow (no reply at all). At
    /// most `GK_WARNINGS` are listed, the rest counted.
    #[tokio::test]
    async fn load_lists_at_most_fifty_group_key_warnings_and_counts_the_rest() {
        let state = crate::state::test_support::make_state();
        for channel in 1..=60 {
            state.gk.warn_for_test(channel, "keys late");
        }
        let load = report(&state).await;
        let listed = load.warnings.iter().filter(|w| w.starts_with('#')).count();
        assert_eq!(listed, GK_WARNINGS);
        assert!(load
            .warnings
            .contains(&"10 more group key warnings: the server's log has each.".to_string()));
    }
}
