//! What the relay carries now, for its admin's Load view (protocol v25): who is here, the
//! shares and the video they cost against `[media]`, memory, processor, the UDP socket's
//! drops, the last minute's refusals, and plain warnings where a limit is near. With
//! `[pool]`, its media edges too (protocol v26).

use voipc_protocol::types::{LoadReport, ShareLoad};

use crate::state::ServerState;

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
        // R2 fills it from `gk::Groups::stats` (plan 2j)
        groups: vec![],
    }
}
