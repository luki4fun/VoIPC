// How far a big community goes on one relay. Three questions:
//
//   community_load frames
//     How many members and channels fit the one 64 KiB frame a list travels in.
//     No relay needed.
//
//   community_load crypto 2000
//     What a real client pays for end-to-end keys in a channel of that many.
//     The relay is not involved in any of it, so the run below cannot show it.
//
//   community_load run 500 127.0.0.1:9987 [relay-pid]
//     N guests connect, then all join one text channel at once, then chat.
//     Reports latency, what was lost, and with the pid the relay's RSS and CPU.
//     The load clients hold no keys: their ciphertext is a timestamp and padding,
//     relayed verbatim, so this measures the relay and nothing else.
//
// The relay needs `max_users` above N. Load clients share the machine with it,
// so CPU times are the relay's own, and latencies are an upper bound.

#[path = "load_common/mod.rs"]
mod load_common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use load_common::{connect, enc, next_message, Error};
use voipc_crypto::{group, prekey, session, SignalStores};
use voipc_protocol::codec::{encode_server_msg, CONTROL_MSGS_PER_SEC, MAX_MSG_SIZE};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{ChannelInfo, ProximityMode, UserInfo};

const CHANNEL: &str = "CommunityLoad";
/// What a moderately long chat message comes to, sealed.
const CHAT_BYTES: usize = 200;
const CHAT_MESSAGES: u64 = 20;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("frames") => frames(),
        Some("crypto") => crypto(number(args.get(1), 2000)?).await,
        Some("run") => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("crypto provider");
            let pid = args.get(3).map(|p| p.parse()).transpose()?;
            let server = args.get(2).map_or("127.0.0.1:9987", String::as_str);
            run(number(args.get(1), 100)?, server, pid).await
        }
        _ => Err(
            "usage: community_load frames | crypto [N] | run [N] [host:port] [relay-pid]".into(),
        ),
    }
}

fn number(arg: Option<&String>, default: usize) -> Result<usize, Error> {
    Ok(arg.map(|a| a.parse()).transpose()?.unwrap_or(default))
}

fn percentile(values: &mut [u64], p: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[(values.len() * p / 100).min(values.len() - 1)]
}

// ── frames ───────────────────────────────────────────────────────────────

/// The largest count of `make`'s items whose message still frames.
fn largest_that_frames<T>(
    make: impl Fn(usize) -> T,
    wrap: impl Fn(Vec<T>) -> ServerMessage,
) -> usize {
    let (mut fits, mut over) = (0usize, MAX_MSG_SIZE as usize);
    while over - fits > 1 {
        let mid = (fits + over) / 2;
        match encode_server_msg(&wrap((0..mid).map(&make).collect())) {
            Ok(_) => fits = mid,
            Err(_) => over = mid,
        }
    }
    fits
}

fn member(i: usize, account: bool, badges: usize) -> UserInfo {
    UserInfo {
        user_id: 100_000 + i as u32,
        username: format!("member{i:06}"),
        channel_id: 0,
        is_muted: false,
        is_deafened: false,
        is_screen_sharing: false,
        is_admin: false,
        shares_history: false,
        account: account.then_some([7u8; 16]),
        is_moderator: false,
        badges: (0..badges).map(|b| format!("badge-group-{b}")).collect(),
    }
}

fn channel(i: usize, description: usize) -> ChannelInfo {
    ChannelInfo {
        channel_id: 1000 + i as u32,
        name: format!("channel-{i:06}"),
        description: "d".repeat(description),
        max_users: 0,
        user_count: 300,
        has_password: false,
        created_by: None,
        proximity: ProximityMode::Off,
        hidden: false,
        anonymous: false,
        screen_share: true,
        hide_members: false,
        text: true,
        auto_join: false,
        message_ttl_secs: 0,
        routed: false,
        announce: false,
        slow_mode_secs: 0,
        nsfw: false,
        log: format!("c:{i:016x}"),
    }
}

fn frames() -> Result<(), Error> {
    println!("one frame holds {MAX_MSG_SIZE} bytes; a list that does not fit never arrives");
    for (what, account, badges) in [
        ("guests, 12-letter names", false, 0),
        ("accounts", true, 0),
        ("accounts, 3 badges each", true, 3),
    ] {
        let n = largest_that_frames(
            |i| member(i, account, badges),
            |users| ServerMessage::UserList {
                channel_id: 0,
                users,
            },
        );
        println!("UserList: {n} {what}");
    }
    for description in [0, 64, 256] {
        let n = largest_that_frames(
            |i| channel(i, description),
            |channels| ServerMessage::ChannelList { channels },
        );
        println!("ChannelList: {n} channels with a {description}-byte description");
    }
    Ok(())
}

// ── crypto ───────────────────────────────────────────────────────────────

fn signal_stores(user_id: u32) -> Result<SignalStores, Error> {
    let identity = voipc_crypto::generate_identity_key_pair();
    let mut stores = SignalStores::new(&identity, 1000 + user_id);
    stores.own_user_id = user_id;
    prekey::generate_prekeys(&mut stores, &identity)?;
    Ok(stores)
}

fn stored_bytes(stores: &SignalStores) -> usize {
    let values = stores
        .session
        .sessions
        .values()
        .chain(stores.sender_key.keys.values());
    values.map(Vec::len).sum()
}

/// One person joins a channel of `n`: a session and a key for each member,
/// each way, as `distribute_sender_key_to_user` does it.
async fn crypto(n: usize) -> Result<(), Error> {
    const CHANNEL_ID: u32 = 7;
    const JOINER: u32 = 1;
    // The size of what `distribute_media_key_to_user` seals.
    let media_key = [9u8; 64];

    println!("making {n} members' keys (not timed)");
    let mut joiner = signal_stores(JOINER)?;
    let mut members = Vec::with_capacity(n);
    for i in 0..n as u32 {
        members.push(signal_stores(i + 2)?);
    }

    // The joiner hands its keys to each member
    let own_key = group::create_distribution_message(&mut joiner, JOINER, CHANNEL_ID).await?;
    let mut sealed = Vec::with_capacity(n);
    let started = Instant::now();
    for (i, member) in members.iter().enumerate() {
        let id = i as u32 + 2;
        session::establish_session(&mut joiner, id, &prekey::bundle(member)?).await?;
        let key = session::encrypt_message(&mut joiner, id, &own_key).await?;
        let media = session::encrypt_message(&mut joiner, id, &media_key).await?;
        sealed.push((key, media));
    }
    let joiner_sends = started.elapsed();

    // Each member opens them, and answers with its own
    let mut member_time = Duration::ZERO;
    let mut answers = Vec::with_capacity(n);
    for (i, (member, (key, media))) in members.iter_mut().zip(sealed).enumerate() {
        let id = i as u32 + 2;
        let own = group::create_distribution_message(member, id, CHANNEL_ID).await?;
        let started = Instant::now();
        let plain = session::decrypt_message(member, JOINER, &key.0, key.1).await?;
        group::process_distribution_message(member, JOINER, CHANNEL_ID, &plain).await?;
        session::decrypt_message(member, JOINER, &media.0, media.1).await?;
        let answer_key = session::encrypt_message(member, JOINER, &own).await?;
        let answer_media = session::encrypt_message(member, JOINER, &media_key).await?;
        member_time += started.elapsed();
        answers.push((id, answer_key, answer_media));
    }

    // The joiner opens every member's
    let started = Instant::now();
    for (id, key, media) in answers {
        let plain = session::decrypt_message(&mut joiner, id, &key.0, key.1).await?;
        group::process_distribution_message(&mut joiner, id, CHANNEL_ID, &plain).await?;
        session::decrypt_message(&mut joiner, id, &media.0, media.1).await?;
    }
    let joiner_opens = started.elapsed();

    let per = |d: Duration| d.as_secs_f64() * 1000.0 / n as f64;
    println!("joining a channel of {n}, on this CPU, one thread:");
    println!(
        "  joiner: {:.1} s to seal ({:.2} ms a member), {:.1} s to open ({:.2} ms a member)",
        joiner_sends.as_secs_f64(),
        per(joiner_sends),
        joiner_opens.as_secs_f64(),
        per(joiner_opens),
    );
    println!("  each member, once: {:.2} ms", per(member_time));
    // A bundle request, a sender key and a media key for each member
    println!(
        "  joiner's control messages: {}, at least {:.0} s at {CONTROL_MSGS_PER_SEC}/s",
        3 * n,
        (3 * n) as f64 / f64::from(CONTROL_MSGS_PER_SEC),
    );
    println!(
        "  keys held in memory by the joiner: {:.1} MiB",
        stored_bytes(&joiner) as f64 / (1024.0 * 1024.0),
    );
    Ok(())
}

// ── run ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Tally {
    up: AtomicUsize,
    refused: AtomicUsize,
    /// Everything the relay sent, all clients together.
    messages: AtomicU64,
    connect_ms: Mutex<Vec<u64>>,
    /// Sessions that got a list for General, which every client is put into.
    general_lists: AtomicUsize,
    join_ms: Mutex<Vec<u64>>,
    /// Members each client that connected knows in the channel, by slot.
    roster: Mutex<Vec<Option<usize>>>,
    chat_ms: Mutex<Vec<u64>>,
    channel_errors: AtomicUsize,
}

/// `(RSS in MiB, CPU seconds)` of a process, from /proc.
fn relay_stats(pid: u32) -> Option<(u64, f64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .trim()
        .trim_end_matches(" kB")
        .parse()
        .ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // After the name, which may hold spaces: utime and stime are the 12th and 13th.
    let mut after_name = stat.rsplit(')').next()?.split_whitespace();
    let utime: f64 = after_name.nth(11)?.parse().ok()?;
    let stime: f64 = after_name.next()?.parse().ok()?;
    Some((rss_kb / 1024, (utime + stime) / 100.0))
}

/// Waits until the relay has stopped sending, or `limit` passes.
async fn settle(tally: &Tally, limit: Duration) {
    let started = Instant::now();
    let mut last = tally.messages.load(Ordering::Relaxed);
    while started.elapsed() < limit {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let now = tally.messages.load(Ordering::Relaxed);
        if now == last {
            return;
        }
        last = now;
    }
}

async fn run(n: usize, server: &str, pid: Option<u32>) -> Result<(), Error> {
    let tally = Arc::new(Tally {
        roster: Mutex::new(vec![None; n]),
        ..Tally::default()
    });
    let clock = Instant::now();
    let (channel_tx, channel_rx) = watch::channel(0u32);
    let (join_tx, join_rx) = watch::channel(false);
    let (chat_tx, chat_rx) = watch::channel(0u64);

    println!("connecting {n} clients to {server}");
    for index in 0..n {
        let (server, tally) = (server.to_string(), tally.clone());
        let (channel_tx, channel_rx) = (channel_tx.clone(), channel_rx.clone());
        let (join_rx, chat_rx) = (join_rx.clone(), chat_rx.clone());
        tokio::spawn(async move {
            let result = client(
                index, &server, &tally, clock, channel_tx, channel_rx, join_rx, chat_rx,
            )
            .await;
            if let Err(e) = result {
                // A count, or thousands of lines; the first few say why.
                if tally.refused.fetch_add(1, Ordering::Relaxed) < 3 {
                    eprintln!("client {index}: {e}");
                }
            }
        });
        // Paced as people arriving, not as an attack on the connect limits
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let limit = Duration::from_secs(60 + n as u64 / 10);
    let started = Instant::now();
    while tally.up.load(Ordering::Relaxed) + tally.refused.load(Ordering::Relaxed) < n
        && started.elapsed() < limit
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    settle(&tally, limit).await;
    let up = tally.up.load(Ordering::Relaxed);
    if up == 0 {
        return Err("no client connected: is the relay up?".into());
    }
    let after_connect = pid.and_then(relay_stats);
    println!(
        "connected {up}, refused {}, General lists received {}, relay {after_connect:?}",
        tally.refused.load(Ordering::Relaxed),
        tally.general_lists.load(Ordering::Relaxed),
    );

    // Everyone joins at once: what the first evening after a move looks like
    let before_join = tally.messages.load(Ordering::Relaxed);
    join_tx.send(true)?;
    let started = Instant::now();
    while tally.join_ms.lock().unwrap().len() < up && started.elapsed() < limit {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let all_joined = started.elapsed();
    settle(&tally, limit).await;
    let after_join = pid.and_then(relay_stats);
    let join_messages = tally.messages.load(Ordering::Relaxed) - before_join;
    let short: Vec<usize> = tally
        .roster
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .filter(|&&known| known + 1 < up)
        .map(|&known| up - 1 - known)
        .collect();
    println!(
        "joined in {:.1} s, {join_messages} messages fanned out; {} of {up} rosters short, by {} members at most",
        all_joined.as_secs_f64(),
        short.len(),
        short.iter().max().copied().unwrap_or(0),
    );

    for seq in 1..=CHAT_MESSAGES {
        chat_tx.send(seq)?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    settle(&tally, Duration::from_secs(30)).await;
    let after_chat = pid.and_then(relay_stats);

    let mut connect_ms = tally.connect_ms.lock().unwrap().clone();
    let mut join_ms = tally.join_ms.lock().unwrap().clone();
    let mut chat_ms = tally.chat_ms.lock().unwrap().clone();
    let expected = CHAT_MESSAGES as usize * up.saturating_sub(1);
    println!(
        "chat: {} of {expected} delivered, {} channel errors",
        chat_ms.len(),
        tally.channel_errors.load(Ordering::Relaxed),
    );
    let cpu = |a: Option<(u64, f64)>, b: Option<(u64, f64)>| match (a, b) {
        (Some(a), Some(b)) => format!("{:.1}", b.1 - a.1),
        _ => "?".into(),
    };
    let rss = after_chat.map_or("?".to_string(), |s| s.0.to_string());
    println!("| clients | connect p95 ms | General lists | join all s | join p95 ms | rosters short | chat p50/p95 ms | chat delivered | relay RSS MiB | relay CPU s: join, chat |");
    println!(
        "| {up} | {} | {} | {:.1} | {} | {} | {}/{} | {}/{expected} | {rss} | {}, {} |",
        percentile(&mut connect_ms, 95),
        tally.general_lists.load(Ordering::Relaxed),
        all_joined.as_secs_f64(),
        percentile(&mut join_ms, 95),
        short.len(),
        percentile(&mut chat_ms, 50),
        percentile(&mut chat_ms, 95),
        chat_ms.len(),
        cpu(after_connect, after_join),
        cpu(after_join, after_chat),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn client(
    index: usize,
    server: &str,
    tally: &Arc<Tally>,
    clock: Instant,
    channel_tx: watch::Sender<u32>,
    mut channel_rx: watch::Receiver<u32>,
    mut join_rx: watch::Receiver<bool>,
    mut chat_rx: watch::Receiver<u64>,
) -> Result<(), Error> {
    let started = Instant::now();
    let c = connect(index, server).await?;
    tally
        .connect_ms
        .lock()
        .unwrap()
        .push(started.elapsed().as_millis() as u64);
    tally.roster.lock().unwrap()[index] = Some(0);
    tally.up.fetch_add(1, Ordering::Relaxed);
    let (user_id, proto) = (c.user_id, c.proto);
    let (mut send, mut recv, mut buf) = (c.send, c.recv, c.buf);

    // One writer, so the reader answering a ping and a phase sending never meet
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(data) = out_rx.recv().await {
            if send.write_all(&data).await.is_err() {
                return;
            }
        }
    });

    if index == 0 {
        let create = ClientMessage::CreateChannel {
            name: CHANNEL.into(),
            password: None,
            proximity: ProximityMode::Off,
            anonymous: false,
            text: true,
        };
        out.send(enc(&create, proto)?)?;
    }

    // The phases, as the main task calls them
    let joined_at = Arc::new(Mutex::new(None::<Instant>));
    {
        let (out, joined_at) = (out.clone(), joined_at.clone());
        let tally = tally.clone();
        tokio::spawn(async move {
            if channel_rx.wait_for(|&id| id != 0).await.is_err()
                || join_rx.wait_for(|&go| go).await.is_err()
            {
                return;
            }
            let channel_id = *channel_rx.borrow();
            *joined_at.lock().unwrap() = Some(Instant::now());
            let join = ClientMessage::JoinChannel {
                channel_id,
                password: None,
            };
            let Ok(data) = enc(&join, proto) else { return };
            if out.send(data).is_err() {
                return;
            }
            while chat_rx.changed().await.is_ok() {
                let seq = *chat_rx.borrow();
                let speakers = tally.up.load(Ordering::Relaxed).max(1);
                if seq as usize % speakers != index {
                    continue;
                }
                let sent_at = clock.elapsed().as_micros() as u64;
                let mut ciphertext = sent_at.to_le_bytes().to_vec();
                ciphertext.resize(CHAT_BYTES, 0);
                let say = ClientMessage::SendEncryptedChannelMessage {
                    channel_id,
                    ciphertext,
                };
                let Ok(data) = enc(&say, proto) else { return };
                if out.send(data).is_err() {
                    return;
                }
            }
        });
    }

    let mut known = HashSet::new();
    let note = |known: &mut HashSet<u32>, tally: &Tally, id: u32| {
        if id != user_id && known.insert(id) {
            tally.roster.lock().unwrap()[index] = Some(known.len());
        }
    };
    loop {
        let msg = next_message(&mut recv, &mut buf, proto).await?;
        tally.messages.fetch_add(1, Ordering::Relaxed);
        let channel_id = *channel_tx.borrow();
        match msg {
            ServerMessage::Ping { timestamp } => {
                out.send(enc(&ClientMessage::Ping { timestamp }, proto)?)?;
            }
            ServerMessage::ChannelCreated { channel } if channel.name == CHANNEL => {
                channel_tx.send_replace(channel.channel_id);
            }
            ServerMessage::UserList { channel_id: 0, .. } => {
                tally.general_lists.fetch_add(1, Ordering::Relaxed);
            }
            ServerMessage::UserList {
                channel_id: id,
                users,
            } if id == channel_id => {
                if let Some(at) = joined_at.lock().unwrap().take() {
                    tally
                        .join_ms
                        .lock()
                        .unwrap()
                        .push(at.elapsed().as_millis() as u64);
                }
                for user in users {
                    note(&mut known, tally, user.user_id);
                }
            }
            ServerMessage::UserJoined { user }
                if user.channel_id == channel_id && channel_id != 0 =>
            {
                note(&mut known, tally, user.user_id);
            }
            ServerMessage::EncryptedChannelChatMessage { ciphertext, .. } => {
                if let Some(sent) = ciphertext.get(..8) {
                    let sent = u64::from_le_bytes(sent.try_into()?);
                    let micros = (clock.elapsed().as_micros() as u64).saturating_sub(sent);
                    tally.chat_ms.lock().unwrap().push(micros / 1000);
                }
            }
            ServerMessage::ChannelError { .. } => {
                tally.channel_errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}
