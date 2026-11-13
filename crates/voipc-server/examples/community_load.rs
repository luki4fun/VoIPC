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
//   community_load channels 300 > channels.json
//     That many text channels everyone follows, for the relay `follow` runs against.
//
//   community_load follow 2000 127.0.0.1:9987 relay-pid [--writers W] [--rate R] [--each C]
//                  [--seconds S] [--churn J] [--leave] [--wave "command"]
//     The live path as an app walks it (protocol 21): N guests in one `JoinTextChannels`,
//     W of them writing R posts a second in all, each in C channels: a key check, the post
//     first, then the reader opens the session and the wrap follows. True sizes, with
//     dummy ciphertext. `--churn` drops and brings back J clients a second. `--leave` has
//     20 followers leave a channel every ten seconds and come back five later. `--wave` runs
//     `kill -9` on the relay halfway, then the command, which must `exec` a new relay, and
//     everyone returns at `reconnectDelay`'s spread. It exits non-zero if a line does not
//     hold. What it cannot see: a post that waited for a lost wrap asks again in a real
//     app (`KeyWanted`); here it only counts as expired.
//
// The relay needs `max_users` above N. Load clients share the machine with it,
// so CPU times are the relay's own, and latencies are an upper bound.

#[path = "load_common/mod.rs"]
mod load_common;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Notify};

use load_common::{connect, connect_with, enc, next_message, Error};
use voipc_crypto::channel_state::{chain_age_limit, exit_gap, WRAPS_A_FRAME};
use voipc_crypto::{group, prekey, session, SignalStores};
use voipc_protocol::codec::{encode_server_msg, CONTROL_MSGS_PER_SEC, MAX_MSG_SIZE};
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::{
    ChannelInfo, OneTimePreKey, PreKeyBundleData, ProximityMode, UserInfo,
};

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
        Some("channels") => channels_file(number(args.get(1), 300)?),
        Some("follow") => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("crypto provider");
            follow(FollowArgs::parse(&args[1..])?).await
        }
        _ => Err(
            "usage: community_load frames | crypto [N] | run [N] [host:port] [relay-pid] | channels [N] | follow N host:port relay-pid [--writers W] [--rate R] [--each C] [--seconds S] [--churn J] [--leave] [--wave \"command\"]".into(),
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
    // A text channel pushes no list since protocol 21: nothing to count short
    println!(
        "joined in {:.1} s, {join_messages} messages fanned out; a text channel pushes no roster (its pages are asked)",
        all_joined.as_secs_f64(),
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
        "| {up} | {} | {} | {:.1} | {} | - | {}/{} | {}/{expected} | {rss} | {}, {} |",
        percentile(&mut connect_ms, 95),
        tally.general_lists.load(Ordering::Relaxed),
        all_joined.as_secs_f64(),
        percentile(&mut join_ms, 95),
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
                // A post reaches whoever its writer was told of (protocol 21)
                let check = ClientMessage::KeyCheck {
                    channel_id,
                    restart: false,
                };
                let Ok(data) = enc(&check, proto) else { return };
                if out.send(data).is_err() {
                    return;
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
            // A text channel's join answers with this since protocol 21, and no list: its
            // members are asked a page at a time (`RequestChannelPage`), not pushed
            ServerMessage::TextJoined { joined, .. }
                if joined.iter().any(|(id, ..)| *id == channel_id) =>
            {
                if let Some(at) = joined_at.lock().unwrap().take() {
                    tally
                        .join_ms
                        .lock()
                        .unwrap()
                        .push(at.elapsed().as_millis() as u64);
                }
            }
            ServerMessage::TextPost { ciphertext, .. } => {
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

// ── follow ───────────────────────────────────────────────────────────────

/// What an app really sends: a post, the hello a reader opens with, a wrap after it.
const POST_BYTES: usize = 400;
const HELLO_BYTES: usize = 1800;
const WRAP_BYTES: usize = 176;
/// As `voipc_crypto::channel_state` paces them.
const OPENS_A_FRAME: usize = 256;
const OPEN_WAIT_MS: u64 = 1_000;
const WRAP_FRAME_BYTES: usize = 56 * 1024;
const HOLD_MS: u64 = 60_000;
const HELLO_BURST: f64 = 128.0;
const HELLOS_A_SECOND: f64 = 2.0;
const PREKEY_REFILL: usize = 50;
/// The lines of the plan's soak.
const FIRST_POST_UP_BYTES: u64 = 450 * 1024;
const FIRST_READER_MS: u64 = 1_000;
const LAST_READER_MS: u64 = 3_000;
const RELAY_CPU: f64 = 60.0;
const RELAY_RSS_OVER_MB: u64 = 100;

struct FollowArgs {
    n: usize,
    server: String,
    pid: u32,
    writers: usize,
    rate: f64,
    each: usize,
    seconds: u64,
    churn: usize,
    leave: bool,
    wave: Option<String>,
}

impl FollowArgs {
    fn parse(args: &[String]) -> Result<FollowArgs, Error> {
        let usage = "follow N host:port relay-pid [--writers W] [--rate R] [--each C] [--seconds S] [--churn J] [--leave] [--wave \"command\"]";
        let [n, server, pid, rest @ ..] = args else {
            return Err(usage.into());
        };
        let mut a = FollowArgs {
            n: n.parse()?,
            server: server.clone(),
            pid: pid.parse()?,
            writers: 20,
            rate: 2.0,
            each: 4,
            seconds: 900,
            churn: 0,
            leave: false,
            wave: None,
        };
        let mut rest = rest.iter();
        while let Some(flag) = rest.next() {
            if flag == "--leave" {
                a.leave = true;
                continue;
            }
            let value = rest.next().ok_or(usage)?;
            match flag.as_str() {
                "--writers" => a.writers = value.parse()?,
                "--rate" => a.rate = value.parse()?,
                "--each" => a.each = value.parse()?,
                "--seconds" => a.seconds = value.parse()?,
                "--churn" => a.churn = value.parse()?,
                "--wave" => a.wave = Some(value.clone()),
                _ => return Err(usage.into()),
            }
        }
        Ok(a)
    }
}

fn channels_file(n: usize) -> Result<(), Error> {
    let channels: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            serde_json::json!({
                "name": format!("load-{i:04}"),
                "text": true,
                "auto_join": true,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&channels)?);
    Ok(())
}

/// One chain's first post: how soon its readers could open it.
#[derive(Clone, Copy)]
struct FirstPost {
    sent_ms: u64,
    first_ms: u64,
    last_ms: u64,
    readers: u64,
}

#[derive(Default)]
struct FollowTally {
    connects: AtomicU64,
    /// Connections that ended with nobody asking for it, wave aside.
    lost: AtomicU64,
    join_up: AtomicU64,
    join_down: AtomicU64,
    refused: AtomicU64,
    /// Frames this path should never need.
    bundles: AtomicU64,
    rosters: AtomicU64,
    channel_errors: AtomicU64,
    asks: AtomicU64,
    hellos: AtomicU64,
    keys_in: AtomicU64,
    keys_sent: AtomicU64,
    posts_up: AtomicU64,
    posts_in: AtomicU64,
    expired: AtomicU64,
    new_chains: AtomicU64,
    /// A post's way to someone already holding the key.
    post_ms: Mutex<Vec<u64>>,
    first_posts: Mutex<HashMap<(u32, u32, u32), FirstPost>>,
    /// What each chain's writer sent for it, posts aside.
    job_up: Mutex<Vec<u64>>,
}

impl FollowTally {
    fn add(&self, field: impl Fn(&Self) -> &AtomicU64) {
        field(self).fetch_add(1, Ordering::Relaxed);
    }
}

/// Its one-way time in the post, and the chain it is on, which is what a key must reach.
fn dummy_post(sent_ms: u64, chain: u32) -> Vec<u8> {
    let mut ct = sent_ms.to_le_bytes().to_vec();
    ct.extend_from_slice(&chain.to_le_bytes());
    ct.resize(POST_BYTES, 0);
    ct
}

fn read_post(ct: &[u8]) -> Option<(u64, u32)> {
    let sent = u64::from_le_bytes(ct.get(..8)?.try_into().ok()?);
    let chain = u32::from_le_bytes(ct.get(8..12)?.try_into().ok()?);
    Some((sent, chain))
}

fn dummy_wrap(chain: u32) -> Vec<u8> {
    let mut ct = chain.to_le_bytes().to_vec();
    ct.resize(WRAP_BYTES, 0);
    ct
}

/// One writer in one channel: `Writing` of `channel_state`, and no key in it.
#[derive(Default)]
struct WriterChannel {
    chain: u32,
    started: Option<u64>,
    named: HashSet<u32>,
    exited: bool,
    check_out: bool,
    owed: Vec<u32>,
    waiting: VecDeque<u64>,
    job_up: u64,
}

impl WriterChannel {
    fn over(&self, now: u64) -> bool {
        let Some(started) = self.started else {
            return true;
        };
        let age = now.saturating_sub(started);
        age >= chain_age_limit(self.named.len())
            || (self.exited && age >= exit_gap(self.named.len()))
    }
}

#[derive(Default)]
struct WriterState {
    channels: Vec<u32>,
    at: HashMap<u32, WriterChannel>,
    sessions: HashSet<u32>,
    opens: VecDeque<(u32, u32)>,
    wraps: VecDeque<(u32, u32)>,
    awaiting: HashSet<u32>,
    open_frame: usize,
    opens_sent_at: u64,
    next_post: usize,
}

impl WriterState {
    /// The next channel's post, as `live_post`: first of all a check.
    fn post(&mut self, clock: &Instant, tally: &FollowTally) -> Option<ClientMessage> {
        if self.channels.is_empty() {
            return None;
        }
        let channel_id = self.channels[self.next_post % self.channels.len()];
        self.next_post += 1;
        let now = clock.elapsed().as_millis() as u64;
        let w = self.at.entry(channel_id).or_default();
        if w.check_out {
            w.waiting.push_back(now);
            return None;
        }
        let restart = w.over(now);
        if restart {
            w.started = None;
            w.named.clear();
            w.exited = false;
            w.chain += 1;
            w.job_up = 0;
            tally.add(|t| &t.new_chains);
        }
        w.check_out = true;
        w.waiting.push_back(now);
        Some(ClientMessage::KeyCheck {
            channel_id,
            restart,
        })
    }

    /// `keys_owed` and `start_round`: the posts go before anything else does.
    #[allow(clippy::too_many_arguments)]
    fn owed(
        &mut self,
        channel_id: u32,
        ids: Vec<u32>,
        more: bool,
        own: u32,
        now: u64,
        out: &mut Vec<ClientMessage>,
        tally: &FollowTally,
    ) {
        let Some(w) = self.at.get_mut(&channel_id) else {
            return;
        };
        w.owed.extend(ids);
        if more {
            return;
        }
        w.check_out = false;
        w.started.get_or_insert(now);
        let mut owed = std::mem::take(&mut w.owed);
        owed.retain(|id| *id != own);
        owed.sort_unstable();
        w.named.extend(owed.iter().copied());
        for sent in w.waiting.drain(..) {
            tally.add(|t| &t.posts_up);
            out.push(ClientMessage::SendEncryptedChannelMessage {
                channel_id,
                ciphertext: dummy_post(sent, w.chain),
            });
        }
        for id in owed {
            if self.sessions.contains(&id) {
                self.wraps.push_back((channel_id, id));
            } else {
                self.opens.push_back((channel_id, id));
            }
        }
    }

    /// `session_hello`: a wrap for every chain of ours that named them.
    fn hello(&mut self, from: u32, now: u64) {
        self.sessions.insert(from);
        self.awaiting.remove(&from);
        for (channel_id, w) in &self.at {
            if w.named.contains(&from) && !w.over(now) {
                self.wraps.push_back((*channel_id, from));
            }
        }
    }

    /// `live_next_frame`, with `next_ask` and `job_over` left out: nobody asks for chat here,
    /// and the refill goes as soon as the relay says it runs low.
    fn next_frame(&mut self, now: u64, tally: &FollowTally) -> Option<ClientMessage> {
        while let Some(&(channel_id, _)) = self.wraps.front() {
            let mut keys = Vec::new();
            let mut bytes = 0;
            while let Some(&(channel, id)) = self.wraps.front() {
                if channel != channel_id || keys.len() >= WRAPS_A_FRAME || bytes >= WRAP_FRAME_BYTES
                {
                    break;
                }
                self.wraps.pop_front();
                let Some(w) = self.at.get(&channel) else {
                    continue;
                };
                if w.over(now) || !w.named.contains(&id) {
                    continue;
                }
                bytes += WRAP_BYTES + 8;
                keys.push((id, 2u8, dummy_wrap(w.chain)));
            }
            if !keys.is_empty() {
                tally
                    .keys_sent
                    .fetch_add(keys.len() as u64, Ordering::Relaxed);
                if let Some(w) = self.at.get_mut(&channel_id) {
                    w.job_up += (bytes + 16) as u64;
                }
                return Some(ClientMessage::DistributeSenderKeys { channel_id, keys });
            }
        }
        if self.opens.is_empty() {
            return None;
        }
        let answered = self.awaiting.len() * 2 <= self.open_frame;
        if !answered && now.saturating_sub(self.opens_sent_at) < OPEN_WAIT_MS {
            return None;
        }
        while let Some(&(channel_id, _)) = self.opens.front() {
            let mut targets = Vec::new();
            while let Some(&(channel, id)) = self.opens.front() {
                if channel != channel_id || targets.len() >= OPENS_A_FRAME {
                    break;
                }
                self.opens.pop_front();
                if self
                    .at
                    .get(&channel)
                    .is_some_and(|w| !w.over(now) && w.named.contains(&id))
                {
                    targets.push(id);
                }
            }
            if !targets.is_empty() {
                self.awaiting = targets.iter().copied().collect();
                self.open_frame = targets.len();
                self.opens_sent_at = now;
                if let Some(w) = self.at.get_mut(&channel_id) {
                    w.job_up += (targets.len() * 4 + 16) as u64;
                }
                return Some(ClientMessage::OpenSessions {
                    channel_id,
                    targets,
                });
            }
        }
        None
    }

    /// Chains whose job is over: what each took to send, for the line.
    fn jobs_done(&mut self, tally: &FollowTally) {
        if !self.wraps.is_empty() || !self.opens.is_empty() {
            return;
        }
        let mut done = Vec::new();
        for w in self.at.values_mut() {
            if w.job_up > 0 {
                done.push(std::mem::take(&mut w.job_up));
            }
        }
        if !done.is_empty() {
            tally.job_up.lock().unwrap().extend(done);
        }
    }
}

type HeldPost = (u64, u32, u64);

/// What a reader holds of a client's run: `channel_state`'s reader, and no key in it.
#[derive(Default)]
struct ReaderState {
    keys: HashMap<(u32, u32), u32>,
    /// By writer and channel: sent, its chain, when it arrived.
    held: HashMap<(u32, u32), Vec<HeldPost>>,
    hello_spent: f64,
    hello_at: u64,
    opened_for: HashSet<u32>,
}

impl ReaderState {
    fn may_hello(&mut self, now: u64) -> bool {
        let gone = now.saturating_sub(self.hello_at) as f64 / 1000.0 * HELLOS_A_SECOND;
        self.hello_spent = (self.hello_spent - gone).max(0.0);
        self.hello_at = now;
        if self.hello_spent + 1.0 > HELLO_BURST {
            return false;
        }
        self.hello_spent += 1.0;
        true
    }
}

fn note_opened(tally: &FollowTally, chain: (u32, u32, u32), sent_ms: u64, now: u64) {
    let took = now.saturating_sub(sent_ms);
    let mut first = tally.first_posts.lock().unwrap();
    let f = first.entry(chain).or_insert(FirstPost {
        sent_ms,
        first_ms: took,
        last_ms: took,
        readers: 0,
    });
    // Only the chain's first post: later ones find the key, or a reader's lag
    if sent_ms <= f.sent_ms {
        f.sent_ms = sent_ms;
        f.first_ms = f.first_ms.min(took);
        f.last_ms = f.last_ms.max(took);
        f.readers += 1;
    }
}

/// Asked of one client from the outside.
#[derive(Default)]
struct Told {
    drop: AtomicBool,
    leave: AtomicBool,
    wake: Notify,
}

struct FollowClient {
    index: usize,
    writes: bool,
    each: usize,
    keys: (Vec<u8>, PreKeyBundleData),
    spare: Vec<OneTimePreKey>,
    server: String,
    clock: Instant,
    tally: Arc<FollowTally>,
    told: Arc<Told>,
    post_gap: Duration,
    wave: Arc<AtomicBool>,
    /// Opens once everyone has arrived, so the relay's memory can be read without a follow.
    follow_now: Arc<AtomicBool>,
}

/// One connection, to its end. `Ok`: told to drop.
async fn follow_once(c: &FollowClient) -> Result<(), Error> {
    // As long as `transport.rs` gives it: on a wave, some land on a relay not up yet
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        connect_with(c.index, &c.server, Some(c.keys.clone())),
    )
    .await??;
    let tally = &c.tally;
    tally.add(|t| &t.connects);
    let (own, proto) = (conn.user_id, conn.proto);
    let (mut send, mut recv, mut buf) = (conn.send, conn.recv, conn.buf);
    let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let backlog = Arc::new(AtomicUsize::new(0));
    let sender = {
        let backlog = backlog.clone();
        tokio::spawn(async move {
            while let Some(data) = out_rx.recv().await {
                if send.write_all(&data).await.is_err() {
                    return;
                }
                backlog.fetch_sub(1, Ordering::Relaxed);
            }
        })
    };
    let say = |msg: &ClientMessage| -> Result<(), Error> {
        backlog.fetch_add(1, Ordering::Relaxed);
        out.send(enc(msg, proto)?)?;
        Ok(())
    };
    let mut writer = WriterState::default();
    let mut reader = ReaderState::default();
    let mut followed: Vec<u32> = Vec::new();
    let mut joined = false;
    let mut left: Option<(u32, Instant)> = None;
    let join = |followed: &[u32], writer: &mut WriterState| -> Result<(), Error> {
        tally.add(|t| &t.join_up);
        say(&ClientMessage::JoinTextChannels {
            channels: followed.to_vec(),
            quiet: Vec::new(),
        })?;
        if c.writes {
            let first = c.index % followed.len();
            writer.channels = (0..c.each)
                .map(|i| followed[(first + i * 7) % followed.len()])
                .collect();
        }
        Ok(())
    };
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut post_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + c.post_gap.mul_f64((c.index % 16) as f64 / 16.0 + 0.1),
        c.post_gap,
    );
    post_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    let result = loop {
        tokio::select! {
            biased;
            _ = c.told.wake.notified() => {
                if c.told.drop.swap(false, Ordering::Relaxed) {
                    break Ok(());
                }
                if c.told.leave.swap(false, Ordering::Relaxed) && !followed.is_empty() {
                    let channel_id = followed[c.index % followed.len()];
                    say(&ClientMessage::LeaveChannel { channel_id })?;
                    left = Some((channel_id, Instant::now()));
                }
            }
            _ = post_tick.tick(), if c.writes && joined => {
                if let Some(msg) = writer.post(&c.clock, tally) {
                    say(&msg)?;
                }
            }
            _ = tick.tick(), if c.writes => {
                let now = c.clock.elapsed().as_millis() as u64;
                while backlog.load(Ordering::Relaxed) == 0 {
                    let Some(msg) = writer.next_frame(now, tally) else { break };
                    say(&msg)?;
                }
                writer.jobs_done(tally);
            }
            _ = expiry.tick() => {
                if !joined && !followed.is_empty() && c.follow_now.load(Ordering::Relaxed) {
                    joined = true;
                    join(&followed, &mut writer)?;
                }
                let now = c.clock.elapsed().as_millis() as u64;
                reader.held.retain(|_, posts| {
                    let before = posts.len();
                    posts.retain(|(_, _, arrived)| now.saturating_sub(*arrived) < HOLD_MS);
                    tally.expired.fetch_add((before - posts.len()) as u64, Ordering::Relaxed);
                    !posts.is_empty()
                });
                if let Some((channel_id, at)) = left {
                    if at.elapsed() >= Duration::from_secs(5) {
                        // Back by the same one frame an app comes back with
                        tally.add(|t| &t.join_up);
                        say(&ClientMessage::JoinTextChannels {
                            channels: vec![channel_id],
                            quiet: Vec::new(),
                        })?;
                        left = None;
                    }
                }
            }
            msg = next_message(&mut recv, &mut buf, proto) => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => break Err(e),
                };
                let now = c.clock.elapsed().as_millis() as u64;
                match msg {
                    ServerMessage::Ping { timestamp } => {
                        say(&ClientMessage::Ping { timestamp })?;
                    }
                    ServerMessage::ChannelList { channels }
                    | ServerMessage::ChannelListMore { channels, more: false } => {
                        followed.extend(channels.iter().filter(|c| c.text).map(|c| c.channel_id));
                        followed.sort_unstable();
                        if !joined && !followed.is_empty() && c.follow_now.load(Ordering::Relaxed) {
                            joined = true;
                            join(&followed, &mut writer)?;
                        }
                    }
                    ServerMessage::ChannelListMore { channels, more: true } => {
                        followed.extend(channels.iter().filter(|c| c.text).map(|c| c.channel_id));
                    }
                    ServerMessage::TextJoined { joined: rows, refused } => {
                        tally.add(|t| &t.join_down);
                        tally.refused.fetch_add(refused.len() as u64, Ordering::Relaxed);
                        drop(rows);
                    }
                    ServerMessage::KeysOwed { channel_id, ids, rows, more, refused } => {
                        if refused {
                            tally.add(|t| &t.channel_errors);
                            if let Some(w) = writer.at.get_mut(&channel_id) {
                                w.check_out = false;
                                w.waiting.clear();
                            }
                            continue;
                        }
                        let ids: Vec<u32> = ids
                            .into_iter()
                            .chain(rows.into_iter().map(|r| r.user_id))
                            .collect();
                        let mut posts = Vec::new();
                        writer.owed(channel_id, ids, more, own, now, &mut posts, tally);
                        for post in &posts {
                            say(post)?;
                        }
                    }
                    ServerMessage::SessionAsked { from, .. } => {
                        tally.add(|t| &t.asks);
                        if reader.opened_for.insert(from) && reader.may_hello(now) {
                            tally.add(|t| &t.hellos);
                            say(&ClientMessage::SessionHello {
                                to: from,
                                message_type: 3,
                                ciphertext: vec![0; HELLO_BYTES],
                            })?;
                        }
                    }
                    ServerMessage::SessionHello { from, .. } => writer.hello(from, now),
                    ServerMessage::TextKeyReceived { channel_id, from, ciphertext, .. } => {
                        tally.add(|t| &t.keys_in);
                        let chain = ciphertext
                            .get(..4)
                            .and_then(|b| b.try_into().ok())
                            .map_or(0, u32::from_le_bytes);
                        let held = reader.keys.entry((from, channel_id)).or_insert(0);
                        *held = chain.max(*held);
                        let held = *held;
                        if let Some(posts) = reader.held.get_mut(&(from, channel_id)) {
                            posts.retain(|(sent, on, _)| {
                                if *on > held {
                                    return true;
                                }
                                note_opened(tally, (from, channel_id, *on), *sent, now);
                                false
                            });
                        }
                    }
                    ServerMessage::TextPost { channel_id, user_id, ciphertext, .. } => {
                        tally.add(|t| &t.posts_in);
                        if let Some((sent, chain)) = read_post(&ciphertext) {
                            let key = reader.keys.get(&(user_id, channel_id)).copied().unwrap_or(0);
                            if key >= chain {
                                tally.post_ms.lock().unwrap().push(now.saturating_sub(sent));
                            } else {
                                reader
                                    .held
                                    .entry((user_id, channel_id))
                                    .or_default()
                                    .push((sent, chain, now));
                            }
                        }
                    }
                    ServerMessage::ChannelExits { channels } => {
                        for channel_id in channels {
                            if let Some(w) = writer.at.get_mut(&channel_id) {
                                w.exited = true;
                            }
                        }
                    }
                    ServerMessage::PreKeysLow { .. } => {
                        say(&ClientMessage::UploadPreKeys { prekeys: c.spare.clone() })?;
                    }
                    ServerMessage::PreKeyBundle { .. } => tally.add(|t| &t.bundles),
                    ServerMessage::UserList { channel_id, .. }
                    | ServerMessage::ChannelPage { channel_id, .. }
                        if channel_id != 0 && followed.contains(&channel_id) =>
                    {
                        tally.add(|t| &t.rosters);
                    }
                    ServerMessage::ChannelError { reason, .. } => {
                        let seen = tally.channel_errors.fetch_add(1, Ordering::Relaxed);
                        if seen < 3 {
                            eprintln!("client {}: {reason}", c.index);
                        }
                    }
                    _ => {}
                }
            }
        }
    };
    sender.abort();
    result
}

/// Connects again and again, as `connect.ts` does, until the run ends.
async fn follow_client(c: FollowClient, stop: Arc<AtomicBool>) {
    let mut attempt = 0;
    while !stop.load(Ordering::Relaxed) {
        let connects = c.tally.connects.load(Ordering::Relaxed);
        match follow_once(&c).await {
            Ok(()) => attempt = 0,
            // A wave's are not lost: they are what it is
            Err(_) if c.wave.load(Ordering::Relaxed) => {}
            Err(e) => {
                if c.tally.lost.fetch_add(1, Ordering::Relaxed) < 3 {
                    eprintln!("client {}: {e}", c.index);
                }
                if c.tally.connects.load(Ordering::Relaxed) > connects {
                    attempt = 0;
                }
            }
        }
        attempt += 1;
        // reconnectDelay
        let base = (1000.0 * 2f64.powi(attempt - 1)).min(10_000.0);
        let delay = base * (0.5 + rand::random::<f64>());
        tokio::time::sleep(Duration::from_millis(delay as u64)).await;
    }
}

/// The share of the cores the relay may use that it used over `seconds`, in %.
fn relay_share(pid: u32, cpu: f64, seconds: f64) -> f64 {
    let cores = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            let list = s
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))?
                .trim()
                .to_string();
            Some(
                list.split(',')
                    .map(|part| match part.split_once('-') {
                        Some((a, b)) => {
                            b.parse::<usize>().unwrap_or(0) + 1 - a.parse::<usize>().unwrap_or(0)
                        }
                        None => 1,
                    })
                    .sum::<usize>(),
            )
        })
        .unwrap_or(1);
    cpu / seconds / cores as f64 * 100.0
}

async fn follow(args: FollowArgs) -> Result<(), Error> {
    // A real bundle's bytes, once: the relay only hands it on
    let stores = signal_stores(1)?;
    let bundle = prekey::bundle(&stores)?;
    let identity = bundle.identity_key.clone();
    let spare: Vec<OneTimePreKey> = bundle.prekeys.iter().take(PREKEY_REFILL).cloned().collect();
    let tally = Arc::new(FollowTally::default());
    let clock = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let wave_on = Arc::new(AtomicBool::new(false));
    let relay_pid = Arc::new(AtomicU32::new(args.pid));
    let follow_now = Arc::new(AtomicBool::new(false));
    let told: Vec<Arc<Told>> = (0..args.n).map(|_| Arc::new(Told::default())).collect();
    let post_gap = Duration::from_secs_f64((args.writers as f64 / args.rate).max(0.05));

    println!(
        "{} clients, {} writers in {} channels each, {} posts a second, {} s",
        args.n, args.writers, args.each, args.rate, args.seconds
    );
    // The relay's CPU over each ten seconds
    let peak = Arc::new(Mutex::new((0f64, 0u64)));
    {
        let (peak, stop, relay_pid) = (peak.clone(), stop.clone(), relay_pid.clone());
        tokio::spawn(async move {
            let mut last = relay_stats(relay_pid.load(Ordering::Relaxed));
            while !stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let pid = relay_pid.load(Ordering::Relaxed);
                let now = relay_stats(pid);
                if let (Some(a), Some(b)) = (last, now) {
                    let mut p = peak.lock().unwrap();
                    if b.1 >= a.1 {
                        p.0 = p.0.max(relay_share(pid, b.1 - a.1, 10.0));
                    }
                    p.1 = p.1.max(b.0);
                }
                last = now;
            }
        });
    }
    for (index, told) in told.iter().enumerate() {
        let c = FollowClient {
            index,
            writes: index < args.writers,
            each: args.each,
            keys: (identity.clone(), bundle.clone()),
            spare: spare.clone(),
            server: args.server.clone(),
            clock,
            tally: tally.clone(),
            told: told.clone(),
            post_gap,
            wave: wave_on.clone(),
            follow_now: follow_now.clone(),
        };
        tokio::spawn(follow_client(c, stop.clone()));
        // Paced as people arriving, not as an attack on the connect limits
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let limit = Duration::from_secs(60 + args.n as u64 / 10);
    let started = Instant::now();
    while (tally.connects.load(Ordering::Relaxed) as usize) < args.n && started.elapsed() < limit {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    // The plan's baseline: this many people here, none of them following anything
    let baseline = relay_stats(args.pid);
    follow_now.store(true, Ordering::Relaxed);
    let started = Instant::now();
    while (tally.join_down.load(Ordering::Relaxed) as usize) < args.n && started.elapsed() < limit {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!(
        "joined: {} of {} in {:.1} s, all at once",
        tally.join_down.load(Ordering::Relaxed),
        args.n,
        started.elapsed().as_secs_f64()
    );
    let after_connect = tally.connects.load(Ordering::Relaxed);

    // The run, and what is asked of it
    let run = Instant::now();
    let mut waved = false;
    let mut next_churn = 0usize;
    let (mut last_churn, mut last_leave) = (Instant::now(), Instant::now());
    let mut leave_at = 0usize;
    while run.elapsed() < Duration::from_secs(args.seconds) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if args.churn > 0 && last_churn.elapsed() >= Duration::from_secs(1) {
            last_churn = Instant::now();
            for _ in 0..args.churn {
                // Writers stay: they are what the others' keys come from
                let i = args.writers + next_churn % (args.n - args.writers).max(1);
                next_churn += 1;
                told[i.min(args.n - 1)].drop.store(true, Ordering::Relaxed);
                told[i.min(args.n - 1)].wake.notify_one();
            }
        }
        if args.leave && last_leave.elapsed() >= Duration::from_secs(10) {
            last_leave = Instant::now();
            for _ in 0..20 {
                let i = args.writers + leave_at % (args.n - args.writers).max(1);
                leave_at += 1;
                told[i.min(args.n - 1)].leave.store(true, Ordering::Relaxed);
                told[i.min(args.n - 1)].wake.notify_one();
            }
        }
        if let (Some(cmd), false) = (&args.wave, waved) {
            if run.elapsed() >= Duration::from_secs(args.seconds / 2) {
                waved = true;
                wave_on.store(true, Ordering::Relaxed);
                let pid = relay_pid.load(Ordering::Relaxed);
                println!(
                    "wave: kill -9 {pid}, at {:.0} s",
                    run.elapsed().as_secs_f64()
                );
                std::process::Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .status()?;
                // Its sockets go with its last thread, and until then the port is taken. A
                // service manager's restart takes a moment longer than that anyway.
                while std::net::TcpStream::connect(&args.server).is_ok() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                let child = std::process::Command::new("sh").args(["-c", cmd]).spawn()?;
                relay_pid.store(child.id(), Ordering::Relaxed);
                // Whoever is lost from here to the return is the wave's
                let back = tally.connects.load(Ordering::Relaxed);
                let at = Instant::now();
                let mut half = None;
                while tally.connects.load(Ordering::Relaxed) < back + args.n as u64
                    && at.elapsed() < limit
                {
                    if half.is_none()
                        && tally.connects.load(Ordering::Relaxed) >= back + args.n as u64 / 2
                    {
                        half = Some(at.elapsed().as_secs_f64());
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                println!(
                    "wave: {} of {} back in {:.1} s, half of them in {:.1} s",
                    tally.connects.load(Ordering::Relaxed) - back,
                    args.n,
                    at.elapsed().as_secs_f64(),
                    half.unwrap_or(0.0),
                );
                wave_on.store(false, Ordering::Relaxed);
            }
        }
    }
    // What is still on its way
    tokio::time::sleep(Duration::from_secs(5)).await;
    stop.store(true, Ordering::Relaxed);

    let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let t = &tally;
    let mut post_ms = t.post_ms.lock().unwrap().clone();
    let firsts: Vec<FirstPost> = t.first_posts.lock().unwrap().values().copied().collect();
    let mut first_ms: Vec<u64> = firsts.iter().map(|f| f.first_ms).collect();
    let mut last_ms: Vec<u64> = firsts.iter().map(|f| f.last_ms).collect();
    let mut jobs = t.job_up.lock().unwrap().clone();
    let (cpu_peak, rss_peak) = *peak.lock().unwrap();
    let job_most = jobs.iter().copied().max().unwrap_or(0);
    let plain = args.churn == 0 && !args.leave && args.wave.is_none();
    println!(
        "connects {} (past the first: {}), lost {}, refused channels {}, channel errors {}",
        get(&t.connects),
        get(&t.connects) - after_connect,
        get(&t.lost),
        get(&t.refused),
        get(&t.channel_errors),
    );
    println!(
        "frames at connect: {} up, {} down, {} clients; bundles {}, text rosters {}",
        get(&t.join_up),
        get(&t.join_down),
        get(&t.connects),
        get(&t.bundles),
        get(&t.rosters),
    );
    println!(
        "asks {}, hellos {}; keys sent {}, in {}; new chains {} ({} a reader by pairs: {})",
        get(&t.asks),
        get(&t.hellos),
        get(&t.keys_sent),
        get(&t.keys_in),
        get(&t.new_chains),
        get(&t.keys_in) / (args.n.max(1) as u64),
        args.writers * args.each,
    );
    println!(
        "posts up {}, in {}, reached a held key at once p50/p95 {}/{} ms; expired holds {}",
        get(&t.posts_up),
        get(&t.posts_in),
        percentile(&mut post_ms, 50),
        percentile(&mut post_ms, 95),
        get(&t.expired),
    );
    println!(
        "a first post's readers: first p95 {} ms, last p95 {} ms, over {} chains; a chain's upload p95 {} B, most {} B",
        percentile(&mut first_ms, 95),
        percentile(&mut last_ms, 95),
        firsts.len(),
        percentile(&mut jobs, 95),
        job_most,
    );
    println!(
        "relay: peak {cpu_peak:.1}% over ten seconds, RSS {rss_peak} MiB at most, {:?} MiB with everyone here and nobody following",
        baseline.map(|b| b.0)
    );

    let mut failed = Vec::new();
    let mut line = |what: String, held: bool| {
        println!(
            "line: {what}: {}",
            if held { "holds" } else { "DOES NOT HOLD" }
        );
        if !held {
            failed.push(what);
        }
    };
    let connects = get(&t.connects);
    line(
        format!(
            "one text frame up at each connect ({} / {connects})",
            get(&t.join_up)
        ),
        args.leave || get(&t.join_up) == connects,
    );
    line(
        format!(
            "one text frame down at each connect ({} / {connects})",
            get(&t.join_down)
        ),
        args.leave || get(&t.join_down) == connects,
    );
    line(
        format!("no bundle asked ({})", get(&t.bundles)),
        get(&t.bundles) == 0,
    );
    line(
        format!("no text roster ({})", get(&t.rosters)),
        get(&t.rosters) == 0,
    );
    if plain {
        // Everyone followed from the start, so what a reader got is a key per chain of a pair
        let chains = get(&t.new_chains);
        let want = chains * (args.n as u64 - 1);
        line(
            format!(
                "keys go by chains of pairs, not members times channels ({} / {want})",
                get(&t.keys_in)
            ),
            get(&t.keys_in) <= want,
        );
    }
    line(format!("nobody lost ({})", get(&t.lost)), get(&t.lost) == 0);
    line(
        format!("no channel error ({})", get(&t.channel_errors)),
        get(&t.channel_errors) == 0,
    );
    line(
        format!("no reader's hold expires ({})", get(&t.expired)),
        get(&t.expired) == 0,
    );
    line(
        format!("a chain's upload under {FIRST_POST_UP_BYTES} B ({job_most})"),
        job_most < FIRST_POST_UP_BYTES,
    );
    line(
        format!(
            "first readers under {FIRST_READER_MS} ms ({})",
            percentile(&mut first_ms, 95)
        ),
        percentile(&mut first_ms, 95) < FIRST_READER_MS,
    );
    line(
        format!(
            "last reader under {LAST_READER_MS} ms ({})",
            percentile(&mut last_ms, 95)
        ),
        percentile(&mut last_ms, 95) < LAST_READER_MS,
    );
    line(
        format!("relay under {RELAY_CPU}% ({cpu_peak:.1})"),
        cpu_peak < RELAY_CPU,
    );
    if let Some((base, _)) = baseline {
        line(
            format!(
                "relay RSS under {RELAY_RSS_OVER_MB} MiB over nobody following ({})",
                rss_peak.saturating_sub(base)
            ),
            rss_peak.saturating_sub(base) < RELAY_RSS_OVER_MB,
        );
    }
    if failed.is_empty() {
        println!("every line holds");
        Ok(())
    } else {
        for f in &failed {
            println!("line not held: {f}");
        }
        std::process::exit(1)
    }
}
