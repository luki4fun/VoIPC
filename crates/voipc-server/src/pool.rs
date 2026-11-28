//! The core's side of the media edge pool (`[pool]`, 1.15). An edge is a
//! `voipc-server -c edge.toml edge` process, often on another machine, that links here on
//! `voipc_protocol::pool::POOL_PATH` with a proof of its secret. Past a share's first
//! `local_first` viewers, the relay places viewers on its edges (`Pool::place`): each is sent
//! a `WatchAt` with the edge's address and a ticket sealed for that edge, and the edge asks
//! this relay for a feed of the share (`EdgeMsg::Subscribe`). The share then costs this
//! relay one copy per edge instead of one per viewer.
//!
//! What lives where:
//! - here, under one plain mutex never held across an await: the linked edges, what each
//!   was assigned, and each edge's feeds, the only home of a feed;
//! - in each share (`state::ScreenShareSession::on_edge`), under the `channels` lock: which
//!   viewer is placed on which edge, with its ticket's slot.
//!
//! Lock order: `channels` first, then this mutex, then a `share_fans` shard. Nothing here
//! looks `sessions` up while holding the mutex, and a message to an edge goes by `try_send`
//! only, so it is safe under both locks; an edge whose queue is full is closed.
//!
//! Every removal of a viewer revokes its slot on its edge (`CoreMsg::Revoke`) and gives its
//! counts back (`Pool::unplace`); the end of a share tells its edges `ShareEnded`
//! (`Pool::end_share`); a lost edge's viewers are seated again (`ServerState::edge_lost`).

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{info, warn};
use voipc_crypto::bind::BIND_LEN;
use voipc_protocol::pool::{
    decode_edge_msg, encode_core_msg, hello_version, CoreMsg, EdgeMsg, MAX_CERT_HASHES,
    MAX_POOL_FRAME, POOL_VERSION,
};
use voipc_protocol::types::{EdgeLoad, EdgeView, SessionId};
use wtransport::error::ConnectionError;
use wtransport::{Connection, SendStream, VarInt};

use crate::config::{PoolConfig, MAX_EDGE_NAME};
use crate::session::NoFrame;
use crate::state::{RateLimiter, ServerState};
use crate::web::{DatagramSink, KeyframeHook};
use crate::{pool_keys, ConnLimits, PreSlot};

/// A share that sent no video for this long has nothing an edge could have passed on: a
/// viewer's `EdgeFailed` then moves nobody (`ServerState::edge_failed`). Well short of the
/// app's 10 s (`EDGE_SILENT_MS`), which it counts from its last whole frame while this is
/// counted from the last fragment here: a sharer stalled within a frame has sent fragments
/// up to a frame (more for a keyframe) after the last whole one, and the `EdgeFailed` takes
/// the way to the viewer and back, so with the same 10 s a stall would read as an edge's
/// fault and move every viewer of the share off its edges.
pub(crate) const SHARE_SILENT_MS: u64 = 7_000;
/// Whether a share whose last video fragment came at `last_ms` (0: none yet) is silent at
/// `now_ms`, both on this relay's clock (`ServerState::uptime_ms`).
pub(crate) fn share_silent(last_ms: u64, now_ms: u64) -> bool {
    last_ms == 0 || now_ms.saturating_sub(last_ms) > SHARE_SILENT_MS
}

/// An edge that failed a viewer is not picked for it again for this long.
pub(crate) const AVOID_FOR: Duration = Duration::from_secs(60);
/// The most edges one viewer avoids at once.
pub(crate) const MAX_AVOID: usize = 8;

/// What may wait for an edge's link writer. Full means the edge does not read: it is closed.
const LINK_QUEUE: usize = 4096;
/// A feed's queue, as a viewer's (`web::start_session`).
const FEED_QUEUE: usize = 512;
/// How long an edge has from its session to its whole `Hello`.
const HELLO_WAIT: Duration = Duration::from_secs(5);
/// What an edge may ask that costs this relay work, a burst and a rate per share it may
/// carry (`max_shares`), so an edge whose secret was stolen cannot loop them into fan
/// rebuilds and keyframes, while one that is not never runs past them. `Subscribe` and
/// `Unsubscribe` together: an edge sends at most one of each per share at once, as when a
/// lost edge's viewers land on it all together, and asks again every few seconds for a share
/// it is not fed. A dropped one would leave that share unfed there, its viewers waiting
/// for the edge to ask again.
const SUBSCRIBE_BURST_PER_SHARE: f64 = 2.0;
const SUBSCRIBE_PER_SEC_PER_SHARE: f64 = 1.0;
/// `KeyframeWanted`, apart, so asks for keyframes never use up what a share's `Subscribe`
/// needs: an edge merges its own to one a second per share, and twice that leaves room for
/// the way bunching them. A dropped one leaves its share's joiners waiting for the
/// sharer's next keyframe, up to 4 s.
const KEYFRAME_BURST_PER_SHARE: f64 = 2.0;
const KEYFRAME_PER_SEC_PER_SHARE: f64 = 2.0;
/// An edge reports its load every 2 s; more often than this is ignored.
const LOAD_EVERY: Duration = Duration::from_secs(1);
/// A feed of a share this edge has no viewer placed for ends after this long.
const FEED_IDLE: Duration = Duration::from_secs(10);
/// The most often a refused edge is warned about: per configured name, and once for all
/// names `[pool] edges` does not list; refusals for a wrong proof and for another pool
/// version each on a clock of their own.
const WARN_EVERY: Duration = Duration::from_secs(60);
/// How long the Load view tells of a refusal for another pool version: an edge of another
/// version asks again every minute, so one still trying keeps it there.
const CLAIM_SHOWN: Duration = Duration::from_secs(180);
/// A configured edge not linked for this long is a warning in the Load view.
const OFFLINE_WARN_AFTER: Duration = Duration::from_secs(60);
/// What this relay may have in flight to an edge, per share it may carry, and at most.
const SEND_WINDOW_PER_SHARE: u64 = 512 * 1024;
const SEND_WINDOW_MAX: u64 = 16 * 1024 * 1024;

/// Where a viewer of a share watches from, when an edge serves it
/// (`state::ScreenShareSession::on_edge`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// `ServerMessage::WatchAt.placement`: new on every one, which `EdgeFailed` names.
    pub id: u64,
    /// The edge's name, as `[pool] edges` has it.
    pub edge: String,
    /// The link of that edge it was placed on (`CoreMsg::Welcome.link`).
    pub link: u64,
    /// Its ticket's slot on that link, which `CoreMsg::Revoke` names.
    pub slot: u64,
}

/// What an edge said it is in its `Hello`.
#[derive(Debug, Clone)]
pub(crate) struct EdgeCaps {
    pub public_host: String,
    pub public_port: u16,
    pub cert_hashes: Vec<[u8; 32]>,
    pub max_viewers: u32,
    pub egress_mbit: u32,
    pub max_shares: u32,
    pub version: String,
}

impl EdgeCaps {
    /// Why viewers could not be sent to an edge with these, if they could not.
    fn check(&self) -> Result<(), String> {
        if !host_ok(&self.public_host) {
            return Err(format!(
                "its public host {:?} is not a DNS name or an IP address",
                self.public_host
            ));
        }
        if self.public_port == 0 {
            return Err("its public port is 0".into());
        }
        if !(1..=MAX_CERT_HASHES).contains(&self.cert_hashes.len()) {
            return Err(format!(
                "it names {} certificates, not 1 to {MAX_CERT_HASHES}",
                self.cert_hashes.len()
            ));
        }
        if !(1..=64).contains(&self.max_shares) {
            return Err(format!("max_shares {} is not 1 to 64", self.max_shares));
        }
        if self.max_viewers == 0 || self.egress_mbit == 0 {
            return Err("max_viewers and egress_mbit must be at least 1".into());
        }
        Ok(())
    }

    /// `host:port` as an app dials it.
    fn address(&self) -> String {
        if self.public_host.contains(':') {
            format!("[{}]:{}", self.public_host, self.public_port)
        } else {
            format!("{}:{}", self.public_host, self.public_port)
        }
    }

    /// Edge limits for a test's edge, reached on 127.0.0.1:9991.
    #[cfg(test)]
    pub(crate) fn test(max_viewers: u32, egress_mbit: u32, max_shares: u32) -> Self {
        Self {
            public_host: "127.0.0.1".into(),
            public_port: 9991,
            cert_hashes: vec![[7; 32]],
            max_viewers,
            egress_mbit,
            max_shares,
            version: voipc_protocol::codec::APP_VERSION.into(),
        }
    }
}

/// A DNS name or an IP literal (no brackets), at most 253 characters.
fn host_ok(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// The media edges this relay may link, and those linked.
pub(crate) struct Pool {
    /// `[pool] local_first`.
    pub local_first: u32,
    /// Each configured edge's keys, by name. The secrets themselves stay in the config.
    keys: BTreeMap<String, Keys>,
    reg: Mutex<Registry>,
    /// `WatchAt.placement`: counted across the relay, never reused while it runs.
    next_placement: AtomicU64,
    /// The core's clock that tickets expire on (`CoreMsg::Welcome.core_ms`).
    started: Instant,
    rng: SystemRandom,
    /// How many refusals were warned about, for the tests.
    #[cfg(test)]
    pub(crate) warnings: std::sync::atomic::AtomicU32,
}

struct Keys {
    proof: hmac::Key,
    ticket: hmac::Key,
}

/// What `Pool`'s mutex holds.
struct Registry {
    links: BTreeMap<String, EdgeLink>,
    /// Every configured edge, linked or not, for the Load view.
    seen: BTreeMap<String, Seen>,
    /// When a name `[pool] edges` does not list was last warned about: one clock for all,
    /// so the map holds configured names only and cannot be made to grow; and one for the
    /// refusals of another pool version among those.
    stranger_warned: Option<Instant>,
    stranger_version_warned: Option<Instant>,
}

/// A configured edge, as the Load view tells of it.
struct Seen {
    /// Since when it is linked, or not linked.
    since: Instant,
    /// Where viewers reached it, the last time it linked.
    address: String,
    /// The pool version a peer that named itself this edge asked for when it was last
    /// refused for that, and when, while this edge was not linked. Unproven: a hello of
    /// another pool version is of a layout this relay does not read, so it cannot show the
    /// secret here, and anyone who reaches the port can send one with this name. So it is
    /// kept apart from what a proven link says, and the Load view says so.
    claimed: Option<(u32, Instant)>,
    /// When a wrong proof of it was last warned about.
    warned: Option<Instant>,
    /// When a refusal of another pool version naming it was last warned about: apart, so
    /// those that anyone can send never keep the warning about a wrong secret out.
    version_warned: Option<Instant>,
}

impl Seen {
    fn new(now: Instant) -> Self {
        Self {
            since: now,
            address: String::new(),
            claimed: None,
            warned: None,
            version_warned: None,
        }
    }
}

/// One linked edge.
struct EdgeLink {
    /// `Welcome.link`: random, new on every link, and in each of its tickets.
    link_id: u64,
    tx: mpsc::Sender<CoreMsg>,
    /// `None` only for a test's edge (`test_edge`).
    conn: Option<Connection>,
    caps: EdgeCaps,
    /// What this relay placed on it: viewers, and the video they cost at their shares'
    /// resolutions (kbit/s).
    assigned_viewers: u32,
    assigned_kbps: u64,
    /// Viewers placed on it, by share. A share is here while it has one.
    shares: HashMap<SessionId, u32>,
    /// The shares it is fed, which it asked for (`Subscribe`).
    feeds: HashMap<SessionId, Feed>,
    last_load: Option<LoadSeen>,
    next_slot: u64,
    /// `SUBSCRIBE_BURST_PER_SHARE`/`SUBSCRIBE_PER_SEC_PER_SHARE`, for its `max_shares`.
    subscribe_budget: RateLimiter,
    /// `KEYFRAME_BURST_PER_SHARE`/`KEYFRAME_PER_SEC_PER_SHARE`, for its `max_shares`.
    keyframe_budget: RateLimiter,
    /// Being closed: nobody more is placed on it.
    closing: bool,
}

/// An edge's last `Load`.
struct LoadSeen {
    at: Instant,
    egress_kbps: u64,
    frames_dropped: u64,
    cpu_secs: u64,
    rss_mib: u32,
}

/// One share's feed to one edge: the queue its packets go into (in the share's fan,
/// `Fan::feeds`) and the pumps that send them over the link.
struct Feed {
    tx: mpsc::Sender<Bytes>,
    /// Since when no viewer is placed on the edge for this share.
    idle_since: Option<Instant>,
    /// A test's edge has no connection to pump into: the feed waits here for the test.
    #[cfg(test)]
    parked: Option<mpsc::Receiver<Bytes>>,
}

impl EdgeLink {
    /// A word to the edge. A queue it does not empty closes it: its viewers are seated
    /// again when its link ends.
    fn send(&mut self, msg: CoreMsg) {
        if self.tx.try_send(msg).is_err() {
            self.close(b"queue full");
        }
    }

    fn close(&mut self, why: &[u8]) {
        self.closing = true;
        if let Some(conn) = &self.conn {
            conn.close(VarInt::from_u32(0), why);
        }
    }

    /// The shares it carries: placed, or still fed for a while after.
    fn carried(&self) -> usize {
        self.shares.len()
            + self
                .feeds
                .keys()
                .filter(|s| !self.shares.contains_key(s))
                .count()
    }

    fn budget_kbps(&self) -> u64 {
        self.caps.egress_mbit as u64 * 1000
    }
}

/// What a link's first frame comes to (`Pool::check_hello`).
pub(crate) enum Hello {
    /// Not a hello, or not from an edge of this relay: closed with no word.
    Close,
    /// Told why (`CoreMsg::Refused`) and closed.
    Refuse(CoreMsg),
    /// Linked.
    Admit { name: String, caps: EdgeCaps },
}

impl Pool {
    /// The pool of `[pool]`; `None` without edges.
    pub(crate) fn new(config: &PoolConfig) -> Option<Self> {
        if config.edges.is_empty() {
            return None;
        }
        let now = Instant::now();
        let keys = config
            .edges
            .iter()
            .map(|(name, secret)| {
                let keys = Keys {
                    proof: pool_keys::proof_key(secret),
                    ticket: pool_keys::ticket_key(secret),
                };
                (name.clone(), keys)
            })
            .collect();
        let seen = config
            .edges
            .keys()
            .map(|name| (name.clone(), Seen::new(now)))
            .collect();
        Some(Self {
            local_first: config.local_first,
            keys,
            reg: Mutex::new(Registry {
                links: BTreeMap::new(),
                seen,
                stranger_warned: None,
                stranger_version_warned: None,
            }),
            next_placement: AtomicU64::new(1),
            started: now,
            rng: SystemRandom::new(),
            #[cfg(test)]
            warnings: Default::default(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Registry> {
        self.reg.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The core's clock, in ms since this pool was made.
    fn core_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// A number nobody can guess or count on: each link's id, so a ticket of an earlier run
    /// of this relay, or of an earlier link of the edge, is good for no link of this one.
    fn random_id(&self) -> u64 {
        let mut bytes = [0u8; 8];
        self.rng
            .fill(&mut bytes)
            .expect("the system's random source works");
        u64::from_le_bytes(bytes)
    }

    /// A new `WatchAt.placement`.
    pub(crate) fn next_placement(&self) -> u64 {
        self.next_placement.fetch_add(1, Ordering::Relaxed)
    }

    /// What a link's first frame comes to. The version is read first, from the frame's
    /// start alone (`pool::hello_version`), so an edge of any version is told
    /// `Refused` whatever the rest holds. A name this relay does not list, or a wrong
    /// proof, is closed with no word, counted, and warned about at most once a minute per
    /// listed name and once a minute for every other name together; an unlisted name is
    /// never logged.
    pub(crate) fn check_hello(
        &self,
        limits: &ConnLimits,
        frame: &[u8],
        binding: Option<&[u8; BIND_LEN]>,
    ) -> Hello {
        let Some(version) = hello_version(frame) else {
            limits.count("refused", "edge hello");
            return Hello::Close;
        };
        if version != POOL_VERSION {
            limits.count("refused", "edge pool version");
            self.version_refused(claimed_name(frame), version);
            return Hello::Refuse(CoreMsg::Refused {
                pool_version: POOL_VERSION,
                reason: format!("this relay speaks pool version {POOL_VERSION}"),
            });
        }
        let Ok(EdgeMsg::Hello {
            name,
            proof,
            public_host,
            public_port,
            cert_hashes,
            max_viewers,
            egress_mbit,
            max_shares,
            version,
            ..
        }) = decode_edge_msg(frame)
        else {
            limits.count("refused", "edge hello");
            return Hello::Close;
        };
        let proven = name.len() <= MAX_EDGE_NAME
            && binding.is_some_and(|binding| {
                self.keys
                    .get(&name)
                    .is_some_and(|keys| pool_keys::proof_ok(&keys.proof, binding, &name, &proof))
            });
        if !proven {
            limits.count("refused", "edge proof");
            self.proof_refused(&name);
            return Hello::Close;
        }
        let caps = EdgeCaps {
            public_host,
            public_port,
            cert_hashes,
            max_viewers,
            egress_mbit,
            max_shares,
            version,
        };
        if let Err(why) = caps.check() {
            // A proven edge, so it is told; it tries again in a minute
            limits.count("refused", "edge hello");
            warn!("edge {name} refused: {why}");
            return Hello::Refuse(CoreMsg::Refused {
                pool_version: POOL_VERSION,
                reason: why,
            });
        }
        Hello::Admit { name, caps }
    }

    /// Whether a refusal last warned about at `last` is to be warned about now.
    fn warn_due(&self, last: &mut Option<Instant>, now: Instant) -> bool {
        if last.is_some_and(|at| now.saturating_duration_since(at) < WARN_EVERY) {
            return false;
        }
        *last = Some(now);
        #[cfg(test)]
        self.warnings.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn proof_refused(&self, name: &str) {
        let listed = self.keys.contains_key(name);
        let mut guard = self.lock();
        let reg = &mut *guard;
        let last = match reg.seen.get_mut(name).filter(|_| listed) {
            Some(seen) => &mut seen.warned,
            None => &mut reg.stranger_warned,
        };
        if !self.warn_due(last, Instant::now()) {
            return;
        }
        drop(guard);
        if listed {
            warn!(
                "edge {name} refused: its proof is wrong (is its secret the one [pool] edges has?)"
            );
        } else {
            warn!("an edge was refused: its name is not in [pool] edges (refusals are counted in the minute's line)");
        }
    }

    /// A hello of another pool version, naming `name`. Nothing in it is proven (`Seen::claimed`):
    /// it is kept for the Load view only while no edge of that name is linked, and warned
    /// about on a clock of its own.
    fn version_refused(&self, name: Option<String>, version: u32) {
        let listed = name.filter(|n| self.keys.contains_key(n));
        let now = Instant::now();
        let mut guard = self.lock();
        let reg = &mut *guard;
        let linked = listed.as_ref().is_some_and(|n| reg.links.contains_key(n));
        let last = match listed.as_ref().and_then(|n| reg.seen.get_mut(n)) {
            Some(seen) => {
                if !linked {
                    seen.claimed = Some((version, now));
                }
                &mut seen.version_warned
            }
            None => &mut reg.stranger_version_warned,
        };
        if !self.warn_due(last, now) {
            return;
        }
        drop(guard);
        let first = if version > POOL_VERSION {
            "update this relay first"
        } else {
            "update the edge"
        };
        match listed {
            Some(name) => warn!(
                "a peer naming itself edge {name} was refused: it speaks pool version {version}, this relay {POOL_VERSION} (unproven: a hello of another version cannot show the secret here); if it is that edge, {first}"
            ),
            None => warn!(
                "an edge of pool version {version} was refused: this relay speaks {POOL_VERSION}"
            ),
        }
    }

    /// Links a proven edge as `name` with a fresh random link id, which its `Welcome` goes
    /// out with first. A link of that name before it is closed ("replaced") and returned,
    /// its feeds out of the shares' fans already: the caller seats its viewers again.
    fn register(
        &self,
        state: &ServerState,
        name: &str,
        caps: EdgeCaps,
        conn: Option<Connection>,
        tx: mpsc::Sender<CoreMsg>,
    ) -> (u64, Option<EdgeLink>) {
        let link_id = self.random_id();
        let _ = tx.try_send(CoreMsg::Welcome {
            link: link_id,
            core_ms: self.core_ms(),
        });
        let now = Instant::now();
        let mut reg = self.lock();
        let seen = reg
            .seen
            .entry(name.to_string())
            .or_insert_with(|| Seen::new(now));
        seen.since = now;
        seen.address = caps.address();
        seen.claimed = None;
        let shares = caps.max_shares as f64;
        let link = EdgeLink {
            link_id,
            tx,
            conn,
            caps,
            assigned_viewers: 0,
            assigned_kbps: 0,
            shares: HashMap::new(),
            feeds: HashMap::new(),
            last_load: None,
            next_slot: 1,
            subscribe_budget: RateLimiter::new(
                SUBSCRIBE_BURST_PER_SHARE * shares,
                SUBSCRIBE_PER_SEC_PER_SHARE * shares,
            ),
            keyframe_budget: RateLimiter::new(
                KEYFRAME_BURST_PER_SHARE * shares,
                KEYFRAME_PER_SEC_PER_SHARE * shares,
            ),
            closing: false,
        };
        let mut old = reg.links.insert(name.to_string(), link);
        if let Some(old) = &mut old {
            old.close(b"replaced");
            for &share in old.feeds.keys() {
                refeed(&reg, state, share);
            }
        }
        (link_id, old)
    }

    /// Takes the link `name`/`link` out, if it is still the one of that name, and its feeds
    /// out of the shares' fans. Its viewers' placements stay in their shares for the caller
    /// to seat again.
    pub(crate) fn unlink(&self, state: &ServerState, name: &str, link: u64) -> bool {
        let mut reg = self.lock();
        if reg.links.get(name).is_none_or(|l| l.link_id != link) {
            return false;
        }
        let Some(mut gone) = reg.links.remove(name) else {
            return false;
        };
        gone.close(b"");
        if let Some(seen) = reg.seen.get_mut(name) {
            seen.since = Instant::now();
        }
        for &share in gone.feeds.keys() {
            refeed(&reg, state, share);
        }
        true
    }

    /// An edge for one more viewer of `share`, which may send `ceiling` kbit/s to each,
    /// avoiding the edges named in `avoid`: its placement, and what the app is sent. An
    /// edge is eligible while it has room for the viewer, for its video, and for the share
    /// (it carries it already, or fewer than its `max_shares`). One that does not carry the
    /// share yet costs this relay a feed, so only with `room_here` for one, counted from its
    /// first placement on, so several placements at once cannot overshoot. The least loaded
    /// edge is taken, by the video it was given against what it may send, but one that
    /// carries the share already wins within 0.10 of it.
    pub(crate) fn place(
        &self,
        share: SessionId,
        ceiling: u32,
        avoid: &[String],
        room_here: bool,
    ) -> Option<(Placement, EdgeView)> {
        let ceiling = ceiling as u64;
        let mut reg = self.lock();
        let eligible: Vec<(&String, f64, bool)> = reg
            .links
            .iter()
            .filter(|(name, edge)| {
                let carries = edge.shares.contains_key(&share);
                !edge.closing
                    && !avoid.contains(name)
                    && edge.assigned_viewers < edge.caps.max_viewers
                    && edge.assigned_kbps + ceiling <= edge.budget_kbps()
                    && (carries || edge.carried() < edge.caps.max_shares as usize)
                    && (carries || room_here)
            })
            .map(|(name, edge)| {
                let load = (edge.assigned_kbps + ceiling) as f64 / edge.budget_kbps() as f64;
                (name, load, edge.shares.contains_key(&share))
            })
            .collect();
        let least = eligible.iter().map(|e| e.1).reduce(f64::min)?;
        let by_load = |a: &&(&String, f64, bool), b: &&(&String, f64, bool)| a.1.total_cmp(&b.1);
        let (name, _, _) = eligible
            .iter()
            .filter(|(_, load, carries)| *carries && *load <= least + 0.10)
            .min_by(by_load)
            .or_else(|| eligible.iter().min_by(by_load))?;
        let name = (*name).clone();
        let keys = self.keys.get(&name)?;
        let core_ms = self.core_ms();
        let edge = reg.links.get_mut(&name)?;
        let slot = edge.next_slot;
        edge.next_slot += 1;
        let ticket = pool_keys::seal(
            &keys.ticket,
            &pool_keys::mint(edge.link_id, share, slot, core_ms),
        );
        edge.assigned_viewers += 1;
        edge.assigned_kbps += ceiling;
        *edge.shares.entry(share).or_insert(0) += 1;
        if let Some(feed) = edge.feeds.get_mut(&share) {
            feed.idle_since = None;
        }
        let placement = Placement {
            id: self.next_placement(),
            edge: name,
            link: edge.link_id,
            slot,
        };
        let view = EdgeView {
            host: edge.caps.public_host.clone(),
            port: edge.caps.public_port,
            cert_hashes: edge.caps.cert_hashes.clone(),
            ticket,
        };
        Some((placement, view))
    }

    /// A fresh slot on the same edge for a viewer who asked to watch the share it watches
    /// there: the slot before is revoked, and the counts stay. `None` if that link is
    /// closing; its end seats the viewer again.
    pub(crate) fn reslot(
        &self,
        held: &Placement,
        share: SessionId,
    ) -> Option<(Placement, EdgeView)> {
        let keys = self.keys.get(&held.edge)?;
        let core_ms = self.core_ms();
        let mut reg = self.lock();
        let edge = reg
            .links
            .get_mut(&held.edge)
            .filter(|e| e.link_id == held.link && !e.closing)?;
        let slot = edge.next_slot;
        edge.next_slot += 1;
        let ticket = pool_keys::seal(
            &keys.ticket,
            &pool_keys::mint(edge.link_id, share, slot, core_ms),
        );
        edge.send(CoreMsg::Revoke {
            slot: held.slot,
            core_ms,
        });
        let placement = Placement {
            id: self.next_placement(),
            edge: held.edge.clone(),
            link: held.link,
            slot,
        };
        let view = EdgeView {
            host: edge.caps.public_host.clone(),
            port: edge.caps.public_port,
            cert_hashes: edge.caps.cert_hashes.clone(),
            ticket,
        };
        Some((placement, view))
    }

    /// Gives back what `placement` took on its edge, for a viewer of `share` at `ceiling`
    /// kbit/s; with `revoke`, the edge is also told to end it (`CoreMsg::Revoke`). Nothing
    /// if its link is gone already.
    pub(crate) fn unplace(
        &self,
        placement: &Placement,
        share: SessionId,
        ceiling: u32,
        revoke: bool,
    ) {
        let core_ms = self.core_ms();
        let mut reg = self.lock();
        if let Some(edge) = reg.links.get_mut(&placement.edge) {
            if edge.link_id == placement.link {
                unplace_on(edge, share, ceiling);
                if revoke {
                    edge.send(CoreMsg::Revoke {
                        slot: placement.slot,
                        core_ms,
                    });
                }
            }
        }
    }

    /// `share` ended: what its `placements` took is given back, every edge that carries it
    /// is told `ShareEnded`, and its feeds end.
    pub(crate) fn end_share<'a>(
        &self,
        state: &ServerState,
        share: SessionId,
        ceiling: u32,
        placements: impl Iterator<Item = &'a Placement>,
    ) {
        let core_ms = self.core_ms();
        let mut reg = self.lock();
        let mut told = Vec::new();
        for placement in placements {
            if let Some(edge) = reg.links.get_mut(&placement.edge) {
                if edge.link_id == placement.link {
                    unplace_on(edge, share, ceiling);
                    told.push(placement.edge.clone());
                }
            }
        }
        let mut fed = false;
        for (name, edge) in reg.links.iter_mut() {
            let feed = edge.feeds.remove(&share);
            fed |= feed.is_some();
            if feed.is_some() || told.contains(name) {
                edge.send(CoreMsg::ShareEnded { share, core_ms });
            }
        }
        if fed {
            refeed(&reg, state, share);
        }
    }

    /// Each second (`ServerState::share_tick`): feeds no viewer was placed for in
    /// `FEED_IDLE` end.
    pub(crate) fn tick(&self, state: &ServerState, now: Instant) {
        let mut reg = self.lock();
        let mut ended = Vec::new();
        for edge in reg.links.values_mut() {
            edge.feeds.retain(|&share, feed| {
                let idle = feed
                    .idle_since
                    .is_some_and(|at| now.saturating_duration_since(at) >= FEED_IDLE);
                if idle {
                    ended.push(share);
                }
                !idle
            });
        }
        for share in ended {
            refeed(&reg, state, share);
        }
    }

    /// The Load view's Edges table: every configured edge, linked or not, and the warnings
    /// about them.
    pub(crate) fn report(&self) -> (Vec<EdgeLoad>, Vec<String>) {
        let now = Instant::now();
        let reg = self.lock();
        let mut edges = Vec::new();
        let mut warnings = Vec::new();
        for (name, seen) in &reg.seen {
            let Some(edge) = reg.links.get(name) else {
                // Its pool version is not known: what a refused hello said is nobody's proof
                edges.push(EdgeLoad {
                    name: name.clone(),
                    address: seen.address.clone(),
                    online: false,
                    ..Default::default()
                });
                let claimed = seen
                    .claimed
                    .filter(|(_, at)| now.saturating_duration_since(*at) < CLAIM_SHOWN);
                if let Some((version, _)) = claimed {
                    warnings.push(format!(
                        "Edge {name} is not linked, and something naming itself {name} was refused: it speaks pool version {version}, this server {POOL_VERSION}. If that is the edge, update {}. (Unproven: an edge of another pool version cannot show its secret here.)",
                        if version > POOL_VERSION { "this server first, then the edge" } else { "the edge" }
                    ));
                } else if now.saturating_duration_since(seen.since) > OFFLINE_WARN_AFTER {
                    warnings.push(format!(
                        "Edge {name} is offline: viewers it would carry are served by this server, or refused ([pool] edges)."
                    ));
                }
                continue;
            };
            let budget_kbps = edge.budget_kbps();
            let load = edge.last_load.as_ref();
            edges.push(EdgeLoad {
                name: name.clone(),
                address: edge.caps.address(),
                online: true,
                pool_version: POOL_VERSION,
                viewers: edge.assigned_viewers,
                max_viewers: edge.caps.max_viewers,
                shares: edge.carried() as u32,
                max_shares: edge.caps.max_shares,
                kbps: edge.assigned_kbps,
                budget_kbps,
                egress_kbps: load.map_or(0, |l| l.egress_kbps),
                frames_dropped: load.map_or(0, |l| l.frames_dropped),
                cpu_secs: load.map_or(0, |l| l.cpu_secs),
                rss_mib: load.map_or(0, |l| l.rss_mib),
                report_age_secs: now
                    .saturating_duration_since(load.map_or(seen.since, |l| l.at))
                    .as_secs() as u32,
            });
            let max_viewers = edge.caps.max_viewers as u64;
            if edge.assigned_viewers as u64 * 10 >= max_viewers * 9 {
                warnings.push(format!(
                    "Edge {name} carries {}% of the viewers it takes (max_viewers in its edge.toml).",
                    edge.assigned_viewers as u64 * 100 / max_viewers
                ));
            }
            if edge.assigned_kbps * 10 >= budget_kbps * 9 {
                warnings.push(format!(
                    "Edge {name} is given {}% of the video it may send (egress_mbit in its edge.toml).",
                    edge.assigned_kbps * 100 / budget_kbps
                ));
            }
        }
        (edges, warnings)
    }

    /// What `name` was assigned: viewers, kbit/s, and viewers by share; `None` unlinked.
    #[cfg(test)]
    pub(crate) fn assigned(&self, name: &str) -> Option<(u32, u64, HashMap<SessionId, u32>)> {
        let reg = self.lock();
        let edge = reg.links.get(name)?;
        Some((
            edge.assigned_viewers,
            edge.assigned_kbps,
            edge.shares.clone(),
        ))
    }

    /// The queue of the feed of `share` to the test's edge `name`, once.
    #[cfg(test)]
    pub(crate) fn take_feed(&self, name: &str, share: SessionId) -> Option<mpsc::Receiver<Bytes>> {
        self.lock()
            .links
            .get_mut(name)?
            .feeds
            .get_mut(&share)?
            .parked
            .take()
    }

    /// Whether `name` is fed `share`.
    #[cfg(test)]
    pub(crate) fn feeds(&self, name: &str, share: SessionId) -> bool {
        self.lock()
            .links
            .get(name)
            .is_some_and(|edge| edge.feeds.contains_key(&share))
    }
}

/// One viewer of `share` at `ceiling` kbit/s less on `edge`.
fn unplace_on(edge: &mut EdgeLink, share: SessionId, ceiling: u32) {
    edge.assigned_viewers = edge.assigned_viewers.saturating_sub(1);
    edge.assigned_kbps = edge.assigned_kbps.saturating_sub(ceiling as u64);
    if let Some(n) = edge.shares.get_mut(&share) {
        *n -= 1;
        if *n == 0 {
            edge.shares.remove(&share);
            if let Some(feed) = edge.feeds.get_mut(&share) {
                feed.idle_since = Some(Instant::now());
            }
        }
    }
}

/// Points `share`'s fan at the feeds its edges have now (`Fan::feeds`), with no `channels`
/// lock; under `Pool`'s mutex, which orders two rebuilds.
fn refeed(reg: &Registry, state: &ServerState, share: SessionId) {
    let feeds: Arc<[mpsc::Sender<Bytes>]> = reg
        .links
        .values()
        .filter_map(|edge| Some(edge.feeds.get(&share)?.tx.clone()))
        .collect();
    if let Some(mut fan) = state.share_fans.get_mut(&share) {
        fan.feeds = feeds;
    }
}

/// The name a `Hello` of another pool version gives, if its second field is still the name:
/// only to tell the admin which of the listed edges is out of date.
fn claimed_name(frame: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    enum Head {
        Hello { _pool_version: u32, name: String },
    }
    match postcard::take_from_bytes::<Head>(frame) {
        Ok((Head::Hello { name, .. }, _)) => Some(name),
        Err(_) => None,
    }
}

/// Starts `share`'s feed to the edge on `conn`, as a viewer's media is pumped: datagrams
/// (screen audio) as datagrams, a stream per frame, whole frames dropped when the link falls
/// behind, and deltas held back until the first keyframe, which the subscriber asks for.
/// A drop asks the sharer for the keyframe that ends it and is counted for the Load view.
fn start_feed(state: &Arc<ServerState>, conn: Option<&Connection>) -> Feed {
    let (tx, rx) = mpsc::channel(FEED_QUEUE);
    let Some(conn) = conn else {
        return Feed {
            tx,
            idle_since: None,
            #[cfg(test)]
            parked: Some(rx),
        };
    };
    let (video_tx, video_rx) = mpsc::channel(FEED_QUEUE);
    let asked = state.clone();
    let hook = KeyframeHook::Edge(Arc::new(move |sharer| {
        asked.limits.count("edge", "feed dropped frames");
        crate::session::relay_keyframe_request(&asked, sharer);
    }));
    tokio::spawn(crate::web::pump_media_out(
        DatagramSink::Quic(conn.clone()),
        rx,
        video_tx,
        hook,
        true,
    ));
    tokio::spawn(crate::web::pump_video_streams(conn.clone(), video_rx));
    Feed {
        tx,
        idle_since: None,
        #[cfg(test)]
        parked: None,
    }
}

/// Whether this relay takes edge links (`web::Routes::relay`): only with `[pool] edges`.
/// Without, the path is not found, as any other.
pub(crate) fn serves_edges(state: &ServerState) -> bool {
    state.pool.is_some()
}

/// Links the proven edge `name` (`Pool::check_hello`): it gets a random link id, which its
/// `Welcome` carries first on `tx`, and a link of that name before it is closed, its viewers
/// seated again, on this link too if it has room. The link id, or `None` without a pool.
pub(crate) async fn link_up(
    state: &ServerState,
    name: &str,
    caps: EdgeCaps,
    conn: Option<Connection>,
    tx: mpsc::Sender<CoreMsg>,
) -> Option<u64> {
    let pool = state.pool.as_deref()?;
    let mut channels = state.channels.write().await;
    let (link, old) = pool.register(state, name, caps, conn, tx);
    if let Some(old) = old {
        let (moved, refused) = state.move_off_edge(&mut channels, name, old.link_id);
        info!("edge {name} linked again, the link before closed; {moved} viewers moved, {refused} refused");
    }
    Some(link)
}

/// What an edge on its link `name`/`link` said, past its `Hello`. `Err`: close the link.
pub(crate) fn on_edge_msg(
    state: &Arc<ServerState>,
    name: &str,
    link: u64,
    msg: EdgeMsg,
) -> Result<(), &'static str> {
    let Some(pool) = state.pool.as_deref() else {
        return Err("this relay has no pool");
    };
    let mut keyframe = None;
    {
        let mut reg = pool.lock();
        let Some(edge) = reg.links.get_mut(name).filter(|e| e.link_id == link) else {
            return Err("replaced by a newer link");
        };
        let budget = match msg {
            EdgeMsg::Subscribe { .. } | EdgeMsg::Unsubscribe { .. } => {
                Some(&mut edge.subscribe_budget)
            }
            EdgeMsg::KeyframeWanted { .. } => Some(&mut edge.keyframe_budget),
            _ => None,
        };
        if budget.is_some_and(|budget| !budget.try_consume()) {
            state.limits.count("edge", "over rate");
            return Ok(());
        }
        let mut refed = None;
        match msg {
            EdgeMsg::Hello { .. } => return Err("a second hello"),
            // Only for a share it has a viewer placed for: an edge is fed nothing else
            EdgeMsg::Subscribe { share } => {
                if !edge.shares.contains_key(&share) {
                    state.limits.count("edge", "unbound subscribe");
                } else if !edge.feeds.contains_key(&share) {
                    let feed = start_feed(state, edge.conn.as_ref());
                    edge.feeds.insert(share, feed);
                    refed = Some(share);
                    keyframe = Some(share);
                }
            }
            EdgeMsg::Unsubscribe { share } => {
                if edge.feeds.remove(&share).is_some() {
                    refed = Some(share);
                }
            }
            EdgeMsg::KeyframeWanted { share } => {
                if edge.feeds.contains_key(&share) {
                    keyframe = Some(share);
                }
            }
            EdgeMsg::Load {
                egress_kbps,
                frames_dropped,
                cpu_secs,
                rss_mib,
                ..
            } => {
                let now = Instant::now();
                let fresh = edge
                    .last_load
                    .as_ref()
                    .is_none_or(|l| now.saturating_duration_since(l.at) >= LOAD_EVERY);
                if fresh {
                    edge.last_load = Some(LoadSeen {
                        at: now,
                        egress_kbps,
                        frames_dropped,
                        cpu_secs,
                        rss_mib,
                    });
                }
            }
            EdgeMsg::CertRotated { cert_hashes } => {
                if (1..=MAX_CERT_HASHES).contains(&cert_hashes.len()) {
                    edge.caps.cert_hashes = cert_hashes;
                } else {
                    state.limits.count("edge", "bad certificate list");
                }
            }
        }
        if let Some(share) = refed {
            refeed(&reg, state, share);
        }
    }
    // The per-share budget every viewer's request shares
    if let Some(share) = keyframe {
        crate::session::relay_keyframe_request(state, share);
    }
    Ok(())
}

/// A test's edge, linked as `name` with `caps` and no connection: what the relay tells it
/// arrives on the queue returned, its `Welcome` first. Its feeds wait for the test
/// (`Pool::take_feed`).
#[cfg(test)]
pub(crate) async fn test_edge(
    state: &ServerState,
    name: &str,
    caps: EdgeCaps,
) -> mpsc::Receiver<CoreMsg> {
    let (tx, rx) = mpsc::channel(LINK_QUEUE);
    link_up(state, name, caps, None, tx)
        .await
        .expect("a relay with a pool");
    rx
}

/// One edge's link, from its accepted session request on (`pool::POOL_PATH`). `slot` is its
/// pre-authentication slot, held until the edge is proven.
pub(crate) async fn run_link(
    connection: Connection,
    state: Arc<ServerState>,
    peer: SocketAddr,
    slot: PreSlot,
) {
    let Some(pool) = state.pool.clone() else {
        connection.close(VarInt::from_u32(0), b"");
        return;
    };
    let mut buf = BytesMut::new();
    let opened = tokio::time::timeout(HELLO_WAIT, async {
        let (send, mut recv) = connection.accept_bi().await.ok()?;
        let frame = crate::web::read_frame(&mut recv, &mut buf, MAX_POOL_FRAME)
            .await
            .ok()?;
        Some((send, recv, frame))
    })
    .await;
    let Ok(Some((mut send, mut recv, frame))) = opened else {
        state.limits.count("refused", "edge hello");
        connection.close(VarInt::from_u32(0), b"");
        return;
    };
    let binding = crate::web::quic_binding(&connection);
    let (name, caps) = match pool.check_hello(&state.limits, &frame, binding.as_ref()) {
        Hello::Admit { name, caps } => (name, caps),
        Hello::Refuse(answer) => {
            if let Ok(bytes) = encode_core_msg(&answer) {
                let _ = tokio::time::timeout(Duration::from_secs(2), async {
                    send.write_all(&bytes).await.ok()?;
                    send.finish().await.ok()
                })
                .await;
            }
            connection.close(VarInt::from_u32(0), b"");
            return;
        }
        Hello::Close => {
            connection.close(VarInt::from_u32(0), b"");
            return;
        }
    };
    let (max_shares, max_viewers, egress_mbit) =
        (caps.max_shares, caps.max_viewers, caps.egress_mbit);
    let version = caps.version.clone();
    let (tx, rx) = mpsc::channel(LINK_QUEUE);
    let Some(link) = link_up(&state, &name, caps, Some(connection.clone()), tx).await else {
        return;
    };
    drop(slot);
    connection
        .quic_connection()
        .set_send_window((SEND_WINDOW_PER_SHARE * max_shares as u64).min(SEND_WINDOW_MAX));
    // Edges are infrastructure, not users: their addresses are logged
    info!(
        "edge {name} linked from {} (pool v{POOL_VERSION}, {version}, {max_viewers} viewers, {egress_mbit} Mbit/s)",
        peer.ip()
    );
    let writer = tokio::spawn(write_link(send, rx));
    let why = loop {
        match crate::web::read_frame(&mut recv, &mut buf, MAX_POOL_FRAME).await {
            Ok(frame) => match decode_edge_msg(&frame) {
                Ok(msg) => {
                    if let Err(why) = on_edge_msg(&state, &name, link, msg) {
                        break why;
                    }
                }
                Err(_) => break "a frame this relay does not read",
            },
            Err(NoFrame::Malformed) => break "a frame too long",
            Err(_) => break closed_why(&connection).await,
        }
    };
    writer.abort();
    connection.close(VarInt::from_u32(0), b"");
    state.edge_lost(&name, link, why).await;
}

/// The link's writer: what the relay tells the edge, a frame each, in order.
async fn write_link(mut send: SendStream, mut rx: mpsc::Receiver<CoreMsg>) {
    while let Some(msg) = rx.recv().await {
        let Ok(bytes) = encode_core_msg(&msg) else {
            continue;
        };
        if send.write_all(&bytes).await.is_err() {
            return;
        }
    }
}

/// Why a link's stream ended, from its connection.
async fn closed_why(connection: &Connection) -> &'static str {
    match tokio::time::timeout(Duration::from_millis(500), connection.closed()).await {
        Ok(ConnectionError::TimedOut) => "timed out",
        Ok(ConnectionError::ApplicationClosed(_) | ConnectionError::ConnectionClosed(_)) => {
            "closed by the edge"
        }
        Ok(ConnectionError::LocallyClosed) => "closed here",
        Ok(_) => "QUIC error",
        Err(_) => "its stream ended",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "edge-one-secret-of-at-least-32-chars";

    fn pool_of(names: &[&str], local_first: u32) -> Pool {
        Pool::new(&PoolConfig {
            edges: names
                .iter()
                .map(|n| (n.to_string(), format!("{n}-{SECRET}")))
                .collect(),
            local_first,
        })
        .unwrap()
    }

    /// `pool` with edges linked straight into its registry, for `place` alone.
    fn linked(pool: &Pool, edges: &[(&str, EdgeCaps)]) {
        let state = ServerState::for_tests();
        for (name, caps) in edges {
            let (tx, rx) = mpsc::channel(LINK_QUEUE);
            std::mem::forget(rx);
            pool.register(&state, name, caps.clone(), None, tx);
        }
    }

    fn on(placed: Option<(Placement, EdgeView)>) -> Option<String> {
        placed.map(|(p, _)| p.edge)
    }

    #[test]
    fn no_pool_without_edges() {
        assert!(Pool::new(&PoolConfig::default()).is_none());
    }

    #[test]
    fn a_viewer_goes_to_the_least_loaded_edge() {
        let pool = pool_of(&["e1", "e2"], 0);
        linked(
            &pool,
            &[
                ("e1", EdgeCaps::test(100, 100, 4)),
                ("e2", EdgeCaps::test(100, 300, 4)),
            ],
        );
        // 7.5 of 100 against 7.5 of 300
        assert_eq!(on(pool.place(1, 7500, &[], true)).as_deref(), Some("e2"));
        // Now e2 would be 15 of 300 for the first of share 2: still the lighter
        assert_eq!(on(pool.place(2, 7500, &[], true)).as_deref(), Some("e2"));
        let (viewers, kbps, shares) = pool.assigned("e2").unwrap();
        assert_eq!((viewers, kbps), (2, 15_000));
        assert_eq!(shares, HashMap::from([(1, 1), (2, 1)]));
        assert_eq!(pool.assigned("e1").unwrap().0, 0);
    }

    #[test]
    fn an_edge_that_carries_the_share_wins_within_a_tenth() {
        let pool = pool_of(&["e1", "e2"], 0);
        linked(
            &pool,
            &[
                ("e1", EdgeCaps::test(100, 100, 4)),
                ("e2", EdgeCaps::test(100, 100, 4)),
            ],
        );
        // Alike, so the first by name
        assert_eq!(on(pool.place(1, 3000, &[], true)).as_deref(), Some("e1"));
        // e1 would be 6, 9 and 12 of 100, e2 3: e1 carries share 1, within 0.10
        for _ in 0..3 {
            assert_eq!(on(pool.place(1, 3000, &[], true)).as_deref(), Some("e1"));
        }
        // e1 would be 15 of 100, e2 3 of 100: more than 0.10 apart
        assert_eq!(on(pool.place(1, 3000, &[], true)).as_deref(), Some("e2"));
    }

    #[test]
    fn an_edge_takes_no_more_shares_than_it_may() {
        let pool = pool_of(&["e1"], 0);
        linked(&pool, &[("e1", EdgeCaps::test(100, 1000, 2))]);
        assert!(pool.place(1, 2000, &[], true).is_some());
        assert!(pool.place(2, 2000, &[], true).is_some());
        assert!(pool.place(3, 2000, &[], true).is_none(), "a third share");
        assert!(
            pool.place(1, 2000, &[], true).is_some(),
            "a share it carries"
        );
    }

    #[test]
    fn an_edge_takes_no_more_viewers_or_video_than_it_may() {
        let pool = pool_of(&["e1"], 0);
        linked(&pool, &[("e1", EdgeCaps::test(2, 1000, 4))]);
        assert!(pool.place(1, 2000, &[], true).is_some());
        assert!(pool.place(1, 2000, &[], true).is_some());
        assert!(pool.place(1, 2000, &[], true).is_none(), "max_viewers");
        let pool = pool_of(&["e1"], 0);
        linked(&pool, &[("e1", EdgeCaps::test(100, 15, 4))]);
        assert!(pool.place(1, 7500, &[], true).is_some());
        assert!(pool.place(1, 7500, &[], true).is_some());
        assert!(pool.place(1, 7500, &[], true).is_none(), "egress_mbit");
    }

    #[test]
    fn an_edge_new_to_the_share_needs_room_here_for_its_feed() {
        let pool = pool_of(&["e1"], 0);
        linked(&pool, &[("e1", EdgeCaps::test(100, 1000, 4))]);
        assert!(pool.place(1, 2000, &[], false).is_none());
        assert!(pool.place(1, 2000, &[], true).is_some());
        assert!(
            pool.place(1, 2000, &[], false).is_some(),
            "it is fed already: no more for this relay"
        );
    }

    #[test]
    fn an_avoided_edge_is_not_picked() {
        let pool = pool_of(&["e1", "e2"], 0);
        linked(
            &pool,
            &[
                ("e1", EdgeCaps::test(100, 1000, 4)),
                ("e2", EdgeCaps::test(100, 100, 4)),
            ],
        );
        assert_eq!(on(pool.place(1, 2000, &[], true)).as_deref(), Some("e1"));
        assert_eq!(
            on(pool.place(1, 2000, &["e1".into()], true)).as_deref(),
            Some("e2")
        );
        assert!(pool
            .place(1, 2000, &["e1".into(), "e2".into()], true)
            .is_none());
    }

    #[test]
    fn a_placements_ticket_opens_on_its_edge_for_its_link_and_share() {
        let pool = pool_of(&["e1"], 0);
        linked(&pool, &[("e1", EdgeCaps::test(100, 1000, 4))]);
        let (first, view) = pool.place(42, 2000, &[], true).unwrap();
        let body = pool_keys::open(
            &pool_keys::ticket_key(&format!("e1-{SECRET}")),
            &view.ticket,
        )
        .unwrap();
        assert_eq!(
            (body.link, body.share, body.slot),
            (first.link, 42, first.slot)
        );
        assert_eq!((view.host.as_str(), view.port), ("127.0.0.1", 9991));
        let (second, _) = pool.place(42, 2000, &[], true).unwrap();
        assert_ne!(first.slot, second.slot, "a slot each");
        assert_ne!(first.id, second.id, "a placement each");
    }

    #[test]
    fn a_link_id_is_random_not_counted() {
        let pool = pool_of(&["e1"], 0);
        let ids: std::collections::HashSet<u64> = (0..64).map(|_| pool.random_id()).collect();
        assert_eq!(ids.len(), 64);
        assert!(ids.iter().any(|&id| id > u32::MAX as u64));
    }

    fn hello(name: &str, version: u32, binding: &[u8; BIND_LEN], secret: &str) -> Vec<u8> {
        let msg = EdgeMsg::Hello {
            pool_version: version,
            name: name.into(),
            proof: pool_keys::proof(&pool_keys::proof_key(secret), binding, name),
            public_host: "edge1.example.org".into(),
            public_port: 9991,
            cert_hashes: vec![[1; 32]],
            max_viewers: 1000,
            egress_mbit: 8000,
            max_shares: 16,
            version: "1.15.0".into(),
        };
        voipc_protocol::pool::encode_edge_msg(&msg).unwrap()[4..].to_vec()
    }

    fn limits() -> ConnLimits {
        ConnLimits::new(64, 32)
    }

    #[test]
    fn a_proven_hello_is_admitted_with_what_it_says() {
        let pool = pool_of(&["e1"], 8);
        let binding = [3; BIND_LEN];
        let frame = hello("e1", POOL_VERSION, &binding, &format!("e1-{SECRET}"));
        let Hello::Admit { name, caps } = pool.check_hello(&limits(), &frame, Some(&binding))
        else {
            panic!("not admitted");
        };
        assert_eq!(name, "e1");
        assert_eq!(caps.address(), "edge1.example.org:9991");
        assert_eq!(
            (caps.max_viewers, caps.egress_mbit, caps.max_shares),
            (1000, 8000, 16)
        );
    }

    #[test]
    fn a_hello_of_another_pool_version_is_told_this_ones() {
        let pool = pool_of(&["e1"], 8);
        let binding = [3; BIND_LEN];
        // Version 2, with fields after the version that version 1 does not read
        let mut frame = postcard::to_allocvec(&(0u8, 2u32, "e1", [9u8; 7])).unwrap();
        frame.extend_from_slice(b"later fields");
        assert_eq!(hello_version(&frame), Some(2));
        assert!(decode_edge_msg(&frame).is_err());
        let limits = limits();
        match pool.check_hello(&limits, &frame, Some(&binding)) {
            Hello::Refuse(CoreMsg::Refused { pool_version, .. }) => assert_eq!(pool_version, 1),
            _ => panic!("not refused with this relay's version"),
        }
        assert_eq!(
            limits.take_counts().into_iter().collect::<Vec<_>>(),
            [(("refused", "edge pool version"), 1)]
        );
        let (edges, warnings) = pool.report();
        assert_eq!(edges[0].pool_version, 0, "not proven");
        assert!(warnings[0].contains("pool version 2"), "{warnings:?}");
        assert!(warnings[0].contains("Unproven"), "{warnings:?}");
    }

    /// Anyone who reaches the port can send a hello of another version with a listed name,
    /// which proves nothing: it keeps no proven edge's warning out, and says nothing of an
    /// edge that is linked, then or later.
    #[test]
    fn a_refusal_for_another_pool_version_is_nobodys_word_for_the_edge() {
        let pool = pool_of(&["e1"], 8);
        let binding = [3; BIND_LEN];
        let limits = limits();
        let claim = postcard::to_allocvec(&(0u8, 2u32, "e1", [9u8; 7])).unwrap();
        pool.check_hello(&limits, &claim, Some(&binding));
        assert_eq!(pool.warnings.load(Ordering::Relaxed), 1);
        // A wrong secret of e1 is still warned about, within the same minute
        let wrong = hello(
            "e1",
            POOL_VERSION,
            &binding,
            "a-guessed-secret-of-at-least-32-chars",
        );
        pool.check_hello(&limits, &wrong, Some(&binding));
        assert_eq!(pool.warnings.load(Ordering::Relaxed), 2);

        // While e1 is linked a claim is kept nowhere, so it does not show once e1 goes
        let state = ServerState::for_tests();
        let (tx, _rx) = mpsc::channel(LINK_QUEUE);
        let (link, _) = pool.register(&state, "e1", EdgeCaps::test(10, 100, 4), None, tx);
        assert!(pool.report().1.is_empty());
        pool.check_hello(&limits, &claim, Some(&binding));
        assert!(pool.unlink(&state, "e1", link));
        let (edges, warnings) = pool.report();
        assert_eq!((edges[0].online, edges[0].pool_version), (false, 0));
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// The app counts its 10 s from its last whole frame, this relay from the last fragment,
    /// which a sharer stalled within a frame sent later: a share is silent here well before
    /// any of its viewers' 10 s are up, so none of them is moved for the sharer's stall.
    #[test]
    fn a_share_is_silent_here_before_any_viewers_10_s_are_up() {
        assert!(share_silent(0, 50_000), "nothing sent yet");
        assert!(!share_silent(40_000, 47_000));
        assert!(share_silent(40_000, 48_000), "8 s since its last fragment");
        assert!(share_silent(40_000, 47_001));
        assert!(
            !share_silent(40_000, 39_000),
            "a clock read before the packet"
        );
    }

    #[test]
    fn a_hello_with_a_wrong_proof_or_name_is_closed_unanswered() {
        let pool = pool_of(&["e1"], 8);
        let binding = [3; BIND_LEN];
        let limits = limits();
        for frame in [
            hello(
                "e1",
                POOL_VERSION,
                &binding,
                "another-secret-of-at-least-32-chars",
            ),
            hello("e2", POOL_VERSION, &binding, &format!("e1-{SECRET}")),
            hello(
                &"e".repeat(33),
                POOL_VERSION,
                &binding,
                &format!("e1-{SECRET}"),
            ),
        ] {
            assert!(matches!(
                pool.check_hello(&limits, &frame, Some(&binding)),
                Hello::Close
            ));
        }
        // Made on another connection
        let frame = hello("e1", POOL_VERSION, &[4; BIND_LEN], &format!("e1-{SECRET}"));
        assert!(matches!(
            pool.check_hello(&limits, &frame, Some(&binding)),
            Hello::Close
        ));
        assert!(matches!(
            pool.check_hello(&limits, &frame, None),
            Hello::Close
        ));
        assert!(matches!(
            pool.check_hello(&limits, b"\x07junk", Some(&binding)),
            Hello::Close
        ));
        let counts = limits.take_counts();
        assert_eq!(counts[&("refused", "edge proof")], 5);
        assert_eq!(counts[&("refused", "edge hello")], 1);
    }

    #[test]
    fn a_proven_edge_with_limits_no_viewer_could_use_is_told_why() {
        let pool = pool_of(&["e1"], 8);
        let binding = [3; BIND_LEN];
        let secret = format!("e1-{SECRET}");
        let with = |change: &dyn Fn(&mut EdgeMsg)| {
            let mut msg = decode_edge_msg(&hello("e1", POOL_VERSION, &binding, &secret)).unwrap();
            change(&mut msg);
            let frame = voipc_protocol::pool::encode_edge_msg(&msg).unwrap()[4..].to_vec();
            match pool.check_hello(&limits(), &frame, Some(&binding)) {
                Hello::Refuse(CoreMsg::Refused { reason, .. }) => reason,
                Hello::Admit { .. } => String::new(),
                _ => panic!("a proven edge is told"),
            }
        };
        let set = |f: fn(&mut EdgeMsg)| with(&f);
        assert_eq!(set(|_| {}), "");
        assert!(!set(|m| if let EdgeMsg::Hello { public_host, .. } = m {
            *public_host = "a b".into()
        })
        .is_empty());
        assert!(!set(|m| if let EdgeMsg::Hello { public_host, .. } = m {
            *public_host = "x".repeat(254)
        })
        .is_empty());
        assert_eq!(
            set(|m| if let EdgeMsg::Hello { public_host, .. } = m {
                *public_host = "2001:db8::1".into()
            }),
            ""
        );
        assert!(!set(|m| if let EdgeMsg::Hello { public_port, .. } = m {
            *public_port = 0
        })
        .is_empty());
        assert!(!set(|m| if let EdgeMsg::Hello { cert_hashes, .. } = m {
            cert_hashes.clear()
        })
        .is_empty());
        assert!(!set(|m| if let EdgeMsg::Hello { cert_hashes, .. } = m {
            *cert_hashes = vec![[0; 32]; 5]
        })
        .is_empty());
        assert!(!set(|m| if let EdgeMsg::Hello { max_shares, .. } = m {
            *max_shares = 65
        })
        .is_empty());
        assert!(!set(|m| if let EdgeMsg::Hello { max_viewers, .. } = m {
            *max_viewers = 0
        })
        .is_empty());
        assert!(!set(|m| if let EdgeMsg::Hello { egress_mbit, .. } = m {
            *egress_mbit = 0
        })
        .is_empty());
    }

    /// The warning about refused edges cannot be made a flood, nor print what a stranger
    /// chose to call itself.
    #[test]
    fn a_thousand_failed_proofs_with_random_names_give_one_warning() {
        let pool = pool_of(&["e1"], 8);
        let binding = [3; BIND_LEN];
        let limits = limits();
        for _ in 0..1000 {
            let name: String = (0..12)
                .map(|_| (b'a' + rand::random::<u8>() % 26) as char)
                .collect();
            let frame = hello(
                &name,
                POOL_VERSION,
                &binding,
                "a-guessed-secret-of-at-least-32-chars",
            );
            assert!(matches!(
                pool.check_hello(&limits, &frame, Some(&binding)),
                Hello::Close
            ));
        }
        assert_eq!(pool.warnings.load(Ordering::Relaxed), 1);
        assert_eq!(limits.take_counts()[&("refused", "edge proof")], 1000);
        assert!(
            pool.lock().seen.keys().eq(["e1"]),
            "only listed names are kept"
        );
        // A listed name has a minute of its own
        let frame = hello(
            "e1",
            POOL_VERSION,
            &binding,
            "a-guessed-secret-of-at-least-32-chars",
        );
        pool.check_hello(&limits, &frame, Some(&binding));
        pool.check_hello(&limits, &frame, Some(&binding));
        assert_eq!(pool.warnings.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn hosts_are_names_or_addresses() {
        for good in [
            "edge1.example.org",
            "localhost",
            "10.0.0.1",
            "2001:db8::1",
            "a-b.c1",
        ] {
            assert!(host_ok(good), "{good}");
        }
        for bad in [
            "",
            "a b",
            "-a.org",
            "a-.org",
            "a..org",
            "a.org.",
            "[::1]",
            "a_b.org",
            &"a".repeat(64),
        ] {
            assert!(!host_ok(bad), "{bad}");
        }
    }

    /// Over QUIC, through the relay's own accept loop (`web::Routes::relay`): what a link's
    /// first frame comes to, and that a link's end is an edge lost.
    mod over_quic {
        use super::*;
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};
        use voipc_protocol::pool::{decode_core_msg, encode_edge_msg, POOL_PATH};
        use wtransport::endpoint::endpoint_side::Client;
        use wtransport::Endpoint;

        const HANG: Duration = Duration::from_secs(60);

        /// Takes whatever certificate the relay shows: these tests are about what comes after.
        #[derive(Debug)]
        struct AnyCert;

        impl ServerCertVerifier for AnyCert {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &ServerName<'_>,
                _: &[u8],
                _: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::ED25519,
                ]
            }
        }

        /// A relay with `e1` in `[pool]`, serving on 127.0.0.1: its state and port.
        fn relay() -> (Arc<ServerState>, u16) {
            let mut config = crate::config::ServerConfig::default();
            config
                .pool
                .edges
                .insert("e1".into(), format!("e1-{SECRET}"));
            let state = Arc::new(ServerState::new(
                &config,
                crate::settings::ServerSettings::default(),
                Vec::new(),
                "test-admin-token".into(),
            ));
            let port = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let web = crate::web::WebTransport::bind_with(
                ([127, 0, 0, 1], port).into(),
                None,
                crate::web::Role::Relay,
            )
            .unwrap();
            tokio::spawn(web.run(state.clone(), state.limits.clone()));
            (state, port)
        }

        /// A link to the relay on `port`, its stream open: the endpoint, which must outlive
        /// it, the connection and its stream.
        async fn dial(
            port: u16,
        ) -> (
            Endpoint<Client>,
            Connection,
            (wtransport::SendStream, wtransport::RecvStream),
        ) {
            let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert))
            .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            let config = wtransport::ClientConfig::builder()
                .with_bind_address("127.0.0.1:0".parse().unwrap())
                .with_custom_tls(tls)
                .build();
            let endpoint = Endpoint::client(config).unwrap();
            let connection = tokio::time::timeout(
                HANG,
                endpoint.connect(format!("https://127.0.0.1:{port}{POOL_PATH}")),
            )
            .await
            .unwrap()
            .unwrap();
            let stream = connection.open_bi().await.unwrap().await.unwrap();
            (endpoint, connection, stream)
        }

        async fn answer(recv: &mut wtransport::RecvStream) -> CoreMsg {
            let mut buf = BytesMut::new();
            let frame =
                tokio::time::timeout(HANG, crate::web::read_frame(recv, &mut buf, MAX_POOL_FRAME))
                    .await
                    .unwrap()
                    .ok()
                    .expect("an answer");
            decode_core_msg(&frame).unwrap()
        }

        #[tokio::test]
        async fn a_link_of_another_pool_version_is_told_this_ones() {
            let (state, port) = relay();
            let (_endpoint, connection, (mut send, mut recv)) = dial(port).await;
            let payload = postcard::to_allocvec(&(0u8, 2u32, "e1", "fields of version 2")).unwrap();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&payload);
            send.write_all(&frame).await.unwrap();
            let CoreMsg::Refused { pool_version, .. } = answer(&mut recv).await else {
                panic!("not refused");
            };
            assert_eq!(pool_version, POOL_VERSION);
            tokio::time::timeout(HANG, connection.closed())
                .await
                .unwrap();
            assert!(state.pool.as_ref().unwrap().assigned("e1").is_none());
        }

        #[tokio::test]
        async fn a_proven_link_is_welcomed_and_its_end_is_an_edge_lost() {
            let (state, port) = relay();
            let (_endpoint, connection, (mut send, mut recv)) = dial(port).await;
            let binding = crate::web::quic_binding(&connection).unwrap();
            let hello = EdgeMsg::Hello {
                pool_version: POOL_VERSION,
                name: "e1".into(),
                proof: pool_keys::proof(
                    &pool_keys::proof_key(&format!("e1-{SECRET}")),
                    &binding,
                    "e1",
                ),
                public_host: "127.0.0.1".into(),
                public_port: 9991,
                cert_hashes: vec![[1; 32]],
                max_viewers: 10,
                egress_mbit: 100,
                max_shares: 4,
                version: "1.15.0".into(),
            };
            send.write_all(&encode_edge_msg(&hello).unwrap())
                .await
                .unwrap();
            let CoreMsg::Welcome { link, .. } = answer(&mut recv).await else {
                panic!("not welcomed");
            };
            let pool = state.pool.as_ref().unwrap();
            assert_eq!(pool.assigned("e1"), Some((0, 0, HashMap::new())));
            let (edges, _) = pool.report();
            assert!(edges[0].online);
            // A second hello on the link ends it
            send.write_all(&encode_edge_msg(&hello).unwrap())
                .await
                .unwrap();
            tokio::time::timeout(HANG, async {
                while pool.assigned("e1").is_some() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the link stayed");
            assert!(on_edge_msg(&state, "e1", link, EdgeMsg::KeyframeWanted { share: 1 }).is_err());
            assert!(!pool.report().0[0].online);
        }
    }
}
