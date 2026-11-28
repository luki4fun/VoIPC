//! The media edge role (`voipc-server -c edge.toml edge`, 1.15): a process of its own, often
//! on another machine, that links to a core relay (`[pool] edges` there) and forwards the
//! screen shares that core places viewers on it for. The core keeps everything about who
//! may watch: each viewer it places here gets a ticket sealed for this edge alone
//! (`pool_keys`), and the edge serves whoever shows a good one. Frames stay sealed end to
//! end, so an edge learns which addresses watch, when, and how big the frames are, never a
//! name, a channel or a key.
//!
//! An edge has no page, tunnel, files, accounts, channels, bans or operator certificate, and
//! no `ServerState`. It is made of:
//! - its viewers' endpoint (`web::WebTransport` as `Role::EdgeViewers`) with a certificate
//!   of its own, rotated as the relay's browser one is, which viewers pin by the hashes
//!   their core sends them (`view.rs`);
//! - one link to its core (`link.rs`): its proof and limits go up, revocations come down,
//!   and each share it asked for arrives as a viewer of the core gets it, a stream per frame
//!   and screen audio as datagrams;
//! - `Edge`, which ties the two together under one mutex never held across an await: who
//!   watches which share, the ticket slots used or revoked, and the link in force.
//!
//! Tickets are read on the core's clock only: the edge maps it through the `Welcome` of its
//! link and its own `Instant`, so neither machine needs NTP. A lost link ends every viewer
//! here ("core lost") and forgets everything: the core seats them again, and a ticket of an
//! earlier link is good for no later one (a link's id is random).

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use ring::hmac;
use serde::Deserialize;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::info;
use voipc_protocol::pool::{EdgeMsg, VIEW_PATH};
use voipc_protocol::types::SessionId;
use voipc_protocol::video::{VideoPacketType, ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE};
use wtransport::{Connection, VarInt};

use crate::config::{edge_name_ok, MAX_EDGE_NAME, MIN_EDGE_SECRET};
use crate::pool_keys::{self, TICKET_TTL_MS};
use crate::web::{KeyframeHook, Role, Routes, WebTransport};
use crate::ConnLimits;

mod link;
#[cfg(test)]
mod tests;
mod view;

/// How long a share stays fed after its last viewer here left, for one who comes back;
/// then the edge tells its core `Unsubscribe`.
const UNSUBSCRIBE_AFTER: Duration = Duration::from_secs(10);
/// The most often one share's keyframe is asked for (`EdgeMsg::KeyframeWanted`), however
/// many of its viewers join or lose frames in that time.
const KEYFRAME_EVERY: Duration = Duration::from_secs(1);
/// A share asked for (`Subscribe`) and not fed this long, while viewers here wait for it,
/// is asked for again. The core starts a feed with a keyframe it asks the sharer for, so a
/// feed taken arrives well within this; one still missing was not taken, as when the ask
/// came past the core's rate, and without asking again its viewers here would wait for as
/// long as any of them stays. The core takes another ask for a share it feeds as nothing.
const RESUBSCRIBE_AFTER: Duration = Duration::from_secs(5);
/// How often waiting keyframe asks, idle shares and old ticket slots are seen to.
const TICK: Duration = Duration::from_millis(250);
/// A viewer's media queue, as on the core (`web::start_session`).
const VIEWER_QUEUE: usize = 512;
/// Connections past `max_viewers` the edge's limits leave room for: those still in their
/// handshake or hello.
const SETUP_ROOM: u32 = 64;
/// How long a stopping edge gives its viewers to read why.
const STOP_GRACE: Duration = Duration::from_secs(1);

// ── edge.toml ──────────────────────────────────────────────────────────

/// edge.toml: where the core is and how this edge proves itself to it, where viewers reach
/// this edge, and what it may carry. Read only by `voipc-server -c edge.toml edge`, and
/// apart from server.toml, so neither can grow a key the other needs.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EdgeConfig {
    /// The core's `host:port`, its UDP port (where its apps connect). An IPv6 address goes
    /// in brackets.
    pub core: String,
    /// The SHA-256 of the core's certificate in hex, colons optional: what
    /// `voipc-server cert fingerprint` prints on the core. Unset, the core's certificate
    /// must be one the public CAs issued for `core`'s name, which then must be a name.
    #[serde(default)]
    pub core_fingerprint: Option<String>,
    /// This edge's name in the core's `[pool] edges`.
    pub name: String,
    /// Its secret there.
    pub secret: String,
    /// The address viewers' QUIC is bound on.
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
    /// `host:port` as viewers reach this edge's UDP port, which the core sends them.
    pub public: String,
    /// The most viewers this edge serves at once.
    #[serde(default = "default_max_viewers")]
    pub max_viewers: u32,
    /// What this edge may send, in Mbit/s. The core places no more video on it than this.
    #[serde(default = "default_egress_mbit")]
    pub egress_mbit: u32,
    /// The most shares it is fed at once.
    #[serde(default = "default_max_shares")]
    pub max_shares: u32,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
}

fn default_host() -> String {
    "::".into()
}

fn default_udp_port() -> u16 {
    9987
}

fn default_max_viewers() -> u32 {
    1000
}

fn default_egress_mbit() -> u32 {
    8000
}

fn default_max_shares() -> u32 {
    16
}

fn default_max_connections_per_ip() -> u32 {
    32
}

/// The most shares an edge may say it carries (`pool::EdgeCaps::check` on the core).
const MAX_SHARES: u32 = 64;

/// Everything but the secret: a config printed into a log or a bug report gives the edge
/// away to nobody.
impl std::fmt::Debug for EdgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeConfig")
            .field("core", &self.core)
            .field("core_fingerprint", &self.core_fingerprint)
            .field("name", &self.name)
            .field("secret", &"<secret>")
            .field("host", &self.host)
            .field("udp_port", &self.udp_port)
            .field("public", &self.public)
            .field("max_viewers", &self.max_viewers)
            .field("egress_mbit", &self.egress_mbit)
            .field("max_shares", &self.max_shares)
            .field("max_connections_per_ip", &self.max_connections_per_ip)
            .finish()
    }
}

/// What an edge runs with: a checked edge.toml (`EdgeConfig::check`), or a test's own.
pub(crate) struct Settings {
    pub core_host: String,
    pub core_port: u16,
    /// `core_fingerprint`; `None`: the public CAs vouch for `core_host`.
    pub core_pin: Option<[u8; 32]>,
    pub name: String,
    pub secret: String,
    pub bind: SocketAddr,
    pub public_host: String,
    pub public_port: u16,
    pub max_viewers: u32,
    pub egress_mbit: u32,
    pub max_shares: u32,
    pub max_connections_per_ip: u32,
}

impl EdgeConfig {
    /// What this edge runs with, or what is wrong in its edge.toml.
    pub(crate) fn check(&self) -> Result<Settings> {
        let (core_host, core_port) = host_port(&self.core).map_err(|e| anyhow!("core: {e}"))?;
        let core_pin = self
            .core_fingerprint
            .as_deref()
            .map(parse_fingerprint)
            .transpose()?;
        if core_pin.is_none() && core_host.parse::<IpAddr>().is_ok() {
            bail!(
                "core is an IP address, which no public certificate names: set core_fingerprint \
                 to what `voipc-server cert fingerprint` prints on the core"
            );
        }
        if !edge_name_ok(&self.name) {
            bail!(
                "name {:?} must be 1 to {MAX_EDGE_NAME} of a-z, 0-9 and -, as in the core's [pool] edges",
                self.name
            );
        }
        if self.secret.chars().count() < MIN_EDGE_SECRET {
            bail!(
                "secret must be at least {MIN_EDGE_SECRET} characters (openssl rand -base64 32), \
                 the same as this edge's in the core's [pool] edges"
            );
        }
        if self.udp_port == 0 {
            bail!("udp_port must not be 0: the core sends viewers to the port in public");
        }
        let bind = (self.host.as_str(), self.udp_port)
            .to_socket_addrs()
            .with_context(|| format!("invalid bind address {}:{}", self.host, self.udp_port))?
            .next()
            .ok_or_else(|| anyhow!("host {} resolves to no address", self.host))?;
        let (public_host, public_port) =
            host_port(&self.public).map_err(|e| anyhow!("public: {e}"))?;
        if self.max_viewers == 0 || self.egress_mbit == 0 {
            bail!("max_viewers and egress_mbit must be at least 1");
        }
        if !(1..=MAX_SHARES).contains(&self.max_shares) {
            bail!("max_shares must be 1 to {MAX_SHARES}");
        }
        if self.max_connections_per_ip < 2 {
            bail!("max_connections_per_ip must be at least 2");
        }
        Ok(Settings {
            core_host,
            core_port,
            core_pin,
            name: self.name.clone(),
            secret: self.secret.clone(),
            bind,
            public_host,
            public_port,
            max_viewers: self.max_viewers,
            egress_mbit: self.egress_mbit,
            max_shares: self.max_shares,
            max_connections_per_ip: self.max_connections_per_ip,
        })
    }
}

/// `host:port`, with a port that is not 0 and a host that is a DNS name or an IP address;
/// an IPv6 one in brackets, which the host comes back without.
fn host_port(text: &str) -> Result<(String, u16), String> {
    let (host, port) = match text.strip_prefix('[') {
        Some(rest) => {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| format!("{text:?} is not [address]:port"))?;
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!("{host:?} in brackets is not an IPv6 address"));
            }
            (host, port)
        }
        None => {
            let (host, port) = text
                .rsplit_once(':')
                .ok_or_else(|| format!("{text:?} is not host:port"))?;
            if host.contains(':') {
                return Err(format!(
                    "{text:?}: an IPv6 address goes in brackets, as [2001:db8::1]:9987"
                ));
            }
            (host, port)
        }
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{port:?} is not a port"))?;
    if port == 0 {
        return Err("the port must not be 0".into());
    }
    if !host_ok(host) {
        return Err(format!("{host:?} is not a DNS name or an IP address"));
    }
    Ok((host.to_string(), port))
}

/// A DNS name or an IP literal (no brackets), at most 253 characters: what the core takes
/// as an edge's public host and an app dials (the core's own check is `pool::host_ok`).
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

/// 32 bytes in hex, colons optional, either case: `voipc-server cert fingerprint`'s
/// `AB:CD:…` as it is printed, or without the colons.
fn parse_fingerprint(text: &str) -> Result<[u8; 32]> {
    let digits: String = text.trim().chars().filter(|c| *c != ':').collect();
    hex::decode(&digits)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            anyhow!(
                "core_fingerprint must be 32 bytes in hex, colons optional, \
                 as `voipc-server cert fingerprint` prints it on the core"
            )
        })
}

// ── What the edge carries ──────────────────────────────────────────────

/// This edge's viewers, its shares and its link: what the viewers' sessions (`view.rs`) and
/// the link (`link.rs`) share.
pub(crate) struct Edge {
    name: String,
    public_host: String,
    public_port: u16,
    max_viewers: u32,
    egress_mbit: u32,
    max_shares: u32,
    proof_key: hmac::Key,
    ticket_key: hmac::Key,
    /// The viewers' endpoint's: every connection holds a pre-authentication slot from its
    /// first packet on, and a viewer with a good ticket moves to the main pool (`promote`),
    /// which `max_viewers` and `max_connections_per_ip` bound.
    limits: Arc<ConnLimits>,
    state: Mutex<State>,
    stats: Arc<Stats>,
}

/// What the edge counted since it started: the Load it reports and its minute's line.
#[derive(Default)]
pub(crate) struct Stats {
    /// Media queued for viewers (bytes): what the edge sends, give or take the frames the
    /// viewers' own queues drop.
    egress_bytes: AtomicU64,
    /// Frames a viewer's queue dropped, each a keyframe asked for.
    frames_dropped: AtomicU64,
    /// Media packets dropped for a viewer whose queue was full.
    queue_full: AtomicU64,
    tickets_refused: AtomicU64,
}

#[derive(Default)]
struct State {
    link: Option<Link>,
    shares: HashMap<SessionId, Share>,
    /// Ticket slots no ticket may be shown for again, until they could not be anyway.
    slots: HashMap<u64, Slot>,
    /// Shares the core ended, with when on its clock, as it said: a ticket of one made by
    /// then is refused (`CoreMsg::ShareEnded`), which by `TICKET_TTL_MS` later is every
    /// such ticket.
    ended: HashMap<SessionId, u64>,
    viewers: u32,
    next_viewer: u64,
}

/// The link in force, from its `Welcome`.
struct Link {
    id: u64,
    /// `Welcome.core_ms` and when it came: the core's clock from then on.
    core_ms: u64,
    at: Instant,
    tx: mpsc::Sender<EdgeMsg>,
    /// `None` for a test's link.
    conn: Option<Connection>,
}

impl Link {
    /// The core's clock at `now`. It runs behind the core's own by the time the `Welcome`
    /// took to come, so a ticket lives here that much longer.
    fn core_now(&self, now: Instant) -> u64 {
        let since = now.saturating_duration_since(self.at).as_millis() as u64;
        self.core_ms.saturating_add(since)
    }

    /// A word to the core. A queue it does not empty means the link is stuck: it is closed,
    /// and the core seats this edge's viewers again.
    fn tell(&self, msg: EdgeMsg) {
        if self.tx.try_send(msg).is_err() {
            if let Some(conn) = &self.conn {
                conn.close(VarInt::from_u32(0), b"queue full");
            }
        }
    }
}

/// A ticket slot that is not to be taken (again).
enum Slot {
    /// Shown by a viewer, who may still watch with it (`viewer`: its share and id), which
    /// `CoreMsg::Revoke` ends. Its ticket is good until `until` on the core's clock.
    Used {
        until: u64,
        viewer: Option<(SessionId, u64)>,
    },
    /// Revoked before anyone showed it; its ticket cannot be good past `until`, which the
    /// core's `Revoke` says (`CoreMsg::Revoke.core_ms`).
    Revoked { until: u64 },
}

/// One share this edge is fed, from its first viewer here until the core is told it is no
/// longer wanted.
struct Share {
    viewers: HashMap<u64, Viewer>,
    fan: Arc<Fan>,
    /// The share's reader, which takes its frame streams in the order the core sent them
    /// (`link::route_stream`).
    inbox: mpsc::Sender<link::FeedStream>,
    /// Since when it has no viewer here.
    empty_since: Option<Instant>,
    keyframe: KeyframeMerge,
    /// Whether anything of it came from the core: a frame stream or screen audio.
    fed: bool,
    /// When the core was last asked for it (`Subscribe`).
    asked: Instant,
}

impl Share {
    /// A share asked of the core at `now`.
    fn new(id: SessionId, stats: &Arc<Stats>, now: Instant) -> Self {
        let fan = Arc::new(Fan::default());
        Self {
            viewers: HashMap::new(),
            inbox: link::spawn_reader(id, fan.clone(), stats.clone()),
            fan,
            empty_since: None,
            keyframe: KeyframeMerge::default(),
            fed: false,
            asked: now,
        }
    }

    /// Points the fan at the viewers it has now.
    fn refan(&self) {
        self.fan
            .set(self.viewers.values().map(|v| v.tx.clone()).collect());
    }
}

struct Viewer {
    slot: u64,
    tx: mpsc::Sender<Bytes>,
    end: oneshot::Sender<End>,
}

/// Why the edge ends a viewer's session (`view.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// Told in an `EdgeViewMsg::Ended` with this reason, then closed.
    Say(&'static str),
    /// Closed at once with no word, as if the edge had died (`Running::kill`).
    Drop,
}

/// A share's viewers' media queues, as its reader and its screen audio reach them: swapped
/// whole on every attach and detach, so a packet clones one `Arc` under a read lock.
#[derive(Default)]
pub(crate) struct Fan(RwLock<Arc<[mpsc::Sender<Bytes>]>>);

impl Fan {
    fn set(&self, viewers: Arc<[mpsc::Sender<Bytes>]>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = viewers;
    }

    /// `packet` to every viewer whose queue has room, as UDP would drop it for the rest.
    /// What was queued, in bytes.
    fn send(&self, packet: &Bytes, stats: &Stats) -> u64 {
        let viewers = self
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut sent = 0;
        for tx in viewers.iter() {
            match tx.try_send(packet.clone()) {
                Ok(()) => sent += packet.len() as u64,
                Err(TrySendError::Full(_)) => {
                    stats.queue_full.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Closed(_)) => {}
            }
        }
        sent
    }
}

/// One share's keyframe asks, at most one a `KEYFRAME_EVERY`: one that comes sooner waits
/// for the tick, and any more in that time go with it.
#[derive(Default)]
struct KeyframeMerge {
    last: Option<Instant>,
    waiting: bool,
}

impl KeyframeMerge {
    /// Whether to ask the core now; otherwise the ask waits (`due`).
    fn ask(&mut self, now: Instant) -> bool {
        let free = self
            .last
            .is_none_or(|at| now.saturating_duration_since(at) >= KEYFRAME_EVERY);
        if free {
            self.last = Some(now);
            self.waiting = false;
        } else {
            self.waiting = true;
        }
        free
    }

    /// Whether a waiting ask may go now.
    fn due(&mut self, now: Instant) -> bool {
        self.waiting && self.ask(now)
    }
}

/// A viewer let in (`Edge::admit`): its share, its id here, its media queue, and how the
/// edge tells it to end.
pub(crate) struct Admitted {
    pub share: SessionId,
    pub viewer: u64,
    pub media: mpsc::Receiver<Bytes>,
    pub end: oneshot::Receiver<End>,
}

impl State {
    /// Takes `viewer` of `share` out, telling it `end`. Its slot stays used.
    fn remove_viewer(&mut self, share: SessionId, viewer: u64, end: End, now: Instant) {
        let Some(carried) = self.shares.get_mut(&share) else {
            return;
        };
        let Some(gone) = carried.viewers.remove(&viewer) else {
            return;
        };
        carried.refan();
        if carried.viewers.is_empty() {
            carried.empty_since = Some(now);
        }
        self.viewers -= 1;
        if let Some(Slot::Used { viewer: holder, .. }) = self.slots.get_mut(&gone.slot) {
            *holder = None;
        }
        let _ = gone.end.send(end);
    }

    /// Ends every viewer of `share` with `end` and stops carrying it.
    fn drop_share(&mut self, share: SessionId, end: End) {
        let Some(gone) = self.shares.remove(&share) else {
            return;
        };
        // Its reader may be inside a frame: from here it reaches nobody
        gone.fan.set(Arc::new([]));
        for gone in gone.viewers.into_values() {
            self.viewers -= 1;
            if let Some(Slot::Used { viewer: holder, .. }) = self.slots.get_mut(&gone.slot) {
                *holder = None;
            }
            let _ = gone.end.send(end);
        }
    }

    /// Ends every viewer with `end` and forgets every share, slot and ended share: for a new
    /// link, all of that is the core's to say again.
    fn forget_all(&mut self, end: End) -> u32 {
        let ended = self.viewers;
        let shares: Vec<SessionId> = self.shares.keys().copied().collect();
        for share in shares {
            self.drop_share(share, end);
        }
        self.slots.clear();
        self.ended.clear();
        ended
    }
}

impl Edge {
    fn new(settings: &Settings, limits: Arc<ConnLimits>) -> Self {
        Self {
            name: settings.name.clone(),
            public_host: settings.public_host.clone(),
            public_port: settings.public_port,
            max_viewers: settings.max_viewers,
            egress_mbit: settings.egress_mbit,
            max_shares: settings.max_shares,
            proof_key: pool_keys::proof_key(&settings.secret),
            ticket_key: pool_keys::ticket_key(&settings.secret),
            limits,
            state: Mutex::new(State::default()),
            stats: Arc::new(Stats::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lets in the viewer at `ip` who showed `ticket`, or says why not; a refusal is counted
    /// by reason. The ticket must be sealed for this edge, of the link in force, not past its
    /// time on the core's clock, of a slot not used or revoked, and of a share the core did
    /// not end since it was made; and the edge must have room for one more viewer, and for
    /// the share if it does not carry it yet. Then the connection moves to the main pool of
    /// `limits` (`promote`), which bounds viewers per address; without that, every viewer
    /// would keep its pre-authentication slot and the pre pool (1024 in all, 16 per
    /// address) would cap the edge. The first viewer of a share asks the core for it
    /// (`Subscribe`), and every one for a keyframe, merged to one a second.
    pub(crate) fn admit(
        &self,
        ticket: &[u8],
        ip: IpAddr,
        now: Instant,
    ) -> Result<Admitted, &'static str> {
        let admitted = self.try_admit(ticket, ip, now);
        if let Err(why) = admitted {
            self.limits.count("ticket refused", why);
            self.stats.tickets_refused.fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    fn try_admit(&self, ticket: &[u8], ip: IpAddr, now: Instant) -> Result<Admitted, &'static str> {
        let body = pool_keys::open(&self.ticket_key, ticket).map_err(|_| "bad ticket")?;
        let mut state = self.lock();
        let State {
            link,
            shares,
            slots,
            ended,
            viewers,
            next_viewer,
        } = &mut *state;
        let link = link
            .as_ref()
            .filter(|link| link.id == body.link)
            .ok_or("another link")?;
        if pool_keys::expired(&body, link.core_now(now)) {
            return Err("expired");
        }
        match slots.get(&body.slot) {
            Some(Slot::Used { .. }) => return Err("used"),
            Some(Slot::Revoked { .. }) => return Err("revoked"),
            None => {}
        }
        let made = body.expires_ms.saturating_sub(TICKET_TTL_MS);
        if ended.get(&body.share).is_some_and(|&at| made <= at) {
            return Err("share ended");
        }
        let carried = shares.contains_key(&body.share);
        if *viewers >= self.max_viewers || (!carried && shares.len() >= self.max_shares as usize) {
            return Err("edge full");
        }
        self.limits.promote(ip).map_err(|_| "edge full")?;

        let id = *next_viewer;
        *next_viewer += 1;
        *viewers += 1;
        slots.insert(
            body.slot,
            Slot::Used {
                until: body.expires_ms,
                viewer: Some((body.share, id)),
            },
        );
        let share = match shares.entry(body.share) {
            Entry::Occupied(carried) => carried.into_mut(),
            Entry::Vacant(new) => {
                link.tell(EdgeMsg::Subscribe { share: body.share });
                new.insert(Share::new(body.share, &self.stats, now))
            }
        };
        let (tx, media) = mpsc::channel(VIEWER_QUEUE);
        let (end_tx, end) = oneshot::channel();
        share.viewers.insert(
            id,
            Viewer {
                slot: body.slot,
                tx,
                end: end_tx,
            },
        );
        share.empty_since = None;
        share.refan();
        // It starts on a keyframe (`web::pump_media_out`), which it asks for here
        if share.keyframe.ask(now) {
            link.tell(EdgeMsg::KeyframeWanted { share: body.share });
        }
        Ok(Admitted {
            share: body.share,
            viewer: id,
            media,
            end,
        })
    }

    /// The viewer left on its own (or was ended already, then nothing happens). Its slot stays
    /// used until its ticket's time is up.
    pub(crate) fn leave(&self, share: SessionId, viewer: u64, now: Instant) {
        self.lock().remove_viewer(share, viewer, End::Drop, now);
    }

    /// `CoreMsg::Revoke`, sent at `core_ms` on the core's clock: the viewer of `slot` is
    /// ended ("revoked"), or its ticket refused if nobody showed it yet.
    pub(crate) fn revoke(&self, slot: u64, core_ms: u64, now: Instant) {
        let mut state = self.lock();
        if state.link.is_none() {
            return;
        }
        let holder = match state.slots.get_mut(&slot) {
            Some(Slot::Used { viewer, .. }) => viewer.take(),
            Some(Slot::Revoked { .. }) => None,
            None => {
                // Its ticket was made before the core said so, so it is past its time by
                // then. Not by the edge's reading of the core's clock now, which runs behind
                // by however long the Welcome took: the ticket would be good again before
                // its time was up here.
                let until = core_ms.saturating_add(TICKET_TTL_MS);
                state.slots.insert(slot, Slot::Revoked { until });
                None
            }
        };
        if let Some((share, id)) = holder {
            state.remove_viewer(share, id, End::Say("revoked"), now);
        }
    }

    /// `CoreMsg::ShareEnded`: every viewer of `share` is ended ("share ended"), and the
    /// tickets of it made by `core_ms`, when it ended on the core's clock, are refused (by
    /// what the core says, as for a `Revoke`). The feed is the core's to stop.
    pub(crate) fn share_ended(&self, share: SessionId, core_ms: u64) {
        let mut state = self.lock();
        if state.link.is_none() {
            return;
        }
        let at = state.ended.entry(share).or_insert(core_ms);
        *at = (*at).max(core_ms);
        state.drop_share(share, End::Say("share ended"));
    }

    /// The core's `Welcome` on a new link: from here tickets of `id` are good, on the core's
    /// clock `core_ms` as of `now`.
    pub(crate) fn link_up(
        &self,
        id: u64,
        core_ms: u64,
        tx: mpsc::Sender<EdgeMsg>,
        conn: Option<Connection>,
        now: Instant,
    ) {
        let mut state = self.lock();
        // A link before it ended already; this is for a test that links twice
        state.forget_all(End::Say("core lost"));
        state.link = Some(Link {
            id,
            core_ms,
            at: now,
            tx,
            conn,
        });
    }

    /// The link `id` ended: every viewer is told "core lost", and everything is forgotten
    /// until the next `Welcome`. How many viewers were ended.
    pub(crate) fn link_lost(&self, id: u64) -> u32 {
        let mut state = self.lock();
        if state.link.as_ref().is_none_or(|link| link.id != id) {
            return 0;
        }
        state.link = None;
        state.forget_all(End::Say("core lost"))
    }

    /// Ends every viewer with `end` and closes the link: the edge is stopping.
    fn stop_all(&self, end: End) {
        let mut state = self.lock();
        if let Some(conn) = state.link.take().and_then(|link| link.conn) {
            conn.close(VarInt::from_u32(0), b"edge stopping");
        }
        state.forget_all(end);
    }

    /// A viewer of `share` needs a keyframe: asked of the core at most once a second for
    /// the share.
    fn keyframe_wanted(&self, share: SessionId, now: Instant) {
        let mut state = self.lock();
        let State { link, shares, .. } = &mut *state;
        let (Some(link), Some(carried)) = (link.as_ref(), shares.get_mut(&share)) else {
            return;
        };
        if carried.keyframe.ask(now) {
            link.tell(EdgeMsg::KeyframeWanted { share });
        }
    }

    /// What a viewer's pump asks when its queue dropped a frame: a keyframe, through the
    /// same merge as a viewer's join.
    fn keyframe_hook(self: &Arc<Self>) -> KeyframeHook {
        let edge = self.clone();
        KeyframeHook::Edge(Arc::new(move |share| {
            edge.stats.frames_dropped.fetch_add(1, Ordering::Relaxed);
            edge.keyframe_wanted(share, Instant::now());
        }))
    }

    /// Each `TICK`: keyframe asks whose second is up go out, a share with viewers that is
    /// not fed `RESUBSCRIBE_AFTER` after it was asked for is asked for again, a share without
    /// viewers for `UNSUBSCRIBE_AFTER` is let go, and slots and ended shares no ticket could
    /// still be shown for are forgotten.
    fn tick(&self, now: Instant) {
        let mut state = self.lock();
        let State {
            link,
            shares,
            slots,
            ended,
            ..
        } = &mut *state;
        let Some(link) = link.as_ref() else {
            return;
        };
        let core_now = link.core_now(now);
        shares.retain(|&share, carried| {
            if carried.keyframe.due(now) {
                link.tell(EdgeMsg::KeyframeWanted { share });
            }
            let waited = now.saturating_duration_since(carried.asked) >= RESUBSCRIBE_AFTER;
            if !carried.fed && !carried.viewers.is_empty() && waited {
                link.tell(EdgeMsg::Subscribe { share });
                carried.asked = now;
            }
            let idle = carried
                .empty_since
                .is_some_and(|at| now.saturating_duration_since(at) >= UNSUBSCRIBE_AFTER);
            if idle {
                link.tell(EdgeMsg::Unsubscribe { share });
                carried.fan.set(Arc::new([]));
            }
            !idle
        });
        // A viewer still watching keeps its slot, so a Revoke still finds it
        slots.retain(|_, slot| match slot {
            Slot::Used { until, viewer } => viewer.is_some() || *until > core_now,
            Slot::Revoked { until } => *until > core_now,
        });
        ended.retain(|_, at| at.saturating_add(TICKET_TTL_MS) > core_now);
    }

    /// The share's reader's inbox, while the edge carries it, for a frame stream of it from
    /// the core: so it is fed.
    fn inbox(&self, share: SessionId) -> Option<mpsc::Sender<link::FeedStream>> {
        let mut state = self.lock();
        let carried = state.shares.get_mut(&share)?;
        carried.fed = true;
        Some(carried.inbox.clone())
    }

    /// One datagram from the core: screen audio (0x15) of a share carried here goes to its
    /// viewers; anything else is dropped.
    fn datagram(&self, packet: Bytes) {
        if packet.len() < ENCRYPTED_SCREEN_AUDIO_HEADER_SIZE
            || packet[0] != VideoPacketType::EncryptedScreenShareAudio as u8
        {
            return;
        }
        let share = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        let Some(fan) = self.lock().shares.get_mut(&share).map(|carried| {
            carried.fed = true;
            carried.fan.clone()
        }) else {
            return;
        };
        let sent = fan.send(&packet, &self.stats);
        self.stats.egress_bytes.fetch_add(sent, Ordering::Relaxed);
    }

    /// What the edge tells its core every 2 s: `egress_kbps` as measured by the caller.
    fn load(&self, egress_kbps: u64) -> EdgeMsg {
        let (rss_mib, cpu_secs) = crate::load::own_usage();
        let state = self.lock();
        EdgeMsg::Load {
            viewers: state.viewers,
            per_share: state
                .shares
                .iter()
                .map(|(&share, carried)| (share, carried.viewers.len() as u32))
                .collect(),
            egress_kbps,
            frames_dropped: self.stats.frames_dropped.load(Ordering::Relaxed),
            tickets_refused: self
                .stats
                .tickets_refused
                .load(Ordering::Relaxed)
                .min(u32::MAX as u64) as u32,
            cpu_secs,
            rss_mib,
        }
    }

    /// Viewers and shares here now.
    fn carried(&self) -> (u32, usize) {
        let state = self.lock();
        (state.viewers, state.shares.len())
    }

    fn linked(&self) -> bool {
        self.lock().link.is_some()
    }
}

// ── Running ────────────────────────────────────────────────────────────

/// An edge at work: its viewers' endpoint, its link, and its timers.
pub(crate) struct Running {
    pub(crate) edge: Arc<Edge>,
    hashes: watch::Receiver<Vec<[u8; 32]>>,
    link: JoinHandle<()>,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    /// The SHA-256 of the viewers' certificate, then of the one before it: what the core
    /// sends viewers.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "tests pin the viewers' certificate")
    )]
    pub(crate) fn cert_hashes(&self) -> Vec<[u8; 32]> {
        self.hashes.borrow().clone()
    }

    /// Whether the core welcomed this edge on the link in force.
    #[cfg_attr(not(test), allow(dead_code, reason = "tests wait for the link"))]
    pub(crate) fn is_linked(&self) -> bool {
        self.edge.linked()
    }

    /// Stop: every viewer is told "edge stopping" and the link closes, so the core seats them
    /// again at once instead of after the link's idle timeout.
    pub(crate) async fn stop(self) {
        self.link.abort();
        self.edge.stop_all(End::Say("edge stopping"));
        tokio::time::sleep(STOP_GRACE).await;
        for task in self.tasks {
            task.abort();
        }
    }

    /// Stop as if the process died: nobody is told anything, every connection just closes.
    #[allow(dead_code, reason = "the pool's end-to-end tests kill an edge")]
    pub(crate) fn kill(self) {
        self.link.abort();
        self.edge.stop_all(End::Drop);
        for task in self.tasks {
            task.abort();
        }
    }
}

/// Starts an edge with `settings`: binds its viewers' endpoint and starts linking to its
/// core.
pub(crate) fn start(settings: Settings) -> Result<Running> {
    let web = WebTransport::bind_with(settings.bind, None, Role::EdgeViewers)?;
    let hashes = web.cert_hashes();
    let limits = Arc::new(ConnLimits::new(
        settings.max_viewers.saturating_add(SETUP_ROOM),
        settings.max_connections_per_ip,
    ));
    let edge = Arc::new(Edge::new(&settings, limits.clone()));
    let viewers = edge.clone();
    let routes = Routes::new(None).at(VIEW_PATH, move |connection, peer, slot| {
        view::run(connection, viewers.clone(), peer, slot)
    });
    let core = link::Core {
        host: settings.core_host,
        port: settings.core_port,
        pin: settings.core_pin,
    };
    let link = tokio::spawn(link::run(edge.clone(), core, hashes.clone()));
    let tasks = vec![
        tokio::spawn(web.serve(limits, Arc::new(routes))),
        tokio::spawn(housekeep(edge.clone())),
        tokio::spawn(minutes(edge.clone(), settings.bind.port())),
    ];
    Ok(Running {
        edge,
        hashes,
        link,
        tasks,
    })
}

/// Run as an edge, reading `config` (edge.toml), until SIGINT or SIGTERM.
pub async fn run(config: Option<String>) -> Result<()> {
    let path = config.ok_or_else(|| {
        anyhow!(
            "an edge reads its own file, named before the command: voipc-server -c edge.toml edge"
        )
    })?;
    let text = std::fs::read_to_string(&path).with_context(|| format!("failed to read {path}"))?;
    let config: EdgeConfig =
        crate::config::parse(&text).with_context(|| format!("{path} is not a valid edge.toml"))?;
    let settings = config.check().with_context(|| format!("in {path}"))?;
    let (name, bind) = (settings.name.clone(), settings.bind);
    let public = if settings.public_host.contains(':') {
        format!("[{}]:{}", settings.public_host, settings.public_port)
    } else {
        format!("{}:{}", settings.public_host, settings.public_port)
    };
    let core = format!("{}:{}", settings.core_host, settings.core_port);
    let running = start(settings)?;
    info!("edge {name} up: viewers on UDP {bind} (reached at {public}), linking to the core at {core}");
    shutdown().await;
    info!("stopping: every viewer here is told, and the core seats them again");
    running.stop().await;
    Ok(())
}

/// SIGINT (Ctrl+C) or SIGTERM (`systemctl stop`).
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            },
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

async fn housekeep(edge: Arc<Edge>) {
    let mut every = tokio::time::interval(TICK);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        edge.tick(Instant::now());
    }
}

/// A minute's viewers, video, drops and refusals in one line, only when anything happened:
/// one line per viewer would flood an edge's log. Addresses are never in it.
async fn minutes(edge: Arc<Edge>, udp_port: u16) {
    let mut every = tokio::time::interval(Duration::from_secs(60));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    every.tick().await;
    let stats = edge.stats.clone();
    let mut sent_before = stats.egress_bytes.load(Ordering::Relaxed);
    let mut dropped_before = stats.frames_dropped.load(Ordering::Relaxed);
    let mut full_before = stats.queue_full.load(Ordering::Relaxed);
    let mut udp_before = crate::web::udp_drops(udp_port).unwrap_or(0);
    loop {
        every.tick().await;
        let counts = edge.limits.take_counts();
        let sent = stats.egress_bytes.load(Ordering::Relaxed);
        let dropped = stats.frames_dropped.load(Ordering::Relaxed);
        let full = stats.queue_full.load(Ordering::Relaxed);
        let udp = crate::web::udp_drops(udp_port).unwrap_or(udp_before);
        let (viewers, shares) = edge.carried();
        let line = minute_line(
            viewers,
            shares,
            sent.saturating_sub(sent_before),
            dropped.saturating_sub(dropped_before),
            full.saturating_sub(full_before),
            &counts,
            udp.saturating_sub(udp_before),
        );
        (sent_before, dropped_before, full_before, udp_before) = (sent, dropped, full, udp);
        if let Some(line) = line {
            info!("{line}");
        }
    }
}

/// The minute's line, or `None` when nothing happened in it. `sent`: bytes queued for
/// viewers in the minute.
fn minute_line(
    viewers: u32,
    shares: usize,
    sent: u64,
    frames_dropped: u64,
    queue_full: u64,
    counts: &std::collections::BTreeMap<(&'static str, &'static str), u64>,
    udp_dropped: u64,
) -> Option<String> {
    if viewers == 0 && sent == 0 && frames_dropped == 0 && counts.is_empty() && udp_dropped == 0 {
        return None;
    }
    let mbit = sent as f64 * 8.0 / 60.0 / 1e6;
    let mut line = format!(
        "last minute: {viewers} viewers of {shares} shares, {mbit:.1} Mbit/s, {frames_dropped} frames dropped"
    );
    if queue_full > 0 {
        line.push_str(&format!(", {queue_full} packets past full queues"));
    }
    let mut kind_before = "";
    for ((kind, why), n) in counts {
        if *kind == kind_before {
            line.push_str(&format!(", {why} {n}"));
        } else {
            line.push_str(&format!("; {kind}: {why} {n}"));
        }
        kind_before = kind;
    }
    if udp_dropped > 0 {
        line.push_str(&format!(
            "; UDP datagrams dropped {udp_dropped} (buffer full, see OPERATING.md 10a)"
        ));
    }
    Some(line)
}
