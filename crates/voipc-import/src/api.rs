//! Asking Discord: a `Transport` the app gives, and a `RateGate` that keeps this under
//! what Discord allows. Every call but the move post is a GET. Nothing here sees the
//! token: `Req.auth` asks the transport to add it.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::sync::watch;
use tokio::time::{sleep, Duration, Instant};

use crate::model;

pub const BASE: &str = "https://discord.com/api/v10";

/// Our own ceiling, under the documented 50 a second. No per-route number is written
/// anywhere: Discord's docs say not to, and each answer says what it needs to.
const PER_SECOND: f64 = 40.0;
/// What may go at once after a quiet spell. A full second's worth would make 80 in a second,
/// past that ceiling.
const BURST: f64 = 5.0;
/// Discord bans at 10,000 invalid requests in 10 minutes. A tenth of that holds everything
/// until it falls back to half of it.
const INVALID_WINDOW_MS: u64 = 10 * 60 * 1000;
const INVALID_HOLD_AT: usize = 1000;
const INVALID_HOLD_UNTIL: usize = 500;
/// A 429 that says nothing of how long, as Cloudflare's own page does.
const UNSAID_WAIT_MS: u64 = 60_000;
/// No promise of Discord's is worth a wait past this: a bad number should not hang a run.
const LONGEST_WAIT_MS: u64 = 24 * 60 * 60 * 1000;
/// A longer wait is shown, or the run looks stuck.
const SHOW_WAIT_OVER_MS: u64 = 60_000;
const JITTER_MS: u64 = 1000;
/// Between tries on a 5xx or a network error.
const RETRIES_MS: [u64; 3] = [1000, 4000, 16_000];
const NO_GOOD_ANSWER_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

pub struct Req {
    pub method: Method,
    pub url: String,
    /// Send the bot's token with it.
    pub auth: bool,
    pub body: Option<Vec<u8>>,
}

/// No body: a move post is someone's words.
impl fmt::Debug for Req {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Req")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// No body: it is members' messages.
impl fmt::Debug for Resp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resp")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn secs_ms(&self, name: &str) -> Option<u64> {
        self.header(name).and_then(|v| secs_ms(v.parse().ok()?))
    }
}

fn secs_ms(secs: f64) -> Option<u64> {
    (secs.is_finite() && secs >= 0.0).then(|| ((secs * 1000.0).ceil() as u64).min(LONGEST_WAIT_MS))
}

/// How a request reaches Discord. The app's fixes the hosts, sets the token as a sensitive
/// header and follows no redirect. An error says nothing of the address.
pub trait Transport: Send + Sync {
    fn request(&self, req: Req) -> impl Future<Output = Result<Resp, String>> + Send;
}

impl<T: Transport> Transport for Arc<T> {
    fn request(&self, req: Req) -> impl Future<Output = Result<Resp, String>> + Send {
        (**self).request(req)
    }
}

/// A route, as the rate limits see it: what is asked, and of which guild or channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    shape: String,
    major: String,
}

impl Route {
    /// `path` from the API's root, with or without a query.
    pub fn of(method: Method, path: &str) -> Self {
        let path = path.split('?').next().unwrap_or(path);
        let mut parts = path.trim_start_matches('/').split('/');
        let first = parts.next().unwrap_or_default();
        let mut shape = format!("{method:?} /{first}");
        let mut major = String::new();
        if matches!(first, "guilds" | "channels") {
            major = parts.next().unwrap_or_default().to_string();
            shape.push_str("/{major}");
        }
        for part in parts {
            shape.push('/');
            let id = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            shape.push_str(if id { "{id}" } else { part });
        }
        Route { shape, major }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Our own pace: nothing to show.
    Pace,
    /// Discord said so.
    Asked,
    /// Too many invalid requests of late.
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    pub ms: u64,
    pub why: Why,
}

/// What an answer comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Good,
    /// Ask again, past the wait `before` will now give.
    Again,
    /// 5xx or the network: worth a few tries.
    Broken,
    /// This one thing is out of reach: no retry, and whoever walks it keeps its cursor.
    Skip(String),
    /// Nothing more can be done in this run.
    Stop(String),
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TooMany {
    retry_after: Option<f64>,
    global: bool,
}

/// All the pacing, on a clock it is told. One per token. `now` is milliseconds from
/// anywhere, so a test moves it by hand.
pub struct RateGate {
    tokens: f64,
    refilled_at: u64,
    global_until: u64,
    /// Discord's name for a route's bucket.
    buckets: HashMap<String, String>,
    /// When a bucket (with its guild or channel) has room again.
    empty_until: HashMap<String, u64>,
    invalid: VecDeque<u64>,
    holding: bool,
    first_bad: Option<u64>,
    seed: u64,
}

impl RateGate {
    /// `seed`: where the jitter starts.
    pub fn new(seed: u64) -> Self {
        RateGate {
            tokens: BURST,
            refilled_at: 0,
            global_until: 0,
            buckets: HashMap::new(),
            empty_until: HashMap::new(),
            invalid: VecDeque::new(),
            holding: false,
            first_bad: None,
            seed: seed | 1,
        }
    }

    fn jitter(&mut self) -> u64 {
        // xorshift: this only has to keep walkers from asking in step
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed % JITTER_MS
    }

    fn bucket_key(&self, route: &Route) -> String {
        let name = self.buckets.get(&route.shape).unwrap_or(&route.shape);
        format!("{name}|{}", route.major)
    }

    fn forget_old_invalid(&mut self, now: u64) {
        while self
            .invalid
            .front()
            .is_some_and(|at| at + INVALID_WINDOW_MS <= now)
        {
            self.invalid.pop_front();
        }
    }

    /// How long until this route may be asked. None: go, and a token is spent.
    pub fn before(&mut self, route: &Route, now: u64) -> Option<Wait> {
        if now < self.global_until {
            return Some(Wait {
                ms: self.global_until - now,
                why: Why::Asked,
            });
        }
        self.forget_old_invalid(now);
        if self.holding {
            if self.invalid.len() < INVALID_HOLD_UNTIL {
                self.holding = false;
            } else {
                // What has to age out for the count to fall under the mark
                let last_to_go = self.invalid[self.invalid.len() - INVALID_HOLD_UNTIL];
                return Some(Wait {
                    ms: (last_to_go + INVALID_WINDOW_MS).saturating_sub(now).max(1),
                    why: Why::Invalid,
                });
            }
        }
        if let Some(until) = self.empty_until.get(&self.bucket_key(route)) {
            if now < *until {
                return Some(Wait {
                    ms: until - now,
                    why: Why::Asked,
                });
            }
        }
        let since = now.saturating_sub(self.refilled_at) as f64 / 1000.0;
        self.tokens = (self.tokens + since * PER_SECOND).min(BURST);
        self.refilled_at = now;
        if self.tokens < 1.0 {
            return Some(Wait {
                ms: (((1.0 - self.tokens) / PER_SECOND * 1000.0).ceil() as u64).max(1),
                why: Why::Pace,
            });
        }
        self.tokens -= 1.0;
        None
    }

    fn count_invalid(&mut self, now: u64) {
        self.forget_old_invalid(now);
        self.invalid.push_back(now);
        if self.invalid.len() >= INVALID_HOLD_AT {
            self.holding = true;
        }
    }

    fn hold_bucket(&mut self, route: &Route, until: u64) {
        let key = self.bucket_key(route);
        let at = self.empty_until.entry(key).or_insert(0);
        *at = (*at).max(until);
    }

    /// Past ten minutes without one good answer there is no point going on. A long wait
    /// Discord asked for is not that.
    fn bad_answer(&mut self, now: u64) -> Option<Verdict> {
        let first = *self.first_bad.get_or_insert(now);
        (now.saturating_sub(first) >= NO_GOOD_ANSWER_MS).then(|| {
            Verdict::Stop(
                "Discord has not given one good answer in ten minutes. Nothing is lost: run it \
                 again later to carry on."
                    .into(),
            )
        })
    }

    /// What an answer means, and what it says about when to ask next.
    pub fn after(&mut self, route: &Route, resp: &Resp, now: u64) -> Verdict {
        if let Some(bucket) = resp.header("x-ratelimit-bucket") {
            self.buckets.insert(route.shape.clone(), bucket.to_string());
        }
        if resp.header("x-ratelimit-remaining") == Some("0") {
            if let Some(ms) = resp.secs_ms("x-ratelimit-reset-after") {
                self.hold_bucket(route, now + ms);
            }
        }
        // Whatever is past its time goes, or this grows with every channel of a large server
        if self.empty_until.len() > 4096 {
            self.empty_until.retain(|_, until| *until > now);
        }
        match resp.status {
            200..=299 => {
                self.first_bad = None;
                Verdict::Good
            }
            429 => self.too_many(route, resp, now),
            401 => {
                self.count_invalid(now);
                Verdict::Stop(
                    "The token no longer works. Nothing is lost: run it again with a new one."
                        .into(),
                )
            }
            500..=599 => self.bad_answer(now).unwrap_or(Verdict::Broken),
            status => {
                if status == 403 {
                    self.count_invalid(now);
                }
                self.bad_answer(now)
                    .unwrap_or_else(|| Verdict::Skip(format!("Discord answered {status}.")))
            }
        }
    }

    fn too_many(&mut self, route: &Route, resp: &Resp, now: u64) -> Verdict {
        let body = serde_json::from_slice::<TooMany>(&resp.body).ok();
        let header_ms = resp.secs_ms("retry-after");
        let body_ms = body.as_ref().and_then(|b| b.retry_after).and_then(secs_ms);
        let ms = match (header_ms, body_ms) {
            (None, None) => UNSAID_WAIT_MS,
            (a, b) => a.unwrap_or(0).max(b.unwrap_or(0)),
        };
        let until = now + ms + self.jitter();
        let scope = resp.header("x-ratelimit-scope");
        // "429 errors returned with X-RateLimit-Scope: shared are not counted against you."
        if scope != Some("shared") {
            self.count_invalid(now);
        }
        let global = resp.header("x-ratelimit-global").is_some()
            || scope == Some("global")
            || body.is_some_and(|b| b.global);
        if global {
            self.global_until = self.global_until.max(until);
        } else {
            self.hold_bucket(route, until);
        }
        // Time Discord asked for is not time it failed to answer
        if let Some(first) = &mut self.first_bad {
            *first += until - now;
        }
        Verdict::Again
    }

    /// The request never got an answer.
    pub fn no_answer(&mut self, now: u64) -> Verdict {
        self.bad_answer(now).unwrap_or(Verdict::Broken)
    }
}

/// What stops a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    /// The run cannot go on. Everything stored stays: a later run carries on.
    Stop(String),
    /// This one thing is out of reach. Note it, and keep its cursor where it is.
    Skip { status: Option<u16>, note: String },
}

impl Fail {
    pub fn words(&self) -> &str {
        match self {
            Fail::Stop(words) => words,
            Fail::Skip { note, .. } => note,
        }
    }
}

fn wait_words(ms: u64, why: Why) -> String {
    let minutes = ms.div_ceil(60_000);
    let time = if minutes == 1 {
        "a minute".to_string()
    } else {
        format!("{minutes} minutes")
    };
    match why {
        Why::Invalid => format!(
            "Discord refused too many requests of late, so this waits {time} before asking again."
        ),
        _ => format!("Discord asked to wait {time}."),
    }
}

/// A token's way to Discord: one `RateGate`, however many walkers share it.
pub struct Api<T> {
    transport: T,
    gate: Mutex<RateGate>,
    started: Instant,
    waiting: watch::Sender<Option<String>>,
}

impl<T: Transport> Api<T> {
    pub fn new(transport: T) -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
        Self::with_gate(transport, RateGate::new(seed))
    }

    pub fn with_gate(transport: T, gate: RateGate) -> Self {
        Api {
            transport,
            gate: Mutex::new(gate),
            started: Instant::now(),
            waiting: watch::Sender::new(None),
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// A wait worth showing, while it lasts.
    pub fn waiting(&self) -> watch::Receiver<Option<String>> {
        self.waiting.subscribe()
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn gate(&self) -> std::sync::MutexGuard<'_, RateGate> {
        // Held across no await, and nothing in it panics
        self.gate.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn pass_gate(&self, route: &Route) {
        loop {
            let now = self.now();
            let wait = self.gate().before(route, now);
            let Some(wait) = wait else {
                return;
            };
            let show = wait.why == Why::Invalid || wait.ms > SHOW_WAIT_OVER_MS;
            if show {
                self.waiting
                    .send_replace(Some(wait_words(wait.ms, wait.why)));
            }
            sleep(Duration::from_millis(wait.ms)).await;
            if show {
                self.waiting.send_replace(None);
            }
        }
    }

    async fn send(&self, method: Method, path: &str, body: Option<Vec<u8>>) -> Result<Resp, Fail> {
        let route = Route::of(method, path);
        let mut tries = RETRIES_MS.iter();
        loop {
            self.pass_gate(&route).await;
            let out = self
                .transport
                .request(Req {
                    method,
                    url: format!("{BASE}{path}"),
                    auth: true,
                    body: body.clone(),
                })
                .await;
            let now = self.now();
            let status = out.as_ref().ok().map(|r| r.status);
            let verdict = match &out {
                Ok(resp) => self.gate().after(&route, resp, now),
                Err(_) => self.gate().no_answer(now),
            };
            match verdict {
                Verdict::Good => {
                    return out.map_err(|_| Fail::Skip {
                        status,
                        note: "No answer.".into(),
                    })
                }
                Verdict::Again => {}
                Verdict::Broken => match tries.next() {
                    Some(ms) => sleep(Duration::from_millis(*ms)).await,
                    None => {
                        return Err(Fail::Skip {
                            status,
                            note: "Discord kept failing, so this was skipped. The next run takes \
                                   it."
                            .into(),
                        })
                    }
                },
                Verdict::Skip(note) => return Err(Fail::Skip { status, note }),
                Verdict::Stop(words) => return Err(Fail::Stop(words)),
            }
        }
    }

    /// A good answer, as it came. `path` from the API's root.
    pub async fn get_raw(&self, path: &str) -> Result<Resp, Fail> {
        self.send(Method::Get, path, None).await
    }

    pub async fn get<D: DeserializeOwned>(&self, path: &str) -> Result<D, Fail> {
        let resp = self.get_raw(path).await?;
        model::parse(&resp.body).map_err(|why| Fail::Skip {
            status: Some(resp.status),
            note: format!("Discord's answer was {why}."),
        })
    }

    /// The one write there is. `nonce`, with `enforce_nonce`, is worked out of what it says,
    /// so a second press or a retry after a timeout does not post it twice.
    pub async fn move_post(&self, channel: u64, text: &str, everyone: bool) -> Result<(), Fail> {
        let parse: &[&str] = if everyone { &["everyone"] } else { &[] };
        let body = serde_json::json!({
            "content": text,
            "allowed_mentions": { "parse": parse },
            "nonce": nonce_of(channel, text, everyone),
            "enforce_nonce": true,
        });
        let path = format!("/channels/{channel}/messages");
        self.send(Method::Post, &path, Some(body.to_string().into_bytes()))
            .await
            .map(|_| ())
    }
}

/// FNV-1a. At most 20 digits, under the 25 characters Discord takes.
fn nonce_of(channel: u64, text: &str, everyone: bool) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let head = [channel.to_be_bytes().as_slice(), &[everyone as u8]].concat();
    for byte in head.iter().chain(text.as_bytes()) {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{Mock, Scripted};
    use std::sync::Arc;

    fn route() -> Route {
        Route::of(Method::Get, "/channels/1/messages?limit=100&after=5")
    }

    fn other_route() -> Route {
        Route::of(Method::Get, "/guilds/9/members?limit=1000")
    }

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Resp {
        Resp {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    /// How long `route` has to wait from `now`, past our own pace.
    fn asked_wait(gate: &mut RateGate, route: &Route, now: u64) -> u64 {
        match gate.before(route, now) {
            Some(Wait {
                ms,
                why: Why::Asked,
            }) => ms,
            None => 0,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn routes_keep_their_guild_or_channel_and_lose_the_rest() {
        assert_eq!(
            route().shape,
            Route::of(Method::Get, "/channels/2/messages").shape
        );
        assert_ne!(route(), Route::of(Method::Get, "/channels/2/messages"));
        assert_eq!(route().major, "1");
        assert_eq!(
            Route::of(Method::Get, "/guilds/9/members/123").shape,
            "Get /guilds/{major}/members/{id}"
        );
        assert_eq!(
            Route::of(Method::Get, "/users/@me/guilds").shape,
            "Get /users/@me/guilds"
        );
        assert_ne!(
            route().shape,
            Route::of(Method::Post, "/channels/1/messages").shape
        );
    }

    #[test]
    fn a_429_waits_the_larger_of_header_and_body() {
        for (header, body, want) in [
            ("2", r#"{"retry_after": 5.5}"#, 5500),
            ("9", r#"{"retry_after": 5.5}"#, 9000),
        ] {
            let mut gate = RateGate::new(7);
            let answer = resp(429, &[("Retry-After", header)], body);
            assert_eq!(gate.after(&route(), &answer, 1000), Verdict::Again);
            let wait = asked_wait(&mut gate, &route(), 1000);
            assert!(
                (want..want + JITTER_MS).contains(&wait),
                "{header} and {body} waited {wait}"
            );
            // It is this route's wait, and no other's
            assert_eq!(gate.before(&other_route(), 1000), None);
            // ... and it ends
            assert_eq!(gate.before(&route(), 1000 + wait), None);
        }
    }

    #[test]
    fn global_pauses_all_routes() {
        for answer in [
            resp(
                429,
                &[("Retry-After", "3"), ("X-RateLimit-Global", "true")],
                "{}",
            ),
            resp(429, &[], r#"{"retry_after": 3, "global": true}"#),
            resp(
                429,
                &[("Retry-After", "3"), ("X-RateLimit-Scope", "global")],
                "{}",
            ),
        ] {
            let mut gate = RateGate::new(7);
            assert_eq!(gate.after(&route(), &answer, 0), Verdict::Again);
            assert!(asked_wait(&mut gate, &other_route(), 0) >= 3000);
            assert!(asked_wait(&mut gate, &route(), 2000) >= 1000);
            assert_eq!(gate.before(&other_route(), 4000), None);
        }
    }

    #[test]
    fn shared_does_not_count_as_invalid() {
        let shared = resp(
            429,
            &[("Retry-After", "1"), ("X-RateLimit-Scope", "shared")],
            "{}",
        );
        let mut gate = RateGate::new(7);
        for _ in 0..3 {
            gate.after(&route(), &shared, 0);
        }
        assert_eq!(gate.invalid.len(), 0);
        // It still waits as asked
        assert!(asked_wait(&mut gate, &route(), 0) >= 1000);
        // The control: one of the user's own does count
        let own = resp(
            429,
            &[("Retry-After", "1"), ("X-RateLimit-Scope", "user")],
            "{}",
        );
        gate.after(&route(), &own, 0);
        assert_eq!(gate.invalid.len(), 1);
    }

    #[test]
    fn remaining_0_waits_for_reset_after() {
        let mut gate = RateGate::new(7);
        let first = resp(
            200,
            &[
                ("X-RateLimit-Bucket", "abc"),
                ("X-RateLimit-Remaining", "1"),
                ("X-RateLimit-Reset-After", "4"),
            ],
            "[]",
        );
        assert_eq!(gate.after(&route(), &first, 0), Verdict::Good);
        // Room left: no wait
        assert_eq!(gate.before(&route(), 0), None);
        let last = resp(
            200,
            &[
                ("X-RateLimit-Bucket", "abc"),
                ("X-RateLimit-Remaining", "0"),
                ("X-RateLimit-Reset-After", "2.5"),
            ],
            "[]",
        );
        assert_eq!(gate.after(&route(), &last, 0), Verdict::Good);
        assert_eq!(asked_wait(&mut gate, &route(), 0), 2500);
        // Another channel has its own bucket of the same name, per the docs' top-level id
        assert_eq!(
            gate.before(&Route::of(Method::Get, "/channels/2/messages"), 0),
            None
        );
        assert_eq!(gate.before(&route(), 2500), None);
    }

    #[test]
    fn a_cloudflare_429_without_json_waits_60s() {
        let mut gate = RateGate::new(7);
        let page = resp(429, &[], "<html>You are being rate limited</html>");
        assert_eq!(gate.after(&route(), &page, 0), Verdict::Again);
        let wait = asked_wait(&mut gate, &route(), 0);
        assert!((60_000..60_000 + JITTER_MS).contains(&wait), "{wait}");
        // Its own header, if it has one, wins
        let mut gate = RateGate::new(7);
        let page = resp(429, &[("Retry-After", "2")], "<html>");
        gate.after(&route(), &page, 0);
        assert!(asked_wait(&mut gate, &route(), 0) < 3000);
        // A body with no number says nothing either
        let mut gate = RateGate::new(7);
        gate.after(&route(), &resp(429, &[], "{}"), 0);
        assert!(asked_wait(&mut gate, &route(), 0) >= 60_000);
    }

    #[test]
    fn a_bad_number_cannot_hang_a_run() {
        let mut gate = RateGate::new(7);
        let answer = resp(429, &[], r#"{"retry_after": 1e30}"#);
        gate.after(&route(), &answer, 0);
        assert!(asked_wait(&mut gate, &route(), 0) <= LONGEST_WAIT_MS + JITTER_MS);
        // Below zero and nonsense are nothing said
        let mut gate = RateGate::new(7);
        let answer = resp(429, &[("Retry-After", "soon")], r#"{"retry_after": -4}"#);
        gate.after(&route(), &answer, 0);
        assert!(asked_wait(&mut gate, &route(), 0) >= UNSAID_WAIT_MS);
    }

    #[test]
    fn a_401_stops_at_once() {
        let mut gate = RateGate::new(7);
        let Verdict::Stop(words) = gate.after(&route(), &resp(401, &[], "{}"), 0) else {
            panic!("a 401 must stop the run");
        };
        assert!(words.contains("token"));
        assert_eq!(gate.invalid.len(), 1);
    }

    #[test]
    fn a_403_skips_without_retry_and_keeps_the_cursor() {
        let mut gate = RateGate::new(7);
        assert!(matches!(
            gate.after(&route(), &resp(403, &[], "{}"), 0),
            Verdict::Skip(_)
        ));
        assert_eq!(gate.invalid.len(), 1);
        // A 404 is not an invalid request, and skips all the same
        assert!(matches!(
            gate.after(&route(), &resp(404, &[], "{}"), 0),
            Verdict::Skip(_)
        ));
        assert_eq!(gate.invalid.len(), 1);
    }

    #[test]
    fn a_thousand_invalid_in_10_minutes_pauses() {
        let mut gate = RateGate::new(7);
        for i in 0..999 {
            gate.after(&route(), &resp(403, &[], "{}"), i);
            gate.first_bad = None;
        }
        // One short: nothing but our own pace
        assert!(!gate.holding);
        gate.tokens = BURST;
        assert_eq!(gate.before(&route(), 999), None);
        gate.after(&route(), &resp(403, &[], "{}"), 999);
        let Some(Wait {
            ms,
            why: Why::Invalid,
        }) = gate.before(&other_route(), 1000)
        else {
            panic!("the thousandth must hold everything");
        };
        // Until only 499 are left in the window: the 501st of them, at 500 ms, has to go
        assert_eq!(ms, INVALID_WINDOW_MS + 500 - 1000);
        assert!(gate.before(&route(), 1000 + ms - 1).is_some());
        gate.tokens = BURST;
        assert_eq!(gate.before(&route(), 1000 + ms), None);
        // The window rolls: the same thousand spread over more than 10 minutes never hold
        let mut gate = RateGate::new(7);
        for i in 0..2000 {
            gate.after(&route(), &resp(403, &[], "{}"), i * 1000);
            gate.first_bad = None;
        }
        assert!(!gate.holding);
    }

    #[test]
    fn ten_minutes_without_a_good_answer_stops() {
        let mut gate = RateGate::new(7);
        assert_eq!(
            gate.after(&route(), &resp(500, &[], ""), 0),
            Verdict::Broken
        );
        assert_eq!(gate.no_answer(NO_GOOD_ANSWER_MS - 1), Verdict::Broken);
        assert!(matches!(
            gate.no_answer(NO_GOOD_ANSWER_MS),
            Verdict::Stop(_)
        ));
        // One good answer starts it over
        let mut gate = RateGate::new(7);
        gate.after(&route(), &resp(500, &[], ""), 0);
        gate.after(&route(), &resp(200, &[], ""), NO_GOOD_ANSWER_MS - 1);
        assert_eq!(gate.no_answer(NO_GOOD_ANSWER_MS), Verdict::Broken);
        // Hours of nothing asked, the relay being slow, say nothing about Discord
        let mut gate = RateGate::new(7);
        gate.after(&route(), &resp(200, &[], ""), 0);
        assert_eq!(gate.no_answer(5 * NO_GOOD_ANSWER_MS), Verdict::Broken);
        // A long wait it asked for is not a failure to answer
        let mut gate = RateGate::new(7);
        gate.after(&route(), &resp(500, &[], ""), 0);
        gate.after(&route(), &resp(429, &[("Retry-After", "1320")], "{}"), 1000);
        assert_eq!(gate.no_answer(1_321_000 + 1000), Verdict::Broken);
    }

    #[test]
    fn our_own_ceiling_holds_with_no_word_from_discord() {
        let mut gate = RateGate::new(7);
        for _ in 0..BURST as u32 {
            assert_eq!(gate.before(&route(), 0), None);
        }
        assert_eq!(
            gate.before(&route(), 0),
            Some(Wait {
                ms: 25,
                why: Why::Pace
            })
        );
        assert_eq!(gate.before(&route(), 25), None);
        // Never past Discord's 50 in any second, even straight after a quiet spell
        let mut asked = 0;
        for ms in 1000..2000 {
            if gate.before(&route(), ms).is_none() {
                asked += 1;
            }
        }
        assert!((40..50).contains(&asked), "{asked} in a second");
        // The control: it is a pace and not a wall
        assert_eq!(gate.before(&route(), 3000), None);
    }

    fn api(mock: &Arc<Mock>) -> Api<Arc<Mock>> {
        Api::with_gate(mock.clone(), RateGate::new(7))
    }

    #[tokio::test(start_paused = true)]
    async fn the_api_waits_what_it_was_told_and_asks_again() {
        let mock = Arc::new(Mock::big(3, 0, 1, 1));
        mock.script(Scripted::new(
            "/guilds/1/members",
            1,
            429,
            &[("retry-after", "120")],
            "{}",
        ));
        let api = Arc::new(api(&mock));
        let mut waiting = api.waiting();
        let asked = Instant::now();
        let call = tokio::spawn({
            let api = api.clone();
            async move {
                api.get_raw("/guilds/1/members?limit=1")
                    .await
                    .map(|r| r.status)
            }
        });
        // A wait over a minute shows, in Discord's terms, and goes when it ends
        waiting.changed().await.unwrap();
        let shown = waiting.borrow_and_update().clone().unwrap();
        assert!(
            shown.contains("wait 2 minutes") || shown.contains("wait 3 minutes"),
            "{shown}"
        );
        assert_eq!(call.await.unwrap(), Ok(200));
        assert!(asked.elapsed() >= Duration::from_secs(120));
        assert_eq!(*waiting.borrow_and_update(), None);
        assert_eq!(mock.requests(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_403_asks_once_and_a_5xx_three_more_times_then_skips() {
        let mock = Arc::new(Mock::big(3, 0, 1, 1));
        mock.script(Scripted::new("/channels/404", 1, 403, &[], "{}").always());
        let api = api(&mock);
        let out = api.get_raw("/channels/404/messages").await;
        assert!(matches!(
            out,
            Err(Fail::Skip {
                status: Some(403),
                ..
            })
        ));
        assert_eq!(mock.requests(), 1);

        let mock = Arc::new(Mock::big(3, 0, 1, 1));
        mock.script(Scripted::new("/channels/500", 1, 503, &[], "").always());
        let api = self::api(&mock);
        let asked = Instant::now();
        let out = api.get_raw("/channels/500/messages").await;
        assert!(matches!(
            out,
            Err(Fail::Skip {
                status: Some(503),
                ..
            })
        ));
        assert_eq!(mock.requests(), 4);
        assert!(asked.elapsed() >= Duration::from_secs(21));

        // A 5xx that clears is no failure at all
        let mock = Arc::new(Mock::big(3, 0, 1, 1));
        mock.script(Scripted::new("/guilds/1/members", 1, 500, &[], ""));
        let api = self::api(&mock);
        let out = api.get_raw("/guilds/1/members?limit=1").await.unwrap();
        assert_eq!(out.status, 200);
        assert_eq!(mock.requests(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_401_stops_the_call_with_no_retry() {
        let mock = Arc::new(Mock::big(3, 0, 1, 1));
        mock.script(Scripted::new("/guilds/1/members", 1, 401, &[], "{}").always());
        let api = api(&mock);
        let out = api.get_raw("/guilds/1/members").await;
        assert!(matches!(out, Err(Fail::Stop(_))));
        assert_eq!(mock.requests(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_press_posts_once() {
        let mock = Arc::new(Mock::big(0, 0, 1, 1));
        let api = api(&mock);
        api.move_post(5, "We are moving.", false).await.unwrap();
        api.move_post(5, "We are moving.", false).await.unwrap();
        assert_eq!(mock.non_gets(), 2);
        assert_eq!(mock.posted().len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&mock.posted()[0]).unwrap();
        // No pings unless asked for
        assert_eq!(body["allowed_mentions"]["parse"], serde_json::json!([]));
        assert_eq!(body["enforce_nonce"], true);
        assert!(body["nonce"].as_str().unwrap().len() <= 25);
        // Other words are another post, and a ping only when ticked
        api.move_post(5, "We have moved.", true).await.unwrap();
        assert_eq!(mock.posted().len(), 2);
        let body: serde_json::Value = serde_json::from_slice(&mock.posted()[1]).unwrap();
        assert_eq!(
            body["allowed_mentions"]["parse"],
            serde_json::json!(["everyone"])
        );
    }

    #[test]
    fn debug_prints_no_body() {
        let answer = resp(200, &[], "secret words of a member");
        assert!(!format!("{answer:?}").contains("secret"));
        let asked = Req {
            method: Method::Post,
            url: "https://discord.com/x".into(),
            auth: true,
            body: Some(b"secret words".to_vec()),
        };
        assert!(!format!("{asked:?}").contains("secret"));
    }
}
