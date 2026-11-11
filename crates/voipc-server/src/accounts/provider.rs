//! Sign-in with a provider (Discord, Google, Facebook), on a relay with a web
//! address (`[accounts] public_url`) and an application at each provider.
//!
//! The relay is the OAuth client; an app only opens a browser. `AccountStart::
//! Provider` makes a flow and answers with the page and a ticket, and the
//! connection ends: an app the system suspends while the browser is open loses
//! nothing. The provider sends the browser back here, the person taps the code
//! their app shows, and only then is the provider asked who it is. The app comes
//! back with the ticket (`AccountStart::ProviderResume`).
//!
//! **A provider vouches for the person, never for the vault.** The relay sees all
//! a provider says, so nothing of it may open anything, and that is what the rest
//! of this file holds to:
//! - The vault goes out without `slot.pass`, which would allow guessing the
//!   password offline. What opens it is the recovery key, another device, or a
//!   sign-in with the password instead.
//! - Nobody gets in without the identity's signature over a challenge, or claiming
//!   an account nobody has opened. A hijacked provider account alone joins no
//!   channel and takes no live session over.
//! - This path never replaces an identity, whatever the session's freshness says:
//!   a code passing makes it fresh, and the code proves nothing about the vault.
//!
//! The code on the page is against somebody sending a person their own link. Only
//! the browser the provider sent back holds the page's key, so they cannot tap for
//! that person. It is not perfect (they can say which code to tap, or ask for that
//! page's address), which is why a person who got this far has still opened nothing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use voipc_crypto::bind::BIND_LEN;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use http_body_util::Full;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use l4f_accounts::model::{AccountId, SessionInfo, User};
use l4f_accounts::oauth::{Kind, Provider};
use l4f_accounts::service::{Host, Intent, LoginStep, NewSession, OAuth, SocialOutcome};
use l4f_accounts::store::Store;
use l4f_accounts::{pow, util};
use rand::seq::SliceRandom;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{info, warn};
use voipc_protocol::messages::{
    AccountReply, AuthContinue, AuthStep, ServerMessage, PAIR_NOBODY_ONLINE, PAIR_NO_ANSWER,
    PAIR_SAID_NO, PAIR_TOO_LATE, PAIR_TOO_MANY,
};
use voipc_protocol::types::{LinkedProvider, PowChallenge, ProviderKind, VaultBlob};

use super::links;
use super::{
    next, refused, second_factor, step, unexpected, vault_item_ok, Relay, SignedIn, BUSY, PINS_NS,
    RESET_KEY_LEN, SLOT_RESET, STEP_WAIT, VAULT_MAX_ITEMS, VAULT_NS, VAULT_TOTAL_BYTES,
};
use crate::state::{RateLimiter, ServerState};

/// Where a provider sends the browser back (l4f's own path) and where the
/// page's form goes.
pub const CALLBACK_PREFIX: &str = "/account/oauth/";
pub const CONFIRM_PATH: &str = "/account/oauth/confirm";

/// l4f's sealed flow expires after as long (`FLOW_SECS` in its `social.rs`).
const FLOW_LIFE: Duration = Duration::from_secs(600);
/// Open flows, all addresses. Each holds a few hundred bytes. A full table makes
/// room (`Flows::sweep`) and refuses nobody.
const MAX_FLOWS: usize = 4096;
/// Flows started per IPv6 /48, which holds 65 536 of the /64s `starts` counts:
/// enough for a carrier's pool on a move day, a small share of `MAX_FLOWS`. Four
/// /64s at full pace use it up, which costs only others on that /48.
const SITE_BURST: f64 = 64.0;
const SITE_REFILL: f64 = 1.0 / 10.0;
/// The same per IPv6 /32, which holds 65 536 /48s and can be leased by one stranger.
const BLOCK_BURST: f64 = 256.0;
const BLOCK_REFILL: f64 = 1.0;
/// Past this many limiters in a map, those whose budget is whole again go, at most
/// once in `PRUNE_SECS`.
const MAX_LIMITERS: usize = 4096;
const PRUNE_SECS: u64 = 30;
/// A person choosing what opens the account, and typing a 52-letter key.
pub(crate) const CHOICE_WAIT: Duration = Duration::from_secs(300);
/// A person walking to their other device.
const PAIR_WAIT: Duration = Duration::from_secs(120);
/// What the app takes for "not yet" (`AuthStep::ProviderPending` says it first).
pub const NOT_YET: &str = "Not finished in the browser yet.";
const NO_ACCOUNT: &str =
    "No account here uses that sign-in. Make one with an invite, or sign in another way and link it in your account panel.";
const ENDED: &str = "That sign-in has ended. Start again in the app.";

fn kind_of(k: ProviderKind) -> Kind {
    match k {
        ProviderKind::Discord => Kind::Discord,
        ProviderKind::Google => Kind::Google,
        ProviderKind::Facebook => Kind::Facebook,
    }
}

fn kind_from(k: Kind) -> ProviderKind {
    match k {
        Kind::Discord => ProviderKind::Discord,
        Kind::Google => ProviderKind::Google,
        Kind::Facebook => ProviderKind::Facebook,
    }
}

/// The application at each provider whose id and secret are in the environment
/// (`VOIPC_OAUTH_DISCORD_ID`, `VOIPC_OAUTH_DISCORD_SECRET`, and so on).
pub(super) fn from_env() -> anyhow::Result<Option<OAuth>> {
    let mut providers: Vec<Provider> = [
        (Kind::Discord, "DISCORD"),
        (Kind::Google, "GOOGLE"),
        (Kind::Facebook, "FACEBOOK"),
    ]
    .into_iter()
    .filter_map(|(kind, env)| {
        let id = std::env::var(format!("VOIPC_OAUTH_{env}_ID")).ok()?;
        let secret = std::env::var(format!("VOIPC_OAUTH_{env}_SECRET")).ok()?;
        Some(Provider::new(kind, id, secret))
    })
    .collect();
    if providers.is_empty() {
        return Ok(None);
    }
    // A stand-in provider for test-provider.mjs, compiled into test builds only:
    // no release is built with VOIPC_SELFTEST. The page stays the provider's own.
    if option_env!("VOIPC_SELFTEST").is_some() {
        if let Ok(base) = std::env::var("VOIPC_OAUTH_TEST_BASE") {
            for p in &mut providers {
                p.token_url = format!("{base}/token");
                p.profile_url = format!("{base}/profile");
            }
            let http = reqwest::Client::builder().no_proxy().build()?;
            return Ok(Some(OAuth::new(http, providers)));
        }
    }
    Ok(Some(OAuth::new(
        l4f_accounts::oauth::client(None)?,
        providers,
    )))
}

/// What a flow is for: a sign-in, or a signed-in connection linking a provider
/// or proving itself with one.
#[derive(Clone, Copy)]
enum Purpose {
    SignIn,
    Account { session_id: u32 },
}

enum Outcome {
    Signed(LoginStep),
    Signup {
        cookie: String,
    },
    /// Sign-up is closed: only with an invite (`resume`).
    NoAccount {
        cookie: String,
    },
    Failed(String),
}

enum Stage {
    /// The browser is at the provider.
    Open,
    /// The provider sent it back with this; waiting for the person to tap. The key
    /// is in the page and goes with this code: whoever brought the code has it.
    Back {
        provider_code: String,
        page_key: String,
    },
    /// Tapped; the provider is being asked. A second tap ends here.
    Asking,
    Done(Outcome),
}

struct Flow {
    kind: Kind,
    /// l4f's sealed flow. It never leaves the relay: the browser is held by the
    /// page's key instead (`Stage::Back`), which needs no cookie of its own.
    cookie: String,
    state: String,
    code: String,
    /// The code and two others, in the order the page shows them.
    choices: [String; 3],
    purpose: Purpose,
    started: Instant,
    stage: Stage,
    /// Who started it: an IPv6 /48, or an IPv4 address.
    who: IpAddr,
}

/// The flows in progress.
#[derive(Default)]
pub struct Flows {
    by_ticket: DashMap<[u8; 32], Flow>,
    by_state: DashMap<String, [u8; 32]>,
    /// Flows per address (`ConnLimits` key): each asks a provider nothing yet,
    /// but holds memory for ten minutes.
    starts: DashMap<IpAddr, RateLimiter>,
    /// The same per /48 and per /32. Maps of their own: a /48's key is also the /64
    /// key of its subnet 0.
    site_starts: DashMap<IpAddr, RateLimiter>,
    block_starts: DashMap<IpAddr, RateLimiter>,
    /// When, in seconds, the limiters were last pruned and a full table last logged.
    pruned: AtomicU64,
    full_said: AtomicU64,
}

impl Flows {
    fn remove(&self, ticket: &[u8; 32]) -> Option<Flow> {
        let (_, flow) = self.by_ticket.remove(ticket)?;
        self.by_state.remove(&flow.state);
        Some(flow)
    }

    /// Drops what timed out, and makes room in a full table.
    ///
    /// shortcut: a sign-in nobody came back for leaves its l4f session to l4f's
    /// idle sweep, like one a crash left behind; ended here if that ever matters.
    fn sweep(&self) {
        let stale: Vec<[u8; 32]> = self
            .by_ticket
            .iter()
            .filter(|f| f.started.elapsed() > FLOW_LIFE)
            .map(|f| *f.key())
            .collect();
        for ticket in stale {
            self.remove(&ticket);
        }
        if self.by_ticket.len() >= MAX_FLOWS {
            let now = util::now_secs();
            if now >= self.full_said.load(Ordering::Relaxed) + 60 {
                self.full_said.store(now, Ordering::Relaxed);
                warn!("{MAX_FLOWS} provider sign-ins open at once: dropping from whoever holds the most");
            }
        }
        // Full: the oldest of whoever holds the most goes, whatever its stage. Sparing
        // those not back yet would spare nothing an attacker wants, since one request
        // makes any flow of theirs "back". Plain age would leave everyone about a minute
        // against a flood from 2000 addresses; this leaves a person's one flow alone.
        while self.by_ticket.len() >= MAX_FLOWS {
            let mut held = HashMap::<IpAddr, usize>::new();
            for f in self.by_ticket.iter() {
                *held.entry(f.who).or_default() += 1;
            }
            let most = held.values().max().copied();
            let oldest = self
                .by_ticket
                .iter()
                .filter(|f| held.get(&f.who).copied() == most)
                .min_by_key(|f| f.started)
                .map(|f| *f.key());
            let Some(ticket) = oldest else {
                break;
            };
            self.remove(&ticket);
        }
    }

    /// Whether `ip` may start a flow. Its /64 or IPv4 address has a budget, and its
    /// IPv6 /48 and /32 have one too. IPv4 has no shared one (`site_key`): a carrier's
    /// NAT or a community at an event is not one stranger.
    fn admit(&self, ip: IpAddr) -> bool {
        self.prune_limiters();
        // Widest first, so a refused prefix grows the maps under it no further. Only
        // looks: someone over their own limit must not spend their neighbours' budget.
        let mut block = crate::block_key(ip).map(|key| {
            self.block_starts
                .entry(key)
                .or_insert_with(|| RateLimiter::new(BLOCK_BURST, BLOCK_REFILL))
        });
        if block.as_mut().is_some_and(|b| !b.has_token()) {
            return false;
        }
        let mut site = crate::site_key(ip).map(|key| {
            self.site_starts
                .entry(key)
                .or_insert_with(|| RateLimiter::new(SITE_BURST, SITE_REFILL))
        });
        if site.as_mut().is_some_and(|b| !b.has_token()) {
            return false;
        }
        let allowed = self
            .starts
            .entry(crate::limit_key(ip))
            .or_insert_with(|| RateLimiter::new(10.0, 1.0 / 30.0))
            .try_consume();
        if allowed {
            if let Some(b) = block.as_mut() {
                b.try_consume();
            }
            if let Some(b) = site.as_mut() {
                b.try_consume();
            }
        }
        allowed
    }

    /// Like `token_guess_failed`: a budget that is whole again says nothing a new
    /// entry would not. Timed like `take_connect_token`: each walk locks every shard on
    /// the workers voice runs on, and frees nothing while budgets are still refilling.
    fn prune_limiters(&self) {
        let maps = [&self.starts, &self.site_starts, &self.block_starts];
        if maps.iter().all(|m| m.len() <= MAX_LIMITERS) {
            return;
        }
        let now = util::now_secs();
        if now < self.pruned.load(Ordering::Relaxed) + PRUNE_SECS {
            return;
        }
        self.pruned.store(now, Ordering::Relaxed);
        for map in maps {
            map.retain(|_, b| !b.is_full());
        }
    }
}

fn six_digits() -> String {
    format!("{:06}", rand::thread_rng().gen_range(0..1_000_000))
}

/// The code and the page's three buttons. With the connection's exporter the code is
/// `voipc_crypto::bind::provider_code` over the provider's address, which an app at 22
/// derives from its own end and shows: through a server that passes the sign-in on, the
/// two differ (W1-24). Six digits: such a server knows both exporters and could start
/// flows here until two codes agree. Without one (it never lacks one), a random code.
fn code_and_choices(binding: Option<[u8; BIND_LEN]>, url: &str) -> (String, [String; 3]) {
    let code = match binding {
        Some(x) => voipc_crypto::bind::provider_code(&x, url.as_bytes()),
        None => six_digits(),
    };
    let mut others = Vec::with_capacity(2);
    while others.len() < 2 {
        let other = six_digits();
        if other != code && !others.contains(&other) {
            others.push(other);
        }
    }
    let mut choices = [code.clone(), others.remove(0), others.remove(0)];
    choices.shuffle(&mut rand::thread_rng());
    (code, choices)
}

impl Relay {
    /// The providers people can sign in with here, or none without a web address.
    pub fn provider_kinds(&self) -> Vec<ProviderKind> {
        self.accounts
            .oauth_kinds()
            .into_iter()
            .map(kind_from)
            .collect()
    }

    /// A new flow: where to send the browser, the code to show, and the ticket.
    fn flow_begin(
        &self,
        kind: ProviderKind,
        purpose: Purpose,
        intent: Intent,
        user: Option<&User>,
        ip: IpAddr,
        binding: Option<[u8; BIND_LEN]>,
    ) -> Result<(String, String, [u8; 32]), String> {
        if !self.providers.admit(ip) {
            return Err("Too many sign-ins from your address. Try again later.".into());
        }
        self.providers.sweep();
        let kind = kind_of(kind);
        let (url, cookie) = self
            .accounts
            .oauth_begin(kind, intent, user, "")
            .map_err(|e| e.message().to_string())?;
        let state = url
            .split(['?', '&'])
            .find_map(|p| p.strip_prefix("state="))
            .ok_or("unexpected sign-in step")?
            .to_string();
        let (code, choices) = code_and_choices(binding, &url);
        let ticket: [u8; 32] = rand::random();
        self.providers.by_state.insert(state.clone(), ticket);
        self.providers.by_ticket.insert(
            ticket,
            Flow {
                kind,
                cookie,
                state,
                code: code.clone(),
                choices,
                purpose,
                started: Instant::now(),
                stage: Stage::Open,
                who: crate::site_key(ip).unwrap_or_else(|| crate::limit_key(ip)),
            },
        );
        Ok((url, code, ticket))
    }

    /// `AccountStart::Provider`.
    pub(super) async fn provider_open<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        kind: ProviderKind,
        ip: IpAddr,
        binding: Option<[u8; BIND_LEN]>,
    ) -> Result<(), String> {
        let (url, code, ticket) =
            self.flow_begin(kind, Purpose::SignIn, Intent::Login, None, ip, binding)?;
        step(
            stream,
            AuthStep::OpenBrowser {
                url,
                code,
                ticket: ticket.to_vec(),
            },
        )
        .await
    }
}

// ── The web page ──────────────────────────────────────────────────────────

/// Sent instead of the web client's policy: a form, and nothing else.
const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; \
    frame-ancestors 'none'; base-uri 'none'";
const PAGE_STYLE: &str = "body{font:18px system-ui,sans-serif;max-width:32rem;margin:15vh auto;\
    padding:0 1.5rem;background:#101215;color:#e8e8e6}\
    button{font:600 1.6rem ui-monospace,monospace;padding:.9rem 1.4rem;margin:.3rem;\
    border-radius:.6rem;border:1px solid #555;background:#1b1e23;color:inherit;cursor:pointer}\
    button[name=none]{font:inherit}p{line-height:1.5}";

fn page(status: StatusCode, title: &str, body: &str) -> Response<Full<Bytes>> {
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title><style>{PAGE_STYLE}</style></head>\
         <body><h1>{title}</h1>{body}</body></html>"
    );
    let mut resp = Response::new(Full::new(Bytes::from(html)));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(PAGE_CSP),
    );
    // The address holds the provider's code
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn ended_page() -> Response<Full<Bytes>> {
    page(
        StatusCode::GONE,
        "This sign-in has ended",
        &format!("<p>{ENDED}</p>"),
    )
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .find_map(|p| p.strip_prefix(key)?.strip_prefix('='))
}

/// `state`, `code` and `error` as a provider sends them: URL-safe, or escaped by
/// it. Anything else on this page comes from the relay.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `GET /account/oauth/<provider>/cb`: the provider sent the browser back. Asks
/// the provider nothing yet: that waits for the person to tap the code. The page's
/// key goes only to a request bringing the provider's code.
pub fn callback(state: &ServerState, path: &str, query: &str) -> Response<Full<Bytes>> {
    let Some(relay) = state.accounts.as_ref() else {
        return ended_page();
    };
    let Some(oauth_state) = query_param(query, "state").map(percent_decode) else {
        return ended_page();
    };
    let Some(ticket) = relay.providers.by_state.get(&oauth_state).map(|t| *t) else {
        return ended_page();
    };
    let Some(mut flow) = relay.providers.by_ticket.get_mut(&ticket) else {
        return ended_page();
    };
    let slug = path
        .strip_prefix(CALLBACK_PREFIX)
        .and_then(|p| p.strip_suffix("/cb"))
        .unwrap_or_default();
    if slug != flow.kind.slug() || flow.started.elapsed() > FLOW_LIFE {
        return ended_page();
    }
    match query_param(query, "code").map(percent_decode) {
        // A reload, or one more fetch of the same address: the same page, key and all
        Some(code)
            if matches!(&flow.stage, Stage::Back { provider_code, .. }
                if util::ct_eq(provider_code, &code)) => {}
        // Back from the provider, or back again after approving once more. The key
        // goes with this code and no other, so holding `state` never gets the key to
        // a code somebody else brought.
        Some(code) if matches!(flow.stage, Stage::Open | Stage::Back { .. }) => {
            flow.stage = Stage::Back {
                provider_code: code,
                page_key: util::b64u(&rand::random::<[u8; 32]>()),
            };
        }
        // Said no at the provider
        None if matches!(flow.stage, Stage::Open) => {
            flow.stage = Stage::Done(Outcome::Failed("Cancelled at the provider.".into()));
            return page(
                StatusCode::OK,
                "Sign-in cancelled",
                "<p>Nothing happened. You can close this page.</p>",
            );
        }
        _ => return ended_page(),
    }
    let Stage::Back { page_key, .. } = &flow.stage else {
        return ended_page();
    };
    let host = relay
        .accounts
        .host
        .config()
        .oauth_base_url
        .split("://")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let buttons: String = flow
        .choices
        .iter()
        .map(|c| format!("<button name=\"pick\" value=\"{c}\">{c}</button>"))
        .collect();
    page(
        StatusCode::OK,
        "Which code does your app show?",
        &format!(
            "<p>Signing in to VoIPC on <b>{host}</b>. Tap the code your VoIPC app shows.</p>\
             <form method=\"post\" action=\"{CONFIRM_PATH}\">\
             <input type=\"hidden\" name=\"state\" value=\"{oauth_state}\">\
             <input type=\"hidden\" name=\"key\" value=\"{key}\">{buttons}\
             <button name=\"none\" value=\"1\">None of these</button></form>\
             <p>If you did not start this in your own app, close this page: someone may be \
             trying to sign in as you.</p>",
            oauth_state = html_attr(&flow.state),
            key = html_attr(page_key),
        ),
    )
}

/// `state` is the relay's own, base64url: this is the backstop.
fn html_attr(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect()
}

/// `POST /account/oauth/confirm`: the person tapped a code.
pub async fn confirm(state: &Arc<ServerState>, body: &[u8], ip: IpAddr) -> Response<Full<Bytes>> {
    let Some(relay) = state.accounts.clone() else {
        return ended_page();
    };
    let form = String::from_utf8_lossy(body);
    let Some(oauth_state) = query_param(&form, "state") else {
        return ended_page();
    };
    let pick = query_param(&form, "pick").unwrap_or_default();
    let key = query_param(&form, "key").unwrap_or_default();
    let Some(ticket) = relay.providers.by_state.get(oauth_state).map(|t| *t) else {
        return ended_page();
    };
    let taken = {
        let Some(mut flow) = relay.providers.by_ticket.get_mut(&ticket) else {
            return ended_page();
        };
        let Stage::Back {
            provider_code,
            page_key,
        } = &flow.stage
        else {
            return ended_page();
        };
        // Whoever started this holds the state and the code, and may not be the person
        // at the provider. Changes nothing, and reads like a flow not back yet.
        if !util::ct_eq(page_key, key) {
            return ended_page();
        }
        let provider_code = provider_code.clone();
        if flow.code != pick {
            // One tap. A wrong one is someone reading the page, not the app.
            flow.stage = Stage::Done(Outcome::Failed(
                "The code tapped was not the one this app showed.".into(),
            ));
            return page(
                StatusCode::FORBIDDEN,
                "That was not the code",
                "<p>This sign-in has been stopped. If you started it, start again in the app. If \
                 you did not, someone may be trying to sign in as you.</p>",
            );
        }
        flow.stage = Stage::Asking;
        (
            flow.kind,
            flow.cookie.clone(),
            flow.state.clone(),
            provider_code,
            flow.purpose,
        )
    };
    // In its own task: a browser that goes away mid-way (a closed tab, a phone off its
    // network) drops this request, and with it the flow stayed Asking until it expired (W2-19)
    let state = state.clone();
    tokio::spawn(async move { exchange(&state, &relay, ticket, taken, ip).await })
        .await
        .unwrap_or_else(|_| ended_page())
}

/// What the provider's code comes to, past the tap.
async fn exchange(
    state: &Arc<ServerState>,
    relay: &Arc<Relay>,
    ticket: [u8; 32],
    taken: (Kind, String, String, String, Purpose),
    ip: IpAddr,
) -> Response<Full<Bytes>> {
    let (kind, cookie, oauth_state, provider_code, purpose) = taken;
    let ctx = relay.ctx(ip, "web");
    match purpose {
        Purpose::SignIn => {
            let outcome = relay
                .accounts
                .oauth_finish(&ctx, kind, &cookie, &oauth_state, &provider_code, None)
                .await;
            let outcome = match outcome {
                Ok((SocialOutcome::Signed(step), _)) => Outcome::Signed(step),
                Ok((SocialOutcome::Signup { cookie }, _)) => Outcome::Signup { cookie },
                Ok((SocialOutcome::NoAccount { cookie }, _)) => Outcome::NoAccount { cookie },
                Ok(_) => Outcome::Failed("unexpected sign-in step".into()),
                // Not "wrong password", on a page that asked for none. An imported ban, or
                // a disabled account
                Err(l4f_accounts::service::Error::BadLogin) => {
                    Outcome::Failed("That account cannot sign in here.".into())
                }
                Err(e) => Outcome::Failed(e.message().to_string()),
            };
            let failed = match &outcome {
                Outcome::Failed(reason) => Some(reason.clone()),
                _ => None,
            };
            if let Some(mut flow) = relay.providers.by_ticket.get_mut(&ticket) {
                flow.stage = Stage::Done(outcome);
            }
            match failed {
                Some(reason) => did_not_work(&reason),
                None => back_to_the_app(),
            }
        }
        Purpose::Account { session_id } => {
            relay.providers.remove(&ticket);
            let done = finish_for_account(
                state,
                relay,
                session_id,
                kind,
                &cookie,
                &oauth_state,
                &provider_code,
                ip,
            )
            .await;
            match done {
                Ok(()) => back_to_the_app(),
                Err(reason) => did_not_work(&reason),
            }
        }
    }
}

fn did_not_work(reason: &str) -> Response<Full<Bytes>> {
    page(
        StatusCode::OK,
        "That did not work",
        &format!("<p>{}</p>", html_text(reason)),
    )
}

/// A link or proof whose connection ended before the tap: a phone's app goes to sleep
/// while the browser is up, and comes back as a new session.
pub(crate) const APP_GONE: &str =
    "The app was no longer connected, so nothing changed. Start again in the app.";

fn html_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn back_to_the_app() -> Response<Full<Bytes>> {
    page(
        StatusCode::OK,
        "Done",
        "<p>You can close this page and go back to the app.</p>",
    )
}

/// A signed-in connection's link or proof. What it comes to reaches the connection,
/// and the page: `Err` is what to show there, since "Done" over nothing done misleads
/// (W2-20). With the connection gone the provider is not asked at all.
#[allow(clippy::too_many_arguments)]
async fn finish_for_account(
    state: &Arc<ServerState>,
    relay: &Arc<Relay>,
    session_id: u32,
    kind: Kind,
    cookie: &str,
    oauth_state: &str,
    provider_code: &str,
    ip: IpAddr,
) -> Result<(), String> {
    let session = state.sessions.get(&session_id).and_then(|s| {
        s.account
            .as_ref()
            .map(|a| (a.user.clone(), a.info.clone(), s.control_tx.clone()))
    });
    let Some((user, info, tx)) = session else {
        return Err(APP_GONE.into());
    };
    let ctx = relay.ctx(ip, "web");
    let done = relay
        .accounts
        .oauth_finish(
            &ctx,
            kind,
            cookie,
            oauth_state,
            provider_code,
            Some((&user, &info)),
        )
        .await;
    let (answer, out) = match done {
        Ok((SocialOutcome::Linked, _)) => (
            AccountReply::ProviderDone {
                kind: kind_from(kind),
                link: true,
            },
            Ok(()),
        ),
        Ok((SocialOutcome::SteppedUp(fresh), _)) => {
            put_session(state, session_id, fresh);
            (
                AccountReply::ProviderDone {
                    kind: kind_from(kind),
                    link: false,
                },
                Ok(()),
            )
        }
        Ok(_) => {
            let why = "unexpected sign-in step";
            (refused("ProviderStart", why), Err(why.to_string()))
        }
        Err(e) => (
            refused("ProviderStart", e.message()),
            Err(e.message().to_string()),
        ),
    };
    let _ = crate::session::send_msg(&tx, &ServerMessage::Account(answer));
    out
}

/// A step-up gave this session a new token; the old one no longer resolves, so
/// `revalidate` would end this connection.
fn put_session(state: &ServerState, session_id: u32, fresh: NewSession) {
    if let Some(a) = state
        .sessions
        .get_mut(&session_id)
        .as_mut()
        .and_then(|s| s.account.as_mut())
    {
        a.token = fresh.token;
        a.info = fresh.info;
    }
}

// ── Back from the browser ─────────────────────────────────────────────────

/// Whether the browser is through with this ticket's flow. `Err`: there is none.
pub(super) fn ready(relay: &Relay, ticket: &[u8]) -> Result<bool, String> {
    let ticket: [u8; 32] = ticket.try_into().map_err(|_| ENDED.to_string())?;
    relay
        .providers
        .by_ticket
        .get(&ticket)
        .filter(|f| f.started.elapsed() <= FLOW_LIFE)
        .map(|f| matches!(f.stage, Stage::Done(_)))
        .ok_or_else(|| ENDED.to_string())
}

/// `AccountStart::ProviderResume`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn resume<S: AsyncRead + AsyncWrite + Unpin>(
    state: &ServerState,
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    ticket: &[u8],
    invite: Option<&str>,
    ctx: &l4f_accounts::service::Ctx,
    ip: IpAddr,
    answers: &mut u32,
    binding: Option<[u8; voipc_crypto::bind::BIND_LEN]>,
) -> Result<SignedIn, String> {
    let ticket: [u8; 32] = ticket.try_into().map_err(|_| ENDED.to_string())?;
    let not_yet = relay
        .providers
        .by_ticket
        .get(&ticket)
        .map(|f| f.started.elapsed() <= FLOW_LIFE && !matches!(f.stage, Stage::Done(_)));
    match not_yet {
        None => return Err(ENDED.into()),
        Some(true) => {
            step(stream, AuthStep::ProviderPending).await?;
            return Err(NOT_YET.into());
        }
        Some(false) => {}
    }
    let flow = relay.providers.remove(&ticket).ok_or(ENDED)?;
    if flow.started.elapsed() > FLOW_LIFE {
        return Err(ENDED.into());
    }
    let session = match flow.stage {
        Stage::Done(Outcome::Signed(LoginStep::Done(session))) => session,
        Stage::Done(Outcome::Signed(LoginStep::NeedMfa(pending))) => {
            second_factor(relay, stream, buf, ctx, pending, answers, ip).await?
        }
        Stage::Done(Outcome::Signup { cookie }) => {
            // A link that ran out is no reason to turn someone away where anyone
            // may sign up: they only do not get what it would have given
            let invite = usable_invite(relay, invite).await;
            signup(relay, stream, buf, ctx, &cookie, invite, answers, ip).await?
        }
        Stage::Done(Outcome::NoAccount { cookie }) => {
            let Some(invite) = invite else {
                return Err(NO_ACCOUNT.into());
            };
            if links::is_link_code(invite) && !relay.link_usable(invite).await.unwrap_or(false) {
                return Err(links::GONE.into());
            }
            signup(relay, stream, buf, ctx, &cookie, Some(invite), answers, ip).await?
        }
        Stage::Done(Outcome::Failed(reason)) => return Err(reason),
        _ => return Err(ENDED.into()),
    };
    let token = session.token.clone();
    let r = finish(
        state, relay, stream, buf, ctx, session, answers, ip, binding,
    )
    .await;
    if r.is_err() {
        let _ = relay.accounts.logout(&token).await;
    }
    r
}

async fn usable_invite<'a>(relay: &Relay, invite: Option<&'a str>) -> Option<&'a str> {
    let invite = invite?;
    if links::is_link_code(invite) && !relay.link_usable(invite).await.unwrap_or(false) {
        return None;
    }
    Some(invite)
}

/// The provider knows this person and nobody here does, and sign-up is open or they
/// hold an invite: a link, or a code an admin made.
#[allow(clippy::too_many_arguments)]
async fn signup<S: AsyncRead + AsyncWrite + Unpin>(
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    ctx: &l4f_accounts::service::Ctx,
    cookie: &str,
    invite: Option<&str>,
    answers: &mut u32,
    ip: IpAddr,
) -> Result<NewSession, String> {
    let suggestion = relay
        .accounts
        .oauth_signup_suggestion(cookie)
        .ok_or(ENDED)?;
    let mut problem = String::new();
    loop {
        let cfg = relay.accounts.host.config();
        let ch = pow::issue(
            &relay.pow_key,
            cfg.signup.pow_maxnumber,
            cfg.signup.pow_ttl_minutes.saturating_mul(60),
        );
        let challenge = PowChallenge {
            altcha: serde_json::to_string(&ch).map_err(|e| e.to_string())?,
            ts: pow::stamp(&relay.pow_key, util::now_secs()),
        };
        step(
            stream,
            AuthStep::ProviderSignup {
                relay_id: relay.relay_id,
                suggestion: suggestion.clone(),
                problem,
                pow: challenge,
            },
        )
        .await?;
        let AuthContinue::ProviderSignup { name, altcha, ts } =
            next(stream, buf, CHOICE_WAIT, answers).await?
        else {
            return Err(unexpected());
        };
        if altcha.is_empty() {
            return Err("The sign-up puzzle was not solved.".into());
        }
        // Asked again, as for a name that is taken; a shape, so it tells nothing (W1-30)
        if super::placeholder::kept_for_the_move(&name) {
            problem = super::placeholder::KEPT_FOR_THE_MOVE.to_string();
            continue;
        }
        let proof = pow::Proof {
            altcha: &altcha,
            ts: &ts,
            ..Default::default()
        };
        let _work = relay.pending_slot(ip).ok_or_else(|| BUSY.to_string())?;
        if let Some(code) = invite.filter(|c| links::is_link_code(c)) {
            let how = links::How::Provider(cookie);
            match links::register(relay, ctx, code, &name, how, &altcha, &ts).await {
                Ok(session) => return Ok(session),
                Err(links::Refused::Name(text)) => problem = text,
                Err(links::Refused::End(text)) => return Err(text),
            }
            continue;
        }
        let made = match invite {
            Some(code) => {
                relay
                    .accounts
                    .oauth_signup_invite(ctx, cookie, code, &name)
                    .await
            }
            None => relay.accounts.oauth_signup(ctx, cookie, &name, proof).await,
        };
        match made {
            Ok(session) => return Ok(session),
            Err(
                e @ (l4f_accounts::service::Error::UsernameTaken
                | l4f_accounts::service::Error::Invalid(_)),
            ) => problem = e.message().to_string(),
            Err(e) => return Err(e.message().to_string()),
        }
    }
}

/// The account's first vault, written whole or not at all. One at a time: nobody
/// but a provider's sign-in does this, and it is over in a few writes.
pub(crate) async fn claim(
    relay: &Relay,
    user: AccountId,
    name: &str,
    identity_key: &[u8],
    vault: &[VaultBlob],
) -> Result<(), String> {
    let gone = || "Something went wrong. Please try again.".to_string();
    if identity_key.is_empty() || identity_key.len() > 64 {
        return Err("malformed identity key".into());
    }
    if vault.len() as i64 > VAULT_MAX_ITEMS
        || vault.iter().map(|b| b.v.len()).sum::<usize>() > VAULT_TOTAL_BYTES
    {
        return Err("The new vault is too big.".into());
    }
    if let Some(reason) = vault.iter().find_map(|b| vault_item_ok(&b.k, &b.v).err()) {
        return Err(reason.into());
    }
    if !vault
        .iter()
        .any(|b| b.k == SLOT_RESET && b.v.len() == RESET_KEY_LEN)
    {
        return Err(unexpected());
    }
    let _one = relay.claiming.lock().await;
    if relay.identity(user).await.map_err(|_| gone())?.is_some() {
        return Err(
            "This account was opened just now, somewhere else. The key this device showed does \
             not count: the one from the device where it opened does."
                .into(),
        );
    }
    // A vault is bound to the name it was made under, which the relay cannot read: one
    // made for a name since changed would look fine and never open. A sweep may also have
    // taken the account.
    let now = relay
        .store()
        .user_by_id(user)
        .await
        .map_err(|_| gone())?
        .ok_or_else(gone)?;
    if now.username != name {
        return Err("This account's name changed just now. Sign in again.".into());
    }
    // Whatever this account came to hold, it was not given to whoever is opening it. Ahead of
    // anything written: a claim refused here leaves it as it was.
    if let Err(e) = relay.hold_power(user).await {
        warn!(user = %user.hex(), "a claim refused: {e:#}");
        return Err(gone());
    }
    // What a claim that died halfway left, which nobody could open
    for ns in [VAULT_NS, PINS_NS] {
        relay
            .store()
            .delete_blobs(user, ns)
            .await
            .map_err(|_| gone())?;
    }
    for b in vault {
        match relay
            .store()
            .put_blob(user, VAULT_NS, &b.k, &b.v, 0, relay.quota)
            .await
        {
            Ok(l4f_accounts::store::PutBlob::Done(_)) => {}
            other => {
                warn!("storing a claimed account's vault: {other:?}");
                let _ = relay.store().delete_blobs(user, VAULT_NS).await;
                return Err(gone());
            }
        }
    }
    relay
        .claim_done(user, identity_key)
        .await
        .map_err(|_| gone())
}

/// The first sign-in to an account the move made: the name it came with is Discord's, and
/// the person may take another. `ProviderSignup` asks, as for a new account: the machine
/// takes it before `ProviderSigned`. Its puzzle is the smallest there is and is never
/// checked, since this spends no sign-up. Within what the connection's answers allow:
/// past that, a new sign-in starts over.
async fn pick_name<S: AsyncRead + AsyncWrite + Unpin>(
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    ctx: &l4f_accounts::service::Ctx,
    user: &mut User,
    answers: &mut u32,
    ip: IpAddr,
) -> Result<(), String> {
    let mut problem = String::new();
    loop {
        let ttl = relay.accounts.host.config().signup.pow_ttl_minutes;
        let ch = pow::issue(&relay.pow_key, 1, ttl.saturating_mul(60));
        let challenge = PowChallenge {
            altcha: serde_json::to_string(&ch).map_err(|e| e.to_string())?,
            ts: pow::stamp(&relay.pow_key, util::now_secs()),
        };
        step(
            stream,
            AuthStep::ProviderSignup {
                relay_id: relay.relay_id,
                suggestion: user.username.clone(),
                problem,
                pow: challenge,
            },
        )
        .await?;
        let AuthContinue::ProviderSignup { name, .. } =
            next(stream, buf, CHOICE_WAIT, answers).await?
        else {
            return Err(unexpected());
        };
        if name.trim().eq_ignore_ascii_case(&user.username) {
            return Ok(());
        }
        let _work = relay.pending_slot(ip).ok_or_else(|| BUSY.to_string())?;
        match relay.placeholder_rename(ctx, user.id, &name).await? {
            Ok(new) => {
                user.username = new;
                return Ok(());
            }
            Err(text) => problem = text,
        }
    }
}

/// From a provider's sign-in to the keys: the same end as `super::finish`, except
/// that the vault has to be opened before anything else happens, and an identity
/// is never replaced here.
#[allow(clippy::too_many_arguments)]
async fn finish<S: AsyncRead + AsyncWrite + Unpin>(
    state: &ServerState,
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    ctx: &l4f_accounts::service::Ctx,
    session: NewSession,
    answers: &mut u32,
    ip: IpAddr,
    binding: Option<[u8; voipc_crypto::bind::BIND_LEN]>,
) -> Result<SignedIn, String> {
    let gone = || "Something went wrong. Please try again.".to_string();
    let work = || relay.pending_slot(ip).ok_or_else(|| BUSY.to_string());
    let (mut user, info, scopes, blobs, known) = {
        let _work = work()?;
        let (user, info, scopes) = relay
            .accounts
            .session_from_token(&session.token, util::now())
            .await
            .map_err(|_| gone())?
            .ok_or_else(gone)?;
        let blobs = relay.vault(user.id).await.map_err(|_| gone())?;
        let known = relay.identity(user.id).await.map_err(|_| gone())?;
        (user, info, scopes, blobs, known)
    };
    let claim_it = known.is_none();
    if claim_it && relay.placeholder_open(user.id).await.map_err(|_| gone())? {
        pick_name(relay, stream, buf, ctx, &mut user, answers, ip).await?;
    }
    let challenge: [u8; 32] = rand::random();
    step(
        stream,
        AuthStep::ProviderSigned {
            relay_id: relay.relay_id,
            name: user.username.clone(),
            claim: claim_it,
            has_password: user.has_password,
            challenge: challenge.to_vec(),
            // Never the password slot: with it anyone could guess the password offline
            blobs: blobs.into_iter().filter(|b| b.k != "slot.pass").collect(),
        },
    )
    .await?;

    let identity_key = loop {
        match next(stream, buf, CHOICE_WAIT, answers).await? {
            AuthContinue::Claim {
                identity_key,
                vault,
            } if claim_it => {
                let _work = work()?;
                claim(relay, user.id, &user.username, &identity_key, &vault).await?;
                info!(user = %user.id.hex(), "account claimed through a provider");
                break identity_key;
            }
            // Only the bound proof (22): an unbound one is what a server passing the
            // sign-in on would hold (W1-24)
            AuthContinue::ProviderProofBound { signature, web } if !claim_it => {
                let key = known.as_deref().ok_or_else(unexpected)?;
                let Some(b) = voipc_crypto::bind::Binding::claimed(web, binding) else {
                    return Err(super::NOT_THIS_CONNECTION.into());
                };
                if !voipc_crypto::account::provider_proof_bound_ok(
                    key,
                    &relay.relay_id,
                    &user.username,
                    &challenge,
                    &b,
                    &signature,
                ) {
                    return Err(
                        "That does not open this account, or the sign-in was not made \
                                on this connection."
                            .into(),
                    );
                }
                break key.to_vec();
            }
            AuthContinue::PairStart { commitment } if !claim_it => {
                pair(state, relay, stream, buf, user.id, commitment, answers).await?;
            }
            _ => return Err(unexpected()),
        }
    };

    let AuthContinue::Keys {
        identity_key: sent,
        prekey_bundle,
        reset_identity: _,
    } = next(stream, buf, STEP_WAIT, answers).await?
    else {
        return Err(unexpected());
    };
    // Never replaced here, `reset_identity` or not
    if sent != identity_key {
        return Err("This device's identity key is not your account's.".into());
    }
    let _work = work()?;
    let account = relay.info_of(&user, &scopes).await.map_err(|_| gone())?;
    let standing = relay.standing(&user, &scopes).await.map_err(|_| gone())?;
    info!(user = %user.id.hex(), method = %info.method, "account signed in");
    Ok(SignedIn {
        user,
        token: session.token,
        info,
        scopes,
        standing,
        account,
        identity_key,
        prekey_bundle,
        vault_proven: true,
        by_secret: false,
    })
}

// ── Pairing ───────────────────────────────────────────────────────────────

/// What the other device sends a device waiting for the vault's key.
pub enum PairEvent {
    Nonce(Vec<u8>),
    Wrapped(Vec<u8>),
    Declined,
}

/// A pairing in progress, from the waiting device's side.
pub struct PairLink {
    user: AccountId,
    to_new: mpsc::Sender<PairEvent>,
}

/// The other device's next word, within `PAIR_WAIT`, listening to this device all
/// the while: it sends nothing here, so a frame or a hang-up ends the pairing, and
/// `pair` tells the other device at once. `read_frame` keeps its bytes in `buf`, so
/// dropping it loses nothing.
async fn pair_wait<S: AsyncRead + Unpin>(
    events: &mut mpsc::Receiver<PairEvent>,
    stream: &mut S,
    buf: &mut BytesMut,
) -> Result<Option<PairEvent>, String> {
    tokio::select! {
        event = tokio::time::timeout(PAIR_WAIT, events.recv()) => Ok(event.ok().flatten()),
        _ = crate::session::read_frame(stream, buf, PAIR_WAIT + Duration::from_secs(1)) => {
            Err("connection closed during sign-in".into())
        }
    }
}

/// Runs one pairing. `Ok` both when the key arrived and when the other device
/// said no (`PairRefused`): what opens the account is the person's choice again.
async fn pair<S: AsyncRead + AsyncWrite + Unpin>(
    state: &ServerState,
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    user: AccountId,
    commitment: Vec<u8>,
    answers: &mut u32,
) -> Result<(), String> {
    if commitment.len() != 32 {
        return Err(unexpected());
    }
    // Each ask puts a question on the person's other device: a stranger holding
    // their provider account must not be able to wear them down.
    if !relay.spend_pair_ask(user) {
        return refuse_pair(stream, PAIR_TOO_MANY).await;
    }
    // From here the ask has its limit above, so a refusal gives back what it used of the
    // connection's answers: asks that time out must not leave too few for the one that
    // goes through.
    let before = *answers - 1;
    let other = state.account_sessions.get(&user.0).map(|s| *s);
    let Some(tx) = other.and_then(|id| state.sessions.get(&id).map(|s| s.control_tx.clone()))
    else {
        *answers = before;
        return refuse_pair(stream, PAIR_NOBODY_ONLINE).await;
    };
    // In 32 bits: the apps' front ends hold it as a JS number
    let pair = u64::from(rand::random::<u32>());
    let (to_new, mut events) = mpsc::channel(4);
    let told = |reply: AccountReply| {
        crate::session::send_msg(&tx, &ServerMessage::Account(reply)).map_err(|_| ())
    };
    // One at a time on the other device, which declines what comes behind an open ask.
    // An ask still open here is from a device that died with no hang-up yet, or that
    // this person gave up on: the new one takes over, and the old one hears it first.
    let open: Vec<u64> = relay
        .pairs
        .iter()
        .filter(|p| p.user == user)
        .map(|p| *p.key())
        .collect();
    for ended in open {
        relay.pairs.remove(&ended);
        let _ = told(AccountReply::PairEnded { pair: ended });
    }
    relay.pairs.insert(pair, PairLink { user, to_new });
    // `Some`: why the ask was refused
    let r = async {
        if told(AccountReply::PairAsked { pair, commitment }).is_err() {
            return Ok(Some(PAIR_NO_ANSWER));
        }
        let nonce = match pair_wait(&mut events, stream, buf).await? {
            Some(PairEvent::Nonce(nonce)) => nonce,
            Some(PairEvent::Declined) => return Ok(Some(PAIR_SAID_NO)),
            _ => return Ok(Some(PAIR_NO_ANSWER)),
        };
        step(stream, AuthStep::PairNonce { nonce }).await?;
        let AuthContinue::PairReveal { ephemeral, blind } =
            next(stream, buf, STEP_WAIT, answers).await?
        else {
            return Err(unexpected());
        };
        if told(AccountReply::PairRevealed {
            pair,
            ephemeral,
            blind,
        })
        .is_err()
        {
            return Ok(Some(PAIR_NO_ANSWER));
        }
        match pair_wait(&mut events, stream, buf).await? {
            Some(PairEvent::Wrapped(wrapped)) => {
                step(stream, AuthStep::PairWrapped { wrapped }).await?;
                Ok(None)
            }
            Some(PairEvent::Declined) => Ok(Some(PAIR_SAID_NO)),
            _ => Ok(Some(PAIR_TOO_LATE)),
        }
    }
    .await;
    relay.pairs.remove(&pair);
    let _ = told(AccountReply::PairEnded { pair });
    match r? {
        Some(reason) => {
            *answers = before;
            refuse_pair(stream, reason).await
        }
        None => Ok(()),
    }
}

async fn refuse_pair<S: AsyncWrite + Unpin>(stream: &mut S, reason: &str) -> Result<(), String> {
    step(
        stream,
        AuthStep::PairRefused {
            reason: reason.into(),
        },
    )
    .await
}

impl Relay {
    /// `voipc-server admin reclaim`: an account back to unopened, for someone who
    /// lost every device and the recovery key. Only without a password: with one,
    /// a sign-in or a reset is the way back, and this would lock it out instead.
    pub async fn reclaim(
        &self,
        ctx: &l4f_accounts::service::Ctx,
        user: &User,
    ) -> Result<(), String> {
        let failed = |e: sqlx::Error| e.to_string();
        if user.has_password {
            return Err(format!(
                "{} has a password: it signs in with that, or resets it with the recovery key.",
                user.username
            ));
        }
        self.power_back_to_waiting(user.id)
            .await
            .map_err(|e| e.to_string())?;
        self.accounts
            .reset_2fa_as_host(ctx, user.id)
            .await
            .map_err(|e| e.message().to_string())?;
        for ns in [VAULT_NS, PINS_NS] {
            self.store()
                .delete_blobs(user.id, ns)
                .await
                .map_err(failed)?;
        }
        let id = &user.id.0[..];
        db!(self.store(), pool => {
            // Its log key went with the vault: nobody can wrap to it any more, and
            // a member nobody can reach would hold up every writer in the channel.
            for q in [
                "DELETE FROM voipc_identity WHERE account = $1",
                "DELETE FROM voipc_logkeys WHERE account = $1",
                "DELETE FROM voipc_members WHERE account = $1",
                "DELETE FROM voipc_pending WHERE owner = $1 OR recipient = $1",
            ] {
                sqlx::query(q).bind(id).execute(pool).await.map_err(failed)?;
            }
        });
        // Whoever held the old key is out at each writer's next post, the same as a leaver
        super::log::walk(self.store(), &user.id.0)
            .await
            .map_err(|e| e.to_string())?;
        info!(user = %user.id.hex(), "account reclaimed from the shell");
        Ok(())
    }

    /// Pairings in progress.
    #[cfg(test)]
    pub(crate) fn pairs_open(&self) -> usize {
        self.pairs.len()
    }

    /// Three asks, then one per ten minutes, per account.
    pub(crate) fn spend_pair_ask(&self, user: AccountId) -> bool {
        self.pair_asks
            .entry(user)
            .or_insert_with(|| RateLimiter::new(3.0, 1.0 / 600.0))
            .try_consume()
    }

    /// A provider's application, for a relay that has a web address.
    pub fn with_providers(mut self, oauth: OAuth) -> Relay {
        self.accounts = self.accounts.with_oauth(oauth);
        self
    }

    /// Passes a device's answer on, if the pairing is this account's.
    pub(super) async fn pair_event(&self, user: AccountId, pair: u64, event: PairEvent) {
        let to_new = self
            .pairs
            .get(&pair)
            .filter(|p| p.user == user)
            .map(|p| p.to_new.clone());
        if let Some(to_new) = to_new {
            let _ = to_new.send(event).await;
        }
    }
}

// ── A signed-in account's providers ───────────────────────────────────────

/// `AccountRequest::ProviderList`.
pub(super) async fn list(relay: &Relay, user: &User) -> anyhow::Result<AccountReply> {
    let linked = relay
        .accounts
        .oauth_linked(user.id)
        .await?
        .into_iter()
        .map(|(kind, c)| LinkedProvider {
            kind: kind_from(kind),
            name: c.name,
        })
        .collect();
    Ok(AccountReply::Providers {
        offered: relay.provider_kinds(),
        linked,
        has_password: user.has_password,
    })
}

/// `AccountRequest::ProviderStart`, once the connection proved itself if it had to.
pub(super) fn start_for_account(
    relay: &Relay,
    session_id: u32,
    user: &User,
    kind: ProviderKind,
    link: bool,
    ip: IpAddr,
    binding: Option<[u8; BIND_LEN]>,
) -> AccountReply {
    let intent = if link { Intent::Link } else { Intent::Reauth };
    let purpose = Purpose::Account { session_id };
    match relay.flow_begin(kind, purpose, intent, Some(user), ip, binding) {
        Ok((url, code, _)) => AccountReply::ProviderBrowser { url, code },
        Err(reason) => refused("ProviderStart", &reason),
    }
}

/// `AccountRequest::ProviderUnlink`, once the connection proved itself. Refused
/// when it is the last way in (l4f checks that).
pub(super) async fn unlink(
    relay: &Relay,
    ctx: &l4f_accounts::service::Ctx,
    user: &User,
    info: &SessionInfo,
    kind: ProviderKind,
) -> anyhow::Result<AccountReply> {
    if !relay.accounts.fresh(info, util::now()) {
        return Ok(refused("ProviderUnlink", "Confirm it's you first."));
    }
    let kind_l4f = kind_of(kind);
    let linked = relay.accounts.oauth_linked(user.id).await?;
    let Some((_, cred)) = linked.into_iter().find(|(k, _)| *k == kind_l4f) else {
        return Ok(refused(
            "ProviderUnlink",
            "That provider is not linked here.",
        ));
    };
    // Deleting the account later still takes what the move brought under this Discord id
    // (W1-34): kept before the link goes, read only then and in the account's export
    if kind_l4f == l4f_accounts::oauth::Kind::Discord {
        if let Some(dc_id) = std::str::from_utf8(&cred.ext_id)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            db!(relay.store(), pool => {
                sqlx::query(
                    "INSERT INTO voipc_dc_unlinked (account, dc_id, at) VALUES ($1, $2, $3)
                     ON CONFLICT DO NOTHING",
                )
                .bind(&user.id.0[..])
                .bind(dc_id)
                .bind(util::now())
                .execute(pool)
                .await?;
            });
        }
    }
    Ok(
        match relay
            .accounts
            .remove_credential(ctx, user, &kind_l4f.credential_kind(), &cred.ext_id)
            .await
        {
            Ok(()) => AccountReply::ProviderUnlinked { kind },
            Err(e) => refused("ProviderUnlink", e.message()),
        },
    )
}

#[cfg(test)]
mod tests {

    /// W3-35: anyone on the internet reaches these at `/account/oauth/`, and no fuzz target
    /// can, the relay being a binary. Many generated inputs instead: no panic, a value is
    /// a piece of what came, and text with no `%` decodes to itself.
    #[test]
    fn the_callbacks_query_reading_takes_anything() {
        let alphabet: Vec<char> = "%=&ab09AF-_.~+/?é漢😀\u{0}".chars().collect();
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let len = (next() % 24) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let decoded = super::percent_decode(&s);
            if !s.contains('%') {
                assert_eq!(decoded, s);
            }
            for key in ["state", "code", "a", ""] {
                if let Some(v) = super::query_param(&s, key) {
                    assert!(s.contains(v), "{s:?} {key:?} {v:?}");
                }
            }
        }
        assert_eq!(super::percent_decode("a%20b%zz%"), "a b%zz%");
        assert_eq!(super::query_param("x=1&code=ab%2F", "code"), Some("ab%2F"));
    }
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn in_site(site: u16, subnet: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, site, subnet, 0, 0, 0, 1))
    }

    #[test]
    fn someone_over_their_limit_does_not_spend_their_sites_budget() {
        let flows = Flows::default();
        let one = in_site(1, 1);
        assert_eq!((0..30).filter(|_| flows.admit(one)).count(), 10);
        let others = (2..200).filter(|n| flows.admit(in_site(1, *n))).count();
        assert!((54..=56).contains(&others), "{others}");
    }

    #[test]
    fn a_site_over_its_budget_does_not_spend_its_blocks() {
        let flows = Flows::default();
        let began = Instant::now();
        let site = (0..1000).filter(|n| flows.admit(in_site(1, *n))).count();
        assert!((64..=66).contains(&site), "{site}");
        let others = (2..1000).filter(|s| flows.admit(in_site(*s, 0))).count();
        let most = 192 + began.elapsed().as_secs() as usize + 2;
        assert!((190..=most).contains(&others), "{others}");
    }

    /// Limiters no budget hangs on anymore go, and one still refilling stays, so the
    /// prune hands no budget back.
    #[test]
    fn the_limiters_do_not_outlive_their_use() {
        let flows = Flows::default();
        let spent = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!((0..11).filter(|_| flows.admit(spent)).count(), 10);
        fill_limiters(&flows);
        assert!(flows.admit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8))));
        assert!(limiters_at_most(&flows, MAX_LIMITERS));
        assert!(!flows.admit(spent), "the prune handed its budget back");
    }

    /// The walk locks every shard and frees nothing while budgets refill, so a flood
    /// past `MAX_LIMITERS` must not get it on every start.
    #[test]
    fn the_limiters_are_pruned_at_most_every_thirty_seconds() {
        let flows = Flows::default();
        let anyone = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        fill_limiters(&flows);
        assert!(flows.admit(anyone));
        assert!(limiters_at_most(&flows, MAX_LIMITERS), "open at first");

        fill_limiters(&flows);
        assert!(flows.admit(anyone));
        assert!(!limiters_at_most(&flows, MAX_LIMITERS), "too soon");

        let past = util::now_secs() - PRUNE_SECS;
        flows.pruned.store(past, Ordering::Relaxed);
        assert!(flows.admit(anyone));
        assert!(limiters_at_most(&flows, MAX_LIMITERS), "due again");
    }

    fn fill_limiters(flows: &Flows) {
        for i in 0..5000u32 {
            let key = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            for map in [&flows.starts, &flows.site_starts, &flows.block_starts] {
                map.insert(key, RateLimiter::new(10.0, 1.0 / 30.0));
            }
        }
    }

    fn limiters_at_most(flows: &Flows, most: usize) -> bool {
        [&flows.starts, &flows.site_starts, &flows.block_starts]
            .iter()
            .all(|m| m.len() <= most)
    }

    /// A flow started `age` seconds ago by `who`.
    fn put_flow(flows: &Flows, who: u32, age: u64, stage: Stage) -> [u8; 32] {
        let ticket: [u8; 32] = rand::random();
        let state = util::b64u(&ticket);
        flows.by_state.insert(state.clone(), ticket);
        flows.by_ticket.insert(
            ticket,
            Flow {
                kind: Kind::Discord,
                cookie: String::new(),
                state,
                code: String::new(),
                choices: Default::default(),
                purpose: Purpose::SignIn,
                started: Instant::now() - Duration::from_secs(age),
                stage,
                who: IpAddr::V4(Ipv4Addr::from(who)),
            },
        );
        ticket
    }

    /// Two starts at the cap can both insert, and each pass would then only hold the
    /// table where it stands.
    #[test]
    fn a_table_over_its_cap_comes_back_under_it() {
        let flows = Flows::default();
        for i in 0..MAX_FLOWS + 5 {
            put_flow(&flows, i as u32, 0, Stage::Open);
        }
        flows.sweep();
        assert_eq!(flows.by_ticket.len(), MAX_FLOWS - 1);
        assert_eq!(flows.by_state.len(), MAX_FLOWS - 1);
    }

    /// Older flows of smaller holders stay, and being back from the provider, which
    /// one request of the holder's own buys, spares nothing.
    #[test]
    fn a_full_table_takes_the_oldest_of_whoever_holds_the_most() {
        let flows = Flows::default();
        let lone = put_flow(&flows, 1, 500, Stage::Open);
        let smaller = put_flow(&flows, 2, 400, Stage::Open);
        for _ in 1..1000 {
            put_flow(&flows, 2, 300, Stage::Open);
        }
        let back = Stage::Back {
            provider_code: String::new(),
            page_key: String::new(),
        };
        let oldest = put_flow(&flows, 3, 200, back);
        let next = put_flow(&flows, 3, 100, Stage::Open);
        while flows.by_ticket.len() < MAX_FLOWS {
            put_flow(&flows, 3, 0, Stage::Open);
        }
        flows.sweep();
        assert!(flows.by_ticket.contains_key(&lone));
        assert!(flows.by_ticket.contains_key(&smaller));
        assert!(!flows.by_ticket.contains_key(&oldest));
        assert!(flows.by_ticket.contains_key(&next));
    }

    /// `sweep` runs on every start: a table with room loses nothing young.
    #[test]
    fn a_table_with_room_drops_only_what_timed_out() {
        let flows = Flows::default();
        let young = put_flow(&flows, 1, 500, Stage::Open);
        let timed_out = put_flow(&flows, 1, 700, Stage::Open);
        flows.sweep();
        assert!(flows.by_ticket.contains_key(&young));
        assert!(!flows.by_ticket.contains_key(&timed_out));
    }
}
