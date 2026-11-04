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
//! The code on the page is against somebody sending a person their own link. It
//! is not perfect (they can send the code along), which is why a person who got
//! this far has still opened nothing.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use voipc_protocol::messages::{AccountReply, AuthContinue, AuthStep, ServerMessage};
use voipc_protocol::types::{LinkedProvider, PowChallenge, ProviderKind, VaultBlob};

use super::{
    next, refused, second_factor, step, unexpected, vault_item_ok, Relay, SignedIn, BUSY,
    RESET_KEY_LEN, SLOT_RESET, STEP_WAIT, VAULT_MAX_ITEMS, VAULT_NS, VAULT_TOTAL_BYTES,
};
use crate::state::{RateLimiter, ServerState};

/// Where a provider sends the browser back (l4f's own path) and where the
/// page's form goes.
pub const CALLBACK_PREFIX: &str = "/account/oauth/";
pub const CONFIRM_PATH: &str = "/account/oauth/confirm";

/// l4f's sealed flow expires after as long (`FLOW_SECS` in its `social.rs`).
const FLOW_LIFE: Duration = Duration::from_secs(600);
/// Open flows, all addresses. Each holds a few hundred bytes.
const MAX_FLOWS: usize = 4096;
/// A person choosing what opens the account, and typing a 52-letter key.
const CHOICE_WAIT: Duration = Duration::from_secs(300);
/// A person walking to their other device.
const PAIR_WAIT: Duration = Duration::from_secs(120);
/// What the app takes for "not yet" (`AuthStep::ProviderPending` says it first).
pub const NOT_YET: &str = "Not finished in the browser yet.";
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
    Ok(Some(OAuth::new(l4f_accounts::oauth::client(None)?, providers)))
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
    Signup { cookie: String },
    Failed(String),
}

enum Stage {
    /// The browser is at the provider.
    Open,
    /// The provider sent it back with this; waiting for the person to tap.
    Back { provider_code: String },
    /// Tapped; the provider is being asked. A second tap ends here.
    Asking,
    Done(Outcome),
}

struct Flow {
    kind: Kind,
    /// l4f's sealed flow. It never leaves the relay: there is no browser cookie
    /// to bind, which is what the code on the page stands in for.
    cookie: String,
    state: String,
    code: String,
    /// The code and two others, in the order the page shows them.
    choices: [String; 3],
    purpose: Purpose,
    started: Instant,
    stage: Stage,
}

/// The flows in progress.
#[derive(Default)]
pub struct Flows {
    by_ticket: DashMap<[u8; 32], Flow>,
    by_state: DashMap<String, [u8; 32]>,
    /// Flows per address (`ConnLimits` key): each asks a provider nothing yet,
    /// but holds memory for ten minutes.
    starts: DashMap<IpAddr, RateLimiter>,
}

impl Flows {
    fn remove(&self, ticket: &[u8; 32]) -> Option<Flow> {
        let (_, flow) = self.by_ticket.remove(ticket)?;
        self.by_state.remove(&flow.state);
        Some(flow)
    }

    /// Drops what timed out.
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
    }
}

fn three_digits() -> String {
    rand::thread_rng().gen_range(100..1000).to_string()
}

fn code_and_choices() -> (String, [String; 3]) {
    let code = three_digits();
    let mut others = Vec::with_capacity(2);
    while others.len() < 2 {
        let other = three_digits();
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
        self.accounts.oauth_kinds().into_iter().map(kind_from).collect()
    }

    /// A new flow: where to send the browser, the code to show, and the ticket.
    fn flow_begin(
        &self,
        kind: ProviderKind,
        purpose: Purpose,
        intent: Intent,
        user: Option<&User>,
        ip: IpAddr,
    ) -> Result<(String, String, [u8; 32]), String> {
        let allowed = self
            .providers
            .starts
            .entry(crate::limit_key(ip))
            .or_insert_with(|| RateLimiter::new(10.0, 1.0 / 30.0))
            .try_consume();
        if !allowed {
            return Err("Too many sign-ins from your address. Try again later.".into());
        }
        self.providers.sweep();
        if self.providers.by_ticket.len() >= MAX_FLOWS {
            return Err(BUSY.into());
        }
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
        let (code, choices) = code_and_choices();
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
    ) -> Result<(), String> {
        let (url, code, ticket) = self.flow_begin(kind, Purpose::SignIn, Intent::Login, None, ip)?;
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
    p{line-height:1.5}";

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
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(PAGE_CSP));
    // The address holds the provider's code
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn ended_page() -> Response<Full<Bytes>> {
    page(StatusCode::GONE, "This sign-in has ended", &format!("<p>{ENDED}</p>"))
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|p| p.strip_prefix(key)?.strip_prefix('='))
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
/// the provider nothing yet: that waits for the person to tap the code.
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
    match query_param(query, "code") {
        Some(code) if matches!(flow.stage, Stage::Open) => {
            flow.stage = Stage::Back {
                provider_code: percent_decode(code),
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
        // A reload: the same page again
        _ => {}
    }
    if !matches!(flow.stage, Stage::Back { .. }) {
        return ended_page();
    }
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
             <input type=\"hidden\" name=\"state\" value=\"{oauth_state}\">{buttons}</form>\
             <p>If you did not start this in your own app, close this page: someone may be \
             trying to sign in as you.</p>",
            oauth_state = html_attr(&flow.state),
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
    let Some(ticket) = relay.providers.by_state.get(oauth_state).map(|t| *t) else {
        return ended_page();
    };
    let taken = {
        let Some(mut flow) = relay.providers.by_ticket.get_mut(&ticket) else {
            return ended_page();
        };
        let Stage::Back { provider_code } = &flow.stage else {
            return ended_page();
        };
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
        (flow.kind, flow.cookie.clone(), flow.state.clone(), provider_code, flow.purpose)
    };
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
                Ok(_) => Outcome::Failed("unexpected sign-in step".into()),
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
                Some(reason) => page(
                    StatusCode::OK,
                    "That did not work",
                    &format!("<p>{}</p>", html_text(&reason)),
                ),
                None => back_to_the_app(),
            }
        }
        Purpose::Account { session_id } => {
            relay.providers.remove(&ticket);
            finish_for_account(
                state, &relay, session_id, kind, &cookie, &oauth_state, &provider_code, ip,
            )
            .await;
            back_to_the_app()
        }
    }
}

fn html_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn back_to_the_app() -> Response<Full<Bytes>> {
    page(
        StatusCode::OK,
        "Done",
        "<p>You can close this page and go back to the app.</p>",
    )
}

/// A signed-in connection's link or proof. What it comes to reaches the
/// connection; if that is gone, the next `ProviderList` shows a link.
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
) {
    let session = state.sessions.get(&session_id).and_then(|s| {
        s.account
            .as_ref()
            .map(|a| (a.user.clone(), a.info.clone(), s.control_tx.clone()))
    });
    let Some((user, info, tx)) = session else {
        return;
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
    let answer = match done {
        Ok((SocialOutcome::Linked, _)) => AccountReply::ProviderDone {
            kind: kind_from(kind),
            link: true,
        },
        Ok((SocialOutcome::SteppedUp(fresh), _)) => {
            put_session(state, session_id, fresh);
            AccountReply::ProviderDone {
                kind: kind_from(kind),
                link: false,
            }
        }
        Ok(_) => refused("ProviderStart", "unexpected sign-in step"),
        Err(e) => refused("ProviderStart", e.message()),
    };
    let _ = crate::session::send_msg(&tx, &ServerMessage::Account(answer));
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
    ctx: &l4f_accounts::service::Ctx,
    ip: IpAddr,
    answers: &mut u32,
) -> Result<SignedIn, String> {
    let ticket: [u8; 32] = ticket.try_into().map_err(|_| ENDED.to_string())?;
    let not_yet = relay.providers.by_ticket.get(&ticket).map(|f| {
        f.started.elapsed() <= FLOW_LIFE && !matches!(f.stage, Stage::Done(_))
    });
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
            signup(relay, stream, buf, ctx, &cookie, answers, ip).await?
        }
        Stage::Done(Outcome::Failed(reason)) => return Err(reason),
        _ => return Err(ENDED.into()),
    };
    let token = session.token.clone();
    let r = finish(state, relay, stream, buf, session, answers, ip).await;
    if r.is_err() {
        let _ = relay.accounts.logout(&token).await;
    }
    r
}

/// The provider knows this person and nobody here does, and sign-up is open.
async fn signup<S: AsyncRead + AsyncWrite + Unpin>(
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    ctx: &l4f_accounts::service::Ctx,
    cookie: &str,
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
        let proof = pow::Proof {
            altcha: &altcha,
            ts: &ts,
            ..Default::default()
        };
        let _work = relay.pending_slot(ip).ok_or_else(|| BUSY.to_string())?;
        match relay.accounts.oauth_signup(ctx, cookie, &name, proof).await {
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
        return Err("This account was opened just now, somewhere else.".into());
    }
    // What a claim that died halfway left, which nobody could open
    relay.store().delete_blobs(user, VAULT_NS).await.map_err(|_| gone())?;
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
    relay.set_identity(user, identity_key).await.map_err(|_| gone())
}

/// From a provider's sign-in to the keys: the same end as `super::finish`, except
/// that the vault has to be opened before anything else happens, and an identity
/// is never replaced here.
async fn finish<S: AsyncRead + AsyncWrite + Unpin>(
    state: &ServerState,
    relay: &Relay,
    stream: &mut S,
    buf: &mut BytesMut,
    session: NewSession,
    answers: &mut u32,
    ip: IpAddr,
) -> Result<SignedIn, String> {
    let gone = || "Something went wrong. Please try again.".to_string();
    let work = || relay.pending_slot(ip).ok_or_else(|| BUSY.to_string());
    let (user, info, scopes, blobs, known) = {
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
            AuthContinue::Claim { identity_key, vault } if claim_it => {
                let _work = work()?;
                claim(relay, user.id, &identity_key, &vault).await?;
                info!(user = %user.id.hex(), "account claimed through a provider");
                break identity_key;
            }
            AuthContinue::ProviderProof { signature } if !claim_it => {
                let key = known.as_deref().ok_or_else(unexpected)?;
                if !voipc_crypto::account::provider_proof_ok(
                    key,
                    &relay.relay_id,
                    &user.username,
                    &challenge,
                    &signature,
                ) {
                    return Err("That does not open this account.".into());
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
        return refuse_pair(stream, "Too many requests to your other device. Try again later.").await;
    }
    let other = state.account_sessions.get(&user.0).map(|s| *s);
    let Some(tx) = other.and_then(|id| state.sessions.get(&id).map(|s| s.control_tx.clone())) else {
        return refuse_pair(stream, "No other device of yours is online here.").await;
    };
    // In 32 bits: the apps' front ends hold it as a JS number
    let pair = u64::from(rand::random::<u32>());
    let (to_new, mut events) = mpsc::channel(4);
    relay.pairs.insert(pair, PairLink { user, to_new });
    let told = |reply: AccountReply| {
        crate::session::send_msg(&tx, &ServerMessage::Account(reply)).map_err(|_| ())
    };
    let r = async {
        if told(AccountReply::PairAsked { pair, commitment }).is_err() {
            return refuse_pair(stream, "Your other device did not answer.").await;
        }
        let nonce = match tokio::time::timeout(STEP_WAIT, events.recv()).await {
            Ok(Some(PairEvent::Nonce(nonce))) => nonce,
            _ => return refuse_pair(stream, "Your other device did not answer.").await,
        };
        step(stream, AuthStep::PairNonce { nonce }).await?;
        let AuthContinue::PairReveal { ephemeral, blind } =
            next(stream, buf, STEP_WAIT, answers).await?
        else {
            return Err(unexpected());
        };
        if told(AccountReply::PairRevealed { pair, ephemeral, blind }).is_err() {
            return refuse_pair(stream, "Your other device did not answer.").await;
        }
        match tokio::time::timeout(PAIR_WAIT, events.recv()).await {
            Ok(Some(PairEvent::Wrapped(wrapped))) => step(stream, AuthStep::PairWrapped { wrapped }).await,
            Ok(Some(PairEvent::Declined)) => refuse_pair(stream, "Your other device said no.").await,
            _ => refuse_pair(stream, "Your other device did not answer in time.").await,
        }
    }
    .await;
    relay.pairs.remove(&pair);
    let _ = told(AccountReply::PairEnded { pair });
    r
}

async fn refuse_pair<S: AsyncWrite + Unpin>(stream: &mut S, reason: &str) -> Result<(), String> {
    step(stream, AuthStep::PairRefused { reason: reason.into() }).await
}

impl Relay {
    /// `voipc-server admin reclaim`: an account back to unopened, for someone who
    /// lost every device and the recovery key. Only without a password: with one,
    /// a sign-in or a reset is the way back, and this would lock it out instead.
    pub async fn reclaim(&self, ctx: &l4f_accounts::service::Ctx, user: &User) -> Result<(), String> {
        let failed = |e: sqlx::Error| e.to_string();
        if user.has_password {
            return Err(format!(
                "{} has a password: it signs in with that, or resets it with the recovery key.",
                user.username
            ));
        }
        self.accounts
            .reset_2fa_as_host(ctx, user.id)
            .await
            .map_err(|e| e.message().to_string())?;
        self.store().delete_blobs(user.id, VAULT_NS).await.map_err(failed)?;
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
        info!(user = %user.id.hex(), "account reclaimed from the shell");
        Ok(())
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
) -> AccountReply {
    let intent = if link { Intent::Link } else { Intent::Reauth };
    let purpose = Purpose::Account { session_id };
    match relay.flow_begin(kind, purpose, intent, Some(user), ip) {
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
        return Ok(refused("ProviderUnlink", "That provider is not linked here."));
    };
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
