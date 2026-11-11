//! The move from Discord, in the desktop app: the way to Discord with a bot's token, the way
//! to the relay for a run's frames, and the commands the wizard asks through. What is read
//! and what becomes of it is `voipc_import`'s; this only carries it.
//!
//! The token is in RAM alone, wiped when it goes: not in settings, not on the wire to the
//! relay, not in an event, a log or an error. What it reads stays in RAM too, for as long as
//! the run holds it. Nothing here writes a file.

use serde_json::Value;
use tauri::State;

use crate::app_state::AppState;

#[cfg(target_os = "android")]
const DESKTOP_ONLY: &str = "this import is in the desktop app";

/// What a token can reach. Holds the token.
#[tauri::command]
pub async fn import_open(
    state: State<'_, AppState>,
    server: String,
    token: String,
) -> Result<Value, String> {
    #[cfg(target_os = "android")]
    {
        let _ = (state, server, token);
        Err(DESKTOP_ONLY.into())
    }
    #[cfg(not(target_os = "android"))]
    {
        desktop::open(&state, &server, token).await
    }
}

/// The dry-run: everything `guild` (decimal) holds and what would become of it. Writes
/// nowhere. It asks the relay itself what the relay can say. What it read stays here for
/// `import_run`.
#[tauri::command]
pub async fn import_plan(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    server: String,
    guild: String,
) -> Result<Value, String> {
    #[cfg(target_os = "android")]
    {
        let _ = (app, state, server, guild);
        Err(DESKTOP_ONLY.into())
    }
    #[cfg(not(target_os = "android"))]
    {
        desktop::plan(&app, &state, &server, &guild).await
    }
}

/// Starts the run the page has begun (`ImportBegun`). `import-progress` follows it, and
/// `import-ended` says how it came out.
#[tauri::command]
pub async fn import_run(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    server: String,
    run: i64,
    choices: Value,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = (app, state, server, run, choices);
        Err(DESKTOP_ONLY.into())
    }
    #[cfg(not(target_os = "android"))]
    {
        desktop::run(&app, &state, &server, run, choices).await
    }
}

/// Stops what is going. Nothing is lost: the next run goes on from what the relay stored.
#[tauri::command]
pub fn import_stop(state: State<'_, AppState>, server: String) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = (state, server);
        Err(DESKTOP_ONLY.into())
    }
    #[cfg(not(target_os = "android"))]
    {
        state.import.stop(&server);
        Ok(())
    }
}

/// Lets go of the token and all that was read with it.
#[tauri::command]
pub fn import_forget(state: State<'_, AppState>, server: String) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = (state, server);
        Err(DESKTOP_ONLY.into())
    }
    #[cfg(not(target_os = "android"))]
    {
        state.import.forget(&server);
        Ok(())
    }
}

/// The one write there is: a post in `channel` (decimal), once, on the operator's click.
#[tauri::command]
pub async fn import_move_post(
    state: State<'_, AppState>,
    server: String,
    channel: String,
    text: String,
    everyone: bool,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = (state, server, channel, text, everyone);
        Err(DESKTOP_ONLY.into())
    }
    #[cfg(not(target_os = "android"))]
    {
        desktop::move_post(&state, &server, &channel, &text, everyone).await
    }
}

#[cfg(not(target_os = "android"))]
pub use desktop::ImportHub;

#[cfg(not(target_os = "android"))]
mod desktop {
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use serde_json::{json, Value};
    use tokio::sync::{oneshot, watch};
    use voipc_crypto::account::Zeroizing;
    use voipc_import::api::{Api, Method, Req, Resp, Transport};
    use voipc_import::plan::{self, Choices, Here, Opening, Plan, PlannedEmote, Read};
    use voipc_import::run::{self as driver, EmoteSink, Job, Outcome, Progress, RelayLink, Stop};
    use voipc_protocol::messages::{
        AccountReply, AccountRequest, AdminOp, AdminReply, ClientMessage,
    };
    use voipc_protocol::types::MoveFilter;

    use crate::app_state::{conn, AppState};
    use crate::emote_sources::desktop::{
        bearer, body_up_to, client, get, host_ok, MAX_IMAGE, NOT_A_HOST,
    };
    use crate::emote_sources::{discord_emoji, discord_sticker, Item};
    use crate::files::Files;
    use crate::network::{emit_server, ControlTx};

    /// One answer may be slow: a whole page of a busy channel.
    const TIMEOUT: Duration = Duration::from_secs(30);
    /// 100 messages, each with what it replies to, at worst.
    const MAX_PAGE: usize = 16 << 20;
    /// The longest post Discord takes.
    const MAX_POST: usize = 2000;
    /// With nothing going for this long, the token goes: a finished run still needs it for
    /// the move post, but no one should have to remember to come back.
    const IDLE: Duration = Duration::from_secs(60 * 60);
    /// A person reads no faster.
    const SHOWN_EVERY: Duration = Duration::from_millis(500);

    const NO_TOKEN: &str = "Enter the bot's token again.";
    const NO_DRY_RUN: &str = "Read the server first: what it holds is not here any more.";
    const GOING: &str = "One is going already. Stop it first.";
    const STOPPED: &str = "Stopped.";
    const CUT: &str = "The connection to the server was lost. Nothing is lost: run it again \
                       to go on from here.";
    const NOT_ACKNOWLEDGED: &str = "Tick what copying members' messages means first.";
    const LEFT_IT: &str = "That was cancelled.";
    const NOT_A_CHANNEL: &str = "That is not a channel.";
    const POST_LENGTH: &str = "A post is 1 to 2000 characters.";
    /// The form Discord's docs require of every request to its API.
    const USER_AGENT: &str = concat!(
        "DiscordBot (https://github.com/luki4fun/VoIPC, ",
        env!("CARGO_PKG_VERSION"),
        ")"
    );

    /// The way to Discord: the one place the token is read. No `Debug`.
    pub struct Discord {
        client: reqwest::Client,
        token: Zeroizing<String>,
    }

    impl Discord {
        fn new(token: &str) -> Result<Self, String> {
            let token = Zeroizing::new(token.trim().to_owned());
            if token.is_empty() {
                return Err("a bot token is needed".into());
            }
            bearer(&Zeroizing::new(format!("Bot {}", *token)))?;
            Ok(Discord {
                client: client(TIMEOUT)?,
                token,
            })
        }

        /// A request as it would go. Nothing but a fixed host is asked, and the token goes
        /// only where `auth` says, in one sensitive header.
        fn made(&self, req: Req) -> Result<reqwest::Request, String> {
            let url = reqwest::Url::parse(&req.url).map_err(|_| "not an address".to_string())?;
            if !host_ok(&url) {
                return Err(NOT_A_HOST.into());
            }
            let mut out = match req.method {
                Method::Get => self.client.get(url),
                Method::Post => self
                    .client
                    .post(url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json"),
            }
            .header(reqwest::header::USER_AGENT, USER_AGENT);
            if req.auth {
                let auth = Zeroizing::new(format!("Bot {}", *self.token));
                out = out.header(reqwest::header::AUTHORIZATION, bearer(&auth)?);
            }
            if let Some(body) = req.body {
                out = out.body(body);
            }
            out.build().map_err(|e| e.without_url().to_string())
        }
    }

    impl Transport for Discord {
        fn request(&self, req: Req) -> impl Future<Output = Result<Resp, String>> + Send {
            let made = self.made(req);
            let http = self.client.clone();
            async move {
                let mut res = http
                    .execute(made?)
                    .await
                    .map_err(|e| e.without_url().to_string())?;
                let status = res.status().as_u16();
                let headers = res
                    .headers()
                    .iter()
                    .filter_map(|(n, v)| Some((n.as_str().to_owned(), v.to_str().ok()?.to_owned())))
                    .collect();
                let body = body_up_to(&mut res, MAX_PAGE).await?;
                Ok(Resp {
                    status,
                    headers,
                    body,
                })
            }
        }
    }

    /// What a dry-run found: in RAM, for as long as the wizard needs it.
    struct Dry {
        read: Read,
        here: Here,
    }

    /// What a frame asked, which is how its reply is known: a reply names no frame, and a
    /// panel may ask for the same kinds of thing beside a run.
    enum Asked {
        Facts,
        Status,
        Excluded,
        Accounts {
            search: String,
            offset: u32,
            filter: MoveFilter,
        },
        Cursors,
        Wishes,
        Roles,
        Channels,
        Members,
        Bans,
        Stored,
        Ended,
        Other,
    }

    impl Asked {
        fn of(op: &AdminOp) -> Self {
            match op {
                AdminOp::ImportFacts => Asked::Facts,
                AdminOp::MoveStatus => Asked::Status,
                AdminOp::MoveExcluded { .. } => Asked::Excluded,
                AdminOp::MoveAccounts {
                    search,
                    offset,
                    filter,
                } => Asked::Accounts {
                    search: search.clone(),
                    offset: *offset,
                    filter: *filter,
                },
                AdminOp::ImportCursors { .. } => Asked::Cursors,
                AdminOp::ArchiveWishes { .. } => Asked::Wishes,
                AdminOp::ImportRoles { .. } => Asked::Roles,
                AdminOp::ImportCategories { .. } | AdminOp::ImportChannels { .. } => {
                    Asked::Channels
                }
                AdminOp::ImportMembers { .. } => Asked::Members,
                AdminOp::ImportBans { .. } => Asked::Bans,
                AdminOp::ImportEmote { .. }
                | AdminOp::ImportThreads { .. }
                | AdminOp::ImportMessages { .. } => Asked::Stored,
                AdminOp::ImportEnd { .. } => Asked::Ended,
                _ => Asked::Other,
            }
        }

        fn takes(&self, reply: &AccountReply) -> bool {
            let reply = match reply {
                // The refusals that are not `ImportRefused`: too many requests, or `*` lost
                AccountReply::Error { .. } => return true,
                AccountReply::Admin(reply) => reply,
                _ => return false,
            };
            match (self, reply) {
                (Asked::Facts, AdminReply::ImportFacts { .. })
                | (Asked::Status, AdminReply::MoveStatus { .. })
                | (Asked::Excluded, AdminReply::MoveExcluded { .. })
                | (Asked::Cursors, AdminReply::ImportCursors { .. })
                | (Asked::Wishes, AdminReply::ArchiveWishes { .. })
                | (Asked::Roles, AdminReply::ImportRolesDone { .. })
                | (Asked::Channels, AdminReply::ImportChannelsDone { .. })
                | (Asked::Members, AdminReply::ImportMembersDone { .. })
                | (Asked::Bans, AdminReply::ImportBansDone { .. })
                | (Asked::Stored, AdminReply::ImportAcked { .. })
                | (Asked::Ended, AdminReply::ImportEnded { .. }) => true,
                (
                    Asked::Roles
                    | Asked::Channels
                    | Asked::Members
                    | Asked::Bans
                    | Asked::Stored
                    | Asked::Ended,
                    AdminReply::ImportRefused { .. },
                ) => true,
                (
                    Asked::Accounts {
                        search,
                        offset,
                        filter,
                    },
                    AdminReply::MoveAccounts {
                        search: s,
                        offset: o,
                        filter: f,
                        ..
                    },
                ) => search == s && offset == o && filter == f,
                _ => false,
            }
        }
    }

    /// Only a run asks these, so they never go to the page: 8 a second, and `ImportCursors`
    /// and others in numbers past what JavaScript can hold.
    fn only_a_run_asks(reply: &AdminReply) -> bool {
        matches!(
            reply,
            AdminReply::ImportRolesDone { .. }
                | AdminReply::ImportMembersDone { .. }
                | AdminReply::ImportBansDone { .. }
                | AdminReply::ImportChannelsDone { .. }
                | AdminReply::ImportAcked { .. }
                | AdminReply::ImportCursors { .. }
                | AdminReply::ArchiveWishes { .. }
                | AdminReply::ImportEnded { .. }
                | AdminReply::ImportRefused { .. }
        )
    }

    struct Waiter {
        asked: Asked,
        answer: oneshot::Sender<Result<AdminReply, Stop>>,
    }

    /// While something is going: its one frame in flight, and what the page has asked around
    /// it. The relay answers a connection in order and a reply names no request, so this is
    /// what tells a panel click's refusal from the run's own: the first must not stop a run.
    #[derive(Default)]
    struct Wire {
        waiter: Option<Waiter>,
        /// Asks of the page's not answered yet.
        page_out: u32,
        /// Those of them sent ahead of the frame in flight, and so answered ahead of it.
        page_ahead: u32,
    }

    impl Wire {
        fn for_the_driver(&mut self, reply: &AccountReply) -> bool {
            let takes = self
                .waiter
                .as_ref()
                .is_some_and(|w| !w.answer.is_closed() && w.asked.takes(reply));
            match reply {
                // A refusal names no step, so it goes by the order they were sent in
                AccountReply::Error { request, .. } if request == "Admin" => {
                    if self.page_ahead > 0 {
                        self.page_ahead -= 1;
                        self.page_out -= 1;
                        false
                    } else if takes {
                        true
                    } else {
                        self.page_out = self.page_out.saturating_sub(1);
                        false
                    }
                }
                // The page reads this list too, and the reply names no `after`: one of its pages
                // answered ahead of the run's first read passed for it, and the run stopped
                // reading at that page, short of who asked for their posts to go (W2-29). In
                // order then. A page ask never answered costs the run this answer, and it
                // stops for want of one, to be gone on with.
                AccountReply::Admin(AdminReply::MoveExcluded { .. })
                    if takes && self.page_ahead > 0 =>
                {
                    self.page_ahead -= 1;
                    self.page_out -= 1;
                    false
                }
                AccountReply::Admin(r) if takes || only_a_run_asks(r) => {
                    // So all the page asked ahead of that frame is answered, or never will be
                    self.page_out -= self.page_ahead;
                    self.page_ahead = 0;
                    takes
                }
                AccountReply::Admin(_) => {
                    self.page_ahead = self.page_ahead.saturating_sub(1);
                    self.page_out = self.page_out.saturating_sub(1);
                    false
                }
                _ => false,
            }
        }
    }

    /// What one server's move holds.
    struct Slot<T> {
        api: Arc<Api<T>>,
        dry: Option<Arc<Dry>>,
        /// What is going, and how to stop it. The number is whose it is.
        going: Option<(u64, watch::Sender<bool>)>,
        wire: Wire,
        /// The last use: an hour after it, with this still the last, the token goes.
        used: u64,
    }

    /// The token and the run, per server. No `Debug`.
    pub struct ImportHub<T = Discord> {
        slots: Mutex<HashMap<String, Slot<T>>>,
        /// Each use and each run its own number, whatever slot it is in.
        next: AtomicU64,
        /// The number of each server's last `forget`. A token sent to Discord before it stays
        /// unheld: the wizard it was for has been left. Under `slots`.
        forgotten: Mutex<HashMap<String, u64>>,
        /// The same, of the last `forget_all`: for any server, known here or not.
        forgotten_all: AtomicU64,
        /// Per server, apart from the token's slot, which goes after an hour.
        uploaded: Mutex<HashMap<String, Uploaded>>,
    }

    /// What this app put in a server's emote store for a Discord emote, by its id: the name
    /// and the picture. A run cut between that and its ledger frame left it listed and in no
    /// ledger, and a server read again names that emote anew (`foo_2`, `foo` being taken).
    /// This is how the next run still finds the first, which no undo would otherwise take
    /// (W2-27). Only for as long as the app runs.
    type Uploaded = Arc<Mutex<HashMap<u64, (String, [u8; 32])>>>;

    impl<T> Default for ImportHub<T> {
        fn default() -> Self {
            ImportHub {
                slots: Mutex::default(),
                next: AtomicU64::new(1),
                forgotten: Mutex::default(),
                forgotten_all: AtomicU64::new(0),
                uploaded: Mutex::default(),
            }
        }
    }

    type Emit = Arc<dyn Fn(&str, Value) + Send + Sync>;

    /// Something going, until this drops.
    struct Going<T: Send + Sync + 'static> {
        hub: Arc<ImportHub<T>>,
        server: String,
        ticket: u64,
        stopped: watch::Receiver<bool>,
        api: Arc<Api<T>>,
    }

    impl<T: Send + Sync + 'static> Drop for Going<T> {
        fn drop(&mut self) {
            if let Some(slot) = self.hub.lock().get_mut(&self.server) {
                if slot.going.as_ref().is_some_and(|(t, _)| *t == self.ticket) {
                    slot.going = None;
                    slot.wire = Wire::default();
                }
            }
            self.hub.keep_for_an_hour(&self.server);
        }
    }

    /// The way to the relay: one frame at a time, its reply back through `on_reply`.
    struct Link<T: Send + Sync + 'static> {
        hub: Arc<ImportHub<T>>,
        server: String,
        ticket: u64,
        tcp_tx: ControlTx,
    }

    impl<T: Send + Sync + 'static> RelayLink for Link<T> {
        async fn call(&mut self, op: AdminOp) -> Result<AdminReply, Stop> {
            let answer = self
                .hub
                .send_frame(&self.server, self.ticket, &self.tcp_tx, op)?;
            tokio::select! {
                out = answer => out.unwrap_or_else(|_| Err(Stop::Gone(CUT.into()))),
                () = self.tcp_tx.closed() => Err(Stop::Gone(CUT.into())),
            }
        }
    }

    /// One press of Stop. `forget` presses it before it lets go of the button.
    async fn pressed(stop: &mut watch::Receiver<bool>) {
        if stop.wait_for(|on| *on).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    impl<T> ImportHub<T> {
        fn lock(&self) -> MutexGuard<'_, HashMap<String, Slot<T>>> {
            self.slots.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn uploaded(&self, server: &str) -> Uploaded {
            self.uploaded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(server.to_string())
                .or_default()
                .clone()
        }

        fn number(&self) -> u64 {
            self.next.fetch_add(1, Ordering::Relaxed)
        }

        fn api(&self, server: &str) -> Result<Arc<Api<T>>, String> {
            self.lock()
                .get(server)
                .map(|s| s.api.clone())
                .ok_or_else(|| NO_TOKEN.to_string())
        }

        /// An account reply on `server`'s connection: for what is going, or gone with it, or
        /// (the answer) for the page.
        pub fn on_reply(&self, server: &str, reply: AccountReply) -> Option<AccountReply> {
            let run_only = matches!(&reply, AccountReply::Admin(r) if only_a_run_asks(r));
            let mut slots = self.lock();
            let Some(wire) = slots
                .get_mut(server)
                .filter(|s| s.going.is_some())
                .map(|s| &mut s.wire)
            else {
                return (!run_only).then_some(reply);
            };
            if !wire.for_the_driver(&reply) {
                return (!run_only).then_some(reply);
            }
            if let Some(waiter) = wire.waiter.take() {
                let _ = waiter.answer.send(match reply {
                    AccountReply::Admin(r) => Ok(r),
                    AccountReply::Error { reason, .. } => Err(Stop::Said(reason)),
                    _ => Err(Stop::Gone(CUT.into())),
                });
            }
            None
        }

        /// A request of the page's, in its place among the run's frames.
        pub fn send_for_page(&self, server: &str, tcp_tx: &ControlTx, msg: &ClientMessage) {
            let mut slots = self.lock();
            if tcp_tx.send(msg).is_err() {
                return;
            }
            if matches!(msg, ClientMessage::Account(AccountRequest::Admin { .. })) {
                if let Some(slot) = slots.get_mut(server).filter(|s| s.going.is_some()) {
                    slot.wire.page_out += 1;
                }
            }
        }

        fn send_frame(
            &self,
            server: &str,
            ticket: u64,
            tcp_tx: &ControlTx,
            op: AdminOp,
        ) -> Result<oneshot::Receiver<Result<AdminReply, Stop>>, Stop> {
            let asked = Asked::of(&op);
            let mut slots = self.lock();
            let slot = slots
                .get_mut(server)
                .filter(|s| s.going.as_ref().is_some_and(|(t, _)| *t == ticket))
                .ok_or_else(|| Stop::Gone(STOPPED.into()))?;
            let (answer, reply) = oneshot::channel();
            slot.wire.waiter = Some(Waiter { asked, answer });
            slot.wire.page_ahead = slot.wire.page_out;
            // Under the lock, so that the count and the wire agree on the order
            tcp_tx
                .send(&ClientMessage::Account(AccountRequest::Admin {
                    op,
                    code: None,
                }))
                .map_err(|_| Stop::Gone(CUT.into()))?;
            Ok(reply)
        }

        pub fn stop(&self, server: &str) {
            if let Some((_, stop)) = self.lock().get(server).and_then(|s| s.going.as_ref()) {
                stop.send_replace(true);
            }
        }

        fn forgotten(&self) -> MutexGuard<'_, HashMap<String, u64>> {
            self.forgotten
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        }

        /// The token goes now, or with the run it stops.
        pub fn forget(&self, server: &str) {
            let slot = {
                let mut slots = self.lock();
                self.forgotten().insert(server.to_string(), self.number());
                slots.remove(server)
            };
            if let Some((_, stop)) = slot.as_ref().and_then(|s| s.going.as_ref()) {
                stop.send_replace(true);
            }
        }

        /// Everything, for a page starting from scratch: it knows of none of this, and nothing
        /// but this knows of a server whose connection is cut.
        pub fn forget_all(&self) {
            let slots: Vec<Slot<T>> = {
                let mut slots = self.lock();
                self.forgotten_all.store(self.number(), Ordering::Relaxed);
                slots.drain().map(|(_, slot)| slot).collect()
            };
            for (_, stop) in slots.iter().filter_map(|s| s.going.as_ref()) {
                stop.send_replace(true);
            }
        }
    }

    impl<T: Send + Sync + 'static> ImportHub<T> {
        fn take_up(self: &Arc<Self>, server: &str) -> Result<Going<T>, String> {
            let mut slots = self.lock();
            let slot = slots.get_mut(server).ok_or(NO_TOKEN)?;
            if slot.going.is_some() {
                return Err(GOING.into());
            }
            let ticket = self.number();
            let (stop, stopped) = watch::channel(false);
            slot.going = Some((ticket, stop));
            slot.wire = Wire::default();
            Ok(Going {
                hub: self.clone(),
                server: server.to_string(),
                ticket,
                stopped,
                api: slot.api.clone(),
            })
        }

        fn link(self: &Arc<Self>, going: &Going<T>, tcp_tx: ControlTx) -> Link<T> {
            Link {
                hub: self.clone(),
                server: going.server.clone(),
                ticket: going.ticket,
                tcp_tx,
            }
        }

        /// From now, an hour. Outside a runtime there is no clock to go by, and no run either.
        fn keep_for_an_hour(self: &Arc<Self>, server: &str) {
            let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                return;
            };
            let used = self.number();
            match self.lock().get_mut(server) {
                Some(slot) => slot.used = used,
                None => return,
            }
            let (hub, server) = (self.clone(), server.to_string());
            runtime.spawn(async move {
                tokio::time::sleep(IDLE).await;
                let mut slots = hub.lock();
                if slots
                    .get(&server)
                    .is_some_and(|s| s.used == used && s.going.is_none())
                {
                    slots.remove(&server);
                }
            });
        }

        /// `asked`: this hub's number from before Discord was asked about this token.
        fn hold(self: &Arc<Self>, server: &str, api: Api<T>, asked: u64) -> Result<(), String> {
            let mut slots = self.lock();
            if self.forgotten_all.load(Ordering::Relaxed) > asked
                || self.forgotten().get(server).is_some_and(|f| *f > asked)
            {
                return Err(LEFT_IT.into());
            }
            if slots.get(server).is_some_and(|s| s.going.is_some()) {
                return Err(GOING.into());
            }
            slots.insert(
                server.to_string(),
                Slot {
                    api: Arc::new(api),
                    dry: None,
                    going: None,
                    wire: Wire::default(),
                    used: 0,
                },
            );
            drop(slots);
            self.keep_for_an_hour(server);
            Ok(())
        }
    }

    impl<T: Transport + 'static> ImportHub<T> {
        /// What a token can reach, and it is held, unless the wizard was left meanwhile.
        async fn open(self: &Arc<Self>, server: &str, api: Api<T>) -> Result<Opening, String> {
            let asked = self.number();
            let opening = plan::open(&api).await?;
            self.hold(server, api, asked)?;
            Ok(opening)
        }

        /// The dry-run. It stays here until the next one, or until the token goes.
        async fn plan(
            self: &Arc<Self>,
            server: &str,
            guild: u64,
            tcp_tx: ControlTx,
            channels: Vec<(String, bool)>,
            emote_names: Vec<String>,
            emit: Emit,
        ) -> Result<Plan, String> {
            let going = self.take_up(server)?;
            let mut stopped = going.stopped.clone();
            let mut link = self.link(&going, tcp_tx);
            let api = going.api.clone();
            let (_progress, shown) = watch::channel(Progress::default());
            let showing = tokio::spawn(forward(shown, api.waiting(), emit));
            let reading = async {
                let here = driver::here_of(&mut link, guild, channels, emote_names).await?;
                let read = plan::read(&api, guild).await?;
                Ok::<_, String>(Dry { read, here })
            };
            let dry = tokio::select! {
                biased;
                () = pressed(&mut stopped) => Err(STOPPED.to_string()),
                dry = reading => dry,
            };
            showing.abort();
            let dry = dry?;
            let plan = plan::build(&dry.read, &dry.here);
            if let Some(slot) = self.lock().get_mut(server) {
                slot.dry = Some(Arc::new(dry));
            }
            Ok(plan)
        }

        /// Starts the run, and returns. `import-ended` is the end of it.
        fn start<E: EmoteSink + 'static>(
            self: &Arc<Self>,
            server: &str,
            run: i64,
            choices: Choices,
            tcp_tx: ControlTx,
            sink: impl FnOnce(Arc<Dry>) -> E,
            emit: Emit,
        ) -> Result<(), String> {
            if let Some(no) = refused_without_the_tick(&choices) {
                return Err(no.into());
            }
            let going = self.take_up(server)?;
            let dry = self
                .lock()
                .get(server)
                .and_then(|s| s.dry.clone())
                .ok_or(NO_DRY_RUN)?;
            let mut link = self.link(&going, tcp_tx);
            let mut sink = sink(dry.clone());
            tokio::spawn(async move {
                let (progress, shown) = watch::channel(Progress::default());
                let api = going.api.clone();
                let showing = tokio::spawn(forward(shown, api.waiting(), emit.clone()));
                let job = Job {
                    run,
                    choices,
                    pace: driver::FRAME_PACE,
                    stop: going.stopped.clone(),
                    progress,
                };
                // On a task of its own: a panic in it still ends in `import-ended`
                let drive = tokio::spawn(async move {
                    let here = dry.here.clone();
                    driver::run(api, &mut link, &mut sink, &dry.read, here, job).await
                });
                let out = drive.await;
                showing.abort();
                drop(going);
                emit("import-ended", ended(run, out));
            });
            Ok(())
        }
    }

    /// How a run came out. `notes` are for the end screen alone, and `kept` is what
    /// `ImportEnd` stores on the relay.
    fn ended(run: i64, out: Result<Outcome, tokio::task::JoinError>) -> Value {
        match out {
            Ok(out) => json!({
                "run": run,
                "stopped": out.stopped,
                "notes": out.report.end_screen(),
                "kept": out.report.kept(),
            }),
            Err(_) => json!({
                "run": run,
                "stopped": "The run failed here. Nothing is lost: run it again to go on.",
                "notes": [],
                "kept": "",
            }),
        }
    }

    /// As much of a run as the page shows: counts and a channel's name, and any wait.
    async fn forward(
        mut progress: watch::Receiver<Progress>,
        mut waiting: watch::Receiver<Option<String>>,
        emit: Emit,
    ) {
        loop {
            let shown = {
                let p = progress.borrow_and_update();
                json!({
                    "phase": p.phase,
                    "done": p.done,
                    "total": p.total,
                    "channel": p.channel,
                    "waiting": *waiting.borrow_and_update(),
                })
            };
            emit("import-progress", shown);
            tokio::time::sleep(SHOWN_EVERY).await;
            let more = tokio::select! {
                changed = progress.changed() => changed,
                changed = waiting.changed() => changed,
            };
            if more.is_err() {
                return;
            }
        }
    }

    fn refused_without_the_tick(choices: &Choices) -> Option<&'static str> {
        let options = plan::effective(&choices.options);
        (options.messages && !options.acknowledged).then_some(NOT_ACKNOWLEDGED)
    }

    /// Where a planned emote is, by the one rule `discord_listing` goes by too.
    fn picture_of(read: &Read, emote: &PlannedEmote) -> Option<Item> {
        if emote.sticker {
            let s = read.stickers.iter().find(|s| s.id == emote.id)?;
            discord_sticker(s.id, &s.name, Some(u64::from(s.format_type)))
        } else {
            let e = read.emojis.iter().find(|e| e.id == emote.id)?;
            Some(discord_emoji(e.id, &e.name, e.animated))
        }
    }

    /// An emote or sticker into the relay's store, by the way any other goes: fetched with
    /// no token, sanitized here, its pack left empty since a Discord server's name is never
    /// filled in.
    struct Sink {
        http: reqwest::Client,
        files: Arc<Files>,
        dry: Arc<Dry>,
        uploaded: Uploaded,
    }

    impl Sink {
        /// A picture as it came from Discord, into the relay's store. `Ok`: the name it is
        /// listed under.
        async fn store(&self, emote: &PlannedEmote, file: Vec<u8>) -> Result<String, String> {
            let access = self
                .files
                .emotes
                .as_ref()
                .ok_or("this server has no emotes")?;
            let max = if emote.sticker {
                access.max_sticker_bytes
            } else {
                access.max_emote_bytes
            } as usize;
            let made = crate::emotes::prepare(file, emote.sticker, max).await?;
            let hash = crate::emotes::sha256(&made.upload);
            // A run cut between the two left it listed and not in the ledger: this files it,
            // under the name this app gave it then, if the server was read again since
            let earlier = self
                .uploaded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&emote.id)
                .filter(|(_, h)| *h == hash)
                .map(|(name, _)| name.clone());
            for name in std::iter::once(emote.name.clone()).chain(earlier) {
                if self.files.emote_listed(&name, &hash) {
                    return Ok(name);
                }
            }
            self.uploaded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(emote.id, (emote.name.clone(), hash));
            crate::emotes::add(
                &self.files,
                emote.name.clone(),
                emote.sticker,
                String::new(),
                (
                    u16::try_from(made.w).unwrap_or(0),
                    u16::try_from(made.h).unwrap_or(0),
                ),
                &made.upload,
            )
            .await?;
            Ok(emote.name.clone())
        }
    }

    impl EmoteSink for Sink {
        async fn add(&mut self, emote: &PlannedEmote) -> Result<String, String> {
            let picture = picture_of(&self.dry.read, emote).ok_or("Discord does not list it")?;
            let file = get(&self.http, &picture.url, None, MAX_IMAGE).await?;
            self.store(emote, file).await
        }
    }

    fn emitter(app: &tauri::AppHandle, server: &str) -> Emit {
        let (app, server) = (app.clone(), server.to_string());
        Arc::new(move |event: &str, data: Value| emit_server(&app, &server, event, data))
    }

    /// What of `server`'s connection a dry-run and a run go through.
    async fn connection_of(
        state: &AppState,
        server: &str,
    ) -> Result<(ControlTx, Arc<Files>, Vec<(String, bool)>), String> {
        let connections = state.connections.read().await;
        let c = conn(&connections, server)?;
        if c.account.is_none() {
            return Err("Sign in with an account first.".into());
        }
        let channels = c
            .channels
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|ch| (ch.name.clone(), ch.text))
            .collect();
        Ok((c.tcp_tx.clone(), c.files.clone(), channels))
    }

    pub(super) async fn open(
        state: &AppState,
        server: &str,
        token: String,
    ) -> Result<Value, String> {
        let token = Zeroizing::new(token);
        connection_of(state, server).await?;
        let api = Api::new(Discord::new(&token)?);
        let opening = state.import.open(server, api).await?;
        serde_json::to_value(opening).map_err(|e| e.to_string())
    }

    pub(super) async fn plan(
        app: &tauri::AppHandle,
        state: &AppState,
        server: &str,
        guild: &str,
    ) -> Result<Value, String> {
        let guild = guild
            .parse()
            .map_err(|_| "A Discord server's id is a number.".to_string())?;
        let (tcp_tx, files, channels) = connection_of(state, server).await?;
        let plan = state
            .import
            .plan(
                server,
                guild,
                tcp_tx,
                channels,
                files.emote_names(),
                emitter(app, server),
            )
            .await?;
        serde_json::to_value(plan).map_err(|e| e.to_string())
    }

    pub(super) async fn run(
        app: &tauri::AppHandle,
        state: &AppState,
        server: &str,
        run: i64,
        choices: Value,
    ) -> Result<(), String> {
        let choices: Choices = serde_json::from_value(choices)
            .map_err(|_| "Those are not the wizard's choices.".to_string())?;
        let (tcp_tx, files, _) = connection_of(state, server).await?;
        let http = client(TIMEOUT)?;
        let uploaded = state.import.uploaded(server);
        state.import.start(
            server,
            run,
            choices,
            tcp_tx,
            |dry| Sink {
                http,
                files,
                dry,
                uploaded,
            },
            emitter(app, server),
        )
    }

    /// Why this post cannot go, whatever the page let through.
    fn post_of(channel: &str, text: &str) -> Result<u64, &'static str> {
        let channel = channel.parse().map_err(|_| NOT_A_CHANNEL)?;
        let chars = text.chars().count();
        if chars == 0 || chars > MAX_POST {
            return Err(POST_LENGTH);
        }
        Ok(channel)
    }

    pub(super) async fn move_post(
        state: &AppState,
        server: &str,
        channel: &str,
        text: &str,
        everyone: bool,
    ) -> Result<(), String> {
        let channel = post_of(channel, text)?;
        let api = state.import.api(server)?;
        let out = api.move_post(channel, text, everyone).await;
        state.import.keep_for_an_hour(server);
        out.map_err(|fail| fail.words().to_string())
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeMap;
        use std::path::Path;

        use bytes::BytesMut;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::mpsc;
        use voipc_import::api::BASE;
        use voipc_import::mock::Mock;
        use voipc_protocol::codec::{decode_client_msg, try_decode_frame, PROTOCOL_VERSION};
        use voipc_protocol::types::{ImportFacts, ImportOptions, Registration};

        use super::*;
        use crate::emote_sources::discord_listing;

        const SERVER: &str = "relay.example:9987";
        const GUILD: u64 = 1_190_000_000_000_000_001;
        const TOP_SAFE: u64 = (1 << 53) - 1;

        fn fixture(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    fixture(root, &path, files);
                } else if path.extension().is_some_and(|e| e == "json") {
                    let name = path.strip_prefix(root).unwrap().to_string_lossy();
                    files.insert(name.replace('\\', "/"), std::fs::read(&path).unwrap());
                }
            }
        }

        fn mock() -> Mock {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testkit/6-mock-discord");
            let mut files = BTreeMap::new();
            fixture(&root, &root, &mut files);
            Mock::new(files)
        }

        fn facts() -> ImportFacts {
            ImportFacts {
                backup_here: true,
                db_bytes: Some(1_048_576),
                max_users: 0,
                online: 1,
                registration: Registration::Invite,
                discord_sign_in: true,
                public_url: "https://voipc.example.net".into(),
                takes_guests: false,
                accounts: 0,
                channel_list_bytes: 200,
                channel_list_limit: 60 * 1024,
                categories: 0,
                max_categories: 200,
                emotes: 0,
                running: None,
                unfinished: None,
                cloud: true,
                last_options: None,
            }
        }

        /// What a relay says yes with, to whatever a run asks.
        fn answer(op: &AdminOp) -> AdminReply {
            match op {
                AdminOp::ImportFacts => AdminReply::ImportFacts { facts: facts() },
                AdminOp::ImportCursors { .. } => AdminReply::ImportCursors {
                    rows: Vec::new(),
                    more: false,
                },
                AdminOp::ArchiveWishes { .. } => AdminReply::ArchiveWishes {
                    rows: Vec::new(),
                    more: false,
                },
                AdminOp::MoveStatus => AdminReply::MoveStatus {
                    claimed: 0,
                    waiting: 0,
                    banned: 0,
                    power_waiting: 0,
                    excluded: 0,
                    unclaimed_days: 90,
                    runs: Vec::new(),
                },
                AdminOp::MoveExcluded { .. } => AdminReply::MoveExcluded {
                    ids: Vec::new(),
                    more: false,
                },
                AdminOp::MoveAccounts {
                    search,
                    offset,
                    filter,
                } => AdminReply::MoveAccounts {
                    search: search.clone(),
                    offset: *offset,
                    filter: *filter,
                    total: 0,
                    rows: Vec::new(),
                },
                AdminOp::ImportRoles { .. } => AdminReply::ImportRolesDone {
                    made: 1,
                    updated: 0,
                    skipped: Vec::new(),
                    power_changed: Vec::new(),
                },
                AdminOp::ImportCategories { .. } | AdminOp::ImportChannels { .. } => {
                    AdminReply::ImportChannelsDone {
                        refused: Vec::new(),
                    }
                }
                AdminOp::ImportMembers { .. } => AdminReply::ImportMembersDone {
                    made: 1,
                    updated: 0,
                    left_out: 0,
                    nicknames_dropped: 0,
                    unlinked: 0,
                    kept_power: 0,
                    failed: Vec::new(),
                },
                AdminOp::ImportBans { .. } => AdminReply::ImportBansDone {
                    made: 1,
                    converted: 0,
                    claimed: Vec::new(),
                    names_kept: Vec::new(),
                },
                AdminOp::ImportEmote { .. }
                | AdminOp::ImportThreads { .. }
                | AdminOp::ImportMessages { .. } => AdminReply::ImportAcked {
                    stored: 1,
                    skipped: 0,
                },
                AdminOp::ImportEnd { run, .. } => AdminReply::ImportEnded { run: *run },
                _ => panic!("a run does not ask this"),
            }
        }

        fn op_of(frame: &[u8]) -> AdminOp {
            let mut buf = BytesMut::from(frame);
            let payload = try_decode_frame(&mut buf).unwrap().unwrap();
            match decode_client_msg(&payload).unwrap() {
                ClientMessage::Account(AccountRequest::Admin { op, .. }) => op,
                _ => panic!("not an admin step"),
            }
        }

        struct Scene {
            hub: Arc<ImportHub<Mock>>,
            tcp_tx: ControlTx,
            frames: mpsc::UnboundedReceiver<Vec<u8>>,
            events: mpsc::UnboundedReceiver<(String, Value)>,
            emit: Emit,
        }

        fn scene() -> Scene {
            let hub = Arc::new(ImportHub::<Mock>::default());
            hub.hold(SERVER, Api::new(mock()), hub.number()).unwrap();
            let (out, frames) = mpsc::unbounded_channel();
            let (shown, events) = mpsc::unbounded_channel();
            Scene {
                hub,
                tcp_tx: ControlTx::new(out, PROTOCOL_VERSION),
                frames,
                events,
                emit: Arc::new(move |event: &str, data: Value| {
                    let _ = shown.send((event.to_string(), data));
                }),
            }
        }

        /// Answers everything in order, and says what went to the page.
        fn relay(
            hub: Arc<ImportHub<Mock>>,
            mut frames: mpsc::UnboundedReceiver<Vec<u8>>,
        ) -> mpsc::UnboundedReceiver<AccountReply> {
            let (page, to_page) = mpsc::unbounded_channel();
            tokio::spawn(async move {
                while let Some(frame) = frames.recv().await {
                    let reply = AccountReply::Admin(answer(&op_of(&frame)));
                    if let Some(reply) = hub.on_reply(SERVER, reply) {
                        let _ = page.send(reply);
                    }
                }
            });
            to_page
        }

        impl Scene {
            /// Goes through the dry-run with a relay that answers, and hands back `frames`.
            async fn dry(mut self) -> Self {
                let (hub, tcp_tx, emit) =
                    (self.hub.clone(), self.tcp_tx.clone(), self.emit.clone());
                let channels = vec![("General".to_string(), false)];
                let plan = hub.plan(SERVER, GUILD, tcp_tx, channels, Vec::new(), emit);
                tokio::pin!(plan);
                loop {
                    tokio::select! {
                        out = &mut plan => {
                            let json = serde_json::to_value(out.unwrap()).unwrap();
                            assert!(no_big_number(&json));
                            return self;
                        }
                        Some(frame) = self.frames.recv() => {
                            let reply = AccountReply::Admin(answer(&op_of(&frame)));
                            assert!(self.hub.on_reply(SERVER, reply).is_none());
                        }
                    }
                }
            }

            fn choices(&self) -> Choices {
                let slots = self.hub.lock();
                let dry = slots[SERVER].dry.clone().unwrap();
                let mut choices = plan::default_choices(&dry.read, &dry.here);
                choices.options.acknowledged = true;
                choices
            }

            fn call(&self) -> oneshot::Receiver<Result<AdminReply, Stop>> {
                self.frame(AdminOp::ImportMessages {
                    run: 1,
                    channel: 1,
                    thread: None,
                    high: 1,
                    rows: Vec::new(),
                })
            }

            fn frame(&self, op: AdminOp) -> oneshot::Receiver<Result<AdminReply, Stop>> {
                let ticket = self.hub.lock()[SERVER].going.as_ref().unwrap().0;
                self.hub
                    .send_frame(SERVER, ticket, &self.tcp_tx, op)
                    .unwrap()
            }

            fn panel_click(&self) {
                let op = AdminOp::PowerWaiting { offset: 0 };
                let msg = ClientMessage::Account(AccountRequest::Admin { op, code: None });
                self.hub.send_for_page(SERVER, &self.tcp_tx, &msg);
            }
        }

        #[derive(Default)]
        struct Recorder(Vec<String>);

        impl EmoteSink for Recorder {
            async fn add(&mut self, emote: &PlannedEmote) -> Result<String, String> {
                self.0.push(emote.name.clone());
                Ok(emote.name.clone())
            }
        }

        fn refused_op(reason: &str) -> AccountReply {
            AccountReply::Error {
                request: "Admin".into(),
                reason: reason.into(),
            }
        }

        fn acked() -> AccountReply {
            AccountReply::Admin(AdminReply::ImportAcked {
                stored: 1,
                skipped: 0,
            })
        }

        fn groups() -> AccountReply {
            AccountReply::Admin(AdminReply::Groups { groups: Vec::new() })
        }

        fn no_big_number(value: &Value) -> bool {
            match value {
                Value::Number(n) => n.as_u64().is_none_or(|n| n <= TOP_SAFE),
                Value::Array(list) => list.iter().all(no_big_number),
                Value::Object(map) => map.values().all(no_big_number),
                _ => true,
            }
        }

        async fn ended_of(
            events: &mut mpsc::UnboundedReceiver<(String, Value)>,
        ) -> Vec<(String, Value)> {
            let mut seen = Vec::new();
            let in_time = tokio::time::timeout(Duration::from_secs(24 * 3600), async {
                while let Some((event, data)) = events.recv().await {
                    let last = event == "import-ended";
                    seen.push((event, data));
                    if last {
                        return;
                    }
                }
            });
            assert!(in_time.await.is_ok(), "the run never said it ended");
            assert_eq!(seen.last().unwrap().0, "import-ended");
            seen
        }

        #[tokio::test(start_paused = true)]
        async fn import_run_refuses_without_the_tick() {
            let mut s = scene().dry().await;
            let mut choices = s.choices();
            choices.options.messages = true;
            choices.options.channels = true;
            choices.options.acknowledged = false;
            let out = s.hub.start(
                SERVER,
                1,
                choices.clone(),
                s.tcp_tx.clone(),
                |_| Recorder::default(),
                s.emit.clone(),
            );
            assert_eq!(out, Err(NOT_ACKNOWLEDGED.to_string()));
            assert!(s.frames.try_recv().is_err(), "nothing was asked of anyone");
            assert!(s.hub.lock()[SERVER].going.is_none());

            // What the tick is about is not on: nothing to tick
            choices.options.messages = false;
            assert_eq!(refused_without_the_tick(&choices), None);
            // Messages need channels, so with those off it is not on either
            choices.options.messages = true;
            choices.options.channels = false;
            assert_eq!(refused_without_the_tick(&choices), None);

            // The negative control: with the tick the very same choices go
            choices.options.channels = true;
            choices.options.acknowledged = true;
            assert_eq!(refused_without_the_tick(&choices), None);
            s.hub
                .start(
                    SERVER,
                    1,
                    choices,
                    s.tcp_tx.clone(),
                    |_| Recorder::default(),
                    s.emit.clone(),
                )
                .unwrap();
            assert!(s.hub.lock()[SERVER].going.is_some());
            s.hub.stop(SERVER);
        }

        #[tokio::test(start_paused = true)]
        async fn a_run_needs_its_dry_run() {
            let s = scene();
            let choices = Choices {
                options: ImportOptions {
                    channels: true,
                    roles: true,
                    permissions: true,
                    members: true,
                    bans: true,
                    emotes: true,
                    messages: false,
                    threads: false,
                    pins: false,
                    reactions: false,
                    anonymise: true,
                    acknowledged: false,
                },
                left_out: Default::default(),
                messages_on: Default::default(),
            };
            let out = s.hub.start(
                SERVER,
                1,
                choices,
                s.tcp_tx.clone(),
                |_| Recorder::default(),
                s.emit.clone(),
            );
            assert_eq!(out, Err(NO_DRY_RUN.to_string()));
            assert!(
                s.hub.lock()[SERVER].going.is_none(),
                "a refusal leaves nothing going"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn a_whole_run_goes_through_the_hub_and_no_frame_reaches_the_page() {
            let mut s = scene().dry().await;
            let choices = s.choices();
            let frames = std::mem::replace(&mut s.frames, mpsc::unbounded_channel().1);
            let mut page = relay(s.hub.clone(), frames);
            s.hub
                .start(
                    SERVER,
                    7,
                    choices,
                    s.tcp_tx.clone(),
                    |_| Recorder::default(),
                    s.emit.clone(),
                )
                .unwrap();
            assert!(
                s.hub.start(
                    SERVER,
                    7,
                    s.choices(),
                    s.tcp_tx.clone(),
                    |_| Recorder::default(),
                    s.emit.clone(),
                ) == Err(GOING.to_string()),
                "one at a time"
            );
            let started = tokio::time::Instant::now();
            let seen = ended_of(&mut s.events).await;
            let took = started.elapsed();
            let (_, end) = seen.last().unwrap();
            assert_eq!(end["run"], 7);
            assert_eq!(end["stopped"], Value::Null, "{end}");
            assert!(end["notes"].is_array());
            let kept: Value = serde_json::from_str(end["kept"].as_str().unwrap()).unwrap();
            assert!(kept["counts"]["channels"].as_u64().unwrap() > 0, "{kept}");
            assert!(page.try_recv().is_err(), "frames' answers stay here");

            let shown = seen
                .iter()
                .filter(|(event, _)| event == "import-progress")
                .collect::<Vec<_>>();
            assert!(!shown.is_empty());
            let at_most = took.as_millis() / SHOWN_EVERY.as_millis() + 2;
            assert!(
                shown.len() as u128 <= at_most,
                "{} in {took:?}",
                shown.len()
            );
            for (_, data) in &shown {
                for key in ["phase", "done", "total", "channel", "waiting"] {
                    assert!(data.get(key).is_some(), "{data}");
                }
            }
            for (_, data) in &seen {
                assert!(no_big_number(data), "{data}");
            }
            assert!(
                s.hub.lock()[SERVER].going.is_none(),
                "over, and the post may use the token"
            );
            assert!(s.hub.api(SERVER).is_ok());
        }

        #[tokio::test(start_paused = true)]
        async fn the_events_of_a_run_hold_no_ones_message() {
            let mut s = scene().dry().await;
            let choices = s.choices();
            let frames = std::mem::replace(&mut s.frames, mpsc::unbounded_channel().1);
            // What went over the wire is what anyone wrote, as this run read it
            let (seen_rows, mut rows_of) = mpsc::unbounded_channel();
            let hub = s.hub.clone();
            tokio::spawn(async move {
                let mut frames = frames;
                while let Some(frame) = frames.recv().await {
                    let op = op_of(&frame);
                    if let AdminOp::ImportMessages { rows, .. } = &op {
                        for row in rows {
                            let _ = seen_rows.send(row.body.clone());
                        }
                    }
                    let _ = hub.on_reply(SERVER, AccountReply::Admin(answer(&op)));
                }
            });
            s.hub
                .start(
                    SERVER,
                    7,
                    choices,
                    s.tcp_tx.clone(),
                    |_| Recorder::default(),
                    s.emit.clone(),
                )
                .unwrap();
            let seen = ended_of(&mut s.events).await;
            let mut bodies = Vec::new();
            while let Ok(body) = rows_of.try_recv() {
                if body.len() > 8 {
                    bodies.push(body);
                }
            }
            assert!(!bodies.is_empty(), "a run that read nothing proves nothing");
            let text = serde_json::to_string(&seen).unwrap();
            for body in bodies {
                assert!(!text.contains(&body), "{body} reached the page");
            }
        }

        #[tokio::test(start_paused = true)]
        async fn cursors_never_reach_the_page_with_nothing_going() {
            let hub = Arc::new(ImportHub::<Mock>::default());
            let run_only = [
                AdminReply::ImportCursors {
                    rows: vec![(u64::MAX, u64::MAX)],
                    more: false,
                },
                AdminReply::ArchiveWishes {
                    rows: vec![voipc_protocol::types::ArchiveWish {
                        author: u64::MAX,
                        channel: u64::MAX,
                        low: u64::MAX,
                        high: u64::MAX,
                        erase: true,
                    }],
                    more: false,
                },
                AdminReply::ImportChannelsDone {
                    refused: vec![(u64::MAX, "no".into())],
                },
                AdminReply::ImportRefused {
                    reason: "no".into(),
                    channel: Some(u64::MAX),
                },
                AdminReply::ImportAcked {
                    stored: 1,
                    skipped: 0,
                },
                AdminReply::ImportEnded { run: 1 },
                answer(&AdminOp::ImportRoles {
                    run: 1,
                    roles: Vec::new(),
                }),
                answer(&AdminOp::ImportMembers {
                    run: 1,
                    members: Vec::new(),
                }),
                answer(&AdminOp::ImportBans {
                    run: 1,
                    bans: Vec::new(),
                }),
            ];
            for reply in &run_only {
                let reply = AccountReply::Admin(reply.clone());
                assert!(hub.on_reply(SERVER, reply).is_none(), "no slot");
            }
            hub.hold(SERVER, Api::new(mock()), hub.number()).unwrap();
            for reply in &run_only {
                let reply = AccountReply::Admin(reply.clone());
                assert!(
                    hub.on_reply(SERVER, reply).is_none(),
                    "a token, nothing going"
                );
            }
            // The negative control: what is not a run's goes on
            assert!(hub.on_reply(SERVER, groups()).is_some());
            assert!(hub.on_reply(SERVER, refused_op("no")).is_some());
            let begun = AccountReply::Admin(AdminReply::ImportBegun {
                run: 1,
                resumed: false,
                backup: None,
            });
            assert!(hub.on_reply(SERVER, begun).is_some());
        }

        #[tokio::test(start_paused = true)]
        async fn a_panel_clicks_refusal_does_not_stop_the_frame_after_it() {
            let s = scene();
            let _going = s.hub.take_up(SERVER).unwrap();
            s.panel_click();
            let mut frame = s.call();
            let back = s
                .hub
                .on_reply(SERVER, refused_op("That is not waiting any more."));
            assert!(back.is_some(), "the panel asked first: it is the panel's");
            assert!(frame.try_recv().is_err(), "the frame waits on");
            assert!(s.hub.on_reply(SERVER, acked()).is_none());
            assert!(matches!(
                frame.try_recv(),
                Ok(Ok(AdminReply::ImportAcked { .. }))
            ));
            assert_eq!(s.hub.lock()[SERVER].wire.page_out, 0);
        }

        #[tokio::test(start_paused = true)]
        async fn too_many_requests_goes_to_the_frame_it_answers() {
            let s = scene();
            let _going = s.hub.take_up(SERVER).unwrap();
            // The negative control of the test above: nothing of the page's ahead of it
            let mut frame = s.call();
            s.panel_click();
            let says = "Too many requests at once; slow down.";
            assert!(s.hub.on_reply(SERVER, refused_op(says)).is_none());
            assert!(
                matches!(frame.try_recv(), Ok(Err(Stop::Said(why))) if why == says),
                "the driver sends its frame again"
            );
            // The panel's click was after the frame, and is the panel's whatever it says
            assert!(s.hub.on_reply(SERVER, refused_op(says)).is_some());
        }

        #[tokio::test(start_paused = true)]
        async fn a_panels_answers_are_told_from_the_drivers() {
            let s = scene();
            let _going = s.hub.take_up(SERVER).unwrap();
            let mut banned = s.frame(AdminOp::MoveAccounts {
                search: String::new(),
                offset: 0,
                filter: MoveFilter::Banned,
            });
            let list = |filter, offset| {
                AccountReply::Admin(AdminReply::MoveAccounts {
                    search: String::new(),
                    offset,
                    filter,
                    total: 0,
                    rows: Vec::new(),
                })
            };
            // Asked before this was going, so not counted, and not what the frame asked
            assert!(s.hub.on_reply(SERVER, groups()).is_some());
            assert!(s.hub.on_reply(SERVER, list(MoveFilter::All, 0)).is_some());
            assert!(s
                .hub
                .on_reply(SERVER, list(MoveFilter::Banned, 50))
                .is_some());
            assert!(banned.try_recv().is_err());
            assert!(s
                .hub
                .on_reply(SERVER, list(MoveFilter::Banned, 0))
                .is_none());
            assert!(banned.try_recv().is_ok());
        }

        #[tokio::test(start_paused = true)]
        async fn a_late_reply_of_a_stopped_frame_goes_nowhere() {
            let s = scene();
            let going = s.hub.take_up(SERVER).unwrap();
            let frame = s.call();
            // Stop drops the driver, and the frame may be on the relay already
            drop(frame);
            assert!(
                s.hub.on_reply(SERVER, acked()).is_none(),
                "no one to take it"
            );
            drop(going);
            assert!(
                s.hub.on_reply(SERVER, acked()).is_none(),
                "nothing going now"
            );

            // A run started right after, its first ask out: no late answer is read as its own
            let _again = s.hub.take_up(SERVER).unwrap();
            let mut first = s.frame(AdminOp::ImportFacts);
            assert!(s.hub.on_reply(SERVER, acked()).is_none());
            assert!(first.try_recv().is_err(), "an answer to something else");
            let good = AccountReply::Admin(AdminReply::ImportFacts { facts: facts() });
            assert!(s.hub.on_reply(SERVER, good).is_none());
            assert!(first.try_recv().is_ok());

            // A question whose asker has gone: its answer is no use to anyone here
            let gone = s.frame(AdminOp::MoveStatus);
            drop(gone);
            let status = AccountReply::Admin(answer(&AdminOp::MoveStatus));
            assert!(s.hub.on_reply(SERVER, status).is_some());
        }

        #[tokio::test(start_paused = true)]
        async fn a_cut_ends_the_wait_at_once() {
            let Scene {
                hub,
                tcp_tx,
                frames,
                ..
            } = scene();
            let going = hub.take_up(SERVER).unwrap();
            let mut link = hub.link(&going, tcp_tx);
            drop(frames);
            let started = tokio::time::Instant::now();
            let out = link.call(AdminOp::ImportFacts).await;
            assert!(matches!(out, Err(Stop::Gone(words)) if words == CUT));
            assert!(started.elapsed() < Duration::from_secs(1));
            // And one that comes while it waits
            let (out_tx, frames) = mpsc::unbounded_channel();
            let tcp_tx = ControlTx::new(out_tx, PROTOCOL_VERSION);
            let mut link = hub.link(&going, tcp_tx);
            let cut = tokio::spawn(async move {
                let mut frames: mpsc::UnboundedReceiver<Vec<u8>> = frames;
                frames.recv().await;
            });
            let out = tokio::time::timeout(Duration::from_secs(1), link.call(AdminOp::ImportFacts))
                .await
                .expect("a cut is seen while it waits");
            cut.await.unwrap();
            assert!(matches!(out, Err(Stop::Gone(words)) if words == CUT));
        }

        #[tokio::test(start_paused = true)]
        async fn stop_ends_a_dry_run_too_and_it_keeps_nothing() {
            let s = scene();
            let (hub, tcp_tx, emit) = (s.hub.clone(), s.tcp_tx.clone(), s.emit.clone());
            let plan = tokio::spawn(async move {
                hub.plan(SERVER, GUILD, tcp_tx, Vec::new(), Vec::new(), emit)
                    .await
                    .map(|_| ())
            });
            // No answer comes: it sits waiting for the relay
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(s.hub.lock()[SERVER].going.is_some());
            s.hub.stop(SERVER);
            assert_eq!(plan.await.unwrap(), Err(STOPPED.to_string()));
            let slots = s.hub.lock();
            assert!(slots[SERVER].going.is_none() && slots[SERVER].dry.is_none());
        }

        /// A compile error, not a failure, if either ever gets a `Debug`.
        #[test]
        fn nothing_holding_the_token_can_be_printed() {
            trait AmbiguousIfDebug<A> {
                fn no_debug() {}
            }
            impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
            struct IsDebug;
            impl<T: ?Sized + std::fmt::Debug> AmbiguousIfDebug<IsDebug> for T {}
            <ImportHub<Discord> as AmbiguousIfDebug<_>>::no_debug();
            <Discord as AmbiguousIfDebug<_>>::no_debug();
        }

        #[tokio::test(start_paused = true)]
        async fn forget_leaves_no_token_and_ends_the_run_at_once() {
            let mut s = scene().dry().await;
            let api = Arc::downgrade(&s.hub.lock()[SERVER].api);
            let dry = Arc::downgrade(s.hub.lock()[SERVER].dry.as_ref().unwrap());
            let choices = s.choices();
            s.hub
                .start(
                    SERVER,
                    7,
                    choices,
                    s.tcp_tx.clone(),
                    |_| Recorder::default(),
                    s.emit.clone(),
                )
                .unwrap();
            // A frame is out, and no answer comes
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(s.frames.try_recv().is_ok());
            let started = tokio::time::Instant::now();
            s.hub.forget(SERVER);
            assert!(s.hub.lock().is_empty());
            assert_eq!(s.hub.api(SERVER).err().as_deref(), Some(NO_TOKEN));
            let seen = ended_of(&mut s.events).await;
            let (_, end) = seen.last().unwrap();
            assert!(end["stopped"].is_string(), "{end}");
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "not after the wait for the relay's answer"
            );
            assert!(api.upgrade().is_none(), "the token is gone with the run");
            assert!(dry.upgrade().is_none(), "and all that was read");
        }

        /// A Discord that never answers.
        struct Stuck;

        impl Transport for Stuck {
            fn request(&self, _: Req) -> impl Future<Output = Result<Resp, String>> + Send {
                std::future::pending()
            }
        }

        #[tokio::test(start_paused = true)]
        async fn forget_ends_what_waits_on_discord_too() {
            let hub = Arc::new(ImportHub::<Stuck>::default());
            hub.hold(SERVER, Api::new(Stuck), hub.number()).unwrap();
            let (out, mut frames) = mpsc::unbounded_channel();
            let tcp_tx = ControlTx::new(out, PROTOCOL_VERSION);
            let reading = hub.clone();
            let plan = tokio::spawn(async move {
                reading
                    .plan(
                        SERVER,
                        GUILD,
                        tcp_tx,
                        Vec::new(),
                        Vec::new(),
                        Arc::new(|_: &str, _: Value| {}),
                    )
                    .await
                    .map(|_| ())
            });
            // The relay says its part, and no frame is out from here on
            for _ in 0..3 {
                let frame = frames.recv().await.unwrap();
                let reply = AccountReply::Admin(answer(&op_of(&frame)));
                assert!(hub.on_reply(SERVER, reply).is_none());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(hub.lock()[SERVER].going.is_some());
            assert!(hub.lock()[SERVER].wire.waiter.is_none());
            hub.forget(SERVER);
            let out = tokio::time::timeout(Duration::from_secs(1), plan)
                .await
                .expect("it stops at once");
            assert_eq!(out.unwrap(), Err(STOPPED.to_string()));
        }

        #[tokio::test(start_paused = true)]
        async fn stop_loses_nothing_and_the_next_run_goes() {
            let mut s = scene().dry().await;
            let start = |s: &Scene, run| {
                s.hub.start(
                    SERVER,
                    run,
                    s.choices(),
                    s.tcp_tx.clone(),
                    |_| Recorder::default(),
                    s.emit.clone(),
                )
            };
            start(&s, 7).unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            let started = tokio::time::Instant::now();
            s.hub.stop(SERVER);
            let seen = ended_of(&mut s.events).await;
            let (_, end) = seen.last().unwrap();
            assert!(end["stopped"].as_str().unwrap().starts_with("Stopped"));
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(s.hub.api(SERVER).is_ok(), "the token is kept for going on");

            let frames = std::mem::replace(&mut s.frames, mpsc::unbounded_channel().1);
            let _page = relay(s.hub.clone(), frames);
            start(&s, 7).unwrap();
            let seen = ended_of(&mut s.events).await;
            let (_, end) = seen.last().unwrap();
            assert_eq!(end["stopped"], Value::Null, "{end}");
        }

        struct Panics;

        impl EmoteSink for Panics {
            async fn add(&mut self, _: &PlannedEmote) -> Result<String, String> {
                panic!("a bug in the run, on purpose");
            }
        }

        #[tokio::test(start_paused = true)]
        async fn a_panic_in_the_run_still_ends_it() {
            let mut s = scene().dry().await;
            let choices = s.choices();
            let frames = std::mem::replace(&mut s.frames, mpsc::unbounded_channel().1);
            let _page = relay(s.hub.clone(), frames);
            s.hub
                .start(
                    SERVER,
                    7,
                    choices,
                    s.tcp_tx.clone(),
                    |_| Panics,
                    s.emit.clone(),
                )
                .unwrap();
            let seen = ended_of(&mut s.events).await;
            let (_, end) = seen.last().unwrap();
            assert!(
                end["stopped"].is_string(),
                "the page does not wait for ever"
            );
            assert!(s.hub.lock()[SERVER].going.is_none());
        }

        #[tokio::test(start_paused = true)]
        async fn a_forgotten_run_cannot_touch_the_one_after_it() {
            let s = scene();
            let old = s.hub.take_up(SERVER).unwrap();
            s.hub.forget(SERVER);
            s.hub
                .hold(SERVER, Api::new(mock()), s.hub.number())
                .unwrap();
            let new = s.hub.take_up(SERVER).unwrap();

            let late = s
                .hub
                .send_frame(SERVER, old.ticket, &s.tcp_tx, AdminOp::ImportFacts);
            assert!(matches!(late, Err(Stop::Gone(_))), "its frame goes nowhere");

            drop(old);
            assert!(
                s.hub.lock()[SERVER]
                    .going
                    .as_ref()
                    .is_some_and(|(t, _)| *t == new.ticket),
                "and when it ends, the new one is still going"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn an_hour_with_nothing_going_drops_the_token() {
            let s = scene();
            let minute = Duration::from_secs(60);
            tokio::time::sleep(30 * minute).await;
            assert!(s.hub.api(SERVER).is_ok());
            // A use starts the hour again
            s.hub.keep_for_an_hour(SERVER);
            tokio::time::sleep(45 * minute).await;
            assert!(s.hub.api(SERVER).is_ok(), "the first hour's clock is off");

            // A run counts as in use, however long it takes
            let going = s.hub.take_up(SERVER).unwrap();
            tokio::time::sleep(5 * IDLE).await;
            assert!(s.hub.api(SERVER).is_ok());
            drop(going);
            tokio::time::sleep(30 * minute).await;
            assert!(s.hub.api(SERVER).is_ok(), "the hour counts from its end");
            tokio::time::sleep(31 * minute).await;
            assert_eq!(s.hub.api(SERVER).err().as_deref(), Some(NO_TOKEN));
        }

        #[tokio::test(start_paused = true)]
        async fn a_token_given_after_another_is_not_on_its_clock() {
            let s = scene();
            tokio::time::sleep(IDLE - Duration::from_secs(1)).await;
            s.hub.forget(SERVER);
            s.hub
                .hold(SERVER, Api::new(mock()), s.hub.number())
                .unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert!(s.hub.api(SERVER).is_ok());
        }

        #[test]
        fn only_fixed_hosts_are_asked_and_the_token_goes_in_one_sensitive_header() {
            let discord = Discord::new(" a.bot.token ").unwrap();
            let ask = |url: &str, auth: bool| {
                discord.made(Req {
                    method: Method::Get,
                    url: url.to_string(),
                    auth,
                    body: None,
                })
            };
            let req = ask(&format!("{BASE}/users/@me"), true).unwrap();
            let auth = req.headers().get(reqwest::header::AUTHORIZATION).unwrap();
            assert_eq!(auth.as_bytes(), b"Bot a.bot.token");
            assert!(auth.is_sensitive(), "never printed");
            assert!(!format!("{req:?}").contains("a.bot.token"));
            let says = req.headers().get(reqwest::header::USER_AGENT).unwrap();
            assert_eq!(
                says.to_str().unwrap(),
                format!(
                    "DiscordBot (https://github.com/luki4fun/VoIPC, {})",
                    env!("CARGO_PKG_VERSION")
                )
            );
            let req = ask(&format!("{BASE}/users/@me"), false).unwrap();
            assert!(
                req.headers().get(reqwest::header::AUTHORIZATION).is_none(),
                "only where it is asked for"
            );
            for elsewhere in [
                "https://evil.example/api/v10/users/@me",
                "http://discord.com/api/v10/users/@me",
                "https://discord.com.evil.example/x",
                "https://discord.com@evil.example/x",
                "https://evil.example/https://discord.com/",
                "file:///etc/passwd",
            ] {
                assert_eq!(
                    ask(elsewhere, true).err().as_deref(),
                    Some(NOT_A_HOST),
                    "{elsewhere}"
                );
            }
            assert!(ask("no address", true).is_err());

            let post = discord
                .made(Req {
                    method: Method::Post,
                    url: format!("{BASE}/channels/1/messages"),
                    auth: true,
                    body: Some(b"{}".to_vec()),
                })
                .unwrap();
            assert_eq!(*post.method(), reqwest::Method::POST);
            assert!(post.headers().contains_key(reqwest::header::USER_AGENT));
            assert_eq!(
                post.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
                "application/json"
            );

            assert!(Discord::new("  ").is_err());
            assert!(Discord::new("two\nlines").is_err());
        }

        #[test]
        fn an_emotes_picture_is_where_the_listing_says() {
            let emojis = json!([
                { "id": "123456789012345678", "name": "pog", "animated": false },
                { "id": "223456789012345678", "name": "dance", "animated": true },
            ]);
            let stickers = json!([
                { "id": "323456789012345678", "name": "wave", "format_type": 2 },
                { "id": "423456789012345678", "name": "spin", "format_type": 4 },
            ]);
            let read = Read {
                emojis: voipc_import::model::parse(emojis.to_string().as_bytes()).unwrap(),
                stickers: voipc_import::model::parse(stickers.to_string().as_bytes()).unwrap(),
                ..Read::default()
            };
            let planned = |id: u64, sticker| PlannedEmote {
                id,
                raw: String::new(),
                name: String::new(),
                sticker,
            };
            let rows: Vec<Item> = [
                (123456789012345678, false),
                (223456789012345678, false),
                (323456789012345678, true),
                (423456789012345678, true),
            ]
            .map(|(id, sticker)| picture_of(&read, &planned(id, sticker)).unwrap())
            .into();
            let listed: Vec<Item> = discord_listing(&emojis, false)
                .items
                .into_iter()
                .chain(discord_listing(&stickers, true).items)
                .collect();
            assert_eq!(rows, listed);
            for item in &rows {
                assert!(
                    host_ok(&reqwest::Url::parse(&item.url).unwrap()),
                    "{}",
                    item.url
                );
            }
            assert_eq!(
                picture_of(&read, &planned(1, false)),
                None,
                "not one the dry-run read"
            );
            assert_eq!(
                picture_of(&read, &planned(123456789012345678, true)),
                None,
                "an emoji's id is no sticker"
            );
        }

        #[test]
        fn a_post_is_checked_here_too() {
            assert_eq!(post_of("123", "hello"), Ok(123));
            assert_eq!(
                post_of("1234567890123456789", &"é".repeat(2000)),
                Ok(1234567890123456789)
            );
            assert_eq!(post_of("123", ""), Err(POST_LENGTH));
            assert_eq!(post_of("123", &"é".repeat(2001)), Err(POST_LENGTH));
            assert_eq!(post_of("12x", "hello"), Err(NOT_A_CHANNEL));
            assert_eq!(post_of("", "hello"), Err(NOT_A_CHANNEL));
        }

        /// An answer as it comes off a socket: what it says it holds, and what it sends.
        async fn answer_of(bytes: &'static str) -> reqwest::Response {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut asked = [0; 1024];
                let _ = socket.read(&mut asked).await;
                let _ = socket.write_all(bytes.as_bytes()).await;
            });
            client(TIMEOUT).unwrap();
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("http://{address}/"))
                .send()
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn a_body_past_its_cap_is_refused() {
            let eleven = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                          b\r\nabcdefghijk\r\n0\r\n\r\n";
            let body = body_up_to(&mut answer_of(eleven).await, 11).await;
            assert_eq!(body.unwrap().len(), 11);
            let body = body_up_to(&mut answer_of(eleven).await, 10).await;
            assert_eq!(body.err().as_deref(), Some("too big"), "however it comes");
            // It says so itself, and is not read at all: nothing else is sent, so reading
            // would answer something else
            let says = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n";
            let body = body_up_to(&mut answer_of(says).await, 10).await;
            assert_eq!(body.err().as_deref(), Some("too big"));
        }

        /// One red pixel.
        const PIXEL: [u8; 70] = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99,
            0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];

        fn files_on(tcp_tx: ControlTx) -> Arc<Files> {
            Arc::new(Files::new(
                Box::new(|_, _| {}),
                Box::new(|| false),
                "relay.example".into(),
                9987,
                false,
                None,
                Some(voipc_protocol::types::EmoteAccess {
                    token: voipc_protocol::types::Secret("t".into()),
                    max_emote_bytes: 1 << 20,
                    max_sticker_bytes: 1 << 20,
                    max_total_bytes: 1 << 30,
                    max_items: 400,
                }),
                tcp_tx,
            ))
        }

        fn sink_on(files: Arc<Files>) -> Sink {
            Sink {
                http: client(TIMEOUT).unwrap(),
                files,
                uploaded: Uploaded::default(),
                dry: Arc::new(Dry {
                    read: Read::default(),
                    here: Here {
                        facts: facts(),
                        channels: Vec::new(),
                        emote_names: Vec::new(),
                        cursors: HashMap::new(),
                        last_started_ms: None,
                    },
                }),
            }
        }

        #[tokio::test]
        async fn an_emote_goes_in_sanitized_with_no_servers_name_on_it() {
            let (out, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
            let files = files_on(ControlTx::new(out, PROTOCOL_VERSION));
            let sink = sink_on(files.clone());
            let emote = PlannedEmote {
                id: 1,
                raw: "PoG!".into(),
                name: "pog".into(),
                sticker: true,
            };
            let relay = tokio::spawn(async move {
                let frame = frames.recv().await.unwrap();
                let mut buf = BytesMut::from(&frame[..]);
                let payload = try_decode_frame(&mut buf).unwrap().unwrap();
                let ClientMessage::EmoteAdd { emote } = decode_client_msg(&payload).unwrap() else {
                    panic!("not an add");
                };
                // It had the file already: the list answers
                files.on_message(voipc_protocol::messages::ServerMessage::EmoteList {
                    stickers: true,
                    emotes: vec![emote.clone()],
                });
                (emote, files)
            });
            sink.store(&emote, PIXEL.to_vec()).await.unwrap();
            let (added, files) = relay.await.unwrap();
            assert_eq!(added.name, "pog");
            assert!(added.sticker);
            assert_eq!(added.pack, "", "a Discord server's name is never filled in");
            assert_eq!((added.w, added.h), (1, 1));
            assert_ne!(
                added.hash,
                crate::emotes::sha256(&PIXEL),
                "what goes up is this app's own writing of it, not Discord's file"
            );
            assert_eq!(files.emote_names(), ["pog"]);
        }

        /// A run cut between the relay's listing and the ledger's frame: on going on, that
        /// name is taken, and by this very picture.
        #[tokio::test]
        async fn a_picture_listed_under_its_name_counts_as_added() {
            let (out, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
            let files = files_on(ControlTx::new(out, PROTOCOL_VERSION));
            let sink = sink_on(files.clone());
            let emote = PlannedEmote {
                id: 1,
                raw: "pog".into(),
                name: "pog".into(),
                sticker: false,
            };
            let made = crate::emotes::prepare(PIXEL.to_vec(), false, 1 << 20)
                .await
                .unwrap();
            let list =
                |name: &str, hash: [u8; 32]| voipc_protocol::messages::ServerMessage::EmoteList {
                    stickers: true,
                    emotes: vec![voipc_protocol::types::Emote {
                        name: name.into(),
                        hash,
                        sticker: false,
                        pack: String::new(),
                        len: 1,
                        w: 1,
                        h: 1,
                    }],
                };
            files.on_message(list("pog", crate::emotes::sha256(&made.upload)));
            sink.store(&emote, PIXEL.to_vec()).await.unwrap();
            assert!(frames.try_recv().is_err(), "nothing to ask the relay");

            // The control: the name is someone else's picture, and the relay says so
            files.on_message(list("pog", [9; 32]));
            let answers = files.clone();
            let relay = tokio::spawn(async move {
                let frame = frames.recv().await.unwrap();
                let mut buf = BytesMut::from(&frame[..]);
                let payload = try_decode_frame(&mut buf).unwrap().unwrap();
                assert!(matches!(
                    decode_client_msg(&payload).unwrap(),
                    ClientMessage::EmoteAdd { .. }
                ));
                answers.on_message(voipc_protocol::messages::ServerMessage::EmoteError {
                    name: "pog".into(),
                    reason: ":pog: is taken".into(),
                });
            });
            let out = sink.store(&emote, PIXEL.to_vec()).await;
            relay.await.unwrap();
            assert_eq!(out.err().as_deref(), Some(":pog: is taken"));
        }

        /// W2-27: cut between the relay's listing and the ledger's frame, and the server read
        /// again before going on: `pog` is taken by then, so the plan says `pog_2`. What this
        /// app put up is filed under its first name, and nothing goes up twice.
        #[tokio::test]
        async fn a_picture_this_app_put_up_is_found_under_its_first_name() {
            let (out, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
            let files = files_on(ControlTx::new(out, PROTOCOL_VERSION));
            let sink = sink_on(files.clone());
            let planned = |id: u64, name: &str| PlannedEmote {
                id,
                raw: "pog".into(),
                name: name.into(),
                sticker: false,
            };
            // The relay lists what it gets, and the answer it would give is lost
            let answers = files.clone();
            let relay = tokio::spawn(async move {
                let frame = frames.recv().await.unwrap();
                let mut buf = BytesMut::from(&frame[..]);
                let payload = try_decode_frame(&mut buf).unwrap().unwrap();
                let ClientMessage::EmoteAdd { emote } = decode_client_msg(&payload).unwrap() else {
                    panic!("not an add");
                };
                answers.on_message(voipc_protocol::messages::ServerMessage::EmoteList {
                    stickers: true,
                    emotes: vec![emote],
                });
                frames
            });
            assert_eq!(
                sink.store(&planned(1, "pog"), PIXEL.to_vec())
                    .await
                    .unwrap(),
                "pog"
            );
            let mut frames = relay.await.unwrap();

            assert_eq!(
                sink.store(&planned(1, "pog_2"), PIXEL.to_vec())
                    .await
                    .unwrap(),
                "pog"
            );
            assert!(frames.try_recv().is_err(), "nothing to ask the relay");

            // The control: the same picture for another emote this app never put up is its own
            let relay = tokio::spawn(async move {
                let frame = frames.recv().await.unwrap();
                let mut buf = BytesMut::from(&frame[..]);
                let payload = try_decode_frame(&mut buf).unwrap().unwrap();
                let ClientMessage::EmoteAdd { emote } = decode_client_msg(&payload).unwrap() else {
                    panic!("not an add");
                };
                files.on_message(voipc_protocol::messages::ServerMessage::EmoteList {
                    stickers: true,
                    emotes: vec![emote],
                });
            });
            assert_eq!(
                sink.store(&planned(2, "pog_2"), PIXEL.to_vec())
                    .await
                    .unwrap(),
                "pog_2"
            );
            relay.await.unwrap();
        }

        #[tokio::test]
        async fn a_file_that_is_no_picture_stays_here() {
            let (out, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
            let sink = sink_on(files_on(ControlTx::new(out, PROTOCOL_VERSION)));
            let emote = PlannedEmote {
                id: 1,
                raw: "x".into(),
                name: "xx".into(),
                sticker: false,
            };
            assert!(sink.store(&emote, b"<html>not".to_vec()).await.is_err());
            assert!(
                frames.try_recv().is_err(),
                "nothing was offered to the relay"
            );
        }

        /// W2-29: the page's "Show more" on the left-out list is out when the run reads it
        /// from the start. Its answer came first and passed for the run's.
        #[tokio::test(start_paused = true)]
        async fn the_pages_left_out_page_is_not_the_runs_first() {
            let s = scene();
            let _going = s.hub.take_up(SERVER).unwrap();
            let ask = |after: &str| AdminOp::MoveExcluded {
                after: after.into(),
            };
            let page_ask = ClientMessage::Account(AccountRequest::Admin {
                op: ask("1000"),
                code: None,
            });
            s.hub.send_for_page(SERVER, &s.tcp_tx, &page_ask);
            let mut first = s.frame(ask(""));
            let reply = |ids: &[&str]| {
                AccountReply::Admin(AdminReply::MoveExcluded {
                    ids: ids.iter().map(|i| (i.to_string(), true, true, 1)).collect(),
                    more: false,
                })
            };
            assert!(
                s.hub.on_reply(SERVER, reply(&["1001"])).is_some(),
                "the page's, answered first"
            );
            assert!(first.try_recv().is_err(), "the run still waits");
            assert!(s.hub.on_reply(SERVER, reply(&["1"])).is_none());
            let Ok(Ok(AdminReply::MoveExcluded { ids, .. })) = first.try_recv() else {
                panic!("not the run's")
            };
            assert_eq!(ids[0].0, "1");
            assert_eq!(s.hub.lock()[SERVER].wire.page_out, 0);
        }

        #[tokio::test(start_paused = true)]
        async fn a_page_ask_never_answered_does_not_take_the_runs_answer() {
            let s = scene();
            let _going = s.hub.take_up(SERVER).unwrap();
            // The relay's handler failed on it, and it stays unanswered
            s.panel_click();
            let mut first = s.frame(AdminOp::MoveStatus);
            let status = AccountReply::Admin(answer(&AdminOp::MoveStatus));
            assert!(s.hub.on_reply(SERVER, status).is_none());
            assert!(first.try_recv().is_ok(), "it is what the run asked");
            assert_eq!(
                s.hub.lock()[SERVER].wire.page_out,
                0,
                "and the count is right again"
            );
            // So a refusal after it is the run's
            let mut next = s.call();
            assert!(s.hub.on_reply(SERVER, refused_op("Too many")).is_none());
            assert!(matches!(next.try_recv(), Ok(Err(Stop::Said(_)))));
        }

        #[tokio::test]
        async fn an_emote_list_is_remembered_for_the_dry_run() {
            let (out, _frames) = mpsc::unbounded_channel();
            let files = Files::new(
                Box::new(|_, _| {}),
                Box::new(|| false),
                "relay.example".into(),
                9987,
                false,
                None,
                None,
                ControlTx::new(out, PROTOCOL_VERSION),
            );
            assert!(files.emote_names().is_empty());
            files.on_message(voipc_protocol::messages::ServerMessage::EmoteList {
                stickers: true,
                emotes: vec![voipc_protocol::types::Emote {
                    name: "pog".into(),
                    hash: [1; 32],
                    sticker: false,
                    pack: String::new(),
                    len: 1,
                    w: 1,
                    h: 1,
                }],
            });
            assert_eq!(files.emote_names(), ["pog"]);
        }

        #[tokio::test]
        async fn a_token_is_held_only_for_a_server_connected_to() {
            let state = AppState::new();
            let out = open(&state, SERVER, "a.bot.token".to_string()).await;
            assert!(out.is_err());
            assert!(state.import.lock().is_empty());
        }

        /// As the importer's crate has it: rows and the token in RAM, and no log to leak by.
        #[test]
        fn this_side_touches_no_disk_and_logs_nothing() {
            let code = include_str!("import.rs");
            let code = code.split("#[cfg(test)]").next().unwrap();
            for word in [
                "std::fs",
                "tokio::fs",
                "File::",
                "crate::config",
                "tracing",
                "info!",
                "warn!",
                "debug!",
                "trace!",
                "println!",
            ] {
                assert!(!code.contains(word), "{word}");
            }
        }

        #[test]
        fn the_connection_goes_through_the_hub_both_ways() {
            let code = include_str!("account.rs");
            let answers = code.split("pub async fn on_reply(").nth(1).unwrap();
            let answers = answers.split("\n}\n").next().unwrap();
            let hub = answers.find(".import.on_reply(server, reply)").unwrap();
            let session = answers.find("link.session().on_reply(&reply)").unwrap();
            assert!(hub < session, "a run's replies never reach the page's way");
            let asks = code.split("pub async fn account_request(").nth(1).unwrap();
            assert!(asks
                .split("\n}\n")
                .next()
                .unwrap()
                .contains(".send_for_page("));
        }

        /// The page reconnects by `disconnect` too, on every try: that is no leaving. The page
        /// calls `import_forget` when the person disconnects.
        #[test]
        fn only_starting_over_forgets_a_token_here_and_a_cut_keeps_it() {
            let code = include_str!("commands.rs");
            let body_of = |command: &str| {
                let body = code.split(command).nth(1).unwrap();
                body.split("#[tauri::command]").next().unwrap().to_string()
            };
            let one = body_of("pub async fn disconnect(");
            assert!(!one.contains("import.forget("), "a reconnect goes this way");
            // What waits on Discord sends no frame to see a cut by, and would hold up the next
            assert!(one.contains("import.stop("));
            // Ahead of the connections: a cut has its server out of them already
            let all = body_of("pub async fn disconnect_all(");
            let forgets = all.find("import.forget_all(").unwrap();
            assert!(forgets < all.find("state.connections").unwrap());
        }

        /// A reload during a cut: nothing is left to say a token is here but this.
        #[tokio::test(start_paused = true)]
        async fn starting_over_forgets_every_server_and_whatever_is_on_its_way() {
            let hub = Arc::new(ImportHub::<Held>::default());
            for server in [SERVER, "elsewhere:1"] {
                let (api, _let_go) = held();
                hub.hold(server, api, hub.number()).unwrap();
            }
            let going = hub.take_up("elsewhere:1").unwrap();
            // And one that no slot knows of yet, on a server with no connection either
            let (api, let_go) = held();
            let opening = hub.clone();
            let asked = tokio::spawn(async move { opening.open("third:1", api).await.map(|_| ()) });
            tokio::time::sleep(Duration::from_secs(1)).await;

            hub.forget_all();
            assert!(hub.lock().is_empty());
            assert!(*going.stopped.borrow(), "what was going is stopped");
            let_go.send_replace(true);
            assert_eq!(asked.await.unwrap(), Err(LEFT_IT.to_string()));
            assert!(hub.lock().is_empty());

            // The control: a token given after it is held
            let (api, let_go) = held();
            let_go.send_replace(true);
            hub.open(SERVER, api).await.unwrap();
            assert!(hub.api(SERVER).is_ok());
        }

        #[tokio::test(start_paused = true)]
        async fn a_cut_keeps_the_token_and_the_dry_run_so_the_run_can_go_on() {
            let mut s = scene().dry().await;
            let choices = s.choices();
            s.hub
                .start(
                    SERVER,
                    7,
                    choices.clone(),
                    s.tcp_tx.clone(),
                    |_| Recorder::default(),
                    s.emit.clone(),
                )
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            // The connection goes, and with it what the frames went by
            drop(std::mem::replace(
                &mut s.frames,
                mpsc::unbounded_channel().1,
            ));
            let seen = ended_of(&mut s.events).await;
            assert_eq!(seen.last().unwrap().1["stopped"], CUT);
            assert!(s.hub.api(SERVER).is_ok());
            assert!(s.hub.lock()[SERVER].dry.is_some());
            // Over a new connection, with nothing asked again
            let (out, frames) = mpsc::unbounded_channel();
            let _page = relay(s.hub.clone(), frames);
            s.hub
                .start(
                    SERVER,
                    7,
                    choices,
                    ControlTx::new(out, PROTOCOL_VERSION),
                    |_| Recorder::default(),
                    s.emit.clone(),
                )
                .unwrap();
            let seen = ended_of(&mut s.events).await;
            assert_eq!(seen.last().unwrap().1["stopped"], Value::Null);
            // The hour still holds
            tokio::time::sleep(IDLE + Duration::from_secs(1)).await;
            assert_eq!(s.hub.api(SERVER).err().as_deref(), Some(NO_TOKEN));
        }

        /// A Discord that answers once it is let.
        struct Held {
            mock: Mock,
            go: watch::Receiver<bool>,
        }

        impl Transport for Held {
            fn request(&self, req: Req) -> impl Future<Output = Result<Resp, String>> + Send {
                let mut go = self.go.clone();
                let answer = self.mock.request(req);
                async move {
                    let _ = go.wait_for(|on| *on).await;
                    answer.await
                }
            }
        }

        fn held() -> (Api<Held>, watch::Sender<bool>) {
            let (let_go, go) = watch::channel(false);
            let mock = mock();
            (Api::new(Held { mock, go }), let_go)
        }

        #[tokio::test(start_paused = true)]
        async fn leaving_the_wizard_while_a_token_is_asked_about_holds_nothing() {
            let hub = Arc::new(ImportHub::<Held>::default());
            let (api, let_go) = held();
            let opening = hub.clone();
            let first = tokio::spawn(async move { opening.open(SERVER, api).await.map(|_| ()) });
            tokio::time::sleep(Duration::from_secs(1)).await;
            hub.forget(SERVER);
            let_go.send_replace(true);
            assert_eq!(first.await.unwrap(), Err(LEFT_IT.to_string()));
            assert_eq!(hub.api(SERVER).err().as_deref(), Some(NO_TOKEN));

            // The control: left alone, the same thing holds it
            let (api, let_go) = held();
            let_go.send_replace(true);
            hub.open(SERVER, api).await.unwrap();
            assert!(hub.api(SERVER).is_ok());
        }

        #[tokio::test(start_paused = true)]
        async fn an_answer_from_before_cannot_take_the_place_of_a_token_given_since() {
            let hub = Arc::new(ImportHub::<Held>::default());
            let (api, let_old_go) = held();
            let opening = hub.clone();
            let old = tokio::spawn(async move { opening.open(SERVER, api).await.map(|_| ()) });
            tokio::time::sleep(Duration::from_secs(1)).await;
            hub.forget(SERVER);
            // Restarted, and this one is answered first
            let (api, let_new_go) = held();
            let_new_go.send_replace(true);
            hub.open(SERVER, api).await.unwrap();
            let newer = Arc::downgrade(&hub.lock()[SERVER].api);
            let_old_go.send_replace(true);
            assert_eq!(old.await.unwrap(), Err(LEFT_IT.to_string()));
            assert!(
                newer.upgrade().is_some() && hub.api(SERVER).is_ok(),
                "the newer token is the one held"
            );
        }

        /// One server's forget says nothing of another's.
        #[tokio::test(start_paused = true)]
        async fn a_forget_is_of_one_server() {
            let hub = Arc::new(ImportHub::<Mock>::default());
            let asked = hub.number();
            hub.forget("elsewhere:1");
            hub.hold(SERVER, Api::new(mock()), asked).unwrap();
            assert!(hub.api(SERVER).is_ok());
        }
    }
}
