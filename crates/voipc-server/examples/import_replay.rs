// A whole run of the Discord importer against a real relay, with no Discord: the real driver
// (`voipc_import::run`), the stand-in Discord (`testkit/6-mock-discord`), real QUIC and real
// frames. It signs in with a password and a code as a device would, so it needs an account
// holding `*`, with codes on, and the authenticator's secret.
//
//   import_replay <host:port> <name> <password> <base32 secret> [options]
//     --v2           what a later delta sees, and the row someone deleted, sent straight
//     --top-up N     N more messages in #lounge, by one person not on the member list
//     --tick ID      the history of this private channel too (again for more)
//     --leave-out ID this channel stays out (again for more)
//     --code-after N the last 30-second step of this secret the relay has seen
//
// A relay takes a code once, and none older than the last. So give --code-after whatever the
// last run said as `code_step`, or what the page last used, or wrong codes pile up and it says
// "Too many attempts". It waits for a code when it has to, up to a minute.
//
// One line of JSON on stdout says how it went: `run`, `stopped`, `counts`, `code_step`, and with
// --v2, `resent` (`[stored, skipped]`). Emotes go only as far as the relay's ledger: nothing here
// has a picture to send. It exits non-zero if the run did not finish.

#[path = "load_common/mod.rs"]
mod load_common;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::watch;
use wtransport::{RecvStream, SendStream};
use zeroize::Zeroizing;

use load_common::{client_endpoint, enc, native_url, next_message, Error};
use voipc_crypto::account::{Method, SignIn, Step};
use voipc_crypto::{prekey, SignalStores};
use voipc_import::api::Api;
use voipc_import::mock::Mock;
use voipc_import::model::Message;
use voipc_import::plan::{self, PlannedEmote};
use voipc_import::rewrite::{self, Names};
use voipc_import::run::{self, EmoteSink, Job, Progress, RelayLink, Stop};
use voipc_protocol::codec::{APP_VERSION, PROTOCOL_VERSION};
use voipc_protocol::messages::{
    AccountReply, AccountRequest, AdminOp, AdminReply, ClientMessage, ServerMessage,
};

const LOUNGE: u64 = 1_190_000_000_000_000_211;
/// A code's life, in seconds.
const PERIOD: i64 = 30;

struct Options {
    server: String,
    name: String,
    password: String,
    secret: Vec<u8>,
    v2: bool,
    top_up: u64,
    tick: Vec<u64>,
    leave_out: Vec<u64>,
    code_after: i64,
}

fn options() -> Result<Options, Error> {
    let usage = "usage: import_replay <host:port> <name> <password> <base32 secret> \
                 [--v2] [--top-up N] [--tick ID]... [--leave-out ID]... [--code-after N]";
    let mut args = std::env::args().skip(1);
    let mut next = || args.next().ok_or(usage);
    let (server, name, password, secret) = (next()?, next()?, next()?, next()?);
    let secret = l4f_accounts::totp::base32_decode(&secret).ok_or("that secret is not base32")?;
    let mut options = Options {
        server,
        name,
        password,
        secret,
        v2: false,
        top_up: 0,
        tick: Vec::new(),
        leave_out: Vec::new(),
        code_after: 0,
    };
    while let Ok(arg) = next() {
        match arg.as_str() {
            "--v2" => options.v2 = true,
            "--top-up" => options.top_up = next()?.parse()?,
            "--tick" => options.tick.push(next()?.parse()?),
            "--leave-out" => options.leave_out.push(next()?.parse()?),
            "--code-after" => options.code_after = next()?.parse()?,
            _ => return Err(usage.into()),
        }
    }
    Ok(options)
}

/// Every `*.json` of the fixture, by its path from there with `/`.
fn fixture(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> Result<(), Error> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            fixture(root, &path, files)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            let name = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(name, std::fs::read(&path)?);
        }
    }
    Ok(())
}

/// A code cannot be used twice, nor an older one after a newer: each is the next in the
/// window the relay takes, and past that this waits for one to open.
struct Codes {
    secret: Vec<u8>,
    last: i64,
}

impl Codes {
    async fn next(&mut self) -> String {
        let now = l4f_accounts::util::now() / PERIOD;
        let step = (self.last + 1).max(now - 1);
        if step > now + 1 {
            let wait = (step - 1) * PERIOD - l4f_accounts::util::now();
            tokio::time::sleep(Duration::from_secs(wait.max(0) as u64 + 1)).await;
        }
        self.last = step;
        format!("{:06}", l4f_accounts::totp::code_at(&self.secret, step))
    }
}

struct Link {
    send: SendStream,
    recv: RecvStream,
    buf: bytes::BytesMut,
    /// This end's TLS exporter, which the sign-in's proofs are bound to (protocol v22).
    binding: [u8; voipc_crypto::bind::BIND_LEN],
}

impl Link {
    async fn write(&mut self, msg: &ClientMessage) -> Result<(), Error> {
        self.send.write_all(&enc(msg, PROTOCOL_VERSION)?).await?;
        Ok(())
    }

    async fn read(&mut self) -> Result<ServerMessage, Error> {
        next_message(&mut self.recv, &mut self.buf, PROTOCOL_VERSION).await
    }

    /// The answer to an admin step: whatever else the relay says meanwhile is about others.
    async fn admin(
        &mut self,
        op: AdminOp,
        code: Option<String>,
    ) -> Result<Result<AdminReply, String>, Error> {
        self.write(&ClientMessage::Account(AccountRequest::Admin { op, code }))
            .await?;
        loop {
            match self.read().await? {
                ServerMessage::Account(AccountReply::Admin(reply)) => return Ok(Ok(reply)),
                ServerMessage::Account(AccountReply::Error { request, reason })
                    if request == "Admin" =>
                {
                    return Ok(Err(reason))
                }
                _ => {}
            }
        }
    }
}

impl RelayLink for Link {
    async fn call(&mut self, op: AdminOp) -> Result<AdminReply, Stop> {
        match self.admin(op, None).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(reason)) => Err(Stop::Said(reason)),
            Err(e) => Err(Stop::Gone(e.to_string())),
        }
    }
}

/// What the relay's emote store would get: nothing here has a picture.
#[derive(Default)]
struct Named(Vec<String>);

impl EmoteSink for Named {
    async fn add(&mut self, emote: &PlannedEmote) -> Result<String, String> {
        self.0.push(emote.name.clone());
        Ok(emote.name.clone())
    }
}

/// Password, code and keys, as a device does, on this machine's own connection. Then what
/// the app holds by that time: each channel's name, and each emote's.
async fn sign_in(
    link: &mut Link,
    options: &Options,
    codes: &mut Codes,
) -> Result<(Vec<(String, bool)>, Vec<String>), Error> {
    let method = Method::Password {
        password: Zeroizing::new(options.password.clone()),
    };
    let (mut machine, first) = SignIn::start(&options.name, method, PROTOCOL_VERSION, APP_VERSION);
    machine.bind(voipc_crypto::bind::Binding::Tls(link.binding));
    link.write(&first).await?;
    let mut channels = Vec::new();
    let mut emotes = Vec::new();
    let mut tries = 0;
    loop {
        let msg = link.read().await?;
        if matches!(msg, ServerMessage::Authenticated { .. }) {
            break;
        }
        for step in machine.on_message(&msg)? {
            match step {
                Step::Send(out) => link.write(&out).await?,
                Step::Keys => {
                    let identity = *machine.identity().ok_or("no identity")?;
                    let mut stores = SignalStores::new(&identity, rand::random());
                    prekey::generate_prekeys(&mut stores, &identity)?;
                    let bundle = prekey::bundle(&stores)?;
                    link.write(&machine.keys(bundle)).await?;
                }
                // Asked again is a code refused. A window holds three
                Step::NeedTotp if tries < 3 => {
                    tries += 1;
                    let code = codes.next().await;
                    link.write(&machine.totp(&code)).await?;
                }
                Step::Ignore => {}
                _ => return Err("a step this account should not need".into()),
            }
        }
    }
    let stamp: u64 = rand::random();
    link.write(&ClientMessage::Ping { timestamp: stamp })
        .await?;
    loop {
        match link.read().await? {
            ServerMessage::Pong { timestamp } if timestamp == stamp => {
                return Ok((channels, emotes));
            }
            ServerMessage::ChannelList { channels: list } => {
                channels = list.into_iter().map(|c| (c.name, c.text)).collect();
            }
            ServerMessage::ChannelListMore { channels: list, .. } => {
                channels.extend(list.into_iter().map(|c| (c.name, c.text)));
            }
            ServerMessage::EmoteList { emotes: list, .. } => {
                emotes = list.into_iter().map(|e| e.name).collect();
            }
            _ => {}
        }
    }
}

/// Takes a code. `ImportBegun` comes once the relay's copy of its database is made.
async fn begin(
    link: &mut Link,
    codes: &mut Codes,
    guild: u64,
    options: voipc_protocol::types::ImportOptions,
    backup_here: bool,
) -> Result<i64, Error> {
    let step = AdminOp::ImportBegin {
        guild_id: guild.to_string(),
        options,
        backup_taken: !backup_here,
    };
    let mut answer = link.admin(step.clone(), None).await?;
    if matches!(answer, Ok(AdminReply::StepUp)) {
        let code = codes.next().await;
        answer = link.admin(step, Some(code)).await?;
    }
    match answer? {
        AdminReply::ImportBegun { run, .. } => Ok(run),
        AdminReply::ImportBackingUp { .. } => loop {
            match link.read().await? {
                ServerMessage::Account(AccountReply::Admin(AdminReply::ImportBegun {
                    run,
                    ..
                })) => return Ok(run),
                ServerMessage::Account(AccountReply::Error { reason, .. }) => {
                    return Err(reason.into())
                }
                _ => {}
            }
        },
        _ => Err("the relay answered something else".into()),
    }
}

/// The row someone deleted, sent again as no walk would: what they took away must stay away,
/// and the relay says so by counting it as skipped.
async fn resend(
    link: &mut Link,
    files: &BTreeMap<String, Vec<u8>>,
    run: i64,
    all_on: voipc_protocol::types::ImportOptions,
) -> Result<Value, Error> {
    let said: Value = serde_json::from_slice(files.get("v2/resend.json").ok_or("no resend.json")?)?;
    let channel: u64 = said["channel"].as_str().ok_or("no channel")?.parse()?;
    let message: Message = serde_json::from_value(said["message"].clone())?;
    let row = rewrite::row_of(&message, &Names::default(), &all_on).ok_or("no row")?;
    let step = AdminOp::ImportMessages {
        run,
        channel,
        thread: None,
        high: row.id,
        rows: vec![row],
    };
    match link.admin(step, None).await? {
        Ok(AdminReply::ImportAcked { stored, skipped }) => Ok(json!([stored, skipped])),
        Ok(AdminReply::ImportRefused { reason, .. }) | Err(reason) => Err(reason.into()),
        Ok(_) => Err("the relay answered something else".into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("crypto provider");
    let options = options()?;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testkit/6-mock-discord");
    let mut files = BTreeMap::new();
    fixture(&root, &root, &mut files)?;
    let mock = Arc::new(Mock::new(files.clone()));
    if options.v2 {
        mock.use_v2();
    }
    if options.top_up > 0 {
        mock.add_messages(LOUNGE, options.top_up, 40);
    }
    let api = Arc::new(Api::new(mock.clone()));

    let addr: SocketAddr = tokio::net::lookup_host(&options.server)
        .await?
        .next()
        .ok_or("cannot resolve server")?;
    let endpoint = client_endpoint(addr, IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    let connection = endpoint.connect(native_url(addr)).await?;
    let (send, recv) = connection.open_bi().await?.await?;
    let mut binding = [0u8; voipc_crypto::bind::BIND_LEN];
    connection
        .export_keying_material(&mut binding, voipc_crypto::bind::EXPORTER_LABEL, &[])
        .map_err(|_| "this connection gives no exporter")?;
    let mut link = Link {
        send,
        recv,
        buf: bytes::BytesMut::with_capacity(8192),
        binding,
    };
    let mut codes = Codes {
        secret: options.secret.clone(),
        last: options.code_after,
    };
    let (channels, emotes) = sign_in(&mut link, &options, &mut codes).await?;

    let opening = plan::open(&api).await?;
    let guild: u64 = opening.guilds.first().ok_or("no server")?.id.parse()?;
    let read = plan::read(&api, guild).await?;
    let here = run::here_of(&mut link, guild, channels, emotes).await?;
    let mut choices = plan::default_choices(&read, &here);
    choices.options.acknowledged = true;
    choices.messages_on.extend(&options.tick);
    choices.left_out.extend(&options.leave_out);

    let backup_here = here.facts.backup_here;
    let run = begin(
        &mut link,
        &mut codes,
        guild,
        choices.options.clone(),
        backup_here,
    )
    .await?;
    let resent = if options.v2 {
        Some(resend(&mut link, &files, run, choices.options.clone()).await?)
    } else {
        None
    };

    let (_stop_tx, stop) = watch::channel(false);
    let (progress, _seen) = watch::channel(Progress::default());
    let job = Job {
        run,
        choices,
        pace: run::FRAME_PACE,
        stop,
        progress,
    };
    let mut sink = Named::default();
    let out = run::run(api, &mut link, &mut sink, &read, here, job).await;

    let mut said = json!({
        "run": run,
        "stopped": out.stopped,
        "counts": out.report.counts,
        "code_step": codes.last,
    });
    if let Some(resent) = resent {
        said["resent"] = resent;
    }
    println!("{said}");
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    match out.stopped {
        None => Ok(()),
        Some(why) => Err(why.into()),
    }
}
