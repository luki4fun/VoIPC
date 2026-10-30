//! The server's emotes and stickers (protocol v14).
//!
//! Admins add them from the app: `EmoteAdd` hands out a ticket, and the file
//! goes up in one `PUT /e/v1/<hash>`. Every member gets the list on join and
//! after each change, and fetches each file with the bearer its
//! `Authenticated` carried. They are the server's own, like its channel
//! names: kept in `[emotes] dir` across restarts, as they came, readable.
//!
//! **The relay never decodes them.** A file is checked against its hash, its
//! size and its first bytes (a PNG, GIF, WebP or JPEG), and that is all;
//! members' clients show only what their own sanitizer writes from it
//! (crates/voipc-media), whatever this relay or an admin sent.
//!
//! The list never says who added what, and every member fetches every file,
//! so what is fetched says nothing about who uses which.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use voipc_protocol::codec::encode_server_msg;
use voipc_protocol::conv::{hex, unhex};
use voipc_protocol::messages::ServerMessage;
use voipc_protocol::types::{
    valid_emote_name, valid_emote_pack, Emote, EmoteAccess, Secret, SessionId, EMOTE_BOX,
    MAX_EMOTES, STICKER_BOX,
};

use crate::config::EmotesConfig;
use crate::files::{Bucket, Prepared, Reply};
use crate::state::ServerState;

/// How long an upload ticket lasts.
const TICKET_LIFETIME: Duration = Duration::from_secs(600);
/// Uploads one admin connection may have open at once.
const TICKETS_PER_SESSION: usize = 64;
/// Changes within this time go out as one list, and one manifest write.
const BROADCAST_AFTER: Duration = Duration::from_secs(1);
const MANIFEST: &str = "manifest.json";

/// What the manifest file holds: the list, and the sticker switch.
#[derive(Default, Serialize, Deserialize)]
struct Manifest {
    stickers: bool,
    emotes: Vec<Stored>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    name: String,
    hash: String,
    sticker: bool,
    #[serde(default)]
    pack: String,
    #[serde(default)]
    w: u16,
    #[serde(default)]
    h: u16,
}

struct Pending {
    session: SessionId,
    emote: Emote,
    until: Instant,
}

#[derive(Default)]
struct Inner {
    stickers: bool,
    emotes: Vec<Emote>,
    files: HashMap<[u8; 32], Bytes>,
    /// Upload tickets, by ticket.
    tickets: HashMap<String, Pending>,
    /// Download bearers, by token: one per connection, with what it may still
    /// fetch (every member fetches every file once; a loop of fetches would
    /// fill the uplink voice needs).
    bearers: HashMap<String, (SessionId, Bucket)>,
    /// Bytes promised to open tickets, so uploads at once cannot pass the cap.
    reserved: u64,
    broadcast_due: bool,
    /// Files no emote names now, deleted once the manifest says so.
    gone: Vec<[u8; 32]>,
}

impl Inner {
    fn total(&self) -> u64 {
        self.files.values().map(|b| b.len() as u64).sum()
    }

    fn sweep(&mut self, now: Instant) {
        let gone: Vec<String> = self
            .tickets
            .iter()
            .filter(|(_, p)| p.until <= now)
            .map(|(t, _)| t.clone())
            .collect();
        for t in gone {
            if let Some(p) = self.tickets.remove(&t) {
                self.reserved -= u64::from(p.emote.len);
            }
        }
    }

    fn list(&self) -> ServerMessage {
        ServerMessage::EmoteList {
            stickers: self.stickers,
            emotes: self.emotes.clone(),
        }
    }
}

/// A shape held to its kind's box: only ever the room a reader keeps.
fn boxed(mut e: Emote) -> Emote {
    let side = if e.sticker { STICKER_BOX } else { EMOTE_BOX };
    (e.w, e.h) = (e.w.min(side), e.h.min(side));
    e
}

pub struct EmoteStore {
    dir: PathBuf,
    max_emote: u32,
    max_sticker: u32,
    max_total: u64,
    inner: Mutex<Inner>,
    /// One manifest write at a time, each of the latest state.
    writing: tokio::sync::Mutex<()>,
}

/// What an `EmoteAdd` comes to.
#[derive(Debug, PartialEq, Eq)]
pub enum Added {
    /// Upload the file with this ticket.
    Ticket(String),
    /// The relay had the file: the emote is in the list now.
    Listed,
}

/// A file's first bytes say it is a picture the clients read.
fn is_picture(b: &[u8]) -> bool {
    b.starts_with(b"\x89PNG\r\n\x1a\n")
        || b.starts_with(b"GIF87a")
        || b.starts_with(b"GIF89a")
        || (b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP")
        || b.starts_with(&[0xFF, 0xD8, 0xFF])
}

impl EmoteStore {
    /// The store in `cfg.dir`, with what an earlier run kept there. An emote
    /// whose file is missing, or not the file its hash names, is dropped, and
    /// a file no emote names is deleted.
    pub fn open(cfg: &EmotesConfig) -> std::io::Result<EmoteStore> {
        let dir = PathBuf::from(&cfg.dir);
        std::fs::create_dir_all(&dir)?;
        let manifest: Manifest = match std::fs::read(dir.join(MANIFEST)) {
            Ok(b) => serde_json::from_slice(&b).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Manifest::default(),
            Err(e) => return Err(e),
        };
        let mut inner = Inner {
            stickers: manifest.stickers,
            ..Inner::default()
        };
        for s in manifest.emotes {
            let Some(hash) = unhex::<32>(&s.hash) else {
                continue;
            };
            if !valid_emote_name(&s.name)
                || !valid_emote_pack(&s.pack)
                || inner.emotes.len() >= MAX_EMOTES
                || inner.emotes.iter().any(|e| e.name == s.name)
            {
                warn!(name = %s.name, "emotes: dropped an entry that is not valid");
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(slot) = inner.files.entry(hash) {
                match std::fs::read(dir.join(hex(&hash))) {
                    Ok(b) if <[u8; 32]>::from(Sha256::digest(&b)) == hash => {
                        slot.insert(Bytes::from(b));
                    }
                    _ => {
                        warn!(name = %s.name, "emotes: its file is missing or damaged; dropped");
                        continue;
                    }
                }
            }
            let len = inner.files[&hash].len() as u32;
            inner.emotes.push(boxed(Emote {
                name: s.name,
                hash,
                sticker: s.sticker,
                pack: s.pack,
                len,
                w: s.w,
                h: s.h,
            }));
        }
        // Only what this store writes is touched: hex names, its temp files
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let orphan = unhex::<32>(name).is_some_and(|h| !inner.files.contains_key(&h));
            let temp = name
                .strip_suffix(".tmp")
                .is_some_and(|n| unhex::<32>(n).is_some() || n == MANIFEST);
            if orphan || temp {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(EmoteStore {
            dir,
            max_emote: cfg.max_emote_kb * 1024,
            max_sticker: cfg.max_sticker_kb * 1024,
            max_total: u64::from(cfg.max_total_mb) << 20,
            inner: Mutex::new(inner),
            writing: tokio::sync::Mutex::new(()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What one connection may download: every file twice and the largest
    /// once more at once, that much again an hour.
    fn download_budget(&self, now: Instant) -> Bucket {
        let cap = (2 * self.max_total + u64::from(self.max_sticker)) as f64;
        Bucket::new(cap, self.max_total as f64 / 3600.0, now)
    }

    /// `Authenticated.emotes` for a new connection: its own bearer.
    pub fn access(&self, session: SessionId) -> EmoteAccess {
        let token = hex(&rand::random::<[u8; 16]>());
        let budget = self.download_budget(Instant::now());
        self.lock().bearers.insert(token.clone(), (session, budget));
        EmoteAccess {
            token: Secret(token),
            max_emote_bytes: self.max_emote,
            max_sticker_bytes: self.max_sticker,
            max_total_bytes: self.max_total,
            max_items: MAX_EMOTES as u32,
        }
    }

    pub fn list(&self) -> ServerMessage {
        self.lock().list()
    }

    /// A connection's end: its bearer and its open uploads go.
    pub fn forget(&self, session: SessionId) {
        let mut inner = self.lock();
        inner.bearers.retain(|_, (s, _)| *s != session);
        let gone: Vec<String> = inner
            .tickets
            .iter()
            .filter(|(_, p)| p.session == session)
            .map(|(t, _)| t.clone())
            .collect();
        for t in gone {
            if let Some(p) = inner.tickets.remove(&t) {
                inner.reserved -= u64::from(p.emote.len);
            }
        }
    }

    fn cap(&self, sticker: bool) -> u32 {
        if sticker {
            self.max_sticker
        } else {
            self.max_emote
        }
    }

    fn too_big(&self, sticker: bool) -> String {
        format!(
            "a{} file may be at most {} KiB here",
            if sticker { " sticker's" } else { "n emote's" },
            self.cap(sticker) / 1024
        )
    }

    /// An admin adds `emote`, a file of `emote.len` bytes.
    pub fn add(&self, session: SessionId, emote: Emote, now: Instant) -> Result<Added, String> {
        if !valid_emote_name(&emote.name) {
            return Err("an emote's name is 2 to 30 of a-z, 0-9 and _".into());
        }
        if !valid_emote_pack(&emote.pack) {
            return Err("a pack's name is one line of at most 32 characters".into());
        }
        let len = emote.len;
        if len == 0 || len > self.cap(emote.sticker) {
            return Err(self.too_big(emote.sticker));
        }
        let emote = boxed(emote);
        let mut inner = self.lock();
        inner.sweep(now);
        // The same add again (an answer that came too late): its own ticket
        if let Some((t, p)) = inner.tickets.iter_mut().find(|(_, p)| {
            p.session == session && p.emote.name == emote.name && p.emote.hash == emote.hash
        }) {
            p.until = now + TICKET_LIFETIME;
            return Ok(Added::Ticket(t.clone()));
        }
        if inner.emotes.iter().any(|e| e.name == emote.name)
            || inner.tickets.values().any(|p| p.emote.name == emote.name)
        {
            return Err(format!(":{}: is taken", emote.name));
        }
        if inner.emotes.len() + inner.tickets.len() >= MAX_EMOTES {
            return Err(format!(
                "a server has at most {MAX_EMOTES} emotes and stickers"
            ));
        }
        if let Some(have) = inner.files.get(&emote.hash) {
            // A file the relay holds already: a rename, or the same picture
            // under a second name
            if have.len() != len as usize {
                return Err("the file is not the size it was said to be".into());
            }
            inner.emotes.push(emote);
            return Ok(Added::Listed);
        }
        if inner
            .tickets
            .values()
            .filter(|p| p.session == session)
            .count()
            >= TICKETS_PER_SESSION
        {
            return Err("too many uploads at once: wait for some to finish".into());
        }
        if inner.total() + inner.reserved + u64::from(len) > self.max_total {
            return Err(format!(
                "the server's emotes may take {} MiB in all, and are full",
                self.max_total >> 20
            ));
        }
        let ticket = hex(&rand::random::<[u8; 16]>());
        inner.reserved += u64::from(len);
        inner.tickets.insert(
            ticket.clone(),
            Pending {
                session,
                emote,
                until: now + TICKET_LIFETIME,
            },
        );
        Ok(Added::Ticket(ticket))
    }

    /// Remove the emotes called `names`; a file goes when no other names it.
    /// The names it does not have.
    pub fn remove(&self, names: &[String]) -> Vec<String> {
        let mut inner = self.lock();
        let mut unknown = Vec::new();
        for name in names {
            let Some(at) = inner.emotes.iter().position(|e| e.name == *name) else {
                unknown.push(name.clone());
                continue;
            };
            let gone = inner.emotes.remove(at);
            if !inner.emotes.iter().any(|e| e.hash == gone.hash) {
                inner.files.remove(&gone.hash);
                inner.gone.push(gone.hash);
            }
        }
        unknown
    }

    /// Call `from` by `to`, where it stands in the list.
    pub fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        if !valid_emote_name(to) {
            return Err("an emote's name is 2 to 30 of a-z, 0-9 and _".into());
        }
        let mut inner = self.lock();
        if inner.emotes.iter().any(|e| e.name == to)
            || inner.tickets.values().any(|p| p.emote.name == to)
        {
            return Err(format!(":{to}: is taken"));
        }
        let e = inner
            .emotes
            .iter_mut()
            .find(|e| e.name == from)
            .ok_or_else(|| format!(":{from}: is not one of this server's"))?;
        e.name = to.to_owned();
        Ok(())
    }

    /// Put `names` in `pack`, and/or make them the kind `sticker`: all of
    /// them, or none and why.
    pub fn moved(
        &self,
        names: &[String],
        pack: Option<&str>,
        sticker: Option<bool>,
    ) -> Result<(), String> {
        if pack.is_some_and(|p| !valid_emote_pack(p)) {
            return Err("a pack's name is one line of at most 32 characters".into());
        }
        let mut inner = self.lock();
        for name in names {
            let e = inner
                .emotes
                .iter()
                .find(|e| e.name == *name)
                .ok_or_else(|| format!(":{name}: is not one of this server's"))?;
            if sticker.is_some_and(|k| e.len > self.cap(k)) {
                return Err(format!(
                    ":{name}: is too big: {}",
                    self.too_big(sticker == Some(true))
                ));
            }
        }
        for e in inner.emotes.iter_mut().filter(|e| names.contains(&e.name)) {
            if let Some(p) = pack {
                p.clone_into(&mut e.pack);
            }
            if let Some(k) = sticker {
                e.sticker = k;
            }
        }
        Ok(())
    }

    pub fn set_stickers(&self, on: bool) {
        self.lock().stickers = on;
    }

    /// An uploaded file, checked and kept: its ticket is spent either way.
    fn store(&self, ticket: &str, hash: [u8; 32], body: &[u8]) -> Result<(), (u16, &'static str)> {
        let mut inner = self.lock();
        let Some(p) = inner
            .tickets
            .remove(ticket)
            .filter(|p| p.emote.hash == hash)
        else {
            return Err((401, "no such upload"));
        };
        inner.reserved -= u64::from(p.emote.len);
        if p.until <= Instant::now() {
            return Err((401, "the upload's ticket has run out"));
        }
        if body.len() != p.emote.len as usize {
            return Err((400, "the file is not the size it was said to be"));
        }
        if <[u8; 32]>::from(Sha256::digest(body)) != hash {
            return Err((422, "the file is not the one its hash names"));
        }
        if !is_picture(body) {
            return Err((415, "not a PNG, GIF, WebP or JPEG"));
        }
        if inner.emotes.iter().any(|e| e.name == p.emote.name) {
            return Err((409, "that name was taken meanwhile"));
        }
        inner.files.insert(hash, Bytes::copy_from_slice(body));
        inner.emotes.push(p.emote);
        Ok(())
    }

    /// A new file, on disk before its upload is answered.
    async fn write_file(&self, hash: [u8; 32], bytes: Bytes) {
        let dir = self.dir.clone();
        let written =
            tokio::task::spawn_blocking(move || atomic_write(&dir, &hex(&hash), &bytes)).await;
        if !matches!(written, Ok(Ok(()))) {
            warn!(?written, "emotes: could not write {}", self.dir.display());
        }
    }

    /// Write the manifest as it is now: to a temp file, then renamed over the
    /// old, so a crash leaves one or the other. Then the files it no longer
    /// names go.
    async fn write_manifest(&self) {
        let _turn = self.writing.lock().await;
        let (manifest, gone) = {
            let mut inner = self.lock();
            // The same picture may have come back under another name meanwhile
            let gone: Vec<[u8; 32]> = std::mem::take(&mut inner.gone)
                .into_iter()
                .filter(|h| !inner.files.contains_key(h))
                .collect();
            let manifest = Manifest {
                stickers: inner.stickers,
                emotes: inner
                    .emotes
                    .iter()
                    .map(|e| Stored {
                        name: e.name.clone(),
                        hash: hex(&e.hash),
                        sticker: e.sticker,
                        pack: e.pack.clone(),
                        w: e.w,
                        h: e.h,
                    })
                    .collect(),
            };
            (manifest, gone)
        };
        let dir = self.dir.clone();
        let written = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            atomic_write(&dir, MANIFEST, &serde_json::to_vec_pretty(&manifest)?)?;
            for hash in gone {
                let _ = std::fs::remove_file(dir.join(hex(&hash)));
            }
            Ok(())
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            warn!(?written, "emotes: could not write {}", self.dir.display());
        }
    }

    /// A change: a moment later the manifest is written and the new list goes
    /// out, with any other change made meanwhile (an import of hundreds is one
    /// write and one list).
    fn changed(self: &Arc<Self>, state: &Arc<ServerState>) {
        let due = std::mem::replace(&mut self.lock().broadcast_due, true);
        if due {
            return;
        }
        let (store, state) = (self.clone(), state.clone());
        tokio::spawn(async move {
            tokio::time::sleep(BROADCAST_AFTER).await;
            store.lock().broadcast_due = false;
            store.write_manifest().await;
            if let Ok(data) = encode_server_msg(&store.list()) {
                state.broadcast_raw_to_all(&data).await;
            }
        });
    }
}

fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(name))
}

// ── Control messages ──────────────────────────────────────────────────────

async fn refuse(tx: &mpsc::Sender<Vec<u8>>, name: String, reason: String) {
    if let Ok(data) = encode_server_msg(&ServerMessage::EmoteError { name, reason }) {
        let _ = tx.send(data).await;
    }
}

/// The store, for an admin; else why not, said to the asker.
async fn for_admin(
    state: &ServerState,
    session: SessionId,
    tx: &mpsc::Sender<Vec<u8>>,
    name: &str,
) -> Option<Arc<EmoteStore>> {
    let Some(store) = state.emotes.clone() else {
        refuse(tx, name.into(), "this server keeps no emotes".into()).await;
        return None;
    };
    if !state.is_admin(session) {
        refuse(
            tx,
            name.into(),
            "only an admin can change the server's emotes".into(),
        )
        .await;
        return None;
    }
    Some(store)
}

/// `ClientMessage::EmoteAdd`.
pub(crate) async fn handle_add(
    state: &Arc<ServerState>,
    session: SessionId,
    emote: Emote,
    tx: &mpsc::Sender<Vec<u8>>,
) {
    let name = emote.name.clone();
    let Some(store) = for_admin(state, session, tx, &name).await else {
        return;
    };
    let hash = emote.hash;
    match store.add(session, emote, Instant::now()) {
        Ok(Added::Ticket(ticket)) => {
            if let Ok(data) = encode_server_msg(&ServerMessage::EmoteTicket { hash, name, ticket })
            {
                let _ = tx.send(data).await;
            }
        }
        Ok(Added::Listed) => store.changed(state),
        Err(reason) => refuse(tx, name, reason).await,
    }
}

/// `ClientMessage::EmoteRemove`.
pub(crate) async fn handle_remove(
    state: &Arc<ServerState>,
    session: SessionId,
    names: Vec<String>,
    tx: &mpsc::Sender<Vec<u8>>,
) {
    let Some(store) = for_admin(state, session, tx, "").await else {
        return;
    };
    if names.len() > MAX_EMOTES {
        return refuse(tx, String::new(), format!("at most {MAX_EMOTES} at once")).await;
    }
    let unknown = store.remove(&names);
    if unknown.len() < names.len() {
        store.changed(state);
    }
    if let Some(first) = unknown.first() {
        let list = unknown
            .iter()
            .take(5)
            .map(|n| format!(":{n}:"))
            .collect::<Vec<_>>()
            .join(", ");
        let more = unknown.len().saturating_sub(5);
        let reason = if more > 0 {
            format!("not this server's: {list} and {more} more")
        } else {
            format!("not this server's: {list}")
        };
        refuse(tx, first.clone(), reason).await;
    }
}

/// `ClientMessage::EmoteRename`.
pub(crate) async fn handle_rename(
    state: &Arc<ServerState>,
    session: SessionId,
    from: String,
    to: String,
    tx: &mpsc::Sender<Vec<u8>>,
) {
    let Some(store) = for_admin(state, session, tx, &from).await else {
        return;
    };
    match store.rename(&from, &to) {
        Ok(()) => store.changed(state),
        Err(reason) => refuse(tx, from, reason).await,
    }
}

/// `ClientMessage::EmoteMove`.
pub(crate) async fn handle_move(
    state: &Arc<ServerState>,
    session: SessionId,
    names: Vec<String>,
    pack: Option<String>,
    sticker: Option<bool>,
    tx: &mpsc::Sender<Vec<u8>>,
) {
    let first = names.first().cloned().unwrap_or_default();
    let Some(store) = for_admin(state, session, tx, &first).await else {
        return;
    };
    if names.len() > MAX_EMOTES {
        return refuse(tx, first, format!("at most {MAX_EMOTES} at once")).await;
    }
    match store.moved(&names, pack.as_deref(), sticker) {
        Ok(()) => store.changed(state),
        Err(reason) => refuse(tx, first, reason).await,
    }
}

/// `ClientMessage::EmoteStickers`.
pub(crate) async fn handle_stickers(
    state: &Arc<ServerState>,
    session: SessionId,
    on: bool,
    tx: &mpsc::Sender<Vec<u8>>,
) {
    let Some(store) = for_admin(state, session, tx, "").await else {
        return;
    };
    store.set_stickers(on);
    store.changed(state);
}

// ── HTTP: `/e/v1/<hash>` ──────────────────────────────────────────────────

/// An upload whose head passed: read at most `len` bytes, then `finish_put`.
pub(crate) struct Upload {
    pub len: usize,
    ticket: String,
    hash: [u8; 32],
}

fn cors(mut reply: Reply, cache: &str) -> Reply {
    reply
        .headers
        .push(("access-control-allow-origin", "*".into()));
    reply.headers.push(("cache-control", cache.into()));
    reply
        .headers
        .push(("x-content-type-options", "nosniff".into()));
    reply
}

fn say(status: u16, body: &'static str) -> Reply {
    cors(
        Reply {
            status,
            headers: vec![("content-type", "text/plain; charset=utf-8".into())],
            body: Bytes::from_static(body.as_bytes()),
        },
        "no-store",
    )
}

/// A `/e/` request after its head: a download is answered at once (the files
/// are in memory), an upload is let through to its body only with a ticket
/// for that very file.
pub(crate) fn prepare(
    state: &ServerState,
    method: &str,
    target: &str,
    authorization: Option<&str>,
) -> Prepared {
    let Some(store) = state.emotes.as_ref() else {
        return Prepared::Reply(say(404, "this server keeps no emotes"));
    };
    let Some(hash) = target.strip_prefix("/e/v1/").and_then(unhex::<32>) else {
        return Prepared::Reply(say(404, "not found"));
    };
    let token = authorization.and_then(|v| v.strip_prefix("Bearer "));
    match method {
        "OPTIONS" => {
            let mut reply = say(204, "");
            reply.body = Bytes::new();
            reply
                .headers
                .push(("access-control-allow-methods", "GET, PUT".into()));
            reply.headers.push((
                "access-control-allow-headers",
                "authorization, content-type".into(),
            ));
            reply.headers.push(("access-control-max-age", "600".into()));
            Prepared::Reply(reply)
        }
        "GET" | "HEAD" => {
            let mut inner = store.lock();
            let Some(body) = inner
                .files
                .get(&hash)
                .filter(|_| inner.emotes.iter().any(|e| e.hash == hash))
                .cloned()
            else {
                let member = token.is_some_and(|t| inner.bearers.contains_key(t));
                return Prepared::Reply(if member {
                    say(404, "no such emote")
                } else {
                    say(401, "a member's token is needed")
                });
            };
            let Some((_, budget)) = token.and_then(|t| inner.bearers.get_mut(t)) else {
                return Prepared::Reply(say(401, "a member's token is needed"));
            };
            if !budget.take(body.len() as f64, Instant::now()) {
                return Prepared::Reply(say(429, "too many downloads: try again later"));
            }
            // Its hash is its name: the same address is always the same file
            Prepared::Reply(cors(
                Reply {
                    status: 200,
                    headers: vec![("content-type", "application/octet-stream".into())],
                    body,
                },
                "private, max-age=31536000, immutable",
            ))
        }
        "PUT" => {
            let inner = store.lock();
            match token.and_then(|t| inner.tickets.get(t).map(|p| (t, p))) {
                Some((t, p)) if p.emote.hash == hash => Prepared::EmotePut(Upload {
                    len: p.emote.len as usize,
                    ticket: t.to_owned(),
                    hash,
                }),
                _ => Prepared::Reply(say(401, "no such upload")),
            }
        }
        _ => {
            let mut reply = say(405, "method not allowed");
            reply.headers.push(("allow", "GET, PUT, OPTIONS".into()));
            Prepared::Reply(reply)
        }
    }
}

/// The body of an upload: checked, kept, and the list goes out.
pub(crate) async fn finish_put(state: &Arc<ServerState>, upload: Upload, body: Bytes) -> Reply {
    let Some(store) = state.emotes.clone() else {
        return say(404, "this server keeps no emotes");
    };
    match store.store(&upload.ticket, upload.hash, &body) {
        Ok(()) => {
            store.write_file(upload.hash, body).await;
            store.changed(state);
            say(201, "stored")
        }
        Err((status, why)) => {
            debug!(status, why, "emotes: an upload was refused");
            say(status, why)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> EmoteStore {
        EmoteStore::open(&EmotesConfig {
            enabled: true,
            max_emote_kb: 1,
            max_sticker_kb: 2,
            max_total_mb: 1,
            dir: dir.to_string_lossy().into_owned(),
        })
        .unwrap()
    }

    fn emote(name: &str, body: &[u8]) -> Emote {
        Emote {
            name: name.into(),
            hash: Sha256::digest(body).into(),
            sticker: false,
            pack: String::new(),
            len: body.len() as u32,
            w: 0,
            h: 0,
        }
    }

    /// `e`, said to be `len` bytes.
    fn sized(e: Emote, len: u32) -> Emote {
        Emote { len, ..e }
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfake but shaped like one";

    fn temp() -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("voipc-emotes-{}", hex(&rand::random::<[u8; 8]>())));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(s: &EmoteStore) -> Vec<String> {
        s.lock().emotes.iter().map(|e| e.name.clone()).collect()
    }

    #[test]
    fn an_upload_needs_its_ticket_its_size_its_hash_and_a_picture() {
        let dir = temp();
        let s = store(&dir);
        let now = Instant::now();
        let e = emote("pog", PNG);
        let Ok(Added::Ticket(t)) = s.add(7, e.clone(), now) else {
            panic!()
        };
        assert_eq!(s.store("guess", e.hash, PNG), Err((401, "no such upload")));
        let Ok(Added::Ticket(t2)) = s.add(7, emote("pog2", PNG), now) else {
            panic!()
        };
        assert_eq!(
            s.store(&t2, e.hash, &PNG[1..]),
            Err((400, "the file is not the size it was said to be"))
        );
        let Ok(Added::Ticket(t3)) = s.add(7, emote("pog3", PNG), now) else {
            panic!()
        };
        let mut other = PNG.to_vec();
        other[20] ^= 1;
        assert_eq!(
            s.store(&t3, e.hash, &other),
            Err((422, "the file is not the one its hash names"))
        );
        let text = b"<svg onload=alert(1)>....";
        let Ok(Added::Ticket(t4)) = s.add(7, emote("svg", text), now) else {
            panic!()
        };
        assert_eq!(
            s.store(&t4, emote("svg", text).hash, text),
            Err((415, "not a PNG, GIF, WebP or JPEG"))
        );
        assert_eq!(s.store(&t, e.hash, PNG), Ok(()));
        assert_eq!(
            s.store(&t, e.hash, PNG),
            Err((401, "no such upload")),
            "a ticket is spent"
        );
        assert_eq!(s.lock().reserved, 0, "every ticket gave its bytes back");
        let ServerMessage::EmoteList { emotes, .. } = s.list() else {
            panic!()
        };
        assert_eq!(emotes, [e]);
    }

    #[test]
    fn the_same_add_again_gets_its_open_ticket_and_a_shape_is_held_to_its_box() {
        let dir = temp();
        let s = store(&dir);
        let now = Instant::now();
        let e = Emote {
            w: 4000,
            h: 64,
            ..emote("pog", PNG)
        };
        let Ok(Added::Ticket(t)) = s.add(7, e.clone(), now) else {
            panic!()
        };
        assert_eq!(
            s.add(7, e.clone(), now + Duration::from_secs(30)),
            Ok(Added::Ticket(t.clone())),
            "an answer that came too late: the add again"
        );
        assert!(
            s.add(8, e.clone(), now).unwrap_err().contains("taken"),
            "another connection's is taken"
        );
        assert_eq!(s.lock().reserved, PNG.len() as u64, "reserved once");
        s.store(&t, e.hash, PNG).unwrap();
        let kept = s.lock().emotes[0].clone();
        assert_eq!((kept.w, kept.h), (EMOTE_BOX, 64));
    }

    #[test]
    fn names_caps_and_a_rename_without_an_upload() {
        let dir = temp();
        let s = store(&dir);
        let now = Instant::now();
        assert!(s.add(1, emote("Bad", PNG), now).is_err());
        assert!(s
            .add(
                1,
                Emote {
                    pack: "two\nlines".into(),
                    ..emote("ok", PNG)
                },
                now
            )
            .is_err());
        assert!(s
            .add(1, sized(emote("big", PNG), 1025), now)
            .unwrap_err()
            .contains("1 KiB"));
        assert!(
            s.add(
                1,
                Emote {
                    sticker: true,
                    ..sized(emote("big", PNG), 1025)
                },
                now
            )
            .is_ok(),
            "a sticker may be bigger"
        );
        let e = emote("pog", PNG);
        let Ok(Added::Ticket(t)) = s.add(1, e.clone(), now) else {
            panic!()
        };
        assert!(
            s.add(1, emote("pog", b"x"), now)
                .unwrap_err()
                .contains("taken"),
            "a name being uploaded is taken"
        );
        s.store(&t, e.hash, PNG).unwrap();
        assert_eq!(s.add(1, emote("pog_renamed", PNG), now), Ok(Added::Listed));
        assert!(s
            .rename("pog_renamed", "pog")
            .unwrap_err()
            .contains("taken"));
        assert!(s.rename("nope", "fresh").is_err());
        assert!(s.rename("pog_renamed", "Bad").is_err());
        s.rename("pog_renamed", "pog_new").unwrap();
        s.rename("pog_new", "pog_renamed").unwrap();
        assert!(s.remove(&["pog".into()]).is_empty());
        assert!(
            s.lock().files.contains_key(&e.hash),
            "the file stays: another emote names it"
        );
        assert_eq!(
            s.remove(&["pog_renamed".into(), "nope".into()]),
            ["nope"],
            "what it does not have is said"
        );
        let inner = s.lock();
        assert!(inner.files.is_empty());
        assert_eq!(inner.gone, [e.hash], "deleted with the next manifest");
    }

    #[test]
    fn a_move_is_all_or_nothing_and_a_sticker_too_big_for_an_emote_stays() {
        let dir = temp();
        let s = store(&dir);
        let now = Instant::now();
        let small = emote("small", PNG);
        let big_body = [PNG, &[0u8; 1100][..]].concat();
        let big = Emote {
            sticker: true,
            ..emote("big", &big_body)
        };
        for (e, body) in [(&small, PNG), (&big, &big_body[..])] {
            let Ok(Added::Ticket(t)) = s.add(1, e.clone(), now) else {
                panic!()
            };
            s.store(&t, e.hash, body).unwrap();
        }
        let both = ["small".to_string(), "big".to_string()];
        assert!(s
            .moved(&both, Some("Cats"), Some(false))
            .unwrap_err()
            .contains(":big: is too big"));
        assert!(
            s.lock().emotes.iter().all(|e| e.pack.is_empty()),
            "none moved"
        );
        assert!(s
            .moved(&["small".into(), "gone".into()], Some("Cats"), None)
            .unwrap_err()
            .contains(":gone:"));
        assert!(s.moved(&both, Some("bad\npack"), None).is_err());
        s.moved(&both, Some("Cats"), Some(true)).unwrap();
        assert!(s
            .lock()
            .emotes
            .iter()
            .all(|e| e.pack == "Cats" && e.sticker));
        assert_eq!(names(&s), both, "in their places");
    }

    #[test]
    fn tickets_run_out_and_go_with_their_session_and_the_total_is_kept() {
        let dir = temp();
        let s = store(&dir);
        let now = Instant::now();
        // 1 MiB in all, 2 KiB stickers: reserving counts
        for i in 0..512 {
            let r = s.add(
                9,
                Emote {
                    sticker: true,
                    ..sized(emote(&format!("s{i}"), &[i as u8]), 2048)
                },
                now,
            );
            if i < TICKETS_PER_SESSION {
                assert!(r.is_ok(), "{i}");
            } else {
                assert!(r.unwrap_err().contains("too many uploads"));
                break;
            }
        }
        let open = |s: &EmoteStore| {
            let inner = s.lock();
            (inner.tickets.len(), inner.reserved)
        };
        s.forget(9);
        assert_eq!(open(&s), (0, 0));
        let Ok(Added::Ticket(_)) = s.add(3, sized(emote("late", PNG), 10), now) else {
            panic!()
        };
        s.lock().sweep(now + TICKET_LIFETIME);
        assert_eq!(open(&s), (0, 0));
    }

    #[tokio::test]
    async fn what_was_kept_comes_back_after_a_restart_and_nothing_else_does() {
        let dir = temp();
        let s = Arc::new(store(&dir));
        let e = Emote {
            w: 100,
            h: 50,
            ..emote("pog", PNG)
        };
        let Ok(Added::Ticket(t)) = s.add(1, e.clone(), Instant::now()) else {
            panic!()
        };
        s.store(&t, e.hash, PNG).unwrap();
        s.set_stickers(true);
        s.write_file(e.hash, Bytes::from_static(PNG)).await;
        s.write_manifest().await;
        std::fs::write(dir.join(hex(&[7; 32])), b"orphan").unwrap();
        std::fs::write(dir.join("keep-me.txt"), b"not ours").unwrap();
        let again = store(&dir);
        let ServerMessage::EmoteList { stickers, emotes } = again.list() else {
            panic!()
        };
        assert!(stickers);
        assert_eq!(emotes, std::slice::from_ref(&e), "its size and shape too");
        assert!(!dir.join(hex(&[7; 32])).exists(), "an orphan file goes");
        assert!(dir.join("keep-me.txt").exists(), "what is not ours stays");
        // Removed: its file goes once the manifest says so
        assert!(s.remove(&["pog".into()]).is_empty());
        assert!(dir.join(hex(&e.hash)).exists());
        s.write_manifest().await;
        assert!(!dir.join(hex(&e.hash)).exists());
        // A damaged file drops its emote
        std::fs::write(dir.join(hex(&e.hash)), b"changed").unwrap();
        let ServerMessage::EmoteList { emotes, .. } = store(&dir).list() else {
            panic!()
        };
        assert!(emotes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_member_downloads_and_only_with_a_ticket_uploads() {
        let dir = temp();
        let s = store(&dir);
        let e = emote("pog", PNG);
        let Ok(Added::Ticket(t)) = s.add(1, e.clone(), Instant::now()) else {
            panic!()
        };
        s.store(&t, e.hash, PNG).unwrap();
        let access = s.access(5);
        assert_eq!(
            format!("{access:?}").matches(&access.token.0).count(),
            0,
            "the token is never in a log"
        );
        assert_eq!((access.max_total_bytes, access.max_items), (1 << 20, 400));
        let mut state = ServerState::for_tests();
        state.emotes = Some(Arc::new(s));
        let path = format!("/e/v1/{}", hex(&e.hash));
        let status = |p: Prepared| match p {
            Prepared::Reply(r) => r.status,
            Prepared::EmotePut(_) => 100,
            _ => 0,
        };
        assert_eq!(status(prepare(&state, "GET", &path, None)), 401);
        assert_eq!(
            status(prepare(&state, "GET", &path, Some("Bearer nope"))),
            401
        );
        let bearer = format!("Bearer {}", access.token.0);
        let Prepared::Reply(ok) = prepare(&state, "GET", &path, Some(&bearer)) else {
            panic!()
        };
        assert_eq!((ok.status, &ok.body[..]), (200, PNG));
        assert!(ok
            .headers
            .iter()
            .any(|(k, v)| *k == "cache-control" && v.contains("immutable")));
        assert_eq!(
            status(prepare(
                &state,
                "GET",
                &format!("/e/v1/{}", hex(&[1; 32])),
                Some(&bearer)
            )),
            404
        );
        assert_eq!(
            status(prepare(&state, "PUT", &path, Some(&bearer))),
            401,
            "a member's token uploads nothing"
        );
        assert_eq!(status(prepare(&state, "DELETE", &path, Some(&bearer))), 405);
        assert_eq!(
            status(prepare(
                &state,
                "GET",
                "/e/v1/../../etc/passwd",
                Some(&bearer)
            )),
            404
        );
        state.emotes.as_ref().unwrap().forget(5);
        assert_eq!(
            status(prepare(&state, "GET", &path, Some(&bearer))),
            401,
            "a bearer goes with its connection"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_member_fetching_in_a_loop_is_told_to_wait() {
        let dir = temp();
        let s = store(&dir);
        let e = emote("pog", PNG);
        let Ok(Added::Ticket(t)) = s.add(1, e.clone(), Instant::now()) else {
            panic!()
        };
        s.store(&t, e.hash, PNG).unwrap();
        let access = s.access(5);
        let mut state = ServerState::for_tests();
        state.emotes = Some(Arc::new(s));
        let (path, bearer) = (
            format!("/e/v1/{}", hex(&e.hash)),
            format!("Bearer {}", access.token.0),
        );
        // 2 MiB + 2 KiB of budget: about 70 000 fetches of this small file
        let mut fetched = 0u64;
        loop {
            let Prepared::Reply(r) = prepare(&state, "GET", &path, Some(&bearer)) else {
                panic!()
            };
            if r.status == 429 {
                break;
            }
            assert_eq!(r.status, 200);
            fetched += PNG.len() as u64;
            assert!(fetched < 3 << 20, "never stopped");
        }
        assert!(fetched >= 2 << 20, "every file twice is fine");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
