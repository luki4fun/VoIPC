//! The server's emotes and stickers (protocol v14), on this side.
//!
//! The list comes as `emote-list` events (files.rs `on_emote_message`). Each
//! file is fetched once, checked against its hash, and kept here only as the
//! PNG this app's sanitizer wrote for it (`media::sanitize`): the relay's
//! bytes, or an admin's, never reach the page. An admin's import goes through
//! `prepare_emote` (what to upload, and what to preview) and `emote_add`.

use std::path::PathBuf;
use std::time::Duration;

use ring::digest::{digest, SHA256};
use serde::Deserialize;
use tauri::State;
use voipc_media::{Motion, Profile, SANITIZER_VERSION};
use voipc_protocol::conv::{hex, unhex};
use voipc_protocol::messages::ClientMessage;
use voipc_protocol::types::Emote;

use crate::app_state::AppState;
use crate::files::{body_bytes, files_of};

/// How long the relay has to answer an add.
const ANSWER_TIME: Duration = Duration::from_secs(30);

pub(crate) fn sha256(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, b).as_ref());
    out
}

fn profile(sticker: bool) -> Profile {
    if sticker {
        Profile::Sticker
    } else {
        Profile::Emote
    }
}

fn dir() -> PathBuf {
    crate::config::data_dir().join("emotes")
}

/// Where the PNG written for `hash` as `profile` is kept: named by the
/// sanitizer's version too, so a decoder fix makes every one again.
fn cached(hash: &[u8; 32], sticker: bool) -> (PathBuf, PathBuf) {
    let base = format!(
        "{}-{SANITIZER_VERSION}-{}",
        hex(hash),
        if sticker { "s" } else { "e" }
    );
    (
        dir().join(format!("{base}.png")),
        dir().join(format!("{base}.still.png")),
    )
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", rand::random::<u32>()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// An emote or sticker of `server` as the PNG it may be shown as (its first
/// frame only, with `still`), from this device's copy or else fetched,
/// checked and sanitized now. With `fetch_only`, only made into that copy:
/// nothing crosses to the page (a server's whole list is, at connect).
#[tauri::command]
pub async fn emote_image(
    state: State<'_, AppState>,
    server: String,
    hash: String,
    sticker: bool,
    still: bool,
    fetch_only: Option<bool>,
) -> Result<tauri::ipc::Response, String> {
    let hash = unhex::<32>(&hash).ok_or("invalid hash")?;
    let fetch_only = fetch_only == Some(true);
    let (png, first) = cached(&hash, sticker);
    let kept = tokio::task::spawn_blocking(move || {
        if fetch_only {
            return png.exists().then(Vec::new);
        }
        if still {
            if let Ok(b) = std::fs::read(&first) {
                return Some(b);
            }
        }
        std::fs::read(&png).ok()
    })
    .await
    .map_err(|e| e.to_string())?;
    if let Some(bytes) = kept {
        return Ok(tauri::ipc::Response::new(bytes));
    }
    let body = fetch_verified(&state, &server, &hash).await?;
    let p = profile(sticker);
    let clean = crate::media::sanitize(body, p, p.max_output(), Motion::default()).await?;
    let (png, first) = cached(&hash, sticker);
    let (out, still_png) = (clean.png.clone(), clean.still.clone());
    let _ = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        std::fs::create_dir_all(dir())?;
        // The still first: a PNG kept here means its still is too
        if let Some(s) = &still_png {
            write_atomic(&first, s)?;
        }
        write_atomic(&png, &out)
    })
    .await;
    Ok(tauri::ipc::Response::new(if fetch_only {
        Vec::new()
    } else if still {
        clean.still.unwrap_or(clean.png)
    } else {
        clean.png
    }))
}

/// An emote's file as `server` keeps it, checked against its hash.
async fn fetch_verified(
    state: &State<'_, AppState>,
    server: &str,
    hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let files = files_of(state, server).await?;
    let token = files
        .emotes
        .as_ref()
        .ok_or("this server has no emotes")?
        .token
        .0
        .clone();
    let (status, body) = files.emote_request("GET", hash, &token, &[]).await?;
    if status != 200 {
        return Err(format!("the server would not give the emote ({status})"));
    }
    if sha256(&body) != *hash {
        return Err("the server gave another file than the emote's".into());
    }
    Ok(body)
}

/// An emote's file itself (admins), for adding it again as the other kind:
/// the page hands it straight back to `emote_add` and never shows it.
#[tauri::command]
pub async fn emote_file(
    state: State<'_, AppState>,
    server: String,
    hash: String,
) -> Result<tauri::ipc::Response, String> {
    let hash = unhex::<32>(&hash).ok_or("invalid hash")?;
    Ok(tauri::ipc::Response::new(
        fetch_verified(&state, &server, &hash).await?,
    ))
}

/// How long a picture no open server lists is kept: a server not connected
/// now still has its emotes when it is again.
const UNLISTED_KEPT: Duration = Duration::from_secs(30 * 24 * 3600);

/// What becomes of a cached picture: made by an older sanitizer, it goes; one
/// an open server lists is kept, from now on; any other once unlisted too long.
#[derive(Debug, PartialEq, Eq)]
enum Kept {
    Go,
    Renew,
    Stay,
}

fn kept(name: &str, keep: &std::collections::HashSet<String>, age: Duration) -> Kept {
    let hash = name.split('-').next().unwrap_or("");
    if !name.contains(&format!("-{SANITIZER_VERSION}-")) {
        Kept::Go
    } else if keep.contains(hash) {
        Kept::Renew
    } else if age > UNLISTED_KEPT {
        Kept::Go
    } else {
        Kept::Stay
    }
}

/// `keep`: the hashes every open server lists. Their pictures are kept, and
/// what this device made for others goes once unlisted for `UNLISTED_KEPT`.
#[tauri::command]
pub async fn emote_cache_retain(keep: Vec<String>) -> Result<(), String> {
    let keep: std::collections::HashSet<String> = keep.into_iter().collect();
    tokio::task::spawn_blocking(move || {
        let Ok(entries) = std::fs::read_dir(dir()) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let age = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .unwrap_or_default();
            match kept(&name, &keep, age) {
                Kept::Go => {
                    let _ = std::fs::remove_file(entry.path());
                }
                // Its time counts from the last list that named it
                Kept::Renew => {
                    let _ = std::fs::File::options()
                        .write(true)
                        .open(entry.path())
                        .and_then(|f| f.set_modified(std::time::SystemTime::now()));
                }
                Kept::Stay => {}
            }
        }
    })
    .await
    .map_err(|e| e.to_string())
}

#[derive(Deserialize)]
struct Prepare {
    sticker: bool,
    /// The most an upload may be (the relay's `max_emote_bytes` or
    /// `max_sticker_bytes`).
    max_bytes: usize,
}

/// A picture an admin picked, made ready to add: what to upload, and the
/// sanitized preview to show for it. Answered as a JSON head (its length in
/// the first four bytes, little-endian) and then the upload, the preview and
/// the preview's still, back to back.
///
/// What goes up is this app's own re-encoding when it fits (no metadata of
/// the file goes to the server), else the file as it is when that fits, else
/// the re-encoding with frames dropped until it fits.
#[tauri::command]
pub async fn prepare_emote(
    request: tauri::ipc::Request<'_>,
) -> Result<tauri::ipc::Response, String> {
    let args: Prepare = request
        .headers()
        .get("x-voipc-prepare")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("prepare_emote needs its x-voipc-prepare header")?;
    let src = body_bytes(&request, "prepare_emote")?;
    let p = profile(args.sticker);
    let full = crate::media::sanitize(src.clone(), p, p.max_output(), Motion::default()).await?;
    // The file as it is goes without its metadata: emotes are readable by
    // every member. Where that cannot be (a turned JPEG), it is made again
    let bare = voipc_media::strip(&src)
        .ok()
        .filter(|b| b.len() <= args.max_bytes);
    let (upload, how) = if full.png.len() <= args.max_bytes && !full.trimmed {
        (full.png.clone(), "clean")
    } else if let Some(bare) = bare {
        (bare, "original")
    } else {
        let fit = crate::media::sanitize(src, p, args.max_bytes, Motion::default()).await?;
        (fit.png, if fit.frames > 1 { "trimmed" } else { "still" })
    };
    let still = full.still.clone().unwrap_or_default();
    let head = serde_json::json!({
        "w": full.w, "h": full.h, "frames": full.frames, "how": how,
        "upload": upload.len(), "preview": full.png.len(), "still": still.len(),
    })
    .to_string();
    let mut out = (head.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(&upload);
    out.extend_from_slice(&full.png);
    out.extend_from_slice(&still);
    Ok(tauri::ipc::Response::new(out))
}

#[derive(Deserialize)]
pub struct Wanted {
    hash: String,
    sticker: bool,
}

/// Which of `items` this device has made nothing of yet, as `hash|s` or
/// `hash|e`: what a download would fetch.
#[tauri::command]
pub async fn emote_missing(items: Vec<Wanted>) -> Result<Vec<String>, String> {
    tokio::task::spawn_blocking(move || {
        items
            .into_iter()
            .filter(|w| unhex::<32>(&w.hash).is_some_and(|h| !cached(&h, w.sticker).0.exists()))
            .map(|w| format!("{}|{}", w.hash, if w.sticker { "s" } else { "e" }))
            .collect()
    })
    .await
    .map_err(|e| e.to_string())
}

/// What the pictures made for emotes and stickers take on this device.
#[tauri::command]
pub async fn emote_cache_size() -> Result<u64, String> {
    tokio::task::spawn_blocking(|| {
        std::fs::read_dir(dir()).map_or(0, |entries| {
            entries
                .flatten()
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
    })
    .await
    .map_err(|e| e.to_string())
}

/// All of them gone: each is made again from its server when next shown.
#[tauri::command]
pub async fn emote_cache_clear() -> Result<(), String> {
    tokio::task::spawn_blocking(|| match std::fs::remove_dir_all(dir()) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
        _ => Ok(()),
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Deserialize)]
struct Seed {
    hash: String,
    sticker: bool,
    /// The body is the preview, then its still.
    preview: usize,
}

/// What this admin's own import made of a file it just added (its
/// `prepare_emote` preview and still, the sanitizer's PNGs), kept as if
/// fetched: the app need not download and sanitize its own upload again.
#[tauri::command]
pub async fn emote_seed(request: tauri::ipc::Request<'_>) -> Result<(), String> {
    let args: Seed = request
        .headers()
        .get("x-voipc-seed")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("emote_seed needs its x-voipc-seed header")?;
    let hash = unhex::<32>(&args.hash).ok_or("invalid hash")?;
    let body = body_bytes(&request, "emote_seed")?;
    if args.preview == 0 || args.preview > body.len() {
        return Err("emote_seed: no preview".into());
    }
    let (png, first) = cached(&hash, args.sticker);
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        if png.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(dir())?;
        let (preview, still) = body.split_at(args.preview);
        // The still first: a PNG kept here means its still is too
        if !still.is_empty() {
            write_atomic(&first, still)?;
        }
        write_atomic(&png, preview)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

/// The files of a .zip or .wastickers an admin picked, read in memory
/// (`voipc_media::read_pack`): a JSON head (the title, each file's name and
/// length, its length in the first four bytes) and the files back to back.
#[tauri::command]
pub async fn read_emote_pack(
    request: tauri::ipc::Request<'_>,
) -> Result<tauri::ipc::Response, String> {
    let bytes = body_bytes(&request, "read_emote_pack")?;
    let pack = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(|| voipc_media::read_pack(&bytes))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|_| "the archive could not be read".to_string())?
    .map_err(|e| e.to_string())?;
    let head = serde_json::json!({
        "title": pack.title,
        "entries": pack.entries.iter().map(|e| serde_json::json!({ "name": e.name, "len": e.bytes.len() })).collect::<Vec<_>>(),
        "skipped": pack.skipped.iter().map(|(name, why)| serde_json::json!({ "name": name, "why": why })).collect::<Vec<_>>(),
    })
    .to_string();
    // Each file let go once it is in the answer: one copy at a time, not two
    let total: usize = pack.entries.iter().map(|e| e.bytes.len()).sum();
    let mut out = Vec::with_capacity(4 + head.len() + total);
    out.extend_from_slice(&(head.len() as u32).to_le_bytes());
    out.extend_from_slice(head.as_bytes());
    for e in pack.entries {
        out.extend_from_slice(&e.bytes);
    }
    Ok(tauri::ipc::Response::new(out))
}

#[derive(Deserialize)]
struct Add {
    server: String,
    name: String,
    sticker: bool,
    pack: String,
    /// Its shape as `prepare_emote` made it: the room readers keep for it.
    #[serde(default)]
    w: u16,
    #[serde(default)]
    h: u16,
}

/// Add an emote (admins): the bytes are what `prepare_emote` said to upload.
/// Done when the relay has it; its list follows as an `emote-list` event.
#[tauri::command]
pub async fn emote_add(
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> Result<(), String> {
    let args: Add = request
        .headers()
        .get("x-voipc-emote")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| serde_json::from_str(v).ok())
        .ok_or("emote_add needs its x-voipc-emote header")?;
    let bytes = body_bytes(&request, "emote_add")?;
    let files = files_of(&state, &args.server).await?;
    let hash = sha256(&bytes);
    let answer = files.wait_emote(&args.name, hash);
    files.send_msg(&ClientMessage::EmoteAdd {
        emote: Emote {
            name: args.name,
            hash,
            sticker: args.sticker,
            pack: args.pack,
            len: bytes.len() as u32,
            w: args.w,
            h: args.h,
        },
    });
    let ticket = match tokio::time::timeout(ANSWER_TIME, answer).await {
        Ok(Ok(answer)) => answer?,
        _ => return Err("the server did not answer".into()),
    };
    let Some(ticket) = ticket else { return Ok(()) };
    let (status, body) = files.emote_request("PUT", &hash, &ticket, &bytes).await?;
    if status == 201 {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&body).into_owned())
    }
}

/// Remove emotes (admins), any number in one message; what the server does
/// not have comes back as an `emote-error` event.
#[tauri::command]
pub async fn emote_remove(
    state: State<'_, AppState>,
    server: String,
    names: Vec<String>,
) -> Result<(), String> {
    files_of(&state, &server)
        .await?
        .send_msg(&ClientMessage::EmoteRemove { names });
    Ok(())
}

/// Put emotes in a pack and/or make them stickers or emotes (admins): all of
/// them, or none with an `emote-error` event.
#[tauri::command]
pub async fn emote_move(
    state: State<'_, AppState>,
    server: String,
    names: Vec<String>,
    pack: Option<String>,
    sticker: Option<bool>,
) -> Result<(), String> {
    files_of(&state, &server)
        .await?
        .send_msg(&ClientMessage::EmoteMove {
            names,
            pack,
            sticker,
        });
    Ok(())
}

/// Call an emote by another name (admins); a refusal comes as an
/// `emote-error` event.
#[tauri::command]
pub async fn emote_rename(
    state: State<'_, AppState>,
    server: String,
    from: String,
    to: String,
) -> Result<(), String> {
    files_of(&state, &server)
        .await?
        .send_msg(&ClientMessage::EmoteRename { from, to });
    Ok(())
}

/// Let members send stickers, or not (admins).
#[tauri::command]
pub async fn emote_stickers(
    state: State<'_, AppState>,
    server: String,
    on: bool,
) -> Result<(), String> {
    files_of(&state, &server)
        .await?
        .send_msg(&ClientMessage::EmoteStickers { on });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_picture_no_open_server_lists_is_kept_a_while_then_goes() {
        let keep = ["aa".to_string()].into_iter().collect();
        let day = Duration::from_secs(24 * 3600);
        let name = |h: &str| format!("{h}-{SANITIZER_VERSION}-e.png");
        assert_eq!(kept(&name("aa"), &keep, 90 * day), Kept::Renew);
        assert_eq!(
            kept(&name("bb"), &keep, day),
            Kept::Stay,
            "another server's, for now"
        );
        assert_eq!(kept(&name("bb"), &keep, 31 * day), Kept::Go);
        assert_eq!(
            kept(&format!("aa-{}-e.png", SANITIZER_VERSION + 1), &keep, day),
            Kept::Go,
            "another sanitizer's"
        );
    }
}
