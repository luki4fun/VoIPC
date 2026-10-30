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
/// checked and sanitized now.
#[tauri::command]
pub async fn emote_image(
    state: State<'_, AppState>,
    server: String,
    hash: String,
    sticker: bool,
    still: bool,
) -> Result<tauri::ipc::Response, String> {
    let hash = unhex::<32>(&hash).ok_or("invalid hash")?;
    let (png, first) = cached(&hash, sticker);
    let kept = tokio::task::spawn_blocking(move || {
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
    Ok(tauri::ipc::Response::new(if still {
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

/// Keep only the emotes of these hashes (every open server's): the rest of
/// what this device made for others goes.
#[tauri::command]
pub async fn emote_cache_retain(keep: Vec<String>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let Ok(entries) = std::fs::read_dir(dir()) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let hash = name.split('-').next().unwrap_or("");
            let current = name.contains(&format!("-{SANITIZER_VERSION}-"));
            if !current || !keep.iter().any(|k| k == hash) {
                let _ = std::fs::remove_file(entry.path());
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
    let (upload, how) = if full.png.len() <= args.max_bytes && !full.trimmed {
        (full.png.clone(), "clean")
    } else if src.len() <= args.max_bytes {
        (src, "original")
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
    let mut out = (head.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(head.as_bytes());
    for e in &pack.entries {
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
        },
        len: bytes.len() as u32,
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

/// Remove an emote (admins); a refusal comes as an `emote-error` event.
#[tauri::command]
pub async fn emote_remove(
    state: State<'_, AppState>,
    server: String,
    name: String,
) -> Result<(), String> {
    files_of(&state, &server)
        .await?
        .send_msg(&ClientMessage::EmoteRemove { name });
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
