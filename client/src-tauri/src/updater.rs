//! The desktop auto-updater (1.0, D15, H4 design input B3).
//!
//! Driven from here only: the page gets no `updater:*` permission, so a script
//! in it can neither point the updater elsewhere nor hand it a package. It can
//! only ask these commands to look at the one feed built in, or to install
//! what that feed offered.
//!
//! Only the NSIS (Windows) and AppImage (Linux) builds update themselves. A
//! .deb belongs to its package manager, a bare build to whoever built it and
//! Android to its store; they keep the download page.
//!
//! What it trusts: a signature from the key built into the app
//! (`tauri.conf.json` → `plugins.updater.pubkey`), bound to the version the
//! feed announces (`requireSignedVersion`, so a tampered feed cannot pair a
//! new version number with an older signed build), and only a newer version
//! (the plugin's default comparator; never overridden). The stable feed is
//! GitHub's `latest` release, so the owner's manual publish is also the gate
//! for updates.
//!
//! Never mid-call: installing restarts the app, so it is refused while this
//! app is in voice anywhere.

use serde::Serialize;

/// Release candidates read a fixed release, which the publish job keeps
/// pointing at the newer of the newest rc and the newest final, so rc testers
/// move on to the final release.
#[cfg(not(target_os = "android"))]
const RC_FEED: &str = "https://github.com/luki4fun/voipc/releases/download/updater-rc/latest.json";
/// GitHub's newest published release that is not a pre-release.
#[cfg(not(target_os = "android"))]
const STABLE_FEED: &str = "https://github.com/luki4fun/voipc/releases/latest/download/latest.json";

/// The feed for a build of `version`: a pre-release (`1.0.0-rc.1`) follows
/// the release candidates.
#[cfg(not(target_os = "android"))]
fn feed(version: &str) -> &'static str {
    if version.contains('-') {
        RC_FEED
    } else {
        STABLE_FEED
    }
}

/// What the page is told about an update.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct UpdateInfo {
    pub version: String,
    pub notes: Option<String>,
    /// The protocol the update speaks, when the feed says (`"protocol": N`):
    /// whether it would let us onto a server that refused us.
    pub protocol: Option<u32>,
}

/// The feed's extra `protocol` field, if it carries a sane one.
#[cfg(any(not(target_os = "android"), test))]
fn protocol_of(raw: &serde_json::Value) -> Option<u32> {
    raw.get("protocol")?
        .as_u64()
        .and_then(|p| u32::try_from(p).ok())
}

#[cfg(not(target_os = "android"))]
mod desktop {
    use super::*;
    use crate::app_state::AppState;
    use std::time::Duration;
    use tauri::{AppHandle, Emitter, Manager};
    use tauri_plugin_updater::{Update, UpdaterExt};

    /// How often a running app looks again.
    const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
    /// The first look waits for the app to settle.
    const FIRST_CHECK_AFTER: Duration = Duration::from_secs(20);

    /// The update the last check found, waiting to be installed.
    #[derive(Default)]
    pub struct Updates {
        pending: std::sync::Mutex<Option<Update>>,
        /// One check or install at a time.
        busy: tokio::sync::Mutex<()>,
    }

    impl Updates {
        pub fn pending(&self) -> Option<Update> {
            self.pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
        fn set(&self, update: Option<Update>) {
            *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = update;
        }
    }

    pub fn info_of(update: &Update) -> UpdateInfo {
        UpdateInfo {
            version: update.version.clone(),
            notes: update.body.clone(),
            protocol: protocol_of(&update.raw_json),
        }
    }

    /// Whether this build replaces itself: an NSIS install, or an AppImage in
    /// a directory this user may write to (otherwise the download page).
    pub fn supported() -> bool {
        use tauri::utils::{config::BundleType, platform::bundle_type};
        match bundle_type() {
            Some(BundleType::Nsis) => true,
            Some(BundleType::AppImage) => appimage_dir_writable(),
            _ => false,
        }
    }

    fn appimage_dir_writable() -> bool {
        let Some(dir) = std::env::var_os("APPIMAGE")
            .map(std::path::PathBuf::from)
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        else {
            return false;
        };
        let probe = dir.join(format!(".voipc-update-{}", std::process::id()));
        let writable = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .is_ok();
        let _ = std::fs::remove_file(&probe);
        writable
    }

    /// Look at the feed now, if this build updates itself and the user has
    /// not switched checking off. Tells the page when there is something new.
    pub async fn check(app: &AppHandle) -> Option<UpdateInfo> {
        if !supported() || !app.state::<AppState>().config().check_updates {
            return None;
        }
        let updates = app.state::<Updates>();
        let _one = updates.busy.lock().await;
        let found = async {
            let url = feed(env!("CARGO_PKG_VERSION"))
                .parse()
                .map_err(|e| format!("{e}"))?;
            app.updater_builder()
                .endpoints(vec![url])
                .map_err(|e| e.to_string())?
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| e.to_string())?
                .check()
                .await
                .map_err(|e| e.to_string())
        }
        .await;
        match found {
            Ok(Some(update)) => {
                let info = info_of(&update);
                tracing::info!("VoIPC {} is available", info.version);
                updates.set(Some(update));
                let _ = app.emit("update-available", &info);
                Some(info)
            }
            Ok(None) => {
                updates.set(None);
                None
            }
            // Offline, GitHub down, no feed yet: say nothing, try again later
            Err(e) => {
                tracing::warn!("update check failed: {e}");
                updates.pending().as_ref().map(info_of)
            }
        }
    }

    /// Check a little after start, then once a day.
    pub fn start(app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(FIRST_CHECK_AFTER).await;
            loop {
                check(&app).await;
                tokio::time::sleep(CHECK_EVERY).await;
            }
        });
    }

    pub async fn install(app: &AppHandle) -> Result<(), String> {
        let state = app.state::<AppState>();
        if state.voice_id().is_some() {
            return Err("Leave the call first: installing the update restarts VoIPC.".into());
        }
        let updates = app.state::<Updates>();
        let _one = updates.busy.lock().await;
        let update = updates.pending().ok_or("There is no update to install.")?;
        tracing::info!("downloading VoIPC {}", update.version);
        // `download` verifies the signature before it returns the bytes
        let bytes = update
            .download(|_, _| {}, || {})
            .await
            .map_err(|e| format!("The update could not be downloaded: {e}"))?;
        // A call may have started while it downloaded
        if state.voice_id().is_some() {
            return Err("Leave the call first: installing the update restarts VoIPC.".into());
        }
        crate::commands::flush_chat_to_disk(&state).await;
        // Windows: starts the installer and exits. Linux: replaces the AppImage.
        update
            .install(&bytes)
            .map_err(|e| format!("The update could not be installed: {e}"))?;
        app.restart();
    }
}

#[cfg(not(target_os = "android"))]
pub use desktop::{start, Updates};

/// Whether this build installs its own updates (else: the download page).
#[tauri::command]
pub fn updates_supported() -> bool {
    #[cfg(not(target_os = "android"))]
    return desktop::supported();
    #[cfg(target_os = "android")]
    false
}

/// What the last check found, for a page that loaded after it.
#[tauri::command]
pub fn pending_update(app: tauri::AppHandle) -> Option<UpdateInfo> {
    #[cfg(not(target_os = "android"))]
    {
        use tauri::Manager;
        app.state::<Updates>()
            .pending()
            .as_ref()
            .map(desktop::info_of)
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
        None
    }
}

/// Look now: a server refused us for an older protocol, or the user asked.
#[tauri::command]
pub async fn check_for_update(app: tauri::AppHandle) -> Option<UpdateInfo> {
    #[cfg(not(target_os = "android"))]
    return desktop::check(&app).await;
    #[cfg(target_os = "android")]
    {
        let _ = app;
        None
    }
}

/// Download, verify and install the update the last check found, then
/// restart. Refused while in voice.
#[tauri::command]
pub async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(not(target_os = "android"))]
    return desktop::install(&app).await;
    #[cfg(target_os = "android")]
    {
        let _ = app;
        Err("This build is updated through its store or package manager.".into())
    }
}

/// The "Check for updates" setting (default on). Switching it on looks at once.
#[tauri::command]
pub async fn set_check_updates(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    use tauri::Manager;
    {
        let state = app.state::<crate::app_state::AppState>();
        let mut config = state.config();
        config.check_updates = enabled;
        crate::config::save_config(&config)?;
    }
    #[cfg(not(target_os = "android"))]
    if enabled {
        desktop::check(&app).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "android"))]
    #[test]
    fn a_release_candidate_follows_the_rc_feed() {
        assert_eq!(feed("1.0.0-rc.1"), RC_FEED);
        assert_eq!(feed("1.0.0"), STABLE_FEED);
        assert_eq!(feed("1.2.3"), STABLE_FEED);
    }

    #[test]
    fn the_feed_may_say_which_protocol_an_update_speaks() {
        assert_eq!(
            protocol_of(&serde_json::json!({"version": "1.0.0", "protocol": 12})),
            Some(12)
        );
        assert_eq!(protocol_of(&serde_json::json!({"version": "1.0.0"})), None);
        assert_eq!(protocol_of(&serde_json::json!({"protocol": "12"})), None);
        assert_eq!(protocol_of(&serde_json::json!({"protocol": -1})), None);
        assert_eq!(
            protocol_of(&serde_json::json!({"protocol": 1u64 << 40})),
            None
        );
    }

    /// The key every update must be signed with, and the version binding, are
    /// in the shipped config: losing either quietly would let a tampered feed
    /// through (or every update fail).
    #[test]
    fn updates_must_be_signed_by_our_key_for_the_version_they_claim() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let updater = &conf["plugins"]["updater"];
        assert_eq!(
            updater["requireSignedVersion"], true,
            "requireSignedVersion must stay on"
        );
        assert!(
            updater.get("allowDowngrades").is_none_or(|v| v == false),
            "downgrades must stay off"
        );
        assert!(
            updater.get("endpoints").is_none(),
            "the feed is chosen in updater.rs, not in the config"
        );
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD
            .decode(updater["pubkey"].as_str().unwrap())
            .unwrap();
        let key = String::from_utf8(key).unwrap();
        assert!(
            key.contains("minisign public key: 5F2A2C7C66012298"),
            "{key}"
        );
        // What the plugin does with it at start: a config it cannot read
        // would stop the app from starting at all
        #[cfg(not(target_os = "android"))]
        {
            let parsed: tauri_plugin_updater::Config =
                serde_json::from_value(updater.clone()).unwrap();
            assert!(parsed.require_signed_version && !parsed.allow_downgrades);
        }
    }
}
