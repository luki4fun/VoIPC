mod app_state;
mod commands;
mod config;
mod crypto;
mod global_keys;
mod network;
mod screenshare;

use app_state::AppState;
use tauri::Manager;

/// Whether the system tray was created. When it wasn't (e.g. libappindicator
/// missing on Linux), close-to-tray is disabled so closing the window quits.
#[cfg(not(target_os = "android"))]
static TRAY_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // WebKitGTK's DMA-BUF renderer crashes the Wayland connection on NVIDIA
    // ("Gdk Error 71 (Protocol error) dispatching to Wayland display").
    // Disable it unless the user explicitly set the variable themselves.
    #[cfg(all(target_os = "linux", not(target_os = "android")))]
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    // Android: log to logcat via tracing-android; try_init avoids panic on Activity recreation.
    // Desktop: log to stderr via fmt subscriber.
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::prelude::*;
        if let Ok(layer) = tracing_android::layer("VoIPC") {
            let _ = tracing_subscriber::registry()
                .with(layer)
                .try_init();
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "voipc_client_lib=info".into()),
            )
            .init();
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new())
        .setup(|app| {
            // On Android, dirs::config_dir() returns None (no $HOME env var).
            // Use Tauri's app_data_dir() which resolves to the app's private files dir.
            #[cfg(target_os = "android")]
            {
                let data_dir = app.path().app_data_dir()
                    .expect("failed to resolve Android app data directory");
                config::init_data_dir(data_dir);
            }

            // Migrate legacy files from next-to-executable to ~/.config/VoIPC/
            // (desktop only — no legacy paths on Android)
            #[cfg(not(target_os = "android"))]
            config::migrate_legacy_paths();

            // Load persistent config
            let mut cfg = config::load_config();

            // Auto-migrate: if user has an existing file at the default path but no
            // chat_history_path configured, persist the default path into the config.
            if cfg.chat_history_path.is_none() {
                let default_path = config::default_chat_history_path();
                if default_path.exists() {
                    if let Ok(data) = std::fs::read(&default_path) {
                        if crypto::has_valid_header(&data) {
                            cfg.chat_history_path =
                                Some(default_path.to_string_lossy().to_string());
                            if let Err(e) = config::save_config(&cfg) {
                                tracing::warn!("Failed to save config: {e}");
                            }
                            tracing::info!(
                                "Auto-configured chat_history_path to default location"
                            );
                        }
                    }
                }
            }

            // Resolve chat history path from config and store in ChatState
            let file_path = config::resolve_chat_history_path(&cfg);
            {
                let state = app.state::<AppState>();
                let mut chat = state.chat.blocking_write();
                chat.file_path = file_path;
            }

            // Apply config to app state
            {
                let state = app.state::<AppState>();

                // Apply to UserSettings
                {
                    let mut s = state.settings.blocking_write();
                    s.input_device = cfg.input_device.clone();
                    s.output_device = cfg.output_device.clone();
                    s.volume = cfg.volume;
                    s.ptt_key = cfg.ptt_key.clone();
                    s.voice_mode = cfg.voice_mode.clone();
                    s.vad_threshold_db = cfg.vad_threshold_db;
                    s.noise_suppression = cfg.noise_suppression;
                    s.muted = cfg.muted;
                    s.deafened = cfg.deafened;
                }
                state.input_gain.store(
                    cfg.input_gain.clamp(0.0, 4.0).to_bits(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                // Hydrate the optional global mute/deafen hotkeys
                *state.mute_binding.write().unwrap() = cfg
                    .mute_key
                    .as_deref()
                    .and_then(commands::parse_ptt_binding);
                *state.deafen_binding.write().unwrap() = cfg
                    .deafen_key
                    .as_deref()
                    .and_then(commands::parse_ptt_binding);

                // Apply PTT binding
                if let Some(binding) = commands::parse_ptt_binding(&cfg.ptt_key) {
                    *state.ptt_binding.write().unwrap() = binding;
                }
                state
                    .ptt_hold_mode
                    .store(cfg.ptt_hold_mode, std::sync::atomic::Ordering::Relaxed);

                // Store loaded config
                *state.config.lock().unwrap() = cfg;

                tracing::info!("Loaded user config from {}", config::config_path().display());
            }

            // Spawn background task to periodically flush dirty chat state to disk
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    let state = handle.state::<AppState>();
                    commands::flush_chat_to_disk(&*state).await;
                }
            });

            // Spawn global key listener for PTT that works even when unfocused.
            // Linux: evdev (reads /dev/input directly — works on X11 + Wayland)
            // Other: rdev (OS-level keyboard hook)
            // Keys are NOT consumed — they still propagate to all other applications.
            global_keys::spawn_listener(
                app.handle().clone(),
                app.state::<AppState>().ptt_binding.clone(),
                app.state::<AppState>().ptt_hold_mode.clone(),
                app.state::<AppState>().mute_binding.clone(),
                app.state::<AppState>().deafen_binding.clone(),
            );

            // System tray: closing the window hides to tray (call keeps
            // running); Quit in the tray menu actually exits.
            #[cfg(not(target_os = "android"))]
            {
                use tauri::menu::{Menu, MenuItem};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
                use tauri::Emitter as _;

                fn toggle_main_window(app: &tauri::AppHandle) {
                    if let Some(window) = app.get_webview_window("main") {
                        if window.is_visible().unwrap_or(false) {
                            let _ = window.hide();
                        } else {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }

                let build_tray = || -> tauri::Result<()> {
                    let show = MenuItem::with_id(app, "show", "Show / Hide", true, None::<&str>)?;
                    let mute = MenuItem::with_id(app, "mute", "Toggle Mute", true, None::<&str>)?;
                    let deafen =
                        MenuItem::with_id(app, "deafen", "Toggle Deafen", true, None::<&str>)?;
                    let quit = MenuItem::with_id(app, "quit", "Quit VoIPC", true, None::<&str>)?;
                    let menu = Menu::with_items(app, &[&show, &mute, &deafen, &quit])?;

                    let mut tray = TrayIconBuilder::with_id("voipc-tray")
                        .menu(&menu)
                        .show_menu_on_left_click(false)
                        .tooltip("VoIPC")
                        .on_menu_event(|app, event| match event.id.as_ref() {
                            "show" => toggle_main_window(app),
                            // VoiceControls listens for these and runs its normal
                            // mute/deafen toggle path, keeping UI + server in sync
                            "mute" => {
                                let _ = app.emit("toggle-mute-request", ());
                            }
                            "deafen" => {
                                let _ = app.emit("toggle-deafen-request", ());
                            }
                            "quit" => app.exit(0),
                            _ => {}
                        })
                        .on_tray_icon_event(|tray, event| {
                            if let TrayIconEvent::Click {
                                button: MouseButton::Left,
                                button_state: MouseButtonState::Up,
                                ..
                            } = event
                            {
                                toggle_main_window(tray.app_handle());
                            }
                        });
                    if let Some(icon) = app.default_window_icon() {
                        tray = tray.icon(icon.clone());
                    }
                    tray.build(app)?;
                    Ok(())
                };

                // libappindicator-sys panics (not errs) when no appindicator
                // library is installed — catch it and run without a tray
                // instead of crashing on startup. Panic hook silenced around
                // the call so the missing-library case logs one warning, not
                // a full panic dump.
                let prev_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(|_| {}));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build_tray));
                std::panic::set_hook(prev_hook);
                match result {
                    Ok(Ok(())) => TRAY_ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed),
                    Ok(Err(e)) => {
                        tracing::warn!("System tray unavailable ({e}) — running without tray; closing the window will quit")
                    }
                    Err(_) => tracing::warn!(
                        "System tray unavailable (libayatana-appindicator3/libappindicator3 not installed) — running without tray; closing the window will quit"
                    ),
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Close-to-tray: intercept only the main window's close, and only
            // when a tray actually exists to bring the window back
            #[cfg(not(target_os = "android"))]
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main"
                    && TRAY_ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
                {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            #[cfg(target_os = "android")]
            let _ = (window, event);
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::join_channel,
            commands::create_channel,
            commands::set_channel_password,
            commands::kick_user,
            commands::request_channel_users,
            commands::send_invite,
            commands::send_poke,
            commands::accept_invite,
            commands::decline_invite,
            commands::send_channel_message,
            commands::send_direct_message,
            commands::start_transmit,
            commands::stop_transmit,
            commands::toggle_mute,
            commands::toggle_deafen,
            commands::ping,
            commands::get_input_devices,
            commands::get_output_devices,
            commands::set_input_device,
            commands::set_output_device,
            commands::set_volume,
            commands::set_input_gain,
            commands::get_voice_stats,
            commands::set_mute_key,
            commands::set_deafen_key,
            commands::set_chat_history_disabled,
            // Chat history (encrypted file)
            commands::get_chat_history_status,
            commands::unlock_chat_history,
            commands::create_chat_history,
            commands::save_chat_messages,
            commands::clear_chat_history,
            commands::delete_chat_history,
            commands::browse_chat_history_directory,
            commands::set_chat_history_path,
            commands::check_path_status,
            // Screen share
            commands::get_platform,
            commands::enumerate_displays,
            commands::enumerate_windows,
            commands::start_screen_share,
            commands::stop_screen_share,
            commands::switch_screen_share_source,
            commands::watch_screen_share,
            commands::stop_watching_screen_share,
            commands::request_keyframe,
            commands::start_screen_capture,
            commands::stop_screen_capture,
            commands::set_keyframe_requested,
            commands::toggle_screen_audio,
            commands::get_screen_audio_status,
            commands::get_screen_share_stats,
            // Global PTT key binding
            commands::set_ptt_key,
            commands::set_ptt_hold_mode,
            // Voice activation
            commands::set_voice_mode,
            commands::set_vad_threshold,
            commands::get_audio_level,
            // Noise suppression
            commands::toggle_noise_suppression,
            // Per-user volume
            commands::set_user_volume,
            commands::get_user_volume,
            // E2E Encryption
            commands::request_prekey_bundle,
            commands::send_encrypted_direct_message,
            commands::send_encrypted_channel_message,
            commands::upload_prekeys,
            commands::forget_server_pin,
            commands::send_channel_history,
            // Moderation
            commands::admin_login,
            commands::admin_kick,
            commands::admin_ban,
            commands::admin_unban,
            commands::admin_list_bans,
            // Persistent config
            commands::load_config,
            commands::save_connection_info,
            commands::save_server,
            commands::remove_server,
            commands::start_mic_test,
            commands::stop_mic_test,
            commands::reset_config,
            commands::set_config_bool,
            // Notification sounds
            commands::play_notification_sound,
            commands::browse_sound_file,
            commands::set_sound_settings,
            commands::preview_sound,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!("Tauri runtime failed: {e}");
            #[cfg(not(target_os = "android"))]
            eprintln!("Tauri runtime failed: {e}");
        });
}
