mod app_state;
mod commands;
mod config;
mod crypto;
mod global_keys;
mod network;
mod screenshare;

use app_state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "voipc_client_lib=info".into()),
        )
        .init();

    tauri::Builder::default()
        .manage(AppState::new())
        .setup(|app| {
            // Migrate legacy files from next-to-executable to ~/.config/VoIPC/
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
                            let _ = config::save_config(&cfg);
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
            );

            Ok(())
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
            commands::distribute_sender_key,
            commands::distribute_media_key,
            commands::upload_prekeys,
            // Persistent config
            commands::load_config,
            commands::save_connection_info,
            commands::reset_config,
            commands::set_config_bool,
            // Notification sounds
            commands::play_notification_sound,
            commands::browse_sound_file,
            commands::set_sound_settings,
            commands::preview_sound,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VoIPC client");
}
