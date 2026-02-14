mod app_state;
mod commands;
mod crypto;
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
            // Resolve and store the encrypted chat history file path (next to executable)
            let exe_dir = std::env::current_exe()
                .expect("failed to get executable path")
                .parent()
                .expect("executable has no parent dir")
                .to_path_buf();
            let file_path = exe_dir.join("chat_history.bin");

            {
                let state = app.state::<AppState>();
                let mut chat = state.chat.blocking_write();
                chat.file_path = file_path;
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
            // Chat history (encrypted file)
            commands::chat_history_exists,
            commands::unlock_chat_history,
            commands::create_chat_history,
            commands::save_chat_messages,
            commands::clear_chat_history,
            // Screen share
            commands::start_screen_share,
            commands::stop_screen_share,
            commands::watch_screen_share,
            commands::stop_watching_screen_share,
            commands::request_keyframe,
            commands::start_screen_capture,
            commands::stop_screen_capture,
            commands::set_keyframe_requested,
            commands::toggle_screen_audio,
            commands::get_screen_audio_status,
            commands::get_screen_share_stats,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running VoIPC client");
}
