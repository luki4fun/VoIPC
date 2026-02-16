//! Global keyboard listener for PTT — works even when the window is unfocused.
//!
//! - **Linux**: Tries `evdev` first (reads `/dev/input/event*` directly — works on X11 + Wayland,
//!   requires user in `input` group). Falls back to `rdev` (X11 XRecord — no special permissions).
//! - **Other platforms**: Uses `rdev` which hooks into OS-level keyboard events.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tauri::{Emitter, Manager};

use crate::app_state::{AppState, PttBinding, VoiceMode};
use crate::commands;

/// Spawn a background thread that monitors global keyboard events and triggers
/// PTT start/stop. Keys are NOT consumed — they still propagate to all applications.
pub fn spawn_listener(
    handle: tauri::AppHandle,
    ptt_binding: Arc<std::sync::RwLock<PttBinding>>,
    ptt_hold_mode: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        // On Linux, try evdev first (best — works on Wayland + X11).
        // If evdev can't find devices (user not in `input` group), fall back to rdev (X11).
        #[cfg(target_os = "linux")]
        {
            let keyboards = find_evdev_keyboards();
            if !keyboards.is_empty() {
                tracing::info!(
                    "Global PTT: monitoring {} keyboard(s) via evdev",
                    keyboards.len()
                );
                run_evdev_loop(keyboards, &handle, &ptt_binding, &ptt_hold_mode);
                return;
            }
            tracing::info!(
                "Global PTT: evdev unavailable (tip: 'sudo usermod -aG input $USER' \
                 for Wayland support). Falling back to X11..."
            );
        }

        run_rdev_loop(handle, ptt_binding, ptt_hold_mode);
    });
}

// ===========================================================================
// rdev-based listener (all platforms — X11 on Linux, native hooks on Windows)
// ===========================================================================

fn js_code_to_rdev_key(code: &str) -> Option<rdev::Key> {
    use rdev::Key;
    match code {
        "Space" => Some(Key::Space),
        "KeyA" => Some(Key::KeyA),
        "KeyB" => Some(Key::KeyB),
        "KeyC" => Some(Key::KeyC),
        "KeyD" => Some(Key::KeyD),
        "KeyE" => Some(Key::KeyE),
        "KeyF" => Some(Key::KeyF),
        "KeyG" => Some(Key::KeyG),
        "KeyH" => Some(Key::KeyH),
        "KeyI" => Some(Key::KeyI),
        "KeyJ" => Some(Key::KeyJ),
        "KeyK" => Some(Key::KeyK),
        "KeyL" => Some(Key::KeyL),
        "KeyM" => Some(Key::KeyM),
        "KeyN" => Some(Key::KeyN),
        "KeyO" => Some(Key::KeyO),
        "KeyP" => Some(Key::KeyP),
        "KeyQ" => Some(Key::KeyQ),
        "KeyR" => Some(Key::KeyR),
        "KeyS" => Some(Key::KeyS),
        "KeyT" => Some(Key::KeyT),
        "KeyU" => Some(Key::KeyU),
        "KeyV" => Some(Key::KeyV),
        "KeyW" => Some(Key::KeyW),
        "KeyX" => Some(Key::KeyX),
        "KeyY" => Some(Key::KeyY),
        "KeyZ" => Some(Key::KeyZ),
        "Digit0" => Some(Key::Num0),
        "Digit1" => Some(Key::Num1),
        "Digit2" => Some(Key::Num2),
        "Digit3" => Some(Key::Num3),
        "Digit4" => Some(Key::Num4),
        "Digit5" => Some(Key::Num5),
        "Digit6" => Some(Key::Num6),
        "Digit7" => Some(Key::Num7),
        "Digit8" => Some(Key::Num8),
        "Digit9" => Some(Key::Num9),
        "F1" => Some(Key::F1),
        "F2" => Some(Key::F2),
        "F3" => Some(Key::F3),
        "F4" => Some(Key::F4),
        "F5" => Some(Key::F5),
        "F6" => Some(Key::F6),
        "F7" => Some(Key::F7),
        "F8" => Some(Key::F8),
        "F9" => Some(Key::F9),
        "F10" => Some(Key::F10),
        "F11" => Some(Key::F11),
        "F12" => Some(Key::F12),
        "ShiftLeft" => Some(Key::ShiftLeft),
        "ShiftRight" => Some(Key::ShiftRight),
        "ControlLeft" => Some(Key::ControlLeft),
        "ControlRight" => Some(Key::ControlRight),
        "AltLeft" => Some(Key::Alt),
        "AltRight" => Some(Key::AltGr),
        "CapsLock" => Some(Key::CapsLock),
        "Tab" => Some(Key::Tab),
        "Backquote" => Some(Key::BackQuote),
        "Minus" => Some(Key::Minus),
        "Equal" => Some(Key::Equal),
        "BracketLeft" => Some(Key::LeftBracket),
        "BracketRight" => Some(Key::RightBracket),
        "Backslash" => Some(Key::BackSlash),
        "Semicolon" => Some(Key::SemiColon),
        "Quote" => Some(Key::Quote),
        "Comma" => Some(Key::Comma),
        "Period" => Some(Key::Dot),
        "Slash" => Some(Key::Slash),
        "Escape" => Some(Key::Escape),
        _ => None,
    }
}

fn rdev_binding_matches(held: &HashSet<rdev::Key>, binding: &PttBinding) -> bool {
    use rdev::Key;
    if binding.ctrl
        && !held.contains(&Key::ControlLeft)
        && !held.contains(&Key::ControlRight)
    {
        return false;
    }
    if binding.alt && !held.contains(&Key::Alt) && !held.contains(&Key::AltGr) {
        return false;
    }
    if binding.shift
        && !held.contains(&Key::ShiftLeft)
        && !held.contains(&Key::ShiftRight)
    {
        return false;
    }
    if let Some(target) = js_code_to_rdev_key(&binding.code) {
        held.contains(&target)
    } else {
        false
    }
}

fn rdev_binding_held(held: &HashSet<rdev::Key>, binding: &PttBinding) -> bool {
    use rdev::Key;
    if !binding.ctrl && !binding.alt && !binding.shift {
        return rdev_binding_matches(held, binding);
    }
    if binding.ctrl
        && !held.contains(&Key::ControlLeft)
        && !held.contains(&Key::ControlRight)
    {
        return false;
    }
    if binding.alt && !held.contains(&Key::Alt) && !held.contains(&Key::AltGr) {
        return false;
    }
    if binding.shift
        && !held.contains(&Key::ShiftLeft)
        && !held.contains(&Key::ShiftRight)
    {
        return false;
    }
    true
}

fn run_rdev_loop(
    handle: tauri::AppHandle,
    ptt_binding: Arc<std::sync::RwLock<PttBinding>>,
    ptt_hold_mode: Arc<AtomicBool>,
) {
    let mut held_keys = HashSet::new();
    let mut ptt_active = false;

    let callback = move |event: rdev::Event| {
        match event.event_type {
            rdev::EventType::KeyPress(key) => {
                held_keys.insert(key);
                let b = ptt_binding.read().unwrap();
                let matches = rdev_binding_matches(&held_keys, &b);
                drop(b);

                if matches && !ptt_active {
                    ptt_active = true;
                    let h = handle.clone();
                    tauri::async_runtime::spawn(async move {
                        let state = h.state::<AppState>();
                        {
                            let conn = state.connection.read().await;
                            if let Some(c) = conn.as_ref() {
                                let mode = VoiceMode::from_u8(
                                    c.voice_mode.load(Ordering::Relaxed),
                                );
                                if mode != VoiceMode::Ptt {
                                    return;
                                }
                            } else {
                                return;
                            }
                        }
                        if let Err(e) = commands::do_start_transmit(&state).await {
                            tracing::warn!("Global PTT start failed: {e}");
                        } else {
                            let _ = h.emit("ptt-global-pressed", ());
                        }
                    });
                }
            }
            rdev::EventType::KeyRelease(key) => {
                held_keys.remove(&key);
                let b = ptt_binding.read().unwrap();
                let hold = ptt_hold_mode.load(Ordering::Relaxed);
                let still = if hold {
                    rdev_binding_held(&held_keys, &b)
                } else {
                    rdev_binding_matches(&held_keys, &b)
                };
                drop(b);

                if !still && ptt_active {
                    ptt_active = false;
                    let h = handle.clone();
                    tauri::async_runtime::spawn(async move {
                        let state = h.state::<AppState>();
                        if let Err(e) = commands::do_stop_transmit(&state).await {
                            tracing::warn!("Global PTT stop failed: {e}");
                        } else {
                            let _ = h.emit("ptt-global-released", ());
                        }
                    });
                }
            }
            _ => {} // Ignore mouse events, etc.
        }
    };

    if let Err(e) = rdev::listen(callback) {
        tracing::error!("Global key listener (rdev) failed: {e:?}");
        tracing::warn!(
            "Global PTT will not work. \
             Window-level PTT still available when app is focused."
        );
    }
}

// ===========================================================================
// Linux only: evdev-based listener (reads /dev/input directly)
// ===========================================================================

#[cfg(target_os = "linux")]
fn js_code_to_evdev_key(code: &str) -> Option<evdev::Key> {
    use evdev::Key;
    match code {
        "Space" => Some(Key::KEY_SPACE),
        "KeyA" => Some(Key::KEY_A),
        "KeyB" => Some(Key::KEY_B),
        "KeyC" => Some(Key::KEY_C),
        "KeyD" => Some(Key::KEY_D),
        "KeyE" => Some(Key::KEY_E),
        "KeyF" => Some(Key::KEY_F),
        "KeyG" => Some(Key::KEY_G),
        "KeyH" => Some(Key::KEY_H),
        "KeyI" => Some(Key::KEY_I),
        "KeyJ" => Some(Key::KEY_J),
        "KeyK" => Some(Key::KEY_K),
        "KeyL" => Some(Key::KEY_L),
        "KeyM" => Some(Key::KEY_M),
        "KeyN" => Some(Key::KEY_N),
        "KeyO" => Some(Key::KEY_O),
        "KeyP" => Some(Key::KEY_P),
        "KeyQ" => Some(Key::KEY_Q),
        "KeyR" => Some(Key::KEY_R),
        "KeyS" => Some(Key::KEY_S),
        "KeyT" => Some(Key::KEY_T),
        "KeyU" => Some(Key::KEY_U),
        "KeyV" => Some(Key::KEY_V),
        "KeyW" => Some(Key::KEY_W),
        "KeyX" => Some(Key::KEY_X),
        "KeyY" => Some(Key::KEY_Y),
        "KeyZ" => Some(Key::KEY_Z),
        "Digit0" => Some(Key::KEY_0),
        "Digit1" => Some(Key::KEY_1),
        "Digit2" => Some(Key::KEY_2),
        "Digit3" => Some(Key::KEY_3),
        "Digit4" => Some(Key::KEY_4),
        "Digit5" => Some(Key::KEY_5),
        "Digit6" => Some(Key::KEY_6),
        "Digit7" => Some(Key::KEY_7),
        "Digit8" => Some(Key::KEY_8),
        "Digit9" => Some(Key::KEY_9),
        "F1" => Some(Key::KEY_F1),
        "F2" => Some(Key::KEY_F2),
        "F3" => Some(Key::KEY_F3),
        "F4" => Some(Key::KEY_F4),
        "F5" => Some(Key::KEY_F5),
        "F6" => Some(Key::KEY_F6),
        "F7" => Some(Key::KEY_F7),
        "F8" => Some(Key::KEY_F8),
        "F9" => Some(Key::KEY_F9),
        "F10" => Some(Key::KEY_F10),
        "F11" => Some(Key::KEY_F11),
        "F12" => Some(Key::KEY_F12),
        "ShiftLeft" => Some(Key::KEY_LEFTSHIFT),
        "ShiftRight" => Some(Key::KEY_RIGHTSHIFT),
        "ControlLeft" => Some(Key::KEY_LEFTCTRL),
        "ControlRight" => Some(Key::KEY_RIGHTCTRL),
        "AltLeft" => Some(Key::KEY_LEFTALT),
        "AltRight" => Some(Key::KEY_RIGHTALT),
        "CapsLock" => Some(Key::KEY_CAPSLOCK),
        "Tab" => Some(Key::KEY_TAB),
        "Backquote" => Some(Key::KEY_GRAVE),
        "Minus" => Some(Key::KEY_MINUS),
        "Equal" => Some(Key::KEY_EQUAL),
        "BracketLeft" => Some(Key::KEY_LEFTBRACE),
        "BracketRight" => Some(Key::KEY_RIGHTBRACE),
        "Backslash" => Some(Key::KEY_BACKSLASH),
        "Semicolon" => Some(Key::KEY_SEMICOLON),
        "Quote" => Some(Key::KEY_APOSTROPHE),
        "Comma" => Some(Key::KEY_COMMA),
        "Period" => Some(Key::KEY_DOT),
        "Slash" => Some(Key::KEY_SLASH),
        "Escape" => Some(Key::KEY_ESC),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn evdev_binding_matches(held: &HashSet<evdev::Key>, binding: &PttBinding) -> bool {
    use evdev::Key;
    if binding.ctrl
        && !held.contains(&Key::KEY_LEFTCTRL)
        && !held.contains(&Key::KEY_RIGHTCTRL)
    {
        return false;
    }
    if binding.alt
        && !held.contains(&Key::KEY_LEFTALT)
        && !held.contains(&Key::KEY_RIGHTALT)
    {
        return false;
    }
    if binding.shift
        && !held.contains(&Key::KEY_LEFTSHIFT)
        && !held.contains(&Key::KEY_RIGHTSHIFT)
    {
        return false;
    }
    if let Some(target) = js_code_to_evdev_key(&binding.code) {
        held.contains(&target)
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
fn evdev_binding_held(held: &HashSet<evdev::Key>, binding: &PttBinding) -> bool {
    use evdev::Key;
    if !binding.ctrl && !binding.alt && !binding.shift {
        return evdev_binding_matches(held, binding);
    }
    if binding.ctrl
        && !held.contains(&Key::KEY_LEFTCTRL)
        && !held.contains(&Key::KEY_RIGHTCTRL)
    {
        return false;
    }
    if binding.alt
        && !held.contains(&Key::KEY_LEFTALT)
        && !held.contains(&Key::KEY_RIGHTALT)
    {
        return false;
    }
    if binding.shift
        && !held.contains(&Key::KEY_LEFTSHIFT)
        && !held.contains(&Key::KEY_RIGHTSHIFT)
    {
        return false;
    }
    true
}

#[cfg(target_os = "linux")]
fn find_evdev_keyboards() -> Vec<evdev::Device> {
    use evdev::Key;
    evdev::enumerate()
        .filter_map(|(path, dev)| {
            if dev
                .supported_keys()
                .map_or(false, |keys| keys.contains(Key::KEY_SPACE))
            {
                tracing::debug!("Global PTT: found keyboard {:?}", path);
                Some(dev)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn run_evdev_loop(
    mut devices: Vec<evdev::Device>,
    handle: &tauri::AppHandle,
    ptt_binding: &Arc<std::sync::RwLock<PttBinding>>,
    ptt_hold_mode: &Arc<AtomicBool>,
) {
    use evdev::{InputEventKind, Key};
    use std::os::unix::io::AsRawFd;

    // Set all devices to non-blocking mode via fcntl
    for dev in &devices {
        unsafe {
            libc::fcntl(dev.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
        }
    }

    let mut held_keys: HashSet<Key> = HashSet::new();
    let mut ptt_active = false;

    loop {
        // Build poll fds for all devices
        let mut fds: Vec<libc::pollfd> = devices
            .iter()
            .map(|d| libc::pollfd {
                fd: d.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();

        // Wait for events (100ms timeout to avoid busy-spinning)
        unsafe {
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100);
        }

        for dev in devices.iter_mut() {
            match dev.fetch_events() {
                Ok(events) => {
                    for event in events {
                        if let InputEventKind::Key(key) = event.kind() {
                            match event.value() {
                                1 => {
                                    // Key press
                                    held_keys.insert(key);
                                    let b = ptt_binding.read().unwrap();
                                    let matches =
                                        evdev_binding_matches(&held_keys, &b);
                                    drop(b);

                                    if matches && !ptt_active {
                                        ptt_active = true;
                                        let h = handle.clone();
                                        tauri::async_runtime::spawn(async move {
                                            let state = h.state::<AppState>();
                                            {
                                                let conn =
                                                    state.connection.read().await;
                                                if let Some(c) = conn.as_ref() {
                                                    let mode =
                                                        VoiceMode::from_u8(
                                                            c.voice_mode.load(
                                                                Ordering::Relaxed,
                                                            ),
                                                        );
                                                    if mode != VoiceMode::Ptt {
                                                        return;
                                                    }
                                                } else {
                                                    return;
                                                }
                                            }
                                            if let Err(e) =
                                                commands::do_start_transmit(
                                                    &state,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Global PTT start failed: {e}"
                                                );
                                            } else {
                                                let _ = h.emit(
                                                    "ptt-global-pressed",
                                                    (),
                                                );
                                            }
                                        });
                                    }
                                }
                                0 => {
                                    // Key release
                                    held_keys.remove(&key);
                                    let b = ptt_binding.read().unwrap();
                                    let hold =
                                        ptt_hold_mode.load(Ordering::Relaxed);
                                    let still = if hold {
                                        evdev_binding_held(&held_keys, &b)
                                    } else {
                                        evdev_binding_matches(&held_keys, &b)
                                    };
                                    drop(b);

                                    if !still && ptt_active {
                                        ptt_active = false;
                                        let h = handle.clone();
                                        tauri::async_runtime::spawn(async move {
                                            let state = h.state::<AppState>();
                                            if let Err(e) =
                                                commands::do_stop_transmit(
                                                    &state,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Global PTT stop failed: {e}"
                                                );
                                            } else {
                                                let _ = h.emit(
                                                    "ptt-global-released",
                                                    (),
                                                );
                                            }
                                        });
                                    }
                                }
                                _ => {} // Repeat (2), ignore
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    tracing::warn!("evdev error: {e}");
                }
            }
        }
    }
}
