//! Wall-clock access that also works on `wasm32-unknown-unknown`, where
//! `SystemTime::now()` panics. libsignal wants `std::time::SystemTime`, and
//! arithmetic on `UNIX_EPOCH` is fine on every target — only `now()` is missing.

use std::time::SystemTime;

#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> SystemTime {
    SystemTime::now()
}

#[cfg(target_arch = "wasm32")]
pub fn now() -> SystemTime {
    let millis = js_sys::Date::now().max(0.0) as u64;
    SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(millis)
}

/// Milliseconds since the Unix epoch.
pub fn now_millis() -> u64 {
    now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
