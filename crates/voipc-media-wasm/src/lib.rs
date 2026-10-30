//! The browser's picture sanitizer: `voipc_media` for the file worker, which
//! must never hand a picture somebody else made to the browser's own decoder.
//!
//! A raw C ABI rather than wasm-bindgen, as voipc-opus-wasm: no glue, and an
//! instance per job (the worker is ended after each). The worker writes the
//! input at [`media_input`], calls [`media_sanitize`] or [`media_read_pack`],
//! and reads the answers back through the pointers and lengths below. No
//! unsafe code: the pointers are only ever handed out.

use std::cell::RefCell;

use voipc_media::{read_pack, sanitize_capped, strip, Motion, Pack, Profile};

#[derive(Default)]
struct State {
    input: Vec<u8>,
    png: Vec<u8>,
    still: Vec<u8>,
    /// width, height, frames, trimmed (0/1)
    meta: [u32; 4],
    error: String,
    pack: Pack,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn with<T>(f: impl FnOnce(&mut State) -> T) -> T {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

/// `voipc_media::SANITIZER_VERSION`: what the page keys its cache by.
#[no_mangle]
pub extern "C" fn media_version() -> u32 {
    voipc_media::SANITIZER_VERSION
}

/// Room for `len` bytes of input; the worker writes them there.
#[no_mangle]
pub extern "C" fn media_input(len: usize) -> *mut u8 {
    with(|s| {
        s.input = vec![0; len];
        s.input.as_mut_ptr()
    })
}

/// Sanitize the input as `profile` (0 emote, 1 sticker, 2 photo), with at
/// most `max_out` bytes of PNG (0: the profile's own cap), a moving picture
/// fitted into `side` and kept in `keep_mb` MiB (0: the defaults; the page
/// clamps a server's). 0 when done, 1 when refused, with the reason at
/// [`media_error`].
#[no_mangle]
pub extern "C" fn media_sanitize(profile: u32, max_out: u32, side: u32, keep_mb: u32) -> u32 {
    with(|s| {
        let Some(p) = Profile::from_u32(profile) else {
            s.error = "no such picture profile".into();
            return 1;
        };
        let cap = if max_out == 0 {
            p.max_output()
        } else {
            max_out as usize
        };
        let d = Motion::default();
        let motion = Motion {
            side: if side == 0 { d.side } else { side },
            keep: if keep_mb == 0 {
                d.keep
            } else {
                (keep_mb as usize) << 20
            },
        };
        match sanitize_capped(&std::mem::take(&mut s.input), p, cap, motion) {
            Ok(c) => {
                s.meta = [c.w, c.h, c.frames as u32, u32::from(c.trimmed)];
                s.still = c.still.unwrap_or_default();
                s.png = c.png;
                0
            }
            Err(e) => {
                s.error = e.to_string();
                1
            }
        }
    })
}

/// The input without its metadata (`voipc_media::strip`), read back at
/// [`media_png`]. 0 when done, 1 when refused, with the reason at
/// [`media_error`].
#[no_mangle]
pub extern "C" fn media_strip() -> u32 {
    with(|s| match strip(&std::mem::take(&mut s.input)) {
        Ok(bare) => {
            s.png = bare;
            0
        }
        Err(e) => {
            s.error = e.to_string();
            1
        }
    })
}

#[no_mangle]
pub extern "C" fn media_png() -> *const u8 {
    with(|s| s.png.as_ptr())
}

#[no_mangle]
pub extern "C" fn media_png_len() -> usize {
    with(|s| s.png.len())
}

/// The first frame of a moving picture; empty for a still one.
#[no_mangle]
pub extern "C" fn media_still() -> *const u8 {
    with(|s| s.still.as_ptr())
}

#[no_mangle]
pub extern "C" fn media_still_len() -> usize {
    with(|s| s.still.len())
}

#[no_mangle]
pub extern "C" fn media_meta(i: u32) -> u32 {
    with(|s| s.meta.get(i as usize).copied().unwrap_or(0))
}

#[no_mangle]
pub extern "C" fn media_error() -> *const u8 {
    with(|s| s.error.as_ptr())
}

#[no_mangle]
pub extern "C" fn media_error_len() -> usize {
    with(|s| s.error.len())
}

/// Read the input as a pack: its number of files, or `u32::MAX` when refused
/// (the reason at [`media_error`]).
#[no_mangle]
pub extern "C" fn media_read_pack() -> u32 {
    with(|s| match read_pack(&std::mem::take(&mut s.input)) {
        Ok(p) => {
            let n = p.entries.len() as u32;
            s.pack = p;
            n
        }
        Err(e) => {
            s.error = e.to_string();
            u32::MAX
        }
    })
}

/// How many of the pack's files were set aside: each by name, with why.
#[no_mangle]
pub extern "C" fn media_skip_count() -> u32 {
    with(|s| s.pack.skipped.len() as u32)
}

#[no_mangle]
pub extern "C" fn media_skip_name(i: u32) -> *const u8 {
    with(|s| {
        s.pack
            .skipped
            .get(i as usize)
            .map_or(std::ptr::null(), |k| k.0.as_ptr())
    })
}

#[no_mangle]
pub extern "C" fn media_skip_name_len(i: u32) -> usize {
    with(|s| s.pack.skipped.get(i as usize).map_or(0, |k| k.0.len()))
}

#[no_mangle]
pub extern "C" fn media_skip_why(i: u32) -> *const u8 {
    with(|s| {
        s.pack
            .skipped
            .get(i as usize)
            .map_or(std::ptr::null(), |k| k.1.as_ptr())
    })
}

#[no_mangle]
pub extern "C" fn media_skip_why_len(i: u32) -> usize {
    with(|s| s.pack.skipped.get(i as usize).map_or(0, |k| k.1.len()))
}

/// The pack's title (UTF-8; empty when it has none).
#[no_mangle]
pub extern "C" fn media_pack_title() -> *const u8 {
    with(|s| s.pack.title.as_deref().unwrap_or("").as_ptr())
}

#[no_mangle]
pub extern "C" fn media_pack_title_len() -> usize {
    with(|s| s.pack.title.as_deref().map_or(0, str::len))
}

#[no_mangle]
pub extern "C" fn media_entry_name(i: u32) -> *const u8 {
    with(|s| {
        s.pack
            .entries
            .get(i as usize)
            .map_or(std::ptr::null(), |e| e.name.as_ptr())
    })
}

#[no_mangle]
pub extern "C" fn media_entry_name_len(i: u32) -> usize {
    with(|s| s.pack.entries.get(i as usize).map_or(0, |e| e.name.len()))
}

#[no_mangle]
pub extern "C" fn media_entry_bytes(i: u32) -> *const u8 {
    with(|s| {
        s.pack
            .entries
            .get(i as usize)
            .map_or(std::ptr::null(), |e| e.bytes.as_ptr())
    })
}

#[no_mangle]
pub extern "C" fn media_entry_bytes_len(i: u32) -> usize {
    with(|s| s.pack.entries.get(i as usize).map_or(0, |e| e.bytes.len()))
}
