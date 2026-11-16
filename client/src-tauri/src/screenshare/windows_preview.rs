//! Pictures for the Windows share picker (1.13, Track 2, D4): a still of each display and
//! window by GDI — `StretchBlt` from the screen, `PrintWindow` for a window — so no capture
//! border flashes and nothing is captured continuously; and a window's icon, the tile's
//! picture when the still says nothing. Drawn in the app only: never sent, never stored.

use std::ffi::c_void;

use windows::Win32::Foundation::{HWND, LPARAM, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, GetMonitorInfoW,
    ReleaseDC, SelectObject, SetBrushOrgEx, SetStretchBltMode, StretchBlt, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HALFTONE, HBITMAP, HDC, HGDIOBJ, HMONITOR,
    MONITORINFO, SRCCOPY,
};
use windows::Win32::Storage::Xps::{PrintWindow, PRINT_WINDOW_FLAGS};
use windows::Win32::UI::WindowsAndMessaging::{
    DrawIconEx, GetClassLongPtrW, GetWindowRect, IsHungAppWindow, IsIconic, SendMessageTimeoutW,
    DI_NORMAL, GCLP_HICON, HICON, ICON_BIG, ICON_SMALL2, SMTO_ABORTIFHUNG, WM_GETICON,
};

use super::{downscale_bgra, preview_size, preview_url, SourcePicture};

/// `PW_RENDERFULLCONTENT`: windows that draw with the GPU (browsers, most apps now) come out
/// black without it. The windows crate names only `PW_CLIENTONLY`.
const PW_RENDERFULLCONTENT: PRINT_WINDOW_FLAGS = PRINT_WINDOW_FLAGS(2);
/// A window larger than this is not drawn for a tile (a DIB of it would be gigabytes).
const MOST_PIXELS: i64 = 8192 * 8192;
const ICON_SIDE: i32 = 32;

/// A 32-bit top-down DIB selected into its own memory DC.
struct Dib {
    dc: HDC,
    bmp: HBITMAP,
    old: HGDIOBJ,
    bits: *mut u8,
    w: i32,
    h: i32,
}

impl Dib {
    unsafe fn new(w: i32, h: i32, like: HDC) -> Option<Dib> {
        let dc = CreateCompatibleDC(like);
        if dc.is_invalid() {
            return None;
        }
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits: *mut c_void = std::ptr::null_mut();
        let Ok(bmp) = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut bits, None, 0) else {
            let _ = DeleteDC(dc);
            return None;
        };
        if bits.is_null() {
            let _ = DeleteObject(bmp);
            let _ = DeleteDC(dc);
            return None;
        }
        let old = SelectObject(dc, bmp);
        Some(Dib {
            dc,
            bmp,
            old,
            bits: bits as *mut u8,
            w,
            h,
        })
    }

    fn pixels(&self) -> &[u8] {
        // SAFETY: the section is w*h*4 bytes, alive until drop
        unsafe { std::slice::from_raw_parts(self.bits, (self.w * self.h * 4) as usize) }
    }

    fn pixels_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, and only this Dib writes it
        unsafe { std::slice::from_raw_parts_mut(self.bits, (self.w * self.h * 4) as usize) }
    }
}

impl Drop for Dib {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.dc, self.old);
            let _ = DeleteObject(self.bmp);
            let _ = DeleteDC(self.dc);
        }
    }
}

/// A display, scaled by GDI's HALFTONE stretch straight to the tile's size.
unsafe fn display_still(hmon: HMONITOR) -> Option<(Vec<u8>, u32, u32)> {
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    if !GetMonitorInfoW(hmon, &mut info).as_bool() {
        return None;
    }
    let r = info.rcMonitor;
    let (mw, mh) = (r.right - r.left, r.bottom - r.top);
    if mw <= 0 || mh <= 0 {
        return None;
    }
    let (pw, ph) = preview_size(mw as u32, mh as u32);
    let screen = GetDC(HWND::default());
    let dib = Dib::new(pw as i32, ph as i32, screen);
    let out = dib.and_then(|dib| {
        SetStretchBltMode(dib.dc, HALFTONE);
        let _ = SetBrushOrgEx(dib.dc, 0, 0, None);
        StretchBlt(
            dib.dc, 0, 0, pw as i32, ph as i32, screen, r.left, r.top, mw, mh, SRCCOPY,
        )
        .as_bool()
        .then(|| (dib.pixels().to_vec(), pw, ph))
    });
    ReleaseDC(HWND::default(), screen);
    out
}

/// A window as it draws itself (`PrintWindow`), cut to its visible frame and scaled down.
/// A hung or minimised window gives none.
unsafe fn window_still(hwnd: HWND) -> Option<(Vec<u8>, u32, u32)> {
    if IsHungAppWindow(hwnd).as_bool() || IsIconic(hwnd).as_bool() {
        return None;
    }
    let mut wr = RECT::default();
    GetWindowRect(hwnd, &mut wr).ok()?;
    let (ww, wh) = (wr.right - wr.left, wr.bottom - wr.top);
    if ww <= 0 || wh <= 0 || ww as i64 * wh as i64 > MOST_PIXELS {
        return None;
    }
    // The frame without the invisible resize borders around it
    let mut fr = wr;
    let _ = DwmGetWindowAttribute(
        hwnd,
        DWMWA_EXTENDED_FRAME_BOUNDS,
        &mut fr as *mut RECT as *mut c_void,
        std::mem::size_of::<RECT>() as u32,
    );
    let screen = GetDC(HWND::default());
    let dib = Dib::new(ww, wh, screen);
    ReleaseDC(HWND::default(), screen);
    let dib = dib?;
    if !PrintWindow(hwnd, dib.dc, PW_RENDERFULLCONTENT).as_bool() {
        return None;
    }
    let ox = (fr.left - wr.left).clamp(0, ww - 1);
    let oy = (fr.top - wr.top).clamp(0, wh - 1);
    let cw = (fr.right - fr.left).clamp(1, ww - ox);
    let ch = (fr.bottom - fr.top).clamp(1, wh - oy);
    let (pw, ph) = preview_size(cw as u32, ch as u32);
    let start = ((oy * ww + ox) * 4) as usize;
    let small = downscale_bgra(
        &dib.pixels()[start..],
        cw as usize,
        ch as usize,
        (ww * 4) as usize,
        pw as usize,
        ph as usize,
    );
    Some((small, pw, ph))
}

/// The window's icon as a 32x32 PNG data URL: drawn on black and on white, the difference
/// gives each pixel's alpha whether the icon has an alpha channel or only a mask.
unsafe fn window_icon(hwnd: HWND) -> Option<String> {
    let mut handle = 0usize;
    for kind in [ICON_SMALL2, ICON_BIG] {
        let mut got = 0usize;
        let sent = SendMessageTimeoutW(
            hwnd,
            WM_GETICON,
            WPARAM(kind as usize),
            LPARAM(0),
            SMTO_ABORTIFHUNG,
            50,
            Some(&mut got),
        );
        if sent.0 != 0 && got != 0 {
            handle = got;
            break;
        }
    }
    if handle == 0 {
        handle = GetClassLongPtrW(hwnd, GCLP_HICON);
    }
    if handle == 0 {
        return None;
    }
    let icon = HICON(handle as *mut c_void);
    let screen = GetDC(HWND::default());
    let on = |fill: u8| -> Option<Vec<u8>> {
        let mut dib = Dib::new(ICON_SIDE, ICON_SIDE, screen)?;
        dib.pixels_mut().fill(fill);
        DrawIconEx(dib.dc, 0, 0, icon, ICON_SIDE, ICON_SIDE, 0, None, DI_NORMAL).ok()?;
        Some(dib.pixels().to_vec())
    };
    let (black, white) = (on(0), on(255));
    ReleaseDC(HWND::default(), screen);
    let (black, white) = (black?, white?);
    let mut rgba = Vec::with_capacity(black.len());
    for (b, w) in black.chunks_exact(4).zip(white.chunks_exact(4)) {
        let alpha = 255 - (w[1] as i32 - b[1] as i32).clamp(0, 255);
        let un = |v: u8| {
            if alpha == 0 {
                0
            } else {
                ((v as i32 * 255) / alpha).min(255) as u8
            }
        };
        rgba.extend_from_slice(&[un(b[2]), un(b[1]), un(b[0]), alpha as u8]);
    }
    if rgba.chunks_exact(4).all(|p| p[3] == 0) {
        return None;
    }
    let png = voipc_media::png(rgba, ICON_SIDE as u32, ICON_SIDE as u32).ok()?;
    use base64::Engine;
    Some(format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    ))
}

/// A picker tile's picture for a source (`display` with an HMONITOR id, `window` with an
/// HWND id): its still, unless that says nothing, and a window's icon.
pub fn source_picture(source_type: &str, source_id: &str) -> SourcePicture {
    let Ok(id) = source_id.parse::<isize>() else {
        return SourcePicture::default();
    };
    unsafe {
        match source_type {
            "display" => SourcePicture {
                picture: display_still(HMONITOR(id as *mut c_void))
                    .and_then(|(px, w, h)| preview_url(&px, w as usize, h as usize)),
                icon: None,
            },
            "window" => {
                let hwnd = HWND(id as *mut c_void);
                SourcePicture {
                    picture: window_still(hwnd)
                        .and_then(|(px, w, h)| preview_url(&px, w as usize, h as usize)),
                    icon: window_icon(hwnd),
                }
            }
            _ => SourcePicture::default(),
        }
    }
}
