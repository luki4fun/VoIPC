//! Reading a picture: what it is from its first bytes, then its frames one at
//! a time, each as a whole RGBA canvas, into a `Sink`. Every size is checked
//! before anything is allocated for it, and the work a file can ask for is
//! bounded however it lies about itself.

use std::io::Cursor;

use crate::{exif, Error, Result};

/// The longest side read at all.
pub const MAX_SIDE: u32 = 16_384;
/// One frame's pixels: a 50-megapixel phone photo.
pub const MAX_FRAME_PIXELS: u64 = 50_000_000;
/// A moving picture's canvas: 4096 × 4096. Composing frames holds two.
pub const MAX_ANIMATION_PIXELS: u64 = 16_777_216;
pub const MAX_FRAMES: usize = 300;
/// Pixels decoded over all frames: what bounds the time a file takes.
pub const MAX_WORK_PIXELS: u64 = 100_000_000;

/// Where frames go: told the canvas size once, then given each frame.
pub trait Sink {
    fn start(&mut self, w: u32, h: u32) -> Result<()>;
    fn frame(&mut self, canvas: &[u8], delay_ms: u16) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Png,
    Gif,
    WebP,
    Jpeg,
}

/// What `b` is from its first bytes; for what is not read here, what it seems
/// to be, so a person learns why.
pub fn sniff(b: &[u8]) -> std::result::Result<Format, &'static str> {
    let at = |i: usize, s: &[u8]| b.len() >= i + s.len() && &b[i..i + s.len()] == s;
    if at(0, b"\x89PNG\r\n\x1a\n") {
        Ok(Format::Png)
    } else if at(0, b"GIF87a") || at(0, b"GIF89a") {
        Ok(Format::Gif)
    } else if at(0, b"RIFF") && at(8, b"WEBP") {
        Ok(Format::WebP)
    } else if at(0, &[0xFF, 0xD8, 0xFF]) {
        Ok(Format::Jpeg)
    } else if at(0, &[0x1F, 0x8B]) {
        Err("a Telegram animated sticker (.tgs) or another packed file")
    } else if at(0, &[0x1A, 0x45, 0xDF, 0xA3]) {
        Err("a video sticker (WebM)")
    } else if at(4, b"ftypavif") || at(4, b"ftypavis") {
        Err("AVIF")
    } else if at(4, b"ftypheic") || at(4, b"ftypheix") || at(4, b"ftypmif1") || at(4, b"ftypmsf1") {
        Err("HEIC")
    } else if at(4, b"ftyp") {
        Err("a video")
    } else if at(0, b"BM") {
        Err("BMP")
    } else {
        let text = b
            .iter()
            .skip_while(|c| c.is_ascii_whitespace())
            .take(5)
            .copied()
            .collect::<Vec<_>>();
        if text.starts_with(b"<") {
            Err("SVG or another markup file")
        } else if text.starts_with(b"{") {
            Err("a Lottie animation")
        } else {
            Err("this kind of file")
        }
    }
}

fn check(w: u32, h: u32) -> Result<()> {
    if w == 0 || h == 0 {
        return Err(Error::Corrupt("no size".into()));
    }
    if w > MAX_SIDE || h > MAX_SIDE || u64::from(w) * u64::from(h) > MAX_FRAME_PIXELS {
        return Err(Error::TooLarge("the picture is too big to show"));
    }
    Ok(())
}

fn check_animation(w: u32, h: u32) -> Result<()> {
    if u64::from(w) * u64::from(h) > MAX_ANIMATION_PIXELS {
        return Err(Error::TooLarge("the animation is too big to show"));
    }
    Ok(())
}

/// Counts frames and the pixels decoded so far, against the budgets.
struct Budget {
    frames: usize,
    work: u64,
}

impl Budget {
    fn take(&mut self, w: u32, h: u32) -> Result<()> {
        self.frames += 1;
        self.work += u64::from(w) * u64::from(h);
        if self.frames > MAX_FRAMES {
            return Err(Error::TooLarge("the animation has too many frames"));
        }
        if self.work > MAX_WORK_PIXELS {
            return Err(Error::TooLarge("the animation is too long to show"));
        }
        Ok(())
    }
}

fn corrupt(e: impl std::fmt::Display) -> Error {
    Error::Corrupt(e.to_string())
}

/// Read `b` into `sink`. Returns the EXIF orientation it asks for (1 = as is).
pub fn decode(b: &[u8], sink: &mut dyn Sink) -> Result<u8> {
    match sniff(b).map_err(Error::Unsupported)? {
        Format::Png => png_frames(b, sink),
        Format::Gif => gif_frames(b, sink).map(|()| 1),
        Format::WebP => webp_frames(b, sink),
        Format::Jpeg => jpeg_frame(b, sink),
    }
}

/// Gray, gray with alpha, RGB or RGBA as RGBA.
fn to_rgba(buf: &[u8], channels: usize) -> Vec<u8> {
    match channels {
        4 => buf.to_vec(),
        3 => buf
            .as_chunks::<3>()
            .0
            .iter()
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        2 => buf
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|p| [p[0], p[0], p[0], p[1]])
            .collect(),
        _ => buf.iter().flat_map(|&g| [g, g, g, 255]).collect(),
    }
}

/// `src` over `dst`, both straight (not premultiplied) RGBA.
fn over(dst: &mut [u8], src: &[u8]) {
    let sa = u32::from(src[3]);
    let da = u32::from(dst[3]) * (255 - sa) / 255;
    let oa = sa + da;
    for i in 0..3 {
        dst[i] = ((u32::from(src[i]) * sa + u32::from(dst[i]) * da) / oa.max(1)) as u8;
    }
    dst[3] = oa as u8;
}

/// Clear a rectangle of a `w`-wide canvas to transparent.
fn clear(canvas: &mut [u8], w: u32, x0: u32, y0: u32, rw: u32, rh: u32) {
    for y in y0..y0 + rh {
        let a = ((y * w + x0) * 4) as usize;
        canvas[a..a + (rw * 4) as usize].fill(0);
    }
}

fn png_frames(b: &[u8], sink: &mut dyn Sink) -> Result<u8> {
    let limits = png::Limits {
        bytes: (MAX_FRAME_PIXELS * 4) as usize,
    };
    let mut dec = png::Decoder::new_with_limits(Cursor::new(b), limits);
    dec.set_transformations(png::Transformations::normalize_to_color8());
    let mut rd = dec.read_info().map_err(corrupt)?;
    let (w, h) = (rd.info().width, rd.info().height);
    check(w, h)?;
    let orientation = rd
        .info()
        .exif_metadata
        .as_deref()
        .map_or(1, exif::orientation);
    let animated = rd
        .info()
        .animation_control()
        .map(|a| a.num_frames as usize)
        .filter(|&n| n > 1);
    if animated.is_some() {
        check_animation(w, h)?;
    }
    sink.start(w, h)?;
    let mut buf = vec![
        0u8;
        rd.output_buffer_size()
            .ok_or(Error::TooLarge("the picture is too big to show"))?
    ];
    let mut budget = Budget { frames: 0, work: 0 };
    let Some(total) = animated else {
        budget.take(w, h)?;
        let out = rd.next_frame(&mut buf).map_err(corrupt)?;
        sink.frame(
            &to_rgba(&buf[..out.buffer_size()], out.color_type.samples()),
            0,
        )?;
        return Ok(orientation);
    };
    let mut canvas = vec![0u8; (w * h * 4) as usize];
    let mut shown = 0;
    let mut first = true;
    while shown < total {
        let out = match rd.next_frame(&mut buf) {
            Ok(o) => o,
            // A last frame cut short: what came before still plays
            Err(_) if shown > 0 => break,
            Err(e) => return Err(corrupt(e)),
        };
        let fc = rd.info().frame_control().copied();
        // An APNG's default image need not be a frame of its animation
        let was_first = std::mem::replace(&mut first, false);
        let Some(fc) = fc else {
            if was_first {
                continue;
            }
            return Err(Error::Corrupt("a frame without its control".into()));
        };
        let (x0, y0, fw, fh) = (fc.x_offset, fc.y_offset, fc.width, fc.height);
        let fits = x0.checked_add(fw).is_some_and(|r| r <= w)
            && y0.checked_add(fh).is_some_and(|b| b <= h);
        if !fits || fw != out.width || fh != out.height {
            return Err(Error::Corrupt("a frame outside the picture".into()));
        }
        budget.take(fw, fh)?;
        let px = to_rgba(&buf[..out.buffer_size()], out.color_type.samples());
        let saved = (fc.dispose_op == png::DisposeOp::Previous).then(|| canvas.clone());
        for y in 0..fh {
            for x in 0..fw {
                let s = ((y * fw + x) * 4) as usize;
                let d = (((y0 + y) * w + x0 + x) * 4) as usize;
                if fc.blend_op == png::BlendOp::Source || px[s + 3] == 255 {
                    canvas[d..d + 4].copy_from_slice(&px[s..s + 4]);
                } else if px[s + 3] > 0 {
                    over(&mut canvas[d..d + 4], &px[s..s + 4]);
                }
            }
        }
        let den = if fc.delay_den == 0 {
            100
        } else {
            u32::from(fc.delay_den)
        };
        sink.frame(
            &canvas,
            (u32::from(fc.delay_num) * 1000 / den).min(65_535) as u16,
        )?;
        shown += 1;
        match fc.dispose_op {
            png::DisposeOp::Background => clear(&mut canvas, w, x0, y0, fw, fh),
            png::DisposeOp::Previous => canvas = saved.unwrap_or(canvas),
            png::DisposeOp::None => {}
        }
    }
    if shown == 0 {
        return Err(Error::Corrupt("no frame".into()));
    }
    Ok(orientation)
}

fn gif_frames(b: &[u8], sink: &mut dyn Sink) -> Result<()> {
    let mut opts = gif::DecodeOptions::new();
    opts.set_color_output(gif::ColorOutput::RGBA);
    if let Some(limit) = std::num::NonZeroU64::new(MAX_ANIMATION_PIXELS * 4) {
        opts.set_memory_limit(gif::MemoryLimit::Bytes(limit));
    }
    let mut d = opts.read_info(Cursor::new(b)).map_err(corrupt)?;
    let (w, h) = (u32::from(d.width()), u32::from(d.height()));
    check(w, h)?;
    check_animation(w, h)?;
    sink.start(w, h)?;
    let mut canvas = vec![0u8; (w * h * 4) as usize];
    let mut budget = Budget { frames: 0, work: 0 };
    while let Some(f) = d.read_next_frame().map_err(corrupt)? {
        let (fx, fy, fw, fh) = (
            u32::from(f.left),
            u32::from(f.top),
            u32::from(f.width),
            u32::from(f.height),
        );
        budget.take(fw.max(1), fh.max(1))?;
        // What of the frame lies on the screen; a GIF may draw past it
        let (cw, ch) = (fw.min(w.saturating_sub(fx)), fh.min(h.saturating_sub(fy)));
        let saved = (f.dispose == gif::DisposalMethod::Previous).then(|| canvas.clone());
        for y in 0..ch {
            for x in 0..cw {
                let s = ((y * fw + x) * 4) as usize;
                if f.buffer.get(s + 3).is_some_and(|&a| a > 0) {
                    let d = (((fy + y) * w + fx + x) * 4) as usize;
                    canvas[d..d + 4].copy_from_slice(&f.buffer[s..s + 4]);
                }
            }
        }
        // 0 and 10 ms are what browsers draw at 100 ms: so do we
        let delay = match u32::from(f.delay) * 10 {
            d if d < 20 => 100,
            d => d.min(65_535),
        };
        sink.frame(&canvas, delay as u16)?;
        match f.dispose {
            gif::DisposalMethod::Background => clear(&mut canvas, w, fx.min(w), fy.min(h), cw, ch),
            gif::DisposalMethod::Previous => canvas = saved.unwrap_or(canvas),
            _ => {}
        }
    }
    if budget.frames == 0 {
        return Err(Error::Corrupt("no frame".into()));
    }
    Ok(())
}

fn webp_frames(b: &[u8], sink: &mut dyn Sink) -> Result<u8> {
    let mut d = image_webp::WebPDecoder::new(Cursor::new(b)).map_err(corrupt)?;
    let (w, h) = d.dimensions();
    check(w, h)?;
    d.set_memory_limit((MAX_FRAME_PIXELS * 4) as usize);
    let orientation = d
        .exif_metadata()
        .ok()
        .flatten()
        .as_deref()
        .map_or(1, exif::orientation);
    let size = d
        .output_buffer_size()
        .ok_or(Error::TooLarge("the picture is too big to show"))?;
    let channels = size / (w as usize * h as usize);
    let mut buf = vec![0u8; size];
    let mut budget = Budget { frames: 0, work: 0 };
    if d.is_animated() {
        check_animation(w, h)?;
        sink.start(w, h)?;
        let n = d.num_frames() as usize;
        for _ in 0..n {
            budget.take(w, h)?;
            let delay = match d.read_frame(&mut buf) {
                Ok(delay) => delay,
                Err(_) if budget.frames > 1 => break,
                Err(e) => return Err(corrupt(e)),
            };
            sink.frame(&to_rgba(&buf, channels), delay.min(65_535) as u16)?;
        }
    } else {
        sink.start(w, h)?;
        budget.take(w, h)?;
        d.read_image(&mut buf).map_err(corrupt)?;
        sink.frame(&to_rgba(&buf, channels), 0)?;
    }
    Ok(orientation)
}

fn jpeg_frame(b: &[u8], sink: &mut dyn Sink) -> Result<u8> {
    use zune_core::{bytestream::ZCursor, colorspace::ColorSpace, options::DecoderOptions};
    let opts = DecoderOptions::default()
        .set_max_width(MAX_SIDE as usize)
        .set_max_height(MAX_SIDE as usize)
        .set_use_unsafe(false)
        .jpeg_set_out_colorspace(ColorSpace::RGBA);
    let mut d = zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(b), opts);
    d.decode_headers()
        .map_err(|e| Error::Corrupt(format!("{e:?}")))?;
    let (w, h) = d
        .dimensions()
        .ok_or_else(|| Error::Corrupt("no size".into()))?;
    let (w, h) = (w as u32, h as u32);
    check(w, h)?;
    let orientation = d.exif().map_or(1, |e| exif::orientation(e));
    sink.start(w, h)?;
    let px = d.decode().map_err(|e| Error::Corrupt(format!("{e:?}")))?;
    if px.len() != (w * h * 4) as usize {
        return Err(Error::Corrupt("short picture data".into()));
    }
    sink.frame(&px, 0)?;
    Ok(orientation)
}
