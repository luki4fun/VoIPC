//! Writing frames as a PNG, or an APNG when there are several. After the
//! first, a frame carries only the rectangle that changed, copied over the one
//! before: most stickers move a little on a still background.

use crate::resize::Frame;
use crate::{Error, Result};

fn failed(e: impl std::fmt::Display) -> Error {
    Error::Corrupt(format!("could not write it: {e}"))
}

pub fn write(frames: &[Frame], w: u32, h: u32, compression: png::Compression) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_color(png::ColorType::Rgba);
    e.set_depth(png::BitDepth::Eight);
    e.set_compression(compression);
    let animated = frames.len() > 1;
    if animated {
        e.set_animated(frames.len() as u32, 0).map_err(failed)?;
    }
    let mut wr = e.write_header().map_err(failed)?;
    for (i, f) in frames.iter().enumerate() {
        if !animated {
            wr.write_image_data(&f.rgba).map_err(failed)?;
            continue;
        }
        wr.set_frame_delay(f.delay_ms, 1000).map_err(failed)?;
        let (x0, y0, x1, y1) = if i == 0 {
            (0, 0, w, h)
        } else {
            changed(&frames[i - 1].rgba, &f.rgba, w, h)
        };
        // Each setter is checked against the others' last values: from 0,0
        wr.set_frame_position(0, 0).map_err(failed)?;
        wr.set_frame_dimension(x1 - x0, y1 - y0).map_err(failed)?;
        wr.set_frame_position(x0, y0).map_err(failed)?;
        wr.set_blend_op(png::BlendOp::Source).map_err(failed)?;
        wr.set_dispose_op(png::DisposeOp::None).map_err(failed)?;
        let mut part = Vec::with_capacity(((x1 - x0) * (y1 - y0) * 4) as usize);
        for y in y0..y1 {
            let a = ((y * w + x0) * 4) as usize;
            part.extend_from_slice(&f.rgba[a..a + ((x1 - x0) * 4) as usize]);
        }
        wr.write_image_data(&part).map_err(failed)?;
    }
    wr.finish().map_err(failed)?;
    Ok(out)
}

/// The smallest rectangle where `b` differs from `a`; one pixel where none
/// does (a frame cannot be empty).
fn changed(a: &[u8], b: &[u8], w: u32, h: u32) -> (u32, u32, u32, u32) {
    let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0, 0);
    for y in 0..h {
        let row = (y * w * 4) as usize;
        for x in 0..w {
            let i = row + (x * 4) as usize;
            if a[i..i + 4] != b[i..i + 4] {
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x + 1);
                y1 = y1.max(y + 1);
            }
        }
    }
    if x1 == 0 {
        (0, 0, 1, 1)
    } else {
        (x0, y0, x1, y1)
    }
}
