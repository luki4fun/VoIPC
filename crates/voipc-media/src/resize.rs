//! Fitting frames into a box as they are decoded, so a big animation never
//! holds more than one full-size canvas.

use crate::decode::Sink;
use crate::{Error, Result};

pub struct Frame {
    pub rgba: Vec<u8>,
    pub delay_ms: u16,
}

/// A `Sink` that keeps each frame fitted into `side` × `side` (never made
/// bigger), and a frame just like the one before only as a longer one.
pub struct Fit {
    side: u32,
    src: (u32, u32),
    dst: (u32, u32),
    frames: Vec<Frame>,
}

impl Fit {
    pub fn new(side: u32) -> Fit {
        Fit {
            side,
            src: (0, 0),
            dst: (0, 0),
            frames: Vec::new(),
        }
    }

    pub fn finish(self) -> Result<(Vec<Frame>, u32, u32)> {
        if self.frames.is_empty() {
            return Err(Error::Corrupt("no frame".into()));
        }
        Ok((self.frames, self.dst.0, self.dst.1))
    }
}

/// `w` × `h` fitted into `side` × `side`, keeping its shape.
pub fn fit(w: u32, h: u32, side: u32) -> (u32, u32) {
    if w <= side && h <= side {
        (w, h)
    } else if w >= h {
        (
            side,
            ((u64::from(h) * u64::from(side)) / u64::from(w)).max(1) as u32,
        )
    } else {
        (
            ((u64::from(w) * u64::from(side)) / u64::from(h)).max(1) as u32,
            side,
        )
    }
}

impl Sink for Fit {
    fn start(&mut self, w: u32, h: u32) -> Result<()> {
        self.src = (w, h);
        self.dst = fit(w, h, self.side);
        Ok(())
    }

    fn frame(&mut self, canvas: &[u8], delay_ms: u16) -> Result<()> {
        let ((w, h), (tw, th)) = (self.src, self.dst);
        if canvas.len() != (w as usize) * (h as usize) * 4 {
            return Err(Error::Corrupt("a frame of the wrong size".into()));
        }
        let rgba = if (tw, th) == (w, h) {
            canvas.to_vec()
        } else {
            shrink(canvas, w, h, tw, th)
        };
        match self.frames.last_mut() {
            Some(last) if last.rgba == rgba => {
                last.delay_ms = last.delay_ms.saturating_add(delay_ms)
            }
            _ => self.frames.push(Frame { rgba, delay_ms }),
        }
        Ok(())
    }
}

/// The mean of each target pixel's area, weighted by alpha so a transparent
/// pixel's colour does not bleed into its neighbours.
pub fn shrink(src: &[u8], w: u32, h: u32, tw: u32, th: u32) -> Vec<u8> {
    let span = |t: u32, n: u32, of: u32| {
        let a = (u64::from(t) * u64::from(n) / u64::from(of)) as u32;
        let b = (u64::from(t + 1) * u64::from(n)).div_ceil(u64::from(of)) as u32;
        (a, b.max(a + 1).min(n))
    };
    let mut out = vec![0u8; (tw * th * 4) as usize];
    for ty in 0..th {
        let (y0, y1) = span(ty, h, th);
        for tx in 0..tw {
            let (x0, x1) = span(tx, w, tw);
            let (mut r, mut g, mut b, mut a, mut n) = (0u64, 0u64, 0u64, 0u64, 0u64);
            for y in y0..y1 {
                let row = ((y * w) * 4) as usize;
                for x in x0..x1 {
                    let i = row + (x * 4) as usize;
                    let pa = u64::from(src[i + 3]);
                    r += u64::from(src[i]) * pa;
                    g += u64::from(src[i + 1]) * pa;
                    b += u64::from(src[i + 2]) * pa;
                    a += pa;
                    n += 1;
                }
            }
            let o = ((ty * tw + tx) * 4) as usize;
            if let (Some(r), Some(g), Some(b)) =
                (r.checked_div(a), g.checked_div(a), b.checked_div(a))
            {
                out[o] = r as u8;
                out[o + 1] = g as u8;
                out[o + 2] = b as u8;
            }
            out[o + 3] = (a / n.max(1)) as u8;
        }
    }
    out
}

/// Every other frame, each kept one lasting as long as the two did.
pub fn every_other(frames: Vec<Frame>) -> Vec<Frame> {
    let mut out: Vec<Frame> = Vec::with_capacity(frames.len().div_ceil(2));
    for (i, f) in frames.into_iter().enumerate() {
        if i % 2 == 0 {
            out.push(f);
        } else if let Some(last) = out.last_mut() {
            last.delay_ms = last.delay_ms.saturating_add(f.delay_ms);
        }
    }
    out
}
