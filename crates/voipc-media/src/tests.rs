use std::borrow::Cow;

use crate::*;

/// A PNG of `w` × `h` in `color`, with `data` as its pixels, and a text chunk
/// that must not survive.
fn png_of(
    w: u32,
    h: u32,
    color: png::ColorType,
    depth: png::BitDepth,
    data: &[u8],
    palette: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_color(color);
    e.set_depth(depth);
    if let Some((plte, trns)) = palette {
        e.set_palette(Cow::Borrowed(plte));
        e.set_trns(Cow::Borrowed(trns));
    }
    e.add_text_chunk("Comment".into(), "secret location".into())
        .unwrap();
    let mut wr = e.write_header().unwrap();
    wr.write_image_data(data).unwrap();
    wr.finish().unwrap();
    out
}

fn rgba(w: u32, h: u32, f: impl Fn(u32, u32) -> [u8; 4]) -> Vec<u8> {
    let f = &f;
    (0..h)
        .flat_map(|y| (0..w).flat_map(move |x| f(x, y)))
        .collect::<Vec<u8>>()
}

/// What a PNG written here holds: its size, and each frame's whole canvas.
fn frames_of(png_bytes: &[u8]) -> (u32, u32, Vec<Vec<u8>>) {
    struct Keep(u32, u32, Vec<Vec<u8>>);
    impl decode::Sink for Keep {
        fn start(&mut self, w: u32, h: u32) -> Result<()> {
            (self.0, self.1) = (w, h);
            Ok(())
        }
        fn frame(&mut self, canvas: &[u8], _: u16) -> Result<()> {
            self.2.push(canvas.to_vec());
            Ok(())
        }
    }
    let mut k = Keep(0, 0, Vec::new());
    decode::decode(png_bytes, &mut k).unwrap();
    (k.0, k.1, k.2)
}

fn px(canvas: &[u8], w: u32, x: u32, y: u32) -> [u8; 4] {
    let i = ((y * w + x) * 4) as usize;
    [canvas[i], canvas[i + 1], canvas[i + 2], canvas[i + 3]]
}

#[test]
fn every_png_colour_type_comes_out_as_rgba_with_nothing_else_of_the_file() {
    let rgb = png_of(
        4,
        2,
        png::ColorType::Rgb,
        png::BitDepth::Eight,
        &[10, 20, 30].repeat(8),
        None,
    );
    let gray = png_of(
        4,
        2,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &[99; 8],
        None,
    );
    let ga = png_of(
        4,
        2,
        png::ColorType::GrayscaleAlpha,
        png::BitDepth::Eight,
        &[50, 128].repeat(8),
        None,
    );
    let indexed = png_of(
        4,
        2,
        png::ColorType::Indexed,
        png::BitDepth::Eight,
        &[0, 1].repeat(4),
        Some((&[255, 0, 0, 0, 255, 0], &[255, 0])),
    );
    let wide = png_of(
        4,
        2,
        png::ColorType::Rgba,
        png::BitDepth::Sixteen,
        &[0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF].repeat(8),
        None,
    );
    for (input, want) in [
        (rgb, [10, 20, 30, 255]),
        (gray, [99, 99, 99, 255]),
        (ga, [50, 50, 50, 128]),
        (indexed, [255, 0, 0, 255]),
        (wide, [255, 0, 0, 255]),
    ] {
        let clean = sanitize(&input, Profile::Photo).unwrap();
        assert_eq!(
            (clean.w, clean.h, clean.frames, clean.trimmed),
            (4, 2, 1, false)
        );
        assert!(clean.still.is_none());
        let (w, _, frames) = frames_of(&clean.png);
        assert_eq!(px(&frames[0], w, 0, 0), want);
        assert!(
            !clean.png.windows(4).any(|c| c == b"tEXt"),
            "the input's text chunk is gone"
        );
    }
    let indexed = png_of(
        4,
        2,
        png::ColorType::Indexed,
        png::BitDepth::Eight,
        &[0, 1].repeat(4),
        Some((&[255, 0, 0, 0, 255, 0], &[255, 0])),
    );
    let (_, _, frames) = frames_of(&sanitize(&indexed, Profile::Emote).unwrap().png);
    assert_eq!(
        px(&frames[0], 4, 1, 0)[3],
        0,
        "tRNS makes palette entry 1 transparent"
    );
}

#[test]
fn a_picture_is_fitted_into_its_profiles_box_and_never_made_bigger() {
    let big = png_of(
        1000,
        500,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &rgba(1000, 500, |x, _| {
            if x < 500 {
                [255, 0, 0, 255]
            } else {
                [0, 0, 255, 255]
            }
        }),
        None,
    );
    let emote = sanitize(&big, Profile::Emote).unwrap();
    assert_eq!((emote.w, emote.h), (128, 64));
    let (w, _, f) = frames_of(&emote.png);
    assert_eq!(px(&f[0], w, 10, 10), [255, 0, 0, 255]);
    assert_eq!(px(&f[0], w, 120, 10), [0, 0, 255, 255]);
    assert_eq!(
        (
            sanitize(&big, Profile::Sticker).unwrap().w,
            sanitize(&big, Profile::Photo).unwrap().w
        ),
        (320, 1000)
    );
    let tall = png_of(
        30,
        900,
        png::ColorType::Rgb,
        png::BitDepth::Eight,
        &[1, 2, 3].repeat(30 * 900),
        None,
    );
    assert_eq!(
        (
            sanitize(&tall, Profile::Emote).unwrap().w,
            sanitize(&tall, Profile::Emote).unwrap().h
        ),
        (4, 128)
    );
    assert_eq!(
        resize::fit(3000, 1, 128),
        (128, 1),
        "never less than a pixel"
    );
}

#[test]
fn transparent_pixels_do_not_bleed_their_colour_when_shrunk() {
    // Half fully transparent green, half opaque red: the edge stays red
    let img = png_of(
        4,
        1,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &[
            [0, 255, 0, 0],
            [0, 255, 0, 0],
            [255, 0, 0, 255],
            [255, 0, 0, 255],
        ]
        .concat(),
        None,
    );
    let out = resize::shrink(&frames_of(&img).2[0], 4, 1, 1, 1);
    assert_eq!(out, vec![255, 0, 0, 127]);
}

/// An APNG of three 4×4 frames: a red canvas, a 2×2 blue square at (2,2)
/// blended over, then a green square at (0,0) disposed to the previous.
fn apng() -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, 4, 4);
    e.set_color(png::ColorType::Rgba);
    e.set_animated(3, 0).unwrap();
    let mut wr = e.write_header().unwrap();
    wr.set_frame_delay(1, 10).unwrap();
    wr.write_image_data(&[255, 0, 0, 255].repeat(16)).unwrap();
    wr.set_frame_dimension(2, 2).unwrap();
    wr.set_frame_position(2, 2).unwrap();
    wr.set_blend_op(png::BlendOp::Over).unwrap();
    wr.set_dispose_op(png::DisposeOp::Previous).unwrap();
    wr.write_image_data(&[0, 0, 255, 255].repeat(4)).unwrap();
    wr.set_frame_position(0, 0).unwrap();
    wr.write_image_data(
        &[
            [0, 255, 0, 255],
            [0, 0, 0, 0],
            [0, 255, 0, 255],
            [0, 0, 0, 0],
        ]
        .concat(),
    )
    .unwrap();
    wr.finish().unwrap();
    out
}

#[test]
fn an_apng_is_composed_as_its_frames_say_and_written_again_as_one() {
    let clean = sanitize(&apng(), Profile::Sticker).unwrap();
    assert_eq!((clean.w, clean.h, clean.frames), (4, 4, 3));
    let (w, _, f) = frames_of(&clean.png);
    assert_eq!(f.len(), 3);
    assert_eq!(px(&f[1], w, 3, 3), [0, 0, 255, 255], "frame 2 over frame 1");
    assert_eq!(
        px(&f[2], w, 3, 3),
        [255, 0, 0, 255],
        "frame 2 disposed to the canvas before it"
    );
    assert_eq!(px(&f[2], w, 0, 0), [0, 255, 0, 255]);
    assert_eq!(
        px(&f[2], w, 1, 0),
        [255, 0, 0, 255],
        "a transparent pixel blended over shows what is under it"
    );
    let (_, _, still) = frames_of(clean.still.as_ref().unwrap());
    assert_eq!(
        (still.len(), px(&still[0], w, 3, 3)),
        (1, [255, 0, 0, 255]),
        "the still is the first frame"
    );
}

/// left, top, width, height, palette indices, disposal, delay (cs)
type GifFrame = (u16, u16, u16, u16, Vec<u8>, gif::DisposalMethod, u16);

fn gif_of(w: u16, h: u16, frames: &[GifFrame]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut e = gif::Encoder::new(&mut out, w, h, &[255, 0, 0, 0, 0, 255, 0, 0, 0]).unwrap();
        for (left, top, fw, fh, idx, dispose, delay) in frames {
            let f = gif::Frame {
                left: *left,
                top: *top,
                width: *fw,
                height: *fh,
                buffer: Cow::Borrowed(idx),
                transparent: Some(2),
                dispose: *dispose,
                delay: *delay,
                ..gif::Frame::default()
            };
            e.write_frame(&f).unwrap();
        }
    }
    out
}

#[test]
fn a_gif_keeps_what_its_transparent_pixels_do_not_cover_and_its_quick_frames_slow_down() {
    let g = gif_of(
        2,
        1,
        &[
            (0, 0, 2, 1, vec![0, 0], gif::DisposalMethod::Keep, 0),
            (0, 0, 2, 1, vec![1, 2], gif::DisposalMethod::Keep, 50),
        ],
    );
    let clean = sanitize(&g, Profile::Emote).unwrap();
    let (w, _, f) = frames_of(&clean.png);
    assert_eq!(f.len(), 2);
    assert_eq!(
        (px(&f[1], w, 0, 0), px(&f[1], w, 1, 0)),
        ([0, 0, 255, 255], [255, 0, 0, 255])
    );
    // 0 cs becomes 100 ms, as browsers draw it: read back from the APNG's fcTL
    let mut d = png::Decoder::new(std::io::Cursor::new(&clean.png[..]))
        .read_info()
        .unwrap();
    let mut buf = vec![0; d.output_buffer_size().unwrap()];
    d.next_frame(&mut buf).unwrap();
    let fc = d.info().frame_control().unwrap();
    assert_eq!(
        u32::from(fc.delay_num) * 1000 / u32::from(fc.delay_den),
        100
    );
}

#[test]
fn a_gif_frame_drawn_past_its_screen_is_cut_to_it() {
    let g = gif_of(
        2,
        2,
        &[(1, 1, 3, 3, vec![1; 9], gif::DisposalMethod::Keep, 10)],
    );
    let clean = sanitize(&g, Profile::Emote).unwrap();
    let (w, _, f) = frames_of(&clean.png);
    assert_eq!(
        (px(&f[0], w, 1, 1), px(&f[0], w, 0, 0)[3]),
        ([0, 0, 255, 255], 0)
    );
}

/// A 1×1 GIF screen with `n` frames of `fw` × `fh`, each a few bytes of LZW:
/// what a frame says it is, not what it holds, is what costs.
fn gif_frames_past_screen(fw: u16, fh: u16, n: usize) -> Vec<u8> {
    gif_frames_sized(&vec![(fw, fh); n])
}

/// `gif_frames_past_screen` with a frame of each size; each draws one white
/// pixel at its corner.
fn gif_frames_sized(sizes: &[(u16, u16)]) -> Vec<u8> {
    let mut g = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff".to_vec();
    for (fw, fh) in sizes {
        g.extend_from_slice(&[0x2C, 0, 0, 0, 0]);
        g.extend_from_slice(&fw.to_le_bytes());
        g.extend_from_slice(&fh.to_le_bytes());
        g.extend_from_slice(&[0, 2, 2, 0x4C, 0x01, 0]);
    }
    g.push(0x3B);
    g
}

#[test]
fn a_gif_frame_is_charged_its_own_size_before_it_is_decoded() {
    for (fw, fh) in [(65_535, 65_535), (4097, 4096)] {
        assert_eq!(
            sanitize(&gif_frames_past_screen(fw, fh, 1), Profile::Photo).unwrap_err(),
            Error::TooLarge("the animation is too big to show"),
            "{fw}×{fh} on a 1×1 screen"
        );
    }
}

#[test]
fn webp_still_and_animated() {
    let mut still = Vec::new();
    image_webp::WebPEncoder::new(&mut still)
        .encode(
            &rgba(3, 2, |x, _| [x as u8 * 80, 7, 9, 200]),
            3,
            2,
            image_webp::ColorType::Rgba8,
        )
        .unwrap();
    let clean = sanitize(&still, Profile::Emote).unwrap();
    let (w, _, f) = frames_of(&clean.png);
    assert_eq!(
        (clean.w, clean.h, px(&f[0], w, 2, 1)),
        (3, 2, [160, 7, 9, 200])
    );
    let anim = sanitize(
        include_bytes!("../tests/fixtures/anim3.webp"),
        Profile::Sticker,
    )
    .unwrap();
    assert_eq!((anim.w, anim.h, anim.frames), (32, 32, 3));
    assert!(anim.still.is_some());
}

/// An EXIF block (its TIFF data) saying orientation `o`, and nothing else.
fn exif_tiff(o: u16) -> Vec<u8> {
    [
        b"II*\0".as_slice(),
        &8u32.to_le_bytes(),
        &1u16.to_le_bytes(),
        &0x0112u16.to_le_bytes(),
        &3u16.to_le_bytes(),
        &1u32.to_le_bytes(),
        &o.to_le_bytes(),
        &[0, 0],
        &0u32.to_le_bytes(),
    ]
    .concat()
}

/// `jpeg` with an EXIF block saying orientation `o`, just after its start.
fn with_orientation(jpeg: &[u8], o: u16) -> Vec<u8> {
    let payload = [b"Exif\0\0".as_slice(), &exif_tiff(o)].concat();
    let len = (payload.len() + 2) as u16;
    [
        &jpeg[..2],
        &[0xFF, 0xE1],
        &len.to_be_bytes(),
        &payload,
        &jpeg[2..],
    ]
    .concat()
}

#[test]
fn a_jpeg_is_turned_the_way_its_exif_says_and_nothing_else_of_its_exif_is_kept() {
    let plain = include_bytes!("../tests/fixtures/red-blue.jpg");
    let as_is = sanitize(plain, Profile::Photo).unwrap();
    let (w, _, f) = frames_of(&as_is.png);
    assert_eq!((as_is.w, as_is.h), (40, 20));
    assert!(
        px(&f[0], w, 2, 10)[0] > 200 && px(&f[0], w, 37, 10)[2] > 200,
        "red left, blue right"
    );
    // 6: shown turned a quarter clockwise, so the left (red) is on top
    let turned = sanitize(&with_orientation(plain, 6), Profile::Photo).unwrap();
    let (w, _, f) = frames_of(&turned.png);
    assert_eq!((turned.w, turned.h), (20, 40));
    assert!(
        px(&f[0], w, 10, 2)[0] > 200 && px(&f[0], w, 10, 37)[2] > 200,
        "red on top, blue below"
    );
    assert!(!turned.png.windows(4).any(|c| c == b"eXIf"));
    for o in 1..=8 {
        let c = sanitize(&with_orientation(plain, o), Profile::Photo).unwrap();
        assert_eq!(
            (c.w, c.h),
            if o >= 5 { (20, 40) } else { (40, 20) },
            "orientation {o}"
        );
    }
    assert_eq!(
        exif::orientation(b"II*\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0\x09\0"),
        1,
        "9 is no orientation"
    );
    assert_eq!(exif::orientation(b"MM\0*"), 1, "cut short");
}

#[test]
fn the_eight_orientations_move_each_pixel_where_it_belongs() {
    // 2 × 1: A B. Shown, orientation 6 is A over B; 8 is B over A
    let ab = [[1, 0, 0, 0], [2, 0, 0, 0]].concat();
    let firsts = |o| {
        let (out, w, h) = exif::orient(&ab, 2, 1, o);
        ((w, h), out.chunks(4).map(|p| p[0]).collect::<Vec<_>>())
    };
    assert_eq!(firsts(1), ((2, 1), vec![1, 2]));
    assert_eq!(firsts(2), ((2, 1), vec![2, 1]));
    assert_eq!(firsts(3), ((2, 1), vec![2, 1]));
    assert_eq!(firsts(4), ((2, 1), vec![1, 2]));
    assert_eq!(firsts(5), ((1, 2), vec![1, 2]));
    assert_eq!(firsts(6), ((1, 2), vec![1, 2]));
    assert_eq!(firsts(7), ((1, 2), vec![2, 1]));
    assert_eq!(firsts(8), ((1, 2), vec![2, 1]));
}

fn crc32(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in b {
        c ^= u32::from(x);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

#[test]
fn what_is_too_big_is_refused_before_anything_is_allocated_for_it() {
    // A real 1×1 PNG whose header claims 100000 × 100000
    let mut huge = png_of(
        1,
        1,
        png::ColorType::Rgb,
        png::BitDepth::Eight,
        &[0, 0, 0],
        None,
    );
    huge[16..20].copy_from_slice(&100_000u32.to_be_bytes());
    huge[20..24].copy_from_slice(&100_000u32.to_be_bytes());
    let crc = crc32(&huge[12..29]);
    huge[29..33].copy_from_slice(&crc.to_be_bytes());
    assert_eq!(
        sanitize(&huge, Profile::Photo).unwrap_err(),
        Error::TooLarge("the picture is too big to show")
    );
    let screen = gif_of(
        65_535,
        65_535,
        &[(0, 0, 1, 1, vec![0], gif::DisposalMethod::Keep, 10)],
    );
    assert!(matches!(
        sanitize(&screen, Profile::Emote),
        Err(Error::TooLarge(_))
    ));
    // (An animation over its frame or work budget stands as its first frame:
    // `an_animation_over_a_budget_stands_as_its_first_frame_and_says_why`)
    assert!(matches!(
        sanitize(&vec![0u8; (16 << 20) + 1], Profile::Emote),
        Err(Error::TooLarge(_))
    ));
    // A WebP canvas of the largest size there is, with nothing in it
    let vp8x = [
        b"RIFF".as_slice(),
        &30u32.to_le_bytes(),
        b"WEBPVP8X",
        &10u32.to_le_bytes(),
        &[0x02, 0, 0, 0],
        &[0xFF, 0xFF, 0xFF],
        &[0xFF, 0xFF, 0xFF],
    ]
    .concat();
    assert!(sanitize(&vp8x, Profile::Photo).is_err());
}

/// `n` one-pixel GIF frames, red then blue, the `i`th at (`i`, `i`) when
/// `walk`, else all at the corner.
fn dots(n: u16, walk: bool) -> Vec<GifFrame> {
    (0..n)
        .map(|i| {
            let at = if walk { i } else { 0 };
            (
                at,
                at,
                1,
                1,
                vec![(i % 2) as u8],
                gif::DisposalMethod::Keep,
                10,
            )
        })
        .collect()
}

/// anim3.webp with its three frames `times` over: an animated WebP of
/// `3 × times` frames.
fn webp_frames_repeated(times: usize) -> Vec<u8> {
    let src = include_bytes!("../tests/fixtures/anim3.webp");
    let (mut before, mut anmf, mut after) = (Vec::new(), Vec::new(), Vec::new());
    let mut at = 12;
    while at + 8 <= src.len() {
        let len = u32::from_le_bytes(src[at + 4..at + 8].try_into().unwrap()) as usize;
        let end = (at + 8 + len + (len & 1)).min(src.len());
        let chunk = &src[at..end];
        if &chunk[..4] == b"ANMF" {
            anmf.extend_from_slice(chunk);
        } else if anmf.is_empty() {
            before.extend_from_slice(chunk);
        } else {
            after.extend_from_slice(chunk);
        }
        at = end;
    }
    let body = [before, anmf.repeat(times), after].concat();
    [
        b"RIFF".as_slice(),
        &(body.len() as u32 + 4).to_le_bytes(),
        b"WEBP",
        &body,
    ]
    .concat()
}

#[test]
fn an_animation_over_a_budget_stands_as_its_first_frame_and_says_why() {
    // Shown as one plain PNG, with nothing to animate on hover
    let one = |c: &Clean| {
        let (w, h, f) = frames_of(&c.png);
        assert_eq!(
            (c.frames, f.len(), c.still.is_none(), c.trimmed, (w, h)),
            (1, 1, true, true, (c.w, c.h))
        );
        (w, f.into_iter().next().unwrap())
    };
    let gif = gif_of(1, 1, &dots(decode::MAX_FRAMES as u16 + 5, false));
    let c = sanitize(&gif, Profile::Emote).unwrap();
    assert_eq!(
        c.stilled,
        Some("the animation has too many frames to play here")
    );
    let (w, f) = one(&c);
    assert_eq!(px(&f, w, 0, 0), [255, 0, 0, 255], "its first frame");

    // A few KB of one-pixel frames on a big screen, each a whole canvas: the
    // reading stops at the work budget (the 24th), in the moving box
    let c = sanitize(&gif_of(2048, 2048, &dots(100, true)), Profile::Photo).unwrap();
    assert_eq!(c.stilled, Some("the animation is too long to play here"));
    let (w, f) = one(&c);
    assert_eq!((c.w, c.h), (1024, 1024));
    // Its first dot alone: the second, blue at (1,1), would share this pixel
    assert_eq!(px(&f, w, 0, 0), [255, 0, 0, 63]);

    // A later frame too big to read, after a first that was fine (S-1: it is
    // charged its own size before a pixel of it is read)
    let c = sanitize(&gif_frames_sized(&[(1, 1), (4097, 4096)]), Profile::Photo).unwrap();
    assert_eq!(c.stilled, Some("the animation is too big to play here"));
    let (w, f) = one(&c);
    assert_eq!(px(&f, w, 0, 0), [255, 255, 255, 255]);

    // An APNG of more frames than are read
    let mut apng = Vec::new();
    {
        let mut e = png::Encoder::new(&mut apng, 1, 1);
        e.set_color(png::ColorType::Rgba);
        e.set_animated(decode::MAX_FRAMES as u32 + 5, 0).unwrap();
        let mut wr = e.write_header().unwrap();
        for i in 0..decode::MAX_FRAMES + 5 {
            wr.write_image_data(&[0, 0, (i % 2) as u8 * 255, 255])
                .unwrap();
        }
        wr.finish().unwrap();
    }
    let c = sanitize(&apng, Profile::Sticker).unwrap();
    assert_eq!(
        c.stilled,
        Some("the animation has too many frames to play here")
    );
    let (w, f) = one(&c);
    assert_eq!(px(&f, w, 0, 0), [0, 0, 0, 255]);

    // An animated WebP of more frames than are read: its first frame, as the
    // 3-frame one shows it
    let short = sanitize(&webp_frames_repeated(1), Profile::Sticker).unwrap();
    assert_eq!((short.frames, short.stilled), (3, None));
    let c = sanitize(&webp_frames_repeated(101), Profile::Sticker).unwrap();
    assert_eq!(
        c.stilled,
        Some("the animation has too many frames to play here")
    );
    let (_, f) = one(&c);
    assert_eq!(f, frames_of(short.still.as_ref().unwrap()).2[0]);

    // Within every budget it moves, and says nothing
    let fine = sanitize(&gif_of(1, 1, &dots(20, false)), Profile::Emote).unwrap();
    assert_eq!((fine.frames, fine.trimmed, fine.stilled), (20, false, None));
}

#[test]
fn what_is_refused_for_anything_but_an_animation_budget_stays_refused() {
    // Over a budget before its first frame (S-1): nothing to show
    for n in [1, 2] {
        assert_eq!(
            sanitize(&gif_frames_past_screen(4097, 4096, n), Profile::Photo).unwrap_err(),
            Error::TooLarge("the animation is too big to show")
        );
    }
    // A screen too big to animate is refused before any frame is read
    assert_eq!(
        sanitize(&gif_of(4097, 4096, &dots(2, true)), Profile::Photo).unwrap_err(),
        Error::TooLarge("the animation is too big to show")
    );
    // Damaged before its budget ran out: refused as damaged, as before
    let long = gif_of(2048, 2048, &dots(100, true));
    let cut = &long[..long.len() * 10 / 100];
    assert!(
        matches!(sanitize(cut, Profile::Photo), Err(Error::Corrupt(_))),
        "{:?}",
        sanitize(cut, Profile::Photo).map(|c| c.frames)
    );
    let mut first_broken = gif_frames_sized(&[(1, 1); 400]);
    first_broken[19 + 10] = 12; // the first frame's LZW code size
    assert!(matches!(
        sanitize(&first_broken, Profile::Emote),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn what_is_not_a_picture_read_here_says_what_it_seems_to_be() {
    let reason = |b: &[u8]| match sanitize(b, Profile::Sticker) {
        Err(Error::Unsupported(r)) => r,
        other => panic!("{other:?}"),
    };
    assert!(reason(&[0x1F, 0x8B, 8, 0]).contains(".tgs"));
    assert!(reason(&[0x1A, 0x45, 0xDF, 0xA3, 0]).contains("WebM"));
    assert_eq!(reason(b"\0\0\0\x1cftypavif"), "AVIF");
    assert_eq!(reason(b"\0\0\0\x1cftypheic"), "HEIC");
    assert!(reason(b"  <svg xmlns='x'>").contains("SVG"));
    assert!(reason(br#"{"v":"5.5.2","fr":60}"#).contains("Lottie"));
    assert_eq!(reason(b"hello"), "this kind of file");
    assert_eq!(
        Error::Unsupported("HEIC").to_string(),
        "HEIC is not supported"
    );
}

#[test]
fn a_damaged_picture_is_refused_at_every_length_and_never_panics() {
    let mut webp = Vec::new();
    image_webp::WebPEncoder::new(&mut webp)
        .encode(&[9; 64 * 4], 8, 8, image_webp::ColorType::Rgba8)
        .unwrap();
    let inputs = [
        apng(),
        gif_of(
            2,
            1,
            &[(0, 0, 2, 1, vec![0, 1], gif::DisposalMethod::Keep, 5)],
        ),
        webp,
        include_bytes!("../tests/fixtures/red-blue.jpg").to_vec(),
        include_bytes!("../tests/fixtures/anim3.webp").to_vec(),
    ];
    for input in &inputs {
        for cut in (0..input.len()).step_by((input.len() / 97).max(1)) {
            let _ = sanitize(&input[..cut], Profile::Emote);
        }
        let mut flipped = input.clone();
        for i in (20..flipped.len()).step_by(13) {
            flipped[i] ^= 0x5A;
            let _ = sanitize(&flipped, Profile::Sticker);
        }
    }
}

#[test]
fn an_animation_over_its_cap_loses_frames_then_its_movement() {
    // 40 frames of noise nothing compresses
    let mut seed = 1u32;
    let mut noise = || {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        (seed >> 16) as u8
    };
    let mut out = Vec::new();
    {
        let mut e = png::Encoder::new(&mut out, 64, 64);
        e.set_color(png::ColorType::Rgba);
        e.set_animated(40, 0).unwrap();
        let mut wr = e.write_header().unwrap();
        for _ in 0..40 {
            let f: Vec<u8> = (0..64 * 64 * 4).map(|_| noise()).collect();
            wr.write_image_data(&f).unwrap();
        }
        wr.finish().unwrap();
    }
    let all = sanitize_capped(&out, Profile::Emote, usize::MAX, Motion::default()).unwrap();
    assert_eq!((all.frames, all.trimmed), (40, false));
    let fewer =
        sanitize_capped(&out, Profile::Emote, all.png.len() / 3, Motion::default()).unwrap();
    assert!(
        fewer.trimmed && fewer.frames < 40 && fewer.frames > 1,
        "{}",
        fewer.frames
    );
    let still = sanitize_capped(&out, Profile::Emote, 64 * 64 * 5, Motion::default()).unwrap();
    assert_eq!((still.frames, still.trimmed), (1, true));
    assert!(matches!(
        sanitize_capped(&out, Profile::Emote, 100, Motion::default()),
        Err(Error::TooLarge(_))
    ));
}

/// The time an APNG takes to play once, from its frames' own delays.
fn total_ms(apng: &[u8]) -> u32 {
    let mut d = png::Decoder::new(std::io::Cursor::new(apng))
        .read_info()
        .unwrap();
    let mut buf = vec![0; d.output_buffer_size().unwrap()];
    let mut ms = 0;
    while d.next_frame(&mut buf).is_ok() {
        if let Some(fc) = d.info().frame_control() {
            ms += u32::from(fc.delay_num) * 1000 / u32::from(fc.delay_den.max(1));
        }
    }
    ms
}

#[test]
fn a_moving_chat_picture_is_kept_as_its_server_says() {
    // Ten different frames on a 1600 × 1600 screen, a tenth of a second each
    let frames: Vec<_> = (0..10u16)
        .map(|i| {
            let at = i * 100;
            (
                at,
                at,
                1,
                1,
                vec![(i % 2) as u8],
                gif::DisposalMethod::Keep,
                10,
            )
        })
        .collect();
    let g = gif_of(1600, 1600, &frames);
    let all = sanitize(&g, Profile::Photo).unwrap();
    assert_eq!(
        (all.w, all.h, all.frames, all.trimmed),
        (1024, 1024, 10, false)
    );
    // A tighter server: 16 MiB holds four frames of 1024 × 1024
    let tight = Motion {
        side: 1024,
        keep: 16 << 20,
    };
    let thin = sanitize_capped(&g, Profile::Photo, usize::MAX, tight).unwrap();
    assert!(
        thin.trimmed && (2..=4).contains(&thin.frames),
        "{}",
        thin.frames
    );
    assert_eq!(total_ms(&thin.png), total_ms(&all.png), "as long as before");
    assert_eq!(total_ms(&all.png), 1000);
    // One frame is a photo, in a photo's own box
    let still = sanitize(&gif_of(1600, 1600, &frames[..1]), Profile::Photo).unwrap();
    assert_eq!((still.w, still.frames), (1600, 1));
}

/// A zip of `(path, bytes, deflate, declared size)`, the way any archiver
/// writes one.
fn zip_of(files: &[(&str, &[u8], bool, Option<u32>)]) -> Vec<u8> {
    let (mut out, mut dir) = (Vec::new(), Vec::new());
    for (path, bytes, deflate, declared) in files {
        let data = if *deflate {
            miniz_oxide::deflate::compress_to_vec(bytes, 6)
        } else {
            bytes.to_vec()
        };
        let size = declared.unwrap_or(bytes.len() as u32);
        let at = out.len() as u32;
        let method: u16 = if *deflate { 8 } else { 0 };
        let common = [
            &20u16.to_le_bytes()[..],
            &0u16.to_le_bytes(),
            &method.to_le_bytes(),
            &[0; 4],
            &[0; 4],
            &(data.len() as u32).to_le_bytes(),
            &size.to_le_bytes(),
            &(path.len() as u16).to_le_bytes(),
            &0u16.to_le_bytes(),
        ]
        .concat();
        out.extend(
            [
                &0x0403_4B50u32.to_le_bytes()[..],
                &common,
                path.as_bytes(),
                &data,
            ]
            .concat(),
        );
        dir.extend(
            [
                &0x0201_4B50u32.to_le_bytes()[..],
                &20u16.to_le_bytes(),
                &common,
                &[0; 10],
                &at.to_le_bytes(),
                path.as_bytes(),
            ]
            .concat(),
        );
    }
    let (n, at, len) = (files.len() as u16, out.len() as u32, dir.len() as u32);
    out.extend(dir);
    out.extend(
        [
            &0x0605_4B50u32.to_le_bytes()[..],
            &[0; 4],
            &n.to_le_bytes(),
            &n.to_le_bytes(),
            &len.to_le_bytes(),
            &at.to_le_bytes(),
            &[0, 0],
        ]
        .concat(),
    );
    out
}

#[test]
fn a_pack_gives_its_pictures_by_their_own_names_only() {
    let pic = png_of(
        1,
        1,
        png::ColorType::Rgb,
        png::BitDepth::Eight,
        &[1, 2, 3],
        None,
    );
    let z = zip_of(&[
        ("emotes/", b"", false, None),
        ("emotes/Pog Champ.png", &pic, true, None),
        ("../../../etc/evil.png", &pic, false, None),
        ("a\\b\\win.png", &pic, true, None),
        ("__MACOSX/emotes/._Pog Champ.png", b"junk", false, None),
        ("emotes/.DS_Store", b"junk", false, None),
    ]);
    let pack = read_pack(&z).unwrap();
    let names: Vec<_> = pack.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["Pog Champ.png", "evil.png", "win.png"]);
    assert!(pack.entries.iter().all(|e| e.bytes == pic));
    assert!(pack.title.is_none());
}

#[test]
fn a_whatsapp_pack_has_a_title_and_its_tray_icon_is_no_sticker() {
    let z = zip_of(&[
        (
            "title.txt",
            "Cats \u{202E}gnp.exe\n2nd line".as_bytes(),
            false,
            None,
        ),
        ("author.txt", b"me", false, None),
        ("tray.png", b"t", false, None),
        ("1.webp", b"s", true, None),
    ]);
    let pack = read_pack(&z).unwrap();
    assert_eq!(
        pack.title.as_deref(),
        Some("Cats gnp.exe"),
        "one line, no direction marks"
    );
    assert_eq!(
        pack.entries,
        [Entry {
            name: "1.webp".into(),
            bytes: b"s".to_vec()
        }]
    );
    // A sticker whose name starts with tray is still one
    let z = zip_of(&[
        ("title.txt", b"Cats", false, None),
        ("tray_happy.webp", b"s", false, None),
    ]);
    assert_eq!(read_pack(&z).unwrap().entries.len(), 1);
    // Without a title, a file called tray is just a picture
    assert_eq!(
        read_pack(&zip_of(&[("tray.png", b"t", false, None)]))
            .unwrap()
            .entries
            .len(),
        1
    );
}

#[test]
fn a_file_of_a_pack_that_lies_or_is_too_big_is_set_aside_and_the_rest_read() {
    let zeros = vec![0u8; 17 << 20];
    let pack = read_pack(&zip_of(&[
        ("big.png", &zeros, true, None),
        ("bomb.png", &zeros[..1 << 20], true, Some(1000)),
        ("short.png", b"abcdef", false, Some(3)),
        ("ok.png", b"fine", true, None),
    ]))
    .unwrap();
    assert_eq!(
        pack.skipped,
        [
            ("big.png".into(), "it is too big"),
            ("bomb.png".into(), "it unpacks to more than it says"),
            ("short.png".into(), "it is not the size it says"),
        ]
    );
    assert_eq!(
        pack.entries,
        [Entry {
            name: "ok.png".into(),
            bytes: b"fine".to_vec()
        }]
    );
    // What lying files claim counts: the pack as a whole stays bounded
    let lies: Vec<(String, &[u8], bool, Option<u32>)> = (0..14)
        .map(|i| (format!("{i}.png"), &zeros[..1024], true, Some(15 << 20)))
        .collect();
    let lies: Vec<(&str, &[u8], bool, Option<u32>)> = lies
        .iter()
        .map(|(n, b, d, s)| (n.as_str(), *b, *d, *s))
        .collect();
    assert_eq!(
        read_pack(&zip_of(&lies)).unwrap_err(),
        Error::TooLarge("the pack unpacks to too much")
    );
    let many: Vec<(String, &[u8], bool, Option<u32>)> = (0..pack::MAX_PACK_ENTRIES + 1)
        .map(|i| (format!("{i}.png"), &b"x"[..], false, None))
        .collect();
    let many: Vec<(&str, &[u8], bool, Option<u32>)> = many
        .iter()
        .map(|(n, b, d, s)| (n.as_str(), *b, *d, *s))
        .collect();
    assert!(matches!(read_pack(&zip_of(&many)), Err(Error::TooLarge(_))));
    let mut zip64 = zip_of(&[("a.png", b"x", false, None)]);
    let end = zip64.len() - 22;
    zip64[end + 10..end + 12].copy_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        read_pack(&zip64).unwrap_err(),
        Error::Unsupported("a split or zip64 archive")
    );
    assert!(read_pack(b"not a zip").is_err());
    let good = zip_of(&[
        ("a.png", b"hello", true, None),
        ("b.png", b"world", false, None),
    ]);
    for cut in 0..good.len() {
        let _ = read_pack(&good[..cut]);
    }
    // An encrypted entry is set aside, not read as plain bytes
    let mut locked = zip_of(&[("a.png", b"x", false, None)]);
    let dir = locked.len() - 22 - (46 + 5);
    locked[dir + 8] |= 1;
    let pack = read_pack(&locked).unwrap();
    assert!(pack.entries.is_empty());
    assert_eq!(pack.skipped, [("a.png".into(), "it is encrypted")]);
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `riff` (a WebP) with a chunk `kind` of `data` added, its size fixed.
fn with_chunk(riff: &[u8], kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = [riff, kind, &(data.len() as u32).to_le_bytes(), data].concat();
    if data.len() % 2 == 1 {
        out.push(0);
    }
    let size = (out.len() - 8) as u32;
    out[4..8].copy_from_slice(&size.to_le_bytes());
    out
}

#[test]
fn an_original_upload_loses_its_metadata_and_nothing_it_shows() {
    let secret = b"secret location";
    let png = png_of(
        2,
        1,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &[255, 0, 0, 255, 0, 0, 255, 128],
        None,
    );
    let gif = {
        let g = gif_of(
            2,
            1,
            &[
                (0, 0, 2, 1, vec![0, 1], gif::DisposalMethod::Keep, 10),
                (0, 0, 2, 1, vec![1, 0], gif::DisposalMethod::Keep, 10),
            ],
        );
        // A comment extension, just before the end
        let comment = [&[0x21, 0xFE, secret.len() as u8][..], secret, &[0]].concat();
        [&g[..g.len() - 1], &comment, &[0x3B]].concat()
    };
    let webp = {
        let w = with_chunk(
            include_bytes!("../tests/fixtures/anim3.webp"),
            b"EXIF",
            secret,
        );
        let mut w = with_chunk(&w, b"XMP ", secret);
        // Its VP8X says so, as a real one would
        w[20] |= 0x08 | 0x04;
        w
    };
    let jpeg = {
        let plain = include_bytes!("../tests/fixtures/red-blue.jpg");
        let comment = [
            &[0xFF, 0xFE][..],
            &((secret.len() + 2) as u16).to_be_bytes(),
            secret,
        ]
        .concat();
        let j = with_orientation(plain, 1);
        [&j[..2], &comment, &j[2..]].concat()
    };
    for (what, file, profile) in [
        ("png", png, Profile::Emote),
        ("gif", gif, Profile::Emote),
        ("webp", webp, Profile::Sticker),
        ("jpeg", jpeg, Profile::Photo),
    ] {
        assert!(holds(&file, secret), "{what}: the test file holds it");
        let bare = strip(&file).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(!holds(&bare, secret), "{what}: gone");
        assert!(bare.len() < file.len(), "{what}");
        assert_eq!(
            sanitize(&bare, profile).unwrap().png,
            sanitize(&file, profile).unwrap().png,
            "{what}: what it shows is the same"
        );
    }
    assert!(!holds(
        &strip(&with_orientation(
            include_bytes!("../tests/fixtures/red-blue.jpg"),
            1
        ))
        .unwrap(),
        b"Exif"
    ));
}

/// `png` with an `eXIf` chunk of `data` just after its IHDR.
fn with_exif_chunk(png: &[u8], data: &[u8]) -> Vec<u8> {
    let body = [b"eXIf".as_slice(), data].concat();
    let chunk = [
        &(data.len() as u32).to_be_bytes()[..],
        &body,
        &crc32(&body).to_be_bytes(),
    ]
    .concat();
    // The signature (8) and IHDR (4 + 4 + 13 + 4)
    [&png[..33], &chunk, &png[33..]].concat()
}

#[test]
fn a_turned_picture_or_a_broken_file_is_not_stripped() {
    let plain = include_bytes!("../tests/fixtures/red-blue.jpg");
    assert!(
        strip(&with_orientation(plain, 6)).is_err(),
        "its turn would be lost"
    );
    assert!(
        strip(&plain[..plain.len() - 2]).is_err(),
        "a JPEG with no end"
    );
    // PNG and WebP too: decode.rs turns them by their EXIF as it does a JPEG
    let wide = png_of(
        2,
        1,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &[255, 0, 0, 255, 0, 0, 255, 255],
        None,
    );
    let turned = with_exif_chunk(&wide, &exif_tiff(6));
    let shown = sanitize(&turned, Profile::Emote).unwrap();
    assert_eq!(
        (shown.w, shown.h),
        (1, 2),
        "the test file is turned when shown"
    );
    assert!(strip(&turned).is_err(), "a turned PNG");
    let upright = strip(&with_exif_chunk(&wide, &exif_tiff(1))).unwrap();
    assert!(!holds(&upright, b"eXIf"), "an upright one loses its EXIF");
    let webp = include_bytes!("../tests/fixtures/anim3.webp");
    assert!(
        strip(&with_chunk(webp, b"EXIF", &exif_tiff(6))).is_err(),
        "a turned WebP"
    );
    let png = png_of(
        1,
        1,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &[1, 2, 3, 4],
        None,
    );
    for cut in [9, 20, png.len() - 1] {
        assert!(strip(&png[..cut]).is_err(), "cut at {cut}");
    }
    let gif = gif_of(
        1,
        1,
        &[(0, 0, 1, 1, vec![0], gif::DisposalMethod::Keep, 10)],
    );
    for cut in 11..gif.len() {
        let _ = strip(&gif[..cut]);
    }
}

#[test]
fn a_jpeg_ends_at_its_end_and_loses_what_is_between_its_scans() {
    let secret = b"secret location";
    let plain = include_bytes!("../tests/fixtures/red-blue.jpg");
    let bare = strip(plain).unwrap();
    // A phone's second image after the end (MPF), then a trailer
    let trailed = [&plain[..], &plain[..], secret].concat();
    let cut = strip(&trailed).unwrap();
    assert_eq!(cut, bare, "nothing after FFD9");
    assert!(!holds(&cut, secret));
    // Progressive (jpegtran -progressive): ten scans, a comment between two
    let prog = include_bytes!("../tests/fixtures/red-blue-progressive.jpg");
    let second = prog
        .windows(2)
        .enumerate()
        .filter(|(_, w)| *w == [0xFF, 0xDA])
        .nth(1)
        .unwrap()
        .0;
    let comment = [
        &[0xFF, 0xFE][..],
        &((secret.len() + 2) as u16).to_be_bytes(),
        secret,
    ]
    .concat();
    let file = [&prog[..second], &comment, &prog[second..], secret].concat();
    let bare = strip(&file).unwrap();
    assert!(!holds(&bare, secret), "between the scans and after the end");
    assert_eq!(bare.last(), Some(&0xD9));
    assert_eq!(
        sanitize(&bare, Profile::Photo).unwrap().png,
        sanitize(prog, Profile::Photo).unwrap().png,
        "what it shows is the same"
    );
}

#[test]
fn a_header_tells_a_pictures_size_and_nothing_is_decoded() {
    let png = png_of(
        3,
        2,
        png::ColorType::Rgba,
        png::BitDepth::Eight,
        &[0; 24],
        None,
    );
    assert_eq!(probe(&png), Some((3, 2)));
    assert_eq!(
        probe(&gif_frames_past_screen(4096, 4096, 1)),
        Some((1, 1)),
        "a GIF's screen"
    );
    assert!(probe(include_bytes!("../tests/fixtures/anim3.webp")).is_some());
    assert!(probe(include_bytes!("../tests/fixtures/red-blue.jpg")).is_some());
    assert_eq!(probe(b"not a picture"), None);
    assert_eq!(probe(&png[..20]), None, "cut short");
}

/// Every hard picture there is, done in time: what a budget missed would show
/// here as a picture that takes long (the GIF whose frames are bigger than its
/// screen took seconds per viewer in 1.4). Timed in a release build only,
/// in test.yml; a debug build is too slow to say anything. shortcut: a
/// generous bound, since CI machines vary; tighten it if a regression hides
/// under it.
#[test]
#[cfg_attr(debug_assertions, ignore = "timed in a release build (test.yml)")]
fn every_hard_picture_is_done_in_time() {
    use std::time::{Duration, Instant};
    // 300 frames of 16 Mpx each on a 1×1 screen: one frame's block, again and again
    let many_big_frames = {
        let one = {
            let mut out = Vec::new();
            let mut e = gif::Encoder::new(&mut out, 1, 1, &[0, 0, 0, 255, 255, 255]).unwrap();
            e.write_frame(&gif::Frame {
                width: 4096,
                height: 4096,
                buffer: Cow::Owned(vec![0; 4096 * 4096]),
                ..gif::Frame::default()
            })
            .unwrap();
            drop(e);
            out
        };
        let head = 13 + 6;
        let block = &one[head..one.len() - 1];
        [&one[..head], &block.repeat(300), &[0x3B]].concat()
    };
    let big_still = png_of(
        7000,
        7000,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &vec![0; 7000 * 7000],
        None,
    );
    let mut hard = vec![
        ("gif frames past the screen", many_big_frames),
        ("a 49 Mpx PNG", big_still),
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions/media");
    for file in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        hard.push(("a fuzz regression", std::fs::read(file.path()).unwrap()));
    }
    for (what, bytes) in &hard {
        for p in [Profile::Emote, Profile::Sticker, Profile::Photo] {
            let start = Instant::now();
            let _ = sanitize(bytes, p);
            let took = start.elapsed();
            assert!(
                took < Duration::from_secs(5),
                "{what} as {p:?} took {took:?}"
            );
        }
    }
}
