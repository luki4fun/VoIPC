//! Files in chat: sealed on the sender's device, kept by the relay for a while
//! as a blob it cannot read, and opened on a reader's device only after a
//! click. Both clients use this one format; the browser reaches it through
//! voipc-web.
//!
//! The bytes:
//!
//! ```text
//! blob    = commit (32) ‖ chunk 0 ‖ chunk 1 ‖ … ‖ chunk n-1
//! commit  = HMAC-SHA256(key, "voipc-file/v1 commit")
//! chunk i = AES-256-GCM(key, nonce = 0u32 ‖ i as u64 BE,
//!                       aad = "voipc-file/v1" ‖ last, 64 KiB of the body) ‖ tag
//! last    = 1 on the final chunk, 0 on every other
//! blob id = SHA-256(blob)
//! ```
//!
//! - The body is the file, or its raw deflate where that is at most 90 % of it
//!   (`FileMeta::deflated`). Ciphertext does not compress, so this happens here,
//!   before the seal. An empty body is one empty chunk; a body that fills its
//!   last chunk exactly has no empty one after it.
//! - The key is fresh for every file and travels only inside the end-to-end
//!   message, so the nonces may count from zero. A forward or a re-seed sends
//!   the same blob again; nothing is ever sealed twice under one key.
//! - The commitment binds a blob to one key. GCM alone does not: a sender can
//!   build one ciphertext that opens under two keys, and show two readers two
//!   different files under one blob id.
//! - The last flag means a blob cut at a chunk boundary does not open, the
//!   index in the nonce means chunks moved do not open, and the framing means
//!   bytes added do not open.
//! - The relay checks every upload against the blob id, and a reader checks it
//!   again (`open`), so no relay, cache or re-seeding member can hand over
//!   another blob.

use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hmac;
use sha2::{Digest, Sha256};
use voipc_protocol::conv::{hex, unhex};

use crate::aead::random;

/// Largest file this format carries. `open` holds a sender's claimed size to
/// it, and the inflate to that size, so it is also the most a small blob can
/// make a reader write.
pub const MAX_FILE_PLAIN: u64 = 64 * 1024 * 1024;

/// Largest blob this format writes: `MAX_FILE_PLAIN` stored as it is.
pub const MAX_FILE_BLOB: u64 = sealed_len(MAX_FILE_PLAIN);

/// Bytes of body per chunk.
const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const COMMIT: usize = 32;
const COMMIT_LABEL: &[u8] = b"voipc-file/v1 commit";
const AAD_LABEL: &[u8; 13] = b"voipc-file/v1";
/// miniz's default level.
const LEVEL: u8 = 6;
/// A file bigger than four of these has its first one deflated before the
/// whole of it, and the rest only if that shrank.
const PROBE: usize = 256 * 1024;

/// What a file message carries about its blob, all of it end to end: the
/// relay sees the blob id and nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// The blob id: SHA-256 of the blob.
    pub hash: [u8; 32],
    pub key: [u8; 32],
    /// The file's own length, before any deflate: what a reader is shown,
    /// and where its inflate stops.
    pub size: u64,
    /// Whether the body is the file's raw deflate.
    pub deflated: bool,
}

impl FileMeta {
    /// A file message's claims as text carries them, bounded: the blob id and
    /// the key as the 64 lowercase hex digits `hash_hex` and `key_hex` write,
    /// and a size within `MAX_FILE_PLAIN`. The envelope, the desktop and the
    /// browser all take a file's meta in through here, so none of them reads
    /// it more loosely than the others.
    pub fn from_parts(
        hash: &str,
        key: &str,
        size: u64,
        deflated: bool,
    ) -> Result<FileMeta, FileError> {
        if size > MAX_FILE_PLAIN {
            return Err(FileError::TooLarge);
        }
        Ok(FileMeta {
            hash: unhex::<32>(hash).ok_or(FileError::Malformed)?,
            key: unhex::<32>(key).ok_or(FileError::Malformed)?,
            size,
            deflated,
        })
    }

    /// The blob id as the relay's routes and the caches name it.
    pub fn hash_hex(&self) -> String {
        hex(&self.hash)
    }

    pub fn key_hex(&self) -> String {
        hex(&self.key)
    }
}

impl std::fmt::Debug for FileMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileMeta")
            .field("hash", &self.hash_hex())
            .field("size", &self.size)
            .field("deflated", &self.deflated)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileError {
    /// Bigger than `MAX_FILE_PLAIN`.
    TooLarge,
    /// The bytes are not the blob the message names.
    NotThisFile,
    /// The blob is not sealed under this key.
    WrongKey,
    /// Does not decrypt: altered, cut short, or chunks moved.
    Sealed,
    /// Lengths or meta no sender writes, or a deflate stream that is not the
    /// file the message describes.
    Malformed,
}

impl FileError {
    /// A name for the error that a client can act on without reading the
    /// text: `NotThisFile` means the bytes in hand are the wrong ones (fetch
    /// again); every other means the sender's file itself will never open.
    pub fn name(&self) -> &'static str {
        match self {
            FileError::TooLarge => "TooLarge",
            FileError::NotThisFile => "NotThisFile",
            FileError::WrongKey => "WrongKey",
            FileError::Sealed => "Sealed",
            FileError::Malformed => "Malformed",
        }
    }
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FileError::TooLarge => "the file is larger than 64 MiB",
            FileError::NotThisFile => "the file's bytes are not the ones its message names",
            FileError::WrongKey => "the file is not sealed under its message's key",
            FileError::Sealed => "the file does not decrypt",
            FileError::Malformed => "the file is malformed",
        })
    }
}

impl std::error::Error for FileError {}

/// How long the blob of a `body`-byte body is: the commitment, the body, and
/// a tag per chunk. The relay caps blobs, not files, so this is what a cap is
/// checked against before anything is read or sealed.
pub const fn sealed_len(body: u64) -> u64 {
    let chunks = if body == 0 {
        1
    } else {
        body.div_ceil(CHUNK as u64)
    };
    COMMIT as u64 + body + chunks * TAG as u64
}

/// The blob id of `blob`.
pub fn blob_hash(blob: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(&Sha256::digest(blob));
    h
}

/// `plain` sealed under a fresh key: what its message carries, and the blob
/// for the relay. With `compress`, the body is deflated first where that
/// saves a tenth or more.
pub fn seal(plain: &[u8], compress: bool) -> Result<(FileMeta, Vec<u8>), FileError> {
    seal_with(random::<32>(), plain, compress)
}

pub(crate) fn seal_with(
    key: [u8; 32],
    plain: &[u8],
    compress: bool,
) -> Result<(FileMeta, Vec<u8>), FileError> {
    if plain.len() as u64 > MAX_FILE_PLAIN {
        return Err(FileError::TooLarge);
    }
    let deflated = if compress { deflate(plain) } else { None };
    let blob = seal_body(&key, deflated.as_deref().unwrap_or(plain));
    let meta = FileMeta {
        hash: blob_hash(&blob),
        key,
        size: plain.len() as u64,
        deflated: deflated.is_some(),
    };
    Ok((meta, blob))
}

pub(crate) fn seal_body(key: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let aead = aead_key(key);
    let pieces: Vec<&[u8]> = if body.is_empty() {
        vec![body]
    } else {
        body.chunks(CHUNK).collect()
    };
    let mut blob = Vec::with_capacity(COMMIT + body.len() + pieces.len() * TAG);
    blob.extend_from_slice(&commitment(key));
    for (i, piece) in pieces.iter().enumerate() {
        let start = blob.len();
        blob.extend_from_slice(piece);
        let tag = aead
            .seal_in_place_separate_tag(
                nonce(i),
                Aad::from(aad(i + 1 == pieces.len())),
                &mut blob[start..],
            )
            .expect("seal");
        blob.extend_from_slice(tag.as_ref());
    }
    blob
}

/// The file back out of `blob`.
///
/// The lengths are checked against `meta` before anything is hashed or
/// decrypted, and the inflate stops one byte past the size the sender
/// claimed, which is itself at most `MAX_FILE_PLAIN`: a small blob cannot
/// make a reader write gigabytes.
pub fn open(meta: &FileMeta, blob: &[u8]) -> Result<Vec<u8>, FileError> {
    if meta.size > MAX_FILE_PLAIN {
        return Err(FileError::TooLarge);
    }
    let size = meta.size as usize;
    let (commit, sealed) = blob.split_at_checked(COMMIT).ok_or(FileError::Malformed)?;
    let chunks = chunks_in(sealed.len()).ok_or(FileError::Malformed)?;
    let body_len = sealed.len() - chunks * TAG;
    // As it is, the body is the file; deflated, it is never the longer.
    let fits = if meta.deflated {
        body_len <= size
    } else {
        body_len == size
    };
    if !fits {
        return Err(FileError::Malformed);
    }
    if blob_hash(blob) != meta.hash {
        return Err(FileError::NotThisFile);
    }
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, &meta.key),
        COMMIT_LABEL,
        commit,
    )
    .map_err(|_| FileError::WrongKey)?;

    let aead = aead_key(&meta.key);
    let mut body = Vec::with_capacity(body_len);
    let mut piece = Vec::with_capacity(CHUNK + TAG);
    for (i, sealed_piece) in sealed.chunks(CHUNK + TAG).enumerate() {
        piece.clear();
        piece.extend_from_slice(sealed_piece);
        let plain = aead
            .open_in_place(nonce(i), Aad::from(aad(i + 1 == chunks)), &mut piece)
            .map_err(|_| FileError::Sealed)?;
        body.extend_from_slice(plain);
    }
    if meta.deflated {
        inflate(&body, size)
    } else {
        Ok(body)
    }
}

/// How many chunks the bytes after the commitment hold, or `None` for a
/// length no seal writes: every chunk but the last is full, and the last
/// carries at least one byte unless it is the only one.
fn chunks_in(sealed: usize) -> Option<usize> {
    if sealed < TAG {
        return None;
    }
    let n = sealed.div_ceil(CHUNK + TAG);
    let last = sealed - (n - 1) * (CHUNK + TAG);
    (last > TAG || n == 1).then_some(n)
}

pub(crate) fn commitment(key: &[u8; 32]) -> [u8; COMMIT] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), COMMIT_LABEL);
    tag.as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
}

fn aead_key(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("32-byte key"))
}

fn nonce(index: usize) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&(index as u64).to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

fn aad(last: bool) -> [u8; 14] {
    let mut a = [0u8; 14];
    a[..13].copy_from_slice(AAD_LABEL);
    a[13] = last as u8;
    a
}

// ── Deflate ───────────────────────────────────────────────────────────────

/// Whether a deflate of `deflated` bytes is worth a reader's inflate of
/// `plain` bytes: at most 90 % of them.
fn worth_it(deflated: usize, plain: usize) -> bool {
    deflated as u64 * 10 <= plain as u64 * 9
}

/// The raw deflate of `plain`, where that is worth it.
///
/// A format that is compressed already is not tried, and nor is a large file
/// whose first `PROBE` bytes do not shrink: a big archive without a signature
/// known here costs one small deflate, not a whole one, before it goes as it
/// is.
fn deflate(plain: &[u8]) -> Option<Vec<u8>> {
    use miniz_oxide::deflate::compress_to_vec;
    if compressed_already(plain) {
        return None;
    }
    if plain.len() > 4 * PROBE {
        let head = &plain[..PROBE];
        if !worth_it(compress_to_vec(head, LEVEL).len(), head.len()) {
            return None;
        }
    }
    let z = compress_to_vec(plain, LEVEL);
    worth_it(z.len(), plain.len()).then_some(z)
}

/// Whether `b` starts like a format that is compressed already, where deflate
/// would spend time to save nothing: archives and office documents (ZIP
/// inside), images, audio, video, PDF.
fn compressed_already(b: &[u8]) -> bool {
    const SIGNATURES: &[&[u8]] = &[
        b"PK\x03\x04", // zip: docx/xlsx/pptx, odt, jar, apk, epub
        b"PK\x05\x06", // an empty zip
        b"PK\x07\x08", // a spanned zip
        b"\x1f\x8b",   // gzip
        b"BZh",
        b"\xfd7zXZ\x00",
        b"\x28\xb5\x2f\xfd", // zstd
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"%PDF-",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff", // jpeg
        b"GIF8",
        b"\x1a\x45\xdf\xa3", // matroska, webm
        b"OggS",             // vorbis, opus
        b"fLaC",
        b"ID3", // mp3 with a tag
        // mp3 frames without one; not every 0xFFEx, which takes in UTF-16 text's FF FE
        b"\xff\xfb",
        b"\xff\xfa",
        b"\xff\xf3",
        b"\xff\xf2",
    ];
    SIGNATURES.iter().any(|s| b.starts_with(s))
        // RIFF: WebP and AVI (WAV is plain PCM, so it is tried)
        || (b.starts_with(b"RIFF") && matches!(b.get(8..12), Some(b"WEBP" | b"AVI ")))
        // ISO media: mp4, mov, m4a, 3gp, heic, avif
        || b.get(4..8) == Some(&b"ftyp"[..])
}

/// `body` inflated, if it is a raw deflate stream of exactly `size` bytes
/// with nothing after it.
pub(crate) fn inflate(body: &[u8], size: usize) -> Result<Vec<u8>, FileError> {
    let mut out = Vec::new();
    inflate_into(body, size, &mut out)?;
    Ok(out)
}

/// `inflate`, into `out`, which keeps whatever it reached.
///
/// The output grows as the stream asks, up to one byte past `size`, and by
/// exactly what it asks: a stream that would write more stops there, however
/// small it is, and a reader holds no more than the file.
fn inflate_into(body: &[u8], size: usize, out: &mut Vec<u8>) -> Result<(), FileError> {
    let cap = size + 1;
    let first = cap.min(body.len().saturating_mul(4).max(CHUNK));
    out.clear();
    // Exact: `resize` alone grows the allocation by doubling, so the last
    // step could take nearly twice `size`.
    out.reserve_exact(first);
    out.resize(first, 0);
    let mut state = Box::<DecompressorOxide>::default();
    let (mut read, mut written) = (0, 0);
    loop {
        let rest = body.get(read..).ok_or(FileError::Malformed)?;
        let (status, used, wrote) = decompress(
            &mut state,
            rest,
            out,
            written,
            inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        read += used;
        written += wrote;
        match status {
            TINFLStatus::Done => break,
            TINFLStatus::HasMoreOutput if out.len() < cap => {
                let grown = out.len().saturating_mul(2).min(cap);
                out.reserve_exact(grown - out.len());
                out.resize(grown, 0);
            }
            _ => return Err(FileError::Malformed),
        }
    }
    out.truncate(written);
    if written != size || read != body.len() {
        return Err(FileError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known answers from Node's crypto (OpenSSL) and zlib, not from this code:
    // createHmac("sha256", KEY), createCipheriv("aes-256-gcm", KEY, nonce)
    // with setAAD per chunk, zlib.deflateRawSync(…, { level: 9 }), and
    // createHash("sha256") over the blob. The key is 00 01 … 1f.
    const KEY: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = i as u8;
            i += 1;
        }
        k
    };
    const KNOWN_COMMIT: &str = "d04eabaa6957913d2b90a16ec81776eb577170a55639b7d8890e333987b53698";
    /// 70 000 bytes of `(i * 31 + 7) % 251`, as they are: two chunks.
    const KNOWN_TWO_CHUNKS: &str =
        "b0849f4194b546d61ddf6e963735d16b7eb8c9056165da314f91130d92f4e1ec";
    /// The first 65 536 of those: one full chunk and no empty one after it.
    const KNOWN_ONE_FULL: &str = "7612f42536594a6e0ccb38047d063bcd2428af712334829baefbafadc2d5e86a";
    const KNOWN_EMPTY: &str = "d04eabaa6957913d2b90a16ec81776eb577170a55639b7d8890e333987b53698\
                               2a504df50a189eca9185b5abb568aa7c";
    /// "voipc " 1000 times, deflated by zlib (level 9, raw).
    const ZLIB_BLOB: &str = "d04eabaa6957913d2b90a16ec81776eb577170a55639b7d8890e333987b53698\
                             e37814dfb52c87bdb8ff5513510866a2909e94e543b3b699ed4505ee1e493069\
                             70e9fc896b2ddf1fa40ca0b495b04f0a0c";
    const ZLIB_HASH: &str = "198b8f517a185db4c6f608a63d78ee307704a2a56b48b5ae9bb95f5710820035";

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
    }

    fn unhex_vec(h: &str) -> Vec<u8> {
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Bytes that do not compress (SHA-256 in counter mode), the same every run.
    fn noise(len: usize) -> Vec<u8> {
        (0u64..)
            .flat_map(|i| blob_hash(&i.to_be_bytes()))
            .take(len)
            .collect()
    }

    fn text(len: usize) -> Vec<u8> {
        b"2026-10-27 12:00:00 INFO relay: a user joined channel 3\n"
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    /// `blob` changed by `edit`, with a meta whose hash matches the change,
    /// so the check under test is the one past the hash.
    fn rehashed(
        meta: &FileMeta,
        blob: &[u8],
        edit: impl FnOnce(&mut Vec<u8>),
    ) -> (FileMeta, Vec<u8>) {
        let mut blob = blob.to_vec();
        edit(&mut blob);
        let meta = FileMeta {
            hash: blob_hash(&blob),
            ..meta.clone()
        };
        (meta, blob)
    }

    #[test]
    fn known_answers() {
        assert_eq!(hex(&commitment(&KEY)), KNOWN_COMMIT);

        let plain = pattern(70_000);
        let (meta, blob) = seal_with(KEY, &plain, false).unwrap();
        assert_eq!(blob.len(), 32 + 70_000 + 2 * 16);
        assert_eq!(hex(&meta.hash), KNOWN_TWO_CHUNKS);
        assert_eq!(open(&meta, &blob).unwrap(), plain);

        let (meta, blob) = seal_with(KEY, &plain[..CHUNK], false).unwrap();
        assert_eq!(blob.len(), 32 + CHUNK + 16);
        assert_eq!(hex(&meta.hash), KNOWN_ONE_FULL);

        let (meta, blob) = seal_with(KEY, b"", true).unwrap();
        assert_eq!(hex(&blob), KNOWN_EMPTY);
        assert!(!meta.deflated);
        assert_eq!(open(&meta, &blob).unwrap(), b"");
    }

    /// The reader's half against another deflate: what zlib wrote opens here.
    #[test]
    fn a_blob_deflated_by_zlib_opens() {
        let blob = unhex_vec(ZLIB_BLOB);
        let meta = FileMeta {
            hash: unhex::<32>(ZLIB_HASH).unwrap(),
            key: KEY,
            size: 6000,
            deflated: true,
        };
        assert_eq!(blob_hash(&blob), meta.hash);
        assert_eq!(open(&meta, &blob).unwrap(), b"voipc ".repeat(1000));
    }

    #[test]
    fn every_length_round_trips_and_has_the_length_it_should() {
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 17] {
            for plain in [noise(len), text(len)] {
                let (meta, blob) = seal(&plain, true).unwrap();
                assert_eq!(meta.size, len as u64);
                assert_eq!(meta.hash, blob_hash(&blob));
                if !meta.deflated {
                    let chunks = len.div_ceil(CHUNK).max(1);
                    assert_eq!(blob.len(), 32 + len + chunks * 16, "{len}");
                    assert_eq!(sealed_len(len as u64), blob.len() as u64, "{len}");
                }
                assert_eq!(open(&meta, &blob).unwrap(), plain, "{len}");
            }
        }
    }

    #[test]
    fn a_fresh_key_every_time() {
        let (a, blob_a) = seal(b"same file", false).unwrap();
        let (b, blob_b) = seal(b"same file", false).unwrap();
        assert_ne!(a.key, b.key);
        assert_ne!(blob_a, blob_b);
    }

    #[test]
    fn another_blob_is_not_this_file() {
        let (meta, blob) = seal(&text(5000), true).unwrap();
        let (_, other) = seal(&text(5000), true).unwrap();
        assert_eq!(open(&meta, &other), Err(FileError::NotThisFile));
        let mut flipped = blob.clone();
        flipped[40] ^= 1;
        assert_eq!(open(&meta, &flipped), Err(FileError::NotThisFile));
    }

    #[test]
    fn another_key_is_refused_by_the_commitment() {
        let (meta, blob) = seal(&pattern(1000), false).unwrap();
        let wrong = FileMeta {
            key: [9; 32],
            ..meta.clone()
        };
        assert_eq!(open(&wrong, &blob), Err(FileError::WrongKey));
        // The commitment altered.
        let (m, b) = rehashed(&meta, &blob, |b| b[0] ^= 1);
        assert_eq!(open(&m, &b), Err(FileError::WrongKey));
        // A commitment to the other key does not make the chunks open under it.
        let (m, b) = rehashed(&wrong, &blob, |b| {
            b[..32].copy_from_slice(&commitment(&[9; 32]))
        });
        assert_eq!(open(&m, &b), Err(FileError::Sealed));
    }

    #[test]
    fn any_altered_byte_is_refused() {
        let plain = pattern(2 * CHUNK + 100);
        let (meta, blob) = seal(&plain, false).unwrap();
        // The first chunk's body and tag, the second's, and the short last one.
        for at in [
            32,
            32 + CHUNK,
            32 + CHUNK + 15,
            32 + CHUNK + 16,
            blob.len() - 1,
        ] {
            let (m, b) = rehashed(&meta, &blob, |b| b[at] ^= 0x80);
            assert_eq!(open(&m, &b), Err(FileError::Sealed), "byte {at}");
        }
    }

    #[test]
    fn a_blob_cut_short_or_added_to_is_refused() {
        let plain = pattern(3 * CHUNK);
        let (meta, blob) = seal(&plain, false).unwrap();
        let piece = CHUNK + TAG;

        // Cut at a chunk boundary, with a size that matches what is left: the
        // chunk now last was not sealed as the last.
        let cut = FileMeta {
            size: 2 * CHUNK as u64,
            ..meta.clone()
        };
        let (m, b) = rehashed(&cut, &blob, |b| b.truncate(32 + 2 * piece));
        assert_eq!(open(&m, &b), Err(FileError::Sealed));

        // Cut inside a chunk.
        let (m, b) = rehashed(&meta, &blob, |b| b.truncate(b.len() - 1));
        assert_eq!(open(&m, &b), Err(FileError::Malformed));

        // Added to: a fourth chunk, and the size to match it.
        let longer = FileMeta {
            size: 3 * CHUNK as u64 + 1,
            ..meta.clone()
        };
        let (m, b) = rehashed(&longer, &blob, |b| b.extend_from_slice(&[0; TAG + 1]));
        assert_eq!(open(&m, &b), Err(FileError::Sealed));

        // An empty chunk after full ones: no seal writes it.
        let (m, b) = rehashed(&meta, &blob, |b| b.extend_from_slice(&[0; TAG]));
        assert_eq!(open(&m, &b), Err(FileError::Malformed));

        // Nothing past the commitment, or not even a whole commitment.
        for len in [0, 31, 32, 32 + TAG - 1] {
            let (m, b) = rehashed(&meta, &blob, |b| b.truncate(len));
            assert_eq!(open(&m, &b), Err(FileError::Malformed), "{len}");
        }
    }

    #[test]
    fn chunks_moved_are_refused() {
        let (meta, blob) = seal(&pattern(3 * CHUNK), false).unwrap();
        let piece = CHUNK + TAG;
        let (m, b) = rehashed(&meta, &blob, |b| {
            let (first, rest) = b[32..].split_at_mut(piece);
            first.swap_with_slice(&mut rest[..piece]);
        });
        assert_eq!(open(&m, &b), Err(FileError::Sealed));
    }

    #[test]
    fn the_size_a_message_claims_must_be_the_files() {
        let (meta, blob) = seal(&pattern(1000), false).unwrap();
        for size in [999, 1001, 0] {
            let m = FileMeta {
                size,
                ..meta.clone()
            };
            assert_eq!(open(&m, &blob), Err(FileError::Malformed), "{size}");
        }
        let huge = FileMeta {
            size: MAX_FILE_PLAIN + 1,
            ..meta.clone()
        };
        assert_eq!(open(&huge, &blob), Err(FileError::TooLarge));

        let (meta, blob) = seal(&text(10_000), true).unwrap();
        assert!(meta.deflated);
        for size in [9_999, 10_001] {
            let m = FileMeta {
                size,
                ..meta.clone()
            };
            assert_eq!(open(&m, &blob), Err(FileError::Malformed), "{size}");
        }
    }

    #[test]
    fn a_file_over_the_limit_is_not_sealed() {
        let plain = vec![0u8; MAX_FILE_PLAIN as usize + 1];
        assert_eq!(seal(&plain, false).err(), Some(FileError::TooLarge));
    }

    #[test]
    fn the_deflate_flag_must_be_the_truth() {
        let (meta, blob) = seal(&pattern(1000), false).unwrap();
        let m = FileMeta {
            deflated: true,
            ..meta
        };
        assert_eq!(open(&m, &blob), Err(FileError::Malformed));

        let (meta, blob) = seal(&text(10_000), true).unwrap();
        let m = FileMeta {
            deflated: false,
            ..meta
        };
        assert_eq!(open(&m, &blob), Err(FileError::Malformed));
    }

    /// A few kilobytes that inflate to megabytes stop one byte past the size
    /// their message claims, and hold no more than that while they run.
    #[test]
    fn a_deflate_bomb_stops_at_the_claimed_size() {
        // Not a power of two, so the last step of the growth is a clamped one.
        let zeros = vec![0u8; 3 * 1024 * 1024 + 12_345];
        let bomb = miniz_oxide::deflate::compress_to_vec(&zeros, 9);
        assert!(bomb.len() < 4096, "{}", bomb.len());

        let mut out = Vec::new();
        assert_eq!(inflate_into(&bomb, zeros.len(), &mut out), Ok(()));
        assert_eq!(out, zeros);
        assert!(out.capacity() <= zeros.len() + 1, "{}", out.capacity());

        for claimed in [4096, 1024 * 1024 + 7, zeros.len() - 1] {
            let mut out = Vec::new();
            assert_eq!(
                inflate_into(&bomb, claimed, &mut out),
                Err(FileError::Malformed)
            );
            assert!(out.len() <= claimed + 1, "{claimed}: wrote {}", out.len());
            assert!(
                out.capacity() <= claimed + 1,
                "{claimed}: held {}",
                out.capacity()
            );
        }

        // Through `open`, with a claim the body fits, so it is the inflate
        // that refuses.
        let blob = seal_body(&KEY, &bomb);
        let meta = FileMeta {
            hash: blob_hash(&blob),
            key: KEY,
            size: 4096,
            deflated: true,
        };
        assert!(bomb.len() <= 4096);
        assert_eq!(open(&meta, &blob), Err(FileError::Malformed));
        let whole = FileMeta {
            size: zeros.len() as u64,
            ..meta
        };
        assert_eq!(open(&whole, &blob).unwrap(), zeros);
    }

    #[test]
    fn a_deflate_stream_must_be_the_whole_body() {
        let file = text(10_000);
        let mut body = miniz_oxide::deflate::compress_to_vec(&file, 6);
        assert_eq!(inflate(&body, file.len()).unwrap(), file);
        // Cut short.
        assert_eq!(
            inflate(&body[..body.len() - 1], file.len()),
            Err(FileError::Malformed)
        );
        // Something after it, sealed by the sender along with it.
        body.push(0);
        assert_eq!(inflate(&body, file.len()), Err(FileError::Malformed));
        // Not deflate at all.
        assert_eq!(inflate(&[0xff; 64], 64), Err(FileError::Malformed));
        assert_eq!(inflate(&[], 0), Err(FileError::Malformed));
    }

    #[test]
    fn what_gets_deflated() {
        assert!(worth_it(90, 100));
        assert!(!worth_it(91, 100));
        assert!(!worth_it(2, 0));

        // Text shrinks; noise does not; nothing does without `compress`.
        assert!(seal(&text(4096), true).unwrap().0.deflated);
        assert!(!seal(&noise(4096), true).unwrap().0.deflated);
        assert!(!seal(&text(4096), false).unwrap().0.deflated);
        assert!(!seal(b"", true).unwrap().0.deflated);
        assert!(!seal(b"hi", true).unwrap().0.deflated, "too small to gain");

        // A compressed format is not tried, however well the rest would shrink.
        let known: [&[u8]; 19] = [
            b"PK\x03\x04",
            b"\x1f\x8b\x08",
            b"BZh9",
            b"\xfd7zXZ\x00",
            b"\x28\xb5\x2f\xfd",
            b"7z\xbc\xaf\x27\x1c",
            b"Rar!\x1a\x07\x01",
            b"%PDF-1.7",
            b"\x89PNG\r\n\x1a\n",
            b"\xff\xd8\xff\xe0",
            b"GIF89a",
            b"\x1a\x45\xdf\xa3",
            b"OggS",
            b"fLaC",
            b"ID3\x04",
            b"\xff\xfb\x90",
            b"RIFF\0\0\0\0WEBP",
            b"RIFF\0\0\0\0AVI ",
            b"\0\0\0\x18ftypisom",
        ];
        for signature in known {
            let label = hex(signature);
            let head = [signature, &text(4096)].concat();
            let (meta, blob) = seal(&head, true).unwrap();
            assert!(!meta.deflated, "{label}");
            assert_eq!(open(&meta, &blob).unwrap(), head);
        }
        // UTF-16 text starts FF FE, near an mp3 frame; it is text, and shrinks.
        let utf16: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain(text(4096).into_iter().flat_map(|c| [c, 0]))
            .collect();
        assert!(seal(&utf16, true).unwrap().0.deflated);
        // WAV is plain PCM: tried.
        let mut wav = b"RIFF\0\0\0\0WAVE".to_vec();
        wav.extend_from_slice(&text(4096));
        assert!(seal(&wav, true).unwrap().0.deflated);
    }

    /// A large file goes as it is when its start does not shrink, and is
    /// deflated whole when it does.
    #[test]
    fn a_large_file_is_probed_first() {
        let len = 4 * PROBE + 1;
        let mut noisy_start = noise(PROBE);
        noisy_start.resize(len, 0);
        let (meta, blob) = seal(&noisy_start, true).unwrap();
        assert!(!meta.deflated, "the probe saw noise");
        assert_eq!(open(&meta, &blob).unwrap(), noisy_start);

        let mut quiet_start = vec![0u8; 2 * PROBE];
        quiet_start.extend_from_slice(&noise(len - 2 * PROBE));
        let (meta, blob) = seal(&quiet_start, true).unwrap();
        assert!(meta.deflated);
        assert_eq!(open(&meta, &blob).unwrap(), quiet_start);
    }

    #[test]
    fn chunk_counts() {
        let full = CHUNK + TAG;
        assert_eq!(chunks_in(TAG - 1), None);
        assert_eq!(chunks_in(TAG), Some(1), "the empty file");
        assert_eq!(chunks_in(TAG + 1), Some(1));
        assert_eq!(chunks_in(full), Some(1));
        assert_eq!(
            chunks_in(full + 1),
            None,
            "a last chunk too short for its tag"
        );
        assert_eq!(
            chunks_in(full + TAG),
            None,
            "an empty chunk after a full one"
        );
        assert_eq!(chunks_in(full + TAG + 1), Some(2));
        assert_eq!(chunks_in(2 * full), Some(2));
    }

    #[test]
    fn a_messages_meta_is_read_strictly() {
        let (meta, blob) = seal(&text(5000), true).unwrap();
        let (hash, key) = (meta.hash_hex(), meta.key_hex());
        let back = FileMeta::from_parts(&hash, &key, meta.size, meta.deflated).unwrap();
        assert_eq!(back, meta);
        assert_eq!(open(&back, &blob).unwrap(), text(5000));

        let parse = |h: &str, k: &str, size| FileMeta::from_parts(h, k, size, true).err();
        assert_eq!(
            parse(&hash, &key, MAX_FILE_PLAIN + 1),
            Some(FileError::TooLarge)
        );
        assert_eq!(parse(&hash, &key, MAX_FILE_PLAIN), None);
        for (h, k) in [
            (hash.to_uppercase(), key.clone()),
            (hash[2..].to_string(), key.clone()),
            (format!("{hash}00"), key.clone()),
            (hash.clone(), key[2..].to_string()),
            (hash.clone(), format!("+{}", &key[1..])),
        ] {
            assert_eq!(parse(&h, &k, 5000), Some(FileError::Malformed), "{h} {k}");
        }
    }

    #[test]
    fn sealed_lengths() {
        assert_eq!(sealed_len(0), 48);
        assert_eq!(sealed_len(1), 49);
        assert_eq!(sealed_len(CHUNK as u64), 32 + CHUNK as u64 + 16);
        assert_eq!(sealed_len(CHUNK as u64 + 1), 32 + CHUNK as u64 + 1 + 32);
        // An incompressible 10 MiB file is a little over a 10 MiB cap.
        assert_eq!(sealed_len(10 << 20), (10 << 20) + 32 + 160 * 16);
        assert_eq!(MAX_FILE_BLOB, MAX_FILE_PLAIN + 32 + 1024 * 16);
    }

    #[test]
    fn errors_have_names_a_client_can_match() {
        for (e, name) in [
            (FileError::TooLarge, "TooLarge"),
            (FileError::NotThisFile, "NotThisFile"),
            (FileError::WrongKey, "WrongKey"),
            (FileError::Sealed, "Sealed"),
            (FileError::Malformed, "Malformed"),
        ] {
            assert_eq!(e.name(), name);
        }
    }

    #[test]
    fn the_key_never_shows_in_debug() {
        let (meta, _) = seal(b"x", false).unwrap();
        let shown = format!("{meta:?}");
        assert!(shown.contains(&hex(&meta.hash)));
        assert!(!shown.contains(&hex(&meta.key)));
    }
}
