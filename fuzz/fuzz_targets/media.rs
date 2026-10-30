//! Pictures and packs nobody here made: what an emote, a sticker or a chat
//! photo can be, through every decoder and the pack reader.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_media::fuzz::fuzz_media(data);
});
