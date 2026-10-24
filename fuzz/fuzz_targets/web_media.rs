//! Media packets through the browser's wasm parsers and video reassembly.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_web::fuzz::fuzz_web_media(data);
});
