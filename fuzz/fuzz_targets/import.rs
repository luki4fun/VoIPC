//! Discord's JSON and a member's words, through the importer.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    voipc_import::fuzz::fuzz_import(data);
});
