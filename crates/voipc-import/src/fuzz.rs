//! Fuzz target: what Discord and its members control, through the importer, on the
//! operator's machine for hours (W3-34). `fuzz/fuzz_targets/import.rs` calls
//! `fuzz_import` under cargo-fuzz; the test below replays `fuzz/regressions/import/*`
//! on stable, so an input that once crashed stays a test.

use crate::model::{Ban, Channel, Guild, Member, Message, Role};
use crate::rewrite::{self, Names};
use voipc_protocol::types::ImportOptions;

/// Discord's JSON, each shape the importer reads, and a message's words through the
/// rewrite: as text, as a row of each kind, and as a label.
pub fn fuzz_import(data: &[u8]) {
    let names = Names {
        anonymise: true,
        ..Names::default()
    };
    let on = ImportOptions {
        channels: true,
        roles: true,
        permissions: true,
        members: true,
        bans: true,
        emotes: true,
        messages: true,
        threads: true,
        pins: true,
        reactions: true,
        anonymise: true,
        acknowledged: true,
    };
    if let Ok(page) = serde_json::from_slice::<Vec<Message>>(data) {
        let _ = rewrite::page_is_blank(&page);
        for m in &page {
            let _ = rewrite::row_of(m, &names, &on);
        }
    }
    let _ = serde_json::from_slice::<Guild>(data);
    let _ = serde_json::from_slice::<Vec<Channel>>(data);
    if let Ok(members) = serde_json::from_slice::<Vec<Member>>(data) {
        for m in &members {
            let _ = rewrite::member_row(m, &names);
        }
    }
    if let Ok(bans) = serde_json::from_slice::<Vec<Ban>>(data) {
        for b in &bans {
            let _ = rewrite::ban_row(b, &names);
        }
    }
    if let Ok(roles) = serde_json::from_slice::<Vec<Role>>(data) {
        for r in &roles {
            let _ = rewrite::role_row(r, 1);
        }
    }
    let text = String::from_utf8_lossy(data);
    let _ = rewrite::rewrite(&text, &names, &[]);
    let _ = rewrite::label(&text, 100);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fuzz_target_replays_on_stable() {
        let page = br#"[{"id":"1200000000000005007","channel_id":"1","author":{"id":"5","username":"cal"},"content":"<:pog:7> <@5> <#1> @everyone","timestamp":"2024-02-01T10:00:00+00:00","type":0}]"#;
        for input in [
            &[][..],
            &[0xff; 64],
            &[0; 64],
            &page[..],
            b"<@&50> <t:1:R> ||x|| https://a.b",
        ] {
            fuzz_import(input);
        }
        // The saved regressions replay in `fixture`, the one module that reads the disk
    }
}
