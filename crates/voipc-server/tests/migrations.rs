//! A shipped migration is never edited: a database that already ran it would
//! not run the edit, and sqlx refuses a database whose applied migration no
//! longer matches its file. A change goes into a new migration instead.
//!
//! Each release adds the migrations it shipped here (a release-checklist line).

use sha2::{Digest, Sha256};

/// (file, SHA-256) of every migration a release shipped.
const SHIPPED: &[(&str, &str)] = &[
    // 0.12.0
    (
        "sqlite/0001_relay.sql",
        "b3aa695420b3ebddc1b04ab652ebb401aa303977d18444cf1186de4bbc6751d4",
    ),
    (
        "sqlite/0002_log.sql",
        "eec55d48a51f09085f7648328565758921173f7dc24d51ef71d37b6f09d3e796",
    ),
    (
        "sqlite/0003_members.sql",
        "7a53eb780aa18da8c44857d5a73217961128df63cd62f6e5b2f439744e3ef017",
    ),
    (
        "postgres/0001_relay.sql",
        "76177c67b1a5b9b769f6b944db680046fe7cd73b0546c947c49f124ec488ad44",
    ),
    (
        "postgres/0002_log.sql",
        "7bf3764e74168509b17ddd22ab6fb79b334f0590b4c0eea1df4ba82472e43799",
    ),
    (
        "postgres/0003_members.sql",
        "bcacbee63b6ee6d98288e2d9226d9aa467df63b064d2a0d3e0b1c65efa5123eb",
    ),
    // 1.0.0
    (
        "sqlite/0004_bans.sql",
        "b0040fbcb16aa360e24c726104ecec7ec8ea297ea6685afcc0b03ef1d796ae14",
    ),
    (
        "postgres/0004_bans.sql",
        "60ddf372ad42d9f40c2f7ea58f1294ad147c77db1a500873f08ad01b3908e473",
    ),
    // 1.7.0
    (
        "sqlite/0005_gates.sql",
        "94b7d20cbed162ccb6c1de186ca4a4feecc54d4bbb03373653ef45ad23a5b757",
    ),
    (
        "postgres/0005_gates.sql",
        "94b7d20cbed162ccb6c1de186ca4a4feecc54d4bbb03373653ef45ad23a5b757",
    ),
    // 1.9.0
    (
        "sqlite/0006_community.sql",
        "29e8ee4b9e7f029a632c08e93318854ffb78255807a01120257dd6d0b903ecd3",
    ),
    (
        "sqlite/0007_group_sections.sql",
        "7e5391a0b6929eb8f6251c4c0008702793d0e77dd18a8171dd80a7db2f58fdfc",
    ),
    (
        "postgres/0006_community.sql",
        "4e9424aaddbf094a19e6afdeb77d6d9566fcb1de525027e58a5df2a409feee28",
    ),
    (
        "postgres/0007_group_sections.sql",
        "bfd8bf320d9d9381bbb06ba0a794d683e6e4ebd0e618d56f200926c7f8584beb",
    ),
    // 1.10.0
    (
        "sqlite/0008_moderation.sql",
        "b3dc46cf813b6c8bde418443b51952e331a6185431cb634a814c9fcbc67d7130",
    ),
    (
        "postgres/0008_moderation.sql",
        "9d315baf10d2bee5b7b32adff2f8325497747509b5cc660f8e165432235880ec",
    ),
    (
        "sqlite/0009_move.sql",
        "c5f52636c862bf33e3c0508c04b0314e4a01df45246d8f98a01ce35060defd1f",
    ),
    (
        "postgres/0009_move.sql",
        "94de0cecb0c6dd1f502209f7688a0c27a047e487eb03d7b996a7067904397e0b",
    ),
    // 1.11.0 (0010 shipped in rc.2; rc.1 had none of it)
    (
        "sqlite/0010_kept.sql",
        "89377a0323a0bc2714aa683834f78bba29e053f09fac50731c8a56d7cccfb37e",
    ),
    (
        "postgres/0010_kept.sql",
        "d775561e5dea64d52ab7b4f4b2b19ff753c0da5e48c1b47d505ba01519630eb3",
    ),
];

#[test]
fn shipped_migrations_are_never_edited() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for (file, want) in SHIPPED {
        let got = Sha256::digest(std::fs::read(dir.join(file)).unwrap());
        let got: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            &got, want,
            "{file} changed after it shipped; add a new migration instead"
        );
    }
}
