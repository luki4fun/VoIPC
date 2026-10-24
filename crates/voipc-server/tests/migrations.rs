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
