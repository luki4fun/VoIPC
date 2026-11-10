//! For this crate's tests only: the stand-in Discord's files, loaded from where they are
//! kept. The one place here that touches a disk, which is why it is a test module.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use voipc_protocol::types::{ImportFacts, Registration};

use crate::api::{Api, RateGate};
use crate::batch;
use crate::mock::Mock;
use crate::model::{self, Member, Message};
use crate::plan::{self, Here};
use crate::rewrite::{self, Names};
use serde_json::Value;
use voipc_protocol::messages::AdminOp;
use voipc_protocol::types::{ImportMessage, ImportOptions};

pub const GUILD: u64 = 1_190_000_000_000_000_001;
pub const MODERATORS: u64 = 1_190_000_000_000_000_102;
pub const TALK: u64 = 1_190_000_000_000_000_200;
pub const HELP_CATEGORY: u64 = 1_190_000_000_000_000_202;
pub const GENERAL: u64 = 1_190_000_000_000_000_210;
pub const LOUNGE: u64 = 1_190_000_000_000_000_211;
pub const STAFF: u64 = 1_190_000_000_000_000_212;
pub const VAULT: u64 = 1_190_000_000_000_000_213;
pub const NEWS: u64 = 1_190_000_000_000_000_215;
pub const AFTER_DARK: u64 = 1_190_000_000_000_000_217;
pub const LOUNGE_THREAD: u64 = 1_200_000_000_000_005_005;
pub const PRIVATE_THREAD_ID: u64 = 1_190_000_000_000_000_302;
pub const EVA: u64 = 1_190_000_000_000_001_002;
/// In `v2/`, from the year 2040, so after any run a test or a lane makes.
pub const NEW_ROOM: u64 = 3_310_000_000_000_000_210;
pub const NEW_PRIVATE: u64 = 3_310_000_000_000_000_211;
/// After all of the first fixture's ids, and before all of `v2/`'s new ones.
pub const NOW_MS: i64 = 1_793_000_000_000;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testkit/6-mock-discord")
}

fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    let listing = fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "{}: {e}. It has to be in the repository: /testkit is in .gitignore, so it needs \
             an exception there",
            dir.display()
        )
    });
    for entry in listing {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(root, &path, files);
        } else if path.extension().is_some_and(|e| e == "json") {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(name, fs::read(&path).unwrap());
        }
    }
}

pub fn files() -> BTreeMap<String, Vec<u8>> {
    let root = dir();
    let mut files = BTreeMap::new();
    walk(&root, &root, &mut files);
    files
}

pub fn mock() -> Mock {
    Mock::new(files())
}

/// A plain relay on SQLite, with nothing imported yet.
pub fn here() -> Here {
    Here {
        facts: ImportFacts {
            backup_here: true,
            db_bytes: Some(1_048_576),
            max_users: 0,
            online: 1,
            registration: Registration::Invite,
            discord_sign_in: true,
            public_url: "https://voipc.example.net".into(),
            takes_guests: false,
            accounts: 0,
            channel_list_bytes: 200,
            channel_list_limit: 60 * 1024,
            categories: 0,
            max_categories: 200,
            emotes: 0,
            running: None,
            unfinished: None,
            cloud: true,
            last_options: None,
        },
        channels: vec![("General".into(), false)],
        emote_names: Vec::new(),
        cursors: HashMap::new(),
        last_started_ms: None,
    }
}

pub fn check_plan_json(plan: &str) {
    let path = dir().join("plan.json");
    if std::env::var_os("VOIPC_WRITE_PLAN").is_some() {
        fs::write(&path, plan).unwrap();
        return;
    }
    let on_disk = fs::read_to_string(&path).unwrap();
    assert!(
        on_disk == plan,
        "plan.json is not what the fixture gives: VOIPC_WRITE_PLAN=1 cargo test -p voipc-import \
         the_wizards_plan, and read the difference"
    );
}

/// What a module of this crate must not hold, spelled so that this file does not hold it.
fn disk_words() -> [String; 4] {
    [
        format!("std{}fs", "::"),
        format!("tokio{}fs", "::"),
        format!("{}File", "fs::"),
        format!("File{}", "::"),
    ]
}

fn touches_disk(source: &str) -> Option<String> {
    disk_words().into_iter().find(|word| source.contains(word))
}

#[test]
fn the_crate_touches_no_disk() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut read = 0;
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        // Read from the folder, so that a module added later cannot be forgotten here
        if path.file_name().is_some_and(|n| n == "fixture.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        assert_eq!(touches_disk(&source), None, "{}", path.display());
        read += 1;
    }
    assert!(read >= 10, "only {read} modules read");
    // The control: the check does find it
    assert!(touches_disk(&format!("use {};", disk_words()[0])).is_some());
    assert!(touches_disk(&fs::read_to_string(src.join("fixture.rs")).unwrap()).is_some());
}

#[test]
fn the_crate_can_reach_no_network_but_its_transport() {
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    for client in ["reqwest", "hyper", "ureq", "curl"] {
        assert!(!manifest.contains(client), "{client}");
    }
    assert!(manifest.contains("tokio = { version = \"1\", default-features = false"));
    for entry in fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().is_some_and(|n| n == "fixture.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        for word in ["TcpStream", "UdpSocket", "tokio::net", "std::net"] {
            assert!(!source.contains(word), "{word} in {}", path.display());
        }
    }
}

const DAN: u64 = 1_190_000_000_000_001_001;
const ZED: u64 = 1_190_000_000_000_001_099;
const DELETED_USER: u64 = 456_226_577_798_135_808;
const M: u64 = 1_200_000_000_000_000_000;
const FORUM_POST: u64 = M + 6001;

async fn messages_after(api: &Api<std::sync::Arc<Mock>>, channel: u64, after: u64) -> Vec<Message> {
    api.get(&format!(
        "/channels/{channel}/messages?limit=100&after={after}"
    ))
    .await
    .unwrap()
}

fn all_on() -> ImportOptions {
    let mut options = plan::default_options(&here());
    options.acknowledged = true;
    options
}

/// Who the fixture's rows go by, as a run would have it.
async fn names_of(api: &Api<std::sync::Arc<Mock>>, anonymise: bool) -> Names {
    let mut names = Names {
        anonymise,
        ..Names::default()
    };
    let members: Vec<Member> = api
        .get(&format!("/guilds/{GUILD}/members?limit=1000"))
        .await
        .unwrap();
    for member in &members {
        names.add_member(member);
    }
    names.channels.insert(GENERAL, "general".into());
    names.add_role(MODERATORS, "Moderators");
    names
}

async fn lounge(anonymise: bool) -> Vec<ImportMessage> {
    let api = Api::with_gate(std::sync::Arc::new(mock()), RateGate::new(7));
    let names = names_of(&api, anonymise).await;
    let page = messages_after(&api, LOUNGE, 0).await;
    let mut rows: Vec<ImportMessage> = page
        .iter()
        .filter_map(|m| rewrite::row_of(m, &names, &all_on()))
        .collect();
    rows.sort_by_key(|r| r.id);
    rows
}

fn row(rows: &[ImportMessage], n: u64) -> &ImportMessage {
    rows.iter().find(|r| r.id == M + n).unwrap()
}

#[tokio::test(start_paused = true)]
async fn the_walk_starts_at_0_so_a_forum_posts_first_message_comes() {
    let api = Api::with_gate(std::sync::Arc::new(mock()), RateGate::new(7));
    let from_zero = messages_after(&api, FORUM_POST, 0).await;
    assert!(from_zero.iter().any(|m| m.id == FORUM_POST));
    assert_eq!(from_zero.len(), 2);
    // The negative: starting at the thread's own id loses the post itself
    let from_thread = messages_after(&api, FORUM_POST, FORUM_POST).await;
    assert!(!from_thread.iter().any(|m| m.id == FORUM_POST));
    assert_eq!(from_thread.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn the_lounge_comes_out_as_each_of_its_traps_should() {
    let rows = lounge(true).await;
    // 19 messages, of which the join and the thread's birth give no row
    assert_eq!(rows.len(), 17);
    assert!(rows.iter().all(|r| r.id != M + 5003 && r.id != M + 5006));
    // A pin and reactions, Unicode and custom
    let first = row(&rows, 5001);
    assert!(first.pinned);
    assert_eq!(first.reactions.len(), 2);
    assert_eq!(first.reactions[1].emoji, ":pog:");
    assert_eq!(row(&rows, 5002).reply_to, Some(M + 5001));
    assert_eq!(row(&rows, 5002).body, "Thanks @Dan D!");
    assert_eq!(row(&rows, 5002).author_name, "Eva");
    assert!(row(&rows, 5004).body.contains("||the butler did it||"));
    assert!(row(&rows, 5004).body.len() > 2000);
    // An emote that did not come stays words, one that came is named, plain text stays
    assert_eq!(
        row(&rows, 5007).body,
        ":pog: and :party_blob: and :gone: :pog:"
    );
    // A webhook: its own name, no id
    let hook = row(&rows, 5008);
    assert_eq!(
        (hook.author, hook.author_name.as_str()),
        (None, "Deploy bot")
    );
    // An ex-member: no name and no id. A private channel goes unnamed, a public one is named
    let zed = row(&rows, 5009);
    assert_eq!(
        (zed.author, zed.author_name.as_str()),
        (None, rewrite::FORMER_MEMBER)
    );
    assert_eq!(
        zed.body,
        "I am off, bye. #unknown #general @&Moderators 2021-04-20T21:20:30Z"
    );
    let gone = row(&rows, 5010);
    assert_eq!(
        (gone.author, gone.author_name.as_str()),
        (None, rewrite::FORMER_MEMBER)
    );
    // A bot in the list keeps its name
    assert_eq!(row(&rows, 5011).author_name, "Helper");
    assert!(row(&rows, 5011).author.is_some());
    assert_eq!(row(&rows, 5012).author_name, "Frank");
    // A file's record, and its line
    let file = row(&rows, 5013);
    assert_eq!(file.body, "Here it is.\n[attachment: picture.png]");
    assert_eq!(file.attachments[0].name, "picture.png");
    assert_eq!(file.attachments[0].bytes, 2048);
    assert_eq!(row(&rows, 5014).body, "[sticker: wave]");
    assert_eq!(row(&rows, 5015).body, "[poll: Pizza or pasta?]");
    assert_eq!(row(&rows, 5016).body, "[forwarded]\nFrom @Former member");
    assert_eq!(row(&rows, 5017).body, "A page\nWhat it says.");
    // Code is left as it was, outside it is not
    assert!(row(&rows, 5018).body.contains(&format!("`<@{DAN}>`")));
    assert!(row(&rows, 5018).body.ends_with("and @Dan D"));
    assert_eq!(
        row(&rows, 5019).body,
        "@Former member left, and @Eva is here. #unknown"
    );

    // With anonymise off, the same rows say who it was
    let rows = lounge(false).await;
    let zed = row(&rows, 5009);
    assert_eq!((zed.author, zed.author_name.as_str()), (Some(ZED), "Zed Z"));
    let gone = row(&rows, 5010);
    assert_eq!(gone.author, Some(DELETED_USER));
    assert_eq!(
        row(&rows, 5019).body,
        "@Zed Z left, and @Eva is here. #unknown"
    );
}

#[tokio::test(start_paused = true)]
async fn someone_left_out_goes_from_the_fixtures_rows() {
    let api = Api::with_gate(std::sync::Arc::new(mock()), RateGate::new(7));
    let mut names = names_of(&api, true).await;
    names.add_excluded(&DAN.to_string(), false, true).unwrap();
    let page = messages_after(&api, LOUNGE, 0).await;
    let rows: Vec<ImportMessage> = page
        .iter()
        .filter_map(|m| rewrite::row_of(m, &names, &all_on()))
        .collect();
    // Their posts do not come, and a mention of them says nobody
    assert!(rows.iter().all(|r| r.author != Some(DAN)));
    assert!(rows.iter().any(|r| r.body == "Thanks @unknown!"));
    let members: Vec<Member> = api
        .get(&format!("/guilds/{GUILD}/members?limit=1000"))
        .await
        .unwrap();
    let sent: Vec<u64> = members
        .iter()
        .filter_map(|m| rewrite::member_row(m, &names))
        .map(|m| m.dc_id)
        .collect();
    // Dan left out, a pending member and two bots held back, and the rest sent
    assert_eq!(members.len(), 11);
    assert_eq!(sent.len(), 7);
    assert!(!sent.contains(&DAN));
    // The neighbour stays
    assert!(sent.contains(&EVA));
    // An id that is none is said to be none
    assert_eq!(names.add_excluded("x", false, true), None);
}

#[tokio::test(start_paused = true)]
async fn every_row_of_the_fixture_frames_and_holds_no_address() {
    let api = Api::with_gate(std::sync::Arc::new(mock()), RateGate::new(7));
    let names = names_of(&api, true).await;
    let files = files();
    let mut checked = 0;
    for (name, bytes) in &files {
        if !name.contains("messages-") {
            continue;
        }
        let page: Vec<Message> = model::parse(bytes).unwrap();
        assert!(!page.is_empty(), "{name}");
        // Discord's own URLs are in the fixture, so that this has something to not find
        let rows: Vec<ImportMessage> = page
            .iter()
            .filter_map(|m| rewrite::row_of(m, &names, &all_on()))
            .collect();
        for row in &rows {
            let wire = postcard::to_allocvec(row).unwrap();
            assert!(!wire.windows(4).any(|w| w == b"http"), "{name}: {}", row.id);
            checked += 1;
        }
        let high = page.iter().map(|m| m.id).max().unwrap();
        for op in batch::messages(1, 5, None, rows, high) {
            assert!(matches!(op, AdminOp::ImportMessages { .. }));
        }
    }
    assert!(checked > 30, "{checked} rows");
    let raw = String::from_utf8_lossy(&files[&format!("messages-{LOUNGE}-1.json")]).to_string();
    assert!(raw.contains("https://cdn.discordapp.com/attachments"));
}

#[test]
fn the_blank_page_reads_as_blank_and_the_lounge_does_not() {
    let files = files();
    let blank: Vec<Message> = model::parse(&files["blank-page.json"]).unwrap();
    assert_eq!(blank.len(), 100);
    assert!(rewrite::page_is_blank(&blank));
    let real: Vec<Message> = model::parse(&files[&format!("messages-{LOUNGE}-1.json")]).unwrap();
    assert!(!rewrite::page_is_blank(&real));
}

#[tokio::test(start_paused = true)]
async fn the_delta_sees_what_v2_adds_and_nothing_else_changes() {
    let mock = std::sync::Arc::new(mock());
    let api = Api::with_gate(mock.clone(), RateGate::new(7));
    let high = messages_after(&api, LOUNGE, 0).await[0].id;
    mock.use_v2();
    let new = messages_after(&api, LOUNGE, high).await;
    assert_eq!(new.len(), 8);
    let room = messages_after(&api, NEW_ROOM, 0).await;
    assert_eq!(room.len(), 2);
    // 10 new messages in all, and the first run's are still there under them
    assert_eq!(messages_after(&api, LOUNGE, 0).await.len(), 27);
    let read = plan::read(&api, GUILD).await.unwrap();
    assert!(read.channels.iter().any(|c| c.id == NEW_ROOM));
    assert!(read.channels.iter().any(|c| c.id == NEW_PRIVATE));
    assert!(read.roles.iter().any(|r| r.name == "New Role"));
    // Sent straight by `import_replay`, which no walk would reach
    let resend: Value = serde_json::from_slice(&files()["v2/resend.json"]).unwrap();
    assert_eq!(resend["channel"], LOUNGE.to_string());
    assert_eq!(resend["message"]["id"], (M + 5001).to_string());
}
