//! Rows into frames. `encode_client_msg` refuses a frame past `MAX_MSG_SIZE`, which would
//! lose those rows. A frame seals before it passes `IMPORT_FRAME_BYTES` or its row cap. One
//! row always fits; two need not.

use serde::Serialize;
use voipc_protocol::codec::{encode_client_msg, MAX_MSG_SIZE};
use voipc_protocol::messages::{AccountRequest, AdminOp, ClientMessage};
use voipc_protocol::types::{
    ImportBan, ImportCategory, ImportChannel, ImportMember, ImportMessage, ImportRole,
    ImportThread, IMPORT_CHANNEL_ROWS, IMPORT_FRAME_BYTES, IMPORT_FRAME_ROWS, IMPORT_MESSAGE_ROWS,
};

/// A frame's own fields and the enums around them.
const HEAD_BYTES: usize = 64;

/// The frame as it will go, checked. A row cannot pass this: `row_of` clips every field to
/// what the relay takes, and the longest such row is well under the limit (`voipc-protocol`
/// tests that).
fn seal(op: AdminOp) -> AdminOp {
    let msg = ClientMessage::Account(AccountRequest::Admin { op, code: None });
    let len = encode_client_msg(&msg).map_or(usize::MAX, |b| b.len() - 4);
    assert!(len <= MAX_MSG_SIZE as usize, "a frame of {len} bytes");
    match msg {
        ClientMessage::Account(AccountRequest::Admin { op, .. }) => op,
        _ => unreachable!("built above"),
    }
}

fn split<T: Serialize>(rows: Vec<T>, max_rows: usize) -> Vec<Vec<T>> {
    let mut frames = Vec::new();
    let mut frame = Vec::new();
    let mut bytes = HEAD_BYTES;
    for row in rows {
        let len = postcard::to_allocvec(&row).map_or(IMPORT_FRAME_BYTES, |b| b.len());
        if !frame.is_empty() && (frame.len() >= max_rows || bytes + len > IMPORT_FRAME_BYTES) {
            frames.push(std::mem::take(&mut frame));
            bytes = HEAD_BYTES;
        }
        bytes += len;
        frame.push(row);
    }
    if !frame.is_empty() {
        frames.push(frame);
    }
    frames
}

pub fn categories(run: i64, rows: Vec<ImportCategory>) -> Vec<AdminOp> {
    split(rows, IMPORT_FRAME_ROWS)
        .into_iter()
        .map(|rows| seal(AdminOp::ImportCategories { run, rows }))
        .collect()
}

pub fn channels(run: i64, rows: Vec<ImportChannel>) -> Vec<AdminOp> {
    split(rows, IMPORT_CHANNEL_ROWS)
        .into_iter()
        .map(|rows| seal(AdminOp::ImportChannels { run, rows }))
        .collect()
}

pub fn threads(run: i64, rows: Vec<ImportThread>) -> Vec<AdminOp> {
    split(rows, IMPORT_FRAME_ROWS)
        .into_iter()
        .map(|rows| seal(AdminOp::ImportThreads { run, rows }))
        .collect()
}

pub fn roles(run: i64, rows: Vec<ImportRole>) -> Vec<AdminOp> {
    split(rows, IMPORT_FRAME_ROWS)
        .into_iter()
        .map(|roles| seal(AdminOp::ImportRoles { run, roles }))
        .collect()
}

pub fn members(run: i64, rows: Vec<ImportMember>) -> Vec<AdminOp> {
    split(rows, IMPORT_FRAME_ROWS)
        .into_iter()
        .map(|members| seal(AdminOp::ImportMembers { run, members }))
        .collect()
}

pub fn bans(run: i64, rows: Vec<ImportBan>) -> Vec<AdminOp> {
    split(rows, IMPORT_FRAME_ROWS)
        .into_iter()
        .map(|bans| seal(AdminOp::ImportBans { run, bans }))
        .collect()
}

/// One page of a channel or thread, in id order, however many frames that takes. A frame's
/// `high` is its own last id, not the page's, so a cut between frames resumes right after
/// what was stored. Only the last says the page is done, up to `page_high`, the newest id
/// it held of any kind: system messages give no row and still advance it, so a frame
/// with no rows is normal.
pub fn messages(
    run: i64,
    channel: u64,
    thread: Option<u64>,
    mut rows: Vec<ImportMessage>,
    page_high: u64,
) -> Vec<AdminOp> {
    rows.sort_by_key(|r| r.id);
    let mut frames = split(rows, IMPORT_MESSAGE_ROWS);
    if frames.is_empty() {
        frames.push(Vec::new());
    }
    let last = frames.len() - 1;
    frames
        .into_iter()
        .enumerate()
        .map(|(i, rows)| {
            let own = rows.last().map_or(0, |r| r.id);
            let high = if i == last { own.max(page_high) } else { own };
            seal(AdminOp::ImportMessages {
                run,
                channel,
                thread,
                high,
                rows,
            })
        })
        .collect()
}

/// A channel walked and found empty: `high` 1, so that `high` 0 only ever means it was never
/// walked, and a delta can tell the two apart.
pub fn walked_empty(run: i64, channel: u64, thread: Option<u64>) -> AdminOp {
    seal(AdminOp::ImportMessages {
        run,
        channel,
        thread,
        high: 1,
        rows: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::Mock;
    use crate::model::{self, Message};
    use crate::rewrite::{row_of, Names};
    use voipc_protocol::types::{
        ImportAttachment, ImportGate, ImportOptions, ImportReaction, IMPORT_BODY_BYTES,
    };

    fn encoded(op: &AdminOp) -> usize {
        encode_client_msg(&ClientMessage::Account(AccountRequest::Admin {
            op: op.clone(),
            code: None,
        }))
        .unwrap()
        .len()
    }

    /// As long as a row can be, once `row_of` has been at it.
    fn worst_row(id: u64) -> ImportMessage {
        ImportMessage {
            id,
            author: Some(u64::MAX),
            author_name: "\u{1F389}".repeat(64),
            body: "\u{1F389}".repeat(IMPORT_BODY_BYTES / 4),
            reply_to: Some(u64::MAX),
            pinned: true,
            reactions: (0..20)
                .map(|_| ImportReaction {
                    emoji: "\u{1F389}".repeat(8),
                    count: u32::MAX,
                })
                .collect(),
            attachments: (0..20)
                .map(|_| ImportAttachment {
                    id: u64::MAX,
                    name: "\u{1F389}".repeat(128),
                    bytes: u64::MAX,
                    mime: "m".repeat(64),
                })
                .collect(),
        }
    }

    fn plain_row(id: u64) -> ImportMessage {
        ImportMessage {
            id,
            author: Some(1),
            author_name: "dan".into(),
            body: "hello".into(),
            reply_to: None,
            pinned: false,
            reactions: vec![],
            attachments: vec![],
        }
    }

    fn message_frames(ops: &[AdminOp]) -> Vec<(u64, Vec<u64>)> {
        ops.iter()
            .map(|op| match op {
                AdminOp::ImportMessages { high, rows, .. } => {
                    (*high, rows.iter().map(|r| r.id).collect())
                }
                other => panic!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn every_frame_of_the_worst_page_frames() {
        let rows: Vec<ImportMessage> = (1..=100).rev().map(worst_row).collect();
        let ops = messages(1, 5, Some(6), rows, 100);
        // A page of the worst does not fit one frame
        assert!(ops.len() > 1);
        let mut seen = 0;
        let frames = message_frames(&ops);
        for (op, (high, ids)) in ops.iter().zip(&frames) {
            assert!(encoded(op) - 4 <= MAX_MSG_SIZE as usize);
            assert!(encoded(op) <= IMPORT_FRAME_BYTES + 4, "{}", encoded(op));
            // In id order, none lost, none twice
            for id in ids {
                seen += 1;
                assert_eq!(*id, seen);
            }
            // Each `high` its own last id, not the page's
            assert_eq!(high, ids.last().unwrap());
        }
        assert_eq!(seen, 100);
        // And not every row may share one: the worst row is too long for two
        assert!(frames.iter().all(|(_, ids)| ids.len() == 1), "{frames:?}");
        // The relay's own row cap holds too
        let rows: Vec<ImportMessage> = (1..=250).map(plain_row).collect();
        let ops = messages(1, 5, None, rows, 250);
        let frames = message_frames(&ops);
        assert!(frames
            .iter()
            .all(|(_, ids)| ids.len() <= IMPORT_MESSAGE_ROWS));
        assert_eq!(frames.iter().map(|(_, ids)| ids.len()).sum::<usize>(), 250);
    }

    #[test]
    fn a_typical_page_is_one_frame() {
        let rows: Vec<ImportMessage> = (1..=100).map(plain_row).collect();
        let frames = message_frames(&messages(1, 5, None, rows, 100));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 100);
    }

    #[test]
    fn a_page_of_system_messages_is_a_frame_with_no_rows() {
        let frames = message_frames(&messages(1, 5, None, vec![], 77));
        assert_eq!(frames, [(77, vec![])]);
        // Rows, then system messages newer than any of them: `high` covers those too
        let frames = message_frames(&messages(1, 5, None, vec![plain_row(10)], 77));
        assert_eq!(frames, [(77, vec![10])]);
        // Over more than one frame, only the last says so
        let rows = vec![worst_row(10), worst_row(20)];
        let frames = message_frames(&messages(1, 5, None, rows, 77));
        assert_eq!(frames, [(10, vec![10]), (77, vec![20])]);
    }

    #[test]
    fn walked_and_empty_is_not_never_walked() {
        let AdminOp::ImportMessages { high, rows, .. } = walked_empty(1, 5, None) else {
            panic!("the wrong op");
        };
        assert_eq!(high, 1);
        assert!(rows.is_empty());
    }

    #[test]
    fn every_kind_of_row_keeps_to_its_cap() {
        let worst_name = "\u{1F389}".repeat(100);
        let cats = categories(
            1,
            (0..500)
                .map(|i| ImportCategory {
                    dc_id: i,
                    name: worst_name.clone(),
                })
                .collect(),
        );
        assert!(cats.iter().all(|op| encoded(op) <= IMPORT_FRAME_BYTES + 4));
        let count: usize = cats
            .iter()
            .map(|op| match op {
                AdminOp::ImportCategories { rows, .. } => {
                    assert!(rows.len() <= IMPORT_FRAME_ROWS);
                    rows.len()
                }
                other => panic!("{other:?}"),
            })
            .sum();
        assert_eq!(count, 500);

        let chans = channels(
            1,
            (0..500)
                .map(|i| ImportChannel {
                    dc_id: i,
                    name: "n".repeat(64),
                    description: "t".repeat(256),
                    text: true,
                    category: Some(u64::MAX),
                    max_users: 10_000,
                    slow_mode_secs: 21_600,
                    nsfw: true,
                    announce: true,
                    screen_share: true,
                    see: ImportGate::Roles(vec![u64::MAX; 16]),
                    speak: ImportGate::Roles(vec![u64::MAX; 16]),
                })
                .collect(),
        );
        assert!(chans.iter().all(|op| encoded(op) <= IMPORT_FRAME_BYTES + 4));
        for op in &chans {
            let AdminOp::ImportChannels { rows, .. } = op else {
                panic!("{op:?}");
            };
            assert!(rows.len() <= IMPORT_CHANNEL_ROWS);
        }

        let ths = threads(
            1,
            (0..1000)
                .map(|i| ImportThread {
                    id: i,
                    parent: u64::MAX,
                    owner: Some(u64::MAX),
                    name: "\u{1F389}".repeat(100),
                    replies: u32::MAX,
                })
                .collect(),
        );
        assert!(ths.iter().all(|op| encoded(op) <= IMPORT_FRAME_BYTES + 4));

        let rols = roles(
            1,
            (0..250)
                .map(|i| ImportRole {
                    dc_id: i,
                    name: "\u{1F389}".repeat(100),
                    color: u32::MAX,
                    position: 250,
                    hoist: true,
                    permissions: u64::MAX,
                })
                .collect(),
        );
        assert!(rols.iter().all(|op| encoded(op) <= IMPORT_FRAME_BYTES + 4));
        assert!(rols.len() > 1);

        // A member with every role Discord allows, and the longest names
        let mems = members(
            1,
            (0..500)
                .map(|i| ImportMember {
                    dc_id: i,
                    username: "u".repeat(32),
                    shown_as: "\u{1F389}".repeat(64),
                    joined_at: i64::MAX,
                    roles: vec![u64::MAX; 250],
                })
                .collect(),
        );
        assert!(mems.iter().all(|op| encoded(op) <= IMPORT_FRAME_BYTES + 4));
        assert!(mems.len() > 1);

        let bs = bans(1, (0..1000).map(|i| ImportBan { dc_id: i }).collect());
        for op in &bs {
            let AdminOp::ImportBans { bans, .. } = op else {
                panic!("{op:?}");
            };
            assert!(bans.len() <= IMPORT_FRAME_ROWS);
        }
        assert_eq!(bs.len(), 5);
        // Nothing to send is no frame
        assert!(bans(1, vec![]).is_empty());
    }

    fn all_on() -> ImportOptions {
        ImportOptions {
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
            anonymise: false,
            acknowledged: true,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_cut_mid_page_resumes_after_what_was_stored() {
        const CHANNEL: u64 = 99;
        use crate::api::{Api, RateGate};
        let mock = std::sync::Arc::new(Mock::big(0, 0, 1, 1));
        // A page's worth with long bodies, so that it takes several frames
        mock.add_messages(CHANNEL, 100, 12 * 1024);
        let api = Api::with_gate(mock.clone(), RateGate::new(7));
        let names = Names::default();
        let path = |after: u64| format!("/channels/{CHANNEL}/messages?limit=100&after={after}");
        let row_ids = |page: &[Message]| -> Vec<u64> {
            let mut ids: Vec<u64> = page.iter().map(|m| m.id).collect();
            ids.sort_unstable();
            ids
        };

        let first: Vec<Message> = api.get(&path(0)).await.unwrap();
        let every_id = row_ids(&first);
        let page_high = *every_id.last().unwrap();
        let rows = first
            .iter()
            .filter_map(|m| row_of(m, &names, &all_on()))
            .collect();
        let frames = message_frames(&messages(1, CHANNEL, None, rows, page_high));
        assert!(frames.len() > 2, "{} frames", frames.len());

        // The relay stored the first two frames, and the connection went
        let stored: Vec<u64> = frames[..2]
            .iter()
            .flat_map(|(_, ids)| ids.clone())
            .collect();
        let cursor = frames[1].0;
        assert_eq!(cursor, *stored.last().unwrap());

        // Resuming from the cursor reads just what was not stored
        let second: Vec<Message> = api.get(&path(cursor)).await.unwrap();
        let again = row_ids(&second);
        assert!(again.iter().all(|id| !stored.contains(id)));
        let mut all = stored;
        all.extend(again);
        assert_eq!(all, every_id);

        // The control: had a frame claimed the page's own high, what it did not hold is lost
        let wrong: Vec<Message> = api.get(&path(page_high)).await.unwrap();
        assert!(wrong.is_empty());
    }

    #[test]
    fn the_longest_message_discord_can_send_makes_a_row_that_frames() {
        // Through `row_of`, so that the clips are the ones the app really runs
        let m: Message = model::parse(
            format!(
                r#"{{"id":"1","author":{{"id":"1","username":"{}"}},"content":"{}",
                    "attachments":[{}]}}"#,
                "\u{1F389}".repeat(40),
                "\u{1F389}".repeat(4000),
                (0..10)
                    .map(|i| format!(
                        r#"{{"id":"{i}","filename":"{}","content_type":"{}"}}"#,
                        "\u{1F389}".repeat(200),
                        "m".repeat(90)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
            .as_bytes(),
        )
        .unwrap();
        let row = row_of(&m, &Names::default(), &all_on()).unwrap();
        assert!(row.body.len() <= IMPORT_BODY_BYTES);
        let ops = messages(1, 5, None, vec![row], 1);
        assert_eq!(ops.len(), 1);
        assert!(encoded(&ops[0]) <= IMPORT_FRAME_BYTES + 4);
    }
}
