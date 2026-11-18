//! Opening posts under the epoch key (3f, §5.8). A post opens with `CK` of its epoch (else it
//! waits, at most 256 a group for 60 s, and the keys are fetched), its writer's blob (attached,
//! or asked with `EpochBlobWanted`), `IK_w` against the pin of the account it names or, for a
//! connection writer, the key that connection first signed with, the sender key installed,
//! and the post's prefix.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

use libsignal_protocol::{
    group_decrypt, process_sender_key_distribution_message, DeviceId, ProtocolAddress,
    SenderKeyDistributionMessage, SenderKeyMessage,
};
use voipc_protocol::gk;
use voipc_protocol::messages::{ClientMessage, ServerMessage};

use super::member::Member;
use super::{ready, GkCtx, GkOut, OpenedPost, Who};
use crate::group_key::timers::CHECK_WAIT_MS;
use crate::group_key::{dist, open_post, open_writer_blob, Epoch, Group, MemberId, Writer};
use crate::stores::SignalStores;

/// Posts a group holds while their keys come.
const QUEUE_MOST: usize = 256;
/// And for so long (ms).
const QUEUE_MS: u64 = 60_000;

/// The identity key each connection writer (`Conn(u)`) first signed a blob with, for this
/// connection.
#[derive(Default)]
pub(super) struct Tofu(HashMap<u32, [u8; 32]>);

/// One group's reading.
#[derive(Default)]
pub(super) struct Reading {
    queue: VecDeque<(u64, ServerMessage)>,
    /// `EpochBlobWanted` out: `(gen, epoch, writer, u)`, when (ms).
    asked: HashMap<([u8; 16], u32, MemberId, u32), u64>,
}

impl Reading {
    /// Whether posts wait for their keys or blobs.
    pub(super) fn waiting(&self) -> bool {
        !self.queue.is_empty()
    }
}

/// Why a post did not open yet.
enum Wait {
    Key,
    Blob,
}

/// `EpochPostIn`.
pub(super) fn post_in(
    m: &mut Member,
    who: &mut Who,
    st: &mut SignalStores,
    tofu: &mut Tofu,
    msg: &ServerMessage,
    c: &mut GkCtx,
    out: &mut GkOut,
) {
    match open(m, st, tofu, msg, c, out) {
        Ok(()) => {}
        Err(Some(Wait::Key)) => {
            queue(m, msg, c.now);
            m.fetch(who, c.now, out);
        }
        Err(Some(Wait::Blob)) => queue(m, msg, c.now),
        Err(None) => {}
    }
}

fn queue(m: &mut Member, msg: &ServerMessage, now: u64) {
    if m.reader.queue.len() >= QUEUE_MOST {
        m.reader.queue.pop_front();
    }
    m.reader.queue.push_back((now, msg.clone()));
}

/// What waits, once more: after a header, a blob.
pub(super) fn retry(
    m: &mut Member,
    _who: &mut Who,
    st: &mut SignalStores,
    tofu: &mut Tofu,
    c: &mut GkCtx,
    out: &mut GkOut,
) {
    for (at, msg) in std::mem::take(&mut m.reader.queue) {
        if let Err(Some(_)) = open(m, st, tofu, &msg, c, out) {
            m.reader.queue.push_back((at, msg));
        }
    }
}

/// `EpochBlob`: each blob installed, then what waited.
pub(super) fn blob_in(
    m: &mut Member,
    who: &mut Who,
    st: &mut SignalStores,
    tofu: &mut Tofu,
    msg: &ServerMessage,
    c: &mut GkCtx,
    out: &mut GkOut,
) {
    let ServerMessage::EpochBlob {
        gen,
        epoch,
        writer,
        blobs,
        ..
    } = msg
    else {
        return;
    };
    let w = Writer {
        m: writer.m.into(),
        u: writer.u,
    };
    let mut installed = false;
    for blob in blobs.iter().take(gk::BLOBS_MAX) {
        match install(m, st, tofu, gen, *epoch, &w, blob, c) {
            Ok(()) => installed = true,
            Err(why) => tracing::debug!(group = %m.t.group, ?why, "a writer blob was not taken"),
        }
    }
    // An answer that installed nothing (none kept, none that opens) is not asked again
    // before the ask ages out (`tick`, 10 s): the posts waiting on it would ask at once
    if installed {
        m.reader.asked.remove(&(*gen, *epoch, w.m, w.u));
    }
    retry(m, who, st, tofu, c, out);
}

/// What waited past 60 s goes; an ask unanswered for 10 s may go again.
pub(super) fn tick(m: &mut Member, now: u64) {
    while m
        .reader
        .queue
        .front()
        .is_some_and(|(at, _)| now >= at.saturating_add(QUEUE_MS))
    {
        m.reader.queue.pop_front();
    }
    m.reader
        .asked
        .retain(|_, at| now < at.saturating_add(CHECK_WAIT_MS));
}

/// The blob of writer `w` for `(gen, epoch)`: opened under `CK`, its `IK_w` checked, its
/// sender key installed.
#[allow(clippy::too_many_arguments)]
fn install(
    m: &Member,
    st: &mut SignalStores,
    tofu: &mut Tofu,
    gen: &[u8; 16],
    epoch: u32,
    w: &Writer,
    blob: &[u8],
    c: &mut GkCtx,
) -> anyhow::Result<()> {
    let key = m
        .key_of(gen, epoch)
        .ok_or_else(|| anyhow::anyhow!("no key"))?;
    let g = Group::new(m.t.kind, &m.t.group, *gen)?;
    let ep = Epoch {
        e: epoch,
        d_e: key.d_e,
    };
    let opened = open_writer_blob(&g, &ep, w, &key.ck, blob)?;
    let ik: [u8; 32] = opened.ik.public_key().public_key_bytes().try_into()?;
    match w.m {
        MemberId::Account(a) => match c.pins.pin(&a) {
            Some(pin) if pin != ik => anyhow::bail!("not the key pinned for its account"),
            Some(_) => {}
            None => c.pins.pin_new(a, ik, c.now),
        },
        MemberId::Conn(u) => {
            anyhow::ensure!(u == w.u, "a connection writer is its own connection");
            let first = *tofu.0.entry(u).or_insert(ik);
            anyhow::ensure!(first == ik, "not the key this connection first signed with");
        }
    }
    let skdm = SenderKeyDistributionMessage::try_from(&opened.skdm[..])?;
    let addr = address(w);
    ready(async {
        Ok(process_sender_key_distribution_message(&addr, &skdm, &mut st.sender_key).await?)
    })
}

fn address(w: &Writer) -> ProtocolAddress {
    ProtocolAddress::new(w.ctx(), DeviceId::new(1).expect("1 is a device id"))
}

/// One post: opened, waiting (`Some`), or refused for good (`None`).
fn open(
    m: &mut Member,
    st: &mut SignalStores,
    tofu: &mut Tofu,
    msg: &ServerMessage,
    c: &mut GkCtx,
    out: &mut GkOut,
) -> Result<(), Option<Wait>> {
    let ServerMessage::EpochPostIn {
        channel_id,
        gen,
        epoch,
        user_id,
        username,
        account,
        is_admin,
        is_moderator,
        writer,
        blob,
        ciphertext,
        timestamp,
        ..
    } = msg
    else {
        return Err(None);
    };
    // The group names no channel: a post the relay files under another channel than the
    // group's is not shown there (as envelope.rs closes it on every channel path)
    if *channel_id != m.t.channel_id {
        return Err(None);
    }
    let w = Writer {
        m: (*writer).into(),
        u: *user_id,
    };
    // A post names the account its blob is checked against, or none
    if let MemberId::Account(a) = w.m {
        if *account != Some(a) {
            return Err(None);
        }
    }
    let Some(key) = m.key_of(gen, *epoch) else {
        return Err(Some(Wait::Key));
    };
    let ep = Epoch {
        e: *epoch,
        d_e: key.d_e,
    };
    let Ok(g) = Group::new(m.t.kind, &m.t.group, *gen) else {
        return Err(None);
    };
    if let Some(blob) = blob {
        if let Err(why) = install(m, st, tofu, gen, *epoch, &w, blob, c) {
            tracing::debug!(group = %m.t.group, ?why, "a writer blob was not taken");
            return Err(None);
        }
    }
    let id = dist(&g, &ep);
    match SenderKeyMessage::try_from(&ciphertext[..]) {
        Ok(s) if s.distribution_id() == id => {}
        _ => return Err(None),
    }
    let addr = address(&w);
    let plain =
        match ready(async { Ok(group_decrypt(ciphertext, &mut st.sender_key, &addr).await?) }) {
            Ok(p) => p,
            Err(e) if crate::group::lacks_key(&e) => {
                if let Entry::Vacant(e) = m.reader.asked.entry((*gen, *epoch, w.m, w.u)) {
                    e.insert(c.now);
                    out.send.push(ClientMessage::EpochBlobWanted {
                        group: m.t.group.clone(),
                        gen: *gen,
                        epoch: *epoch,
                        writer: gk::GkWriter {
                            m: w.m.into(),
                            u: w.u,
                        },
                    });
                }
                return Err(Some(Wait::Blob));
            }
            Err(_) => return Err(None),
        };
    let Ok(body) = open_post(gen, &ep, &plain) else {
        return Err(None);
    };
    out.posts.push(OpenedPost {
        channel_id: *channel_id,
        group: m.t.group.clone(),
        user_id: *user_id,
        username: username.clone(),
        account: *account,
        is_admin: *is_admin,
        is_moderator: *is_moderator,
        envelope: body.to_vec(),
        timestamp: *timestamp,
    });
    Ok(())
}
