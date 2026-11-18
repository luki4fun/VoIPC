//! An edge's viewers (`pool::VIEW_PATH`). Each shows the ticket its core sent it, and from
//! the edge's `Ready` on gets its share as it would from the core: a stream per frame,
//! screen audio as datagrams, whole frames dropped when it falls behind. It sends nothing
//! more; it watches until it leaves, or until the edge ends it and says why.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::debug;
use voipc_protocol::pool::{
    decode_viewer_msg, encode_edge_view_msg, EdgeViewMsg, ViewerMsg, MAX_TICKET_BYTES,
};
use wtransport::{Connection, SendStream, VarInt};

use super::{Admitted, Edge, End, VIEWER_QUEUE};
use crate::web::{pump_media_out, pump_video_streams, read_frame, DatagramSink};
use crate::PreSlot;

/// How long a viewer has from its session to its whole `Hello`.
const HELLO_WAIT: Duration = Duration::from_secs(5);
/// The longest `Hello`: a ticket and a few bytes around it.
const MAX_HELLO: usize = MAX_TICKET_BYTES + 64;
/// How long the edge waits to say something to a viewer.
const SAY_WAIT: Duration = Duration::from_secs(2);
/// How long a session the edge ended waits for the viewer to close it, so the viewer has
/// read why first (as the core's sessions linger, `web::run_session`).
const LINGER: Duration = Duration::from_secs(5);

/// One viewer's session, from its accepted request on. `slot` is its pre-authentication
/// slot, which a good ticket moves to the main pool (`Edge::admit`) until it ends.
pub(super) async fn run(connection: Connection, edge: Arc<Edge>, peer: SocketAddr, slot: PreSlot) {
    // Addresses only at debug, as on the core: the default log keeps no record of who
    // watched from where
    debug!(%peer, "edge viewer connected");
    let mut buf = BytesMut::new();
    let hello = tokio::time::timeout(HELLO_WAIT, async {
        let (send, mut recv) = connection.accept_bi().await.ok()?;
        let frame = read_frame(&mut recv, &mut buf, MAX_HELLO).await.ok()?;
        Some((send, recv, frame))
    })
    .await;
    // The viewer's half of the stream stays open: it has nothing more to say
    let Ok(Some((mut send, _recv, frame))) = hello else {
        edge.limits.count("setup failed", "viewer hello");
        connection.close(VarInt::from_u32(0), b"");
        return;
    };
    let Ok(ViewerMsg::Hello { ticket }) = decode_viewer_msg(&frame) else {
        edge.limits.count("setup failed", "viewer hello");
        connection.close(VarInt::from_u32(0), b"");
        return;
    };
    let Admitted {
        share,
        viewer,
        media,
        mut end,
    } = match edge.admit(&ticket, peer.ip(), Instant::now()) {
        Ok(admitted) => admitted,
        Err(why) => {
            debug!(%peer, "edge viewer refused: {why}");
            say(&mut send, "ticket refused").await;
            drop(slot);
            linger(connection);
            return;
        }
    };

    let ready = encode_edge_view_msg(&EdgeViewMsg::Ready).expect("Ready encodes");
    let told = if tokio::time::timeout(SAY_WAIT, send.write_all(&ready))
        .await
        .is_ok_and(|written| written.is_ok())
    {
        // The share's frames, from its next keyframe on (`Edge::admit` asked for one)
        let (video_tx, video_rx) = mpsc::channel(VIEWER_QUEUE);
        let mut pumps = JoinSet::new();
        pumps.spawn(pump_media_out(
            DatagramSink::Quic(connection.clone()),
            media,
            video_tx,
            edge.keyframe_hook(),
            true,
        ));
        pumps.spawn(pump_video_streams(connection.clone(), video_rx));
        // The edge ends a viewer by taking its queue out of the share's fan and telling it
        // why at once, so its pumps run dry only after the word is in
        let told = tokio::select! {
            biased;
            told = &mut end => told.unwrap_or(End::Drop),
            _ = connection.closed() => End::Drop,
            _ = pumps.join_next() => end.try_recv().unwrap_or(End::Drop),
        };
        pumps.shutdown().await;
        Some(told)
    } else {
        None
    };
    edge.leave(share, viewer, Instant::now());
    if let Some(End::Say(why)) = told {
        say(&mut send, why).await;
    }
    // Back to the pre pool, which the slot then leaves
    edge.limits.demote(peer.ip());
    drop(slot);
    match told {
        Some(End::Say(_)) => linger(connection),
        _ => connection.close(VarInt::from_u32(0), b""),
    }
    debug!(%peer, "edge viewer left");
}

/// `EdgeViewMsg::Ended { reason }`, and the end of the edge's half of the stream.
async fn say(send: &mut SendStream, reason: &str) {
    let ended = EdgeViewMsg::Ended {
        reason: reason.into(),
    };
    let Ok(bytes) = encode_edge_view_msg(&ended) else {
        return;
    };
    let _ = tokio::time::timeout(SAY_WAIT, async {
        send.write_all(&bytes).await.ok()?;
        send.finish().await.ok()
    })
    .await;
}

/// Closes `connection` once the viewer did, or `LINGER` from now, off the session's task.
fn linger(connection: Connection) {
    tokio::spawn(async move {
        let _ = tokio::time::timeout(LINGER, connection.closed()).await;
        connection.close(VarInt::from_u32(0), b"");
    });
}
