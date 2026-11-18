//! Cutting the relay's multi-part messages into frames (plan 1e, part 13): `EpochIn`,
//! `EpochDue`, `KeyringIn`, `EpochNamesIn`. Each frame's piece stays under
//! `PIECE_MAX_BYTES` with its frame around it. A list spreads over parts in order; an
//! `Option` goes whole into the first part with room, once a sequence. Every item fits a
//! part alone (part 13), so nothing here splits one.
#![cfg_attr(not(test), allow(dead_code))]

use serde::Serialize;
use voipc_protocol::gk::{
    DuePiece, InPiece, KeyringPiece, NamesPiece, KEYRING_SLICE_MAX_BYTES, PIECE_MAX_BYTES,
};
use voipc_protocol::messages::ServerMessage;

/// Encoded bytes of a value.
pub fn len<T: Serialize + ?Sized>(x: &T) -> usize {
    postcard::experimental::serialized_size(x).unwrap_or(usize::MAX)
}

/// The frame around a piece at most: variant (2), the group (3 + bytes), `due` (10), part
/// (3), last (1), `KeyringIn`'s gen, epoch and join (26), and each list's length growing
/// past one byte (3 each, five lists at most).
fn room(group: &str) -> usize {
    PIECE_MAX_BYTES - (2 + 3 + group.len() + 10 + 3 + 1 + 26 + 5 * 3)
}

/// Parts being filled: each with the bytes it holds.
struct Cut<T> {
    parts: Vec<(T, usize)>,
    room: usize,
    blank: T,
}

impl<T: Clone + Serialize> Cut<T> {
    fn new(blank: T, group: &str) -> Cut<T> {
        let used = len(&blank);
        Cut {
            parts: vec![(blank.clone(), used)],
            room: room(group),
            blank,
        }
    }

    /// The first part at or after `from` with room for `n` bytes, a new one if none.
    fn slot(&mut self, from: usize, n: usize) -> usize {
        let mut i = from;
        while i < self.parts.len() && self.parts[i].1 + n > self.room {
            i += 1;
        }
        if i == self.parts.len() {
            let used = len(&self.blank);
            self.parts.push((self.blank.clone(), used));
        }
        self.parts[i].1 += n;
        i
    }

    /// Puts `item` into the first part with room.
    fn option<V: Serialize>(&mut self, item: Option<V>, put: impl FnOnce(&mut T, V)) {
        if let Some(item) = item {
            let i = self.slot(0, len(&item));
            put(&mut self.parts[i].0, item);
        }
    }

    /// Spreads `items` over the parts in order.
    fn list<V: Serialize>(&mut self, items: Vec<V>, push: impl Fn(&mut T, V)) {
        let mut at = 0;
        for item in items {
            at = self.slot(at, len(&item));
            push(&mut self.parts[at].0, item);
        }
    }

    fn done(self) -> Vec<T> {
        self.parts.into_iter().map(|(p, _)| p).collect()
    }
}

fn parts<T>(
    pieces: Vec<T>,
    mut frame: impl FnMut(u16, bool, T) -> ServerMessage,
) -> Vec<ServerMessage> {
    let n = pieces.len();
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, p)| frame(i as u16, i + 1 == n, p))
        .collect()
}

/// `EpochIn` for `group`, in parts.
pub fn epoch_in(group: &str, whole: InPiece) -> Vec<ServerMessage> {
    let InPiece {
        chain,
        walk,
        kh,
        head,
        opening,
        own_join,
        leaf,
        path,
        seal,
        seat,
        seed_welcome,
        self_rows,
        past,
        pushed,
    } = whole;
    let mut cut = Cut::new(
        InPiece {
            pushed,
            ..InPiece::default()
        },
        group,
    );
    cut.option(past, |p, x| p.past = Some(x));
    cut.option(head, |p, x| p.head = Some(x));
    cut.option(kh, |p, x| p.kh = Some(x));
    cut.option(opening, |p, x| p.opening = Some(x));
    cut.option(own_join, |p, x| p.own_join = Some(x));
    cut.option(leaf, |p, x| p.leaf = Some(x));
    cut.option(path, |p, x| p.path = Some(x));
    cut.option(seal, |p, x| p.seal = Some(x));
    cut.option(seat, |p, x| p.seat = Some(x));
    cut.option(seed_welcome, |p, x| p.seed_welcome = Some(x));
    cut.list(chain, |p, x| p.chain.push(x));
    cut.list(walk, |p, x| p.walk.push(x));
    cut.list(self_rows, |p, x| p.self_rows.push(x));
    parts(cut.done(), |part, last, piece| ServerMessage::EpochIn {
        group: group.to_string(),
        part,
        last,
        piece: Box::new(piece),
    })
}

/// `EpochDue` number `due` for `group`, in parts: every part carries the scalars, the
/// lists spread, `promote` and `remove` once.
pub fn epoch_due(group: &str, due: u64, whole: DuePiece) -> Vec<ServerMessage> {
    let DuePiece {
        joins,
        exits,
        promote,
        remove,
        seed_seats,
        pairs,
        held,
        ..
    } = &whole;
    let (joins, exits, promote, remove, seed_seats, pairs, held) = (
        joins.clone(),
        exits.clone(),
        promote.clone(),
        *remove,
        seed_seats.clone(),
        pairs.clone(),
        held.clone(),
    );
    let blank = DuePiece {
        joins: vec![],
        exits: vec![],
        promote: None,
        remove: None,
        seed_seats: vec![],
        pairs: vec![],
        held: vec![],
        ..whole
    };
    let mut cut = Cut::new(blank, group);
    cut.option(promote, |p, x| p.promote = Some(x));
    cut.option(remove, |p, x| p.remove = Some(x));
    cut.list(pairs, |p, x| p.pairs.push(x));
    cut.list(joins, |p, x| p.joins.push(x));
    cut.list(exits, |p, x| p.exits.push(x));
    cut.list(seed_seats, |p, x| p.seed_seats.push(x));
    cut.list(held, |p, x| p.held.push(x));
    parts(cut.done(), |part, last, piece| ServerMessage::EpochDue {
        group: group.to_string(),
        due,
        part,
        last,
        piece: Box::new(piece),
    })
}

/// `KeyringIn` at `(epoch, join)`: the `KRK` welcome in part 0, the stream in slices.
pub fn keyring_in(
    group: &str,
    gen: [u8; 16],
    at: (u32, u32),
    krk: Option<voipc_protocol::gk::KrkIn>,
    stream: &[u8],
) -> Vec<ServerMessage> {
    let mut pieces = vec![KeyringPiece {
        krk,
        stream: vec![],
    }];
    let first = room(group).saturating_sub(len(&pieces[0]));
    let mut rest = stream;
    let n = rest.len().min(first).min(KEYRING_SLICE_MAX_BYTES);
    pieces[0].stream = rest[..n].to_vec();
    rest = &rest[n..];
    while !rest.is_empty() {
        let n = rest.len().min(KEYRING_SLICE_MAX_BYTES);
        pieces.push(KeyringPiece {
            krk: None,
            stream: rest[..n].to_vec(),
        });
        rest = &rest[n..];
    }
    parts(pieces, |part, last, piece| ServerMessage::KeyringIn {
        group: group.to_string(),
        gen,
        epoch: at.0,
        join: at.1,
        part,
        last,
        piece,
    })
}

/// `EpochNamesIn` for `group`, in parts.
pub fn names_in(group: &str, whole: NamesPiece) -> Vec<ServerMessage> {
    let NamesPiece {
        lists,
        joins,
        removals,
        gone,
    } = whole;
    let mut cut = Cut::new(NamesPiece::default(), group);
    cut.option(gone, |p, x| p.gone = Some(x));
    cut.list(lists, |p, x| p.lists.push(x));
    cut.list(joins, |p, x| p.joins.push(x));
    cut.list(removals, |p, x| p.removals.push(x));
    parts(cut.done(), |part, last, piece| {
        ServerMessage::EpochNamesIn {
            group: group.to_string(),
            part,
            last,
            piece,
        }
    })
}
