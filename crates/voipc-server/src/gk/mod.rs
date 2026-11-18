//! The group epoch key on the relay (docs/GROUP-KEY.md, plan 2a). W1's stub: the switch,
//! this start's run and the frame after `Authenticated`; R1 builds the groups here.

use std::time::{SystemTime, UNIX_EPOCH};

use voipc_protocol::messages::ServerMessage;

/// Every group with a key on this relay.
pub struct Groups {
    /// `group_key` in server.toml, read at start.
    pub on: bool,
    /// 16 random bytes per start: the run in every `r:<run>:<channel id>` group id.
    pub run: [u8; 16],
}

impl Groups {
    pub fn new(on: bool) -> Groups {
        Groups {
            on,
            run: rand::random(),
        }
    }

    /// The frame right after `Authenticated` (plan 1f.8): which paths this relay uses.
    pub fn hello(&self) -> ServerMessage {
        ServerMessage::GroupKeys {
            on: self.on,
            run: self.run,
            clock: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }
    }
}
