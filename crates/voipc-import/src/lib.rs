//! Reads a Discord server for the desktop importer (1.11): no Tauri, no HTTP client, no
//! disk. The app gives it a transport to Discord and a link to the relay, so a test can
//! give it a stand-in for each, and a whole run can be checked against a real relay with
//! no call to Discord.
//!
//! What it reads stays in RAM. Nothing here writes a file or logs, and it has no way to
//! reach a network but the transport it is given.

pub mod api;
pub mod batch;
pub mod fit;
pub mod gates;
pub mod model;
pub mod names;
pub mod plan;
pub mod rewrite;
pub mod run;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

#[cfg(test)]
mod fixture;

/// Something a run has to say about what did not come over whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// What kind of thing this is, so that a long list can say "and 37 more of this kind".
    pub kind: &'static str,
    pub text: String,
    /// May be stored on the relay with the report. False: it names someone, or something
    /// that was left out, so it stays on the importer's screen.
    pub keep: bool,
    /// The channel it is about: a note of a channel left out never goes to the relay.
    pub channel: Option<u64>,
}

impl Note {
    /// About what was imported: fine to keep with the report.
    pub fn kept(kind: &'static str, channel: Option<u64>, text: String) -> Self {
        Note {
            kind,
            text,
            keep: true,
            channel,
        }
    }

    /// For the importer's own screen, and never the relay.
    pub fn screen(kind: &'static str, channel: Option<u64>, text: String) -> Self {
        Note {
            kind,
            text,
            keep: false,
            channel,
        }
    }
}
