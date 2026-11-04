//! Talking to an older relay (1.6). A relay admits only its own protocol, but
//! an app speaks every protocol from its own down to `OLDEST_RELAY_PROTOCOL`:
//! it asks with `PROTOCOL_VERSION`, and when the relay refuses with an older
//! one in that range, it connects again speaking that one.
//!
//! What makes this small: every message a protocol added went to the end of
//! its enum, so the variant indices never moved. Only the few messages whose
//! fields changed are rewritten here, in both directions, into the shape the
//! older relay knows (`tests/golden/v<N>.json`). A message the relay has never
//! heard of is refused before it is sent: the app hides what an older relay
//! cannot do, and this is the backstop.
//!
//! A new protocol needs its rows here before release; the golden guard below
//! fails until `RESHAPED` names every message whose layout changed.

use serde::{Deserialize, Serialize};

use crate::codec::{decode_server_msg, encode_client_msg, frame, PROTOCOL_VERSION};
use crate::error::ProtocolError;
use crate::messages::{AccountRequest, AuthContinue, ClientMessage, ServerMessage};
use crate::types::*;

/// The oldest relay protocol an app still speaks: 1.0's. At least three
/// protocols back, so a relay that has not updated keeps working.
pub const OLDEST_RELAY_PROTOCOL: u32 = 12;
const _: () = assert!(
    PROTOCOL_VERSION - OLDEST_RELAY_PROTOCOL >= 3,
    "the apps talk to relays at least three protocols back"
);

/// Which side sends a message, for `RESHAPED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    Client,
    Server,
}

/// Every message whose layout at an older protocol differs from today's,
/// named by that protocol and its variant index, and how it is handled. The
/// golden guard checks this list against `tests/golden/`.
pub const RESHAPED: &[(u32, Side, u32, &str)] = &[
    (
        12,
        Side::Client,
        40,
        "AuthContinue::Reset without key_signature",
    ),
    (
        12,
        Side::Client,
        41,
        "AccountRequest::RecoveryKeyNew and Admin are refused",
    ),
    (
        12,
        Side::Server,
        0,
        "Authenticated without files and emotes",
    ),
    (
        12,
        Side::Server,
        46,
        "AccountReply::RecoveryKeyChanged and Admin never come",
    ),
    (
        13,
        Side::Server,
        0,
        "Authenticated with 1.3's FileLimits, no emotes",
    ),
    (
        14,
        Side::Client,
        45,
        "EmoteAdd with the length beside the emote",
    ),
    (14, Side::Client, 46, "EmoteRemove of one name"),
    (14, Side::Server, 0, "Authenticated with 1.4's EmoteAccess"),
    (14, Side::Server, 56, "EmoteList of 1.4's Emote"),
    (14, Side::Server, 57, "EmoteTicket without the name"),
    (12, Side::Server, 3, "UserJoined without badges"),
    (12, Side::Server, 5, "UserList without badges"),
    (12, Side::Server, 18, "ChannelUsers without badges"),
    (13, Side::Client, 41, "AccountRequest::Admin is refused"),
    (13, Side::Server, 3, "UserJoined without badges"),
    (13, Side::Server, 5, "UserList without badges"),
    (13, Side::Server, 18, "ChannelUsers without badges"),
    (13, Side::Server, 46, "AccountReply::Admin never comes"),
    (14, Side::Client, 41, "AccountRequest::Admin is refused"),
    (14, Side::Server, 3, "UserJoined without badges"),
    (14, Side::Server, 5, "UserList without badges"),
    (14, Side::Server, 18, "ChannelUsers without badges"),
    (14, Side::Server, 46, "AccountReply::Admin never comes"),
    (15, Side::Client, 41, "AccountRequest::Admin is refused"),
    (15, Side::Server, 3, "UserJoined without badges"),
    (15, Side::Server, 5, "UserList without badges"),
    (15, Side::Server, 18, "ChannelUsers without badges"),
    (15, Side::Server, 46, "AccountReply::Admin never comes"),
    (
        12,
        Side::Client,
        0,
        "Authenticate: the provider starts are refused",
    ),
    (
        12,
        Side::Server,
        45,
        "AuthStep: the provider steps never come from it",
    ),
    (
        13,
        Side::Client,
        0,
        "Authenticate: the provider starts are refused",
    ),
    (
        13,
        Side::Client,
        40,
        "AuthContinue: the provider steps are refused",
    ),
    (
        13,
        Side::Server,
        45,
        "AuthStep: the provider steps never come from it",
    ),
    (
        14,
        Side::Client,
        0,
        "Authenticate: the provider starts are refused",
    ),
    (
        14,
        Side::Client,
        40,
        "AuthContinue: the provider steps are refused",
    ),
    (
        14,
        Side::Server,
        45,
        "AuthStep: the provider steps never come from it",
    ),
    (
        15,
        Side::Client,
        0,
        "Authenticate: the provider starts are refused",
    ),
    (
        15,
        Side::Client,
        40,
        "AuthContinue: the provider steps are refused",
    ),
    (
        15,
        Side::Server,
        45,
        "AuthStep: the provider steps never come from it",
    ),
    (
        16,
        Side::Client,
        0,
        "Authenticate: the provider starts are refused",
    ),
    (
        16,
        Side::Client,
        40,
        "AuthContinue: the provider steps are refused",
    ),
    (
        16,
        Side::Client,
        41,
        "AccountRequest: the provider requests are refused",
    ),
    (
        16,
        Side::Server,
        45,
        "AuthStep: the provider steps never come from it",
    ),
    (
        16,
        Side::Server,
        46,
        "AccountReply: the provider replies never come from it",
    ),
];

/// How many messages each side had at a protocol: an index at or past it is
/// one that relay has never heard of.
fn client_messages(proto: u32) -> u32 {
    match proto {
        ..=12 => 42,
        13 => 45,
        14 => 49,
        15..=16 => 50,
        _ => u32::MAX,
    }
}

const AUTH_CONTINUE: u32 = 40;
const AUTH_CONTINUE_RESET: u32 = 6;
const EMOTE_ADD: u32 = 45;
const EMOTE_REMOVE: u32 = 46;
const AUTHENTICATED: u32 = 0;
const USER_JOINED: u32 = 3;
const USER_LIST: u32 = 5;
const CHANNEL_USERS: u32 = 18;
const EMOTE_LIST: u32 = 56;
const EMOTE_TICKET: u32 = 57;

/// `encode_client_msg` for a relay at `proto`: the frames to send, one each
/// so a sender's pacer counts them as the relay does (`EmoteRemove` of many
/// names is many at 14), or `NotOnThisRelay`.
pub fn encode_client_msg_for(
    msg: &ClientMessage,
    proto: u32,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    if proto >= PROTOCOL_VERSION {
        return Ok(vec![encode_client_msg(msg)?]);
    }
    let old =
        |payload: Vec<u8>| -> Result<Vec<Vec<u8>>, ProtocolError> { Ok(vec![frame(payload)]) };
    match msg {
        // A 1.0 relay checks the identity's signature alone
        ClientMessage::AuthContinue(AuthContinue::Reset {
            signature,
            auth_secret,
            pass_slot,
            totp,
            recovery_code,
            ..
        }) if proto < 13 => old(postcard::to_allocvec(&(
            AUTH_CONTINUE,
            AUTH_CONTINUE_RESET,
            Reset12 {
                signature: signature.clone(),
                auth_secret: auth_secret.clone(),
                pass_slot: pass_slot.clone(),
                totp: totp.clone(),
                recovery_code: recovery_code.clone(),
            },
        ))?),
        ClientMessage::Account(AccountRequest::RecoveryKeyNew { .. }) if proto < 13 => {
            Err(ProtocolError::NotOnThisRelay(proto))
        }
        ClientMessage::Account(AccountRequest::Admin { .. }) if proto < 16 => {
            Err(ProtocolError::NotOnThisRelay(proto))
        }
        // New variants of enums nested in a message that is older: its index
        // says nothing, so they are named.
        ClientMessage::Authenticate {
            account:
                Some(
                    AccountStart::Providers
                    | AccountStart::Provider { .. }
                    | AccountStart::ProviderResume { .. }
                    | AccountStart::ProviderStatus { .. },
                ),
            ..
        }
        | ClientMessage::AuthContinue(
            AuthContinue::ProviderSignup { .. }
            | AuthContinue::Claim { .. }
            | AuthContinue::ProviderProof { .. }
            | AuthContinue::PairStart { .. }
            | AuthContinue::PairReveal { .. },
        )
        | ClientMessage::Account(
            AccountRequest::ProviderList
            | AccountRequest::ProviderStart { .. }
            | AccountRequest::ProviderUnlink { .. }
            | AccountRequest::PairNonce { .. }
            | AccountRequest::PairApprove { .. }
            | AccountRequest::PairDecline { .. },
        ) if proto < 17 => Err(ProtocolError::NotOnThisRelay(proto)),
        ClientMessage::EmoteAdd { emote } if proto == 14 => old(postcard::to_allocvec(&(
            EMOTE_ADD,
            EmoteAdd14 {
                emote: Emote14::from(emote),
                len: emote.len,
            },
        ))?),
        ClientMessage::EmoteRemove { names } if proto == 14 => names
            .iter()
            .map(|name| Ok(frame(postcard::to_allocvec(&(EMOTE_REMOVE, name))?)))
            .collect(),
        _ => {
            let payload = postcard::to_allocvec(msg)?;
            let (index, _) = postcard::take_from_bytes::<u32>(&payload)?;
            if index >= client_messages(proto) {
                return Err(ProtocolError::NotOnThisRelay(proto));
            }
            old(payload)
        }
    }
}

/// `decode_server_msg` for a relay at `proto`: an older message comes out in
/// today's shape, with what that relay never said filled in.
pub fn decode_server_msg_from(payload: &[u8], proto: u32) -> Result<ServerMessage, ProtocolError> {
    if proto >= PROTOCOL_VERSION {
        return decode_server_msg(payload);
    }
    let (index, rest) = postcard::take_from_bytes::<u32>(payload)?;
    Ok(match (index, proto) {
        (AUTHENTICATED, ..=12) => postcard::from_bytes::<Authenticated12>(rest)?.into(),
        (AUTHENTICATED, 13) => postcard::from_bytes::<Authenticated13>(rest)?.into(),
        (AUTHENTICATED, 14) => postcard::from_bytes::<Authenticated14>(rest)?.into(),
        (USER_JOINED, ..=15) => ServerMessage::UserJoined {
            user: postcard::from_bytes::<UserJoined15>(rest)?.user.into(),
        },
        (USER_LIST, ..=15) => {
            let l: UserList15 = postcard::from_bytes(rest)?;
            ServerMessage::UserList {
                channel_id: l.channel_id,
                users: l.users.into_iter().map(UserInfo::from).collect(),
            }
        }
        (CHANNEL_USERS, ..=15) => {
            let l: ChannelUsers15 = postcard::from_bytes(rest)?;
            ServerMessage::ChannelUsers {
                channel_id: l.channel_id,
                users: l.users.into_iter().map(UserInfo::from).collect(),
            }
        }
        (EMOTE_LIST, 14) => {
            let list: EmoteList14 = postcard::from_bytes(rest)?;
            ServerMessage::EmoteList {
                stickers: list.stickers,
                emotes: list.emotes.into_iter().map(Emote::from).collect(),
            }
        }
        (EMOTE_TICKET, 14) => {
            let t: EmoteTicket14 = postcard::from_bytes(rest)?;
            // The app matches a ticket by its hash alone when the name is empty
            ServerMessage::EmoteTicket {
                hash: t.hash,
                name: String::new(),
                ticket: t.ticket,
            }
        }
        _ => decode_server_msg(payload)?,
    })
}

// The old shapes, each as `tests/golden/v<N>.json` recorded it. The renames
// make their traced names match the golden ones.

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Reset")]
struct Reset12 {
    signature: Vec<u8>,
    auth_secret: Vec<u8>,
    pass_slot: Vec<u8>,
    totp: Option<String>,
    recovery_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Authenticated")]
struct Authenticated12 {
    user_id: UserId,
    session_id: SessionId,
    accounts: Option<RelayAccounts>,
    account: Option<AccountInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "FileLimits")]
struct FileLimits13 {
    max_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Authenticated")]
struct Authenticated13 {
    user_id: UserId,
    session_id: SessionId,
    accounts: Option<RelayAccounts>,
    account: Option<AccountInfo>,
    files: Option<FileLimits13>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "EmoteAccess")]
struct EmoteAccess14 {
    token: Secret,
    max_emote_bytes: u32,
    max_sticker_bytes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Authenticated")]
struct Authenticated14 {
    user_id: UserId,
    session_id: SessionId,
    accounts: Option<RelayAccounts>,
    account: Option<AccountInfo>,
    files: Option<FileLimits>,
    emotes: Option<EmoteAccess14>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Emote")]
struct Emote14 {
    name: String,
    hash: [u8; 32],
    sticker: bool,
    pack: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "EmoteAdd")]
struct EmoteAdd14 {
    emote: Emote14,
    len: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "EmoteList")]
struct EmoteList14 {
    stickers: bool,
    emotes: Vec<Emote14>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "EmoteTicket")]
struct EmoteTicket14 {
    hash: [u8; 32],
    ticket: String,
}

/// `UserInfo` from 1.0 to 1.6: no badges.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "UserInfo")]
struct UserInfo15 {
    user_id: UserId,
    username: String,
    channel_id: ChannelId,
    is_muted: bool,
    is_deafened: bool,
    is_screen_sharing: bool,
    is_admin: bool,
    shares_history: bool,
    account: Option<[u8; 16]>,
    is_moderator: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "UserJoined")]
struct UserJoined15 {
    user: UserInfo15,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "UserList")]
struct UserList15 {
    channel_id: ChannelId,
    users: Vec<UserInfo15>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "ChannelUsers")]
struct ChannelUsers15 {
    channel_id: ChannelId,
    users: Vec<UserInfo15>,
}

impl From<UserInfo15> for UserInfo {
    fn from(u: UserInfo15) -> Self {
        UserInfo {
            user_id: u.user_id,
            username: u.username,
            channel_id: u.channel_id,
            is_muted: u.is_muted,
            is_deafened: u.is_deafened,
            is_screen_sharing: u.is_screen_sharing,
            is_admin: u.is_admin,
            shares_history: u.shares_history,
            account: u.account,
            is_moderator: u.is_moderator,
            badges: Vec::new(),
        }
    }
}

impl From<Authenticated12> for ServerMessage {
    fn from(a: Authenticated12) -> Self {
        ServerMessage::Authenticated {
            user_id: a.user_id,
            session_id: a.session_id,
            accounts: a.accounts,
            account: a.account,
            files: None,
            emotes: None,
        }
    }
}

impl From<Authenticated13> for ServerMessage {
    fn from(a: Authenticated13) -> Self {
        ServerMessage::Authenticated {
            user_id: a.user_id,
            session_id: a.session_id,
            accounts: a.accounts,
            account: a.account,
            files: a.files.map(|f| FileLimits {
                max_bytes: f.max_bytes,
                animation_side: ANIMATION_SIDE_DEFAULT,
                animation_mb: ANIMATION_MB_DEFAULT,
            }),
            emotes: None,
        }
    }
}

impl From<Authenticated14> for ServerMessage {
    fn from(a: Authenticated14) -> Self {
        ServerMessage::Authenticated {
            user_id: a.user_id,
            session_id: a.session_id,
            accounts: a.accounts,
            account: a.account,
            files: a.files,
            emotes: a.emotes.map(|e| EmoteAccess {
                token: e.token,
                max_emote_bytes: e.max_emote_bytes,
                max_sticker_bytes: e.max_sticker_bytes,
                // shortcut: 1.4 never sent its cap, so this is its default
                // `max_total_mb`; the relay still refuses past its real one
                max_total_bytes: 32 << 20,
                max_items: MAX_EMOTES as u32,
            }),
        }
    }
}

impl From<Emote14> for Emote {
    fn from(e: Emote14) -> Self {
        // 0 is "unknown" for all three
        Emote {
            name: e.name,
            hash: e.hash,
            sticker: e.sticker,
            pack: e.pack,
            len: 0,
            w: 0,
            h: 0,
        }
    }
}

impl From<&Emote> for Emote14 {
    fn from(e: &Emote) -> Self {
        Emote14 {
            name: e.name.clone(),
            hash: e.hash,
            sticker: e.sticker,
            pack: e.pack.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{encode_server_msg, try_decode_frame};
    use crate::messages::AdminOp;
    use bytes::BytesMut;
    use serde_json::Value;
    use serde_reflection::{Tracer, TracerConfig};
    use std::collections::BTreeSet;

    fn golden(v: u32) -> Value {
        let path = format!("{}/tests/golden/v{v}.json", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// A format with every named type spelled out, so that two versions
    /// compare by what goes over the wire, not by type names.
    fn expand(reg: &Value, f: &Value) -> Value {
        match f {
            Value::Object(m) if m.len() == 1 && m.contains_key("TYPENAME") => {
                expand(reg, &reg[m["TYPENAME"].as_str().unwrap()])
            }
            Value::Object(m) => {
                Value::Object(m.iter().map(|(k, v)| (k.clone(), expand(reg, v))).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(|v| expand(reg, v)).collect()),
            other => other.clone(),
        }
    }

    /// The guard: every message whose layout at an older protocol differs
    /// from today's is in `RESHAPED`, and nothing else is.
    #[test]
    fn reshaped_names_every_changed_message() {
        let now = golden(PROTOCOL_VERSION);
        let mut found = BTreeSet::new();
        for v in OLDEST_RELAY_PROTOCOL..PROTOCOL_VERSION {
            let old = golden(v);
            for (side, name) in [
                (Side::Client, "ClientMessage"),
                (Side::Server, "ServerMessage"),
            ] {
                for (i, variant) in old[name]["ENUM"].as_object().unwrap() {
                    if expand(&old, variant) != expand(&now, &now[name]["ENUM"][i]) {
                        found.insert((v, side, i.parse::<u32>().unwrap()));
                    }
                }
            }
        }
        let listed: BTreeSet<_> = RESHAPED.iter().map(|&(v, s, i, _)| (v, s, i)).collect();
        assert_eq!(
            found, listed,
            "a message changed layout: add its row to RESHAPED and handle it"
        );
    }

    /// The counts match what each golden file recorded.
    #[test]
    fn message_counts_match_the_golden_files() {
        for v in OLDEST_RELAY_PROTOCOL..PROTOCOL_VERSION {
            let n = golden(v)["ClientMessage"]["ENUM"]
                .as_object()
                .unwrap()
                .len() as u32;
            assert_eq!(client_messages(v), n, "protocol {v}");
        }
    }

    /// Each old shape, traced, is what its golden file recorded.
    #[test]
    fn old_shapes_match_the_golden_files() {
        fn traced<'de, T: Deserialize<'de>>() -> Value {
            let mut tracer = Tracer::new(TracerConfig::default());
            // An enum inside RelayAccounts, traced through all its variants first
            tracer.trace_simple_type::<Registration>().unwrap();
            tracer.trace_simple_type::<T>().unwrap();
            serde_json::to_value(tracer.registry().unwrap()).unwrap()
        }
        let variant = |v: u32, path: &[&str]| {
            let g = golden(v);
            let mut f = &g;
            for p in path {
                f = &f[*p];
            }
            expand(&g, f)
        };
        let shape = |reg: Value, name: &str| expand(&reg, &reg[name]);
        let cases = [
            (
                traced::<Reset12>(),
                "Reset",
                variant(12, &["AuthContinue", "ENUM", "6", "Reset"]),
            ),
            (
                traced::<Authenticated12>(),
                "Authenticated",
                variant(12, &["ServerMessage", "ENUM", "0", "Authenticated"]),
            ),
            (
                traced::<Authenticated13>(),
                "Authenticated",
                variant(13, &["ServerMessage", "ENUM", "0", "Authenticated"]),
            ),
            (
                traced::<Authenticated14>(),
                "Authenticated",
                variant(14, &["ServerMessage", "ENUM", "0", "Authenticated"]),
            ),
            (
                traced::<EmoteAdd14>(),
                "EmoteAdd",
                variant(14, &["ClientMessage", "ENUM", "45", "EmoteAdd"]),
            ),
            (
                traced::<EmoteList14>(),
                "EmoteList",
                variant(14, &["ServerMessage", "ENUM", "56", "EmoteList"]),
            ),
            (
                traced::<EmoteTicket14>(),
                "EmoteTicket",
                variant(14, &["ServerMessage", "ENUM", "57", "EmoteTicket"]),
            ),
        ];
        let cases = cases
            .into_iter()
            .chain((OLDEST_RELAY_PROTOCOL..16).flat_map(|v| {
                [
                    (
                        traced::<UserJoined15>(),
                        "UserJoined",
                        variant(v, &["ServerMessage", "ENUM", "3", "UserJoined"]),
                    ),
                    (
                        traced::<UserList15>(),
                        "UserList",
                        variant(v, &["ServerMessage", "ENUM", "5", "UserList"]),
                    ),
                    (
                        traced::<ChannelUsers15>(),
                        "ChannelUsers",
                        variant(v, &["ServerMessage", "ENUM", "18", "ChannelUsers"]),
                    ),
                ]
            }));
        for (reg, name, want) in cases {
            assert_eq!(shape(reg, name), want, "{name}");
        }
        // EmoteRemove at 14 is one name, which the encoder writes bare
        assert_eq!(
            variant(14, &["ClientMessage", "ENUM", "46", "EmoteRemove"]),
            serde_json::json!({ "STRUCT": [{ "name": "STR" }] })
        );
    }

    /// The payloads of the frames, each checked to be exactly one frame.
    fn frames(framed: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        framed
            .into_iter()
            .map(|f| {
                let mut buf = BytesMut::from(&f[..]);
                let payload = try_decode_frame(&mut buf).unwrap().unwrap();
                assert!(buf.is_empty());
                payload
            })
            .collect()
    }

    fn emote(name: &str) -> Emote {
        Emote {
            name: name.into(),
            hash: [7; 32],
            sticker: true,
            pack: "p".into(),
            len: 900,
            w: 64,
            h: 32,
        }
    }

    #[test]
    fn today_passes_through() {
        let msg = ClientMessage::EmoteRemove {
            names: vec!["a".into()],
        };
        assert_eq!(
            encode_client_msg_for(&msg, PROTOCOL_VERSION).unwrap(),
            vec![encode_client_msg(&msg).unwrap()]
        );
        let msg = ServerMessage::EmoteTicket {
            hash: [1; 32],
            name: "n".into(),
            ticket: "t".into(),
        };
        let bytes = encode_server_msg(&msg).unwrap();
        assert!(matches!(
            decode_server_msg_from(&bytes[4..], PROTOCOL_VERSION).unwrap(),
            ServerMessage::EmoteTicket { name, .. } if name == "n"
        ));
    }

    #[test]
    fn unchanged_messages_keep_their_bytes() {
        let msg = ClientMessage::JoinChannel {
            channel_id: 3,
            password: None,
        };
        for v in OLDEST_RELAY_PROTOCOL..PROTOCOL_VERSION {
            assert_eq!(
                encode_client_msg_for(&msg, v).unwrap(),
                vec![encode_client_msg(&msg).unwrap()]
            );
        }
        let msg = ServerMessage::ChannelList { channels: vec![] };
        let bytes = encode_server_msg(&msg).unwrap();
        assert!(matches!(
            decode_server_msg_from(&bytes[4..], 12).unwrap(),
            ServerMessage::ChannelList { .. }
        ));
    }

    #[test]
    fn what_an_older_relay_never_heard_of_is_refused() {
        let cases = [
            (ClientMessage::FileCancel { hash: [0; 32] }, 12),
            (ClientMessage::EmoteStickers { on: true }, 13),
            (ClientMessage::EmoteAdd { emote: emote("ab") }, 13),
            (
                ClientMessage::EmoteMove {
                    names: vec![],
                    pack: None,
                    sticker: None,
                },
                14,
            ),
            (
                ClientMessage::Account(AccountRequest::RecoveryKeyNew {
                    secret: vec![],
                    recovery_slot: vec![],
                    reset_key: vec![],
                    totp: None,
                    recovery_code: None,
                }),
                12,
            ),
            (
                ClientMessage::Account(AccountRequest::Admin {
                    op: AdminOp::Groups,
                    code: None,
                }),
                15,
            ),
            (
                ClientMessage::Authenticate {
                    username: String::new(),
                    protocol_version: 16,
                    app_version: String::new(),
                    identity_key: None,
                    prekey_bundle: None,
                    account: Some(AccountStart::Providers),
                },
                16,
            ),
            (
                ClientMessage::AuthContinue(AuthContinue::ProviderProof { signature: vec![] }),
                16,
            ),
            (ClientMessage::Account(AccountRequest::ProviderList), 16),
            (
                ClientMessage::Account(AccountRequest::PairDecline { pair: 1 }),
                16,
            ),
        ];
        for (msg, v) in cases {
            assert!(
                matches!(encode_client_msg_for(&msg, v), Err(ProtocolError::NotOnThisRelay(p)) if p == v),
                "{msg:?} at {v}"
            );
        }
        // ... and the same messages are fine where they exist
        assert!(encode_client_msg_for(&ClientMessage::FileCancel { hash: [0; 32] }, 13).is_ok());
        assert!(encode_client_msg_for(&ClientMessage::EmoteStickers { on: true }, 14).is_ok());
    }

    #[test]
    fn rosters_from_an_older_relay_come_without_badges() {
        let old = UserInfo15 {
            user_id: 7,
            username: "ann".into(),
            channel_id: 2,
            is_muted: true,
            is_deafened: false,
            is_screen_sharing: false,
            is_admin: false,
            shares_history: true,
            account: Some([5; 16]),
            is_moderator: true,
        };
        let bytes = postcard::to_allocvec(&(USER_JOINED, UserJoined15 { user: old })).unwrap();
        for v in OLDEST_RELAY_PROTOCOL..16 {
            let ServerMessage::UserJoined { user } = decode_server_msg_from(&bytes, v).unwrap()
            else {
                panic!("UserJoined at {v}");
            };
            assert_eq!(
                (
                    user.username.as_str(),
                    user.account,
                    user.is_moderator,
                    user.badges.len()
                ),
                ("ann", Some([5; 16]), true, 0)
            );
        }
        let list = postcard::to_allocvec(&(
            USER_LIST,
            UserList15 {
                channel_id: 2,
                users: vec![],
            },
        ))
        .unwrap();
        assert!(matches!(
            decode_server_msg_from(&list, 15).unwrap(),
            ServerMessage::UserList { channel_id: 2, .. }
        ));
    }

    /// The arms above are for the protocols before badges, and only those. As
    /// `_` they turned on the first relay of the protocol before today's: all of
    /// a 1.7 relay's rosters failed to decode once this app spoke 17.
    #[test]
    fn rosters_with_badges_decode_at_every_protocol_that_has_them() {
        let user = UserInfo {
            user_id: 7,
            username: "ann".into(),
            channel_id: 2,
            is_muted: false,
            is_deafened: false,
            is_screen_sharing: false,
            is_admin: false,
            shares_history: false,
            account: Some([5; 16]),
            is_moderator: false,
            badges: vec!["crew".into()],
        };
        let messages = [
            ServerMessage::UserJoined { user: user.clone() },
            ServerMessage::UserList {
                channel_id: 2,
                users: vec![user.clone()],
            },
            ServerMessage::ChannelUsers {
                channel_id: 2,
                users: vec![user],
            },
        ];
        for v in 16..=PROTOCOL_VERSION {
            for msg in &messages {
                let bytes = postcard::to_allocvec(msg).unwrap();
                let back = decode_server_msg_from(&bytes, v).unwrap();
                let users = match back {
                    ServerMessage::UserJoined { user } => vec![user],
                    ServerMessage::UserList { users, .. }
                    | ServerMessage::ChannelUsers { users, .. } => users,
                    other => panic!("{other:?} at {v}"),
                };
                assert_eq!(users[0].badges, ["crew"], "at {v}");
            }
        }
    }

    #[test]
    fn reset_at_12_drops_the_key_signature() {
        let msg = ClientMessage::AuthContinue(AuthContinue::Reset {
            signature: vec![1, 2],
            key_signature: vec![9; 64],
            auth_secret: vec![3],
            pass_slot: vec![4],
            totp: Some("123456".into()),
            recovery_code: None,
        });
        let f = frames(encode_client_msg_for(&msg, 12).unwrap());
        let (outer, rest) = postcard::take_from_bytes::<u32>(&f[0]).unwrap();
        let (inner, rest) = postcard::take_from_bytes::<u32>(rest).unwrap();
        let reset: Reset12 = postcard::from_bytes(rest).unwrap();
        assert_eq!((outer, inner), (AUTH_CONTINUE, AUTH_CONTINUE_RESET));
        assert_eq!(
            (
                reset.signature,
                reset.auth_secret,
                reset.pass_slot,
                reset.totp
            ),
            (vec![1, 2], vec![3], vec![4], Some("123456".into()))
        );
        // Today's encoding of the same message starts with the same indices
        let now = encode_client_msg(&msg).unwrap();
        assert_eq!(
            &now[4..6],
            &[AUTH_CONTINUE as u8, AUTH_CONTINUE_RESET as u8]
        );
        // A 13 relay gets it as it is
        assert_eq!(encode_client_msg_for(&msg, 13).unwrap(), vec![now]);
    }

    #[test]
    fn emotes_at_14() {
        let f = frames(
            encode_client_msg_for(&ClientMessage::EmoteAdd { emote: emote("ab") }, 14).unwrap(),
        );
        let (index, rest) = postcard::take_from_bytes::<u32>(&f[0]).unwrap();
        let add: EmoteAdd14 = postcard::from_bytes(rest).unwrap();
        assert_eq!(
            (index, add.emote.name.as_str(), add.len, add.emote.sticker),
            (EMOTE_ADD, "ab", 900, true)
        );

        let names = vec!["a1".to_string(), "b2".to_string(), "c3".to_string()];
        let f = frames(
            encode_client_msg_for(
                &ClientMessage::EmoteRemove {
                    names: names.clone(),
                },
                14,
            )
            .unwrap(),
        );
        let got: Vec<String> = f
            .iter()
            .map(|p| {
                let (index, rest) = postcard::take_from_bytes::<u32>(p).unwrap();
                assert_eq!(index, EMOTE_REMOVE);
                postcard::from_bytes(rest).unwrap()
            })
            .collect();
        assert_eq!(got, names);

        let list = postcard::to_allocvec(&(
            EMOTE_LIST,
            EmoteList14 {
                stickers: true,
                emotes: vec![Emote14::from(&emote("cd"))],
            },
        ))
        .unwrap();
        match decode_server_msg_from(&list, 14).unwrap() {
            ServerMessage::EmoteList { stickers, emotes } => {
                assert!(stickers);
                let e = &emotes[0];
                assert_eq!(
                    (e.name.as_str(), e.len, e.w, e.h, e.pack.as_str()),
                    ("cd", 0, 0, 0, "p")
                );
            }
            other => panic!("{other:?}"),
        }
        let ticket = postcard::to_allocvec(&(
            EMOTE_TICKET,
            EmoteTicket14 {
                hash: [5; 32],
                ticket: "t".into(),
            },
        ))
        .unwrap();
        match decode_server_msg_from(&ticket, 14).unwrap() {
            ServerMessage::EmoteTicket { hash, name, ticket } => {
                assert_eq!((hash, name.as_str(), ticket.as_str()), ([5; 32], "", "t"))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn authenticated_from_each_older_relay() {
        let base = |v: u32| -> Vec<u8> {
            match v {
                12 => postcard::to_allocvec(&(
                    AUTHENTICATED,
                    Authenticated12 {
                        user_id: 4,
                        session_id: 5,
                        accounts: None,
                        account: None,
                    },
                )),
                13 => postcard::to_allocvec(&(
                    AUTHENTICATED,
                    Authenticated13 {
                        user_id: 4,
                        session_id: 5,
                        accounts: None,
                        account: None,
                        files: Some(FileLimits13 { max_bytes: 77 }),
                    },
                )),
                _ => postcard::to_allocvec(&(
                    AUTHENTICATED,
                    Authenticated14 {
                        user_id: 4,
                        session_id: 5,
                        accounts: None,
                        account: None,
                        files: Some(FileLimits {
                            max_bytes: 77,
                            animation_side: 512,
                            animation_mb: 64,
                        }),
                        emotes: Some(EmoteAccess14 {
                            token: Secret("tok".into()),
                            max_emote_bytes: 1,
                            max_sticker_bytes: 2,
                        }),
                    },
                )),
            }
            .unwrap()
        };
        // 15's Authenticated is today's
        for v in OLDEST_RELAY_PROTOCOL..15 {
            let ServerMessage::Authenticated {
                user_id,
                session_id,
                files,
                emotes,
                ..
            } = decode_server_msg_from(&base(v), v).unwrap()
            else {
                panic!("protocol {v}");
            };
            assert_eq!((user_id, session_id), (4, 5));
            match v {
                12 => assert!(files.is_none() && emotes.is_none()),
                13 => {
                    let f = files.unwrap();
                    assert_eq!(
                        (f.max_bytes, f.animation_side, f.animation_mb),
                        (77, ANIMATION_SIDE_DEFAULT, ANIMATION_MB_DEFAULT)
                    );
                    assert!(emotes.is_none());
                }
                _ => {
                    assert_eq!(files.unwrap().animation_side, 512);
                    let e = emotes.unwrap();
                    assert_eq!(
                        (
                            e.token.0.as_str(),
                            e.max_sticker_bytes,
                            e.max_total_bytes,
                            e.max_items
                        ),
                        ("tok", 2, 32 << 20, 400)
                    );
                }
            }
        }
    }
}
