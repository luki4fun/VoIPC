//! A signed-in account on one connection, without I/O: the stored-message log
//! and the pins (`sync`), remembering this device (`DeviceEnrol`), which user
//! here is which account (from the rosters), and what the front end hears of
//! it all. The desktop client and the browser (through wasm) only carry
//! messages in and out, emit what it says, and keep what it hands them. They
//! used to hold these rules in two copies, and the copies drifted.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, PoisonError};

use libsignal_protocol::KeyPair;
use serde_json::{json, Value};
use voipc_protocol::conv::{hex, unhex16};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage};
use voipc_protocol::types::{may_share_history, AccountInfo, ProviderKind, ReportTaker, UserInfo};
use zeroize::Zeroizing;

use crate::account::{
    derive_from_master, kdf_salt, login_key_proof, recovery_text, reset_key, DeviceEnrol, LoginKey,
    PinCheck, SignedIn, Vault,
};
use crate::sync::{AccountSync, Event, KeptPins, LogMemory, Prefs};

/// A device the relay remembers now: what signs this account in there next
/// time, without the password. The host keeps it in its own vault.
pub struct Remembered {
    pub relay_id: [u8; 16],
    pub name: String,
    pub device_id: [u8; 16],
    /// Ed25519, PKCS#8.
    pub device_key: Zeroizing<Vec<u8>>,
    /// The vault's key: a device key opens no slot.
    pub dek: Zeroizing<[u8; 32]>,
}

/// What the host does after a call.
#[derive(Default)]
pub struct Actions {
    pub send: Vec<ClientMessage>,
    /// Front-end events, name and payload, to emit as they are.
    pub emit: Vec<(&'static str, Value)>,
    /// Keep this device's key: the relay remembers it now.
    pub remember: Option<Remembered>,
    /// Keep this for the next run, under this key (`memory_key`): the log's
    /// read cursors moved.
    pub memory: Option<(String, LogMemory)>,
    /// Who it names as readers moved since it last said: a host that keeps that apart.
    pub memory_named: bool,
}

impl Actions {
    fn sending(send: Vec<ClientMessage>) -> Actions {
        Actions {
            send,
            ..Default::default()
        }
    }

    fn absorb(&mut self, other: Actions) {
        self.send.extend(other.send);
        self.emit.extend(other.emit);
        self.memory = other.memory.or(self.memory.take());
        self.memory_named |= other.memory_named;
    }
}

/// A pin decision that came before the pages of pins did.
enum PinWait {
    Identity(u32, Vec<u8>),
    Guest(u32, String),
}

/// Decisions held at most, while a relay sits on the pages.
const PIN_WAIT_MOST: usize = 65_536;

pub struct AccountSession {
    sync: AccountSync,
    /// The relay's protocol, for `may_share_history`.
    proto: u32,
    /// The device's switch, and whether it counts here: `sync` shares by both.
    switch: bool,
    right: bool,
    me: [u8; 16],
    relay_id: [u8; 16],
    name: String,
    dek: Zeroizing<[u8; 32]>,
    /// What the sync asks for first, sent once the connection is up.
    first: Vec<ClientMessage>,
    /// Signed in with the password: this device may be remembered.
    password_based: bool,
    /// The relay knows this device's key (and has not forgotten it since).
    remembered: bool,
    /// A role here waits for two-factor codes.
    needs_2fa: bool,
    enrol: Option<DeviceEnrol>,
    /// Who here is which account, and the name they go by (the rosters).
    roster: HashMap<u32, ([u8; 16], String)>,
    /// Conversations purged on request, whose tombstone follows the relay's
    /// `LogPurged` (sent before it, the purge would take it too).
    tombstones: std::collections::HashSet<String>,
    /// A new device asking for the vault's key, until the person answers.
    pairing: Option<Pairing>,
    /// What waits for the pages of pins, and whether they were out when the host looked.
    pin_wait: Vec<PinWait>,
    pins_out: bool,
    /// What this connection's proofs are bound to (`crate::bind`).
    binding: Option<crate::bind::Binding>,
    /// The password is the account's login key here (protocol v22): a request that wants
    /// it again goes after a `KeyStepUp` (`confirmed`).
    keyed: bool,
    /// A request waiting for its `KeyStepUp`.
    stepping: Option<Stepping>,
    /// A `LoginKeySet` out: `Some("PasswordChange")` for a new password (its refusal is
    /// that request's), `Some("")` for the move after a sign-in with the secret.
    key_set: Option<&'static str>,
}

/// A request that wants the password again, on a keyed account: the key that signs the
/// challenge, the codes, what goes once the step-up held, and the request's name.
struct Stepping {
    key: LoginKey,
    totp: Option<String>,
    recovery_code: Option<String>,
    then: ClientMessage,
    request: &'static str,
}

/// A pairing this device was asked for (`crate::pair`).
struct Pairing {
    pair: u64,
    commitment: Vec<u8>,
    /// Once the person agreed to look: the key this device answered with, and its
    /// raw bytes as they went out.
    key: Option<(KeyPair, Vec<u8>)>,
    /// Once revealed and checked: what the DEK would be wrapped to.
    ephemeral: Option<Vec<u8>>,
    /// Wrong codes typed so far.
    wrong: u32,
    /// When this step began (ms). One nobody ended goes from `tick`.
    since: u64,
}

impl Pairing {
    /// `account-pair-ended`. `looked`: this device's key went out and no reveal came,
    /// which is how someone trying codes looks from here. `typing`: the field for the
    /// code went away with nothing handed over, which must not pass for the code
    /// being taken while the new device asks about that.
    fn ended(&self) -> (&'static str, Value) {
        (
            "account-pair-ended",
            json!({
                "pair": self.pair,
                "looked": self.key.is_some() && self.ephemeral.is_none(),
                "typing": self.ephemeral.is_some(),
            }),
        )
    }
}

/// A step of a pairing nobody ended: the relay's wait for a person, and a margin.
const PAIR_EXPIRY_MS: u64 = 130_000;
/// How often a wrong code may be typed again before this device says no.
const PAIR_RETRIES: u32 = 3;
/// The relay's numbers (`spend_pair_ask` there), which bind only an honest relay.
const PAIR_ASKS: f64 = 3.0;
const PAIR_ASK_MS: f64 = 600_000.0;

#[derive(Debug, PartialEq)]
enum PairBudget {
    /// Ask the person.
    Ask,
    /// No more for now, and they have not heard so.
    SpentNow,
    Spent,
}

/// What is left of a relay's asks on this device.
struct PairAsks {
    left: f64,
    /// When `left` was counted (ms).
    at: u64,
    told: bool,
}

/// Per relay, for the whole run and not one session: a relay could otherwise start
/// over by dropping the connection.
static PAIR_BUDGETS: LazyLock<Mutex<HashMap<[u8; 16], PairAsks>>> = LazyLock::new(Default::default);

fn spend_pair_ask(relay: [u8; 16], now: u64) -> PairBudget {
    let mut budgets = PAIR_BUDGETS.lock().unwrap_or_else(PoisonError::into_inner);
    let asks = budgets.entry(relay).or_insert(PairAsks {
        left: PAIR_ASKS,
        at: now,
        told: false,
    });
    asks.left = (asks.left + now.saturating_sub(asks.at) as f64 / PAIR_ASK_MS).min(PAIR_ASKS);
    asks.at = now;
    if asks.left >= 1.0 {
        asks.left -= 1.0;
        asks.told = false;
        PairBudget::Ask
    } else if std::mem::replace(&mut asks.told, true) {
        PairBudget::Spent
    } else {
        PairBudget::SpentNow
    }
}

fn pair_declined(pair: u64) -> ClientMessage {
    ClientMessage::Account(AccountRequest::PairDecline { pair })
}

impl AccountSession {
    /// After `Authenticated`: what the sign-in left, the account it is, what
    /// this device kept of the log last time, the device's switch for sharing
    /// with joiners, and the relay's protocol. Tells the front end it signed in,
    /// and whether the switch counts here.
    pub fn start(
        signed: SignedIn,
        info: &AccountInfo,
        memory: LogMemory,
        switch: bool,
        password_based: bool,
        proto: u32,
    ) -> (AccountSession, Actions) {
        let right = may_share_history(proto, true, Some(&info.scopes));
        // Signed in with the password's secret at 22: the password moves to its login key
        // now, signed by the identity over this connection
        let upgrade = match (signed.login_key, signed.binding) {
            (Some(key), Some(b)) if proto >= 22 => {
                Some(ClientMessage::Account(AccountRequest::LoginKeySet {
                    login_key: key.to_vec(),
                    identity_sig: login_key_proof(
                        &signed.identity,
                        &signed.relay_id,
                        &signed.name,
                        &key,
                        None,
                        &b,
                    ),
                    pass_slot: None,
                    web: b.web(),
                }))
            }
            _ => None,
        };
        let keyed = signed.keyed || upgrade.is_some();
        let (mut sync, mut first) = AccountSync::start(&signed, info.id, memory, switch && right);
        let key_set = upgrade.as_ref().map(|_| "");
        first.extend(upgrade);
        sync.set_protocol(proto);
        let signed_in = json!({
            "name": signed.name,
            "relay_id": hex(&signed.relay_id),
            "info": info,
            "recovery": signed.recovery,
            "prefs": sync.prefs(),
            "blocks": sync.blocks(),
        });
        let s = AccountSession {
            sync,
            proto,
            switch,
            right,
            me: info.id,
            relay_id: signed.relay_id,
            dek: Zeroizing::new(signed.vault.dek()),
            name: signed.name,
            first,
            password_based,
            remembered: !password_based,
            needs_2fa: info.needs_2fa,
            enrol: None,
            roster: HashMap::new(),
            tombstones: Default::default(),
            pairing: None,
            pin_wait: Vec::new(),
            pins_out: false,
            binding: signed.binding,
            keyed,
            stepping: None,
            key_set,
        };
        (
            s,
            Actions {
                emit: vec![
                    ("account-signed-in", signed_in),
                    ("share-right", json!({ "may": right })),
                ],
                ..Default::default()
            },
        )
    }

    /// Once the connection is up, and listed (so the front end's commands
    /// find it): what the sync asks first, then the second-factor setup a role
    /// waits for, or else remembering this device.
    pub fn after_connect(&mut self) -> Actions {
        let mut a = Actions::sending(self.sync.pins_first());
        a.send.append(&mut self.first);
        if self.needs_2fa {
            a.send
                .push(ClientMessage::Account(AccountRequest::TotpSetup));
        } else if self.password_based && !self.remembered {
            self.start_enrol(&mut a);
        }
        a
    }

    /// Every couple of seconds while connected (`AccountSync::tick`).
    pub fn tick(&mut self) -> Actions {
        let (send, events) = self.sync.tick();
        let mut a = Actions::sending(send);
        self.events(events, &mut a);
        self.pins_came_in(&mut a);
        // A relay gone quiet must neither hold a question up nor bar the next one
        let now = crate::time::now_millis();
        if let Some(p) = self
            .pairing
            .take_if(|p| now.saturating_sub(p.since) > PAIR_EXPIRY_MS)
        {
            a.send.push(pair_declined(p.pair));
            a.emit.push(p.ended());
        }
        a
    }

    fn start_enrol(&mut self, a: &mut Actions) {
        // One at a time: a second would sign the first one's challenge.
        if self.enrol.is_some() {
            return;
        }
        let (enrol, ask) = DeviceEnrol::start(self.relay_id);
        self.enrol = Some(enrol);
        a.send.push(ask);
    }

    /// The person agreed to look at `account-pair-look`. Only now does anything go
    /// out: a fresh key, which the relay could not know when the new device committed.
    pub fn pair_look(&mut self, pair: u64) -> Actions {
        let Some(p) = self
            .pairing
            .as_mut()
            .filter(|p| p.pair == pair && p.key.is_none())
        else {
            return Actions::default();
        };
        let (own, nonce) = crate::pair::answer_key();
        p.key = Some((own, nonce.clone()));
        p.since = crate::time::now_millis();
        Actions::sending(vec![ClientMessage::Account(AccountRequest::PairNonce {
            pair,
            nonce,
        })])
    }

    /// The person said no, at either question.
    pub fn pair_decline(&mut self, pair: u64) -> Actions {
        match self.pairing.take_if(|p| p.pair == pair) {
            Some(_) => Actions::sending(vec![pair_declined(pair)]),
            None => Actions::default(),
        }
    }

    /// What the person typed at `account-pair-ask`. The vault's key leaves this
    /// device only if it is the code worked out here, and only to the key that was
    /// committed to before this device's key was known. A wrong one costs a retry,
    /// and past those this device says no and warns: someone may be in between.
    pub fn pair_answer(&mut self, pair: u64, typed: &str) -> Actions {
        let Some(p) = self.pairing.as_mut().filter(|p| p.pair == pair) else {
            return Actions::default();
        };
        let (Some((own, answer)), Some(ephemeral)) = (&p.key, &p.ephemeral) else {
            return Actions::default();
        };
        let typed = typed.trim().replace(' ', "");
        if typed != crate::pair::code(&p.commitment, answer, ephemeral) {
            p.wrong += 1;
            if p.wrong <= PAIR_RETRIES {
                let left = PAIR_RETRIES + 1 - p.wrong;
                return Actions {
                    emit: vec![(
                        "account-pair-ask",
                        json!({ "pair": pair, "left": left, "retry": true }),
                    )],
                    ..Default::default()
                };
            }
            self.pairing = None;
            return Actions {
                send: vec![pair_declined(pair)],
                emit: vec![("account-pair-ended", json!({ "pair": pair, "wrong": true }))],
                ..Default::default()
            };
        }
        let wrapped = crate::pair::wrap_dek(
            own,
            ephemeral,
            &self.dek,
            &self.relay_id,
            &self.name,
            &p.commitment,
        );
        self.pairing = None;
        match wrapped {
            Some(wrapped) => Actions {
                send: vec![ClientMessage::Account(AccountRequest::PairApprove {
                    pair,
                    wrapped,
                })],
                emit: vec![(
                    "account-pair-ended",
                    json!({ "pair": pair, "handed": true }),
                )],
                ..Default::default()
            },
            None => Actions::sending(vec![pair_declined(pair)]),
        }
    }

    /// The pairing replies. `None`: not one.
    fn on_pair_reply(&mut self, reply: &AccountReply) -> Option<Actions> {
        match reply {
            AccountReply::PairAsked { pair, commitment } => {
                // One at a time: the person is looking at the first.
                if self.pairing.is_some() {
                    return Some(Actions::sending(vec![pair_declined(*pair)]));
                }
                let now = crate::time::now_millis();
                match spend_pair_ask(self.relay_id, now) {
                    PairBudget::Ask => {}
                    PairBudget::SpentNow => {
                        return Some(Actions {
                            send: vec![pair_declined(*pair)],
                            emit: vec![("account-pair-limit", json!({}))],
                            ..Default::default()
                        })
                    }
                    PairBudget::Spent => return Some(Actions::sending(vec![pair_declined(*pair)])),
                }
                self.pairing = Some(Pairing {
                    pair: *pair,
                    commitment: commitment.clone(),
                    key: None,
                    ephemeral: None,
                    wrong: 0,
                    since: now,
                });
                Some(Actions {
                    emit: vec![("account-pair-look", json!({ "pair": pair }))],
                    ..Default::default()
                })
            }
            AccountReply::PairRevealed {
                pair,
                ephemeral,
                blind,
            } => {
                // Not before the look, and not twice: that would change the code
                let p = self
                    .pairing
                    .as_mut()
                    .filter(|p| p.pair == *pair && p.key.is_some() && p.ephemeral.is_none())?;
                if !crate::pair::reveal_ok(&p.commitment, ephemeral, blind) {
                    // Not the key it committed to: somebody is in the middle.
                    let ended = p.ended();
                    self.pairing = None;
                    return Some(Actions {
                        send: vec![pair_declined(*pair)],
                        emit: vec![ended],
                        ..Default::default()
                    });
                }
                p.ephemeral = Some(ephemeral.clone());
                p.since = crate::time::now_millis();
                let left = PAIR_RETRIES + 1;
                Some(Actions {
                    emit: vec![(
                        "account-pair-ask",
                        json!({ "pair": pair, "left": left, "retry": false }),
                    )],
                    ..Default::default()
                })
            }
            AccountReply::PairEnded { pair } => {
                let p = self.pairing.take_if(|p| p.pair == *pair)?;
                Some(Actions {
                    emit: vec![p.ended()],
                    ..Default::default()
                })
            }
            _ => None,
        }
    }

    /// Link a provider (`link`), or prove it's you with one you have linked. A
    /// link needs a recent sign-in: `master` is the stretched password, where
    /// the account has one. `ProviderBrowser` answers as `account-reply`.
    pub fn provider_start(
        &mut self,
        kind: ProviderKind,
        link: bool,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Actions {
        self.confirmed(
            master,
            (totp, recovery_code),
            "ProviderStart",
            |secret, totp, recovery_code| AccountRequest::ProviderStart {
                kind,
                link,
                secret,
                totp,
                recovery_code,
            },
        )
    }

    /// As for a link. `ProviderUnlinked` answers as `account-reply`.
    pub fn provider_unlink(
        &mut self,
        kind: ProviderKind,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Actions {
        self.confirmed(
            master,
            (totp, recovery_code),
            "ProviderUnlink",
            |secret, totp, recovery_code| AccountRequest::ProviderUnlink {
                kind,
                secret,
                totp,
                recovery_code,
            },
        )
    }

    /// A request that wants the password again (`master`, stretched) and the second
    /// factor where there is one. On a keyed account at 22 the password never goes: a
    /// challenge, `KeyStepUp` with the login key and the codes, then the request without
    /// them (`on_key_reply`). Otherwise the request with the password's secret, as before.
    fn confirmed(
        &mut self,
        master: Option<&[u8; 32]>,
        (totp, recovery_code): (Option<String>, Option<String>),
        request: &'static str,
        then: impl FnOnce(Option<Vec<u8>>, Option<String>, Option<String>) -> AccountRequest,
    ) -> Actions {
        let totp = totp
            .map(|c| c.trim().replace(' ', ""))
            .filter(|c| !c.is_empty());
        let recovery_code = recovery_code
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        match master {
            Some(m) if self.keyed && self.proto >= 22 => {
                if self.binding.is_none() {
                    return self.refusal(request, NO_BINDING);
                }
                self.stepping = Some(Stepping {
                    key: LoginKey::from_master(m),
                    totp,
                    recovery_code,
                    then: ClientMessage::Account(then(None, None, None)),
                    request,
                });
                Actions::sending(vec![ClientMessage::Account(AccountRequest::KeyChallenge)])
            }
            _ => Actions::sending(vec![ClientMessage::Account(then(
                secret_of(master),
                totp,
                recovery_code,
            ))]),
        }
    }

    /// The page hears `reason` as the answer to `request`.
    fn refusal(&self, request: &str, reason: &str) -> Actions {
        Actions {
            emit: vec![(
                "account-reply",
                json!({ "Error": { "request": request, "reason": reason } }),
            )],
            ..Default::default()
        }
    }

    /// The login key's replies (protocol v22): the challenge signed, the step-up's request
    /// sent, a refusal on the page as the request's own, the move to the key done.
    fn on_key_reply(&mut self, reply: &AccountReply) -> Option<Actions> {
        match reply {
            AccountReply::KeyChallenge { challenge } => {
                let st = self.stepping.as_ref()?;
                let Some(b) = self.binding else {
                    let request = self.stepping.take()?.request;
                    return Some(self.refusal(request, NO_BINDING));
                };
                Some(Actions::sending(vec![ClientMessage::Account(
                    AccountRequest::KeyStepUp {
                        challenge: challenge.clone(),
                        signature: st.key.sign(&self.relay_id, &self.name, challenge, &b),
                        totp: st.totp.clone(),
                        recovery_code: st.recovery_code.clone(),
                        web: b.web(),
                    },
                )]))
            }
            AccountReply::SteppedUp => {
                let st = self.stepping.take()?;
                Some(Actions::sending(vec![st.then]))
            }
            AccountReply::Error { request, reason }
                if request == "KeyChallenge" || request == "KeyStepUp" =>
            {
                let st = self.stepping.take()?;
                if st.request == "PasswordChange" {
                    self.key_set = None;
                }
                Some(self.refusal(st.request, reason))
            }
            AccountReply::LoginKeySaved => {
                self.key_set = None;
                self.keyed = true;
                Some(Actions::default())
            }
            AccountReply::Error { request, reason } if request == "LoginKeySet" => {
                match self.key_set.take()? {
                    // The move after a sign-in: the account stays as it was
                    "" => {
                        self.keyed = false;
                        Some(Actions::default())
                    }
                    r => Some(self.refusal(r, reason)),
                }
            }
            _ => None,
        }
    }

    /// The account's name here.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One `AccountReply`. What none of this answers goes to the front end
    /// as `account-reply`.
    pub fn on_reply(&mut self, reply: &AccountReply) -> Actions {
        // A numbered answer (`AdminAsk`, protocol v22): what it holds, as any other, and its
        // number goes to the page with it. One that does not decode is nobody's
        if let AccountReply::Asked { ask, reply } = reply {
            let Ok(inner) = voipc_protocol::codec::decode_asked(reply) else {
                return Actions::default();
            };
            let mut a = self.on_reply(&inner);
            for (name, value) in a.emit.iter_mut() {
                if let (&mut "account-reply", Value::Object(fields)) = (name, value) {
                    fields.insert("ask".into(), (*ask).into());
                }
            }
            return a;
        }
        if let Some(actions) = self.on_pair_reply(reply) {
            return actions;
        }
        if let Some(actions) = self.on_key_reply(reply) {
            return actions;
        }
        if let Some(next) = self.enrol.as_ref().and_then(|e| e.on_reply(reply)) {
            return Actions::sending(vec![next]);
        }
        if let Some((send, events)) = self.sync.on_reply(reply) {
            let mut a = Actions::sending(send);
            self.events(events, &mut a);
            self.pins_came_in(&mut a);
            return a;
        }
        let mut a = Actions::default();
        match reply {
            AccountReply::DeviceAdded => {
                if let Some(e) = self.enrol.take() {
                    self.remembered = true;
                    a.remember = Some(Remembered {
                        relay_id: self.relay_id,
                        name: self.name.clone(),
                        device_id: e.key.device_id,
                        device_key: Zeroizing::new(e.key.pkcs8().to_vec()),
                        dek: self.dek.clone(),
                    });
                }
            }
            // Codes on: the relay forgot every device key of the account, and
            // a role that waited for them counts now.
            AccountReply::TotpEnabled { .. } => {
                self.remembered = false;
                self.needs_2fa = false;
            }
            // A new password forgets every device key, this one's too: the
            // person just typed the password, so remember this device again.
            AccountReply::PasswordChanged => {
                self.remembered = false;
                self.password_based = true;
                if !self.needs_2fa {
                    self.start_enrol(&mut a);
                }
            }
            AccountReply::Info(info) => {
                self.needs_2fa = info.needs_2fa;
                if !info.needs_2fa && self.password_based && !self.remembered {
                    self.start_enrol(&mut a);
                }
                let right = may_share_history(self.proto, true, Some(&info.scopes));
                if right != self.right {
                    self.right = right;
                    self.sync.set_share(self.switch && right);
                    a.emit.push(("share-right", json!({ "may": right })));
                    // The relay clears the flag by itself, and never sets it
                    if right && self.switch {
                        a.send
                            .push(ClientMessage::SetHistorySharing { enabled: true });
                    }
                }
            }
            AccountReply::Error { request, .. } if request.starts_with("Device") => {
                self.enrol = None
            }
            // Our entries in `conv` are gone from the relay: a tombstone
            // tells the readers' devices to drop their copies too.
            AccountReply::LogPurged {
                conv: Some(conv), ..
            } if self.tombstones.remove(conv) => {
                let now = crate::time::now_millis();
                let tomb = crate::envelope::purge_envelope(&crate::envelope::new_message_id(), now);
                match voipc_protocol::conv::dm_parties(conv) {
                    Some((x, y)) => a.send.extend(self.sync.send_dm(
                        if x == self.me { y } else { x },
                        tomb,
                        now,
                        None,
                    )),
                    None => a.send.extend(self.sync.send_channel(conv, tomb, now, None)),
                }
            }
            // From 22 the code the app shows is its own, from its end of the connection;
            // a browser shows the relay's, having nothing else (W1-24)
            AccountReply::ProviderBrowser { url, code } if self.proto >= 22 => {
                let code = match self.binding {
                    Some(crate::bind::Binding::Tls(x)) => {
                        crate::bind::provider_code(&x, url.as_bytes())
                    }
                    Some(crate::bind::Binding::Web) => code.clone(),
                    None => {
                        a.emit.push((
                            "account-reply",
                            json!({ "Error": {
                                "request": "ProviderStart",
                                "reason": "This connection cannot be checked. Nothing was opened.",
                            }}),
                        ));
                        return a;
                    }
                };
                a.emit.push((
                    "account-reply",
                    json!({ "ProviderBrowser": { "url": url, "code": code } }),
                ));
                return a;
            }
            _ => {}
        }
        a.emit.push((
            "account-reply",
            serde_json::to_value(reply).unwrap_or(Value::Null),
        ));
        a
    }

    /// The pages are in: the decisions that waited for them.
    fn pins_came_in(&mut self, a: &mut Actions) {
        if self.pin_wait.is_empty() || !self.sync.pins_in() {
            return;
        }
        for wait in std::mem::take(&mut self.pin_wait) {
            a.absorb(match wait {
                PinWait::Identity(user_id, key) => self.check_identity(user_id, &key),
                PinWait::Guest(user_id, name) => self.note_person(user_id, None, &name),
            });
        }
    }

    /// Takes over what an earlier connection of this account kept (`keep_pins`), before the
    /// host asks `pins_in`.
    pub fn adopt_pins(&mut self, kept: KeptPins) {
        self.sync.adopt_pins(kept);
    }

    /// What this connection hands the next, in memory: an app that stays up reads again only
    /// the pages whose generation moved.
    pub fn keep_pins(&self) -> Option<KeptPins> {
        self.sync.keep_pins()
    }

    /// Whether the pages of pins are in. If not, the host holds the live path's key jobs,
    /// and asks `take_pins_in` after each reply.
    pub fn pins_in(&mut self) -> bool {
        let pins_in = self.sync.pins_in();
        self.pins_out |= !pins_in;
        pins_in
    }

    /// `true` once, when pages that were out have come in: the key jobs go on.
    pub fn take_pins_in(&mut self) -> bool {
        self.sync.pins_in() && std::mem::take(&mut self.pins_out)
    }

    /// Whatever pins were not saved yet, now: the person is leaving (`AccountSync::flush_pins`).
    pub fn flush_pins(&mut self) -> Actions {
        Actions::sending(self.sync.flush_pins())
    }

    /// Whether all of that is stored: a sign-out waits a moment for it.
    pub fn pins_saved(&self) -> bool {
        self.sync.pins_saved()
    }

    /// A direct message came from `user_id`: their pin keeps the half open channels cannot fill.
    pub fn note_direct(&mut self, user_id: u32) {
        if let Some((account, _)) = self.roster.get(&user_id) {
            self.sync.reserve_pin(*account);
        }
    }

    /// Accounts met in a gated channel: the same.
    pub fn note_gated_people(&mut self, accounts: &[[u8; 16]]) {
        for account in accounts {
            self.sync.reserve_pin(*account);
        }
    }

    /// A channel log with a gate: who is met in it counts as in `note_gated_people`.
    pub fn note_gated_log(&mut self, conv: &str) {
        self.sync.note_gated_log(conv);
    }

    /// The person opened `user_id`'s safety number: their pin is kept, and goes now.
    pub fn verified(&mut self, user_id: u32) -> Actions {
        match self.roster.get(&user_id) {
            Some((account, _)) => Actions::sending(self.sync.verified_pin(*account)),
            None => Actions::default(),
        }
    }

    fn events(&mut self, events: Vec<Event>, a: &mut Actions) {
        let mut read = self.sync.take_memory_changed();
        for e in events {
            read |= e.reads();
            match &e {
                Event::IdentityChanged {
                    account,
                    name,
                    replaced,
                } => self.identity_changed(account, name, *replaced, a),
                _ => a.emit.extend(e.to_wire()),
            }
        }
        if read {
            a.memory = Some((self.memory_key(), self.sync.memory()));
            a.memory_named = self.sync.take_named_changed();
        }
    }

    /// Told by user id where they are here, else by name: they may be away,
    /// and a change nobody hears of is pinned all the same.
    fn identity_changed(&self, account: &[u8; 16], name: &str, replaced: bool, a: &mut Actions) {
        let here: Vec<u32> = self
            .roster
            .iter()
            .filter(|(_, (acc, _))| acc == account)
            .map(|(u, _)| *u)
            .collect();
        if here.is_empty() {
            a.emit.push((
                "identity-key-changed",
                json!({ "user_id": null, "name": name, "replaced": replaced }),
            ));
        }
        for user_id in here {
            a.emit.push((
                "identity-key-changed",
                json!({ "user_id": user_id, "name": name, "replaced": replaced }),
            ));
        }
    }

    /// The accounts in a roster (`UserList`, `UserJoined`, `ChannelUsers`),
    /// for the pins and for keeping copies of direct messages to them. The
    /// relay never sends an account behind a pseudonym. A name this account
    /// first met as an account, shown now as a guest, is a warning: an honest
    /// relay with accounts never lets a guest use an account's name.
    pub fn note_roster(&mut self, users: &[UserInfo]) -> Actions {
        let mut a = Actions::default();
        for u in users {
            a.emit
                .extend(self.note_person(u.user_id, u.account, &u.username).emit);
        }
        a
    }

    /// One person, as a row of a roster does: on the live path a post, a session ask or
    /// `KeysOwed` may be the first anyone says of them, and an id off the roster goes
    /// unchecked against the pins.
    pub fn note_person(&mut self, user_id: u32, account: Option<[u8; 16]>, name: &str) -> Actions {
        let mut a = Actions::default();
        match account {
            Some(account) => {
                self.roster.insert(user_id, (account, name.to_string()));
            }
            None if !self.sync.pins_in() => {
                if self.pin_wait.len() < PIN_WAIT_MOST {
                    self.pin_wait
                        .push(PinWait::Guest(user_id, name.to_string()));
                }
            }
            None if self.sync.knows_name(name) => {
                a.emit.push((
                    "identity-key-changed",
                    json!({ "user_id": user_id, "name": name, "as_guest": true }),
                ));
            }
            None => {}
        }
        a
    }

    /// The account signed in on this connection: what its kept sessions go by, with the server.
    pub fn account_id(&self) -> [u8; 16] {
        self.me
    }

    /// The account the rosters say `user_id` is.
    pub fn account_of(&self, user_id: u32) -> Option<[u8; 16]> {
        self.roster.get(&user_id).map(|(account, _)| *account)
    }

    /// An identity `user_id` showed — in a pre-key bundle, or in a session
    /// they opened (`VoipcIdentityStore::take_seen`) — against the pins.
    pub fn check_identity(&mut self, user_id: u32, key: &[u8]) -> Actions {
        if !self.sync.pins_in() {
            if self.pin_wait.len() < PIN_WAIT_MOST {
                self.pin_wait.push(PinWait::Identity(user_id, key.to_vec()));
            }
            return Actions::default();
        }
        let Some((account, name)) = self.roster.get(&user_id).cloned() else {
            return Actions::default();
        };
        let (check, send) = self.sync.check_peer(&account, &name, key);
        let mut a = Actions::sending(send);
        if check.warns() {
            a.emit.push(("identity-key-changed", json!({ "user_id": user_id, "name": name, "new_identity_key": key, "replaced": check == PinCheck::Replaced })));
        }
        a
    }

    /// A direct message to `user_id`, kept for them too when cloud copies are
    /// on and they signed in to an account.
    pub fn outgoing_dm(
        &mut self,
        user_id: u32,
        envelope: Vec<u8>,
        sent_at: u64,
        ttl_secs: Option<u32>,
    ) -> Actions {
        match self.roster.get(&user_id).map(|(peer, _)| *peer) {
            Some(peer) => {
                self.sync.reserve_pin(peer);
                Actions::sending(self.sync.send_dm(peer, envelope, sent_at, ttl_secs))
            }
            None => Actions::default(),
        }
    }

    /// A direct message for an account that is away (`account_hex`): kept in
    /// the stored log only, which is the one way it reaches them. `once`: a
    /// report its writer chose to keep sealed for them, whatever cloud copies
    /// say; everything else needs those on.
    pub fn kept_dm(
        &mut self,
        account_hex: &str,
        envelope: Vec<u8>,
        sent_at: u64,
        ttl_secs: Option<u32>,
        once: bool,
    ) -> Result<Actions, String> {
        if !self.cloud() && !once {
            return Err("They are away, and your messages are not kept on this server".into());
        }
        let peer = unhex16(account_hex).ok_or("not an account id")?;
        Ok(Actions::sending(
            self.sync.keep_dm(peer, envelope, sent_at, ttl_secs),
        ))
    }

    /// Who the relay says takes reports. Someone in a hidden channel is on no
    /// roster, and without this their identity would go unchecked against the
    /// pins, and no copy be kept for them. Noted before anything is sent to them.
    pub fn note_takers(&mut self, takers: &[ReportTaker]) {
        for t in takers {
            if let (Some(user_id), Some(account)) = (t.user_id, t.account) {
                self.roster.insert(user_id, (account, t.name.clone()));
            }
        }
    }

    /// A message written in a channel with log `log` (`ChannelInfo::log`;
    /// empty: none), kept for its members too.
    pub fn outgoing_channel(
        &mut self,
        log: &str,
        envelope: Vec<u8>,
        sent_at: u64,
        ttl_secs: Option<u32>,
    ) -> Actions {
        if log.is_empty() {
            return Actions::default();
        }
        Actions::sending(self.sync.send_channel(log, envelope, sent_at, ttl_secs))
    }

    /// In a channel with log `conv`: keep it, and read what it kept.
    pub fn enter(&mut self, conv: &str) -> Actions {
        Actions::sending(self.sync.enter(conv))
    }

    /// A channel that slept came on screen: read what was kept meanwhile.
    pub fn read_now(&mut self, conv: &str) -> Actions {
        Actions::sending(self.sync.read_now(conv))
    }

    /// In these channels' logs, newly followed: keep them in one frame, and read them.
    pub fn enter_many(&mut self, convs: &[String]) -> Actions {
        Actions::sending(self.sync.enter_many(convs))
    }

    /// `user_id` left channel log `conv`, or was put out of it (`MemberGone`).
    pub fn member_gone(&mut self, conv: &str, user_id: u32) {
        let account = self.roster.get(&user_id).map(|(account, _)| *account);
        self.sync.member_gone(conv, account);
    }

    /// Whether a direct message to `user_id` that did not arrive is kept for
    /// them all the same (`DirectMessageUndelivered`).
    /// Out of channel log `conv` (`AccountSync::leave`).
    pub fn leave(&mut self, conv: &str, tell: bool) -> Actions {
        Actions::sending(self.sync.leave(conv, tell))
    }

    pub fn kept_for(&self, user_id: u32) -> bool {
        self.cloud() && self.roster.contains_key(&user_id) && !self.sync.copy_refused()
    }

    /// The safety number with `user_id`: our identity `own_key`, their pinned
    /// one, and `live`, the key the session with them runs on. One that is
    /// not the pinned key was never checked against it, so there is no number.
    pub fn safety_number(
        &self,
        user_id: u32,
        own_key: &[u8],
        live: Option<&[u8]>,
    ) -> Result<String, String> {
        let (peer, _) = self
            .roster
            .get(&user_id)
            .ok_or("They are not signed in to an account")?;
        if !self.sync.pins_in() {
            return Err("Still reading who you have met here. Try again in a moment.".into());
        }
        let pinned = self
            .sync
            .pinned(peer)
            .ok_or("Their identity has not been seen yet")?;
        if live.is_some_and(|l| l != pinned) {
            return Err("Their identity changed: the conversation runs on another key than the one pinned. Reconnect, then verify again.".into());
        }
        crate::account::safety_number(&self.me, own_key, peer, pinned)
            .ok_or_else(|| "could not compute the safety number".into())
    }

    /// Deletes what this account wrote to the stored logs: in `conv` (then a
    /// tombstone asks the readers' devices to drop their copies too), or
    /// (None) everywhere, where the copies already read stay.
    pub fn purge(&mut self, conv: Option<&str>) -> Actions {
        if let Some(c) = conv {
            self.tombstones.insert(c.to_string());
        }
        Actions::sending(vec![ClientMessage::Account(AccountRequest::LogPurge {
            conv: conv.map(str::to_string),
        })])
    }

    /// Deletes this account, from `stretch` of its password and the second
    /// factor where it has one. `AccountDeleted` answers; the relay then
    /// closes the connection.
    pub fn delete_account(
        &mut self,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Actions {
        self.confirmed(
            master,
            (totp, recovery_code),
            "DeleteAccount",
            |secret, totp, recovery_code| AccountRequest::DeleteAccount {
                secret: secret.unwrap_or_default(),
                totp,
                recovery_code,
            },
        )
    }

    /// The PBKDF2 salt for this account's passwords (`account::stretch`).
    pub fn kdf_salt(&self) -> String {
        kdf_salt(&self.relay_id, &self.name)
    }

    /// A new password, from `stretch` of the old one and of the new one, and
    /// the second factor where the account has one. The vault's password
    /// slot is wrapped again for the new one; the DEK and the recovery slot
    /// stay. `PasswordChanged` answers it; every other device is signed out.
    pub fn password_change(
        &mut self,
        old_master: &[u8; 32],
        new_master: &[u8; 32],
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Actions {
        let (old, new) = (
            derive_from_master(old_master),
            derive_from_master(new_master),
        );
        let vault = Vault::from_dek(self.relay_id, &self.name, *self.dek);
        // A keyed account (22): the old key steps up, then the new key goes in, signed by
        // the identity with the new slot over this connection. Neither secret goes.
        if self.keyed && self.proto >= 22 {
            let Some(b) = self.binding else {
                return self.refusal("PasswordChange", NO_BINDING);
            };
            let key = LoginKey::from_master(new_master).public_key();
            let slot = vault.pass_slot(&new.vault_key).v;
            let identity_sig = login_key_proof(
                self.sync.identity(),
                &self.relay_id,
                &self.name,
                &key,
                Some(&slot),
                &b,
            );
            self.key_set = Some("PasswordChange");
            return self.confirmed(
                Some(old_master),
                (totp, recovery_code),
                "PasswordChange",
                |_, _, _| AccountRequest::LoginKeySet {
                    login_key: key.to_vec(),
                    identity_sig,
                    pass_slot: Some(slot),
                    web: b.web(),
                },
            );
        }
        Actions::sending(vec![ClientMessage::Account(
            AccountRequest::PasswordChange {
                old_secret: old.auth_secret.to_vec(),
                new_secret: new.auth_secret.to_vec(),
                pass_slot: vault.pass_slot(&new.vault_key).v,
                totp: totp
                    .map(|c| c.trim().replace(' ', ""))
                    .filter(|c| !c.is_empty()),
                recovery_code: recovery_code
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty()),
            },
        )])
    }

    /// A new recovery key, confirmed by the password (and the second factor
    /// where the account has one), with the text to show once. It also gives
    /// an account made before 1.3 its reset key (`slot.reset`), so only the
    /// recovery key resets its password from then on (S-006).
    pub fn recovery_key_new(
        &mut self,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> (Actions, String) {
        let recovery = Zeroizing::new(crate::aead::random::<32>());
        let vault = Vault::from_dek(self.relay_id, &self.name, *self.dek);
        let recovery_slot = vault.recovery_slot(&recovery).v;
        let reset = reset_key(&recovery, &self.relay_id, &self.name).to_vec();
        let a = self.confirmed(
            master,
            (totp, recovery_code),
            "RecoveryKeyNew",
            |secret, totp, recovery_code| AccountRequest::RecoveryKeyNew {
                secret: secret.unwrap_or_default(),
                recovery_slot,
                reset_key: reset,
                totp,
                recovery_code,
            },
        );
        (a, recovery_text(&recovery))
    }

    pub fn cloud(&self) -> bool {
        self.sync.prefs().cloud
    }

    pub fn prefs(&self) -> Prefs {
        self.sync.prefs()
    }

    pub fn set_prefs(&mut self, prefs: Prefs) -> Actions {
        Actions::sending(self.sync.set_prefs(prefs))
    }

    /// Blocks or unblocks the person `key` names (`AccountSync::set_block`), and
    /// tells the front end who is blocked now. `Err` says why the list could not
    /// be kept. Nothing here reaches the person, and the relay gets one sealed item.
    pub fn set_block(&mut self, key: &str, label: &str, on: bool) -> Result<Actions, String> {
        let mut a = Actions::sending(self.sync.set_block(key, label, on)?);
        a.emit
            .push(("account-blocks", json!({ "blocks": self.sync.blocks() })));
        Ok(a)
    }

    /// The device's switch moved.
    pub fn set_share(&mut self, switch: bool) {
        self.switch = switch;
        self.sync.set_share(switch && self.right);
    }

    /// Whether the switch counts on this connection.
    pub fn may_share(&self) -> bool {
        self.right
    }

    /// Where the host keeps `Actions::memory` (and finds it for `start`).
    pub fn memory_key(&self) -> String {
        memory_key(&self.relay_id, &self.name)
    }
}

/// Said instead of a proof when the host gave the session no binding.
const NO_BINDING: &str = "This connection cannot be checked. Nothing was sent.";

/// What a stretched password proves itself with. An account without a password
/// sends none (a recent sign-in through a provider, or a code, stands in for it).
fn secret_of(master: Option<&[u8; 32]>) -> Option<Vec<u8>> {
    master.map(|m| derive_from_master(m).auth_secret.to_vec())
}

/// `AccountSession::memory_key` before there is one: `relay hex|name`.
pub fn memory_key(relay_id: &[u8; 16], name: &str) -> String {
    format!("{}|{}", hex(relay_id), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Vault;
    use libsignal_protocol::IdentityKeyPair;

    const RELAY: [u8; 16] = [7; 16];
    const ME: [u8; 16] = [1; 16];

    fn info(needs_2fa: bool) -> AccountInfo {
        AccountInfo {
            id: ME,
            name: "me".into(),
            scopes: Vec::new(),
            needs_2fa,
            totp_enabled: false,
        }
    }

    fn session(password_based: bool, needs_2fa: bool) -> (AccountSession, Actions) {
        let signed = SignedIn {
            relay_id: RELAY,
            name: "me".into(),
            vault: Vault::create(RELAY, "me"),
            identity: IdentityKeyPair::generate(&mut crate::rng()),
            recovery: None,
            binding: None,
            keyed: false,
            login_key: None,
            blobs: Vec::new(),
        };
        AccountSession::start(
            signed,
            &info(needs_2fa),
            LogMemory::default(),
            false,
            password_based,
            voipc_protocol::codec::PROTOCOL_VERSION,
        )
    }

    /// A session on a relay of its own: the ask budget goes by relay, for the whole run.
    fn fresh() -> AccountSession {
        let relay = crate::aead::random::<16>();
        let signed = SignedIn {
            relay_id: relay,
            name: "me".into(),
            vault: Vault::create(relay, "me"),
            identity: IdentityKeyPair::generate(&mut crate::rng()),
            recovery: None,
            binding: None,
            keyed: false,
            login_key: None,
            blobs: Vec::new(),
        };
        AccountSession::start(
            signed,
            &info(false),
            LogMemory::default(),
            false,
            true,
            voipc_protocol::codec::PROTOCOL_VERSION,
        )
        .0
    }

    fn asked_msg(pair: u64, new: &crate::pair::PairRequest) -> AccountReply {
        AccountReply::PairAsked {
            pair,
            commitment: new.commitment().to_vec(),
        }
    }

    /// Up to the person's yes to looking: the key that went out.
    fn looked(s: &mut AccountSession, pair: u64, new: &crate::pair::PairRequest) -> Vec<u8> {
        s.on_reply(&asked_msg(pair, new));
        let a = s.pair_look(pair);
        let [ClientMessage::Account(AccountRequest::PairNonce { nonce, .. })] = &a.send[..] else {
            panic!("no answer: {:?}", a.send)
        };
        nonce.clone()
    }

    /// Up to the prompt that wants the code typed: the code the new device shows.
    fn at_the_code(
        s: &mut AccountSession,
        pair: u64,
        new: &mut crate::pair::PairRequest,
    ) -> String {
        let raw = looked(s, pair, new);
        let shown = new.take_answer(&raw).unwrap();
        let (ephemeral, blind) = new.reveal();
        let a = s.on_reply(&AccountReply::PairRevealed {
            pair,
            ephemeral,
            blind,
        });
        assert!(a.send.is_empty(), "nothing leaves before the person types");
        assert_eq!(a.emit[0].0, "account-pair-ask");
        shown
    }

    fn declined(a: &Actions, pair: u64) -> bool {
        matches!(&a.send[..], [ClientMessage::Account(AccountRequest::PairDecline { pair: p })] if *p == pair)
    }

    /// W1-8: an answer that goes out unseen lets a relay retry until a code matches.
    #[test]
    fn no_answer_leaves_before_the_person_agrees_to_look() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        let a = s.on_reply(&asked_msg(5, &new));
        assert!(
            a.send.is_empty(),
            "sent before the person agreed: {:?}",
            a.send
        );
        assert_eq!(a.emit[0].0, "account-pair-look");
        assert_eq!(a.emit[0].1["pair"], 5);
        let a = s.pair_look(5);
        assert!(
            matches!(
                &a.send[..],
                [ClientMessage::Account(AccountRequest::PairNonce {
                    pair: 5,
                    ..
                })]
            ),
            "{:?}",
            a.send
        );
        assert!(s.pair_look(5).send.is_empty(), "one answer per ask");
        assert!(s.pair_look(6).send.is_empty(), "and only to this ask");
    }

    #[test]
    fn a_no_to_looking_declines() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        s.on_reply(&asked_msg(5, &new));
        assert!(declined(&s.pair_decline(5), 5));
        assert!(s.pair_look(5).send.is_empty(), "it is over");
        assert!(s.pair_decline(5).send.is_empty());
    }

    #[test]
    fn a_reveal_before_the_look_shows_nothing() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        s.on_reply(&asked_msg(5, &new));
        let (ephemeral, blind) = new.reveal();
        let a = s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral,
            blind,
        });
        assert!(
            !a.emit.iter().any(|(n, _)| *n == "account-pair-ask"),
            "asked"
        );
        assert!(a.send.is_empty());
    }

    /// The old device never shows the code: a stale or fake prompt has nothing to agree to.
    #[test]
    fn the_old_device_asks_for_the_code_and_does_not_show_it() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        let raw = looked(&mut s, 5, &new);
        let shown = new.take_answer(&raw).unwrap();
        let (ephemeral, blind) = new.reveal();
        let a = s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral,
            blind,
        });
        let (name, payload) = &a.emit[0];
        assert_eq!(*name, "account-pair-ask");
        assert!(
            !payload.to_string().contains(&shown),
            "the code is on the old device's screen: {payload}"
        );
    }

    #[test]
    fn the_vault_key_goes_only_on_the_code_the_new_device_shows() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        let shown = at_the_code(&mut s, 5, &mut new);
        let wrong = if shown == "000000" {
            "000001"
        } else {
            "000000"
        };
        let a = s.pair_answer(5, wrong);
        assert!(
            a.send.is_empty(),
            "a wrong code handed something over: {:?}",
            a.send
        );
        // Spaces are no typo
        let a = s.pair_answer(5, &format!(" {} {} ", &shown[..3], &shown[3..]));
        let [ClientMessage::Account(AccountRequest::PairApprove { pair: 5, wrapped })] =
            &a.send[..]
        else {
            panic!("no key: {:?}", a.send)
        };
        assert_eq!(new.open(wrapped, &s.relay_id, "me"), Some(*s.dek));
        assert!(s.pair_answer(5, &shown).send.is_empty(), "answered once");
    }

    /// W1-3: the code covers this key, so the wrap has to come from it.
    #[test]
    fn the_wrap_comes_from_the_key_that_answered() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        let raw = looked(&mut s, 5, &new);
        let shown = new.take_answer(&raw).unwrap();
        let (ephemeral, blind) = new.reveal();
        s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral,
            blind,
        });
        let a = s.pair_answer(5, &shown);
        let [ClientMessage::Account(AccountRequest::PairApprove { wrapped, .. })] = &a.send[..]
        else {
            panic!("no key: {:?}", a.send)
        };
        assert_eq!(&wrapped[1..33], &raw[..]);
    }

    /// The owner's rule: a typo may be retried three times, and then it says no
    /// and warns, with nothing handed over.
    #[test]
    fn three_retries_of_a_wrong_code_then_it_declines_and_warns() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        let shown = at_the_code(&mut s, 5, &mut new);
        let wrong = if shown == "000000" {
            "000001"
        } else {
            "000000"
        };
        for left in [3, 2, 1] {
            let a = s.pair_answer(5, wrong);
            assert!(a.send.is_empty(), "{:?}", a.send);
            assert_eq!(a.emit[0].0, "account-pair-ask", "asked again");
            assert_eq!(a.emit[0].1["left"], left);
            assert_eq!(a.emit[0].1["pair"], 5);
        }
        let a = s.pair_answer(5, wrong);
        assert!(declined(&a, 5), "{:?}", a.send);
        assert_eq!(a.emit[0].0, "account-pair-ended");
        assert_eq!(a.emit[0].1["wrong"], true, "the person is warned");
        assert!(
            s.pair_answer(5, &shown).send.is_empty(),
            "too late for the right one"
        );
    }

    /// The control for the rule above: the last retry can still be the right code.
    #[test]
    fn the_right_code_on_the_last_retry_still_counts() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        let shown = at_the_code(&mut s, 5, &mut new);
        let wrong = if shown == "000000" {
            "000001"
        } else {
            "000000"
        };
        for _ in 0..3 {
            s.pair_answer(5, wrong);
        }
        let a = s.pair_answer(5, &shown);
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::PairApprove {
                pair: 5,
                ..
            })]
        ));
        assert_eq!(a.emit[0].0, "account-pair-ended", "the prompt closes");
        assert_eq!(a.emit[0].1["handed"], true);
    }

    #[test]
    fn a_no_at_the_code_declines() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        at_the_code(&mut s, 5, &mut new);
        assert!(declined(&s.pair_decline(5), 5));
    }

    /// The attack: a prompt left over from a pairing that ended, answered when a
    /// new one holds the same id, with the relay's key behind it.
    #[test]
    fn a_prompt_for_an_ended_pairing_cannot_answer_the_next() {
        let mut s = fresh();
        let mut honest = crate::pair::PairRequest::new();
        let shown = at_the_code(&mut s, 5, &mut honest);
        s.on_reply(&AccountReply::PairEnded { pair: 5 });
        let mut relays = crate::pair::PairRequest::new();
        at_the_code(&mut s, 5, &mut relays);
        let a = s.pair_answer(5, &shown);
        assert!(
            a.send.is_empty(),
            "the new device's code opened the relay's ask: {:?}",
            a.send
        );
    }

    #[test]
    fn a_swapped_key_is_declined_and_the_person_told() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        looked(&mut s, 5, &new);
        // A relay revealing a key of its own under the commitment it was shown
        let (theirs, blind) = crate::pair::PairRequest::new().reveal();
        let a = s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral: theirs,
            blind,
        });
        assert!(declined(&a, 5), "{:?}", a.send);
        assert_eq!(
            a.emit[0].0, "account-pair-ended",
            "the miss is not invisible"
        );
        assert_eq!(a.emit[0].1["looked"], true);
        assert!(s.pair_answer(5, "000000").send.is_empty());
    }

    #[test]
    fn a_second_reveal_changes_nothing() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        let shown = at_the_code(&mut s, 5, &mut new);
        let (ephemeral, blind) = new.reveal();
        let a = s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral,
            blind,
        });
        assert!(!a.emit.iter().any(|(n, _)| *n == "account-pair-ask"));
        assert!(matches!(
            &s.pair_answer(5, &shown).send[..],
            [ClientMessage::Account(AccountRequest::PairApprove { .. })]
        ));
    }

    #[test]
    fn a_second_ask_waits_its_turn_and_an_ended_one_goes() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        looked(&mut s, 5, &new);
        let a = s.on_reply(&asked_msg(6, &new));
        assert!(declined(&a, 6), "{:?}", a.send);
        assert!(a.emit.is_empty(), "no prompt for it");
        let a = s.on_reply(&AccountReply::PairEnded { pair: 5 });
        assert_eq!(a.emit[0].0, "account-pair-ended");
        assert_eq!(
            a.emit[0].1["looked"], true,
            "a key was out and no code followed"
        );
        looked(&mut s, 7, &new);
    }

    #[test]
    fn an_ask_that_ends_unlooked_warns_of_nothing() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        s.on_reply(&asked_msg(5, &new));
        let a = s.on_reply(&AccountReply::PairEnded { pair: 5 });
        assert_eq!(a.emit[0].1["looked"], false, "nothing was out");
        assert_eq!(a.emit[0].1["typing"], false);
    }

    /// A relay can take the field away just as it asks the new device whether the code
    /// took: going quietly, that looks like the code being taken. So it is said.
    #[test]
    fn an_ask_that_ends_at_the_code_says_nothing_was_handed_over() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        at_the_code(&mut s, 6, &mut new);
        let a = s.on_reply(&AccountReply::PairEnded { pair: 6 });
        assert_eq!(a.emit[0].0, "account-pair-ended");
        assert_eq!(a.emit[0].1["looked"], false, "the code came");
        assert_eq!(a.emit[0].1["typing"], true);
        // And the same when nobody ended it
        let mut new = crate::pair::PairRequest::new();
        at_the_code(&mut s, 7, &mut new);
        s.pairing.as_mut().unwrap().since -= PAIR_EXPIRY_MS + 1;
        let a = s.tick();
        let (_, ended) = a
            .emit
            .iter()
            .find(|(n, _)| *n == "account-pair-ended")
            .expect("it never expired");
        assert_eq!(ended["typing"], true);
    }

    /// The control: the honest end of a pairing brings no such warning.
    #[test]
    fn a_handed_key_is_no_ask_ended_at_the_code() {
        let mut s = fresh();
        let mut new = crate::pair::PairRequest::new();
        let shown = at_the_code(&mut s, 6, &mut new);
        let a = s.pair_answer(6, &shown);
        assert_eq!(a.emit[0].1["handed"], true);
        assert!(a.emit[0].1["typing"].is_null());
        // The relay's own `PairEnded` follows it, and has nothing left to end
        let a = s.on_reply(&AccountReply::PairEnded { pair: 6 });
        assert!(!a.emit.iter().any(|(n, _)| *n == "account-pair-ended"));
    }

    /// "Asking again after a death fails within a second": an ask whose new device
    /// died with no `PairEnded` kept the next one declined, for good.
    #[test]
    fn an_ask_nobody_ended_goes_from_tick_and_the_next_is_heard() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        s.on_reply(&asked_msg(5, &new));
        assert!(
            !s.tick()
                .emit
                .iter()
                .any(|(n, _)| *n == "account-pair-ended"),
            "not yet"
        );
        assert!(declined(&s.on_reply(&asked_msg(6, &new)), 6), "still open");
        s.pairing.as_mut().unwrap().since -= PAIR_EXPIRY_MS + 1;
        let a = s.tick();
        let (_, ended) = a
            .emit
            .iter()
            .find(|(n, _)| *n == "account-pair-ended")
            .expect("it never expired");
        assert_eq!(ended["pair"], 5);
        assert_eq!(ended["looked"], false);
        let a = s.on_reply(&asked_msg(7, &new));
        assert_eq!(
            a.emit[0].0, "account-pair-look",
            "the next ask reaches the person"
        );
    }

    /// A key out with no reveal behind it: someone may be trying codes. It must
    /// not go unseen when the relay simply stays silent.
    #[test]
    fn a_look_held_with_no_reveal_expires_and_warns() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        looked(&mut s, 5, &new);
        s.pairing.as_mut().unwrap().since -= PAIR_EXPIRY_MS + 1;
        let a = s.tick();
        let (_, ended) = a
            .emit
            .iter()
            .find(|(n, _)| *n == "account-pair-ended")
            .expect("it never expired");
        assert_eq!(ended["looked"], true);
    }

    /// The relay's limit binds an honest relay only. Past this one a hostile relay
    /// gets a no and no prompt, so the window stays usable.
    #[test]
    fn asks_past_the_budget_are_declined_with_one_notice() {
        let mut s = fresh();
        let new = crate::pair::PairRequest::new();
        for pair in 1..=3 {
            let a = s.on_reply(&asked_msg(pair, &new));
            assert_eq!(a.emit[0].0, "account-pair-look", "ask {pair}");
            assert!(declined(&s.pair_decline(pair), pair));
        }
        let a = s.on_reply(&asked_msg(4, &new));
        assert!(declined(&a, 4), "{:?}", a.send);
        assert_eq!(a.emit.len(), 1, "one notice");
        assert_eq!(a.emit[0].0, "account-pair-limit");
        let a = s.on_reply(&asked_msg(5, &new));
        assert!(declined(&a, 5));
        assert!(a.emit.is_empty(), "and only one");
        assert!(s.pair_look(5).send.is_empty(), "no prompt stands behind it");
    }

    /// Per relay and past a reconnect, with its own clock: a new session is no new budget.
    #[test]
    fn the_budget_outlives_the_connection_and_refills_one_per_ten_minutes() {
        let relay = crate::aead::random::<16>();
        let t = 1_000_000_000_000u64;
        for _ in 0..3 {
            assert_eq!(spend_pair_ask(relay, t), PairBudget::Ask);
        }
        assert_eq!(spend_pair_ask(relay, t), PairBudget::SpentNow);
        assert_eq!(spend_pair_ask(relay, t + 1), PairBudget::Spent);
        assert_eq!(
            spend_pair_ask(relay, t + 599_000),
            PairBudget::Spent,
            "not yet"
        );
        assert_eq!(
            spend_pair_ask(relay, t + 601_000),
            PairBudget::Ask,
            "one back"
        );
        assert_eq!(spend_pair_ask(relay, t + 601_001), PairBudget::SpentNow);
        assert_eq!(
            spend_pair_ask(crate::aead::random::<16>(), t),
            PairBudget::Ask,
            "another relay has its own"
        );
    }

    fn sends(a: &Actions, what: &str) -> usize {
        a.send
            .iter()
            .filter(
                |m| matches!(m, ClientMessage::Account(r) if format!("{r:?}").starts_with(what)),
            )
            .count()
    }

    fn user(user_id: u32, account: [u8; 16], name: &str) -> UserInfo {
        UserInfo {
            user_id,
            username: name.into(),
            channel_id: 1,
            is_muted: false,
            is_deafened: false,
            is_screen_sharing: false,
            is_admin: false,
            shares_history: false,
            account: Some(account),
            is_moderator: false,
            badges: vec![],
        }
    }

    // ── Sharing with joiners: the switch and the right, on a real `AccountSync` ──

    const SHARE: &str = voipc_protocol::types::SHARE_HISTORY;

    fn held(scopes: &[&str]) -> AccountInfo {
        AccountInfo {
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            ..info(false)
        }
    }

    /// A session that wrote in `CONV` under a key of its own, so it has older keys to give.
    fn writer(switch: bool, scopes: &[&str], proto: u32) -> (AccountSession, Actions) {
        let relay = crate::aead::random::<16>();
        let vault = Vault::create(relay, "me");
        let logkey = crate::log::LogKey::generate();
        let blobs = vec![voipc_protocol::types::VaultBlob {
            version: 1,
            ..vault.seal_item(crate::sync::ITEM_LOGKEY, 1, &logkey.to_bytes())
        }];
        let signed = SignedIn {
            relay_id: relay,
            name: "me".into(),
            vault,
            identity: IdentityKeyPair::generate(&mut crate::rng()),
            recovery: None,
            binding: None,
            keyed: false,
            login_key: None,
            blobs,
        };
        let (mut s, started) = AccountSession::start(
            signed,
            &held(scopes),
            LogMemory::default(),
            switch,
            true,
            proto,
        );
        s.set_prefs(Prefs {
            cloud: true,
            asked: true,
        });
        s.on_reply(&AccountReply::LogJoined {
            conv: CONV.to_string(),
        });
        s.on_reply(&AccountReply::Wraps {
            conv: CONV.to_string(),
            wraps: Vec::new(),
        });
        s.sync
            .send_channel(CONV, crate::envelope::envelope("m", "hello", None), 1, None);
        // Nobody else is a member yet: the key that goes out is for ourselves
        if proto >= voipc_protocol::types::KEPT_CHAINS_SINCE {
            s.on_reply(&AccountReply::OwnChains {
                conv: CONV.to_string(),
                newest: None,
                chains: Vec::new(),
                more: false,
            });
            s.on_reply(&AccountReply::OwnBuckets {
                conv: CONV.to_string(),
                buckets: Vec::new(),
                more: false,
            });
            s.on_reply(&AccountReply::LogMemberIdsFound {
                conv: CONV.to_string(),
                ids: Vec::new(),
                more: false,
            });
            s.on_reply(&AccountReply::ChainStored {
                conv: CONV.to_string(),
                epoch: 1 << 12,
                behind: false,
            });
        } else {
            s.on_reply(&AccountReply::LogMembersFound {
                conv: CONV.to_string(),
                members: Vec::new(),
            });
        }
        (s, started)
    }

    const CONV: &str = "c:1";

    /// Someone joins the channel's log: does this writer hand over its older keys?
    fn gives_older_keys(s: &mut AccountSession) -> bool {
        let identity = IdentityKeyPair::generate(&mut crate::rng());
        let logkey = crate::log::LogKey::generate();
        let joiner = [0x55; 16];
        s.on_reply(&AccountReply::LogPending {
            conv: CONV.to_string(),
            joiners: vec![joiner],
        });
        let a = s.on_reply(&AccountReply::LogKeysFound {
            keys: vec![voipc_protocol::messages::LogKeyInfo {
                account: joiner,
                name: "newcomer".into(),
                identity: identity.public_key().serialize().to_vec(),
                logkey: logkey.public(),
                sig: logkey.endorse(&identity),
            }],
        });
        let put = |m: &ClientMessage, older: bool| {
            matches!(
                m,
                ClientMessage::Account(AccountRequest::ChainPut { step, wraps, .. })
                    if !wraps.is_empty() && step.is_none() == older
            )
        };
        let given = sends(&a, "EpochPut") > 0 || a.send.iter().any(|m| put(m, true));
        assert!(
            given || sends(&a, "LogMembers") > 0 || a.send.iter().any(|m| put(m, false)),
            "the control: it did answer, with a new key or a fresh step: {:?}",
            a.send
        );
        given
    }

    fn told_right(a: &Actions) -> Vec<bool> {
        a.emit
            .iter()
            .filter(|(n, _)| *n == "share-right")
            .map(|(_, v)| v["may"].as_bool().unwrap())
            .collect()
    }

    fn flag_sent(a: &Actions) -> Vec<bool> {
        a.send
            .iter()
            .filter_map(|m| match m {
                ClientMessage::SetHistorySharing { enabled } => Some(*enabled),
                _ => None,
            })
            .collect()
    }

    const NOW: u32 = voipc_protocol::types::SHARE_HISTORY_SINCE;

    #[test]
    fn older_keys_go_by_switch_and_right() {
        for (switch, scopes, want) in [
            (true, &[SHARE][..], true),
            (true, &["*"], true),
            (false, &[SHARE], false),
            (true, &[], false),
            (false, &[], false),
        ] {
            let (mut s, started) = writer(switch, scopes, NOW);
            assert_eq!(gives_older_keys(&mut s), want, "{switch} {scopes:?}");
            assert_eq!(told_right(&started), [!scopes.is_empty()], "{scopes:?}");
        }
    }

    #[test]
    fn losing_the_privilege_stops_older_keys_at_once() {
        let (mut s, _) = writer(true, &[SHARE], NOW);
        assert!(s.may_share());
        let a = s.on_reply(&AccountReply::Info(held(&[])));
        assert_eq!(told_right(&a), [false]);
        assert!(flag_sent(&a).is_empty(), "the relay cleared it itself");
        assert!(!s.may_share());
        assert!(!gives_older_keys(&mut s));
    }

    #[test]
    fn gaining_the_privilege_with_the_switch_on_says_so() {
        let (mut s, _) = writer(true, &[], NOW);
        assert!(!gives_older_keys(&mut s));
        let (mut s, _) = writer(true, &[], NOW);
        let a = s.on_reply(&AccountReply::Info(held(&[SHARE])));
        assert_eq!(told_right(&a), [true]);
        assert_eq!(flag_sent(&a), [true], "only the app ever asks for the flag");
        assert!(gives_older_keys(&mut s));
        let a = s.on_reply(&AccountReply::Info(held(&[SHARE])));
        assert!(
            told_right(&a).is_empty() && flag_sent(&a).is_empty(),
            "no change"
        );

        // The control: with the switch off the relay hears nothing, and nothing is offered
        let (mut s, _) = writer(false, &[], NOW);
        let a = s.on_reply(&AccountReply::Info(held(&[SHARE])));
        assert_eq!(told_right(&a), [true]);
        assert!(flag_sent(&a).is_empty());
        assert!(!gives_older_keys(&mut s));
    }

    #[test]
    fn an_older_relay_goes_by_the_switch_alone() {
        let (mut s, started) = writer(true, &[], NOW - 1);
        assert_eq!(told_right(&started), [true]);
        assert!(gives_older_keys(&mut s));
        let (mut s, _) = writer(false, &[], NOW - 1);
        assert!(!gives_older_keys(&mut s));
    }

    /// One server's account cannot be switched into sharing by a change meant for all.
    #[test]
    fn a_set_share_with_no_right_stays_off() {
        let (mut s, _) = writer(false, &[], NOW);
        s.set_share(true);
        assert!(!gives_older_keys(&mut s));
        let (mut s, _) = writer(false, &[SHARE], NOW);
        s.set_share(true);
        assert!(gives_older_keys(&mut s));
        let (mut s, _) = writer(true, &[SHARE], NOW);
        s.set_share(false);
        assert!(!gives_older_keys(&mut s));
    }

    /// W2-31: the page goes by the number to tell whose an answer is, a refusal most of all.
    /// W3: on a keyed account the password goes as a step-up with its login key, and the
    /// request after it without any secret; a refusal of the step-up is the request's own.
    #[test]
    fn a_keyed_account_steps_up_with_its_key_and_sends_no_secret() {
        use crate::bind::{login_ok, Binding};
        let session_at = |keyed: bool, login_key: Option<[u8; 32]>, proto: u32| {
            let signed = SignedIn {
                relay_id: RELAY,
                name: "me".into(),
                vault: Vault::create(RELAY, "me"),
                identity: IdentityKeyPair::generate(&mut crate::rng()),
                recovery: None,
                binding: Some(Binding::Tls([5; 32])),
                keyed,
                login_key,
                blobs: Vec::new(),
            };
            AccountSession::start(
                signed,
                &info(false),
                LogMemory::default(),
                false,
                true,
                proto,
            )
            .0
        };
        let master = [3u8; 32];
        let key = LoginKey::from_master(&master).public_key();

        let mut s = session_at(true, None, 22);
        let a = s.delete_account(Some(&master), Some("123 456".into()), None);
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::KeyChallenge)]
        ));
        let a = s.on_reply(&AccountReply::KeyChallenge {
            challenge: "tok".into(),
        });
        let [ClientMessage::Account(AccountRequest::KeyStepUp {
            signature,
            totp,
            web: false,
            ..
        })] = &a.send[..]
        else {
            panic!("{:?}", a.send)
        };
        assert!(login_ok(
            &key,
            &RELAY,
            "me",
            "tok",
            &Binding::Tls([5; 32]),
            signature
        ));
        assert_eq!(totp.as_deref(), Some("123456"));
        let a = s.on_reply(&AccountReply::SteppedUp);
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::DeleteAccount { secret, totp: None, .. })] if secret.is_empty()
        ));
        // A refused step-up reaches the page as the request's
        s.provider_unlink(ProviderKind::Discord, Some(&master), None, None);
        s.on_reply(&AccountReply::KeyChallenge {
            challenge: "tok".into(),
        });
        let a = s.on_reply(&AccountReply::Error {
            request: "KeyStepUp".into(),
            reason: "Wrong password.".into(),
        });
        let (_, page) = a.emit.iter().find(|(n, _)| *n == "account-reply").unwrap();
        assert_eq!(page["Error"]["request"], "ProviderUnlink");
        assert!(a.send.is_empty());
        // A relay before 22 gets the secret, as before
        let mut s = session_at(true, None, 21);
        let a = s.delete_account(Some(&master), None, None);
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::DeleteAccount { secret, .. })] if secret.len() == 32
        ));

        // A sign-in with the secret at 22: the move to the key goes first thing
        let mut s = session_at(false, Some(key), 22);
        let a = s.after_connect();
        let Some(ClientMessage::Account(AccountRequest::LoginKeySet {
            login_key,
            pass_slot: None,
            ..
        })) = a.send.iter().find(|m| {
            matches!(
                m,
                ClientMessage::Account(AccountRequest::LoginKeySet { .. })
            )
        })
        else {
            panic!("no move to the key")
        };
        assert_eq!(login_key[..], key[..]);
        // Refused: the account stays as it was, and the page hears nothing of it
        let a = s.on_reply(&AccountReply::Error {
            request: "LoginKeySet".into(),
            reason: "no".into(),
        });
        assert!(a.emit.is_empty() && a.send.is_empty());
        let a = s.delete_account(Some(&master), None, None);
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::DeleteAccount { secret, .. })] if secret.len() == 32
        ));
    }

    /// W1-24: from 22 the app shows the code it derives from its own end of the connection,
    /// never the one the relay sends (a server passing the flow on would send the relay's).
    #[test]
    fn a_link_shows_the_code_of_this_end_of_the_connection() {
        use crate::bind::{provider_code, Binding};
        let shown = |b: Option<Binding>, proto: u32| {
            let signed = SignedIn {
                relay_id: RELAY,
                name: "me".into(),
                vault: Vault::create(RELAY, "me"),
                identity: IdentityKeyPair::generate(&mut crate::rng()),
                recovery: None,
                binding: b,
                keyed: false,
                login_key: None,
                blobs: Vec::new(),
            };
            let (mut s, _) = AccountSession::start(
                signed,
                &info(false),
                LogMemory::default(),
                false,
                true,
                proto,
            );
            let a = s.on_reply(&AccountReply::ProviderBrowser {
                url: "https://discord.com/x?state=s".into(),
                code: "111111".into(),
            });
            let (_, v) = a.emit.iter().find(|(n, _)| *n == "account-reply").unwrap();
            v.clone()
        };
        let ours = provider_code(&[3; 32], b"https://discord.com/x?state=s");
        assert_ne!(ours, "111111");
        assert_eq!(
            shown(Some(Binding::Tls([3; 32])), 22)["ProviderBrowser"]["code"],
            ours.as_str()
        );
        assert_eq!(
            shown(Some(Binding::Web), 22)["ProviderBrowser"]["code"],
            "111111"
        );
        assert_eq!(
            shown(Some(Binding::Tls([3; 32])), 21)["ProviderBrowser"]["code"],
            "111111",
            "an older relay's code is the only one there is"
        );
        let none = shown(None, 22);
        assert!(none.get("ProviderBrowser").is_none(), "{none}");
        assert_eq!(none["Error"]["request"], "ProviderStart");
    }

    #[test]
    fn a_numbered_answer_reaches_the_page_as_itself_with_its_number() {
        let (mut s, _) = session(true, false);
        let inner = AccountReply::Error {
            request: "Admin".into(),
            reason: "No such run.".into(),
        };
        let numbered = voipc_protocol::codec::encode_asked(9, &inner).unwrap();
        let a = s.on_reply(&numbered);
        let (_, value) = a.emit.iter().find(|(n, _)| *n == "account-reply").unwrap();
        assert_eq!(value["ask"], 9);
        assert_eq!(value["Error"]["reason"], "No such run.");
        // The control, and what is not a reply at all
        let plain = s.on_reply(&inner);
        let (_, value) = plain
            .emit
            .iter()
            .find(|(n, _)| *n == "account-reply")
            .unwrap();
        assert!(value.get("ask").is_none());
        let junk = AccountReply::Asked {
            ask: 1,
            reply: vec![0xff; 8],
        };
        assert!(s.on_reply(&junk).emit.is_empty());
    }

    /// A conversation's tombstone goes only after the relay purged it: sent
    /// before, the purge would take it too. A purge of everything sends none.
    #[test]
    fn a_purge_sends_its_tombstone_after_the_relay_did_it() {
        let (mut s, _) = session(true, false);
        s.set_prefs(Prefs {
            cloud: true,
            asked: true,
        });
        let conv = format!("c:{}", "ab".repeat(16));
        let a = s.purge(Some(&conv));
        assert_eq!(sends(&a, "LogPurge"), 1);
        assert!(
            s.on_reply(&AccountReply::LogPurged {
                conv: Some("c:other".into()),
                entries: 0
            })
            .send
            .is_empty(),
            "not one we asked for"
        );
        let a = s.on_reply(&AccountReply::LogPurged {
            conv: Some(conv.clone()),
            entries: 2,
        });
        assert!(
            !a.send.is_empty(),
            "the tombstone is on its way (its first ask)"
        );
        assert!(a.emit.iter().any(|(n, _)| *n == "account-reply"));
        assert!(
            s.on_reply(&AccountReply::LogPurged {
                conv: Some(conv),
                entries: 0
            })
            .send
            .is_empty(),
            "once"
        );
        s.purge(None);
        assert!(s
            .on_reply(&AccountReply::LogPurged {
                conv: None,
                entries: 5
            })
            .send
            .is_empty());
    }

    #[test]
    fn a_password_sign_in_remembers_the_device_once_and_hands_its_key_over() {
        let (mut s, started) = session(true, false);
        assert_eq!(started.emit[0].0, "account-signed-in");
        let a = s.after_connect();
        assert_eq!(sends(&a, "DeviceChallenge"), 1);
        // An Info while the challenge is out starts no second enrolment.
        let info_reply = AccountReply::Info(info(false));
        assert_eq!(sends(&s.on_reply(&info_reply), "DeviceChallenge"), 0);
        let a = s.on_reply(&AccountReply::DeviceChallenge {
            challenge: "c".into(),
        });
        assert_eq!(
            sends(&a, "DeviceAdd"),
            1,
            "the challenge is answered, nothing emitted"
        );
        assert!(a.emit.is_empty());
        let a = s.on_reply(&AccountReply::DeviceAdded);
        let kept = a.remember.expect("the key to keep");
        assert_eq!((kept.relay_id, kept.name.as_str()), (RELAY, "me"));
        assert!(
            s.on_reply(&AccountReply::DeviceAdded).remember.is_none(),
            "once"
        );
        assert_eq!(
            sends(&s.on_reply(&info_reply), "DeviceChallenge"),
            0,
            "remembered already"
        );
    }

    #[test]
    fn a_role_that_waits_for_codes_asks_for_their_setup_not_for_the_device() {
        let (mut s, _) = session(true, true);
        let a = s.after_connect();
        assert_eq!(
            (sends(&a, "TotpSetup"), sends(&a, "DeviceChallenge")),
            (1, 0)
        );
        // Codes on: the relay forgot device keys; the next Info remembers this one.
        s.on_reply(&AccountReply::TotpEnabled {
            recovery_codes: Vec::new(),
        });
        assert_eq!(
            sends(
                &s.on_reply(&AccountReply::Info(info(false))),
                "DeviceChallenge"
            ),
            1
        );
    }

    #[test]
    fn a_device_key_sign_in_never_enrols() {
        let (mut s, _) = session(false, false);
        assert_eq!(sends(&s.after_connect(), "DeviceChallenge"), 0);
        assert_eq!(
            sends(
                &s.on_reply(&AccountReply::Info(info(false))),
                "DeviceChallenge"
            ),
            0
        );
    }

    #[test]
    fn identities_of_report_takers_are_checked() {
        let (mut s, _) = session(false, false);
        let key = || {
            IdentityKeyPair::generate(&mut crate::rng())
                .public_key()
                .serialize()
                .to_vec()
        };
        let (k1, k2) = (key(), key());
        let taker = |user_id, account, name: &str| ReportTaker {
            user_id,
            account,
            name: name.into(),
        };
        assert!(
            s.check_identity(5, &k1).emit.is_empty() && s.check_identity(5, &k2).emit.is_empty(),
            "on no roster and not noted: nothing checks them"
        );
        s.note_takers(&[
            taker(Some(5), Some([5; 16]), "bob"),
            // Neither of these is anyone to check, by id or by account
            taker(None, Some([6; 16]), "away"),
            taker(Some(7), None, "admin"),
        ]);
        assert!(s.check_identity(5, &k1).emit.is_empty(), "pinned");
        let a = s.check_identity(5, &k2);
        assert_eq!(a.emit.len(), 1);
        assert_eq!(
            (
                a.emit[0].0,
                a.emit[0].1["user_id"].as_u64(),
                a.emit[0].1["name"].as_str()
            ),
            ("identity-key-changed", Some(5), Some("bob"))
        );
        s.set_prefs(Prefs {
            cloud: true,
            asked: true,
        });
        assert!(
            s.kept_for(5),
            "and a copy is kept for them, as for a roster"
        );
        assert!(!s.kept_for(7), "the token has no account");
    }

    #[test]
    fn identities_are_checked_for_the_accounts_the_rosters_name() {
        let (mut s, _) = session(false, false);
        let key = || {
            IdentityKeyPair::generate(&mut crate::rng())
                .public_key()
                .serialize()
                .to_vec()
        };
        let (k1, k2) = (key(), key());
        assert!(
            s.check_identity(5, &k1).emit.is_empty(),
            "a guest: nothing to check"
        );
        s.note_roster(&[user(5, [5; 16], "bob")]);
        assert!(
            s.check_identity(5, &k1).emit.is_empty(),
            "first sight is pinned"
        );
        assert!(s.check_identity(5, &k1).emit.is_empty());
        let a = s.check_identity(5, &k2);
        assert_eq!(a.emit.len(), 1);
        assert_eq!(
            (
                a.emit[0].0,
                a.emit[0].1["user_id"].as_u64(),
                a.emit[0].1["name"].as_str()
            ),
            ("identity-key-changed", Some(5), Some("bob"))
        );
        // "bob" again, under another account id: a change too.
        s.note_roster(&[user(6, [9; 16], "bob")]);
        assert_eq!(
            s.check_identity(6, &k2).emit.len(),
            1,
            "the name was another account's"
        );
        assert!(
            s.safety_number(6, &k1, Some(&k1)).is_err(),
            "a live key that is not the pin has no number"
        );
        assert!(s.safety_number(6, &k1, Some(&k2)).is_ok());
        assert!(s.safety_number(7, &k1, None).is_err(), "not an account");
    }

    /// A relay inventing an id for a pinned person, on the live path, where no roster has
    /// to name them: the post itself feeds the check.
    #[test]
    fn a_post_under_a_pinned_name_with_another_key_warns() {
        let (mut s, _) = session(false, false);
        let (k1, k2) = (vec![1u8; 33], vec![2u8; 33]);
        s.note_person(5, Some([5; 16]), "bob");
        assert!(s.check_identity(5, &k1).emit.is_empty());
        // Off the roster, an identity goes unchecked: why a first sight is checked at all
        assert!(s.check_identity(9999, &k2).emit.is_empty());
        s.note_person(9999, Some([5; 16]), "bob");
        let a = s.check_identity(9999, &k2);
        assert_eq!(a.emit.len(), 1);
        assert_eq!(a.emit[0].0, "identity-key-changed");
        assert_eq!(a.emit[0].1["user_id"], 9999);
    }

    #[test]
    fn a_known_name_as_a_guest_in_a_post_warns() {
        let (mut s, _) = session(false, false);
        s.note_person(5, Some([5; 16]), "bob");
        s.check_identity(5, &[1u8; 33]);
        let a = s.note_person(9999, None, "bob");
        assert_eq!(a.emit.len(), 1);
        assert_eq!(a.emit[0].1["as_guest"], true);
        // The control: a name nobody knows
        assert!(s.note_person(9998, None, "stranger").emit.is_empty());
    }

    #[test]
    fn a_keys_owed_target_is_checked_against_the_pins() {
        let (mut s, _) = session(false, false);
        let (k1, k2) = (vec![1u8; 33], vec![2u8; 33]);
        s.note_person(5, Some([5; 16]), "bob");
        s.check_identity(5, &k1);
        // A hello for an id only `KeysOwed` named, as a row: noted, then checked
        s.note_roster(&[user(6, [5; 16], "bob")]);
        assert!(s.check_identity(6, &k1).emit.is_empty(), "the pinned key");
        assert_eq!(s.check_identity(6, &k2).emit.len(), 1);
        assert_eq!(s.account_of(6), Some([5; 16]));
        assert_eq!(s.account_of(7), None);
    }

    #[test]
    fn copies_go_where_an_account_is_and_cloud_copies_are_on() {
        let (mut s, _) = session(false, false);
        s.note_roster(&[user(5, [5; 16], "bob")]);
        assert!(
            s.outgoing_dm(5, b"x".to_vec(), 1, None).send.is_empty(),
            "cloud copies are off"
        );
        assert!(!s.kept_for(5));
        assert!(s
            .kept_dm(&hex(&[5; 16]), b"x".to_vec(), 1, None, false)
            .is_err());
        assert!(
            s.kept_dm(&hex(&[5; 16]), b"x".to_vec(), 1, None, true)
                .is_ok(),
            "a report kept for this one message"
        );
        s.set_prefs(Prefs {
            cloud: true,
            asked: true,
        });
        assert!(s.kept_for(5) && !s.kept_for(6), "a guest has no log");
        assert!(
            s.outgoing_channel("", b"x".to_vec(), 1, None)
                .send
                .is_empty(),
            "no log in that channel"
        );
        assert!(s.kept_dm("zz", b"x".to_vec(), 1, None, false).is_err());
        assert_eq!(s.memory_key(), memory_key(&RELAY, "me"));
    }

    /// What the rosters and sessions show while the pages of pins are out waits, as a whole
    /// sign-in's worth of them may. Then it is decided against them, and the host hears the
    /// key jobs may go on, once.
    #[test]
    fn identities_wait_for_the_pages_of_pins() {
        let vault = Vault::create(RELAY, "me");
        // `item.pins` as an index of one page, which a build reads by its format
        let index = postcard::to_allocvec(&vec![1u64]).unwrap();
        let blobs = vec![vault.seal_item_as(crate::account::ITEM_PINS, 2, 2, &index)];
        let dek = vault.dek();
        let signed = SignedIn {
            relay_id: RELAY,
            name: "me".into(),
            vault,
            identity: IdentityKeyPair::generate(&mut crate::rng()),
            recovery: None,
            binding: None,
            keyed: false,
            login_key: None,
            blobs,
        };
        let (mut s, _) = AccountSession::start(
            signed,
            &info(false),
            LogMemory::default(),
            false,
            false,
            voipc_protocol::codec::PROTOCOL_VERSION,
        );
        assert!(!s.pins_in());
        assert!(!s.take_pins_in(), "still out");
        let a = s.after_connect();
        assert_eq!(sends(&a, "VaultPage"), 1);

        let (k1, k2) = (vec![1u8; 33], vec![2u8; 33]);
        s.note_person(5, Some([5; 16]), "bobby");
        assert!(s.check_identity(5, &k2).emit.is_empty(), "before its pin");
        assert!(
            s.note_person(6, None, "bobby").emit.is_empty(),
            "as a guest"
        );
        assert!(s.safety_number(5, &k1, None).is_err());

        let vault = Vault::from_dek(RELAY, "me", dek);
        let mut pins = crate::account::Pins::default();
        pins.check(&[5; 16], "bobby", &k1);
        let page = vault.seal_item("pins.0", 1, &pins.to_bytes());
        let a = s.on_reply(&AccountReply::VaultPageFound {
            k: "pins.0".into(),
            blob: Some(page),
        });
        assert!(s.take_pins_in());
        assert!(!s.take_pins_in(), "once");
        let told: Vec<&Value> = a
            .emit
            .iter()
            .filter(|(name, _)| *name == "identity-key-changed")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(told.len(), 2, "{told:?}");
        assert_eq!(told[0]["user_id"], 5);
        assert_eq!(told[1]["as_guest"], true);
    }

    /// Who the person writes to keeps the half open channels cannot fill, whichever way the
    /// words went; a safety number opened saves at once.
    #[test]
    fn a_direct_conversation_and_a_gated_channel_claim_the_reserved_half() {
        let (mut s, _) = session(false, false);
        s.note_person(5, Some([5; 16]), "bobby");
        s.note_direct(5);
        s.note_gated_people(&[[6; 16]]);
        s.outgoing_dm(5, b"x".to_vec(), 1, None);
        assert!(s.check_identity(5, &[1u8; 33]).send.is_empty(), "coalesced");
        let a = s.verified(5);
        assert_eq!(sends(&a, "VaultPut"), 1, "{:?}", a.send);
    }

    /// The front end starts from the list and hears each change from here, on
    /// both backends. The relay hears one sealed item, the person nothing.
    #[test]
    fn a_block_is_told_to_the_front_end_and_nobody_else() {
        let (mut s, started) = session(false, false);
        assert_eq!(started.emit[0].1["blocks"], json!([]));
        let key = format!("a:{}", hex(&[5; 16]));
        let a = s.set_block(&key, "bob", true).unwrap();
        assert_eq!(a.send.len(), 1);
        assert_eq!(sends(&a, "VaultPut"), 1, "{:?}", a.send);
        assert_eq!(a.emit[0].0, "account-blocks");
        assert_eq!(a.emit[0].1["blocks"], json!([[key, "bob"]]));
        assert!(
            s.set_block("nobody", "x", true).is_err(),
            "an error for the front end to show"
        );
        // The list goes with the next sign-in: from the vault, in `AccountSync`'s tests
        let a = s.set_block(&key, "bob", false).unwrap();
        assert_eq!(a.emit[0].1["blocks"], json!([]));
    }
}
