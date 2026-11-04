//! A signed-in account on one connection, without I/O: the stored-message log
//! and the pins (`sync`), remembering this device (`DeviceEnrol`), which user
//! here is which account (from the rosters), and what the front end hears of
//! it all. The desktop client and the browser (through wasm) only carry
//! messages in and out, emit what it says, and keep what it hands them. They
//! used to hold these rules in two copies, and the copies drifted.

use std::collections::HashMap;

use serde_json::{json, Value};
use voipc_protocol::conv::{hex, unhex16};
use voipc_protocol::messages::{AccountReply, AccountRequest, ClientMessage};
use voipc_protocol::types::{AccountInfo, ProviderKind, ReportTaker, UserInfo};
use zeroize::Zeroizing;

use crate::account::{
    derive_from_master, kdf_salt, recovery_text, reset_key, DeviceEnrol, PinCheck, SignedIn, Vault,
};
use crate::sync::{AccountSync, Event, LogMemory, Prefs};

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
}

impl Actions {
    fn sending(send: Vec<ClientMessage>) -> Actions {
        Actions {
            send,
            ..Default::default()
        }
    }
}

pub struct AccountSession {
    sync: AccountSync,
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
}

/// A pairing this device was asked for (`crate::pair`).
struct Pairing {
    pair: u64,
    commitment: Vec<u8>,
    nonce: Vec<u8>,
    /// Once revealed and checked: what the DEK would be wrapped to.
    ephemeral: Option<Vec<u8>>,
}

impl AccountSession {
    /// After `Authenticated`: what the sign-in left, the account it is, what
    /// this device kept of the log last time, and whether joiners of a
    /// channel's log get our older keys. Tells the front end it signed in.
    pub fn start(
        signed: SignedIn,
        info: &AccountInfo,
        memory: LogMemory,
        share: bool,
        password_based: bool,
    ) -> (AccountSession, Actions) {
        let (sync, first) = AccountSync::start(&signed, info.id, memory, share);
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
        };
        (
            s,
            Actions {
                emit: vec![("account-signed-in", signed_in)],
                ..Default::default()
            },
        )
    }

    /// Once the connection is up, and listed (so the front end's commands
    /// find it): what the sync asks first, then the second-factor setup a role
    /// waits for, or else remembering this device.
    pub fn after_connect(&mut self) -> Actions {
        let mut a = Actions::sending(std::mem::take(&mut self.first));
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

    /// The person's answer to `account-pair-ask`. Only after they compared the
    /// codes does the vault's key leave this device, and only to the key that
    /// was committed to before this device's nonce was known.
    pub fn pair_answer(&mut self, pair: u64, yes: bool) -> Actions {
        let Some(p) = self.pairing.take_if(|p| p.pair == pair) else {
            return Actions::default();
        };
        let wrapped = p.ephemeral.as_ref().filter(|_| yes).and_then(|ephemeral| {
            crate::pair::wrap_dek(
                ephemeral,
                &self.dek,
                &self.relay_id,
                &self.name,
                &p.commitment,
            )
        });
        Actions::sending(vec![ClientMessage::Account(match wrapped {
            Some(wrapped) => AccountRequest::PairApprove { pair, wrapped },
            None => AccountRequest::PairDecline { pair },
        })])
    }

    /// The pairing replies. `None`: not one.
    fn on_pair_reply(&mut self, reply: &AccountReply) -> Option<Actions> {
        match reply {
            AccountReply::PairAsked { pair, commitment } => {
                // One at a time: the person is looking at the first.
                if self.pairing.is_some() {
                    return Some(Actions::sending(vec![ClientMessage::Account(
                        AccountRequest::PairDecline { pair: *pair },
                    )]));
                }
                let nonce = crate::aead::random::<{ crate::pair::NONCE_LEN }>().to_vec();
                self.pairing = Some(Pairing {
                    pair: *pair,
                    commitment: commitment.clone(),
                    nonce: nonce.clone(),
                    ephemeral: None,
                });
                Some(Actions::sending(vec![ClientMessage::Account(
                    AccountRequest::PairNonce { pair: *pair, nonce },
                )]))
            }
            AccountReply::PairRevealed {
                pair,
                ephemeral,
                blind,
            } => {
                let p = self.pairing.as_mut().filter(|p| p.pair == *pair)?;
                if !crate::pair::reveal_ok(&p.commitment, ephemeral, blind) {
                    // Not the key it committed to: somebody is in the middle.
                    self.pairing = None;
                    return Some(Actions::sending(vec![ClientMessage::Account(
                        AccountRequest::PairDecline { pair: *pair },
                    )]));
                }
                let code = crate::pair::code(&p.commitment, &p.nonce, ephemeral);
                p.ephemeral = Some(ephemeral.clone());
                Some(Actions {
                    emit: vec![(
                        "account-pair-ask",
                        serde_json::json!({ "pair": pair, "code": code }),
                    )],
                    ..Default::default()
                })
            }
            AccountReply::PairEnded { pair } => {
                self.pairing.take_if(|p| p.pair == *pair)?;
                Some(Actions {
                    emit: vec![("account-pair-ended", serde_json::json!({ "pair": pair }))],
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
        &self,
        kind: ProviderKind,
        link: bool,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Actions {
        Actions::sending(vec![ClientMessage::Account(
            AccountRequest::ProviderStart {
                kind,
                link,
                secret: secret_of(master),
                totp,
                recovery_code,
            },
        )])
    }

    /// As for a link. `ProviderUnlinked` answers as `account-reply`.
    pub fn provider_unlink(
        &self,
        kind: ProviderKind,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Actions {
        Actions::sending(vec![ClientMessage::Account(
            AccountRequest::ProviderUnlink {
                kind,
                secret: secret_of(master),
                totp,
                recovery_code,
            },
        )])
    }

    /// The account's name here.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One `AccountReply`. What none of this answers goes to the front end
    /// as `account-reply`.
    pub fn on_reply(&mut self, reply: &AccountReply) -> Actions {
        if let Some(actions) = self.on_pair_reply(reply) {
            return actions;
        }
        if let Some(next) = self.enrol.as_ref().and_then(|e| e.on_reply(reply)) {
            return Actions::sending(vec![next]);
        }
        if let Some((send, events)) = self.sync.on_reply(reply) {
            let mut a = Actions::sending(send);
            self.events(events, &mut a);
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
            _ => {}
        }
        a.emit.push((
            "account-reply",
            serde_json::to_value(reply).unwrap_or(Value::Null),
        ));
        a
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
            match u.account {
                Some(account) => {
                    self.roster.insert(u.user_id, (account, u.username.clone()));
                }
                None if self.sync.knows_name(&u.username) => {
                    a.emit.push((
                        "identity-key-changed",
                        json!({ "user_id": u.user_id, "name": u.username, "as_guest": true }),
                    ));
                }
                None => {}
            }
        }
        a
    }

    /// An identity `user_id` showed — in a pre-key bundle, or in a session
    /// they opened (`VoipcIdentityStore::take_seen`) — against the pins.
    pub fn check_identity(&mut self, user_id: u32, key: &[u8]) -> Actions {
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
        match self.roster.get(&user_id) {
            Some((peer, _)) => {
                Actions::sending(self.sync.send_dm(*peer, envelope, sent_at, ttl_secs))
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
        &self,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Actions {
        Actions::sending(vec![ClientMessage::Account(
            AccountRequest::DeleteAccount {
                secret: secret_of(master).unwrap_or_default(),
                totp: totp
                    .map(|c| c.trim().replace(' ', ""))
                    .filter(|c| !c.is_empty()),
                recovery_code: recovery_code
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty()),
            },
        )])
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
        &self,
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
        &self,
        master: Option<&[u8; 32]>,
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> (Actions, String) {
        let recovery = Zeroizing::new(crate::aead::random::<32>());
        let vault = Vault::from_dek(self.relay_id, &self.name, *self.dek);
        let msg = AccountRequest::RecoveryKeyNew {
            secret: secret_of(master).unwrap_or_default(),
            recovery_slot: vault.recovery_slot(&recovery).v,
            reset_key: reset_key(&recovery, &self.relay_id, &self.name).to_vec(),
            totp: totp
                .map(|c| c.trim().replace(' ', ""))
                .filter(|c| !c.is_empty()),
            recovery_code: recovery_code
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty()),
        };
        (
            Actions::sending(vec![ClientMessage::Account(msg)]),
            recovery_text(&recovery),
        )
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

    pub fn set_share(&mut self, share: bool) {
        self.sync.set_share(share);
    }

    /// Where the host keeps `Actions::memory` (and finds it for `start`).
    pub fn memory_key(&self) -> String {
        memory_key(&self.relay_id, &self.name)
    }
}

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
            blobs: Vec::new(),
        };
        AccountSession::start(
            signed,
            &info(needs_2fa),
            LogMemory::default(),
            false,
            password_based,
        )
    }

    /// This device's side of a pairing, from the ask to the wrapped key.
    fn asked(s: &mut AccountSession, new: &crate::pair::PairRequest) -> Vec<u8> {
        let a = s.on_reply(&AccountReply::PairAsked {
            pair: 5,
            commitment: new.commitment().to_vec(),
        });
        let [ClientMessage::Account(AccountRequest::PairNonce { pair: 5, nonce })] = &a.send[..]
        else {
            panic!("no nonce: {:?}", a.send)
        };
        assert!(a.emit.is_empty(), "nothing to ask the person yet");
        nonce.clone()
    }

    #[test]
    fn the_vault_key_goes_only_to_the_committed_key_and_only_on_a_yes() {
        let (mut s, _) = session(true, false);
        let new = crate::pair::PairRequest::new();
        let nonce = asked(&mut s, &new);
        let (ephemeral, blind) = new.reveal();
        let a = s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral,
            blind,
        });
        assert!(
            a.send.is_empty(),
            "nothing leaves before the person says so"
        );
        let (name, payload) = &a.emit[0];
        assert_eq!(*name, "account-pair-ask");
        assert_eq!(
            payload["code"],
            new.code(&nonce),
            "both devices show the same"
        );

        let a = s.pair_answer(5, true);
        let [ClientMessage::Account(AccountRequest::PairApprove { pair: 5, wrapped })] =
            &a.send[..]
        else {
            panic!("no key: {:?}", a.send)
        };
        assert_eq!(new.open(wrapped, &RELAY, "me"), Some(*s.dek));
        assert!(s.pair_answer(5, true).send.is_empty(), "answered once");
    }

    #[test]
    fn a_no_or_a_swapped_key_hands_nothing_over() {
        let (mut s, _) = session(true, false);
        let new = crate::pair::PairRequest::new();
        asked(&mut s, &new);
        let (ephemeral, blind) = new.reveal();
        s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral,
            blind,
        });
        let a = s.pair_answer(5, false);
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::PairDecline {
                pair: 5
            })]
        ));

        // A relay revealing a key of its own under the commitment it was shown
        asked(&mut s, &new);
        let (theirs, blind) = crate::pair::PairRequest::new().reveal();
        let a = s.on_reply(&AccountReply::PairRevealed {
            pair: 5,
            ephemeral: theirs,
            blind,
        });
        assert!(a.emit.is_empty(), "the person is not even asked");
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::PairDecline {
                pair: 5
            })]
        ));
        assert!(s.pair_answer(5, true).send.is_empty());
    }

    #[test]
    fn a_second_ask_waits_its_turn_and_an_ended_one_goes() {
        let (mut s, _) = session(true, false);
        let new = crate::pair::PairRequest::new();
        asked(&mut s, &new);
        let a = s.on_reply(&AccountReply::PairAsked {
            pair: 6,
            commitment: new.commitment().to_vec(),
        });
        assert!(matches!(
            &a.send[..],
            [ClientMessage::Account(AccountRequest::PairDecline {
                pair: 6
            })]
        ));
        let a = s.on_reply(&AccountReply::PairEnded { pair: 5 });
        assert_eq!(a.emit[0].0, "account-pair-ended");
        asked(&mut s, &new);
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
