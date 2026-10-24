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
use voipc_protocol::types::{AccountInfo, UserInfo};
use zeroize::Zeroizing;

use crate::account::{derive_from_master, kdf_salt, DeviceEnrol, PinCheck, SignedIn, Vault};
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
        Actions { send, ..Default::default() }
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
}

impl AccountSession {
    /// After `Authenticated`: what the sign-in left, the account it is, what
    /// this device kept of the log last time, and whether joiners of a
    /// channel's log get our older keys. Tells the front end it signed in.
    pub fn start(signed: SignedIn, info: &AccountInfo, memory: LogMemory, share: bool, password_based: bool) -> (AccountSession, Actions) {
        let (sync, first) = AccountSync::start(&signed, info.id, memory, share);
        let signed_in = json!({
            "name": signed.name,
            "relay_id": hex(&signed.relay_id),
            "info": info,
            "recovery": signed.recovery,
            "prefs": sync.prefs(),
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
        };
        (s, Actions { emit: vec![("account-signed-in", signed_in)], ..Default::default() })
    }

    /// Once the connection is up, and listed (so the front end's commands
    /// find it): what the sync asks first, then the second-factor setup a role
    /// waits for, or else remembering this device.
    pub fn after_connect(&mut self) -> Actions {
        let mut a = Actions::sending(std::mem::take(&mut self.first));
        if self.needs_2fa {
            a.send.push(ClientMessage::Account(AccountRequest::TotpSetup));
        } else if self.password_based && !self.remembered {
            self.start_enrol(&mut a);
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

    /// One `AccountReply`. What none of this answers goes to the front end
    /// as `account-reply`.
    pub fn on_reply(&mut self, reply: &AccountReply) -> Actions {
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
            AccountReply::Error { request, .. } if request.starts_with("Device") => self.enrol = None,
            // Our entries in `conv` are gone from the relay: a tombstone
            // tells the readers' devices to drop their copies too.
            AccountReply::LogPurged { conv: Some(conv), .. } if self.tombstones.remove(conv) => {
                let now = crate::time::now_millis();
                let tomb = crate::envelope::purge_envelope(&crate::envelope::new_message_id(), now);
                match voipc_protocol::conv::dm_parties(conv) {
                    Some((x, y)) => a.send.extend(self.sync.send_dm(if x == self.me { y } else { x }, tomb, now, None)),
                    None => a.send.extend(self.sync.send_channel(conv, tomb, now, None)),
                }
            }
            _ => {}
        }
        a.emit.push(("account-reply", serde_json::to_value(reply).unwrap_or(Value::Null)));
        a
    }

    fn events(&mut self, events: Vec<Event>, a: &mut Actions) {
        let mut read = self.sync.take_memory_changed();
        for e in events {
            read |= e.reads();
            match &e {
                Event::IdentityChanged { account, name, replaced } => self.identity_changed(account, name, *replaced, a),
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
        let here: Vec<u32> = self.roster.iter().filter(|(_, (acc, _))| acc == account).map(|(u, _)| *u).collect();
        if here.is_empty() {
            a.emit.push(("identity-key-changed", json!({ "user_id": null, "name": name, "replaced": replaced })));
        }
        for user_id in here {
            a.emit.push(("identity-key-changed", json!({ "user_id": user_id, "name": name, "replaced": replaced })));
        }
    }

    /// The accounts in a roster (`UserList`, `UserJoined`), for the pins. The
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
                    a.emit.push(("identity-key-changed", json!({ "user_id": u.user_id, "name": u.username, "as_guest": true })));
                }
                None => {}
            }
        }
        a
    }

    /// An identity `user_id` showed — in a pre-key bundle, or in a session
    /// they opened (`VoipcIdentityStore::take_seen`) — against the pins.
    pub fn check_identity(&mut self, user_id: u32, key: &[u8]) -> Actions {
        let Some((account, name)) = self.roster.get(&user_id).cloned() else { return Actions::default() };
        let (check, send) = self.sync.check_peer(&account, &name, key);
        let mut a = Actions::sending(send);
        if check.warns() {
            a.emit.push(("identity-key-changed", json!({ "user_id": user_id, "name": name, "new_identity_key": key, "replaced": check == PinCheck::Replaced })));
        }
        a
    }

    /// A direct message to `user_id`, kept for them too when cloud copies are
    /// on and they signed in to an account.
    pub fn outgoing_dm(&mut self, user_id: u32, envelope: Vec<u8>, sent_at: u64, ttl_secs: Option<u32>) -> Actions {
        match self.roster.get(&user_id) {
            Some((peer, _)) => Actions::sending(self.sync.send_dm(*peer, envelope, sent_at, ttl_secs)),
            None => Actions::default(),
        }
    }

    /// A direct message for an account that is away (`account_hex`): kept in
    /// the stored log only, which is the one way it reaches them.
    pub fn kept_dm(&mut self, account_hex: &str, envelope: Vec<u8>, sent_at: u64, ttl_secs: Option<u32>) -> Result<Actions, String> {
        if !self.cloud() {
            return Err("They are away, and your messages are not kept on this server".into());
        }
        let peer = unhex16(account_hex).ok_or("not an account id")?;
        Ok(Actions::sending(self.sync.send_dm(peer, envelope, sent_at, ttl_secs)))
    }

    /// A message written in a channel with log `log` (`ChannelInfo::log`;
    /// empty: none), kept for its members too.
    pub fn outgoing_channel(&mut self, log: &str, envelope: Vec<u8>, sent_at: u64, ttl_secs: Option<u32>) -> Actions {
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
        self.cloud() && self.roster.contains_key(&user_id)
    }

    /// The safety number with `user_id`: our identity `own_key`, their pinned
    /// one, and `live`, the key the session with them runs on. One that is
    /// not the pinned key was never checked against it, so there is no number.
    pub fn safety_number(&self, user_id: u32, own_key: &[u8], live: Option<&[u8]>) -> Result<String, String> {
        let (peer, _) = self.roster.get(&user_id).ok_or("They are not signed in to an account")?;
        let pinned = self.sync.pinned(peer).ok_or("Their identity has not been seen yet")?;
        if live.is_some_and(|l| l != pinned) {
            return Err("Their identity changed: the conversation runs on another key than the one pinned. Reconnect, then verify again.".into());
        }
        crate::account::safety_number(&self.me, own_key, peer, pinned).ok_or_else(|| "could not compute the safety number".into())
    }

    /// Deletes what this account wrote to the stored logs: in `conv` (then a
    /// tombstone asks the readers' devices to drop their copies too), or
    /// (None) everywhere, where the copies already read stay.
    pub fn purge(&mut self, conv: Option<&str>) -> Actions {
        if let Some(c) = conv {
            self.tombstones.insert(c.to_string());
        }
        Actions::sending(vec![ClientMessage::Account(AccountRequest::LogPurge { conv: conv.map(str::to_string) })])
    }

    /// Deletes this account, from `stretch` of its password and the second
    /// factor where it has one. `AccountDeleted` answers; the relay then
    /// closes the connection.
    pub fn delete_account(&self, master: &[u8; 32], totp: Option<String>, recovery_code: Option<String>) -> Actions {
        Actions::sending(vec![ClientMessage::Account(AccountRequest::DeleteAccount {
            secret: derive_from_master(master).auth_secret.to_vec(),
            totp: totp.map(|c| c.trim().replace(' ', "")).filter(|c| !c.is_empty()),
            recovery_code: recovery_code.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()),
        })])
    }

    /// The PBKDF2 salt for this account's passwords (`account::stretch`).
    pub fn kdf_salt(&self) -> String {
        kdf_salt(&self.relay_id, &self.name)
    }

    /// A new password, from `stretch` of the old one and of the new one, and
    /// the second factor where the account has one. The vault's password
    /// slot is wrapped again for the new one; the DEK and the recovery slot
    /// stay. `PasswordChanged` answers it; every other device is signed out.
    pub fn password_change(&self, old_master: &[u8; 32], new_master: &[u8; 32], totp: Option<String>, recovery_code: Option<String>) -> Actions {
        let (old, new) = (derive_from_master(old_master), derive_from_master(new_master));
        let vault = Vault::from_dek(self.relay_id, &self.name, *self.dek);
        Actions::sending(vec![ClientMessage::Account(AccountRequest::PasswordChange {
            old_secret: old.auth_secret.to_vec(),
            new_secret: new.auth_secret.to_vec(),
            pass_slot: vault.pass_slot(&new.vault_key).v,
            totp: totp.map(|c| c.trim().replace(' ', "")).filter(|c| !c.is_empty()),
            recovery_code: recovery_code.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()),
        })])
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

    pub fn set_share(&mut self, share: bool) {
        self.sync.set_share(share);
    }

    /// Where the host keeps `Actions::memory` (and finds it for `start`).
    pub fn memory_key(&self) -> String {
        memory_key(&self.relay_id, &self.name)
    }
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
        AccountInfo { id: ME, name: "me".into(), scopes: Vec::new(), needs_2fa, totp_enabled: false }
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
        AccountSession::start(signed, &info(needs_2fa), LogMemory::default(), false, password_based)
    }

    fn sends(a: &Actions, what: &str) -> usize {
        a.send.iter().filter(|m| matches!(m, ClientMessage::Account(r) if format!("{r:?}").starts_with(what))).count()
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
        }
    }

    /// A conversation's tombstone goes only after the relay purged it: sent
    /// before, the purge would take it too. A purge of everything sends none.
    #[test]
    fn a_purge_sends_its_tombstone_after_the_relay_did_it() {
        let (mut s, _) = session(true, false);
        s.set_prefs(Prefs { cloud: true, asked: true });
        let conv = format!("c:{}", "ab".repeat(16));
        let a = s.purge(Some(&conv));
        assert_eq!(sends(&a, "LogPurge"), 1);
        assert!(s.on_reply(&AccountReply::LogPurged { conv: Some("c:other".into()), entries: 0 }).send.is_empty(), "not one we asked for");
        let a = s.on_reply(&AccountReply::LogPurged { conv: Some(conv.clone()), entries: 2 });
        assert!(!a.send.is_empty(), "the tombstone is on its way (its first ask)");
        assert!(a.emit.iter().any(|(n, _)| *n == "account-reply"));
        assert!(s.on_reply(&AccountReply::LogPurged { conv: Some(conv), entries: 0 }).send.is_empty(), "once");
        s.purge(None);
        assert!(s.on_reply(&AccountReply::LogPurged { conv: None, entries: 5 }).send.is_empty());
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
        let a = s.on_reply(&AccountReply::DeviceChallenge { challenge: "c".into() });
        assert_eq!(sends(&a, "DeviceAdd"), 1, "the challenge is answered, nothing emitted");
        assert!(a.emit.is_empty());
        let a = s.on_reply(&AccountReply::DeviceAdded);
        let kept = a.remember.expect("the key to keep");
        assert_eq!((kept.relay_id, kept.name.as_str()), (RELAY, "me"));
        assert!(s.on_reply(&AccountReply::DeviceAdded).remember.is_none(), "once");
        assert_eq!(sends(&s.on_reply(&info_reply), "DeviceChallenge"), 0, "remembered already");
    }

    #[test]
    fn a_role_that_waits_for_codes_asks_for_their_setup_not_for_the_device() {
        let (mut s, _) = session(true, true);
        let a = s.after_connect();
        assert_eq!((sends(&a, "TotpSetup"), sends(&a, "DeviceChallenge")), (1, 0));
        // Codes on: the relay forgot device keys; the next Info remembers this one.
        s.on_reply(&AccountReply::TotpEnabled { recovery_codes: Vec::new() });
        assert_eq!(sends(&s.on_reply(&AccountReply::Info(info(false))), "DeviceChallenge"), 1);
    }

    #[test]
    fn a_device_key_sign_in_never_enrols() {
        let (mut s, _) = session(false, false);
        assert_eq!(sends(&s.after_connect(), "DeviceChallenge"), 0);
        assert_eq!(sends(&s.on_reply(&AccountReply::Info(info(false))), "DeviceChallenge"), 0);
    }

    #[test]
    fn identities_are_checked_for_the_accounts_the_rosters_name() {
        let (mut s, _) = session(false, false);
        let key = || IdentityKeyPair::generate(&mut crate::rng()).public_key().serialize().to_vec();
        let (k1, k2) = (key(), key());
        assert!(s.check_identity(5, &k1).emit.is_empty(), "a guest: nothing to check");
        s.note_roster(&[user(5, [5; 16], "bob")]);
        assert!(s.check_identity(5, &k1).emit.is_empty(), "first sight is pinned");
        assert!(s.check_identity(5, &k1).emit.is_empty());
        let a = s.check_identity(5, &k2);
        assert_eq!(a.emit.len(), 1);
        assert_eq!((a.emit[0].0, a.emit[0].1["user_id"].as_u64(), a.emit[0].1["name"].as_str()), ("identity-key-changed", Some(5), Some("bob")));
        // "bob" again, under another account id: a change too.
        s.note_roster(&[user(6, [9; 16], "bob")]);
        assert_eq!(s.check_identity(6, &k2).emit.len(), 1, "the name was another account's");
        assert!(s.safety_number(6, &k1, Some(&k1)).is_err(), "a live key that is not the pin has no number");
        assert!(s.safety_number(6, &k1, Some(&k2)).is_ok());
        assert!(s.safety_number(7, &k1, None).is_err(), "not an account");
    }

    #[test]
    fn copies_go_where_an_account_is_and_cloud_copies_are_on() {
        let (mut s, _) = session(false, false);
        s.note_roster(&[user(5, [5; 16], "bob")]);
        assert!(s.outgoing_dm(5, b"x".to_vec(), 1, None).send.is_empty(), "cloud copies are off");
        assert!(!s.kept_for(5));
        assert!(s.kept_dm(&hex(&[5; 16]), b"x".to_vec(), 1, None).is_err());
        s.set_prefs(Prefs { cloud: true, asked: true });
        assert!(s.kept_for(5) && !s.kept_for(6), "a guest has no log");
        assert!(s.outgoing_channel("", b"x".to_vec(), 1, None).send.is_empty(), "no log in that channel");
        assert!(s.kept_dm("zz", b"x".to_vec(), 1, None).is_err());
        assert_eq!(s.memory_key(), memory_key(&RELAY, "me"));
    }
}
