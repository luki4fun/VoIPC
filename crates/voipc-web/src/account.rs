//! Account sign-in for the browser: `voipc_crypto::account::SignIn`, the same
//! steps the desktop client runs, behind wasm-bindgen. Messages go in and out
//! as postcard payloads without the length prefix, the bytes the transport
//! carries, so nothing is converted to JS and back on the way.

use serde::Deserialize;

use voipc_crypto::account::{
    normalize_name, password_ok, recovery_parse, DeviceKey, Method, SignIn, SignedIn, Step,
    Zeroizing, KDF_ROUNDS,
};
use voipc_crypto::account_session::{AccountSession as Session, Actions};
use voipc_crypto::sync::{LogMemory, Prefs};
use voipc_protocol::codec::{decode_server_msg, APP_VERSION, PROTOCOL_VERSION};
use voipc_protocol::conv::unhex16;
use voipc_protocol::messages::AccountReply;
use voipc_protocol::messages::{ClientMessage, ServerMessage};
use voipc_protocol::types::PreKeyBundleData;
use voipc_protocol::types::{AccountInfo, UserInfo};
use wasm_bindgen::prelude::*;

fn bytes(msg: &ClientMessage) -> Vec<u8> {
    postcard::to_allocvec(msg).expect("a client message encodes")
}

fn obj(key: &str, value: JsValue) -> JsValue {
    let o = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&o, &JsValue::from_str(key), &value);
    o.into()
}

fn array16(v: &[u8], what: &str) -> Result<[u8; 16], JsError> {
    v.try_into()
        .map_err(|_| JsError::new(&format!("{what} is not 16 bytes")))
}

/// How the browser signs in, from JS.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum MethodJs {
    Login {
        password: String,
    },
    Register {
        password: String,
        invite: Option<String>,
    },
    Device {
        device_id: Vec<u8>,
        device_key: Vec<u8>,
        relay_id: Vec<u8>,
        dek: Vec<u8>,
    },
    /// A forgotten password, with the recovery key as shown (`recovery`).
    Reset {
        recovery: String,
        password: String,
    },
}

#[wasm_bindgen]
pub struct AccountSignIn {
    machine: Option<SignIn>,
    first: Vec<u8>,
    /// After `finish`, until `startSync` takes it.
    signed: Option<SignedIn>,
}

#[wasm_bindgen]
impl AccountSignIn {
    /// `method`: `{ kind: "login", password }`, `{ kind: "register",
    /// password, invite }`, `{ kind: "device", device_id, device_key,
    /// relay_id, dek }` (byte fields as arrays or Uint8Arrays) or `{ kind:
    /// "reset", recovery, password }`. The page stretches the password itself
    /// (`{ stretch: salt }`, then `stretched`), with WebCrypto.
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str, method: JsValue) -> Result<AccountSignIn, JsError> {
        let name = normalize_name(name).map_err(JsError::new)?;
        let method = match serde_wasm_bindgen::from_value::<MethodJs>(method)? {
            MethodJs::Login { password } => Method::Password {
                password: Zeroizing::new(password),
            },
            MethodJs::Register { password, invite } => {
                password_ok(&password).map_err(JsError::new)?;
                Method::Register {
                    password: Zeroizing::new(password),
                    invite,
                }
            }
            MethodJs::Device {
                device_id,
                device_key,
                relay_id,
                dek,
            } => {
                let key = DeviceKey::from_parts(array16(&device_id, "device id")?, device_key)
                    .ok_or_else(|| JsError::new("This device's key is damaged."))?;
                let dek: [u8; 32] = dek
                    .try_into()
                    .map_err(|_| JsError::new("the vault key is not 32 bytes"))?;
                Method::Device {
                    key,
                    relay_id: array16(&relay_id, "relay id")?,
                    dek,
                }
            }
            MethodJs::Reset { recovery, password } => {
                password_ok(&password).map_err(JsError::new)?;
                let recovery =
                    recovery_parse(&recovery).ok_or_else(|| JsError::new(NOT_A_RECOVERY_KEY))?;
                Method::Reset {
                    recovery: Zeroizing::new(recovery),
                    password: Zeroizing::new(password),
                }
            }
        };
        let (mut machine, first) = SignIn::start(&name, method, PROTOCOL_VERSION, APP_VERSION);
        machine.stretch_outside();
        Ok(AccountSignIn {
            machine: Some(machine),
            first: bytes(&first),
            signed: None,
        })
    }

    /// The `Authenticate` payload to open the connection with.
    pub fn first(&self) -> Vec<u8> {
        self.first.clone()
    }

    fn m(&self) -> Result<&SignIn, JsError> {
        self.machine
            .as_ref()
            .ok_or_else(|| JsError::new("the sign-in is over"))
    }

    /// What this browser knows of relay ids (H5-01): the hex id this address
    /// had before, if any, and `[hex id, address]` for the others. A server
    /// naming another's id is refused before the password is stretched.
    #[wasm_bindgen(js_name = expectRelay)]
    pub fn expect_relay(
        &mut self,
        here: Option<String>,
        elsewhere: JsValue,
    ) -> Result<(), JsError> {
        let elsewhere: Vec<(String, String)> = serde_wasm_bindgen::from_value(elsewhere)?;
        let elsewhere = elsewhere
            .into_iter()
            .filter_map(|(id, addr)| Some((unhex16(&id)?, addr)))
            .collect();
        let m = self
            .machine
            .as_mut()
            .ok_or_else(|| JsError::new("the sign-in is over"))?;
        m.expect_relay(here.as_deref().and_then(unhex16), elsewhere);
        Ok(())
    }

    /// One server payload in, the steps out: `{ send: Uint8Array }`,
    /// `{ keys: true }` (take `signalClient()`, then send `keys(bundle)`),
    /// `{ needTotp: true }`, `{ stretch: salt }` (PBKDF2 the password, then
    /// `stretched`), `{ resetDone: true }`; unrelated messages give none.
    /// Throws the reason when the sign-in fails.
    pub fn step(&mut self, payload: &[u8]) -> Result<js_sys::Array, JsError> {
        let msg: ServerMessage = decode_server_msg(payload)?;
        let m = self
            .machine
            .as_mut()
            .ok_or_else(|| JsError::new("the sign-in is over"))?;
        Ok(steps(m.on_message(&msg).map_err(|e| JsError::new(&e))?))
    }

    /// PBKDF2-SHA256 (`kdfRounds()`, 32 bytes) of the password with the salt
    /// `{ stretch }` named; the steps that follow, as `step` gives them.
    pub fn stretched(&mut self, master: &[u8]) -> Result<js_sys::Array, JsError> {
        let master: [u8; 32] = master
            .try_into()
            .map_err(|_| JsError::new("the stretched password is not 32 bytes"))?;
        let m = self
            .machine
            .as_mut()
            .ok_or_else(|| JsError::new("the sign-in is over"))?;
        Ok(steps(m.stretched(&master).map_err(|e| JsError::new(&e))?))
    }

    /// The Signal client for the account's identity, made here: the identity's
    /// private key never reaches JS (1.0 audit H2-10).
    #[wasm_bindgen(js_name = signalClient)]
    pub fn signal_client(&self) -> Result<crate::SignalClient, JsError> {
        let identity = self
            .m()?
            .identity()
            .ok_or_else(|| JsError::new("no identity yet"))?;
        Ok(crate::SignalClient {
            core: crate::signal::SignalCore::with_identity(identity).map_err(crate::js_err)?,
        })
    }

    /// The `Keys` payload, from `SignalClient.bundle().prekey_bundle`.
    pub fn keys(&self, prekey_bundle: JsValue) -> Result<Vec<u8>, JsError> {
        let bundle: PreKeyBundleData = serde_wasm_bindgen::from_value(prekey_bundle)?;
        Ok(bytes(&self.m()?.keys(bundle)))
    }

    pub fn totp(&self, code: &str) -> Result<Vec<u8>, JsError> {
        Ok(bytes(&self.m()?.totp(code)))
    }

    pub fn recovery(&self, code: &str) -> Result<Vec<u8>, JsError> {
        Ok(bytes(&self.m()?.recovery_code(code)))
    }

    /// After `Authenticated`: `{ relay_id: Uint8Array, name }`, which name
    /// where this browser kept the log's read cursors (`memoryKey`).
    pub fn finish(&mut self) -> Result<JsValue, JsError> {
        let m = self
            .machine
            .take()
            .ok_or_else(|| JsError::new("the sign-in is over"))?;
        let s = m.finish().map_err(|e| JsError::new(&e))?;
        let o = js_sys::Object::new();
        let set = |k: &str, v: JsValue| {
            let _ = js_sys::Reflect::set(&o, &JsValue::from_str(k), &v);
        };
        set("relay_id", js_sys::Uint8Array::from(&s.relay_id[..]).into());
        set("name", JsValue::from_str(&s.name));
        self.signed = Some(s);
        Ok(o.into())
    }

    /// After `finish`: the account's session (the stored log, the pins,
    /// remembering this browser), from `info` (the `AccountInfo` in
    /// `Authenticated`), what this browser kept of the log last time (JSON, or
    /// null), whether joiners of a channel's log get our older keys, and
    /// whether this sign-in was with the password.
    /// `{ session: AccountSession, actions }` (`AccountSession` for actions).
    #[wasm_bindgen(js_name = startSession)]
    pub fn start_session(
        &mut self,
        info: JsValue,
        memory: Option<String>,
        share: bool,
        password_based: bool,
    ) -> Result<JsValue, JsError> {
        let signed = self
            .signed
            .take()
            .ok_or_else(|| JsError::new("finish the sign-in first"))?;
        let info: AccountInfo = serde_wasm_bindgen::from_value(info)?;
        let memory: LogMemory = memory
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();
        let (session, started) = Session::start(signed, &info, memory, share, password_based);
        let o = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&o, &"session".into(), &AccountSession { session }.into());
        let _ = js_sys::Reflect::set(&o, &"actions".into(), &actions(started)?);
        Ok(o.into())
    }
}

const NOT_A_RECOVERY_KEY: &str =
    "That is not a recovery key: 52 letters and digits, as it was shown.";

fn steps(steps: Vec<Step>) -> js_sys::Array {
    let out = js_sys::Array::new();
    for step in steps {
        match step {
            Step::Send(c) => {
                out.push(&obj(
                    "send",
                    js_sys::Uint8Array::from(&bytes(&c)[..]).into(),
                ));
            }
            Step::Keys => {
                out.push(&obj("keys", JsValue::TRUE));
            }
            Step::NeedTotp => {
                out.push(&obj("needTotp", JsValue::TRUE));
            }
            Step::Stretch { salt } => {
                out.push(&obj("stretch", JsValue::from_str(&salt)));
            }
            Step::ResetDone => {
                out.push(&obj("resetDone", JsValue::TRUE));
            }
            Step::Ignore => {}
        }
    }
    out
}

/// The PBKDF2 rounds of `stretch` (`voipc_crypto::account::KDF_ROUNDS`).
#[wasm_bindgen(js_name = kdfRounds)]
pub fn kdf_rounds() -> u32 {
    KDF_ROUNDS
}

fn payloads(out: Vec<ClientMessage>) -> js_sys::Array {
    out.iter()
        .map(|m| JsValue::from(js_sys::Uint8Array::from(&bytes(m)[..])))
        .collect()
}

/// What the session asks the page to do (`voipc_crypto::account_session::Actions`):
/// `{ send: Uint8Array[], emit: { name, payload }[], remember?: { relay_id,
/// name, device_id, device_key, dek }, memory?: { key, json } }`.
fn actions(a: Actions) -> Result<JsValue, JsError> {
    let plain = |v: &serde_json::Value| {
        serde::Serialize::serialize(v, &serde_wasm_bindgen::Serializer::json_compatible())
    };
    let o = js_sys::Object::new();
    let set = |k: &str, v: &JsValue| {
        let _ = js_sys::Reflect::set(&o, &JsValue::from_str(k), v);
    };
    set("send", &payloads(a.send).into());
    let emit = js_sys::Array::new();
    for (name, payload) in a.emit {
        // As plain objects: by default a JSON object comes out as a JS Map,
        // whose fields a property read does not see.
        emit.push(&plain(
            &serde_json::json!({ "name": name, "payload": payload }),
        )?);
    }
    set("emit", &emit.into());
    if let Some(r) = a.remember {
        let device = serde_json::json!({
            "relay_id": r.relay_id, "name": r.name, "device_id": r.device_id,
            "device_key": &r.device_key[..], "dek": &r.dek[..],
        });
        set("remember", &plain(&device)?);
    }
    if let Some((key, memory)) = a.memory {
        set(
            "memory",
            &plain(
                &serde_json::json!({ "key": key, "json": serde_json::to_string(&memory).unwrap_or_default() }),
            )?,
        );
    }
    Ok(o.into())
}

/// `voipc_crypto::account_session::AccountSession`: the rules the desktop
/// client runs too, for what follows a sign-in.
#[wasm_bindgen]
pub struct AccountSession {
    session: Session,
}

#[wasm_bindgen]
impl AccountSession {
    /// Once the session is listed: the sync's first asks, then the
    /// second-factor setup a role waits for, or remembering this browser.
    #[wasm_bindgen(js_name = afterConnect)]
    pub fn after_connect(&mut self) -> Result<JsValue, JsError> {
        actions(self.session.after_connect())
    }

    /// A decoded `AccountReply`.
    #[wasm_bindgen(js_name = onReply)]
    pub fn on_reply(&mut self, reply: JsValue) -> Result<JsValue, JsError> {
        let reply: AccountReply = serde_wasm_bindgen::from_value(reply)?;
        actions(self.session.on_reply(&reply))
    }

    /// The `users` of a `UserList` or `UserJoined`, for the pins.
    #[wasm_bindgen(js_name = noteRoster)]
    pub fn note_roster(&mut self, users: JsValue) -> Result<JsValue, JsError> {
        let users: Vec<UserInfo> = serde_wasm_bindgen::from_value(users)?;
        actions(self.session.note_roster(&users))
    }

    /// An identity `user_id` showed (a pre-key bundle, or a session they
    /// opened: `SignalClient.takeSeen`), against the pins.
    #[wasm_bindgen(js_name = checkIdentity)]
    pub fn check_identity(&mut self, user_id: u32, key: &[u8]) -> Result<JsValue, JsError> {
        actions(self.session.check_identity(user_id, key))
    }

    #[wasm_bindgen(js_name = outgoingDm)]
    pub fn outgoing_dm(
        &mut self,
        user_id: u32,
        envelope: &[u8],
        sent_at: f64,
        ttl_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        actions(
            self.session
                .outgoing_dm(user_id, envelope.to_vec(), sent_at as u64, ttl_secs),
        )
    }

    /// A direct message for an account that is away (its hex id).
    #[wasm_bindgen(js_name = keptDm)]
    pub fn kept_dm(
        &mut self,
        account_hex: &str,
        envelope: &[u8],
        sent_at: f64,
        ttl_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        let a = self
            .session
            .kept_dm(account_hex, envelope.to_vec(), sent_at as u64, ttl_secs)
            .map_err(|e| JsError::new(&e))?;
        actions(a)
    }

    #[wasm_bindgen(js_name = outgoingChannel)]
    pub fn outgoing_channel(
        &mut self,
        log: &str,
        envelope: &[u8],
        sent_at: f64,
        ttl_secs: Option<u32>,
    ) -> Result<JsValue, JsError> {
        actions(
            self.session
                .outgoing_channel(log, envelope.to_vec(), sent_at as u64, ttl_secs),
        )
    }

    /// In a channel with log `conv`: keep it, and read what it kept.
    pub fn enter(&mut self, conv: &str) -> Result<JsValue, JsError> {
        actions(self.session.enter(conv))
    }

    /// Delete what this account wrote to the stored logs, in `conv` or
    /// (null) everywhere.
    pub fn purge(&mut self, conv: Option<String>) -> Result<JsValue, JsError> {
        actions(self.session.purge(conv.as_deref()))
    }

    /// Delete this account, from its stretched password (`kdfSalt`).
    #[wasm_bindgen(js_name = deleteAccount)]
    pub fn delete_account(
        &self,
        master: &[u8],
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Result<JsValue, JsError> {
        let master: [u8; 32] = master
            .try_into()
            .map_err(|_| JsError::new("the stretched password is not 32 bytes"))?;
        actions(self.session.delete_account(&master, totp, recovery_code))
    }

    /// Out of channel log `conv`; with `tell`, asks the relay to take us out.
    pub fn leave(&mut self, conv: &str, tell: bool) -> Result<JsValue, JsError> {
        actions(self.session.leave(conv, tell))
    }

    #[wasm_bindgen(js_name = keptFor)]
    pub fn kept_for(&self, user_id: u32) -> bool {
        self.session.kept_for(user_id)
    }

    /// Throws why there is none (not an account, never seen, a key changed).
    #[wasm_bindgen(js_name = safetyNumber)]
    pub fn safety_number(
        &self,
        user_id: u32,
        own_key: &[u8],
        live: Option<Vec<u8>>,
    ) -> Result<String, JsError> {
        self.session
            .safety_number(user_id, own_key, live.as_deref())
            .map_err(|e| JsError::new(&e))
    }

    pub fn cloud(&self) -> bool {
        self.session.prefs().cloud
    }

    pub fn asked(&self) -> bool {
        self.session.prefs().asked
    }

    #[wasm_bindgen(js_name = setPrefs)]
    pub fn set_prefs(&mut self, cloud: bool, asked: bool) -> Result<JsValue, JsError> {
        actions(self.session.set_prefs(Prefs { cloud, asked }))
    }

    #[wasm_bindgen(js_name = setShare)]
    pub fn set_share(&mut self, share: bool) {
        self.session.set_share(share);
    }

    /// The PBKDF2 salt for this account's passwords.
    #[wasm_bindgen(js_name = kdfSalt)]
    pub fn kdf_salt(&self) -> String {
        self.session.kdf_salt()
    }

    /// A new password, from the stretched old and new ones (`kdfSalt`), and
    /// a code where the account has codes on.
    #[wasm_bindgen(js_name = passwordChange)]
    pub fn password_change(
        &self,
        old_master: &[u8],
        new_master: &[u8],
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Result<JsValue, JsError> {
        let m32 = |m: &[u8]| -> Result<[u8; 32], JsError> {
            m.try_into()
                .map_err(|_| JsError::new("a stretched password is not 32 bytes"))
        };
        actions(self.session.password_change(
            &m32(old_master)?,
            &m32(new_master)?,
            totp,
            recovery_code,
        ))
    }

    /// A new recovery key, from the stretched password (`kdfSalt`) and a code
    /// where the account has codes on: the actions to run, and `key`, the
    /// text to show once `RecoveryKeyChanged` answers (S-006).
    #[wasm_bindgen(js_name = recoveryKeyNew)]
    pub fn recovery_key_new(
        &self,
        master: &[u8],
        totp: Option<String>,
        recovery_code: Option<String>,
    ) -> Result<JsValue, JsError> {
        let master: [u8; 32] = master
            .try_into()
            .map_err(|_| JsError::new("the stretched password is not 32 bytes"))?;
        let (a, key) = self.session.recovery_key_new(&master, totp, recovery_code);
        let out = actions(a)?;
        js_sys::Reflect::set(&out, &JsValue::from_str("key"), &JsValue::from_str(&key))
            .map_err(|_| JsError::new("could not hand the key over"))?;
        Ok(out)
    }
}

/// The authenticator app's QR code for an `otpauth://` link, drawn here.
#[wasm_bindgen(js_name = qrSvg)]
pub fn qr_svg(text: &str) -> Option<String> {
    voipc_crypto::account::qr_svg(text)
}

/// An account name as the relay stores it; throws why not.
#[wasm_bindgen(js_name = normalizeAccountName)]
pub fn normalize_account_name(raw: &str) -> Result<String, JsError> {
    normalize_name(raw).map_err(JsError::new)
}
